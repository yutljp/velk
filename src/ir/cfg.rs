use std::collections::HashSet;

use crate::ir::visit::statement_registers;
use crate::ir::{Block, Expr, FunctionIr, Stmt};

/// Normal successors and the landing pads of protected calls in the block.
/// Unwinding can leave before the block's later statements execute.
pub(crate) fn successors(ir: &FunctionIr, index: usize) -> Vec<usize> {
    let edges = block_successors_with_exceptions(&ir.blocks, index, &ir.landing_pads);
    let mut out = edges.normal;
    for next in edges.exceptional {
        if !out.contains(&next) {
            out.push(next);
        }
    }
    out
}

pub(crate) struct BlockSuccessors {
    pub normal: Vec<usize>,
    pub exceptional: Vec<usize>,
    pub unknown_normal: bool,
    pub unknown_exceptional: bool,
}

pub(crate) fn block_successors_with_exceptions(
    blocks: &[Block],
    index: usize,
    landing_pads: &[(u64, Vec<(u64, u64)>)],
) -> BlockSuccessors {
    let block = &blocks[index];
    let unknown_normal = matches!(
        block.stmts.last(),
        Some(Stmt::BrIndirect { .. } | Stmt::Br { target: None })
    );
    let mut edges = BlockSuccessors {
        normal: if unknown_normal {
            Vec::new()
        } else {
            block_successors(blocks, index)
        },
        exceptional: Vec::new(),
        unknown_normal,
        unknown_exceptional: false,
    };
    if !block
        .stmts
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Call { .. } | Stmt::Unsupported { .. }))
    {
        return edges;
    }
    let start = block.start;
    let end = blocks.get(index + 1).map_or(u64::MAX, |next| next.start);
    for (pad, sites) in landing_pads {
        if !sites
            .iter()
            .any(|(from, to)| from < to && start < *to && *from < end)
        {
            continue;
        }
        match blocks.iter().position(|block| block.start == *pad) {
            Some(next) if !edges.exceptional.contains(&next) => edges.exceptional.push(next),
            Some(_) => {}
            None => edges.unknown_exceptional = true,
        }
    }
    edges
}

/// The starts of the blocks some path from the entry reaches.
pub(crate) fn reached(ir: &FunctionIr) -> HashSet<u64> {
    let mut seen = vec![false; ir.blocks.len()];
    let mut pending = vec![0];
    while let Some(at) = pending.pop() {
        if at < ir.blocks.len() && !std::mem::replace(&mut seen[at], true) {
            pending.extend(successors(ir, at));
        }
    }
    ir.blocks
        .iter()
        .zip(seen)
        .filter(|(_, seen)| *seen)
        .map(|(block, _)| block.start)
        .collect()
}

pub(crate) fn block_successors(blocks: &[Block], index: usize) -> Vec<usize> {
    normal_successors(
        blocks[index].stmts.last(),
        (index + 1 < blocks.len()).then_some(index + 1),
        |address| blocks.iter().position(|block| block.start == address),
        UnknownBranch::Fallthrough,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnknownBranch {
    Fallthrough,
    Stop,
}

/// Normal edges in terminator order, retaining repeated destinations.
pub(crate) fn normal_successors(
    terminator: Option<&Stmt>,
    fallthrough: Option<usize>,
    find: impl Fn(u64) -> Option<usize>,
    unknown_branch: UnknownBranch,
) -> Vec<usize> {
    let mut out = Vec::new();
    match terminator {
        Some(Stmt::Br {
            target: Some(target),
        }) => out.extend(find(*target)),
        Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
            out.extend(find(*target));
            out.extend(fallthrough);
        }
        Some(Stmt::Switch { cases, default, .. }) => {
            for (_, target) in cases {
                out.extend(find(*target));
            }
            if let Some(target) = default {
                out.extend(find(*target));
            }
        }
        Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
        Some(Stmt::Br { target: None }) if unknown_branch == UnknownBranch::Stop => {}
        _ => out.extend(fallthrough),
    }
    out
}

/// The blocks that can reach themselves: the bodies of the loops.
pub(crate) fn cyclic_blocks(ir: &FunctionIr) -> std::collections::HashSet<usize> {
    let index: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let successors: Vec<Vec<usize>> = ir
        .blocks
        .iter()
        .map(|block| {
            let fallthrough = index.get(&block.start).map(|position| position + 1);
            let mut next = normal_successors(
                block.stmts.last(),
                fallthrough,
                |address| index.get(&address).copied(),
                UnknownBranch::Fallthrough,
            );
            next.retain(|position| *position < ir.blocks.len());
            next
        })
        .collect();
    let mut cyclic = std::collections::HashSet::new();
    for start in 0..ir.blocks.len() {
        let mut seen = std::collections::HashSet::new();
        let mut stack = successors[start].clone();
        while let Some(next) = stack.pop() {
            if next == start {
                cyclic.insert(start);
                break;
            }
            if seen.insert(next) {
                stack.extend(successors[next].iter().copied());
            }
        }
    }
    cyclic
}

/// An unmodeled instruction or an indirect jump may read anything, so a block
/// holding one keeps every definition and reads everything.
pub(crate) fn opaque(block: &Block) -> bool {
    block.stmts.iter().any(|stmt| {
        matches!(
            stmt,
            Stmt::Unsupported { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }
        )
    })
}

/// The registers live on entry to each block. Computed over dense bit sets
/// of the registers the function names, from each block's upward-exposed
/// reads and its writes; a block with an unmodeled effect may read any of
/// them.
pub(crate) fn live_in(ir: &FunctionIr) -> Vec<HashSet<u16>> {
    let count = ir.blocks.len();
    let registers = registers_used_or_machine(ir);
    let register_positions: std::collections::HashMap<u16, usize> = registers
        .iter()
        .enumerate()
        .map(|(position, register)| (*register, position))
        .collect();
    let words = registers.len().div_ceil(64);
    let set = |bits: &mut [u64], register: u16| {
        let at = register_positions[&register];
        bits[at / 64] |= 1 << (at % 64);
    };
    let clear = |bits: &mut [u64], register: u16| {
        let at = register_positions[&register];
        bits[at / 64] &= !(1 << (at % 64));
    };
    // What each block reads before writing it, and what it writes.
    let mut uses = vec![vec![0u64; words]; count];
    let mut defs = vec![vec![0u64; words]; count];
    for (index, block) in ir.blocks.iter().enumerate() {
        for stmt in block.stmts.iter().rev() {
            let (writes, reads) = statement_registers(stmt);
            for written in writes {
                clear(&mut uses[index], written);
                set(&mut defs[index], written);
            }
            for read in reads {
                set(&mut uses[index], read);
            }
        }
        if opaque(block) {
            uses[index].fill(u64::MAX);
        }
    }
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut live = vec![vec![0u64; words]; count];
    // The sets only grow, so this reaches a fixpoint.
    loop {
        let mut changed = false;
        for index in (0..count).rev() {
            let mut next = uses[index].clone();
            for successor in &successors[index] {
                for word in 0..words {
                    next[word] |= live[*successor][word] & !defs[index][word];
                }
            }
            if next != live[index] {
                live[index] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    live.iter()
        .map(|bits| {
            registers
                .iter()
                .enumerate()
                .filter(|(position, _)| bits[position / 64] >> (position % 64) & 1 == 1)
                .map(|(_, register)| *register)
                .collect()
        })
        .collect()
}

/// The registers live on leaving block `index`, given `live_in`.
pub(crate) fn live_out(ir: &FunctionIr, live_in: &[HashSet<u16>], index: usize) -> HashSet<u16> {
    if opaque(&ir.blocks[index]) {
        return registers_used_or_machine(ir).into_iter().collect();
    }
    live_out_of(live_in, &successors(ir, index))
}

/// Every register the function's statements name, and the machine registers
/// of either architecture, which an unmodeled effect may read.
fn registers_used_or_machine(ir: &FunctionIr) -> Vec<u16> {
    let mut registers: std::collections::BTreeSet<u16> = crate::arch::machine_registers()
        .chain(crate::ir::FLAG_OPERANDS)
        .chain([crate::ir::EXCHANGE])
        .collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = statement_registers(stmt);
        registers.extend(writes);
        registers.extend(reads);
    }
    registers.into_iter().collect()
}

fn live_out_of(live_in: &[HashSet<u16>], successors: &[usize]) -> HashSet<u16> {
    successors
        .iter()
        .flat_map(|next| live_in[*next].iter().copied())
        .collect()
}

/// The value of the last return that is not a tail call, which returns
/// whatever its callee does.
pub(crate) fn own_return(blocks: &[Block]) -> Option<&Expr> {
    blocks
        .iter()
        .rev()
        .find_map(|block| match block.stmts.as_slice() {
            [.., Stmt::Call { .. }, Stmt::Ret { .. }] => None,
            [.., Stmt::Ret { value }] => Some(value),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::{block_successors_with_exceptions, successors};
    use crate::ir::{Block, Convention, Expr, FunctionIr, Stmt};
    use crate::loader::Isa;

    #[test]
    fn cyclic_edges_match_start_map_dispatch() {
        use crate::ir::Cond;
        use std::collections::{HashMap, HashSet};
        let branches = vec![
            Vec::new(),
            vec![Stmt::Br { target: None }],
            vec![Stmt::Br { target: Some(8) }],
            vec![Stmt::Br { target: Some(99) }],
            vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                target: 8,
            }],
            vec![Stmt::BrifFlags {
                cond: Cond::Eq,
                target: 99,
            }],
            vec![Stmt::Switch {
                index: Expr::reg(0, 64),
                cases: vec![(0, 8), (1, 8), (2, 99)],
                default: Some(0),
            }],
            vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
            vec![Stmt::Trap],
            vec![Stmt::BrIndirect {
                target: Expr::reg(0, 64),
            }],
        ];
        for starts in [[0, 8, 16], [0, 0, 8], [8, 0, 8]] {
            let index: HashMap<u64, usize> = starts
                .into_iter()
                .enumerate()
                .map(|(position, start)| (start, position))
                .collect();
            for first in &branches {
                for second in &branches {
                    for third in &branches {
                        let blocks = vec![
                            Block {
                                start: starts[0],
                                stmts: first.clone(),
                            },
                            Block {
                                start: starts[1],
                                stmts: second.clone(),
                            },
                            Block {
                                start: starts[2],
                                stmts: third.clone(),
                            },
                        ];
                        let mut successors = Vec::new();
                        for block in &blocks {
                            let mut next = Vec::new();
                            match block.stmts.last() {
                                Some(Stmt::Brif { target, .. })
                                | Some(Stmt::BrifFlags { target, .. }) => {
                                    if let Some(target) = index.get(target) {
                                        next.push(*target);
                                    }
                                    next.push(
                                        index
                                            .get(&block.start)
                                            .map(|position| position + 1)
                                            .unwrap_or_default(),
                                    );
                                }
                                Some(Stmt::Br {
                                    target: Some(target),
                                }) => {
                                    if let Some(target) = index.get(target) {
                                        next.push(*target);
                                    }
                                }
                                Some(Stmt::Switch { cases, default, .. }) => {
                                    for (_, target) in cases {
                                        if let Some(target) = index.get(target) {
                                            next.push(*target);
                                        }
                                    }
                                    if let Some(target) = default
                                        && let Some(target) = index.get(target)
                                    {
                                        next.push(*target);
                                    }
                                }
                                Some(Stmt::Ret { .. })
                                | Some(Stmt::BrIndirect { .. })
                                | Some(Stmt::Trap) => {}
                                _ => {
                                    if let Some(position) = index.get(&block.start) {
                                        next.push(position + 1);
                                    }
                                }
                            }
                            next.retain(|position| *position < blocks.len());
                            let mut actual = super::normal_successors(
                                block.stmts.last(),
                                index.get(&block.start).map(|position| position + 1),
                                |address| index.get(&address).copied(),
                                super::UnknownBranch::Fallthrough,
                            );
                            actual.retain(|position| *position < blocks.len());
                            assert_eq!(actual, next);
                            successors.push(next);
                        }
                        let mut expected = HashSet::new();
                        for start in 0..blocks.len() {
                            let mut seen = HashSet::new();
                            let mut work = successors[start].clone();
                            while let Some(next) = work.pop() {
                                if next == start {
                                    expected.insert(start);
                                    break;
                                }
                                if seen.insert(next) {
                                    work.extend(successors[next].iter().copied());
                                }
                            }
                        }
                        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
                        ir.blocks = blocks;
                        assert_eq!(super::cyclic_blocks(&ir), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn normal_edge_order_and_unknown_branch_policies() {
        let mut blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Switch {
                    index: Expr::reg(0, 64),
                    cases: vec![(0, 16), (1, 8), (2, 16), (3, 99)],
                    default: Some(8),
                }],
            },
            Block {
                start: 8,
                stmts: Vec::new(),
            },
            Block {
                start: 16,
                stmts: Vec::new(),
            },
        ];
        assert_eq!(super::block_successors(&blocks, 0), vec![2, 1, 2, 1]);
        for branch in [
            Stmt::Br { target: None },
            Stmt::BrIndirect {
                target: Expr::reg(0, 64),
            },
        ] {
            let direct = matches!(branch, Stmt::Br { .. });
            blocks[0].stmts = vec![branch];
            assert_eq!(
                super::block_successors(&blocks, 0),
                if direct { vec![1] } else { vec![] }
            );
            assert_eq!(
                super::normal_successors(
                    blocks[0].stmts.last(),
                    Some(1),
                    |address| blocks.iter().position(|block| block.start == address),
                    super::UnknownBranch::Stop,
                ),
                Vec::<usize>::new()
            );
        }
    }

    fn call() -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
            clobbers: None,
            via: None,
        }
    }

    #[test]
    fn protected_ranges_cover_each_call_block_and_have_half_open_ends() {
        let blocks: Vec<_> = [0, 8, 16, 24, 32]
            .into_iter()
            .map(|start| Block {
                start,
                stmts: vec![call()],
            })
            .collect();
        let pads = [(32, vec![(8, 24)])];
        for (index, expected) in [(0, vec![]), (1, vec![4]), (2, vec![4]), (3, vec![])] {
            let edges = block_successors_with_exceptions(&blocks, index, &pads);
            assert_eq!(edges.exceptional, expected);
            assert!(!edges.unknown_exceptional);
        }
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks = blocks;
        ir.landing_pads = pads.to_vec();
        assert_eq!(successors(&ir, 1), vec![2, 4]);
    }

    #[test]
    fn unknown_normal_and_exception_targets_are_independent() {
        for branch in [
            Stmt::Br { target: None },
            Stmt::BrIndirect {
                target: Expr::reg(1, 64),
            },
        ] {
            let blocks = [
                Block {
                    start: 0,
                    stmts: vec![branch],
                },
                Block {
                    start: 8,
                    stmts: Vec::new(),
                },
            ];
            let edges = block_successors_with_exceptions(&blocks, 0, &[]);
            assert!(edges.normal.is_empty());
            assert!(edges.unknown_normal);
            assert!(!edges.unknown_exceptional);
        }
        let blocks = [Block {
            start: 0,
            stmts: vec![call()],
        }];
        let edges = block_successors_with_exceptions(&blocks, 0, &[(16, vec![(0, 4)])]);
        assert!(!edges.unknown_normal);
        assert!(edges.unknown_exceptional);
        assert!(edges.exceptional.is_empty());
    }

    #[test]
    fn opaque_protected_blocks_keep_the_exception_edge() {
        let blocks = [
            Block {
                start: 0,
                stmts: vec![Stmt::Unsupported {
                    text: "opaque".to_owned(),
                    writes: Some(Vec::new()),
                }],
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                }],
            },
        ];
        assert_eq!(
            block_successors_with_exceptions(&blocks, 0, &[(8, vec![(0, 8)])]).exceptional,
            vec![1]
        );
        let known = [Block {
            start: 0,
            stmts: vec![Stmt::Store {
                addr: Expr::Const(0),
                value: Expr::Const(0),
                width: 8,
            }],
        }];
        let edges = block_successors_with_exceptions(&known, 0, &[(8, vec![(0, 8)])]);
        assert!(edges.exceptional.is_empty());
        assert!(!edges.unknown_exceptional);
    }
}
