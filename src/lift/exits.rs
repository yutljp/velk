//! What a branch out of the function is. It is a tail call only when the
//! stack is back at the height it had on entry and the target is a
//! function's start. Otherwise the code it reaches runs in this function's
//! frame, and is lifted as part of the function: another function's body
//! entered past its start, or a function start the code jumps to with its
//! own frame still set up.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::{BinOp, Block, Expr, Stmt};
use crate::lift::{Summaries, tail_call};
use crate::loader::Image;

/// Code outside the function's extent that its branches continue in, by
/// start and size.
pub(super) type ContinuedCode = BTreeMap<u64, u64>;

/// How a branch out of the function leaves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leaving {
    TailCall,
    /// The function goes on in the code at this start and size.
    Continues(u64, u64),
}

/// Lifts each branch out of the function as a tail call: a jump ends its
/// block with it, and a conditional branch goes to a block of its own
/// holding it, so the arguments it passes stay visible to the passes.
/// Returns the code the branches that are no tail call continue in; until
/// that code is lifted with the function, they stay tail calls. When the
/// extent is only estimated, a branch past it may mean the estimate is
/// short, so only a branch to another known function counts. `ends` gives
/// the address of the branch ending each block.
pub(super) fn resolve_exits(
    image: &Image,
    summaries: Summaries<'_>,
    function: u64,
    blocks: &mut Vec<Block>,
    ends: &HashMap<u64, u64>,
) -> ContinuedCode {
    let own = image.functions.get(&function);
    let exact = own.is_some_and(|function| function.size.is_some() && !function.size_estimated);
    let extent = own.and_then(|function| function.size).unwrap_or(0);
    let starts: HashSet<u64> = blocks.iter().map(|block| block.start).collect();
    let heights = stack_heights(blocks, image.isa);
    let mut exits: Vec<u64> = Vec::new();
    let mut continued_code = ContinuedCode::new();
    // The blocks ending in a jump out, which their tail call then ends.
    let mut jumps: Vec<usize> = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let (target, jump) = match block.stmts.last() {
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => (*target, false),
            Some(Stmt::Br {
                target: Some(target),
                ..
            }) => (*target, true),
            _ => continue,
        };
        if starts.contains(&target) || !(exact || image.functions.contains_key(&target)) {
            continue;
        }
        // Code running off the end of a part of the function into the next
        // is no branch the code makes, and is taken for a tail call.
        if let Some(pc) = ends.get(&block.start) {
            // The unwind table speaks for this function's own code and the
            // fragments split off it, not for code it continues in elsewhere.
            let at_entry = Some(*pc)
                .filter(|pc| {
                    (function..function.saturating_add(extent)).contains(pc)
                        || image.fragment_at(*pc).is_some()
                })
                .and_then(|pc| image.stack_at_entry(pc))
                .or(heights[index].map(|height| height == 0));
            if let Leaving::Continues(start, size) = leaving(image, function, target, at_entry) {
                continued_code.insert(start, size);
            }
        }
        if jump {
            jumps.push(index);
        } else {
            exits.push(target);
        }
    }
    for index in jumps {
        let stmts = &mut blocks[index].stmts;
        let Some(Stmt::Br { target, at }) = stmts.pop() else {
            unreachable!("a jump ends the block")
        };
        let [call, result] = tail_call(image, summaries, target);
        stmts.push(call.with_origin(at));
        stmts.push(result);
    }
    if exits.is_empty() {
        return continued_code;
    }
    exits.sort_unstable();
    exits.dedup();
    // The last block must not fall through into the exits; past its end
    // is code that a call which does not return never reaches.
    if let Some(last) = blocks.last_mut()
        && !matches!(
            last.stmts.last(),
            Some(
                Stmt::Ret { .. }
                    | Stmt::Br { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. }
                    | Stmt::Trap { .. }
            )
        )
    {
        last.stmts.push(Stmt::Trap { at: None });
    }
    for target in exits {
        blocks.push(Block {
            start: target,
            stmts: tail_call(image, summaries, Some(target)).into(),
        });
    }
    continued_code
}

/// A branch to `target`, with the stack as on entry, or not, or unknown, is
/// a tail call when it reaches a function's start with the stack as on
/// entry, or unknown. Into another function's body, or to a start with a
/// frame still set up, it goes on in that code, as far as the function
/// there extends.
fn leaving(image: &Image, function: u64, target: u64, at_entry: Option<bool>) -> Leaving {
    if let Some(callee) = image.functions.get(&target) {
        return match (at_entry, callee.size) {
            (Some(false), Some(size)) => Leaving::Continues(target, size),
            _ => Leaving::TailCall,
        };
    }
    image
        .functions
        .range(..target)
        .next_back()
        .filter(|(start, _)| **start != function)
        .and_then(|(start, function)| Some(start + function.size?))
        .filter(|end| target < *end)
        .map_or(Leaving::TailCall, |end| {
            Leaving::Continues(target, end - target)
        })
}

/// How far the stack pointer stands from where it was on entry at the end
/// of each block, where every path there agrees. Registers that hold an
/// offset from the entry stack pointer, as a frame pointer does, carry it
/// back when the stack pointer is restored from them.
pub(crate) fn stack_heights(blocks: &[Block], isa: crate::loader::Isa) -> Vec<Option<i64>> {
    let sp = crate::arch::stack_pointer(isa);
    let count = blocks.len();
    let successors: Vec<Vec<usize>> = (0..count)
        .map(|index| crate::ir::cfg::block_successors(blocks, index))
        .collect();
    let mut entry: Vec<Option<HashMap<u16, i64>>> = vec![None; count];
    let mut exit: Vec<Option<HashMap<u16, i64>>> = vec![None; count];
    if count == 0 {
        return Vec::new();
    }
    let start = HashMap::from([(sp, 0)]);
    // Each round only removes registers or reaches a block, so it settles.
    loop {
        let mut next: Vec<Option<HashMap<u16, i64>>> = vec![None; count];
        next[0] = Some(start.clone());
        for (index, out) in exit.iter().enumerate() {
            let Some(out) = out else {
                continue;
            };
            for successor in &successors[index] {
                next[*successor] = Some(match next[*successor].take() {
                    None => out.clone(),
                    Some(mut known) => {
                        known.retain(|register, offset| out.get(register) == Some(offset));
                        known
                    }
                });
            }
        }
        if next == entry {
            break;
        }
        entry = next;
        for (index, block) in blocks.iter().enumerate() {
            exit[index] = entry[index].clone().map(|mut state| {
                for stmt in &block.stmts {
                    step(stmt, &mut state);
                }
                state
            });
        }
    }
    exit.into_iter()
        .map(|state| state.and_then(|state| state.get(&sp).copied()))
        .collect()
}

/// The offsets from the entry stack pointer the registers hold after `stmt`.
fn step(stmt: &Stmt, state: &mut HashMap<u16, i64>) {
    if let Stmt::Assign { dest, value, .. } = stmt
        && dest.width == 64
    {
        match offset_of(value, state) {
            Some(offset) => state.insert(dest.index, offset),
            None => state.remove(&dest.index),
        };
        return;
    }
    for register in crate::ir::visit::statement_writes(stmt) {
        state.remove(&register);
    }
}

/// The offset from the entry stack pointer `value` computes, when it is
/// `r`, `r + k` or `r - k` for a register holding one.
fn offset_of(value: &Expr, state: &HashMap<u16, i64>) -> Option<i64> {
    match value {
        Expr::Reg { index, width: 64 } => state.get(index).copied(),
        Expr::Bin { op, lhs, rhs } => {
            let Expr::Const(by) = rhs.as_ref() else {
                return None;
            };
            let base = offset_of(lhs, state)?;
            match op {
                BinOp::Add => Some(base.wrapping_add(*by as i64)),
                BinOp::Sub => Some(base.wrapping_sub(*by as i64)),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::ir::eval;
    use crate::ir::{Block, FunctionIr, Stmt};
    use crate::lift::lift;
    use crate::loader::{Function, Image, Isa};

    /// The code, holding the functions at the given starts and sizes.
    fn image(isa: Isa, code: Vec<u8>, functions: &[(u64, u64)]) -> Image {
        let mut image = Image::from_code(isa, 0, code);
        for (addr, size) in functions {
            image.functions.insert(
                *addr,
                Function {
                    addr: *addr,
                    size: Some(*size),
                    size_estimated: false,
                    name: None,
                    aliases: Vec::new(),
                    library: None,
                    sources: Vec::new(),
                },
            );
        }
        image
    }

    fn lifted(image: &Image) -> Vec<Block> {
        let size = image.functions[&0].size.expect("sized");
        lift(image, 0, size, &HashSet::new()).expect("lifts")
    }

    fn calls(blocks: &[Block]) -> Vec<Option<u64>> {
        blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .filter_map(|stmt| match stmt {
                Stmt::Call { target, .. } => Some(*target),
                _ => None,
            })
            .collect()
    }

    /// What the lifted code returns with the given registers.
    fn returns(isa: Isa, blocks: Vec<Block>, registers: &[(u16, u64)]) -> u64 {
        let mut ir = FunctionIr::single_block(isa, Vec::new());
        ir.blocks = blocks;
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers,
            memory: &[],
            step_limit: 100,
        };
        match eval::run(&ir, &setup) {
            eval::Outcome::Return { value, .. } => value,
            other => panic!("{other:?}\n{}", ir.render()),
        }
    }

    /// The code, followed at 0x10 by `mov eax, 7; ret`.
    fn returning_seven(mut code: Vec<u8>) -> Vec<u8> {
        code.resize(0x10, 0xcc);
        code.extend([0xb8, 7, 0, 0, 0, 0xc3]);
        code
    }

    #[test]
    fn a_jump_to_a_function_with_the_stack_as_on_entry_is_a_tail_call() {
        // jmp 0x10
        let image = image(
            Isa::X86_64,
            returning_seven(vec![0xeb, 0x0e]),
            &[(0, 2), (0x10, 6)],
        );
        let blocks = lifted(&image);
        assert_eq!(calls(&blocks), [Some(0x10)]);
        assert_eq!(blocks.len(), 1, "{blocks:?}");
    }

    #[test]
    fn a_jump_after_the_frame_pointer_restores_the_stack_is_a_tail_call() {
        // push rbp; mov rbp, rsp; sub rsp, 16; mov rsp, rbp; pop rbp; jmp 0x10
        let code = vec![
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xec, 0x5d, 0xeb, 0x02,
        ];
        let image = image(Isa::X86_64, returning_seven(code), &[(0, 14), (0x10, 6)]);
        assert_eq!(calls(&lifted(&image)), [Some(0x10)]);
    }

    #[test]
    fn a_jump_to_a_function_with_a_value_still_pushed_continues_in_it() {
        // push rbx; jmp 0x10; 0x10: pop rbx; mov eax, 7; ret
        let mut code = vec![0x53, 0xeb, 0x0d];
        code.resize(0x10, 0xcc);
        code.extend([0x5b, 0xb8, 7, 0, 0, 0, 0xc3]);
        let image = image(Isa::X86_64, code, &[(0, 3), (0x10, 7)]);
        let blocks = lifted(&image);
        assert_eq!(calls(&blocks), []);
        assert_eq!(returns(Isa::X86_64, blocks, &[]), 7);
    }

    #[test]
    fn a_conditional_branch_with_a_value_still_pushed_continues_in_its_target() {
        // push rbx; test edi, edi; jne 0x10; pop rbx; xor eax, eax; ret;
        // 0x10: pop rbx; mov eax, 7; ret
        let mut code = vec![0x53, 0x85, 0xff, 0x75, 0x0b, 0x5b, 0x31, 0xc0, 0xc3];
        code.resize(0x10, 0xcc);
        code.extend([0x5b, 0xb8, 7, 0, 0, 0, 0xc3]);
        let image = image(Isa::X86_64, code, &[(0, 9), (0x10, 7)]);
        let blocks = lifted(&image);
        assert_eq!(calls(&blocks), []);
        assert_eq!(returns(Isa::X86_64, blocks.clone(), &[(7, 1)]), 7);
        assert_eq!(returns(Isa::X86_64, blocks, &[(7, 0)]), 0);
    }

    #[test]
    fn a_jump_into_another_function_s_body_continues_there() {
        // jmp 0x12; 0x10: xor eax, eax; mov eax, 7; ret
        let mut code = vec![0xeb, 0x10];
        code.resize(0x10, 0xcc);
        code.extend([0x31, 0xc0, 0xb8, 7, 0, 0, 0, 0xc3]);
        let image = image(Isa::X86_64, code, &[(0, 2), (0x10, 8)]);
        let blocks = lifted(&image);
        assert_eq!(calls(&blocks), []);
        assert_eq!(returns(Isa::X86_64, blocks, &[]), 7);
    }

    #[test]
    fn a_branch_to_padding_goes_on_to_the_code_after_it() {
        // test edi, edi; jne 7; jmp 6; 6: nop; 7: mov eax, 2; ret
        let code = vec![
            0x85, 0xff, 0x75, 0x03, 0xeb, 0x00, 0x90, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let image = image(Isa::X86_64, code, &[(0, 13)]);
        let blocks = lifted(&image);
        assert_eq!(calls(&blocks), []);
        assert_eq!(returns(Isa::X86_64, blocks, &[(7, 0)]), 2);
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn an_aarch64_branch_is_a_tail_call_only_once_the_frame_is_gone() {
        const NOP: u32 = 0xd503_201f;
        // stp x29, x30, [sp, #-16]!; b 0x10;
        // 0x10: ldp x29, x30, [sp], #16; mov w0, #7; ret
        let framed = words(&[
            0xa9bf_7bfd,
            0x1400_0003,
            NOP,
            NOP,
            0xa8c1_7bfd,
            0x5280_00e0,
            0xd65f_03c0,
        ]);
        let framed_image = image(Isa::AArch64, framed, &[(0, 8), (0x10, 12)]);
        let blocks = lifted(&framed_image);
        assert_eq!(calls(&blocks), []);
        assert_eq!(returns(Isa::AArch64, blocks, &[]), 7);
        // b 0x10; 0x10: mov w0, #7; ret
        let bare = words(&[0x1400_0004, NOP, NOP, NOP, 0x5280_00e0, 0xd65f_03c0]);
        let bare_image = image(Isa::AArch64, bare, &[(0, 4), (0x10, 8)]);
        assert_eq!(calls(&lifted(&bare_image)), [Some(0x10)]);
    }
}
