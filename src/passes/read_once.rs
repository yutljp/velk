use std::collections::HashSet;

use crate::ir::cfg::{live_in, live_out, opaque, successors};

use crate::ir::visit::{children, children_mut, collect_reads, expr_width, statement_registers};
use crate::ir::{
    BinOp, CType, Cond, Expr, FunctionIr, Operation, RegRef, Stmt, TEMP_BASE, VALUE_BASE,
    VARIABLE_BASE,
};
use crate::passes::copies::{
    comparison_preserved, left_by_call, reads_memory, substitute_reg_inner, truncated,
};

/// The most expression nodes a value may have to move into its reader.
const VALUE_NODES: usize = 10;
/// The most nodes an operand of the reader may have once the value is in it.
const OPERAND_NODES: usize = 16;
/// The most nodes both sides of a branch's comparison may have together.
const CONDITION_NODES: usize = 10;
/// The most nodes a call's arguments may have together.
const ARGUMENT_NODES: usize = 28;
/// The deepest an operand of the reader may nest.
const OPERAND_DEPTH: usize = 5;

/// Writes a value a variable holds for one read straight into the
/// statement that reads it, later in the same block or in the blocks that
/// only it leads into: `v5 = *(p + 8); f(v5);` reads `f(*(p + 8))`. The
/// value moves only where it computes the same: nothing between writes a
/// register it reads, and a value that reads memory, or may fault, moves
/// past no other memory access, call or unmodeled instruction. Values too
/// large for their reader stay, as do floats and structure pointers whose
/// values read memory or may fault.
pub fn fold_values_read_once(ir: &mut FunctionIr) {
    let types = crate::render::variable_types(ir);
    let sp = crate::arch::stack_pointer(ir.isa);
    let live_in = live_in(ir);
    let live_out: Vec<_> = (0..ir.blocks.len())
        .map(|index| live_out(ir, &live_in, index))
        .collect();
    let chained = chained(ir);
    let predecessors = crate::render::structure::compare_chain::predecessors(ir);
    let mut uses = std::collections::HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in statement_registers(stmt).1 {
            let count = uses.entry(register).or_default();
            *count = count.saturating_add(count_operands(stmt, register).max(1));
        }
    }
    let split = ir.landing_pads.is_empty() && !ir.blocks.iter().any(opaque);
    let kept = |index: u16, value: &Expr, ir: &FunctionIr| {
        !(VARIABLE_BASE..VALUE_BASE).contains(&index)
            || types.get(&index).is_none_or(|ty| match ty {
                CType::Int { .. } => false,
                CType::Named(name)
                    if unsigned_integer(ty)
                        && integer_value(value, ir, &types, ty)
                        && !faults(value)
                        && !name
                            .split_whitespace()
                            .any(|word| matches!(word, "bool" | "_Bool" | "char" | "volatile")) =>
                {
                    false
                }
                CType::Pointer(_) => {
                    ty.pointee_struct().is_some() && (reads_memory(value) || faults(value))
                }
                _ => true,
            })
    };
    for block in 0..ir.blocks.len() {
        if opaque(&ir.blocks[block]) {
            continue;
        }
        let mut index = ir.blocks[block].stmts.len();
        while index > 0 {
            index -= 1;
            let Stmt::Assign { dest, value } = &ir.blocks[block].stmts[index] else {
                continue;
            };
            if kept(dest.index, value, ir) {
                continue;
            }
            let (dest, value) = (*dest, truncated(value, dest.width));
            let mut path = None;
            if split
                && chained[block].is_none()
                && block.saturating_add(1) < ir.blocks.len()
                && matches!(ir.blocks[block].stmts.last(), Some(Stmt::Brif { target, .. })
                    if ir.blocks.iter().any(|block| block.start == *target))
                && uses.get(&dest.index) == Some(&1)
                && types
                    .get(&dest.index)
                    .is_some_and(|ty| unsigned_integer(ty) && integer_value(&value, ir, &types, ty))
                && !faults(&value)
            {
                let mut sources = HashSet::new();
                collect_reads(&value, &mut sources);
                // Moving a local's read would also change its live range.
                if sources.iter().all(|source| {
                    *source < TEMP_BASE && ir.params.iter().any(|param| param.index == *source)
                }) {
                    let targets: Vec<_> = successors(ir, block)
                        .into_iter()
                        .filter(|next| {
                            *next != 0
                                && *next != block
                                && predecessors.get(&ir.blocks[*next].start) == Some(&1)
                                && live_in[*next].contains(&dest.index)
                        })
                        .collect();
                    if let [next] = targets.as_slice() {
                        let mut extended = chained.clone();
                        extended[block] = Some(*next);
                        path = Some(extended);
                    }
                }
            }
            let Some((at, reader)) = reader(
                ir,
                path.as_deref().unwrap_or(&chained),
                (block, index),
                dest.index,
                &value,
                &live_out,
                sp,
            ) else {
                continue;
            };
            let mut folded = ir.blocks[at].stmts[reader].clone();
            if !substitute(&mut folded, dest, &value) || !readable(&folded, sp) {
                continue;
            }
            ir.blocks[at].stmts[reader] = folded;
            ir.blocks[block].stmts.remove(index);
        }
    }
}

fn unsigned_integer(ty: &CType) -> bool {
    ty.integer()
        .is_some_and(|(bits, signed)| matches!(bits, 32 | 64) && !signed)
        && match ty {
            CType::Int { .. } => true,
            CType::Named(name) => name.split_whitespace().all(|word| {
                matches!(
                    word,
                    "const" | "unsigned" | "int" | "long" | "uint32_t" | "uint64_t"
                )
            }),
            _ => false,
        }
}

fn integer_value(
    expr: &Expr,
    ir: &FunctionIr,
    types: &std::collections::BTreeMap<u16, CType>,
    expected: &CType,
) -> bool {
    match expr {
        Expr::Reg { index, .. } => ir
            .params
            .iter()
            .find(|param| param.index == *index)
            .map(|param| &param.ty)
            .or_else(|| types.get(index))
            .is_some_and(|ty| {
                unsigned_integer(ty)
                    && ty.integer() == expected.integer()
                    && !matches!(ty, CType::Named(name)
                        if name.split_whitespace().any(|word| matches!(word, "char" | "volatile")))
            }),
        Expr::Load { .. } => false,
        _ => children(expr)
            .into_iter()
            .all(|child| integer_value(child, ir, types, expected)),
    }
}

/// For each block, the block control always goes on to when that block is
/// the only way into it.
fn chained(ir: &FunctionIr) -> Vec<Option<usize>> {
    let successors: Vec<Vec<usize>> = (0..ir.blocks.len())
        .map(|index| successors(ir, index))
        .collect();
    let mut entries = vec![0usize; ir.blocks.len()];
    for next in successors.iter().flatten() {
        entries[*next] += 1;
    }
    successors
        .iter()
        .enumerate()
        .map(|(index, next)| match next.as_slice() {
            [next] if *next != index && *next != 0 && entries[*next] == 1 => {
                (!opaque(&ir.blocks[*next])).then_some(*next)
            }
            _ => None,
        })
        .collect()
}

/// Where the one read of `dest`, which the statement at `def` assigns
/// `value`, is, when the value can move there unchanged and nothing else
/// reads it: no later statement before `dest` is assigned again, nor a
/// later block when the last block searched leaves it as it is.
fn reader(
    ir: &FunctionIr,
    chained: &[Option<usize>],
    def: (usize, usize),
    dest: u16,
    value: &Expr,
    live_out: &[HashSet<u16>],
    sp: u16,
) -> Option<(usize, usize)> {
    if expr_width(value).is_none() || size(value, sp) > VALUE_NODES || floats(value) {
        return None;
    }
    let (mut block, index) = def;
    let mut sources = HashSet::new();
    collect_reads(value, &mut sources);
    // A register a call before left a further result in reads better as
    // the variable it was copied to.
    if sources.contains(&dest)
        || sources.iter().any(|source| {
            *source < TEMP_BASE && left_by_call(&ir.blocks[block].stmts[..index], *source)
        })
    {
        return None;
    }
    let ordered = reads_memory(value) || faults(value);
    let mut found = None;
    let mut start = index + 1;
    loop {
        for (position, stmt) in ir.blocks[block].stmts.iter().enumerate().skip(start) {
            let (writes, read) = statement_registers(stmt);
            if read.contains(&dest) {
                if found.is_some() || count_operands(stmt, dest) != 1 {
                    return None;
                }
                found = Some((block, position));
            }
            if writes.contains(&dest) {
                return found;
            }
            if found.is_some() {
                continue;
            }
            if writes.iter().any(|written| sources.contains(written)) {
                return None;
            }
            let quiet = match stmt {
                Stmt::Assign { value, .. } => !reads_memory(value),
                Stmt::Br { .. } => true,
                _ => false,
            };
            if ordered && !quiet {
                return None;
            }
        }
        match chained[block] {
            Some(next) if next != def.0 => {
                block = next;
                start = 0;
            }
            _ => break,
        }
    }
    found.filter(|_| !live_out[block].contains(&dest))
}

/// How many times the expressions of `stmt` that a value may move into read
/// `dest`: not the address an indirect call goes through.
fn count_operands(stmt: &Stmt, dest: u16) -> usize {
    if stmt.declared_call_reads().contains(&dest)
        || stmt
            .preserved_output_sources()
            .iter()
            .any(|(_, source)| *source == dest)
    {
        return 0;
    }
    match stmt {
        Stmt::Call {
            args: Some(args),
            through,
            ..
        } => {
            let through = through.as_ref().map_or(0, |through| count(through, dest));
            if through > 0 {
                return 0;
            }
            args.iter().map(|arg| count(arg, dest)).sum()
        }
        // What else a function returns reads as a note after the return.
        Stmt::Call { .. }
        | Stmt::Ret {
            value:
                Expr::Apply {
                    op: Operation::Results,
                    ..
                },
        } => 0,
        _ => stmt
            .operands()
            .into_iter()
            .map(|operand| count(operand, dest))
            .sum(),
    }
}

fn count(expr: &Expr, register: u16) -> usize {
    match expr {
        Expr::Reg { index, .. } => usize::from(*index == register),
        _ => children(expr)
            .into_iter()
            .map(|child| count(child, register))
            .sum(),
    }
}

/// Replaces the read of `dest` in the statement with the value; false when
/// the read's width does not fit the value's.
pub(super) fn substitute(stmt: &mut Stmt, dest: RegRef, value: &Expr) -> bool {
    if stmt.declared_call_reads().contains(&dest.index)
        || stmt
            .preserved_output_sources()
            .iter()
            .any(|(_, source)| *source == dest.index)
    {
        return false;
    }
    let original_width = match stmt {
        Stmt::Brif { lhs, rhs, .. } => Some(crate::ir::semantics::operand_width(lhs, rhs)),
        _ => None,
    };
    let width = expr_width(value).unwrap_or(64);
    if let Stmt::Brif {
        cond: Cond::Eq | Cond::Ne,
        lhs,
        rhs,
        ..
    } = stmt
    {
        substitute_tested(lhs, rhs, dest, value);
        substitute_tested(rhs, lhs, dest, value);
    }
    let mut ok = true;
    for operand in stmt.operands_mut() {
        substitute_masked(operand, dest, value);
        substitute_reg_inner(operand, dest.index, width, value, &mut ok);
    }
    ok && match (&*stmt, original_width) {
        (Stmt::Brif { cond, lhs, rhs, .. }, Some(width)) => {
            comparison_preserved(*cond, width, lhs, rhs)
        }
        _ => true,
    }
}

/// Replaces `dest & mask` compared for equality with a constant, when the
/// mask and the constant both fit the value, whatever the widths of the
/// read and the value: `(v7 & 0x4) != 0x0`.
fn substitute_tested(tested: &mut Expr, other: &Expr, dest: RegRef, value: &Expr) {
    let bits = crate::ir::semantics::width(value).min(u32::from(dest.width));
    let fits = |constant: u64| bits >= 64 || constant >> bits == 0;
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = tested
        && let (Expr::Reg { index, width }, Expr::Const(mask)) = (lhs.as_ref(), rhs.as_ref())
        && *index == dest.index
        && fits(*mask)
        && (u32::from(*width) >= 64 || mask >> width == 0)
        && matches!(other, Expr::Const(constant) if fits(*constant))
    {
        **lhs = value.clone();
    }
}

/// Replaces a read of `dest` cut to its low 8, 16 or 32 bits, which the
/// value has too, whatever the widths of the read and the value.
fn substitute_masked(expr: &mut Expr, dest: RegRef, value: &Expr) {
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
        && let (Expr::Reg { index, width }, Expr::Const(mask @ (0xff | 0xffff | 0xffff_ffff))) =
            (lhs.as_ref(), rhs.as_ref())
        && *index == dest.index
        && mask.count_ones() <= u32::from((*width).min(dest.width))
    {
        **lhs = value.clone();
        return;
    }
    for child in children_mut(expr) {
        substitute_masked(child, dest, value);
    }
}

/// Whether the statement still reads at a glance.
fn readable(stmt: &Stmt, sp: u16) -> bool {
    let operands = stmt.operands();
    let fits = operands
        .iter()
        .all(|operand| size(operand, sp) <= OPERAND_NODES && depth(operand, sp) <= OPERAND_DEPTH);
    let total: usize = operands.iter().map(|operand| size(operand, sp)).sum();
    fits && match stmt {
        Stmt::Brif { .. } => total <= CONDITION_NODES,
        Stmt::Call { .. } => total <= ARGUMENT_NODES,
        _ => true,
    }
}

/// The nodes of an expression as the output spells it: a stack slot reads
/// as one name.
fn size(expr: &Expr, sp: u16) -> usize {
    if slot(expr, sp) {
        return 1;
    }
    1 + children(expr)
        .into_iter()
        .map(|child| size(child, sp))
        .sum::<usize>()
}

fn depth(expr: &Expr, sp: u16) -> usize {
    match expr {
        Expr::Reg { .. } | Expr::Const(_) => 0,
        _ if slot(expr, sp) => 0,
        _ => {
            1 + children(expr)
                .into_iter()
                .map(|child| depth(child, sp))
                .max()
                .unwrap_or(0)
        }
    }
}

/// Whether evaluating the value may fault, as a division does.
fn faults(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Bin {
            op: BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU,
            ..
        } | Expr::Apply {
            op: Operation::WideDivide { .. },
            ..
        }
    ) || children(expr).into_iter().any(faults)
}

/// Whether the value computes or reads a float.
fn floats(expr: &Expr) -> bool {
    matches!(expr, Expr::Apply { op, .. } if op.result_precision().is_some() || op.argument_precision().is_some())
        || children(expr).into_iter().any(floats)
}

/// Whether the expression loads a stack slot at a fixed place in the frame.
fn slot(expr: &Expr, sp: u16) -> bool {
    let Expr::Load { addr, .. } = expr else {
        return false;
    };
    match addr.as_ref() {
        Expr::Reg { index, .. } => *index == sp,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp)
                && matches!(rhs.as_ref(), Expr::Const(_))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::fold_values_read_once;
    use crate::ir::eval::{self, Outcome, Setup};
    use crate::ir::{
        BinOp, Block, CType, Cond, Convention, Expr, FunctionIr, Param, RegRef, Stmt, VARIABLE_BASE,
    };
    use crate::loader::Isa;

    const V1: u16 = VARIABLE_BASE;
    const V2: u16 = VARIABLE_BASE + 1;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn load(addr: Expr) -> Expr {
        Expr::Load {
            addr: Box::new(addr),
            width: 8,
            signed: false,
        }
    }

    fn call(args: Vec<Expr>) -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::SysV,
            args: Some(args),
            floats_named: false,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(Convention::SysV, None),
            clobbers: None,
            via: None,
        }
    }

    fn field(base: u16, offset: u64) -> Expr {
        load(Expr::bin(
            BinOp::Add,
            Expr::reg(base, 64),
            Expr::Const(offset),
        ))
    }

    fn folded(stmts: Vec<Stmt>) -> Vec<Stmt> {
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        fold_values_read_once(&mut ir);
        ir.blocks.remove(0).stmts
    }

    fn run(ir: &FunctionIr, registers: &[(u16, u64)], memory: &[(u64, u64)]) -> Outcome {
        let outcome = eval::run(
            ir,
            &Setup {
                seed: 0,
                convention: eval::Convention {
                    arguments: &[7, 6],
                    clobbered: &[],
                },
                registers,
                memory,
                step_limit: 64,
            },
        );
        assert!(matches!(&outcome, Outcome::Return { .. }), "{outcome:?}");
        outcome
    }

    #[test]
    fn a_load_read_once_moves_into_the_call_that_reads_it() {
        // v1 = *(rdi + 8); v2 = *(rdi + 16); f(v1, v2);
        let stmts = folded(vec![
            assign(V1, field(7, 8)),
            assign(V2, field(7, 16)),
            call(vec![Expr::reg(V1, 64), Expr::reg(V2, 64)]),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ]);
        assert!(
            matches!(&stmts[0], Stmt::Call { args: Some(args), .. } if *args == [field(7, 8), field(7, 16)]),
            "{stmts:?}"
        );
    }

    #[test]
    fn a_load_stays_before_a_store() {
        // v1 = *(rdi + 8); *(rsi) = 0; return v1;
        let stmts = folded(vec![
            assign(V1, field(7, 8)),
            Stmt::Store {
                addr: Expr::reg(6, 64),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(V1, 64),
            },
        ]);
        assert_eq!(stmts.len(), 3, "{stmts:?}");
    }

    #[test]
    fn a_load_stays_before_a_call() {
        let stmts = folded(vec![
            assign(V1, field(7, 8)),
            call(vec![]),
            Stmt::Ret {
                value: Expr::reg(V1, 64),
            },
        ]);
        assert_eq!(stmts.len(), 3, "{stmts:?}");
    }

    #[test]
    fn a_sum_moves_past_a_call_but_not_past_a_write_to_what_it_reads() {
        let sum = Expr::bin(BinOp::Add, Expr::reg(V2, 64), Expr::Const(1));
        let stmts = folded(vec![
            assign(V1, sum.clone()),
            call(vec![]),
            Stmt::Ret {
                value: Expr::reg(V1, 64),
            },
        ]);
        assert!(
            matches!(stmts.as_slice(), [_, Stmt::Ret { value }] if *value == sum),
            "{stmts:?}"
        );
        let stmts = folded(vec![
            assign(V1, sum),
            assign(V2, Expr::Const(5)),
            Stmt::Ret {
                value: Expr::reg(V1, 64),
            },
        ]);
        assert_eq!(stmts.len(), 3, "{stmts:?}");
    }

    #[test]
    fn a_value_read_twice_stays() {
        let stmts = folded(vec![
            assign(V1, field(7, 8)),
            call(vec![Expr::reg(V1, 64), Expr::reg(V1, 64)]),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ]);
        assert_eq!(stmts.len(), 3, "{stmts:?}");
    }

    #[test]
    fn a_load_folded_into_a_wide_read_keeps_the_assignment_truncation() {
        let address = 0x3000_0000_0000;
        for signed in [false, true] {
            let loaded = Expr::Load {
                addr: Box::new(Expr::reg(7, 64)),
                width: 4,
                signed,
            };
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: V1,
                            width: 32,
                        },
                        value: loaded.clone(),
                    },
                    Stmt::Ret {
                        value: Expr::reg(V1, 64),
                    },
                ],
            );
            ir.params = vec![Param {
                index: 7,
                name: "p".to_owned(),
                ty: CType::pointer_to(CType::int(4, signed)),
            }];
            assert!(matches!(
                crate::render::variable_types(&ir).get(&V1),
                Some(CType::Int { .. })
            ));
            let original = ir.clone();

            fold_values_read_once(&mut ir);

            let expected = if signed {
                Expr::bin(BinOp::And, loaded, Expr::Const(0xffff_ffff))
            } else {
                loaded
            };
            assert!(
                matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Ret { value }] if *value == expected),
                "{}",
                ir.render()
            );
            for word in [0u32, 0x7fff_ffff, 0x8000_0080, 0xffff_ffff] {
                let registers = [(7, address)];
                let memory = [(address, 0x1234_5678_0000_0000 | u64::from(word))];
                let setup = Setup {
                    seed: 0,
                    convention: eval::Convention {
                        arguments: &[7],
                        clobbered: &[],
                    },
                    registers: &registers,
                    memory: &memory,
                    step_limit: 16,
                };
                let before = eval::run(&original, &setup);
                assert!(
                    matches!(&before, Outcome::Return { value, .. } if *value == u64::from(word)),
                    "{before:?}"
                );
                assert_eq!(
                    eval::run(&ir, &setup),
                    before,
                    "signed={signed}, word={word:#x}"
                );
            }
        }
    }

    #[test]
    fn a_folded_wide_assignment_keeps_the_explicit_narrow_read() {
        let address = 0x3000_0000_2000;
        for (value, registers, memory, expected) in [
            (
                Expr::Load {
                    addr: Box::new(Expr::reg(7, 64)),
                    width: 4,
                    signed: true,
                },
                vec![(7, address)],
                vec![(address, 0x8000_0080)],
                0x8000_0080,
            ),
            (
                Expr::bin(BinOp::Add, Expr::reg(7, 32), Expr::reg(6, 32)),
                vec![(7, 0x8000_0000), (6, 0x8000_0000)],
                Vec::new(),
                0,
            ),
        ] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    assign(V1, value.clone()),
                    Stmt::Ret {
                        value: Expr::reg(V1, 32),
                    },
                ],
            );
            let original = ir.clone();
            let before = run(&original, &registers, &memory);
            assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));

            fold_values_read_once(&mut ir);

            let masked = Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff));
            assert!(
                matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Ret { value }] if *value == masked),
                "{}",
                ir.render()
            );
            assert_eq!(run(&ir, &registers, &memory), before);
        }
    }

    #[test]
    fn a_fold_does_not_change_the_sign_width_of_an_arithmetic_shift() {
        let address = 0x3000_0000_2000;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: V1,
                        width: 32,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 1,
                        signed: true,
                    },
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Sar, Expr::reg(V1, 64), Expr::Const(1)),
                },
            ],
        );
        let original = ir.clone();

        fold_values_read_once(&mut ir);

        assert_eq!(ir.render(), original.render());
        for byte in [5u8, 0x85, 0xff] {
            let registers = [(7, address)];
            let memory = [(address, u64::from(byte))];
            let before = run(&original, &registers, &memory);
            let expected = ((i64::from(byte as i8) as u64) & 0xffff_ffff) >> 1;
            assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
            assert_eq!(run(&ir, &registers, &memory), before);
        }
    }

    #[test]
    fn a_fold_does_not_narrow_a_branch_comparison() {
        let address = 0x3000_0000_2000;
        for (cond, rhs, expected) in [
            (Cond::Eq, 0xffff_ffff_ffff_ff85, 0),
            (Cond::Ne, 0xffff_ffff_ffff_ff85, 1),
            (Cond::Lt, 0, 0),
            (Cond::Cs, 0x1_0000_0000, 0),
        ] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: V1,
                            width: 32,
                        },
                        value: Expr::Load {
                            addr: Box::new(Expr::reg(7, 64)),
                            width: 1,
                            signed: true,
                        },
                    },
                    Stmt::Brif {
                        cond,
                        lhs: Expr::reg(V1, 64),
                        rhs: Expr::Const(rhs),
                        target: 0x20,
                    },
                ],
            );
            ir.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(0),
                    }],
                },
                Block {
                    start: 0x20,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(1),
                    }],
                },
            ]);
            let original = ir.clone();
            let registers = [(7, address)];
            let memory = [(address, 0x85)];
            let before = run(&original, &registers, &memory);
            assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));

            fold_values_read_once(&mut ir);

            assert_eq!(ir.render(), original.render());
            assert_eq!(run(&ir, &registers, &memory), before, "{cond:?}");
        }
    }

    #[test]
    fn a_masked_test_keeps_the_original_comparison_width() {
        let address = 0x3000_0000_2000;
        for rhs in [0, 256] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    assign(V1, load(Expr::reg(7, 64))),
                    Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: Expr::bin(BinOp::And, Expr::reg(V1, 8), Expr::Const(4)),
                        rhs: Expr::Const(rhs),
                        target: 0x20,
                    },
                ],
            );
            ir.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(0),
                    }],
                },
                Block {
                    start: 0x20,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(1),
                    }],
                },
            ]);
            let original = ir.clone();

            fold_values_read_once(&mut ir);

            if rhs == 0 {
                assert!(
                    matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Brif { .. }]),
                    "{}",
                    ir.render()
                );
            } else {
                assert_eq!(ir.render(), original.render());
            }
            for word in [0, 4, 256] {
                let registers = [(7, address)];
                let memory = [(address, word)];
                let before = run(&original, &registers, &memory);
                let expected = u64::from(word & 4 == 0);
                assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
                assert_eq!(
                    run(&ir, &registers, &memory),
                    before,
                    "rhs={rhs}, word={word}"
                );
            }
        }
    }

    #[test]
    fn a_tested_byte_moves_into_its_branch_in_the_block_after() {
        // v1 = load8(rdi); then, in the only block that follows,
        // if ((v1 & 4) != 0) ...
        let byte = Expr::Load {
            addr: Box::new(Expr::reg(7, 64)),
            width: 1,
            signed: false,
        };
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![assign(V1, byte.clone())]);
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::bin(BinOp::And, Expr::reg(V1, 64), Expr::Const(4)),
                rhs: Expr::Const(0),
                target: 0x20,
            }],
        });
        for start in [0x18, 0x20] {
            ir.blocks.push(Block {
                start,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(start),
                }],
            });
        }

        fold_values_read_once(&mut ir);

        assert!(ir.blocks[0].stmts.is_empty(), "{}", ir.render());
        assert!(
            matches!(&ir.blocks[1].stmts[0], Stmt::Brif { lhs, .. }
                if *lhs == Expr::bin(BinOp::And, byte, Expr::Const(4))),
            "{}",
            ir.render()
        );
    }
    #[test]
    fn declared_reads_cannot_receive_an_inlined_load() {
        let mut attached = call(vec![Expr::reg(7, 64)]);
        if let Stmt::Call { abi, .. } = &mut attached {
            *abi = Some(crate::ir::calls::test_call_abi(vec![7], false));
        }
        let original = attached.clone();
        let register = RegRef {
            index: 7,
            width: 64,
        };
        assert_eq!(super::count_operands(&attached, 7), 0);
        assert!(!super::substitute(&mut attached, register, &field(6, 8)));
        assert_eq!(format!("{attached:?}"), format!("{original:?}"));

        let mut unattached = call(vec![Expr::reg(7, 64)]);
        assert_eq!(super::count_operands(&unattached, 7), 1);
        assert!(super::substitute(&mut unattached, register, &field(6, 8)));
        assert!(matches!(unattached, Stmt::Call { args: Some(args), .. } if args == [field(6, 8)]));
    }
}
