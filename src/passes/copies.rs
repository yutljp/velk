use crate::ir::cfg::{live_in, live_out, opaque};
use crate::ir::visit::assign_of;
use crate::ir::visit::children;
use crate::ir::visit::expr_reads;
use crate::ir::visit::expr_width;
use crate::ir::visit::statement_reads;
use crate::ir::visit::statement_registers;
use crate::ir::{Cond, Expr, FunctionIr, Stmt, VARIABLE_BASE};
use crate::passes::frame::reads_outside_frame;

mod debug;
pub(crate) use debug::fold_debug_locals;

/// Folds a definition read exactly once before its register is written again
/// into that reader, so `x8 = w8; if (x8 & 0x80000000) ...` keeps no temporary.
/// A definition a later block, or the next pass of a loop, may read stays.
pub fn inline_local_copies(ir: &mut FunctionIr) {
    let live_in = live_in(ir);
    let live_out: Vec<_> = (0..ir.blocks.len())
        .map(|index| live_out(ir, &live_in, index))
        .collect();
    let params = parameters(ir);
    let sp = crate::arch::stack_pointer(ir.isa);
    let private_frame = super::memory::fixed_private_frame(ir, sp);
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let mut index = 0;
        while index < block.stmts.len() {
            let Some((dest, value)) = (match &block.stmts[index] {
                Stmt::Assign { dest, value } => Some((dest.index, truncated(value, dest.width))),
                _ => None,
            }) else {
                index += 1;
                continue;
            };
            // The value's width must be known to check it against the read.
            if expr_width(&value).is_none() {
                index += 1;
                continue;
            }
            // The registers the value reads must not change before the use,
            // nor the memory it loads.
            let mut sources = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(&value, &mut sources);
            let loads = reads_memory(&value);
            let mut reads = 0usize;
            let mut use_at = None;
            let mut clobbered = false;
            let mut redefined = false;
            for position in index + 1..block.stmts.len() {
                let stmt = &block.stmts[position];
                if use_at.is_none()
                    && super::memory::atomic(stmt)
                    && !super::memory::crosses_atomic(&value, sp, private_frame)
                {
                    clobbered = true;
                    break;
                }
                if use_at.is_none()
                    && loads
                    && matches!(
                        stmt,
                        Stmt::Store { .. }
                            | Stmt::Call { .. }
                            | Stmt::Unsupported { .. }
                            | Stmt::Machine { .. }
                    )
                    && !super::memory::atomic(stmt)
                    && !statement_reads(stmt).contains(&dest)
                {
                    clobbered = true;
                    break;
                }
                let used = statement_reads(stmt);
                if used.contains(&dest) {
                    // Folding into two reads would duplicate the value.
                    reads += count_reg(stmt, dest);
                    use_at = Some(position);
                }
                let written = statement_registers(stmt).0;
                if written.contains(&dest) {
                    redefined = true;
                    break;
                }
                if written.intersection(&sources).next().is_some() {
                    clobbered = true;
                    break;
                }
            }
            // A later block may read the definition this block leaves behind.
            if !redefined && live_out[position].contains(&dest) {
                index += 1;
                continue;
            }
            let Some(use_at) = use_at else {
                index += 1;
                continue;
            };
            if reads != 1
                || clobbered
                || !further_result_moves(&block.stmts, index, use_at, &params)
            {
                index += 1;
                continue;
            }
            // Skip a reader that overwrites a register the value reads.
            if let Stmt::Assign { dest: reader, .. } = &block.stmts[use_at] {
                let mut reader_sources = std::collections::HashSet::new();
                crate::ir::visit::collect_reads(&value, &mut reader_sources);
                if reader_sources.contains(&reader.index) {
                    index += 1;
                    continue;
                }
            }
            let mut ok = true;
            let mut folded = block.stmts[use_at].clone();
            substitute_in_statement(&mut folded, dest, &value, &mut ok);
            if !ok {
                index += 1;
                continue;
            }
            block.stmts[use_at] = folded;
            block.stmts.remove(index);
        }
    }
}

/// The value a register of `width` bits holds once it is assigned `value`:
/// a narrow destination drops the high bits a sum or product may carry.
pub(crate) fn truncated(value: &Expr, width: u8) -> Expr {
    let mask = crate::ir::semantics::mask(u32::from(width));
    if width >= 64 || crate::ssa::ranges::of(value).hi <= mask {
        return value.clone();
    }
    Expr::bin(crate::ir::BinOp::And, value.clone(), Expr::Const(mask))
}

pub(crate) fn reads_memory(expr: &Expr) -> bool {
    matches!(expr, Expr::Load { .. }) || children(expr).into_iter().any(reads_memory)
}

pub(crate) fn comparison_preserved(cond: Cond, before: u32, lhs: &Expr, rhs: &Expr) -> bool {
    let after = crate::ir::semantics::operand_width(lhs, rhs);
    let mask = crate::ir::semantics::mask(before.min(after));
    before == after
        || (matches!(cond, Cond::Eq | Cond::Ne)
            && crate::ssa::ranges::of(lhs).hi <= mask
            && crate::ssa::ranges::of(rhs).hi <= mask)
}

/// Replaces every read of `dest` in one statement with the value; clears `ok`
/// when a read's width does not fit the value's.
fn substitute_in_statement(stmt: &mut Stmt, dest: u16, value: &Expr, ok: &mut bool) {
    if stmt.declared_call_reads().contains(&dest)
        || stmt
            .preserved_output_sources()
            .iter()
            .any(|(_, source)| *source == dest)
    {
        *ok = false;
        return;
    }
    let width = expr_width(value).unwrap_or(64);
    match stmt {
        Stmt::Machine { inputs, .. } => {
            for input in inputs {
                substitute_reg_inner(input, dest, width, value, ok);
            }
        }
        Stmt::Assign { value: target, .. } => substitute_reg_inner(target, dest, width, value, ok),
        Stmt::Store {
            addr,
            value: stored,
            ..
        } => {
            substitute_reg_inner(addr, dest, width, value, ok);
            substitute_reg_inner(stored, dest, width, value, ok);
        }
        Stmt::Brif { cond, lhs, rhs, .. } => {
            let comparison = crate::ir::semantics::operand_width(lhs, rhs);
            substitute_reg_inner(lhs, dest, width, value, ok);
            substitute_reg_inner(rhs, dest, width, value, ok);
            *ok &= comparison_preserved(*cond, comparison, lhs, rhs);
        }
        Stmt::Ret { value: returned } => substitute_reg_inner(returned, dest, width, value, ok),
        Stmt::Switch { index, .. } => substitute_reg_inner(index, dest, width, value, ok),
        Stmt::BrIndirect { target } => substitute_reg_inner(target, dest, width, value, ok),
        _ => *ok = false,
    }
}

/// Copy propagation: folds a single-use assignment (a register copy, a sign
/// extension or a small expression) into its only consumer when the widths
/// match, so no value is extended or truncated by accident.
pub fn copy_propagate(ir: &mut FunctionIr) {
    copy_propagate_with(ir, false);
}

/// Copy propagation for use after CSE: does not duplicate a compound value
/// into several reads of one consumer.
pub fn copy_propagate_guarded(ir: &mut FunctionIr) {
    copy_propagate_with(ir, true);
}

/// The registers each block reads.
fn block_reads(ir: &FunctionIr) -> Vec<std::collections::HashSet<u16>> {
    ir.blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .flat_map(|stmt| statement_registers(stmt).1)
                .collect()
        })
        .collect()
}

/// The registers some block other than `index` reads.
fn reads_elsewhere(
    reads: &[std::collections::HashSet<u16>],
    index: usize,
) -> std::collections::HashSet<u16> {
    reads
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != index)
        .flat_map(|(_, set)| set.iter().copied())
        .collect()
}

fn copy_propagate_with(ir: &mut FunctionIr, avoid_duplication: bool) {
    let reads = block_reads(ir);
    // A register live on leaving the block, such as one a tail call through
    // an indirect jump reads or the block itself reads again on the next
    // pass of a loop, is kept too.
    let live_in = live_in(ir);
    let live_out: Vec<_> = (0..ir.blocks.len())
        .map(|index| live_out(ir, &live_in, index))
        .collect();
    let params = parameters(ir);
    let sp = crate::arch::stack_pointer(ir.isa);
    let private_frame = super::memory::fixed_private_frame(ir, sp);
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        if opaque(block) {
            continue;
        }
        let mut outer = reads_elsewhere(&reads, index);
        outer.extend(live_out[index].iter().copied());
        copy_propagate_block(block, &outer, &params, avoid_duplication, sp, private_frame);
    }
}

/// Whether the last of `stmts` to write `register` is a call.
pub(crate) fn left_by_call(stmts: &[Stmt], register: u16) -> bool {
    stmts
        .iter()
        .rev()
        .find(|stmt| statement_registers(stmt).0.contains(&register))
        .is_some_and(|stmt| matches!(stmt, Stmt::Call { .. }))
}

/// Whether the copy at `index` may fold into `consumer`. One into a variable
/// of what a call before it left in a parameter's register, such as a
/// further result, only moves on into another variable: elsewhere the
/// register would read as the parameter it is named for.
fn further_result_moves(
    stmts: &[Stmt],
    index: usize,
    consumer: usize,
    params: &std::collections::HashSet<u16>,
) -> bool {
    let Stmt::Assign {
        dest,
        value: Expr::Reg { index: src, .. },
    } = &stmts[index]
    else {
        return true;
    };
    let further =
        dest.index >= VARIABLE_BASE && params.contains(src) && left_by_call(&stmts[..index], *src);
    !further
        || matches!(
            &stmts[consumer],
            Stmt::Assign {
                dest: next,
                value: Expr::Reg { index: read, width: 64 },
            } if next.index >= VARIABLE_BASE && next.width == 64 && *read == dest.index
        )
}

fn parameters(ir: &FunctionIr) -> std::collections::HashSet<u16> {
    ir.params.iter().map(|param| param.index).collect()
}

fn copy_propagate_block(
    block: &mut crate::ir::Block,
    outer_reads: &std::collections::HashSet<u16>,
    params: &std::collections::HashSet<u16>,
    avoid_duplication: bool,
    sp: u16,
    private_frame: bool,
) {
    let mut index = 0;
    while index < block.stmts.len() {
        let copy = match &block.stmts[index] {
            Stmt::Assign { dest, value } => {
                // A value of unknown width, such as a sign extension, takes
                // the destination's width.
                let fold_width = expr_width(value).unwrap_or(dest.width);
                let foldable = match value {
                    Expr::Reg { index: src, .. } => *src != dest.index,
                    Expr::SignExtend { .. } => true,
                    // A read outside the frame may be volatile, and a large
                    // expression hurts readability once inlined.
                    _ => !reads_outside_frame(value) && expr_size(value) <= 8,
                };
                foldable.then(|| (dest.index, fold_width, truncated(value, dest.width)))
            }
            _ => None,
        };
        let Some((dest, width, template)) = copy else {
            index += 1;
            continue;
        };
        // A read in another block keeps the temporary alive, unless this block
        // redefines it later so other blocks see that value instead.
        let redefined = block
            .stmts
            .iter()
            .skip(index + 1)
            .any(|stmt| statement_registers(stmt).0.contains(&dest));
        if outer_reads.contains(&dest) && !redefined {
            index += 1;
            continue;
        }
        // A value that reads its own destination cannot move.
        let mut sources: std::collections::HashSet<u16> = std::collections::HashSet::new();
        expr_reads(&template, &mut sources);
        if sources.contains(&dest) {
            index += 1;
            continue;
        }
        // Exactly one consumer, and no redefinition of the sources before it.
        let mut consumer = None;
        let mut foldable = true;
        let loads = reads_memory(&template);
        for later in index + 1..block.stmts.len() {
            if super::memory::atomic(&block.stmts[later])
                && !super::memory::crosses_atomic(&template, sp, private_frame)
            {
                foldable = false;
                break;
            }
            let (writes, reads) = statement_registers(&block.stmts[later]);
            let reads_dest = reads.contains(&dest);
            if consumer.is_none()
                && loads
                && !reads_dest
                && match &block.stmts[later] {
                    Stmt::Store { addr, width, .. } => {
                        !super::memory::loads_avoid(&template, addr, *width)
                    }
                    Stmt::Call { .. } | Stmt::Unsupported { .. } | Stmt::Machine { .. } => true,
                    _ => false,
                }
                && !super::memory::atomic(&block.stmts[later])
            {
                foldable = false;
                break;
            }
            // The consumer may rewrite a source: it reads before it writes.
            if writes.iter().any(|written| sources.contains(written)) && !reads_dest {
                foldable = false;
                break;
            }
            if reads_dest {
                if consumer.is_some() {
                    foldable = false;
                    break;
                }
                consumer = Some(later);
            }
            if writes.contains(&dest) {
                break;
            }
        }
        let Some(consumer) = consumer else {
            index += 1;
            continue;
        };
        if !foldable || !further_result_moves(&block.stmts, index, consumer, params) {
            index += 1;
            continue;
        }
        // Removing the copy is safe when the consumer redefines the register
        // or nothing else reads it before its next definition.
        let rewrites_dest = match assign_of(&block.stmts[consumer]) {
            Some((dest_ref, _)) => dest_ref.index == dest,
            None => false,
        };
        let mut other_reads = block.stmts.iter().enumerate().any(|(position, stmt)| {
            position != consumer && position != index && statement_registers(stmt).1.contains(&dest)
        });
        if other_reads && !rewrites_dest {
            let mut escapes = false;
            for later in consumer + 1..block.stmts.len() {
                let (writes, reads) = statement_registers(&block.stmts[later]);
                if writes.contains(&dest) {
                    break;
                }
                if reads.contains(&dest) {
                    escapes = true;
                    break;
                }
            }
            other_reads = escapes;
        }
        if !rewrites_dest && other_reads {
            index += 1;
            continue;
        }
        // Inlining a compound value into two reads would undo CSE, and a
        // choice repeated reads as two.
        let reads_in_consumer = count_reg(&block.stmts[consumer], dest);
        if reads_in_consumer > 1
            && ((avoid_duplication && expr_size(&template) > 1) || contains_select(&template))
        {
            index += 1;
            continue;
        }
        if !substitute_stmt(&mut block.stmts[consumer], dest, width, &template) {
            index += 1;
            continue;
        }
        block.stmts.remove(index);
        // `index` now names the statement after the removed copy.
    }
}

fn contains_select(expr: &Expr) -> bool {
    matches!(expr, Expr::Select { .. })
        || crate::ir::visit::children(expr)
            .into_iter()
            .any(contains_select)
}

/// How many times a statement reads one register.
fn count_reg(stmt: &Stmt, reg: u16) -> usize {
    fn count(expr: &Expr, reg: u16) -> usize {
        match expr {
            Expr::Reg { index, .. } if *index == reg => 1,
            _ => children(expr)
                .into_iter()
                .map(|child| count(child, reg))
                .sum(),
        }
    }
    let mut total = stmt
        .preserved_output_sources()
        .iter()
        .filter(|(_, source)| *source == reg)
        .count();
    total += usize::from(stmt.declared_call_reads().contains(&reg));
    match stmt {
        Stmt::Machine { inputs, .. } => {
            total += inputs.iter().map(|input| count(input, reg)).sum::<usize>()
        }
        Stmt::Assign { value, .. } => total += count(value, reg),
        Stmt::Store { addr, value, .. } => {
            total += count(addr, reg) + count(value, reg);
        }
        Stmt::Brif { lhs, rhs, .. } => total += count(lhs, reg) + count(rhs, reg),
        Stmt::Ret { value } => total += count(value, reg),
        Stmt::BrIndirect { target } => total += count(target, reg),
        Stmt::Call {
            convention,
            through,
            args,
            floats_named,
            ..
        } => {
            total += through.iter().map(|expr| count(expr, reg)).sum::<usize>();
            total += match args {
                Some(args) => args.iter().map(|arg| count(arg, reg)).sum::<usize>(),
                None => usize::from(
                    convention
                        .call_reads_through(through.as_ref(), *floats_named)
                        .contains(&reg),
                ),
            };
        }
        _ => {}
    }
    total
}

/// Number of expression nodes, used to keep inlining from exploding.
pub(crate) fn expr_size(expr: &Expr) -> usize {
    1 + children(expr).into_iter().map(expr_size).sum::<usize>()
}

fn substitute_stmt(stmt: &mut Stmt, dest: u16, width: u8, template: &Expr) -> bool {
    if stmt.declared_call_reads().contains(&dest)
        || stmt
            .preserved_output_sources()
            .iter()
            .any(|(_, source)| *source == dest)
    {
        return false;
    }
    let mut folded = stmt.clone();
    let mut ok = true;
    match &mut folded {
        Stmt::Machine { inputs, .. } => {
            for input in inputs {
                substitute_reg_inner(input, dest, width, template, &mut ok);
            }
        }
        Stmt::Assign { value, .. } => substitute_reg_inner(value, dest, width, template, &mut ok),
        Stmt::Store { addr, value, .. } => {
            substitute_reg_inner(addr, dest, width, template, &mut ok);
            substitute_reg_inner(value, dest, width, template, &mut ok);
        }
        Stmt::Brif { cond, lhs, rhs, .. } => {
            let comparison = crate::ir::semantics::operand_width(lhs, rhs);
            substitute_reg_inner(lhs, dest, width, template, &mut ok);
            substitute_reg_inner(rhs, dest, width, template, &mut ok);
            ok &= comparison_preserved(*cond, comparison, lhs, rhs);
        }
        Stmt::Ret { value } => substitute_reg_inner(value, dest, width, template, &mut ok),
        Stmt::BrIndirect { target } => substitute_reg_inner(target, dest, width, template, &mut ok),
        // A call naming its arguments reads nothing else of them.
        Stmt::Call {
            through,
            args: Some(args),
            convention,
            floats_named,
            ..
        } if !convention.unnamed_reads(*floats_named).contains(&dest) => {
            for expr in through.iter_mut().chain(args.iter_mut()) {
                substitute_reg_inner(expr, dest, width, template, &mut ok);
            }
        }
        _ => ok = false,
    }
    if ok {
        *stmt = folded;
    }
    ok
}

pub(crate) fn substitute_reg_inner(
    expr: &mut Expr,
    dest: u16,
    width: u8,
    template: &Expr,
    ok: &mut bool,
) {
    if !*ok {
        return;
    }
    if let Expr::Reg { index, width: read } = expr {
        if *index == dest {
            let narrow_expression = matches!(expr_width(template), Some(32));
            if *read != width && !(narrow_expression && *read > 32 && width <= 32) {
                *ok = false;
                return;
            }
            *expr = truncated(template, *read);
        }
        return;
    }
    // A low-bit mask permits different expression widths, but the register
    // read still truncates before that mask.
    if let Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        let mask = match rhs.as_ref() {
            Expr::Const(mask) => Some(*mask),
            _ => None,
        };
        if let Some(mask) = mask
            && mask <= 0xffff_ffff
            && let Expr::Reg { index, width: read } = lhs.as_ref()
            && *index == dest
            && matches!(expr_width(template), Some(32))
        {
            let kept_mask = mask;
            *expr = Expr::bin(
                crate::ir::BinOp::And,
                truncated(template, *read),
                Expr::constant(kept_mask),
            );
            return;
        }
    }
    match expr {
        Expr::Bin { op, lhs, rhs } => {
            // The operands' width decides the sign of these operations.
            let sensitive = matches!(
                op,
                crate::ir::BinOp::Sar | crate::ir::BinOp::DivS | crate::ir::BinOp::ModS
            );
            let before = crate::ir::semantics::operand_width(lhs, rhs);
            substitute_reg_inner(lhs, dest, width, template, ok);
            substitute_reg_inner(rhs, dest, width, template, ok);
            if sensitive && before != crate::ir::semantics::operand_width(lhs, rhs) {
                *ok = false;
            }
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let comparison = crate::ir::semantics::operand_width(lhs, rhs);
            substitute_reg_inner(lhs, dest, width, template, ok);
            substitute_reg_inner(rhs, dest, width, template, ok);
            substitute_reg_inner(then, dest, width, template, ok);
            substitute_reg_inner(els, dest, width, template, ok);
            *ok &= comparison_preserved(*cond, comparison, lhs, rhs);
        }
        Expr::Load { addr, .. } => substitute_reg_inner(addr, dest, width, template, ok),
        Expr::SignExtend { value, .. } => substitute_reg_inner(value, dest, width, template, ok),
        Expr::Apply { args, .. } => {
            for arg in args {
                substitute_reg_inner(arg, dest, width, template, ok);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_propagate, copy_propagate_guarded, inline_local_copies, truncated};
    use crate::ir::eval::{self, Outcome};
    use crate::ir::{
        BinOp, Block, CType, Cond, Convention, Expr, FunctionIr, Operation, Param, Precision,
        RegRef, Stmt, VARIABLE_BASE,
    };
    use crate::loader::Isa;

    fn run(ir: &FunctionIr, address: u64, word: u64) -> Outcome {
        let registers = [(7, 0x3000_0000_2000)];
        let memory = [(address, word)];
        let outcome = eval::run(
            ir,
            &eval::Setup {
                seed: 0,
                convention: eval::Convention {
                    arguments: &[7],
                    clobbered: &[],
                },
                registers: &registers,
                memory: &memory,
                step_limit: 100,
            },
        );
        assert!(matches!(&outcome, Outcome::Return { .. }), "{outcome:?}");
        outcome
    }

    fn copy_passes() -> [fn(&mut FunctionIr); 3] {
        [inline_local_copies, copy_propagate, copy_propagate_guarded]
    }

    fn stack_load(bytes: u8, signed: bool) -> Expr {
        Expr::Load {
            addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(8))),
            width: bytes,
            signed,
        }
    }

    fn with_copy(value: Expr, width: u8, consumer: Stmt) -> FunctionIr {
        FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width,
                    },
                    value,
                },
                consumer,
            ],
        )
    }

    #[test]
    fn folded_reads_keep_their_own_truncation() {
        let cases = [
            (
                stack_load(4, true),
                Expr::reg(VARIABLE_BASE, 32),
                0x8000_0080,
            ),
            (
                Expr::bin(BinOp::Add, stack_load(4, false), Expr::Const(1)),
                Expr::reg(VARIABLE_BASE, 32),
                0xffff_ffff,
            ),
            (
                stack_load(4, true),
                Expr::bin(BinOp::And, Expr::reg(VARIABLE_BASE, 8), Expr::Const(0xffff)),
                0x8000_1280,
            ),
        ];
        for (value, returned, word) in cases {
            let before = with_copy(value, 64, Stmt::Ret { value: returned });
            let expected = run(&before, eval::STACK_TOP + 8, word);
            for pass in copy_passes() {
                let mut after = before.clone();
                pass(&mut after);
                assert!(
                    matches!(after.blocks[0].stmts.as_slice(), [Stmt::Ret { .. }]),
                    "{}",
                    after.render()
                );
                assert_eq!(
                    run(&after, eval::STACK_TOP + 8, word),
                    expected,
                    "{}",
                    after.render()
                );
            }
        }
    }

    #[test]
    fn copy_folding_preserves_signed_operation_and_comparison_widths() {
        let check = |before: &FunctionIr| {
            let expected = run(before, eval::STACK_TOP + 8, 0x80);
            for pass in copy_passes() {
                let mut after = before.clone();
                pass(&mut after);
                assert_eq!(
                    run(&after, eval::STACK_TOP + 8, 0x80),
                    expected,
                    "{}",
                    after.render()
                );
            }
        };
        for op in [BinOp::Sar, BinOp::DivS, BinOp::ModS] {
            for rhs in [
                Expr::Const(3),
                Expr::bin(BinOp::Add, Expr::reg(7, 8), Expr::Const(3)),
            ] {
                let before = with_copy(
                    stack_load(1, true),
                    32,
                    Stmt::Ret {
                        value: Expr::bin(op, Expr::reg(VARIABLE_BASE, 64), rhs),
                    },
                );
                check(&before);
            }
        }
        for (cond, rhs) in [
            (Cond::Lt, Expr::Const(0)),
            (Cond::Eq, Expr::Const(0x1_ffff_ff80)),
        ] {
            let before = with_copy(
                stack_load(1, true),
                32,
                Stmt::Ret {
                    value: Expr::Select {
                        cond,
                        lhs: Box::new(Expr::reg(VARIABLE_BASE, 64)),
                        rhs: Box::new(rhs.clone()),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::Const(2)),
                    },
                },
            );
            check(&before);
            let mut branch = with_copy(
                stack_load(1, true),
                32,
                Stmt::Brif {
                    cond,
                    lhs: Expr::reg(VARIABLE_BASE, 64),
                    rhs,
                    target: 0x20,
                },
            );
            branch.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(2),
                    }],
                },
                Block {
                    start: 0x20,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(1),
                    }],
                },
            ]);
            check(&branch);
        }
    }

    #[test]
    fn equality_folds_when_both_values_fit_the_smaller_comparison_width() {
        for cond in [Cond::Eq, Cond::Ne] {
            let before = with_copy(
                stack_load(1, true),
                32,
                Stmt::Ret {
                    value: Expr::Select {
                        cond,
                        lhs: Box::new(Expr::bin(
                            BinOp::And,
                            Expr::reg(VARIABLE_BASE, 64),
                            Expr::Const(4),
                        )),
                        rhs: Box::new(Expr::Const(0)),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::Const(2)),
                    },
                },
            );
            for word in [0x80, 0x84] {
                let expected = run(&before, eval::STACK_TOP + 8, word);
                for pass in copy_passes() {
                    let mut after = before.clone();
                    pass(&mut after);
                    assert!(
                        matches!(after.blocks[0].stmts.as_slice(), [Stmt::Ret { .. }]),
                        "{}",
                        after.render()
                    );
                    assert_eq!(
                        run(&after, eval::STACK_TOP + 8, word),
                        expected,
                        "{}",
                        after.render()
                    );
                }
            }
        }
    }

    #[test]
    fn a_rejected_substitution_leaves_the_consumer_unchanged() {
        let before = with_copy(
            Expr::reg(7, 32),
            32,
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(VARIABLE_BASE, 64),
                    Expr::reg(VARIABLE_BASE, 16),
                ),
            },
        );
        for pass in copy_passes() {
            let mut after = before.clone();
            pass(&mut after);
            assert_eq!(after.render(), before.render());
            assert_eq!(
                run(&after, eval::STACK_TOP + 8, 0),
                run(&before, eval::STACK_TOP + 8, 0)
            );
        }
    }

    #[test]
    fn folded_signed_loads_keep_assignment_truncation() {
        let passes = [
            (
                "local copies",
                inline_local_copies as fn(&mut FunctionIr),
                false,
            ),
            ("copy propagation", copy_propagate, true),
            ("guarded copies", copy_propagate_guarded, true),
        ];
        for (name, pass, stack) in passes {
            let (address, location) = if stack {
                (
                    Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(8)),
                    eval::STACK_TOP + 8,
                )
            } else {
                (Expr::reg(7, 64), 0x3000_0000_2000)
            };
            for bytes in [1u8, 2, 4] {
                let sign = 1u64 << (bytes * 8 - 1);
                let source_mask = (1u64 << (bytes * 8)) - 1;
                for word in [5, sign | 5, source_mask] {
                    let mut ir = FunctionIr::single_block(
                        Isa::X86_64,
                        vec![
                            Stmt::Assign {
                                dest: RegRef {
                                    index: VARIABLE_BASE,
                                    width: 32,
                                },
                                value: Expr::Load {
                                    addr: Box::new(address.clone()),
                                    width: bytes,
                                    signed: true,
                                },
                            },
                            Stmt::Ret {
                                value: Expr::reg(VARIABLE_BASE, 64),
                            },
                        ],
                    );
                    if !stack {
                        ir.params = vec![Param {
                            index: 7,
                            name: "p".to_owned(),
                            ty: CType::pointer_to(CType::int(bytes, false)),
                        }];
                    }
                    let before = run(&ir, location, word);
                    let expected = if word & sign != 0 {
                        (word | !source_mask) & 0xffff_ffff
                    } else {
                        word
                    };
                    assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
                    pass(&mut ir);
                    assert!(
                        matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Ret { .. }]),
                        "{name}: {}",
                        ir.render()
                    );
                    assert_eq!(
                        run(&ir, location, word),
                        before,
                        "{name}: signed {bytes}-byte load of {word:x}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_single_precision_result_needs_no_integer_mask() {
        for bits in [
            0,
            0x8000_0000,
            0x3f80_0000,
            0xbf80_0000,
            0x7f80_0000,
            0x7fc0_0080,
        ] {
            let value = Expr::apply(
                Operation::FloatAdd(Precision::Single),
                vec![Expr::Const(bits), Expr::Const(0x3f00_0000)],
            );
            assert_eq!(truncated(&value, 32), value);
            let mut before = with_copy(
                value.clone(),
                32,
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 32),
                },
            );
            before.ret_type = CType::Named("float".to_owned());
            let expected = run(&before, eval::STACK_TOP + 8, 0);
            for pass in copy_passes() {
                let mut after = before.clone();
                pass(&mut after);
                assert!(
                    matches!(after.blocks[0].stmts.as_slice(), [Stmt::Ret { value: returned }] if *returned == value),
                    "{}",
                    after.render()
                );
                assert_eq!(run(&after, eval::STACK_TOP + 8, 0), expected);
            }
        }
    }

    #[test]
    fn load_truncation_retains_bits_without_changing_full_width_values() {
        let address = 0x3000_0000_2000;
        for bytes in [1u8, 2, 4, 8] {
            let source_bits = u32::from(bytes) * 8;
            let source_mask = u64::MAX >> (64 - source_bits);
            let sign = 1u64 << (source_bits - 1);
            for signed in [false, true] {
                let value = Expr::Load {
                    addr: Box::new(Expr::Const(address)),
                    width: bytes,
                    signed,
                };
                for width in [8u8, 16, 32, 64] {
                    let retained = truncated(&value, width);
                    if width == 64 || (!signed && source_bits <= u32::from(width)) {
                        assert_eq!(retained, value);
                    } else {
                        assert_ne!(retained, value);
                    }
                    for word in [5, sign | 5, source_mask] {
                        let before = FunctionIr::single_block(
                            Isa::X86_64,
                            vec![
                                Stmt::Assign {
                                    dest: RegRef {
                                        index: VARIABLE_BASE,
                                        width,
                                    },
                                    value: value.clone(),
                                },
                                Stmt::Ret {
                                    value: Expr::reg(VARIABLE_BASE, 64),
                                },
                            ],
                        );
                        let after = FunctionIr::single_block(
                            Isa::X86_64,
                            vec![Stmt::Ret {
                                value: retained.clone(),
                            }],
                        );
                        assert_eq!(run(&before, address, word), run(&after, address, word));
                    }
                }
            }
        }
    }

    #[test]
    fn shifted_signed_loads_still_need_the_assignment_mask() {
        let address = 0x3000_0000_2000;
        for bytes in [1u8, 2, 4] {
            for count in [0, 1, 63, 64, 65] {
                let value = Expr::bin(
                    BinOp::Shr,
                    Expr::Load {
                        addr: Box::new(Expr::Const(address)),
                        width: bytes,
                        signed: true,
                    },
                    Expr::Const(count),
                );
                let before = FunctionIr::single_block(
                    Isa::X86_64,
                    vec![
                        Stmt::Assign {
                            dest: RegRef {
                                index: VARIABLE_BASE,
                                width: 32,
                            },
                            value: value.clone(),
                        },
                        Stmt::Ret {
                            value: Expr::reg(VARIABLE_BASE, 64),
                        },
                    ],
                );
                let after = FunctionIr::single_block(
                    Isa::X86_64,
                    vec![Stmt::Ret {
                        value: truncated(&value, 32),
                    }],
                );
                let word = 1u64 << (bytes * 8 - 1);
                assert_eq!(run(&before, address, word), run(&after, address, word));
            }
        }
    }

    #[test]
    fn a_folded_narrow_sum_keeps_its_truncation() {
        // eax = ecx + edx; return eax;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 32,
                    },
                    value: Expr::bin(BinOp::Add, Expr::reg(1, 32), Expr::reg(2, 32)),
                },
                Stmt::Ret {
                    value: Expr::reg(0, 32),
                },
            ],
        );

        copy_propagate(&mut ir);

        let sum = Expr::bin(BinOp::Add, Expr::reg(1, 32), Expr::reg(2, 32));
        let truncated = Expr::bin(BinOp::And, sum, Expr::Const(0xffff_ffff));
        assert!(
            matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Ret { value }] if *value == truncated),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_further_result_in_a_parameter_register_stays_in_its_variable() {
        // v1 = f(rbx); v2 = rbx; return v2; with rbx the parameter.
        let (first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::GoAmd64,
                    args: Some(vec![Expr::reg(3, 64)]),
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(Convention::GoAmd64, None),
                    via: None,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: first,
                        width: 64,
                    },
                    value: Expr::reg(0, 64),
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: second,
                        width: 64,
                    },
                    value: Expr::reg(3, 64),
                },
                Stmt::Ret {
                    value: Expr::reg(second, 64),
                },
            ],
        );
        ir.params = vec![Param {
            index: 3,
            name: "a0".to_owned(),
            ty: CType::I64,
        }];

        copy_propagate(&mut ir);

        assert!(
            matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Call { .. }, Stmt::Assign { dest, value: copied }, Stmt::Assign { .. }, Stmt::Ret { value }] if dest.index == first && *copied == Expr::reg(0, 64) && *value == Expr::reg(second, 64)),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_load_does_not_move_past_a_store() {
        let load = |index| Expr::Load {
            addr: Box::new(Expr::reg(index, 64)),
            width: 4,
            signed: false,
        };
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let store = |value, addr| Stmt::Store {
            addr: Expr::reg(addr, 64),
            value: Expr::reg(value, 64),
            width: 4,
        };
        // t = *a; *a = *b; *b = t;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                assign(8, load(1)),
                assign(9, load(0)),
                store(8, 0),
                store(9, 1),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );

        inline_local_copies(&mut ir);

        let stmts = &ir.blocks[0].stmts;
        let saved = stmts
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == 9));
        let overwritten = stmts
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Store { addr, .. } if *addr == Expr::reg(0, 64)));
        assert!(
            saved.is_some_and(|saved| Some(saved) < overwritten),
            "the load of *a stays before the store to *a:\n{}",
            ir.render()
        );
    }

    #[test]
    fn keeps_a_definition_a_later_block_reads() {
        let load = Expr::Load {
            addr: Box::new(Expr::reg(1, 64)),
            width: 8,
            signed: false,
        };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 8,
                        width: 64,
                    },
                    value: load,
                },
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(8, 64),
                    rhs: Expr::Const(0),
                    target: 0x10,
                },
            ],
        );
        ir.blocks.push(Block {
            start: 0x8,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(8, 64),
            }],
        });
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        });

        inline_local_copies(&mut ir);

        assert!(
            matches!(ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index == 8),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn inlines_a_masked_temporary() {
        let masked = |index| Expr::bin(BinOp::And, Expr::reg(index, 64), Expr::Const(0xffff_ffff));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: masked(1),
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: 2,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::ModS, masked(0), masked(2)),
                },
                Stmt::Ret { value: masked(2) },
            ],
        );

        copy_propagate(&mut ir);

        assert!(
            !matches!(ir.blocks[0].stmts.first(), Some(Stmt::Assign { dest, .. }) if dest.index == 0),
            "the masked copy should inline: {:?}",
            ir.blocks[0].stmts
        );
    }
    #[test]
    fn copies_keep_a_precise_calls_preserved_output_source() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 1,
                        width: 64,
                    },
                    value: Expr::Const(17),
                },
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::Aapcs64,
                    args: Some(Vec::new()),
                    floats_named: true,
                    abi: None,
                    clobbers: Some(Default::default()),
                    outputs: vec![crate::ir::CallOutput {
                        register: 1,
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                    }],
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        );
        let before = ir.clone();
        for pass in [copy_propagate, inline_local_copies] {
            ir = before.clone();
            pass(&mut ir);
            assert!(
                matches!(ir.blocks[0].stmts.first(), Some(Stmt::Assign { dest, value: Expr::Const(17) }) if dest.index == 1),
                "{}",
                ir.render()
            );
            let setup = eval::Setup {
                seed: 5,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 32,
            };
            let expected = eval::run(&before, &setup);
            assert!(matches!(&expected, Outcome::Return { value: 17, .. }));
            assert_eq!(eval::run(&ir, &setup), expected);
        }
    }
    #[test]
    fn declared_inputs_keep_their_load_producer_and_fallback_arguments() {
        for arguments in [Vec::new(), vec![Expr::reg(7, 64)]] {
            let call = Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(arguments),
                floats_named: true,
                clobbers: Some(Default::default()),
                outputs: Vec::new(),
                abi: Some(crate::ir::calls::test_call_abi(vec![7], false)),
                via: None,
            };
            let load = Expr::Load {
                addr: Box::new(Expr::reg(2, 64)),
                width: 8,
                signed: false,
            };
            let producer = Stmt::Assign {
                dest: RegRef {
                    index: 7,
                    width: 64,
                },
                value: load.clone(),
            };
            let before = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    producer.clone(),
                    call.clone(),
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            );
            for pass in copy_passes() {
                let mut ir = before.clone();
                pass(&mut ir);
                assert!(
                    matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, value }
                    if dest.index == 7 && *value == load)
                );
                assert_eq!(format!("{:?}", ir.blocks[0].stmts[1]), format!("{call:?}"));
            }
        }
    }

    #[test]
    fn declared_reads_refuse_substitution_but_unattached_calls_allow_it() {
        let mut call = Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::SysV,
            args: Some(vec![Expr::reg(7, 64)]),
            floats_named: true,
            clobbers: Some(Default::default()),
            outputs: Vec::new(),
            abi: Some(crate::ir::calls::test_call_abi(vec![7], false)),
            via: None,
        };
        assert_eq!(super::count_reg(&call, 7), 2);
        let original = call.clone();
        assert!(!super::substitute_stmt(&mut call, 7, 64, &Expr::Const(9)));
        assert_eq!(format!("{call:?}"), format!("{original:?}"));
        if let Stmt::Call { abi, .. } = &mut call {
            *abi = None;
        }
        assert_eq!(super::count_reg(&call, 7), 1);
        assert!(super::substitute_stmt(&mut call, 7, 64, &Expr::Const(9)));
        assert!(matches!(call, Stmt::Call { args: Some(args), .. } if args == [Expr::Const(9)]));
    }
}
