mod jump_table;
pub mod prototypes;
pub mod refs;
mod results;
#[cfg(test)]
mod semantics_tests;
mod signature;
mod structures;
mod summary;
pub(crate) mod typing;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::{FunctionIr, Stmt};
use crate::loader::{Function, Image};
use crate::{lift, passes};
use refs::Reference;
pub use summary::summary;

/// Bytes lifted for a function whose extent neither symbols nor scanning give.
pub const UNKNOWN_SIZE: u64 = 256;

#[derive(Debug, Clone)]
pub struct Analysis {
    pub ir: FunctionIr,
    pub references: Vec<Reference>,
}

impl Analysis {
    pub fn strings(&self) -> Vec<String> {
        self.references
            .iter()
            .filter_map(|r| r.text.clone())
            .collect()
    }
}

pub fn analyze(image: &Image, function: &Function) -> Result<Analysis, LiftError> {
    let lifted = lift_function(image, function)?;
    Ok(optimize(image, lifted))
}

fn float_return_slot(isa: crate::loader::Isa) -> Option<u16> {
    match isa {
        crate::loader::Isa::X86_64 => Some(crate::arch::x86::XMM0),
        crate::loader::Isa::AArch64 => Some(crate::arch::aarch64::V0),
        crate::loader::Isa::Unsupported => None,
    }
}

/// Whether, without debug info, the function returns a float, and which:
/// every path to a return writes the float return register, and either
/// some path leaves the integer one as it came in, or every path writes it
/// before the float one. On x86-64 an untouched integer register means
/// nothing, and on AArch64 it is the first argument, which a function
/// returning a float does not return. A float is a single when the last
/// write on every path that says computes or loads one.
fn float_result(
    blocks: &[crate::ir::Block],
    isa: crate::loader::Isa,
) -> Option<crate::ir::Precision> {
    use crate::ir::{Precision, Stmt};
    let slot = float_return_slot(isa)?;
    if blocks.is_empty() {
        return None;
    }
    // Per block on entry: whether every path wrote the float register and
    // the integer one (a call writes both), whether every path wrote the
    // float one last, and the precision the last write to the float
    // register shows, when the paths agree.
    #[derive(Clone, Copy, PartialEq)]
    struct State {
        float: bool,
        int: bool,
        float_last: bool,
        precision: Option<Precision>,
    }
    let mut entry: Vec<Option<State>> = vec![None; blocks.len()];
    entry[0] = Some(State {
        float: false,
        int: false,
        float_last: false,
        precision: None,
    });
    let mut work = vec![0];
    let mut returns = Vec::new();
    while let Some(index) = work.pop() {
        let mut state = entry[index].expect("visited");
        for stmt in &blocks[index].stmts {
            match stmt {
                Stmt::Assign { dest, .. } if dest.index == crate::arch::RETURN => {
                    state.int = true;
                    state.float_last = false;
                }
                Stmt::Assign { dest, value } if dest.index == slot => {
                    state.float = true;
                    state.float_last = true;
                    state.precision = written_precision(value, slot);
                }
                Stmt::Call { .. } => {
                    state = State {
                        float: true,
                        int: true,
                        float_last: false,
                        precision: None,
                    }
                }
                Stmt::Ret { .. } => returns.push(state),
                _ => {}
            }
        }
        for next in crate::ir::cfg::block_successors(blocks, index) {
            let merged = match entry[next] {
                Some(old) => State {
                    float: old.float && state.float,
                    int: old.int && state.int,
                    float_last: old.float_last && state.float_last,
                    precision: if old.precision == state.precision {
                        old.precision
                    } else {
                        None
                    },
                },
                None => state,
            };
            if entry[next] != Some(merged) {
                entry[next] = Some(merged);
                work.push(next);
            }
        }
    }
    let floats = !returns.is_empty() && returns.iter().all(|state| state.float);
    let int_first = returns.iter().all(|state| !state.int || state.float_last);
    let single = returns
        .iter()
        .any(|state| state.precision == Some(Precision::Single))
        && returns
            .iter()
            .all(|state| state.precision != Some(Precision::Double));
    (floats && int_first).then_some(if single {
        Precision::Single
    } else {
        Precision::Double
    })
}

/// The precision of the float a write to the vector register `slot` puts
/// in its low half: what an operation computes or a load reads. x86 merges
/// a single into the register's other bits, and AArch64 clears them.
fn written_precision(value: &crate::ir::Expr, slot: u16) -> Option<crate::ir::Precision> {
    use crate::ir::{BinOp, Expr, Precision};
    match value {
        Expr::Apply { op, .. } => op.result_precision(),
        Expr::Load { width: 4, .. } => Some(Precision::Single),
        Expr::Load { width: 8, .. } => Some(Precision::Double),
        Expr::Bin {
            op: BinOp::And | BinOp::Or,
            lhs,
            rhs,
        } => {
            let kept = |side: &Expr| match side {
                Expr::Const(_) => true,
                Expr::Bin { lhs, rhs, .. } => {
                    matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == slot)
                        && matches!(rhs.as_ref(), Expr::Const(_))
                }
                _ => false,
            };
            match (kept(lhs), kept(rhs)) {
                (true, false) => written_precision(rhs, slot),
                (false, true) => written_precision(lhs, slot),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Gives a call whose callee's arguments are unknown, such as one through a
/// pointer, the argument registers the code sets up for it: up to the last
/// one written since the block's previous call and not used again before
/// the call, as a register holding scratch is. Loading through a register,
/// as a virtual call loads its table through the object, is no such use.
fn set_up_arguments(ir: &mut FunctionIr) {
    // The registers an expression reads other than as the base of a load.
    fn used(expr: &crate::ir::Expr, out: &mut HashSet<u16>) {
        use crate::ir::{BinOp, Expr};
        match expr {
            Expr::Load { addr, .. } => match addr.as_ref() {
                Expr::Reg { .. } => {}
                Expr::Bin {
                    op: BinOp::Add,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), Expr::Reg { .. })
                    && matches!(rhs.as_ref(), Expr::Const(_)) => {}
                other => used(other, out),
            },
            Expr::Reg { index, .. } => {
                out.insert(*index);
            }
            other => {
                for child in crate::ir::visit::children(other) {
                    used(child, out);
                }
            }
        }
    }
    for block in &mut ir.blocks {
        let mut written: HashSet<u16> = HashSet::new();
        for stmt in &mut block.stmts {
            let Stmt::Call {
                convention, args, ..
            } = stmt
            else {
                let mut reads = HashSet::new();
                for operand in stmt.operands() {
                    used(operand, &mut reads);
                }
                for read in reads {
                    written.remove(&read);
                }
                written.extend(crate::ir::visit::statement_registers(stmt).0);
                continue;
            };
            let registers = convention.arguments();
            if args.is_none()
                && let Some(last) = registers
                    .iter()
                    .rposition(|register| written.contains(register))
            {
                *args = Some(
                    registers[..=last]
                        .iter()
                        .map(|register| crate::ir::Expr::reg(*register, 64))
                        .collect(),
                );
            }
            written.clear();
        }
    }
}

/// Drops a write of AArch64's indirect result register that only a call
/// reads, implicitly, when the callee does not return through memory: the
/// compiler used it as a scratch register for the call's arguments.
fn drop_unread_indirect_result(ir: &mut FunctionIr, image: &Image) {
    const INDIRECT: u16 = 8;
    if ir.isa != crate::loader::Isa::AArch64 {
        return;
    }
    let reads = |expr: &crate::ir::Expr| {
        let mut read = HashSet::new();
        crate::ir::visit::collect_reads(expr, &mut read);
        read.contains(&INDIRECT)
    };
    for block in &mut ir.blocks {
        let mut dead = Vec::new();
        for (position, stmt) in block.stmts.iter().enumerate() {
            let Stmt::Assign { dest, .. } = stmt else {
                continue;
            };
            if dest.index != INDIRECT {
                continue;
            }
            for later in &block.stmts[position + 1..] {
                match later {
                    Stmt::Call {
                        target: Some(target),
                        args: Some(_),
                        ..
                    } if !later.operands().into_iter().any(reads)
                        && !summary::summary(image, *target).indirect_result =>
                    {
                        dead.push(position);
                        break;
                    }
                    _ => {
                        let (writes, read) = crate::ir::visit::statement_registers(later);
                        if read.contains(&INDIRECT) || writes.contains(&INDIRECT) {
                            break;
                        }
                    }
                }
            }
        }
        for position in dead.into_iter().rev() {
            block.stmts.remove(position);
        }
    }
}

/// The function's IR before any optimization pass, with its recovered signature.
struct Lifted {
    ir: FunctionIr,
    has_jump_tables: bool,
    types: Option<crate::loader::dwarf::FunctionTypes>,
}

/// Folds the cases of jump tables back into their functions where the
/// prologue scan took a case, which follows a return like a new function
/// would, for a function start. Each pass widens the functions it merges,
/// which may expose further tables.
pub fn absorb_jump_table_cases(image: &mut Image) {
    for _ in 0..4 {
        let mut cases = HashSet::new();
        for function in image.functions.values() {
            if !function
                .sources
                .contains(&crate::loader::NameSource::Prologue)
            {
                continue;
            }
            let size = function.size.unwrap_or(UNKNOWN_SIZE);
            // Function extents are still settling, so no callee is summarized yet.
            let Ok(blocks) = lift::lift_with(image, function.addr, size, &HashSet::new(), &|_| {
                crate::loader::Summary::default()
            }) else {
                continue;
            };
            for table in jump_table::recover(&blocks, image) {
                cases.extend(
                    table
                        .targets()
                        .into_iter()
                        .filter(|target| *target != function.addr),
                );
            }
            cases.extend(
                jump_table::unbounded_targets(&blocks, image, function.addr, 0x1_0000)
                    .into_iter()
                    .filter(|target| *target != function.addr),
            );
        }
        if !image.drop_scanned_starts(&cases) {
            return;
        }
    }
}

fn lift_function(image: &Image, function: &Function) -> Result<Lifted, LiftError> {
    let size = function.size.unwrap_or(UNKNOWN_SIZE);
    let mut blocks = lift::lift(image, function.addr, size, &HashSet::new())?;
    let mut tables = jump_table::recover(&blocks, image);
    if !tables.is_empty() {
        let targets = tables
            .iter()
            .flat_map(jump_table::Recovered::targets)
            .collect();
        blocks = lift::lift(image, function.addr, size, &targets)?;
        tables = jump_table::recover(&blocks, image);
    }
    let types = crate::loader::dwarf::function_types(image, function.addr);
    // A function returning a float returns it in xmm0 or v0.
    let declared = types.as_ref().and_then(|types| types.ret.as_ref());
    let float_return = match declared {
        Some(ret) if ret.is_sse_float() => Some(if ret.to_string().contains("double") {
            crate::ir::Precision::Double
        } else {
            crate::ir::Precision::Single
        }),
        Some(_) => None,
        None => float_result(&blocks, image.isa),
    };
    // Without debug info, a function whose callers all ignore what is left
    // in the return register returns nothing either. A linkage stub returns
    // what the library function does, whatever these callers make of it.
    let ignored = declared.is_none()
        && float_return.is_none()
        && !function.sources.contains(&crate::loader::NameSource::Plt)
        && results::ignored_by_callers(image, function.addr);
    // A function the debug info says returns nothing returns no register.
    if declared == Some(&crate::ir::CType::Void) || ignored {
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt {
                *value = crate::ir::Expr::constant(0);
            }
        }
    }
    if let (Some(precision), Some(slot)) = (float_return, float_return_slot(image.isa)) {
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt {
                *value = crate::ir::Expr::reg(slot, precision.bits());
            }
        }
    }
    // The signature reads the returns as they now are.
    let signature = signature::recover(&blocks, image.isa, image.format, image.go);
    jump_table::apply(&mut blocks, &tables);
    // The arguments past the registers follow the register ones.
    let stack_params = signature
        .stack
        .iter()
        .enumerate()
        .map(|(slot, offset)| {
            let position = signature.params.len() + slot;
            crate::ir::StackParam {
                offset: *offset,
                size: 8,
                name: format!("a{position}"),
                ty: crate::ir::CType::I64,
                position,
            }
        })
        .collect();
    let ir = FunctionIr {
        isa: image.isa,
        convention: crate::ir::Convention::of(image.isa, image.format, image.go),
        params: signature.params,
        stack_params,
        variadic: false,
        ret_type: match float_return {
            _ if ignored => crate::ir::CType::Void,
            Some(precision) => crate::ir::CType::Named(
                match precision {
                    crate::ir::Precision::Single => "float",
                    crate::ir::Precision::Double => "double",
                }
                .to_owned(),
            ),
            None => signature.ret,
        },
        accesses: signature.accesses,
        members: Vec::new(),
        structures: Vec::new(),
        signed_params: signature.signed,
        addr: function.addr,
        name: function.name.clone(),
        size,
        blocks,
    };
    Ok(Lifted {
        ir,
        has_jump_tables: !tables.is_empty(),
        types,
    })
}

fn optimize(image: &Image, lifted: Lifted) -> Analysis {
    let Lifted {
        mut ir,
        has_jump_tables,
        types,
    } = lifted;
    let uniform_32 = passes::widths::specialize_widths(&mut ir);
    passes::optimize(&mut ir, has_jump_tables);
    crate::ssa::count_variadic_arguments(&mut ir, image);
    set_up_arguments(&mut ir);
    passes::dce::dce(&mut ir);
    // Every general register becomes the variables it holds, apart from the
    // stack pointer, and the frame pointer while it addresses the frame.
    // So do the vector registers, each half on its own, and the registers
    // the lifter keeps flag operands and exchanged values in.
    let sp = crate::arch::stack_pointer(ir.isa);
    let fp = crate::arch::frame_pointer(ir.isa);
    let addresses_frame = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| match stmt {
            Stmt::Assign { dest, value } if dest.index == fp => {
                let mut read = HashSet::new();
                crate::ir::visit::collect_reads(value, &mut read);
                read.contains(&sp)
            }
            _ => false,
        });
    let general: Vec<u16> = match ir.isa {
        crate::loader::Isa::AArch64 => (0..=30).collect::<Vec<u16>>(),
        _ => (0..16).collect(),
    }
    .into_iter()
    .filter(|register| *register != sp && (*register != fp || !addresses_frame))
    .chain(
        crate::arch::machine_registers()
            .filter(|register| crate::arch::vector_half(ir.isa, *register).is_some()),
    )
    .chain(crate::ir::FLAG_OPERANDS)
    .chain(crate::ir::FLAG_CARRIED)
    .chain([crate::ir::EXCHANGE])
    .collect();
    // Bits no read looks at go first, so the variables they tied split apart.
    crate::ssa::narrow_partial_writes(&mut ir);
    crate::ssa::split_variables(&mut ir, &general);
    // The new variables leave copies between them to fold away.
    passes::copies::copy_propagate_guarded(&mut ir);
    passes::dce::dce(&mut ir);
    typing::apply_width_types(&mut ir, &uniform_32);
    typing::apply_void_return(&mut ir);
    typing::apply_partial_return(&mut ir);
    typing::apply_dwarf_types(types, &mut ir);
    passes::simplify::simplify(&mut ir);
    // Simplifying can fold a variable's value into its readers.
    passes::dce::dce(&mut ir);
    drop_unread_indirect_result(&mut ir, image);
    structures::recover(&mut ir);
    let references = refs::collect(&ir, image);
    passes::frame_slots::settle(&mut ir);
    Analysis { ir, references }
}
