mod jump_table;
pub mod prototypes;
pub mod refs;
#[cfg(test)]
mod semantics_tests;
mod signature;
mod summary;
mod typing;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::FunctionIr;
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
/// every path to a return writes the float return register, and some path
/// leaves the integer one as it came in. On x86-64 that value means nothing,
/// and on AArch64 it is the first argument, which a function returning a
/// float does not return. A float is a single when every write computes one.
fn float_result(
    blocks: &[crate::ir::Block],
    isa: crate::loader::Isa,
) -> Option<crate::ir::Precision> {
    use crate::ir::{Expr, Precision, Stmt};
    let slot = float_return_slot(isa)?;
    if blocks.is_empty() {
        return None;
    }
    // Per block on entry: whether every path wrote the float register, and
    // whether every path wrote the integer one; a call writes both.
    let mut entry: Vec<Option<(bool, bool)>> = vec![None; blocks.len()];
    entry[0] = Some((false, false));
    let mut work = vec![0];
    let mut returns = Vec::new();
    let mut precision = None;
    while let Some(index) = work.pop() {
        let (mut float, mut int) = entry[index].expect("visited");
        for stmt in &blocks[index].stmts {
            match stmt {
                Stmt::Assign { dest, .. } if dest.index == crate::arch::RETURN => int = true,
                Stmt::Assign { dest, value } if dest.index == slot => {
                    float = true;
                    let single = |expr: &Expr| matches!(expr, Expr::Apply { op, .. } if op.result_precision() == Some(Precision::Single));
                    let this = match value {
                        Expr::Bin { rhs, .. } if single(rhs) => Precision::Single,
                        expr if single(expr) => Precision::Single,
                        _ => Precision::Double,
                    };
                    precision = Some(match precision {
                        Some(Precision::Double) => Precision::Double,
                        _ => this,
                    });
                }
                Stmt::Call { .. } => (float, int) = (true, true),
                Stmt::Ret { .. } => returns.push((float, int)),
                _ => {}
            }
        }
        for next in crate::ir::cfg::block_successors(blocks, index) {
            let merged = match entry[next] {
                Some((f, i)) => (f && float, i && int),
                None => (float, int),
            };
            if entry[next] != Some(merged) {
                entry[next] = Some(merged);
                work.push(next);
            }
        }
    }
    let floats = !returns.is_empty() && returns.iter().all(|(float, _)| *float);
    let int_everywhere = returns.iter().all(|(_, int)| *int);
    (floats && !int_everywhere).then_some(precision?)
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
    // A function the debug info says returns nothing returns no register.
    if declared == Some(&crate::ir::CType::Void) {
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
    let ir = FunctionIr {
        isa: image.isa,
        convention: crate::ir::Convention::of(image.isa, image.format, image.go),
        params: signature.params,
        stack_params: Vec::new(),
        variadic: false,
        ret_type: match float_return {
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
    passes::dce::dce(&mut ir);
    // Every general register becomes the variables it holds, apart from the
    // stack and frame pointers, which address the frame.
    // So do the registers the lifter keeps flag operands and exchanged
    // values in.
    let general: Vec<u16> = match ir.isa {
        crate::loader::Isa::AArch64 => (0..=30)
            .filter(|register| *register != 29)
            .collect::<Vec<u16>>(),
        _ => (0..16)
            .filter(|register| !matches!(register, 4 | 5))
            .collect(),
    }
    .into_iter()
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
    let references = refs::collect(&ir, image);
    passes::frame_slots::settle(&mut ir);
    Analysis { ir, references }
}
