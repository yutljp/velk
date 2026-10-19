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
    let signature = signature::recover(&blocks, image.isa, image.format, image.go);
    jump_table::apply(&mut blocks, &tables);
    let types = crate::loader::dwarf::function_types(image, function.addr);
    // An x86-64 function returning a float returns it in xmm0.
    if image.isa == crate::loader::Isa::X86_64
        && types
            .as_ref()
            .and_then(|types| types.ret.as_ref())
            .is_some_and(crate::ir::CType::is_sse_float)
    {
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt {
                *value = crate::ir::Expr::reg(crate::arch::x86::XMM0, 64);
            }
        }
    }
    let ir = FunctionIr {
        isa: image.isa,
        convention: crate::ir::Convention::of(image.isa, image.format, image.go),
        params: signature.params,
        ret_type: signature.ret,
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
    let general: Vec<u16> = match ir.isa {
        crate::loader::Isa::AArch64 => (0..=30).filter(|register| *register != 29).collect(),
        _ => (0..16)
            .filter(|register| !matches!(register, 4 | 5))
            .collect(),
    };
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
