mod jump_table;
pub mod refs;
mod signature;
mod typing;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::FunctionIr;
use crate::loader::{Function, Image};
use crate::{lift, passes};
use refs::Reference;

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
    let mut ir = FunctionIr {
        isa: image.isa,
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
    let uniform_32 = passes::widths::specialize_widths(&mut ir);
    passes::optimize(&mut ir, !tables.is_empty());
    typing::apply_width_types(&mut ir, &uniform_32);
    typing::apply_void_return(&mut ir);
    typing::apply_dwarf_types(image, function.addr, &mut ir);
    passes::simplify::simplify(&mut ir);
    let references = refs::collect(&ir, image);
    passes::frame_slots::settle(&mut ir);
    Ok(Analysis { ir, references })
}
