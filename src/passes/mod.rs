pub mod coalesce;
pub mod copies;
pub mod cse;
pub mod dce;
pub mod deobfuscation;
pub mod division;
pub mod frame;
pub mod frame_slots;
pub mod layout;
pub mod memory;
pub mod read_once;
pub mod simplify;
pub mod widths;

use crate::ir::FunctionIr;

/// Functions with recovered jump tables skip the flow-sensitive cleanups.
pub fn optimize(ir: &mut FunctionIr, has_jump_tables: bool) -> deobfuscation::Simplification {
    cse::cse(ir);
    simplify::simplify(ir);
    division::recover_divisions(ir);
    simplify::simplify(ir);
    frame::elide_frame_pointer(ir);
    frame::elide_callee_saves(ir);
    copies::copy_propagate(ir);
    dce::dce(ir);
    // The pop matching the push goes first when nothing reads it.
    frame::drop_alignment_pushes(ir);
    if !has_jump_tables {
        dce::dce_flow(ir);
    }
    simplify::simplify(ir);
    copies::copy_propagate_guarded(ir);
    dce::dce(ir);
    if !has_jump_tables {
        dce::dce_flow(ir);
        memory::forward_stored_values(ir);
        copies::inline_local_copies(ir);
        copies::copy_propagate_guarded(ir);
        simplify::simplify(ir);
        dce::dce(ir);
    }
    memory::fuse_load_op_store(ir);
    let changes = deobfuscation::predicates(ir);
    simplify::simplify(ir);
    dce::dce(ir);
    changes
}
