pub mod coalesce;
pub mod copies;
pub mod cse;
pub mod dce;
pub mod deobfuscation;
pub mod division;
pub mod frame;
pub mod frame_slots;
pub mod layout;
mod mba;
pub mod memory;
pub mod read_once;
pub mod simplify;
pub mod widths;

use crate::ir::FunctionIr;

/// Runs the pass `site`; with the `validate` feature, records an SMT
/// obligation for each statement it rewrites.
#[inline]
pub(crate) fn checked<R>(
    site: &'static str,
    ir: &mut FunctionIr,
    run: impl FnOnce(&mut FunctionIr) -> R,
) -> R {
    checked_assuming(site, ir, &Callees::default(), run)
}

/// What the summaries of a function's callees tell a pass that relies on
/// them.
#[derive(Debug, Default)]
pub(crate) struct Callees {
    /// The callees that return 32-bit values.
    pub(crate) narrow_results: Vec<u64>,
    /// The callees that take no result address in `AArch64`'s x8.
    pub(crate) without_result_address: Vec<u64>,
}

/// The same for a pass that relies on what `callees` says.
#[inline]
pub(crate) fn checked_assuming<R>(
    site: &'static str,
    ir: &mut FunctionIr,
    callees: &Callees,
    run: impl FnOnce(&mut FunctionIr) -> R,
) -> R {
    #[cfg(feature = "validate")]
    return crate::ir::smt::validate::pass(site, ir, callees, run);
    #[cfg(not(feature = "validate"))]
    {
        let _ = (site, callees);
        run(ir)
    }
}

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
    let mut changes = deobfuscation::predicates(ir);
    changes.mba_expressions_simplified = mba::simplify(ir);
    changes.simplified |= changes.mba_expressions_simplified != 0;
    simplify::simplify(ir);
    dce::dce(ir);
    changes
}
