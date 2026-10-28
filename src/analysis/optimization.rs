//! Optimization scheduling before and after variable splitting and type recovery.

use std::collections::HashSet;
use std::time::Instant;

use crate::deadline::passed;
use crate::error::{Error, LiftError};
use crate::ir::{Block, FunctionIr, Stmt};
use crate::loader::Image;
use crate::passes;

use super::{
    Analysis, Lifted, apply_call_return, constant_spills, drop_dead_constant_reads,
    drop_folded_away, drop_stack_protector, drop_unread_indirect_result, go_types,
    name_indirect_result, prototypes, refs, set_up_arguments, structures, summary, typing,
    variadic,
};

pub(super) fn optimize(
    image: &Image,
    lifted: Lifted,
    deadline: Option<Instant>,
) -> Result<Analysis, Error> {
    passed(deadline)?;
    let Lifted {
        mut ir,
        has_jump_tables,
        types,
    } = lifted;
    if ir.isa == crate::loader::Isa::I386 {
        super::com::recover_i386(&mut ir, image, types.as_ref());
        crate::ssa::count_variadic_arguments(&mut ir, image);
        passes::frame_slots::settle_i386(&mut ir);
    } else if ir.isa == crate::loader::Isa::Arm32 {
        passes::frame_slots::settle(&mut ir);
    }
    let declared_return = types.as_ref().is_some_and(|types| types.ret.is_some());
    let uniform_32 = passes::widths::specialize_widths(&mut ir, &|target| {
        summary::summary(image, target).narrow_return
    });
    // Before the stack adjustments a call reads unseen, such as the push
    // of an argument, are dropped as dead.
    passed(deadline)?;
    if ir.isa != crate::loader::Isa::I386 {
        crate::ssa::count_variadic_arguments(&mut ir, image);
    }
    if ir.isa == crate::loader::Isa::I386 {
        for block in &ir.blocks {
            for stmt in &block.stmts {
                if matches!(stmt, Stmt::Call { args: None, .. })
                    && !is_variadic_forwarding_call(&ir, block, stmt, image)
                {
                    return Err(Error::Lift {
                        addr: ir.addr,
                        source: LiftError::UnknownArguments { block: block.start },
                    });
                }
            }
        }
    }
    passed(deadline)?;
    crate::ssa::undefine_clobbered_reads(&mut ir);
    let reached = crate::ir::cfg::reached(&ir);
    let mut simplification =
        cleanup_before_split(&mut ir, image, has_jump_tables, &reached, deadline)?;
    // Guessed register arguments do not bound a callee's stack arguments.
    // Calls that save execution state can also reach the frame implicitly.
    let promote_slots = ir.blocks.iter().flat_map(|block| &block.stmts).all(|stmt| {
        let Stmt::Call {
            kind,
            target,
            through,
            args,
            ..
        } = stmt
        else {
            return true;
        };
        if *kind == crate::ir::CallKind::Syscall {
            return true;
        }
        if args.is_none() {
            return false;
        }
        let name = target
            .and_then(|target| image.functions.get(&target))
            .and_then(|function| function.name.as_deref())
            .or_else(|| match through {
                Some(through) => crate::lift::import_name(image, through),
                None => None,
            });
        !name.is_some_and(|name| {
            matches!(
                name.trim_start_matches('_'),
                "setjmp"
                    | "sigsetjmp"
                    | "longjmp"
                    | "siglongjmp"
                    | "longjmp_chk"
                    | "savectx"
                    | "getcontext"
                    | "swapcontext"
            )
        })
    });
    passed(deadline)?;
    set_up_arguments(&mut ir, types.as_ref());
    passed(deadline)?;
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
    let word_temporaries: &[u16] =
        if matches!(ir.isa, crate::loader::Isa::I386 | crate::loader::Isa::Arm32) {
            &crate::lift::pairs32::TEMPORARIES
        } else {
            &[]
        };
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
    .chain([crate::ir::EXCHANGE, crate::ir::SWITCH_INDEX])
    .chain(word_temporaries.iter().copied())
    .collect();
    // Bits no read looks at go first, so the variables they tied split apart;
    // a narrow return reads fewer of them.
    passed(deadline)?;
    typing::apply_partial_return(&mut ir);
    passed(deadline)?;
    crate::ssa::narrow_partial_writes(&mut ir);
    passed(deadline)?;
    drop_unread_indirect_result(&mut ir, image);
    passed(deadline)?;
    crate::ssa::split_variables(&mut ir, &general);
    let frame_slot_promotion = if promote_slots {
        FrameSlotPromotion::Allowed
    } else {
        FrameSlotPromotion::Blocked
    };
    cleanup_after_split(&mut ir, has_jump_tables, frame_slot_promotion, deadline)?;
    passed(deadline)?;
    typing::apply_width_types(&mut ir, &uniform_32);
    passed(deadline)?;
    typing::apply_void_return(&mut ir);
    passed(deadline)?;
    typing::apply_partial_return(&mut ir);
    passed(deadline)?;
    apply_call_return(&mut ir, image);
    passed(deadline)?;
    let inferred = if types.is_none() {
        crate::lift::pairs32::definition_types(image, ir.addr)
    } else {
        None
    };
    let inferred_parameters = if types.is_none() && inferred.is_none() {
        crate::lift::pairs32::inference::parameters(image, ir.addr)
    } else {
        None
    };
    typing::apply_dwarf_types(types, &mut ir);
    if let Some((params, ret)) = inferred {
        super::pairs32::place_inferred(params, ret, &mut ir);
    } else if let Some(params) = inferred_parameters {
        super::pairs32::place_inferred_parameters(params, &mut ir);
    }
    cleanup_after_types(&mut ir, deadline)?;
    passed(deadline)?;
    name_indirect_result(&mut ir);
    passed(deadline)?;
    structures::recover(&mut ir);
    passed(deadline)?;
    if !declared_return {
        typing::apply_pointer_return_with(&mut ir, &|stmt| prototypes::called(image, stmt));
    }
    // It returns the pointer it wrote the result through.
    if !declared_return
        && ir.declared_signature.is_none()
        && let Some(result) = ir.params.iter().find(|param| param.name == "result")
    {
        ir.ret_type = result.ty.clone();
    }
    passed(deadline)?;
    crate::lift::fold_literals(&mut ir, image);
    let mut references = refs::collect(&ir, image);
    passed(deadline)?;
    passes::frame_slots::settle(&mut ir);
    passed(deadline)?;
    drop_stack_protector(&mut ir, image);
    // Settling simplifies again, which can leave a table read unused.
    passed(deadline)?;
    drop_dead_constant_reads(&mut ir, image);
    passed(deadline)?;
    crate::ssa::take_results_directly(&mut ir);
    passed(deadline)?;
    passes::read_once::fold_values_read_once(&mut ir);
    // Folding the last frame loads can leave their stores unused.
    let plain_frame_stores = ir.blocks.iter().flat_map(|block| &block.stmts).all(|stmt| {
        let Stmt::Store { addr, value, width } = stmt else {
            return true;
        };
        matches!(
            value,
            crate::ir::Expr::Reg { .. } | crate::ir::Expr::Const(_)
        ) && matches!(width, 1 | 2 | 4 | 8)
            && passes::memory::private_address(addr, *width, sp)
            && passes::frame_slots::frame_slot(addr, 0, sp)
                .is_some_and(|slot| slot >= ir.frame_bottom)
    });
    if passes::memory::fixed_private_frame(&ir, sp)
        && !ir.blocks.iter().any(crate::ir::cfg::opaque)
        && plain_frame_stores
    {
        passes::frame::drop_dead_frame_stores(&mut ir);
    }
    // A variable passed where a callee takes a pointer holds one.
    let mut pointer_values = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if stmt.has_declared_call() {
            continue;
        }
        if let Stmt::Call {
            target: Some(target),
            args: Some(args),
            ..
        } = stmt
        {
            let pointers = summary::summary(image, *target).pointers;
            for (position, arg) in args.iter().enumerate().take(32) {
                if pointers & 1 << position != 0
                    && let crate::ir::Expr::Reg { index, width: 64 } = arg
                    && *index >= crate::ir::VARIABLE_BASE
                {
                    pointer_values.push(*index);
                }
            }
        }
    }
    ir.pointer_values = pointer_values;
    passed(deadline)?;
    typing::apply_prototypes(&mut ir, image);
    super::pairs32::type_temporaries(&mut ir);
    prototypes::apply_records(&mut ir, image);
    passed(deadline)?;
    variadic::mark_variadic(&mut ir);
    passed(deadline)?;
    passes::coalesce::reuse_pointers(&mut ir);
    passed(deadline)?;
    go_types::apply(&mut ir, image);
    let changes = passes::deobfuscation::simplify(&mut ir);
    if changes.simplified {
        references = refs::collect(&ir, image);
    }
    simplification.add(changes);
    ir.callee_signatures = crate::analysis::calls::printable_signatures(image, &ir);
    Ok(Analysis {
        unused_parameters: Default::default(),
        import_parameters: Default::default(),
        callee_parameters: Default::default(),
        callee_structures: Default::default(),
        ir,
        references,
        simplification,
    })
}

fn is_variadic_forwarding_call(ir: &FunctionIr, block: &Block, stmt: &Stmt, image: &Image) -> bool {
    ir.blocks.len() == 1
        && block.stmts.len() == 2
        && matches!(
            stmt,
            Stmt::Call {
                kind: crate::ir::CallKind::Tail,
                through: Some(_),
                ..
            }
        )
        && prototypes::called(image, stmt).is_some_and(|prototype| prototype.variadic)
}

fn cleanup_before_split(
    ir: &mut FunctionIr,
    image: &Image,
    has_jump_tables: bool,
    reached: &HashSet<u64>,
    deadline: Option<Instant>,
) -> Result<passes::deobfuscation::Simplification, Error> {
    passed(deadline)?;
    let changes = passes::optimize(ir, has_jump_tables);
    constant_spills::forward(ir, image);
    passed(deadline)?;
    drop_folded_away(ir, reached);
    Ok(changes)
}

enum FrameSlotPromotion {
    Allowed,
    Blocked,
}

fn cleanup_after_split(
    ir: &mut FunctionIr,
    has_jump_tables: bool,
    frame_slot_promotion: FrameSlotPromotion,
    deadline: Option<Instant>,
) -> Result<(), Error> {
    // The new variables leave copies between them to fold away, and values
    // spilled across calls that now survive them in their variables.
    passed(deadline)?;
    passes::copies::copy_propagate_guarded(ir);
    if !has_jump_tables {
        passed(deadline)?;
        passes::memory::forward_stored_values(ir);
        passed(deadline)?;
        passes::memory::forward_spilled_variables(ir);
        if matches!(frame_slot_promotion, FrameSlotPromotion::Allowed) {
            passes::memory::promote_frame_slots(ir);
        }
    }
    passed(deadline)?;
    passes::dce::dce(ir);
    Ok(())
}

fn cleanup_after_types(ir: &mut FunctionIr, deadline: Option<Instant>) -> Result<(), Error> {
    // A narrower return reads fewer bits, which may leave more of a
    // partial write unread.
    passed(deadline)?;
    crate::ssa::narrow_partial_writes(ir);
    passed(deadline)?;
    passes::copies::copy_propagate_guarded(ir);
    passed(deadline)?;
    passes::simplify::simplify(ir);
    // With the variables split, what they hold narrows again.
    passed(deadline)?;
    crate::ssa::ranges::simplify(ir);
    // Simplifying can fold a variable's value into its readers.
    passed(deadline)?;
    passes::dce::dce(ir);
    passed(deadline)?;
    passes::coalesce::coalesce_copies(ir);
    Ok(())
}
