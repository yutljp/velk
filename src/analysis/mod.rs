mod jump_table;
pub mod refs;
#[cfg(test)]
mod semantics_tests;
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
            let Ok(blocks) = lift::lift(image, function.addr, size, &HashSet::new()) else {
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

/// Library functions that never return, known by name because their code
/// lies in another module.
const NORETURN_IMPORTS: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__stack_chk_fail",
    "__assert_fail",
    "__assert_rtn",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "_Unwind_Resume",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx",
    "__fortify_fail",
    "__chk_fail",
    "ExitProcess",
];

/// Marks the functions that never return: the library functions known by
/// name, and every function no path of which reaches a return, once calls to
/// those already known end their paths. Repeats until nothing changes, so a
/// function that only calls one that never returns is found too.
pub fn mark_noreturn(image: &mut Image) {
    image.noreturn = image
        .functions
        .values()
        .filter(|function| {
            function.name.as_deref().is_some_and(|name| {
                let name = name
                    .strip_prefix('_')
                    .filter(|_| image.format == crate::loader::Format::MachO)
                    .unwrap_or(name);
                NORETURN_IMPORTS.contains(&name)
            })
        })
        .map(|function| function.addr)
        .collect();
    let bodies: Vec<(u64, Vec<crate::ir::Block>)> = image
        .functions
        .values()
        .filter_map(|function| {
            let size = function.size.unwrap_or(UNKNOWN_SIZE);
            let blocks = lift::lift(image, function.addr, size, &HashSet::new()).ok()?;
            Some((function.addr, blocks))
        })
        .collect();
    loop {
        let found: Vec<u64> = bodies
            .iter()
            .filter(|(addr, blocks)| {
                !image.noreturn.contains(addr) && !can_return(blocks, &image.noreturn)
            })
            .map(|(addr, _)| *addr)
            .collect();
        if found.is_empty() {
            return;
        }
        image.noreturn.extend(found);
    }
}

/// Whether some path from the entry reaches a return, an unknown jump, or
/// the end of the code; a call to a function in `noreturn` ends its path.
fn can_return(blocks: &[crate::ir::Block], noreturn: &HashSet<u64>) -> bool {
    use crate::ir::Stmt;
    if blocks.is_empty() {
        return true;
    }
    let mut seen = vec![false; blocks.len()];
    let mut work = vec![0];
    while let Some(index) = work.pop() {
        if std::mem::replace(&mut seen[index], true) {
            continue;
        }
        let block = &blocks[index];
        let ends = block.stmts.iter().any(|stmt| {
            matches!(stmt, Stmt::Call { target: Some(target), .. } if noreturn.contains(target))
        });
        if ends {
            continue;
        }
        match block.stmts.last() {
            Some(Stmt::Ret { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }) => {
                return true;
            }
            Some(Stmt::Trap) => {}
            _ => {
                let next = crate::ir::cfg::block_successors(blocks, index);
                // Code that runs off the end of what was lifted may go anywhere.
                let terminated = matches!(
                    block.stmts.last(),
                    Some(
                        Stmt::Br { .. }
                            | Stmt::Brif { .. }
                            | Stmt::BrifFlags { .. }
                            | Stmt::Switch { .. }
                    )
                );
                if next.is_empty() && !terminated {
                    return true;
                }
                work.extend(next);
            }
        }
    }
    false
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
    let parameters: Vec<u16> = ir.params.iter().map(|param| param.index).collect();
    crate::ssa::split_variables(&mut ir, &parameters);
    typing::apply_width_types(&mut ir, &uniform_32);
    typing::apply_void_return(&mut ir);
    typing::apply_partial_return(&mut ir);
    typing::apply_dwarf_types(types, &mut ir);
    passes::simplify::simplify(&mut ir);
    let references = refs::collect(&ir, image);
    passes::frame_slots::settle(&mut ir);
    Analysis { ir, references }
}
