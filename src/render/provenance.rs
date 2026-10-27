//! Local pointer facts for proving that memory ranges do not overlap.
use std::collections::HashMap;

use super::{Ctx, Node};
use crate::ir::{BinOp, Expr, Stmt};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Base {
    Unknown(usize, u16),
    Absolute,
    Frame,
    Heap(usize, bool, Option<u64>),
}

#[derive(Clone, Copy)]
struct Pointer {
    base: Base,
    offset: u64,
    created_at: usize,
}

pub(super) struct Facts {
    values: HashMap<u16, Pointer>,
}

impl Facts {
    pub(super) fn preceding(nodes: &[Node], ctx: &Ctx<'_>) -> Self {
        let mut facts = Self {
            values: HashMap::new(),
        };
        for node in nodes {
            if let Node::Stmt(stmt) = node {
                let (_, reads) = crate::ir::visit::statement_registers(stmt);
                for index in reads {
                    facts.values.entry(index).or_insert(Pointer {
                        base: Base::Unknown(0, index),
                        offset: 0,
                        created_at: 0,
                    });
                }
            }
        }
        for (&index, &offset) in &ctx.frame_origins {
            facts.values.insert(
                index,
                Pointer {
                    base: Base::Frame,
                    offset: offset as u64,
                    created_at: 0,
                },
            );
        }
        for (position, node) in nodes.iter().enumerate() {
            let time = position + 1;
            match node {
                Node::Stmt(Stmt::Assign { dest, value }) => {
                    let pointer = if dest.width == 64 {
                        facts.pointer(value)
                    } else {
                        None
                    };
                    facts.values.remove(&dest.index);
                    if let Some(pointer) = pointer {
                        facts.values.insert(dest.index, pointer);
                    } else if dest.width == 64 {
                        facts.values.insert(
                            dest.index,
                            Pointer {
                                base: Base::Unknown(time, dest.index),
                                offset: 0,
                                created_at: time,
                            },
                        );
                    }
                }
                Node::Stmt(
                    stmt @ Stmt::Call {
                        target, via, args, ..
                    },
                ) => {
                    let name = target
                        .and_then(|target| {
                            ctx.symbols
                                .allocator_names
                                .get(&target)
                                .or_else(|| ctx.symbols.original_or_printed_function_name(target))
                        })
                        .or_else(|| {
                            via.as_ref()
                                .and_then(|via| ctx.symbols.import_name(&via.slot))
                        });
                    let allocation = name.and_then(|name| allocation_is_reallocated(name));
                    let size = name.and_then(|name| allocation_size(name, args.as_deref(), &facts));
                    // Other calls may release objects whose addresses remain in registers.
                    if allocation != Some(false) {
                        facts.discard_freshness();
                    }
                    for index in stmt.call_clobbers() {
                        facts.values.remove(&index);
                    }
                    for output in stmt.call_outputs() {
                        facts.values.remove(&output.dest.index);
                    }
                    if let (Some(reallocated), Some(output)) =
                        (allocation, stmt.primary_call_output())
                        && output.dest.width == 64
                    {
                        facts.values.insert(
                            output.dest.index,
                            Pointer {
                                base: Base::Heap(time, reallocated, size),
                                offset: 0,
                                created_at: time,
                            },
                        );
                    }
                }
                Node::Stmt(Stmt::Store { .. }) => {}
                Node::If { then, els, .. }
                    if then
                        .iter()
                        .chain(els)
                        .all(|node| matches!(node, Node::Stmt(_))) =>
                {
                    for node in then.iter().chain(els) {
                        let Node::Stmt(stmt) = node else {
                            continue;
                        };
                        if matches!(stmt, Stmt::Call { .. } | Stmt::Unsupported { .. }) {
                            facts.discard_freshness();
                        }
                        for index in crate::ir::visit::statement_registers(stmt).0 {
                            facts.values.remove(&index);
                        }
                    }
                }
                _ => {
                    facts.values.clear();
                    for (&index, &offset) in &ctx.frame_origins {
                        facts.values.insert(
                            index,
                            Pointer {
                                base: Base::Frame,
                                offset: offset as u64,
                                created_at: 0,
                            },
                        );
                    }
                }
            }
        }
        facts
    }

    fn discard_freshness(&mut self) {
        for pointer in self.values.values_mut() {
            pointer.created_at = usize::MAX;
            if let Base::Heap(time, _, size) = pointer.base {
                pointer.base = Base::Heap(time, true, size);
            }
        }
    }

    fn pointer(&self, value: &Expr) -> Option<Pointer> {
        match value {
            Expr::Reg { index, width: 64 } => self.values.get(index).copied(),
            Expr::Const(offset) => Some(Pointer {
                base: Base::Absolute,
                offset: *offset,
                created_at: 0,
            }),
            Expr::Bin { op, lhs, rhs } if matches!(op, BinOp::Add | BinOp::Sub) => {
                let Some(mut pointer) = self.pointer(lhs) else {
                    return None;
                };
                let Expr::Const(offset) = rhs.as_ref() else {
                    return None;
                };
                pointer.offset = if *op == BinOp::Add {
                    pointer.offset.wrapping_add(*offset)
                } else {
                    pointer.offset.wrapping_sub(*offset)
                };
                Some(pointer)
            }
            _ => None,
        }
    }

    pub(super) fn disjoint(&self, a: &Expr, b: &Expr, bytes: u64, ctx: &Ctx<'_>) -> bool {
        let (Some(a), Some(b)) = (self.pointer(a), self.pointer(b)) else {
            return false;
        };
        if a.base == b.base {
            return a.offset.wrapping_sub(b.offset) >= bytes
                && b.offset.wrapping_sub(a.offset) >= bytes;
        }
        let global = |p: Pointer| {
            p.base == Base::Absolute
                && ctx.data_ranges.iter().any(|(start, size)| {
                    let (Some(end), Some(limit)) =
                        (p.offset.checked_add(bytes), start.checked_add(*size))
                    else {
                        return false;
                    };
                    p.offset >= *start && end <= limit
                })
        };
        let frame = |p: Pointer| {
            p.base == Base::Frame
                && (p.offset as i64) < 0
                && i64::try_from(bytes)
                    .ok()
                    .and_then(|bytes| (p.offset as i64).checked_add(bytes))
                    .is_some_and(|end| end <= 0)
        };
        let fresh = |heap: Pointer, old: Pointer| match heap.base {
            Base::Heap(time, reallocated, Some(size))
                if heap
                    .offset
                    .checked_add(bytes)
                    .is_some_and(|end| end <= size) =>
            {
                frame(old)
                    || global(old)
                    || (!reallocated && old.created_at < time && old.offset == 0)
            }
            _ => false,
        };
        (global(a) && frame(b)) || (frame(a) && global(b)) || fresh(a, b) || fresh(b, a)
    }
}

pub(super) fn allocation_is_reallocated(name: &str) -> Option<bool> {
    let name = name.strip_prefix("__rustc::").unwrap_or(name);
    crate::analysis::prototypes::effects::lookup(name.trim_start_matches('_'))
        .and_then(|effects| effects.allocation)
        .map(|allocation| {
            allocation == crate::analysis::prototypes::effects::Allocation::Reallocated
        })
}

pub(super) fn frame_origins(ir: &crate::ir::FunctionIr) -> HashMap<u16, i64> {
    use super::stack_bytes::{origins, transfer};
    if !ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt,
        Stmt::Store { addr: Expr::Reg { .. }, value: Expr::Load { addr, .. }, .. }
            if matches!(addr.as_ref(), Expr::Reg { .. }))
    }) {
        return HashMap::new();
    }
    let entry = std::collections::BTreeMap::from([(crate::arch::stack_pointer(ir.isa), Some(0))]);
    let Some(entries) = origins(ir, &entry) else {
        return HashMap::new();
    };
    let mut found = HashMap::<u16, Option<i64>>::new();
    for (block, entry) in ir.blocks.iter().zip(entries) {
        let Some(mut state) = entry else {
            continue;
        };
        for stmt in &block.stmts {
            for index in crate::ir::visit::statement_registers(stmt).1 {
                let offset = state.get(&index).copied().flatten();
                found
                    .entry(index)
                    .and_modify(|previous| {
                        if *previous != offset {
                            *previous = None;
                        }
                    })
                    .or_insert(offset);
            }
            transfer(stmt, &mut state);
        }
    }
    found
        .into_iter()
        .filter_map(|(index, offset)| offset.map(|offset| (index, offset)))
        .collect()
}

fn allocation_size(name: &str, args: Option<&[Expr]>, facts: &Facts) -> Option<u64> {
    let Some(args) = args else {
        return None;
    };
    let constant = |index| match args.get(index).and_then(|arg| facts.pointer(arg)) {
        Some(Pointer {
            base: Base::Absolute,
            offset,
            ..
        }) => Some(offset),
        _ => None,
    };
    let name = name
        .strip_prefix("__rustc::")
        .unwrap_or(name)
        .trim_start_matches('_');
    use crate::analysis::prototypes::effects::{self, SizeRule};
    let rule = effects::lookup(name).map_or(SizeRule::Argument(0), |effects| effects.size);
    match rule {
        SizeRule::Product(first, second) => match (constant(first), constant(second)) {
            (Some(count), Some(size)) => count.checked_mul(size),
            _ => None,
        },
        SizeRule::Argument(index) => constant(index),
        SizeRule::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_effects_preserve_sizes_and_symbol_handling() {
        let facts = Facts {
            values: HashMap::new(),
        };
        let args = [
            Expr::Const(7),
            Expr::Const(11),
            Expr::Const(13),
            Expr::Const(17),
        ];
        for (name, reallocated, size) in [
            ("___malloc", false, Some(7)),
            ("calloc", false, Some(77)),
            ("realloc", true, Some(11)),
            ("__rustc::__rust_realloc", true, Some(17)),
            ("rdl_realloc", true, Some(17)),
            ("runtime.newobject", false, None),
        ] {
            assert_eq!(allocation_is_reallocated(name), Some(reallocated));
            assert_eq!(allocation_size(name, Some(&args), &facts), size);
        }
        assert_eq!(allocation_is_reallocated("unknown"), None);
        assert_eq!(allocation_size("unknown", Some(&args), &facts), Some(7));
        assert_eq!(allocation_size("malloc", None, &facts), None);
        let overflow = [Expr::Const(u64::MAX), Expr::Const(2)];
        assert_eq!(allocation_size("calloc", Some(&overflow), &facts), None);
    }
}
