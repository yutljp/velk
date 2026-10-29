use super::{Layout, List, address};
use crate::ir::{BinOp, Cond, Expr, FunctionIr, RegRef, Stmt};

/// In a 32-bit sum loop, the cached offset advances by eight until zero, then only the
/// stack pointer advances. Require the complete loop, including both updates.
pub(super) fn recover(ir: &mut FunctionIr, list: &List, argument: u16) -> bool {
    let Some(matched) = match_loop(ir, list, argument) else {
        return false;
    };
    matched.apply(ir);
    true
}

struct MatchedLoop {
    target: u64,
    initialization: Stmt,
    body: Vec<Stmt>,
}

fn match_loop(ir: &FunctionIr, list: &List, argument: u16) -> Option<MatchedLoop> {
    if !matches!(list.layout, Layout::Aapcs64)
        || list.floating
        || ir.blocks.len() != 10
        || !matches!(ir.ret_type.integer(), Some((32, _)))
    {
        return None;
    }
    let blocks = &ir.blocks;
    let [
        Stmt::Assign {
            dest: stack,
            value: stack_load,
            ..
        },
        Stmt::Assign {
            dest: top,
            value: top_load,
            ..
        },
        Stmt::Assign {
            dest: total,
            value: Expr::Const(0),
            ..
        },
        Stmt::Assign {
            dest: offset,
            value: offset_load,
            ..
        },
        Stmt::Br {
            target: Some(header),
            ..
        },
    ] = blocks[1].stmts.as_slice()
    else {
        return None;
    };
    let [
        Stmt::Assign {
            dest: next_stack, ..
        },
        Stmt::Assign { .. },
    ] = blocks[2].stmts.as_slice()
    else {
        return None;
    };
    let [
        Stmt::Assign {
            dest: next_offset, ..
        },
        Stmt::Br { .. },
    ] = blocks[5].stmts.as_slice()
    else {
        return None;
    };
    let [decrement, update_offset, consume, update_stack, exit] = blocks[3].stmts.as_slice() else {
        return None;
    };
    let Stmt::Assign {
        dest: count,
        value: decrement_value,
        ..
    } = decrement
    else {
        return None;
    };
    let registers = [stack, top, offset, next_stack, next_offset, total];
    if registers
        .iter()
        .any(|reg| reg.index == count.index || reg.index == list.sp)
        || [stack, top, offset, next_stack, total]
            .iter()
            .any(|reg| reg.width != 64)
        || next_offset.width != 32
        || count.width != 32
        || count.index == list.sp
        || registers
            .iter()
            .enumerate()
            .any(|(i, reg)| registers[..i].iter().any(|other| other.index == reg.index))
    {
        return None;
    }
    let register_expression = |reg: &RegRef| Expr::reg(reg.index, reg.width);
    let assign = |dest: &RegRef, value| Stmt::Assign {
        dest: *dest,
        value,
        at: None,
    };
    let branch = |block: usize| Stmt::Br {
        target: Some(blocks[block].start),
        at: None,
    };
    let load = |field, width| Expr::Load {
        addr: Box::new(address(list.sp, field)),
        width,
        signed: false,
    };
    let masked_offset = Expr::bin(
        BinOp::And,
        register_expression(offset),
        Expr::Const(0xffff_ffff),
    );
    if *header != blocks[4].start
        || *stack_load != load(list.stack(), 8)
        || *top_load != load(list.base + 8, 8)
        || *offset_load != load(list.gp_offset(), 4)
        || *decrement_value != Expr::bin(BinOp::Sub, register_expression(count), Expr::Const(1))
        || !same(
            update_offset,
            &assign(offset, register_expression(next_offset)),
        )
        || !same(
            update_stack,
            &assign(stack, register_expression(next_stack)),
        )
        || !same(
            exit,
            &Stmt::Brif {
                cond: Cond::Eq,
                lhs: register_expression(count),
                rhs: Expr::Const(0),
                target: blocks[9].start,
                at: None,
            },
        )
        || !same_block(
            &blocks[2].stmts,
            &[
                assign(next_stack, register_expression(stack)),
                assign(
                    stack,
                    Expr::bin(
                        BinOp::Add,
                        register_expression(top),
                        Expr::SignExtend {
                            value: Box::new(register_expression(offset)),
                            width: 4,
                        },
                    ),
                ),
            ],
        )
        || !same_block(
            &blocks[4].stmts,
            &[Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::bin(
                    BinOp::And,
                    register_expression(offset),
                    Expr::Const(0x8000_0000),
                ),
                rhs: Expr::Const(0),
                target: blocks[6].start,
                at: None,
            }],
        )
        || !same_block(
            &blocks[5].stmts,
            &[assign(next_offset, register_expression(offset)), branch(7)],
        )
        || !same_block(
            &blocks[6].stmts,
            &[
                assign(
                    next_offset,
                    Expr::bin(BinOp::Add, masked_offset.clone(), Expr::Const(8)),
                ),
                Stmt::Store {
                    addr: address(list.sp, list.gp_offset()),
                    value: register_expression(next_offset),
                    width: 4,
                    at: None,
                },
                Stmt::Brif {
                    cond: Cond::Ls,
                    lhs: masked_offset,
                    rhs: Expr::Const(0xffff_fff8),
                    target: blocks[2].start,
                    at: None,
                },
            ],
        )
        || !same_block(
            &blocks[7].stmts,
            &[
                assign(next_stack, address(stack.index, 8)),
                Stmt::Store {
                    addr: address(list.sp, list.stack()),
                    value: register_expression(next_stack),
                    width: 8,
                    at: None,
                },
                branch(3),
            ],
        )
    {
        return None;
    }
    // No other edge may enter the expansion, or bypass its initialization.
    let edges: Vec<_> = (0..blocks.len())
        .map(|b| {
            let mut edges = crate::ir::cfg::successors(ir, b);
            edges.sort_unstable();
            edges
        })
        .collect();
    if edges
        != vec![
            vec![1, 8],
            vec![4],
            vec![3],
            vec![4, 9],
            vec![5, 6],
            vec![7],
            vec![2, 7],
            vec![3],
            vec![9],
            vec![],
        ]
    {
        return None;
    }
    let Stmt::Assign { dest, value, .. } = consume else {
        return None;
    };
    if dest != total {
        return None;
    }
    let sum = |pointer| {
        Expr::bin(
            BinOp::And,
            Expr::bin(
                BinOp::Add,
                Expr::Load {
                    addr: Box::new(Expr::reg(pointer, 64)),
                    width: 4,
                    signed: false,
                },
                Expr::bin(
                    BinOp::And,
                    register_expression(total),
                    Expr::Const(0xffff_ffff),
                ),
            ),
            Expr::Const(0xffff_ffff),
        )
    };
    // Preserve the 32-bit sum; wider consumers need their own argument type proof.
    if *value != sum(stack.index) {
        return None;
    }
    let replacement = sum(argument);
    let [
        Stmt::Ret {
            value: returned, ..
        },
    ] = blocks[9].stmts.as_slice()
    else {
        return None;
    };
    if !same_block(&blocks[8].stmts, &[assign(total, Expr::Const(0))])
        || *returned
            != Expr::bin(
                BinOp::And,
                register_expression(total),
                Expr::Const(0xffff_ffff),
            )
    {
        return None;
    }

    let protocol = [
        stack.index,
        top.index,
        offset.index,
        next_stack.index,
        next_offset.index,
    ];
    for (block_index, block) in blocks.iter().enumerate() {
        for (position, stmt) in block.stmts.iter().enumerate() {
            if matches!(block_index, 2 | 4 | 5 | 6 | 7)
                || (block_index == 1 && matches!(position, 0 | 1 | 3 | 4))
                || (block_index == 3 && matches!(position, 1 | 3))
            {
                continue;
            }
            let rewritten = assign(total, replacement.clone());
            let stmt = if block_index == 3 && position == 2 {
                &rewritten
            } else {
                stmt
            };
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            if protocol
                .iter()
                .any(|reg| reads.contains(reg) || writes.contains(reg))
            {
                return None;
            }
        }
    }
    let target = blocks[3].start;
    let initialization = blocks[1].stmts[2].clone();
    let body = vec![decrement.clone(), assign(total, replacement), exit.clone()];
    Some(MatchedLoop {
        target,
        initialization,
        body,
    })
}

impl MatchedLoop {
    fn apply(self, ir: &mut FunctionIr) {
        let Self {
            target,
            initialization,
            body,
        } = self;
        ir.blocks[1].stmts = vec![
            initialization,
            Stmt::Br {
                target: Some(target),
                at: None,
            },
        ];
        ir.blocks[3].stmts = body;
        ir.blocks[4].stmts = vec![Stmt::Br {
            target: Some(target),
            at: None,
        }];
        let mut index = 0;
        ir.blocks.retain(|_| {
            let keep = !matches!(index, 2 | 5 | 6 | 7);
            index += 1;
            keep
        });
    }
}

fn same_block(actual: &[Stmt], expected: &[Stmt]) -> bool {
    actual.len() == expected.len() && actual.iter().zip(expected).all(|(a, b)| same(a, b))
}

fn same(a: &Stmt, b: &Stmt) -> bool {
    match (a, b) {
        (
            Stmt::Assign {
                dest: a, value: av, ..
            },
            Stmt::Assign {
                dest: b, value: bv, ..
            },
        ) => a == b && av == bv,
        (
            Stmt::Store {
                addr: a,
                value: av,
                width: aw,
                ..
            },
            Stmt::Store {
                addr: b,
                value: bv,
                width: bw,
                ..
            },
        ) => a == b && av == bv && aw == bw,
        (Stmt::Br { target: a, .. }, Stmt::Br { target: b, .. }) => a == b,
        (
            Stmt::Brif {
                cond: a,
                lhs: al,
                rhs: ar,
                target: at,
                ..
            },
            Stmt::Brif {
                cond: b,
                lhs: bl,
                rhs: br,
                target: bt,
                ..
            },
        ) => a == b && al == bl && ar == br && at == bt,
        _ => false,
    }
}
