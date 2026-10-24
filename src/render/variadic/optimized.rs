use super::{Layout, List, address};
use crate::ir::{BinOp, Cond, Expr, FunctionIr, RegRef, Stmt};

/// In a 32-bit sum loop, the cached offset advances by eight until zero, then only the
/// stack pointer advances. Require the complete loop, including both updates.
pub(super) fn recover(ir: &mut FunctionIr, list: &List, argument: u16) -> bool {
    if !matches!(list.layout, Layout::Aapcs64)
        || list.floating
        || ir.blocks.len() != 10
        || !matches!(ir.ret_type.integer(), Some((32, _)))
    {
        return false;
    }
    let blocks = &ir.blocks;
    let [
        Stmt::Assign {
            dest: stack,
            value: stack_load,
        },
        Stmt::Assign {
            dest: top,
            value: top_load,
        },
        Stmt::Assign {
            dest: total,
            value: Expr::Const(0),
        },
        Stmt::Assign {
            dest: offset,
            value: offset_load,
        },
        Stmt::Br {
            target: Some(header),
        },
    ] = blocks[1].stmts.as_slice()
    else {
        return false;
    };
    let [
        Stmt::Assign {
            dest: next_stack, ..
        },
        Stmt::Assign { .. },
    ] = blocks[2].stmts.as_slice()
    else {
        return false;
    };
    let [
        Stmt::Assign {
            dest: next_offset, ..
        },
        Stmt::Br { .. },
    ] = blocks[5].stmts.as_slice()
    else {
        return false;
    };
    let [decrement, update_offset, consume, update_stack, exit] = blocks[3].stmts.as_slice() else {
        return false;
    };
    let Stmt::Assign {
        dest: count,
        value: decrement_value,
    } = decrement
    else {
        return false;
    };
    let regs = [stack, top, offset, next_stack, next_offset, total];
    if regs
        .iter()
        .any(|reg| reg.index == count.index || reg.index == list.sp)
        || [stack, top, offset, next_stack, total]
            .iter()
            .any(|reg| reg.width != 64)
        || next_offset.width != 32
        || count.width != 32
        || count.index == list.sp
        || regs
            .iter()
            .enumerate()
            .any(|(i, reg)| regs[..i].iter().any(|other| other.index == reg.index))
    {
        return false;
    }
    let r = |reg: &RegRef| Expr::reg(reg.index, reg.width);
    let assign = |dest: &RegRef, value| Stmt::Assign { dest: *dest, value };
    let br = |block: usize| Stmt::Br {
        target: Some(blocks[block].start),
    };
    let load = |field, width| Expr::Load {
        addr: Box::new(address(list.sp, field)),
        width,
        signed: false,
    };
    let masked_offset = Expr::bin(BinOp::And, r(offset), Expr::Const(0xffff_ffff));
    if *header != blocks[4].start
        || *stack_load != load(list.stack(), 8)
        || *top_load != load(list.base + 8, 8)
        || *offset_load != load(list.gp_offset(), 4)
        || *decrement_value != Expr::bin(BinOp::Sub, r(count), Expr::Const(1))
        || !same(update_offset, &assign(offset, r(next_offset)))
        || !same(update_stack, &assign(stack, r(next_stack)))
        || !same(
            exit,
            &Stmt::Brif {
                cond: Cond::Eq,
                lhs: r(count),
                rhs: Expr::Const(0),
                target: blocks[9].start,
            },
        )
        || !same_block(
            &blocks[2].stmts,
            &[
                assign(next_stack, r(stack)),
                assign(
                    stack,
                    Expr::bin(
                        BinOp::Add,
                        r(top),
                        Expr::SignExtend {
                            value: Box::new(r(offset)),
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
                lhs: Expr::bin(BinOp::And, r(offset), Expr::Const(0x8000_0000)),
                rhs: Expr::Const(0),
                target: blocks[6].start,
            }],
        )
        || !same_block(&blocks[5].stmts, &[assign(next_offset, r(offset)), br(7)])
        || !same_block(
            &blocks[6].stmts,
            &[
                assign(
                    next_offset,
                    Expr::bin(BinOp::Add, masked_offset.clone(), Expr::Const(8)),
                ),
                Stmt::Store {
                    addr: address(list.sp, list.gp_offset()),
                    value: r(next_offset),
                    width: 4,
                },
                Stmt::Brif {
                    cond: Cond::Ls,
                    lhs: masked_offset,
                    rhs: Expr::Const(0xffff_fff8),
                    target: blocks[2].start,
                },
            ],
        )
        || !same_block(
            &blocks[7].stmts,
            &[
                assign(next_stack, address(stack.index, 8)),
                Stmt::Store {
                    addr: address(list.sp, list.stack()),
                    value: r(next_stack),
                    width: 8,
                },
                br(3),
            ],
        )
    {
        return false;
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
        return false;
    }
    let Stmt::Assign { dest, value } = consume else {
        return false;
    };
    if dest != total {
        return false;
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
                Expr::bin(BinOp::And, r(total), Expr::Const(0xffff_ffff)),
            ),
            Expr::Const(0xffff_ffff),
        )
    };
    // Preserve the 32-bit sum; wider consumers need their own argument type proof.
    if *value != sum(stack.index) {
        return false;
    }
    let replacement = sum(argument);
    let [Stmt::Ret { value: returned }] = blocks[9].stmts.as_slice() else {
        return false;
    };
    if !same_block(&blocks[8].stmts, &[assign(total, Expr::Const(0))])
        || *returned != Expr::bin(BinOp::And, r(total), Expr::Const(0xffff_ffff))
    {
        return false;
    }

    let protocol = [
        stack.index,
        top.index,
        offset.index,
        next_stack.index,
        next_offset.index,
    ];
    for (b, block) in blocks.iter().enumerate() {
        for (p, stmt) in block.stmts.iter().enumerate() {
            if matches!(b, 2 | 4 | 5 | 6 | 7)
                || (b == 1 && matches!(p, 0 | 1 | 3 | 4))
                || (b == 3 && matches!(p, 1 | 3))
            {
                continue;
            }
            let rewritten = assign(total, replacement.clone());
            let stmt = if b == 3 && p == 2 { &rewritten } else { stmt };
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            if protocol
                .iter()
                .any(|reg| reads.contains(reg) || writes.contains(reg))
            {
                return false;
            }
        }
    }
    let target = blocks[3].start;
    let init = blocks[1].stmts[2].clone();
    let body = vec![decrement.clone(), assign(total, replacement), exit.clone()];
    ir.blocks[1].stmts = vec![
        init,
        Stmt::Br {
            target: Some(target),
        },
    ];
    ir.blocks[3].stmts = body;
    ir.blocks[4].stmts = vec![Stmt::Br {
        target: Some(target),
    }];
    let mut index = 0;
    ir.blocks.retain(|_| {
        let keep = !matches!(index, 2 | 5 | 6 | 7);
        index += 1;
        keep
    });
    true
}

fn same_block(actual: &[Stmt], expected: &[Stmt]) -> bool {
    actual.len() == expected.len() && actual.iter().zip(expected).all(|(a, b)| same(a, b))
}

fn same(a: &Stmt, b: &Stmt) -> bool {
    match (a, b) {
        (Stmt::Assign { dest: a, value: av }, Stmt::Assign { dest: b, value: bv }) => {
            a == b && av == bv
        }
        (
            Stmt::Store {
                addr: a,
                value: av,
                width: aw,
            },
            Stmt::Store {
                addr: b,
                value: bv,
                width: bw,
            },
        ) => a == b && av == bv && aw == bw,
        (Stmt::Br { target: a }, Stmt::Br { target: b }) => a == b,
        (
            Stmt::Brif {
                cond: a,
                lhs: al,
                rhs: ar,
                target: at,
            },
            Stmt::Brif {
                cond: b,
                lhs: bl,
                rhs: br,
                target: bt,
            },
        ) => a == b && al == bl && ar == br && at == bt,
        _ => false,
    }
}
