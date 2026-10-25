use super::{
    BinOp, Block, Cond, Expr, Instruction, Lifter, Mnemonic, OpKind, RAX, RegRef, Stmt, Write,
    load_at, preserve_compare,
};

/// The bytes a string instruction moves at a time; None for a form the
/// lifter does not model, such as a 16-bit address size.
pub(super) fn string_size(ins: &Instruction) -> Option<u8> {
    use Mnemonic::*;
    let size = match ins.mnemonic() {
        Movsb | Stosb | Lodsb => 1,
        Movsw | Stosw | Lodsw => 2,
        Movsd | Stosd | Lodsd => 4,
        Movsq | Stosq | Lodsq => 8,
        _ => return None,
    };
    let wide_addresses = (0..ins.op_count()).all(|index| match ins.op_kind(index) {
        OpKind::MemorySegRSI | OpKind::MemoryESRDI => true,
        OpKind::MemorySegDI | OpKind::MemorySegSI | OpKind::MemoryESDI => false,
        _ => true,
    });
    (wide_addresses && !ins.has_repne_prefix()).then_some(size)
}

/// `movs`, `stos` and `lods`: one element moved, and the pointers past it,
/// following the direction flag. With `rep`, a loop: the instruction's own
/// block tests the count and leaves when it is zero, and a body after it
/// moves one element, counts it, and goes back to the test.
pub(super) fn lift_string(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use Mnemonic::*;
    let Some(size) = string_size(ins) else {
        return false;
    };
    let bits = if (0..ins.op_count()).any(|index| {
        matches!(
            ins.op_kind(index),
            OpKind::MemoryESEDI | OpKind::MemorySegESI | OpKind::MemorySegEDI
        )
    }) {
        32
    } else {
        64
    };
    let read = |index| Lifter::read_reg(index, bits);
    let narrow = |value| {
        if bits == 32 {
            Expr::bin(BinOp::And, value, Expr::constant(0xffff_ffff))
        } else {
            value
        }
    };
    let (rsi, rdi, rcx) = (6, 7, 1);
    // The pointers and the count may be what the flags were set from.
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    for index in [rsi, rdi, rcx, RAX] {
        preserve_compare(
            &mut lifter.last_compare,
            Write::Register(index, None),
            &mut lifter.stmts,
        );
    }
    let increment = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(Expr::reg(super::DIRECTION, 64)),
        rhs: Box::new(Expr::constant(0)),
        then: Box::new(Expr::constant(u64::from(size))),
        els: Box::new(Expr::constant(0u64.wrapping_sub(u64::from(size)))),
    };
    let advance = |index: u16| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value: narrow(Expr::bin(BinOp::Add, read(index), increment.clone())),
    };
    let mut step = Vec::new();
    match ins.mnemonic() {
        Movsb | Movsw | Movsd | Movsq => {
            step.push(Stmt::Store {
                addr: read(rdi),
                value: load_at(read(rsi), size),
                width: size,
            });
            step.extend([advance(rsi), advance(rdi)]);
        }
        Stosb | Stosw | Stosd | Stosq => {
            step.push(Stmt::Store {
                addr: read(rdi),
                value: Lifter::read_reg(RAX, size * 8),
                width: size,
            });
            step.push(advance(rdi));
        }
        _ => {
            let before = lifter.stmts.len();
            lifter.assign(RAX, size * 8, load_at(read(rsi), size));
            step.extend(lifter.stmts.drain(before..));
            step.push(advance(rsi));
        }
    }
    if !ins.has_rep_prefix() {
        lifter.stmts.extend(step);
        return false;
    }
    lifter.stmts.push(Stmt::Brif {
        cond: Cond::Eq,
        lhs: read(rcx),
        rhs: Expr::constant(0),
        target: ins.next_ip(),
    });
    step.push(Stmt::Assign {
        dest: RegRef {
            index: rcx,
            width: 64,
        },
        value: narrow(Expr::bin(BinOp::Sub, read(rcx), Expr::constant(1))),
    });
    step.push(Stmt::Br {
        target: Some(ins.ip()),
    });
    lifter.extra.push(Block {
        start: ins.ip() + 1,
        stmts: step,
    });
    true
}
