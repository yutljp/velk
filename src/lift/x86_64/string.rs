use super::{
    BinOp, Block, Cond, Expr, Instruction, Lifter, Mnemonic, OpKind, RAX, RegRef, Stmt, Write,
    load_at, preserve_compare,
};

/// The bytes a string instruction moves at a time; None for a form the
/// lifter does not model, such as a 32-bit address size.
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
        OpKind::MemorySegRSI | OpKind::MemorySegDI | OpKind::MemoryESRDI => true,
        OpKind::MemoryESEDI | OpKind::MemorySegESI | OpKind::MemorySegEDI => false,
        _ => true,
    });
    (wide_addresses && !ins.has_repne_prefix()).then_some(size)
}

/// `movs`, `stos` and `lods`: one element moved, and the pointers past it,
/// with the direction flag clear. With `rep`, a loop: the instruction's own
/// block tests the count and leaves when it is zero, and a body after it
/// moves one element, counts it, and goes back to the test.
pub(super) fn lift_string(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use Mnemonic::*;
    let Some(size) = string_size(ins) else {
        return false;
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
    let advance = |index: u16| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value: Expr::bin(
            BinOp::Add,
            Expr::reg(index, 64),
            Expr::constant(u64::from(size)),
        ),
    };
    let mut step = Vec::new();
    match ins.mnemonic() {
        Movsb | Movsw | Movsd | Movsq => {
            step.push(Stmt::Store {
                addr: Expr::reg(rdi, 64),
                value: load_at(Expr::reg(rsi, 64), size),
                width: size,
            });
            step.extend([advance(rsi), advance(rdi)]);
        }
        Stosb | Stosw | Stosd | Stosq => {
            step.push(Stmt::Store {
                addr: Expr::reg(rdi, 64),
                value: Lifter::read_reg(RAX, size * 8),
                width: size,
            });
            step.push(advance(rdi));
        }
        _ => {
            let before = lifter.stmts.len();
            lifter.assign(RAX, size * 8, load_at(Expr::reg(rsi, 64), size));
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
        lhs: Expr::reg(rcx, 64),
        rhs: Expr::constant(0),
        target: ins.next_ip(),
    });
    step.push(Stmt::Assign {
        dest: RegRef {
            index: rcx,
            width: 64,
        },
        value: Expr::bin(BinOp::Sub, Expr::reg(rcx, 64), Expr::constant(1)),
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
