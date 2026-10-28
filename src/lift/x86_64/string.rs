use super::{
    BinOp, Block, Cond, Expr, Flags, Instruction, Lifter, Mnemonic, OpKind, RAX, RegRef, Stmt,
    Write, load_at, preserve_compare,
};

pub(in crate::lift) const STRING_FLAGS: u16 = crate::ir::TEMP_BASE + 0x4e;
pub(in crate::lift) const STRING_OVERFLOW: u16 = crate::ir::TEMP_BASE + 0x4f;

/// The element size of a string instruction with 32- or 64-bit addresses.
pub(super) fn string_size(ins: &Instruction) -> Option<u8> {
    use Mnemonic::*;
    let size = match ins.mnemonic() {
        Movsb | Stosb | Lodsb | Cmpsb | Scasb => 1,
        Movsw | Stosw | Lodsw | Cmpsw | Scasw => 2,
        Movsd | Stosd | Lodsd | Cmpsd | Scasd => 4,
        Movsq | Stosq | Lodsq | Cmpsq | Scasq => 8,
        _ => return None,
    };
    let mut string = false;
    for index in 0..ins.op_count() {
        match ins.op_kind(index) {
            OpKind::MemorySegDI | OpKind::MemorySegSI | OpKind::MemoryESDI => return None,
            OpKind::MemorySegRSI
            | OpKind::MemoryESRDI
            | OpKind::MemoryESEDI
            | OpKind::MemorySegESI
            | OpKind::MemorySegEDI => string = true,
            _ => {}
        }
    }
    string.then_some(size)
}

fn stored_flags() -> Flags {
    Flags::stored(
        Expr::reg(STRING_FLAGS, 64),
        Some(Expr::reg(STRING_OVERFLOW, 64)),
    )
}

fn save_flags(flags: Option<&Flags>, isa: crate::loader::Isa) -> Vec<Stmt> {
    let mut byte = Expr::constant(2);
    let unknown = || Expr::reg(crate::ir::TEMP_BASE + 0x50, 64);
    if let Some(flags) = flags {
        for (test, bit) in [
            (flags.test(Cond::Mi, isa), 7),
            (flags.test(Cond::Eq, isa), 6),
            (flags.adjust(), 4),
            (flags.parity(true), 2),
            (flags.test(Cond::Cc, isa), 0),
        ] {
            let value = test.select(Expr::constant(1 << bit), Expr::constant(0));
            byte = Expr::bin(BinOp::Or, byte, value.unwrap_or_else(unknown));
        }
    } else {
        byte = unknown();
    }
    let overflow = flags
        .and_then(|flags| {
            flags
                .test(Cond::Vs, isa)
                .select(Expr::constant(1), Expr::constant(0))
        })
        .unwrap_or_else(unknown);
    vec![
        Stmt::Assign {
            dest: RegRef {
                index: STRING_FLAGS,
                width: 64,
            },
            value: byte,
        },
        Stmt::Assign {
            dest: RegRef {
                index: STRING_OVERFLOW,
                width: 64,
            },
            value: overflow,
        },
    ]
}

/// String instructions execute one element at a time, including overlapping moves.
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
    let source = match ins.segment_prefix() {
        super::Register::FS => Expr::bin(
            BinOp::Add,
            Expr::reg(crate::arch::x86::FS_BASE, 64),
            read(6),
        ),
        super::Register::GS => Expr::bin(
            BinOp::Add,
            Expr::reg(crate::arch::x86::GS_BASE, 64),
            read(6),
        ),
        _ => read(6),
    };
    let narrow = |value| {
        if bits == 32 {
            Expr::bin(BinOp::And, value, Expr::constant(0xffff_ffff))
        } else {
            value
        }
    };
    let (rsi, rdi, rcx) = (6, 7, 1);
    let comparing = matches!(
        ins.mnemonic(),
        Cmpsb | Cmpsw | Cmpsd | Cmpsq | Scasb | Scasw | Scasd | Scasq
    );
    let repeated = ins.has_rep_prefix() || ins.has_repne_prefix();
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
                value: load_at(source, size),
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
        Lodsb | Lodsw | Lodsd | Lodsq => {
            let before = lifter.stmts.len();
            lifter.assign(RAX, size * 8, load_at(source, size));
            step.extend(lifter.stmts.drain(before..));
            step.push(advance(rsi));
        }
        _ => {
            let lhs = if matches!(ins.mnemonic(), Cmpsb | Cmpsw | Cmpsd | Cmpsq) {
                load_at(source, size)
            } else {
                Lifter::read_reg(RAX, size * 8)
            };
            let flags = Flags::difference(lhs, load_at(read(rdi), size));
            step.extend(save_flags(Some(&flags), lifter.image.isa));
            if matches!(ins.mnemonic(), Cmpsb | Cmpsw | Cmpsd | Cmpsq) {
                step.push(advance(rsi));
            }
            step.push(advance(rdi));
        }
    }
    if !repeated {
        lifter.stmts.extend(step);
        if comparing {
            lifter.set_flags(stored_flags());
        }
        return false;
    }
    if comparing {
        // Only a zero count needs the incoming flags. A nonempty comparison
        // sets them before any following instruction can read them.
        let initial = save_flags(lifter.last_compare.as_ref(), lifter.image.isa);
        for stmt in initial {
            if let Stmt::Assign { dest, value } = stmt {
                lifter.stmts.push(Stmt::Assign {
                    dest,
                    value: Expr::Select {
                        cond: Cond::Eq,
                        lhs: Box::new(read(rcx)),
                        rhs: Box::new(Expr::constant(0)),
                        then: Box::new(value),
                        els: Box::new(Expr::constant(0)),
                    },
                });
            }
        }
        lifter.set_flags(stored_flags());
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
    if comparing {
        let keep = Expr::Select {
            cond: if ins.has_repne_prefix() {
                Cond::Eq
            } else {
                Cond::Ne
            },
            lhs: Box::new(Expr::bin(
                BinOp::And,
                Expr::reg(STRING_FLAGS, 64),
                Expr::constant(64),
            )),
            rhs: Box::new(Expr::constant(0)),
            then: Box::new(read(rcx)),
            els: Box::new(Expr::constant(0)),
        };
        step.push(Stmt::Brif {
            cond: Cond::Ne,
            lhs: keep,
            rhs: Expr::constant(0),
            target: ins.ip() + 1,
        });
    } else {
        step.push(Stmt::Brif {
            cond: Cond::Ne,
            lhs: read(rcx),
            rhs: Expr::constant(0),
            target: ins.ip() + 1,
        });
    }
    lifter.extra.push((
        Block {
            start: ins.ip() + 1,
            stmts: step,
        },
        lifter.last_compare.clone(),
    ));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::{CONDITIONS, Proofs};
    use crate::loader::Isa;

    #[test]
    fn smt_saved_string_comparison_flags_preserve_conditions() {
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for bits in [8, 16, 32, 64] {
            for isa in [Isa::I386, Isa::X86_64] {
                let flags = Flags::difference(Expr::reg(0, bits), Expr::reg(1, bits));
                let assignments = save_flags(Some(&flags), isa);
                let [
                    Stmt::Assign { value: byte, .. },
                    Stmt::Assign {
                        value: overflow, ..
                    },
                ] = assignments.as_slice()
                else {
                    panic!("saved flags have two values");
                };
                let saved = Flags::stored(byte.clone(), Some(overflow.clone()));
                for condition in CONDITIONS {
                    let before = flags
                        .test(condition, isa)
                        .select(Expr::constant(1), Expr::constant(0))
                        .expect("comparison condition is known");
                    let after = saved
                        .test(condition, isa)
                        .select(Expr::constant(1), Expr::constant(0))
                        .expect("saved condition is known");
                    proofs.expression(
                        format!("string comparison flags/{isa:?}/{bits}/{condition:?}"),
                        &before,
                        &after,
                        64,
                    );
                }
            }
        }
        proofs.check();
    }
}
