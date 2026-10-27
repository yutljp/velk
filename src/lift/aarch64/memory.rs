use super::{
    BinOp, Expr, Lifter, MemoryAccess, Operand, RegRef, SizeCode, Stmt, a64, destination,
    extend_shift, register_width, simd,
};

pub(super) struct Memory {
    pub(super) address: Expr,
    pub(super) writeback: Option<(RegRef, Expr)>,
}

pub(super) fn memory(operand: Operand, width: u8) -> Option<Memory> {
    match operand {
        Operand::RegPreIndex(reg, offset, writeback) => {
            let base = Expr::reg(reg, 64);
            let address = if offset == 0 {
                base
            } else {
                Expr::bin(BinOp::Add, base, Expr::constant(offset as i64 as u64))
            };
            let dest = RegRef {
                index: reg,
                width: 64,
            };
            Some(Memory {
                address: address.clone(),
                writeback: writeback.then_some((dest, address)),
            })
        }
        Operand::RegPostIndex(reg, offset) => {
            let base = Expr::reg(reg, 64);
            let updated = if offset == 0 {
                base.clone()
            } else {
                Expr::bin(
                    BinOp::Add,
                    base.clone(),
                    Expr::constant(offset as i64 as u64),
                )
            };
            Some(Memory {
                address: base,
                writeback: Some((
                    RegRef {
                        index: reg,
                        width: 64,
                    },
                    updated,
                )),
            })
        }
        Operand::RegPostIndexReg(reg, increment) => {
            let base = Expr::reg(reg, 64);
            Some(Memory {
                address: base.clone(),
                writeback: Some((
                    RegRef {
                        index: reg,
                        width: 64,
                    },
                    Expr::bin(BinOp::Add, base, Lifter::read_reg(increment, 64)),
                )),
            })
        }
        Operand::RegRegOffset(base_reg, index_reg, size, style, amount) => {
            let base = Expr::reg(base_reg, 64);
            let index_width = if size == SizeCode::X { 64 } else { 32 };
            let index = Lifter::read_reg(index_reg, index_width);
            let Some(index) = extend_shift(style, amount as u64, index, size) else {
                return None;
            };
            Some(Memory {
                address: Expr::bin(BinOp::Add, base, index),
                writeback: None,
            })
        }
        Operand::RegisterOrSP(_, 31) => Some(Memory {
            address: Expr::reg(31, 64),
            writeback: None,
        }),
        Operand::Register(_, index) => Some(Memory {
            address: Lifter::read_reg(index, width),
            writeback: None,
        }),
        _ => None,
    }
}

pub(super) fn write_back(lifter: &mut Lifter, writeback: Option<(RegRef, Expr)>) {
    if let Some((dest, value)) = writeback {
        lifter.assign(dest, value);
    }
}

pub(super) fn lift_load(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode, pc: u64) {
    let literal = if let Operand::PCOffset(offset) = ops[1] {
        let Some(address) = pc.checked_add_signed(offset) else {
            lifter
                .stmts
                .push(Stmt::unsupported("literal load address overflow"));
            return;
        };
        Some(address)
    } else {
        None
    };
    let load_memory = |width| {
        if let Some(address) = literal {
            Some(Memory {
                address: Expr::constant(address),
                writeback: None,
            })
        } else {
            memory(ops[1], width)
        }
    };
    if let Some((slot, bits)) = simd(ops[0]) {
        let Some(mem) = load_memory((bits / 8) as u8) else {
            lifter
                .stmts
                .push(Stmt::unsupported("load address".to_owned()));
            return;
        };
        let halves = simd_load(&mem.address, bits);
        lifter.write_simd(slot, bits, halves);
        write_back(lifter, mem.writeback);
        return;
    }
    // A load into the zero register discards the value but still writes
    // back its base.
    let Some(dest) = destination(ops[0]) else {
        let bytes = register_width(ops[0]).map_or(8, |bits| bits / 8);
        if let Some(mem) = load_memory(bytes) {
            write_back(lifter, mem.writeback);
        }
        return;
    };
    let (load_width, signed) = match opcode {
        a64::Opcode::LDR => (if dest.width == 64 { 8 } else { 4 }, false),
        a64::Opcode::LDRB => (1, false),
        a64::Opcode::LDRH => (2, false),
        a64::Opcode::LDRSB => (1, true),
        a64::Opcode::LDRSH => (2, true),
        a64::Opcode::LDRSW => (4, true),
        _ => (4, false),
    };
    let Some(mem) = load_memory(dest.width / 8) else {
        lifter
            .stmts
            .push(Stmt::unsupported("load address".to_owned()));
        return;
    };
    let value = Expr::Load {
        addr: Box::new(mem.address),
        width: load_width,
        signed,
    };
    lifter.assign(dest, value);
    write_back(lifter, mem.writeback);
}

pub(super) fn lift_store(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
    if let Some((slot, bits)) = simd(ops[0]) {
        let Some(mem) = memory(ops[1], (bits / 8) as u8) else {
            lifter
                .stmts
                .push(Stmt::unsupported("store address".to_owned()));
            return;
        };
        lifter.simd_store(slot, bits, &mem.address);
        write_back(lifter, mem.writeback);
        return;
    }
    let width = match opcode {
        a64::Opcode::STRB => 1,
        a64::Opcode::STRH => 2,
        _ => match register_width(ops[0]) {
            Some(bits) => bits / 8,
            None => {
                lifter
                    .stmts
                    .push(Stmt::unsupported("SIMD store".to_owned()));
                return;
            }
        },
    };
    let value_width = if width == 8 { 64 } else { 32 };
    let Some(value) = lifter.operand(ops[0], value_width) else {
        return;
    };
    let Some(mem) = memory(ops[1], width) else {
        lifter
            .stmts
            .push(Stmt::unsupported("store address".to_owned()));
        return;
    };
    lifter.stmts.push(Stmt::Store {
        addr: mem.address,
        value,
        width,
    });
    write_back(lifter, mem.writeback);
}

pub(super) fn lift_pair(lifter: &mut Lifter, ops: [Operand; 4], store: MemoryAccess, signed: bool) {
    let store = matches!(store, MemoryAccess::Store);
    if let (Some((first, bits)), Some((second, _))) = (simd(ops[0]), simd(ops[1])) {
        let Some(mem) = memory(ops[2], (bits / 8) as u8) else {
            return;
        };
        let second_addr = Expr::bin(
            BinOp::Add,
            mem.address.clone(),
            Expr::constant(u64::from(bits / 8)),
        );
        if store {
            lifter.simd_store(first, bits, &mem.address);
            lifter.simd_store(second, bits, &second_addr);
        } else {
            // Both loads read memory as it was before either write.
            let (a, b) = (simd_load(&mem.address, bits), simd_load(&second_addr, bits));
            lifter.write_simd(first, bits, a);
            lifter.write_simd(second, bits, b);
        }
        write_back(lifter, mem.writeback);
        return;
    }
    let (Some(first_bits), Some(second_bits)) = (register_width(ops[0]), register_width(ops[1]))
    else {
        // A vector pair touches registers the scalar IR does not model.
        lifter.stmts.push(Stmt::unsupported(if store {
            "SIMD vector pair store".to_owned()
        } else {
            "SIMD vector pair load".to_owned()
        }));
        return;
    };
    let Some(mem) = memory(ops[2], 8) else {
        return;
    };
    // ldpsw's elements are 32 bits, sign-extended into 64-bit registers.
    let width = if signed { 4 } else { first_bits / 8 };
    let second_addr = Expr::bin(
        BinOp::Add,
        mem.address.clone(),
        Expr::constant(width as u64),
    );
    if store {
        let (Some(a), Some(b)) = (
            lifter.operand(ops[0], first_bits),
            lifter.operand(ops[1], second_bits),
        ) else {
            return;
        };
        lifter.stmts.push(Stmt::Store {
            addr: mem.address,
            value: a,
            width,
        });
        lifter.stmts.push(Stmt::Store {
            addr: second_addr,
            value: b,
            width,
        });
    } else {
        let load = |addr: Expr| Expr::Load {
            addr: Box::new(addr),
            width,
            signed,
        };
        let (a, b) = (load(mem.address), load(second_addr));
        // The second address may read the register the first load writes.
        let b = match destination(ops[0]) {
            Some(first)
                if {
                    let mut read = std::collections::HashSet::new();
                    crate::ir::visit::collect_reads(&b, &mut read);
                    read.contains(&first.index)
                } =>
            {
                lifter.hold(b)
            }
            _ => b,
        };
        // A load into the zero register is discarded.
        if let Some(first) = destination(ops[0]) {
            lifter.assign(first, a);
        }
        if let Some(second) = destination(ops[1]) {
            lifter.assign(second, b);
        }
    }
    write_back(lifter, mem.writeback);
}

/// The low and high halves `bits` of memory at `address` fill.
fn simd_load(address: &Expr, bits: u16) -> (Expr, Expr) {
    let load = |addr: Expr, width: u8| Expr::Load {
        addr: Box::new(addr),
        width,
        signed: false,
    };
    if bits == 128 {
        let high = Expr::bin(BinOp::Add, address.clone(), Expr::constant(8));
        (load(address.clone(), 8), load(high, 8))
    } else {
        (load(address.clone(), (bits / 8) as u8), Expr::constant(0))
    }
}
