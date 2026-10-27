//! SIMD structure loads, stores, and load-and-replicate forms.

use super::{
    BinOp, Expr, Instruction, Lifter, Operand, RegRef, Stmt, Write, a64, lane_value, mask_bits,
    memory, preserve_compare,
};

pub(super) fn lift(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use a64::Opcode as O;
    let (structures, store, replicate) = match ins.opcode {
        O::LD1 => (1, false, false),
        O::LD2 => (2, false, false),
        O::LD3 => (3, false, false),
        O::LD4 => (4, false, false),
        O::ST1 => (1, true, false),
        O::ST2 => (2, true, false),
        O::ST3 => (3, true, false),
        O::ST4 => (4, true, false),
        O::LD1R => (1, false, true),
        O::LD2R => (2, false, true),
        O::LD3R => (3, false, true),
        O::LD4R => (4, false, true),
        _ => return false,
    };
    let (first, count, full, element, lane_index) = match ins.operands[0] {
        Operand::SIMDRegisterGroup(size, first, element, count) => {
            (first, count, size == a64::SIMDSizeCode::Q, element, None)
        }
        Operand::SIMDRegisterGroupLane(first, element, count, lane_index) => {
            (first, count, true, element, Some(lane_index))
        }
        _ => {
            lifter.incomplete.set(true);
            return true;
        }
    };
    let bits = match element {
        a64::SIMDSizeCode::B => 8,
        a64::SIMDSizeCode::H => 16,
        a64::SIMDSizeCode::S => 32,
        a64::SIMDSizeCode::D => 64,
        _ => {
            lifter.incomplete.set(true);
            return true;
        }
    };
    if !(1..=4).contains(&count)
        || (structures != 1 && count != structures)
        || lane_index.is_some_and(|lane_index| u16::from(lane_index) * u16::from(bits) >= 128)
    {
        lifter.incomplete.set(true);
        return true;
    }
    let Some(mem) = memory::memory(ins.operands[1], 64) else {
        lifter.incomplete.set(true);
        return true;
    };
    let bytes = bits / 8;
    if store {
        preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    }
    let load = |offset| Expr::Load {
        addr: Box::new(Expr::bin(
            BinOp::Add,
            mem.address.clone(),
            Expr::constant(offset),
        )),
        width: bytes,
        signed: false,
    };
    for register_index in 0..count {
        let number = (first + u16::from(register_index)) % 32;
        let slot = crate::arch::aarch64::V0 + 2 * number;
        if let Some(lane_index) = lane_index {
            let shift = u64::from(lane_index) * u64::from(bits);
            let slot = slot + (shift / 64) as u16;
            let shift = shift % 64;
            let mask = mask_bits(u64::from(bits));
            if store {
                lifter.stmts.push(Stmt::Store {
                    addr: Expr::bin(
                        BinOp::Add,
                        mem.address.clone(),
                        Expr::constant(u64::from(register_index) * u64::from(bytes)),
                    ),
                    value: lane_value((slot, shift, u64::from(bits))),
                    width: bytes,
                });
            } else {
                let value = Expr::bin(
                    BinOp::Or,
                    Expr::bin(
                        BinOp::And,
                        Expr::reg(slot, 64),
                        Expr::constant(!(mask << shift)),
                    ),
                    Expr::bin(
                        BinOp::Shl,
                        load(u64::from(register_index) * u64::from(bytes)),
                        Expr::constant(shift),
                    ),
                );
                lifter.assign(
                    RegRef {
                        index: slot,
                        width: 64,
                    },
                    value,
                );
            }
        } else if replicate {
            let value = lifter.hold(load(u64::from(register_index) * u64::from(bytes)));
            let half = super::replicate(value, bits);
            lifter.write_vector((slot, full, bits), half.clone(), half);
        } else {
            let lanes = if full { 128 / bits } else { 64 / bits };
            let mut halves = [Expr::constant(0), Expr::constant(0)];
            for index in 0..lanes {
                let shift = u64::from(index) * u64::from(bits);
                let offset = if structures == 1 {
                    u64::from(register_index) * u64::from(lanes) + u64::from(index)
                } else {
                    u64::from(index) * u64::from(count) + u64::from(register_index)
                } * u64::from(bytes);
                if store {
                    lifter.stmts.push(Stmt::Store {
                        addr: Expr::bin(BinOp::Add, mem.address.clone(), Expr::constant(offset)),
                        value: lane_value((
                            slot + (shift / 64) as u16,
                            shift % 64,
                            u64::from(bits),
                        )),
                        width: bytes,
                    });
                } else {
                    let half = &mut halves[(shift / 64) as usize];
                    *half = Expr::bin(
                        BinOp::Or,
                        half.clone(),
                        Expr::bin(BinOp::Shl, load(offset), Expr::constant(shift % 64)),
                    );
                }
            }
            if !store {
                let [low, high] = halves;
                lifter.write_vector((slot, full, bits), low, high);
            }
        }
    }
    memory::write_back(lifter, mem.writeback);
    true
}
