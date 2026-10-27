//! Decodes and lifts little-endian A32 and T32 instructions.

mod additional;

use std::collections::HashSet;

use yaxpeax_arm::armv7::{self, Instruction, Opcode, Operand, RegShiftStyle, ShiftStyle};

use super::flags::{Flags, Test};
use super::{Decoded, Machine, Summaries, Write};
use crate::error::LiftError;
use crate::ir::{BinOp, Block, CallKind, Cond, Expr, RegRef, Stmt};
use crate::loader::{ArmMode, Image, Isa};

pub(crate) fn position_independent_instruction(bytes: &[u8]) -> bool {
    matches!(
        additional::decode(bytes, crate::loader::ArmMode::Arm),
        Some(
            additional::Instruction::Extend { .. }
                | additional::Instruction::Divide { .. }
                | additional::Instruction::Bitfield { .. }
                | additional::Instruction::Reverse { .. }
                | additional::Instruction::HalfMultiply { .. }
        )
    )
}

pub(super) enum Step {
    Guard {
        condition: Cond,
        target: u64,
    },
    Execute {
        instruction: Instruction,
        additional: Option<additional::Instruction>,
        pc: u64,
        next: u64,
        target: Option<u64>,
    },
}

fn signed(value: u32, bits: u32) -> i64 {
    i64::from((value << (32 - bits)) as i32 >> (32 - bits))
}

fn target(instruction: &Instruction, bytes: &[u8], pc: u64) -> Option<u64> {
    if !matches!(
        instruction.opcode,
        Opcode::B | Opcode::BL | Opcode::BLX | Opcode::CBZ | Opcode::CBNZ
    ) {
        return None;
    }
    if matches!(instruction.operands[0], Operand::Reg(_))
        && !matches!(instruction.opcode, Opcode::CBZ | Opcode::CBNZ)
    {
        return None;
    }
    let [first, second, ..] = bytes else {
        return None;
    };
    let half = u32::from(u16::from_le_bytes([*first, *second]));
    let offset = if !instruction.thumb {
        let [a, b, c, d, ..] = bytes else {
            return None;
        };
        let word = u32::from_le_bytes([*a, *b, *c, *d]);
        signed((word & 0xffffff) << 2, 26)
            + 8
            + if instruction.opcode == Opcode::BLX {
                i64::from((word >> 23) & 2)
            } else {
                0
            }
    } else if !instruction.wide {
        if matches!(instruction.opcode, Opcode::CBZ | Opcode::CBNZ) {
            i64::from(((half >> 3) & 0x1f) * 2 + ((half >> 9) & 1) * 64) + 4
        } else if half & 0xf000 == 0xd000 {
            signed((half & 255) << 1, 9) + 4
        } else {
            signed((half & 2047) << 1, 12) + 4
        }
    } else {
        let [_, _, third, fourth, ..] = bytes else {
            return None;
        };
        let low = u32::from(u16::from_le_bytes([*third, *fourth]));
        let s = (half >> 10) & 1;
        let j1 = (low >> 13) & 1;
        let j2 = (low >> 11) & 1;
        if low & 0xd000 == 0x8000 {
            signed(
                s << 20 | j2 << 19 | j1 << 18 | (half & 63) << 12 | (low & 2047) << 1,
                21,
            ) + 4
        } else {
            signed(
                s << 24
                    | (1 ^ j1 ^ s) << 23
                    | (1 ^ j2 ^ s) << 22
                    | (half & 1023) << 12
                    | (low & 2047) << 1,
                25,
            ) + 4
        }
    };
    let base = if instruction.thumb && instruction.opcode == Opcode::BLX {
        pc & !3
    } else {
        pc
    };
    Some((base as u32).wrapping_add(offset as u32) as u64 & !1)
}

fn decode(image: &Image, bytes: &[u8], addr: u64) -> (Vec<Decoded<Step>>, Option<String>) {
    use yaxpeax_arch::{Decoder, ReaderBuilder};

    let mut decoded = Vec::new();
    let mut offset = 0;
    let mut it = 0u8;
    while offset < bytes.len() {
        let Some(pc) = addr.checked_add(offset as u64) else {
            return (decoded, Some("ARM instruction address overflow".into()));
        };
        let mode = image.arm_mode(pc & !1);
        if mode == ArmMode::Data {
            offset += 1;
            continue;
        }
        let decoder = armv7::InstDecoder::default()
            .allow_nonconforming(false)
            .with_thumb_mode(mode == ArmMode::Thumb);
        let mut reader = ReaderBuilder::<u32, u8>::read_at(&bytes[offset..], 0);
        let extra = additional::decode(&bytes[offset..], mode);
        let mut instruction = match decoder.decode(&mut reader) {
            Ok(instruction) => instruction,
            Err(_) if mode == ArmMode::Arm && double_literal(&bytes[offset..]).is_some() => {
                double_literal(&bytes[offset..]).expect("validated double-word literal encoding")
            }
            Err(_) if extra.is_some() => Instruction {
                condition: if mode == ArmMode::Thumb {
                    armv7::ConditionCode::AL
                } else {
                    additional::condition(bytes[offset + 3] >> 4)
                },
                thumb: mode == ArmMode::Thumb,
                wide: mode == ArmMode::Thumb,
                ..Instruction::default()
            },
            Err(error) => {
                return (
                    decoded,
                    Some(format!("undecodable ARM instruction at 0x{pc:x}: {error}")),
                );
            }
        };
        let len = if instruction.thumb && !instruction.wide {
            2
        } else {
            4
        };
        let Some(next) = pc.checked_add(len as u64) else {
            return (
                decoded,
                Some(format!("ARM instruction address overflow at 0x{pc:x}")),
            );
        };
        let mut condition = Cond::from_code(instruction.condition as u8);
        if instruction.opcode == Opcode::IT {
            if it != 0 {
                return (decoded, Some(format!("nested IT at 0x{pc:x}")));
            }
            let [Operand::Imm32(cond), Operand::Imm32(mask), ..] = instruction.operands else {
                return (decoded, Some(format!("invalid IT at 0x{pc:x}")));
            };
            it = ((cond << 4) | mask) as u8;
        } else if it != 0 {
            condition = Cond::from_code(it >> 4);
            // Narrow Thumb arithmetic implicitly sets flags only outside IT.
            if !instruction.wide
                && !matches!(instruction.opcode, Opcode::CMP | Opcode::CMN | Opcode::TST)
            {
                instruction.s = false;
            }
            it = if it & 7 == 0 {
                0
            } else {
                (it & 0xe0) | ((it << 1) & 0x1f)
            };
        }
        let destination = image
            .relocations
            .get(&pc)
            .map(|value| value & !1)
            .or_else(|| target(&instruction, &bytes[offset..], pc));
        let body = if let Some(cond) = condition {
            decoded.push(Decoded {
                pc,
                next: pc + 1,
                instruction: Step::Guard {
                    condition: cond.invert(),
                    target: next,
                },
            });
            pc + 1
        } else {
            pc
        };
        decoded.push(Decoded {
            pc: body,
            next,
            instruction: Step::Execute {
                instruction,
                additional: extra,
                pc,
                next,
                target: destination,
            },
        });
        offset += len;
    }
    let stop = (it != 0).then(|| "truncated ARM IT block".into());
    (decoded, stop)
}

pub(super) fn lift(
    image: &Image,
    addr: u64,
    bytes: &[u8],
    targets: &HashSet<u64>,
    summaries: Summaries<'_>,
) -> Result<Vec<Block>, LiftError> {
    lift_in_mode(
        image,
        addr,
        bytes,
        targets,
        summaries,
        super::execution::Mode::Analysis,
    )
}

pub(super) fn lift_in_mode(
    image: &Image,
    addr: u64,
    bytes: &[u8],
    targets: &HashSet<u64>,
    summaries: Summaries<'_>,
    mode: super::execution::Mode,
) -> Result<Vec<Block>, LiftError> {
    if !matches!(
        image.format,
        crate::loader::Format::Elf | crate::loader::Format::Raw
    ) || image.byte_order() != Some(object::Endianness::Little)
        || addr > u64::from(u32::MAX)
        || addr
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > u64::from(u32::MAX) + 1)
    {
        return Err(LiftError::UnsupportedIsa);
    }
    let blocks = super::lift_continuing(
        image,
        summaries,
        || {
            super::execution::Located::new(
                Lifter {
                    image,
                    summaries,
                    stmts: Vec::new(),
                    flags: None,
                    float_comparison: false,
                    touched: false,
                },
                mode,
            )
        },
        addr,
        bytes,
        &|bytes, address| decode(image, bytes, address),
        targets,
    );
    match blocks {
        Ok(mut blocks) => {
            if unsupported_declaration(image, addr)
                && let Some(entry) = blocks.first_mut()
            {
                entry.stmts.insert(
                    0,
                    Stmt::unsupported("AAPCS32 multiword, floating-point or aggregate declaration"),
                );
            }
            Ok(blocks)
        }
        Err(error) => Err(error),
    }
}

fn unsupported_declaration(image: &Image, address: u64) -> bool {
    let Some(types) = crate::loader::dwarf::function_types(image, address) else {
        return false;
    };
    !crate::analysis::abi::aapcs32_words(&types)
}

pub(crate) fn listing(image: &Image, bytes: &[u8], addr: u64, max: usize) -> Vec<String> {
    let (decoded, stop) = decode(image, bytes, addr);
    let mut lines: Vec<_> = decoded
        .iter()
        .filter_map(|d| match &d.instruction {
            Step::Execute {
                instruction,
                additional,
                pc,
                ..
            } => Some(match additional {
                Some(extra) => {
                    let text = extra.to_string();
                    let (mnemonic, operands) = text.split_once(' ').unwrap_or((&text, ""));
                    format!("0x{pc:<12x} {mnemonic}{} {operands}", instruction.condition)
                }
                None => format!("0x{pc:<12x} {instruction}"),
            }),
            _ => None,
        })
        .take(max)
        .collect();
    if lines.len() < max
        && let Some(stop) = stop
    {
        lines.push(stop);
    }
    lines
}

struct Lifter<'a> {
    image: &'a Image,
    summaries: Summaries<'a>,
    stmts: Vec<Stmt>,
    flags: Option<Flags>,
    float_comparison: bool,
    touched: bool,
}

pub(super) fn low(value: Expr) -> Expr {
    Expr::bin(BinOp::And, value, Expr::constant(0xffff_ffff))
}

fn extend(value: Expr, width: u8, signed: bool, rotation: u8) -> Expr {
    let value = super::rotate(
        value,
        Expr::constant(u64::from(rotation)),
        32,
        /* right */ true,
    );
    if signed {
        Expr::SignExtend {
            value: Box::new(value),
            width,
        }
    } else {
        Expr::bin(BinOp::And, value, Expr::constant((1u64 << (width * 8)) - 1))
    }
}

fn bitfield(value: Expr, start: u64, width: u64) -> Expr {
    let shifted = Expr::bin(BinOp::Shr, value, Expr::constant(start));
    Expr::bin(BinOp::And, shifted, Expr::constant((1u64 << width) - 1))
}

fn literal(image: &Image, addr: &Expr, width: u8, signed: bool) -> Option<Expr> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let Expr::Const(address) = addr else {
        return None;
    };
    let Some(end) = address.checked_add(u64::from(width)) else {
        return None;
    };
    if !image
        .literal_sections
        .iter()
        .any(|section| section.contains(address) && end <= section.end)
        || image
            .literal_relocations
            .range(address.saturating_sub(7)..end)
            .next()
            .is_some()
    {
        return None;
    }
    let Some(bytes) = image.read_vaddr(*address, u64::from(width)) else {
        return None;
    };
    let mut value = 0;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    Some(if signed {
        Expr::SignExtend {
            value: Box::new(Expr::constant(value)),
            width,
        }
    } else {
        Expr::constant(value)
    })
}

fn double_literal(bytes: &[u8]) -> Option<Instruction> {
    let [a, b, c, d, ..] = bytes else { return None };
    let word = u32::from_le_bytes([*a, *b, *c, *d]);
    let register = ((word >> 12) & 15) as u8;
    if word >> 28 >= 15 || word & 0x0f7f_00f0 != 0x014f_00d0 || register & 1 != 0 || register >= 14
    {
        return None;
    }
    Some(Instruction {
        condition: additional::condition((word >> 28) as u8),
        opcode: Opcode::LDRD,
        operands: [
            Operand::Reg(armv7::Reg::from_u8(register)),
            Operand::Reg(armv7::Reg::from_u8(register + 1)),
            Operand::RegDerefPreindexOffset(
                armv7::Reg::from_u8(15),
                (((word >> 4) & 0xf0) | (word & 15)) as u16,
                word & (1 << 23) != 0,
                false,
            ),
            Operand::Nothing,
        ],
        ..Instruction::default()
    })
}

pub(crate) fn fold_literals(ir: &mut crate::ir::FunctionIr, image: &Image) {
    if image.literal_sections.is_empty() {
        return;
    }
    fn fold(expr: &mut Expr, image: &Image) {
        for child in crate::ir::visit::children_mut(expr) {
            fold(child, image);
        }
        if let Expr::Load {
            addr,
            width,
            signed,
        } = expr
            && let Some(value) = literal(image, addr, *width, *signed)
        {
            *expr = value;
        }
    }
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Assign { value, .. } | Stmt::Ret { value } => fold(value, image),
                Stmt::Store { addr, value, .. } => {
                    fold(addr, image);
                    fold(value, image);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    fold(lhs, image);
                    fold(rhs, image);
                }
                Stmt::Call { through, args, .. } => {
                    if let Some(through) = through {
                        fold(through, image);
                    }
                    for arg in args.iter_mut().flatten() {
                        fold(arg, image);
                    }
                }
                _ => {}
            }
        }
    }
}

fn divide(left: Expr, right: Expr, signed: bool) -> Expr {
    let operand = |value| {
        if signed {
            Expr::SignExtend {
                value: Box::new(value),
                width: 4,
            }
        } else {
            low(value)
        }
    };
    let right = operand(right);
    Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(right.clone()),
        rhs: Box::new(Expr::constant(0)),
        then: Box::new(Expr::constant(0)),
        els: Box::new(Expr::bin(
            if signed { BinOp::DivS } else { BinOp::DivU },
            operand(left),
            right,
        )),
    }
}

impl Lifter<'_> {
    fn read(index: u8, pc: u64, thumb: bool) -> Expr {
        if index == 15 {
            Expr::constant((pc as u32).wrapping_add(if thumb { 4 } else { 8 }) as u64)
        } else {
            Expr::reg(u16::from(index), if index == 13 { 64 } else { 32 })
        }
    }

    fn operand(&self, op: Operand, pc: u64, thumb: bool) -> Option<Expr> {
        let carry = self
            .flags
            .as_ref()
            .map_or(Test::Unknown, |flags| flags.test(Cond::Cs, Isa::Arm32))
            .select(Expr::constant(1), Expr::constant(0));
        Self::operand_value(op, pc, thumb, carry.as_ref())
    }

    fn operand_value(op: Operand, pc: u64, thumb: bool, carry: Option<&Expr>) -> Option<Expr> {
        match op {
            Operand::Reg(reg) => Some(Self::read(reg.number(), pc, thumb)),
            Operand::Imm12(value) => Some(Expr::constant(u64::from(value))),
            Operand::Imm32(value) => Some(Expr::constant(u64::from(value))),
            Operand::RegShift(shift) => {
                let (reg, style, amount) = match shift.into_shift() {
                    RegShiftStyle::RegImm(shift) => (
                        shift.shiftee(),
                        shift.stype(),
                        Expr::constant(u64::from(shift.imm())),
                    ),
                    RegShiftStyle::RegReg(shift) => (
                        shift.shiftee(),
                        shift.stype(),
                        Expr::bin(
                            BinOp::And,
                            Self::read(shift.shifter().number(), pc, thumb),
                            Expr::constant(255),
                        ),
                    ),
                };
                let value = Self::read(reg.number(), pc, thumb);
                if style == ShiftStyle::RRX {
                    let Some(carry) = carry else { return None };
                    Some(Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::Shr, value, Expr::constant(1)),
                        Expr::bin(BinOp::Shl, carry.clone(), Expr::constant(31)),
                    ))
                } else {
                    shift_value(value, style, amount)
                }
            }
            _ => None,
        }
    }

    fn assign(&mut self, index: u8, value: Expr) {
        let index = u16::from(index);
        super::preserve_compare(
            &mut self.flags,
            Write::Register(index, Some(&value)),
            &mut self.stmts,
        );
        // Stack analysis uses full-width IR registers; ARM values remain 32-bit.
        let frame = matches!(index, 7 | 11)
            && match &value {
                Expr::Reg {
                    index: 13,
                    width: 64,
                } => true,
                Expr::Bin { lhs, .. } => matches!(
                    lhs.as_ref(),
                    Expr::Reg {
                        index: 13,
                        width: 64
                    }
                ),
                _ => false,
            };
        let value = if index == 13 || frame {
            value
        } else {
            low(value)
        };
        self.stmts.push(Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        });
    }

    fn memory(&self, op: Operand, pc: u64, thumb: bool) -> Option<(Expr, Option<(u8, Expr)>)> {
        let (base, offset, add, pre, back) = match op {
            Operand::RegDeref(reg) => (reg, Expr::constant(0), true, true, false),
            Operand::RegDerefPreindexOffset(reg, offset, add, back) => {
                (reg, Expr::constant(u64::from(offset)), add, true, back)
            }
            Operand::RegDerefPostindexOffset(reg, offset, add, _) => {
                (reg, Expr::constant(u64::from(offset)), add, false, true)
            }
            Operand::RegDerefPreindexReg(reg, offset, add, back) => {
                (reg, Self::read(offset.number(), pc, thumb), add, true, back)
            }
            Operand::RegDerefPostindexReg(reg, offset, add, _) => (
                reg,
                Self::read(offset.number(), pc, thumb),
                add,
                false,
                true,
            ),
            Operand::RegDerefPreindexRegShift(reg, offset, add, back) => {
                let Some(offset) = self.operand(Operand::RegShift(offset), pc, thumb) else {
                    return None;
                };
                (reg, offset, add, true, back)
            }
            Operand::RegDerefPostindexRegShift(reg, offset, add, _) => {
                let Some(offset) = self.operand(Operand::RegShift(offset), pc, thumb) else {
                    return None;
                };
                (reg, offset, add, false, true)
            }
            _ => return None,
        };
        let number = base.number();
        let base = if matches!(number, 7 | 11 | 13) {
            Expr::reg(u16::from(number), 64)
        } else if number == 15 && thumb {
            Expr::constant(u64::from((pc as u32).wrapping_add(4) & !3))
        } else {
            Self::read(number, pc, thumb)
        };
        let adjusted = Expr::bin(
            if add { BinOp::Add } else { BinOp::Sub },
            base.clone(),
            offset,
        );
        let adjusted = if matches!(number, 7 | 11 | 13) {
            adjusted
        } else {
            low(adjusted)
        };
        Some((
            if pre { adjusted.clone() } else { base },
            back.then_some((number, adjusted)),
        ))
    }

    // Failure here rejects this entire instruction; step discards any partial statements.
    fn execute(
        &mut self,
        instruction: &Instruction,
        pc: u64,
        next: u64,
        target: Option<u64>,
    ) -> Option<bool> {
        if matches!(instruction.opcode, Opcode::BL | Opcode::BLX) {
            self.float_comparison = false;
        }
        let [a, b, c, d] = instruction.operands;
        let carry = self
            .flags
            .as_ref()
            .map_or(Test::Unknown, |flags| flags.test(Cond::Cs, Isa::Arm32))
            .select(Expr::constant(1), Expr::constant(0));
        let overflow = self
            .flags
            .as_ref()
            .map_or(Test::Unknown, |flags| flags.test(Cond::Vs, Isa::Arm32))
            .select(Expr::constant(1), Expr::constant(0));
        let operand = |op| Self::operand_value(op, pc, instruction.thumb, carry.as_ref());
        match instruction.opcode {
            Opcode::NOP | Opcode::IT => {}
            Opcode::B => {
                self.stmts.push(Stmt::Br { target });
                return Some(true);
            }
            Opcode::CBZ | Opcode::CBNZ => {
                let (Some(lhs), Some(target)) = (operand(a), target) else {
                    return None;
                };
                self.stmts.push(Stmt::Brif {
                    cond: if instruction.opcode == Opcode::CBZ {
                        Cond::Eq
                    } else {
                        Cond::Ne
                    },
                    lhs,
                    rhs: Expr::constant(0),
                    target,
                });
                return Some(true);
            }
            Opcode::BX if matches!(a, Operand::Reg(reg) if reg.number() == 14) => {
                self.stmts.push(Stmt::Ret {
                    value: Expr::reg(0, 32),
                });
                return Some(true);
            }
            Opcode::BX => {
                let Some(value) = operand(a) else {
                    return None;
                };
                self.stmts.push(Stmt::BrIndirect { target: low(value) });
                return Some(true);
            }
            Opcode::BL | Opcode::BLX => {
                if target.is_some_and(|target| unsupported_declaration(self.image, target)) {
                    self.stmts
                        .push(Stmt::unsupported("AAPCS32 callee declaration"));
                }
                let through = if target.is_none() {
                    let Some(value) = operand(a) else {
                        return None;
                    };
                    Some(low(value))
                } else {
                    None
                };
                if let Some(through) = through {
                    // Capture a target in lr before the call writes its link.
                    self.assign_temp(through);
                    self.assign(14, Expr::constant(next | u64::from(instruction.thumb)));
                    self.stmts.push(super::call_through(
                        CallKind::Invoke,
                        self.image,
                        Expr::reg(crate::ir::EXCHANGE, 64),
                    ));
                } else {
                    self.assign(14, Expr::constant(next | u64::from(instruction.thumb)));
                    self.stmts.push(super::call(
                        CallKind::Invoke,
                        self.image,
                        self.summaries,
                        target,
                    ));
                }
                self.flags = None;
                self.touched = true;
            }
            Opcode::MOV | Opcode::MVN | Opcode::MOVT => {
                let Operand::Reg(reg) = a else {
                    return None;
                };
                if reg.number() == 15 {
                    if matches!(b, Operand::Reg(reg) if reg.number() == 14)
                        && instruction.opcode == Opcode::MOV
                        && !instruction.s
                    {
                        self.stmts.push(Stmt::Ret {
                            value: Expr::reg(0, 32),
                        });
                        return Some(true);
                    }
                    return None;
                }
                let source = if instruction.opcode == Opcode::MVN && c != Operand::Nothing {
                    c
                } else {
                    b
                };
                let Some(mut value) = operand(source) else {
                    return None;
                };
                if instruction.opcode == Opcode::MVN {
                    value = Expr::bin(BinOp::Xor, value, Expr::constant(0xffff_ffff));
                }
                if instruction.opcode == Opcode::MOVT {
                    value = Expr::bin(
                        BinOp::Or,
                        Expr::bin(
                            BinOp::And,
                            Self::read(reg.number(), pc, instruction.thumb),
                            Expr::constant(65535),
                        ),
                        Expr::bin(BinOp::Shl, value, Expr::constant(16)),
                    );
                }
                if instruction.s {
                    let out = match source {
                        Operand::RegShift(shift) => match shift.into_shift() {
                            RegShiftStyle::RegImm(shift) => shifted_carry(
                                Self::read(shift.shiftee().number(), pc, instruction.thumb),
                                shift.stype(),
                                &Expr::constant(u64::from(shift.imm())),
                                carry.clone(),
                            ),
                            _ => None,
                        },
                        _ => None,
                    };
                    let flags = match out {
                        Some(out) => shift_flags(value.clone(), out, overflow),
                        None => Flags::result(low(value.clone())),
                    };
                    self.set_flags(flags);
                }
                self.assign(reg.number(), value);
            }
            Opcode::ADR => {
                let (Operand::Reg(reg), Some(Expr::Const(offset))) =
                    (a, operand(if c == Operand::Nothing { b } else { c }))
                else {
                    return None;
                };
                if reg.number() == 15 {
                    return None;
                }
                let base = (pc as u32).wrapping_add(if instruction.thumb { 4 } else { 8 });
                let add = if instruction.thumb {
                    true
                } else {
                    let Some(bytes) = self.image.read_vaddr(pc, 4) else {
                        return None;
                    };
                    let [a, b, c, d] = bytes else { return None };
                    u32::from_le_bytes([*a, *b, *c, *d]) & (1 << 23) != 0
                };
                let address = if add {
                    (base & !3).wrapping_add(offset as u32)
                } else {
                    (base & !3).wrapping_sub(offset as u32)
                };
                self.assign(reg.number(), Expr::constant(u64::from(address)));
            }
            Opcode::ADD
            | Opcode::SUB
            | Opcode::RSB
            | Opcode::AND
            | Opcode::ORR
            | Opcode::ORN
            | Opcode::EOR
            | Opcode::BIC
            | Opcode::MUL
            | Opcode::CMP
            | Opcode::CMN
            | Opcode::TST
            | Opcode::TEQ
            | Opcode::LSL
            | Opcode::LSR
            | Opcode::ASR
            | Opcode::ROR => return self.arithmetic(instruction, pc, carry, overflow),
            Opcode::ADC | Opcode::SBC | Opcode::RSC => {
                return self.carry_arithmetic(instruction, pc, carry);
            }
            Opcode::SDIV | Opcode::UDIV => {
                let Operand::Reg(reg) = a else {
                    return None;
                };
                if reg.number() == 15 {
                    return None;
                }
                let (Some(lhs), Some(rhs)) = (operand(b), operand(c)) else {
                    return None;
                };
                let value = divide(lhs, rhs, instruction.opcode == Opcode::SDIV);
                self.assign(reg.number(), value);
            }
            Opcode::UMULL | Opcode::SMULL | Opcode::UMLAL | Opcode::SMLAL => {
                let (Operand::Reg(lo), Operand::Reg(hi), Some(left), Some(right)) =
                    (a, b, operand(c), operand(d))
                else {
                    return None;
                };
                if lo.number() == 15 || hi.number() == 15 || lo == hi || instruction.s {
                    return None;
                }
                let signed = matches!(instruction.opcode, Opcode::SMULL | Opcode::SMLAL);
                let extend = |value| {
                    if signed {
                        Expr::SignExtend {
                            value: Box::new(value),
                            width: 4,
                        }
                    } else {
                        low(value)
                    }
                };
                let mut value = Expr::bin(BinOp::Mul, extend(left), extend(right));
                if matches!(instruction.opcode, Opcode::UMLAL | Opcode::SMLAL) {
                    value = Expr::bin(
                        BinOp::Add,
                        value,
                        super::pairs32::join(
                            Self::read(lo.number(), pc, instruction.thumb),
                            Self::read(hi.number(), pc, instruction.thumb),
                        ),
                    );
                }
                self.assign_temp(value);
                self.assign(lo.number(), Expr::reg(crate::ir::EXCHANGE, 64));
                self.assign(
                    hi.number(),
                    Expr::bin(
                        BinOp::Shr,
                        Expr::reg(crate::ir::EXCHANGE, 64),
                        Expr::constant(32),
                    ),
                );
            }
            Opcode::MLA | Opcode::MLS => {
                let Operand::Reg(reg) = a else {
                    return None;
                };
                if reg.number() == 15 || instruction.s {
                    return None;
                }
                let (Some(left), Some(right), Some(addend)) = (operand(b), operand(c), operand(d))
                else {
                    return None;
                };
                let product = Expr::bin(BinOp::Mul, left, right);
                let value = Expr::bin(
                    if instruction.opcode == Opcode::MLS {
                        BinOp::Sub
                    } else {
                        BinOp::Add
                    },
                    addend,
                    product,
                );
                self.assign(reg.number(), value);
            }
            Opcode::UXTB | Opcode::UXTH | Opcode::SXTB | Opcode::SXTH => {
                let Operand::Reg(reg) = a else {
                    return None;
                };
                if reg.number() == 15 {
                    return None;
                }
                let rotation = match c {
                    Operand::Nothing => 0,
                    Operand::Ror(rotation) if rotation <= 24 && rotation % 8 == 0 => rotation,
                    _ => return None,
                };
                let width = if matches!(instruction.opcode, Opcode::UXTB | Opcode::SXTB) {
                    1
                } else {
                    2
                };
                let Some(value) = operand(b) else {
                    return None;
                };
                let value = extend(
                    value,
                    width,
                    matches!(instruction.opcode, Opcode::SXTB | Opcode::SXTH),
                    rotation,
                );
                self.assign(reg.number(), value);
            }
            Opcode::REV => {
                let Operand::Reg(destination) = a else {
                    return None;
                };
                let Some(value) = operand(b) else {
                    return None;
                };
                if destination.number() == 15 {
                    return None;
                }
                self.assign(destination.number(), super::reverse_bytes(value, 32, 4));
            }
            Opcode::UBFX => {
                let Operand::Reg(destination) = a else {
                    return None;
                };
                let (Some(value), Some(Expr::Const(start)), Some(Expr::Const(width))) =
                    (operand(b), operand(c), operand(d))
                else {
                    return None;
                };
                if destination.number() == 15 || width == 0 || width > 32 || start > 32 - width {
                    return None;
                }
                self.assign(destination.number(), bitfield(value, start, width));
            }
            Opcode::LDRD | Opcode::STRD => {
                let (Operand::Reg(first), Operand::Reg(second)) = (a, b) else {
                    return None;
                };
                let load = instruction.opcode == Opcode::LDRD;
                if first.number() == 15 || second.number() == 15 || (load && first == second) {
                    return None;
                }
                let Some((mut addr, back)) = self.memory(c, pc, instruction.thumb) else {
                    return None;
                };
                if load {
                    let mut reads = HashSet::new();
                    if let Some((base, value)) = &back {
                        crate::ir::visit::collect_reads(value, &mut reads);
                        if *base == first.number()
                            || *base == second.number()
                            || reads.contains(&u16::from(first.number()))
                            || reads.contains(&u16::from(second.number()))
                        {
                            return None;
                        }
                    }
                    reads.clear();
                    crate::ir::visit::collect_reads(&addr, &mut reads);
                    if reads.contains(&u16::from(first.number())) {
                        self.assign_temp(addr);
                        addr = Expr::reg(crate::ir::EXCHANGE, 64);
                    }
                }
                let registers = [first, second].into_iter().enumerate();
                for (position, register) in registers {
                    let address = Expr::bin(
                        BinOp::Add,
                        addr.clone(),
                        Expr::constant(position as u64 * 4),
                    );
                    if load {
                        let value =
                            literal(self.image, &address, 4, false).unwrap_or_else(|| Expr::Load {
                                addr: Box::new(address),
                                width: 4,
                                signed: false,
                            });
                        self.assign(register.number(), value);
                    } else {
                        super::preserve_compare(&mut self.flags, Write::Memory, &mut self.stmts);
                        self.stmts.push(Stmt::Store {
                            addr: address,
                            value: Self::read(register.number(), pc, instruction.thumb),
                            width: 4,
                        });
                    }
                }
                if let Some((base, value)) = back {
                    self.assign(base, value);
                }
            }
            Opcode::LDR
            | Opcode::LDRB
            | Opcode::LDRH
            | Opcode::LDRSB
            | Opcode::LDRSH
            | Opcode::STR
            | Opcode::STRB
            | Opcode::STRH => {
                let Operand::Reg(reg) = a else {
                    return None;
                };
                let Some((addr, back)) = self.memory(b, pc, instruction.thumb) else {
                    return None;
                };
                let load = matches!(
                    instruction.opcode,
                    Opcode::LDR | Opcode::LDRB | Opcode::LDRH | Opcode::LDRSB | Opcode::LDRSH
                );
                let width = match instruction.opcode {
                    Opcode::LDRB | Opcode::LDRSB | Opcode::STRB => 1,
                    Opcode::LDRH | Opcode::LDRSH | Opcode::STRH => 2,
                    _ => 4,
                };
                if load {
                    if reg.number() == 15 {
                        if instruction.opcode == Opcode::LDR
                            && addr == Expr::reg(13, 64)
                            && let Some((13, value)) = back
                            && value == Expr::bin(BinOp::Add, Expr::reg(13, 64), Expr::constant(4))
                        {
                            self.assign(13, value);
                            self.stmts.push(Stmt::Ret {
                                value: Expr::reg(0, 32),
                            });
                            return Some(true);
                        }
                        return None;
                    }
                    if let Some((_, value)) = &back {
                        let mut reads = HashSet::new();
                        crate::ir::visit::collect_reads(value, &mut reads);
                        if reads.contains(&u16::from(reg.number())) {
                            return None;
                        }
                    }
                    let signed = matches!(instruction.opcode, Opcode::LDRSB | Opcode::LDRSH);
                    let value =
                        literal(self.image, &addr, width, signed).unwrap_or_else(|| Expr::Load {
                            addr: Box::new(addr),
                            width,
                            signed,
                        });
                    self.assign(reg.number(), value);
                    if let Some((base, value)) = back {
                        self.assign(base, value);
                    }
                } else {
                    let Some(value) = operand(a) else {
                        return None;
                    };
                    super::preserve_compare(&mut self.flags, Write::Memory, &mut self.stmts);
                    self.stmts.push(Stmt::Store { addr, value, width });
                    if let Some((base, value)) = back {
                        self.assign(base, value);
                    }
                }
            }
            Opcode::PUSH | Opcode::POP | Opcode::LDM(..) | Opcode::STM(..) => {
                return self.transfer_multiple(instruction, pc, next);
            }
            Opcode::RRX => {
                let (Operand::Reg(dest), Some(value), Some(carry)) = (a, operand(b), carry) else {
                    return None;
                };
                if dest.number() == 15 {
                    return None;
                }
                let result = Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::Shr, value.clone(), Expr::constant(1)),
                    Expr::bin(BinOp::Shl, carry, Expr::constant(31)),
                );
                if instruction.s {
                    self.set_flags(shift_flags(
                        result.clone(),
                        Expr::bin(BinOp::And, value, Expr::constant(1)),
                        overflow,
                    ));
                }
                self.assign(dest.number(), result);
            }
            Opcode::CLZ => {
                let (Operand::Reg(dest), Some(value)) = (a, operand(b)) else {
                    return None;
                };
                if dest.number() == 15 {
                    return None;
                }
                self.assign(
                    dest.number(),
                    Expr::Select {
                        cond: Cond::Eq,
                        lhs: Box::new(value.clone()),
                        rhs: Box::new(Expr::constant(0)),
                        then: Box::new(Expr::constant(32)),
                        els: Box::new(Expr::apply(
                            crate::ir::Operation::CountLeadingZeros(32),
                            vec![value],
                        )),
                    },
                );
            }
            Opcode::UDF | Opcode::BKPT => {
                self.stmts.push(Stmt::Trap);
                return Some(true);
            }
            _ => return None,
        }
        Some(false)
    }

    fn arithmetic(
        &mut self,
        instruction: &Instruction,
        pc: u64,
        carry: Option<Expr>,
        overflow: Option<Expr>,
    ) -> Option<bool> {
        let [a, b, c, _] = instruction.operands;
        let operand = |op| Self::operand_value(op, pc, instruction.thumb, carry.as_ref());
        let compare = matches!(
            instruction.opcode,
            Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ
        );
        let (left, right) = if compare || c == Operand::Nothing {
            (a, b)
        } else {
            (b, c)
        };
        let Some(mut lhs) = operand(left) else {
            return None;
        };
        if instruction.thumb
            && matches!(left, Operand::Reg(reg) if reg.number() == 15)
            && matches!(instruction.opcode, Opcode::ADD | Opcode::SUB)
        {
            lhs = Expr::constant(u64::from((pc as u32).wrapping_add(4) & !3));
        }
        let frame = matches!(a, Operand::Reg(reg) if matches!(reg.number(), 7 | 11 | 13))
            && matches!(left, Operand::Reg(reg) if reg.number() == 13)
            && matches!(instruction.opcode, Opcode::ADD | Opcode::SUB);
        let lhs = if frame { Expr::reg(13, 64) } else { low(lhs) };
        let Some(rhs) = operand(right) else {
            return None;
        };
        let rhs = if matches!(
            instruction.opcode,
            Opcode::LSL | Opcode::LSR | Opcode::ASR | Opcode::ROR
        ) && matches!(right, Operand::Reg(_))
        {
            Expr::bin(BinOp::And, rhs, Expr::constant(255))
        } else {
            low(rhs)
        };
        let op = match instruction.opcode {
            Opcode::ADD | Opcode::CMN => BinOp::Add,
            Opcode::SUB | Opcode::CMP | Opcode::RSB => BinOp::Sub,
            Opcode::AND | Opcode::BIC | Opcode::TST => BinOp::And,
            Opcode::ORR | Opcode::ORN => BinOp::Or,
            Opcode::EOR | Opcode::TEQ => BinOp::Xor,
            Opcode::MUL => BinOp::Mul,
            Opcode::LSL => BinOp::Shl,
            Opcode::LSR => BinOp::Shr,
            Opcode::ASR => BinOp::Sar,
            _ => BinOp::Or,
        };
        let (lhs, rhs) = if instruction.opcode == Opcode::RSB {
            (rhs, lhs)
        } else {
            (lhs, rhs)
        };
        let value = match instruction.opcode {
            Opcode::LSL | Opcode::LSR | Opcode::ASR | Opcode::ROR => {
                let Some(value) = shift_value(
                    lhs.clone(),
                    match instruction.opcode {
                        Opcode::LSL => ShiftStyle::LSL,
                        Opcode::LSR => ShiftStyle::LSR,
                        Opcode::ASR => ShiftStyle::ASR,
                        _ => ShiftStyle::ROR,
                    },
                    rhs.clone(),
                ) else {
                    return None;
                };
                value
            }
            Opcode::BIC | Opcode::ORN => Expr::bin(
                op,
                lhs.clone(),
                Expr::bin(BinOp::Xor, rhs.clone(), Expr::constant(0xffff_ffff)),
            ),
            _ => Expr::bin(op, lhs.clone(), rhs.clone()),
        };
        if instruction.s || compare {
            let flags = match op {
                BinOp::Add => Flags::sum(lhs.clone(), rhs.clone()),
                BinOp::Sub => Flags::difference(lhs.clone(), rhs.clone()),
                _ => Flags::result(low(value.clone())),
            };
            let shifted = match instruction.opcode {
                Opcode::LSL | Opcode::LSR | Opcode::ASR => {
                    let style = match instruction.opcode {
                        Opcode::LSL => ShiftStyle::LSL,
                        Opcode::LSR => ShiftStyle::LSR,
                        _ => ShiftStyle::ASR,
                    };
                    shifted_carry(lhs, style, &rhs, carry.clone())
                        .map(|out| shift_flags(value.clone(), out, overflow.clone()))
                }
                _ => None,
            };
            self.set_flags(shifted.unwrap_or(flags));
        }
        if !compare {
            let Operand::Reg(reg) = a else {
                return None;
            };
            if reg.number() == 15 {
                return None;
            }
            let value = if frame || (reg.number() == 13 && matches!(op, BinOp::Add | BinOp::Sub)) {
                let left = if matches!(left, Operand::Reg(reg) if reg.number() == 13) {
                    Expr::reg(13, 64)
                } else {
                    let Some(value) = operand(left) else {
                        return None;
                    };
                    value
                };
                let Some(right) = operand(right) else {
                    return None;
                };
                Expr::bin(op, left, right)
            } else {
                value
            };
            self.assign(reg.number(), value);
        }
        Some(false)
    }

    fn carry_arithmetic(
        &mut self,
        instruction: &Instruction,
        pc: u64,
        carry: Option<Expr>,
    ) -> Option<bool> {
        let [a, b, c, _] = instruction.operands;
        let operand = |op| Self::operand_value(op, pc, instruction.thumb, carry.as_ref());
        let Operand::Reg(destination) = a else {
            return None;
        };
        if destination.number() == 15 {
            return None;
        }
        let (left, right) = if c == Operand::Nothing {
            (a, b)
        } else {
            (b, c)
        };
        let (Some(left), Some(right)) = (operand(left), operand(right)) else {
            return None;
        };
        let Some(carry) = carry else {
            return None;
        };
        self.assign_temp(carry);
        let carry = Expr::reg(crate::ir::EXCHANGE, 64);
        let (left, right) = if instruction.opcode == Opcode::RSC {
            (low(right), low(left))
        } else {
            (low(left), low(right))
        };
        let subtract = instruction.opcode != Opcode::ADC;
        let value = if subtract {
            Expr::bin(
                BinOp::Sub,
                Expr::bin(BinOp::Sub, left.clone(), right.clone()),
                Expr::bin(BinOp::Xor, carry.clone(), Expr::constant(1)),
            )
        } else {
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, left.clone(), right.clone()),
                carry.clone(),
            )
        };
        if instruction.s {
            let addend = if subtract {
                Expr::bin(BinOp::Xor, right.clone(), Expr::constant(0xffff_ffff))
            } else {
                right.clone()
            };
            let out = super::flags::carry_out(&left, &addend, carry, 32);
            let result = low(value.clone());
            let zero = Test::Compare(Cond::Eq, result.clone(), Expr::constant(0))
                .select(Expr::constant(64), Expr::constant(0))
                .expect("a comparison is decided");
            let sign = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, result.clone(), Expr::constant(24)),
                Expr::constant(128),
            );
            let first = Expr::bin(
                BinOp::Xor,
                left.clone(),
                if subtract {
                    right.clone()
                } else {
                    result.clone()
                },
            );
            let second = Expr::bin(BinOp::Xor, if subtract { left } else { right }, result);
            let overflow = Expr::bin(
                BinOp::Shr,
                Expr::bin(BinOp::And, first, second),
                Expr::constant(31),
            );
            // The stored-flags representation uses an inverted carry bit.
            let byte = Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::Or, zero, sign),
                Expr::bin(BinOp::Xor, out, Expr::constant(1)),
            );
            self.set_flags(Flags::stored(byte, Some(overflow)));
        }
        self.assign(destination.number(), value);
        Some(false)
    }

    fn transfer_multiple(&mut self, instruction: &Instruction, pc: u64, next: u64) -> Option<bool> {
        let [a, b, _, _] = instruction.operands;
        let (base, list, load, add, pre, back) = match instruction.opcode {
            Opcode::PUSH | Opcode::POP => {
                let Operand::RegList(list) = a else {
                    return None;
                };
                (
                    13,
                    list,
                    instruction.opcode == Opcode::POP,
                    instruction.opcode == Opcode::POP,
                    instruction.opcode == Opcode::PUSH,
                    true,
                )
            }
            Opcode::LDM(add, pre, _, user) | Opcode::STM(add, pre, _, user)
                if instruction.thumb || !user =>
            {
                let (Operand::RegWBack(reg, back), Operand::RegList(list)) = (a, b) else {
                    return None;
                };
                (
                    reg.number(),
                    list,
                    matches!(instruction.opcode, Opcode::LDM(..)),
                    add,
                    if instruction.thumb
                        && next - pc == 2
                        && matches!(instruction.opcode, Opcode::STM(..))
                    {
                        false
                    } else {
                        pre
                    },
                    back,
                )
            }
            _ => return None,
        };
        if list == 0
            || base == 15
            || (list & (1 << base) != 0 && back)
            || (!load && list & 0x8000 != 0)
        {
            return None;
        }
        let count = i64::from(list.count_ones()) * 4;
        let first = if add {
            if pre { 4 } else { 0 }
        } else {
            -count + if pre { 0 } else { 4 }
        };
        let mut address = if base == 13 {
            Expr::reg(13, 64)
        } else {
            Self::read(base, pc, instruction.thumb)
        };
        if list & (1 << base) != 0 {
            self.assign_temp(address);
            address = Expr::reg(crate::ir::EXCHANGE, 64);
        }
        let mut offset = first;
        for index in 0..16u8 {
            if list & (1 << index) == 0 {
                continue;
            }
            let addr = Expr::bin(BinOp::Add, address.clone(), Expr::constant(offset as u64));
            if load {
                if index != 15 {
                    self.assign(
                        index,
                        Expr::Load {
                            addr: Box::new(addr),
                            width: 4,
                            signed: false,
                        },
                    );
                }
            } else {
                super::preserve_compare(&mut self.flags, Write::Memory, &mut self.stmts);
                self.stmts.push(Stmt::Store {
                    addr,
                    value: Self::read(index, pc, instruction.thumb),
                    width: 4,
                });
            }
            offset += 4;
        }
        if back {
            self.assign(
                base,
                Expr::bin(
                    BinOp::Add,
                    address,
                    Expr::constant(if add { count } else { -count } as u64),
                ),
            );
        }
        if load && list & 0x8000 != 0 {
            // A stack return restores the caller's pc; other computed loads need indirect control flow.
            if base != 13 {
                return None;
            }
            self.stmts.push(Stmt::Ret {
                value: Expr::reg(0, 32),
            });
            return Some(true);
        }
        Some(false)
    }

    fn assign_temp(&mut self, value: Expr) {
        super::preserve_compare(
            &mut self.flags,
            Write::Register(crate::ir::EXCHANGE, Some(&value)),
            &mut self.stmts,
        );
        self.stmts.push(Stmt::Assign {
            dest: RegRef {
                index: crate::ir::EXCHANGE,
                width: 64,
            },
            value,
        });
    }

    fn set_flags(&mut self, mut flags: Flags) {
        for operand in flags.operands_mut() {
            if matches!(operand, Expr::Const(_)) {
                // Carried flags must keep constant operands at the instruction's width.
                *operand = Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(operand.clone()),
                    rhs: Box::new(Expr::constant(0xffff_ffff)),
                };
            }
        }
        flags.width = Some(32);
        self.flags = Some(flags);
        self.touched = true;
    }
}

fn shifted_carry(value: Expr, style: ShiftStyle, amount: &Expr, old: Option<Expr>) -> Option<Expr> {
    if style == ShiftStyle::RRX {
        return Some(Expr::bin(BinOp::And, value, Expr::constant(1)));
    }
    let Expr::Const(amount) = amount else {
        return None;
    };
    let shift = match (style, *amount) {
        (_, 0) => return old,
        (ShiftStyle::LSL, 1..=32) => 32 - amount,
        (ShiftStyle::LSR, 1..=32) | (ShiftStyle::ASR, 1..=31) => amount - 1,
        (ShiftStyle::ASR, _) => 31,
        (ShiftStyle::ROR, _) => (amount - 1) & 31,
        _ => return Some(Expr::constant(0)),
    };
    Some(Expr::bin(
        BinOp::And,
        Expr::bin(BinOp::Shr, value, Expr::constant(shift)),
        Expr::constant(1),
    ))
}

fn shift_flags(value: Expr, carry: Expr, overflow: Option<Expr>) -> Flags {
    let result = low(value);
    let zero = Test::Compare(Cond::Eq, result.clone(), Expr::constant(0))
        .select(Expr::constant(64), Expr::constant(0))
        .expect("a comparison is decided");
    let sign = Expr::bin(
        BinOp::And,
        Expr::bin(BinOp::Shr, result, Expr::constant(24)),
        Expr::constant(128),
    );
    Flags::stored(
        Expr::bin(
            BinOp::Or,
            Expr::bin(BinOp::Or, sign, zero),
            Expr::bin(BinOp::Xor, carry, Expr::constant(1)),
        ),
        overflow,
    )
}

fn shift_value(value: Expr, style: ShiftStyle, amount: Expr) -> Option<Expr> {
    let value = if style == ShiftStyle::ASR {
        Expr::SignExtend {
            value: Box::new(value),
            width: 4,
        }
    } else {
        value
    };
    match style {
        ShiftStyle::LSL | ShiftStyle::LSR | ShiftStyle::ASR => {
            let op = match style {
                ShiftStyle::LSL => BinOp::Shl,
                ShiftStyle::LSR => BinOp::Shr,
                _ => BinOp::Sar,
            };
            let beyond = if style == ShiftStyle::ASR {
                Expr::bin(BinOp::Sar, value.clone(), Expr::constant(31))
            } else {
                Expr::constant(0)
            };
            Some(Expr::Select {
                cond: Cond::Cs,
                lhs: Box::new(amount.clone()),
                rhs: Box::new(Expr::constant(32)),
                then: Box::new(beyond),
                els: Box::new(Expr::bin(op, value, amount)),
            })
        }
        ShiftStyle::ROR => Some(super::rotate(value, amount, 32, /* right */ true)),
        ShiftStyle::RRX => None,
    }
}

impl Machine for Lifter<'_> {
    type Instruction = Step;
    fn branch_target(&self, instruction: &Step, _: u64) -> Option<u64> {
        match instruction {
            Step::Guard { target, .. } => Some(*target),
            Step::Execute {
                target,
                instruction,
                ..
            } if matches!(instruction.opcode, Opcode::B | Opcode::CBZ | Opcode::CBNZ) => *target,
            _ => None,
        }
    }
    fn step(&mut self, instruction: &Step, _: u64) -> bool {
        match instruction {
            Step::Guard { condition, target } => {
                let test = self
                    .flags
                    .as_ref()
                    .map_or(Test::Unknown, |flags| flags.test(*condition, Isa::Arm32));
                if let Some(branch) = test.branch(*condition, *target) {
                    self.stmts.push(branch);
                    return true;
                }
                false
            }
            Step::Execute {
                instruction,
                additional,
                pc,
                next,
                target,
            } => {
                if let Some(extra) = additional {
                    extra.execute(self, *pc, instruction.thumb);
                    return false;
                }
                let first = self.stmts.len();
                // Operand failures discard every partial effect of this instruction.
                match self.execute(instruction, *pc, *next, *target) {
                    Some(ended) => ended,
                    None => {
                        self.stmts.truncate(first);
                        self.stmts
                            .push(Stmt::unsupported(format!("ARM {instruction} at 0x{pc:x}")));
                        self.flags = None;
                        self.float_comparison = false;
                        self.touched = true;
                        false
                    }
                }
            }
        }
    }
    fn take_statements(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }
    fn block_ended(&mut self) {
        self.flags = None;
        self.float_comparison = false;
    }
    fn block_split(&mut self) {
        self.flags = None;
        self.float_comparison = false;
    }
    fn exit_flags(&self) -> Option<Flags> {
        self.flags.clone()
    }
    fn flags_touched(&self) -> bool {
        self.touched
    }
    fn enter_block(&mut self, flags: Option<Flags>) {
        self.float_comparison = false;
        self.flags = flags;
        self.touched = false;
    }
}

#[cfg(test)]
mod smt_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{FunctionIr, eval};

    fn run(code: Vec<u8>, thumb: bool, registers: &[(u16, u64)], memory: &[(u64, u64)]) -> u64 {
        let size = code.len() as u64;
        let mut image = Image::from_code(Isa::Arm32, 0, code);
        image
            .arm_modes
            .insert(0, if thumb { ArmMode::Thumb } else { ArmMode::Arm });
        let mut ir = FunctionIr::single_block(Isa::Arm32, Vec::new());
        ir.blocks = super::lift(
            &image,
            0,
            image.read_vaddr(0, size).unwrap(),
            &HashSet::new(),
            &|_| Default::default(),
        )
        .unwrap();
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[0, 1, 2, 3],
                clobbered: &[0, 1, 2, 3, 12, 14],
            },
            registers,
            memory,
            step_limit: 200,
        };
        match eval::run(&ir, &setup) {
            eval::Outcome::Return { value, .. } => value,
            other => panic!("{other:?}\n{}", ir.render()),
        }
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }
    fn halves(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn adr_uses_the_aligned_pc_and_encoded_direction() {
        for (code, thumb, expected) in [
            (words(&[0xe28f0010, 0xe12fff1e]), false, 24),
            (words(&[0xe24f0010, 0xe12fff1e]), false, 0xffff_fff8),
            (halves(&[0xbf00, 0xa000, 0x4770]), true, 4),
        ] {
            assert_eq!(run(code.clone(), thumb, &[], &[]), expected);
            let mut image = Image::from_code(Isa::Arm32, 0, code.clone());
            image
                .arm_modes
                .insert(0, if thumb { ArmMode::Thumb } else { ArmMode::Arm });
            let mut ir = FunctionIr::single_block(Isa::Arm32, Vec::new());
            ir.blocks =
                super::lift(&image, 0, &code, &HashSet::new(), &|_| Default::default()).unwrap();
            crate::passes::simplify::simplify(&mut ir);
            ir.name = Some("address_value".into());
            let printed = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
            crate::lift::atomic_tests::compile_run(
                &format!(
                    "#include <stdint.h>\n{printed}\nint main(void) {{ return address_value() != {expected}ULL; }}"
                ),
                &format!("arm32_adr_{expected}"),
            );
        }
    }

    #[test]
    fn carry_arithmetic_sets_all_condition_flags() {
        use std::fmt::Write as _;

        let mut printed = String::from("#include <stdint.h>\n#include <stdbool.h>\n");
        let mut checks = String::new();
        for subtract in [false, true] {
            for condition in 0..14u32 {
                let name = format!("carry_flags_{}_{}", u8::from(subtract), condition);
                let code = words(&[
                    0xe3530001,
                    if subtract { 0xe0d02001 } else { 0xe0b02001 },
                    0xe3a00000,
                    condition << 28 | 0x03a00001,
                    0xe12fff1e,
                ]);
                let image = Image::from_code(Isa::Arm32, 0, code.clone());
                let mut ir = FunctionIr::single_block(Isa::Arm32, Vec::new());
                ir.blocks = super::lift(&image, 0, &code, &HashSet::new(), &|_| Default::default())
                    .unwrap();
                ir.name = Some(name.clone());
                ir.params = [(0, "a"), (1, "b"), (3, "carry")]
                    .iter()
                    .map(|(index, name)| crate::ir::Param {
                        index: *index,
                        name: (*name).into(),
                        ty: crate::ir::CType::U32,
                    })
                    .collect();
                crate::passes::simplify::simplify(&mut ir);
                printed.push_str(&crate::render::render(
                    &ir,
                    &[],
                    &crate::render::Symbols::default(),
                    &[],
                ));
                for a in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                    for b in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                        for carry in [0u64, 1] {
                            let exact = if subtract {
                                i64::from(a as i32) - i64::from(b as i32) - (1 - carry as i64)
                            } else {
                                i64::from(a as i32) + i64::from(b as i32) + carry as i64
                            };
                            let result = exact as u32;
                            let negative = result >> 31 != 0;
                            let zero = result == 0;
                            let carried = if subtract {
                                u64::from(a) >= u64::from(b) + 1 - carry
                            } else {
                                u64::from(a) + u64::from(b) + carry > u64::from(u32::MAX)
                            };
                            let overflow =
                                exact < i64::from(i32::MIN) || exact > i64::from(i32::MAX);
                            let expected = match condition {
                                0 => zero,
                                1 => !zero,
                                2 => carried,
                                3 => !carried,
                                4 => negative,
                                5 => !negative,
                                6 => overflow,
                                7 => !overflow,
                                8 => carried && !zero,
                                9 => !carried || zero,
                                10 => negative == overflow,
                                11 => negative != overflow,
                                12 => !zero && negative == overflow,
                                _ => zero || negative != overflow,
                            };
                            assert_eq!(
                                run(
                                    code.clone(),
                                    false,
                                    &[(0, u64::from(a)), (1, u64::from(b)), (3, carry)],
                                    &[]
                                ),
                                u64::from(expected),
                                "{name}({a}, {b}, {carry})"
                            );
                            writeln!(
                                checks,
                                "if ({name}({a}u, {b}u, {carry}u) != {}) return 1;",
                                u8::from(expected)
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
        writeln!(printed, "int main(void) {{ {checks} return 0; }}").unwrap();
        crate::lift::atomic_tests::compile_run(
            &crate::render::combine(&printed),
            "arm32_carry_flags",
        );
    }

    #[test]
    fn arm_arithmetic_wraps_at_32_bits() {
        for value in [0, 1, 0x7fff_ffff, 0xffff_ffff, u64::MAX] {
            assert_eq!(
                run(
                    words(&[0xe2800001, 0xe12fff1e]),
                    /* thumb */ false,
                    &[(0, value)],
                    &[]
                ),
                u64::from((value as u32).wrapping_add(1))
            );
        }
    }

    #[test]
    fn predicated_writes_and_returns_use_the_comparison() {
        // cmp r0, r1; movlt r0, r1; bx lr
        for (a, b) in [(1, 3), (3, 1), (0x8000_0000, 1), (0xffff_ffff, 0)] {
            assert_eq!(
                run(
                    words(&[0xe1500001, 0xb1a00001, 0xe12fff1e]),
                    /* thumb */ false,
                    &[(0, a), (1, b)],
                    &[]
                ),
                if (a as i32) < (b as i32) { b } else { a }
            );
        }
        // cmp r0, #0; bxeq lr; add r0, r0, #1; bx lr
        for a in [0, 1, 0xffff_ffff] {
            assert_eq!(
                run(
                    words(&[0xe3500000, 0x012fff1e, 0xe2800001, 0xe12fff1e]),
                    /* thumb */ false,
                    &[(0, a)],
                    &[]
                ),
                if a == 0 {
                    0
                } else {
                    u64::from((a as u32).wrapping_add(1))
                }
            );
        }
        let image = Image::from_code(Isa::Arm32, 0, words(&[0xb1a00001]));
        let lines = super::listing(&image, image.read_vaddr(0, 4).unwrap(), 0, 1);
        assert!(lines[0].contains("movlt"), "{lines:?}");
    }

    #[test]
    fn conditional_moves_keep_addition_carry_and_overflow() {
        for (a, b) in [
            (0u32, 0u32),
            (1, 2),
            (u32::MAX, 1),
            (0x7fff_ffff, 1),
            (0x8000_0000, 0x8000_0000),
        ] {
            let registers = [(0, u64::from(a)), (1, u64::from(b))];
            let sum = a.wrapping_add(b);
            let carry = u64::from(u64::from(a) + u64::from(b) > u64::from(u32::MAX));
            let overflow = u64::from((a ^ sum) & (b ^ sum) & 0x8000_0000 != 0);
            assert_eq!(
                run(
                    words(&[0xe0902001, 0x23a00001, 0x33a00000, 0xe12fff1e]),
                    /* thumb */ false,
                    &registers,
                    &[]
                ),
                carry
            );
            assert_eq!(
                run(
                    words(&[0xe0902001, 0x63a00001, 0x73a00000, 0xe12fff1e]),
                    /* thumb */ false,
                    &registers,
                    &[]
                ),
                overflow
            );
        }
    }

    #[test]
    fn immediate_flag_results_test_bit_31() {
        for (instruction, expected) in [(0xe3b00102, 1), (0xe3b0007f, 0), (0xe3b00000, 0)] {
            let code = words(&[instruction, 0x43a00001, 0x53a00000, 0xe12fff1e]);
            assert_eq!(run(code.clone(), /* thumb */ false, &[], &[]), expected);
            let image = Image::from_code(Isa::Arm32, 0, code);
            let mut ir = FunctionIr::single_block(Isa::Arm32, Vec::new());
            ir.blocks = super::lift(
                &image,
                0,
                image.read_vaddr(0, 16).unwrap(),
                &HashSet::new(),
                &|_| Default::default(),
            )
            .unwrap();
            ir.name = Some("flag_sign".into());
            let printed = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
            crate::lift::atomic_tests::compile_run(
                &format!(
                    "#include <stdint.h>\n{printed}\nint main(void) {{ return flag_sign() != {expected}; }}"
                ),
                &format!("arm32_flag_sign_{instruction:x}"),
            );
        }
    }

    #[test]
    fn thumb_register_shifts_use_eight_bit_counts_and_saturate() {
        for amount in [0u32, 1, 31, 32, 33, 63, 64, 255, 256] {
            let count = amount & 255;
            let registers = [(0, 0x8000_0001), (1, u64::from(amount))];
            let left = if count >= 32 {
                0
            } else {
                0x8000_0001u32 << count
            };
            let right = (0x8000_0001u32 as i32 >> count.min(31)) as u32;
            assert_eq!(
                run(
                    halves(&[0x4088, 0x4770]),
                    /* thumb */ true,
                    &registers,
                    &[]
                ),
                u64::from(left)
            );
            assert_eq!(
                run(
                    halves(&[0x4108, 0x4770]),
                    /* thumb */ true,
                    &registers,
                    &[]
                ),
                u64::from(right)
            );
        }
    }

    #[test]
    fn thumb_it_and_branches_use_physical_addresses() {
        // cmp r0, r1; it lt; movlt r0, r1; bx lr
        for (a, b) in [(1, 3), (3, 1), (0xffff_ffff, 0)] {
            assert_eq!(
                run(
                    halves(&[0x4288, 0xbfb8, 0x4608, 0x4770]),
                    /* thumb */ true,
                    &[(0, a), (1, b)],
                    &[]
                ),
                if (a as i32) < (b as i32) { b } else { a }
            );
        }
        // b +4; movs r0, #9; movs r0, #7; bx lr
        assert_eq!(
            run(
                halves(&[0xe000, 0x2009, 0x2007, 0x4770]),
                /* thumb */ true,
                &[],
                &[]
            ),
            7
        );
    }

    #[test]
    fn stack_saves_and_stack_arguments_are_four_bytes() {
        // push {r4, lr}; ldr r0, [sp, #8]; pop {r4, pc}
        assert_eq!(
            run(
                words(&[0xe92d4010, 0xe59d0008, 0xe8bd8010]),
                /* thumb */ false,
                &[(13, 0x1000), (4, 7), (14, 0x2001)],
                &[(eval::stack_top(Isa::Arm32), 0x12345678)]
            ),
            0x12345678
        );
        // push {r4, lr}; ldr r0, [sp, #8]; pop {r4, pc}
        assert_eq!(
            run(
                halves(&[0xb510, 0x9802, 0xbd10]),
                /* thumb */ true,
                &[(13, 0x1000), (4, 7), (14, 0x2001)],
                &[(eval::stack_top(Isa::Arm32), 0x12345678)]
            ),
            0x12345678
        );
    }

    #[test]
    fn halfword_post_indexed_transfers_update_the_base() {
        for instruction in [0xe0d100b2, 0xe0c100b2] {
            assert_eq!(
                run(
                    words(&[instruction, 0xe1a00001, 0xe12fff1e]),
                    /* thumb */ false,
                    &[(0, 7), (1, 0x1000)],
                    &[(0x1000, 0x1234)]
                ),
                0x1002
            );
        }
        assert_eq!(
            run(
                words(&[0xe09100b2, 0xe1a00001, 0xe12fff1e]),
                /* thumb */ false,
                &[(1, 0x1000), (2, 4)],
                &[(0x1000, 0x1234)]
            ),
            0x1004
        );
        for (instruction, expected) in [
            (0xe0d100b2, 0x2236),
            (0xe09100b2, 0x2238),
            (0xe5b10004, 0x667c),
        ] {
            assert_eq!(
                run(
                    words(&[instruction, 0xe0800001, 0xe12fff1e]),
                    /* thumb */ false,
                    &[(1, 0x1000), (2, 4)],
                    &[(0x1000, 0x0000_5678_0000_1234)]
                ),
                expected
            );
        }
    }

    #[test]
    fn calls_define_the_link_and_use_word_stack_slots() {
        for thumb in [false, true] {
            let code = if thumb {
                halves(&[0xf000, 0xf800, 0x4770])
            } else {
                words(&[0xeb000000, 0xe12fff1e])
            };
            let mut image = Image::from_code(Isa::Arm32, 0, code);
            image
                .arm_modes
                .insert(0, if thumb { ArmMode::Thumb } else { ArmMode::Arm });
            let summary = |_| crate::loader::Summary {
                arity: Some(4),
                stack: 2,
                ..Default::default()
            };
            let bytes = image.read_vaddr(0, if thumb { 6 } else { 8 }).unwrap();
            let blocks = super::lift(&image, 0, bytes, &HashSet::new(), &summary).unwrap();
            let statements: Vec<_> = blocks.iter().flat_map(|block| &block.stmts).collect();
            assert!(statements.iter().any(|stmt| matches!(stmt, Stmt::Assign { dest, value: Expr::Const(value) } if dest.index == 14 && *value == if thumb { 5 } else { 4 })));
            let args = statements
                .iter()
                .find_map(|stmt| match stmt {
                    Stmt::Call { args, .. } => args.as_ref(),
                    _ => None,
                })
                .unwrap();
            assert_eq!(args.len(), 6);
            for arg in &args[..4] {
                assert!(matches!(arg, Expr::Reg { width: 32, .. }));
            }
            let stack_args = args[4..].iter().enumerate();
            for (slot, arg) in stack_args {
                let Expr::Load { addr, width: 4, .. } = arg else {
                    panic!("{arg:?}");
                };
                assert_eq!(
                    addr.as_ref(),
                    &Expr::bin(
                        BinOp::Add,
                        Expr::reg(13, 64),
                        Expr::constant(slot as u64 * 4)
                    )
                );
            }
        }
    }

    #[test]
    fn blx_reads_the_old_link_register_before_defining_the_return_address() {
        for thumb in [false, true] {
            let code = if thumb {
                halves(&[0x47f0])
            } else {
                words(&[0xe12fff3e])
            };
            let size = code.len() as u64;
            let mut image = Image::from_code(Isa::Arm32, 0, code);
            image
                .arm_modes
                .insert(0, if thumb { ArmMode::Thumb } else { ArmMode::Arm });
            let mut ir = FunctionIr::single_block(Isa::Arm32, Vec::new());
            ir.blocks = super::lift(
                &image,
                0,
                image.read_vaddr(0, size).unwrap(),
                &HashSet::new(),
                &|_| Default::default(),
            )
            .unwrap();
            let setup = eval::Setup {
                seed: 0,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(14, 0x2001)],
                memory: &[],
                step_limit: 20,
            };
            let outcome = eval::run(&ir, &setup);
            let eval::Outcome::Trap { calls, .. } = outcome else {
                panic!("{outcome:?}");
            };
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].target, Some(0x2000));
            assert!(
                calls[0]
                    .arguments
                    .iter()
                    .all(|value| *value <= u64::from(u32::MAX))
            );
        }
    }

    #[test]
    fn register_exchange_reaches_thumb_code_in_the_same_function() {
        let mut image =
            Image::from_code(Isa::Arm32, 0, words(&[0xe3a03009, 0xe12fff13, 0x47702007]));
        image
            .arm_modes
            .extend([(0, ArmMode::Arm), (8, ArmMode::Thumb)]);
        let bytes = image.read_vaddr(0, 12).unwrap();
        let mut ir = FunctionIr::single_block(Isa::Arm32, Vec::new());
        ir.blocks =
            super::lift(&image, 0, bytes, &HashSet::new(), &|_| Default::default()).unwrap();
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[],
            memory: &[],
            step_limit: 20,
        };
        assert!(matches!(
            eval::run(&ir, &setup),
            eval::Outcome::Return { value: 7, .. }
        ));
        crate::passes::simplify::simplify(&mut ir);
        assert!(
            !ir.blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::BrIndirect { .. }))
        );
        ir.name = Some("exchange".into());
        let code = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
        assert!(code.contains("return 7;"), "{code}");
        crate::lift::atomic_tests::compile_run(
            &format!("#include <stdint.h>\n{code}\nint main(void) {{ return exchange() != 7; }}"),
            "arm32_exchange",
        );
    }

    #[test]
    fn mapping_symbols_skip_data_and_switch_instruction_sets() {
        let mut image =
            Image::from_code(Isa::Arm32, 0, words(&[0xea000000, 0xffff_ffff, 0x47702007]));
        image
            .arm_modes
            .extend([(0, ArmMode::Arm), (4, ArmMode::Data), (8, ArmMode::Thumb)]);
        let bytes = image.read_vaddr(0, 12).unwrap();
        let (decoded, stop) = decode(&image, bytes, 0);
        assert!(stop.is_none());
        assert_eq!(decoded.iter().map(|d| d.pc).collect::<Vec<_>>(), [0, 8, 10]);
        assert_eq!(image.arm_mode(1), ArmMode::Thumb);
    }
}
