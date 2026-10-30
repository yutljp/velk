//! ARM encodings not handled by the general instruction decoder.

use std::fmt;

use yaxpeax_arm::armv7::ConditionCode;

use super::Lifter;
use crate::ir::{BinOp, Cond, Expr, Operation, Precision, RegRef, Rounding, Stmt};
use crate::loader::ArmMode;

const COMPARE_LEFT: u16 = crate::ir::TEMP_BASE + 0x4c;
const COMPARE_RIGHT: u16 = crate::ir::TEMP_BASE + 0x4d;

#[derive(Clone, Copy)]
pub(in crate::lift) enum Instruction {
    FloatMemory {
        register: u8,
        base: u8,
        offset: i64,
        double: bool,
        load: bool,
    },
    HalfMultiply {
        destination: u8,
        left: u8,
        right: u8,
        halves: u8,
    },
    Extend {
        destination: u8,
        addend: Option<u8>,
        source: u8,
        rotation: u8,
        width: u8,
        signed: bool,
    },
    Divide {
        destination: u8,
        left: u8,
        right: u8,
        signed: bool,
    },
    Bitfield {
        destination: u8,
        source: u8,
        start: u8,
        width: u8,
    },
    Reverse {
        destination: u8,
        source: u8,
    },
    FloatStack {
        first: u8,
        count: u8,
        double: bool,
        pop: bool,
    },
    Float {
        word: u32,
        operation: FloatOperation,
    },
}

#[derive(Clone, Copy)]
pub(in crate::lift) enum FloatOperation {
    Add,
    Subtract,
    MultiplyAdd,
    Convert,
    ToSigned,
    Compare,
    ReadFlags,
    Move,
}

pub(super) fn condition(code: u8) -> ConditionCode {
    use ConditionCode::*;
    [EQ, NE, HS, LO, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL][usize::from(code.min(14))]
}

pub(super) fn decode(bytes: &[u8], mode: ArmMode) -> Option<Instruction> {
    let [a, b, c, d, ..] = bytes else {
        return None;
    };
    let word = match mode {
        ArmMode::Arm => u32::from_le_bytes([*a, *b, *c, *d]),
        ArmMode::Thumb => {
            u32::from(u16::from_le_bytes([*a, *b])) << 16 | u32::from(u16::from_le_bytes([*c, *d]))
        }
        ArmMode::Data => return None,
    };
    let register_number = |shift: u32| ((word >> shift) & 15) as u8;
    let vector_load = match mode {
        ArmMode::Arm => word & 0xffb0_0fff == 0xf420_070f,
        ArmMode::Thumb => word & 0xffb0_0fff == 0xf920_070f,
        ArmMode::Data => false,
    };
    if vector_load && register_number(16) != 15 {
        return Some(Instruction::FloatMemory {
            register: register_number(12) | ((word >> 18) & 16) as u8,
            base: register_number(16),
            offset: 0,
            double: true,
            load: true,
        });
    }
    if ((mode == ArmMode::Arm && word >> 28 < 15) || (mode == ArmMode::Thumb && word >> 28 == 14))
        && word & 0x0f20_0e00 == 0x0d00_0a00
    {
        let double = word & 0x100 != 0;
        let register = if double {
            register_number(12) | ((word >> 18) & 16) as u8
        } else {
            (register_number(12) * 2) | ((word >> 22) & 1) as u8
        };
        let base = register_number(16);
        let load = word & (1 << 20) != 0;
        if base == 15 && !load {
            return None;
        }
        let offset = i64::from(word & 255) * 4;
        return Some(Instruction::FloatMemory {
            register,
            base,
            offset: if word & (1 << 23) != 0 {
                offset
            } else {
                -offset
            },
            double,
            load,
        });
    }
    let multiply = match mode {
        ArmMode::Arm if word >> 28 < 15 && word & 0x0ff0_f090 == 0x0160_0080 => Some((
            register_number(16),
            register_number(0),
            register_number(8),
            ((word >> 5) & 3) as u8,
        )),
        ArmMode::Thumb if word & 0xfff0_f0c0 == 0xfb10_f000 => {
            let halves = (((word >> 5) & 1) | ((word >> 3) & 2)) as u8;
            Some((
                register_number(8),
                register_number(16),
                register_number(0),
                halves,
            ))
        }
        _ => None,
    };
    if let Some((destination, left, right, halves)) = multiply {
        if [destination, left, right].contains(&15)
            || (mode == ArmMode::Thumb && [destination, left, right].contains(&13))
        {
            return None;
        }
        return Some(Instruction::HalfMultiply {
            destination,
            left,
            right,
            halves,
        });
    }
    if (mode == ArmMode::Arm && word >> 28 < 15) || (mode == ArmMode::Thumb && word >> 28 == 14) {
        let encoding = word & 0x0fbf_0e00;
        if matches!(encoding, 0x0d2d_0a00 | 0x0cbd_0a00) {
            let double = word & 0x100 != 0;
            let words = (word & 255) as u8;
            let first = if double {
                register_number(12) | ((word >> 18) & 16) as u8
            } else {
                (register_number(12) * 2) | ((word >> 22) & 1) as u8
            };
            let count = if double { words / 2 } else { words };
            if words == 0
                || (double && (!words.is_multiple_of(2) || count > 16))
                || u16::from(first) + u16::from(count) > 32
            {
                return None;
            }
            return Some(Instruction::FloatStack {
                first,
                count,
                double,
                pop: encoding == 0x0cbd_0a00,
            });
        }
    }
    if mode == ArmMode::Arm && word >> 28 < 15 {
        if word & 0x0f80_03f0 == 0x0680_0070 {
            let signed = word & (1 << 22) == 0;
            let width = match (word >> 20) & 3 {
                2 => 1,
                3 => 2,
                _ => return None,
            };
            if register_number(12) == 15 || register_number(0) == 15 {
                return None;
            }
            return Some(Instruction::Extend {
                destination: register_number(12),
                addend: (register_number(16) != 15).then_some(register_number(16)),
                source: register_number(0),
                rotation: ((word >> 10) & 3) as u8 * 8,
                width,
                signed,
            });
        }
        if word & 0x0fd0_f0f0 == 0x0710_f010 {
            if register_number(16) == 15 || register_number(0) == 15 || register_number(8) == 15 {
                return None;
            }
            return Some(Instruction::Divide {
                destination: register_number(16),
                left: register_number(0),
                right: register_number(8),
                signed: word & (1 << 21) == 0,
            });
        }
        if word & 0x0fff_0ff0 == 0x06bf_0f30
            && register_number(12) != 15
            && register_number(0) != 15
        {
            return Some(Instruction::Reverse {
                destination: register_number(12),
                source: register_number(0),
            });
        }
        if word & 0x0fe0_0070 == 0x07e0_0050 {
            let start = ((word >> 7) & 31) as u8;
            let width = ((word >> 16) & 31) as u8 + 1;
            if register_number(12) == 15
                || register_number(0) == 15
                || u16::from(start) + u16::from(width) > 32
            {
                return None;
            }
            return Some(Instruction::Bitfield {
                destination: register_number(12),
                source: register_number(0),
                start,
                width,
            });
        }
    }
    if mode == ArmMode::Thumb && word & 0xffa0_f0c0 == 0xfa00_f080 {
        let destination = register_number(8);
        let source = register_number(0);
        let base = register_number(16);
        if [destination, source]
            .iter()
            .any(|register| matches!(register, 13 | 15))
            || base == 13
        {
            return None;
        }
        return Some(Instruction::Extend {
            destination,
            addend: (base != 15).then_some(base),
            source,
            rotation: ((word >> 4) & 3) as u8 * 8,
            width: if word & (1 << 22) != 0 { 1 } else { 2 },
            signed: word & (1 << 20) == 0,
        });
    }
    if (mode == ArmMode::Arm && word >> 28 == 15) || (mode == ArmMode::Thumb && word >> 28 != 14) {
        return None;
    }
    let operation = match word & 0x0fb0_0e50 {
        0x0e30_0a00 => FloatOperation::Add,
        0x0e30_0a40 => FloatOperation::Subtract,
        0x0e00_0a00 => FloatOperation::MultiplyAdd,
        _ => match word & 0x0fbf_0ed0 {
            0x0eb7_0ac0 => FloatOperation::Convert,
            0x0ebd_0ac0 => FloatOperation::ToSigned,
            0x0eb4_0a40 => FloatOperation::Compare,
            _ if word & 0x0fff_ffff == 0x0ef1_fa10 => FloatOperation::ReadFlags,
            _ if word & 0x0fe0_0f7f == 0x0e00_0a10 && register_number(12) != 15 => {
                FloatOperation::Move
            }
            _ => return None,
        },
    };
    Some(Instruction::Float { word, operation })
}

// D0..D15 overlap pairs of S registers; D16..D31 have no S aliases.
fn read(number: u8, precision: Precision) -> Expr {
    if precision == Precision::Double {
        return Expr::reg(crate::arch::arm32::D0 + u16::from(number), 64);
    }
    let value = Expr::reg(crate::arch::arm32::D0 + u16::from(number / 2), 64);
    let value = if number & 1 == 0 {
        value
    } else {
        Expr::bin(BinOp::Shr, value, Expr::constant(32))
    };
    super::low(value)
}

fn write(lifter: &mut Lifter<'_>, number: u8, precision: Precision, value: Expr) {
    let (index, value) = if precision == Precision::Double {
        (crate::arch::arm32::D0 + u16::from(number), value)
    } else {
        let index = crate::arch::arm32::D0 + u16::from(number / 2);
        let shift = u64::from(number & 1) * 32;
        let kept = Expr::bin(
            BinOp::And,
            Expr::reg(index, 64),
            Expr::constant(!(0xffff_ffff << shift)),
        );
        let changed = Expr::bin(BinOp::Shl, super::low(value), Expr::constant(shift));
        (index, Expr::bin(BinOp::Or, kept, changed))
    };
    super::super::preserve_compare(
        &mut lifter.flags,
        super::super::Write::Register(index, Some(&value)),
        &mut lifter.stmts,
    );
    lifter.stmts.push(Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
        at: None,
    });
}

impl Instruction {
    pub(super) fn execute(self, lifter: &mut Lifter<'_>, pc: u64, thumb: bool) {
        match self {
            Self::FloatMemory {
                register,
                base,
                offset,
                double,
                load,
            } => {
                let value = if base == 15 {
                    Expr::constant(u64::from(
                        (pc as u32).wrapping_add(if thumb { 4 } else { 8 }) & !3,
                    ))
                } else if matches!(base, 7 | 11 | 13) {
                    Expr::reg(u16::from(base), 64)
                } else {
                    Lifter::read(base, pc, thumb)
                };
                let addr = Expr::bin(BinOp::Add, value, Expr::constant(offset as u64));
                let addr = if matches!(base, 7 | 11 | 13) {
                    addr
                } else {
                    super::low(addr)
                };
                let precision = if double {
                    Precision::Double
                } else {
                    Precision::Single
                };
                let width = if double { 8 } else { 4 };
                if load {
                    write(
                        lifter,
                        register,
                        precision,
                        super::literal(lifter.image, &addr, width, false).unwrap_or_else(|| {
                            Expr::Load {
                                addr: Box::new(addr),
                                width,
                                signed: false,
                            }
                        }),
                    );
                } else {
                    lifter.stmts.push(Stmt::Store {
                        addr,
                        value: read(register, precision),
                        width,
                        at: None,
                    });
                }
            }
            Self::HalfMultiply {
                destination,
                left,
                right,
                halves,
            } => {
                let half = |register, top| Expr::SignExtend {
                    value: Box::new(if top {
                        Expr::bin(
                            BinOp::Shr,
                            Expr::reg(u16::from(register), 32),
                            Expr::constant(16),
                        )
                    } else {
                        Expr::reg(u16::from(register), 32)
                    }),
                    width: 2,
                };
                lifter.assign(
                    destination,
                    Expr::bin(
                        BinOp::Mul,
                        half(left, halves & 1 != 0),
                        half(right, halves & 2 != 0),
                    ),
                );
            }
            Self::FloatStack {
                first,
                count,
                double,
                pop,
            } => {
                let width = if double { 8 } else { 4 };
                let bytes = u64::from(count) * u64::from(width);
                if !pop {
                    lifter.assign(
                        13,
                        Expr::bin(BinOp::Sub, Expr::reg(13, 64), Expr::constant(bytes)),
                    );
                }
                let precision = if double {
                    Precision::Double
                } else {
                    Precision::Single
                };
                for slot in 0..count {
                    let addr = Expr::bin(
                        BinOp::Add,
                        Expr::reg(13, 64),
                        Expr::constant(u64::from(slot) * u64::from(width)),
                    );
                    if pop {
                        write(
                            lifter,
                            first + slot,
                            precision,
                            Expr::Load {
                                addr: Box::new(addr),
                                width,
                                signed: false,
                            },
                        );
                    } else {
                        lifter.stmts.push(Stmt::Store {
                            addr,
                            value: read(first + slot, precision),
                            width,
                            at: None,
                        });
                    }
                }
                if pop {
                    lifter.assign(
                        13,
                        Expr::bin(BinOp::Add, Expr::reg(13, 64), Expr::constant(bytes)),
                    );
                }
            }
            Self::Extend {
                destination,
                addend,
                source,
                rotation,
                width,
                signed,
            } => {
                let mut value =
                    super::extend(Expr::reg(u16::from(source), 32), width, signed, rotation);
                if let Some(addend) = addend {
                    value = Expr::bin(BinOp::Add, Expr::reg(u16::from(addend), 32), value);
                }
                lifter.assign(destination, value);
            }
            Self::Divide {
                destination,
                left,
                right,
                signed,
            } => {
                let value = super::divide(
                    Expr::reg(u16::from(left), 32),
                    Expr::reg(u16::from(right), 32),
                    signed,
                );
                lifter.assign(destination, value);
            }
            Self::Bitfield {
                destination,
                source,
                start,
                width,
            } => {
                lifter.assign(
                    destination,
                    super::bitfield(
                        Expr::reg(u16::from(source), 32),
                        u64::from(start),
                        u64::from(width),
                    ),
                );
            }
            Self::Reverse {
                destination,
                source,
            } => {
                let value = super::super::reverse_bytes(Expr::reg(u16::from(source), 32), 32, 4);
                lifter.assign(destination, value);
            }
            Self::Float { word, operation } => execute_float(lifter, word, operation),
        }
    }
}

fn execute_float(lifter: &mut Lifter<'_>, word: u32, operation: FloatOperation) {
    let precision = if word & 0x100 == 0 {
        Precision::Single
    } else {
        Precision::Double
    };
    let register = |field: u32, bit: u32, precision| {
        let low = ((word >> field) & 15) as u8;
        let high = ((word >> bit) & 1) as u8;
        if precision == Precision::Double {
            low | high << 4
        } else {
            low << 1 | high
        }
    };
    let destination = register(12, 22, precision);
    let left = register(16, 7, precision);
    let right = register(0, 5, precision);
    let value = match operation {
        FloatOperation::Add | FloatOperation::Subtract | FloatOperation::MultiplyAdd => {
            let product = Expr::apply(
                match operation {
                    FloatOperation::Add => Operation::FloatAdd(precision),
                    FloatOperation::Subtract => Operation::FloatSub(precision),
                    FloatOperation::MultiplyAdd => Operation::FloatMul(precision),
                    _ => unreachable!("arithmetic operations are matched above"),
                },
                vec![read(left, precision), read(right, precision)],
            );
            if matches!(operation, FloatOperation::MultiplyAdd) {
                Expr::apply(
                    Operation::FloatAdd(precision),
                    vec![read(destination, precision), product],
                )
            } else {
                product
            }
        }
        FloatOperation::Convert => {
            let to = if precision == Precision::Single {
                Precision::Double
            } else {
                Precision::Single
            };
            let value = Expr::apply(
                Operation::FloatConvert {
                    from: precision,
                    to,
                },
                vec![read(right, precision)],
            );
            write(lifter, register(12, 22, to), to, value);
            return;
        }
        FloatOperation::ToSigned => {
            let source = read(right, precision);
            let value = Expr::apply(
                Operation::FloatToInt {
                    signed: true,
                    bits: 32,
                    from: precision,
                    saturating: true,
                    rounding: Rounding::TowardZero,
                },
                vec![source.clone()],
            );
            let constant = |value: f64| {
                Expr::constant(match precision {
                    Precision::Single => u64::from((value as f32).to_bits()),
                    Precision::Double => value.to_bits(),
                })
            };
            let choose = |test, then, els| Expr::Select {
                cond: Cond::Ne,
                lhs: Box::new(test),
                rhs: Box::new(Expr::constant(0)),
                then: Box::new(then),
                els: Box::new(els),
            };
            let value = choose(
                Expr::apply(
                    Operation::FloatLessEqual(precision),
                    vec![constant(2147483648.0), source.clone()],
                ),
                Expr::constant(0x7fff_ffff),
                value,
            );
            let value = choose(
                Expr::apply(
                    Operation::FloatLessEqual(precision),
                    vec![source.clone(), constant(-2147483648.0)],
                ),
                Expr::constant(0x8000_0000),
                value,
            );
            let value = choose(
                Expr::apply(
                    Operation::FloatUnordered(precision),
                    vec![source.clone(), source],
                ),
                Expr::constant(0),
                value,
            );
            write(
                lifter,
                register(12, 22, Precision::Single),
                Precision::Single,
                value,
            );
            return;
        }
        FloatOperation::Move => {
            let single = register(16, 7, Precision::Single);
            let core = ((word >> 12) & 15) as u8;
            if word & (1 << 20) == 0 {
                write(
                    lifter,
                    single,
                    Precision::Single,
                    Expr::reg(u16::from(core), 32),
                );
            } else {
                lifter.assign(core, read(single, Precision::Single));
            }
            return;
        }
        FloatOperation::Compare => {
            lifter.float_comparison = true;
            for (index, number) in [(COMPARE_LEFT, destination), (COMPARE_RIGHT, right)] {
                let value = read(number, precision);
                let value = if precision == Precision::Single {
                    Expr::apply(
                        Operation::FloatConvert {
                            from: precision,
                            to: Precision::Double,
                        },
                        vec![value],
                    )
                } else {
                    value
                };
                super::super::preserve_compare(
                    &mut lifter.flags,
                    super::super::Write::Register(index, Some(&value)),
                    &mut lifter.stmts,
                );
                lifter.stmts.push(Stmt::Assign {
                    dest: RegRef { index, width: 64 },
                    value,
                    at: None,
                });
            }
            return;
        }
        FloatOperation::ReadFlags => {
            if !lifter.float_comparison {
                lifter.stmts.push(Stmt::unsupported(
                    "ARM VMRS without a known floating-point comparison",
                ));
                lifter.flags = None;
                lifter.touched = true;
                return;
            }
            lifter.set_flags(super::Flags::float_compare(
                Expr::reg(COMPARE_LEFT, 64),
                Expr::reg(COMPARE_RIGHT, 64),
                Precision::Double,
            ));
            return;
        }
    };
    write(lifter, destination, precision, value);
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FloatMemory {
                register,
                base,
                offset,
                double,
                load,
            } => write!(
                f,
                "v{} {}{register}, [r{base}, #{offset}]",
                if *load { "ldr" } else { "str" },
                if *double { "d" } else { "s" }
            ),
            Self::HalfMultiply {
                destination,
                left,
                right,
                halves,
            } => write!(
                f,
                "smul{}{} r{destination}, r{left}, r{right}",
                if halves & 1 == 0 { "b" } else { "t" },
                if halves & 2 == 0 { "b" } else { "t" }
            ),
            Self::FloatStack {
                first,
                count,
                double,
                pop,
            } => write!(
                f,
                "v{} {{{}{first}..{}}}",
                if *pop { "pop" } else { "push" },
                if *double { "d" } else { "s" },
                u16::from(*first) + u16::from(*count) - 1
            ),
            Self::Extend {
                destination,
                addend,
                source,
                rotation,
                width,
                signed,
            } => {
                if let Err(error) = write!(
                    f,
                    "{}xt{}{} r{destination}, ",
                    if *signed { "s" } else { "u" },
                    if addend.is_some() { "a" } else { "" },
                    if *width == 1 { "b" } else { "h" }
                ) {
                    return Err(error);
                }
                if let Some(addend) = addend
                    && let Err(error) = write!(f, "r{addend}, ")
                {
                    return Err(error);
                }
                write!(f, "r{source}, ror #{rotation}")
            }
            Self::Divide {
                destination,
                left,
                right,
                signed,
            } => write!(
                f,
                "{}div r{destination}, r{left}, r{right}",
                if *signed { "s" } else { "u" }
            ),
            Self::Bitfield {
                destination,
                source,
                start,
                width,
            } => write!(f, "ubfx r{destination}, r{source}, #{start}, #{width}"),
            Self::Reverse {
                destination,
                source,
            } => write!(f, "rev r{destination}, r{source}"),
            Self::Float { word, operation } => {
                let name = match operation {
                    FloatOperation::Add => "vadd",
                    FloatOperation::Subtract => "vsub",
                    FloatOperation::MultiplyAdd => "vmla",
                    FloatOperation::Convert => "vcvt",
                    FloatOperation::ToSigned => "vcvt.s32",
                    FloatOperation::Compare => "vcmp",
                    FloatOperation::ReadFlags => "vmrs",
                    FloatOperation::Move => "vmov",
                };
                write!(f, "{name} (0x{word:08x})")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_load_decodes_registers_and_rejects_writeback() {
        for mode in [ArmMode::Arm, ArmMode::Thumb] {
            for register in 0..32u32 {
                for base in 0..15u32 {
                    let prefix = if mode == ArmMode::Arm {
                        0xf420_070f
                    } else {
                        0xf920_070f
                    };
                    let word =
                        prefix | (base << 16) | ((register & 15) << 12) | ((register & 16) << 18);
                    let bytes = if mode == ArmMode::Arm {
                        word.to_le_bytes()
                    } else {
                        let high = (word >> 16) as u16;
                        let low = word as u16;
                        let [a, b] = high.to_le_bytes();
                        let [c, d] = low.to_le_bytes();
                        [a, b, c, d]
                    };
                    assert!(
                        matches!(decode(&bytes, mode), Some(Instruction::FloatMemory {
                        register: actual, base: actual_base, offset: 0, double: true, load: true
                    }) if u32::from(actual) == register && u32::from(actual_base) == base)
                    );
                }
            }
        }
        assert!(decode(&0xf460_070du32.to_le_bytes(), ArmMode::Arm).is_none());
        assert!(decode(&0xf46f_070fu32.to_le_bytes(), ArmMode::Arm).is_none());
    }

    #[test]
    fn invalid_and_truncated_encodings_are_not_accepted() {
        for bytes in [&[][..], &[0x70, 0, 0xaf][..]] {
            assert!(decode(bytes, ArmMode::Arm).is_none());
            assert!(decode(bytes, ArmMode::Thumb).is_none());
        }
        for word in [
            0xf6af_0070u32,
            0xe6af_f070,
            0xe6af_007f,
            0xe710_ff10,
            0xe7ff_0fd0,
            0xee10_fa10,
        ] {
            assert!(
                decode(&word.to_le_bytes(), ArmMode::Arm).is_none(),
                "{word:08x}"
            );
        }
        assert!(decode(&[0x30, 0xfe, 0x00, 0x0a], ArmMode::Thumb).is_none());
        for bytes in [
            [0x51, 0xfa, 0x82, 0xfd],
            [0x51, 0xfa, 0x8f, 0xf0],
            [0x5d, 0xfa, 0x82, 0xf0],
            [0x51, 0xfa, 0xc2, 0xf0],
        ] {
            assert!(decode(&bytes, ArmMode::Thumb).is_none(), "{bytes:x?}");
        }
    }
    #[test]
    fn vmrs_requires_a_comparison_since_the_last_call() {
        use crate::loader::{Image, Isa};
        use std::collections::HashSet;

        for (words, supported) in [
            (vec![0xeef1_fa10, 0xe12f_ff1e], false),
            (vec![0xeeb4_0b41, 0xeef1_fa10, 0xe12f_ff1e], true),
            (
                vec![0xeeb4_0b41, 0xeb00_0100, 0xeef1_fa10, 0xe12f_ff1e],
                false,
            ),
        ] {
            let code: Vec<u8> = words
                .iter()
                .flat_map(|word: &u32| word.to_le_bytes())
                .collect();
            let size = code.len() as u64;
            let image = Image::from_code(Isa::Arm32, 0, code);
            let blocks = super::super::lift(
                &image,
                0,
                image.read_vaddr(0, size).unwrap(),
                &HashSet::new(),
                &|_| Default::default(),
            )
            .unwrap();
            let unsupported = blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::Unsupported { .. }));
            assert_eq!(!unsupported, supported, "{blocks:?}");
        }
    }
}
