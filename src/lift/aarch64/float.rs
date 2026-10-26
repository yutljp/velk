use super::{
    BinOp, Expr, Flags, Instruction, LaneParity, Lifter, Operand, Operation, Precision, RegRef,
    Rounding, Stmt, a64, destination, immediate_lane, lane, lane_value, mask_bits, register_width,
    replicated, shift_count, simd, source_halves, unzip, vector, write_narrow,
};

fn unary_operation(opcode: a64::Opcode, p: Precision) -> Option<Operation> {
    use a64::Opcode as O;
    Some(match opcode {
        O::FABS => Operation::FloatAbs(p),
        O::FNEG => Operation::FloatNegate(p),
        O::FSQRT => Operation::FloatSqrt(p),
        O::FRINTA => Operation::FloatRound(p, Rounding::NearestAway),
        O::FRINTM => Operation::FloatRound(p, Rounding::Down),
        O::FRINTP => Operation::FloatRound(p, Rounding::Up),
        O::FRINTZ => Operation::FloatRound(p, Rounding::TowardZero),
        O::FRINTN | O::FRINTX | O::FRINTI => Operation::FloatRound(p, Rounding::NearestEven),
        _ => return None,
    })
}

fn integer_conversion(opcode: a64::Opcode) -> Option<(bool, Rounding)> {
    use a64::Opcode as O;
    Some(match opcode {
        O::FCVTZS => (true, Rounding::TowardZero),
        O::FCVTZU => (false, Rounding::TowardZero),
        O::FCVTNS => (true, Rounding::NearestEven),
        O::FCVTNU => (false, Rounding::NearestEven),
        O::FCVTAS => (true, Rounding::NearestAway),
        O::FCVTAU => (false, Rounding::NearestAway),
        O::FCVTMS => (true, Rounding::Down),
        O::FCVTMU => (false, Rounding::Down),
        O::FCVTPS => (true, Rounding::Up),
        O::FCVTPU => (false, Rounding::Up),
        _ => return None,
    })
}

/// `2^exponent` as a float of `precision`.
fn power_of_two(exponent: u32, precision: Precision) -> Expr {
    let value = 2f64.powi(exponent as i32);
    Expr::constant(match precision {
        Precision::Double => value.to_bits(),
        Precision::Single => u64::from((value as f32).to_bits()),
    })
}

fn precision(bits: u16) -> Option<Precision> {
    match bits {
        32 => Some(Precision::Single),
        64 => Some(Precision::Double),
        _ => None,
    }
}

pub(super) fn half_immediate(value: f64) -> Option<u64> {
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff).checked_sub(1008)?;
    if !(12..=19).contains(&exponent) || bits & ((1 << 48) - 1) != 0 {
        return None;
    }
    Some(((bits >> 48) & 0x8000) | (exponent << 10) | ((bits >> 42) & 0x3ff))
}

/// `f` on each float lane of `bits` of `args`, taken lane by lane: a
/// double in each half, or two singles. A scalar keeps only the lowest.
fn float_lanes(
    (bits, full, scalar): (u8, bool, bool),
    args: &[(Expr, Expr)],
    f: impl Fn(Vec<Expr>) -> Expr,
) -> (Expr, Expr) {
    let half = |part: fn(&(Expr, Expr)) -> Expr| {
        let parts: Vec<Expr> = args.iter().map(part).collect();
        if bits == 64 {
            return f(parts);
        }
        let low = f(parts
            .iter()
            .map(|part| Expr::bin(BinOp::And, part.clone(), Expr::constant(0xffff_ffff)))
            .collect());
        if scalar {
            return low;
        }
        let high = f(parts
            .iter()
            .map(|part| Expr::bin(BinOp::Shr, part.clone(), Expr::constant(32)))
            .collect());
        Expr::bin(
            BinOp::Or,
            low,
            Expr::bin(BinOp::Shl, high, Expr::constant(32)),
        )
    };
    let low = half(|part| part.0.clone());
    let high = if full {
        half(|part| part.1.clone())
    } else {
        Expr::constant(0)
    };
    (low, high)
}

/// The floating-point instructions on vectors, and on scalars where only
/// the vector forms' encodings give them.
pub(super) fn lift_vector_float(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use a64::Opcode as O;
    let ops = ins.operands;
    let (dest, scalar) = match ops[0] {
        Operand::SIMDRegister(a64::SIMDSizeCode::S, number) => {
            ((crate::arch::aarch64::V0 + 2 * number, false, 32), true)
        }
        operand => (vector(operand)?, false),
    };
    let source = |operand: Operand| match operand {
        Operand::SIMDRegister(..) => {
            let (slot, _) = simd(operand)?;
            Some((Expr::reg(slot, 64), Expr::constant(0)))
        }
        operand => source_halves(operand),
    };
    let shape = (dest.2, dest.1, scalar);
    let p = precision(u16::from(dest.2));
    let apply = |op: Operation, args: Vec<Expr>| Expr::apply(op, args);
    let truth = |value: Expr| {
        Expr::bin(
            BinOp::Mul,
            value,
            Expr::constant(mask_bits(u64::from(dest.2))),
        )
    };
    let (low, high) = match ins.opcode {
        O::FADD | O::FSUB | O::FMUL | O::FDIV | O::FABD => {
            let p = p?;
            let args = [source(ops[1])?, source(ops[2])?];
            float_lanes(shape, &args, |mut lane| {
                let (a, b) = (lane.remove(0), lane.remove(0));
                match ins.opcode {
                    O::FADD => apply(Operation::FloatAdd(p), vec![a, b]),
                    O::FSUB => apply(Operation::FloatSub(p), vec![a, b]),
                    O::FMUL => apply(Operation::FloatMul(p), vec![a, b]),
                    O::FDIV => apply(Operation::FloatDiv(p), vec![a, b]),
                    _ => apply(
                        Operation::FloatAbs(p),
                        vec![apply(Operation::FloatSub(p), vec![a, b])],
                    ),
                }
            })
        }
        // The product added to the destination, or for fmls the first
        // source negated, rounded once.
        O::FMLA | O::FMLS => {
            let p = p?;
            let accumulator = (Expr::reg(dest.0, 64), Expr::reg(dest.0 + 1, 64));
            let args = [source(ops[1])?, source(ops[2])?, accumulator];
            float_lanes(shape, &args, |mut lane| {
                let (n, m, acc) = (lane.remove(0), lane.remove(0), lane.remove(0));
                let n = if ins.opcode == O::FMLS {
                    apply(Operation::FloatNegate(p), vec![n])
                } else {
                    n
                };
                apply(Operation::FloatMulAdd(p), vec![n, m, acc])
            })
        }
        O::FABS
        | O::FNEG
        | O::FSQRT
        | O::FRINTN
        | O::FRINTA
        | O::FRINTM
        | O::FRINTP
        | O::FRINTZ
        | O::FRINTX
        | O::FRINTI => {
            let p = p?;
            let op = unary_operation(ins.opcode, p)?;
            float_lanes(shape, &[source(ops[1])?], |lane| apply(op, lane))
        }
        // All ones where the comparison holds; against zero, or the
        // absolute values for the facge and facgt.
        O::FCMEQ | O::FCMGE | O::FCMGT | O::FCMLE | O::FCMLT | O::FACGE | O::FACGT => {
            let p = p?;
            let args = [source(ops[1])?, source(ops[2])?];
            float_lanes(shape, &args, |mut lane| {
                let (a, b) = (lane.remove(0), lane.remove(0));
                let abs = |value| apply(Operation::FloatAbs(p), vec![value]);
                truth(match ins.opcode {
                    O::FCMEQ => apply(Operation::FloatEqual(p), vec![a, b]),
                    O::FCMGE => apply(Operation::FloatLessEqual(p), vec![b, a]),
                    O::FCMGT => apply(Operation::FloatLess(p), vec![b, a]),
                    O::FCMLE => apply(Operation::FloatLessEqual(p), vec![a, b]),
                    O::FCMLT => apply(Operation::FloatLess(p), vec![a, b]),
                    O::FACGE => apply(Operation::FloatLessEqual(p), vec![abs(b), abs(a)]),
                    _ => apply(Operation::FloatLess(p), vec![abs(b), abs(a)]),
                })
            })
        }
        // A fixed-point source has that many fraction bits; dividing by a
        // power of two adds no rounding.
        O::SCVTF | O::UCVTF => {
            let p = p?;
            let fraction = shift_count(ops[2]).unwrap_or(0) as u32;
            float_lanes(shape, &[source(ops[1])?], |lane| {
                let converted = apply(
                    Operation::IntToFloat {
                        signed: ins.opcode == O::SCVTF,
                        bits: dest.2,
                        to: p,
                    },
                    lane,
                );
                if fraction > 0 {
                    apply(
                        Operation::FloatDiv(p),
                        vec![converted, power_of_two(fraction, p)],
                    )
                } else {
                    converted
                }
            })
        }
        O::FCVTZS
        | O::FCVTZU
        | O::FCVTNS
        | O::FCVTNU
        | O::FCVTAS
        | O::FCVTAU
        | O::FCVTMS
        | O::FCVTMU
        | O::FCVTPS
        | O::FCVTPU => {
            let p = p?;
            let (signed, rounding) = integer_conversion(ins.opcode)?;
            let fraction = shift_count(ops[2]).unwrap_or(0) as u32;
            float_lanes(shape, &[source(ops[1])?], |mut lane| {
                let value = lane.remove(0);
                // A fixed-point result keeps that many fraction bits.
                let value = if fraction > 0 {
                    apply(
                        Operation::FloatMul(p),
                        vec![value, power_of_two(fraction, p)],
                    )
                } else {
                    value
                };
                apply(
                    Operation::FloatToInt {
                        signed,
                        bits: dest.2,
                        from: p,
                        saturating: true,
                        rounding,
                    },
                    vec![value],
                )
            })
        }
        // Neighbouring lanes of the two sources taken as one added, or the
        // two lanes of one source for the scalar form.
        O::FADDP => {
            let p = p?;
            let add = |lane: Vec<Expr>| apply(Operation::FloatAdd(p), lane);
            let a = source(ops[1])?;
            if matches!(ops[2], Operand::Nothing) {
                let pair = if dest.2 == 64 {
                    (a.0, a.1)
                } else {
                    (
                        Expr::bin(BinOp::And, a.0.clone(), Expr::constant(0xffff_ffff)),
                        Expr::bin(BinOp::Shr, a.0, Expr::constant(32)),
                    )
                };
                (add(vec![pair.0, pair.1]), Expr::constant(0))
            } else {
                let b = source(ops[2])?;
                let even = unzip(a.clone(), b.clone(), dest.2, dest.1, LaneParity::Even);
                let odd = unzip(a, b, dest.2, dest.1, LaneParity::Odd);
                float_lanes(shape, &[even, odd], add)
            }
        }
        // Singles to doubles, from the low half or, for fcvtl2, the high one.
        O::FCVTL | O::FCVTL2 if dest.2 == 64 => {
            let (low, high) = source(ops[1])?;
            let half = if ins.opcode == O::FCVTL2 { high } else { low };
            let widen = |single: Expr| {
                apply(
                    Operation::FloatConvert {
                        from: Precision::Single,
                        to: Precision::Double,
                    },
                    vec![single],
                )
            };
            (
                widen(Expr::bin(
                    BinOp::And,
                    half.clone(),
                    Expr::constant(0xffff_ffff),
                )),
                widen(Expr::bin(BinOp::Shr, half, Expr::constant(32))),
            )
        }
        // Doubles to singles, into the low half or, for fcvtn2, the high one.
        O::FCVTN | O::FCVTN2 if dest.2 == 32 => {
            let (low, high) = source(ops[1])?;
            let narrow = |double: Expr| {
                apply(
                    Operation::FloatConvert {
                        from: Precision::Double,
                        to: Precision::Single,
                    },
                    vec![double],
                )
            };
            let value = Expr::bin(
                BinOp::Or,
                narrow(low),
                Expr::bin(BinOp::Shl, narrow(high), Expr::constant(32)),
            );
            write_narrow(lifter, dest, ins.opcode == O::FCVTN2, value);
            return Some(());
        }
        _ => return None,
    };
    lifter.write_vector(dest, low, high);
    Some(())
}

/// The scalar instructions on floating-point registers.
pub(super) fn lift_float(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use a64::Opcode as O;
    let ops = ins.operands;
    let read = |lifter: &Lifter, operand: Operand| -> Option<(Expr, Precision)> {
        let (slot, bits) = simd(operand)?;
        Some((lifter.read_simd(slot, bits), precision(bits)?))
    };
    let float = |op: Operation, args: Vec<Expr>| Expr::apply(op, args);
    match ins.opcode {
        O::FADD | O::FSUB | O::FMUL | O::FDIV | O::FNMUL => {
            let (slot, bits) = simd(ops[0])?;
            let ((a, p), (b, _)) = (read(lifter, ops[1])?, read(lifter, ops[2])?);
            let value = match ins.opcode {
                O::FADD => float(Operation::FloatAdd(p), vec![a, b]),
                O::FSUB => float(Operation::FloatSub(p), vec![a, b]),
                O::FMUL => float(Operation::FloatMul(p), vec![a, b]),
                O::FDIV => float(Operation::FloatDiv(p), vec![a, b]),
                _ => float(
                    Operation::FloatNegate(p),
                    vec![float(Operation::FloatMul(p), vec![a, b])],
                ),
            };
            lifter.write_simd(slot, bits, (value, Expr::constant(0)));
        }
        O::FSQRT
        | O::FNEG
        | O::FABS
        | O::FRINTN
        | O::FRINTA
        | O::FRINTM
        | O::FRINTP
        | O::FRINTZ
        | O::FRINTX
        | O::FRINTI => {
            let (slot, bits) = simd(ops[0])?;
            let (a, p) = read(lifter, ops[1])?;
            let op = unary_operation(ins.opcode, p)?;
            lifter.write_simd(slot, bits, (float(op, vec![a]), Expr::constant(0)));
        }
        // fmadd d, n, m, a is a + n * m; fmsub negates the product, fnmadd
        // both the product and the addend, and fnmsub the addend.
        O::FMADD | O::FMSUB | O::FNMADD | O::FNMSUB => {
            let (slot, bits) = simd(ops[0])?;
            let ((n, p), (m, _), (a, _)) = (
                read(lifter, ops[1])?,
                read(lifter, ops[2])?,
                read(lifter, ops[3])?,
            );
            let negate = |value| float(Operation::FloatNegate(p), vec![value]);
            let fused = |n, a| float(Operation::FloatMulAdd(p), vec![n, m.clone(), a]);
            let value = match ins.opcode {
                O::FMADD => fused(n, a),
                O::FMSUB => fused(negate(n), a),
                O::FNMADD => fused(negate(n), negate(a)),
                _ => fused(n, negate(a)),
            };
            lifter.write_simd(slot, bits, (value, Expr::constant(0)));
        }
        O::FCMP | O::FCMPE => {
            let (a, p) = read(lifter, ops[0])?;
            let b = match ops[1] {
                Operand::ImmediateDouble(_) => Expr::constant(0),
                operand => read(lifter, operand)?.0,
            };
            lifter.last_compare = Some(Flags::float_compare(a, b, p));
        }
        // Compare when the condition holds, and otherwise set the flags to the
        // immediate, as ccmp does.
        O::FCCMP | O::FCCMPE => {
            let earlier = match ops[3] {
                Operand::ConditionCode(code) => lifter.test_code(code),
                _ => return None,
            };
            let ((a, p), (b, _), Operand::Immediate(nzcv)) =
                (read(lifter, ops[0])?, read(lifter, ops[1])?, ops[2])
            else {
                return None;
            };
            lifter.last_compare = Flags::float_compare(a, b, p).chosen_by(earlier, nzcv as u8);
        }
        O::FCSEL => {
            let (slot, bits) = simd(ops[0])?;
            let ((a, _), (b, _)) = (read(lifter, ops[1])?, read(lifter, ops[2])?);
            let Operand::ConditionCode(code) = ops[3] else {
                return None;
            };
            match lifter.test_code(code).select(a, b) {
                Some(value) => lifter.write_simd(slot, bits, (value, Expr::constant(0))),
                None => lifter.stmts.push(Stmt::unsupported(
                    "conditional select on flags not modelled here".to_owned(),
                )),
            }
        }
        O::FCVT => {
            let (slot, bits) = simd(ops[0])?;
            let (a, from) = read(lifter, ops[1])?;
            let to = precision(bits)?;
            let value = float(Operation::FloatConvert { from, to }, vec![a]);
            lifter.write_simd(slot, bits, (value, Expr::constant(0)));
        }
        O::SCVTF | O::UCVTF => {
            let (slot, bits) = simd(ops[0])?;
            let to = precision(bits)?;
            let source = register_width(ops[1])?;
            let value = lifter.operand(ops[1], source)?;
            let converted = float(
                Operation::IntToFloat {
                    signed: ins.opcode == O::SCVTF,
                    bits: source,
                    to,
                },
                vec![value],
            );
            // A fixed-point source has that many fraction bits; dividing by
            // a power of two adds no rounding.
            let converted = match ops[2] {
                Operand::Immediate(fraction) if fraction > 0 => float(
                    Operation::FloatDiv(to),
                    vec![converted, power_of_two(fraction, to)],
                ),
                _ => converted,
            };
            lifter.write_simd(slot, bits, (converted, Expr::constant(0)));
        }
        O::FCVTZS
        | O::FCVTZU
        | O::FCVTNS
        | O::FCVTNU
        | O::FCVTAS
        | O::FCVTAU
        | O::FCVTMS
        | O::FCVTMU
        | O::FCVTPS
        | O::FCVTPU => {
            let (a, from) = read(lifter, ops[1])?;
            let (signed, rounding) = integer_conversion(ins.opcode)?;
            // A fixed-point result keeps that many fraction bits.
            let a = match ops[2] {
                Operand::Immediate(fraction) if fraction > 0 => float(
                    Operation::FloatMul(from),
                    vec![a, power_of_two(fraction, from)],
                ),
                _ => a,
            };
            let converted = float(
                Operation::FloatToInt {
                    signed,
                    bits: register_width(ops[0])?,
                    from,
                    saturating: true,
                    rounding,
                },
                vec![a],
            );
            if let Some(dest) = destination(ops[0]) {
                lifter.assign(dest, converted);
            }
        }
        O::FMOV => match (ops[0], ops[1]) {
            (Operand::SIMDRegister(..), Operand::SIMDRegister(..)) => {
                let ((slot, bits), (from, _)) = (simd(ops[0])?, simd(ops[1])?);
                let value = lifter.read_simd(from, bits);
                lifter.write_simd(slot, bits, (value, Expr::constant(0)));
            }
            (Operand::SIMDRegister(..), Operand::Register(..)) => {
                let (slot, bits) = simd(ops[0])?;
                let value = lifter.operand(ops[1], bits as u8)?;
                lifter.write_simd(slot, bits, (value, Expr::constant(0)));
            }
            (Operand::Register(..), Operand::SIMDRegister(..)) => {
                let (from, bits) = simd(ops[1])?;
                let value = lifter.read_simd(from, bits);
                if let Some(dest) = destination(ops[0]) {
                    lifter.assign(dest, value);
                }
            }
            (Operand::SIMDRegister(..), Operand::ImmediateDouble(value)) => {
                let (slot, bits) = simd(ops[0])?;
                let pattern = if bits == 16 {
                    half_immediate(value)?
                } else {
                    match precision(bits)? {
                        Precision::Double => value.to_bits(),
                        Precision::Single => u64::from((value as f32).to_bits()),
                    }
                };
                lifter.write_simd(slot, bits, (Expr::constant(pattern), Expr::constant(0)));
            }
            // The constant in every lane.
            (Operand::SIMDRegisterElements(..), Operand::ImmediateDouble(value)) => {
                let dest = vector(ops[0])?;
                let pattern = match precision(u16::from(dest.2))? {
                    Precision::Double => value.to_bits(),
                    Precision::Single => u64::from((value as f32).to_bits()),
                };
                let half = Expr::constant(replicated(pattern, dest.2));
                lifter.write_vector(dest, half.clone(), half);
            }
            // The upper half of a 128-bit register, which the rest keeps.
            (Operand::SIMDRegisterElementsLane(_, number, a64::SIMDSizeCode::D, 1), source) => {
                let value = lifter.operand(source, 64)?;
                let slot = crate::arch::aarch64::V0 + 2 * number + 1;
                lifter.assign(
                    RegRef {
                        index: slot,
                        width: 64,
                    },
                    value,
                );
            }
            (dest, Operand::SIMDRegisterElementsLane(_, number, a64::SIMDSizeCode::D, 1)) => {
                let value = Expr::reg(crate::arch::aarch64::V0 + 2 * number + 1, 64);
                if let Some(dest) = destination(dest) {
                    lifter.assign(dest, value);
                }
            }
            _ => return None,
        },
        // A lane read out to a scalar or general register.
        O::DUP | O::UMOV | O::SMOV if lane(ops[1]).is_some() && vector(ops[0]).is_none() => {
            let source = lane(ops[1])?;
            let value = lane_value(source);
            match simd(ops[0]) {
                Some((slot, bits)) if u64::from(bits) == source.2 => {
                    lifter.write_simd(slot, bits, (value, Expr::constant(0)))
                }
                Some(_) => return None,
                None => {
                    let value = if ins.opcode == O::SMOV {
                        Expr::SignExtend {
                            value: Box::new(value),
                            width: (source.2 / 8) as u8,
                        }
                    } else {
                        value
                    };
                    if let Some(dest) = destination(ops[0]) {
                        lifter.assign(dest, value);
                    }
                }
            }
        }
        // A lane written from a general register or another lane; the rest
        // of the register stays.
        O::INS => {
            let (slot, shift, bits) = lane(ops[0])?;
            let value = match lane(ops[1]) {
                Some(source) => lane_value(source),
                None => lifter.operand(ops[1], bits as u8)?,
            };
            let ones = if bits == 64 {
                u64::MAX
            } else {
                (1 << bits) - 1
            };
            let merged = if bits == 64 {
                value
            } else {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(
                        BinOp::And,
                        Expr::reg(slot, 64),
                        Expr::constant(!(ones << shift)),
                    ),
                    Expr::bin(
                        BinOp::Shl,
                        Expr::bin(BinOp::And, value, Expr::constant(ones)),
                        Expr::constant(shift),
                    ),
                )
            };
            lifter.assign(
                RegRef {
                    index: slot,
                    width: 64,
                },
                merged,
            );
        }
        // Zero, or a 64-bit pattern in each half.
        // A shifted immediate (or its complement) in every lane.
        O::MOVI | O::MVNI if matches!(ops[1], Operand::ImmShift(..) | Operand::ImmShiftMSL(..)) => {
            let dest = vector(ops[0])?;
            let lane = immediate_lane(ops[1], ins.opcode == O::MVNI, dest.2)?;
            let half = Expr::constant(replicated(lane, dest.2));
            lifter.write_vector(dest, half.clone(), half);
        }
        O::MOVI => {
            let Operand::Imm64(value) = ops[1] else {
                return None;
            };
            match ops[0] {
                Operand::SIMDRegister(a64::SIMDSizeCode::D, number) => lifter.write_simd(
                    crate::arch::aarch64::V0 + 2 * number,
                    64,
                    (Expr::constant(value), Expr::constant(0)),
                ),
                Operand::SIMDRegisterElements(size, number, a64::SIMDSizeCode::D)
                    if value == 0 || size == a64::SIMDSizeCode::Q =>
                {
                    let high = if size == a64::SIMDSizeCode::Q {
                        value
                    } else {
                        0
                    };
                    lifter.write_simd(
                        crate::arch::aarch64::V0 + 2 * number,
                        128,
                        (Expr::constant(value), Expr::constant(high)),
                    )
                }
                Operand::SIMDRegisterElements(size, number, _) if value == 0 => lifter.write_simd(
                    crate::arch::aarch64::V0 + 2 * number,
                    if size == a64::SIMDSizeCode::Q {
                        128
                    } else {
                        64
                    },
                    (Expr::constant(0), Expr::constant(0)),
                ),
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_properties_preserve_rounding_and_signedness() {
        use a64::Opcode as O;
        for p in [Precision::Single, Precision::Double] {
            for (opcode, expected) in [
                (O::FABS, Operation::FloatAbs(p)),
                (O::FNEG, Operation::FloatNegate(p)),
                (O::FSQRT, Operation::FloatSqrt(p)),
                (O::FRINTN, Operation::FloatRound(p, Rounding::NearestEven)),
                (O::FRINTA, Operation::FloatRound(p, Rounding::NearestAway)),
                (O::FRINTM, Operation::FloatRound(p, Rounding::Down)),
                (O::FRINTP, Operation::FloatRound(p, Rounding::Up)),
                (O::FRINTZ, Operation::FloatRound(p, Rounding::TowardZero)),
                (O::FRINTX, Operation::FloatRound(p, Rounding::NearestEven)),
                (O::FRINTI, Operation::FloatRound(p, Rounding::NearestEven)),
            ] {
                assert_eq!(unary_operation(opcode, p), Some(expected));
                assert_eq!(integer_conversion(opcode), None);
            }
        }
        for (opcode, signed, rounding) in [
            (O::FCVTZS, true, Rounding::TowardZero),
            (O::FCVTZU, false, Rounding::TowardZero),
            (O::FCVTNS, true, Rounding::NearestEven),
            (O::FCVTNU, false, Rounding::NearestEven),
            (O::FCVTAS, true, Rounding::NearestAway),
            (O::FCVTAU, false, Rounding::NearestAway),
            (O::FCVTMS, true, Rounding::Down),
            (O::FCVTMU, false, Rounding::Down),
            (O::FCVTPS, true, Rounding::Up),
            (O::FCVTPU, false, Rounding::Up),
        ] {
            assert_eq!(integer_conversion(opcode), Some((signed, rounding)));
            assert_eq!(unary_operation(opcode, Precision::Single), None);
        }
        for opcode in [O::FADD, O::FCVT, O::SCVTF, O::UCVTF] {
            assert_eq!(unary_operation(opcode, Precision::Double), None);
            assert_eq!(integer_conversion(opcode), None);
        }
        assert_eq!(precision(16), None);
        assert_eq!(precision(32), Some(Precision::Single));
        assert_eq!(precision(64), Some(Precision::Double));
    }
}
