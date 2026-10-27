use super::{
    BinOp, Cond, Expr, Flags, Instruction, Lifter, Mnemonic, OpKind, Operation, Precision,
    Rounding, gpr, load_at, memory_address, operand, operand_width, xmm,
};

/// The scalar SSE floating-point instructions: arithmetic on the low double
/// or single of an xmm register, which keeps the register's other bits,
/// conversions, and the compares that set the flags.
pub(super) fn lift_float(lifter: &mut Lifter, instruction: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let precision = match instruction.mnemonic() {
        Addsd | Subsd | Mulsd | Divsd | Sqrtsd | Minsd | Maxsd | Ucomisd | Comisd | Cvtsi2sd
        | Cvttsd2si | Cvtsd2si | Cvtsd2ss | Roundsd => Precision::Double,
        Addss | Subss | Mulss | Divss | Sqrtss | Minss | Maxss | Ucomiss | Comiss | Cvtsi2ss
        | Cvttss2si | Cvtss2si | Cvtss2sd | Roundss => Precision::Single,
        _ => return None,
    };
    // An xmm operand's low bits, or a value loaded from memory.
    let float_operand = |index: u32, precision: Precision| -> Option<Expr> {
        match instruction.op_kind(index) {
            OpKind::Register => {
                let slot = xmm(instruction.op_register(index))?;
                Some(Lifter::read_reg(slot, precision.bits()))
            }
            OpKind::Memory => Some(load_at(memory_address(instruction)?, precision.bits() / 8)),
            _ => None,
        }
    };
    // The low bits of the destination receive `value`; the rest stay.
    let write_low = |lifter: &mut Lifter, value: Expr, precision: Precision| -> Option<()> {
        let slot = xmm(instruction.op0_register())?;
        let merged = match precision {
            Precision::Double => value,
            Precision::Single => Expr::bin(
                BinOp::Or,
                Expr::bin(
                    BinOp::And,
                    Lifter::read_reg(slot, 64),
                    Expr::constant(!0xffff_ffff),
                ),
                value,
            ),
        };
        lifter.assign(slot, 64, merged);
        Some(())
    };
    match instruction.mnemonic() {
        Addsd | Addss | Subsd | Subss | Mulsd | Mulss | Divsd | Divss => {
            let op = match instruction.mnemonic() {
                Addsd | Addss => Operation::FloatAdd(precision),
                Subsd | Subss => Operation::FloatSub(precision),
                Mulsd | Mulss => Operation::FloatMul(precision),
                _ => Operation::FloatDiv(precision),
            };
            let (a, b) = (float_operand(0, precision)?, float_operand(1, precision)?);
            write_low(lifter, Expr::apply(op, vec![a, b]), precision)?;
        }
        Sqrtsd | Sqrtss => {
            let a = float_operand(1, precision)?;
            write_low(
                lifter,
                Expr::apply(Operation::FloatSqrt(precision), vec![a]),
                precision,
            )?;
        }
        // The second operand unless the first is strictly smaller (larger),
        // which a NaN or two zeros never are.
        Minsd | Minss | Maxsd | Maxss => {
            let (a, b) = (float_operand(0, precision)?, float_operand(1, precision)?);
            let (smaller, larger) = if matches!(instruction.mnemonic(), Minsd | Minss) {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            };
            let first = Expr::Select {
                cond: Cond::Ne,
                lhs: Box::new(Expr::apply(
                    Operation::FloatLess(precision),
                    vec![smaller, larger],
                )),
                rhs: Box::new(Expr::constant(0)),
                then: Box::new(a),
                els: Box::new(b),
            };
            write_low(lifter, first, precision)?;
        }
        Ucomisd | Comisd | Ucomiss | Comiss => {
            let (a, b) = (float_operand(0, precision)?, float_operand(1, precision)?);
            lifter.set_flags(Flags::float_compare(a, b, precision));
        }
        Cvtsi2sd | Cvtsi2ss => {
            let bits = operand_width(instruction, 1)?;
            let value = operand(lifter, instruction, 1)?;
            let converted = Expr::apply(
                Operation::IntToFloat {
                    signed: true,
                    bits,
                    to: precision,
                },
                vec![value],
            );
            write_low(lifter, converted, precision)?;
        }
        // The rounding ones round as the default mode does.
        Cvttsd2si | Cvttss2si | Cvtsd2si | Cvtss2si => {
            let (index, bits) = gpr(instruction.op0_register())?;
            let value = float_operand(1, precision)?;
            let rounding = match instruction.mnemonic() {
                Cvttsd2si | Cvttss2si => Rounding::TowardZero,
                _ => Rounding::NearestEven,
            };
            let converted = Expr::apply(
                Operation::FloatToInt {
                    signed: true,
                    bits,
                    from: precision,
                    saturating: false,
                    rounding,
                },
                vec![value],
            );
            lifter.assign(index, bits, converted);
        }
        // The immediate names the rounding, or with bit 2 the current mode.
        Roundsd | Roundss => {
            let value = float_operand(1, precision)?;
            let rounding = match instruction.immediate8() {
                mode if mode & 4 != 0 => Rounding::NearestEven,
                mode => match mode & 3 {
                    0 => Rounding::NearestEven,
                    1 => Rounding::Down,
                    2 => Rounding::Up,
                    _ => Rounding::TowardZero,
                },
            };
            let rounded = Expr::apply(Operation::FloatRound(precision, rounding), vec![value]);
            write_low(lifter, rounded, precision)?;
        }
        Cvtsd2ss | Cvtss2sd => {
            let to = match precision {
                Precision::Double => Precision::Single,
                Precision::Single => Precision::Double,
            };
            let value = float_operand(1, precision)?;
            let converted = Expr::apply(
                Operation::FloatConvert {
                    from: precision,
                    to,
                },
                vec![value],
            );
            write_low(lifter, converted, to)?;
        }
        _ => return None,
    }
    Some(())
}
