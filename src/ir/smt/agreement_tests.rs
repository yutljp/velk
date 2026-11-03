//! The SMT translation computes what the interpreter computes: every proof
//! and every rewrite check rests on the two agreeing.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use super::{constant, memory_value};
use crate::ir::{BinOp, Expr, LaneOp, Operation, Precision, Rounding};

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn value(&mut self) -> u64 {
        match self.below(4) {
            0 => self.pick(&[
                0,
                1,
                2,
                7,
                63,
                64,
                0x7f,
                0x80,
                0xff,
                0x7fff,
                0x8000,
                0xffff,
                0x7fff_ffff,
                0x8000_0000,
                0xffff_ffff,
                1 << 32,
                i64::MAX as u64,
                i64::MIN as u64,
                u64::MAX,
                u64::MAX - 1,
            ]),
            1 => self.next() & 0xff,
            2 => self.next() & 0xffff_ffff,
            _ => self.next(),
        }
    }
}

const BINARY: [BinOp; 15] = [
    BinOp::Add,
    BinOp::Sub,
    BinOp::Mul,
    BinOp::MulHigh,
    BinOp::MulHighS,
    BinOp::And,
    BinOp::Or,
    BinOp::Xor,
    BinOp::Shl,
    BinOp::Shr,
    BinOp::Sar,
    BinOp::DivS,
    BinOp::ModS,
    BinOp::DivU,
    BinOp::ModU,
];

const LANES: [LaneOp; 24] = [
    LaneOp::Add,
    LaneOp::Sub,
    LaneOp::Mul,
    LaneOp::Equal,
    LaneOp::GreaterSigned,
    LaneOp::GreaterUnsigned,
    LaneOp::GreaterEqualSigned,
    LaneOp::GreaterEqualUnsigned,
    LaneOp::MinSigned,
    LaneOp::MinUnsigned,
    LaneOp::MaxSigned,
    LaneOp::MaxUnsigned,
    LaneOp::ShiftLeft,
    LaneOp::ShiftRight,
    LaneOp::ShiftRightSigned,
    LaneOp::ShiftVariableUnsigned,
    LaneOp::AddSaturatingSigned,
    LaneOp::AddSaturatingUnsigned,
    LaneOp::SubSaturatingSigned,
    LaneOp::SubSaturatingUnsigned,
    LaneOp::Average,
    LaneOp::MulHighSigned,
    LaneOp::MulHighUnsigned,
    LaneOp::CountLeadingZeros,
];

fn operation(random: &mut Random) -> Operation {
    let precision = random.pick(&[Precision::Single, Precision::Double]);
    let rounding = random.pick(&[
        Rounding::TowardZero,
        Rounding::NearestEven,
        Rounding::NearestAway,
        Rounding::Down,
        Rounding::Up,
    ]);
    let lane = random.pick(&[8, 16, 32]);
    let bits = random.pick(&[8, 16, 32, 64]);
    match random.below(22) {
        0 => Operation::Lanes(random.pick(&LANES), lane),
        1 => Operation::Lanes(LaneOp::PopCount, 8),
        2 => Operation::InterleaveLow(random.pick(&[8, 16])),
        3 => Operation::InterleaveHigh(random.pick(&[8, 16])),
        4 => Operation::Widen {
            bits: random.pick(&[8, 16]),
            signed: random.below(2) == 0,
            high: random.below(2) == 0,
        },
        5 => Operation::Narrow(random.pick(&[16, 32])),
        6 => Operation::SignBits(lane),
        7 => Operation::SumLanes(lane),
        8 => Operation::Pack {
            from: random.pick(&[16, 32]),
            unsigned: random.below(2) == 0,
        },
        9 => Operation::SumLanesLong {
            bits: lane,
            signed: random.below(2) == 0,
        },
        10 => Operation::CountLeadingZeros(bits),
        11 => Operation::CountTrailingZeros(bits),
        12 => Operation::PopCount(bits),
        13 => Operation::ReverseBits(bits),
        14 => random.pick(&[
            Operation::FloatAdd(precision),
            Operation::FloatSub(precision),
            Operation::FloatMul(precision),
            Operation::FloatDiv(precision),
            Operation::FloatEqual(precision),
            Operation::FloatLess(precision),
            Operation::FloatLessEqual(precision),
            Operation::FloatUnordered(precision),
        ]),
        15 => random.pick(&[
            Operation::FloatSqrt(precision),
            Operation::FloatNegate(precision),
            Operation::FloatAbs(precision),
        ]),
        16 => Operation::FloatMulAdd(precision),
        17 => Operation::FloatRound(precision, rounding),
        18 => Operation::IntToFloat {
            signed: random.below(2) == 0,
            bits: random.pick(&[32, 64]),
            to: precision,
        },
        19 => Operation::FloatToInt {
            signed: random.below(2) == 0,
            bits: random.pick(&[32, 64]),
            from: precision,
            saturating: random.below(2) == 0,
            rounding,
        },
        20 => Operation::FloatConvert {
            from: precision,
            to: random.pick(&[Precision::Single, Precision::Double]),
        },
        _ => Operation::Lanes(random.pick(&LANES), lane),
    }
}

fn expression(random: &mut Random, depth: u32) -> Expr {
    if depth == 0 || random.below(4) == 0 {
        return if random.below(2) == 0 {
            Expr::Reg {
                index: random.below(4) as u16,
                width: random.pick(&[8, 16, 32, 64]),
            }
        } else {
            Expr::Const(random.value())
        };
    }
    match random.below(8) {
        0..=3 => Expr::Bin {
            op: random.pick(&BINARY),
            lhs: Box::new(expression(random, depth - 1)),
            rhs: Box::new(expression(random, depth - 1)),
        },
        4 => Expr::SignExtend {
            value: Box::new(expression(random, depth - 1)),
            width: random.pick(&[1, 2, 4]),
        },
        5 => Expr::Select {
            cond: random.pick(&super::CONDITIONS),
            lhs: Box::new(expression(random, depth - 1)),
            rhs: Box::new(expression(random, depth - 1)),
            then: Box::new(expression(random, depth - 1)),
            els: Box::new(expression(random, depth - 1)),
        },
        6 if random.below(2) == 0 => Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(expression(random, depth - 1)),
            rhs: Box::new(Expr::Const(random.pick(&[0xff, 0xffff, 0xffff_ffff]))),
        },
        _ => {
            let op = operation(random);
            let args = (0..op.arity())
                .map(|_| expression(random, depth - 1))
                .collect();
            Expr::Apply { op, args }
        }
    }
}

fn floats(expr: &Expr) -> bool {
    matches!(expr, Expr::Apply { op, .. } if op.argument_precision().is_some()
        || op.result_precision().is_some())
        || crate::ir::visit::children(expr).into_iter().any(floats)
}

#[test]
fn translation_agrees_with_the_interpreter() {
    let Ok(mut child) = Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    else {
        eprintln!("SKIP translation agreement: z3 unavailable");
        return;
    };
    let mut stdin = child.stdin.take().expect("piped z3 stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped z3 stdout"));
    writeln!(
        stdin,
        "(declare-const memory (Array (_ BitVec 64) (_ BitVec 8)))\n\
         (define-fun count8 ((x (_ BitVec 8))) (_ BitVec 4) (bvadd \
         ((_ zero_extend 3) ((_ extract 0 0) x)) ((_ zero_extend 3) ((_ extract 1 1) x)) \
         ((_ zero_extend 3) ((_ extract 2 2) x)) ((_ zero_extend 3) ((_ extract 3 3) x)) \
         ((_ zero_extend 3) ((_ extract 4 4) x)) ((_ zero_extend 3) ((_ extract 5 5) x)) \
         ((_ zero_extend 3) ((_ extract 6 6) x)) ((_ zero_extend 3) ((_ extract 7 7) x))))"
    )
    .expect("write SMT preamble");
    let mut random = Random(0x5eed_1234_abcd_ef01);
    let mut compared = 0;
    let mut undefined = 0;
    let mut failures = Vec::new();
    for _ in 0..20_000 {
        let expr = expression(&mut random, 3);
        let values: Vec<u64> = (0..4).map(|_| random.value()).collect();
        let expected =
            crate::ir::semantics::evaluate(&expr, &|index| values.get(usize::from(index)).copied());
        // The interpreter leaves a NaN's bit pattern to the processor.
        if expected.is_none() && floats(&expr) {
            continue;
        }
        let registers: BTreeMap<u16, String> = values
            .iter()
            .enumerate()
            .map(|(index, value)| (index as u16, constant(*value)))
            .collect();
        let translated = memory_value(&expr, &registers, "memory");
        writeln!(
            stdin,
            "(simplify {})\n(simplify {})",
            translated.defined, translated.term
        )
        .expect("write SMT query");
        stdin.flush().expect("flush SMT query");
        let mut read = || {
            let mut line = String::new();
            stdout.read_line(&mut line).expect("read z3 answer");
            line.trim().to_owned()
        };
        let defined = read();
        let term = read();
        let actual = (defined == "true")
            .then(|| term.strip_prefix("#x"))
            .flatten()
            .map(|hex| u64::from_str_radix(hex, 16).expect("hexadecimal z3 constant"));
        assert!(
            defined == "true" || defined == "false",
            "{expr:?}: definedness {defined}"
        );
        if expected.is_none() {
            undefined += 1;
        }
        compared += 1;
        if actual != expected && failures.len() < 20 {
            failures.push(format!(
                "{expr:?} with {values:x?}: interpreter {expected:x?}, SMT {actual:x?} ({term})"
            ));
        }
    }
    drop(stdin);
    child.wait().expect("wait for z3");
    assert!(
        failures.is_empty(),
        "SMT translation disagrees with the interpreter:\n{}",
        failures.join("\n")
    );
    assert!(
        compared > 10_000 && undefined > 100,
        "{compared} {undefined}"
    );
    eprintln!("translation agrees on {compared} expressions ({undefined} undefined)");
}
