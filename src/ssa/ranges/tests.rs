use super::{Changes, Fact, decide, expression, refine, simplify};
use crate::ir::semantics::{evaluate, holds, mask};
use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt};
use crate::loader::Isa;

/// A small deterministic generator, so a failure reproduces.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Values of the kinds code holds: small counts, negatives, values
    /// near the edges of a width, masked fields and anything at all.
    fn value(&mut self, kind: u64) -> u64 {
        let raw = self.next();
        match kind % 6 {
            0 => raw % 16,
            1 => (raw % 16).wrapping_neg(),
            2 => (0x7fff_fff0 + raw % 32) & mask(32),
            3 => raw & 0xff0,
            4 => raw % 300,
            _ => raw,
        }
    }

    /// A handful of values of one kind, and the fact that joins them.
    fn sample(&mut self) -> (Vec<u64>, Fact) {
        let kind = self.next();
        let count = 1 + self.next() % 5;
        let values: Vec<u64> = (0..count).map(|_| self.value(kind)).collect();
        let fact = values
            .iter()
            .map(|value| Fact::constant(*value))
            .reduce(Fact::join)
            .expect("at least one value");
        (values, fact)
    }
}

const OPERATIONS: [BinOp; 15] = [
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

const WIDTHS: [u8; 4] = [8, 16, 32, 64];

#[test]
fn every_operation_keeps_the_values_it_can_produce() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    for round in 0..20_000 {
        let (left, left_fact) = random.sample();
        let (right, right_fact) = random.sample();
        let op = OPERATIONS[round % OPERATIONS.len()];
        let (left_width, right_width) = (
            WIDTHS[(random.next() % 4) as usize],
            WIDTHS[(random.next() % 4) as usize],
        );
        // The right operand is a constant half the time, as shifts and
        // divisors by a constant are.
        let constant = right.len() == 1 && random.next().is_multiple_of(2);
        let rhs = if constant {
            Expr::Const(right[0])
        } else {
            Expr::reg(2, right_width)
        };
        let expr = Expr::Bin {
            op,
            lhs: Box::new(Expr::reg(1, left_width)),
            rhs: Box::new(rhs),
        };
        let facts = |index: u16| if index == 1 { left_fact } else { right_fact };
        let fact =
            expression(&expr, &|index, bits| Some(facts(index).truncate(bits))).expect("defined");
        for a in &left {
            for b in &right {
                let registers = |index: u16| Some(if index == 1 { *a } else { *b });
                if let Some(value) = evaluate(&expr, &registers) {
                    assert!(
                        fact.contains(value),
                        "{op:?} of {a:#x}/{left_width} and {b:#x}/{right_width} is {value:#x}, \
                         outside {fact:x?} from {left_fact:x?} and {right_fact:x?}"
                    );
                }
            }
        }
    }
}

#[test]
fn extensions_and_truncations_keep_their_values() {
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for _ in 0..5_000 {
        let (values, fact) = random.sample();
        for bits in [1, 7, 8, 16, 31, 32, 63, 64] {
            let truncated = fact.truncate(bits);
            let extended = fact.sign_extend(bits);
            for value in &values {
                assert!(
                    truncated.contains(value & mask(bits)),
                    "{value:#x} to {bits}"
                );
                let sign = crate::ir::semantics::sign_extend(*value, bits) as u64;
                assert!(extended.contains(sign), "{value:#x} extended from {bits}");
            }
        }
    }
}

const CONDITIONS: [Cond; 14] = [
    Cond::Eq,
    Cond::Ne,
    Cond::Cs,
    Cond::Cc,
    Cond::Mi,
    Cond::Pl,
    Cond::Vs,
    Cond::Vc,
    Cond::Hi,
    Cond::Ls,
    Cond::Ge,
    Cond::Lt,
    Cond::Gt,
    Cond::Le,
];

#[test]
fn a_comparison_is_decided_and_narrowed_only_as_its_values_allow() {
    let mut random = Random(0x1234_5678_9abc_def1);
    for round in 0..20_000 {
        let (left, left_fact) = random.sample();
        let (right, right_fact) = random.sample();
        let cond = CONDITIONS[round % CONDITIONS.len()];
        let bits = u32::from(WIDTHS[(random.next() % 4) as usize]);
        let decided = decide(cond, left_fact, right_fact, bits);
        let narrowed = refine(cond, left_fact, right_fact, bits);
        for a in &left {
            for b in &right {
                let held = holds(cond, *a, *b, bits);
                if let Some(decided) = decided {
                    assert_eq!(held, decided, "{cond:?} {a:#x} {b:#x} at {bits}");
                }
                if held {
                    let narrowed = narrowed.unwrap_or_else(|| {
                        panic!("{cond:?} holds for {a:#x} {b:#x} at {bits}, narrowed to nothing")
                    });
                    assert!(
                        narrowed.contains(a & mask(bits)),
                        "{cond:?} {a:#x} {b:#x} at {bits}: {narrowed:x?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_fact_keeps_both_views_consistent() {
    // Bounds within one aligned block of 16 fix the bits above it.
    let fact = Fact::range(0x120, 0x12f).expect("not empty");
    assert_eq!(fact.zeros, !0x12f);
    assert_eq!(fact.ones, 0x120);
    // Known low bits raise the lower bound.
    let fact = Fact::new(0, 0b101, 0, 100).expect("not empty");
    assert_eq!(fact.lo, 0b101);
    assert!(Fact::new(1, 1, 0, 10).is_none());
    assert!(
        Fact::constant(4)
            .meet(Fact::range(5, 9).expect("range"))
            .is_none()
    );
}

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
        at: None,
    }
}

fn function(blocks: Vec<Vec<Stmt>>) -> FunctionIr {
    let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
    ir.blocks = blocks
        .into_iter()
        .enumerate()
        .map(|(index, stmts)| Block {
            start: 0x10 * index as u64,
            stmts,
        })
        .collect();
    ir
}

fn brif(cond: Cond, lhs: Expr, rhs: Expr, target: u64) -> Stmt {
    Stmt::Brif {
        cond,
        lhs,
        rhs,
        target,
        at: None,
    }
}

fn ret(value: Expr) -> Stmt {
    Stmt::Ret { value, at: None }
}

const RDI: u16 = 7;

#[test]
fn the_true_edge_of_a_bounds_check_bounds_the_value() {
    // if (rdi < 8) return rdi & 0xf; return 0;
    let mut ir = function(vec![
        vec![brif(Cond::Cc, Expr::reg(RDI, 64), Expr::Const(8), 0x20)],
        vec![ret(Expr::Const(0))],
        vec![ret(Expr::bin(
            BinOp::And,
            Expr::reg(RDI, 64),
            Expr::Const(0xf),
        ))],
    ]);
    let changes = simplify(&mut ir);
    assert_eq!(changes.masks, 1, "{}", ir.render());
    assert!(
        matches!(
            &ir.blocks[2].stmts[0],
            Stmt::Ret {
                value: Expr::Reg { index: RDI, .. },
                ..
            }
        ),
        "{}",
        ir.render()
    );
    // The other side knows nothing of the low bits.
    assert!(matches!(
        &ir.blocks[1].stmts[0],
        Stmt::Ret {
            value: Expr::Const(0),
            ..
        }
    ));
}

#[test]
fn a_branch_the_bounds_decide_is_removed() {
    // if (rdi < 8) { if (rdi > 9) return 1; return 2; } return 0;
    let mut ir = function(vec![
        vec![brif(Cond::Cc, Expr::reg(RDI, 64), Expr::Const(8), 0x20)],
        vec![ret(Expr::Const(0))],
        vec![brif(Cond::Hi, Expr::reg(RDI, 64), Expr::Const(9), 0x40)],
        vec![ret(Expr::Const(2))],
        vec![ret(Expr::Const(1))],
    ]);
    let changes = simplify(&mut ir);
    assert_eq!(changes.branches, 1, "{}", ir.render());
    assert!(
        !ir.blocks[2]
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Brif { .. })),
        "{}",
        ir.render()
    );
}

#[test]
fn a_bounds_check_through_an_offset_bounds_the_switch() {
    // v = (edi - 10) & 0xffffffff; if (v > 2) return 0; switch (edi) {10, 11, 12} default
    let index = Expr::reg(RDI, 32);
    let mut ir = function(vec![
        vec![
            assign(
                0,
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Sub, index.clone(), Expr::Const(10)),
                    Expr::Const(0xffff_ffff),
                ),
            ),
            brif(Cond::Hi, Expr::reg(0, 32), Expr::Const(2), 0x50),
        ],
        vec![Stmt::Switch {
            index,
            cases: vec![(10, 0x20), (11, 0x30), (12, 0x40), (13, 0x40)],
            default: Some(0x50),
            at: None,
        }],
        vec![ret(Expr::Const(1))],
        vec![ret(Expr::Const(2))],
        vec![ret(Expr::Const(3))],
        vec![ret(Expr::Const(0))],
    ]);
    let changes = simplify(&mut ir);
    assert_eq!((changes.cases, changes.defaults), (1, 1), "{}", ir.render());
    let Some(Stmt::Switch { cases, default, .. }) = ir.blocks[1].stmts.last() else {
        panic!("{}", ir.render());
    };
    assert_eq!(cases.len(), 3);
    assert_eq!(*default, None);
}

#[test]
fn a_counted_loop_leaves_its_bound() {
    // r0 = 0; do r0 += 1; while (r0 < 10); return r0 & 0xfff;
    let mut ir = function(vec![
        vec![assign(0, Expr::Const(0))],
        vec![
            assign(0, Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
            brif(Cond::Cc, Expr::reg(0, 64), Expr::Const(10), 0x10),
        ],
        vec![ret(Expr::bin(
            BinOp::And,
            Expr::reg(0, 64),
            Expr::Const(0xfff),
        ))],
    ]);
    simplify(&mut ir);
    assert!(
        matches!(
            &ir.blocks[2].stmts[0],
            Stmt::Ret {
                value: Expr::Const(10),
                ..
            }
        ),
        "{}",
        ir.render()
    );
}

#[test]
fn a_tested_bit_is_known_past_the_test() {
    // if ((rdi & 1) == 0) return rdi & 1; return 5;
    let bit = Expr::bin(BinOp::And, Expr::reg(RDI, 64), Expr::Const(1));
    let mut ir = function(vec![
        vec![brif(Cond::Eq, bit.clone(), Expr::Const(0), 0x20)],
        vec![ret(Expr::Const(5))],
        vec![ret(bit)],
    ]);
    simplify(&mut ir);
    assert!(
        matches!(
            &ir.blocks[2].stmts[0],
            Stmt::Ret {
                value: Expr::Const(0),
                ..
            }
        ),
        "{}",
        ir.render()
    );
}

#[test]
fn a_mask_under_a_signed_comparison_keeps_its_width() {
    // if (rdi < 0x100) { if ((int8_t)(rdi & 0xff) < 0) return 1; } return 0;
    let mut ir = function(vec![
        vec![brif(Cond::Cc, Expr::reg(RDI, 64), Expr::Const(0x100), 0x20)],
        vec![ret(Expr::Const(0))],
        vec![brif(
            Cond::Lt,
            Expr::bin(BinOp::And, Expr::reg(RDI, 64), Expr::Const(0xff)),
            Expr::Const(0),
            0x40,
        )],
        vec![ret(Expr::Const(0))],
        vec![ret(Expr::Const(1))],
    ]);
    let changes = simplify(&mut ir);
    assert_eq!(changes, Changes::default(), "{}", ir.render());
}

#[test]
fn a_value_never_negative_needs_no_sign_extension() {
    // if (rdi < 100) return (int64_t)(int32_t)rdi; return 0;
    let mut ir = function(vec![
        vec![brif(Cond::Cc, Expr::reg(RDI, 64), Expr::Const(100), 0x20)],
        vec![ret(Expr::Const(0))],
        vec![ret(Expr::SignExtend {
            value: Box::new(Expr::reg(RDI, 64)),
            width: 4,
        })],
    ]);
    let changes = simplify(&mut ir);
    assert_eq!(changes.extensions, 1, "{}", ir.render());
}

#[test]
fn an_expression_alone_bounds_what_it_reads() {
    use super::of;
    let x = || Expr::reg(RDI, 64);
    assert_eq!(of(&Expr::bin(BinOp::Shr, x(), Expr::Const(60))).hi, 0xf);
    assert_eq!(of(&Expr::bin(BinOp::ModU, x(), Expr::Const(5))).hi, 4);
    assert_eq!(of(&Expr::reg(RDI, 8)).hi, 0xff);
    assert_eq!(
        of(&Expr::bin(BinOp::Shl, Expr::reg(RDI, 8), Expr::Const(4))).possible(),
        0xff0
    );
    assert_eq!(of(&x()), Fact::TOP);
}

#[test]
fn a_mask_that_gives_a_variable_its_width_stays() {
    // if (rdi < 8) { r0 = rdi & 0xff; return r0; } return 0;
    let mut ir = function(vec![
        vec![brif(Cond::Cc, Expr::reg(RDI, 64), Expr::Const(8), 0x20)],
        vec![ret(Expr::Const(0))],
        vec![
            assign(
                0,
                Expr::bin(BinOp::And, Expr::reg(RDI, 64), Expr::Const(0xff)),
            ),
            ret(Expr::reg(0, 64)),
        ],
    ]);
    let changes = simplify(&mut ir);
    assert_eq!(changes.masks, 0, "{}", ir.render());
}
