//! Test-only equivalence checks of expressions produced by the Rust rewrites.

use std::collections::{BTreeMap, HashSet};
use std::io::BufReader;
use std::process::{Command, Stdio};

use super::{BinOp, Cond, Expr, LaneOp, Operation, Stmt};

mod floating;
mod integer;
mod inventory;
mod program;
mod render_tests;
mod rewrite_tests;
mod tests;

pub(crate) const CONDITIONS: [Cond; 14] = [
    Cond::Eq,
    Cond::Ne,
    Cond::Cs,
    Cond::Cc,
    Cond::Hi,
    Cond::Ls,
    Cond::Ge,
    Cond::Lt,
    Cond::Gt,
    Cond::Le,
    Cond::Mi,
    Cond::Pl,
    Cond::Vs,
    Cond::Vc,
];

/// Constructs a binary expression without simplifying its operands or operation.
pub(crate) fn raw_bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Bin {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

pub(crate) fn constant(value: u64) -> String {
    format!("(_ bv{value} 64)")
}

fn binary(op: &str, a: &str, b: &str) -> String {
    format!("({op} {a} {b})")
}

fn field(value: &str, offset: u32, bits: u32) -> String {
    format!(
        "((_ zero_extend {}) ((_ extract {} {offset}) {value}))",
        64 - bits,
        offset + bits - 1
    )
}

pub(crate) fn low(value: &str, bits: u32) -> String {
    match bits {
        0 => constant(0),
        64.. => value.to_owned(),
        _ => format!(
            "((_ zero_extend {}) ((_ extract {} 0) {value}))",
            64 - bits,
            bits - 1
        ),
    }
}

pub(crate) fn signed(value: &str, bits: u32) -> String {
    if bits >= 64 {
        value.to_owned()
    } else {
        format!(
            "((_ sign_extend {}) ((_ extract {} 0) {value}))",
            64 - bits,
            bits - 1
        )
    }
}

pub(crate) fn condition(cond: Cond, a: &str, b: &str, bits: u32) -> String {
    let a = low(a, bits);
    let b = low(b, bits);
    let difference = low(&binary("bvsub", &a, &b), bits);
    let negative = binary("bvslt", &signed(&difference, bits), &constant(0));
    let overflow = binary(
        "bvslt",
        &signed(
            &binary(
                "bvand",
                &binary("bvxor", &a, &b),
                &binary("bvxor", &a, &difference),
            ),
            bits,
        ),
        &constant(0),
    );
    match cond {
        Cond::Eq => binary("=", &a, &b),
        Cond::Ne => format!("(not (= {a} {b}))"),
        Cond::Cs => binary("bvuge", &a, &b),
        Cond::Cc => binary("bvult", &a, &b),
        Cond::Hi => binary("bvugt", &a, &b),
        Cond::Ls => binary("bvule", &a, &b),
        Cond::Ge => binary("bvsge", &signed(&a, bits), &signed(&b, bits)),
        Cond::Lt => binary("bvslt", &signed(&a, bits), &signed(&b, bits)),
        Cond::Gt => binary("bvsgt", &signed(&a, bits), &signed(&b, bits)),
        Cond::Le => binary("bvsle", &signed(&a, bits), &signed(&b, bits)),
        Cond::Mi => negative,
        Cond::Pl => format!("(not {negative})"),
        Cond::Vs => overflow,
        Cond::Vc => format!("(not {overflow})"),
    }
}

struct Value {
    term: String,
    defined: String,
}

fn operation(op: Operation, args: &[Value]) -> String {
    let a = &args[0].term;
    if let Some(result) = floating::operation(op, args) {
        return result;
    }
    if let Some(result) = integer::operation(op, args) {
        return result;
    }
    match op {
        Operation::PopCount(bits) => {
            let mut bytes = Vec::new();
            for start in (0..bits).step_by(8) {
                if bits > 8 && start + 8 <= bits {
                    let byte = format!("((_ extract {} {start}) {a})", start + 7);
                    bytes.push(format!("((_ zero_extend 60) (count8 {byte}))"));
                    continue;
                }
                let mut sum = "(_ bv0 8)".to_owned();
                for bit in start..bits.min(start + 8) {
                    let extracted = format!("((_ zero_extend 7) ((_ extract {bit} {bit}) {a}))");
                    sum = binary("bvadd", &sum, &extracted);
                }
                bytes.push(format!("((_ zero_extend 56) {sum})"));
            }
            let mut total = constant(0);
            for byte in bytes {
                total = binary("bvadd", &total, &byte);
            }
            total
        }
        Operation::Lanes(lane, bits) => {
            let bits = u32::from(bits);
            let mut result = constant(0);
            for offset in (0u32..64).step_by(bits as usize) {
                let a = field(a, offset, bits);
                let b = if args.len() > 1 {
                    field(&args[1].term, offset, bits)
                } else {
                    constant(0)
                };
                let truth = |test| {
                    format!(
                        "(ite {test} {} {})",
                        constant(super::semantics::mask(bits)),
                        constant(0)
                    )
                };
                let value = match lane {
                    LaneOp::Add => binary("bvadd", &a, &b),
                    LaneOp::Sub => binary("bvsub", &a, &b),
                    LaneOp::Mul => binary("bvmul", &a, &b),
                    LaneOp::Equal => truth(binary("=", &a, &b)),
                    LaneOp::GreaterSigned => {
                        truth(binary("bvsgt", &signed(&a, bits), &signed(&b, bits)))
                    }
                    LaneOp::GreaterUnsigned => truth(binary("bvugt", &a, &b)),
                    LaneOp::GreaterEqualSigned => {
                        truth(binary("bvsge", &signed(&a, bits), &signed(&b, bits)))
                    }
                    LaneOp::GreaterEqualUnsigned => truth(binary("bvuge", &a, &b)),
                    LaneOp::MinSigned
                    | LaneOp::MaxSigned
                    | LaneOp::MinUnsigned
                    | LaneOp::MaxUnsigned => {
                        let signed_compare = matches!(lane, LaneOp::MinSigned | LaneOp::MaxSigned);
                        let minimum = matches!(lane, LaneOp::MinSigned | LaneOp::MinUnsigned);
                        let test = if signed_compare {
                            binary(
                                if minimum { "bvsle" } else { "bvsge" },
                                &signed(&a, bits),
                                &signed(&b, bits),
                            )
                        } else {
                            binary(if minimum { "bvule" } else { "bvuge" }, &a, &b)
                        };
                        format!("(ite {test} {a} {b})")
                    }
                    LaneOp::ShiftLeft | LaneOp::ShiftRight => binary(
                        if lane == LaneOp::ShiftLeft {
                            "bvshl"
                        } else {
                            "bvlshr"
                        },
                        &a,
                        &args[1].term,
                    ),
                    LaneOp::ShiftRightSigned => {
                        let count = &args[1].term;
                        let count = format!(
                            "(ite (bvult {count} {}) {count} {})",
                            constant(u64::from(bits)),
                            constant(u64::from(bits) - 1)
                        );
                        binary("bvashr", &signed(&a, bits), &count)
                    }
                    LaneOp::ShiftVariableUnsigned => {
                        let count = signed(&b, 8);
                        let negative = binary("bvslt", &count, &constant(0));
                        format!("(ite {negative} (bvlshr {a} (bvneg {count})) (bvshl {a} {count}))")
                    }
                    LaneOp::AddSaturatingUnsigned => {
                        assert!(bits <= 32, "wide saturating lanes are not modeled");
                        let sum = binary("bvadd", &a, &b);
                        let maximum = constant(super::semantics::mask(bits));
                        format!("(ite (bvugt {sum} {maximum}) {maximum} {sum})")
                    }
                    LaneOp::SubSaturatingUnsigned => {
                        format!("(ite (bvult {a} {b}) {} (bvsub {a} {b}))", constant(0))
                    }
                    LaneOp::AddSaturatingSigned | LaneOp::SubSaturatingSigned => {
                        assert!(bits <= 32, "wide saturating lanes are not modeled");
                        let operator = if lane == LaneOp::AddSaturatingSigned {
                            "bvadd"
                        } else {
                            "bvsub"
                        };
                        let result = binary(operator, &signed(&a, bits), &signed(&b, bits));
                        let minimum = constant((1u64 << (bits - 1)).wrapping_neg());
                        let maximum = constant((1u64 << (bits - 1)) - 1);
                        format!(
                            "(ite (bvslt {result} {minimum}) {minimum} (ite (bvsgt {result} {maximum}) {maximum} {result}))"
                        )
                    }
                    LaneOp::Average => format!(
                        "(bvlshr (bvadd (bvadd {a} {b}) {}) {})",
                        constant(1),
                        constant(1)
                    ),
                    LaneOp::MulHighSigned | LaneOp::MulHighUnsigned => {
                        assert!(bits <= 32, "wide high-product lanes are not modeled");
                        let product = if lane == LaneOp::MulHighSigned {
                            binary("bvmul", &signed(&a, bits), &signed(&b, bits))
                        } else {
                            binary("bvmul", &a, &b)
                        };
                        binary("bvlshr", &product, &constant(u64::from(bits)))
                    }
                    LaneOp::CountLeadingZeros => integer::zero_count(&a, bits, true),
                    LaneOp::PopCount if bits == 8 => {
                        format!("((_ zero_extend 60) (count8 ((_ extract 7 0) {a})))")
                    }
                    LaneOp::PopCount => operation(
                        Operation::PopCount(bits as u8),
                        &[Value {
                            term: a,
                            defined: "true".to_owned(),
                        }],
                    ),
                };
                result = binary(
                    "bvor",
                    &result,
                    &binary("bvshl", &low(&value, bits), &constant(u64::from(offset))),
                );
            }
            result
        }
        Operation::SumLanesLong {
            bits,
            signed: is_signed,
        } => {
            let mut sum = constant(0);
            for arg in args {
                for offset in (0..64).step_by(usize::from(bits)) {
                    let value = field(&arg.term, offset, u32::from(bits));
                    let value = if is_signed {
                        signed(&value, u32::from(bits))
                    } else {
                        value
                    };
                    sum = binary("bvadd", &sum, &value);
                }
            }
            low(&sum, 2 * u32::from(bits))
        }
        _ => panic!("unsupported SMT operation: {op:?}"),
    }
}

fn value(expr: &Expr, registers: &BTreeMap<u16, String>) -> Value {
    memory_value(expr, registers, "memory")
}

fn memory_value(expr: &Expr, registers: &BTreeMap<u16, String>, memory: &str) -> Value {
    let mut defined = Vec::new();
    let term = match expr {
        Expr::Const(n) => constant(*n),
        Expr::Reg { index, width } => low(
            &registers
                .get(index)
                .cloned()
                .unwrap_or_else(|| format!("r{index}")),
            u32::from(*width),
        ),
        Expr::Load {
            addr,
            width,
            signed: is_signed,
        } => {
            let addr = memory_value(addr, registers, memory);
            defined.push(addr.defined);
            let mut loaded = constant(0);
            for byte in 0..*width {
                let address = binary("bvadd", &addr.term, &constant(u64::from(byte)));
                let byte_value = format!("((_ zero_extend 56) (select {memory} {address}))");
                loaded = binary(
                    "bvor",
                    &loaded,
                    &binary("bvshl", &byte_value, &constant(u64::from(byte) * 8)),
                );
            }
            if *is_signed {
                signed(&loaded, u32::from(*width) * 8)
            } else {
                loaded
            }
        }
        Expr::SignExtend {
            value: inner,
            width,
        } => {
            let inner = memory_value(inner, registers, memory);
            defined.push(inner.defined);
            signed(&inner.term, u32::from(*width) * 8)
        }
        Expr::Bin { op, lhs, rhs } => {
            let a = memory_value(lhs, registers, memory);
            let b = memory_value(rhs, registers, memory);
            defined.extend([a.defined, b.defined]);
            let bits = super::semantics::operand_width(lhs, rhs);
            let (a, b) = (a.term, b.term);
            match op {
                BinOp::Add => binary("bvadd", &a, &b),
                BinOp::Sub => binary("bvsub", &a, &b),
                BinOp::Mul => binary("bvmul", &a, &b),
                BinOp::MulHigh | BinOp::MulHighS => {
                    let extension = if *op == BinOp::MulHigh {
                        "zero_extend"
                    } else {
                        "sign_extend"
                    };
                    format!(
                        "((_ extract 127 64) (bvmul ((_ {extension} 64) {a}) ((_ {extension} 64) {b})))"
                    )
                }
                BinOp::And => binary("bvand", &a, &b),
                BinOp::Or => binary("bvor", &a, &b),
                BinOp::Xor => binary("bvxor", &a, &b),
                BinOp::Shl => match rhs.as_ref() {
                    Expr::Const(count) => binary("bvmul", &a, &constant(1u64 << (count & 63))),
                    _ => binary("bvshl", &a, &low(&b, 6)),
                },
                BinOp::Shr => binary("bvlshr", &a, &low(&b, 6)),
                BinOp::Sar => low(&binary("bvashr", &signed(&a, bits), &low(&b, 6)), bits),
                BinOp::DivU | BinOp::ModU => {
                    defined.push(format!("(not (= {b} {}))", constant(0)));
                    binary(
                        if *op == BinOp::DivU {
                            "bvudiv"
                        } else {
                            "bvurem"
                        },
                        &a,
                        &b,
                    )
                }
                BinOp::DivS | BinOp::ModS => {
                    let a = signed(&a, bits);
                    let b = signed(&b, bits);
                    defined.push(format!("(not (= {b} {}))", constant(0)));
                    low(
                        &binary(
                            if *op == BinOp::DivS {
                                "bvsdiv"
                            } else {
                                "bvsrem"
                            },
                            &a,
                            &b,
                        ),
                        bits,
                    )
                }
            }
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let a = memory_value(lhs, registers, memory);
            let b = memory_value(rhs, registers, memory);
            let test = condition(
                *cond,
                &a.term,
                &b.term,
                super::semantics::operand_width(lhs, rhs),
            );
            let then = memory_value(then, registers, memory);
            let els = memory_value(els, registers, memory);
            defined.extend([
                a.defined,
                b.defined,
                format!("(ite {test} {} {})", then.defined, els.defined),
            ]);
            format!("(ite {test} {} {})", then.term, els.term)
        }
        Expr::Apply { op, args } => {
            let args: Vec<Value> = args
                .iter()
                .map(|arg| memory_value(arg, registers, memory))
                .collect();
            defined.extend(args.iter().map(|arg| arg.defined.clone()));
            operation(*op, &args)
        }
    };
    Value {
        term,
        defined: format!("(and true {})", defined.join(" ")),
    }
}

pub(crate) fn term(expr: &Expr) -> String {
    value(expr, &BTreeMap::new()).term
}

fn returned(statements: &[Stmt]) -> Value {
    let mut registers = BTreeMap::new();
    let mut defined = Vec::new();
    for statement in statements {
        match statement {
            Stmt::Assign { dest, value: expr } => {
                let assigned = value(expr, &registers);
                defined.push(assigned.defined);
                registers.insert(dest.index, low(&assigned.term, u32::from(dest.width)));
            }
            Stmt::Ret { value: expr } => {
                let result = value(expr, &registers);
                defined.push(result.defined);
                return Value {
                    term: result.term,
                    defined: format!("(and true {})", defined.join(" ")),
                };
            }
            _ => panic!("unsupported SMT statement: {statement:?}"),
        }
    }
    panic!("SMT statement sequence must return a value");
}

#[derive(Default)]
pub(crate) struct Proofs {
    cases: Vec<(String, String)>,
    negative_cases: Vec<(String, String)>,
}

impl Proofs {
    /// Requires a counterexample to a deliberately incorrect equality.
    pub(crate) fn counterexample(&mut self, name: impl Into<String>, before: &str, wrong: &str) {
        self.negative_cases
            .push((name.into(), format!("(not (= {before} {wrong}))")));
    }

    pub(crate) fn available() -> bool {
        match Command::new("z3").arg("-version").output() {
            Ok(output) if output.status.success() => true,
            result => {
                eprintln!("SKIP SMT proofs: z3 executable unavailable ({result:?})");
                false
            }
        }
    }

    pub(crate) fn predicate(&mut self, name: impl Into<String>, before: &str, after: &str) {
        if before == after {
            return;
        }
        self.cases
            .push((name.into(), format!("(not (= {before} {after}))")));
    }

    pub(crate) fn expression(
        &mut self,
        name: impl Into<String>,
        before: &Expr,
        after: &Expr,
        bits: u32,
    ) {
        if before == after {
            return;
        }
        let before = value(before, &BTreeMap::new());
        let after = value(after, &BTreeMap::new());
        let mismatch = format!(
            "(or (not (= {} {})) (and {} (not (= {} {}))))",
            before.defined,
            after.defined,
            before.defined,
            low(&before.term, bits),
            low(&after.term, bits)
        );
        self.cases.push((name.into(), mismatch));
    }

    fn rendered(&mut self, name: String, before: &Value, after: &str, defined: &str) {
        self.cases.push((
            name,
            format!(
                "(and {} (or (not {defined}) (not (= {} {after}))))",
                before.defined, before.term
            ),
        ));
    }

    pub(crate) fn program(&mut self, name: String, before: &[Stmt], after: &[Stmt]) {
        if before.len() == after.len() {
            let mut unchanged = true;
            for (a, b) in before.iter().zip(after) {
                unchanged &= match (a, b) {
                    (Stmt::Assign { dest: a, value: x }, Stmt::Assign { dest: b, value: y }) => {
                        a == b && x == y
                    }
                    (Stmt::Ret { value: a }, Stmt::Ret { value: b }) => a == b,
                    _ => false,
                };
            }
            if unchanged {
                return;
            }
        }
        let before = returned(before);
        let after = returned(after);
        self.cases.push((
            name,
            format!(
                "(or (not (= {} {})) (and {} (not (= {} {}))))",
                before.defined, after.defined, before.defined, before.term, after.term
            ),
        ));
    }

    pub(crate) fn check(self) {
        use std::io::{BufRead, Write};

        assert!(
            !self.cases.is_empty(),
            "an SMT test must exercise at least one obligation"
        );

        // Bound solver work rather than elapsed time, which depends on system load.
        let mut script = String::from("(set-option :rlimit 10000000)\n");
        for index in 0..64 {
            script.push_str(&format!("(declare-const r{index} (_ BitVec 64))\n"));
        }
        script.push_str("(declare-const memory (Array (_ BitVec 64) (_ BitVec 8)))\n");
        // Prove count identities for any per-byte count fitting four bits.
        script.push_str("(declare-fun count8 ((_ BitVec 8)) (_ BitVec 4))\n");
        script.push_str("(declare-const q Int)\n(declare-const r Int)\n");
        let mut child = Command::new("z3")
            .args(["-in", "-smt2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start z3");
        let mut stdin = child.stdin.take().expect("piped z3 stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped z3 stdout"));
        let check = "(check-sat-using (then (using-params simplify :som true :sort-sums true :bv-sort-ac true :bv-extract-prop true) reduce-bv-size smt))";
        let mut seen = HashSet::new();
        let cases = self.cases.iter().map(|case| (case, "unsat"));
        let negative_cases = self.negative_cases.iter().map(|case| (case, "sat"));
        for ((name, mismatch), expected) in cases.chain(negative_cases) {
            if !seen.insert((mismatch.as_str(), expected)) {
                continue;
            }
            // Keep solver heuristics from depending on earlier obligations.
            writeln!(stdin, "(reset)\n{script}(assert {mismatch})\n{check}")
                .expect("write SMT query");
            stdin.flush().expect("flush SMT query");
            let mut answer = String::new();
            stdout.read_line(&mut answer).expect("read z3 answer");
            let answer = answer.trim();
            if answer != expected {
                let file_name: String = name
                    .chars()
                    .take(60)
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect();
                std::fs::write(
                    format!("target/smt-failure-{file_name}.smt2"),
                    format!("{script}(assert {mismatch})\n{check}\n"),
                )
                .expect("save failed SMT query");
                let query = if answer == "sat" {
                    "(get-value (r0 r1 r2 r3 r6 r7))"
                } else {
                    "(get-info :reason-unknown)"
                };
                writeln!(stdin, "{query}\n(exit)").expect("request SMT diagnostic");
                drop(stdin);
                use std::io::Read;
                let mut diagnostic = String::new();
                stdout
                    .read_to_string(&mut diagnostic)
                    .expect("read SMT diagnostic");
                child.wait().expect("wait for z3");
                panic!("SMT proof {name}: expected {expected}, got {answer}\n{diagnostic}");
            }
        }
        drop(stdin);
        assert!(
            child.wait().expect("wait for z3").success(),
            "z3 must exit successfully"
        );
        eprintln!(
            "SMT: {} equivalence obligations proved, {} negative controls rejected ({} unique queries)",
            self.cases.len(),
            self.negative_cases.len(),
            seen.len()
        );
    }
}
