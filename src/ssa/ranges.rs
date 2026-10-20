//! Known bits and value ranges. Each value keeps the bits known to be clear
//! and set, and the unsigned bounds it lies within. They flow through the
//! operations that build it, join at φs, and are narrowed on the edge a
//! branch takes: in the blocks only the true side of `x < 8` reaches, `x`
//! lies in [0, 7]. As with constant propagation, only the edges that can
//! run carry values, so a branch the facts decide keeps its other side out
//! of the joins.
//!
//! The same transfer functions answer, for any expression, what it may hold
//! when nothing is known of the registers it reads.

use std::collections::{HashMap, HashSet};

use super::{ENTRY, Ssa};
use crate::ir::semantics::{mask, operand_width, sign_extend, width};
use crate::ir::{BinOp, Cond, Expr, FunctionIr, Operation, Precision, Stmt, VALUE_BASE};

/// What is known of a 64-bit value: the bits known clear, the bits known
/// set, and unsigned bounds `lo..=hi`. Every operation keeps both views
/// consistent, each tightened by the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fact {
    pub zeros: u64,
    pub ones: u64,
    pub lo: u64,
    pub hi: u64,
}

impl Fact {
    pub const TOP: Fact = Fact {
        zeros: 0,
        ones: 0,
        lo: 0,
        hi: u64::MAX,
    };

    pub fn constant(value: u64) -> Fact {
        Fact {
            zeros: !value,
            ones: value,
            lo: value,
            hi: value,
        }
    }

    /// The values satisfying both views, or None when there are none.
    pub fn new(zeros: u64, ones: u64, lo: u64, hi: u64) -> Option<Fact> {
        let (mut zeros, mut ones, mut lo, mut hi) = (zeros, ones, lo, hi);
        for _ in 0..2 {
            if zeros & ones != 0 {
                return None;
            }
            lo = lo.max(ones);
            hi = hi.min(!zeros);
            if lo > hi {
                return None;
            }
            // The bits above the highest one in which the bounds differ are
            // the same in every value between them.
            let differ = lo ^ hi;
            let prefix = !mask(64 - differ.leading_zeros());
            ones |= lo & prefix;
            zeros |= !lo & prefix;
        }
        (zeros & ones == 0).then_some(Fact {
            zeros,
            ones,
            lo,
            hi,
        })
    }

    pub fn range(lo: u64, hi: u64) -> Option<Fact> {
        Fact::new(0, 0, lo, hi)
    }

    pub fn bits(zeros: u64, ones: u64) -> Option<Fact> {
        Fact::new(zeros, ones, 0, u64::MAX)
    }

    /// Any value below `2^bits`.
    pub fn width(bits: u32) -> Fact {
        Fact::TOP.truncate(bits)
    }

    pub fn singleton(self) -> Option<u64> {
        (self.lo == self.hi).then_some(self.lo)
    }

    pub fn contains(self, value: u64) -> bool {
        self.lo <= value
            && value <= self.hi
            && value & self.zeros == 0
            && value & self.ones == self.ones
    }

    /// The bits the value may have set.
    pub fn possible(self) -> u64 {
        !self.zeros
    }

    /// Every value either fact allows.
    pub fn join(self, other: Fact) -> Fact {
        Fact::new(
            self.zeros & other.zeros,
            self.ones & other.ones,
            self.lo.min(other.lo),
            self.hi.max(other.hi),
        )
        .unwrap_or(Fact::TOP)
    }

    /// The values both facts allow.
    pub fn meet(self, other: Fact) -> Option<Fact> {
        Fact::new(
            self.zeros | other.zeros,
            self.ones | other.ones,
            self.lo.max(other.lo),
            self.hi.min(other.hi),
        )
    }

    /// The low `bits` of the value.
    pub fn truncate(self, bits: u32) -> Fact {
        if bits >= 64 {
            return self;
        }
        let low = mask(bits);
        let (lo, hi) = if self.hi <= low {
            (self.lo, self.hi)
        } else if self.lo >> bits == self.hi >> bits {
            (self.lo & low, self.hi & low)
        } else {
            (0, low)
        };
        Fact::new(self.zeros | !low, self.ones & low, lo, hi).unwrap_or(Fact {
            zeros: !low,
            ones: 0,
            lo: 0,
            hi: low,
        })
    }

    /// The low `bits` of the value, their top bit copied into the bits above.
    pub fn sign_extend(self, bits: u32) -> Fact {
        let low = self.truncate(bits);
        if bits >= 64 || bits == 0 {
            return low;
        }
        let sign = 1u64 << (bits - 1);
        let kept = mask(bits);
        if low.zeros & sign != 0 {
            return low;
        }
        if low.ones & sign != 0 {
            return Fact::new(
                low.zeros & kept,
                low.ones | !kept,
                low.lo | !kept,
                low.hi | !kept,
            )
            .unwrap_or(Fact::TOP);
        }
        Fact::bits(low.zeros & (kept >> 1), low.ones & (kept >> 1)).unwrap_or(Fact::TOP)
    }

    /// The bounds as signed numbers of `bits`, of a fact already truncated
    /// to them.
    fn signed(self, bits: u32) -> (i64, i64) {
        let sign = 1u64 << (bits - 1);
        if self.hi < sign {
            (self.lo as i64, self.hi as i64)
        } else if self.lo >= sign {
            (sign_extend(self.lo, bits), sign_extend(self.hi, bits))
        } else {
            (sign_extend(sign, bits), sign_extend(sign - 1, bits))
        }
    }

    /// How many of the low bits are known.
    fn known_low(self) -> u32 {
        (self.zeros | self.ones).trailing_ones()
    }

    /// The low bits a sum, difference or product of two facts determines
    /// exactly: those below the lowest bit unknown in either.
    fn low_bits(self, other: Fact, value: u64) -> (u64, u64) {
        let low = mask(self.known_low().min(other.known_low()));
        (!value & low, value & low)
    }

    fn plus(self, other: Fact) -> Fact {
        let (zeros, ones) = self.low_bits(other, self.ones.wrapping_add(other.ones));
        let (lo, hi) = match (self.hi.checked_add(other.hi), self.lo.checked_add(other.lo)) {
            (Some(hi), _) => (self.lo + other.lo, hi),
            // Every sum wraps exactly once.
            (None, None) => (
                self.lo.wrapping_add(other.lo),
                self.hi.wrapping_add(other.hi),
            ),
            _ => (0, u64::MAX),
        };
        Fact::new(zeros, ones, lo, hi).unwrap_or(Fact::TOP)
    }

    fn minus(self, other: Fact) -> Fact {
        let (zeros, ones) = self.low_bits(other, self.ones.wrapping_sub(other.ones));
        let (lo, hi) = if self.lo >= other.hi {
            (self.lo - other.hi, self.hi - other.lo)
        } else if self.hi < other.lo {
            // Every difference wraps exactly once.
            (
                self.lo.wrapping_sub(other.hi),
                self.hi.wrapping_sub(other.lo),
            )
        } else {
            (0, u64::MAX)
        };
        Fact::new(zeros, ones, lo, hi).unwrap_or(Fact::TOP)
    }

    fn times(self, other: Fact) -> Fact {
        let (mut zeros, ones) = self.low_bits(other, self.ones.wrapping_mul(other.ones));
        // A product has the trailing zeros of both factors.
        let trailing = (self.zeros.trailing_ones() + other.zeros.trailing_ones()).min(64);
        zeros |= mask(trailing);
        let (lo, hi) = match self.hi.checked_mul(other.hi) {
            Some(hi) => (self.lo * other.lo, hi),
            None => (0, u64::MAX),
        };
        Fact::new(zeros & !ones, ones, lo, hi).unwrap_or(Fact::TOP)
    }

    fn and(self, other: Fact) -> Fact {
        Fact::new(
            self.zeros | other.zeros,
            self.ones & other.ones,
            0,
            self.hi.min(other.hi),
        )
        .unwrap_or(Fact::TOP)
    }

    fn or(self, other: Fact) -> Fact {
        Fact::new(
            self.zeros & other.zeros,
            self.ones | other.ones,
            self.lo.max(other.lo),
            u64::MAX,
        )
        .unwrap_or(Fact::TOP)
    }

    fn xor(self, other: Fact) -> Fact {
        Fact::bits(
            (self.zeros & other.zeros) | (self.ones & other.ones),
            (self.zeros & other.ones) | (self.ones & other.zeros),
        )
        .unwrap_or(Fact::TOP)
    }

    /// Shifted left by `amount`, which wraps at 64 as the operation does.
    fn shifted_left(self, amount: Fact) -> Fact {
        let Some(shift) = amount.singleton().map(|shift| (shift & 63) as u32) else {
            // Shifting left only adds zeros at the bottom.
            return Fact::bits(mask(self.zeros.trailing_ones()), 0).unwrap_or(Fact::TOP);
        };
        let (lo, hi) = if self.hi.leading_zeros() >= shift {
            (self.lo << shift, self.hi << shift)
        } else {
            (0, u64::MAX)
        };
        Fact::new(
            (self.zeros << shift) | mask(shift),
            self.ones << shift,
            lo,
            hi,
        )
        .unwrap_or(Fact::TOP)
    }

    fn shifted_right(self, amount: Fact) -> Fact {
        let Some(shift) = amount.singleton().map(|shift| (shift & 63) as u32) else {
            return Fact::range(0, self.hi).unwrap_or(Fact::TOP);
        };
        Fact::new(
            (self.zeros >> shift) | !(u64::MAX >> shift),
            self.ones >> shift,
            self.lo >> shift,
            self.hi >> shift,
        )
        .unwrap_or(Fact::TOP)
    }

    /// The low `bits` shifted right with their sign, as the operation does.
    fn shifted_right_signed(self, amount: Fact, bits: u32) -> Fact {
        let Some(shift) = amount.singleton().map(|shift| (shift & 63) as u32) else {
            return Fact::width(bits);
        };
        let extended = self.sign_extend(bits);
        let spread = |known: u64| ((known as i64) >> shift) as u64;
        let (lo, hi) = if extended.hi < 1 << 63 || extended.lo >= 1 << 63 {
            (spread(extended.lo), spread(extended.hi))
        } else {
            (0, u64::MAX)
        };
        Fact::new(spread(extended.zeros), spread(extended.ones), lo, hi)
            .unwrap_or(Fact::TOP)
            .truncate(bits)
    }

    fn quotient(self, divisor: Fact) -> Fact {
        let (lo, hi) = match self.hi.checked_div(divisor.lo) {
            Some(hi) => (self.lo / divisor.hi, hi),
            None => (0, self.hi),
        };
        Fact::range(lo, hi).unwrap_or(Fact::TOP)
    }

    fn remainder(self, divisor: Fact) -> Fact {
        if divisor.lo > 0 && self.hi < divisor.lo {
            return self;
        }
        if let Some(power) = divisor.singleton()
            && power.is_power_of_two()
        {
            return self.and(Fact::constant(power - 1));
        }
        let hi = match divisor.hi {
            0 => self.hi,
            hi => self.hi.min(hi - 1),
        };
        Fact::range(0, hi).unwrap_or(Fact::TOP)
    }
}

/// What `expr` may hold, given what each register read of a width may; None
/// when it reads a value no path has defined yet.
pub fn expression(expr: &Expr, read: &dyn Fn(u16, u32) -> Option<Fact>) -> Option<Fact> {
    Some(match expr {
        Expr::Reg { index, width } => read(*index, u32::from(*width))?,
        Expr::Const(value) => Fact::constant(*value),
        Expr::Load {
            addr,
            width,
            signed,
        } => {
            expression(addr, read)?;
            let bits = u32::from(*width) * 8;
            if *signed {
                Fact::TOP.sign_extend(bits)
            } else {
                Fact::width(bits)
            }
        }
        Expr::SignExtend { value, width } => {
            expression(value, read)?.sign_extend(u32::from(*width) * 8)
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let bits = operand_width(lhs, rhs);
            let decided = decide(*cond, expression(lhs, read)?, expression(rhs, read)?, bits);
            let (then, els) = (expression(then, read)?, expression(els, read)?);
            match decided {
                Some(true) => then,
                Some(false) => els,
                None => then.join(els),
            }
        }
        Expr::Apply { op, args } => {
            for arg in args {
                expression(arg, read)?;
            }
            applied(*op)
        }
        Expr::Bin { op, lhs, rhs } => {
            let (a, b) = (expression(lhs, read)?, expression(rhs, read)?);
            let bits = operand_width(lhs, rhs);
            match op {
                BinOp::Add => a.plus(b),
                BinOp::Sub => a.minus(b),
                BinOp::Mul => a.times(b),
                BinOp::MulHigh => {
                    let high = |x: u64, y: u64| ((u128::from(x) * u128::from(y)) >> 64) as u64;
                    Fact::range(high(a.lo, b.lo), high(a.hi, b.hi)).unwrap_or(Fact::TOP)
                }
                BinOp::MulHighS => Fact::TOP,
                BinOp::And => a.and(b),
                BinOp::Or => a.or(b),
                BinOp::Xor => a.xor(b),
                BinOp::Shl => a.shifted_left(b),
                BinOp::Shr => a.shifted_right(b),
                BinOp::Sar => a.shifted_right_signed(b, bits),
                BinOp::DivU => a.quotient(b),
                BinOp::ModU => a.remainder(b),
                BinOp::DivS | BinOp::ModS => {
                    // Operands that are never negative divide as unsigned ones.
                    let (a, b) = (a.truncate(bits), b.truncate(bits));
                    let sign = 1u64 << (bits - 1);
                    match (a.hi < sign && b.hi < sign, op) {
                        (true, BinOp::DivS) => a.quotient(b),
                        (true, _) => a.remainder(b),
                        (false, _) => Fact::width(bits),
                    }
                }
            }
        }
    })
}

/// What an operation's result may hold, whatever its arguments.
fn applied(op: Operation) -> Fact {
    let bits = match op {
        Operation::CountLeadingZeros(bits)
        | Operation::CountTrailingZeros(bits)
        | Operation::PopCount(bits) => {
            return Fact::range(0, u64::from(bits)).unwrap_or(Fact::TOP);
        }
        Operation::FloatEqual(_)
        | Operation::FloatLess(_)
        | Operation::FloatLessEqual(_)
        | Operation::FloatUnordered(_) => return Fact::range(0, 1).unwrap_or(Fact::TOP),
        Operation::ReverseBits(bits) | Operation::FloatToInt { bits, .. } => u32::from(bits),
        Operation::SignBits(bits) => 64 / u32::from(bits),
        Operation::Crc32 { .. } => 32,
        _ if op.result_precision() == Some(Precision::Single) => 32,
        _ => 64,
    };
    Fact::width(bits)
}

/// What `expr` may hold whatever the registers it reads hold.
pub fn of(expr: &Expr) -> Fact {
    expression(expr, &|_, bits| Some(Fact::width(bits))).unwrap_or(Fact::TOP)
}

/// Whether `cond` holds between values of the two facts at `bits`, when
/// every pair of them decides it the same way.
pub fn decide(cond: Cond, lhs: Fact, rhs: Fact, bits: u32) -> Option<bool> {
    let (a, b) = (lhs.truncate(bits), rhs.truncate(bits));
    let (sa, sb) = (a.signed(bits), b.signed(bits));
    let either = |yes: bool, no: bool| {
        if yes {
            Some(true)
        } else if no {
            Some(false)
        } else {
            None
        }
    };
    match cond {
        Cond::Eq => match (a.singleton(), b.singleton()) {
            (Some(x), Some(y)) => Some(x == y),
            _ => a.meet(b).is_none().then_some(false),
        },
        Cond::Ne => decide(Cond::Eq, a, b, bits).map(|equal| !equal),
        Cond::Cc => either(a.hi < b.lo, a.lo >= b.hi),
        Cond::Cs => either(a.lo >= b.hi, a.hi < b.lo),
        Cond::Hi => either(a.lo > b.hi, a.hi <= b.lo),
        Cond::Ls => either(a.hi <= b.lo, a.lo > b.hi),
        Cond::Lt => either(sa.1 < sb.0, sa.0 >= sb.1),
        Cond::Ge => either(sa.0 >= sb.1, sa.1 < sb.0),
        Cond::Gt => either(sa.0 > sb.1, sa.1 <= sb.0),
        Cond::Le => either(sa.1 <= sb.0, sa.0 > sb.1),
        Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc => None,
    }
}

/// What the left operand may hold, as `bits` wide, where `cond` holds
/// between it and the right one; None when no value lets it hold.
pub fn refine(cond: Cond, lhs: Fact, rhs: Fact, bits: u32) -> Option<Fact> {
    let (a, b) = (lhs.truncate(bits), rhs.truncate(bits));
    let top = mask(bits);
    match cond {
        Cond::Eq => a.meet(b),
        Cond::Ne => match b.singleton() {
            Some(value) if a.singleton() == Some(value) => None,
            Some(value) if a.lo == value => a.meet(Fact::range(value + 1, top)?),
            Some(value) if a.hi == value => a.meet(Fact::range(0, value - 1)?),
            _ => Some(a),
        },
        Cond::Cc => a.meet(Fact::range(0, b.hi.checked_sub(1)?)?),
        Cond::Ls => a.meet(Fact::range(0, b.hi)?),
        Cond::Hi => a.meet(Fact::range(b.lo.checked_add(1)?, top)?),
        Cond::Cs => a.meet(Fact::range(b.lo, top)?),
        Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge => {
            let ((mut lo, mut hi), (blo, bhi)) = (a.signed(bits), b.signed(bits));
            match cond {
                Cond::Lt => hi = hi.min(bhi.checked_sub(1)?),
                Cond::Le => hi = hi.min(bhi),
                Cond::Gt => lo = lo.max(blo.checked_add(1)?),
                _ => lo = lo.max(blo),
            }
            if lo > hi {
                return None;
            }
            if lo >= 0 || hi < 0 {
                a.meet(Fact::range(lo as u64 & top, hi as u64 & top)?)
            } else {
                Some(a)
            }
        }
        Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc => Some(a),
    }
}

/// The same comparison with its operands exchanged.
fn swapped(cond: Cond) -> Option<Cond> {
    Some(match cond {
        Cond::Eq | Cond::Ne => cond,
        Cond::Cc => Cond::Hi,
        Cond::Hi => Cond::Cc,
        Cond::Cs => Cond::Ls,
        Cond::Ls => Cond::Cs,
        Cond::Lt => Cond::Gt,
        Cond::Gt => Cond::Lt,
        Cond::Ge => Cond::Le,
        Cond::Le => Cond::Ge,
        Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc => return None,
    })
}

/// A read of `bits` of a value known as `fact`, narrowed by a constraint on
/// its low `low` bits.
fn constrained(fact: Fact, bits: u32, low: u32, constraint: Fact) -> Option<Fact> {
    if low >= bits {
        fact.meet(constraint.truncate(bits))
    } else if fact.hi <= mask(low) {
        fact.meet(constraint)
    } else {
        fact.meet(Fact::bits(
            constraint.zeros & mask(low),
            constraint.ones & mask(low),
        )?)
    }
}

/// How many definitions a constraint is followed back through.
const DEFINITIONS: usize = 4;
/// How many branches a read's narrowing looks back through.
const DEPTH: usize = 2;
/// Sweeps after which the solver gives up rather than settle.
const SWEEPS: usize = 64;
/// Changes to a φ before its moving bounds jump to their ends; twice as
/// many, and it may hold anything.
const PATIENCE: u8 = 3;

/// The facts of a function in SSA form, and how branches narrow them.
pub struct Ranges<'a> {
    ssa: &'a Ssa,
    facts: Vec<Option<Fact>>,
    executable: Vec<bool>,
    edges: HashSet<(usize, usize)>,
    starts: HashMap<u64, usize>,
    pads: HashSet<usize>,
    /// Where each value is assigned, and at what width.
    definitions: HashMap<u16, (&'a Expr, u32)>,
    /// The blocks entered by one edge only whose branch narrows each value.
    guards: HashMap<u16, Vec<usize>>,
    /// Entry and exit times of each block in a walk of the dominator tree.
    order: Vec<Option<(usize, usize)>>,
    changes: HashMap<u16, u8>,
    /// What each edge tells of each value, from the facts as they stood
    /// when first asked in this sweep. The last sweep changes nothing, so
    /// what it was told agrees with the settled facts; a narrowing sweep
    /// only lowers facts, so what it was told earlier is looser, not wrong.
    told: std::cell::RefCell<HashMap<Edge, Option<Told>>>,
}

/// An edge between two blocks, a value and how far back reads look.
type Edge = (usize, usize, u16, usize);
/// Constraints on the low bits of a value.
type Told = Vec<(u32, Fact)>;

impl<'a> Ranges<'a> {
    fn index(value: u16) -> Option<usize> {
        value.checked_sub(VALUE_BASE).map(usize::from)
    }

    fn fact(&self, value: u16) -> Option<Fact> {
        match Self::index(value).and_then(|index| self.facts.get(index)) {
            Some(fact) => *fact,
            None => Some(Fact::TOP),
        }
    }

    fn dominates(&self, a: usize, b: usize) -> bool {
        match (self.order[a], self.order[b]) {
            (Some((enter_a, exit_a)), Some((enter_b, exit_b))) => {
                enter_a <= enter_b && exit_b <= exit_a
            }
            _ => false,
        }
    }

    /// What a read of `bits` of `value` may hold in `block`, narrowed by the
    /// branches on the way there.
    pub fn read(&self, value: u16, bits: u32, block: usize, depth: usize) -> Option<Fact> {
        let mut fact = self.fact(value)?.truncate(bits);
        if depth == 0 {
            return Some(fact);
        }
        for guard in self.guards.get(&value).into_iter().flatten() {
            if !self.dominates(*guard, block) {
                continue;
            }
            let from = self.ssa.predecessors[*guard][0];
            for (low, constraint) in self.edge(from, *guard, value, depth - 1)? {
                fact = constrained(fact, bits, low, constraint)?;
            }
        }
        Some(fact)
    }

    /// What `expr` may hold in `block`.
    pub fn eval(&self, expr: &Expr, block: usize, depth: usize) -> Option<Fact> {
        expression(expr, &|value, bits| self.read(value, bits, block, depth))
    }

    /// What the edge from `from` to `to` tells of `value`: constraints, each
    /// on its low bits; None when the edge cannot be taken.
    fn edge(&self, from: usize, to: usize, value: u16, depth: usize) -> Option<Told> {
        let key = (from, to, value, depth);
        if let Some(told) = self.told.borrow().get(&key) {
            return told.clone();
        }
        let told = self.tell(from, to, value, depth);
        self.told.borrow_mut().insert(key, told.clone());
        told
    }

    fn tell(&self, from: usize, to: usize, value: u16, depth: usize) -> Option<Told> {
        let mut out = Vec::new();
        if self.pads.contains(&to) {
            return Some(out);
        }
        match self.ssa.ir.blocks[from].stmts.last() {
            Some(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) => {
                let taken = self.starts.get(target) == Some(&to);
                if taken == (to == from + 1) {
                    return Some(out);
                }
                let cond = if taken { *cond } else { cond.invert() };
                let bits = operand_width(lhs, rhs);
                let (a, b) = (self.eval(lhs, from, depth)?, self.eval(rhs, from, depth)?);
                let left = refine(cond, a, b, bits)?;
                self.constrain(lhs, bits, left, value, DEFINITIONS, &mut out)?;
                if let Some(cond) = swapped(cond) {
                    let right = refine(cond, b, a, bits)?;
                    self.constrain(rhs, bits, right, value, DEFINITIONS, &mut out)?;
                }
            }
            Some(Stmt::Switch {
                index,
                cases,
                default,
            }) => {
                if default.and_then(|default| self.starts.get(&default).copied()) == Some(to) {
                    return Some(out);
                }
                let fact = cases
                    .iter()
                    .filter(|(_, target)| self.starts.get(target) == Some(&to))
                    .map(|(case, _)| Fact::constant(*case as u64))
                    .reduce(Fact::join);
                if let Some(fact) = fact {
                    self.constrain(index, 64, fact, value, DEFINITIONS, &mut out)?;
                }
            }
            _ => {}
        }
        Some(out)
    }

    /// Follows a constraint on the low `bits` of `expr` back to `value`;
    /// None when it leaves no value possible.
    fn constrain(
        &self,
        expr: &Expr,
        bits: u32,
        constraint: Fact,
        value: u16,
        definitions: usize,
        out: &mut Vec<(u32, Fact)>,
    ) -> Option<()> {
        match expr {
            Expr::Reg { index, width } => {
                let low = bits.min(u32::from(*width));
                let constraint = constraint.meet(Fact::width(low))?;
                if *index == value {
                    out.push((low, constraint));
                } else if definitions > 0
                    && let Some((defined, assigned)) = self.definitions.get(index)
                {
                    let low = low.min(*assigned);
                    let constraint = constraint.truncate(low);
                    self.constrain(defined, low, constraint, value, definitions - 1, out)?;
                }
            }
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } => {
                let Expr::Const(kept) = rhs.as_ref() else {
                    return Some(());
                };
                let kept = kept & mask(bits);
                if kept != 0 && kept.wrapping_add(1).is_power_of_two() {
                    let low = kept.count_ones();
                    let constraint = constraint.meet(Fact::width(low))?;
                    self.constrain(lhs, low, constraint, value, definitions, out)?;
                } else {
                    let known = Fact::bits(constraint.zeros & kept, constraint.ones & kept)?;
                    self.constrain(lhs, bits, known, value, definitions, out)?;
                }
            }
            Expr::Bin {
                op: op @ (BinOp::Add | BinOp::Sub),
                lhs,
                rhs,
            } => {
                let Expr::Const(offset) = rhs.as_ref() else {
                    return Some(());
                };
                let back = |bound: u64| {
                    let moved = if *op == BinOp::Add {
                        bound.wrapping_sub(*offset)
                    } else {
                        bound.wrapping_add(*offset)
                    };
                    moved & mask(bits)
                };
                let (lo, hi) = (back(constraint.lo), back(constraint.hi));
                if lo <= hi && hi - lo == constraint.hi - constraint.lo {
                    self.constrain(lhs, bits, Fact::range(lo, hi)?, value, definitions, out)?;
                }
            }
            _ => {}
        }
        Some(())
    }

    /// The values a branch's operands are built from, as `constrain`
    /// follows them.
    fn constrainable(&self, expr: &Expr, definitions: usize, out: &mut Vec<u16>) {
        match expr {
            Expr::Reg { index, .. } => {
                out.push(*index);
                if definitions > 0
                    && let Some((defined, _)) = self.definitions.get(index)
                {
                    self.constrainable(defined, definitions - 1, out);
                }
            }
            Expr::Bin {
                op: BinOp::And | BinOp::Add | BinOp::Sub,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(_)) => {
                self.constrainable(lhs, definitions, out);
            }
            _ => {}
        }
    }

    fn set(&mut self, value: u16, fact: Fact, widen: bool, narrowing: bool) -> bool {
        let Some(index) = Self::index(value) else {
            return false;
        };
        let old = self.facts[index];
        let mut new = match (old, narrowing) {
            (Some(old), false) => old.join(fact),
            _ => fact,
        };
        if widen
            && !narrowing
            && let Some(old) = old
            && new != old
        {
            let count = self.changes.entry(value).or_insert(0);
            *count += 1;
            if *count >= 2 * PATIENCE {
                new = Fact::TOP;
            } else if *count >= PATIENCE {
                // Bounds still moving jump to the end they move towards;
                // narrowing later brings back what the branches bound.
                if new.hi > old.hi {
                    new.hi = u64::MAX;
                }
                if new.lo < old.lo {
                    new.lo = 0;
                }
                new = Fact::new(new.zeros, new.ones, new.lo, new.hi).unwrap_or(Fact::TOP);
            }
        }
        if old == Some(new) {
            return false;
        }
        self.facts[index] = Some(new);
        true
    }

    fn mark(&mut self, from: usize, to: usize, narrowing: bool) -> bool {
        if narrowing {
            return false;
        }
        let mut changed = self.edges.insert((from, to));
        if !self.executable[to] {
            self.executable[to] = true;
            changed = true;
        }
        changed
    }

    /// The successors a block's last statement can lead to, given the facts.
    fn live_successors(&self, block: usize) -> Vec<usize> {
        let successors = &self.ssa.successors[block];
        match self.ssa.ir.blocks[block].stmts.last() {
            Some(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) => {
                let (Some(a), Some(b)) =
                    (self.eval(lhs, block, DEPTH), self.eval(rhs, block, DEPTH))
                else {
                    return Vec::new();
                };
                let target = self.starts.get(target).copied();
                let skipped = match decide(*cond, a, b, operand_width(lhs, rhs)) {
                    Some(true) if target != Some(block + 1) => Some(block + 1),
                    Some(false) if target != Some(block + 1) => target,
                    _ => None,
                };
                successors
                    .iter()
                    .copied()
                    .filter(|next| self.pads.contains(next) || Some(*next) != skipped)
                    .collect()
            }
            Some(Stmt::Switch {
                index,
                cases,
                default,
            }) => {
                let Some(fact) = self.eval(index, block, DEPTH) else {
                    return Vec::new();
                };
                let mut live: Vec<usize> = cases
                    .iter()
                    .filter(|(case, _)| fact.contains(*case as u64))
                    .filter_map(|(_, target)| self.starts.get(target).copied())
                    .collect();
                if !covered(fact, cases) {
                    live.extend(default.and_then(|default| self.starts.get(&default).copied()));
                }
                live.extend(successors.iter().filter(|next| self.pads.contains(next)));
                live
            }
            _ => successors.clone(),
        }
    }

    /// One pass over the blocks that can run; true when anything changed.
    fn sweep(&mut self, narrowing: bool) -> bool {
        let ssa = self.ssa;
        self.told.borrow_mut().clear();
        let mut changed = false;
        for block in 0..ssa.ir.blocks.len() {
            if !self.executable[block] {
                continue;
            }
            for phi in &ssa.phis[block] {
                let mut joined: Option<Fact> = None;
                for (predecessor, arg) in ssa.predecessors[block].iter().zip(&phi.args) {
                    if !self.edges.contains(&(*predecessor, block)) {
                        continue;
                    }
                    let incoming = if *predecessor == ENTRY {
                        self.fact(*arg)
                    } else {
                        self.incoming(*predecessor, block, *arg)
                    };
                    if let Some(incoming) = incoming {
                        joined = Some(joined.map_or(incoming, |fact| fact.join(incoming)));
                    }
                }
                if let Some(joined) = joined {
                    changed |= self.set(phi.value, joined, true, narrowing);
                }
            }
            for stmt in &ssa.ir.blocks[block].stmts {
                if let Stmt::Assign { dest, value } = stmt
                    && let Some(fact) = self.eval(value, block, DEPTH)
                {
                    let fact = fact.truncate(u32::from(dest.width));
                    changed |= self.set(dest.index, fact, false, narrowing);
                }
            }
            for next in self.live_successors(block) {
                changed |= self.mark(block, next, narrowing);
            }
        }
        changed
    }

    /// What `arg` holds as it reaches a φ along the edge from `from` to `to`.
    fn incoming(&self, from: usize, to: usize, arg: u16) -> Option<Fact> {
        let mut fact = self.read(arg, 64, from, DEPTH)?;
        for (low, constraint) in self.edge(from, to, arg, DEPTH - 1)? {
            fact = constrained(fact, 64, low, constraint)?;
        }
        Some(fact)
    }

    /// Solves the facts of every value; None when they do not settle.
    pub fn solve(ssa: &'a Ssa) -> Option<Ranges<'a>> {
        let count = ssa.ir.blocks.len();
        if count == 0 {
            return None;
        }
        let mut facts = vec![Some(Fact::TOP); ssa.origin.len()];
        let mut definitions = HashMap::new();
        for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let Stmt::Assign { dest, value } = stmt {
                definitions.insert(dest.index, (value, u32::from(dest.width)));
            }
        }
        // Values assigned or chosen by a φ start undefined; any other, as a
        // call's result or what it clobbers, may hold anything.
        for value in definitions
            .keys()
            .chain(ssa.phis.iter().flatten().map(|phi| &phi.value))
        {
            if let Some(index) = Self::index(*value) {
                facts[index] = None;
            }
        }
        for value in ssa.entry.values() {
            if let Some(index) = Self::index(*value) {
                facts[index] = Some(Fact::TOP);
            }
        }
        let dominators = super::dom::dominators(&ssa.successors);
        let mut children = vec![Vec::new(); count];
        for (block, idom) in dominators.idom.iter().enumerate() {
            if let Some(idom) = idom {
                children[*idom].push(block);
            }
        }
        let mut order = vec![None; count];
        let mut clock = 0;
        let mut stack = vec![(0usize, 0usize)];
        let mut enter = vec![0; count];
        enter[0] = clock;
        while let Some((block, next)) = stack.last_mut() {
            if let Some(child) = children[*block].get(*next).copied() {
                *next += 1;
                clock += 1;
                enter[child] = clock;
                stack.push((child, 0));
            } else {
                clock += 1;
                order[*block] = Some((enter[*block], clock));
                stack.pop();
            }
        }
        let starts: HashMap<u64, usize> = ssa
            .ir
            .blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.start, index))
            .collect();
        let pads = ssa
            .ir
            .landing_pads
            .iter()
            .filter_map(|(pad, _)| starts.get(pad).copied())
            .collect();
        let mut ranges = Ranges {
            ssa,
            facts,
            executable: vec![false; count],
            edges: HashSet::new(),
            starts,
            pads,
            definitions,
            guards: HashMap::new(),
            order,
            changes: HashMap::new(),
            told: std::cell::RefCell::new(HashMap::new()),
        };
        for block in 0..count {
            let [from] = ssa.predecessors[block][..] else {
                continue;
            };
            if from == ENTRY || ranges.pads.contains(&block) {
                continue;
            }
            let mut values = Vec::new();
            match ssa.ir.blocks[from].stmts.last() {
                Some(Stmt::Brif { lhs, rhs, .. }) => {
                    ranges.constrainable(lhs, DEFINITIONS, &mut values);
                    ranges.constrainable(rhs, DEFINITIONS, &mut values);
                }
                Some(Stmt::Switch { index, .. }) => {
                    ranges.constrainable(index, DEFINITIONS, &mut values);
                }
                _ => {}
            }
            values.sort_unstable();
            values.dedup();
            for value in values {
                ranges.guards.entry(value).or_default().push(block);
            }
        }
        ranges.executable[0] = true;
        ranges.edges.insert((ENTRY, 0));
        let mut sweeps = 0;
        while ranges.sweep(false) {
            sweeps += 1;
            if sweeps > SWEEPS {
                return None;
            }
        }
        // Jumping ahead may have overshot; recomputing from the settled
        // facts stays above every value that can occur.
        for _ in 0..2 {
            ranges.sweep(true);
        }
        Some(ranges)
    }

    pub fn executable(&self, block: usize) -> bool {
        self.executable[block]
    }
}

/// Whether every value the fact allows has a case.
fn covered(fact: Fact, cases: &[(i64, u64)]) -> bool {
    if fact.hi - fact.lo >= 4096 {
        return false;
    }
    let values: HashSet<u64> = cases.iter().map(|(case, _)| *case as u64).collect();
    (fact.lo..=fact.hi).all(|value| !fact.contains(value) || values.contains(&value))
}

/// What the rewrite changed, by kind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Changes {
    pub masks: usize,
    pub extensions: usize,
    pub constants: usize,
    pub branches: usize,
    pub cases: usize,
    pub defaults: usize,
}

impl Changes {
    fn any(self) -> bool {
        self != Changes::default()
    }
}

/// Rewrites what the facts make redundant: a mask over a value that already
/// fits it, a sign extension of a value that is never negative, a read of a
/// value the branches leave one choice for, a branch they decide, and the
/// cases of a switch its index never takes. A mask or an extension goes
/// only where the expression keeps its width, which types are read from,
/// and reads under a comparison or a signed operation keep the width it
/// acts at, as constant propagation's do.
pub fn simplify(ir: &mut FunctionIr) -> Changes {
    let Some(mut ssa) = super::build(ir) else {
        return Changes::default();
    };
    let Some(ranges) = Ranges::solve(&ssa) else {
        return Changes::default();
    };
    let mut changes = Changes::default();
    let mut rewritten: Vec<(usize, Vec<Stmt>)> = Vec::new();
    for block in 0..ssa.ir.blocks.len() {
        if !ranges.executable(block) {
            continue;
        }
        let mut stmts = ssa.ir.blocks[block].stmts.clone();
        let next = ssa.ir.blocks.get(block + 1).map(|next| next.start);
        for stmt in &mut stmts {
            rewrite_stmt(stmt, &ranges, block, &mut changes);
        }
        terminate(&mut stmts, &ranges, block, next, &mut changes);
        rewritten.push((block, stmts));
    }
    if !changes.any() {
        return changes;
    }
    for (block, stmts) in rewritten {
        ssa.ir.blocks[block].stmts = stmts;
    }
    *ir = super::lower(&ssa);
    if changes.branches + changes.cases + changes.defaults > 0 {
        drop_unreachable(ir);
    }
    changes
}

/// Removes the blocks no path from the entry reaches any more, unless a
/// jump to an unknown address may reach any of them. Landing pads stay:
/// exceptions enter them.
fn drop_unreachable(ir: &mut FunctionIr) {
    if ir.blocks.iter().any(|block| {
        matches!(
            block.stmts.last(),
            Some(Stmt::BrIndirect { .. } | Stmt::Br { target: None })
        )
    }) {
        return;
    }
    let pads: HashSet<u64> = ir.landing_pads.iter().map(|(pad, _)| *pad).collect();
    let mut seen = vec![false; ir.blocks.len()];
    let mut pending: Vec<usize> = std::iter::once(0)
        .chain(
            ir.blocks
                .iter()
                .enumerate()
                .filter(|(_, block)| pads.contains(&block.start))
                .map(|(index, _)| index),
        )
        .collect();
    while let Some(block) = pending.pop() {
        if !std::mem::replace(&mut seen[block], true) {
            pending.extend(crate::ir::cfg::successors(ir, block));
        }
    }
    let mut position = 0;
    ir.blocks.retain(|_| {
        position += 1;
        seen[position - 1]
    });
}

fn rewrite_stmt(stmt: &mut Stmt, ranges: &Ranges, block: usize, changes: &mut Changes) {
    match stmt {
        Stmt::Brif { lhs, rhs, .. } => {
            rewrite(lhs, ranges, block, true, changes);
            rewrite(rhs, ranges, block, true, changes);
        }
        Stmt::Assign { value, .. } | Stmt::Ret { value } => {
            rewrite_value(value, ranges, block, changes);
        }
        other => {
            for expr in other.operands_mut() {
                rewrite(expr, ranges, block, false, changes);
            }
        }
    }
}

/// Rewrites what a variable is assigned or the function returns, keeping
/// the shapes its type is read from: a mask to a register's width, and the
/// bits a partial register write keeps.
fn rewrite_value(value: &mut Expr, ranges: &Ranges, block: usize, changes: &mut Changes) {
    let kept = |expr: &Expr| {
        matches!(expr, Expr::Bin { op: BinOp::And, lhs, rhs }
            if matches!(lhs.as_ref(), Expr::Reg { .. })
                && matches!(rhs.as_ref(), Expr::Const(keep) if [8, 16, 32].iter().any(|bits| *keep == !mask(*bits))))
    };
    match value {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xff | 0xffff | 0xffff_ffff)) => {
            rewrite(lhs, ranges, block, false, changes);
        }
        Expr::Bin {
            op: BinOp::Or,
            lhs,
            rhs,
        } if kept(lhs) => rewrite_value(rhs, ranges, block, changes),
        Expr::Bin {
            op: BinOp::Or,
            lhs,
            rhs,
        } if kept(rhs) => rewrite_value(lhs, ranges, block, changes),
        other => rewrite(other, ranges, block, false, changes),
    }
}

/// A branch the facts decide becomes a jump or falls through; a switch
/// loses the cases its index never takes, and its default when every value
/// it takes has a case.
fn terminate(
    stmts: &mut Vec<Stmt>,
    ranges: &Ranges,
    block: usize,
    next: Option<u64>,
    changes: &mut Changes,
) {
    match stmts.last_mut() {
        Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        }) => {
            let (Some(a), Some(b)) = (
                ranges.eval(lhs, block, DEPTH),
                ranges.eval(rhs, block, DEPTH),
            ) else {
                return;
            };
            let Some(taken) = decide(*cond, a, b, operand_width(lhs, rhs)) else {
                return;
            };
            let target = *target;
            if next.is_none() || !ranges.starts.contains_key(&target) {
                return;
            }
            stmts.pop();
            if taken && Some(target) != next {
                stmts.push(Stmt::Br {
                    target: Some(target),
                });
            }
            changes.branches += 1;
        }
        Some(Stmt::Switch {
            index,
            cases,
            default,
        }) => {
            let Some(fact) = ranges.eval(index, block, DEPTH) else {
                return;
            };
            let kept: Vec<(i64, u64)> = cases
                .iter()
                .copied()
                .filter(|(case, _)| fact.contains(*case as u64))
                .collect();
            // A default that cases lead to as well stays, so they read as it.
            let shared = kept.iter().any(|(_, target)| Some(*target) == *default);
            let default_kept = if covered(fact, cases) && !shared {
                None
            } else {
                *default
            };
            let mut targets: Vec<u64> = kept
                .iter()
                .map(|(_, target)| *target)
                .chain(default_kept)
                .collect();
            targets.sort_unstable();
            targets.dedup();
            if targets.is_empty() || (kept.len() == cases.len() && default_kept == *default) {
                return;
            }
            changes.cases += cases.len() - kept.len();
            if default_kept != *default {
                changes.defaults += 1;
            }
            if let [target] = targets[..] {
                stmts.pop();
                if Some(target) != next {
                    stmts.push(Stmt::Br {
                        target: Some(target),
                    });
                }
            } else {
                *cases = kept;
                *default = default_kept;
            }
        }
        _ => {}
    }
}

/// Rewrites one expression; `sensitive` where an enclosing operation takes
/// its width from this one.
fn rewrite(expr: &mut Expr, ranges: &Ranges, block: usize, sensitive: bool, changes: &mut Changes) {
    let outer = width(expr);
    match expr {
        Expr::Reg { index, width } => {
            if !sensitive
                && super::Ssa::is_value(*index)
                && let Some(value) = ranges
                    .read(*index, u32::from(*width), block, DEPTH)
                    .and_then(Fact::singleton)
            {
                *expr = Expr::Const(value);
                changes.constants += 1;
            }
        }
        Expr::Const(_) => {}
        Expr::Load { addr, .. } => rewrite(addr, ranges, block, false, changes),
        Expr::SignExtend { value, width } => {
            rewrite(value, ranges, block, false, changes);
            let bits = u32::from(*width) * 8;
            if bits < 64
                && crate::ir::semantics::width(value) == 64
                && ranges
                    .eval(value, block, DEPTH)
                    .is_some_and(|fact| fact.hi < 1 << (bits - 1))
            {
                *expr = (**value).clone();
                changes.extensions += 1;
            }
        }
        Expr::Bin { op, lhs, rhs } => {
            let signed = matches!(op, BinOp::Sar | BinOp::DivS | BinOp::ModS);
            let low_mask = *op == BinOp::And
                && matches!(rhs.as_ref(), Expr::Const(value) if value.wrapping_add(1).is_power_of_two());
            rewrite(
                lhs,
                ranges,
                block,
                signed || (sensitive && !low_mask),
                changes,
            );
            rewrite(rhs, ranges, block, signed || sensitive, changes);
            if *op == BinOp::And
                && let Expr::Const(kept) = rhs.as_ref()
                && let Some(fact) = ranges.eval(lhs, block, DEPTH)
            {
                if fact.possible() & !kept == 0 && width(lhs) == outer {
                    *expr = (**lhs).clone();
                    changes.masks += 1;
                    return;
                }
                if fact.possible() & kept == 0 && !sensitive {
                    *expr = Expr::Const(0);
                    changes.masks += 1;
                    return;
                }
            }
            if !sensitive && let (Expr::Const(_), Expr::Const(_)) = (lhs.as_ref(), rhs.as_ref()) {
                *expr = Expr::bin(*op, (**lhs).clone(), (**rhs).clone());
            }
        }
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            rewrite(lhs, ranges, block, true, changes);
            rewrite(rhs, ranges, block, true, changes);
            rewrite(then, ranges, block, sensitive, changes);
            rewrite(els, ranges, block, sensitive, changes);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                rewrite(arg, ranges, block, false, changes);
            }
        }
    }
}

#[cfg(test)]
mod tests;
