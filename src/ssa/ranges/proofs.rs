//! Soundness of the known-bits and range domain: every value a fact allows
//! stays allowed by what the transfer functions compute from it, measured
//! against the operations' own semantics in `crate::ir::semantics`.
//!
//! Products, unsigned and signed quotients and high products are not proved
//! here: their 64-bit multipliers and dividers kept CBMC from finishing in 30
//! minutes with either SAT solver. The seeded test
//! `every_operation_keeps_the_values_it_can_produce` checks them instead.

use super::*;
use crate::ir::semantics::{holds, scalar};

/// Any fact `Fact::new` can build.
fn any_fact() -> Fact {
    let fact = Fact::new(kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(fact.is_some());
    fact.unwrap()
}

/// Any value `fact` allows.
fn member(fact: Fact) -> u64 {
    let value: u64 = kani::any();
    kani::assume(fact.contains(value));
    value
}

fn any_bits() -> u32 {
    let bits: u32 = kani::any();
    kani::assume((1..=64).contains(&bits));
    bits
}

/// The binary operation's fact allows the result for any members of the
/// operands' facts.
fn sound(op: BinOp, transfer: fn(Fact, Fact) -> Fact) {
    let (a, b) = (any_fact(), any_fact());
    let (x, y) = (member(a), member(b));
    let Some(result) = scalar(op, x, y, 64) else {
        return;
    };
    assert!(transfer(a, b).contains(result));
    kani::cover!(
        a.singleton().is_none() && b.singleton().is_none(),
        "neither operand is a single value"
    );
}

#[kani::proof]
#[kani::unwind(3)]
fn facts_keep_every_member() {
    let (zeros, ones, lo, hi): (u64, u64, u64, u64) = kani::any();
    let value: u64 = kani::any();
    kani::assume(value & zeros == 0 && value & ones == ones && lo <= value && value <= hi);
    let fact = Fact::new(zeros, ones, lo, hi);
    assert!(fact.is_some_and(|fact| fact.contains(value)));
    kani::cover!(
        fact.is_some_and(|fact| fact.zeros != zeros && fact.lo != lo),
        "both views tighten each other"
    );
}

#[kani::proof]
#[kani::unwind(3)]
fn joins_and_meets_are_sound() {
    let (a, b) = (any_fact(), any_fact());
    let x = member(a);
    assert!(a.join(b).contains(x) && b.join(a).contains(x));
    if b.contains(x) {
        assert!(a.meet(b).is_some_and(|both| both.contains(x)));
    }
}

#[kani::proof]
#[kani::unwind(3)]
fn sums_are_sound() {
    sound(BinOp::Add, Fact::plus);
    let (a, b) = (any_fact(), any_fact());
    kani::cover!(
        a.lo.checked_add(b.lo).is_none() && a.singleton().is_none(),
        "every sum of two ranges wraps"
    );
}

#[kani::proof]
#[kani::unwind(3)]
fn differences_are_sound() {
    sound(BinOp::Sub, Fact::minus);
    let (a, b) = (any_fact(), any_fact());
    kani::cover!(
        a.hi < b.lo && a.singleton().is_none(),
        "every difference wraps"
    );
}

#[kani::proof]
#[kani::unwind(3)]
fn bitwise_operations_are_sound() {
    sound(BinOp::And, Fact::and);
    sound(BinOp::Or, Fact::or);
    sound(BinOp::Xor, Fact::xor);
}

#[kani::proof]
#[kani::unwind(3)]
fn left_shifts_are_sound() {
    sound(BinOp::Shl, Fact::shifted_left);
}

#[kani::proof]
#[kani::unwind(3)]
fn right_shifts_are_sound() {
    sound(BinOp::Shr, Fact::shifted_right);
}

#[kani::proof]
#[kani::unwind(3)]
fn signed_right_shifts_are_sound() {
    let (a, b) = (any_fact(), any_fact());
    let (x, y) = (member(a), member(b));
    let bits = any_bits();
    let result = scalar(BinOp::Sar, x, y, bits).unwrap();
    assert!(a.shifted_right_signed(b, bits).contains(result));
}

#[kani::proof]
#[kani::unwind(3)]
fn remainders_are_sound() {
    sound(BinOp::ModU, Fact::remainder);
}

#[kani::proof]
#[kani::unwind(3)]
fn truncations_and_sign_extensions_are_sound() {
    let fact = any_fact();
    let value = member(fact);
    let bits = any_bits();
    assert!(fact.truncate(bits).contains(value & mask(bits)));
    assert!(
        fact.sign_extend(bits)
            .contains(sign_extend(value, bits) as u64)
    );
}

/// A decided comparison comes out the same for every pair of members.
#[kani::proof]
#[kani::unwind(3)]
fn decided_comparisons_hold_for_every_member() {
    let (a, b) = (any_fact(), any_fact());
    let (x, y) = (member(a), member(b));
    let cond: Cond = kani::any();
    let bits = any_bits();
    if let Some(outcome) = decide(cond, a, b, bits) {
        assert_eq!(holds(cond, x, y, bits), outcome);
        kani::cover!(
            a.singleton().is_none() && b.singleton().is_none(),
            "ranges decide it"
        );
    }
}

/// Narrowing to the side where a comparison holds keeps every member for
/// which it holds against some member of the other side.
fn refinement_is_sound(cond: Cond) {
    let (a, b) = (any_fact(), any_fact());
    let (x, y) = (member(a), member(b));
    let bits = any_bits();
    if holds(cond, x, y, bits) {
        let refined = refine(cond, a, b, bits);
        assert!(refined.is_some_and(|fact| fact.contains(x & mask(bits))));
        // The flag conditions narrow nothing by design.
        if !matches!(cond, Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc) {
            kani::cover!(
                refined.is_some_and(|fact| fact != a.truncate(bits)),
                "the fact narrows"
            );
        }
    }
}

#[kani::proof]
#[kani::unwind(3)]
fn equal_refines_soundly() {
    refinement_is_sound(Cond::Eq);
}

#[kani::proof]
#[kani::unwind(3)]
fn not_equal_refines_soundly() {
    refinement_is_sound(Cond::Ne);
}

#[kani::proof]
#[kani::unwind(3)]
fn unsigned_below_refines_soundly() {
    refinement_is_sound(Cond::Cc);
}

#[kani::proof]
#[kani::unwind(3)]
fn unsigned_at_or_above_refines_soundly() {
    refinement_is_sound(Cond::Cs);
}

#[kani::proof]
#[kani::unwind(3)]
fn unsigned_above_refines_soundly() {
    refinement_is_sound(Cond::Hi);
}

#[kani::proof]
#[kani::unwind(3)]
fn unsigned_at_or_below_refines_soundly() {
    refinement_is_sound(Cond::Ls);
}

#[kani::proof]
#[kani::unwind(3)]
fn signed_below_refines_soundly() {
    refinement_is_sound(Cond::Lt);
}

#[kani::proof]
#[kani::unwind(3)]
fn signed_at_or_below_refines_soundly() {
    refinement_is_sound(Cond::Le);
}

#[kani::proof]
#[kani::unwind(3)]
fn signed_above_refines_soundly() {
    refinement_is_sound(Cond::Gt);
}

#[kani::proof]
#[kani::unwind(3)]
fn signed_at_or_above_refines_soundly() {
    refinement_is_sound(Cond::Ge);
}

#[kani::proof]
#[kani::unwind(3)]
fn flag_conditions_refine_soundly() {
    refinement_is_sound(Cond::Mi);
    refinement_is_sound(Cond::Pl);
    refinement_is_sound(Cond::Vs);
    refinement_is_sound(Cond::Vc);
}

fn any_register_width() -> u32 {
    match kani::any::<u8>() % 4 {
        0 => 8,
        1 => 16,
        2 => 32,
        _ => 64,
    }
}

/// `expression` on an operation of two register reads allows the
/// operation's value, for registers holding any members of their facts.
fn expression_is_sound(op: BinOp) {
    let bits = any_register_width();
    let (a, b) = (any_fact().truncate(bits), any_fact().truncate(bits));
    let (x, y) = (member(a), member(b));
    let width = bits as u8;
    let expr = Expr::bin(op, Expr::reg(0, width), Expr::reg(1, width));
    let facts = |index: u16, _: u32| Some(if index == 0 { a } else { b });
    // What `evaluate` computes for this expression: the reads are already
    // within their width, so it is `scalar` at the operand width.
    let Some(value) = scalar(op, x, y, bits) else {
        return;
    };
    assert!(expression(&expr, &facts).is_some_and(|fact| fact.contains(value)));
    kani::cover!(sign_extend(x, bits) < 0, "a negative left operand");
}

#[kani::proof]
#[kani::unwind(3)]
fn signed_remainders_are_sound() {
    expression_is_sound(BinOp::ModS);
}

/// Exchanging the operands with `swapped`, or negating with `invert`, keeps
/// the comparison's outcome.
#[kani::proof]
fn swapped_and_inverted_comparisons_agree() {
    let cond: Cond = kani::any();
    let (x, y): (u64, u64) = kani::any();
    let bits = any_bits();
    if let Some(other) = swapped(cond) {
        assert_eq!(holds(other, y, x, bits), holds(cond, x, y, bits));
    }
    assert_eq!(holds(cond.invert(), x, y, bits), !holds(cond, x, y, bits));
}

/// A constraint on a read's low bits keeps every value of the read whose
/// low bits meet it.
#[kani::proof]
#[kani::unwind(3)]
fn constrained_reads_keep_every_member() {
    let bits = any_bits();
    let low = any_bits();
    let fact = any_fact();
    kani::assume(fact.hi <= mask(bits));
    let constraint = any_fact();
    let value = member(fact);
    if constraint.contains(value & mask(low)) {
        let narrowed = constrained(fact, bits, low, constraint);
        assert!(narrowed.is_some_and(|narrowed| narrowed.contains(value)));
        kani::cover!(
            low < bits && fact.hi > mask(low),
            "only the low bits are constrained"
        );
    }
}
