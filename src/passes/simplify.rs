use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};

/// Propagates constants within a basic block and simplifies expressions.
pub fn simplify(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        let mut constants: HashMap<u16, u64> = HashMap::new();
        for stmt in &mut block.stmts {
            simplify_stmt(stmt, &mut constants);
        }
    }
}

fn simplify_stmt(stmt: &mut Stmt, constants: &mut HashMap<u16, u64>) {
    match stmt {
        Stmt::Assign { dest, value } => {
            let simplified = simplify_expr(value.clone(), constants);
            if let Expr::Const(value) = simplified {
                constants.insert(dest.index, value);
            } else {
                constants.remove(&dest.index);
            }
            *value = simplified;
        }
        Stmt::Store { addr, value, width } => {
            *addr = simplify_expr(addr.clone(), constants);
            *value = simplify_expr(value.clone(), constants);
            let kept = crate::ir::semantics::mask(u32::from(*width) * 8);
            // A partial register write merges the bits it keeps of the
            // register; none of them lies in the stored bytes.
            if let Expr::Bin {
                op: BinOp::Or,
                lhs,
                rhs,
            } = value
            {
                let register_bits = |part: &Expr| {
                    matches!(part,
                    Expr::Bin { op: BinOp::And, lhs, rhs }
                        if matches!(lhs.as_ref(), Expr::Reg { .. })
                            && matches!(rhs.as_ref(), Expr::Const(_)))
                };
                if let Some(low) = outside_mask(lhs, rhs, kept)
                    .filter(|_| register_bits(lhs))
                    .or_else(|| outside_mask(rhs, lhs, kept).filter(|_| register_bits(rhs)))
                    .cloned()
                {
                    *value = low;
                }
            }
            // A store keeps only its low bytes, which a mask covering them
            // does not change.
            while let Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } = value
                && let Expr::Const(mask) = rhs.as_ref()
                && mask & kept == kept
            {
                *value = lhs.as_ref().clone();
            }
        }
        Stmt::Brif { cond, lhs, rhs, .. } => {
            *lhs = simplify_expr(lhs.clone(), constants);
            *rhs = simplify_expr(rhs.clone(), constants);
            if let Some(width) =
                crate::ir::visit::expr_width(lhs).or_else(|| crate::ir::visit::expr_width(rhs))
            {
                cancel_round_trip(lhs, width);
                cancel_round_trip(rhs, width);
                // A constant compares at the operands' width.
                if width < 64 {
                    for side in [&mut *lhs, &mut *rhs] {
                        if let Expr::Const(value) = side {
                            *value &= (1u64 << width) - 1;
                        }
                    }
                }
            }
            if matches!(cond, crate::ir::Cond::Eq | crate::ir::Cond::Ne) {
                move_offset_across(lhs, rhs);
            }
        }
        Stmt::BrIndirect { target } => {
            *target = simplify_expr(target.clone(), constants);
        }
        Stmt::Switch { index, .. } => {
            *index = simplify_expr(index.clone(), constants);
        }
        Stmt::Ret { value } => {
            *value = simplify_expr(value.clone(), constants);
        }
        Stmt::Call { through, args, .. } => {
            if let Some(through) = through {
                *through = simplify_expr(through.clone(), constants);
            }
            for arg in args.iter_mut().flatten() {
                *arg = simplify_expr(arg.clone(), constants);
            }
            // A call may clobber registers.
            constants.clear();
        }
        Stmt::Unsupported { .. } => {
            // Unknown effects may clobber registers.
            constants.clear();
        }
        Stmt::Br { .. } | Stmt::BrifFlags { .. } | Stmt::Trap => {}
    }
}

/// `other` when `kept` is `r & keep` and `keep` shares no bit with `mask`.
fn outside_mask<'e>(kept: &Expr, other: &'e Expr, mask: u64) -> Option<&'e Expr> {
    (crate::ssa::ranges::of(kept).possible() & mask == 0).then_some(other)
}

/// In a compare at `width` bits, `(a - b) + b` and `(a + b) - b` are `a`; a
/// 32-bit mask on the inner result changes nothing at 32 bits.
fn cancel_round_trip(expr: &mut Expr, width: u8) {
    use crate::ir::BinOp;
    let Expr::Bin { op, lhs, rhs } = &*expr else {
        return;
    };
    let inverse = match op {
        BinOp::Add => BinOp::Sub,
        BinOp::Sub => BinOp::Add,
        _ => return,
    };
    let mut inner = lhs.as_ref();
    if width <= 32
        && let Expr::Bin {
            op: BinOp::And,
            lhs: masked,
            rhs: mask,
        } = inner
        && matches!(mask.as_ref(), Expr::Const(0xffff_ffff))
    {
        inner = masked;
    }
    if let Expr::Bin {
        op: inner_op,
        lhs: original,
        rhs: offset,
    } = inner
        && *inner_op == inverse
        && offset == rhs
    {
        *expr = original.as_ref().clone();
    }
}

/// `x + c == k` is `x == k - c` at the width of `x`, as is `x - c == k`
/// with `k + c`.
fn move_offset_across(lhs: &mut Expr, rhs: &mut Expr) {
    let (
        Expr::Bin {
            op,
            lhs: inner,
            rhs: offset,
        },
        Expr::Const(k),
    ) = (&*lhs, &*rhs)
    else {
        return;
    };
    let Expr::Const(c) = offset.as_ref() else {
        return;
    };
    let moved = match op {
        crate::ir::BinOp::Add => k.wrapping_sub(*c),
        crate::ir::BinOp::Sub => k.wrapping_add(*c),
        _ => return,
    };
    let Some(width) = crate::ir::visit::expr_width(inner) else {
        return;
    };
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    *rhs = Expr::Const(moved & mask);
    *lhs = inner.as_ref().clone();
}

fn simplify_expr(expr: Expr, constants: &HashMap<u16, u64>) -> Expr {
    match expr {
        Expr::Reg { index, width } => match constants.get(&index) {
            Some(value) if width >= 64 => Expr::constant(*value),
            Some(value) => Expr::constant(*value & ((1u64 << width) - 1)),
            None => Expr::Reg { index, width },
        },
        Expr::Const(_) => expr,
        Expr::Bin { op, lhs, rhs } => fold_offsets(algebraic(Expr::bin(
            op,
            simplify_expr(*lhs, constants),
            simplify_expr(*rhs, constants),
        ))),
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(simplify_expr(*addr, constants)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => {
            let value = simplify_expr(*value, constants);
            // The extension reads only its low bytes, which the kept bits of
            // a partial register write do not reach.
            let low = (1u64 << (u32::from(width.min(4)) * 8)).wrapping_sub(1);
            let value = match &value {
                Expr::Bin {
                    op: crate::ir::BinOp::Or,
                    lhs: a,
                    rhs: b,
                } => outside_mask(a, b, low)
                    .or_else(|| outside_mask(b, a, low))
                    .cloned()
                    .unwrap_or(value),
                _ => value,
            };
            // In `(int8_t)(x & 0xff)` the mask repeats the extension's truncation.
            let value = match value {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    lhs,
                    rhs,
                } => match rhs.as_ref() {
                    Expr::Const(mask)
                        if *mask == (1u64 << (width.min(8) as u32 * 8)).wrapping_sub(1) =>
                    {
                        lhs.as_ref().clone()
                    }
                    _ => Expr::Bin {
                        op: crate::ir::BinOp::And,
                        lhs,
                        rhs,
                    },
                },
                other => other,
            };
            Expr::SignExtend {
                value: Box::new(value),
                width,
            }
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond,
            lhs: Box::new(simplify_expr(*lhs, constants)),
            rhs: Box::new(simplify_expr(*rhs, constants)),
            then: Box::new(simplify_expr(*then, constants)),
            els: Box::new(simplify_expr(*els, constants)),
        },
        Expr::Apply { op, args } => {
            let args: Vec<Expr> = args
                .into_iter()
                .map(|arg| simplify_expr(arg, constants))
                .collect();
            // Comparing or subtracting a value's lanes with themselves, as
            // `pcmpeqd x, x` does to set every bit, reads nothing of them.
            if let (crate::ir::Operation::Lanes(lane, _), [a, b]) = (op, args.as_slice())
                && a == b
            {
                use crate::ir::LaneOp;
                match lane {
                    LaneOp::Equal | LaneOp::GreaterEqualSigned | LaneOp::GreaterEqualUnsigned => {
                        return Expr::constant(u64::MAX);
                    }
                    LaneOp::Sub | LaneOp::GreaterSigned | LaneOp::GreaterUnsigned => {
                        return Expr::constant(0);
                    }
                    _ => {}
                }
            }
            let values: Option<Vec<u64>> = args
                .iter()
                .map(|arg| match arg {
                    Expr::Const(value) => Some(*value),
                    _ => None,
                })
                .collect();
            match values.and_then(|values| crate::ir::semantics::fold(op, &values)) {
                Some(value) => Expr::constant(value),
                None => {
                    let applied = Expr::Apply { op, args };
                    counted_bits(&applied).unwrap_or(applied)
                }
            }
        }
    }
}

/// The bits of one value an Or-tree puts back where they were: each term
/// is `x & m` with contiguous `m`, or `((x >> k) & m) << k`; when the
/// terms are disjoint and cover bits 0 up to some width, the tree is `x`
/// within that width.
fn reassembled(expr: &Expr) -> Option<Expr> {
    use crate::ir::BinOp;
    let mut terms = Vec::new();
    let mut work = vec![expr];
    while let Some(term) = work.pop() {
        match term {
            Expr::Bin {
                op: BinOp::Or,
                lhs,
                rhs,
            } => work.extend([lhs.as_ref(), rhs.as_ref()]),
            other => terms.push(other),
        }
    }
    if terms.len() < 2 {
        return None;
    }
    // A contiguous run of ones: its lowest bit and how many.
    let run = |mask: u64| -> Option<(u32, u32)> {
        if mask == 0 {
            return None;
        }
        let low = mask.trailing_zeros();
        let ones = (mask >> low).trailing_ones();
        (ones == 64 || (mask >> low) >> ones == 0).then_some((low, ones))
    };
    let field = |term: &Expr| -> Option<(Expr, u32, u32)> {
        match term {
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } => {
                let Expr::Const(mask) = rhs.as_ref() else {
                    return None;
                };
                let Some((low, ones)) = run(*mask) else {
                    return None;
                };
                Some((lhs.as_ref().clone(), low, ones))
            }
            Expr::Bin {
                op: BinOp::Shl,
                lhs,
                rhs,
            } => {
                let (
                    Expr::Const(up),
                    Expr::Bin {
                        op: BinOp::And,
                        lhs: inner,
                        rhs: mask,
                    },
                ) = (rhs.as_ref(), lhs.as_ref())
                else {
                    return None;
                };
                let (
                    Expr::Const(mask),
                    Expr::Bin {
                        op: BinOp::Shr,
                        lhs: source,
                        rhs: down,
                    },
                ) = (mask.as_ref(), inner.as_ref())
                else {
                    return None;
                };
                let Some((0, ones)) = run(*mask) else {
                    return None;
                };
                (matches!(down.as_ref(), Expr::Const(down) if down == up) && *up < 64).then(|| {
                    (
                        source.as_ref().clone(),
                        *up as u32,
                        ones.min(64 - *up as u32),
                    )
                })
            }
            _ => None,
        }
    };
    let Some(fields) = terms
        .into_iter()
        .map(field)
        .collect::<Option<Vec<(Expr, u32, u32)>>>()
    else {
        return None;
    };
    let source = fields[0].0.clone();
    if fields.iter().any(|(value, ..)| *value != source) {
        return None;
    }
    let mut ranges: Vec<(u32, u32)> = fields.iter().map(|(_, low, ones)| (*low, *ones)).collect();
    ranges.sort_unstable();
    let mut covered = 0;
    for (low, ones) in ranges {
        if low != covered {
            return None;
        }
        covered += ones;
    }
    Some(if covered >= 64 {
        source
    } else {
        Expr::bin(BinOp::And, source, Expr::constant((1 << covered) - 1))
    })
}

/// Removes a double negation and the addition or subtraction of zero.
/// The bit count a vector sums out of per-byte counts, as AArch64 counts
/// the bits of a general register: `uaddlv(cnt(x))` is `popcount(x)`.
fn counted_bits(expr: &Expr) -> Option<Expr> {
    use crate::ir::{LaneOp, Operation};
    let Expr::Apply {
        op: Operation::SumLanesLong {
            bits: 8,
            signed: false,
        },
        args,
    } = expr
    else {
        return None;
    };
    let mut counts = Vec::new();
    for half in args {
        match half {
            Expr::Const(0) => {}
            Expr::Apply {
                op: Operation::Lanes(LaneOp::PopCount, 8),
                args,
            } => counts.push(Expr::apply(Operation::PopCount(64), vec![args[0].clone()])),
            _ => return None,
        }
    }
    counts
        .into_iter()
        .reduce(|sum, count| Expr::bin(crate::ir::BinOp::Add, sum, count))
}

/// `x` without a mask to 32 bits it does not need: a value that already
/// fits.
fn low32(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) && fits32(lhs) => lhs,
        other => other,
    }
}

/// Whether `expr` provably holds less than 2^32.
fn fits32(expr: &Expr) -> bool {
    crate::ssa::ranges::of(expr).hi <= 0xffff_ffff
}

/// The divisor a multiply-and-shift by `magic` and `shift` divides a value
/// below 2^32 by, exactly: `(x * magic) >> shift` is `x / d` for every such
/// `x` when `2^shift <= magic * d <= 2^shift + 2^(shift - 32)`.
fn magic_divisor(magic: u64, shift: u64) -> Option<u64> {
    if magic == 0 || magic > 0xffff_ffff || !(32..64).contains(&shift) {
        return None;
    }
    let power = 1u128 << shift;
    let estimate = power / u128::from(magic);
    (estimate..=estimate + 1).find_map(|divisor| {
        let product = u128::from(magic) * divisor;
        (divisor >= 2 && product >= power && product - power <= 1u128 << (shift - 32))
            .then_some(divisor as u64)
    })
}

pub(crate) fn algebraic(expr: Expr) -> Expr {
    // The undefined value may be taken as any value, as zero: masked or
    // shifted it stays undefined, and bits put in beside it, as a partial
    // write of a register a call left undefined puts them, are the value.
    if let Expr::Bin { op, lhs, rhs } = &expr {
        let undefined = |expr: &Expr| {
            matches!(
                expr,
                Expr::Apply {
                    op: crate::ir::Operation::Undefined,
                    ..
                }
            )
        };
        match op {
            BinOp::And if undefined(lhs) || undefined(rhs) => {
                return Expr::apply(crate::ir::Operation::Undefined, Vec::new());
            }
            BinOp::Shl | BinOp::Shr | BinOp::Sar if undefined(lhs) => return lhs.as_ref().clone(),
            BinOp::Or if undefined(lhs) => return rhs.as_ref().clone(),
            BinOp::Or if undefined(rhs) => return lhs.as_ref().clone(),
            _ => {}
        }
    }
    // A multiply by a magic number and a shift, as compilers divide a
    // 32-bit value by a constant.
    if let Expr::Bin {
        op: BinOp::Shr,
        lhs,
        rhs,
    } = &expr
        && let (
            Expr::Bin {
                op: BinOp::Mul,
                lhs: value,
                rhs: magic,
            },
            Expr::Const(shift),
        ) = (lhs.as_ref(), rhs.as_ref())
        && let Expr::Const(magic) = magic.as_ref()
        && fits32(value)
        && let Some(divisor) = magic_divisor(*magic, *shift)
    {
        return Expr::bin(BinOp::DivU, value.as_ref().clone(), Expr::Const(divisor));
    }
    // `q + (q << k)` is `q * (2^k + 1)`, for a quotient whose remainder
    // this leads to.
    if let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = &expr
        && let Expr::Bin {
            op: BinOp::Shl,
            lhs: shifted,
            rhs: amount,
        } = rhs.as_ref()
        && let Expr::Const(amount @ 1..=31) = amount.as_ref()
        && low32(shifted) == low32(lhs)
        && matches!(
            low32(lhs),
            Expr::Bin {
                op: BinOp::DivU,
                ..
            }
        )
        && fits32(low32(lhs))
    {
        return Expr::bin(
            BinOp::Mul,
            low32(lhs).clone(),
            Expr::Const((1 << amount) + 1),
        );
    }
    // `x - (x / d) * d` is `x % d`.
    if let Expr::Bin {
        op: BinOp::Sub,
        lhs,
        rhs,
    } = &expr
        && let Expr::Bin {
            op: BinOp::Mul,
            lhs: quotient,
            rhs: times,
        } = low32(rhs)
        && let Expr::Bin {
            op: BinOp::DivU,
            lhs: dividend,
            rhs: divisor,
        } = low32(quotient)
        && times == divisor
        && low32(dividend) == low32(lhs)
    {
        return Expr::bin(BinOp::ModU, low32(lhs).clone(), divisor.as_ref().clone());
    }
    // Only where the operations around it see the same width.
    if let Some(whole) = reassembled(&expr)
        && crate::ir::semantics::width(&whole) == crate::ir::semantics::width(&expr)
    {
        return whole;
    }
    // `x | ((x >> k) & m) << k` sets only bits of `x` that `x` sets: `x`;
    // so is `(x & low) | ((x >> k) & m) << k` when the two cover every bit.
    if let Expr::Bin {
        op: BinOp::Or,
        lhs,
        rhs,
    } = &expr
        && let Expr::Bin {
            op: BinOp::Shl,
            lhs: masked,
            rhs: back,
        } = rhs.as_ref()
        && let Expr::Bin {
            op: BinOp::And,
            lhs: shifted,
            rhs: mask,
        } = masked.as_ref()
        && matches!(mask.as_ref(), Expr::Const(_))
        && let Expr::Bin {
            op: BinOp::Shr,
            lhs: value,
            rhs: out,
        } = shifted.as_ref()
        && out == back
    {
        if value == lhs {
            return lhs.as_ref().clone();
        }
        if let (
            Expr::Bin {
                op: BinOp::And,
                lhs: low_value,
                rhs: low,
            },
            Expr::Const(shift),
            Expr::Const(high),
        ) = (lhs.as_ref(), back.as_ref(), mask.as_ref())
            && let Expr::Const(low) = low.as_ref()
            && *shift > 0
            && *shift < 64
            && low_value == value
            && *low == (1u64 << shift) - 1
            && (high << shift) | low == u64::MAX
        {
            return value.as_ref().clone();
        }
    }
    let Expr::Bin { op, lhs, rhs } = &expr else {
        return expr;
    };
    let zero = |value: &Expr| matches!(value, Expr::Const(0));
    match op {
        // `0 - (0 - x)`, left behind by the absolute-value and negate shapes.
        crate::ir::BinOp::Sub if zero(lhs) => {
            if let Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs: inner,
                rhs: inner_rhs,
            } = rhs.as_ref()
                && zero(inner)
            {
                return inner_rhs.as_ref().clone();
            }
            expr
        }
        crate::ir::BinOp::Sub if zero(rhs) => lhs.as_ref().clone(),
        crate::ir::BinOp::Add if zero(rhs) => lhs.as_ref().clone(),
        // An unsigned load is already zero above its bytes; a mask of
        // exactly those bytes keeps its width too.
        crate::ir::BinOp::And
            if let (
                Expr::Load {
                    width,
                    signed: false,
                    ..
                },
                Expr::Const(mask),
            ) = (lhs.as_ref(), rhs.as_ref())
                && *mask == crate::ir::semantics::mask(u32::from(*width) * 8) =>
        {
            lhs.as_ref().clone()
        }
        // `(x & a) & b` is `x & (a & b)`.
        crate::ir::BinOp::And
            if let (
                Expr::Const(outer),
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    lhs: inner,
                    rhs: inner_mask,
                },
            ) = (rhs.as_ref(), lhs.as_ref())
                && let Expr::Const(inner_mask) = inner_mask.as_ref() =>
        {
            Expr::bin(
                crate::ir::BinOp::And,
                inner.as_ref().clone(),
                Expr::Const(outer & inner_mask),
            )
        }
        // `((r & keep) | v) & mask` with `keep & mask == 0` is `v & mask`:
        // the kept bits of a partial register write fall outside the mask.
        crate::ir::BinOp::And
            if let Expr::Const(mask) = rhs.as_ref()
                && let Expr::Bin {
                    op: crate::ir::BinOp::Or,
                    lhs: a,
                    rhs: b,
                } = lhs.as_ref()
                && let Some(value) =
                    outside_mask(a, b, *mask).or_else(|| outside_mask(b, a, *mask)) =>
        {
            Expr::bin(crate::ir::BinOp::And, value.clone(), Expr::Const(*mask))
        }
        // The low 32 bits of a sum, difference, product or bitwise operation
        // depend only on the low 32 bits of its operands.
        crate::ir::BinOp::And if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => {
            let Expr::Bin {
                op: inner,
                lhs: a,
                rhs: b,
            } = lhs.as_ref()
            else {
                return expr;
            };
            use crate::ir::BinOp;
            if !matches!(
                inner,
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
            ) {
                return expr;
            }
            // A masked register stays: it reads as the 32-bit register.
            let low = |operand: &Expr| match operand {
                Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                    && !matches!(lhs.as_ref(), Expr::Reg { .. }) =>
                {
                    lhs.as_ref().clone()
                }
                other => other.clone(),
            };
            Expr::bin(
                BinOp::And,
                Expr::bin(*inner, low(a), low(b)),
                Expr::Const(0xffff_ffff),
            )
        }
        _ => expr,
    }
}

/// Reassociates constant offsets so an address reads as one base plus one
/// displacement (`(sp - 0x20) + 8` becomes `sp - 0x18`).
fn fold_offsets(expr: Expr) -> Expr {
    let Expr::Bin { op, lhs, rhs } = expr else {
        return expr;
    };
    let Expr::Const(delta) = rhs.as_ref() else {
        return Expr::Bin { op, lhs, rhs };
    };
    let Expr::Bin {
        op: inner_op,
        lhs: base,
        rhs: inner,
    } = lhs.as_ref()
    else {
        return Expr::Bin { op, lhs, rhs };
    };
    let Expr::Const(offset) = inner.as_ref() else {
        return Expr::Bin { op, lhs, rhs };
    };
    let outer = match op {
        crate::ir::BinOp::Add => *delta,
        crate::ir::BinOp::Sub => delta.wrapping_neg(),
        _ => return Expr::Bin { op, lhs, rhs },
    };
    let total = match inner_op {
        crate::ir::BinOp::Add => offset.wrapping_add(outer),
        crate::ir::BinOp::Sub => outer.wrapping_sub(*offset),
        _ => return Expr::Bin { op, lhs, rhs },
    };
    Expr::bin(
        crate::ir::BinOp::Add,
        base.as_ref().clone(),
        Expr::constant(total),
    )
}

#[cfg(test)]
mod tests {
    use super::simplify;
    use crate::ir::{BinOp, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    #[test]
    fn stores_discard_preserved_register_bits_outside_the_access() {
        for width in [1, 2, 4, 8] {
            let low = crate::ir::semantics::mask(u32::from(width) * 8);
            for overlap in [false, true] {
                for reversed in [false, true] {
                    let preserved = Expr::bin(
                        BinOp::And,
                        Expr::reg(3, 64),
                        Expr::Const(!low | u64::from(overlap)),
                    );
                    let incoming = Expr::reg(7, 64);
                    let value = if reversed {
                        Expr::bin(BinOp::Or, incoming, preserved)
                    } else {
                        Expr::bin(BinOp::Or, preserved, incoming)
                    };
                    let original = FunctionIr::single_block(
                        Isa::X86_64,
                        vec![
                            Stmt::Store {
                                addr: Expr::Const(0x1000),
                                value,
                                width,
                            },
                            Stmt::Ret {
                                value: Expr::Load {
                                    addr: Box::new(Expr::Const(0x1000)),
                                    width,
                                    signed: false,
                                },
                            },
                        ],
                    );
                    let mut simplified = original.clone();
                    simplify(&mut simplified);
                    let Stmt::Store { value, .. } = &simplified.blocks[0].stmts[0] else {
                        panic!("the store remains");
                    };
                    let mut reads = std::collections::HashSet::new();
                    crate::ir::visit::collect_reads(value, &mut reads);
                    assert_eq!(
                        reads.contains(&3),
                        overlap,
                        "{width} {overlap} {reversed}: {}",
                        simplified.render()
                    );
                    for seed in 0..16 {
                        let setup = crate::ir::eval::Setup {
                            seed,
                            convention: crate::ir::eval::Convention {
                                arguments: &[],
                                clobbered: &[],
                            },
                            registers: &[],
                            memory: &[],
                            step_limit: 16,
                        };
                        assert_eq!(
                            crate::ir::eval::run(&original, &setup),
                            crate::ir::eval::run(&simplified, &setup),
                            "{width} {overlap} {reversed} {seed}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_store_does_not_discard_a_real_wide_load_of_preserved_bits() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Store {
                addr: Expr::Const(0x1000),
                width: 1,
                value: Expr::bin(
                    BinOp::Or,
                    Expr::bin(
                        BinOp::And,
                        Expr::Load {
                            addr: Box::new(Expr::Const(0x2000)),
                            width: 8,
                            signed: false,
                        },
                        Expr::Const(!0xff),
                    ),
                    Expr::reg(7, 64),
                ),
            }],
        );
        simplify(&mut ir);
        let Stmt::Store { value, .. } = &ir.blocks[0].stmts[0] else {
            panic!("the store remains");
        };
        let Expr::Bin {
            op: BinOp::Or, lhs, ..
        } = value
        else {
            panic!("the real load remains in its merge");
        };
        let Expr::Bin {
            op: BinOp::And,
            lhs,
            ..
        } = lhs.as_ref()
        else {
            panic!("the real load keeps its mask");
        };
        assert!(matches!(lhs.as_ref(), Expr::Load { width: 8, .. }));
    }

    #[test]
    fn a_mask_drops_the_bits_a_partial_write_kept() {
        // ((rcx & ~0xff) | v) & 0xff is v & 0xff.
        let value = Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(0xff));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::And,
                    Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, Expr::reg(1, 64), Expr::Const(!0xff)),
                        value.clone(),
                    ),
                    Expr::Const(0xff),
                ),
            }],
        );

        simplify(&mut ir);

        let Stmt::Ret { value: simplified } = &ir.blocks[0].stmts[0] else {
            panic!("the return stays");
        };
        let mut reads = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(simplified, &mut reads);
        assert!(!reads.contains(&1), "{}", ir.render());
    }

    #[test]
    fn folds_an_offset_from_a_subtracted_base() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(0x20)),
                    Expr::Const(8),
                ),
            }],
        );

        simplify(&mut ir);

        let Stmt::Ret { value } = &ir.blocks[0].stmts[0] else {
            panic!("the return stays");
        };
        let expected = Expr::bin(
            BinOp::Add,
            Expr::reg(31, 64),
            Expr::Const(0x18u64.wrapping_neg()),
        );
        assert_eq!(*value, expected, "{}", ir.render());
    }

    #[test]
    fn a_narrow_read_of_a_constant_keeps_its_low_bits() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 8,
                        width: 64,
                    },
                    value: Expr::Const(0x1_0000_0001),
                },
                Stmt::Ret {
                    value: Expr::reg(8, 32),
                },
            ],
        );

        simplify(&mut ir);

        assert!(
            matches!(
                ir.blocks[0].stmts[1],
                Stmt::Ret {
                    value: Expr::Const(1)
                }
            ),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn folds_constant_register_uses() {
        let x10 = RegRef {
            index: 10,
            width: 64,
        };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: x10,
                    value: Expr::Const(0x5556),
                },
                Stmt::Assign {
                    dest: x10,
                    value: Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, Expr::reg(10, 64), Expr::Const(0xffff_ffff)),
                        Expr::Const(0x5555_0000),
                    ),
                },
                Stmt::Ret {
                    value: Expr::reg(10, 64),
                },
            ],
        );

        simplify(&mut ir);

        let rendered = ir.render();
        assert!(rendered.contains("ret #0x55555556"), "{rendered}");
    }
}

#[cfg(test)]
mod magic_tests {
    use super::magic_divisor;

    #[test]
    fn a_magic_multiply_divides_every_32_bit_value() {
        // The magic numbers compilers use for unsigned 32-bit division.
        for (magic, shift, divisor) in [
            (0xaaaa_aaab, 33, 3),
            (0xcccc_cccd, 34, 5),
            (0xcccc_cccd, 35, 10),
        ] {
            assert_eq!(magic_divisor(magic, shift), Some(divisor));
            for x in [
                0u64,
                1,
                2,
                divisor - 1,
                divisor,
                0x7fff_ffff,
                0xffff_fffe,
                0xffff_ffff,
            ] {
                assert_eq!((x * magic) >> shift, x / divisor, "{x} / {divisor}");
            }
        }
    }
}
