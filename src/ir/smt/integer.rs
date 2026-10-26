//! Integer operation semantics beyond the scalar binary operators.

use super::{Value, binary, constant, field, low, signed};
use crate::ir::Operation;

pub(super) fn zero_count(a: &str, bits: u32, leading: bool) -> String {
    let mut result = constant(u64::from(bits));
    for bit in 0..bits {
        let index = if leading { bit } else { bits - 1 - bit };
        let count = bits - 1 - bit;
        result = format!(
            "(ite (= ((_ extract {index} {index}) {a}) #b1) {} {result})",
            constant(u64::from(count))
        );
    }
    result
}

pub(super) fn operation(op: Operation, args: &[Value]) -> Option<String> {
    let a = &args[0].term;
    let mut result = constant(0);
    match op {
        Operation::CountLeadingZeros(bits) | Operation::CountTrailingZeros(bits) => {
            return Some(zero_count(
                a,
                u32::from(bits),
                matches!(op, Operation::CountLeadingZeros(_)),
            ));
        }
        Operation::ReverseBits(bits) => {
            let bits = u32::from(bits);
            for index in 0..bits {
                result = binary(
                    "bvor",
                    &result,
                    &binary(
                        "bvshl",
                        &field(a, index, 1),
                        &constant(u64::from(bits - 1 - index)),
                    ),
                );
            }
        }
        Operation::SignBits(bits) => {
            let bits = u32::from(bits);
            for index in 0..64 / bits {
                result = binary(
                    "bvor",
                    &result,
                    &binary(
                        "bvshl",
                        &field(a, (index + 1) * bits - 1, 1),
                        &constant(u64::from(index)),
                    ),
                );
            }
        }
        Operation::InterleaveLow(bits) | Operation::InterleaveHigh(bits) => {
            let bits = u32::from(bits);
            let start = if matches!(op, Operation::InterleaveHigh(_)) {
                32
            } else {
                0
            };
            for index in 0..32 / bits {
                for (half, value) in args.iter().enumerate() {
                    let lane = field(&value.term, start + index * bits, bits);
                    result = binary(
                        "bvor",
                        &result,
                        &binary(
                            "bvshl",
                            &lane,
                            &constant(u64::from(2 * index * bits) + half as u64 * u64::from(bits)),
                        ),
                    );
                }
            }
        }
        Operation::Widen {
            bits,
            signed: is_signed,
            high,
        } => {
            let bits = u32::from(bits);
            let start = if high { 32 } else { 0 };
            for index in 0..32 / bits {
                let lane = field(a, start + index * bits, bits);
                let wide = if is_signed {
                    low(&signed(&lane, bits), 2 * bits)
                } else {
                    lane
                };
                result = binary(
                    "bvor",
                    &result,
                    &binary("bvshl", &wide, &constant(u64::from(index * 2 * bits))),
                );
            }
        }
        Operation::Narrow(from) => {
            let from = u32::from(from);
            for index in 0..128 / from {
                let source = if index < 64 / from { a } else { &args[1].term };
                let lane = field(source, (index % (64 / from)) * from, from / 2);
                result = binary(
                    "bvor",
                    &result,
                    &binary("bvshl", &lane, &constant(u64::from(index * from / 2))),
                );
            }
        }
        Operation::SumLanes(bits) => {
            let bits = u32::from(bits);
            for value in args {
                for index in 0..64 / bits {
                    result = binary("bvadd", &result, &field(&value.term, index * bits, bits));
                }
            }
            result = low(&result, bits);
        }
        _ => return None,
    }
    Some(result)
}
