//! C definitions for integer vector operations used by printed expressions.

use crate::ir::{Expr, FunctionIr, LaneOp, Operation};
use std::collections::BTreeMap;
mod aes;

pub(super) const VALUE_DEFINITION: &str = "struct velk_vector { union { uint64_t u64; int64_t i64; uint32_t u32; int32_t i32; uint16_t u16; int16_t i16; uint8_t u8; int8_t i8; float f32; double f64; } low, high; };\n\n";

pub(super) fn definitions(ir: &FunctionIr) -> String {
    fn collect(expr: &Expr, found: &mut BTreeMap<String, String>) {
        if let Expr::Apply { op, .. } = expr
            && let Some(body) = definition(*op)
        {
            found.insert(crate::ir::operation_name(*op), body);
        }
        for child in crate::ir::visit::children(expr) {
            collect(child, found);
        }
    }
    let mut found = BTreeMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for value in stmt.operands() {
            collect(value, &mut found);
        }
    }
    found.into_values().collect()
}

fn definition(op: Operation) -> Option<String> {
    if let Operation::Aes { round, high } = op {
        return Some(aes::definition(round, high));
    }
    let name = crate::ir::operation_name(op);
    let (bits, body) = match op {
        Operation::Lanes(LaneOp::Add, 64) => return None,
        Operation::Lanes(lane, bits) => {
            let value = match lane {
                LaneOp::Add => "x + y",
                LaneOp::Sub => "x - y",
                LaneOp::Mul => "x * y",
                LaneOp::Equal => "x == y ? mask : 0",
                LaneOp::GreaterSigned => "sx > sy ? mask : 0",
                LaneOp::GreaterUnsigned => "x > y ? mask : 0",
                LaneOp::GreaterEqualSigned => "sx >= sy ? mask : 0",
                LaneOp::GreaterEqualUnsigned => "x >= y ? mask : 0",
                LaneOp::MinSigned => "sx <= sy ? x : y",
                LaneOp::MinUnsigned => "x <= y ? x : y",
                LaneOp::MaxSigned => "sx >= sy ? x : y",
                LaneOp::MaxUnsigned => "x >= y ? x : y",
                LaneOp::ShiftLeft => "b < BITS ? x << b : 0",
                LaneOp::ShiftRight => "b < BITS ? x >> b : 0",
                LaneOp::ShiftRightSigned => "sx >> (b < BITS ? b : BITS - 1)",
                LaneOp::ShiftVariableUnsigned => "(int8_t)y >= BITS || (int8_t)y <= -BITS ? 0 : ((int8_t)y >= 0 ? x << (int8_t)y : x >> -(int8_t)y)",
                LaneOp::AddSaturatingSigned => "sx + sy < low ? low : (sx + sy > high ? high : sx + sy)",
                LaneOp::SubSaturatingSigned => "sx - sy < low ? low : (sx - sy > high ? high : sx - sy)",
                LaneOp::AddSaturatingUnsigned => "(unsigned __int128)x + y > mask ? mask : x + y",
                LaneOp::SubSaturatingUnsigned => "x < y ? 0 : x - y",
                LaneOp::Average => "((unsigned __int128)x + y + 1) >> 1",
                LaneOp::MulHighSigned => "(sx * sy) >> BITS",
                LaneOp::MulHighUnsigned => "((unsigned __int128)x * y) >> BITS",
                LaneOp::PopCount => "__builtin_popcountll(x)",
                LaneOp::CountLeadingZeros => "x ? __builtin_clzll(x) - (64 - BITS) : BITS",
            };
            (bits, format!("    for (unsigned i = 0; i < 64; i += BITS) {{\n        uint64_t x = (a >> i) & mask, y = (b >> i) & mask;\n        __int128 sx = (int{bits}_t)x, sy = (int{bits}_t)y;\n        __int128 low = -((__int128)1 << (BITS - 1)), high = -low - 1;\n        out |= ((uint64_t)({value}) & mask) << i;\n    }}\n"))
        }
        Operation::Widen { bits, signed, high } => {
            let start = if high { 32 } else { 0 };
            let lane = if signed { format!("(uint64_t)(int64_t)(int{bits}_t)x") } else { "x".into() };
            (bits, format!("    for (unsigned i = 0; i < 32 / BITS; ++i) {{\n        uint64_t x = (a >> ({start} + i * BITS)) & mask;\n        out |= ({lane} & (UINT64_MAX >> (64 - 2 * BITS))) << (2 * i * BITS);\n    }}\n"))
        }
        Operation::Narrow(bits) => (bits, "    for (unsigned i = 0; i < 128 / BITS; ++i) {\n        uint64_t half = i < 64 / BITS ? a : b;\n        out |= ((half >> ((i % (64 / BITS)) * BITS)) & (mask >> (BITS / 2))) << (i * BITS / 2);\n    }\n".into()),
        Operation::SumLanes(bits) => (bits, "    for (unsigned i = 0; i < 64; i += BITS) out += ((a >> i) & mask) + ((b >> i) & mask);\n    out &= mask;\n".into()),
        Operation::InterleaveLow(bits) | Operation::InterleaveHigh(bits) => {
            let start = if matches!(op, Operation::InterleaveHigh(_)) { 32 } else { 0 };
            (bits, format!("    for (unsigned i = 0; i < 32 / BITS; ++i) {{\n        out |= ((a >> ({start} + i * BITS)) & mask) << (2 * i * BITS);\n        out |= ((b >> ({start} + i * BITS)) & mask) << ((2 * i + 1) * BITS);\n    }}\n"))
        }
        Operation::SignBits(bits) => (bits, "    for (unsigned i = 0; i < 64 / BITS; ++i) out |= ((a >> ((i + 1) * BITS - 1)) & 1) << i;\n".into()),
        Operation::Pack { from: bits, unsigned } => {
            let low = if unsigned { "0".into() } else { "-((int64_t)1 << (BITS / 2 - 1))".to_owned() };
            let high = if unsigned { "(int64_t)(mask >> (BITS / 2))" } else { "((int64_t)1 << (BITS / 2 - 1)) - 1" };
            (bits, format!("    for (unsigned i = 0; i < 128 / BITS; ++i) {{\n        uint64_t half = i < 64 / BITS ? a : b;\n        int64_t x = (int{bits}_t)(half >> ((i % (64 / BITS)) * BITS));\n        int64_t low = {low}, high = {high};\n        uint64_t held = (uint64_t)(x < low ? low : (x > high ? high : x));\n        out |= (held & (mask >> (BITS / 2))) << (i * BITS / 2);\n    }}\n"))
        }
        Operation::SumLanesLong { bits, signed } => {
            let x = if signed { format!("(int{bits}_t)x") } else { "x".into() };
            let y = if signed { format!("(int{bits}_t)y") } else { "y".into() };
            (bits, format!("    for (unsigned i = 0; i < 64; i += BITS) {{\n        uint64_t x = (a >> i) & mask, y = (b >> i) & mask;\n        out += (uint64_t)({x}) + (uint64_t)({y});\n    }}\n    out &= UINT64_MAX >> (64 - 2 * BITS);\n"))
        }
        Operation::MultiplyAddPairs => (16, "    for (unsigned i = 0; i < 2; ++i) {\n        int64_t x = (int16_t)(a >> (32 * i)), y = (int16_t)(b >> (32 * i));\n        int64_t z = (int16_t)(a >> (32 * i + 16)), w = (int16_t)(b >> (32 * i + 16));\n        out |= ((uint64_t)(x * y + z * w) & UINT32_MAX) << (32 * i);\n    }\n".into()),
        Operation::SumAbsoluteDifferences => (8, "    for (unsigned i = 0; i < 64; i += 8) {\n        uint64_t x = (a >> i) & 255, y = (b >> i) & 255;\n        out += x > y ? x - y : y - x;\n    }\n".into()),
        _ => return None,
    };
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return None;
    }
    let parameters = if op.arity() == 1 {
        "uint64_t a"
    } else {
        "uint64_t a, uint64_t b"
    };
    let body = body.replace("BITS", &bits.to_string());
    Some(format!(
        "#ifndef VELK_{name}\n#define VELK_{name}\nstatic inline uint64_t {name}({parameters}) {{\n    const uint64_t mask = UINT64_MAX >> {};\n    uint64_t out = 0;\n{body}    return out;\n}}\n#endif\n\n",
        64 - bits
    ))
}
