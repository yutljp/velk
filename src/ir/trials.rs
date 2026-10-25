//! The inputs the behavior checks run a function on: argument registers
//! with small, boundary and hashed values, in the calling convention of the
//! image's code, and the state Go code expects on entry.

use super::CType;
use super::eval::{Convention, Setup, hash};
use crate::loader::{Format, Image, Isa};

pub const TRIALS: u64 = 12;
pub const STEP_LIMIT: usize = 20_000;
const INTERESTING: [u64; 10] = [
    0,
    1,
    2,
    7,
    u64::MAX,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x8000_0000_0000_0000,
    0x7fff_ffff_ffff_ffff,
];

/// Go keeps the current goroutine in r14, and every function first compares
/// the stack pointer with the goroutine's stack guard; a zero guard always passes.
const GO_G: u64 = 0x5000_0000;
const GO_STACK_GUARD: u64 = 0x10;
const R14: u16 = 14;

pub fn initial_memory(image: &Image) -> Vec<(u64, u64)> {
    if image.go {
        vec![(GO_G + GO_STACK_GUARD, 0)]
    } else {
        Vec::new()
    }
}

/// The calling convention of the image's code.
pub fn convention(image: &Image) -> Convention<'static> {
    match image.isa {
        Isa::Arm32 => Convention {
            arguments: &[0, 1, 2, 3],
            clobbered: &[0, 1, 2, 3, 12, 14],
        },
        Isa::AArch64 => Convention {
            arguments: &[0, 1, 2, 3, 4, 5, 6, 7],
            clobbered: &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            ],
        },
        // Go's internal ABI: everything but rsp, rbp, r14 (the goroutine) and r15.
        Isa::X86_64 if image.go => Convention {
            arguments: &[0, 3, 1, 7, 6, 8, 9, 10, 11],
            clobbered: &[0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13],
        },
        Isa::X86_64 if matches!(image.format, Format::Pe | Format::Coff) => Convention {
            arguments: &[1, 2, 8, 9],
            clobbered: &[0, 1, 2, 8, 9, 10, 11],
        },
        Isa::X86_64 => Convention {
            arguments: &[7, 6, 2, 1, 8, 9],
            clobbered: &[0, 1, 2, 6, 7, 8, 9, 10, 11],
        },
        Isa::I386 => Convention {
            arguments: &[],
            clobbered: &[0, 1, 2],
        },
        Isa::Unsupported => Convention {
            arguments: &[],
            clobbered: &[],
        },
    }
}

pub fn setup<'a>(
    image: &Image,
    trial: u64,
    registers: &'a [(u16, u64)],
    memory: &'a [(u64, u64)],
) -> Setup<'a> {
    Setup {
        seed: trial,
        convention: convention(image),
        registers,
        memory,
        step_limit: STEP_LIMIT,
    }
}

/// Argument registers for one trial. A third of the trials use small values,
/// so loops over a count finish; the rest use boundary values or hashed ones.
pub fn registers(image: &Image, trial: u64) -> Vec<(u16, u64)> {
    convention(image)
        .arguments
        .iter()
        .enumerate()
        .map(|(position, register)| {
            let pick = hash(trial, position as u64);
            let value = match trial % 3 {
                0 => pick % 16,
                1 => INTERESTING[pick as usize % INTERESTING.len()],
                _ => pick,
            };
            (*register, value)
        })
        .chain(entry_state(image))
        .collect()
}

/// The registers Go code expects set on entry: r14 holds the goroutine,
/// and on x86-64 xmm15 is zero.
pub fn entry_state(image: &Image) -> Vec<(u16, u64)> {
    let goroutine = image.go.then_some((R14, GO_G));
    let zero = (image.go && image.isa == Isa::X86_64)
        .then_some([
            (crate::arch::x86::XMM0 + 30, 0),
            (crate::arch::x86::XMM0 + 31, 0),
        ])
        .into_iter()
        .flatten();
    goroutine.into_iter().chain(zero).collect()
}

#[must_use]
pub fn return_bits(ret: &CType) -> Option<u32> {
    match ret {
        CType::Void => None,
        CType::Int { bytes, .. } => Some(u32::from(*bytes) * 8),
        CType::Named(_) => Some(ret.integer().map_or(64, |(bits, _)| bits)),
        CType::Pointer(_) | CType::Array(_) => Some(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_return_widths_include_fixed_width_integer_types() {
        for (name, bits) in [
            ("int32_t", 32),
            ("uint32_t", 32),
            ("int16_t", 16),
            ("int64_t", 64),
            ("long", 64),
            ("unsigned short", 16),
        ] {
            assert_eq!(return_bits(&CType::Named(name.into())), Some(bits));
        }
    }
}
