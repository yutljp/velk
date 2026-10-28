use crate::loader::Isa;

pub const RETURN: u16 = 0;

pub mod x86 {
    pub const RAX: u16 = 0;
    pub const RDX: u16 = 2;
    pub const RSP: u16 = 4;
    /// The segment bases thread-local storage is addressed through.
    pub const FS_BASE: u16 = 16;
    pub const GS_BASE: u16 = 17;
    /// The low 64 bits of xmm0; each xmm register is a pair of slots, low
    /// half first.
    pub const XMM0: u16 = 18;
    /// Bits 128 to 191 of ymm0, then 192 to 255; each ymm register's upper
    /// half is a pair of slots in the same order as the xmm ones.
    pub const YMM_UPPER: u16 = 50;

    /// The slot that holds the bits 128 above those of an xmm slot.
    #[must_use]
    pub fn upper(slot: u16) -> u16 {
        YMM_UPPER + (slot - XMM0)
    }
}

pub mod aarch64 {
    /// The EL0 software thread identifier, used as the thread-local base.
    pub const TPIDR_EL0: u16 = 96;
    /// x30, where a call leaves the address it returns to.
    pub const LR: u16 = 30;
    pub const SP: u16 = 31;
    /// The low 64 bits of v0; each vector register is a pair of slots, low
    /// half first.
    pub const V0: u16 = 32;
}

pub mod arm32 {
    /// D0; each pair of D registers also forms one Q register.
    pub const D0: u16 = 64;
}

/// The supported architectures' register slots: general registers, segment
/// bases, and vector halves.
#[must_use]
pub fn machine_registers() -> std::ops::Range<u16> {
    0..aarch64::V0 + 64
}

/// Whether `index` is half of a vector register: Some(true) for a high
/// half, Some(false) for a low one, which also holds a scalar float.
#[must_use]
pub fn vector_half(isa: Isa, index: u16) -> Option<bool> {
    let (base, length) = match isa {
        Isa::I386 | Isa::X86_64 => (x86::XMM0, 64),
        Isa::AArch64 => (aarch64::V0, 64),
        Isa::Arm32 => (arm32::D0, 32),
        Isa::Unsupported => return None,
    };
    (base..base + length)
        .contains(&index)
        .then(|| (index - base) % 2 == 1)
}

#[must_use]
pub fn frame_pointer(isa: Isa) -> u16 {
    match isa {
        Isa::AArch64 => 29,
        Isa::Arm32 => 11,
        Isa::I386 | Isa::X86_64 | Isa::Unsupported => 5,
    }
}

#[must_use]
pub fn stack_pointer(isa: Isa) -> u16 {
    match isa {
        Isa::AArch64 => aarch64::SP,
        Isa::Arm32 => 13,
        Isa::I386 | Isa::X86_64 | Isa::Unsupported => x86::RSP,
    }
}

pub(crate) fn code_address(isa: Isa, address: u64) -> u64 {
    if isa == Isa::Arm32 {
        address & !1
    } else {
        address
    }
}

/// The size of a pointer and an integer stack slot, in bytes.
#[must_use]
pub fn pointer_bytes(isa: Isa) -> u8 {
    match isa {
        Isa::I386 | Isa::Arm32 => 4,
        Isa::X86_64 | Isa::AArch64 | Isa::Unsupported => 8,
    }
}
