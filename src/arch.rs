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
    pub fn upper(slot: u16) -> u16 {
        YMM_UPPER + (slot - XMM0)
    }
}

pub mod aarch64 {
    pub const SP: u16 = 31;
    /// The low 64 bits of v0; each vector register is a pair of slots, low
    /// half first.
    pub const V0: u16 = 32;
}

/// The registers of either architecture, as the IR numbers them: general
/// ones, x86's segment bases and xmm halves, AArch64's vector halves.
pub fn machine_registers() -> std::ops::Range<u16> {
    0..aarch64::V0 + 64
}

/// Whether `index` is half of a vector register: Some(true) for a high
/// half, Some(false) for a low one, which also holds a scalar float.
pub fn vector_half(isa: Isa, index: u16) -> Option<bool> {
    let base = match isa {
        Isa::X86_64 => x86::XMM0,
        Isa::AArch64 => aarch64::V0,
        Isa::Unsupported => return None,
    };
    (base..base + 64)
        .contains(&index)
        .then(|| (index - base) % 2 == 1)
}

pub fn frame_pointer(isa: Isa) -> u16 {
    match isa {
        Isa::AArch64 => 29,
        Isa::X86_64 | Isa::Unsupported => 5,
    }
}

pub fn stack_pointer(isa: Isa) -> u16 {
    match isa {
        Isa::AArch64 => aarch64::SP,
        Isa::X86_64 | Isa::Unsupported => x86::RSP,
    }
}
