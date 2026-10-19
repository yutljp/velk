use crate::loader::Isa;

pub const RETURN: u16 = 0;

pub mod x86 {
    pub const RAX: u16 = 0;
    pub const RDX: u16 = 2;
    pub const RSP: u16 = 4;
    /// The segment bases thread-local storage is addressed through.
    pub const FS_BASE: u16 = 16;
    pub const GS_BASE: u16 = 17;
}

pub mod aarch64 {
    pub const SP: u16 = 31;
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
