use crate::loader::Isa;

/// A set of machine registers, one bit for each index below 128.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Registers(pub u128);

impl Registers {
    pub fn insert(&mut self, index: u16) {
        if index < 128 {
            self.0 |= 1 << index;
        }
    }

    pub fn contains(self, index: u16) -> bool {
        index < 128 && self.0 & 1 << index != 0
    }

    pub fn iter(self) -> impl Iterator<Item = u16> {
        (0..128).filter(move |index| self.contains(*index))
    }
}

impl FromIterator<u16> for Registers {
    fn from_iter<I: IntoIterator<Item = u16>>(iter: I) -> Self {
        let mut set = Registers::default();
        for index in iter {
            set.insert(index);
        }
        set
    }
}

const X86_NAMES64: [&str; 82] = [
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "fs_base",
    "gs_base",
    "xmm0",
    "xmm0_hi",
    "xmm1",
    "xmm1_hi",
    "xmm2",
    "xmm2_hi",
    "xmm3",
    "xmm3_hi",
    "xmm4",
    "xmm4_hi",
    "xmm5",
    "xmm5_hi",
    "xmm6",
    "xmm6_hi",
    "xmm7",
    "xmm7_hi",
    "xmm8",
    "xmm8_hi",
    "xmm9",
    "xmm9_hi",
    "xmm10",
    "xmm10_hi",
    "xmm11",
    "xmm11_hi",
    "xmm12",
    "xmm12_hi",
    "xmm13",
    "xmm13_hi",
    "xmm14",
    "xmm14_hi",
    "xmm15",
    "xmm15_hi",
    "ymm0_128",
    "ymm0_192",
    "ymm1_128",
    "ymm1_192",
    "ymm2_128",
    "ymm2_192",
    "ymm3_128",
    "ymm3_192",
    "ymm4_128",
    "ymm4_192",
    "ymm5_128",
    "ymm5_192",
    "ymm6_128",
    "ymm6_192",
    "ymm7_128",
    "ymm7_192",
    "ymm8_128",
    "ymm8_192",
    "ymm9_128",
    "ymm9_192",
    "ymm10_128",
    "ymm10_192",
    "ymm11_128",
    "ymm11_192",
    "ymm12_128",
    "ymm12_192",
    "ymm13_128",
    "ymm13_192",
    "ymm14_128",
    "ymm14_192",
    "ymm15_128",
    "ymm15_192",
];

/// Register indices from here up are per-function CSE temporaries, printed as
/// `t<n>`.
pub const TEMP_BASE: u16 = 0x1000;

/// The registers holding the operands the flags were set from, and those of
/// the condition that chose a conditional compare, after the instruction that
/// sets the flags, or a later one, overwrites what they read.
pub const FLAG_OPERANDS: [u16; 4] = [
    TEMP_BASE + 0x40,
    TEMP_BASE + 0x41,
    TEMP_BASE + 0x43,
    TEMP_BASE + 0x44,
];

/// The registers that carry the operands the flags were set from into a
/// block that reads them, from the end of each block before it.
pub const FLAG_CARRIED: [u16; 4] = [
    TEMP_BASE + 0x45,
    TEMP_BASE + 0x46,
    TEMP_BASE + 0x47,
    TEMP_BASE + 0x48,
];

/// The register holding a value an exchange overwrites before it is written
/// back.
pub const EXCHANGE: u16 = TEMP_BASE + 0x42;

/// The register holding a jump table's index where the code computing the
/// target overwrites the register it came in.
pub const SWITCH_INDEX: u16 = TEMP_BASE + 0x49;

/// What a landing pad receives: the exception being thrown, and the value
/// that chooses among its handlers.
pub const EXCEPTION: u16 = TEMP_BASE + 0x4a;
pub const SELECTOR: u16 = TEMP_BASE + 0x4b;

/// Register indices from here up are the variables a parameter register
/// holds once its parameter is dead, printed as `v<n>`.
pub const VARIABLE_BASE: u16 = TEMP_BASE + 0x100;

/// Register indices from here up are SSA values, printed as `s<n>`.
pub const VALUE_BASE: u16 = 0x2000;

pub fn is_temp(index: u16) -> bool {
    index >= TEMP_BASE
}

pub fn temp_id(index: u16) -> u64 {
    u64::from(index - TEMP_BASE) + 1
}

pub fn reg_name(isa: Isa, index: u16, width: u8) -> String {
    let _ = (isa, width);
    if index >= VALUE_BASE {
        return format!("s{}", index - VALUE_BASE);
    }
    if index >= VARIABLE_BASE {
        return format!("v{}", index - VARIABLE_BASE + 1);
    }
    match index {
        EXCEPTION => return "exception".to_owned(),
        SELECTOR => return "selector".to_owned(),
        _ => {}
    }
    if is_temp(index) {
        return format!("t{isode}", isode = temp_id(index));
    }
    match isa {
        Isa::AArch64 if index >= crate::arch::aarch64::V0 => {
            let number = (index - crate::arch::aarch64::V0) / 2;
            match ((index - crate::arch::aarch64::V0) % 2, width) {
                (1, _) => format!("v{number}_hi"),
                (_, 32) => format!("s{number}"),
                _ => format!("d{number}"),
            }
        }
        Isa::AArch64 => {
            if index == 31 && width == 64 {
                "sp".to_owned()
            } else if width == 32 {
                format!("w{index}")
            } else {
                format!("x{index}")
            }
        }
        Isa::X86_64 => {
            let index = index as usize;
            let base = X86_NAMES64.get(index).copied().unwrap_or("reg");
            if width == 32 {
                match index {
                    0..=7 => format!("e{}", &base[1..]),
                    8..=15 => format!("{base}d"),
                    // The segment bases and xmm halves have no 32-bit names.
                    _ => format!("(uint32_t){base}"),
                }
            } else {
                base.to_owned()
            }
        }
        Isa::Unsupported => format!("reg{index}"),
    }
}
