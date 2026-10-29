//! Deterministic thread-local state for bounded execution, without a runtime loader.

use crate::emulation::{Memory, Word};
use crate::loader::{Format, Image, Isa};

pub(crate) fn register(image: &Image) -> Option<u16> {
    if image.format == Format::Pe {
        match image.isa {
            Isa::X86_64 => return Some(crate::arch::x86::GS_BASE),
            Isa::I386 => return Some(crate::arch::x86::FS_BASE),
            _ => {}
        }
    }
    match image.isa {
        Isa::X86_64 => Some(crate::arch::x86::FS_BASE),
        Isa::I386 => Some(crate::arch::x86::GS_BASE),
        Isa::AArch64 => Some(crate::arch::aarch64::TPIDR_EL0),
        _ => None,
    }
}

pub(crate) fn initial(
    image: &Image,
    memory: &Memory<'_>,
    canary: Option<&Word>,
) -> Result<Vec<(u64, u8)>, String> {
    let value = match canary {
        Some(word) => match word.value() {
            Ok(value) => value,
            Err(error) => return Err(error.to_string()),
        },
        None => 0x6a09_e667_bb67_ae00,
    };
    let width = crate::arch::pointer_bytes(image.isa);
    let mut words = Vec::new();
    if image.format == Format::Pe && matches!(image.isa, Isa::X86_64 | Isa::I386) {
        let offset = if width == 8 { 0x30 } else { 0x18 };
        let mut bytes = Vec::new();
        for index in 0..width {
            bytes.push((
                memory.tls_base + offset + u64::from(index),
                (memory.tls_base >> (index * 8)) as u8,
            ));
        }
        return Ok(bytes);
    }
    match image.isa {
        Isa::X86_64 => {
            words.push((memory.tls_base, memory.tls_base));
            words.push((memory.tls_base + 0x10, memory.tls_base));
            words.push((memory.tls_base + 0x28, value));
        }
        Isa::I386 => {
            words.push((memory.tls_base, memory.tls_base));
            words.push((memory.tls_base + 8, memory.tls_base));
            words.push((memory.tls_base + 0x14, value));
        }
        // AArch64 glibc uses the global guard. Sysreg builds using TP + 0x28
        // are also supported; other offsets can be initialized explicitly.
        Isa::AArch64 => words.push((memory.tls_base + 0x28, value)),
        _ => {}
    }
    for (&address, name) in &image.data_symbols {
        let name = name.split('@').next().unwrap_or(name);
        if name == "__stack_chk_guard"
            || (image.format == Format::MachO && name == "___stack_chk_guard")
        {
            if !memory.check(address, u64::from(width), /* write */ false) {
                return Err(format!("invalid stack guard at 0x{address:x}"));
            }
            words.push((address, value));
        }
    }
    let mut bytes = Vec::new();
    for (address, value) in words {
        for offset in 0..width {
            bytes.push((address + u64::from(offset), (value >> (offset * 8)) as u8));
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defined_guards_use_pointer_width_and_object_symbol_names() {
        for isa in [Isa::X86_64, Isa::I386, Isa::AArch64] {
            for (format, name) in [
                (Format::Elf, "__stack_chk_guard@GLIBC_2.4"),
                (Format::MachO, "___stack_chk_guard"),
            ] {
                let mut image = Image::from_code(isa, 0x1000, vec![0; 8]);
                image.format = format;
                image.data_symbols.insert(0x1000, name.to_owned());
                let memory = Memory::new(&image).expect("mapped guard");
                let bytes = initial(
                    &image,
                    &memory,
                    Some(&Word::Text("0xfedcba9876543200".to_owned())),
                )
                .expect("initialized guard");
                let actual: Vec<u8> = bytes
                    .iter()
                    .filter(|(address, _)| (0x1000..0x1008).contains(address))
                    .map(|(_, byte)| *byte)
                    .collect();
                let expected = 0xfedcba9876543200u64.to_le_bytes();
                assert_eq!(
                    actual,
                    expected[..usize::from(crate::arch::pointer_bytes(isa))]
                );
            }
        }
    }
}
