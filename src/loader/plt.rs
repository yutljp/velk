//! The stubs of the procedure linkage table, named after the imported
//! function each one jumps to through its slot in the global offset table.

use std::collections::HashMap;

use object::RelocationTarget;
use object::read::{File as ObjFile, Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};

/// Whether a section holds linkage stubs, whose code no prologue scan
/// should split.
pub(super) fn is_stub_section(name: &str) -> bool {
    matches!(name, ".plt" | ".plt.sec" | ".plt.got" | "__stubs")
}

/// `(stub address, imported name)` for every stub that jumps through a slot
/// a dynamic relocation names.
pub(super) fn stubs(file: &ObjFile) -> Vec<(u64, String)> {
    let (Some(relocations), Some(symbols)) =
        (file.dynamic_relocations(), file.dynamic_symbol_table())
    else {
        return Vec::new();
    };
    let slots: HashMap<u64, String> = relocations
        .filter_map(|(slot, relocation)| {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                return None;
            };
            let name = symbols.symbol_by_index(index).ok()?.name().ok()?;
            (!name.is_empty()).then(|| (slot, name.to_owned()))
        })
        .collect();
    let mut stubs = Vec::new();
    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if !is_stub_section(name) {
            continue;
        }
        let Ok(bytes) = section.data() else {
            continue;
        };
        // `.plt.got` holds 8-byte stubs; the others 16-byte ones.
        let stride = if name == ".plt.got" { 8 } else { 16 };
        let found = match file.architecture() {
            object::Architecture::X86_64 => x86_slots(bytes, section.address()),
            object::Architecture::Aarch64 => aarch64_slots(bytes, section.address()),
            _ => Vec::new(),
        };
        for (at, slot) in found {
            if let Some(import) = slots.get(&slot) {
                stubs.push((at - (at - section.address()) % stride, import.clone()));
            }
        }
    }
    stubs.sort();
    stubs.dedup_by_key(|(address, _)| *address);
    stubs
}

/// `(instruction address, slot)` for each `jmp [rip + displacement]`.
fn x86_slots(bytes: &[u8], base: u64) -> Vec<(u64, u64)> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut slots = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Jmp
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_base() == Register::RIP
        {
            slots.push((instruction.ip(), instruction.ip_rel_memory_address()));
        }
    }
    slots
}

/// `(adrp address, slot)` for each `adrp x16, page; ldr x17, [x16, #offset]`.
fn aarch64_slots(bytes: &[u8], base: u64) -> Vec<(u64, u64)> {
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect();
    let mut slots = Vec::new();
    for (index, pair) in words.windows(2).enumerate() {
        let (adrp, ldr) = (pair[0], pair[1]);
        // adrp x16, and ldr x17, [x16, #imm] scaled by 8.
        if adrp & 0x9f00_001f != 0x9000_0010 || ldr & 0xffc0_03ff != 0xf940_0211 {
            continue;
        }
        let pc = base + 4 * index as u64;
        let immediate = (((adrp >> 5) & 0x7_ffff) << 2 | (adrp >> 29) & 0x3) as i64;
        let pages = (immediate << 43) >> 43;
        let page = (pc & !0xfff).wrapping_add((pages << 12) as u64);
        let offset = u64::from((ldr >> 10) & 0xfff) * 8;
        slots.push((pc, page + offset));
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::{aarch64_slots, x86_slots};

    #[test]
    fn stubs_jump_through_their_slots() {
        // jmp [rip + 0x10] at 0x1000: the slot is 0x1016.
        assert_eq!(
            x86_slots(&[0xff, 0x25, 0x10, 0x00, 0x00, 0x00], 0x1000),
            vec![(0x1000, 0x1016)]
        );
        // adrp x16, +1 page; ldr x17, [x16, #0x18] at 0x2000: slot 0x3018.
        let code: Vec<u8> = [0xb000_0010u32, 0xf940_0e11]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(aarch64_slots(&code, 0x2000), vec![(0x2000, 0x3018)]);
    }
}
