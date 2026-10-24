//! The stubs of the procedure linkage table, named after the imported
//! function each one jumps to through its slot in the global offset table.

mod pe;

use std::collections::HashMap;

use object::read::{File as ObjFile, Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use object::{RelocationTarget, SymbolIndex};

/// Whether a section holds linkage stubs, whose code no prologue scan
/// should split.
pub(super) fn is_stub_section(name: &str) -> bool {
    matches!(name, ".plt" | ".plt.sec" | ".plt.got" | "__stubs")
}

/// The slots dynamic relocations, or Mach-O's indirect symbol table, fill
/// with the address of a symbol another module defines, by the symbol's
/// name.
pub(super) fn imports(file: &ObjFile) -> HashMap<u64, String> {
    if let ObjFile::Pe64(pe) = file {
        return self::pe::imports(pe);
    }
    let (Some(relocations), Some(symbols)) =
        (file.dynamic_relocations(), file.dynamic_symbol_table())
    else {
        return macho_entries(file, false).into_iter().collect();
    };
    relocations
        .filter_map(|(slot, relocation)| {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                return None;
            };
            let symbol = symbols.symbol_by_index(index).ok()?;
            let name = symbol.name().ok()?;
            (!name.is_empty() && symbol.is_undefined()).then(|| (slot, name.to_owned()))
        })
        .collect()
}

/// `(stub address, imported name)` for every stub that jumps through a slot
/// a dynamic relocation names, or that Mach-O's indirect symbol table names.
pub(super) fn stubs(file: &ObjFile) -> Vec<(u64, String)> {
    if let ObjFile::Pe64(pe) = file {
        return self::pe::stubs(pe);
    }
    let (Some(relocations), Some(symbols)) =
        (file.dynamic_relocations(), file.dynamic_symbol_table())
    else {
        return macho_entries(file, true);
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

/// `(address, imported name)` for each entry of a Mach-O image's sections
/// that the indirect symbol table names: the stubs when `stubs`, else the
/// slots the dynamic linker fills.
fn macho_entries(file: &ObjFile, stubs: bool) -> Vec<(u64, String)> {
    use object::read::macho::Section as _;
    let ObjFile::MachO64(macho) = file else {
        return Vec::new();
    };
    let endian = macho.endian();
    let Ok(mut commands) = macho.macho_load_commands() else {
        return Vec::new();
    };
    let mut table = None;
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(dysymtab)) = command.dysymtab() {
            table = dysymtab.indirect_symbols(endian, macho.data()).ok();
            break;
        }
    }
    let Some(table) = table else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for section in macho.sections() {
        let header = section.macho_section();
        if (header.section_type(endian) == object::macho::S_SYMBOL_STUBS) != stubs {
            continue;
        }
        let Ok(indices) = header.indirect_symbols(endian, table) else {
            continue;
        };
        let stride = if stubs {
            u64::from(header.symbol_stub_size(endian))
        } else {
            8
        };
        for (position, entry) in indices.iter().enumerate() {
            // A slot the linker bound to a local definition names no import.
            let Some(index) = entry.get(endian).index() else {
                continue;
            };
            let Ok(symbol) = file.symbol_by_index(SymbolIndex(index as usize)) else {
                continue;
            };
            let Ok(name) = symbol.name() else {
                continue;
            };
            if name.is_empty() || !symbol.is_undefined() {
                continue;
            }
            let Some(address) = (position as u64)
                .checked_mul(stride)
                .and_then(|offset| header.addr(endian).checked_add(offset))
            else {
                continue;
            };
            entries.push((address, name.to_owned()));
        }
    }
    entries
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
