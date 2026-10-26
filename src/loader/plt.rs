//! The stubs of the procedure linkage table, named after the imported
//! function each one jumps to through its slot in the global offset table.

mod pe;

use std::collections::{BTreeMap, HashMap};

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
    if let ObjFile::Pe32(pe) = file {
        return self::pe::imports(pe);
    }
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

pub(super) fn qualified_imports(file: &ObjFile) -> HashMap<u64, String> {
    match file {
        ObjFile::Pe32(pe) => self::pe::qualified_imports(pe),
        ObjFile::Pe64(pe) => self::pe::qualified_imports(pe),
        _ => HashMap::new(),
    }
}

/// `(stub address, imported name)` for every stub that jumps through a slot
/// a dynamic relocation names, or that Mach-O's indirect symbol table names.
pub(super) fn stubs(file: &ObjFile) -> Vec<(u64, String)> {
    if let ObjFile::Pe32(pe) = file {
        return self::pe::stubs(pe);
    }
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
    let got = file
        .symbols()
        .find(|symbol| symbol.name() == Ok("_GLOBAL_OFFSET_TABLE_"))
        .map(|symbol| symbol.address())
        .or_else(|| {
            file.section_by_name(".got.plt")
                .map(|section| section.address())
        });
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
            object::Architecture::I386 => x86_slots_mode(bytes, section.address(), 32, got),
            object::Architecture::X86_64 => x86_slots(bytes, section.address()),
            object::Architecture::Aarch64 => aarch64_slots(bytes, section.address()),
            object::Architecture::Arm if file.is_little_endian() => {
                for (at, slot) in arm_slots(bytes, section.address()) {
                    if let Some(import) = slots.get(&slot) {
                        stubs.push((at, import.clone()));
                    }
                }
                continue;
            }
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

fn arm_slots(bytes: &[u8], base: u64) -> Vec<(u64, u64)> {
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect();
    let mut slots = Vec::new();
    for (index, instructions) in words.windows(3).enumerate() {
        let [first, second, third] = instructions else {
            continue;
        };
        let Some(pc) = (index as u64)
            .checked_mul(4)
            .and_then(|offset| base.checked_add(offset))
            .filter(|pc| *pc <= u64::from(u32::MAX) - 8)
        else {
            continue;
        };
        let Some(slot) = super::arm_linkage::slot([*first, *second, *third], pc as u32) else {
            continue;
        };
        slots.push((pc, u64::from(slot)));
    }
    slots
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
    x86_slots_mode(bytes, base, 64, None)
}

fn x86_slots_mode(bytes: &[u8], base: u64, bitness: u32, got: Option<u64>) -> Vec<(u64, u64)> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    let mut decoder = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut slots = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Jmp
            && instruction.op0_kind() == OpKind::Memory
            && (instruction.memory_base() == Register::RIP
                || (bitness == 32
                    && instruction.memory_base() == Register::None
                    && instruction.memory_index() == Register::None)
                || (bitness == 32
                    && got.is_some()
                    && instruction.memory_base() == Register::EBX
                    && instruction.memory_index() == Register::None))
        {
            slots.push((
                instruction.ip(),
                if bitness == 32 && instruction.memory_base() == Register::EBX {
                    got.unwrap_or(0)
                        .wrapping_add_signed(i64::from(instruction.memory_displacement32() as i32))
                        & 0xffff_ffff
                } else if bitness == 32 {
                    instruction.memory_displacement64()
                } else {
                    instruction.ip_rel_memory_address()
                },
            ));
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

pub(super) fn local_branches(file: &ObjFile) -> BTreeMap<u64, u64> {
    if file.architecture() != object::Architecture::I386 {
        return Default::default();
    }
    let definitions: HashMap<_, _> = file
        .dynamic_symbols()
        .filter_map(|symbol| {
            if symbol.is_undefined() {
                return None;
            }
            let Ok(name) = symbol.name() else { return None };
            Some((name.to_owned(), symbol.address()))
        })
        .collect();
    let targets: HashMap<_, _> = stubs(file)
        .into_iter()
        .filter_map(|(stub, name)| definitions.get(&name).copied().map(|target| (stub, target)))
        .collect();
    let mut branches: BTreeMap<_, _> = targets
        .iter()
        .map(|(stub, target)| (*stub, *target))
        .collect();
    for section in file
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
    {
        let Ok(bytes) = section.data() else { continue };
        let decoder = iced_x86::Decoder::with_ip(
            32,
            bytes,
            section.address(),
            iced_x86::DecoderOptions::NONE,
        );
        for ins in decoder {
            if matches!(
                ins.flow_control(),
                iced_x86::FlowControl::Call | iced_x86::FlowControl::UnconditionalBranch
            ) && ins.op0_kind() == iced_x86::OpKind::NearBranch32
                && let Some(target) = targets.get(&ins.near_branch_target())
            {
                branches.insert(ins.ip(), *target);
            }
        }
    }
    branches
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
        let words = [0xe28f_c600u32, 0xe28c_ca01, 0xe5bc_f024];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        for base in [0x1000, u64::from(u32::MAX) - 11] {
            let expected = (base as u32)
                .wrapping_add(8)
                .wrapping_add(0x1000)
                .wrapping_add(0x24);
            assert_eq!(
                super::arm_slots(&code, base),
                vec![(base, u64::from(expected))]
            );
            assert_eq!(super::arm_slots(&code[..11], base), Vec::new());
        }
        assert!(super::arm_slots(&code, u64::from(u32::MAX) - 7).is_empty());
        assert!(super::arm_slots(&code, u64::MAX).is_empty());
        for index in 0..3 {
            let mut invalid = words;
            invalid[index] ^= 1 << 16;
            let code: Vec<u8> = invalid.iter().flat_map(|word| word.to_le_bytes()).collect();
            assert!(super::arm_slots(&code, 0x1000).is_empty());
        }
    }
}
