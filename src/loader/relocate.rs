//! Laying out and relocating the sections of a relocatable object as a linker
//! would, so that calls and data references reach real addresses.

use std::borrow::Cow;
use std::collections::HashMap;

use object::read::{File as ObjFile, Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use object::{RelocationFlags, RelocationKind, RelocationTarget, SectionIndex, SectionKind};

/// Base addresses for the sections of an ELF or COFF relocatable object,
/// whose sections all start at zero: the allocated sections follow one another
/// in file order, each at its alignment. Other files keep their addresses.
pub(super) fn layout(file: &ObjFile) -> HashMap<SectionIndex, u64> {
    let mut bases = HashMap::new();
    let relocatable = file.kind() == object::ObjectKind::Relocatable
        && matches!(
            file.format(),
            object::BinaryFormat::Elf | object::BinaryFormat::Coff
        );
    if !relocatable {
        return bases;
    }
    let mut cursor = 0u64;
    for section in file.sections() {
        if !allocated(&section) {
            continue;
        }
        // Sizes no address space holds leave the sections after unplaced.
        let align = section.align().max(1);
        let Some(base) = cursor.div_ceil(align).checked_mul(align) else {
            break;
        };
        let Some(end) = base.checked_add(section.size()) else {
            break;
        };
        bases.insert(section.index(), base);
        cursor = end;
    }
    bases
}

/// Whether the section occupies memory: an ELF section says so with its
/// flags, which also covers kinds such as unwind tables.
pub(super) fn allocated<'data>(section: &impl ObjectSection<'data>) -> bool {
    if let object::SectionFlags::Elf { sh_flags, .. } = section.flags() {
        return sh_flags.contains(object::elf::SHF_ALLOC);
    }
    matches!(
        section.kind(),
        SectionKind::Text
            | SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyDataWithRel
            | SectionKind::ReadOnlyString
            | SectionKind::UninitializedData
            | SectionKind::Tls
            | SectionKind::UninitializedTls
    )
}

/// The address of a symbol once its section is laid out at `bases`.
pub(super) fn symbol_address<'data>(
    symbol: &impl ObjectSymbol<'data>,
    bases: &HashMap<SectionIndex, u64>,
) -> u64 {
    let base = symbol
        .section_index()
        .and_then(|index| bases.get(&index))
        .copied()
        .unwrap_or(0);
    base.wrapping_add(symbol.address())
}

/// Applies the relocations of every laid-out section, and of the debug
/// information that names places in them, to `bytes`, the file's contents.
/// A relocation against an undefined symbol, or of a kind this does not
/// model, leaves its place as the object has it.
pub(super) fn apply(file: &ObjFile, bases: &HashMap<SectionIndex, u64>, bytes: &mut Cow<'_, [u8]>) {
    // Debug information is not loaded: it and the offsets into it start at
    // zero.
    let debug = |index: SectionIndex| {
        !bases.is_empty()
            && file
                .section_by_index(index)
                .and_then(|section| section.name())
                .is_ok_and(|name| name.starts_with(".debug"))
    };
    for section in file.sections() {
        let base = match bases.get(&section.index()) {
            Some(base) => *base,
            None if debug(section.index()) => 0,
            None => continue,
        };
        let Some((file_offset, _)) = section.file_range() else {
            continue;
        };
        for (offset, relocation) in section.relocations() {
            let target = match relocation.target() {
                RelocationTarget::Symbol(index) => match file.symbol_by_index(index) {
                    Ok(symbol) if !symbol.is_undefined() => symbol_address(&symbol, bases),
                    _ => continue,
                },
                RelocationTarget::Section(index) => match bases.get(&index) {
                    Some(base) => *base,
                    None if debug(index) => 0,
                    None => continue,
                },
                _ => continue,
            };
            let Some(place) = usize::try_from(file_offset.saturating_add(offset)).ok() else {
                continue;
            };
            let pc = base.wrapping_add(offset);
            patch(bytes.to_mut(), place, pc, target, &relocation);
        }
    }
}

/// Fills the pointers a dynamic loader would, at a load address of zero: a
/// relative relocation's addend, and the address of a symbol the image
/// defines itself. Pointers to symbols of other modules stay as they are.
pub(super) fn apply_dynamic(file: &ObjFile, bytes: &mut Cow<'_, [u8]>) {
    let Some(relocations) = file.dynamic_relocations() else {
        return;
    };
    // Dynamic relocations number the dynamic symbols, not the full table's.
    let Some(symbols) = file.dynamic_symbol_table() else {
        return;
    };
    let file_offset = |address: u64| {
        file.sections().find_map(|section| {
            let Some((offset, size)) = section.file_range() else {
                return None;
            };
            if address < section.address() || address - section.address() >= size {
                return None;
            }
            offset.checked_add(address - section.address())
        })
    };
    // The ELF types by machine: relative, then those holding a symbol's
    // address (absolute, GOT entry, PLT slot).
    let (relative, absolute): (u32, &[u32]) = match file.architecture() {
        object::Architecture::I386 => (8, &[1, 6, 7]),
        object::Architecture::X86_64 => (8, &[1, 6, 7]),
        object::Architecture::Aarch64 => (1027, &[257, 1025, 1026]),
        object::Architecture::Arm => (23, &[21]),
        _ => return,
    };
    let word = if file.is_64() { 8 } else { 4 };
    for (address, relocation) in relocations {
        let RelocationFlags::Elf { r_type } = relocation.flags() else {
            continue;
        };
        let r_type = r_type.0;
        let Some(place) = file_offset(address).and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        let implicit = if relocation.has_implicit_addend() {
            if word == 4 {
                read_u32(bytes, place).map(u64::from)
            } else {
                read_u64(bytes, place)
            }
        } else {
            Some(0)
        };
        let Some(implicit) = implicit else { continue };
        let addend = if file.architecture() == object::Architecture::I386 && matches!(r_type, 6 | 7)
        {
            0
        } else {
            (relocation.addend() as u64).wrapping_add(implicit)
        };
        let value = match relocation.target() {
            _ if r_type == relative => addend,
            _ if !absolute.contains(&r_type) => continue,
            RelocationTarget::Symbol(index) => match symbols.symbol_by_index(index) {
                Ok(symbol) if !symbol.is_undefined() && symbol.address() != 0 => {
                    symbol.address().wrapping_add(addend)
                }
                _ => continue,
            },
            _ => continue,
        };
        if word == 4 {
            if read_u32(bytes, place) != Some(value as u32) {
                write_u32(bytes.to_mut(), place, value as u32);
            }
        } else {
            if read_u64(bytes, place) != Some(value) {
                write_u64(bytes.to_mut(), place, value);
            }
        }
    }
}

fn patch(bytes: &mut [u8], place: usize, pc: u64, symbol: u64, relocation: &object::Relocation) {
    let implicit = if relocation.has_implicit_addend() {
        match relocation.size() {
            32 => read_u32(bytes, place).map(|value| i64::from(value as i32)),
            64 => read_u64(bytes, place).map(|value| value as i64),
            _ => None,
        }
        .unwrap_or(0)
    } else {
        0
    };
    let value = symbol.wrapping_add_signed(relocation.addend().wrapping_add(implicit));
    let relative = value.wrapping_sub(pc);
    if let RelocationFlags::Elf { r_type } = relocation.flags()
        && let Some(()) = patch_aarch64(bytes, place, pc, value, r_type)
    {
        return;
    }
    match (relocation.kind(), relocation.encoding(), relocation.size()) {
        (RelocationKind::Absolute, object::RelocationEncoding::Generic, 64) => {
            write_u64(bytes, place, value)
        }
        (
            RelocationKind::Absolute,
            object::RelocationEncoding::Generic | object::RelocationEncoding::X86Signed,
            32,
        ) => write_u32(bytes, place, value as u32),
        (
            RelocationKind::Relative | RelocationKind::PltRelative,
            object::RelocationEncoding::Generic | object::RelocationEncoding::X86Branch,
            32,
        ) => write_u32(bytes, place, relative as u32),
        (RelocationKind::Relative, object::RelocationEncoding::Generic, 64) => {
            write_u64(bytes, place, relative)
        }
        _ => {}
    }
}

/// The `AArch64` instruction relocations: page and low-12-bit address parts,
/// and branch displacements.
fn patch_aarch64(
    bytes: &mut [u8],
    place: usize,
    pc: u64,
    value: u64,
    r_type: object::elf::RelocationType,
) -> Option<()> {
    use object::elf;
    let Some(instruction) = read_u32(bytes, place) else {
        return None;
    };
    let low12 = (value & 0xfff) as u32;
    let patched = match r_type {
        elf::R_AARCH64_ADR_PREL_PG_HI21 | elf::R_AARCH64_ADR_PREL_PG_HI21_NC => {
            let pages = ((value & !0xfff).wrapping_sub(pc & !0xfff) as i64 >> 12) as u32;
            instruction & !((0x3 << 29) | (0x7ffff << 5))
                | ((pages & 0x3) << 29)
                | (((pages >> 2) & 0x7ffff) << 5)
        }
        elf::R_AARCH64_ADD_ABS_LO12_NC | elf::R_AARCH64_LDST8_ABS_LO12_NC => {
            instruction & !(0xfff << 10) | (low12 << 10)
        }
        elf::R_AARCH64_CALL26 | elf::R_AARCH64_JUMP26 => {
            let words = (value.wrapping_sub(pc) as i64 >> 2) as u32;
            instruction & !0x3ff_ffff | (words & 0x3ff_ffff)
        }
        _ => {
            let shifts = [
                (elf::R_AARCH64_LDST16_ABS_LO12_NC, 1),
                (elf::R_AARCH64_LDST32_ABS_LO12_NC, 2),
                (elf::R_AARCH64_LDST64_ABS_LO12_NC, 3),
                (elf::R_AARCH64_LDST128_ABS_LO12_NC, 4),
            ];
            let Some((_, shift)) = shifts.iter().find(|(kind, _)| *kind == r_type) else {
                return None;
            };
            instruction & !(0xfff << 10) | ((low12 >> shift) << 10)
        }
    };
    write_u32(bytes, place, patched);
    Some(())
}

fn read_u32(bytes: &[u8], place: usize) -> Option<u32> {
    let Some(end) = place.checked_add(4) else {
        return None;
    };
    let Some(field) = bytes.get(place..end) else {
        return None;
    };
    let Some(value) = field.try_into().ok() else {
        return None;
    };
    Some(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], place: usize) -> Option<u64> {
    let Some(end) = place.checked_add(8) else {
        return None;
    };
    let Some(field) = bytes.get(place..end) else {
        return None;
    };
    let Some(value) = field.try_into().ok() else {
        return None;
    };
    Some(u64::from_le_bytes(value))
}

fn write_u32(bytes: &mut [u8], place: usize, value: u32) {
    if let Some(field) = place
        .checked_add(4)
        .and_then(|end| bytes.get_mut(place..end))
    {
        field.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64(bytes: &mut [u8], place: usize, value: u64) {
    if let Some(field) = place
        .checked_add(8)
        .and_then(|end| bytes.get_mut(place..end))
    {
        field.copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::patch_aarch64;
    use object::elf;

    fn patched(instruction: u32, pc: u64, value: u64, r_type: elf::RelocationType) -> u32 {
        let mut bytes = instruction.to_le_bytes().to_vec();
        patch_aarch64(&mut bytes, 0, pc, value, r_type).expect("a modeled relocation");
        u32::from_le_bytes(bytes.try_into().expect("four bytes"))
    }

    #[test]
    fn page_and_offset_relocations_address_the_target() {
        // adrp x8, 0 -> adrp x8, page 1; add x8, x8, #0 -> add x8, x8, #0x28.
        assert_eq!(
            patched(0x9000_0008, 0x10, 0x1028, elf::R_AARCH64_ADR_PREL_PG_HI21),
            0xb000_0008
        );
        assert_eq!(
            patched(0x9100_0108, 0x14, 0x1028, elf::R_AARCH64_ADD_ABS_LO12_NC),
            0x9100_a108
        );
        for (kind, expected) in [
            (elf::R_AARCH64_LDST8_ABS_LO12_NC, 0xffc00),
            (elf::R_AARCH64_LDST16_ABS_LO12_NC, 0x7fc00),
            (elf::R_AARCH64_LDST32_ABS_LO12_NC, 0x3fc00),
            (elf::R_AARCH64_LDST64_ABS_LO12_NC, 0x1fc00),
            (elf::R_AARCH64_LDST128_ABS_LO12_NC, 0xfc00),
        ] {
            assert_eq!(
                patched(0x8000_0001, 0, 0x13ff, kind),
                0x8000_0001 | expected
            );
        }
        // ldr x8, [x8] scales the offset by its 8-byte access.
        assert_eq!(
            patched(0xf940_0108, 0x14, 0x1028, elf::R_AARCH64_LDST64_ABS_LO12_NC),
            0xf940_1508
        );
    }

    #[test]
    fn a_call_relocation_encodes_the_displacement() {
        // bl 0 at 0x20 calling 0x8: two words back.
        assert_eq!(
            patched(0x9400_0000, 0x20, 0x8, elf::R_AARCH64_CALL26),
            0x97ff_fffa
        );
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    #[kani::unwind(20)]
    fn relocation_words() {
        let mut bytes: [u8; 16] = kani::any();
        let original = bytes;
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let place: usize = kani::any();
        let value: u64 = kani::any();
        super::write_u64(&mut bytes[..len], place, value);
        if place <= len && len - place >= 8 {
            assert_eq!(super::read_u64(&bytes[..len], place), Some(value));
            for index in 0..bytes.len() {
                if index < place || index >= place + 8 {
                    assert_eq!(bytes[index], original[index]);
                }
            }
        } else {
            assert_eq!(super::read_u64(&bytes[..len], place), None);
            assert_eq!(bytes, original);
        }
        let value: u32 = kani::any();
        let original = bytes;
        super::write_u32(&mut bytes[..len], place, value);
        if place <= len && len - place >= 4 {
            assert_eq!(super::read_u32(&bytes[..len], place), Some(value));
            for index in 0..bytes.len() {
                if index < place || index >= place + 4 {
                    assert_eq!(bytes[index], original[index]);
                }
            }
        } else {
            assert_eq!(super::read_u32(&bytes[..len], place), None);
            assert_eq!(bytes, original);
        }
        kani::cover!(
            len == 16 && place == 12,
            "the last complete 32-bit word is written"
        );
        kani::cover!(
            place == usize::MAX,
            "an overflowing write offset is rejected"
        );
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn aarch64_relocation() {
        let instruction: u32 = kani::any();
        let pc: u64 = kani::any();
        let value: u64 = kani::any();
        let kind: u32 = kani::any();
        let mut bytes = instruction.to_le_bytes();
        let _ = super::patch_aarch64(&mut bytes, 0, pc, value, object::elf::RelocationType(kind));
        if kind == object::elf::R_AARCH64_CALL26.0 {
            let patched = u32::from_le_bytes(bytes);
            assert_eq!(patched & !0x03ff_ffff, instruction & !0x03ff_ffff);
            assert_eq!(
                patched & 0x03ff_ffff,
                (value.wrapping_sub(pc) >> 2) as u32 & 0x03ff_ffff
            );
            kani::cover!(value < pc, "a backward call is encoded");
            kani::cover!(
                value.wrapping_sub(pc) & 3 != 0,
                "an unaligned call target is checked"
            );
        }
    }
}
