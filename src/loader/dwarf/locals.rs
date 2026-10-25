//! Fixed stack locations of source variables.

use super::{attribute, attribute_string, plausible_type, resolve_low, type_name, type_size};
use crate::ir::DebugLocal;
use crate::loader::{Image, Isa};
use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, Operation, Register, Unit};

type Reader<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Location {
    Cfa,
    ValueRegister(Register),
    Frame(i64),
    Register(Register, i64),
}

fn expression(
    expr: gimli::Expression<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    frame_base: bool,
) -> Option<Location> {
    let mut ops = expr.operations(unit.encoding());
    let Ok(Some(op)) = ops.next() else {
        return None;
    };
    let location = match op {
        Operation::Register { register } if frame_base => Location::Register(register, 0),
        Operation::Register { register } => Location::ValueRegister(register),
        Operation::CallFrameCFA => Location::Cfa,
        Operation::FrameOffset { offset } => Location::Frame(offset),
        Operation::RegisterOffset {
            register, offset, ..
        } => Location::Register(register, offset),
        _ => return None,
    };
    match ops.next() {
        Ok(None) => Some(location),
        _ => None,
    }
}

fn location(
    dwarf: &Dwarf<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    value: AttributeValue<Reader<'_>>,
    start: u64,
    end: u64,
    frame_base: bool,
) -> Option<Location> {
    if let AttributeValue::Exprloc(expr) = value {
        return expression(expr, unit, frame_base);
    }
    let Ok(Some(mut list)) = dwarf.attr_locations(unit, value) else {
        return None;
    };
    // A location that changes or leaves gaps cannot name storage for the whole function.
    let mut result = None;
    let mut covered = start;
    while let Ok(Some(entry)) = list.next() {
        if entry.range.end <= covered || entry.range.begin >= end {
            continue;
        }
        if entry.range.begin > covered {
            return None;
        }
        let Some(current) = expression(entry.data, unit, frame_base) else {
            return None;
        };
        if result.is_some_and(|previous| previous != current) {
            return None;
        }
        result = Some(current);
        covered = entry.range.end;
    }
    if covered >= end { result } else { None }
}

fn stack_offset(
    image: &Image,
    location: Location,
    start: u64,
    end: u64,
    frame_base: bool,
) -> Option<i64> {
    let (sp, entry_offset) = match image.isa {
        Isa::I386 => (Register(4), 4i64),
        Isa::X86_64 => (Register(7), 8i64),
        Isa::AArch64 => (Register(31), 0i64),
        Isa::Arm32 | Isa::Unsupported => return None,
    };
    if image.stack_at_entry(start) != Some(true) {
        return None;
    }
    match location {
        Location::Cfa => Some(entry_offset),
        Location::Frame(_) | Location::ValueRegister(_) => None,
        Location::Register(register, offset) => {
            let rows = image
                .stack_rows
                .get_or_init(|| crate::loader::unwind::stack_rows(image));
            let mut base = None;
            for row in rows.iter().filter(|row| row.start < end && row.end > start) {
                if row.cfa.0 != register || (frame_base && register == sp && row.at_entry) {
                    continue;
                }
                let Some(value) = entry_offset
                    .checked_sub(row.cfa.1)
                    .and_then(|base| base.checked_add(offset))
                else {
                    return None;
                };
                if base.is_some_and(|base| base != value) {
                    return None;
                }
                base = Some(value);
            }
            // A changing SP-relative location is deliberately rejected above.
            if register == sp && base.is_none() {
                return None;
            }
            base
        }
    }
}

pub(super) fn read<'a>(
    image: &Image,
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<Reader<'a>>,
    function: &gimli::DebuggingInformationEntry<Reader<'a>>,
    registers: &mut Vec<(u16, String)>,
) -> Vec<DebugLocal> {
    let Some(start) = resolve_low(dwarf, unit, function) else {
        return Vec::new();
    };
    let Ok(mut ranges) = dwarf.die_ranges(unit, function) else {
        return Vec::new();
    };
    let Ok(Some(range)) = ranges.next() else {
        return Vec::new();
    };
    if range.begin != start || range.end <= start {
        return Vec::new();
    }
    let end = range.end;
    let frame = attribute(function, gimli::DW_AT_frame_base)
        .and_then(|value| location(dwarf, unit, value, start, end, true))
        .and_then(|loc| stack_offset(image, loc, start, end, true));
    let Ok(mut entries) = unit.entries_at_offset(function.offset()) else {
        return Vec::new();
    };
    let mut locals = Vec::new();
    let mut nested = None;
    while let Ok(Some(entry)) = entries.next_dfs() {
        if entry.offset() == function.offset() {
            continue;
        }
        if entry.depth() <= 0 {
            break;
        }
        if nested.is_some_and(|depth| entry.depth() > depth) {
            continue;
        }
        nested = None;
        if matches!(
            entry.tag(),
            gimli::DW_TAG_inlined_subroutine | gimli::DW_TAG_subprogram
        ) {
            nested = Some(entry.depth());
            continue;
        }
        if !matches!(
            entry.tag(),
            gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter
        ) {
            continue;
        }
        let Some(name) = attribute(entry, gimli::DW_AT_name)
            .and_then(|value| attribute_string(dwarf, unit, value))
        else {
            continue;
        };
        let Some(AttributeValue::UnitRef(ty)) = attribute(entry, gimli::DW_AT_type) else {
            continue;
        };
        let Some(size) = type_size(unit, ty, 16).filter(|size| *size > 0) else {
            continue;
        };
        let Some(ty) = type_name(dwarf, unit, ty, 16).filter(plausible_type) else {
            continue;
        };
        let Some(loc) = attribute(entry, gimli::DW_AT_location)
            .and_then(|value| location(dwarf, unit, value, start, end, false))
        else {
            continue;
        };
        if let Location::ValueRegister(reg) = loc {
            let register = match image.isa {
                Isa::I386 if reg.0 < 8 => Some(reg.0),
                Isa::X86_64 => [0, 2, 1, 3, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15]
                    .get(usize::from(reg.0))
                    .copied(),
                Isa::AArch64 if reg.0 < 31 => Some(reg.0),
                _ => None,
            };
            if let Some(register) = register {
                registers.push((register, name));
            }
            continue;
        }
        let slot = match loc {
            Location::Frame(offset) => frame.and_then(|frame| frame.checked_add(offset)),
            other => stack_offset(image, other, start, end, false),
        };
        let Some(slot) = slot else { continue };
        if i64::try_from(size)
            .ok()
            .and_then(|size| slot.checked_add(size))
            .is_none()
        {
            continue;
        }
        locals.push(DebugLocal {
            name,
            ty,
            slot,
            size,
        });
    }
    locals
}
