use std::collections::HashMap;

use crate::ir::{CType, Definition, FunctionIr};

use super::{declaration, naming::Layout};

pub(super) fn add_debug(ir: &FunctionIr, arrays: &mut HashMap<String, Layout>) {
    for definition in &ir.definitions {
        let Some(name) = definition.name.strip_prefix("struct ") else {
            continue;
        };
        if ir
            .definitions
            .iter()
            .filter(|other| other.name == definition.name)
            .count()
            != 1
            || ir.structures.iter().any(|other| other.name == name)
            || !usable(ir, definition, name)
        {
            arrays.remove(name);
            continue;
        }
        arrays.insert(
            name.to_owned(),
            Layout {
                size: definition.size,
            },
        );
    }
}

fn usable(ir: &FunctionIr, definition: &Definition, name: &str) -> bool {
    let Some(alignment) = definition.alignment else {
        return false;
    };
    if definition.size == 0
        || definition.size > i64::MAX as u64
        || !alignment.is_power_of_two()
        || !definition.size.is_multiple_of(alignment)
        || definition.compatible_profiles.is_empty()
    {
        return false;
    }
    let fields: Vec<_> = ir
        .members
        .iter()
        .filter(|field| field.structure == name)
        .collect();
    let mut end = 0u64;
    let mut named = 0;
    for text in &definition.members {
        if let Some(gap) = text.strip_prefix("uint8_t gap_0x") {
            let Some((offset, width)) = gap.split_once("[0x") else {
                return false;
            };
            let (Ok(offset), Some(width)) =
                (u64::from_str_radix(offset, 16), width.strip_suffix("];"))
            else {
                return false;
            };
            let Ok(width) = u64::from_str_radix(width, 16) else {
                return false;
            };
            if offset != end || width == 0 {
                return false;
            }
            let Some(next) = end.checked_add(width) else {
                return false;
            };
            end = next;
            continue;
        }
        let matches: Vec<_> = fields
            .iter()
            .filter(|field| format!("{};", declaration(&field.ty, &field.name)) == *text)
            .collect();
        let [field] = matches.as_slice() else {
            return false;
        };
        let width = match &field.ty {
            CType::Pointer(_) => 8,
            ty => match CType::pointer_to(ty.clone()).pointee_size() {
                Some(width) => u64::from(width),
                None => return false,
            },
        };
        if !matches!(width, 1 | 2 | 4 | 8)
            || field.width != width
            || alignment < width
            || field.offset < 0
            || field.offset as u64 != end
            || !end.is_multiple_of(width)
            || !definition.fields.contains(&field.name)
        {
            return false;
        }
        let Some(next) = end.checked_add(width) else {
            return false;
        };
        end = next;
        named += 1;
    }
    named > 0 && named == fields.len() && end == definition.size
}
