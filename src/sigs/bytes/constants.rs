//! Exact values for fixed-width, read-only PC-relative loads.

use object::{Object, ObjectSection, ObjectSymbol};

use super::Body;
use crate::loader::Image;

pub(super) fn image(image: &Image, body: &Body) -> Option<Vec<Vec<u8>>> {
    let mut values = Vec::new();
    for reference in &body.references {
        let Some(end) = reference.target.checked_add(reference.size as u64) else {
            return None;
        };
        if !image.sections.iter().any(|section| {
            section.loaded
                && section.read_only
                && !section.executable
                && reference.target >= section.vaddr
                && end <= section.vaddr.saturating_add(section.size)
        }) {
            return None;
        }
        let Some(bytes) = image.read_vaddr(reference.target, reference.size as u64) else {
            return None;
        };
        values.push(bytes.to_vec());
    }
    Some(values)
}

pub(super) fn object(
    file: &object::File<'_>,
    body: &Body,
    relocations: &[&(u64, object::Relocation)],
    function_offset: usize,
) -> Option<Vec<Vec<u8>>> {
    let mut values = Vec::new();
    for reference in &body.references {
        let Some((_, relocation)) = relocations.iter().find(|(offset, _)| {
            offset.checked_sub(function_offset as u64) == Some(reference.offset as u64)
        }) else {
            return None;
        };
        let arm_literal = file.architecture() == object::Architecture::Aarch64
            && matches!(relocation.flags(), object::RelocationFlags::Elf { r_type } if r_type.0 == 273);
        if relocation.kind() != object::RelocationKind::Relative
            || relocation.has_implicit_addend()
            || (!arm_literal && relocation.size() != 32)
        {
            return None;
        }
        let object::RelocationTarget::Symbol(index) = relocation.target() else {
            return None;
        };
        let Ok(symbol) = file.symbol_by_index(index) else {
            return None;
        };
        let Some(index) = symbol.section_index() else {
            return None;
        };
        let Ok(section) = file.section_by_index(index) else {
            return None;
        };
        if !matches!(
            section.kind(),
            object::SectionKind::ReadOnlyData | object::SectionKind::ReadOnlyString
        ) || section.relocations().next().is_some()
        {
            return None;
        }
        let Some(offset) = symbol
            .address()
            .checked_sub(section.address())
            .and_then(|offset| {
                offset.checked_add(if arm_literal {
                    0
                } else {
                    reference.next.saturating_sub(reference.offset) as u64
                })
            })
            .and_then(|offset| offset.checked_add_signed(relocation.addend()))
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            return None;
        };
        let Ok(data) = section.data() else {
            return None;
        };
        let Some(end) = offset.checked_add(reference.size) else {
            return None;
        };
        let Some(bytes) = data.get(offset..end) else {
            return None;
        };
        values.push(bytes.to_vec());
    }
    Some(values)
}
