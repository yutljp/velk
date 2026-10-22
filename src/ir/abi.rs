use super::{AbiIssue, AbiProfile, Precision, RegisterClass};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypeLayout {
    pub size: u64,
    pub alignment: Option<u64>,
    pub kind: LayoutKind,
    pub trivial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LayoutKind {
    Integer,
    Boolean,
    Pointer,
    Float(Precision),
    Array {
        element: Box<TypeLayout>,
        count: u64,
    },
    Struct(Vec<LayoutField>),
    Union(Vec<LayoutField>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LayoutField {
    pub bit_offset: u64,
    pub bit_size: Option<u64>,
    pub defined: bool,
    pub layout: TypeLayout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassifiedValue {
    pub aggregate: bool,
    pub size: u64,
    pub alignment: u64,
    pub defined_bits: Vec<(u64, u64)>,
    pub passing: ValueClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueClass {
    Registers(Vec<ClassPiece>),
    Memory,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassPiece {
    pub object_offset: u64,
    pub bytes: u64,
    pub class: RegisterClass,
}

pub(crate) fn canonical(layout: &TypeLayout) -> Result<TypeLayout, AbiIssue> {
    fn resolve(layout: &TypeLayout, depth: u8, budget: &mut usize) -> Result<TypeLayout, AbiIssue> {
        spend(budget)?;
        if depth >= 64 {
            return Err(AbiIssue::UnknownLayout);
        }
        let mut resolved = layout.clone();
        resolved.kind = match &layout.kind {
            LayoutKind::Array { element, count } => LayoutKind::Array {
                element: Box::new(resolve(element, depth + 1, budget)?),
                count: *count,
            },
            LayoutKind::Struct(fields) | LayoutKind::Union(fields) => {
                let fields: Result<Vec<_>, _> = fields
                    .iter()
                    .map(|field| {
                        let mut field = field.clone();
                        field.layout = resolve(&field.layout, depth + 1, budget)?;
                        Ok(field)
                    })
                    .collect();
                if matches!(layout.kind, LayoutKind::Struct(_)) {
                    LayoutKind::Struct(fields?)
                } else {
                    LayoutKind::Union(fields?)
                }
            }
            kind => kind.clone(),
        };
        if resolved.alignment.is_none() {
            resolved.alignment = Some(match &resolved.kind {
                LayoutKind::Array { element, .. } => {
                    element.alignment.ok_or(AbiIssue::UnknownLayout)?
                }
                LayoutKind::Struct(fields) | LayoutKind::Union(fields) => fields
                    .iter()
                    .map(|field| field.layout.alignment.ok_or(AbiIssue::UnknownLayout))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .max()
                    .ok_or(AbiIssue::UnknownLayout)?,
                _ => return Err(AbiIssue::UnknownLayout),
            });
        }
        valid_alignment(&resolved)?;
        Ok(resolved)
    }
    resolve(layout, 0, &mut 65536)
}

pub(crate) fn alternatives(layout: &TypeLayout) -> Result<Vec<TypeLayout>, AbiIssue> {
    fn expand(
        layout: &TypeLayout,
        depth: u8,
        budget: &mut usize,
    ) -> Result<Vec<TypeLayout>, AbiIssue> {
        spend(budget)?;
        if depth >= 64 || layout.size == 0 || layout.size.checked_mul(8).is_none() {
            return Err(AbiIssue::UnknownLayout);
        }
        let mut layouts = vec![layout.clone()];
        match &layout.kind {
            LayoutKind::Array { element, count } => {
                layouts = expand(element, depth + 1, budget)?
                    .into_iter()
                    .map(|element| {
                        let mut alternative = layout.clone();
                        alternative.kind = LayoutKind::Array {
                            element: Box::new(element),
                            count: *count,
                        };
                        alternative
                    })
                    .collect();
            }
            LayoutKind::Struct(fields) | LayoutKind::Union(fields) => {
                for (index, field) in fields.iter().enumerate() {
                    let variants = expand(&field.layout, depth + 1, budget)?;
                    let mut combined = Vec::new();
                    for previous in &layouts {
                        for variant in &variants {
                            spend(budget)?;
                            if combined.len() == 256 {
                                return Err(AbiIssue::UnknownLayout);
                            }
                            let mut alternative = previous.clone();
                            let (LayoutKind::Struct(fields) | LayoutKind::Union(fields)) =
                                &mut alternative.kind
                            else {
                                unreachable!()
                            };
                            fields[index].layout = variant.clone();
                            combined.push(alternative);
                        }
                    }
                    layouts = combined;
                }
            }
            _ if layout.alignment.is_none() => return Err(AbiIssue::UnknownLayout),
            _ => {}
        }
        let alignments = match layout.alignment {
            Some(alignment) => vec![alignment],
            None => {
                let mut values = Vec::new();
                let mut alignment = 1;
                while layout.size.is_multiple_of(alignment) {
                    values.push(alignment);
                    let Some(next) = alignment.checked_mul(2) else {
                        break;
                    };
                    alignment = next;
                }
                values
            }
        };
        let mut resolved = Vec::new();
        for layout in layouts {
            for &alignment in &alignments {
                spend(budget)?;
                if resolved.len() == 256 {
                    return Err(AbiIssue::UnknownLayout);
                }
                let mut alternative = layout.clone();
                alternative.alignment = Some(alignment);
                valid_alignment(&alternative)?;
                resolved.push(alternative);
            }
        }
        Ok(resolved)
    }
    expand(layout, 0, &mut 65536)
}

fn spend(budget: &mut usize) -> Result<(), AbiIssue> {
    *budget = budget.checked_sub(1).ok_or(AbiIssue::UnknownLayout)?;
    Ok(())
}

fn valid_alignment(layout: &TypeLayout) -> Result<(), AbiIssue> {
    let alignment = layout.alignment.ok_or(AbiIssue::UnknownLayout)?;
    if layout.size == 0
        || layout.size.checked_mul(8).is_none()
        || !alignment.is_power_of_two()
        || !layout.size.is_multiple_of(alignment)
    {
        return Err(AbiIssue::UnknownLayout);
    }
    Ok(())
}

pub(crate) fn classify(
    profile: AbiProfile,
    layout: &TypeLayout,
) -> Result<ClassifiedValue, AbiIssue> {
    let mut defined_bits = Vec::new();
    let mut slots = [None; 2];
    let mut unaligned = false;
    inspect(
        layout,
        0,
        0,
        &mut 65536,
        &mut defined_bits,
        &mut slots,
        &mut unaligned,
    )?;
    merge_ranges(&mut defined_bits);
    let alignment = layout.alignment.ok_or(AbiIssue::UnknownLayout)?;
    let aggregate = matches!(
        layout.kind,
        LayoutKind::Array { .. } | LayoutKind::Struct(_) | LayoutKind::Union(_)
    );
    let integer_pieces = || {
        (0..layout.size.div_ceil(8))
            .map(|index| ClassPiece {
                object_offset: index * 8,
                bytes: (layout.size - index * 8).min(8),
                class: RegisterClass::Integer,
            })
            .collect()
    };
    let passing = match profile {
        AbiProfile::SysV if layout.size > 16 || unaligned => ValueClass::Memory,
        AbiProfile::SysV => ValueClass::Registers(
            slots
                .iter()
                .enumerate()
                .filter_map(|(index, class)| {
                    class.map(|class| ClassPiece {
                        object_offset: index as u64 * 8,
                        bytes: (layout.size - index as u64 * 8).min(8),
                        class,
                    })
                })
                .collect(),
        ),
        AbiProfile::Aapcs64 => {
            if let Some(pieces) = homogeneous(layout) {
                ValueClass::Registers(pieces)
            } else if layout.size > 16 {
                ValueClass::Indirect
            } else {
                ValueClass::Registers(integer_pieces())
            }
        }
        AbiProfile::Win64 if !aggregate && matches!(layout.kind, LayoutKind::Float(_)) => {
            ValueClass::Registers(vec![ClassPiece {
                object_offset: 0,
                bytes: layout.size,
                class: RegisterClass::Simd,
            }])
        }
        AbiProfile::Win64 if matches!(layout.size, 1 | 2 | 4 | 8) => {
            ValueClass::Registers(integer_pieces())
        }
        AbiProfile::Win64 if aggregate => ValueClass::Indirect,
        AbiProfile::Win64 => return Err(AbiIssue::UnsupportedType),
    };
    if matches!(&passing, ValueClass::Registers(pieces) if pieces.is_empty()) {
        return Err(AbiIssue::UnsupportedType);
    }
    Ok(ClassifiedValue {
        aggregate,
        size: layout.size,
        alignment,
        defined_bits,
        passing,
    })
}

pub(crate) fn compatible(
    profile: AbiProfile,
    original: &TypeLayout,
    generated: &TypeLayout,
) -> Result<(), AbiIssue> {
    let generated = classify(profile, &canonical(generated)?)?;
    let mut baseline: Option<ClassifiedValue> = None;
    for original in alternatives(original)? {
        let original = classify(profile, &original)?;
        if original.aggregate != generated.aggregate
            || original.size != generated.size
            || original.passing != generated.passing
            || original.defined_bits.iter().any(|&(offset, count)| {
                let index = generated
                    .defined_bits
                    .partition_point(|&(start, bits)| start + bits <= offset);
                generated
                    .defined_bits
                    .get(index)
                    .is_none_or(|&(start, bits)| start > offset || start + bits < offset + count)
            })
            || baseline
                .as_ref()
                .is_some_and(|baseline| baseline.defined_bits != original.defined_bits)
        {
            return Err(AbiIssue::IncompatibleDefinition);
        }
        baseline = Some(original);
    }
    Ok(())
}

fn inspect(
    layout: &TypeLayout,
    offset: u64,
    depth: u8,
    budget: &mut usize,
    ranges: &mut Vec<(u64, u64)>,
    slots: &mut [Option<RegisterClass>; 2],
    unaligned: &mut bool,
) -> Result<(), AbiIssue> {
    *budget = budget.checked_sub(1).ok_or(AbiIssue::UnknownLayout)?;
    if depth >= 64 {
        return Err(AbiIssue::UnknownLayout);
    }
    if !layout.trivial {
        return Err(AbiIssue::NonTrivial);
    }
    let alignment = layout.alignment.ok_or(AbiIssue::UnknownLayout)?;
    if layout.size == 0 || !alignment.is_power_of_two() || !layout.size.is_multiple_of(alignment) {
        return Err(AbiIssue::UnknownLayout);
    }
    let bits = layout.size.checked_mul(8).ok_or(AbiIssue::UnknownLayout)?;
    offset.checked_add(bits).ok_or(AbiIssue::UnknownLayout)?;
    *unaligned |= !offset.is_multiple_of(alignment * 8);
    match &layout.kind {
        LayoutKind::Integer | LayoutKind::Boolean | LayoutKind::Pointer | LayoutKind::Float(_) => {
            let class = match layout.kind {
                LayoutKind::Float(precision) if layout.size * 8 == u64::from(precision.bits()) => {
                    RegisterClass::Simd
                }
                LayoutKind::Float(_) => return Err(AbiIssue::UnsupportedType),
                LayoutKind::Pointer if layout.size == 8 => RegisterClass::Integer,
                LayoutKind::Boolean if layout.size == 1 && alignment == 1 => RegisterClass::Integer,
                LayoutKind::Integer if matches!(layout.size, 1 | 2 | 4 | 8 | 16) => {
                    RegisterClass::Integer
                }
                _ => return Err(AbiIssue::UnsupportedType),
            };
            ranges.push((
                offset,
                if matches!(layout.kind, LayoutKind::Boolean) {
                    1
                } else {
                    bits
                },
            ));
            mark(slots, offset, bits, class);
        }
        LayoutKind::Array { element, count } => {
            if *count == 0 || element.size.checked_mul(*count) != Some(layout.size) {
                return Err(AbiIssue::UnknownLayout);
            }
            for index in 0..*count {
                inspect(
                    element,
                    offset + index * element.size * 8,
                    depth + 1,
                    budget,
                    ranges,
                    slots,
                    unaligned,
                )?;
            }
        }
        LayoutKind::Struct(fields) | LayoutKind::Union(fields) => {
            if fields.is_empty() {
                return Err(AbiIssue::UnsupportedType);
            }
            let union = matches!(layout.kind, LayoutKind::Union(_));
            let mut end = 0;
            for field in fields {
                *budget = budget.checked_sub(1).ok_or(AbiIssue::UnknownLayout)?;
                let first_range = ranges.len();
                let field_bits = field.bit_size.unwrap_or(
                    field
                        .layout
                        .size
                        .checked_mul(8)
                        .ok_or(AbiIssue::UnknownLayout)?,
                );
                let field_end = field
                    .bit_offset
                    .checked_add(field_bits)
                    .ok_or(AbiIssue::UnknownLayout)?;
                if field_end > bits
                    || (!union && field.bit_offset < end)
                    || (union && field.bit_offset != 0)
                {
                    return Err(AbiIssue::UnknownLayout);
                }
                end = field_end;
                let field_offset = offset + field.bit_offset;
                if let Some(width) = field.bit_size {
                    if !field.layout.trivial {
                        return Err(AbiIssue::NonTrivial);
                    }
                    let storage_bits = field
                        .layout
                        .size
                        .checked_mul(8)
                        .ok_or(AbiIssue::UnknownLayout)?;
                    let alignment = field.layout.alignment.ok_or(AbiIssue::UnknownLayout)?;
                    if field.layout.size == 0
                        || !alignment.is_power_of_two()
                        || field.layout.size % alignment != 0
                    {
                        return Err(AbiIssue::UnknownLayout);
                    }
                    if !matches!(field.layout.kind, LayoutKind::Integer | LayoutKind::Boolean)
                        || !matches!(field.layout.size, 1 | 2 | 4 | 8 | 16)
                        || width > storage_bits
                    {
                        return Err(AbiIssue::UnsupportedType);
                    }
                    if matches!(field.layout.kind, LayoutKind::Boolean)
                        && (field.layout.size != 1 || alignment != 1 || width > 1)
                    {
                        return Err(AbiIssue::UnsupportedType);
                    }
                    if width != 0 {
                        ranges.push((field_offset, width));
                        mark(slots, field_offset, width, RegisterClass::Integer);
                    }
                } else {
                    inspect(
                        &field.layout,
                        field_offset,
                        depth + 1,
                        budget,
                        ranges,
                        slots,
                        unaligned,
                    )?;
                }
                if !field.defined {
                    ranges.truncate(first_range);
                }
            }
        }
    }
    Ok(())
}

fn mark(slots: &mut [Option<RegisterClass>; 2], offset: u64, bits: u64, class: RegisterClass) {
    for (index, slot) in slots.iter_mut().enumerate() {
        if offset < (index as u64 + 1) * 64 && offset + bits > index as u64 * 64 {
            *slot = Some(match (*slot, class) {
                (Some(RegisterClass::Integer), _) | (_, RegisterClass::Integer) => {
                    RegisterClass::Integer
                }
                _ => RegisterClass::Simd,
            });
        }
    }
}

fn merge_ranges(ranges: &mut Vec<(u64, u64)>) {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for &(offset, bits) in ranges.iter() {
        if let Some((previous, count)) = merged.last_mut()
            && offset <= *previous + *count
        {
            *count = (*previous + *count).max(offset + bits) - *previous;
        } else {
            merged.push((offset, bits));
        }
    }
    *ranges = merged;
}

fn homogeneous(layout: &TypeLayout) -> Option<Vec<ClassPiece>> {
    fn members(layout: &TypeLayout, offset: u64, found: &mut Vec<(u64, Precision)>) -> Option<()> {
        match &layout.kind {
            LayoutKind::Float(precision) => found.push((offset, *precision)),
            LayoutKind::Array { element, count } if *count <= 4 => {
                for index in 0..*count {
                    members(element, offset + index * element.size, found)?;
                }
            }
            LayoutKind::Struct(fields) | LayoutKind::Union(fields) => {
                for field in fields {
                    if field.bit_size.is_some() || field.bit_offset % 8 != 0 {
                        return None;
                    }
                    members(&field.layout, offset + field.bit_offset / 8, found)?;
                }
            }
            _ => return None,
        }
        found.sort_unstable_by_key(|member| member.0);
        found.dedup();
        (found.len() <= 4).then_some(())
    }
    let mut found = Vec::new();
    members(layout, 0, &mut found)?;
    let precision = found.first()?.1;
    let bytes = u64::from(precision.bits()) / 8;
    if found
        .iter()
        .enumerate()
        .any(|(index, &(offset, member))| member != precision || offset != index as u64 * bytes)
    {
        return None;
    }
    Some(
        found
            .into_iter()
            .map(|(object_offset, _)| ClassPiece {
                object_offset,
                bytes,
                class: RegisterClass::Simd,
            })
            .collect(),
    )
}

pub(crate) fn profile(
    isa: crate::loader::Isa,
    format: crate::loader::Format,
) -> Result<AbiProfile, AbiIssue> {
    use crate::loader::{Format, Isa};
    match (isa, format) {
        (Isa::X86_64, Format::Elf) => Ok(AbiProfile::SysV),
        (Isa::X86_64, Format::Pe | Format::Coff) => Ok(AbiProfile::Win64),
        (Isa::AArch64, Format::Elf) => Ok(AbiProfile::Aapcs64),
        _ => Err(AbiIssue::UnsupportedProfile),
    }
}

#[cfg(test)]
mod tests;
