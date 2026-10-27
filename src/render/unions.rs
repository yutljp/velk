//! Unions for bytes read and written at more than one width: the cell the
//! accesses share and the members that name each of them. Stack regions and
//! recovered structures declare their overlapping accesses this way.

/// The size of the aligned cell of one, two, four or eight bytes that the
/// overlapping accesses `group` (offset from the object's start, width)
/// fill, each a whole number of its widths into the object.
pub(crate) fn cell(group: &[(i64, u8)]) -> Option<u8> {
    let is_naturally_aligned =
        |offset: i64, width: u8| matches!(width, 1 | 2 | 4 | 8) && offset % i64::from(width) == 0;
    let Some(start) = group.iter().map(|(offset, _)| *offset).min() else {
        return None;
    };
    let Some(stop) = group
        .iter()
        .map(|(offset, width)| offset.saturating_add(i64::from(*width)))
        .max()
    else {
        return None;
    };
    let Ok(size) = u8::try_from(stop - start) else {
        return None;
    };
    (is_naturally_aligned(start, size)
        && group
            .iter()
            .all(|(offset, width)| is_naturally_aligned(*offset, *width)))
    .then_some(size)
}

#[derive(Clone, Copy)]
pub(crate) enum MemberIndex {
    Array,
    Scalar,
}

/// The member of a cell's union that names an access of `width` bytes at
/// `offset` into the cell: `as_u32`, or `as_u32[1]` where accesses of that
/// width are read past the cell's start.
pub(crate) fn member(width: u8, signed: bool, offset: i64, indexed: MemberIndex) -> String {
    let indexed = matches!(indexed, MemberIndex::Array);
    let base = format!(
        "as_{}{}",
        if signed { "i" } else { "u" },
        u32::from(width) * 8
    );
    if indexed {
        format!("{base}[{}]", offset / i64::from(width))
    } else {
        base
    }
}

/// The declarations of a union's members, widest first, for the accesses
/// `views` (offset into a cell of `size` bytes, width, signed) make.
pub(crate) fn members(size: u8, views: &[(i64, u8, bool)]) -> Vec<String> {
    let mut members: Vec<(u8, String)> = Vec::new();
    for (_, width, signed) in views {
        let indexed = views
            .iter()
            .any(|(offset, other, _)| other == width && *offset != 0);
        let ty = super::expr::type_of(*width, *signed);
        let declared = if indexed {
            format!(
                "{ty} {}[{}];",
                member(*width, *signed, 0, MemberIndex::Scalar),
                size / width
            )
        } else {
            format!("{ty} {};", member(*width, *signed, 0, MemberIndex::Scalar))
        };
        if !members.iter().any(|(_, known)| *known == declared) {
            members.push((*width, declared));
        }
    }
    members.sort_by_key(|(width, _)| std::cmp::Reverse(*width));
    members.into_iter().map(|(_, member)| member).collect()
}

/// A structure's fields, each an offset and a type.
type Fields = Vec<(u64, crate::ir::CType)>;

/// The fields of a structure grouped into the cells they share: each a
/// start, a size, and the fields in it.
pub(crate) fn cells(fields: &[(u64, crate::ir::CType)]) -> Vec<(u64, u64, Fields)> {
    let width = |ty: &crate::ir::CType| match ty {
        crate::ir::CType::Pointer(_) => 8,
        _ => crate::ir::CType::pointer_to(ty.clone())
            .pointee_size()
            .map_or(0, u64::from),
    };
    let mut sorted: Fields = fields.to_vec();
    sorted.sort_by_key(|(offset, ty)| (*offset, std::cmp::Reverse(width(ty))));
    let mut cells: Vec<(u64, u64, Fields)> = Vec::new();
    for (offset, ty) in sorted {
        let end = offset.saturating_add(width(&ty));
        match cells.last_mut() {
            Some((start, size, members)) if offset < start.saturating_add(*size) => {
                *size = (*size).max(end.saturating_sub(*start));
                members.push((offset, ty));
            }
            _ => cells.push((offset, end.saturating_sub(offset), vec![(offset, ty)])),
        }
    }
    cells
}
