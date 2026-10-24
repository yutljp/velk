//! Unions for bytes read and written at more than one width: the cell the
//! accesses share and the members that name each of them. Stack regions and
//! recovered structures declare their overlapping accesses this way.

/// The size of the aligned cell of two, four or eight bytes that the
/// overlapping accesses `group` (offset from the object's start, width)
/// fill, each a whole number of its widths into the object.
pub(crate) fn cell(group: &[(i64, u8)]) -> Option<u8> {
    let natural =
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
    (natural(start, size) && group.iter().all(|(offset, width)| natural(*offset, *width)))
        .then_some(size)
}

/// The member of a cell's union that names an access of `width` bytes at
/// `offset` into the cell: `as_u32`, or `as_u32[1]` where accesses of that
/// width are read past the cell's start.
pub(crate) fn member(width: u8, signed: bool, offset: i64, indexed: bool) -> String {
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
                member(*width, *signed, 0, false),
                size / width
            )
        } else {
            format!("{ty} {};", member(*width, *signed, 0, false))
        };
        if !members.iter().any(|(_, known)| *known == declared) {
            members.push((*width, declared));
        }
    }
    members.sort_by_key(|(width, _)| std::cmp::Reverse(*width));
    members.into_iter().map(|(_, member)| member).collect()
}
