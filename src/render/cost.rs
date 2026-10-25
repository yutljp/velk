//! Counts explicit conversions in printed C.

/// Casts to a scalar, pointer or structure type, such as `(int8_t)` or `(struct s1 *)`.
pub(crate) fn casts(code: &str) -> usize {
    code.match_indices('(')
        .filter(|&(start, _)| {
            let rest = &code[start + 1..];
            let Some(end) = rest.find(')') else {
                return false;
            };
            let inner = rest[..end].trim_end_matches([' ', '*']);
            inner.ends_with("_t")
                && inner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || inner.strip_prefix("struct ").is_some_and(|name| {
                    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
                || matches!(inner, "float" | "double" | "bool" | "char")
        })
        .count()
}
