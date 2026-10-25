//! Counts explicit conversions in printed C.

/// Casts to a scalar, pointer or structure type, such as `(int8_t)` or `(struct s1 *)`.
pub(crate) fn casts(code: &str) -> usize {
    code.match_indices('(')
        .filter(|&(start, _)| {
            let rest = &code[start + 1..];
            let Some(end) = rest.find(')') else {
                return false;
            };
            let ty = rest[..end].trim();
            let mut inner = ty.trim_end_matches([' ', '*']);
            while let Some(unqualified) = inner
                .strip_prefix("const ")
                .or_else(|| inner.strip_prefix("volatile "))
            {
                inner = unqualified;
            }
            inner.ends_with("_t")
                && inner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || inner.strip_prefix("struct ").is_some_and(|name| {
                    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
                || matches!(
                    inner,
                    "float"
                        | "double"
                        | "bool"
                        | "char"
                        | "int"
                        | "unsigned int"
                        | "long"
                        | "unsigned long"
                        | "long long"
                        | "unsigned long long"
                        | "short"
                        | "unsigned short"
                        | "FILE"
                )
                || (inner == "void" && ty.ends_with('*'))
        })
        .count()
}
