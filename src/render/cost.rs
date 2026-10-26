//! Counts explicit conversions in printed C.

/// Casts to a scalar, pointer or structure type, such as `(int8_t)` or `(struct s1 *)`.
pub(crate) fn casts(code: &str) -> usize {
    cast_types(code)
        .filter(|ty| {
            let ty = ty.trim();
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

/// Counts casts using the narrower type recognition used to select memory transfers.
pub(crate) fn transfer_casts(text: &str) -> usize {
    let mut count = 0;
    for ty in cast_types(text) {
        let ty = ty.trim_end_matches([' ', '*']);
        if ty.ends_with("_t")
            && ty
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || ty.strip_prefix("struct ").is_some_and(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
            || matches!(ty, "float" | "double" | "bool" | "char")
        {
            count += 1;
        }
    }
    count
}

fn cast_types(code: &str) -> impl Iterator<Item = &str> {
    code.match_indices('(').filter_map(|(start, _)| {
        let rest = &code[start + 1..];
        let Some(end) = rest.find(')') else {
            return None;
        };
        Some(&rest[..end])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast_policies_preserve_whitespace_and_qualifier_differences() {
        let cases = [
            ("(uint64_t)", 1, 1),
            ("( uint64_t)", 1, 0),
            ("(uint64_t\t)", 1, 0),
            ("(const uint64_t *)", 1, 0),
            ("(volatile const struct item *)", 1, 0),
            ("(unsigned int)", 1, 0),
            ("(void *)", 1, 0),
            ("(void)", 0, 0),
            ("(FILE *)", 1, 0),
            ("(struct item *)", 1, 1),
            ("(struct bad-name)", 0, 0),
            ("(float)", 1, 1),
            ("(uint_t + x)", 0, 0),
            ("(outer(uint64_t))", 1, 1),
            ("(uint64_t", 0, 0),
        ];
        for (text, general, transfer) in cases {
            assert_eq!(casts(text), general, "{text}");
            assert_eq!(transfer_casts(text), transfer, "{text}");
        }
    }
}
