use std::collections::HashMap;

/// Declare locals at their first top-level assignment, in execution order.
pub(super) fn fold(
    declarations: &mut String,
    body: &str,
    candidates: impl Iterator<Item = (String, String)>,
) -> String {
    let mut candidates: HashMap<_, _> = candidates.collect();
    let mut result = String::with_capacity(body.len());
    let mut prefix = String::new();
    let mut consumed = 0;
    for line in body.split_inclusive('\n') {
        // Keep declarations before labels so a label never directly precedes
        // a declaration in C11. Nested statements remain in their own scope.
        if line.trim_end().ends_with(':') {
            result.push_str(&body[consumed..]);
            return result;
        }
        let straight = line.starts_with("    ")
            && !line.starts_with("        ")
            && line.trim_end().ends_with(';');
        consumed += line.len();
        if straight
            && let Some((name, value)) = line.trim_start().split_once(" = ")
            && let Some(declaration) = candidates.remove(name)
            && !super::variables::mentions(&prefix, name)
            && !super::variables::mentions(value, name)
        {
            let old = format!("    {declaration};\n");
            if let Some(at) = declarations.find(&old) {
                // Other initial declarations can take a local's address.
                let mut others = declarations.clone();
                others.replace_range(at..at + old.len(), "");
                if !super::variables::mentions(&others, name) {
                    declarations.replace_range(at..at + old.len(), "");
                    result.push_str(&format!("    {declaration} = {value}"));
                    prefix.push_str(line);
                    continue;
                }
            }
        }
        result.push_str(line);
        prefix.push_str(line);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::fold;

    #[test]
    fn initializers_preserve_order_and_prior_uses() {
        let mut declarations = "    int x;\n    int y;\n    int z;\n".to_owned();
        let body = "    consume(&x);\n    x = 3;\n    y = x;\n    z = z + 1;\n    if (x) {\n        x = 4;\n    }\n";
        let actual = fold(
            &mut declarations,
            body,
            ["x", "y", "z"]
                .into_iter()
                .map(|name| (name.into(), format!("int {name}"))),
        );
        assert_eq!(declarations, "    int x;\n    int z;\n");
        assert_eq!(actual, body.replace("    y = x;", "    int y = x;"));
    }

    #[test]
    fn declarations_keep_names_used_by_other_initializers_or_labels() {
        for (original, body) in [
            ("    int x;\n    int *p = &x;\n", "    x = 3;\n"),
            ("    int x;\n", "label:\n    x = 3;\n"),
            ("    int x;\n", "    if (flag) {\n        x = 3;\n    }\n"),
        ] {
            let mut declarations = original.to_owned();
            let actual = fold(
                &mut declarations,
                body,
                std::iter::once(("x".into(), "int x".into())),
            );
            assert_eq!(declarations, original);
            assert_eq!(actual, body);
        }
    }

    #[test]
    fn guards_allow_later_initializers_but_nested_uses_keep_declarations() {
        let body = "    if (flag) {\n        consume(&x);\n        return;\n    }\n    x = 3;\n    y = 4;\n";
        let mut declarations = "    int x;\n    int y;\n".to_owned();
        let actual = fold(
            &mut declarations,
            body,
            ["x", "y"]
                .into_iter()
                .map(|name| (name.into(), format!("int {name}"))),
        );
        assert_eq!(declarations, "    int x;\n");
        assert_eq!(actual, body.replace("    y = 4;", "    int y = 4;"));
    }
}
