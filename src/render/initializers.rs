use std::collections::HashMap;

/// Declare locals at their first assignment when all uses remain in its scope.
pub(super) fn fold(
    declarations: &mut String,
    body: &str,
    candidates: impl Iterator<Item = (String, String)>,
) -> String {
    let mut candidates: HashMap<_, _> = candidates.collect();
    let mut result = String::with_capacity(body.len());
    let mut prefix = String::new();
    let mut consumed = 0;
    let mut after_label = false;
    for line in body.split_inclusive('\n') {
        let indentation = line.len() - line.trim_start().len();
        let straight = indentation >= 4 && !after_label && line.trim_end().ends_with(';');
        consumed += line.len();
        let text = line.trim();
        if !text.is_empty() && !text.starts_with("/*") {
            after_label = text.ends_with(':');
        }
        if straight
            && let Some((name, value)) = line.trim_start().split_once(" = ")
            && let Some(declaration) = candidates.remove(name)
            && !super::variables::mentions(&prefix, name)
            && !super::variables::mentions(value, name)
            && (indentation == 4 || scoped_uses(&body[consumed..], indentation, name))
        {
            let old = format!("    {declaration};\n");
            if let Some(at) = declarations.find(&old) {
                // Other initial declarations can take a local's address.
                let mut others = declarations.clone();
                others.replace_range(at..at + old.len(), "");
                if !super::variables::mentions(&others, name) {
                    declarations.replace_range(at..at + old.len(), "");
                    result.push_str(&format!(
                        "{}{declaration} = {value}",
                        " ".repeat(indentation)
                    ));
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

// A less-indented line bounds the scope conservatively, including case labels.
fn scoped_uses(body: &str, indentation: usize, name: &str) -> bool {
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        let text = line.trim_start();
        if !text.trim().is_empty()
            && !text.starts_with("/*")
            && line.len() - text.len() < indentation
        {
            return !super::variables::mentions(&body[offset..], name);
        }
        // Keep the object's lifetime when its address can escape or a jump
        // can reenter the scope after the initializer.
        if text.trim_end().ends_with(':')
            || (line.contains('&') && super::variables::mentions(line, name))
        {
            return false;
        }
        offset += line.len();
    }
    true
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
    fn nested_initializers_keep_uses_in_other_scopes_and_following_labels() {
        let body = "    if (flag) {\n        x = 3;\n        consume(x);\n        y = 4;\n    }\n    consume(y);\nlabel:\n    y = 5;\n    z = 6;\n    consume(z);\n";
        let mut declarations = "    int x;\n    int y;\n    int z;\n".to_owned();
        let actual = fold(
            &mut declarations,
            body,
            ["x", "y", "z"]
                .into_iter()
                .map(|name| (name.into(), format!("int {name}"))),
        );
        assert_eq!(declarations, "    int y;\n");
        assert_eq!(
            actual,
            body.replace("        x = 3;", "        int x = 3;")
                .replace("    z = 6;", "    int z = 6;")
        );
    }

    #[test]
    fn nested_initializers_keep_escaping_addresses_and_reentered_values() {
        for body in [
            "    if (flag) {\n        x = 3;\n        save(&x);\n    }\n    use_saved();\n",
            "    if (flag) {\n        x = 3;\n    inner:\n        consume(x);\n    }\n    goto inner;\n",
            "    if (flag) {\n        x = 3;\n        if (other) {\n        inner:\n            consume(x);\n        }\n    }\n    goto inner;\n",
        ] {
            let mut declarations = "    int x;\n".to_owned();
            let actual = fold(
                &mut declarations,
                body,
                std::iter::once(("x".into(), "int x".into())),
            );
            assert_eq!(declarations, "    int x;\n");
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
