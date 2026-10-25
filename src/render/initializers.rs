use std::collections::HashMap;

pub(super) enum Placement {
    Assignments,
    Scoped,
}

/// Declare locals at their first assignment when all uses remain in its scope.
pub(super) fn fold(
    declarations: &mut String,
    body: &str,
    candidates: impl Iterator<Item = (String, String)>,
    placement: Placement,
) -> String {
    let candidates: HashMap<_, _> = candidates.collect();
    let lines: Vec<&str> = body.split_inclusive('\n').collect();
    let mut scopes = Vec::with_capacity(lines.len());
    let mut stack = Vec::new();
    let mut labels = HashMap::new();
    let mut jumps = Vec::new();
    for (position, line) in lines.iter().enumerate() {
        let text = line.trim();
        if text.starts_with('}') {
            stack.pop();
        }
        scopes.push(stack.clone());
        if text.ends_with(':') {
            labels.insert(text.trim_end_matches(':'), position);
        }
        for (at, _) in text.match_indices("goto ") {
            let name = text[at + 5..].split(';').next().unwrap_or("");
            jumps.push((position, name));
        }
        if text.ends_with('{') {
            stack.push(position);
        }
    }
    let mut replacements = HashMap::new();
    for (name, declaration) in candidates {
        let Some(position) = lines
            .iter()
            .position(|line| super::variables::mentions(line, &name))
        else {
            continue;
        };
        let line = lines[position];
        let for_init = if matches!(placement, Placement::Scoped)
            && line.trim_end().ends_with('{')
            && line.matches(';').count() == 2
        {
            line.trim_start()
                .strip_prefix("for (")
                .and_then(|header| header.split_once(';'))
        } else {
            None
        };
        let assignment = for_init.map_or(line.trim_start(), |(init, _)| init);
        let Some(value) = assignment.strip_prefix(&format!("{name} = ")) else {
            continue;
        };
        let terminated = for_init.is_some()
            || line.trim_end().ends_with(';')
            || (matches!(placement, Placement::Scoped)
                && line
                    .split_once("; /*")
                    .is_some_and(|(_, comment)| comment.trim_end().ends_with("*/")));
        if !terminated || super::variables::mentions(value, &name) {
            continue;
        }
        if matches!(placement, Placement::Assignments) {
            // Score exit merging with the existing assignment placement rules.
            let indentation = line.len() - line.trim_start().len();
            let after_label = lines[..position]
                .iter()
                .rev()
                .find(|line| {
                    let text = line.trim();
                    !text.is_empty() && !text.starts_with("/*")
                })
                .is_some_and(|line| line.trim_end().ends_with(':'));
            let consumed: usize = lines[..=position].iter().map(|line| line.len()).sum();
            if indentation < 4
                || after_label
                || (indentation != 4 && !scoped_uses(&body[consumed..], indentation, &name))
            {
                continue;
            }
        } else {
            let mut scope = scopes[position].clone();
            if for_init.is_some() {
                scope.push(position);
            }
            let scope = &scope;
            // An escaped pointer can keep the object live beyond a nested block.
            let address = format!("&{name}");
            if !scope.is_empty()
                && body.match_indices(&address).any(|(at, value)| {
                    let tail = &body[at + value.len()..];
                    !tail.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                        && !tail.starts_with("->")
                        && !tail.starts_with('[')
                })
            {
                continue;
            }
            if lines
                .iter()
                .enumerate()
                .skip(position + 1)
                .any(|(at, line)| {
                    super::variables::mentions(line, &name) && !scopes[at].starts_with(scope)
                })
            {
                continue;
            }
            let last_use = lines
                .iter()
                .rposition(|line| super::variables::mentions(line, &name))
                .expect("first assignment mentions the local");
            // A switch dispatch or a goto must not bypass the initializer.
            if lines
                .iter()
                .enumerate()
                .take(last_use + 1)
                .skip(position + 1)
                .any(|(at, line)| {
                    let text = line.trim();
                    scopes[at] == *scope && (text.starts_with("case ") || text == "default:")
                })
                || jumps.iter().any(|(source, target)| {
                    labels.get(target).is_some_and(|target| {
                        *target >= position
                            && scopes[*target].starts_with(scope)
                            && (*source < position || !scopes[*source].starts_with(scope))
                    })
                })
            {
                continue;
            }
        }
        let old = format!("    {declaration};\n");
        let Some(at) = declarations.find(&old) else {
            continue;
        };
        let mut others = declarations.clone();
        others.replace_range(at..at + old.len(), "");
        if super::variables::mentions(&others, &name) {
            continue;
        }
        declarations.replace_range(at..at + old.len(), "");
        if for_init.is_none() && position > 0 && lines[position - 1].trim_end().ends_with(':') {
            replacements.insert(
                position - 1,
                format!("{};\n", lines[position - 1].trim_end()),
            );
        }
        let indent = &line[..line.len() - line.trim_start().len()];
        let initialized = match for_init {
            Some((_, rest)) => format!("{indent}for ({declaration} = {value};{rest}"),
            None => format!("{indent}{declaration} = {value}"),
        };
        replacements.insert(position, initialized);
    }
    let mut result = String::with_capacity(body.len());
    for (position, line) in lines.iter().enumerate() {
        result.push_str(replacements.get(&position).map_or(*line, String::as_str));
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
        if text.trim_end().ends_with(':')
            || (line.contains('&') && super::variables::mentions(line, name))
        {
            return false;
        }
        offset += line.len();
    }
    true
}

/// Removes constant assignments to scalar locals whose values and addresses are unused.
pub(super) fn drop_unused_constants(body: &mut String, names: impl Iterator<Item = String>) {
    for name in names {
        let prefix = format!("{name} = ");
        let unused = body
            .lines()
            .filter(|line| super::function::code_mentions(line, &name))
            .all(|line| {
                let Some(value) = line
                    .trim()
                    .strip_prefix(&prefix)
                    .and_then(|value| value.strip_suffix(';'))
                else {
                    return false;
                };
                let value = value.trim_end_matches(['U', 'L']).trim_start_matches('-');
                match value.strip_prefix("0x") {
                    Some(hex) => {
                        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }
                    None => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                }
            });
        if unused {
            *body = body
                .split_inclusive('\n')
                .filter(|line| !super::function::code_mentions(line, &name))
                .collect();
        }
    }
}

#[cfg(test)]
mod tests {
    fn fold(
        declarations: &mut String,
        body: &str,
        candidates: impl Iterator<Item = (String, String)>,
    ) -> String {
        super::fold(declarations, body, candidates, super::Placement::Scoped)
    }

    #[test]
    fn unused_constant_assignments_keep_addresses_reads_and_effects() {
        let mut body = String::from(
            "    unused = 0x1000;\n    used = 1;\n    keep(&used);\n    effect = call();\n    read = 2;\n    return read;\n",
        );
        super::drop_unused_constants(
            &mut body,
            ["unused", "used", "effect", "read"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(!body.contains("unused"));
        assert!(body.contains("used = 1;"));
        assert!(body.contains("effect = call();"));
        assert!(body.contains("read = 2;"));
    }

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
            (
                "    int x;\n",
                "    if (flag) goto later;\nlabel:\n    x = 3;\nlater:\n    use(x);\n",
            ),
            (
                "    int x;\n",
                "    if (flag) {\n        x = 3;\n    }\n    use(x);\n",
            ),
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

    #[test]
    fn nested_initializers_stay_in_scope_and_cannot_be_bypassed() {
        for (body, folded) in [
            (
                "    if (flag) {\n        x = 3;\n        pointer = &x;\n    }\n    use(*pointer);\n",
                false,
            ),
            (
                "    if (flag) {\n        x = 3;\n        use(x);\n    }\n",
                true,
            ),
            (
                "    while (flag) {\n        x = next();\n        use(x);\n    }\n",
                true,
            ),
            (
                "    if (flag) {\n        x = 3;\n    }\n    use(x);\n",
                false,
            ),
            (
                "    if (flag) goto label;\n    x = 3;\nlabel:\n    use(x);\n",
                false,
            ),
            (
                "    switch (flag) {\n    case 1:\n        x = 3;\n    case 2:\n        use(x);\n    }\n",
                false,
            ),
            (
                "    x = 3;\nlabel:\n    use(x);\n    if (flag) goto label;\n",
                true,
            ),
        ] {
            let mut declarations = "    int x;\n".to_owned();
            let actual = fold(
                &mut declarations,
                body,
                std::iter::once(("x".into(), "int x".into())),
            );
            let expected = if folded {
                body.replace("x = ", "int x = ")
            } else {
                body.to_owned()
            };
            assert_eq!(actual, expected, "{body}");
            assert_eq!(declarations.is_empty(), folded, "{body}");
        }
        let body = "    if (flag) {\n        x = object;\n        pointer = &x->field;\n    }\n    use(pointer);\n";
        let mut declarations = "    struct item *x;\n".to_owned();
        let actual = fold(
            &mut declarations,
            body,
            std::iter::once(("x".into(), "struct item *x".into())),
        );
        assert!(declarations.is_empty());
        assert_eq!(
            actual,
            body.replace("x = object", "struct item *x = object")
        );
    }

    #[test]
    fn output_comments_allow_an_initializer() {
        let body = "    x = result; /* also returned by the call */\n    use(x);\n";
        let mut declarations = "    int x;\n".to_owned();
        let actual = fold(
            &mut declarations,
            body,
            std::iter::once(("x".into(), "int x".into())),
        );
        assert!(declarations.is_empty());
        assert_eq!(actual, body.replace("x = result", "int x = result"));
    }

    #[test]
    fn for_initializers_keep_uses_inside_the_loop() {
        for (body, folded) in [
            (
                "    for (x = 0; x < n; ++x) {\n        use(x);\n    }\n",
                true,
            ),
            (
                "    for (x = 0; x < n; ++x) {\n        use(x);\n    }\n    use(x);\n",
                false,
            ),
            (
                "    for (x = x + 1; x < n; ++x) {\n        use(x);\n    }\n",
                false,
            ),
            (
                "    if (flag) goto loop_body;\n    for (x = 0; x < n; ++x) {\nloop_body:\n        use(x);\n    }\n",
                false,
            ),
        ] {
            let mut declarations = "    int x;\n".to_owned();
            let actual = fold(
                &mut declarations,
                body,
                std::iter::once(("x".into(), "int x".into())),
            );
            assert_eq!(declarations.is_empty(), folded, "{body}");
            let expected = if folded {
                body.replace("for (x =", "for (int x =")
            } else {
                body.to_owned()
            };
            assert_eq!(actual, expected);
        }
    }
}
