//! Shared support definitions for one or more printed functions.

use std::collections::BTreeSet;

const START: &str = "/* velk prelude */\n";
const END: &str = "/* end velk prelude */\n";
const PROJECT: &str = "/* velk project declarations */\n";

#[derive(Default)]
pub struct Prelude {
    definitions: BTreeSet<String>,
}

impl Prelude {
    /// Remove marked support sections, retaining their unique definitions.
    pub fn extract(&mut self, code: &str) -> String {
        let mut rest = code;
        let mut body = String::new();
        while let Some((before, after)) = rest.split_once(START) {
            let Some((definitions, remaining)) = after.split_once(END) else {
                break;
            };
            body.push_str(before);
            for definition in definitions.split("\n\n") {
                let definition = definition.trim_matches('\n');
                if definition.starts_with(PROJECT) {
                    self.definitions.insert(definition.trim_end().to_owned());
                    continue;
                }
                let mut current = String::new();
                let mut conditional_depth = 0usize;
                for line in definition.lines() {
                    if line.starts_with("#if") {
                        conditional_depth += 1;
                    } else if line.starts_with("#endif") {
                        conditional_depth = conditional_depth.saturating_sub(1);
                    }
                    current.push_str(line);
                    current.push('\n');
                    let declaration = line.split_once(" /*").map_or(line, |(text, _)| text);
                    if conditional_depth == 0
                        && !line.starts_with(char::is_whitespace)
                        && (declaration.ends_with(';')
                            || declaration.ends_with('}')
                            || line.starts_with("#include ")
                            || line.starts_with("#endif")
                            || line.starts_with("extern "))
                    {
                        self.definitions.insert(current.trim_end().to_owned());
                        current.clear();
                    }
                }
                if !current.trim().is_empty() {
                    self.definitions.insert(current.trim_end().to_owned());
                }
            }
            rest = remaining;
        }
        body.push_str(rest);
        body
    }

    fn bind_definitions(&mut self, body: &str) {
        for line in body.lines() {
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            let Some(signature) = line.strip_suffix(" {") else {
                continue;
            };
            if !signature.ends_with(')') {
                continue;
            }
            let Some(open) = signature.find('(') else {
                continue;
            };
            let before = &signature[..open];
            let name = before
                .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or("");
            if name.is_empty() || name == "__attribute__" {
                continue;
            }
            let ending = format!(" {name}();");
            let old = self.definitions.len();
            self.definitions
                .retain(|definition| !definition.ends_with(&ending));
            if self.definitions.len() == old {
                continue;
            }
            let words: Vec<_> = signature
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|word| !word.is_empty())
                .collect();
            let mut records = BTreeSet::new();
            for pair in words.windows(2) {
                if matches!(pair[0], "struct" | "union") {
                    records.insert(format!("{} {}; ", pair[0], pair[1]));
                }
            }
            self.definitions.insert(format!(
                "{}{signature};",
                records.into_iter().collect::<String>()
            ));
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        if self.definitions.is_empty() {
            return String::new();
        }
        let mut definitions: Vec<_> = self.definitions.iter().cloned().collect();
        definitions.sort_by_key(|definition| order(definition));
        let mut dependencies = vec![0usize; definitions.len()];
        let mut dependents = vec![Vec::new(); definitions.len()];
        for (record, other) in definitions.iter().enumerate() {
            let Some((name, _)) = other.split_once(" {") else {
                continue;
            };
            if !name.starts_with("struct ") && !name.starts_with("union ") {
                continue;
            }
            let prefix = format!("{name} ");
            for (index, definition) in definitions.iter().enumerate() {
                if index != record
                    && definition.match_indices(&prefix).any(|(at, _)| {
                        !definition[at + prefix.len()..]
                            .trim_start()
                            .starts_with('*')
                    })
                {
                    dependencies[index] += 1;
                    dependents[record].push(index);
                }
            }
        }
        let mut ready: BTreeSet<usize> = dependencies
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(index, _)| index)
            .collect();
        let mut ordered = Vec::new();
        while let Some(index) = ready.pop_first() {
            ordered.push(definitions[index].as_str());
            for dependent in &dependents[index] {
                dependencies[*dependent] -= 1;
                if dependencies[*dependent] == 0 {
                    ready.insert(*dependent);
                }
            }
        }
        for (index, definition) in definitions.iter().enumerate() {
            if dependencies[index] != 0 {
                ordered.push(definition);
            }
        }
        let mut output = START.to_owned();
        let mut previous: Option<(u8, bool)> = None;
        for definition in ordered {
            let group = match order(definition) {
                1 | 2 => 1,
                group => group,
            };
            if previous.is_some_and(|(previous, project)| {
                previous != group || project || definition.starts_with(PROJECT)
            }) {
                output.push('\n');
            }
            output.push_str(definition);
            output.push('\n');
            previous = Some((group, definition.starts_with(PROJECT)));
        }
        output.push_str(END);
        output
    }
}

fn order(definition: &str) -> u8 {
    if definition.starts_with(PROJECT) || definition.starts_with("#include ") {
        0
    } else if [
        "struct go_string {",
        "struct go_slice {",
        "struct go_iface {",
    ]
    .iter()
    .any(|prefix| definition.starts_with(prefix))
        || ((definition.starts_with("struct ") || definition.starts_with("union "))
            && definition.ends_with(';')
            && !definition.contains(['{', '(']))
    {
        1
    } else if definition.starts_with("typedef ")
        || ((definition.starts_with("struct ") || definition.starts_with("union "))
            && (definition.contains(" {") || !definition.contains('(')))
    {
        2
    } else if definition.starts_with("extern ")
        && (!definition.contains('(') || definition.contains("/* address:"))
    {
        3
    } else {
        4
    }
}

pub(super) fn section(definitions: &str) -> String {
    if definitions.is_empty() {
        String::new()
    } else {
        format!("{START}{definitions}{END}")
    }
}

pub(crate) fn project_section(declarations: &str) -> String {
    section(&format!("{PROJECT}#include <stdint.h>\n{declarations}\n"))
}

/// Combine standalone outputs with their support definitions printed once.
#[must_use]
pub fn combine(code: &str) -> String {
    let code = super::globals::resolve(code);
    let mut prelude = Prelude::default();
    let body = prelude.extract(&code);
    prelude.bind_definitions(&body);
    format!("{}{body}", prelude.render())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_tags_precede_function_pointer_parameters() {
        let code = combine(&section(
            "struct Z;\nstruct A { int (*Method)(struct Z *); };\n",
        ));
        assert!(
            code.find("struct Z;").unwrap() < code.find("struct A {").unwrap(),
            "{code}"
        );
    }

    #[test]
    fn declarations_are_grouped_and_remain_deduplicated() {
        let definitions = "struct item {\n    int value;\n};\n\nextern int a;\n\nextern int b;\n\nint f(void);\n\nint g(void);\n";
        let output = combine(&section(definitions));
        assert_eq!(
            output,
            format!(
                "{START}struct item {{\n    int value;\n}};\n\nextern int a;\nextern int b;\n\nint f(void);\nint g(void);\n{END}"
            )
        );
        assert_eq!(combine(&format!("{output}{output}")), output);
    }

    #[test]
    fn grouped_multiline_definitions_keep_their_boundaries() {
        let first = section("#include <stdint.h>\n\nstruct first {\n    int n;\n};\n\n");
        let second = section(
            "#include <stdbool.h>\n\nstruct second {\n    struct first value;\n};\n\n#ifndef HELPER\n#define HELPER\nstatic inline int helper(void) { return 1; }\n#endif\n",
        );
        let combined = combine(&format!("{first}{second}"));
        assert_eq!(combine(&format!("{combined}{first}{second}")), combined);
        assert!(
            combined.find("struct first {").unwrap() < combined.find("struct second {").unwrap()
        );
        assert!(
            combined.find("#include <stdint.h>").unwrap()
                < combined.find("#ifndef HELPER").unwrap()
        );
    }

    #[test]
    fn shared_definitions_precede_all_bodies() {
        let first = format!("{}void f(void) {{}}\n", section("\n#include <cpuid.h>\n\n"));
        let second = format!(
            "{}int g(void) {{ return helper(); }}\n",
            section("#include <cpuid.h>\n\nstatic inline int helper(void) { return 1; }\n\n")
        );
        let combined = combine(&format!("{first}{second}"));
        assert_eq!(combined.matches("#include <cpuid.h>").count(), 1);
        assert_eq!(combined.matches(START).count(), 1);
        assert!(combined.find("static inline").unwrap() < combined.find("void f").unwrap());
        assert_eq!(combine(&combined), combined);
        let mut prelude = Prelude::default();
        assert_eq!(
            prelude.extract(&combined),
            "void f(void) {}\nint g(void) { return helper(); }\n"
        );
    }
}
