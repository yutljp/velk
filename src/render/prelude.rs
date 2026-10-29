//! Shared support definitions for one or more printed functions.

use std::collections::BTreeSet;

mod calls;
mod structures;

const START: &str = "/* velk prelude */\n";
const END: &str = "/* end velk prelude */\n";
const PROJECT: &str = "/* velk project declarations */\n";

#[derive(Default)]
pub struct Prelude {
    definitions: BTreeSet<String>,
    structures: structures::StructureTagNames,
}

impl Prelude {
    /// Remove marked support sections, retaining their unique definitions.
    pub fn extract(&mut self, code: &str) -> String {
        let code = self.structures.resolve(code);
        let code = code.as_str();
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
            let Some((signature, _)) = line.split_once(" {") else {
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
            let old = self.definitions.len();
            self.definitions.retain(|definition| {
                if !definition.ends_with(';')
                    || definition.starts_with('#')
                    || definition.contains('{')
                {
                    return true;
                }
                let Some((before, _)) = definition.split_once('(') else {
                    return true;
                };
                let declared = before
                    .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next();
                declared != Some(name)
            });
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
            let declaration = format!("{}{signature}", records.into_iter().collect::<String>());
            self.definitions.insert(format!("{declaration};"));
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        if self.definitions.is_empty() {
            return String::new();
        }
        let mut definitions: Vec<_> = self.definitions.iter().collect();
        definitions.sort_by_key(|definition| definition_order(definition));
        let mut dependencies = vec![0usize; definitions.len()];
        let mut dependents = vec![Vec::new(); definitions.len()];
        let mut records = rustc_hash::FxHashMap::default();
        let mut unusual = Vec::new();
        for (record, other) in definitions.iter().enumerate() {
            let Some((name, _)) = other.split_once(" {") else {
                continue;
            };
            let Some(tag) = name
                .strip_prefix("struct ")
                .or_else(|| name.strip_prefix("union "))
            else {
                continue;
            };
            if tag.is_empty() || tag.contains(' ') {
                unusual.push((record, format!("{name} ")));
            } else {
                records.entry(name).or_insert_with(Vec::new).push(record);
            }
        }
        for (index, definition) in definitions.iter().enumerate() {
            let mut found = rustc_hash::FxHashSet::default();
            for keyword in ["struct ", "union "] {
                for (at, _) in definition.match_indices(keyword) {
                    let tag_start = at + keyword.len();
                    let Some(end) = definition[tag_start..].find(' ') else {
                        continue;
                    };
                    let end = tag_start + end;
                    let Some(matching) = records.get(&definition[at..end]) else {
                        continue;
                    };
                    if !definition[end + 1..].trim_start().starts_with('*') {
                        for &record in matching {
                            if index != record {
                                found.insert(record);
                            }
                        }
                    }
                }
            }
            for (record, prefix) in &unusual {
                if index != *record
                    && definition.match_indices(prefix).any(|(at, _)| {
                        !definition[at + prefix.len()..]
                            .trim_start()
                            .starts_with('*')
                    })
                {
                    found.insert(*record);
                }
            }
            for record in found {
                dependencies[index] += 1;
                dependents[record].push(index);
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
            let group = match definition_order(definition) {
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

pub(crate) fn promoted_parameter(ty: &crate::ir::CType) -> bool {
    if ty.is_pointer() {
        return false;
    }
    ty.integer().is_some_and(|(bits, _)| bits < 32)
        || matches!(ty, crate::ir::CType::Named(name) if ty.is_sse_float() && name.split_whitespace().any(|word| word == "float"))
}

fn definition_order(definition: &str) -> u8 {
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
    let code = structures::StructureTagNames::default().resolve(code);
    let code = super::globals::resolve(&code);
    let mut prelude = Prelude::default();
    let body = prelude.extract(&code);
    prelude.bind_definitions(&body);
    let body = calls::conform(&body);
    format!("{}{body}", prelude.render())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_declarations_use_the_definition_prototype() {
        let code = format!(
            "{}uint32_t invoke(void) {{\n    return read_value(7);\n}}\nstruct item *read_value(uint64_t address) {{\n    return (void *)address;\n}}\n",
            section("uint64_t read_value();\n")
        );
        let combined = combine(&code);
        assert!(
            combined.contains("struct item *read_value(uint64_t address);"),
            "{combined}"
        );
        assert!(combined.contains("struct item *read_value(uint64_t address) {"));
        assert_eq!(combine(&combined), combined);
    }

    #[test]
    fn fixed_declarations_keep_parameter_types() {
        for signature in ["int known(int value)", "int main(int argc, char **argv)"] {
            let code = format!(
                "{}{signature} {{\n    return 0;\n}}\n",
                section(&format!("{signature};\n"))
            );
            let combined = combine(&code);
            assert!(combined.contains(&format!("{signature};")), "{combined}");
        }
    }

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
    fn record_dependencies_include_substrings_and_ignore_pointers() {
        let definitions = "struct Z { int x; };\n\nstruct A { int xstruct Z value; };\n\nstruct B { struct Z *pointer; };\n";
        let output = combine(&section(definitions));
        assert!(output.find("struct Z {").unwrap() < output.find("struct A {").unwrap());
        assert!(output.find("struct B {").unwrap() < output.find("struct Z {").unwrap());
    }

    #[test]
    fn conflicting_numbered_tags_are_renamed_with_their_uses() {
        let first = format!(
            "{}struct S1 *first(struct S1 *p) {{ return p; }}\n",
            section("struct S1 { int a; };\n\nunion S2 { int b; };\n")
        );
        let second = format!(
            "{}struct S1 *second(struct S1 *p) {{ int S1 = 0; puts(\"struct S1\"); /* struct S1 */ return p + S1; }}\n",
            section("struct S1 { long a; };\n")
        );
        let mut prelude = Prelude::default();
        let body = prelude.extract(&format!("{first}{second}{second}"));
        let combined = format!("{}{body}", prelude.render());
        assert!(combined.contains("struct S3 { long a; };"), "{combined}");
        assert!(combined.contains("union S2 { int b; };"), "{combined}");
        assert!(
            combined.contains("struct S3 *second(struct S3 *p)"),
            "{combined}"
        );
        assert!(
            combined.contains("int S1 = 0; puts(\"struct S1\"); /* struct S1 */ return p + S1;")
        );
        assert_eq!(combined.matches("struct S3 { long a; };").count(), 1);
        assert_eq!(combine(&combined), combined);
        assert!(
            prelude
                .extract(&second)
                .contains("struct S3 *second(struct S3 *p)")
        );
        let combined = combine(&format!("{first}{}", section("union S1 { char c; };\n")));
        assert!(combined.contains("union S1 { char c; };"), "{combined}");
        assert!(
            combined.contains("struct S3 *first(struct S3 *p)"),
            "{combined}"
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
