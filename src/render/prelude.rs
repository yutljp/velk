//! Shared support definitions for one or more printed functions.

use std::collections::BTreeSet;

const START: &str = "/* velk prelude */\n";
const END: &str = "/* end velk prelude */\n";

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
                if !definition.trim().is_empty() {
                    self.definitions.insert(definition.trim_end().to_owned());
                }
            }
            rest = remaining;
        }
        body.push_str(rest);
        body
    }

    pub fn render(&self) -> String {
        if self.definitions.is_empty() {
            return String::new();
        }
        format!(
            "{START}{}\n{END}",
            self.definitions
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    }
}

pub(super) fn section(definitions: &str) -> String {
    if definitions.is_empty() {
        String::new()
    } else {
        format!("{START}{definitions}{END}")
    }
}

/// Combine standalone outputs with their support definitions printed once.
pub fn combine(code: &str) -> String {
    let mut prelude = Prelude::default();
    let body = prelude.extract(code);
    prelude.render() + &body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_definitions_precede_all_bodies() {
        let first = section("#include <cpuid.h>\n\n") + "void f(void) {}\n";
        let second =
            section("#include <cpuid.h>\n\nstatic inline int helper(void) { return 1; }\n\n")
                + "int g(void) { return helper(); }\n";
        let combined = combine(&(first + &second));
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
