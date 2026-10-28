//! Resolve generated structure tags before combining standalone declarations.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct StructureTagNames {
    definitions: BTreeMap<String, String>,
    tags: BTreeMap<String, String>,
    reserved: BTreeSet<String>,
}

fn definitions(code: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current = None;
    for line in code.lines() {
        if let Some((_, definition)) = &mut current {
            *definition += line;
        } else if let Some((tag, _)) = line
            .strip_prefix("struct ")
            .or_else(|| line.strip_prefix("union "))
            .or_else(|| line.strip_prefix("enum "))
            .and_then(|line| line.split_once(" {"))
            && super::super::globals::identifier(tag) == tag
        {
            current = Some((tag.to_owned(), line.to_owned()));
        }
        if line.ends_with("};")
            && let Some(definition) = current.take()
        {
            result.push(definition);
        }
    }
    result
}

impl StructureTagNames {
    pub(super) fn resolve(&mut self, code: &str) -> String {
        for (tag, definition) in definitions(code) {
            self.reserved.insert(tag.clone());
            if !definition.starts_with("struct ") {
                self.tags.entry(tag).or_insert(definition);
            }
        }
        let mut output = String::new();
        for section in code.split_inclusive(super::START) {
            // A marked section and its following body share a tag namespace.
            let mut replacements = BTreeMap::new();
            let support = section.split_once(super::END).map_or("", |(text, _)| text);
            for (tag, definition) in definitions(support) {
                if !definition.starts_with("struct ") {
                    continue;
                }
                let definition = rename(&definition, &replacements);
                let digits = tag
                    .strip_prefix('S')
                    .filter(|digits| {
                        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .or_else(|| {
                        let Some((_, suffix)) = tag.rsplit_once('_') else {
                            return None;
                        };
                        suffix
                            .strip_prefix('s')
                            .or_else(|| suffix.strip_prefix('a'))
                    });
                if !digits.is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
                }) {
                    continue;
                }
                let name = if let Some(name) = self.definitions.get(&definition) {
                    name.clone()
                } else {
                    let mut name = tag.clone();
                    if self
                        .tags
                        .get(&tag)
                        .is_some_and(|known| *known != definition)
                    {
                        let mut serial = 1;
                        loop {
                            name = format!("S{serial}");
                            serial += 1;
                            if self.reserved.insert(name.clone()) {
                                break;
                            }
                        }
                    }
                    self.tags.insert(name.clone(), definition.clone());
                    self.definitions.insert(definition, name.clone());
                    name
                };
                if name != tag {
                    replacements.insert(tag, name);
                }
            }
            output.push_str(&rename(section, &replacements));
        }
        output
    }
}

fn rename(code: &str, replacements: &BTreeMap<String, String>) -> String {
    if replacements.is_empty() {
        return code.to_owned();
    }
    let bytes = code.as_bytes();
    let mut output = String::new();
    let mut copied = 0;
    let mut at = 0;
    let mut tag = false;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if bytes[at..].starts_with(b"/*") {
            at += 2;
            while at < bytes.len() && !bytes[at..].starts_with(b"*/") {
                at += 1;
            }
            at = at.saturating_add(2).min(bytes.len());
        } else if matches!(bytes[at], b'\'' | b'"') {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                let byte = bytes[at];
                at += 1;
                if byte == b'\\' {
                    at = at.saturating_add(1).min(bytes.len());
                } else if byte == quote {
                    break;
                }
            }
            tag = false;
        } else if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            let start = at;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            let word = &code[start..at];
            if tag && let Some(name) = replacements.get(word) {
                output.push_str(&code[copied..start]);
                output.push_str(name);
                copied = at;
            }
            tag = word == "struct";
        } else {
            if !bytes[at].is_ascii_whitespace() {
                tag = false;
            }
            at += 1;
        }
    }
    output.push_str(&code[copied..]);
    output
}
