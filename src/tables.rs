//! Exact signatures for standard constant tables and decoded immediate groups.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Instant;

use memchr::memmem::Finder;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::deadline::passed;
use crate::error::Result;
use crate::loader::Image;
use crate::service::Binary;

#[derive(Deserialize)]
struct Signature {
    name: String,
    width: usize,
    values: Vec<String>,
    immediates: bool,
}

struct Pattern {
    name: String,
    immediates: bool,
    words: Vec<u64>,
    bytes: Vec<u8>,
    order: &'static str,
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let signatures: Vec<Signature> =
            serde_json::from_str(include_str!("tables/signatures.json"))
                .expect("built-in signatures are valid JSON");
        let mut patterns = Vec::new();
        for signature in signatures {
            assert!(
                matches!(signature.width, 1 | 2 | 4 | 8),
                "built-in word widths are valid"
            );
            let words: Vec<u64> = signature
                .values
                .iter()
                .map(|word| u64::from_str_radix(word, 16).expect("built-in words are hexadecimal"))
                .collect();
            assert!(!words.is_empty(), "built-in signatures are nonempty");
            for little in [true, false] {
                if !little && signature.width == 1 {
                    continue;
                }
                let mut bytes = Vec::new();
                for word in &words {
                    if little {
                        bytes.extend_from_slice(&word.to_le_bytes()[..signature.width]);
                    } else {
                        bytes.extend_from_slice(&word.to_be_bytes()[8 - signature.width..]);
                    }
                }
                patterns.push(Pattern {
                    name: signature.name.clone(),
                    immediates: signature.immediates,
                    words: words.clone(),
                    bytes,
                    order: if signature.width == 1 {
                        "bytes"
                    } else if little {
                        "little"
                    } else {
                        "big"
                    },
                });
            }
        }
        patterns
    })
}

pub(crate) struct DataMatch {
    pub name: &'static str,
    pub address: u64,
    pub size: u64,
    section: String,
    order: &'static str,
}

pub(crate) fn data(image: &Image, deadline: Option<Instant>) -> Result<Vec<DataMatch>> {
    let mut result = Vec::new();
    for section in &image.sections {
        // Instruction encodings are searched as decoded immediates instead.
        if section.executable {
            continue;
        }
        let Some(bytes) = crate::memory::section_bytes(image, section) else {
            continue;
        };
        for pattern in patterns() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            if bytes.len() < pattern.bytes.len() {
                continue;
            }
            let finder = Finder::new(&pattern.bytes);
            let mut start = 0usize;
            while start < bytes.len() {
                if let Err(error) = passed(deadline) {
                    return Err(error);
                }
                let Some(found) = finder.find(&bytes[start..]) else {
                    break;
                };
                let Some(offset) = start.checked_add(found) else {
                    break;
                };
                start = match offset.checked_add(1) {
                    Some(start) => start,
                    None => break,
                };
                let Some(address) = section.vaddr.checked_add(offset as u64) else {
                    continue;
                };
                result.push(DataMatch {
                    name: &pattern.name,
                    address,
                    size: pattern.bytes.len() as u64,
                    section: section.name.clone(),
                    order: pattern.order,
                });
            }
        }
    }
    // A longer exact match supplies the unambiguous name for shared prefixes.
    result.sort_by_key(|matched| {
        (
            matched.address,
            std::cmp::Reverse(matched.size),
            matched.name,
        )
    });
    Ok(result)
}

pub(crate) fn names(image: &Image) -> BTreeMap<u64, String> {
    let mut names = BTreeMap::new();
    let Ok(matches) = data(image, None) else {
        return names;
    };
    for matched in matches {
        names
            .entry(matched.address)
            .or_insert_with(|| matched.name.to_owned());
    }
    names
}

pub(crate) fn detect(binary: &mut Binary, deadline: Option<Instant>) -> Result<Value> {
    let data = match data(binary.image(), deadline) {
        Ok(data) => data,
        Err(error) => return Err(error),
    };
    let immediates = match crate::xrefs::constants::all(binary.image(), deadline) {
        Ok(values) => values,
        Err(error) => return Err(error),
    };
    let index = match binary.navigation(deadline) {
        Ok(index) => index,
        Err(error) => return Err(error),
    };
    let mut matches = Vec::new();
    for matched in data {
        let functions: BTreeSet<_> = index
            .xrefs
            .iter()
            .filter(|xref| {
                xref.target >= matched.address && xref.target - matched.address < matched.size
            })
            .map(|xref| crate::addr::format(xref.function))
            .collect();
        matches.push(json!({ "name": matched.name, "addr": crate::addr::format(matched.address), "size": matched.size, "section": matched.section, "byteOrder": matched.order, "kind": "data", "functions": functions }));
    }
    let mut by_function = BTreeMap::<u64, BTreeMap<u64, u64>>::new();
    for immediate in immediates {
        if let Some(function) = immediate.function {
            by_function
                .entry(function)
                .or_default()
                .entry(immediate.value)
                .or_insert(immediate.instruction);
        }
    }
    for pattern in patterns() {
        if !pattern.immediates || pattern.order != "little" {
            continue;
        }
        for (function, values) in &by_function {
            if !pattern.words.iter().all(|word| values.contains_key(word)) {
                continue;
            }
            let address = pattern
                .words
                .iter()
                .filter_map(|word| values.get(word))
                .min()
                .copied()
                .expect("a nonempty matched immediate group");
            matches.push(json!({ "name": pattern.name, "addr": crate::addr::format(address), "size": pattern.bytes.len(), "section": Value::Null, "byteOrder": Value::Null, "kind": "immediates", "functions": [crate::addr::format(*function)] }));
        }
    }
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    Ok(json!({ "matches": matches, "failures": index.failures }))
}

#[cfg(test)]
mod tests;
