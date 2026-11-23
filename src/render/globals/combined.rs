use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, PartialEq)]
struct Declaration {
    address: u64,
    ty: String,
    name: String,
    array: bool,
}

impl Declaration {
    fn parse(line: &str) -> Option<Self> {
        let Some(line) = line.strip_prefix("extern ") else {
            return None;
        };
        let Some((declaration, address)) = line.split_once("; /* address: 0x") else {
            return None;
        };
        let Some(address) = address.strip_suffix(" */") else {
            return None;
        };
        let Ok(address) = u64::from_str_radix(address, 16) else {
            return None;
        };
        let Some((ty, name)) = declaration.rsplit_once(' ') else {
            return None;
        };
        Some(Self {
            address,
            ty: ty.to_owned(),
            name: name.trim_end_matches("[]").to_owned(),
            array: name.ends_with("[]"),
        })
    }

    fn pointer(&self) -> String {
        if self.array {
            self.name.clone()
        } else {
            format!("(&{})", self.name)
        }
    }

    fn rank(&self) -> u8 {
        match self.ty.as_str() {
            "uint8_t" | "int8_t" | "char" | "unsigned char" | "signed char" => 1,
            "uint16_t" | "int16_t" | "short" | "unsigned short" => 2,
            "uint32_t" | "int32_t" | "int" | "unsigned int" | "float" => 4,
            "uint64_t" | "int64_t" | "double" => 8,
            _ => 16,
        }
    }
}

/// The text of one function with the globals it declares. The text is the
/// lines it was given, each ended by a newline: a part of the code they
/// come from while they follow one another there ended that way.
#[derive(Default)]
struct Body<'code> {
    text: std::borrow::Cow<'code, str>,
    declarations: Vec<Declaration>,
}

impl<'code> Body<'code> {
    fn push(&mut self, code: &'code str, line: &'code str) {
        let start = line.as_ptr() as usize - code.as_ptr() as usize;
        let end = start + line.len();
        let ended = code.as_bytes().get(end) == Some(&b'\n');
        match self.text {
            _ if ended && self.text.is_empty() => {
                self.text = std::borrow::Cow::Borrowed(&code[start..=end]);
            }
            std::borrow::Cow::Borrowed(text)
                if ended && text.as_ptr() as usize + text.len() == line.as_ptr() as usize =>
            {
                self.text = std::borrow::Cow::Borrowed(&code[start - text.len()..=end]);
            }
            _ => {
                let text = self.text.to_mut();
                text.push_str(line);
                text.push('\n');
            }
        }
    }
}

// A standalone function may infer a different access type from another
// function. Resolve those declarations before their support sections merge.
pub(in crate::render) fn resolve(code: &str) -> String {
    let mut globals = BTreeMap::<u64, Declaration>::new();
    let mut conflicts = false;
    for line in code.lines() {
        let Some(declaration) = Declaration::parse(line) else {
            continue;
        };
        if let Some(previous) = globals.get_mut(&declaration.address) {
            conflicts |= *previous != declaration;
            if declaration.rank() > previous.rank() {
                previous.ty.clone_from(&declaration.ty);
            }
            previous.array |= declaration.array;
            if declaration.name.len() < previous.name.len() {
                previous.name.clone_from(&declaration.name);
            }
        } else {
            globals.insert(declaration.address, declaration);
        }
    }
    let mut destinations = BTreeMap::new();
    let mut merged = BTreeMap::<u64, Declaration>::new();
    let mut end = 0;
    for (address, declaration) in globals {
        let width = if declaration.rank() == 16 {
            1
        } else {
            u64::from(declaration.rank())
        };
        let next_end = address.saturating_add(width);
        if address < end
            && let Some((base, global)) = merged.last_key_value()
        {
            let base = *base;
            let capacity = u64::from(global.rank());
            destinations.insert(address, (base, address - base));
            if declaration.array {
                merged
                    .get_mut(&base)
                    .expect("the last global is present")
                    .array = true;
            }
            if next_end.saturating_sub(base) > capacity {
                let global = merged.get_mut(&base).expect("the last global is present");
                global.ty = "uint8_t".to_owned();
                global.array = true;
            }
            end = end.max(next_end);
            conflicts = true;
        } else {
            destinations.insert(address, (address, 0));
            merged.insert(address, declaration);
            end = next_end;
        }
    }
    let mut globals = merged;
    if !conflicts {
        return code.to_owned();
    }

    let mut bodies = Vec::new();
    let mut body = Body::default();
    let mut support = String::new();
    let mut in_support = false;
    let mut pending = Vec::new();
    for line in code.lines() {
        if line == "/* velk prelude */" {
            if !body.text.is_empty() {
                bodies.push(body);
                body = Body::default();
            }
            in_support = true;
            support.push('\n');
        } else if line == "/* end velk prelude */" {
            in_support = false;
            support.push('\n');
        } else if in_support {
            if let Some(declaration) = Declaration::parse(line) {
                pending.push(declaration);
            } else {
                support.push_str(line);
                support.push('\n');
            }
        } else {
            if line.starts_with("/* velk pseudo-C:") {
                bodies.push(body);
                body = Body {
                    declarations: std::mem::take(&mut pending),
                    ..Body::default()
                };
            } else if !pending.is_empty() {
                body.declarations.append(&mut pending);
            }
            body.push(code, line);
        }
    }
    bodies.push(body);
    // The words of the bodies stay where they are: there is one for every
    // few bytes of the output. `reserved` holds the rest.
    let mut reserved = HashSet::new();
    for word in support.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
        reserved.insert(word.to_owned());
    }
    let mut words = HashSet::new();
    for body in &bodies {
        for word in body
            .text
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        {
            if !words.contains(word)
                && !body
                    .declarations
                    .iter()
                    .any(|declaration| declaration.name == word)
            {
                words.insert(word);
            }
        }
    }
    for global in globals.values_mut() {
        let base = global.name.clone();
        if words.contains(global.name.as_str()) || reserved.contains(&global.name) {
            global.name = format!("{base}_{:x}", global.address);
        }
        let candidate = global.name.clone();
        let mut suffix = 2;
        while words.contains(global.name.as_str()) || !reserved.insert(global.name.clone()) {
            global.name = format!("{candidate}_{suffix}");
            suffix += 1;
        }
        let array = if global.array { "[]" } else { "" };
        support.push_str(&format!(
            "\nextern {} {}{array}; /* address: 0x{:x} */\n\n",
            global.ty, global.name, global.address
        ));
    }
    // No more than the input holds, and allocated in one piece, so that
    // the buffer of the text this one was made from can be used again.
    let support = crate::render::prelude::section(&support);
    let mut output = String::with_capacity(code.len().max(support.len()));
    output.push_str(&support);
    drop(support);
    for body in bodies {
        let mut replacements = HashMap::new();
        for declaration in body.declarations {
            let (base, offset) = destinations[&declaration.address];
            let global = &globals[&base];
            let pointer =
                super::view_pointer(&global.pointer(), &global.ty, &declaration.ty, offset);
            let value = if declaration.array {
                pointer.clone()
            } else if offset == 0 && declaration.ty == global.ty && !global.array {
                global.name.clone()
            } else if offset == 0 && declaration.ty == global.ty {
                format!("{}[0]", global.name)
            } else {
                format!("(*{pointer})")
            };
            replacements.insert(format!("(&{})", declaration.name), pointer.clone());
            replacements.insert(format!("*(&{})", declaration.name), format!("(*{pointer})"));
            replacements.insert(format!("{}[", declaration.name), format!("{value}["));
            replacements.insert(declaration.name, value);
        }
        output.push_str(&super::replace_expressions(&body.text, &replacements));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn lines_that_follow_one_another_stay_part_of_the_code() {
        let code = "first\n\nsecond\nskipped\nthird\r\nlast";
        let lines: Vec<_> = code.lines().collect();
        let mut body = Body::default();
        for line in &lines[..3] {
            body.push(code, line);
        }
        assert!(matches!(body.text, Cow::Borrowed("first\n\nsecond\n")));
        // A line taken from further on, one ended another way and one the
        // code does not end are copied with the newline they are given.
        let mut apart = Body::default();
        apart.push(code, lines[0]);
        apart.push(code, lines[3]);
        assert!(matches!(&apart.text, Cow::Owned(text) if text == "first\nskipped\n"));
        let mut returned = Body::default();
        returned.push(code, lines[4]);
        assert!(matches!(&returned.text, Cow::Owned(text) if text == "third\n"));
        let mut unended = Body::default();
        unended.push(code, lines[5]);
        assert!(matches!(&unended.text, Cow::Owned(text) if text == "last\n"));
    }
}
