//! Data-reference recovery: string literals and code/data targets.

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::loader::Image;

const MAX_STRING: u64 = 96;

/// Constants up to this are taken for numbers rather than addresses.
const SMALL_CONSTANT: u64 = 0x10000;

#[derive(Debug, Clone)]
pub struct Reference {
    pub addr: u64,
    pub section: String,
    pub text: Option<String>,
    pub pointer: Option<u64>,
    /// Matching Windows header GUID identifiers and their exact bytes.
    pub guid: Option<super::prototypes::LibraryGuid>,
}

impl Reference {
    #[must_use]
    pub fn describe(&self) -> String {
        if let Some(guid) = &self.guid {
            return format!(
                "0x{:x} {} ({})",
                self.addr,
                guid.names.join(" / "),
                guid.value
            );
        }
        match (&self.text, self.pointer) {
            (Some(text), Some(pointer)) => {
                format!("0x{:x} -> 0x{pointer:x} \"{}\"", self.addr, escape(text))
            }
            (Some(text), None) => format!("0x{:x} \"{}\"", self.addr, escape(text)),
            (None, _) => format!("0x{:x} {}", self.addr, self.section),
        }
    }
}

fn escape(text: &str) -> String {
    text.chars().flat_map(|c| c.escape_default()).collect()
}

fn strings_at(image: &Image, addr: u64) -> Option<String> {
    let Some(section) = image.section_at(addr) else {
        return None;
    };
    if section.executable || !section.read_only {
        return None;
    }
    let Some(bytes) = image.read_vaddr(addr, MAX_STRING) else {
        return None;
    };
    let Some(end) = bytes.iter().position(|b| *b == 0) else {
        return None;
    };
    if end < 3 {
        return None;
    }
    let text = &bytes[..end];
    if !text.iter().all(|b| (0x20..0x7f).contains(b) || *b == b'\t') {
        return None;
    }
    Some(String::from_utf8_lossy(text).into_owned())
}

#[must_use]
pub fn name_hints(strings: &[String]) -> Vec<String> {
    let mut hints = Vec::new();
    for text in strings {
        let slug: String = text
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        let slug = slug.trim_matches('_').to_owned();
        if slug.len() >= 3 && !hints.contains(&slug) {
            hints.push(slug);
        }
        if hints.len() >= 4 {
            break;
        }
    }
    hints
}

pub fn collect(ir: &FunctionIr, image: &Image) -> Vec<Reference> {
    let mut candidates = Vec::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { value, .. } => expr_constants(value, &mut candidates),
                Stmt::Store { addr, value, .. } => {
                    expr_constants(addr, &mut candidates);
                    expr_constants(value, &mut candidates);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    expr_constants(lhs, &mut candidates);
                    expr_constants(rhs, &mut candidates);
                }
                Stmt::Ret { value } => expr_constants(value, &mut candidates),
                Stmt::BrIndirect { target } => expr_constants(target, &mut candidates),
                Stmt::Switch { index, .. } => expr_constants(index, &mut candidates),
                Stmt::Call { .. } => {
                    for value in stmt.operands() {
                        expr_constants(value, &mut candidates);
                    }
                }
                _ => {}
            }
        }
    }

    candidates.sort_unstable();
    candidates.dedup();

    let mut references = Vec::new();
    for addr in candidates {
        let Some(section) = image.section_at(addr) else {
            continue;
        };
        let guid = super::prototypes::guid_at(image, addr);
        let mut text = if guid.is_none() {
            strings_at(image, addr)
        } else {
            None
        };
        let mut pointer = None;
        if text.is_none()
            && guid.is_none()
            && !section.executable
            && let Some(bytes) = image.read_vaddr(addr, 8)
        {
            let target = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if target != 0
                && image.section_at(target).is_some()
                && let Some(resolved) = strings_at(image, target)
            {
                text = Some(resolved);
                pointer = Some(target);
            }
        }
        if text.is_none() && section.executable {
            continue;
        }
        references.push(Reference {
            addr,
            section: section.name.clone(),
            text,
            pointer,
            guid,
        });
    }
    // A call passing a pointer and a length, as Go and Rust pass a string,
    // names that many characters, which need end in no zero byte. A small
    // constant where the callee takes a pointer, or a format string, points
    // at a string in read-only data too, as in a position-independent
    // executable whose data starts low.
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let Stmt::Call {
            args: Some(args),
            target,
            through,
            ..
        } = stmt
        else {
            continue;
        };
        let prototype = target
            .and_then(|target| image.functions.get(&target))
            .and_then(|function| function.name.as_deref())
            .or_else(|| crate::lift::import_name(image, through.as_ref()?))
            .and_then(|name| crate::analysis::prototypes::for_image(name, image));
        // A parameter the prototype declares a C string ends at its zero byte,
        // whatever argument follows it.
        let c_string = |position: usize| {
            prototype.is_some_and(|prototype| {
                prototype.params.get(position).is_some_and(|ty| {
                    matches!(ty.to_string().trim_end(), "const char *" | "char *")
                })
            })
        };
        let named = prototype
            .and_then(|prototype| prototype.format)
            .map_or(0, |format| 1u64 << format.min(63));
        let strings = (0..64)
            .filter(|position| c_string(*position))
            .fold(0, |mask, position| mask | 1u64 << position);
        let pointers = named
            | strings
            | target.map_or(0, |target| {
                u64::from(crate::analysis::summary::summary(image, target).pointers)
            });
        for (position, arg) in args.iter().enumerate().take(64) {
            let Expr::Const(addr) = arg else {
                continue;
            };
            if pointers & 1 << position == 0
                || references
                    .iter()
                    .any(|known| known.addr == *addr && known.text.is_some())
            {
                continue;
            }
            let Some(section) = image.section_at(*addr) else {
                continue;
            };
            let read_only = string_section(&section.name);
            if !read_only {
                continue;
            }
            if super::prototypes::guid_at(image, *addr).is_some() {
                continue;
            }
            if let Some(text) = strings_at(image, *addr) {
                references.retain(|known| known.addr != *addr);
                references.push(Reference {
                    addr: *addr,
                    section: section.name.clone(),
                    text: Some(text),
                    pointer: None,
                    guid: None,
                });
            }
        }
        for (position, pair) in args.windows(2).enumerate() {
            let (Expr::Const(addr), Expr::Const(length)) = (&pair[0], &pair[1]) else {
                continue;
            };
            if c_string(position) {
                continue;
            }
            let known = references.iter().position(|known| known.addr == *addr);
            if known.is_some_and(|known| {
                references[known].text.is_some() || references[known].guid.is_some()
            }) {
                continue;
            }
            let Some((section, text)) = sized_string(image, *addr, *length) else {
                continue;
            };
            match known {
                Some(known) => references[known].text = Some(text),
                None => references.push(Reference {
                    addr: *addr,
                    section,
                    text: Some(text),
                    pointer: None,
                    guid: super::prototypes::guid_at(image, *addr),
                }),
            }
        }
    }
    references.sort_by_key(|reference| reference.addr);
    references
}

fn string_section(name: &str) -> bool {
    ["rodata", "rdata", "cstring", "__const"]
        .iter()
        .any(|kind| name.contains(kind))
}

/// The `length` printable characters at `addr` in data, when they are.
fn sized_string(image: &Image, addr: u64, length: u64) -> Option<(String, String)> {
    if !(2..=256).contains(&length) {
        return None;
    }
    // Only read-only data holds string literals; a size passed with a count
    // could fall anywhere else.
    let Some(section) = image.section_at(addr) else {
        return None;
    };
    let read_only = string_section(&section.name);
    if section.executable || !read_only {
        return None;
    }
    let Some(bytes) = image.read_vaddr(addr, length) else {
        return None;
    };
    if !bytes
        .iter()
        .all(|b| (0x20..0x7f).contains(b) || matches!(b, b'\t' | b'\n'))
    {
        return None;
    }
    Some((
        section.name.clone(),
        String::from_utf8_lossy(&bytes[..length as usize]).into_owned(),
    ))
}

fn expr_constants(expr: &Expr, out: &mut Vec<u64>) {
    match expr {
        Expr::Reg { .. } => {}
        Expr::Const(value) if *value > SMALL_CONSTANT => out.push(*value),
        Expr::Const(_) => {}
        Expr::Bin { lhs, rhs, .. } => {
            expr_constants(lhs, out);
            expr_constants(rhs, out);
        }
        Expr::Load { addr, .. } => expr_constants(addr, out),
        Expr::SignExtend { value, .. } => expr_constants(value, out),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            expr_constants(lhs, out);
            expr_constants(rhs, out);
            expr_constants(then, out);
            expr_constants(els, out);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                expr_constants(arg, out);
            }
        }
    }
}
