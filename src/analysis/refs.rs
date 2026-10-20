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
}

impl Reference {
    pub fn describe(&self) -> String {
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
    let section = image.section_at(addr)?;
    if section.executable {
        return None;
    }
    let bytes = image.read_vaddr(addr, MAX_STRING)?;
    let end = bytes.iter().position(|b| *b == 0)?;
    if end < 3 {
        return None;
    }
    let text = &bytes[..end];
    if !text.iter().all(|b| (0x20..0x7f).contains(b) || *b == b'\t') {
        return None;
    }
    Some(String::from_utf8_lossy(text).into_owned())
}

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
        let mut text = strings_at(image, addr);
        let mut pointer = None;
        if text.is_none()
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
            ..
        } = stmt
        else {
            continue;
        };
        let pointers = target.map_or(0, |target| {
            let named = image
                .functions
                .get(&target)
                .and_then(|function| function.name.as_deref())
                .and_then(|name| {
                    crate::analysis::prototypes::of(
                        name,
                        image.format == crate::loader::Format::MachO,
                    )
                })
                .and_then(|prototype| prototype.format)
                .map_or(0, |format| 1u64 << format.min(63));
            named | u64::from(crate::analysis::summary::summary(image, target).pointers)
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
            let read_only = ["rodata", "rdata", "cstring", "__const"]
                .iter()
                .any(|kind| section.name.contains(kind));
            if !read_only {
                continue;
            }
            if let Some(text) = strings_at(image, *addr) {
                references.retain(|known| known.addr != *addr);
                references.push(Reference {
                    addr: *addr,
                    section: section.name.clone(),
                    text: Some(text),
                    pointer: None,
                });
            }
        }
        for pair in args.windows(2) {
            let (Expr::Const(addr), Expr::Const(length)) = (&pair[0], &pair[1]) else {
                continue;
            };
            let known = references.iter().position(|known| known.addr == *addr);
            if known.is_some_and(|known| references[known].text.is_some()) {
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
                }),
            }
        }
    }
    references.sort_by_key(|reference| reference.addr);
    references
}

/// The `length` printable characters at `addr` in data, when they are.
fn sized_string(image: &Image, addr: u64, length: u64) -> Option<(String, String)> {
    if !(2..=256).contains(&length) {
        return None;
    }
    // Only read-only data holds string literals; a size passed with a count
    // could fall anywhere else.
    let section = image.section_at(addr)?;
    let read_only = ["rodata", "rdata", "cstring", "__const"]
        .iter()
        .any(|kind| section.name.contains(kind));
    if section.executable || !read_only {
        return None;
    }
    let bytes = image.read_vaddr(addr, length)?;
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
