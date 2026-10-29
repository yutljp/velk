//! Comments for instruction origins retained by the renderer.

use std::collections::BTreeMap;

pub(super) fn summary_returns(body: &str, ir: &crate::ir::FunctionIr) -> String {
    let mut at = None;
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if !matches!(stmt, crate::ir::Stmt::Ret { .. }) {
            continue;
        }
        let Some(origin) = stmt.origin() else {
            return body.to_owned();
        };
        if at.is_some_and(|at| at != origin) {
            return body.to_owned();
        }
        at = Some(origin);
    }
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        out.push_str(line);
        out.push('\n');
        if line.trim_start().starts_with("return ") {
            append(&mut out, at, true);
        }
    }
    out
}

/// Maps one-based lines of pseudo-C to the hexadecimal addresses in their comments.
/// Strings, character literals and comments with other contents are excluded.
#[must_use]
pub fn instruction_addresses(code: &str) -> BTreeMap<usize, Vec<String>> {
    let bytes = code.as_bytes();
    let mut result: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut position = 0;
    let mut line = 1;
    while position < bytes.len() {
        match bytes[position] {
            b'\n' => line += 1,
            quote @ (b'"' | b'\'') => {
                position += 1;
                while position < bytes.len() {
                    match bytes[position] {
                        b'\\' => {
                            if bytes.get(position + 1) == Some(&b'\n') {
                                line += 1;
                            }
                            position = position.saturating_add(1);
                        }
                        byte if byte == quote => break,
                        b'\n' => line += 1,
                        _ => {}
                    }
                    position = position.saturating_add(1);
                }
            }
            b'/' if bytes.get(position + 1) == Some(&b'/') => {
                while position < bytes.len() && bytes[position] != b'\n' {
                    position += 1;
                }
                continue;
            }
            b'/' if bytes.get(position + 1) == Some(&b'*') => {
                let start = position + 2;
                let comment_line = line;
                position = start;
                while position < bytes.len()
                    && !(bytes[position] == b'*' && bytes.get(position + 1) == Some(&b'/'))
                {
                    if bytes[position] == b'\n' {
                        line += 1;
                    }
                    position += 1;
                }
                if let Some(digits) = code[start..position]
                    .strip_prefix(" 0x")
                    .and_then(|text| text.strip_suffix(' '))
                    && !digits.is_empty()
                    && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && let Ok(address) = u64::from_str_radix(digits, 16)
                {
                    let addresses = result.entry(comment_line).or_default();
                    let address = format!("0x{address:x}");
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                position = position.saturating_add(1);
            }
            _ => {}
        }
        position = position.saturating_add(1);
    }
    result
}

// Text rewrites must see ordinary C. Only unambiguous, unchanged lines retain an origin.
pub(super) fn reconcile(plain: &str, annotated: &str) -> String {
    let mut lines = plain.lines();
    let unchanged = annotated
        .lines()
        .all(|line| lines.next() == Some(line_origin(line).0))
        && lines.next().is_none();
    if unchanged {
        return annotated.to_owned();
    }
    let mut origins = BTreeMap::new();
    for line in annotated.lines() {
        let (text, at) = match split(line) {
            Some((text, address)) => {
                let digits = address
                    .strip_suffix(" */")
                    .expect("split checks the suffix");
                (text, u64::from_str_radix(digits, 16).ok())
            }
            None => (line, None),
        };
        origins
            .entry(text.trim())
            .and_modify(|known| {
                if *known != at {
                    *known = None;
                }
            })
            .or_insert(at);
    }
    let mut out = String::with_capacity(plain.len());
    for line in plain.lines() {
        out.push_str(line);
        out.push('\n');
        if let Some(at) = origins.get(line.trim()) {
            append(&mut out, *at, true);
        }
    }
    out
}

#[inline]
pub(super) fn append(out: &mut String, address: Option<u64>, enabled: bool) {
    let Some(address) = address.filter(|_| enabled) else {
        return;
    };
    if out.ends_with('\n') {
        out.pop();
        out.push_str(&format!(" /* 0x{address:x} */\n"));
    }
}

fn split(line: &str) -> Option<(&str, &str)> {
    let Some((code, address)) = line.rsplit_once(" /* 0x") else {
        return None;
    };
    let Some(digits) = address.strip_suffix(" */") else {
        return None;
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((code, address))
}

pub(super) fn line_origin(line: &str) -> (&str, Option<u64>) {
    let line = line.trim_end_matches('\n');
    match split(line) {
        Some((code, address)) => {
            let digits = address
                .strip_suffix(" */")
                .expect("split checks the suffix");
            (code, u64::from_str_radix(digits, 16).ok())
        }
        None => (line, None),
    }
}

pub(super) fn align(code: &str) -> String {
    let mut column = 0;
    for line in code.lines() {
        if let Some((text, address)) = split(line)
            && text.len().saturating_add(address.len()).saturating_add(6) <= 100
        {
            column = column.max(text.len());
        }
    }
    let mut out = String::with_capacity(code.len());
    for line in code.lines() {
        match split(line) {
            Some((text, address)) => {
                out.push_str(text);
                let padding = if column.saturating_add(address.len()).saturating_add(6) <= 100 {
                    column.saturating_sub(text.len())
                } else {
                    0
                };
                for _ in 0..padding {
                    out.push(' ');
                }
                out.push_str(" /* 0x");
                out.push_str(address);
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Expr, FunctionIr, Stmt};
    use crate::loader::Isa;
    use crate::render::{FunctionSymbols, Symbols};

    #[test]
    fn conditional_break_keeps_the_branch_origin_and_executes_as_c() {
        use std::fs;
        use std::process::Command;

        use crate::ir::{BinOp, Block, CType, Cond, Param, RegRef};

        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.addr = 0x1000;
        ir.name = Some("loop_effect".into());
        ir.params = vec![
            Param {
                index: 7,
                name: "value".into(),
                ty: CType::U64,
            },
            Param {
                index: 6,
                name: "pointer".into(),
                ty: CType::pointer_to(CType::U32),
            },
        ];
        let mut tail = Vec::new();
        for offset in 0..8 {
            tail.push(Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(offset * 4)),
                value: Expr::Const(offset),
                width: 4,
                at: Some(0x1040 + offset * 4),
            });
        }
        tail.push(Stmt::Ret {
            value: Expr::reg(7, 64),
            at: Some(0x1060),
        });
        ir.blocks = vec![
            Block {
                start: 0x1000,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(7, 64),
                    rhs: Expr::Const(0),
                    target: 0x1040,
                    at: Some(0x1005),
                }],
            },
            Block {
                start: 0x1010,
                stmts: vec![
                    Stmt::Store {
                        addr: Expr::reg(6, 64),
                        value: Expr::Const(1),
                        width: 4,
                        at: Some(0x1010),
                    },
                    Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: Expr::reg(7, 64),
                        rhs: Expr::Const(7),
                        target: 0x1040,
                        at: Some(0x1015),
                    },
                ],
            },
            Block {
                start: 0x1020,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: 7,
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Sub, Expr::reg(7, 64), Expr::Const(1)),
                        at: Some(0x1020),
                    },
                    Stmt::Br {
                        target: Some(0x1000),
                        at: Some(0x1025),
                    },
                ],
            },
            Block {
                start: 0x1040,
                stmts: tail,
            },
        ];
        let symbols = Symbols::default();
        let mut view = FunctionSymbols::new(&symbols);
        view.addresses = true;
        let rendered = crate::render::function::render_with_symbols(&ir, &[], &view, &[]);
        assert!(
            rendered.code.lines().any(
                |line| line.trim_start().starts_with("break;") && line.contains("/* 0x1015 */")
            ),
            "{}",
            rendered.code
        );
        let mut source = crate::render::combine(&rendered.code);
        source.push_str("int main(void) { for (unsigned value = 0; value < 16; ++value) { uint32_t words[8] = {0}; if (loop_effect(value, words) != (value >= 7 ? 7 : 0)) return 1; for (unsigned i = 0; i < 8; ++i) if (words[i] != i) return 2; } return 0; }\n");
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/instruction-address-loop");
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("loop.c");
        let executable = directory.join("loop");
        fs::write(&input, source).unwrap();
        let compiled = Command::new("clang")
            .args(["-std=c11", "-Werror=implicit-function-declaration"])
            .arg(&input)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}");
        assert!(Command::new(executable).status().unwrap().success());
    }

    #[test]
    fn summaries_require_one_return_origin_on_every_path() {
        let body = "    return strlen(text);\n";
        for (other, expected) in [(Some(0x20), Some(0x20)), (Some(0x30), None), (None, None)] {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Ret {
                        value: Expr::Const(0),
                        at: Some(0x20),
                    },
                    Stmt::Ret {
                        value: Expr::Const(1),
                        at: other,
                    },
                ],
            );
            assert_eq!(line_origin(&summary_returns(body, &ir)).1, expected);
        }
    }

    #[test]
    fn map_skips_literals_and_preserves_line_numbers_and_full_addresses() {
        let code = "puts(\" /* 0x42 */\"); /* 0x0 */ /* annotation */\n// /* 0x43 */\nreturn 7; /* 0xffffffffffffffff */\n/* 0x10000000000000000 */\n";
        assert_eq!(
            instruction_addresses(code),
            BTreeMap::from([
                (1, vec!["0x0".to_owned()]),
                (3, vec!["0xffffffffffffffff".to_owned()]),
            ])
        );
    }

    #[test]
    fn text_rewrites_preserve_only_unambiguous_lines() {
        let plain = "x = 1;\nx = 1;\ny = 2;\nz = 3;\n";
        let annotated = "x = 1; /* 0x1 */\nx = 1; /* 0x2 */\ny = 2; /* 0x3 */\n";
        assert_eq!(
            reconcile(plain, annotated),
            "x = 1;\nx = 1;\ny = 2; /* 0x3 */\nz = 3;\n"
        );
        assert_eq!(reconcile("x = 1;\nx = 1;\ny = 2;\n", annotated), annotated);
    }

    #[test]
    fn zero_and_maximum_origins_survive_rendering_and_unknown_stays_absent() {
        let symbols = Symbols::default();
        let mut view = FunctionSymbols::new(&symbols);
        for at in [None, Some(0), Some(u64::MAX)] {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: Expr::Const(7),
                    at,
                }],
            );
            view.addresses = false;
            let plain = crate::render::function::render_with_symbols(&ir, &[], &view, &[]);
            view.addresses = true;
            let annotated = crate::render::function::render_with_symbols(&ir, &[], &view, &[]);
            match at {
                Some(address) => assert!(
                    annotated
                        .code
                        .contains(&format!("return 7; /* 0x{address:x} */")),
                    "{}",
                    annotated.code
                ),
                None => assert_eq!(annotated, plain),
            }
            assert!(!plain.code.contains("/* 0x"));
        }
    }

    #[test]
    fn comments_align_when_they_fit_and_wide_statements_keep_one_space() {
        let wide = "x".repeat(100);
        let input = format!(
            "    return 0; /* 0x0 */\n    value = 7; /* 0xffff */\n{wide}; /* 0x8 */\n}}\n"
        );
        let output = align(&input);
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines[0].find("/*"), lines[1].find("/*"));
        assert_eq!(lines[2], format!("{wide}; /* 0x8 */"));
        assert_eq!(lines[3], "}");
    }
}
