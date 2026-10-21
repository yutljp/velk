//! Every fixture's analysis output, compared with the files under tests/golden/fixtures/.
//! After an intended change, regenerate them with `VELK_BLESS=1 cargo test --test golden`
//! and review the diff before committing it. Counts of what makes the output
//! harder to read, over every function, are kept in tests/golden/readability.txt.

mod common;

use std::fmt::Write as _;
use std::path::Path;

use velk::loader::Function;
use velk::service::Binary;

#[test]
fn analysis_output_matches_golden_files() {
    let golden_dir = common::root().join("tests/golden/fixtures");
    let fixtures = common::fixtures();
    let rendered = common::in_parallel(&fixtures, |fixture| {
        render_fixture(&common::fixtures_dir().join(fixture), fixture)
    });
    let mut failures = Vec::new();
    let mut expected_files = Vec::new();
    let mut readability = String::from(
        "# fixture: output lines, declared variables, casts, register names, \
         unsigned comments, traps, gotos, indirect calls\n",
    );
    for (fixture, (actual, counts)) in fixtures.iter().zip(rendered) {
        writeln!(readability, "{}: {counts}", fixture.display()).expect("writing to a String");
        let golden = golden_dir.join(format!("{}.txt", fixture.display()));
        if let Some(difference) = common::check_expected(&golden, &actual) {
            failures.push(difference);
        }
        expected_files.push(golden);
    }
    failures.extend(stale_files(&golden_dir, &expected_files));
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/readability.txt"),
        &readability,
    ));
    assert!(
        failures.is_empty(),
        "{} golden file(s) differ; rerun with VELK_BLESS=1 after checking the change:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Golden files whose fixture no longer exists; blessing removes them.
fn stale_files(dir: &Path, expected: &[std::path::PathBuf]) -> Vec<String> {
    let mut stale = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if !expected.contains(&path) {
                if common::blessing() {
                    std::fs::remove_file(&path)
                        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                } else {
                    stale.push(format!("{}: no fixture produces this file", path.display()));
                }
            }
        }
    }
    stale
}

fn render_fixture(path: &Path, fixture: &Path) -> (String, Readability) {
    let mut binary = Binary::open(path).unwrap_or_else(|error| panic!("{error}"));
    let functions: Vec<Function> = binary.image().functions.values().cloned().collect();
    let mut out = String::new();
    let mut lift_failures = 0;
    let mut unsupported = 0;
    let mut gotos = 0;
    let mut readability = Readability::default();
    let mut details = String::new();
    for function in &functions {
        let decompiled = match binary.decompile(function.addr, None) {
            Ok(text) => text,
            Err(error) => {
                lift_failures += 1;
                format!("error: {error}\n")
            }
        };
        unsupported += decompiled.matches("/* unsupported").count();
        gotos += decompiled.matches("goto ").count();
        readability.add(&decompiled);
        if recorded(fixture, function) {
            details.push_str(&render_function(&mut binary, function, &decompiled));
        }
    }
    let image = binary.image();
    writeln!(
        out,
        "# {}: {} {} {}, {} functions, {} lift failures, {} unsupported, {} gotos",
        fixture.display(),
        image.format,
        image.isa,
        image
            .entry
            .map_or("no entry".to_owned(), velk::addr::format),
        functions.len(),
        lift_failures,
        unsupported,
        gotos
    )
    .expect("writing to a String");
    for function in &functions {
        let sources: Vec<String> = function.sources.iter().map(ToString::to_string).collect();
        writeln!(
            out,
            "{} {} {} {}",
            velk::addr::format(function.addr),
            function
                .size
                .map_or("?".to_owned(), |size| size.to_string()),
            function.name.as_deref().unwrap_or("-"),
            sources.join(",")
        )
        .expect("writing to a String");
    }
    out.push_str(&details);
    (out, readability)
}

/// What makes pseudo-C harder to read, counted over a fixture's functions.
#[derive(Default)]
struct Readability {
    lines: usize,
    variables: usize,
    casts: usize,
    registers: usize,
    unsigned: usize,
    traps: usize,
    gotos: usize,
    indirect_calls: usize,
}

impl Readability {
    fn add(&mut self, decompiled: &str) {
        for line in decompiled.lines() {
            self.lines += 1;
            let code = line.split("/*").next().unwrap_or("");
            if is_declaration(code) {
                self.variables += 1;
            }
            self.casts += casts(code);
            self.indirect_calls += indirect_calls(code);
            self.registers += code
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| is_register(word))
                .count();
        }
        self.unsigned += decompiled.matches("/* unsigned */").count();
        self.traps += decompiled.matches("__builtin_trap").count();
        self.gotos += decompiled.matches("goto ").count();
    }
}

impl std::fmt::Display for Readability {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} lines, {} variables, {} casts, {} registers, {} unsigned, {} traps, {} gotos, \
             {} indirect calls",
            self.lines,
            self.variables,
            self.casts,
            self.registers,
            self.unsigned,
            self.traps,
            self.gotos,
            self.indirect_calls
        )
    }
}

/// A local declaration such as `int32_t v1;` or `uint8_t local_0[16];`.
fn is_declaration(code: &str) -> bool {
    let Some(body) = code.strip_prefix("    ") else {
        return false;
    };
    let Some(body) = body.trim_end().strip_suffix(';') else {
        return false;
    };
    if body.starts_with(' ') || body.contains(['=', '(']) {
        return false;
    }
    let name = body
        .rsplit([' ', '*'])
        .next()
        .unwrap_or("")
        .split('[')
        .next()
        .unwrap_or("");
    body.contains(' ')
        && (name.strip_prefix('v').or(name.strip_prefix("local_")))
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Casts to a scalar, pointer or structure type, such as `(int8_t)` or `(struct s1 *)`.
fn casts(code: &str) -> usize {
    code.match_indices('(')
        .filter(|&(start, _)| {
            let rest = &code[start + 1..];
            let Some(end) = rest.find(')') else {
                return false;
            };
            let inner = rest[..end].trim_end_matches([' ', '*']);
            inner.ends_with("_t")
                && inner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || inner.starts_with("struct ")
                || matches!(inner, "float" | "double" | "bool" | "char")
        })
        .count()
}

/// Calls through a pointer the analysis could not resolve, printed
/// `((uint64_t (*)())address)(arguments)`.
fn indirect_calls(code: &str) -> usize {
    code.matches("((uint64_t (*)())").count()
}

/// A machine register name left in the output instead of a variable.
fn is_register(word: &str) -> bool {
    const X86: [&str; 16] = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "eax", "ebx", "ecx", "edx", "esi",
        "edi", "r8", "r9",
    ];
    let numbered = |prefix: &str, range: std::ops::Range<u32>| {
        word.strip_prefix(prefix).is_some_and(|digits| {
            (digits == "0" || !digits.starts_with('0'))
                && digits.parse::<u32>().is_ok_and(|n| range.contains(&n))
        })
    };
    X86.contains(&word)
        || numbered("r", 10..16)
        || numbered("xmm", 0..16)
        || numbered("x", 0..31)
        || numbered("w", 0..31)
}

/// Go and Rust executables carry thousands of runtime functions; only the
/// test program's own functions are recorded in full.
fn recorded(fixture: &Path, function: &Function) -> bool {
    let name = fixture.to_string_lossy();
    let symbol = function.name.as_deref().unwrap_or("");
    if name.starts_with("go_") {
        symbol.starts_with("main.")
    } else if name.starts_with("rust_") {
        symbol.contains("rust_demo::") || symbol.contains("rust_probe::")
    } else {
        true
    }
}

fn render_function(binary: &mut Binary, function: &Function, decompiled: &str) -> String {
    let mut out = format!(
        "\n== {} {}\n-- decompile\n{decompiled}",
        velk::addr::format(function.addr),
        function.name.as_deref().unwrap_or("-")
    );
    if let Ok(analysis) = binary.analysis(function.addr) {
        let ir = &analysis.ir;
        let params: Vec<String> = ir
            .params
            .iter()
            .map(|p| format!("{} {}", p.ty, p.name))
            .collect();
        let references: Vec<String> = analysis.references.iter().map(|r| r.describe()).collect();
        write!(
            out,
            "-- signature\n{} ({})\n-- references\n{}\n-- ir\n{}",
            ir.ret_type,
            params.join(", "),
            references.join("\n"),
            ir.render()
        )
        .expect("writing to a String");
    }
    let mut card = serde_json::to_value(
        binary
            .card(function.addr, velk::card::DEFAULT_BUDGET, None)
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .expect("a card serializes");
    if let Some(fields) = card.as_object_mut() {
        fields.remove("disasmPreview");
    }
    writeln!(out, "-- card\n{card}").expect("writing to a String");
    out
}
