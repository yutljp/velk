//! Every fixture's analysis output, compared with the files under tests/golden/fixtures/.
//! After an intended change, regenerate them with `VELK_BLESS=1 cargo test --test golden`
//! and review the diff before committing it. Counts of what makes the output
//! harder to read, over every function, are kept in tests/golden/readability.txt.

mod common;
#[path = "../src/render/cost.rs"]
mod cost;

use std::collections::{BTreeMap, BTreeSet};
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
        "# fixture: function lines, prelude lines, declared variables, casts, register names, \
         unsigned comments, traps, gotos, indirect calls\n",
    );
    let mut cast_counts = String::from(
        "# fixture: lines; memory pointer, byte pointer, other pointer, address integer, scalar casts\n",
    );
    let mut local_counts = String::from(
        "# fixture: initialized, stack, pointer, aggregate, scalar local declarations\n",
    );
    let mut structure_types =
        String::from("# fixture: distinct printed structure types across all functions\n");
    let mut groups: BTreeMap<String, (usize, usize, usize, usize, usize)> = BTreeMap::new();
    let mut shapes = String::new();
    for (fixture, (actual, counts)) in fixtures.iter().zip(rendered) {
        let total = groups.entry(counts.group.clone()).or_default();
        total.0 += counts.variables;
        total.1 += counts.casts;
        total.2 += counts.lines + counts.prelude_lines;
        total.3 += counts.gotos;
        total.4 += counts.tokens;
        shapes.push_str(&counts.shapes);
        writeln!(readability, "{}: {counts}", fixture.display()).expect("writing to a String");
        writeln!(
            structure_types,
            "{}: {}",
            fixture.display(),
            counts.structures.len()
        )
        .expect("writing to a String");
        writeln!(
            cast_counts,
            "{}: {} lines; {:?}",
            fixture.display(),
            counts.lines,
            counts.cast_classes
        )
        .expect("writing to a String");
        writeln!(
            local_counts,
            "{}: {:?}",
            fixture.display(),
            counts.local_classes
        )
        .expect("writing to a String");
        let golden = golden_dir.join(format!("{}.txt", fixture.display()));
        if let Some(difference) = common::check_expected(&golden, &actual) {
            failures.push(difference);
        }
        expected_files.push(golden);
    }
    let mut grouped =
        String::from("# group: locals, casts, total lines, gotos, card approxTokens\n");
    for (group, (locals, casts, lines, gotos, tokens)) in groups {
        writeln!(
            grouped,
            "{group}: {locals}, {casts}, {lines}, {gotos}, {tokens}"
        )
        .expect("writing to a String");
    }
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/variable_groups.txt"),
        &grouped,
    ));
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/variable_shapes.txt"),
        &shapes,
    ));
    failures.extend(stale_files(&golden_dir, &expected_files));
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/readability.txt"),
        &readability,
    ));
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/structure_types.txt"),
        &structure_types,
    ));
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/casts.txt"),
        &cast_counts,
    ));
    failures.extend(common::check_expected(
        &common::root().join("tests/golden/locals.txt"),
        &local_counts,
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
    let mut readability = Readability {
        group: common::fixture_group(fixture, binary.image()).to_owned(),
        ..Readability::default()
    };
    let mut details = String::new();
    let mut prelude = velk::render::Prelude::default();
    let mut details_prelude = velk::render::Prelude::default();
    for function in &functions {
        let decompiled = match binary.decompile(function.addr, None, None) {
            Ok(text) => text,
            Err(error) => {
                lift_failures += 1;
                format!("error: {error}\n")
            }
        };
        let standalone = decompiled;
        readability.add_structures(&standalone);
        let decompiled = prelude.extract(&standalone);
        unsupported += decompiled.matches("/* unsupported").count();
        gotos += decompiled.matches("goto ").count();
        readability.add(&decompiled);
        readability.tokens += binary
            .card(function.addr, velk::card::DEFAULT_BUDGET, None, None)
            .expect("fixture card")
            .approx_tokens;
        write!(
            readability.shapes,
            "{} {:#x}:",
            fixture.display(),
            function.addr
        )
        .expect("writing to a String");
        for line in decompiled.lines() {
            let text = line.trim();
            let text = text.strip_prefix("} ").unwrap_or(text);
            for token in [
                "if (",
                "else",
                "else if (",
                "for (",
                "while (",
                "do {",
                "switch (",
                "case ",
                "default:",
                "goto ",
                "break;",
                "continue;",
            ] {
                let found = text.starts_with(token) || (token == "goto " && text.contains(token));
                if found {
                    write!(
                        readability.shapes,
                        " {}{}",
                        line.len() - line.trim_start().len(),
                        token.trim()
                    )
                    .expect("writing to a String");
                }
            }
        }
        readability.shapes.push('\n');
        if recorded(fixture, function) {
            let decompiled = details_prelude.extract(&standalone);
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
    let prelude = prelude.render();
    readability.prelude_lines = prelude.lines().count();
    out.push_str(&details_prelude.render());
    out.push_str(&details);
    (out, readability)
}

/// What makes pseudo-C harder to read, counted over a fixture's functions.
#[derive(Default)]
struct Readability {
    tokens: usize,
    shapes: String,
    group: String,
    structures: BTreeSet<String>,
    lines: usize,
    prelude_lines: usize,
    variables: usize,
    local_classes: [usize; 5],
    casts: usize,
    cast_classes: [usize; 5],
    registers: usize,
    unsigned: usize,
    traps: usize,
    gotos: usize,
    indirect_calls: usize,
}

impl Readability {
    fn add_structures(&mut self, decompiled: &str) {
        let mut definition = None;
        for line in decompiled.lines() {
            if let Some(definition) = &mut definition {
                *definition += line;
            }
            if let Some((name, _)) = line
                .strip_prefix("struct ")
                .and_then(|line| line.split_once(" {"))
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                definition = Some(line.to_owned());
            }
            if line.trim_end().ends_with("};")
                && let Some(definition) = definition.take()
            {
                self.structures.insert(definition);
            }
        }
    }

    fn add(&mut self, decompiled: &str) {
        let mut in_function = false;
        for line in decompiled.lines() {
            if !line.starts_with(char::is_whitespace) {
                if line.ends_with(") {") {
                    in_function = true;
                } else if line == "}" {
                    in_function = false;
                }
            }
            self.lines += 1;
            let code = line.split("/*").next().unwrap_or("");
            if in_function
                && (is_declaration(code) || (line.contains("; /* [sp") && !code.contains('(')))
            {
                self.variables += 1;
                let class = if code.contains('=') {
                    0
                } else if line.contains("; /* [sp") {
                    1
                } else if code.contains('*') {
                    2
                } else if code.trim_start().starts_with("struct ")
                    || code.trim_start().starts_with("union ")
                    || code.contains('[')
                {
                    3
                } else {
                    4
                };
                self.local_classes[class] += 1;
            }
            self.casts += cost::casts(code);
            for (total, count) in self.cast_classes.iter_mut().zip(cast_classes(code)) {
                *total += count;
            }
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
            "{} lines, {} prelude lines, {} variables, {} casts, {} registers, {} unsigned, {} traps, {} gotos, \
             {} indirect calls",
            self.lines,
            self.prelude_lines,
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

/// A recovered local or an initialized scalar or pointer.
fn is_declaration(code: &str) -> bool {
    let Some(body) = code.strip_prefix("    ") else {
        return false;
    };
    let body = body.trim_start();
    if let Some(header) = body.strip_prefix("for (")
        && let Some((init, _)) = header.split_once(';')
    {
        return is_declaration(&format!("    {init};"));
    }
    if body.starts_with('{') || body.starts_with("return ") || body.starts_with("goto ") {
        return false;
    }
    if let Some((declaration, _)) = body.split_once('=') {
        if declaration.contains('[') {
            return false;
        }
        return is_declaration(&format!("    {};", declaration.trim_end()));
    }
    let Some(body) = body.trim_end().strip_suffix(';') else {
        return false;
    };
    if body.contains('(') {
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
        && !is_register(name)
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[test]
fn structure_counts_include_support_sections_and_all_tag_names() {
    let mut counts = Readability::default();
    let code = "/* velk prelude */\nstruct S1 { int x; };\nstruct Ac_0u4_8u4 { int x; int y; };\nstruct named {\n    int x;\n};\n/* end velk prelude */\nint f(void) { return 0; }\n";
    counts.add_structures(code);
    counts.add_structures(code);
    assert_eq!(counts.structures.len(), 3);
    let body = velk::render::Prelude::default().extract(code);
    counts.add(&body);
    assert_eq!(counts.lines, 1);
}

#[test]
fn named_variable_counts_exclude_structure_fields() {
    let mut counts = Readability::default();
    counts.add("struct item {\n    int field;\n};\nint f(void) {\n    int result;\n    if (flag) {\n        int value = 1;\n        result = value;\n    }\n    return result;\n}\n");
    assert_eq!(counts.variables, 2);
}

#[test]
fn local_classes_partition_declarations() {
    let mut counts = Readability::default();
    counts.add(concat!(
        "void f(void) {\n",
        "    uint64_t x = 1;\n",
        "    int32_t i; /* [sp-4] */\n",
        "    char *p;\n",
        "    struct item value;\n",
        "    uint8_t bytes[4];\n",
        "    uint32_t result;\n",
        "}\n",
    ));
    assert_eq!(counts.local_classes, [1, 1, 1, 2, 1]);
    assert_eq!(counts.local_classes.iter().sum::<usize>(), counts.variables);
}

#[test]
fn declarations_include_named_global_views() {
    for code in [
        "    int32_t v1;",
        "    int32_t i;",
        "    uint64_t result;",
        "    char *buf_2;",
        "    uint8_t local_0[16];",
        "    struct pair *v2;",
        "    uint32_t *const counter = (uint32_t *)(uintptr_t)0x1000;",
        "    uint8_t *const bytes_u8 = (uint8_t *)(uintptr_t)0x1001;",
        "    float *const samples = (float *)(uintptr_t)0x2000;",
        "    double *values = (double *)(uintptr_t)0x3000;",
        "    uint64_t fs_base = velk_x86_fs_base();",
        "    uint64_t target_state = read_target_state();",
        "    float gain = 1.0f;",
        "    int64_t result = 1;",
        "    size_t n = 8;",
        "    struct pair *v2 = source;",
        "    uint64_t **v3 = source;",
        "    int result = 1;",
        "    long count = 8;",
        "    const char *text = source;",
        "    const void *address = source;",
        "    bool ready = true;",
        "    unsigned long count = 8;",
        "    FILE *stream = source;",
        "    for (int i = 0; i < n; i++) {",
    ] {
        assert!(is_declaration(code), "{code}");
    }
    let mut counts = Readability::default();
    counts.add("int f(void) {\n    const char *text = \"/*\";\n    int64_t value = 0 /* undefined */;\n    return text[0] + value;\n}\n");
    assert_eq!(counts.variables, 2);
    for code in [
        "    uint64_t rax;",
        "    *counter = 1;",
        "    { counter = 1; }",
        "    counter[0] = 1;",
        "    counter = (uint32_t *)(uintptr_t)0x1000;",
        "    counter *= 2;",
        "    fs_base = velk_x86_fs_base();",
        "    target_state = read_target_state();",
        "    object.field = read_target_state();",
        "    object->field = read_target_state();",
        "    uint64_t 1state = read_target_state();",
        "    uint64_t state[0] = read_target_state();",
        "    return read_target_state();",
        "    consume(read_target_state());",
        "    return *counter;",
        "    return counter;",
        "    return v1;",
        "    goto L0;",
        "    goto local_0;",
        "    consume(counter);",
        "    for (i = 0; i < n; i++) {",
        "uint32_t counter(void);",
    ] {
        assert!(!is_declaration(code), "{code}");
    }
    let mut counts = Readability::default();
    counts.add(concat!(
        "void f(void) {\n",
        "    uint32_t *const counter = (uint32_t *)(uintptr_t)0x1000;\n",
        "    uint64_t fs_base = velk_x86_fs_base();\n",
        "    float gain = 1.0f;\n",
        "    uint64_t rax;\n",
        "    *counter = rax;\n",
        "}\n",
    ));
    assert_eq!(counts.variables, 3);
    assert_eq!(counts.registers, 2);
}

/// Disjoint syntactic classes using the same type recognition as `casts`.
fn cast_classes(code: &str) -> [usize; 5] {
    let mut counts = [0; 5];
    for (start, _) in code.match_indices('(') {
        let rest = &code[start + 1..];
        let Some(end) = rest.find(')') else {
            continue;
        };
        let ty = &rest[..end];
        if ty.contains('(') || cost::casts(&code[start..start + end + 2]) != 1 {
            continue;
        }
        let class = if ty.trim_end().ends_with('*') {
            if code[..start].trim_end().ends_with('*') {
                0
            } else if ty.trim() == "uint8_t *" {
                1
            } else {
                2
            }
        } else if matches!(ty.trim(), "uintptr_t" | "intptr_t") {
            3
        } else {
            4
        };
        counts[class] += 1;
    }
    counts
}

#[test]
fn cast_classes_partition_casts() {
    let code = "*(uint32_t *)((uint8_t *)p + (uintptr_t)q) + (int8_t)x + (struct item *)r";
    let classes = cast_classes(code);
    assert_eq!(classes, [1, 1, 1, 1, 1]);
    assert_eq!(classes.iter().sum::<usize>(), cost::casts(code));
    assert_eq!(cost::casts("result(struct item *value, int32_t count)"), 0);
    assert_eq!(cost::casts("(const void *)p + (const char *)q + (int)r"), 3);
    assert_eq!(cost::casts("(volatile const uint32_t *)p"), 1);
    assert_eq!(cost::casts("result(void)"), 0);
}

#[test]
fn cast_scorers_preserve_distinct_recognition() {
    let cases = [
        ("(uint32_t *)p", 1, 1),
        ("(struct item *)p", 1, 1),
        ("(float)x + (double)y + (bool)z + (char)w", 4, 4),
        ("(const uint32_t *)p", 1, 0),
        ("(volatile const uint32_t *)p", 1, 0),
        ("( uint32_t *)p", 1, 0),
        ("(\tuint32_t *)p", 1, 0),
        ("(uint32_t\t)p", 1, 0),
        ("(uint32_t **  )p", 1, 1),
        ("(int)x + (unsigned long)y + (FILE *)p", 3, 0),
        ("(void *)p + (const void *)q", 2, 0),
        ("(void)x + (struct )p + (uint32_t value)x", 0, 0),
        ("((uint32_t *)p)", 1, 1),
        ("(uint32_t", 0, 0),
        ("result(struct item *value, int32_t count)", 0, 0),
    ];
    for (code, general, transfer) in cases {
        assert_eq!(cost::casts(code), general, "general scorer: {code}");
        assert_eq!(
            cost::transfer_casts(code),
            transfer,
            "transfer scorer: {code}"
        );
    }
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

/// Go and Rust executables carry thousands of runtime functions; the test
/// program's functions and selected runtime examples are recorded in full.
fn recorded(fixture: &Path, function: &Function) -> bool {
    let name = fixture.to_string_lossy();
    let symbol = function.name.as_deref().unwrap_or("");
    if name.starts_with("go_") {
        symbol.starts_with("main.") || symbol == "runtime.printstring"
    } else if name.starts_with("rust_") {
        symbol.contains("rust_demo::")
            || symbol.contains("rust_probe::")
            || symbol.contains("memchr_raw::detect")
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
    if let Ok(analysis) = binary.analysis(function.addr, None) {
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
            .card(function.addr, velk::card::DEFAULT_BUDGET, None, None)
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .expect("a card serializes");
    if let Some(fields) = card.as_object_mut() {
        fields.remove("disasmPreview");
    }
    writeln!(out, "-- card\n{card}").expect("writing to a String");
    out
}
