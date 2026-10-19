//! Every fixture's analysis output, compared with the files under tests/golden/fixtures/.
//! After an intended change, regenerate them with `VELK_BLESS=1 cargo test --test golden`
//! and review the diff before committing it.

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
    for (fixture, actual) in fixtures.iter().zip(rendered) {
        let golden = golden_dir.join(format!("{}.txt", fixture.display()));
        if let Some(difference) = common::check_expected(&golden, &actual) {
            failures.push(difference);
        }
        expected_files.push(golden);
    }
    failures.extend(stale_files(&golden_dir, &expected_files));
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

fn render_fixture(path: &Path, fixture: &Path) -> String {
    let mut binary = Binary::open(path).unwrap_or_else(|error| panic!("{error}"));
    let functions: Vec<Function> = binary.image().functions.values().cloned().collect();
    let mut out = String::new();
    let mut lift_failures = 0;
    let mut unsupported = 0;
    let mut gotos = 0;
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
    out
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
