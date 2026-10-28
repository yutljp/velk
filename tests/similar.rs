//! Ranking against symbol ground truth; function names are not scoring features.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde_json::Value;
use velk::loader::OpenOptions;
use velk::service::{Binary, CacheLocation};
use velk::similar::{self, Features};

fn normalized(value: Value) -> Value {
    match value {
        Value::Number(number) => Value::from(number.as_f64().expect("JSON numbers fit in f64")),
        Value::Array(values) => Value::Array(values.into_iter().map(normalized).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, normalized(value)))
                .collect(),
        ),
        other => other,
    }
}

fn open(path: &Path) -> Binary {
    Binary::open_input(
        path,
        None,
        &OpenOptions {
            cache: Some(CacheLocation::Enabled(false)),
            ..Default::default()
        },
    )
    .expect("fixture binary loads")
}

struct Indexed {
    binary: Binary,
    queries: Vec<(String, Features)>,
}

fn indexed(path: &Path) -> Indexed {
    let mut binary = open(path);
    let functions = binary.functions();
    let index = binary.similarity_index(None).expect("fixture index builds");
    let mut queries = Vec::new();
    for function in functions {
        if let (Some(name), Some(features)) = (function.name, index.features(function.addr)) {
            queries.push((name, features));
        }
    }
    Indexed { binary, queries }
}

fn measure(groups: &mut BTreeMap<String, Vec<Indexed>>) -> (usize, usize, usize, usize) {
    let (mut pairs, mut total, mut first, mut five) = (0, 0, 0, 0);
    for variants in groups.values_mut() {
        for left in 0..variants.len() {
            for right in 0..variants.len() {
                if left == right {
                    continue;
                }
                pairs += 1;
                let queries = variants[left].queries.clone();
                let available: Vec<_> = variants[right]
                    .queries
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect();
                let index = variants[right]
                    .binary
                    .similarity_index(None)
                    .expect("fixture index builds");
                for (name, features) in queries {
                    if !available.contains(&name) {
                        continue;
                    }
                    total += 1;
                    let report = index
                        .search(&features, None, 5, None)
                        .expect("unlimited search succeeds");
                    let rank = report
                        .matches
                        .iter()
                        .position(|candidate| candidate.function.name.as_ref() == Some(&name));
                    if rank == Some(0) {
                        first += 1;
                    }
                    if rank.is_some() {
                        five += 1;
                    }
                    let again = index
                        .search(&features, None, 5, None)
                        .expect("unlimited search succeeds");
                    assert_eq!(
                        serde_json::to_value(report).expect("report serializes"),
                        serde_json::to_value(again).expect("report serializes")
                    );
                }
            }
        }
    }
    (pairs, total, first, five)
}

#[test]
fn corpus_ranking() {
    let mut groups = BTreeMap::<String, Vec<Indexed>>::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(common::fixtures_dir().join("metrics"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        let filename = path.file_name().unwrap().to_str().unwrap();
        if !filename.ends_with(".debug.elf") && !filename.ends_with(".debug.dll") {
            continue;
        }
        let source = filename.split('.').next().unwrap().to_owned();
        groups.entry(source).or_default().push(indexed(&path));
    }
    // ARM and Thumb fixtures use the same C sources as the metrics corpus.
    let mut paths: Vec<PathBuf> = fs::read_dir(common::fixtures_dir().join("arm32"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        if path.extension().and_then(|s| s.to_str()) != Some("elf") {
            continue;
        }
        let filename = path.file_name().unwrap().to_str().unwrap();
        let source = filename.split('.').next().unwrap().to_owned();
        groups.entry(source).or_default().push(indexed(&path));
    }
    let (pairs, total, first, five) = measure(&mut groups);
    eprintln!(
        "corpus: {pairs} directed binary pairs, {total} queries; hit@1 {first}/{total} ({:.2}%), hit@5 {five}/{total} ({:.2}%)",
        first as f64 * 100.0 / total as f64,
        five as f64 * 100.0 / total as f64
    );
    assert!(total > 1000);
    assert!(
        first * 2 > total,
        "matching functions should rank first in most corpus queries"
    );
    assert!(five * 5 > total * 4);
}

#[test]
fn compiler_and_optimization_ranking() {
    let directory = common::root().join("target/similarity-compilers");
    fs::create_dir_all(&directory).unwrap();
    let source = common::root().join("tests/cases/c/loops.c");
    let mut groups = BTreeMap::<String, Vec<Indexed>>::new();
    for compiler in ["clang", "cc"] {
        let version = Command::new(compiler).arg("--version").output().unwrap();
        eprintln!(
            "{compiler}: {}",
            String::from_utf8_lossy(&version.stdout)
                .lines()
                .next()
                .unwrap()
        );
        for optimization in ["O0", "O2"] {
            let path = directory.join(format!("{compiler}.{optimization}.o"));
            let output = Command::new(compiler)
                .args(["-c", "-fno-inline"])
                .arg(format!("-{optimization}"))
                .arg(&source)
                .arg("-o")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            groups
                .entry("loops".to_owned())
                .or_default()
                .push(indexed(&path));
        }
    }
    let (pairs, total, first, five) = measure(&mut groups);
    eprintln!(
        "compilers: {pairs} directed binary pairs, hit@1 {first}/{total}, hit@5 {five}/{total}"
    );
    assert!(first * 2 > total);
    assert_eq!(five, total);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cli_javascript_and_mcp_match_library() {
    let path = common::fixtures_dir().join("arm64.o");
    let other = common::fixtures_dir().join("arm64_macho.o");
    let mut source = open(&path);
    let addr = source.find("pair_sum").unwrap().addr;
    let mut destination = open(&other);
    let expected = normalized(
        serde_json::to_value(
            similar::search(&mut source, addr, &mut destination, 3, None).unwrap(),
        )
        .unwrap(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--similar", "pair_sum"])
        .arg(&path)
        .arg("--in")
        .arg(&other)
        .args(["--limit", "3", "--json", "--cache", "off"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        normalized(serde_json::from_slice::<Value>(&output.stdout).unwrap()),
        expected
    );
    let code = format!(
        "const b=velk.open({path:?},{{cache:false}}); const other=velk.open({other:?},{{cache:false}}); JSON.stringify(b.getFunction('pair_sum').similar({{in:other,limit:3}}))"
    );
    let engine = velk::script::Engine::new().unwrap();
    let output = engine.run(&code, None);
    assert!(output.error.is_none(), "{:?}", output.error);
    assert_eq!(
        normalized(serde_json::from_str::<Value>(&output.output).unwrap()),
        expected
    );
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call", "params":{
        "name":"velk_run_script","arguments":{"code":code,"max_output_chars":20000}}});
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        normalized(
            serde_json::from_str::<Value>(reply["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap()
        ),
        expected
    );
    let local = source.similar(addr, usize::MAX, None).unwrap();
    assert!(
        local
            .matches
            .iter()
            .all(|candidate| candidate.function.addr != addr)
    );
    assert!(source.similar(addr, 0, None).unwrap().matches.is_empty());
    assert!(source.similar(u64::MAX, 1, None).is_err());
    assert!(source.similarity_index(Some(Instant::now())).is_err());
    assert!(expected["matches"][0]["score"].as_f64().unwrap() > 0.0);
}

#[test]
fn resolved_calls_and_strings_supply_evidence() {
    for (path, feature) in [
        (
            common::fixtures_dir().join("metrics/calls.x86_64.O0.debug.elf"),
            "calls",
        ),
        (
            common::root().join("tests/comparison/fixtures/first.x86_64.debug.elf"),
            "strings",
        ),
    ] {
        let mut binary = open(&path);
        let functions = binary.functions();
        let index = binary.similarity_index(None).unwrap();
        let mut found = false;
        for function in functions {
            let Some(query) = index.features(function.addr) else {
                continue;
            };
            let report = index.search(&query, None, usize::MAX, None).unwrap();
            let same = report
                .matches
                .iter()
                .find(|candidate| candidate.function.addr == function.addr)
                .unwrap();
            if same.evidence.iter().any(|item| {
                item.feature == feature && item.similarity == 1.0 && !item.shared.is_empty()
            }) {
                found = true;
            }
        }
        assert!(
            found,
            "{} must expose resolved {feature} evidence",
            path.display()
        );
    }
}

#[test]
fn unrelated_fixture_functions_score_low() {
    let mut source = open(&common::fixtures_dir().join("arm64.o"));
    let addr = source.find("sum3").unwrap().addr;
    let mut destination = open(&common::fixtures_dir().join("arm64_loops.o"));
    let report = similar::search(&mut source, addr, &mut destination, usize::MAX, None).unwrap();
    assert_eq!(report.matches.len(), 4);
    for candidate in report.matches {
        assert!(
            candidate.score < 0.3,
            "{} scored {}",
            candidate.function.name.unwrap(),
            candidate.score
        );
    }
}

#[test]
fn javascript_local_search_and_invalid_options() {
    let path = common::fixtures_dir().join("arm64.o");
    let code = format!(
        r#"
        const b = velk.open({path:?}, {{cache:false}});
        const f = b.getFunction("pair_sum");
        const before = f.decompile();
        const local = f.similar();
        if (f.decompile() !== before) throw new Error("indexing changed the printed C");
        if (local.matches.some(m => m.function.addr === f.addr)) throw new Error("self included");
        if (!f.similar({{in:b}}).matches.some(m => m.function.addr === f.addr)) throw new Error("explicit destination excluded self");
        if (f.similar({{limit:0}}).matches.length) throw new Error("zero limit ignored");
        for (const options of [{{in:{{}}}}, {{limit:-1}}, {{limit:1.5}}]) {{
            let failed = false;
            try {{ f.similar(options); }} catch (_) {{ failed = true; }}
            if (!failed) throw new Error("invalid options accepted");
        }}
        true
    "#
    );
    let outcome = velk::script::Engine::new().unwrap().run(&code, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(outcome.output, "true");
}
