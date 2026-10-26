//! Ordered whole-binary C and navigation results with different thread limits.

mod common;

use std::process::{Command, Output};
use velk::service::Binary;

fn cli(fixture: &str, threads: usize, operation: &str, selectors: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("VELK_THREADS", threads.to_string())
        .arg(operation)
        .arg(common::fixtures_dir().join(fixture))
        .args(selectors)
        .output()
        .expect("the CLI can run on a fixture")
}

#[test]
fn whole_binary_c_and_navigation_are_identical_across_thread_limits() {
    for fixture in [
        "arm64.o",
        "calls_a64.elf",
        "cpp_virtual_x64.elf",
        "arm64_loops_stripped.o",
        "metrics/l0_arith.i386.O2.debug.elf",
        "arm32/control.arm.O2.elf",
        "arm32/control.thumb.O2.elf",
    ] {
        let one = cli(fixture, 1, "--decompile", &[]);
        let many = cli(fixture, 4, "--decompile", &["*"]);
        assert_eq!(one.status.code(), many.status.code(), "{fixture}");
        assert_eq!(one.stderr, many.stderr, "{fixture}");
        assert_eq!(one.stdout, many.stdout, "{fixture}");
        assert!(!one.stdout.is_empty(), "{fixture}");

        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
        let mut expected = String::new();
        for address in addresses {
            if let Ok(code) = binary.decompile(address, None, None) {
                expected.push_str(&code);
            }
        }
        assert_eq!(
            String::from_utf8(one.stdout).unwrap(),
            velk::render::combine(&expected),
            "{fixture}"
        );

        let one = cli(fixture, 1, "--xrefs", &["0x0"]);
        let many = cli(fixture, 4, "--xrefs", &["0x0"]);
        assert!(one.status.success(), "{fixture}: {:?}", one.stderr);
        assert_eq!(one.status.code(), many.status.code(), "{fixture}");
        assert_eq!(one.stderr, many.stderr, "{fixture}");
        assert_eq!(one.stdout, many.stdout, "{fixture}");
    }
}

#[test]
fn batch_keeps_duplicates_failures_order_and_cached_output() {
    let mut binary = Binary::open(&common::fixtures_dir().join("calls_a64.elf")).unwrap();
    assert!(binary.decompile_many(&[], None, None).unwrap().is_empty());
    let addresses: Vec<_> = binary.image().functions.keys().copied().take(3).collect();
    assert_eq!(addresses.len(), 3);
    let selected = [addresses[2], u64::MAX, addresses[0], addresses[2]];
    let mut expected = Vec::new();
    for &address in &selected {
        expected.push(
            binary
                .decompile(address, None, None)
                .map_err(|error| error.to_string()),
        );
    }
    let results = binary.decompile_many(&selected, None, None).unwrap();
    let actual: Vec<_> = results
        .into_iter()
        .map(|result| result.map_err(|error| error.to_string()))
        .collect();
    assert_eq!(actual, expected);
    let mut fresh = Binary::open(&common::fixtures_dir().join("calls_a64.elf")).unwrap();
    let results = fresh.decompile_many(&selected, None, None).unwrap();
    let actual: Vec<_> = results
        .into_iter()
        .map(|result| result.map_err(|error| error.to_string()))
        .collect();
    assert_eq!(actual, expected);
    for &address in &addresses {
        assert_eq!(
            fresh.decompile(address, None, None).unwrap(),
            binary.decompile(address, None, None).unwrap()
        );
    }
}

#[test]
fn script_batch_matches_a_loop_over_functions() {
    let path = common::fixtures_dir().join("arm64.o");
    let script = format!(
        r#"
const b = velk.open({path:?});
const functions = b.functions();
const batch = b.decompile(functions);
if (batch.length !== functions.length) throw Error("result count");
for (let i = 0; i < functions.length; i++) {{
  if (batch[i].addr !== functions[i].addr || batch[i].error !== null || batch[i].code !== functions[i].decompile()) throw Error("function output");
}}
"#
    );
    let outcome = velk::script::Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
}

#[test]
fn single_function_batch_reuses_only_the_single_request_summaries() {
    for (fixture, name) in [
        ("go_probe", "main.main"),
        ("rust_probe", "rust_probe::main"),
        ("calls_a64.elf", "factorial"),
    ] {
        let path = common::fixtures_dir().join(fixture);
        let mut single = Binary::open(&path).unwrap();
        let addr = single.find(name).unwrap().addr;
        let expected = single.decompile(addr, None, None).unwrap();
        let mut batch = Binary::open(&path).unwrap();
        let mut results = batch.decompile_many(&[addr], None, None).unwrap();
        assert_eq!(results.len(), 1, "{fixture}");
        assert_eq!(results.remove(0).unwrap(), expected, "{fixture}");
        assert_eq!(
            *batch.image().summaries.read().unwrap(),
            *single.image().summaries.read().unwrap(),
            "{fixture}"
        );
    }
}

#[test]
fn timed_out_batch_can_be_retried_and_signatures_match_single_requests() {
    let path = common::fixtures_dir().join("arm64.o");
    let mut binary = Binary::open(&path).unwrap();
    let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
    let deadline = std::time::Instant::now() - std::time::Duration::from_secs(1);
    assert!(matches!(
        binary.decompile_many(&addresses, None, Some(deadline)),
        Err(velk::error::Error::TimedOut)
    ));

    let signatures = binary.build_signatures(None).unwrap().database;
    let batch = binary
        .decompile_many(&addresses, Some(&signatures), None)
        .unwrap();
    let mut single = Binary::open(&path).unwrap();
    for (address, result) in std::iter::zip(addresses, batch) {
        assert_eq!(
            result.unwrap(),
            single.decompile(address, Some(&signatures), None).unwrap()
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn signatures_and_annotations_preserve_request_order() {
    let directory = common::root()
        .join("target")
        .join(format!("batch-annotations-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("input.c");
    let original = directory.join("original.so");
    let stripped = directory.join("stripped.so");
    std::fs::write(
        &source,
        r#"
__attribute__((visibility("hidden"), noinline)) void *malloc(unsigned long n) {
    volatile unsigned long values[8] = {n, n, n, n, n, n, n, n};
    return (void *)values[n & 7];
}
__attribute__((visibility("hidden"), noinline)) void *invoke(unsigned long n) { return malloc(n); }
void *top(unsigned long n) { return invoke(n); }
"#,
    )
    .unwrap();
    let compiled = Command::new("clang")
        .args([
            "-O1",
            "-fno-builtin",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-Wl,-Bsymbolic",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&original)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{:?}", compiled.stderr);
    std::fs::copy(&original, &stripped).unwrap();
    let status = Command::new("strip")
        .arg("--strip-all")
        .arg(&stripped)
        .status()
        .unwrap();
    assert!(status.success());
    let mut named = Binary::open(&original).unwrap();
    let invoke = named.find("invoke").unwrap().addr;
    let top = named.find("top").unwrap().addr;
    let mut database = named.build_signatures(None).unwrap().database;
    assert!(database.entries.iter().any(|entry| entry.name == "malloc"));
    // A recognized name changes the types inferred for the annotated caller.
    for entry in &mut database.entries {
        if entry.name == "malloc" {
            entry.name = "abort".to_owned();
        }
    }
    let annotation: velk::project::Annotation = serde_json::from_value(serde_json::json!({
        "target": {"kind": "parameter", "function": format!("0x{invoke:x}"), "storage": {"kind": "register", "register": 7}},
        "c_type": "uint64_t"
    })).unwrap();
    velk::project::update(&stripped, |project| {
        project.set(annotation);
        Ok(())
    })
    .unwrap();
    let mut sequential = Binary::open(&stripped).unwrap();
    let first = sequential
        .decompile(top, Some(&database), None)
        .map_err(|error| error.to_string());
    let second = sequential
        .decompile(top, Some(&database), None)
        .map_err(|error| error.to_string());
    assert_ne!(first, second);
    let mut batch = Binary::open(&stripped).unwrap();
    let results = batch
        .decompile_many(&[top, top], Some(&database), None)
        .unwrap();
    let actual: Vec<_> = results
        .into_iter()
        .map(|result| result.map_err(|error| error.to_string()))
        .collect();
    assert_eq!(actual, [first, second]);
    std::fs::remove_dir_all(directory).unwrap();
}
