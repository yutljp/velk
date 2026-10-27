// Each test binary uses a different subset of these helpers.
#![allow(
    dead_code,
    reason = "Integration test targets use different subsets of these shared helpers."
)]

pub mod compiler;

use std::path::{Path, PathBuf};
use std::process::{Child, Output};

use serde_json::Value;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixtures_dir() -> PathBuf {
    root().join("tests/fixtures")
}

/// Every fixture binary, relative to the fixtures directory, in a stable order.
pub fn fixtures() -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect(&fixtures_dir(), Path::new(""), &mut found);
    found.sort();
    assert!(
        !found.is_empty(),
        "no fixtures in {}",
        fixtures_dir().display()
    );
    found
}

fn collect(dir: &Path, relative: &Path, found: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
        let name = entry.file_name();
        let path = entry.path();
        if path.is_dir() {
            collect(&path, &relative.join(&name), found);
        } else if path.extension().is_none_or(|extension| {
            !matches!(
                extension.to_str(),
                Some("txt" | "pdb" | "velk-cache" | "tmp")
            )
        }) {
            found.push(relative.join(name));
        }
    }
}

/// `work` applied in parallel, with results in the items' order.
pub fn in_parallel<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(3, |count| count.get().min(3));
    let mut results: Vec<(usize, R)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            return done;
                        };
                        done.push((index, work(item)));
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

/// True when expected files should be rewritten from the current output.
pub fn blessing() -> bool {
    std::env::var_os("VELK_BLESS").is_some_and(|value| value == "1")
}

/// Compares `actual` with the file at `path`, or rewrites the file when blessing.
/// Returns a description of the first difference.
pub fn check_expected(path: &Path, actual: &str) -> Option<String> {
    if blessing() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("{}: {error}", parent.display()));
        }
        std::fs::write(path, actual).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        return None;
    }
    let expected = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            return Some(format!(
                "{}: {error} (run with VELK_BLESS=1 to create it)",
                path.display()
            ));
        }
    };
    if expected == actual {
        return None;
    }
    let mut expected_lines = expected.lines();
    let mut actual_lines = actual.lines();
    let mut line = 1;
    loop {
        match (expected_lines.next(), actual_lines.next()) {
            (Some(e), Some(a)) if e == a => line += 1,
            (e, a) => {
                return Some(format!(
                    "{}:{line}\n  expected: {}\n  actual:   {}",
                    path.display(),
                    e.unwrap_or("<end of file>"),
                    a.unwrap_or("<end of file>")
                ));
            }
        }
    }
}

/// Fixture language groups, with C/C++ separated by available debug names.
pub fn fixture_group(fixture: &Path, image: &velk::loader::Image) -> &'static str {
    use velk::loader::NameSource;

    let name = fixture.to_string_lossy();
    if name.contains("rust_") {
        "Rust"
    } else if name.contains("go_") {
        "Go"
    } else if image.functions.values().any(|function| {
        function
            .sources
            .iter()
            .any(|source| matches!(source, NameSource::Dwarf | NameSource::CodeView))
    }) {
        "C/C++ debug"
    } else {
        "C/C++ stripped"
    }
}

/// Writes one JSON-RPC request, closes input, and collects the server output.
pub fn mcp_request(mut child: Child, request: &Value) -> Output {
    use std::io::Write as _;

    writeln!(child.stdin.take().expect("piped MCP input"), "{request}")
        .expect("writing MCP request");
    child.wait_with_output().expect("MCP server shutdown")
}
