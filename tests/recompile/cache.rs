use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(super) struct Cache {
    context: Option<String>,
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    input: String,
    output: String,
    checksum: u64,
}

fn hash(value: &str) -> u64 {
    let mut hash = DefaultHasher::new();
    value.hash(&mut hash);
    hash.finish()
}

fn compiler_identity() -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let selected = super::compiler();
    let compiler = if selected.components().count() > 1 {
        Some(selected)
    } else {
        let Some(paths) = std::env::var_os("PATH") else {
            return None;
        };
        std::env::split_paths(&paths)
            .map(|path| path.join(&selected))
            .find(|path| {
                path.metadata().is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
    };
    let Some(compiler) = compiler else {
        return None;
    };
    let Ok(compiler) = compiler.canonicalize() else {
        return None;
    };
    let Ok(version) = Command::new(&compiler).arg("--version").output() else {
        return None;
    };
    if !version.status.success() {
        return None;
    }
    Some(format!(
        "{compiler:?}\n{:?}\n{:?}\n{}\n{}",
        version.stdout,
        version.stderr,
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
}

const MAX_CACHE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;

fn prune(root: &Path, limit: u64) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut files = Vec::new();
    let mut bytes = 0_u64;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.len() != 16 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        bytes = bytes.saturating_add(metadata.len());
        files.push((metadata.modified().ok(), entry.path(), metadata.len()));
    }
    files.sort();
    for (_, path, size) in files {
        if bytes <= limit {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            bytes = bytes.saturating_sub(size);
        }
    }
}

impl Cache {
    pub(super) fn new(program: &str, inputs: &impl Serialize, compiler_args: &[&str]) -> Self {
        static COMPILER: OnceLock<Option<String>> = OnceLock::new();
        let context =
            if std::env::var_os("VELK_RECOMPILE_NO_CACHE").is_some_and(|value| value == "1") {
                None
            } else {
                COMPILER
                    .get_or_init(compiler_identity)
                    .as_ref()
                    .map(|compiler| {
                        serde_json::to_string(&(
                            program,
                            inputs,
                            compiler,
                            super::FLAGS,
                            super::LEVELS,
                            ["-fsyntax-only", "-ferror-limit=0", "-o"],
                            compiler_args,
                            [
                                "CPATH",
                                "C_INCLUDE_PATH",
                                "LIBRARY_PATH",
                                "COMPILER_PATH",
                                "SDKROOT",
                                "DEVELOPER_DIR",
                                "MACOSX_DEPLOYMENT_TARGET",
                                "CCC_OVERRIDE_OPTIONS",
                                "LD_LIBRARY_PATH",
                                "DYLD_LIBRARY_PATH",
                            ]
                            .map(|name| (name, format!("{:?}", std::env::var_os(name)))),
                            include_str!("../recompile.rs"),
                            include_str!("cache.rs"),
                        ))
                        .expect("serializable cache context")
                    })
            };
        let root = super::common::root().join("target/recompile-cache");
        if context.is_some() {
            static PRUNED: OnceLock<()> = OnceLock::new();
            PRUNED.get_or_init(|| prune(&root, MAX_CACHE_BYTES));
        }
        Self { context, root }
    }

    pub(super) fn expectations() -> Self {
        // Bump this version whenever interpreter behavior changes. Source checks also
        // invalidate local edits made without a version bump.
        const INTERPRETER_VERSION: u32 = 1;
        static SOURCE: OnceLock<u64> = OnceLock::new();
        let context =
            if std::env::var_os("VELK_RECOMPILE_NO_CACHE").is_some_and(|value| value == "1") {
                None
            } else {
                Some(format!(
                    "expectations {INTERPRETER_VERSION} {:016x}",
                    *SOURCE.get_or_init(|| hash(&format!(
                        "{}{}{}{}{}",
                        include_str!("../../src/ir/eval.rs"),
                        include_str!("../../src/ir/semantics.rs"),
                        include_str!("../../src/ir/trials.rs"),
                        include_str!("../recompile.rs"),
                        include_str!("cache.rs"),
                    )))
                ))
            };
        Self {
            context,
            root: super::common::root().join("target/recompile-cache"),
        }
    }

    pub(super) fn get_or_compute<T: Serialize + DeserializeOwned>(
        &self,
        stage: &str,
        input: &impl Serialize,
        compute: impl FnOnce() -> T,
    ) -> T {
        self.get_or_compute_if(stage, input, compute, |_| true)
    }

    pub(super) fn get_or_compute_if<T: Serialize + DeserializeOwned>(
        &self,
        stage: &str,
        input: &impl Serialize,
        compute: impl FnOnce() -> T,
        cacheable: impl Fn(&T) -> bool,
    ) -> T {
        let Some(context) = &self.context else {
            return compute();
        };
        let input =
            serde_json::to_string(&(context, stage, input)).expect("serializable cache input");
        let path = self.root.join(format!("{:016x}", hash(&input)));
        if let Ok(bytes) = std::fs::read(&path)
            && let Ok(entry) = serde_json::from_slice::<Entry>(&bytes)
            && entry.input == input
            && entry.checksum == hash(&entry.output)
            && let Ok(output) = serde_json::from_str(&entry.output)
            && cacheable(&output)
        {
            return output;
        }
        let output = compute();
        if !cacheable(&output) {
            return output;
        }
        let text = serde_json::to_string(&output).expect("serializable cache output");
        let entry = Entry {
            input,
            checksum: hash(&text),
            output: text,
        };
        let bytes = serde_json::to_vec(&entry).expect("serializable cache entry");
        if bytes.len() > MAX_ENTRY_BYTES {
            return output;
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temporary = self.root.join(format!(
            ".{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if std::fs::create_dir_all(&self.root).is_ok() {
            if std::fs::write(&temporary, bytes).is_ok() {
                let _ = std::fs::rename(&temporary, &path);
            }
            let _ = std::fs::remove_file(&temporary);
            // Eviction only removes complete entries; concurrent readers can recompute a miss.
            static WRITES: AtomicU64 = AtomicU64::new(0);
            if WRITES.fetch_add(1, Ordering::Relaxed).is_multiple_of(16) {
                prune(&self.root, MAX_CACHE_BYTES);
            }
        }
        output
    }
}

#[test]
fn entries_require_matching_inputs_and_intact_complete_outputs() {
    let root = super::scratch_dir("cache-integrity");
    let cache = Cache {
        context: Some("test".into()),
        root: root.clone(),
    };
    let read = |input, value| cache.get_or_compute("execute", &input, || value);
    assert_eq!(read("first", 7u64), 7);
    assert_eq!(read("first", 8), 7);
    assert_eq!(read("changed expectation", 8), 8);
    let path = cache.root.join(format!(
        "{:016x}",
        hash(&serde_json::to_string(&("test", "execute", "first")).unwrap())
    ));
    for bytes in [b"".as_slice(), b"{", b"{}"] {
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read("first", 9), 9);
    }
    let mut entry: Entry = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    entry.output = "10".into();
    std::fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
    assert_eq!(read("first", 11), 11);
    entry.input = "different input with the same filename".into();
    entry.checksum = hash(&entry.output);
    std::fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
    assert_eq!(read("first", 12), 12);
    let disabled = Cache {
        context: None,
        root: root.clone(),
    };
    assert_eq!(disabled.get_or_compute("execute", &"first", || 13u64), 13);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_printed_function_change_only_recompiles_its_fixture() {
    use super::*;
    let scratch = scratch_dir("cache-fixture-isolation");
    let make_fixture = |name: &str| Fixture {
        name: name.into(),
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: Vec::new(),
        functions: 1,
        excluded: BTreeMap::new(),
        candidates: vec![printed_candidate(
            synthetic_ir(
                name,
                Vec::new(),
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::Const(7),
                    at: None,
                }],
            ),
            vec![Vec::new()],
        )],
    };
    let mut fixtures = [make_fixture("cache_first"), make_fixture("cache_second")];
    // Observe actual syntax checks and builds, including on a warm cache.
    let compilation_count = || COMPILATIONS.get();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for fixture in &mut fixtures {
        writeln!(fixture.candidates[0].code, "/* {unique} */").unwrap();
    }
    let before = compilation_count();
    let verify = |fixtures: &[Fixture]| {
        for result in check(fixtures, &scratch, Mode::Registers, &[]) {
            assert_comparison_runs(&result, 1, 1);
        }
    };
    verify(&fixtures);
    let cold = compilation_count() - before;
    assert_eq!(cold, 6);
    verify(&fixtures);
    let warm = compilation_count();
    if std::env::var_os("VELK_RECOMPILE_NO_CACHE").is_some_and(|value| value == "1") {
        assert!(warm > before + cold);
    } else {
        assert_eq!(warm, before + cold);
        fixtures[0].candidates[0]
            .code
            .push_str("\n/* changed printed function */\n");
        verify(&fixtures);
        assert_eq!(compilation_count() - warm, 3);
        let length =
            fixtures[0].candidates[0].code.len() - "\n/* changed printed function */\n".len();
        fixtures[0].candidates[0].code.truncate(length);
        let changed = compilation_count();
        verify(&fixtures);
        assert_eq!(compilation_count(), changed);
        fixtures[0].candidates[0].ir.blocks[0].stmts = vec![Stmt::Ret {
            value: Expr::Const(9),
            at: None,
        }];
        let results = check(&fixtures, &scratch, Mode::Registers, &[]);
        assert_eq!(results[0].differing, 1);
        assert_eq!(results[1].differing, 0);
        assert_eq!(compilation_count() - changed, 2);
    }
    println!(
        "fixture cache: cold={cold}, warm=0, one changed fixture=3, restored=0 compiler calls"
    );
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn eviction_preserves_temporary_files_and_limits_complete_entries() {
    let root = super::scratch_dir("cache-eviction");
    for index in 0..5 {
        std::fs::write(root.join(format!("{index:016x}")), [0; 10]).unwrap();
    }
    let temporary = root.join(".pending");
    std::fs::write(&temporary, [0; 10]).unwrap();
    prune(&root, 20);
    let mut bytes = 0;
    for entry in std::fs::read_dir(&root).unwrap() {
        let entry = entry.unwrap();
        if entry.path() != temporary {
            bytes += entry.metadata().unwrap().len();
        }
    }
    assert_eq!(bytes, 20);
    assert!(temporary.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn batches_reuse_unchanged_code_and_detect_wrong_results_with_a_warm_cache() {
    use super::*;
    let scratch = scratch_dir("cache-batches");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for mode in [Mode::Registers, Mode::Memory] {
        let batch_size = if mode == Mode::Registers { 32 } else { 1 };
        let mut fixture = Fixture {
            name: "cache_batches".into(),
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            entry_registers: Vec::new(),
            initial_memory: Vec::new(),
            functions: batch_size + 1,
            excluded: BTreeMap::new(),
            candidates: Vec::new(),
        };
        for index in 0..=batch_size {
            let mut candidate = printed_candidate(
                synthetic_ir(
                    &format!("batch_{index}"),
                    Vec::new(),
                    CType::U64,
                    vec![Stmt::Ret {
                        value: Expr::Const(7),
                        at: None,
                    }],
                ),
                vec![Vec::new()],
            );
            writeln!(candidate.code, "/* {unique} {index} */").unwrap();
            fixture.candidates.push(candidate);
        }
        let verify = |fixture: &Fixture| {
            let mut results = Vec::new();
            for candidates in fixture.candidates.chunks(batch_size) {
                let candidates: Vec<&Candidate> = candidates.iter().collect();
                results.push(check_batch(fixture, &candidates, &scratch, mode, &[]));
            }
            results
        };
        let before = COMPILATIONS.get();
        let cold = verify(&fixture);
        assert_comparison_runs(&cold[0], batch_size, batch_size);
        assert_comparison_runs(&cold[1], 1, 1);
        assert_eq!(COMPILATIONS.get() - before, 6);
        verify(&fixture);
        let warm = COMPILATIONS.get();
        let disabled =
            std::env::var_os("VELK_RECOMPILE_NO_CACHE").is_some_and(|value| value == "1");
        if !disabled {
            assert_eq!(warm - before, 6);
        }
        let original = fixture.candidates[0].code.clone();
        fixture.candidates[0].code = original.replace("return 7;", "return 8;");
        assert_ne!(fixture.candidates[0].code, original);
        let wrong = verify(&fixture);
        assert_eq!(wrong[0].differing, 1);
        assert_eq!(wrong[0].runs, batch_size);
        assert_comparison_runs(&wrong[1], 1, 1);
        if !disabled {
            assert_eq!(COMPILATIONS.get() - warm, 3);
        }
        fixture.candidates[0].code = original;
        let parallel = check_parallel(std::slice::from_ref(&fixture), &scratch, mode);
        assert_comparison_runs(&parallel[0], batch_size + 1, batch_size + 1);
        if mode == Mode::Memory {
            fixture.candidates[0].ir.blocks[0]
                .stmts
                .insert(0, sc_store(REGION, Expr::Const(99)));
            let changed_memory = verify(&fixture);
            assert_eq!(changed_memory[0].differing, 1);
            assert!(changed_memory[0].lines[0].contains("and memory"));
        }
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn host_failures_are_never_reused_or_stored() {
    let root = super::scratch_dir("cache-timeout");
    let cache = Cache {
        context: Some("test".into()),
        root: root.clone(),
    };
    let read = |value: &str| {
        cache.get_or_compute_if(
            "execute",
            &(),
            || value.to_owned(),
            |output| super::can_cache_run(output),
        )
    };
    assert_eq!(read("timeout"), "timeout");
    assert_eq!(read("unreachable"), "unreachable");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    // Also reject complete timeout entries written by a previous cache policy.
    cache.get_or_compute("execute", &(), || "timeout".to_owned());
    assert_eq!(read("timeout"), "timeout");
    assert_eq!(read("v 7"), "v 7");
    assert_eq!(read("v 8"), "v 7");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn timed_out_programs_retry_once() {
    use std::os::unix::fs::PermissionsExt;
    let root = super::scratch_dir("timeout-retry");
    let program = root.join("run");
    let count = root.join("count");
    std::fs::write(&program, format!("#!/bin/sh\ncat >/dev/null\nif test -f '{}'; then echo 'v 7'; else touch '{}'; echo timeout; fi\n", count.display(), count.display())).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(super::run(&program, ""), "v 7\n");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\ncat >/dev/null\nprintf x >> '{}'\necho timeout\n",
            count.display()
        ),
    )
    .unwrap();
    assert_eq!(super::run(&program, ""), "timeout\n");
    assert_eq!(std::fs::read(&count).unwrap(), b"xx");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn expectation_cache_preserves_values_checksums_and_refusals() {
    use super::{ExpectedOutcome, Interpretation};
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let cache = Cache::expectations();
    let calls = std::cell::Cell::new(0);
    let expected = || {
        vec![
            Ok(Interpretation {
                outcome: ExpectedOutcome::Return { value: 7 },
                checksum: Some(123),
            }),
            Err("step limit".to_owned()),
            Ok(Interpretation {
                outcome: ExpectedOutcome::Trap,
                checksum: None,
            }),
        ]
    };
    for _ in 0..2 {
        let output: Vec<Result<Interpretation, String>> =
            cache.get_or_compute("interpret", &unique, || {
                calls.set(calls.get() + 1);
                expected()
            });
        assert_eq!(output, expected());
    }
    let disabled = std::env::var_os("VELK_RECOMPILE_NO_CACHE").is_some_and(|value| value == "1");
    assert_eq!(calls.get(), if disabled { 2 } else { 1 });
}
