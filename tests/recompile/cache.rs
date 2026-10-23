use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
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
    let Some(paths) = std::env::var_os("PATH") else {
        return None;
    };
    let compiler = std::env::split_paths(&paths)
        .map(|path| path.join(super::COMPILER))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        });
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
        {
            return output;
        }
        let output = compute();
        let text = serde_json::to_string(&output).expect("serializable cache output");
        let entry = Entry {
            input,
            checksum: hash(&text),
            output: text,
        };
        let bytes = serde_json::to_vec(&entry).expect("serializable cache entry");
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
                }],
            ),
            vec![Vec::new()],
        )],
    };
    let mut fixtures = [make_fixture("cache_first"), make_fixture("cache_second")];
    // Observe actual syntax checks and builds, including on a warm cache.
    let checks = || COMPILATIONS.get();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for fixture in &mut fixtures {
        writeln!(fixture.candidates[0].code, "/* {unique} */").unwrap();
    }
    let before = checks();
    let verify = |fixtures: &[Fixture]| {
        for result in check(fixtures, &scratch, Mode::Registers, &[]) {
            assert_comparison_runs(&result, 1, 1);
        }
    };
    verify(&fixtures);
    let cold = checks() - before;
    assert_eq!(cold, 6);
    verify(&fixtures);
    let warm = checks();
    if std::env::var_os("VELK_RECOMPILE_NO_CACHE").is_some_and(|value| value == "1") {
        assert!(warm > before + cold);
    } else {
        assert_eq!(warm, before + cold);
        fixtures[0].candidates[0]
            .code
            .push_str("\n/* changed printed function */\n");
        verify(&fixtures);
        assert_eq!(checks() - warm, 3);
        let length =
            fixtures[0].candidates[0].code.len() - "\n/* changed printed function */\n".len();
        fixtures[0].candidates[0].code.truncate(length);
        let changed = checks();
        verify(&fixtures);
        assert_eq!(checks(), changed);
        fixtures[0].candidates[0].ir.blocks[0].stmts = vec![Stmt::Ret {
            value: Expr::Const(9),
        }];
        let results = check(&fixtures, &scratch, Mode::Registers, &[]);
        assert_eq!(results[0].differing, 1);
        assert_eq!(results[1].differing, 0);
        assert_eq!(checks() - changed, 2);
    }
    println!(
        "fixture cache: cold={cold}, warm=0, one changed fixture=3, restored=0 compiler calls"
    );
    std::fs::remove_dir_all(scratch).unwrap();
}
