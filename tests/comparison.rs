mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use velk::compare;
use velk::project::{self, Annotation, Target};
use velk::service::Binary;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    directory: PathBuf,
    first: PathBuf,
    second: PathBuf,
    first_names: BTreeMap<u64, String>,
    second_names: BTreeMap<u64, String>,
    global: u64,
    second_global: u64,
}

impl Fixture {
    fn new(arch: &str, stripped: bool) -> Self {
        let directory = common::root().join("target/comparison-tests").join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).expect("comparison fixture must be valid");
        let fixtures = common::root().join("tests/comparison/fixtures");
        let mut first_debug = Binary::open(&fixtures.join(format!("first.{arch}.debug.elf")))
            .expect("comparison fixture must be valid");
        let second_debug = Binary::open(&fixtures.join(format!("second.{arch}.debug.elf")))
            .expect("comparison fixture must be valid");
        let names = |binary: &Binary| {
            binary
                .functions()
                .into_iter()
                .filter_map(|function| function.name.map(|name| (function.addr, name)))
                .collect()
        };
        let profile = if stripped { "stripped" } else { "debug" };
        let first = directory.join("first.elf");
        let second = directory.join("second.elf");
        fs::copy(fixtures.join(format!("first.{arch}.{profile}.elf")), &first)
            .expect("comparison fixture must be valid");
        fs::copy(
            fixtures.join(format!("second.{arch}.{profile}.elf")),
            &second,
        )
        .expect("comparison fixture must be valid");
        // The same data reference is present in both versions, even without symbols.
        let read = first_debug
            .find("read_total")
            .expect("comparison fixture must be valid")
            .addr;
        let global = first_debug
            .analysis(read, None)
            .expect("comparison fixture must be valid")
            .ir
            .debug_globals
            .iter()
            .find(|(_, _, size)| *size == 4)
            .map(|(address, _, _)| *address)
            .unwrap_or_else(|| {
                first_debug
                    .find_address("total_before")
                    .expect("comparison fixture must be valid")
            });
        let second_global = second_debug
            .find_address("total_after")
            .expect("comparison fixture must be valid");
        Self {
            directory,
            first,
            second,
            first_names: names(&first_debug),
            second_names: names(&second_debug),
            global,
            second_global,
        }
    }

    fn address(&self, name: &str) -> u64 {
        *self
            .first_names
            .iter()
            .find(|(_, candidate)| candidate.as_str() == name)
            .expect("comparison fixture must be valid")
            .0
    }

    fn seed(&self) {
        let stable = self.address("stable");
        let removed = self.address("removed");
        let mut binary = Binary::open(&self.first).expect("comparison fixture must be valid");
        let origins = project::origins(
            &binary
                .analysis(stable, None)
                .expect("comparison fixture must be valid")
                .ir,
        );
        let parameter = origins
            .iter()
            .find(|origin| origin["target"]["kind"] == "parameter")
            .expect("comparison fixture must be valid")["target"]
            .clone();
        let annotations = [
            json!({"target":{"kind":"function","address":stable},"name":"calculation"}),
            json!({"target":{"kind":"comment","address":stable},"text":"Review this calculation."}),
            json!({"target":{"kind":"signature","function":stable},"text":"int32_t (int32_t input_value)"}),
            json!({"target":parameter,"name":"input_value","c_type":"int32_t"}),
            json!({"target":{"kind":"global","address":self.global},"name":"running_total","c_type":"int32_t"}),
            json!({"target":{"kind":"function","address":self.address("read_total")},"name":"read_carried"}),
            json!({"target":{"kind":"function","address":removed},"name":"removed_label"}),
            json!({"target":{"kind":"comment","address":stable + 1},"text":"Instruction comment."}),
            json!({"target":{"kind":"comment","address":removed + 1},"text":"Removed instruction comment."}),
        ];
        project::update(&self.first, |project| {
            for value in annotations {
                project.set(
                    serde_json::from_value::<Annotation>(value)
                        .expect("comparison fixture must be valid"),
                );
            }
            Ok(())
        })
        .expect("comparison fixture must be valid");
        let second_stable = *self
            .second_names
            .iter()
            .find(|(_, name)| name.as_str() == "stable")
            .expect("comparison fixture must be valid")
            .0;
        project::update(&self.second, |project| {
            project.set(serde_json::from_value(json!({"target":{"kind":"function","address":second_stable},"name":"user_calculation"})).expect("comparison fixture must be valid"));
            Ok(())
        }).expect("comparison fixture must be valid");
    }

    fn validate_transfer(&self, report: &Value) {
        assert!(
            report["transfer"]["copied"]
                .as_array()
                .expect("comparison fixture must be valid")
                .len()
                >= 4,
            "{report:#}"
        );
        assert!(
            report["transfer"]["skipped"]
                .as_array()
                .expect("comparison fixture must be valid")
                .len()
                >= 3,
            "{report:#}"
        );
        let saved = project::load(&self.second)
            .expect("comparison fixture must be valid")
            .expect("comparison fixture must be valid");
        let global = saved
            .get(&Target::Global {
                address: self.second_global,
            })
            .expect("global references match");
        assert_eq!(global.name.as_deref(), Some("running_total"));
        assert_eq!(global.c_type.as_deref(), Some("int32_t"));
        assert!(
            saved
                .annotations
                .iter()
                .any(|annotation| annotation.name.as_deref() == Some("user_calculation"))
        );
        assert!(
            !saved
                .annotations
                .iter()
                .any(|annotation| annotation.name.as_deref() == Some("removed_label"))
        );
        let mut binary = Binary::open(&self.second).expect("comparison fixture must be valid");
        let stable = binary
            .find("user_calculation")
            .expect("comparison fixture must be valid")
            .addr;
        let code = binary
            .decompile(stable, None, None)
            .expect("comparison fixture must be valid");
        assert!(code.contains("Review this calculation."), "{code}");
        assert!(code.contains("Instruction comment."), "{code}");
        assert!(code.contains("input_value"), "{code}");
        let read = *self
            .second_names
            .iter()
            .find(|(_, name)| name.as_str() == "read_total")
            .expect("comparison fixture must be valid")
            .0;
        assert!(
            binary
                .decompile(read, None, None)
                .expect("comparison fixture must be valid")
                .contains("running_total")
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn matches(arch: &str, stripped: bool) {
    let fixture = Fixture::new(arch, stripped);
    let mut first = Binary::open(&fixture.first).expect("comparison fixture must be valid");
    let mut second = Binary::open(&fixture.second).expect("comparison fixture must be valid");
    let report = compare::compare(&mut first, &mut second, false, None)
        .expect("comparison fixture must be valid");
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let mut correct = 0;
    for pair in report.changed.iter().chain(&report.identical) {
        let name = &fixture.first_names[&pair.first.addr];
        let expected = match name.as_str() {
            "renamed_before" => "renamed_after",
            "route_before" => "route_after",
            "message_before" => "message_after",
            other => other,
        };
        assert_eq!(
            fixture.second_names[&pair.second.addr], expected,
            "wrong match for {name}"
        );
        assert!(pair.similarity > 0.0 && pair.similarity <= 1.0);
        correct += 1;
    }
    assert!(
        report
            .only_first
            .iter()
            .any(|function| fixture.first_names[&function.addr] == "removed")
    );
    assert!(
        report
            .only_first
            .iter()
            .any(|function| fixture.first_names[&function.addr] == "folded")
    );
    assert!(
        report
            .only_second
            .iter()
            .any(|function| fixture.second_names[&function.addr] == "added")
    );
    let renamed = report
        .changed
        .iter()
        .chain(&report.identical)
        .find(|pair| fixture.first_names[&pair.first.addr] == "renamed_before")
        .expect("comparison fixture must be valid");
    assert_eq!(renamed.rule, "shape");
    let route = report
        .changed
        .iter()
        .chain(&report.identical)
        .find(|pair| fixture.first_names[&pair.first.addr] == "route_before")
        .expect("comparison fixture must be valid");
    assert_eq!(route.rule, "references");
    assert!(!route.c_diff.is_empty());
    assert!(!route.block_diff.is_empty());
    if stripped {
        assert!(
            report
                .only_first
                .iter()
                .any(|function| fixture.first_names[&function.addr] == "ambiguous_a")
        );
        assert!(correct >= 7, "recall {correct}/10");
    } else {
        assert_eq!(correct, 10);
        let edited = report
            .changed
            .iter()
            .find(|pair| pair.first.name.as_deref() == Some("edited"))
            .expect("comparison fixture must be valid");
        assert!(
            edited.c_diff.contains("31") && edited.c_diff.contains("37"),
            "{}",
            edited.c_diff
        );
    }
    eprintln!("{arch} stripped={stripped}: precision {correct}/{correct}, recall {correct}/10");
    fixture.seed();
    let mut first = Binary::open(&fixture.first).expect("comparison fixture must be valid");
    let mut second = Binary::open(&fixture.second).expect("comparison fixture must be valid");
    let carried = compare::compare(&mut first, &mut second, true, None)
        .expect("comparison fixture must be valid");
    fixture.validate_transfer(&json!(carried));
    let repeated = compare::compare(&mut first, &mut second, true, None)
        .expect("comparison fixture must be valid");
    assert!(
        repeated
            .transfer
            .expect("comparison fixture must be valid")
            .copied
            .is_empty()
    );
}

#[test]
fn x86_debug() {
    matches("x86_64", false);
}
#[test]
fn x86_stripped() {
    matches("x86_64", true);
}
#[test]
fn arm_debug() {
    matches("aarch64", false);
}
#[test]
fn arm_stripped() {
    matches("aarch64", true);
}

#[test]
fn cli_transfer() {
    let fixture = Fixture::new("x86_64", false);
    fixture.seed();
    let first_project = project::path(&fixture.first);
    let second_project = project::path(&fixture.second);
    let custom_first = fixture.directory.join("source.json");
    let custom_second = fixture.directory.join("destination.json");
    fs::rename(&first_project, &custom_first).expect("comparison fixture must be valid");
    fs::rename(&second_project, &custom_second).expect("comparison fixture must be valid");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--compare")
        .arg(&fixture.first)
        .arg(&fixture.second)
        .arg("--carry-annotations")
        .arg("--project")
        .arg(&custom_first)
        .arg("--other-project")
        .arg(&custom_second)
        .output()
        .expect("comparison fixture must be valid");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!first_project.exists() && !second_project.exists());
    fs::rename(&custom_second, &second_project).expect("comparison fixture must be valid");
    fixture.validate_transfer(
        &serde_json::from_slice::<Value>(&output.stdout).expect("comparison fixture must be valid"),
    );
}

#[test]
fn javascript_transfer() {
    let fixture = Fixture::new("aarch64", true);
    fixture.seed();
    let engine = velk::script::Engine::new().expect("comparison fixture must be valid");
    let outcome = engine.run(&format!("const a=velk.open({:?}); const b=velk.open({:?}); b.functions(); const r=a.compare(b, {{carryAnnotations:true}}); if (!b.functions().some(f=>f.name==='read_carried')) throw Error('stale function list'); r", fixture.first, fixture.second), None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    fixture.validate_transfer(
        &serde_json::from_str::<Value>(&outcome.output).expect("comparison fixture must be valid"),
    );
}

#[test]
fn mcp_transfer() {
    let fixture = Fixture::new("x86_64", true);
    fixture.seed();
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("comparison fixture must be valid");
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":format!("velk.open({:?}).compare(velk.open({:?}), {{carryAnnotations:true}})",fixture.first, fixture.second),"max_output_chars":20000,"timeout_ms":120000}}});
    writeln!(
        child
            .stdin
            .take()
            .expect("comparison fixture must be valid"),
        "{request}"
    )
    .expect("comparison fixture must be valid");
    let output = child
        .wait_with_output()
        .expect("comparison fixture must be valid");
    assert!(output.status.success());
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("comparison fixture must be valid");
    assert_ne!(response["result"]["isError"], true, "{response}");
    let report: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("comparison fixture must be valid"),
    )
    .expect("comparison fixture must be valid");
    fixture.validate_transfer(&report);
}

#[test]
fn unchanged_functions_and_local_origins_transfer() {
    let fixture = Fixture::new("x86_64", false);
    fs::copy(&fixture.first, &fixture.second).expect("comparison fixture must be valid");
    let mut first = Binary::open(&fixture.first).expect("comparison fixture must be valid");
    let mut second = Binary::open(&fixture.second).expect("comparison fixture must be valid");
    let report = compare::compare(&mut first, &mut second, false, None)
        .expect("comparison fixture must be valid");
    assert!(report.changed.is_empty());
    assert_eq!(report.identical.len(), 12);
    let route = first
        .find("route_before")
        .expect("comparison fixture must be valid")
        .addr;
    let local = project::origins(
        &first
            .analysis(route, None)
            .expect("comparison fixture must be valid")
            .ir,
    )
    .into_iter()
    .filter(|origin| origin["target"]["kind"] == "local")
    .nth(1)
    .expect("comparison fixture must be valid")["target"]
        .clone();
    project::update(&fixture.first, |project| {
        project.set(
            serde_json::from_value(json!({"target":local,"name":"saved_value"}))
                .expect("comparison fixture must be valid"),
        );
        Ok(())
    })
    .expect("comparison fixture must be valid");
    let report = compare::compare(&mut first, &mut second, true, None)
        .expect("comparison fixture must be valid");
    assert_eq!(
        report
            .transfer
            .expect("comparison fixture must be valid")
            .copied
            .len(),
        1
    );
    let code = second
        .decompile(route, None, None)
        .expect("comparison fixture must be valid");
    assert!(code.contains("saved_value"), "{code}");
}

#[test]
fn changed_functions_keep_parameter_and_signature_annotations_when_layouts_agree() {
    let fixture = Fixture::new("x86_64", false);
    let mut first = Binary::open(&fixture.first).expect("fixture opens");
    let mut second = Binary::open(&fixture.second).expect("fixture opens");
    let address = first.find("edited").expect("fixture has edited").addr;
    let parameter = project::origins(&first.analysis(address, None).expect("fixture analyzes").ir)
        .into_iter()
        .find(|origin| origin["target"]["kind"] == "parameter")
        .expect("edited has a parameter")["target"]
        .clone();
    project::update(&fixture.first, |project| {
        project.set(serde_json::from_value(json!({"target":parameter,"name":"edited_input","c_type":"int32_t"})).expect("annotation is valid"));
        project.set(serde_json::from_value(json!({"target":{"kind":"signature","function":address},"text":"int32_t (int32_t edited_input)"})).expect("annotation is valid"));
        Ok(())
    }).expect("source project is writable");
    let report =
        compare::compare(&mut first, &mut second, true, None).expect("comparison succeeds");
    assert_eq!(report.transfer.expect("transfer requested").copied.len(), 2);
    let address = second.find("edited").expect("fixture has edited").addr;
    let code = second
        .decompile(address, None, None)
        .expect("annotations render");
    assert!(
        code.contains("edited_input") && code.contains("37"),
        "{code}"
    );
}

#[test]
fn type_conflicts_and_timeouts_preserve_destination() {
    let fixture = Fixture::new("x86_64", false);
    fixture.seed();
    let declaration = |text: &str| {
        serde_json::from_value(json!({"target":{"kind":"declaration","name":"count"},"text":text}))
            .expect("comparison fixture must be valid")
    };
    project::update(&fixture.first, |project| {
        project.set(declaration("typedef int32_t count;"));
        project.set(serde_json::from_value(json!({"target":{"kind":"global","address":fixture.global},"name":"running_total","c_type":"count"})).expect("comparison fixture must be valid"));
        Ok(())
    }).expect("comparison fixture must be valid");
    project::update(&fixture.second, |project| {
        project.set(declaration("typedef int64_t count;"));
        Ok(())
    })
    .expect("comparison fixture must be valid");
    let before =
        fs::read(project::path(&fixture.second)).expect("comparison fixture must be valid");
    let mut first = Binary::open(&fixture.first).expect("comparison fixture must be valid");
    let mut second = Binary::open(&fixture.second).expect("comparison fixture must be valid");
    assert!(
        compare::compare(
            &mut first,
            &mut second,
            true,
            Some(std::time::Instant::now())
        )
        .is_err()
    );
    assert_eq!(
        fs::read(project::path(&fixture.second)).expect("comparison fixture must be valid"),
        before
    );
    let report = compare::compare(&mut first, &mut second, true, None)
        .expect("comparison fixture must be valid");
    assert!(
        report
            .transfer
            .expect("comparison fixture must be valid")
            .skipped
            .iter()
            .any(|item| item.reason == "destination has a conflicting type declaration")
    );
    let saved = project::load(&fixture.second)
        .expect("comparison fixture must be valid")
        .expect("comparison fixture must be valid");
    assert!(
        saved
            .get(&Target::Global {
                address: fixture.second_global
            })
            .is_none()
    );
    assert_eq!(
        saved
            .get(&Target::Declaration {
                name: "count".to_owned()
            })
            .expect("comparison fixture must be valid")
            .text
            .as_deref(),
        Some("typedef int64_t count;")
    );
    let mut same = Binary::open(&fixture.first).expect("comparison fixture must be valid");
    assert!(compare::compare(&mut first, &mut same, true, None).is_err());
}

#[test]
fn transferred_names_and_scalar_types_compile_and_preserve_results() {
    let fixture = Fixture::new("x86_64", false);
    fixture.seed();
    let mut first = Binary::open(&fixture.first).expect("comparison fixture must be valid");
    let mut second = Binary::open(&fixture.second).expect("comparison fixture must be valid");
    compare::compare(&mut first, &mut second, true, None)
        .expect("comparison fixture must be valid");
    let stable = second
        .find("user_calculation")
        .expect("comparison fixture must be valid")
        .addr;
    let read = second
        .find("read_carried")
        .expect("comparison fixture must be valid")
        .addr;
    let stable_code = second
        .decompile(stable, None, None)
        .expect("comparison fixture must be valid");
    let global_code = second
        .decompile(read, None, None)
        .expect("comparison fixture must be valid");
    let code = velk::render::combine(&format!("{stable_code}\n{global_code}"));
    let original = fixture.directory.join("original.o");
    let source = common::root().join("tests/comparison/fixtures/second.c");
    let output = Command::new("clang")
        .args(["-O1", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&original)
        .output()
        .expect("comparison fixture must be valid");
    assert!(output.status.success(), "{:?}", output);
    let executable = fixture.directory.join("verify");
    let input = fixture.directory.join("verify.c");
    fs::write(&input, format!("{code}\nint32_t running_total = 41;\nint stable(int);\nint read_total(int);\nint main(void) {{ for (int i=-1000;i<=1000;i++) {{ if (user_calculation(i)!=stable(i)) return 1; if (read_carried(i)!=read_total(i)) return 2; }} return 0; }}\n")).expect("comparison fixture must be valid");
    let output = Command::new("clang")
        .args(["-std=c11", "-Werror=implicit-function-declaration"])
        .arg(&input)
        .arg(&original)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("comparison fixture must be valid");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Command::new(executable)
            .status()
            .expect("comparison fixture must be valid")
            .success()
    );
}
