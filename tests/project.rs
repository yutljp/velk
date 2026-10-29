mod common;

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use velk::project::{self, Annotation, Project, Target};
use velk::service::Binary;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    directory: PathBuf,
    binary: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = common::root().join("target/project-tests").join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).expect("test directory can be created");
        let binary = directory.join("app.o");
        std::fs::copy(common::fixtures_dir().join("arm64.o"), &binary)
            .expect("test binary can be copied");
        Self { directory, binary }
    }
    fn native() -> Self {
        let fixture = Self::new();
        let source = fixture.directory.join("input.c");
        std::fs::write(&source, r#"
#include <stdint.h>
struct pair { int32_t first; int32_t second; };
__attribute__((noinline)) int32_t add_pair(struct pair *p) { return p->first + p->second; }
int32_t relay_pair(struct pair *p) { return add_pair(p); }
__attribute__((noinline)) int32_t triple(int32_t x) { return x * 3; }
int32_t invoke(int32_t x) { return triple(x) + 5; }
int32_t accumulate(int32_t *values, int32_t count) { int32_t sum = 0, combined = 0; for (int32_t i=0;i<count;i++) { sum += values[i]; combined ^= sum; } return sum + combined; }
__attribute__((noinline)) int32_t ninth(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int32_t f, int32_t g, int32_t h, int32_t i) { return a+b+c+d+e+f+g+h+i; }
int32_t invoke_ninth(int32_t x) { return ninth(x,x+1,x+2,x+3,x+4,x+5,x+6,x+7,x+8); }
int32_t total;
int32_t global_add(int32_t x) { return total + x; }
__attribute__((noinline)) void touch(int32_t *p) { *p += 7; }
__attribute__((nodebug)) int32_t stack_work(int32_t x) { int32_t slots[4]; slots[0]=x; slots[1]=x+1; touch(slots); return slots[0] + slots[1]; }
"#).expect("test source can be written");
        let result = common::compiler::run(
            Command::new("clang")
                .args([
                    "-O1",
                    "-g",
                    "-fPIC",
                    if cfg!(target_os = "macos") {
                        "-dynamiclib"
                    } else {
                        "-shared"
                    },
                ])
                // These tests annotate definitions and their direct data accesses.
                .args(if cfg!(target_os = "linux") {
                    &["-Wl,-Bsymbolic"][..]
                } else {
                    &[]
                })
                .arg(&source)
                .arg("-o")
                .arg(&fixture.binary),
            None,
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }
    fn set(&self, value: Value) {
        let annotation: Annotation =
            serde_json::from_value(value).expect("test annotation is valid JSON");
        project::update(&self.binary, |project| {
            project.set(annotation);
            Ok(())
        })
        .expect("test annotation can be saved");
    }
    fn cli(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg(match args[0] {
                "set" => "--annotate",
                "get" => "--annotation",
                "list" => "--annotations",
                "remove" => "--unannotate",
                "export" => "--export-project",
                "import" => "--import-project",
                "origins" => "--origins",
                other => other,
            })
            .arg(&self.binary)
            .args(&args[1..])
            .output()
            .expect("annotation command can be launched")
    }
    fn compile_and_run(&self, code: &str) {
        let source = self.directory.join("output.c");
        let executable = self.directory.join("verify");
        std::fs::write(&source, code).expect("rendered source can be written");
        let result = common::compiler::run(
            Command::new("clang")
                .args([
                    "-std=c11",
                    "-Werror=implicit-function-declaration",
                    "-include",
                    "stdint.h",
                ])
                .arg(&source)
                .arg(&self.binary)
                .arg("-o")
                .arg(&executable),
            None,
        );
        assert!(
            result.status.success(),
            "{}\n{code}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            Command::new(executable)
                .status()
                .expect("compiled verification program can run")
                .success(),
            "{code}"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn cli_round_trip_persistence_and_json_errors() {
    let fixture = Fixture::new();
    let annotation = json!({"target":{"kind":"function","address":"0x0"},"name":"sum_values"});
    assert!(
        fixture
            .cli(&["set", &annotation.to_string()])
            .status
            .success()
    );
    let found: Value = serde_json::from_slice(
        &fixture
            .cli(&["get", &annotation["target"].to_string()])
            .stdout,
    )
    .unwrap();
    assert_eq!(found, annotation);
    let exported = fixture.cli(&["export"]);
    let project: Project = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(project.version, 1);
    assert_eq!(project.binary_sha256.len(), 64);
    let imported = fixture.directory.join("import.json");
    std::fs::write(&imported, &exported.stdout).unwrap();
    assert!(
        fixture
            .cli(&["remove", &annotation["target"].to_string()])
            .status
            .success()
    );
    assert!(
        fixture
            .cli(&["import", imported.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(project::load(&fixture.binary).unwrap().unwrap(), project);
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-D")
        .arg(&fixture.binary)
        .arg("sum_values")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("sum_values(uint32_t"));
    let failure = fixture.cli(&["set", "{}"]);
    assert!(!failure.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&failure.stderr).unwrap()["code"],
        "project_json"
    );
    assert_eq!(project::load(&fixture.binary).unwrap().unwrap(), project);
}

#[test]
fn different_binary_and_version_are_rejected_without_writes() {
    let fixture = Fixture::new();
    fixture.set(json!({"target":{"kind":"comment","address":0},"text":"reviewed"}));
    let before = std::fs::read(project::path(&fixture.binary)).unwrap();
    let other = Fixture::native();
    std::fs::copy(project::path(&fixture.binary), project::path(&other.binary)).unwrap();
    let error = project::load(&other.binary).unwrap_err();
    assert!(error.to_string().contains("binary_mismatch"));
    assert!(
        Binary::open(&other.binary)
            .err()
            .unwrap()
            .to_string()
            .contains("binary_mismatch")
    );
    let mut imported: Project = serde_json::from_slice(&before).unwrap();
    imported.version = 99;
    assert!(
        project::update(&fixture.binary, |project| {
            *project = imported;
            Ok(())
        })
        .unwrap_err()
        .to_string()
        .contains("project_version")
    );
    assert_eq!(
        std::fs::read(project::path(&fixture.binary)).unwrap(),
        before
    );
}

#[test]
fn concurrent_process_writers_preserve_every_edit() {
    let fixture = Fixture::new();
    let mut children = Vec::new();
    for address in 0..12 {
        children.push(Command::new(env!("CARGO_BIN_EXE_velk")).arg("--annotate").arg(&fixture.binary)
            .arg(json!({"target":{"kind":"comment","address":address},"text":format!("comment {address}")}).to_string())
            .stdout(std::process::Stdio::null()).spawn().unwrap());
    }
    let reader_path = fixture.binary.clone();
    let reader = std::thread::spawn(move || {
        for _ in 0..200 {
            project::load(&reader_path).unwrap();
            std::thread::yield_now();
        }
    });
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    reader.join().unwrap();
    assert_eq!(
        project::load(&fixture.binary)
            .unwrap()
            .unwrap()
            .annotations
            .len(),
        12
    );
    assert_eq!(std::fs::read_dir(&fixture.directory).unwrap().count(), 2);
}

#[test]
fn names_comments_and_parameters_preserve_computation() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("triple").unwrap().addr;
    let ir = &binary.analysis(address, None).unwrap().ir;
    assert_eq!(
        ir.params[0].ty.integer(),
        Some((32, cfg!(target_os = "linux")))
    );
    let origins = project::origins(ir);
    let parameter = origins
        .into_iter()
        .find(|row| row["target"]["kind"] == "parameter")
        .unwrap();
    let parameter_type = parameter["c_type"].as_str().unwrap();
    fixture.set(json!({"target":{"kind":"function","address":address},"name":"multiply_three"}));
    fixture.set(json!({"target":parameter["target"],"name":"input"}));
    fixture.set(json!({"target":{"kind":"comment","address":address},"text":"checked */ *??/\n/ return 99; /* \\\nreturn 99; /*"}));
    let code = binary.decompile(address, None, None).unwrap();
    assert!(
        code.contains(&format!("multiply_three({parameter_type} input)")),
        "{code}"
    );
    assert!(code.contains("checked * /"));
    fixture.compile_and_run(&format!("{code}\nint32_t triple(int32_t);\nint main(void) {{ for (int32_t i=-100;i<100;i++) if (multiply_three(i)!=triple(i)) return 1; return 0; }}"));
    project::update(&fixture.binary, |project| {
        project.annotations.clear();
        Ok(())
    })
    .unwrap();
    assert!(
        binary
            .decompile(address, None, None)
            .unwrap()
            .contains("triple(")
    );
}

#[test]
fn structures_typedefs_enums_and_signatures_apply_and_compile() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("add_pair").unwrap().addr;
    let parameter = project::origins(&binary.analysis(address, None).unwrap().ir)
        .into_iter()
        .find(|row| row["target"]["kind"] == "parameter")
        .unwrap()["target"]
        .clone();
    fixture.set(json!({"target":{"kind":"declaration","name":"struct record"},"text":"struct record { int32_t left; int32_t right; };"}));
    fixture.set(
        json!({"target":{"kind":"declaration","name":"count"},"text":"typedef uint64_t count;"}),
    );
    fixture.set(json!({"target":{"kind":"declaration","name":"enum mode"},"text":"enum mode { idle, ready = 2 };"}));
    fixture.set(json!({"target":parameter,"name":"record","c_type":"struct record *"}));
    fixture.set(json!({"target":{"kind":"function","address":address},"name":"record_sum"}));
    let code = binary.decompile(address, None, None).unwrap();
    assert!(
        code.contains("record->left") && code.contains("record->right"),
        "{code}"
    );
    assert!(code.contains("typedef uint64_t count;") && code.contains("enum mode"));
    fixture.compile_and_run(&format!("{code}\nint32_t add_pair(void *);\nint main(void) {{ struct record r={{17,-5}}; return record_sum(&r)!=add_pair(&r); }}"));
    let triple = binary.find("triple").unwrap().addr;
    let invoke = binary.find("invoke").unwrap().addr;
    fixture.set(
        json!({"target":{"kind":"signature","function":triple},"text":"int32_t (int32_t value)"}),
    );
    let caller = binary.decompile(invoke, None, None).unwrap();
    assert!(caller.contains("int32_t triple(int32_t);"), "{caller}");
    let callee = binary.decompile(triple, None, None).unwrap();
    assert!(callee.contains("triple(int32_t value)"), "{callee}");
}

#[test]
fn classification_is_persistent_and_reversible() {
    let fixture = Fixture::new();
    let binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("sum3").unwrap().addr;
    fixture.set(json!({"target":{"kind":"classification","address":address},"text":"data"}));
    assert!(
        Binary::open(&fixture.binary)
            .unwrap()
            .function(address)
            .is_err()
    );
    fixture.set(json!({"target":{"kind":"classification","address":address},"text":"code"}));
    assert!(
        Binary::open(&fixture.binary)
            .unwrap()
            .decompile(address, None, None)
            .unwrap()
            .contains("return")
    );
}

#[test]
fn unsupported_types_and_ambiguous_storage_fail_explicitly() {
    let fixture = Fixture::new();
    fixture.set(json!({"target":{"kind":"comment","address":0},"text":"keep"}));
    let before = std::fs::read(project::path(&fixture.binary)).unwrap();
    let failure = fixture.cli(&["set", &json!({"target":{"kind":"parameter","function":0,"storage":{"kind":"register","register":0}},"c_type":"int; return 99;"}).to_string()]);
    assert!(!failure.status.success());
    assert_eq!(
        std::fs::read(project::path(&fixture.binary)).unwrap(),
        before
    );
    fixture.set(json!({"target":{"kind":"local","function":0,"storage":{"kind":"register","register":65535}},"name":"missing"}));
    let error = Binary::open(&fixture.binary)
        .unwrap()
        .decompile(0, None, None)
        .unwrap_err();
    assert!(error.to_string().contains("unknown_storage"));
}

#[test]
fn globals_and_local_definition_names_apply() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let global = *binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, name)| name.ends_with("total"))
        .unwrap()
        .0;
    let address = binary.find("global_add").unwrap().addr;
    fixture.set(json!({"target":{"kind":"global","address":global},"name":"running_total"}));
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("running_total"), "{code}");
    let stack = binary.find("stack_work").unwrap().addr;
    let origins = project::origins(&binary.analysis(stack, None).unwrap().ir);
    let target = origins
        .iter()
        .find(|row| {
            row["target"]["kind"] == "local"
                && row["target"]["storage"]["kind"] == "stack"
                && row["name"]
                    .as_str()
                    .is_some_and(|name| name.contains(".f_4"))
        })
        .expect("a frame field")["target"]
        .clone();
    fixture.set(json!({"target":target,"name":"saved_input","c_type":"int32_t"}));
    let code = binary.decompile(stack, None, None).unwrap();
    assert!(code.contains("int32_t saved_input"), "{code}");
}

#[test]
fn high_addresses_round_trip_without_javascript_precision_loss() {
    let fixture = Fixture::new();
    fixture.set(
        json!({"target":{"kind":"comment","address":"0xfffffffffffffff0"},"text":"high address"}),
    );
    let project = project::load(&fixture.binary).unwrap().unwrap();
    assert_eq!(
        project.annotations[0].target,
        Target::Comment {
            address: u64::MAX - 15
        }
    );
    assert_eq!(
        serde_json::to_value(&project.annotations[0]).unwrap()["target"]["address"],
        "0xfffffffffffffff0"
    );
}

#[test]
fn definition_origins_rename_locals_without_changing_results() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("accumulate").unwrap().addr;
    let origins = project::origins(&binary.analysis(address, None).unwrap().ir);
    fixture
        .set(json!({"target":{"kind":"function","address":address},"name":"annotated_accumulate"}));
    let mut renamed = None;
    for row in origins.iter().filter(|row| {
        row["target"]["kind"] == "local" && row["target"]["storage"]["kind"] == "definition"
    }) {
        fixture.set(json!({"target":row["target"],"name":"partial_sum"}));
        let code = binary.decompile(address, None, None).unwrap();
        if code.contains("partial_sum") {
            renamed = Some(code);
            break;
        }
        let target: Target = serde_json::from_value(row["target"].clone()).unwrap();
        project::update(&fixture.binary, |project| {
            project.remove(&target);
            Ok(())
        })
        .unwrap();
    }
    let code = renamed.expect("a visible local with a definition origin");
    fixture.compile_and_run(&format!("{code}\nint32_t accumulate(int32_t *,int32_t);\nint main(void) {{ int32_t a[8]={{1,2,3,4,5,6,7,8}}; for(int32_t n=0;n<=8;n++) if(annotated_accumulate(a,n)!=accumulate(a,n)) return 1; return 0; }}"));
}

#[test]
fn parse_errors_are_human_readable() {
    let help = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    assert!(String::from_utf8_lossy(&help.stdout).contains("JSON errors after argument parsing"));
    let empty = Command::new(env!("CARGO_BIN_EXE_velk")).output().unwrap();
    assert_eq!(empty.status.code(), Some(2));
    assert!(empty.stderr.is_empty());
    assert_eq!(empty.stdout, help.stdout);
    for args in [
        vec!["--unknown"],
        vec!["--decompile"],
        vec!["--functions", "--sections", "binary"],
        vec!["--annotations"],
        vec!["--functions", "binary", "--limit", "invalid"],
    ] {
        let failure = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(failure.status.code(), Some(2));
        assert!(failure.stdout.is_empty());
        let message = String::from_utf8_lossy(&failure.stderr);
        assert!(message.starts_with("error:"), "{message}");
        assert!(message.contains("Usage:"), "{message}");
        assert!(message.contains("--help"), "{message}");
    }
}

#[test]
fn project_failures_and_duplicate_targets_are_machine_readable() {
    let fixture = Fixture::new();
    let failure = fixture.cli(&["unknown"]);
    assert_eq!(failure.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failure.stderr).starts_with("error:"));
    let failure = fixture.cli(&["origins", "missing_function"]);
    assert!(!failure.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&failure.stderr).unwrap()["code"],
        "analysis_error"
    );
    fixture.set(json!({"target":{"kind":"comment","address":0},"text":"keep"}));
    let before = std::fs::read(project::path(&fixture.binary)).unwrap();
    let error = project::update(&fixture.binary, |project| {
        project.annotations.push(project.annotations[0].clone());
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("duplicate_target"));
    assert_eq!(
        std::fs::read(project::path(&fixture.binary)).unwrap(),
        before
    );
}

#[test]
fn malformed_c_declarations_fail_without_panics_or_writes() {
    let fixture = Fixture::new();
    for declaration in [
        json!({"target":{"kind":"declaration","name":"label"},"text":"typedef int élabel;"}),
        json!({"target":{"kind":"declaration","name":"struct bad"},"text":"struct bad { uint8_t first; uint64_t gap_0x1; };"}),
        json!({"target":{"kind":"declaration","name":"struct bad"},"text":"struct bad { int32_t first; int32_t first; };"}),
        json!({"target":{"kind":"declaration","name":"enum bad"},"text":"enum bad { first = 2147483648 };"}),
    ] {
        let failure = fixture.cli(&["set", &declaration.to_string()]);
        assert!(!failure.status.success());
        let detail: Value = serde_json::from_slice(&failure.stderr).unwrap();
        assert_eq!(detail["code"], "invalid_declaration");
        assert!(!project::path(&fixture.binary).exists());
    }
}

#[test]
fn renaming_to_a_library_function_cannot_enable_library_assumptions() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("triple").unwrap().addr;
    fixture.set(json!({"target":{"kind":"function","address":address},"name":"malloc"}));
    let error = binary.decompile(address, None, None).unwrap_err();
    assert!(error.to_string().contains("name_collision"));
}

#[test]
fn stack_parameter_types_and_signatures_propagate_to_callers() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("ninth").unwrap().addr;
    let caller = binary.find("invoke_ninth").unwrap().addr;
    let ir = &binary.analysis(address, None).unwrap().ir;
    assert_eq!(ir.ret_type.integer(), Some((32, true)));
    assert_eq!(ir.params.len() + ir.stack_params.len(), 9);
    let types = ir
        .params
        .iter()
        .map(|param| &param.ty)
        .chain(ir.stack_params.iter().map(|param| &param.ty));
    for (position, ty) in types.enumerate() {
        // ELF debug types preserve source signedness and refine stack arguments
        // to int32_t; Mach-O infers arithmetic-only register parameters as unsigned
        // and retains the 64-bit stack slot when no debug type is available.
        let width = if position < ir.params.len() || cfg!(target_os = "linux") {
            32
        } else {
            64
        };
        assert_eq!(
            ty.integer(),
            Some((
                width,
                position >= ir.params.len() || cfg!(target_os = "linux")
            ))
        );
    }
    let integer_type = ir.ret_type.to_string();
    let mut parameter_types: Vec<String> =
        ir.params.iter().map(|param| param.ty.to_string()).collect();
    let origins = project::origins(ir);
    let target = origins
        .iter()
        .rfind(|row| {
            row["target"]["kind"] == "parameter" && row["target"]["storage"]["kind"] == "stack"
        })
        .expect("a stack parameter")["target"]
        .clone();
    fixture.set(json!({"target":target,"name":"last_value","c_type":"uint32_t"}));
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("uint32_t last_value"), "{code}");
    let code = binary.decompile(caller, None, None).unwrap();
    parameter_types.push("uint32_t".to_owned());
    let prototype = format!("{integer_type} ninth({});", parameter_types.join(", "));
    assert!(code.contains(&prototype), "{code}");
    fixture.set(json!({"target":{"kind":"signature","function":address},"text":"int32_t (int32_t first, int32_t second, int32_t third, int32_t fourth, int32_t fifth, int32_t sixth, int32_t seventh, int32_t eighth, uint32_t ninth_value)"}));
    let code = binary.decompile(address, None, None).unwrap();
    assert!(
        code.contains("int32_t first") && code.contains("uint32_t last_value"),
        "{code}"
    );
}

#[test]
fn global_types_apply_and_compile_with_the_renamed_object() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("global_add").unwrap().addr;
    let global = *binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, name)| name.ends_with("total"))
        .unwrap()
        .0;
    fixture.set(json!({"target":{"kind":"global","address":global},"name":"running_total","c_type":"int32_t"}));
    fixture
        .set(json!({"target":{"kind":"function","address":address},"name":"annotated_global_add"}));
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("extern int32_t running_total;"), "{code}");
    fixture.compile_and_run(&format!("{code}\nint32_t running_total; extern int32_t total; int32_t global_add(int32_t);\nint main(void) {{ total=running_total=17; for(int32_t i=-20;i<20;i++) if(annotated_global_add(i)!=global_add(i)) return 1; return 0; }}"));
}

#[test]
fn typedef_expansion_cannot_bypass_pointer_depth_limit() {
    let fixture = Fixture::new();
    for depth in 1..=16 {
        let previous = if depth == 1 {
            "int32_t".to_owned()
        } else {
            format!("level{}", depth - 1)
        };
        fixture.set(json!({"target":{"kind":"declaration","name":format!("level{depth}")},"text":format!("typedef {previous} *level{depth};")}));
    }
    let before = std::fs::read(project::path(&fixture.binary)).unwrap();
    let failure = fixture.cli(&["set", &json!({"target":{"kind":"declaration","name":"level17"},"text":"typedef level16 *level17;"}).to_string()]);
    assert!(!failure.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&failure.stderr).unwrap()["code"],
        "unsupported_type"
    );
    assert_eq!(
        std::fs::read(project::path(&fixture.binary)).unwrap(),
        before
    );
}

#[test]
fn generated_function_and_macro_names_are_reserved() {
    let fixture = Fixture::new();
    for name in [
        "sub_401000",
        "VELK_add_lanes32",
        "velk_entry_stack_pointer",
        "va_arg",
    ] {
        let result = fixture.cli(&[
            "set",
            &json!({"target":{"kind":"function","address":0},"name":name}).to_string(),
        ]);
        assert!(!result.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&result.stderr).unwrap()["code"],
            "invalid_identifier"
        );
        assert!(!project::path(&fixture.binary).exists());
    }
}

#[test]
fn operation_helper_collisions_fail_before_c_is_returned() {
    let fixture = Fixture::new();
    std::fs::copy(
        common::fixtures_dir().join("calls_a64.elf"),
        &fixture.binary,
    )
    .unwrap();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let address = binary.find("factorial").unwrap().addr;
    assert!(
        binary
            .decompile(address, None, None)
            .unwrap()
            .contains("#define VELK_add_lanes32")
    );
    fixture.set(json!({"target":{"kind":"function","address":address},"name":"add_lanes32"}));
    let error = binary.decompile(address, None, None).unwrap_err();
    assert!(error.to_string().contains("name_collision"));
}

#[test]
fn shared_declarations_compile_once_across_callees_and_callers() {
    let fixture = Fixture::native();
    let mut binary = Binary::open(&fixture.binary).unwrap();
    let add = binary.find("add_pair").unwrap().addr;
    let relay = binary.find("relay_pair").unwrap().addr;
    fixture.set(json!({"target":{"kind":"declaration","name":"struct record"},"text":"struct record {\n\n int32_t left;\n int32_t right;\n};"}));
    for (address, name) in [(add, "user_add"), (relay, "user_relay")] {
        let target = project::origins(&binary.analysis(address, None).unwrap().ir)
            .into_iter()
            .find(|row| row["target"]["kind"] == "parameter")
            .unwrap()["target"]
            .clone();
        fixture.set(json!({"target":target,"name":"record","c_type":"struct record *"}));
        fixture.set(json!({"target":{"kind":"function","address":address},"name":name}));
    }
    let first = binary.decompile(add, None, None).unwrap();
    let second = binary.decompile(relay, None, None).unwrap();
    let combined = velk::render::combine(&format!("{first}{second}"));
    assert_eq!(combined.matches("struct record {").count(), 1, "{combined}");
    fixture.compile_and_run(&format!("{combined}\nstruct pair {{int32_t first; int32_t second;}}; int32_t add_pair(struct pair *); int32_t relay_pair(struct pair *);\nint main(void) {{ struct record r={{17,-5}}; struct pair expected={{17,-5}}; return user_add(&r)!=add_pair(&expected) || user_relay(&r)!=relay_pair(&expected); }}"));
}

#[test]
fn custom_project_path_supports_read_only_binary_directories() {
    let fixture = Fixture::new();
    let directory = fixture.directory.join("read-only");
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("app.o");
    std::fs::copy(&fixture.binary, &binary).unwrap();
    let destination = fixture.directory.join("annotations.json");
    let mut permissions = std::fs::metadata(&directory).unwrap().permissions();
    let original = permissions.clone();
    permissions.set_readonly(true);
    std::fs::set_permissions(&directory, permissions).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--annotate")
        .arg(&binary)
        .arg(r#"{"target":{"kind":"function","address":"0x0"},"name":"renamed"}"#)
        .arg("--project")
        .arg(&destination)
        .output()
        .unwrap();
    std::fs::set_permissions(&directory, original).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(destination.exists());
    assert!(!project::path(&binary).exists());
    let mut loaded = Binary::open_with_project(&binary, Some(&destination)).unwrap();
    let address = loaded.find("renamed").unwrap().addr;
    assert!(
        loaded
            .decompile(address, None, None)
            .unwrap()
            .contains("renamed(")
    );
}
