mod common;

use std::time::{Duration, Instant};
use velk::script::Engine;
use velk::service::Binary;
use velk::xrefs::Kind;

fn fixture(name: &str) -> Binary {
    Binary::open(&common::fixtures_dir().join(name))
        .expect("the compiled navigation fixture must be readable")
}

#[test]
fn fixture_calls_and_bounded_paths() {
    let mut binary = fixture("cpp_virtual_x64.elf");
    let method_address = binary.find("Square::area() const").unwrap().addr;
    let caller_address = binary.find("square_area(int)").unwrap().addr;
    let indirect = binary.find("any_area(Shape const*)").unwrap().addr;
    let printed = binary.decompile(caller_address, None, None).unwrap();
    let index = binary.navigation(None).unwrap();
    assert!(index.failures.is_empty());
    assert!(
        index
            .to(method_address)
            .iter()
            .any(|xref| xref.function == caller_address && xref.kind == Kind::ResolvedCall)
    );
    assert_eq!(
        index.path(caller_address, method_address, 0),
        Vec::<u64>::new()
    );
    assert_eq!(
        index.path(caller_address, method_address, 1),
        vec![caller_address, method_address]
    );
    assert_eq!(
        index.path(method_address, method_address, 0),
        vec![method_address]
    );
    assert_eq!(index.graph(caller_address, false, 0), Vec::<u64>::new());
    assert!(
        index
            .graph(method_address, true, 1)
            .contains(&caller_address)
    );
    assert!(
        index
            .from(indirect)
            .iter()
            .any(|xref| xref.kind == Kind::CandidateCall)
    );
    assert!(index.graph(indirect, false, 1).is_empty());
    assert!(
        !index
            .graph(method_address, true, usize::MAX)
            .contains(&method_address)
    );
    let pointer = index as *const _;
    assert_eq!(binary.navigation(None).unwrap() as *const _, pointer);
    assert_eq!(
        binary.decompile(caller_address, None, None).unwrap(),
        printed
    );
}

#[test]
fn jump_table_targets_and_global_accesses() {
    let mut binary = fixture("l5_switch.elf");
    let dense = binary.find("dense").unwrap().addr;
    let index = binary.navigation(None).unwrap();
    assert!(
        index
            .from(dense)
            .iter()
            .any(|xref| xref.kind == Kind::JumpTable)
    );
    assert!(index.graph(dense, false, 1).is_empty());
    let mut binary = fixture("arm64_linked.elf");
    let global = binary.find_address("kName").unwrap();
    let pick = binary.find("pick").unwrap().addr;
    let index = binary.navigation(None).unwrap();
    assert!(
        index
            .to(global)
            .iter()
            .any(|xref| xref.function == pick && xref.kind == Kind::Read)
    );
    let literal = index
        .strings()
        .iter()
        .find(|s| s.text == "velk-aarch64-string")
        .unwrap();
    assert_eq!(literal.encoding, "ascii");
    assert!(!literal.section.is_empty());
}

#[test]
fn timed_out_index_can_be_retried() {
    let mut binary = fixture("calls_a64.elf");
    assert!(
        binary
            .navigation(Some(Instant::now() - Duration::from_secs(1)))
            .is_err()
    );
    assert!(binary.navigation(None).unwrap().failures.is_empty());
}

#[test]
fn cli_and_script_navigation_agree() {
    let path = common::fixtures_dir().join("tail_calls.o");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
        .args([
            "--callers",
            path.to_str().unwrap(),
            "tail_one",
            "--depth",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let code = format!(
        r#"
const b = velk.open({path:?});
const f = b.getFunction("tail_one");
console.log(JSON.stringify(f.callers({{depth: 2}})));
console.log(JSON.stringify(b.callPath("tail_two", "tail_one", {{depth: 1}})));
console.log(JSON.stringify(f.summary()));
console.log(JSON.stringify(b.constants("0x1")));
console.log(JSON.stringify(f.xrefs()));
console.log(JSON.stringify(f.callees()));
console.log(JSON.stringify(b.xrefs("tail_one")));
console.log(JSON.stringify(b.callees("tail_one")));
console.log(JSON.stringify(b.strings()));
console.log(JSON.stringify(b.callers("tail_one", {{depth: 2}})));
"#,
        path = path.to_str().unwrap()
    );
    let outcome = Engine::new().unwrap().run(&code, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    let rows: Vec<serde_json::Value> = outcome
        .output
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(cli, rows[0]);
    assert_eq!(cli, rows[9]);
    assert_eq!(rows[1]["path"].as_array().unwrap().len(), 2);
    assert_eq!(rows[2]["name"], "tail_one");
    assert!(rows[2]["signature"].is_object());
    assert!(!rows[3]["matches"].as_array().unwrap().is_empty());
    assert_eq!(rows[4], rows[6]);
    assert_eq!(rows[5], rows[7]);
    assert!(rows[8]["strings"].is_array());
}

#[test]
fn import_calls_are_queryable_by_name_and_read_the_slot() {
    let mut binary = fixture("metrics/windows.win64.O2.debug.dll");
    let import = binary.find_address("imported_value").unwrap();
    let caller = binary.find("call_import").unwrap().addr;
    let index = binary.navigation(None).unwrap();
    assert!(
        index
            .to(import)
            .iter()
            .any(|x| x.function == caller && matches!(x.kind, Kind::ResolvedCall | Kind::TailCall))
    );
    assert!(
        index
            .to(import)
            .iter()
            .any(|x| x.function == caller && x.kind == Kind::Read)
    );
    assert!(index.graph(import, true, 1).contains(&caller));
    let summary = binary.summary(caller, None).unwrap();
    assert!(
        summary["imports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == "imported_value")
    );
}
