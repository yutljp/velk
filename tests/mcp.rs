//! Exercises the public stdio protocol as an MCP client.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn exchange(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the MCP server starts");
    let mut stdin = child.stdin.take().expect("piped input");
    for request in requests {
        writeln!(stdin, "{request}").expect("the request is written");
    }
    drop(stdin);
    let output = child.wait_with_output().expect("the MCP server exits");
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty(), "{:?}", output);
    String::from_utf8(output.stdout)
        .expect("UTF-8 responses")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect()
}

fn tool(id: usize, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "method":"tools/call",
        "params":{"name":name, "arguments":arguments}})
}

fn script(id: usize, code: &str) -> Value {
    tool(id, "velk_run_script", json!({"code":code}))
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("a text tool result")
}

#[test]
fn com_library_types_are_data_over_stdio() {
    for (fixture, width, convention) in [
        ("crt_windows.i686.exe", 4, "stdcall"),
        ("type_library_windows.win64.exe", 8, "win64"),
    ] {
        let path = common::fixtures_dir().join(fixture);
        let responses = exchange(&[script(
            1,
            &format!("velk.open({path:?}).libraryType('struct IUnknownVtbl')"),
        )]);
        assert_eq!(responses[0]["result"]["isError"], false);
        let record: Value = serde_json::from_str(text(&responses[0])).unwrap();
        assert_eq!(record["size"], 3 * width);
        assert_eq!(record["fields"][0]["name"], "QueryInterface");
        assert_eq!(
            record["fields"][0]["function"]["callingConvention"],
            convention
        );
        assert_eq!(record["fields"][1]["offset"], width);
    }
}

#[test]
fn com_calls_and_guid_names_are_available_over_stdio() {
    for arch in ["x86_64", "i686"] {
        let path = common::fixtures_dir().join(format!("com_{arch}.dll"));
        let responses = exchange(&[script(
            1,
            &format!(
                "const b = velk.open({path:?}); ({{code:b.getFunction('com_read').decompile(), signature:b.getFunction('com_read').signature(), references:b.getFunction('com_file_dialog_class').references()}})"
            ),
        )]);
        assert_eq!(responses[0]["result"]["isError"], false);
        let data: Value = serde_json::from_str(text(&responses[0])).unwrap();
        assert!(data["code"].as_str().unwrap().contains("->lpVtbl->Read("));
        assert_eq!(data["signature"]["params"].as_array().unwrap().len(), 4);
        let guid = data["references"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|reference| reference.get("guid").filter(|guid| !guid.is_null()))
            .unwrap();
        assert!(
            guid["names"]
                .as_array()
                .unwrap()
                .contains(&Value::String("CLSID_FileOpenDialog".into()))
        );
    }
}

#[test]
fn scalar_word_results_match_cli_javascript_and_mcp() {
    for (target, mode) in [
        ("i386-linux-gnu", ""),
        ("armv7a-linux-gnueabihf", "-mthumb"),
    ] {
        let scratch = common::root().join(format!("target/mcp-word-results-{target}"));
        std::fs::create_dir_all(&scratch).unwrap();
        let source = scratch.join("original.c");
        let object = scratch.join("original.o");
        let image = scratch.join("original.elf");
        let mut compiler = Command::new("clang");
        compiler.args(["-target", target, "-c", "-O0", "-fno-inline", "-fno-pic"]);
        if !mode.is_empty() {
            compiler.arg(mode);
        }
        common::compiler::compile_file(
            compiler.arg(&source).arg("-o").arg(&object),
            &source,
            include_str!("recompile/word_pairs.c"),
        );
        let linked = Command::new("ld.lld")
            .args([
                "-m",
                if target.starts_with("i386") {
                    "elf_i386"
                } else {
                    "armelf_linux_eabi"
                },
                "--entry=stack_caller",
            ])
            .arg(&object)
            .arg("-o")
            .arg(&image)
            .output()
            .unwrap();
        assert!(linked.status.success(), "{linked:?}");
        let mut binary = velk::service::Binary::open(&image).unwrap();
        let address = binary.find("g").unwrap().addr;
        let expected = binary.decompile(address, None, None).unwrap();
        assert!(
            binary
                .analysis(address, None)
                .unwrap()
                .ir
                .ret_type
                .integer()
                .is_some_and(|(bits, _)| bits == 64),
            "{expected}"
        );
        let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("-D")
            .arg(&image)
            .arg("g")
            .output()
            .unwrap();
        assert!(cli.status.success(), "{cli:?}");
        assert_eq!(
            String::from_utf8(cli.stdout).unwrap().trim(),
            expected.trim()
        );
        let code = format!("velk.open({image:?}).getFunction('g').decompile()");
        let script_path = scratch.join("decompile.js");
        std::fs::write(&script_path, format!("console.log({code});")).unwrap();
        let javascript = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--run")
            .arg(script_path)
            .output()
            .unwrap();
        assert!(javascript.status.success(), "{javascript:?}");
        assert_eq!(
            String::from_utf8(javascript.stdout).unwrap().trim(),
            expected.trim()
        );
        let responses = exchange(&[script(0, &code)]);
        assert_eq!(responses[0]["result"]["isError"], false);
        assert_eq!(text(&responses[0]), expected);
    }
}

#[test]
fn discovery_and_fresh_scripts_work_over_stdio() {
    let path = common::fixtures_dir().join("arm64.o");
    let responses = exchange(&[
        json!({"jsonrpc":"2.0", "id":0, "method":"initialize",
            "params":{"protocolVersion":"2024-11-05"}}),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}),
        tool(2, "velk_read_api", json!({})),
        tool(3, "velk_read_api", json!({"topic":"binary"})),
        script(
            4,
            &format!("const b=velk.open({path:?}); b.getFunction('sum3').decompile()"),
        ),
        script(5, "typeof b"),
    ]);
    assert_eq!(responses.len(), 6, "notifications have no response");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");
    let mut names = Vec::new();
    for tool in responses[1]["result"]["tools"].as_array().unwrap() {
        names.push(tool["name"].as_str().unwrap());
    }
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "velk_classes",
            "velk_emulate",
            "velk_read_api",
            "velk_run_script"
        ]
    );
    assert!(text(&responses[2]).contains("fresh context"));
    assert!(text(&responses[3]).contains("interface Binary"));
    let mut binary = velk::service::Binary::open(&path).unwrap();
    let addr = binary.find("sum3").unwrap().addr;
    assert_eq!(
        text(&responses[4]),
        binary.decompile(addr, None, None).unwrap()
    );
    assert_eq!(text(&responses[5]), "undefined");
}

#[test]
fn batch_decompilation_example_matches_individual_functions_over_stdio() {
    let path = common::fixtures_dir().join("arm64.o");
    let code = format!(
        r#"
const b = velk.open({path:?});
const functions = b.functions().slice(0, 5);
for (const result of b.decompile(functions)) {{
  if (result.error !== null) throw new Error(result.error);
  const single = b.getFunction(result.addr).decompile();
  if (result.code !== single) throw new Error("function output");
  console.log(result.code);
}}
"#
    );
    let responses = exchange(&[script(0, &code)]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["result"]["isError"], false);
    let mut binary = velk::service::Binary::open(&path).unwrap();
    let addresses: Vec<_> = binary.image().functions.keys().copied().take(5).collect();
    let mut expected = String::new();
    for address in addresses {
        if !expected.is_empty() {
            expected.push('\n');
        }
        expected.push_str(&binary.decompile(address, None, None).unwrap());
    }
    assert_eq!(text(&responses[0]), velk::render::combine(&expected));
}

#[test]
fn errors_are_actionable_and_the_server_recovers() {
    let path = common::fixtures_dir().join("arm64.o");
    let prefix = format!("const b=velk.open({path:?}); ");
    let run = |id, code| script(id, &format!("{prefix}{code}"));
    let responses = exchange(&[
        run(0, "b.getFunction('sum33')"),
        run(1, "b.getFunction('0xffffffffffffffff')"),
        run(2, "b.getFunction('*').decompile()"),
        script(
            3,
            &format!("velk.open({:?})", common::root().join("Cargo.toml")),
        ),
        script(4, "function fail(){throw new Error('broken')} fail()"),
        tool(
            5,
            "velk_run_script",
            json!({"code":"while(true){}", "timeout_ms":5}),
        ),
        script(6, "({answer:42})"),
        tool(7, "velk_read_api", json!({"topic":"x".repeat(30_000)})),
    ]);
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(response["id"], index);
        assert_eq!(response["result"]["isError"], index != 6, "{response}");
        assert!(!text(response).contains("at <eval>"), "{response}");
        assert!(text(response).chars().count() <= 4_000, "{response}");
    }
    assert!(text(&responses[0]).contains("sum3 (0x0)"));
    assert!(text(&responses[1]).contains("exact function start"));
    assert!(text(&responses[2]).contains("slice(0, 5)"));
    assert!(text(&responses[3]).contains("expected an ELF, PE/COFF or Mach-O file"));
    assert_eq!(text(&responses[4]), "error: Error: broken");
    assert!(text(&responses[5]).contains("increase timeout_ms"));
    assert_eq!(text(&responses[6]), "{\"answer\":42}");
}

#[test]
fn large_results_are_bounded_and_slices_retrieve_the_rest() {
    let path = common::fixtures_dir().join("arm64.o");
    let code = format!(
        "const b=velk.open({path:?}); for(const f of b.functions()) console.log(f.decompile())"
    );
    let responses = exchange(&[
        script(0, "'あ🦀'.repeat(20000)"),
        tool(
            1,
            "velk_run_script",
            json!({"code":code, "max_output_chars":256}),
        ),
        script(
            2,
            &format!(
                "velk.open({path:?}).getFunction('sum_arr').decompile().split('\\n').slice(0,20).join('\\n')"
            ),
        ),
        script(
            3,
            &format!(
                "velk.open({path:?}).getFunction('sum_arr').decompile().split('\\n').slice(20).join('\\n')"
            ),
        ),
    ]);
    assert_eq!(text(&responses[0]).chars().count(), 4_000);
    assert_eq!(text(&responses[1]).chars().count(), 256);
    assert!(text(&responses[1]).contains("truncated"));
    for response in &responses {
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    let mut binary = velk::service::Binary::open(&path).unwrap();
    let address = binary.find("sum_arr").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert_eq!(
        format!("{}\n{}", text(&responses[2]), text(&responses[3])),
        code
    );
}

#[test]
fn annotations_refresh_navigation_and_later_scripts() {
    let directory = common::root()
        .join("target")
        .join(format!("mcp-project-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("calls.o");
    let project = directory.join("analysis.json");
    std::fs::copy(common::fixtures_dir().join("tail_calls.o"), &path).unwrap();
    let prefix = format!("const b=velk.open({path:?},{{project:{project:?}}}); ");
    let run = |id, code| script(id, &format!("{prefix}{code}"));
    let responses = exchange(&[
        run(0, "b.xrefs('tail_one')"),
        run(
            1,
            "b.projectSet({target:{kind:'function',address:b.getFunction('tail_one').addr},name:'analyzed_tail'})",
        ),
        run(2, "b.getFunction('analyzed_tail').decompile()"),
        run(
            3,
            "({name:b.getFunction('analyzed_tail').summary().name,callees:b.callees('tail_two').functions,xrefs:b.xrefs('analyzed_tail').xrefs})",
        ),
        run(
            4,
            "b.projectRemove({kind:'function',address:b.getFunction('analyzed_tail').addr})",
        ),
        run(5, "b.getFunction('tail_one').summary().name"),
    ]);
    for response in &responses {
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    assert!(text(&responses[2]).contains("analyzed_tail(int32_t"));
    let navigation: Value = serde_json::from_str(text(&responses[3])).unwrap();
    assert_eq!(navigation["name"], "analyzed_tail");
    assert_eq!(navigation["callees"][0]["name"], "analyzed_tail");
    assert_eq!(navigation["xrefs"][0]["name"], "analyzed_tail");
    assert_eq!(text(&responses[5]), "tail_one");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn classes_tool_matches_the_script_api() {
    let path = common::fixtures_dir().join("cpp/rtti.stripped.elf");
    let responses = exchange(&[
        tool(1, "velk_classes", json!({"path": path})),
        script(2, &format!("velk.open({path:?}).classes()")),
        tool(3, "velk_classes", json!({})),
    ]);
    assert_eq!(text(&responses[0]), text(&responses[1]));
    assert!(text(&responses[0]).contains("Multiple"));
    assert_eq!(responses[0]["result"]["isError"], false);
    assert_eq!(responses[2]["result"]["isError"], true);
}

#[test]
fn structure_layout_data_agrees_across_cli_javascript_and_mcp() {
    for fixture in [
        "metrics/struct_arrays.x86_64.O2.stripped.elf",
        "metrics/struct_arrays.aarch64.O2.stripped.elf",
        "metrics/struct_arrays.win64.O2.stripped.dll",
    ] {
        let path = common::fixtures_dir().join(fixture);
        let mut binary = velk::service::Binary::open(&path).unwrap();
        let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
        let mut checked = 0;
        for addr in addresses {
            let card = binary
                .card(addr, velk::card::DEFAULT_BUDGET, None, None)
                .unwrap();
            let expected = serde_json::to_value(&card).unwrap();
            let Some(layouts) = expected.get("structureLayouts") else {
                continue;
            };
            for layout in layouts.as_array().unwrap() {
                assert!(layout["sourceFields"].is_null());
                assert!(layout["sourceSize"].is_null());
                assert!(
                    layout["elementSize"].as_u64().unwrap()
                        >= layout["minimumSize"].as_u64().unwrap()
                );
                assert!(layout["fields"].as_array().unwrap().len() >= 2);
            }
            let address = velk::addr::format(addr);
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--card")
                .arg(&path)
                .arg(&address)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let cli: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(cli["structureLayouts"], *layouts);
            let code = format!(
                "const b=velk.open({path:?}); JSON.stringify(b.getFunction({address:?}).card().structureLayouts)"
            );
            let outcome = velk::script::Engine::new().unwrap().run(&code, None);
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            assert_eq!(
                serde_json::from_str::<Value>(&outcome.output).unwrap(),
                *layouts
            );
            let responses = exchange(&[script(1, &code)]);
            assert_eq!(responses[0]["result"]["isError"], false);
            assert_eq!(
                serde_json::from_str::<Value>(text(&responses[0])).unwrap(),
                *layouts
            );
            checked += 1;
        }
        assert!(checked > 0, "{fixture}: no inferred array layouts");
    }
}
