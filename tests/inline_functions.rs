//! Compiled memory effects and recognition data across the public interfaces.
mod common;

use std::fs;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::render::Rendered;
use velk::script::Engine;
use velk::service::Binary;

const FUNCTIONS: &[&str] = &[
    "fill13", "fill24", "zero13", "copy24", "move16", "length", "compare",
];

fn arguments(code: &str, name: &str, expressions: &[&str]) -> String {
    let marker = format!("{name}(");
    let signature = code
        .lines()
        .find(|line| line.contains(&marker) && line.ends_with(" {"))
        .unwrap_or_else(|| panic!("missing function {name}: {code}"));
    let (_, parameters) = signature.split_once('(').expect("function parameters open");
    let (parameters, _) = parameters
        .split_once(')')
        .expect("function parameters close");
    let types: Vec<_> = parameters
        .split(',')
        .map(|parameter| {
            let parameter = parameter.trim();
            let end = parameter
                .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .expect("parameter has a type and name");
            &parameter[..=end]
        })
        .collect();
    assert_eq!(types.len(), expressions.len(), "{signature}");
    types
        .iter()
        .zip(expressions)
        .map(|(ty, value)| format!("({ty})(uintptr_t)({value})"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn execute(name: &str, rendered: &Rendered, label: &str, binary: &Binary) {
    let mut reference = include_str!("cases/inline_functions/functions.c").to_owned();
    for function in FUNCTIONS {
        reference = reference.replace(function, &format!("reference_{function}"));
    }
    let expressions: &[&str] = match name {
        "copy24" => &["a+8", "a+48"],
        "move16" => &["a+32", "a+offset"],
        "compare" => &["a", "b"],
        "length" => &["a"],
        _ => &["a+8"],
    };
    let arguments = arguments(&rendered.code, name, expressions);
    let check = match name {
        "length" => {
            format!("a[offset]=0; if ({name}({arguments}) != reference_length(a)) return 1;")
        }
        "compare" => format!(
            "b[(seed*7)%64] ^= (unsigned char)seed; a[offset]=0; b[63-offset]=0; if ({name}({arguments}) != reference_compare(a,b)) return 1;"
        ),
        "copy24" => {
            format!(
                "{name}({arguments}); reference_copy24(b+8,b+48); if (memcmp(a,b,96)) return 1;"
            )
        }
        "move16" => format!(
            "{name}({arguments}); reference_move16(b+32,b+offset); if (memcmp(a,b,96)) return 1;"
        ),
        _ => format!("{name}({arguments}); reference_{name}(b+8); if (memcmp(a,b,96)) return 1;"),
    };
    let mut definitions = String::new();
    let mut initialization = String::new();
    for line in rendered.code.lines() {
        let Some(declaration) = line.strip_prefix("extern ") else {
            continue;
        };
        let (declaration, comment) = declaration
            .split_once(';')
            .expect("global declaration ends");
        let (ty, global) = declaration.rsplit_once(' ').expect("global type and name");
        let address = comment
            .strip_prefix(" /* address: 0x")
            .expect("global has an address")
            .strip_suffix(" */")
            .expect("address comment ends");
        let address = u64::from_str_radix(address, 16).expect("hexadecimal global address");
        if ty == "uint8_t" {
            let global = global.strip_suffix("[]").expect("literal byte array");
            let bytes = binary
                .image()
                .read_vaddr(address, 16)
                .expect("sixteen literal bytes");
            let values = bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            definitions.push_str(&format!(
                "_Alignas(16) uint8_t {global}[16] = {{ {values} }};\n"
            ));
            continue;
        }
        assert!(matches!(ty, "double" | "uint64_t"), "{line}");
        let bytes = binary
            .image()
            .read_vaddr(address, 8)
            .expect("fixture literal exists");
        let bits = u64::from_le_bytes(bytes.try_into().expect("eight literal bytes"));
        definitions.push_str(&format!("{declaration};\n"));
        initialization.push_str(&format!(
            "{{ uint64_t bits=UINT64_C({bits}); memcpy(&{global}, &bits, 8); }}\n"
        ));
    }
    let source = format!(
        "#include <stdint.h>\n#include <string.h>\n{reference}\n{}\n{definitions}\nint main(void) {{ {initialization} _Alignas(16) unsigned char a[96], b[96]; for (unsigned seed=0;seed<256;++seed) {{ for (unsigned offset=0;offset<64;++offset) {{ for(unsigned i=0;i<96;++i) a[i]=b[i]=(unsigned char)(1+(i*17+seed)%255); {check} }} }} return 0; }}\n",
        rendered.code
    );
    let directory = common::root()
        .join("target/inline-function-tests")
        .join(label);
    fs::create_dir_all(&directory).expect("create compilation directory");
    let input = directory.join(format!("{name}.c"));
    let output = directory.join(name);
    common::compiler::compile_file(
        Command::new("cc")
            .args([
                "-std=c11",
                "-O2",
                "-Werror",
                "-fno-inline",
                "-fno-strict-aliasing",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&output),
        &input,
        &source,
    );
    assert!(
        Command::new(&output)
            .status()
            .expect("execute compiled C")
            .success(),
        "{label}: {name}"
    );
}

#[test]
fn optimized_fixtures_compile_and_match_reference_execution() {
    let mut recognized = 0;
    let mut missed = 0;
    let mut report =
        String::from("# Recognition requires one call covering the complete source operation.\n");
    for architecture in ["x86_64", "aarch64"] {
        for compiler in ["clang", "gcc"] {
            for level in [2, 3] {
                for suffix in ["", ".debug"] {
                    let label = format!("{architecture}.{compiler}.O{level}{suffix}");
                    let path =
                        common::root().join(format!("tests/data/inline_functions/{label}.elf"));
                    let mut binary = Binary::open(&path).unwrap();
                    for name in FUNCTIONS {
                        let address = binary.find_address(name).unwrap();
                        let rendered = binary
                            .decompile_with_dependencies(address, None, None)
                            .unwrap();
                        let (expected_function, expected_bytes) = match *name {
                            "fill13" | "zero13" => ("memset", Some(13)),
                            "fill24" => ("memset", Some(24)),
                            "copy24" => ("memmove", Some(24)),
                            "move16" => ("memmove", Some(16)),
                            "length" => ("strlen", None),
                            _ => ("", None),
                        };
                        if rendered.inline_functions.iter().any(|call| {
                            call.function == expected_function && call.bytes == expected_bytes
                        }) {
                            recognized += 1;
                        } else {
                            missed += 1;
                        }
                        execute(name, &rendered, &label, &binary);
                        report.push_str(&format!(
                            "{label} {name}: {}; {} lines\n",
                            serde_json::to_string(&rendered.inline_functions).unwrap(),
                            rendered.code.lines().count()
                        ));
                    }
                }
            }
        }
    }
    eprintln!("recognized={recognized} missed={missed} wrong=0");
    report.push_str(&format!(
        "recognized={recognized} missed={missed} wrong=0\n"
    ));
    assert!(
        common::check_expected(
            &common::root().join("tests/golden/inline_functions.txt"),
            &report
        )
        .is_none(),
        "{report}"
    );
}

#[test]
fn summaries_agree_in_cli_javascript_and_mcp() {
    for architecture in ["x86_64", "aarch64"] {
        for compiler in ["clang", "gcc"] {
            let path = common::root().join(format!(
                "tests/data/inline_functions/{architecture}.{compiler}.O2.elf"
            ));
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--summary")
                .arg(&path)
                .arg("fill13")
                .output()
                .unwrap();
            assert!(output.status.success());
            let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
            let expected = json!([{"function":"memset", "bytes":13}]);
            assert_eq!(summary["inlineFunctions"], expected);
            let code = format!(
                "const b=velk.open({path:?}); b.getFunction('fill13').summary().inlineFunctions"
            );
            let result = Engine::new().unwrap().run(&format!("const b=velk.open({path:?}); JSON.stringify(b.getFunction('fill13').summary().inlineFunctions)"), None);
            assert!(result.error.is_none(), "{:?}", result.error);
            let result: Value = serde_json::from_str(&result.output).unwrap();
            assert_eq!(result, expected);
            let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code}}});
            let output = common::mcp_request(child, &request);
            assert!(output.status.success());
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(response["result"]["isError"], false, "{response}");
            let result: Value =
                serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap();
            assert_eq!(result, expected);
        }
    }
}
