//! Compare printed MBA functions with native source and unsigned formulas.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::service::Binary;

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory = common::root().join(format!("target/mba-tests-{}", std::process::id()));
        let output = Command::new("sh")
            .arg(common::root().join("tests/make_mba_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("building the MBA fixtures");
        assert!(output.status.success(), "{output:?}");
        directory
    })
}

const CASES: &[(&str, &str)] = &[
    ("mba_add", "x + y"),
    ("mba_xor", "x ^ y"),
    ("mba_or", "x | y"),
    ("mba_identity", "x"),
    ("mba_constant", "42ull"),
    ("mba_scaled", "7 * y"),
    ("mba_square", "2 * x * y"),
    ("different_coefficient", "(x ^ y) + 3 * (x & y)"),
    ("unchanged_shift", "(x ^ y) + ((x & y) >> 1)"),
    ("mba_add32", "(uint32_t)((uint32_t)x + (uint32_t)y)"),
    ("mba_add16", "(uint16_t)((uint16_t)x + (uint16_t)y)"),
    ("mba_add8", "(uint8_t)((uint8_t)x + (uint8_t)y)"),
    ("mba_product", "x * y"),
];

#[test]
fn printed_functions_match_native_source_and_formulas() {
    for isa in ["x86_64", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{isa}_{optimization}.o"));
            let mut binary = Binary::open(&path).unwrap();
            let mut source = String::from("#include <stdint.h>\n");
            for &(name, _) in CASES {
                source.push_str(&format!("#define {name} reference_{name}\n"));
            }
            source.push_str(include_str!("cases/mba/expressions.c"));
            for &(name, _) in CASES {
                source.push_str(&format!("\n#undef {name}\n"));
            }
            let mut checks = String::new();
            for &(name, expected) in CASES {
                let address = binary.find(name).unwrap().addr;
                let printed = binary.decompile(address, None, None).unwrap();
                let count = binary
                    .analysis(address, None)
                    .unwrap()
                    .simplification
                    .mba_expressions_simplified;
                eprintln!(
                    "{isa} {optimization} {name}: {} rewrites={count} lines={} bytes={}",
                    if count == 0 {
                        "unchanged"
                    } else {
                        "simplified"
                    },
                    printed.lines().count(),
                    printed.len()
                );
                if name.starts_with("unchanged_") {
                    assert_eq!(count, 0, "{printed}");
                }
                if optimization == "O0"
                    && [
                        "mba_add",
                        "mba_xor",
                        "mba_or",
                        "mba_identity",
                        "mba_constant",
                        "mba_scaled",
                        "mba_product",
                    ]
                    .contains(&name)
                {
                    assert!(count > 0, "{isa} {name}: {printed}");
                    assert!(
                        !printed.contains(" & ") && !printed.contains(" ^ ") || name == "mba_xor",
                        "{printed}"
                    );
                }
                source.push_str(&printed);
                // Constant/identity simplification can remove an unused parameter.
                let params = binary.analysis(address, None).unwrap().ir.params.len();
                let args = match params {
                    0 => "",
                    1 if name == "mba_scaled" => "y",
                    1 => "x",
                    2 => "x, y",
                    _ => panic!("unexpected parameter count: {printed}"),
                };
                let result_type = match name {
                    "mba_add32" => "uint32_t",
                    "mba_add16" => "uint16_t",
                    "mba_add8" => "uint8_t",
                    _ => "uint64_t",
                };
                checks.push_str(&format!("if ((uint64_t)({result_type}){name}({args}) != (uint64_t)({expected}) || reference_{name}(x,y) != (uint64_t)({expected})) return {index};\n", index = checks.lines().count() + 1));
            }
            source.push_str(&format!(r#"
int main(void) {{
    const uint64_t edges[] = {{0,1,2,0x7f,0x80,0xff,0xffff,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000,UINT64_MAX}};
    uint64_t seed = 0x8f4a7c159e3779b9ull;
    for (unsigned i = 0; i < 65536; ++i) {{
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint64_t x = i < 169 ? edges[i / 13] : seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint64_t y = i < 169 ? edges[i % 13] : seed;
        {checks}
    }}
    return 0;
}}
"#));
            let file = fixtures().join(format!("{isa}_{optimization}.c"));
            for level in ["-O0", "-O2"] {
                let executable = file.with_extension(format!("{level}.exe"));
                let mut compiler = Command::new("clang");
                compiler
                    .args([
                        "-std=c11",
                        "-Werror=implicit-function-declaration",
                        "-fsanitize=undefined",
                        "-fno-sanitize-recover=undefined",
                        level,
                    ])
                    .arg(&file)
                    .arg("-o")
                    .arg(&executable);
                common::compiler::compile_file(&mut compiler, &file, &source);
                let output = Command::new(&executable).output().unwrap();
                assert!(
                    output.status.success(),
                    "{isa} {optimization} {level}: {output:?}"
                );
            }
        }
    }
}

#[test]
fn cli_javascript_and_mcp_expose_counts() {
    use std::io::Write as _;

    let path = fixtures().join("x86_64_O0.o");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--card")
        .arg(&path)
        .arg("mba_add")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let card: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected = &card["simplification"];
    assert_eq!(expected["simplified"], true);
    assert!(expected["mbaExpressionsSimplified"].as_u64().unwrap() > 0);
    // This is also the documented JavaScript example.
    let script = format!(
        "const f = velk.open({path:?}).getFunction('mba_add'); [f.card().simplification, f.summary().simplification]"
    );
    let output = velk::script::Engine::new().unwrap().run(&script, None);
    assert!(output.error.is_none(), "{:?}", output.error);
    let javascript: Value = serde_json::from_str(&output.output).unwrap();
    assert_eq!(javascript, json!([expected, expected]));
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":script}}});
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mcp: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(mcp, javascript);
}

#[test]
fn complemented_structure_indexes_keep_named_fields() {
    let mut binary = Binary::open(&common::fixtures_dir().join("rust_probe")).unwrap();
    let address = binary
        .image()
        .functions
        .values()
        .find(|function| {
            function.name.as_deref().is_some_and(|name| {
                name.starts_with("core::slice::sort::stable::drift::sort::<")
                    && name.contains("gimli::common::DebugInfoOffset")
            })
        })
        .expect("the fixture includes stable sorting")
        .addr;
    let printed = binary.decompile(address, None, None).unwrap();
    assert!(
        printed.lines().any(|line| {
            line.split_once(".high.s64 = ")
                .is_some_and(|(_, value)| value.contains("[~") && value.contains("].f_8"))
        }),
        "{printed}"
    );
}
