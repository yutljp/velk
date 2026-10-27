//! Compile printed functions and compare them with independent unsigned C formulas.

mod common;

use std::fs;
use std::process::Command;

use velk::service::Binary;

#[test]
fn printed_control_flow_matches_originals() {
    for isa in ["x86_64", "aarch64"] {
        for optimization in ["O0", "O2"] {
            for fixture in ["flattened", "flattened_stores", "predicates"] {
                let path = common::fixtures_dir().join(format!("{fixture}_{isa}_{optimization}.o"));
                let mut binary = Binary::open(&path).unwrap();
                let functions: Vec<_> = binary
                    .image()
                    .functions
                    .values()
                    .map(|function| (function.addr, function.name.clone()))
                    .collect();
                let mut code = String::from("#include <stdint.h>\n");
                let mut checks = String::new();
                for (address, name) in functions {
                    let name = name.as_deref().unwrap();
                    let printed = binary.decompile(address, None, None).unwrap();
                    code.push_str(&printed);
                    let expected = match name {
                        "original_line" | "flattened_line" => "((x + 3u) ^ 85u)",
                        "original_branch" | "flattened_branch" => {
                            "((x & 1u ? x + 3u : x ^ 85u) + 7u)"
                        }
                        "original_loop" | "flattened_loop" => "((x & 15u) * ((x & 15u) - 1u) / 2u)",
                        "variable_transition" => "(x == 29u ? x + 3u : x)",
                        "original" | "opaque_parity" | "opaque_bits" => "(x + 7u)",
                        "original_fixed" | "opaque_fixed" => "(x + (x & 1u ? 2u : 0u) + 7u)",
                        "variable_predicate" => "(x & 1u ? x - 19u : x + 7u)",
                        "original64" | "opaque_parity64" => {
                            checks.push_str(&format!(
                                "if ((uint64_t){name}(wide) != wide + 7ull) return 1;\n"
                            ));
                            continue;
                        }
                        _ => panic!("uncovered function: {name}"),
                    };
                    checks.push_str(&format!(
                        "if ((uint32_t){name}(x) != (uint32_t){expected}) return 1;\n"
                    ));
                    if isa == "x86_64" && optimization == "O0" && name.starts_with("flattened_") {
                        let analysis = binary.analysis(address, None).unwrap();
                        assert!(
                            analysis.simplification.dispatcher_states_removed >= 3,
                            "{name}"
                        );
                        assert!(!printed.contains("for (;;)"), "{printed}");
                    }
                    if name == "variable_transition" {
                        assert_eq!(
                            binary
                                .analysis(address, None)
                                .unwrap()
                                .simplification
                                .dispatcher_states_removed,
                            0
                        );
                    }
                }
                code.push_str(&format!(
                    r#"
int main(void) {{
    uint64_t seed = 0x8f4a7c159e3779b9ull;
    for (uint32_t i = 0; i < 2048; ++i) {{
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint64_t wide = i < 64 ? (i & 1 ? UINT64_MAX - i / 2 : i / 2) : seed;
        uint32_t x = (uint32_t)wide;
        if (x == 11u) continue;
        {checks}
    }}
    return 0;
}}
"#
                ));
                let directory = common::root().join(format!(
                    "target/control-flow/{fixture}_{isa}_{optimization}"
                ));
                fs::create_dir_all(&directory).unwrap();
                let source = directory.join("printed.c");
                for level in ["-O0", "-O2"] {
                    let executable = directory.join(format!("printed{level}"));
                    let mut compiler = Command::new("clang");
                    compiler
                        .args([
                            "-std=c11",
                            "-Werror=implicit-function-declaration",
                            "-fsanitize=undefined",
                            "-fno-sanitize-recover=undefined",
                            level,
                        ])
                        .arg(&source)
                        .arg("-o")
                        .arg(&executable);
                    common::compiler::compile_file(&mut compiler, &source, &code);
                    let result = Command::new(&executable).output().unwrap();
                    assert!(
                        result.status.success(),
                        "{fixture} {isa} {optimization} {level}: {result:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn summaries_expose_simplification_counts() {
    let path = common::fixtures_dir().join("flattened_x86_64_O0.o");
    let mut binary = Binary::open(&path).unwrap();
    let addr = binary.find("flattened_branch").unwrap().addr;
    let card = binary
        .card(addr, velk::card::DEFAULT_BUDGET, None, None)
        .unwrap();
    let summary = binary.summary(addr, None).unwrap();
    assert!(card.simplification.simplified);
    assert_eq!(
        summary["simplification"]["dispatcherStatesRemoved"],
        card.simplification.dispatcher_states_removed
    );
    let code = format!(
        "const f = velk.open({:?}).getFunction('flattened_branch'); [f.card().simplification, f.summary().simplification]",
        path.to_str().unwrap()
    );
    let output = velk::script::Engine::new().unwrap().run(&code, None);
    assert!(output.error.is_none(), "{:?}", output.error);
    assert!(
        output.output.contains("dispatcherStatesRemoved"),
        "{}",
        output.output
    );
}

#[test]
fn reduced_existing_checks_preserve_calls_and_memory() {
    let directory = common::root().join("target/control-flow/redundant-checks");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("checks.c");
    for level in ["-O0", "-O2"] {
        let executable = directory.join(format!("checks{level}"));
        let mut compiler = Command::new("clang");
        compiler
            .args([
                "-std=c11",
                "-Werror=implicit-function-declaration",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=undefined",
                level,
            ])
            .arg(&source)
            .arg("-o")
            .arg(&executable);
        common::compiler::compile_file(
            &mut compiler,
            &source,
            include_str!("cases/control_flow/redundant_checks.c"),
        );
        let result = Command::new(&executable).output().unwrap();
        assert!(result.status.success(), "{level}: {result:?}");
    }
}
