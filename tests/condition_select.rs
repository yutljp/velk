mod common;

use std::collections::HashSet;
use std::fmt::Write as _;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use velk::ir::{CType, Param, Stmt, eval};
use velk::service::Binary;

fn fixtures() -> &'static std::path::Path {
    static OUT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    OUT.get_or_init(|| {
        let root = common::root();
        let out = root.join(format!("target/condition-test-{}", std::process::id()));
        assert!(
            Command::new("sh")
                .arg(root.join("tests/scripts/make_condition_fixtures.sh"))
                .arg(&out)
                .status()
                .expect("fixture build starts")
                .success()
        );
        out
    })
}

#[test]
fn condition_joins() {
    let out = fixtures();
    let mut printed = String::new();
    let mut checks = String::new();
    for architecture in ["arm32", "aarch64", "x86_64", "i386"] {
        let mut binary = Binary::open(&out.join(format!("{architecture}.elf"))).unwrap();
        let conditions = [
            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
            "pe", "po",
        ];
        let widths: &[u32] = match architecture {
            "arm32" => &[32],
            "aarch64" => &[32, 64],
            "i386" => &[8, 16, 32],
            _ => &[8, 16, 32, 64],
        };
        for &width in widths {
            for (condition, name) in conditions.iter().enumerate() {
                if matches!(architecture, "arm32" | "aarch64") && condition >= 14 {
                    continue;
                }
                let suffix = if width == 32 {
                    String::new()
                } else {
                    format!("_{width}")
                };
                let function = binary
                    .find(&format!("select_{name}{suffix}"))
                    .unwrap()
                    .clone();
                let mut ir = binary.analysis(function.addr, None).unwrap().ir.clone();
                ir.blocks = velk::lift::lift(
                    binary.image(),
                    function.addr,
                    function.size.unwrap(),
                    &HashSet::new(),
                )
                .unwrap();
                assert!(
                    !ir.blocks
                        .iter()
                        .flat_map(|b| &b.stmts)
                        .any(|s| matches!(s, Stmt::Unsupported { .. } | Stmt::BrifFlags { .. })),
                    "{}",
                    ir.render()
                );
                ir.name = Some(format!("{architecture}_{name}_{width}"));
                let indices = if matches!(architecture, "arm32" | "aarch64") {
                    [0, 1, 2]
                } else {
                    [7, 6, 2]
                };
                ir.params = ["a", "b", "choose"]
                    .iter()
                    .zip(indices)
                    .map(|(name, index)| Param {
                        index,
                        name: (*name).into(),
                        ty: CType::U64,
                    })
                    .collect();
                velk::passes::optimize(&mut ir, false);
                printed.push_str(&velk::render::render(&ir, &[], &Default::default(), &[]));
                let mask = u64::MAX >> (64 - width);
                let sign = 1u64 << (width - 1);
                for a in [0, 1, sign - 1, sign, mask] {
                    for b in [0, 1, sign - 1, sign, mask] {
                        for choose in [0u64, 1] {
                            let result = if choose != 0 {
                                a.wrapping_add(b)
                            } else {
                                a.wrapping_sub(b)
                            } & mask;
                            let carry = if choose != 0 {
                                u128::from(a) + u128::from(b) > u128::from(mask)
                            } else {
                                a >= b
                            };
                            let overflow = if choose != 0 {
                                (!(a ^ b) & (a ^ result) & sign) != 0
                            } else {
                                ((a ^ b) & (a ^ result) & sign) != 0
                            };
                            let n = result & sign != 0;
                            let z = result == 0;
                            let carry = if matches!(architecture, "x86_64" | "i386") && choose != 0
                            {
                                !carry
                            } else {
                                carry
                            };
                            let parity = (result as u8).count_ones().is_multiple_of(2);
                            let expected = match condition {
                                0 => z,
                                1 => !z,
                                2 => carry,
                                3 => !carry,
                                4 => n,
                                5 => !n,
                                6 => overflow,
                                7 => !overflow,
                                8 => carry && !z,
                                9 => !carry || z,
                                10 => n == overflow,
                                11 => n != overflow,
                                12 => !z && n == overflow,
                                13 => z || n != overflow,
                                14 => parity,
                                _ => !parity,
                            };
                            let regs = [(indices[0], a), (indices[1], b), (indices[2], choose)];
                            let setup = eval::Setup {
                                seed: 0,
                                convention: eval::Convention {
                                    arguments: &[],
                                    clobbered: &[],
                                },
                                registers: &regs,
                                memory: &[],
                                step_limit: 300,
                            };
                            assert!(
                                matches!(eval::run(&ir, &setup), eval::Outcome::Return { value, .. } if value == u64::from(expected)),
                                "{name} {a:x} {b:x} {choose}: {}",
                                ir.render()
                            );
                            writeln!(
                            checks,
                            "if ({architecture}_{name}_{width}({a}ull, {b}ull, {choose}ull) != {}) return 1;",
                            u8::from(expected)
                        )
                        .unwrap();
                        }
                    }
                }
            }
        }
    }
    let code = velk::render::combine(&format!(
        "#include <stdint.h>\n{printed}\nint main(void) {{ {checks} return 0; }}"
    ));
    std::fs::write(out.join("check.c"), code).unwrap();
    assert!(
        Command::new("clang")
            .args(["-std=c11", "-O2", "-Werror"])
            .arg(out.join("check.c"))
            .arg("-o")
            .arg(out.join("check"))
            .status()
            .unwrap()
            .success()
    );
    assert!(Command::new(out.join("check")).status().unwrap().success());
}

#[test]
fn internal_pc_targets() {
    let out = fixtures();
    let mut binary = Binary::open(&out.join("arm32.elf")).unwrap();
    let ip = binary.find("pc_load_ip").unwrap().addr;
    let ip_code = binary.decompile(ip, None, None).unwrap();
    assert!(ip_code.contains("unsupported:"), "{ip_code}");
    for name in [
        "arm",
        "thumb",
        "arm_thumb",
        "thumb_arm",
        "register",
        "shifted",
        "negative",
        "split",
    ] {
        let function = binary.find(&format!("pc_internal_{name}")).unwrap().clone();
        let target_bytes = if matches!(name, "thumb" | "arm_thumb") {
            4
        } else if name == "split" {
            12
        } else {
            8
        };
        let expected = function.addr + function.size.unwrap() - target_bytes - 4;
        let raw = velk::lift::lift(
            binary.image(),
            function.addr,
            function.size.unwrap(),
            &HashSet::new(),
        )
        .unwrap();
        assert!(
            !raw.iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::Unsupported { .. } | Stmt::BrIndirect { .. })),
            "{raw:#?}"
        );
        let ir = binary.analysis(function.addr, None).unwrap().ir.clone();
        assert!(
            !ir.blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(
                    stmt,
                    Stmt::Unsupported { .. } | Stmt::BrIndirect { .. } | Stmt::Call { .. }
                )),
            "{}",
            ir.render()
        );
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[],
            memory: &[],
            step_limit: 100,
        };
        assert!(
            matches!(eval::run(&ir, &setup), eval::Outcome::Return { value, .. } if value == expected),
            "{}",
            ir.render()
        );
        let code = binary.decompile(function.addr, None, None).unwrap();
        assert!(!code.contains("unsupported:"), "{code}");
        let source = velk::render::combine(&format!(
            "#include <stdint.h>\n{code}\nint main(void) {{ return pc_internal_{name}() != {expected}u; }}"
        ));
        let source_path = out.join(format!("internal-{name}.c"));
        let binary_path = out.join(format!("internal-{name}"));
        std::fs::write(&source_path, source).unwrap();
        assert!(
            Command::new("clang")
                .args(["-std=c11", "-O2", "-Werror"])
                .arg(source_path)
                .arg("-o")
                .arg(&binary_path)
                .status()
                .unwrap()
                .success()
        );
        assert!(Command::new(binary_path).status().unwrap().success());
    }
}

#[test]
fn rejected_pc_targets() {
    let out = fixtures();
    let mut binary = Binary::open(&out.join("arm32.elf")).unwrap();
    for name in ["invalid_mode", "unaligned", "outside"] {
        let function = binary.find(&format!("pc_internal_{name}")).unwrap().clone();
        let code = binary.decompile(function.addr, None, None).unwrap();
        assert!(
            code.contains("ARM PC load with writeback requires a proven internal target"),
            "{code}"
        );
        assert!(
            !binary
                .analysis(function.addr, None)
                .unwrap()
                .ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::Call { .. })),
            "{code}"
        );
    }
}

#[test]
fn interfaces() {
    let out = fixtures();
    check_interfaces(&out.join("arm32.elf"), "pc_internal_arm");
    check_interfaces(&out.join("x86_64.elf"), "select_vs");
}

#[test]
fn pc_load_modes() {
    let out = fixtures();
    let mut binary = Binary::open(&out.join("arm32.elf")).unwrap();
    let arm = binary.find("pc_load_arm").unwrap().clone();
    let thumb_target = binary.find("pc_load_thumb").unwrap().addr + 4;
    let mut exchange = binary.analysis(arm.addr, None).unwrap().ir.clone();
    exchange.blocks = velk::lift::lift(
        binary.image(),
        arm.addr,
        thumb_target + 4 - arm.addr,
        &HashSet::from([thumb_target]),
    )
    .unwrap();
    let registers = [(1, 0x1000)];
    let memory = [(0x1004, thumb_target | 1)];
    let setup = eval::Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &registers,
        memory: &memory,
        step_limit: 300,
    };
    assert!(
        matches!(
            eval::run(&exchange, &setup),
            eval::Outcome::Return { value: 0x1004, .. }
        ),
        "{}",
        exchange.render()
    );
    for mode in ["arm", "thumb"] {
        let function = binary.find(&format!("pc_load_{mode}")).unwrap().clone();
        let target = function.addr + 4;
        let mut ir = binary.analysis(function.addr, None).unwrap().ir.clone();
        let size = if mode == "arm" { 12 } else { 8 };
        ir.blocks = velk::lift::lift(
            binary.image(),
            function.addr,
            size,
            &HashSet::from([target]),
        )
        .unwrap();
        assert!(
            !ir.blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s, Stmt::Unsupported { .. })),
            "{}",
            ir.render()
        );
        let registers = [(1, 0x1000)];
        let memory = [(0x1004, target | u64::from(mode == "thumb"))];
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &registers,
            memory: &memory,
            step_limit: 300,
        };
        assert!(
            matches!(
                eval::run(&ir, &setup),
                eval::Outcome::Return { value: 0x1004, .. }
            ),
            "{}",
            ir.render()
        );
        let code = binary.decompile(function.addr, None, None).unwrap();
        assert!(!code.contains("unsupported:"), "{code}");
        #[cfg(target_os = "linux")]
        {
            let source = format!(
                "{code}\nstatic uint32_t table[2];\n\
                 static uint32_t destination(uint32_t a, uint32_t b) {{ (void)a; return b; }}\n\
                 int main(void) {{ table[1] = (uint32_t)(uintptr_t)destination; \
                 return pc_load_{mode}(0, (uint32_t)(uintptr_t)table) != \
                 (uint32_t)(uintptr_t)&table[1]; }}\n"
            );
            let source_path = out.join(format!("pc-{mode}.c"));
            let binary_path = out.join(format!("pc-{mode}"));
            std::fs::write(&source_path, source).unwrap();
            assert!(
                Command::new("clang")
                    .args([
                        "-std=c11",
                        "-O2",
                        "-Werror",
                        "-Wno-int-to-pointer-cast",
                        "-Wno-deprecated-non-prototype",
                        "-fno-pie",
                        "-no-pie",
                    ])
                    .arg(source_path)
                    .arg("-o")
                    .arg(&binary_path)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(Command::new(binary_path).status().unwrap().success());
        }
    }
}

fn check_interfaces(path: &std::path::Path, name: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-D")
        .arg(path)
        .arg(name)
        .output()
        .expect("the fixture interface succeeds");
    assert!(output.status.success());
    let cli = String::from_utf8(output.stdout).expect("the fixture interface succeeds");
    assert!(!cli.contains("unsupported:"), "{cli}");
    let script = format!("velk.open({path:?}).getFunction({name:?}).decompile()");
    let result = velk::script::Engine::new()
        .expect("the fixture interface succeeds")
        .run(&script, None);
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.output.trim(), cli.trim());
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the fixture interface succeeds");
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":script}}});
    let output = common::mcp_request(child, &request);
    assert!(output.status.success());
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("the fixture interface succeeds");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("the fixture interface succeeds")
            .trim(),
        cli.trim()
    );
}
