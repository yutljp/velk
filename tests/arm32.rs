mod common;

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::process::Command;

use velk::ir::{Stmt, eval};
use velk::loader::{ArmMode, Isa};
use velk::service::Binary;

const HEADER: &str = "#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <math.h>\n#include <string.h>\n#include <stdlib.h>\n";

#[test]
fn every_arm32_fixture_function_has_valid_c_syntax() {
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|path| path.starts_with("arm32"))
        .collect();
    assert_eq!(fixtures.len(), 96);
    let scratch = common::root().join("target/arm32-syntax");
    std::fs::create_dir_all(&scratch).unwrap();
    let mut results = String::new();
    let mut failures = Vec::new();
    for fixture in fixtures {
        let mut binary = Binary::open(&common::fixtures_dir().join(&fixture)).unwrap();
        assert_eq!(binary.image().isa, Isa::Arm32);
        let functions: Vec<_> = binary.image().functions.values().cloned().collect();
        assert!(!functions.is_empty(), "{}", fixture.display());
        let mut complete = 0;
        let mut lifted = 0;
        let mut compiled = 0;
        for function in &functions {
            assert_eq!(function.addr & 1, 0);
            let size = function.size.unwrap();
            let Ok(blocks) = velk::lift::lift(binary.image(), function.addr, size, &HashSet::new())
            else {
                continue;
            };
            lifted += 1;
            complete += usize::from(
                !blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(stmt, Stmt::Unsupported { .. } | Stmt::BrifFlags { .. })),
            );
            let rendered = binary.decompile(function.addr, None, None).unwrap();
            let symbols = velk::render::callee_names(binary.image());
            let mut callees: BTreeSet<_> = symbols
                .functions
                .iter()
                .filter(|(address, _)| **address != function.addr)
                .map(|(_, name)| name.clone())
                .collect();
            let statements = blocks.iter().flat_map(|block| &block.stmts);
            for stmt in statements {
                if let Stmt::Call {
                    target: Some(target),
                    ..
                } = stmt
                    && *target != function.addr
                    && !symbols.functions.contains_key(target)
                {
                    callees.insert(format!("sub_{target:x}"));
                }
            }
            let declarations: String = callees
                .iter()
                .map(|name| format!("extern uint64_t {name}();\n"))
                .collect();
            let source = scratch.join("check.c");
            std::fs::write(&source, format!("{HEADER}{declarations}{rendered}")).unwrap();
            let output = Command::new("clang")
                .args([
                    "-std=c17",
                    "-fsyntax-only",
                    "-Werror=implicit-function-declaration",
                    "-Werror=int-conversion",
                    "-Wno-incompatible-library-redeclaration",
                    "-Wno-unused-value",
                ])
                .arg(&source)
                .output()
                .unwrap();
            if output.status.success() {
                compiled += 1;
            } else {
                failures.push(format!(
                    "{} {}: {}\n{rendered}",
                    fixture.display(),
                    function.name.as_deref().unwrap_or("?"),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        writeln!(
            results,
            "{}: functions {}, complete lifts {}, syntax {}/{}, does not lift {}",
            fixture.display(),
            functions.len(),
            complete,
            compiled,
            lifted,
            functions.len() - lifted
        )
        .unwrap();
    }
    std::fs::write(scratch.join("failures.txt"), failures.join("\n")).unwrap();
    let difference =
        common::check_expected(&common::root().join("tests/golden/arm32.txt"), &results);
    assert!(
        failures.is_empty(),
        "{} syntax failures; see target/arm32-syntax/failures.txt",
        failures.len()
    );
    assert!(difference.is_none(), "{}", difference.unwrap_or_default());
}

#[test]
fn arm32_arithmetic_matches_independent_oracles_and_printed_c() {
    let scratch = common::root().join("target/arm32-semantics");
    std::fs::create_dir_all(&scratch).unwrap();
    for case in ["l0_arith", "l1_branch"] {
        for mode in ["arm", "thumb"] {
            for opt in ["O0", "O2"] {
                let path = common::fixtures_dir().join(format!("arm32/{case}.{mode}.{opt}.elf"));
                let mut binary = Binary::open(&path).unwrap();
                let mut code = String::new();
                let mut assertions = String::new();
                let names: &[&str] = if case == "l0_arith" {
                    &["add3", "scale", "pick", "negate"]
                } else {
                    &["classify", "clamp", "sign_of"]
                };
                for &name in names {
                    let function = binary.find(name).unwrap().clone();
                    assert_eq!(
                        binary.image().arm_mode(function.addr),
                        if mode == "thumb" {
                            ArmMode::Thumb
                        } else {
                            ArmMode::Arm
                        }
                    );
                    let mut ir = binary.analysis(function.addr, None).unwrap().ir.clone();
                    ir.blocks = velk::lift::lift(
                        binary.image(),
                        function.addr,
                        function.size.unwrap(),
                        &HashSet::new(),
                    )
                    .unwrap();
                    code.push_str(&binary.decompile(function.addr, None, None).unwrap());
                    for a in [0u32, 1, 7, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                        for b in [0u32, 3, u32::MAX] {
                            let expected = match name {
                                "add3" => a.wrapping_add(b).wrapping_add(5),
                                "scale" => a.wrapping_mul(7).wrapping_add(3),
                                "pick" => {
                                    if (a as i32) > (b as i32) {
                                        a
                                    } else {
                                        b
                                    }
                                }
                                "negate" => a.wrapping_neg(),
                                "classify" | "sign_of" => {
                                    if (a as i32) < 0 {
                                        u32::MAX
                                    } else if a == 0 {
                                        0
                                    } else {
                                        1
                                    }
                                }
                                "clamp" => {
                                    if (a as i32) < (b as i32) {
                                        b
                                    } else if (a as i32) > 5 {
                                        5
                                    } else {
                                        a
                                    }
                                }
                                _ => unreachable!(),
                            };
                            let registers = [
                                (0, u64::from(a)),
                                (1, u64::from(b)),
                                (2, 5),
                                (13, 0x100000),
                                (14, 0x200001),
                            ];
                            let setup = eval::Setup {
                                seed: 0,
                                convention: eval::Convention {
                                    arguments: &[0, 1, 2, 3],
                                    clobbered: &[0, 1, 2, 3, 12, 14],
                                },
                                registers: &registers,
                                memory: &[],
                                step_limit: 1000,
                            };
                            let outcome = eval::run(&ir, &setup);
                            assert!(
                                matches!(outcome, eval::Outcome::Return { value, .. } if value == u64::from(expected)),
                                "{mode} {opt} {name}({a}, {b}): {outcome:?}\n{}",
                                ir.render()
                            );
                            let args = match name {
                                "add3" | "clamp" => format!("(int32_t){a}u, (int32_t){b}u, 5"),
                                "pick" => format!("(int32_t){a}u, (int32_t){b}u"),
                                _ => format!("(int32_t){a}u"),
                            };
                            writeln!(
                                assertions,
                                "if ((uint32_t){name}({args}) != {expected}u) return 1;"
                            )
                            .unwrap();
                        }
                    }
                }
                code.push_str(&format!("int main(void) {{\n{assertions}return 0;\n}}\n"));
                let source = scratch.join(format!("{case}.{mode}.{opt}.c"));
                std::fs::write(&source, format!("{HEADER}{}", velk::render::combine(&code)))
                    .unwrap();
                for level in ["-O0", "-O2"] {
                    let executable = scratch.join(format!("{case}.{mode}.{opt}{level}"));
                    let output = Command::new("clang")
                        .args([
                            "-fwrapv",
                            "-fno-strict-aliasing",
                            "-Werror=implicit-function-declaration",
                            level,
                        ])
                        .arg(&source)
                        .arg("-o")
                        .arg(&executable)
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert!(
                        Command::new(&executable).status().unwrap().success(),
                        "{mode} {opt} {level}"
                    );
                }
            }
        }
    }
}

#[test]
fn thumb_function_lookup_accepts_the_mode_bit() {
    let mut binary =
        Binary::open(&common::fixtures_dir().join("arm32/l0_arith.thumb.O2.elf")).unwrap();
    let address = binary.find("add3").unwrap().addr;
    assert_eq!(
        binary.find(&format!("0x{:x}", address | 1)).unwrap().addr,
        address
    );
    assert_eq!(
        binary.decompile(address, None, None).unwrap(),
        binary.decompile(address | 1, None, None).unwrap()
    );
    assert_eq!(
        binary.disasm(address, 8).unwrap(),
        binary.disasm(address | 1, 8).unwrap()
    );
}

#[test]
fn arm32_stack_arguments_match_the_interpreter_and_printed_c() {
    let scratch = common::root().join("target/arm32-stack");
    std::fs::create_dir_all(&scratch).unwrap();
    for mode in ["arm", "thumb"] {
        for opt in ["O0", "O2"] {
            let mut binary = Binary::open(
                &common::fixtures_dir().join(format!("arm32/l6_abi.{mode}.{opt}.elf")),
            )
            .unwrap();
            let function = binary.find("six_args").unwrap().clone();
            let mut ir = binary.analysis(function.addr, None).unwrap().ir.clone();
            ir.blocks = velk::lift::lift(
                binary.image(),
                function.addr,
                function.size.unwrap(),
                &HashSet::new(),
            )
            .unwrap();
            let code = binary.decompile(function.addr, None, None).unwrap();
            let mut assertions = String::new();
            for a in [0u32, 7, 0x7fff_ffff, u32::MAX] {
                let values = [a, 2, 3, 5, 11, 13];
                let expected = values
                    .iter()
                    .fold(0u32, |sum, value| sum.wrapping_add(*value));
                let registers = [(0, u64::from(a)), (1, 2), (2, 3), (3, 5)];
                let memory = [(eval::stack_top(Isa::Arm32), 11 | (13 << 32))];
                let setup = eval::Setup {
                    seed: 0,
                    convention: eval::Convention {
                        arguments: &[0, 1, 2, 3],
                        clobbered: &[0, 1, 2, 3, 12, 14],
                    },
                    registers: &registers,
                    memory: &memory,
                    step_limit: 200,
                };
                assert!(
                    matches!(eval::run(&ir, &setup), eval::Outcome::Return { value, .. } if value == u64::from(expected)),
                    "{mode} {opt}\n{}",
                    ir.render()
                );
                writeln!(assertions, "if ((uint32_t)six_args((int32_t){a}u, 2, 3, 5, 11, 13) != {expected}u) return 1;").unwrap();
            }
            let source = scratch.join(format!("{mode}.{opt}.c"));
            std::fs::write(
                &source,
                format!("{HEADER}{code}\nint main(void) {{ {assertions} return 0; }}"),
            )
            .unwrap();
            for level in ["-O0", "-O2"] {
                let executable = scratch.join(format!("{mode}.{opt}{level}"));
                let output = Command::new("clang")
                    .args(["-fwrapv", "-fno-strict-aliasing", level])
                    .arg(&source)
                    .arg("-o")
                    .arg(&executable)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}\n{code}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    Command::new(executable).status().unwrap().success(),
                    "{mode} {opt}\n{code}"
                );
            }
        }
    }
}

#[test]
fn indirect_tail_calls_keep_the_argument_before_exchange() {
    for mode in ["arm", "thumb"] {
        for opt in ["O0", "O2"] {
            let mut binary = Binary::open(
                &common::fixtures_dir().join(format!("arm32/l6_abi.{mode}.{opt}.elf")),
            )
            .unwrap();
            let address = binary.find("tail_indirect").unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(!code.contains("velk_jump_target"), "{code}");
            assert!(code.contains("uint32_t (*)"), "{code}");
            assert!(!code.contains("0xfffffffe"), "{code}");
            assert!(code.contains("x + 1"), "{code}");
        }
    }
}

#[test]
fn thumb_entry_presence_uses_the_tagged_address() {
    let mut bytes =
        std::fs::read(common::fixtures_dir().join("arm32/l0_arith.thumb.O2.elf")).unwrap();
    assert_eq!(bytes[4], 1);
    bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
    let scratch = common::root().join("target/arm32-entry.elf");
    std::fs::write(&scratch, bytes).unwrap();
    let image = velk::loader::load(&scratch).unwrap();
    assert_eq!(image.entry, Some(0));
    assert_eq!(image.arm_mode(0), ArmMode::Thumb);
}
