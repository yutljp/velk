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
        assert_eq!(
            lifted,
            functions.len(),
            "{} has functions that do not lift",
            fixture.display()
        );
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

#[test]
fn extend_divide_bitfield_and_vfp_match_printed_c() {
    let scratch = common::root().join("target/arm32-instructions");
    std::fs::create_dir_all(&scratch).unwrap();
    let instructions = [
        "sxtb r0, r0",
        "sxth r0, r0",
        "uxtb r0, r0",
        "uxth r0, r0",
        "sxtb r0, r0, ror #8",
        "sxth r0, r0, ror #16",
        "uxtb r0, r0, ror #24",
        "uxth r0, r0, ror #8",
        "sdiv r0, r0, r1",
        "udiv r0, r0, r1",
        "ubfx r0, r0, #4, #4",
        "vmov s0, r0\nvmov s1, r1\nvadd.f32 s0, s0, s1\nvmov r0, s0",
        "vmov s0, r0\nvmov s1, r1\nvsub.f32 s0, s0, s1\nvmov r0, s0",
        "vmov s0, r0\nvmov s1, r1\nvmla.f32 s0, s0, s1\nvmov r0, s0",
        "vmov s0, r0\nvcvt.f64.f32 d16, s0\nvmov s0, r1\nvcvt.f64.f32 d17, s0\nvadd.f64 d0, d16, d17\nvcvt.f32.f64 s0, d0\nvmov r0, s0",
        "vmov s0, r0\nvcvt.f64.f32 d0, s0\nvcvt.s32.f64 s0, d0\nvmov r0, s0",
        "vmov s0, r0\nvmov s1, r1\nvcmp.f32 s0, s1\nvmrs APSR_nzcv, fpscr\nmov r0, #0\n{it}movlt r0, #1",
        "vmov s0, r0\nvcvt.f64.f32 d0, s0\nvmov s2, r1\nvcvt.f64.f32 d1, s2\nvcmp.f64 d0, d1\nvmrs APSR_nzcv, fpscr\nmov r0, #0\n{it}movlt r0, #1",
        "rev r0, r0",
    ];
    let edges = [
        0u32,
        1,
        255,
        256,
        0x1234_5678,
        0x3f80_0000,
        0x3f80_0001,
        0xbf7f_fffe,
        0xbfc0_0000,
        0x7f80_0000,
        0xff80_0000,
        0x7fff_ffff,
        0x8000_0000,
        u32::MAX,
    ];
    for mode in ["arm", "thumb"] {
        let mut assembly =
            format!(".syntax unified\n.cpu cortex-a15\n.fpu neon-vfpv4\n.{mode}\n.text\n");
        for (index, instruction) in instructions.iter().enumerate() {
            if mode == "thumb" {
                assembly.push_str(".thumb_func\n");
            }
            let instruction =
                instruction.replace("{it}", if mode == "thumb" { "it lt\n" } else { "" });
            writeln!(assembly, ".global case_{index}\n.type case_{index}, %function\ncase_{index}:\n{instruction}\nbx lr\n.size case_{index}, .-case_{index}").unwrap();
        }
        let source = scratch.join(format!("{mode}.s"));
        let object = scratch.join(format!("{mode}.o"));
        std::fs::write(&source, assembly).unwrap();
        let output = Command::new("clang")
            .args(["--target=armv7a-linux-gnueabihf", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut binary = Binary::open(&object).unwrap();
        let mut code = String::from(HEADER);
        let mut checks = String::new();
        for index in 0..instructions.len() {
            let name = format!("case_{index}");
            let function = binary.find(&name).unwrap().clone();
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
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(stmt, Stmt::Unsupported { .. } | Stmt::BrifFlags { .. })),
                "{mode} {name}: {}",
                ir.render()
            );
            let printed = binary.decompile(function.addr, None, None).unwrap();
            assert!(!printed.contains("unsupported"), "{printed}");
            code.push_str(&printed);
            let parameter_count = ir.params.len();
            for &left in &edges {
                for &right in &edges {
                    let a = f32::from_bits(left);
                    let b = f32::from_bits(right);
                    let expected = match index {
                        0 => left as i8 as u32,
                        1 => left as i16 as u32,
                        2 => left & 255,
                        3 => left & 65535,
                        4 => left.rotate_right(8) as i8 as u32,
                        5 => left.rotate_right(16) as i16 as u32,
                        6 => left.rotate_right(24) & 255,
                        7 => left.rotate_right(8) & 65535,
                        8 if right == 0 => 0,
                        8 => (left as i32).wrapping_div(right as i32) as u32,
                        9 if right == 0 => 0,
                        9 => left / right,
                        10 => (left >> 4) & 15,
                        11 => (a + b).to_bits(),
                        12 => (a - b).to_bits(),
                        13 => (a + a * b).to_bits(),
                        14 => ((f64::from(a) + f64::from(b)) as f32).to_bits(),
                        15 => (a as i32) as u32,
                        // LT tests N != V: unordered also satisfies it.
                        16 | 17 => u32::from(a < b || a.is_nan() || b.is_nan()),
                        18 => left.swap_bytes(),
                        _ => unreachable!(),
                    };
                    let expected_nan =
                        (11..=14).contains(&index) && f32::from_bits(expected).is_nan();
                    let registers = [(0, u64::from(left)), (1, u64::from(right))];
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
                    let result = eval::run(&ir, &setup);
                    assert!(
                        matches!(result, eval::Outcome::Return { value, .. } if value == u64::from(expected)
                            || (expected_nan && f32::from_bits(value as u32).is_nan())),
                        "{mode} {name}({left:#x}, {right:#x}): {result:?}, expected {expected:#x}\n{}",
                        ir.render()
                    );
                    let args = if parameter_count == 2 {
                        format!("{left}u, {right}u")
                    } else {
                        format!("{left}u")
                    };
                    let mismatch = if expected_nan {
                        format!(
                            "!isnan(((union {{ uint32_t bits; float value; }}){{ .bits = (uint32_t){name}({args}) }}).value)"
                        )
                    } else {
                        format!("(uint32_t){name}({args}) != {expected}u")
                    };
                    writeln!(checks, "if ({mismatch}) return {};", index + 1).unwrap();
                }
            }
        }
        writeln!(code, "int main(void) {{\n{checks}return 0;\n}}").unwrap();
        let source = scratch.join(format!("{mode}.c"));
        std::fs::write(&source, velk::render::combine(&code)).unwrap();
        for level in ["-O0", "-O2"] {
            let executable = scratch.join(format!("{mode}{level}"));
            let output = Command::new("clang")
                .args([
                    "-fwrapv",
                    "-ffp-contract=off",
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
            let status = Command::new(&executable).status().unwrap();
            assert!(status.success(), "{mode} {level}: {status}");
        }
    }
}
