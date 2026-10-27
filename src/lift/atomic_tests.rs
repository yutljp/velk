use std::collections::HashSet;
use std::process::Command;

use crate::ir::eval::{self, Outcome};
use crate::ir::{CType, Expr, FunctionIr, Param, Stmt};
use crate::loader::{Image, Isa};

fn lifted(isa: Isa, bytes: &[u8], result: Expr) -> FunctionIr {
    let image = Image::from_code(isa, 0, bytes.to_vec());
    let mut ir = FunctionIr::single_block(isa, vec![]);
    ir.blocks = super::lift(&image, 0, bytes.len() as u64, &HashSet::new()).unwrap();
    for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        assert!(!matches!(stmt, Stmt::Unsupported { .. }), "{stmt:?}");
        if let Stmt::Ret { value } = stmt {
            *value = result.clone();
        }
    }
    ir
}

fn check_atomic_result(
    mut ir: FunctionIr,
    registers: &[u16],
    initial: u64,
    argument: u64,
    expected: u64,
    name: &str,
) -> String {
    let pointer = registers[0];
    let inputs = [
        (pointer, 0x1000),
        (registers[1], argument),
        (registers[2], initial),
    ];
    let memory = [(0x1000, initial)];
    let setup = eval::Setup {
        seed: 1,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &inputs,
        memory: &memory,
        step_limit: 1000,
    };
    for optimize in [false, true] {
        if optimize {
            crate::passes::optimize(&mut ir, false);
        }
        assert!(
            matches!(eval::run(&ir, &setup), Outcome::Return { value, .. } if value == expected),
            "{}: {:?}\n{}",
            name,
            eval::run(&ir, &setup),
            ir.render()
        );
    }
    ir.name = Some(name.to_owned());
    ir.params = registers
        .iter()
        .zip(["p", "operand", "expected"])
        .map(|(&index, name)| Param {
            index,
            name: name.to_owned(),
            ty: CType::U64,
        })
        .collect();
    let printed = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(printed.contains("__atomic_"), "{printed}");
    printed
}

pub(super) fn compile_run(code: &str, name: &str) {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/atomic-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join(format!("{name}.c"));
    std::fs::write(&source, code).unwrap();
    for level in ["-O0", "-O2"] {
        let binary = dir.join(format!("{name}{level}"));
        let mut command = Command::new("clang");
        if name == "wide" {
            command.arg("-mcx16");
            if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
                command.args(["-arch", "x86_64"]);
            }
        }
        let compiled = command
            .args(["-std=c11", level, "-Werror", "-Wno-unused-variable"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}\n{code}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let result = Command::new(&binary).output().unwrap();
        assert!(result.status.success(), "{result:?}\n{code}");
    }
}

#[test]
fn x86_atomic_families_print_compile_and_execute() {
    let mut code = String::from("#include <stdint.h>\n");
    let mut main = String::from("int main(void) { uint64_t v;\n");
    for (name, bytes, initial, operand, updated) in [
        ("add", vec![0xf0, 0x48, 0x01, 0x37], 5, 3, 8),
        ("sub", vec![0xf0, 0x48, 0x29, 0x37], 5, 3, 2),
        ("inc", vec![0xf0, 0x48, 0xff, 0x07], 5, 3, 6),
        ("dec", vec![0xf0, 0x48, 0xff, 0x0f], 5, 3, 4),
        ("bit_and", vec![0xf0, 0x48, 0x21, 0x37], 5, 3, 1),
        ("bit_or", vec![0xf0, 0x48, 0x09, 0x37], 5, 3, 7),
        ("bit_xor", vec![0xf0, 0x48, 0x31, 0x37], 5, 3, 6),
        ("exchange", vec![0x48, 0x87, 0x37], 5, 3, 3),
        ("xadd", vec![0xf0, 0x48, 0x0f, 0xc1, 0x37], 5, 3, 8),
        ("cas", vec![0xf0, 0x48, 0x0f, 0xb1, 0x37], 5, 3, 3),
        ("bts", vec![0xf0, 0x48, 0x0f, 0xba, 0x2f, 1], 5, 3, 7),
        ("btr", vec![0xf0, 0x48, 0x0f, 0xba, 0x37, 0], 5, 3, 4),
        ("btc", vec![0xf0, 0x48, 0x0f, 0xba, 0x3f, 0], 5, 3, 4),
        ("bts_register", vec![0xf0, 0x48, 0x0f, 0xab, 0x37], 5, 3, 13),
        ("btr_register", vec![0xf0, 0x48, 0x0f, 0xb3, 0x37], 5, 3, 5),
        ("btc_register", vec![0xf0, 0x48, 0x0f, 0xbb, 0x37], 5, 3, 13),
        ("byte_add", vec![0xf0, 0x40, 0x00, 0x37], 255, 3, 2),
        ("half_add", vec![0xf0, 0x66, 0x01, 0x37], 65535, 3, 2),
        ("word_add", vec![0xf0, 0x01, 0x37], 4294967295, 3, 2),
    ] {
        let bytes = [bytes, vec![0xc3]].concat();
        let result = Expr::Load {
            addr: Box::new(Expr::reg(7, 64)),
            width: 8,
            signed: false,
        };
        let ir = lifted(Isa::X86_64, &bytes, result);
        code.push_str(&check_atomic_result(
            ir,
            &[7, 6, 0],
            initial,
            operand,
            updated,
            name,
        ));
        main.push_str(&format!("v = {initial}; if ({name}((uint64_t)&v, {operand}, {initial}) != {updated} || v != {updated}) return 1;\n"));
    }
    assert!(code.contains("__ATOMIC_SEQ_CST"));
    main.push_str("return 0; }\n");
    compile_run(&format!("{code}{main}"), "x86");
}

#[test]
fn arm_atomic_families_print_compile_and_execute() {
    let mut code = String::from("#include <stdint.h>\n");
    let mut main = String::from("int main(void) { uint64_t v;\n");
    for (name, word, initial, operand, updated, result) in [
        ("add", 0xf8210002u32, 5, 3, 8, 5),
        ("add_acquire", 0xf8a10002, 5, 3, 8, 5),
        ("add_release", 0xf8610002, 5, 3, 8, 5),
        ("add_acqrel", 0xf8e10002, 5, 3, 8, 5),
        ("clear", 0xf8211002, 5, 3, 4, 5),
        ("set", 0xf8213002, 5, 3, 7, 5),
        ("swap", 0xf8218002, 5, 3, 3, 5),
        ("cas", 0xc8a17c02, 5, 5, 5, 5),
        ("load", 0xc8dffc02, 5, 3, 5, 5),
        ("store", 0xc89ffc01, 5, 3, 3, 5),
        ("byte_add", 0x38210002, 255, 3, 2, 255),
        ("half_add", 0x78210002, 65535, 3, 2, 65535),
    ] {
        let bytes = [word.to_le_bytes(), 0xd65f03c0u32.to_le_bytes()].concat();
        let ir = lifted(
            Isa::AArch64,
            &bytes,
            Expr::reg(if name == "cas" { 1 } else { 2 }, 64),
        );
        code.push_str(&check_atomic_result(
            ir,
            &[0, 1, 2],
            initial,
            operand,
            result,
            name,
        ));
        main.push_str(&format!("v = {initial}; if ({name}((uint64_t)&v, {operand}, {initial}) != {result} || v != {updated}) return 1;\n"));
    }
    for order in ["RELAXED", "ACQUIRE", "RELEASE", "ACQ_REL"] {
        assert!(code.contains(&format!("__ATOMIC_{order}")), "{code}");
    }
    main.push_str("return 0; }\n");
    compile_run(&format!("{code}{main}"), "arm");
}

#[test]
fn exchange_results_compare_failure_and_flags_survive_optimization() {
    let mut code = String::from("#include <stdint.h>\n");
    let mut main = String::from("int main(void) { uint64_t v;\n");
    for (name, bytes, result, expected, memory) in [
        (
            "exchange_old",
            vec![0x48, 0x87, 0x37, 0xc3],
            Expr::reg(6, 64),
            5,
            3,
        ),
        (
            "xadd_old",
            vec![0xf0, 0x48, 0x0f, 0xc1, 0x37, 0xc3],
            Expr::reg(6, 64),
            5,
            8,
        ),
        // The initial accumulator is 5; compare it with 5, then return ZF.
        (
            "cas_equal",
            vec![0xf0, 0x48, 0x0f, 0xb1, 0x37, 0x0f, 0x94, 0xc0, 0xc3],
            Expr::bin(crate::ir::BinOp::And, Expr::reg(0, 64), Expr::constant(255)),
            1,
            3,
        ),
        // Clear the accumulator so the comparison fails and returns memory.
        (
            "cas_failure",
            vec![0x31, 0xc0, 0xf0, 0x48, 0x0f, 0xb1, 0x37, 0xc3],
            Expr::reg(0, 64),
            5,
            5,
        ),
        (
            "cas_word_high",
            vec![
                0x48, 0xb8, 5, 0, 0, 0, 0, 0, 0xed, 0xfe, 0xf0, 0x0f, 0xb1, 0x37, 0xc3,
            ],
            Expr::reg(0, 64),
            5,
            3,
        ),
        (
            "cas_word_failure_high",
            vec![
                0x48, 0xb8, 4, 0, 0, 0, 0, 0, 0xed, 0xfe, 0xf0, 0x0f, 0xb1, 0x37, 0xc3,
            ],
            Expr::reg(0, 64),
            5,
            5,
        ),
        (
            "sub_zero",
            vec![0xf0, 0x48, 0x83, 0x2f, 5, 0x0f, 0x94, 0xc0, 0xc3],
            Expr::bin(crate::ir::BinOp::And, Expr::reg(0, 64), Expr::constant(255)),
            1,
            0,
        ),
    ] {
        let ir = lifted(Isa::X86_64, &bytes, result);
        code.push_str(&check_atomic_result(ir, &[7, 6, 0], 5, 3, expected, name));
        main.push_str(&format!(
            "v = 5; if ({name}((uint64_t)&v, 3, 5) != {expected} || v != {memory}) return 1;\n"
        ));
    }
    main.push_str("return 0; }\n");
    compile_run(&format!("{code}{main}"), "results");
}

#[test]
fn ordinary_memory_values_are_not_forwarded_across_atomic_accesses() {
    // Store, load, atomic decrement, load: the first load must stay before
    // the atomic access and the last one must observe its result.
    let bytes = [
        0x48, 0xc7, 0x07, 9, 0, 0, 0, 0x48, 0x8b, 0x07, 0xf0, 0x48, 0xff, 0x0f, 0x48, 0x2b, 0x07,
        0xc3,
    ];
    let ir = lifted(Isa::X86_64, &bytes, Expr::reg(0, 64));
    let printed = check_atomic_result(ir, &[7, 6, 0], 5, 3, 1, "barrier");
    compile_run(
        &format!(
            "#include <stdint.h>\n{printed}\nint main(void) {{ uint64_t v = 5; return barrier((uint64_t)&v, 3, 5) != 1 || v != 8; }}\n"
        ),
        "barrier",
    );
}

#[test]
fn wide_compare_exchange_compiles_and_updates_both_halves() {
    let mut code = String::from("#include <stdint.h>\n");
    for (name, prefix, half) in [("cas8", 0x0f, 4u8), ("cas16", 0x48, 8u8)] {
        let bytes = if prefix == 0x48 {
            vec![0xf0, 0x48, 0x0f, 0xc7, 0x0f, 0xc3]
        } else {
            vec![0xf0, 0x0f, 0xc7, 0x0f, 0xc3]
        };
        let result = Expr::Load {
            addr: Box::new(Expr::reg(7, 64)),
            width: half,
            signed: false,
        };
        let mut ir = lifted(Isa::X86_64, &bytes, result);
        for optimize in [false, true] {
            if optimize {
                crate::passes::optimize(&mut ir, false);
            }
            for equal in [false, true] {
                let inputs = [
                    (7, 0x1000),
                    (0, if equal { 5 } else { 4 }),
                    (2, 7),
                    (3, 3),
                    (1, 11),
                ];
                let memory = if half == 8 {
                    vec![(0x1000, 5), (0x1008, 7)]
                } else {
                    vec![(0x1000, 5 | (7 << 32))]
                };
                let setup = eval::Setup {
                    seed: 1,
                    convention: eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &inputs,
                    memory: &memory,
                    step_limit: 1000,
                };
                assert!(
                    matches!(eval::run(&ir, &setup), Outcome::Return { value, .. } if value == if equal {3} else {5}),
                    "{}",
                    ir.render()
                );
            }
        }
        ir.name = Some(name.to_owned());
        ir.params = [7, 0, 2, 3, 1]
            .into_iter()
            .zip(["p", "lo", "hi", "newlo", "newhi"])
            .map(|(index, name)| Param {
                index,
                name: name.to_owned(),
                ty: CType::U64,
            })
            .collect();
        code.push_str(&crate::render::render(&ir, &[], &Default::default(), &[]));
    }
    code.push_str("\nint main(void) { _Alignas(16) uint64_t v[2] = {5, 7}; if (cas16((uint64_t)v, 5, 7, 3, 11) != 3 || v[0] != 3 || v[1] != 11) return 1; v[0] = 5; v[1] = 7; if (cas16((uint64_t)v, 4, 7, 3, 11) != 5 || v[0] != 5 || v[1] != 7) return 2; v[0] = 5ULL | (7ULL << 32); if (cas8((uint64_t)v, 5, 7, 3, 11) != 3 || v[0] != (3ULL | (11ULL << 32))) return 3; return 0; }\n");
    compile_run(&code, "wide");
}

#[test]
fn exclusive_retry_loop_becomes_one_atomic_update() {
    let bytes: Vec<u8> = [
        0xc85ffc02u32,
        0x8b010043,
        0xc804fc03,
        0x35ffffa4,
        0xd65f03c0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let ir = lifted(Isa::AArch64, &bytes, Expr::reg(3, 64));
    let printed = check_atomic_result(ir, &[0, 1, 2], 5, 3, 8, "exclusive_loop");
    assert_eq!(
        printed.matches("__atomic_fetch_add").count(),
        1,
        "{printed}"
    );
    assert!(printed.contains("__ATOMIC_ACQ_REL"), "{printed}");
    compile_run(
        &format!(
            "#include <stdint.h>\n{printed}\nint main(void) {{ uint64_t v = 5; return exclusive_loop((uint64_t)&v, 3, 5) != 8 || v != 8; }}\n"
        ),
        "exclusive",
    );
}

#[test]
fn exclusive_retry_can_test_the_zero_extended_status_register() {
    let bytes: Vec<u8> = [
        0xc85ffc02u32, // ldaxr x2, [x0]
        0x8b010042,    // add x2, x2, x1
        0xc804fc02,    // stlxr w4, x2, [x0]
        0xb5ffffa4,    // cbnz x4, retry
        0xd65f03c0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let ir = lifted(Isa::AArch64, &bytes, Expr::reg(2, 64));
    let printed = check_atomic_result(ir, &[0, 1, 2], 5, 3, 8, "wide_status_loop");
    assert_eq!(
        printed.matches("__atomic_fetch_add").count(),
        1,
        "{printed}"
    );
    assert!(printed.contains("__ATOMIC_ACQ_REL"), "{printed}");
    compile_run(
        &format!(
            "#include <stdint.h>\n{printed}\nint main(void) {{ uint64_t v = 5; return wide_status_loop((uint64_t)&v, 3, 5) != 8 || v != 8; }}\n"
        ),
        "wide_status_exclusive",
    );
}
