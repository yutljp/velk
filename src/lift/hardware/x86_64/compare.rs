use super::*;
use crate::ir::{CType, Param};
use std::fmt::Write as _;

#[test]
fn immediate_comparisons_match_processor_and_printed_c() {
    let runner = runner().expect("x86-64 compiler and execution support");
    let mut cases = Vec::new();
    for bits in [8u32, 16, 32, 64] {
        let mask = crate::ir::semantics::mask(bits);
        let sign = 1u64 << (bits - 1);
        for short in [false, true] {
            if bits == 8 && short {
                continue;
            }
            let immediates: Vec<u64> = if short || bits == 8 {
                vec![0, 1, 5, 127, 128, 237, 255]
            } else {
                let sign = 1u64 << (bits.min(32) - 1);
                vec![0, 1, 5, 127, 128, sign - 1, sign, sign + 1, 0xffff_ffff]
            };
            for memory in [false, true] {
                for immediate in &immediates {
                    for input in [0, 1, 5, 127, sign - 1, sign, mask - 18, mask] {
                        let mut code = Vec::new();
                        if memory {
                            // The runner owns the stack below the return address.
                            if bits == 64 {
                                code.extend([0x48, 0x89, 0x44, 0x24, 0xf8]);
                            } else {
                                if bits == 16 {
                                    code.push(0x66);
                                }
                                code.extend([
                                    if bits == 8 { 0xc6 } else { 0xc7 },
                                    0x44,
                                    0x24,
                                    0xf8,
                                ]);
                                code.extend(&input.to_le_bytes()[..(bits / 8) as usize]);
                            }
                        }
                        if bits == 16 {
                            code.push(0x66);
                        } else if bits == 64 {
                            code.push(0x48);
                        }
                        code.push(if bits == 8 {
                            0x80
                        } else if short {
                            0x83
                        } else {
                            0x81
                        });
                        if memory {
                            code.extend([0x7c, 0x24, 0xf8]);
                        } else {
                            code.push(0xf8);
                        }
                        let bytes = if short || bits == 8 {
                            1
                        } else {
                            (bits / 8).min(4) as usize
                        };
                        code.extend(&immediate.to_le_bytes()[..bytes]);
                        let mut registers = [0; 16];
                        registers[0] = input | (!mask & 0xa5a5_a5a5_a5a5_a5a5);
                        cases.push(Case {
                            code,
                            registers,
                            flags: 2,
                            vectors: [0; 32],
                            memory: None,
                        });
                    }
                }
            }
        }
    }
    let outcomes = run(runner, &cases);
    let mut functions = String::new();
    let mut checks = String::new();
    let mut count = 0;
    for (case, outcome) in cases.iter().zip(outcomes) {
        assert_eq!(outcome.signal, 0, "{:02x?}", case.code);
        for cc in 0..16u8 {
            let (_, expected) = condition(cc, outcome.flags);
            let tail = [0x70 | cc, 6, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3];
            // Check both a parameter and a value available to constant propagation.
            for constant in [false, true] {
                let mut body = Vec::new();
                if constant {
                    body.extend([0x48, 0xb8]);
                    body.extend(case.registers[0].to_le_bytes());
                }
                body.extend(&case.code);
                body.extend(tail);
                let mut ir = lifted(Isa::X86_64, body).expect("lift comparison");
                let registers = [(0, case.registers[0])];
                assert!(
                    condition_differs(&ir, &registers, expected).is_none(),
                    "raw cc={cc} {:02x?}\n{}",
                    case.code,
                    ir.render()
                );
                ir.name = Some(format!("compare_{count}"));
                ir.ret_type = CType::U64;
                if !constant {
                    ir.params = vec![Param {
                        index: 0,
                        name: "input".into(),
                        ty: CType::U64,
                    }];
                }
                crate::passes::optimize(&mut ir, false);
                assert!(
                    condition_differs(&ir, &registers, expected).is_none(),
                    "optimized cc={cc} input={:#x} {:02x?}\n{}",
                    case.registers[0],
                    case.code,
                    ir.render()
                );
                functions.push_str(&crate::render::render(&ir, &[], &Default::default(), &[]));
                let argument = if constant {
                    String::new()
                } else {
                    format!("UINT64_C({})", case.registers[0])
                };
                writeln!(checks, "if (compare_{count}({argument}) != {}) {{ fprintf(stderr, \"comparison {count} failed\\n\"); return 1; }}", u8::from(expected)).unwrap();
                count += 1;
            }
        }
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/hardware/compare-immediates");
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("check.c");
    std::fs::write(&source, format!("#include <stdint.h>\n#include <stdio.h>\n{}\nint main(void) {{\n{checks}return 0;\n}}\n", crate::render::combine(&functions))).unwrap();
    for level in ["-O0", "-O2"] {
        let program = dir.join(format!("check{level}"));
        let compiled = Command::new("clang")
            .args([
                "-std=gnu11",
                "-fwrapv",
                "-Werror=implicit-function-declaration",
                level,
            ])
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(Command::new(program).status().unwrap().success(), "{level}");
    }
    eprintln!("{count} printed comparisons agree with x86-64 at both optimization levels");
}
