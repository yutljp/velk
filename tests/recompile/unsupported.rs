use super::*;

#[test]
fn printed_fixture_simd_and_flag_joins_preserve_results() {
    let instructions = [
        ("shuffle_bytes", vec![0x66, 0x0f, 0x38, 0x00, 0xc1]),
        ("insert_dword", vec![0x66, 0x0f, 0x3a, 0x22, 0xc1, 2]),
        (
            "vector_test",
            vec![0xc4, 0xe2, 0x7d, 0x17, 0xc1, 0x0f, 0x96, 0xc0],
        ),
        (
            "flag_join",
            vec![
                0x48, 0x85, 0xd2, 0x74, 5, 0x48, 0x39, 0xd8, 0xeb, 2, 0x39, 0xd8, 0x0f, 0x94, 0xc0,
            ],
        ),
        (
            "shift_zero",
            vec![0x48, 0x39, 0xd8, 0x48, 0xd3, 0xe0, 0x0f, 0x94, 0xc2],
        ),
    ];
    let registers = [0, 1, 2, 3, 18, 19, 20, 21, 50, 51, 52, 53];
    let mut candidates = Vec::new();
    for (name, mut code) in instructions {
        code.push(0xc3);
        let size = code.len() as u64;
        let image = code_image(&code);
        let blocks = velk::lift::lift(&image, 0, size, &Default::default()).unwrap();
        assert!(
            blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .all(|stmt| !matches!(stmt, Stmt::Unsupported { .. }))
        );
        for output in [0, 2, 18, 19, 50, 51] {
            let params = registers
                .iter()
                .map(|index| Param {
                    index: *index,
                    name: format!("arg{index}"),
                    ty: CType::U64,
                })
                .collect();
            let mut ir = synthetic_ir(&format!("{name}_{output}"), params, CType::U64, vec![]);
            ir.blocks = blocks.clone();
            for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                if let Stmt::Ret { value } = stmt {
                    *value = Expr::reg(output, 64);
                }
            }
            let rows = (0..trials::TRIALS)
                .map(|trial| {
                    registers
                        .iter()
                        .map(|index| match trial {
                            0 => 0,
                            1 => u64::MAX,
                            2 => 0x8080_8080_8080_8080,
                            3 => 0x0f08_0706_0504_0302,
                            _ if *index == 1 => trial * 16,
                            _ if *index == 2 => trial % 3,
                            _ => eval::hash(trial, u64::from(*index)),
                        })
                        .collect()
                })
                .collect();
            candidates.push(printed_candidate(ir, rows));
        }
    }
    check_candidates("fixture_instructions", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_reverse_string_copies_preserve_memory() {
    let mut candidates = Vec::new();
    for (name, opcode) in [
        ("reverse_bytes", vec![0xa4]),
        ("reverse_words", vec![0x48, 0xa5]),
    ] {
        let code = [vec![0xfd, 0xeb, 0, 0xf3], opcode, vec![0xfc, 0xc3]].concat();
        let size = code.len() as u64;
        let image = code_image(&code);
        let params = [1, 6, 7]
            .into_iter()
            .map(|index| Param {
                index,
                name: format!("arg{index}"),
                ty: if index == 1 {
                    CType::U64
                } else {
                    CType::Pointer(Box::new(CType::Int {
                        bytes: 1,
                        signed: false,
                    }))
                },
            })
            .collect();
        let mut ir = synthetic_ir(name, params, CType::U64, vec![]);
        ir.blocks = velk::lift::lift(&image, 0, size, &Default::default()).unwrap();
        for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let Stmt::Ret { value } = stmt {
                *value = Expr::constant(0);
            }
        }
        let inputs = (0..trials::TRIALS)
            .map(|trial| vec![trial, REGION + 5000, REGION + 6000])
            .collect();
        candidates.push(printed_candidate(ir, inputs));
    }
    check_candidates("reverse_strings", candidates, Mode::Memory, &[]);
}

fn code_image(code: &[u8]) -> Image {
    instruction_image(code, "x86_64")
}

fn instruction_image(code: &[u8], architecture: &str) -> Image {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch = scratch_dir(&format!("fixture_instruction_code_{counter}"));
    let source = scratch.join("code.s");
    let object = scratch.join("code.o");
    let bytes = code
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        &source,
        format!(
            ".text\n.globl code\n.type code,@function\ncode:\n.byte {bytes}\n.size code, .-code\n"
        ),
    )
    .unwrap();
    let result = Command::new(compiler())
        .args([&format!("--target={architecture}-unknown-linux-gnu"), "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let image = velk::loader::load(&object).unwrap();
    std::fs::remove_dir_all(scratch).unwrap();
    image
}

#[test]
fn printed_flag_joins_do_not_reuse_flags_across_calls() {
    // test edi, edi; jz join; call 0x100; join: jmp next; next: sete al; ret
    let code = [
        0x85, 0xff, 0x74, 5, 0xe8, 0xf7, 0, 0, 0, 0xeb, 0, 0x0f, 0x94, 0xc0, 0xc3,
    ];
    let image = code_image(&code);
    let mut ir = synthetic_ir("flags_after_call", Vec::new(), CType::U64, Vec::new());
    ir.blocks = velk::lift::lift(&image, 0, code.len() as u64, &Default::default()).unwrap();
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(
        code.contains("/* unsupported: setcc without compare"),
        "{code}"
    );
}

#[test]
fn printed_arm64_table_shift_and_aes_preserve_results() {
    let base = velk::arch::aarch64::V0;
    let registers: Vec<_> = (base..base + 10).collect();
    let mut candidates = Vec::new();
    for (name, word) in [
        ("arm_shift64", 0x6ee2_4420u32),
        ("arm_shift8", 0x6e22_4420),
        ("arm_table", 0x4e00_2000),
        ("arm_table_extend", 0x0e00_7020),
        ("arm_aes", 0x4e28_4820),
        ("arm_mix", 0x4e28_6800),
    ] {
        let code = [word, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let image = instruction_image(&code, "aarch64");
        let blocks = velk::lift::lift(&image, 0, 8, &Default::default()).unwrap();
        assert!(
            blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .all(|s| !matches!(s, Stmt::Unsupported { .. }))
        );
        for output in [base, base + 1] {
            let params = registers
                .iter()
                .map(|index| Param {
                    index: *index,
                    name: format!("arg{index}"),
                    ty: CType::U64,
                })
                .collect();
            let mut ir = synthetic_ir(&format!("{name}_{output}"), params, CType::U64, vec![]);
            ir.isa = velk::loader::Isa::AArch64;
            ir.blocks = blocks.clone();
            for stmt in ir.blocks.iter_mut().flat_map(|b| &mut b.stmts) {
                if let Stmt::Ret { value } = stmt {
                    *value = Expr::reg(output, 64);
                }
            }
            let inputs = (0..64)
                .map(|trial| {
                    registers
                        .iter()
                        .map(|index| match trial {
                            0 => 0,
                            1 => u64::MAX,
                            2 => 0x807f_403f_201f_100f,
                            _ => eval::hash(trial, u64::from(*index)),
                        })
                        .collect()
                })
                .collect();
            let candidate = printed_candidate(ir, inputs);
            assert!(
                !candidate.code.contains("unsupported:"),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("arm64-simd", candidates, Mode::Registers, &[]);
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[test]
fn printed_arm64_exclusive_and_system_operations_preserve_memory() {
    for (name, words, result, initialization, assertion, expected) in [
        (
            "exclusive",
            vec![0xc85f_fc01u32, 0x9100_0421, 0xc802_fc01],
            2,
            "uint64_t data = 41;",
            "data == (status ? 41 : 42) && status <= 1",
            "stlxr",
        ),
        (
            "exclusive_pair",
            vec![0xc87f_8801, 0xc823_8801],
            3,
            "_Alignas(16) uint64_t data[2] = {41, 42};",
            "data[0] == 41 && data[1] == 42 && status <= 1",
            "stlxp",
        ),
        (
            "exclusive_flags",
            vec![
                0xc85f_fc01,
                0xd280_0542,
                0xf100_a43f,
                0xc801_fc02,
                0x9a9f_17e3,
            ],
            3,
            "uint64_t data = 41;",
            "status == 1 && (data == 41 || data == 42)",
            "stlxr",
        ),
        (
            "exclusive_byte",
            vec![0x085f_fc01, 0x0802_fc01],
            2,
            "uint64_t data = 41;",
            "data == 41 && status <= 1",
            "stlxrb",
        ),
        (
            "exclusive_half",
            vec![0x485f_fc01, 0x4802_fc01],
            2,
            "uint64_t data = 41;",
            "data == 41 && status <= 1",
            "stlxrh",
        ),
        (
            "acquire",
            vec![0xf8bf_c001],
            1,
            "uint64_t data = 41;",
            "data == 41 && status == 41",
            "ldapr",
        ),
        (
            "acquire_offset",
            vec![0x9940_4001],
            1,
            "uint64_t data = UINT64_C(0x12345678ffffffff);",
            "status == 0x12345678",
            "ldapr",
        ),
        (
            "acquire_low_word",
            vec![0xf8bf_c001, 0x2a01_03e1],
            1,
            "uint64_t data = UINT64_C(0x1234567887654321);",
            "status == UINT64_C(0x87654321) && data == UINT64_C(0x1234567887654321)",
            "ldapr %x0",
        ),
        (
            "exclusive_low_word",
            vec![0xc85f_fc01, 0x2a01_03e1],
            1,
            "uint64_t data = UINT64_C(0x1234567887654321);",
            "status == UINT64_C(0x87654321) && data == UINT64_C(0x1234567887654321)",
            "ldaxr %x0",
        ),
        (
            "system_low_word",
            vec![0xd53b_d041, 0x2a01_03e1],
            1,
            "uint64_t data = 0, thread; __asm__ volatile (\"mrs %0, tpidr_el0\" : \"=r\"(thread));",
            "status == (uint32_t)thread",
            "mrs %x0",
        ),
        (
            "release_offset",
            vec![0x5280_0541, 0x1900_3001],
            1,
            "uint64_t data = 0;",
            "data == UINT64_C(0x2a000000) && status == 42",
            "__atomic_store_n",
        ),
        (
            "barriers",
            vec![0xd503_39bf, 0xd503_3b9f, 0xd503_3fdf],
            0,
            "uint64_t data = 41;",
            "status == (uint64_t)&data && data == 41",
            "isb",
        ),
        (
            "cache_zero",
            vec![0xd280_0541, 0xf900_0001, 0xd50b_7420, 0xf940_0002],
            2,
            "_Alignas(4096) uint8_t data[8192]; for (unsigned i = 0; i < 8192; ++i) data[i] = 85; uint64_t dczid; __asm__ volatile (\"mrs %0, dczid_el0\" : \"=r\"(dczid)); if ((dczid & 16) || (dczid & 15) > 10) return 0; unsigned block = 4u << (dczid & 15);",
            "status == 0 && data[0] == 0 && data[block - 1] == 0 && data[block] == 85",
            "dc zva",
        ),
    ] {
        let code = words
            .into_iter()
            .chain([0xd65f_03c0])
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let size = code.len() as u64;
        let image = instruction_image(&code, "aarch64");
        let mut ir = synthetic_ir(
            name,
            vec![Param {
                index: 0,
                name: "p".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![],
        );
        ir.isa = velk::loader::Isa::AArch64;
        ir.blocks = velk::lift::lift(&image, 0, size, &Default::default()).unwrap();
        for stmt in ir.blocks.iter_mut().flat_map(|b| &mut b.stmts) {
            if let Stmt::Ret { value } = stmt {
                *value = Expr::reg(result, 64);
            }
        }
        velk::passes::optimize(&mut ir, false);
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains("unsupported:"), "{code}");
        assert!(!code.contains("x86intrin.h"), "{code}");
        assert!(code.contains(expected), "{code}");
        syntax::run_printed(
            &code,
            "",
            &format!(
                "{initialization} uint64_t status = {name}((uint64_t)&data); return !({assertion});"
            ),
        );
    }
}

#[test]
fn printed_arm64_structure_accesses_preserve_lanes_and_writeback() {
    let base = velk::arch::aarch64::V0;
    let mut code = String::new();
    let mut assertions = String::from("uint8_t data[128];");
    let word_at = |offset: u64| {
        (0..8).fold(0u64, |value, byte| {
            value | ((offset + byte + 1) << (8 * byte))
        })
    };
    for (case, word, expected, increment, store) in [
        (
            0,
            0x4cdf_a140u32,
            [word_at(0), word_at(8), word_at(16), word_at(24)],
            32,
            false,
        ),
        (
            1,
            0x4dcb_8540,
            [0x1122_3344_5566_7788, word_at(0), 0, 0],
            24,
            false,
        ),
        (
            2,
            0x4d9f_8540,
            [0x1122_3344_5566_7788, 0x8877_6655_4433_2211, 0, 0],
            8,
            true,
        ),
        (
            3,
            0x4cdf_0d40,
            [word_at(0), word_at(32), word_at(8), word_at(40)],
            64,
            false,
        ),
        (
            4,
            0x4dff_e940,
            [
                0x0403_0201_0403_0201,
                0x0403_0201_0403_0201,
                0x0807_0605_0807_0605,
                0x0807_0605_0807_0605,
            ],
            16,
            false,
        ),
        (5, 0x0d40_c140, [0x0101_0101_0101_0101, 0, 0, 0], 0, false),
    ] {
        let bytes: Vec<_> = [word, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let image = instruction_image(&bytes, "aarch64");
        let blocks = velk::lift::lift(&image, 0, 8, &Default::default()).unwrap();
        for output in 0..5 {
            let name = format!("structure_{case}_{output}");
            let params = [0, 10, 11, base, base + 1, base + 2, base + 3]
                .into_iter()
                .map(|index| Param {
                    index,
                    name: format!("arg{index}"),
                    ty: CType::U64,
                })
                .collect();
            let mut ir = synthetic_ir(&name, params, CType::U64, vec![]);
            ir.isa = velk::loader::Isa::AArch64;
            ir.blocks = blocks.clone();
            let value = if output == 4 {
                Expr::bin(BinOp::Sub, Expr::reg(10, 64), Expr::reg(0, 64))
            } else {
                Expr::reg(base + output as u16, 64)
            };
            for stmt in ir.blocks.iter_mut().flat_map(|b| &mut b.stmts) {
                if let Stmt::Ret { value: ret } = stmt {
                    *ret = value.clone();
                }
            }
            velk::passes::optimize(&mut ir, false);
            let rendered = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(!rendered.contains("unsupported:"), "{rendered}");
            code.push_str(&rendered);
            let expected = if output == 4 {
                increment
            } else {
                expected[output]
            };
            assertions.push_str(&format!("for (unsigned i = 0; i < 128; ++i) data[i] = i + 1; if ({name}((uint64_t)data, (uint64_t)data, 24, UINT64_C(0x1122334455667788), UINT64_C(0x8877665544332211), 0, 0) != UINT64_C({expected})) return 1;"));
            assertions.push_str(if store { "for (unsigned i = 0; i < 8; ++i) if (data[i] != (uint8_t)(UINT64_C(0x8877665544332211) >> (8 * i))) return 2; for (unsigned i = 8; i < 128; ++i) if (data[i] != i + 1) return 3;" } else { "for (unsigned i = 0; i < 128; ++i) if (data[i] != i + 1) return 4;" });
        }
    }
    assertions.push_str("return 0;");
    syntax::run_printed(&velk::render::combine(&code), "", &assertions);
}

#[test]
fn printed_arm64_atomic_stack_addresses_have_pointer_operands() {
    let mut binary = Binary::open(&common::fixtures_dir().join("go_probe_arm64")).unwrap();
    let returns = syntax::return_types(&velk::render::callee_names(binary.image()));
    let code = binary.decompile(0x527d0, None, None).unwrap();
    assert!(code.contains("__atomic_compare_exchange_n"), "{code}");
    let scratch = scratch_dir("arm64-atomic-stack");
    let error = syntax::check(&code, &scratch.join("function.c"), &returns);
    assert!(error.is_none(), "{error:?}\n{code}");
}

#[test]
fn printed_arm64_entry_stack_pointer_uses_the_interpreter_frame() {
    let mut ir = synthetic_ir(
        "entry_stack",
        vec![],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::reg(31, 64),
        }],
    );
    ir.isa = Isa::AArch64;
    let candidate = printed_candidate(ir, vec![vec![]]);
    assert!(
        candidate.code.contains("/* target entry stack pointer */"),
        "{}",
        candidate.code
    );
    check_candidates("arm64-entry-stack", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn printed_aes_round_helpers_preserve_results() {
    use velk::ir::AesRound;
    let mut candidates = Vec::new();
    for (index, round) in [
        AesRound::Encrypt,
        AesRound::EncryptLast,
        AesRound::Decrypt,
        AesRound::DecryptLast,
        AesRound::MixColumns,
    ]
    .into_iter()
    .enumerate()
    {
        for high in [false, true] {
            let params = (0..4)
                .map(|index| Param {
                    index,
                    name: format!("arg{index}"),
                    ty: CType::U64,
                })
                .collect();
            let ir = synthetic_ir(
                &format!("aes_round_{index}_{}", u8::from(high)),
                params,
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::apply(
                        Operation::Aes { round, high },
                        (0..4).map(|index| Expr::reg(index, 64)).collect(),
                    ),
                }],
            );
            let inputs = (0..64)
                .map(|trial| {
                    (0..4)
                        .map(|index| match trial {
                            0 => 0,
                            1 => u64::MAX,
                            _ => eval::hash(trial, index),
                        })
                        .collect()
                })
                .collect();
            let candidate = printed_candidate(ir, inputs);
            assert!(
                candidate.code.contains("static inline uint64_t aes"),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("aes-round-helpers", candidates, Mode::Registers, &[]);
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[test]
fn printed_arm64_machine_loads_share_recovered_stack_storage() {
    use velk::ir::{MachineInstruction, RegRef, TEMP_BASE};
    for (index, instruction) in [
        MachineInstruction::ArmLoadAcquire { width: 8 },
        MachineInstruction::ArmExclusive {
            load: true,
            width: 8,
            pair: false,
            ordered: true,
        },
        MachineInstruction::ArmExclusive {
            load: true,
            width: 8,
            pair: true,
            ordered: true,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let pair = index == 2;
        let address = Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const((-16i64) as u64));
        let mut ir = synthetic_ir(
            &format!("stack_machine_{index}"),
            vec![],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: address.clone(),
                    value: Expr::Const(42),
                    width: 8,
                },
                Stmt::Store {
                    addr: Expr::bin(BinOp::Add, address.clone(), Expr::Const(8)),
                    value: Expr::Const(43),
                    width: 8,
                },
                Stmt::Machine {
                    instruction,
                    inputs: vec![address],
                    outputs: (0..if pair { 2 } else { 1 })
                        .map(|offset| RegRef {
                            index: TEMP_BASE + offset,
                            width: 64,
                        })
                        .collect(),
                },
                Stmt::Ret {
                    value: if pair {
                        Expr::bin(
                            BinOp::Add,
                            Expr::reg(TEMP_BASE, 64),
                            Expr::reg(TEMP_BASE + 1, 64),
                        )
                    } else {
                        Expr::reg(TEMP_BASE, 64)
                    },
                },
            ],
        );
        ir.isa = Isa::AArch64;
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
        syntax::run_printed(
            &code,
            "",
            &format!(
                "return stack_machine_{index}() != {};",
                if pair { 85 } else { 42 }
            ),
        );
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[test]
fn printed_arm64_machine_memory_keeps_fixed_string_addresses() {
    use velk::ir::{MachineInstruction, RegRef, TEMP_BASE};
    let mut ir = synthetic_ir(
        "fixed_machine_address",
        vec![],
        CType::U64,
        vec![
            Stmt::Machine {
                instruction: MachineInstruction::ArmLoadAcquire { width: 8 },
                inputs: vec![Expr::Const(REGION)],
                outputs: vec![RegRef {
                    index: TEMP_BASE,
                    width: 64,
                }],
            },
            Stmt::Ret {
                value: Expr::reg(TEMP_BASE, 64),
            },
        ],
    );
    ir.isa = Isa::AArch64;
    let refs = [velk::analysis::refs::Reference {
        addr: REGION,
        section: "data".into(),
        text: Some("different bytes".into()),
        pointer: None,
    }];
    let code = velk::render::render(&ir, &refs, &Default::default(), &[(REGION, 4096)]);
    assert!(code.contains("\"r\"((uint64_t)(0x300000000000"), "{code}");
    syntax::run_printed(
        &code,
        "#include <sys/mman.h>",
        &format!(
            "void *p = mmap((void *)UINT64_C({REGION}), 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0); if (p == MAP_FAILED) return 2; *(uint64_t *)p = 42; return fixed_machine_address() != 42;"
        ),
    );
}
