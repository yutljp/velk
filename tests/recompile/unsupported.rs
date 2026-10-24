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
    let result = Command::new(COMPILER)
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
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
