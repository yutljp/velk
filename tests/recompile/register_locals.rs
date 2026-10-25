use super::*;

#[test]
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn printed_byte_loop_uses_named_narrow_locals() {
    let scratch = scratch_dir("register-locals");
    let original = scratch.join("original.c");
    let executable = scratch.join("original");
    let mut input = include_str!("register_locals.c").to_owned();
    input.push_str("int main(void) { return decrement_byte(3); }\n");
    let effect_source = scratch.join("effect.c");
    std::fs::write(&effect_source, "void effect(void) {}\n").unwrap();
    std::fs::write(&original, input).unwrap();
    let compiled = Command::new(compiler())
        .args(["-target", "arm64-apple-macos11", "-O2", "-fno-inline"])
        .arg(&original)
        .arg(&effect_source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&executable).unwrap();
    let address = binary.find("_decrement_byte").unwrap().addr;
    let effect = binary.find("_effect").unwrap().addr;
    let global = *binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, name)| name.as_str() == "_byte_state")
        .unwrap()
        .0;
    let mut ir = binary.analysis(address, None).unwrap().ir.clone();
    ir.name = Some("decrement_byte".into());
    let symbols = velk::render::Symbols {
        functions: [(effect, "effect".into())].into(),
        function_returns: [(effect, CType::Void)].into(),
        data: [(global, "state_ptr".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[(global, 1)]);
    for index in 0..31 {
        assert!(
            !code
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|word| word == format!("x{index}") || word == format!("w{index}")),
            "{code}"
        );
    }
    assert!(code.contains("uint32_t v1;"), "{code}");
    assert!(!code.contains("0xffffffff"), "{code}");
    assert!(!code.contains("(int8_t)("), "{code}");
    let code = code.replace("extern uint8_t state_ptr;", "");
    let code = replace_c_identifier(&code, "state_ptr", "state");
    let mut source = String::from(HEADER);
    source.push_str(
        "static uint8_t state;\nstatic unsigned effects;\nvoid effect(uint64_t ignored) { (void)ignored; ++effects; }\n",
    );
    source.push_str(&code);
    source.push_str("int main(void) {\n");
    for value in 0..256u64 {
        let outcome = eval::run(
            &ir,
            &eval::Setup {
                seed: value,
                convention: eval::Convention {
                    arguments: ir.convention.arguments(),
                    clobbered: ir.convention.clobbered(),
                },
                registers: &[(ir.params[0].index, 3)],
                memory: &[(global, value)],
                step_limit: trials::STEP_LIMIT,
            },
        );
        let Outcome::Return {
            value: result,
            calls,
            memory,
        } = outcome
        else {
            panic!("{outcome:?}\n{code}");
        };
        let byte = memory[&global];
        let expected = u32::from_ne_bytes(i32::from(byte as i8).to_ne_bytes());
        assert_eq!(result as u32, expected);
        writeln!(source, "state = {value}; effects = 0; if ((uint32_t)decrement_byte(3) != UINT32_C({expected}) || state != {byte} || effects != {}) return 1;", calls.len()).unwrap();
    }
    source.push_str("return 0;\n}\n");
    let program = Program {
        text: source,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_implicit_call_output_keeps_its_high_bits() {
    use velk::ir::{CallOutput, RegRef, Registers, VARIABLE_BASE};
    let ir = synthetic_ir(
        "keep_output",
        vec![Param {
            index: 7,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: 2,
                    width: 64,
                },
                value: Expr::reg(7, 64),
            },
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![Expr::reg(2, 32)]),
                floats_named: false,
                outputs: vec![CallOutput {
                    register: 2,
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                }],
                clobbers: Some(Registers(0)),
                via: None,
            },
            Stmt::Ret {
                value: Expr::reg(VARIABLE_BASE, 64),
            },
        ],
    );
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "effect".into())].into(),
        function_returns: [(0x1000, CType::Void)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("uint64_t v2;"), "{code}");
    let mut source = String::from(HEADER);
    source.push_str(
        "static unsigned effects;\nvoid effect(uint32_t ignored) { (void)ignored; ++effects; }\n",
    );
    source.push_str(&code);
    source.push_str("int main(void) {\n");
    for value in [0, 1, 0xffff_ffff, 0x1234_5678_9abc_def0, u64::MAX] {
        let outcome = eval::run(
            &ir,
            &eval::Setup {
                seed: 1,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(7, value)],
                memory: &[],
                step_limit: 100,
            },
        );
        let Outcome::Return {
            value: expected,
            calls,
            ..
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        assert_eq!(expected, value);
        assert_eq!(calls.len(), 1);
        writeln!(source, "effects = 0; if (keep_output(UINT64_C({value})) != UINT64_C({expected}) || effects != 1) return 1;").unwrap();
    }
    source.push_str("return 0;\n}\n");
    let scratch = scratch_dir("implicit-call-output");
    let program = Program {
        text: source,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}
