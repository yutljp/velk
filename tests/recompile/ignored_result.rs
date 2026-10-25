use super::*;

#[test]
fn printed_explicit_result_survives_callers_discarding_it() {
    check_result(false);
}

#[test]
fn declared_void_callees_do_not_gain_preserved_result_arguments() {
    check_result(true);
}

fn check_result(debug: bool) {
    let scratch = scratch_dir(&format!("ignored-result-{debug}"));
    let original = scratch.join("original.c");
    let executable = scratch.join("original");
    std::fs::write(&original, include_str!("ignored_result.c")).unwrap();
    let compiled = Command::new(compiler())
        .args(["-O2", "-fno-inline"])
        .args(if debug {
            &[
                "--target=aarch64-unknown-linux-gnu",
                "-ffreestanding",
                "-c",
                "-g",
            ][..]
        } else {
            &[]
        })
        .arg(&original)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&executable).unwrap();
    let prefix = if cfg!(target_os = "macos") && !debug {
        "_"
    } else {
        ""
    };
    let address = binary.find(&format!("{prefix}final_byte")).unwrap().addr;
    let effect = binary.find(&format!("{prefix}effect")).unwrap().addr;
    let mut ir = binary.analysis(address, None).unwrap().ir.clone();
    ir.name = Some("returned_byte".into());
    let symbols = velk::render::Symbols {
        functions: [(effect, "effect".into())].into(),
        function_returns: [(effect, CType::Void)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert_ne!(ir.ret_type, CType::Void, "{code}");
    assert!(code.contains("return (int8_t)"), "{code}");
    assert_eq!(ir.params.len(), 1, "{code}");
    let mut source = String::from(HEADER);
    source.push_str("static unsigned effects;\n");
    source.push_str(if debug {
        "static void effect(void) { ++effects; }\n"
    } else {
        "static void effect(uint64_t ignored) { (void)ignored; ++effects; }\n"
    });
    source.push_str(&code);
    source.push_str("int main(void) {\n");
    for value in 0..256u64 {
        let registers = [(ir.params[0].index, value)];
        let outcome = eval::run(
            &ir,
            &eval::Setup {
                seed: value,
                convention: eval::Convention {
                    arguments: ir.convention.arguments(),
                    clobbered: ir.convention.clobbered(),
                },
                registers: &registers,
                memory: &[],
                step_limit: trials::STEP_LIMIT,
            },
        );
        let Outcome::Return {
            value: result,
            calls,
            ..
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        assert_eq!(calls.len(), 1);
        let expected = value as u8 as i8 as i32 as u32;
        assert_eq!(result as u32, expected);
        writeln!(source, "effects = 0; if ((uint32_t)returned_byte({value}) != UINT32_C({expected}) || effects != 1) return 1;").unwrap();
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
