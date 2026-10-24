use super::*;

/// Compiles `source` without optimization, prints each of `functions`, and
/// runs the printed C next to the original on every input: both, and the
/// interpreter on the IR, must return the same 32-bit value. Each function
/// takes one 32-bit argument.
pub(crate) fn check_against_original(pass: &str, source: &str, functions: &[&str], inputs: &[u32]) {
    let scratch = scratch_dir(pass);
    let original = scratch.join("original.c");
    let executable = scratch.join("original");
    std::fs::write(&original, source).unwrap();
    let compiled = Command::new(COMPILER)
        .args(["-O0", "-fno-stack-protector"])
        .arg(&original)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&executable).unwrap();
    let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
    let mut text = String::from(HEADER);
    text.push_str(&source.replace("int main(", "int original_main("));
    let mut checks = String::new();
    for function in functions {
        let address = binary.find(&format!("{prefix}{function}")).unwrap().addr;
        let mut ir = binary.analysis(address, None).unwrap().ir.clone();
        let printed = format!("printed_{function}");
        ir.name = Some(printed.clone());
        let code = velk::render::render(&ir, &[], &velk::render::Symbols::default(), &[]);
        text.push_str(&code);
        for input in inputs {
            let registers: Vec<(u16, u64)> = ir
                .params
                .iter()
                .map(|param| (param.index, u64::from(*input)))
                .collect();
            let outcome = eval::run(
                &ir,
                &eval::Setup {
                    seed: u64::from(*input),
                    convention: eval::Convention {
                        arguments: ir.convention.arguments(),
                        clobbered: ir.convention.clobbered(),
                    },
                    registers: &registers,
                    memory: &[],
                    step_limit: trials::STEP_LIMIT,
                },
            );
            let Outcome::Return { value, .. } = outcome else {
                panic!("{function}({input}): {outcome:?}\n{code}");
            };
            let arguments = vec![format!("UINT32_C({input})"); ir.params.len()].join(", ");
            writeln!(
                checks,
                "if ((uint32_t){printed}({arguments}) != {function}(UINT32_C({input})) || (uint32_t){printed}({arguments}) != UINT32_C({})) return 1;",
                value as u32
            )
            .unwrap();
        }
    }
    text.push_str("int main(void) {\n");
    text.push_str(&checks);
    text.push_str("return 0;\n}\n");
    let program = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "", "{}", program.text);
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_indexed_arrays_keep_elements_read_at_fixed_offsets() {
    check_against_original(
        "frame-arrays",
        include_str!("frame_arrays.c"),
        &["indexed_bytes", "indexed_words"],
        &[0, 1, 0x55, 0x1234_5678, 0xffff_fffe],
    );
}
