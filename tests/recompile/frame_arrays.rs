use super::*;

/// Compiles `source` without optimization, prints each of `functions`, and
/// runs the printed C next to the original on every input: both, and the
/// interpreter on the IR where it makes no call, must return the same
/// 32-bit value. Each function takes successive wrapping 32-bit arguments
/// starting at the input; calls in the printed C reach the originals.
pub(crate) fn check_against_original(
    pass: &str,
    source: &str,
    functions: &[&str],
    inputs: &[u32],
) -> Vec<String> {
    check_against_original_with_flags(pass, source, functions, inputs, &[])
}

fn check_against_original_with_flags(
    pass: &str,
    source: &str,
    functions: &[&str],
    inputs: &[u32],
    flags: &[&str],
) -> Vec<String> {
    let scratch = scratch_dir(pass);
    let original = scratch.join("original.c");
    let executable = scratch.join("original");
    std::fs::write(&original, source).unwrap();
    let compiled = Command::new(compiler())
        .args(["-O0", "-fno-stack-protector"])
        .args(flags)
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
    let mut printed_code = Vec::new();
    let addresses: Vec<u64> = functions
        .iter()
        .map(|function| binary.find(&format!("{prefix}{function}")).unwrap().addr)
        .collect();
    for (function, address) in functions.iter().zip(&addresses) {
        let address = *address;
        let mut ir = binary.analysis(address, None).unwrap().ir.clone();
        let printed = format!("printed_{function}");
        ir.name = Some(printed.clone());
        let mut others = velk::render::Symbols::default();
        for (other, at) in functions.iter().zip(&addresses) {
            if *at != address {
                others.functions.insert(*at, (*other).into());
            }
        }
        let code = velk::render::render(&ir, &[], &others, &[]);
        text.push_str(&code);
        printed_code.push(code.clone());
        for input in inputs {
            let values: Vec<_> = (0..ir.params.len())
                .map(|position| input.wrapping_add(position as u32))
                .collect();
            let registers: Vec<(u16, u64)> = ir
                .params
                .iter()
                .zip(&values)
                .map(|(param, value)| (param.index, u64::from(*value)))
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
            let Outcome::Return { value, calls, .. } = outcome else {
                panic!("{function}({input}): {outcome:?}\n{code}");
            };
            let arguments = values
                .iter()
                .map(|value| format!("UINT32_C({value})"))
                .collect::<Vec<_>>()
                .join(", ");
            write!(
                checks,
                "if ((uint32_t){printed}({arguments}) != {function}({arguments})"
            )
            .unwrap();
            // What a call returns is the interpreter's guess.
            if calls.is_empty() {
                write!(
                    checks,
                    " || (uint32_t){printed}({arguments}) != UINT32_C({})",
                    value as u32
                )
                .unwrap();
            }
            checks.push_str(") return 1;\n");
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
    printed_code
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

#[test]
fn printed_large_frames_keep_arguments_across_the_stack_probe() {
    check_against_original(
        "stack-probe",
        include_str!("stack_probe.c"),
        &["large_frame", "calls_large_frame", "large_frame_pair"],
        &[0, 1, 0x55, 0x1234_5678, 0xffff_fffe],
    );
}

#[test]
#[cfg(target_os = "macos")]
fn printed_x64_large_frames_keep_arguments_across_the_stack_probe() {
    let printed = check_against_original_with_flags(
        "x64-stack-probe",
        include_str!("stack_probe.c"),
        &["large_frame", "calls_large_frame", "large_frame_pair"],
        &[0, 1, 0x55, 0x1234_5678, 0xffff_fffe],
        &["-arch", "x86_64"],
    );
    for code in printed {
        assert!(!code.contains("chkstk"), "{code}");
        assert!(!code.contains("undefined"), "{code}");
        assert!(code.contains("a0"), "{code}");
    }
}

#[test]
fn printed_frame_addresses_held_in_registers_reach_their_locals() {
    let printed = check_against_original(
        "frame-pointers",
        include_str!("frame_pointers.c"),
        &["far_locals"],
        &[0, 1, 0x55, 0x1234_5678, 0xffff_fffe],
    );
    // Run as it was laid out by chance, a pointer to one local that reaches
    // others still computes the right result; it must not be printed.
    for code in printed {
        assert!(!code.contains("void *local_"), "{code}");
        assert!(!code.contains("_s1 *"), "{code}");
    }
}

#[test]
fn printed_narrow_signed_comparisons_keep_negative_constants() {
    check_against_original(
        "narrow-compares",
        include_str!("narrow_compares.c"),
        &["narrow_signed_loops"],
        &[0, 1, 2, 3, 4, 5, 6, 0x55, 0xffff_fffe],
    );
}
