use super::unsupported::code_image;
use super::*;

/// A callee that saves the frame pointer and restores it from its own slot
/// keeps it, although a local's address escapes and a reference count is
/// updated atomically: the caller's frame stays named storage after the call.
#[test]
fn a_frame_survives_a_call_to_a_callee_with_escaping_locals_and_atomics() {
    let mut binary = Binary::open(&common::fixtures_dir().join("rust_probe")).unwrap();
    // rustc_demangle::try_demangle, whose callee keeps rbp only through its save.
    let code = binary.decompile(0x45fcf, None, None).unwrap();
    assert!(!code.contains("undefined"), "{code}");
    assert!(!code.contains("(-0x"), "{code}");
    assert!(!code.contains("(uintptr_t)&local"), "{code}");
    // The local the callee fills ends where the saved registers start.
    assert!(code.contains("int64_t f_38; } local_0;"), "{code}");
}

/// A callee that hands the address of its spilled arguments to a closure
/// returns what the closure left there, not its arguments.
#[test]
fn spilled_arguments_written_through_their_address_are_results() {
    let mut binary = Binary::open(&common::fixtures_dir().join("go_probe")).unwrap();
    // runtime.traceWriter.ensure returns what runtime.traceWriter.refill returns.
    let code = binary.decompile(0x452100, None, None).unwrap();
    assert!(code.contains("= runtime_traceWriter_refill("), "{code}");
}

#[test]
fn a_frame_survives_a_callee_with_a_register_only_unsupported_instruction() {
    // Save a caller local across a callee that saves rbp and executes rdpmc.
    let mut code = vec![
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x7d, 0xf8, 0xe8, 15, 0, 0, 0,
        0x48, 0x8b, 0x45, 0xf8, 0x48, 0x83, 0xc4, 0x10, 0x5d, 0xc3,
    ];
    code.resize(32, 0x90);
    code.extend([0x55, 0x48, 0x89, 0xe5, 0x0f, 0x33, 0x5d, 0xc3]);
    let mut image = code_image(&code);
    let caller = velk::loader::Function {
        addr: 0,
        size: Some(27),
        size_estimated: false,
        name: Some("saved_frame".into()),
        aliases: vec![],
        sources: vec![velk::loader::NameSource::Symtab],
    };
    image.functions.insert(0, caller.clone());
    image.functions.insert(
        32,
        velk::loader::Function {
            addr: 32,
            size: Some(8),
            size_estimated: false,
            name: Some("clock_value".into()),
            aliases: vec![],
            sources: vec![velk::loader::NameSource::Symtab],
        },
    );
    let summary = velk::analysis::summary(&image, 32);
    assert!(!summary.clobbers.unwrap().contains(5));
    let callee = velk::lift::lift(&image, 32, 8, &Default::default()).unwrap();
    assert!(
        callee
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(
                stmt,
                Stmt::Unsupported {
                    writes_memory: Some(false),
                    ..
                }
            ))
    );
    let analyzed = velk::analysis::analyze(&image, &caller, None).unwrap();
    let symbols = velk::render::callee_names(&image);
    let printed = velk::render::render(&analyzed.ir, &analyzed.references, &symbols, &[]);
    assert!(!printed.contains("undefined"), "{printed}");
    assert!(printed.contains("clock_value("), "{printed}");
    assert!(printed.contains("return a0;"), "{printed}");
    let source = Program {
        text: format!(
            "{HEADER}\nstatic unsigned calls;\nstatic uint64_t clock_value(void) {{ ++calls; return 123; }}\n{printed}\nint main(void) {{\nuint64_t values[] = {{ 0, 1, UINT64_MAX, UINT64_C(0x1234567887654321) }};\nfor (unsigned i = 0; i < 4; ++i) {{ if (saved_frame(values[i]) != (int32_t)values[i]) return 1; }}\nreturn calls != 4;\n}}\n"
        ),
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("unsupported-saved-frame");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &[]);
        assert_eq!(run(&program, ""), "");
    }
    std::fs::remove_dir_all(&scratch).unwrap();
}
