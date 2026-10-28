use super::*;

#[test]
fn go_return_slot_and_frame_address_compile_and_run() {
    let sp = velk::arch::stack_pointer(Isa::X86_64);
    let mut source = String::from(HEADER);
    for (name, value) in [
        (
            "return_pc",
            Expr::Load {
                addr: Box::new(Expr::reg(sp, 64)),
                width: 8,
                signed: false,
            },
        ),
        (
            "argument_frame",
            Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(8)),
        ),
    ] {
        let mut ir = synthetic_ir(name, vec![], CType::U64, vec![Stmt::Ret { value }]);
        ir.convention = Convention::GoAmd64;
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(code.contains("velk_return_address_slot"), "{code}");
        assert!(!code.contains("rsp"), "{code}");
        source.push_str(&code);
    }
    source.push_str("\nstatic uint64_t frame[2];\nuint64_t *velk_return_address_slot(void) { return frame; }\nint main(void) { for (unsigned i = 0; i < 100; ++i) { frame[0] = (uint64_t)i * 0xfedcba987654321ULL; if (return_pc() != frame[0] || argument_frame() != (uintptr_t)(frame + 1)) return 1; } return 0; }\n");
    let scratch = scratch_dir("go-frame");
    let input = scratch.join("frame.c");
    std::fs::write(&input, source).unwrap();
    for level in ["-O0", "-O2"] {
        let executable = scratch.join(format!("frame{level}"));
        let compiled = Command::new(compiler())
            .args(FLAGS)
            .arg(level)
            .arg(&input)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(Command::new(&executable).status().unwrap().success());
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn go_abi0_wrapper_recovers_stack_parameters_and_result() {
    let mut binary = Binary::open(&common::fixtures_dir().join("go_probe")).unwrap();
    let ir = &binary.analysis(0x466160, None).unwrap().ir;
    assert_eq!(ir.convention, Convention::GoAbi0);
    assert_eq!(ir.stack_params.len(), 3);
    let code = binary.decompile(0x466160, None, None).unwrap();
    assert!(code.contains("velk_entry_stack_pointer"), "{code}");
    assert!(code.contains("return"), "{code}");
    let mut source = String::from(HEADER);
    source.push_str("\nstatic uint64_t stack[8];\nuint64_t velk_entry_stack_pointer(void) { return (uintptr_t)stack; }\n");
    source.push_str("\nstatic uint64_t runtime_write_45fe40(int64_t a, int64_t b, uint32_t c) { return (uint32_t)((uint64_t)a * 7 + (uint64_t)b * 13 + c); }\n");
    source.push_str(&code);
    source.push_str("\nint main(void) { for (unsigned i = 0; i < 100; ++i) { int64_t a = (int64_t)((uint64_t)i * 0xfedcba987654321ULL); int64_t b = -a; uint32_t c = i * 123456789u; uint32_t expected = runtime_write_45fe40(a, b, c); if (runtime_write_466160(a, b, c) != (int32_t)expected) return 1; uint32_t stored; __builtin_memcpy(&stored, (unsigned char *)stack + 0x20, 4); if (stored != expected) return 2; } return 0; }\n");
    let scratch = scratch_dir("go-abi0");
    let input = scratch.join("wrapper.c");
    std::fs::write(&input, source).unwrap();
    for level in ["-O0", "-O2"] {
        let executable = scratch.join(format!("wrapper{level}"));
        let compiled = Command::new(compiler())
            .args(FLAGS)
            .arg(level)
            .arg(&input)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(Command::new(&executable).status().unwrap().success());
    }
    std::fs::remove_dir_all(scratch).ok();
}
