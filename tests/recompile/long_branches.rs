use super::*;

#[test]
fn printed_branches_reach_code_after_many_instructions() {
    let scratch = scratch_dir("long-branches");
    let mut candidates = Vec::new();
    for (name, target, index) in [
        ("long_aarch64", "aarch64-linux-gnu", 0),
        ("long_x86_64", "x86_64-linux-gnu", 7),
    ] {
        let source = scratch.join(format!("{name}.c"));
        let object = scratch.join(format!("{name}.o"));
        std::fs::write(
            &source,
            format!(
                "unsigned long long {name}(unsigned long long input) {{\n\
                 if (input) {{\n\
                 __asm__ volatile(\".rept 8192\\nnop\\n.endr\");\n\
                 input++;\n\
                 }}\n\
                 return input + 2;\n\
                 }}\n"
            ),
        )
        .expect("write source");
        let compiled = Command::new(COMPILER)
            .args(["-target", target, "-O1", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .expect("compile function");
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let image = velk::loader::load(&object).expect("load object");
        let function = image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .expect("function symbol");
        let blocks = velk::lift::lift(
            &image,
            function.addr,
            function.size.expect("function size"),
            &Default::default(),
        )
        .expect("lift complete function");
        assert!(
            matches!(
                blocks.last().expect("shared return").stmts.last(),
                Some(Stmt::Ret { .. })
            ),
            "{blocks:?}"
        );
        let mut ir = synthetic_ir(
            name,
            vec![Param {
                index,
                name: "input".into(),
                ty: CType::U64,
            }],
            CType::U64,
            Vec::new(),
        );
        ir.addr = function.addr;
        ir.isa = image.isa;
        ir.convention = image.convention_of(function.addr);
        ir.blocks = blocks;
        candidates.push(printed_candidate(
            ir,
            vec![vec![0], vec![1], vec![9], vec![u64::MAX]],
        ));
    }
    check_candidates("long-branches", candidates, Mode::Registers, &[]);
    std::fs::remove_dir_all(scratch).ok();
}
