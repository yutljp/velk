use super::*;

#[test]
fn combined_vector_prelude_compiles_and_runs() {
    let mut code = String::new();
    for name in ["first", "second"] {
        let ir = synthetic_ir(
            name,
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Apply {
                    op: velk::ir::Operation::Lanes(velk::ir::LaneOp::Add, 32),
                    args: vec![Expr::reg(7, 64), Expr::Const(0x0000_0001_0000_0001)],
                },
            }],
        );
        let standalone = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(standalone.starts_with("/* velk prelude */\n"));
        assert_eq!(
            standalone
                .matches("static inline uint64_t add_lanes32")
                .count(),
            1
        );
        code.push_str(&standalone);
    }
    let combined = velk::render::combine(&code);
    assert_eq!(
        combined
            .matches("static inline uint64_t add_lanes32")
            .count(),
        1
    );
    assert_eq!(combined.matches("/* velk prelude */").count(), 1);
    let source = format!(
        "#include <stdint.h>\n{combined}\nint main(void) {{ return first(UINT64_MAX) != 0 || second(0) != UINT64_C(0x100000001); }}\n"
    );
    let scratch = scratch_dir("combined-prelude");
    let path = scratch.join("check.c");
    let executable = scratch.join("check");
    std::fs::write(&path, source).unwrap();
    let compiled = Command::new(compiler())
        .args(["-std=gnu11", "-O2"])
        .arg(&path)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}
