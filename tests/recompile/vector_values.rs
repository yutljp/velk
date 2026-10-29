use super::*;
use velk::ir::RegRef;

#[test]
fn printed_vector_members_preserve_order_and_partial_writes() {
    let low = velk::ir::VARIABLE_BASE;
    let high = low + 1;
    let address = |offset| Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset));
    let load = |offset| Expr::Load {
        addr: Box::new(address(offset)),
        width: 8,
        signed: false,
    };
    let mut ir = synthetic_ir(
        "vector_copy",
        vec![Param {
            index: 7,
            name: "p".into(),
            ty: CType::pointer_to(CType::U64),
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: low,
                    width: 64,
                },
                value: load(0),
                at: None,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: high,
                    width: 64,
                },
                value: load(8),
                at: None,
            },
            Stmt::Store {
                addr: address(8),
                value: Expr::reg(low, 64),
                width: 8,
                at: None,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: low,
                    width: 64,
                },
                value: Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(low, 64), Expr::Const(!0xff)),
                    Expr::Const(0x5a),
                ),
                at: None,
            },
            Stmt::Store {
                addr: address(0),
                value: Expr::reg(high, 64),
                width: 8,
                at: None,
            },
            Stmt::Store {
                addr: address(16),
                value: Expr::reg(low, 64),
                width: 8,
                at: None,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::And, Expr::reg(low, 64), Expr::Const(0xffff)),
                    Expr::bin(BinOp::And, Expr::reg(high, 64), Expr::Const(0xffff)),
                ),
                at: None,
            },
        ],
    );
    ir.variable_registers = [(low, 18), (high, 19)].into();
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("struct velk_vector vector"), "{code}");
    assert!(
        code.contains("vector.low") && code.contains("vector.high"),
        "{code}"
    );
    let code = velk::render::combine(&format!(
        "{code}{}",
        code.replace("vector_copy", "vector_copy_again")
    ));
    assert_eq!(code.matches("struct velk_vector {").count(), 1, "{code}");
    let source = format!(
        "#include <stdint.h>\n{code}\nint main(void) {{\nuint64_t p[3] = {{UINT64_C(0x123456789abcdef0), UINT64_C(0xfedcba9876543210), 0}};\nuint64_t result = vector_copy(p);\nreturn p[0] != UINT64_C(0xfedcba9876543210) || p[1] != UINT64_C(0x123456789abcdef0) || p[2] != UINT64_C(0x123456789abcde5a) || result != (UINT64_C(0xde5a) + UINT64_C(0x3210));\n}}\n"
    );
    let scratch = scratch_dir("vector-values");
    let path = scratch.join("check.c");
    std::fs::write(&path, source).unwrap();
    for level in ["-O0", "-O2"] {
        let executable = scratch.join("check");
        let compiled = Command::new(compiler())
            .args(["-std=c11", "-Werror", level])
            .arg(&path)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}\n{code}");
        assert!(
            Command::new(&executable).status().unwrap().success(),
            "{code}"
        );
    }
}
