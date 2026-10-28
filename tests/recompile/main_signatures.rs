use super::*;

#[test]
fn main_parameters_use_standard_types_and_preserve_byte_addresses() {
    for isa in [Isa::X86_64, Isa::AArch64] {
        let convention = Convention::of(isa, velk::loader::Format::Elf, false);
        let registers = convention.arguments();
        let load = |address, width| Expr::Load {
            addr: Box::new(address),
            width,
            signed: false,
        };
        let mut ir = synthetic_ir(
            "main",
            vec![
                Param {
                    index: registers[0],
                    name: "a0".into(),
                    ty: CType::U32,
                },
                Param {
                    index: registers[1],
                    name: "a1".into(),
                    ty: CType::pointer_to(CType::int(1, false)),
                },
                Param {
                    index: registers[2],
                    name: "a2".into(),
                    ty: CType::U64,
                },
            ],
            CType::U32,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(registers[0], 32),
                    Expr::bin(
                        BinOp::Add,
                        load(
                            load(
                                Expr::bin(BinOp::Add, Expr::reg(registers[1], 64), Expr::Const(8)),
                                8,
                            ),
                            1,
                        ),
                        load(load(Expr::reg(registers[2], 64), 8), 1),
                    ),
                ),
            }],
        );
        ir.isa = isa;
        ir.convention = convention;
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(
            code.contains("int main(int argc, char **argv, char **envp)"),
            "{code}"
        );
        syntax::run_printed(
            &code.replace(" main(", " printed_main("),
            "",
            "char *argv[] = {\"program\", \"Z\", 0}; char *envp[] = {\"A=1\", 0}; int values[] = {0, 1, -1, INT32_MIN, INT32_MAX}; for (unsigned i=0; i<5; ++i) if ((uint32_t)printed_main(values[i], argv, envp) != (uint32_t)values[i] + 'Z' + 'A') return 1; return 0;",
        );
    }
}

#[test]
fn main_with_only_argc_adds_argv_and_no_inputs_use_void() {
    for count in [0, 1] {
        let params = if count == 0 {
            vec![]
        } else {
            vec![Param {
                index: 7,
                name: "count".into(),
                ty: CType::U32,
            }]
        };
        let ir = synthetic_ir(
            "main",
            params,
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Const(42),
            }],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        let signature = if count == 0 {
            "int main(void)"
        } else {
            "int main(int argc, char **argv)"
        };
        assert!(code.contains(signature), "{code}");
        let call = if count == 0 {
            "printed_main()"
        } else {
            "printed_main(1, 0)"
        };
        syntax::run_printed(
            &code.replace(" main(", " printed_main("),
            "",
            &format!("return {call} != 42;"),
        );
    }
}
