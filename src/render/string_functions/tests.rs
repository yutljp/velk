use super::*;
use crate::ir::{Block, CType, FunctionIr, Param, RegRef};
use crate::loader::Isa;

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
        at: None,
    }
}

fn load(addr: Expr) -> Expr {
    Expr::Load {
        addr: Box::new(addr),
        width: 1,
        signed: false,
    }
}

#[test]
fn repeated_value_expansion_stops_before_exhausting_memory() {
    let value = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(load(Expr::reg(1, 64))),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::reg(0, 64)),
        els: Box::new(Expr::reg(0, 64)),
    };
    let nodes = vec![Node::Stmt(assign(0, value)); 64];
    let mut values = Values::from([(0, Expr::Const(0)), (1, Expr::reg(1, 64))]);
    assert!(!assignments(&nodes, &mut values, &mut Vec::new()));
    assert!(crate::passes::copies::expr_size(&values[&0]) <= 128);
}

#[test]
fn affine_states_and_unsigned_byte_classes_have_symbolic_proofs() {
    use crate::ir::smt::{Proofs, raw_bin};

    assert!(Proofs::available(), "string effect proofs require z3");
    let mut proofs = Proofs::default();
    for offset in [0, 1, u64::MAX, 1 << 63] {
        let value = raw_bin(
            BinOp::Sub,
            raw_bin(
                BinOp::Add,
                Expr::reg(0, 64),
                raw_bin(BinOp::Add, Expr::reg(1, 64), Expr::Const(offset)),
            ),
            Expr::reg(0, 64),
        );
        proofs.expression(
            format!("string state/{offset}"),
            &value,
            &sum(value.clone()),
            64,
        );
    }
    let a = "(bvand r0 (_ bv255 64))";
    let b = "(bvand r1 (_ bv255 64))";
    let zero = "(_ bv0 64)";
    let az = format!("(= {a} {zero})");
    let bz = format!("(= {b} {zero})");
    let classes = [
        (format!("(and {az} {bz})"), [0, 0]),
        (format!("(and {az} (not {bz}))"), [0, 1]),
        (format!("(and (not {az}) {bz})"), [1, 0]),
        (format!("(and (not {az}) (= {a} {b}))"), [1, 1]),
        (
            format!("(and (not {az}) (not {bz}) (bvult {a} {b}))"),
            [1, 2],
        ),
        (
            format!("(and (not {az}) (not {bz}) (bvugt {a} {b}))"),
            [2, 1],
        ),
    ];
    let partition = classes
        .iter()
        .map(|(class, _)| class.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    proofs.predicate(
        "unsigned byte partition",
        "true",
        &format!("(or {partition})"),
    );
    for (class, pair) in &classes {
        for cond in [
            Cond::Eq,
            Cond::Ne,
            Cond::Cc,
            Cond::Cs,
            Cond::Hi,
            Cond::Ls,
            Cond::Lt,
            Cond::Le,
            Cond::Gt,
            Cond::Ge,
        ] {
            let expected = crate::ir::semantics::holds(cond, pair[0], pair[1], 32);
            let predicate = crate::ir::smt::condition(cond, a, b, 32);
            proofs.predicate(
                format!("byte class/{pair:?}/{cond:?}"),
                "true",
                &format!("(=> {class} (= {predicate} {expected}))"),
            );
        }
    }
    proofs.counterexample(
        "changed string step",
        "(bvadd r0 (_ bv1 64))",
        "(bvadd r0 (_ bv2 64))",
    );
    proofs.check();
}

#[test]
fn finite_compiler_comparisons_have_symbolic_memory_proofs() {
    use crate::ir::smt::Proofs;

    assert!(Proofs::available(), "finite string comparisons require z3");
    let mut proofs = Proofs::default();
    for architecture in ["x86_64", "aarch64"] {
        for compiler in ["clang", "gcc"] {
            for level in [2, 3] {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                    "tests/data/string_functions/{architecture}.{compiler}.O{level}.debug.elf"
                ));
                let mut binary = crate::service::Binary::open(&path).unwrap();
                for (name, terminated) in [("short_compare", false), ("short_string_compare", true)]
                {
                    let addr = binary.find_address(name).unwrap();
                    let mut before = binary.analysis(addr, None).unwrap().ir.clone();
                    let a = Expr::reg(before.params[0].index, 64);
                    let b = Expr::reg(before.params[1].index, 64);
                    let mut value = Expr::Const(0);
                    for offset in (0..3).rev() {
                        let x = load(Expr::bin(BinOp::Add, a.clone(), Expr::Const(offset)));
                        let y = load(Expr::bin(BinOp::Add, b.clone(), Expr::Const(offset)));
                        if terminated {
                            value = Expr::Select {
                                cond: Cond::Eq,
                                lhs: Box::new(x.clone()),
                                rhs: Box::new(Expr::Const(0)),
                                then: Box::new(Expr::Const(0)),
                                els: Box::new(value),
                            };
                        }
                        let different = Expr::Select {
                            cond: Cond::Cc,
                            lhs: Box::new(x.clone()),
                            rhs: Box::new(y.clone()),
                            then: Box::new(Expr::Const(u64::MAX)),
                            els: Box::new(Expr::Const(1)),
                        };
                        value = Expr::Select {
                            cond: Cond::Eq,
                            lhs: Box::new(x),
                            rhs: Box::new(y),
                            then: Box::new(value),
                            els: Box::new(different),
                        };
                    }
                    for stmt in before.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                        if let Stmt::Ret { value, .. } = stmt {
                            *value = Expr::bin(BinOp::And, value.clone(), Expr::Const(0xffff_ffff));
                        }
                    }
                    let after = FunctionIr::single_block(
                        before.isa,
                        vec![Stmt::Ret {
                            value: Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff)),
                            at: None,
                        }],
                    );
                    proofs.function(
                        format!("finite compare/{architecture}/{compiler}/{level}/{name}"),
                        &before,
                        &after,
                    );
                }
            }
        }
    }
    proofs.check();
}

fn scan(isa: Isa, pointer: bool) -> FunctionIr {
    let mut ir = FunctionIr::single_block(isa, vec![]);
    ir.name = Some(
        if pointer {
            "pointer_length"
        } else {
            "index_length"
        }
        .to_owned(),
    );
    ir.params = vec![Param {
        index: 2,
        name: "source".to_owned(),
        ty: CType::pointer_to(CType::Int {
            bytes: 1,
            signed: false,
        }),
    }];
    ir.ret_type = CType::U64;
    let address = if pointer {
        Expr::reg(3, 64)
    } else {
        Expr::bin(BinOp::Add, Expr::reg(2, 64), Expr::reg(3, 64))
    };
    let result = if pointer {
        Expr::bin(BinOp::Sub, Expr::reg(3, 64), Expr::reg(2, 64))
    } else {
        Expr::reg(3, 64)
    };
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                assign(
                    3,
                    if pointer {
                        Expr::reg(2, 64)
                    } else {
                        Expr::Const(0)
                    },
                ),
                Stmt::Br {
                    target: Some(10),
                    at: None,
                },
            ],
        },
        Block {
            start: 10,
            stmts: vec![
                assign(4, load(address)),
                assign(3, Expr::bin(BinOp::Add, Expr::reg(3, 64), Expr::Const(1))),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(4, 64),
                    rhs: Expr::Const(0),
                    target: 10,
                    at: None,
                },
            ],
        },
        Block {
            start: 20,
            stmts: vec![Stmt::Ret {
                value: Expr::bin(BinOp::Sub, result, Expr::Const(1)),
                at: None,
            }],
        },
    ];
    ir
}

#[test]
fn scalar_lengths_compile_and_match_native_for_both_targets() {
    for (label, isa) in [("x86_64", Isa::X86_64), ("aarch64", Isa::AArch64)] {
        let mut source = String::from("#include <stdint.h>\n#include <string.h>\n");
        for pointer in [false, true] {
            let ir = scan(isa, pointer);
            let rendered =
                crate::render::render_with_dependencies(&ir, &[], &Default::default(), &[]);
            assert_eq!(
                rendered.inline_functions,
                vec![InlineFunction {
                    function: "strlen".to_owned(),
                    bytes: None
                }],
                "{}",
                rendered.code
            );
            assert!(
                rendered.code.contains("__builtin_strlen"),
                "{}",
                rendered.code
            );
            source.push_str(&rendered.code);
        }
        source.push_str("int main(void) { unsigned char s[4]; for (unsigned a=0;a<256;++a) for (unsigned b=0;b<256;++b) for (unsigned n=0;n<3;++n) { s[0]=a; s[1]=b; s[2]=127; s[n]=0; s[3]=0; if(index_length(s)!=strlen((char *)s) || pointer_length(s)!=strlen((char *)s)) return 1; } return 0; }\n");
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/string-function-tests");
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join(format!("{label}.c"));
        let output = directory.join(label);
        std::fs::write(&input, &source).unwrap();
        let compiled = std::process::Command::new("clang")
            .args(["-std=c11", "-Werror", "-O2"])
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}\n{source}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            std::process::Command::new(&output)
                .status()
                .unwrap()
                .success()
        );
    }
}

#[test]
fn different_steps_results_reads_and_writes_keep_the_loop() {
    for kind in 0..10 {
        let mut ir = scan(Isa::X86_64, false);
        match kind {
            0 => {
                ir.blocks[2].stmts = vec![Stmt::Ret {
                    value: Expr::reg(3, 64),
                    at: None,
                }]
            }
            1 => {
                ir.blocks[1].stmts[1] =
                    assign(3, Expr::bin(BinOp::Add, Expr::reg(3, 64), Expr::Const(2)))
            }
            2 => {
                ir.blocks[1].stmts[1] =
                    assign(3, Expr::bin(BinOp::Sub, Expr::reg(3, 64), Expr::Const(1)))
            }
            3 => ir.blocks[1].stmts.insert(
                0,
                Stmt::Store {
                    addr: Expr::reg(2, 64),
                    value: Expr::Const(0),
                    width: 1,
                    at: None,
                },
            ),
            4 => ir.blocks[1]
                .stmts
                .insert(0, assign(5, load(Expr::reg(2, 64)))),
            5 => {
                let Stmt::Assign {
                    value: Expr::Load { width, .. },
                    ..
                } = &mut ir.blocks[1].stmts[0]
                else {
                    unreachable!()
                };
                *width = 2;
            }
            6 => {
                let Stmt::Assign { dest, .. } = &mut ir.blocks[1].stmts[1] else {
                    unreachable!()
                };
                dest.width = 32;
            }
            7 => {
                let Stmt::Brif { cond, .. } = &mut ir.blocks[1].stmts[2] else {
                    unreachable!()
                };
                *cond = Cond::Eq;
            }
            8 => {
                let Stmt::Assign { dest, .. } = &mut ir.blocks[1].stmts[0] else {
                    unreachable!()
                };
                dest.width = 8;
            }
            _ => {
                ir.params[0].ty = CType::Int {
                    bytes: 1,
                    signed: true,
                }
            }
        }
        let rendered = crate::render::render_with_dependencies(&ir, &[], &Default::default(), &[]);
        assert!(
            rendered.inline_functions.is_empty(),
            "{kind}: {}",
            rendered.code
        );
        assert!(
            !rendered.code.contains("__builtin_strlen"),
            "{kind}: {}",
            rendered.code
        );
    }
}
