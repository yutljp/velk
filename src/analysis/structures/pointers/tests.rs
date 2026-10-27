use super::*;

use crate::ir::RegRef;
use crate::loader::Isa;

#[test]
fn smt_normalized_pointers_preserve_assignments_and_addresses() {
    use crate::ir::smt::{Proofs, raw_bin};

    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for isa in [Isa::X86_64, Isa::AArch64] {
        for size in [8, 12, 16, 24, 32, 65536] {
            for phase in [1, size / 2, size - 1] {
                for delta in [0, size, size * 2, u64::MAX, 1 << 63] {
                    let register = VARIABLE_BASE;
                    let before = raw_bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(delta));
                    let mut ir = FunctionIr::single_block(isa, vec![]);
                    ir.blocks = vec![crate::ir::Block {
                        start: 0,
                        stmts: vec![
                            Stmt::Assign {
                                dest: RegRef {
                                    index: register,
                                    width: 64,
                                },
                                value: Expr::reg(7, 64),
                            },
                            Stmt::Assign {
                                dest: RegRef {
                                    index: register,
                                    width: 64,
                                },
                                value: before.clone(),
                            },
                            Stmt::Store {
                                addr: before.clone(),
                                value: Expr::Const(0),
                                width: 1,
                            },
                        ],
                    }];
                    let original = ir.blocks[0].stmts.clone();
                    assert_eq!(normalize(&mut ir, &[(register, phase)]), vec![register]);
                    let substitution = [(
                        register,
                        raw_bin(BinOp::Sub, Expr::reg(register, 64), Expr::Const(phase)),
                    )];
                    for (original, stmt) in original.iter().zip(&ir.blocks[0].stmts) {
                        let (value, assigned) = match stmt {
                            Stmt::Assign { value, .. } => (value, true),
                            Stmt::Store { addr, .. } => (addr, false),
                            _ => unreachable!(),
                        };
                        let value =
                            crate::ir::visit::substitute_values(value.clone(), &substitution);
                        let mut restored = if assigned {
                            raw_bin(BinOp::Add, value, Expr::Const(phase))
                        } else {
                            value
                        };
                        let mut original = match original {
                            Stmt::Assign { value, .. } => value.clone(),
                            Stmt::Store { addr, .. } => addr.clone(),
                            _ => unreachable!(),
                        };
                        let renamed = std::collections::HashMap::from([(register, 0), (7, 1)]);
                        crate::ir::visit::rename_registers(&mut original, &renamed);
                        crate::ir::visit::rename_registers(&mut restored, &renamed);
                        proofs.expression(
                            format!(
                                "{isa:?} size {size} phase {phase} delta {delta} assign {assigned}"
                            ),
                            &original,
                            &restored,
                            64,
                        );
                    }
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn partial_reads_and_writes_keep_the_original_pointer() {
    for width in [8, 16, 32] {
        for partial_write in [false, true] {
            let register = VARIABLE_BASE;
            let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
            ir.blocks = vec![crate::ir::Block {
                start: 0,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: register,
                            width: 64,
                        },
                        value: Expr::Const(0),
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: register,
                            width: if partial_write { width } else { 64 },
                        },
                        value: Expr::reg(register, if partial_write { 64 } else { width }),
                    },
                ],
            }];
            let before = format!("{:?}", ir.blocks);
            assert!(normalize(&mut ir, &[(register, 4)]).is_empty());
            assert_eq!(format!("{:?}", ir.blocks), before);
        }
    }
}

#[test]
fn an_incoming_local_value_is_not_represented_as_an_element_pointer() {
    let register = VARIABLE_BASE;
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: register,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(16)),
            },
            Stmt::Store {
                addr: Expr::reg(register, 64),
                value: Expr::Const(0),
                width: 1,
            },
        ],
    );
    let before = format!("{:?}", ir.blocks);
    assert!(normalize(&mut ir, &[(register, 8)]).is_empty());
    assert_eq!(format!("{:?}", ir.blocks), before);
}
