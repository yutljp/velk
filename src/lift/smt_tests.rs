use super::*;
use crate::ir::smt::{self, Proofs};

#[test]
fn return_address_calls_preserve_registers_memory_and_flags() {
    use crate::ir::{BinOp, FunctionIr};
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for register in 0..8u16 {
        for observed in 0..8u16 {
            let mut code = vec![0xe8, 0x1b, 0, 0, 0, 0xc3];
            code.resize(32, 0x90);
            code.extend([0x8b, 0x04 | ((register as u8) << 3), 0x24, 0xc3]);
            let image = Image::from_code(Isa::I386, 0x1000, code);
            let blocks =
                lift(&image, 0x1000, 6, &HashSet::new()).expect("return-address call lifts");
            let mut after = blocks[0].stmts.clone();
            if register == 4 {
                assert!(after.iter().any(|stmt| matches!(stmt, Stmt::Call { .. })));
                continue;
            }
            assert!(!after.iter().any(|stmt| matches!(stmt, Stmt::Call { .. })));
            after.pop();
            after.push(Stmt::Ret {
                value: Expr::reg(observed, 64),
            });
            let address = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Sub, Expr::reg(4, 64), Expr::Const(4)),
                Expr::Const(0xffff_ffff),
            );
            let before = vec![
                Stmt::Store {
                    addr: address.clone(),
                    value: Expr::Const(0x1005),
                    width: 4,
                },
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: register,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(address),
                        width: 4,
                        signed: false,
                    },
                },
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 4,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::And, Expr::reg(4, 64), Expr::Const(0xffff_ffff)),
                },
                Stmt::Ret {
                    value: Expr::reg(observed, 64),
                },
            ];
            let before = FunctionIr::single_block(Isa::I386, before);
            let after = FunctionIr::single_block(Isa::I386, after);
            proofs.function(
                format!("return address/{register}/{observed}"),
                &before,
                &after,
            );
        }
    }
    for register in [0u8, 1] {
        let mut code = vec![
            0x83, 0xf8, 0, 0xe8, 0x18, 0, 0, 0, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3,
        ];
        code.resize(32, 0x90);
        code.extend([0x8b, 0x04 | (register << 3), 0x24, 0xc3]);
        let image = Image::from_code(Isa::I386, 0x1000, code);
        let after =
            lift(&image, 0x1000, 15, &HashSet::new()).expect("comparison survives the call");
        let address = Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Sub, Expr::reg(4, 64), Expr::Const(4)),
            Expr::Const(0xffff_ffff),
        );
        let before = vec![
            Stmt::Store {
                addr: address,
                value: Expr::Const(0x1008),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::Select {
                    cond: crate::ir::Cond::Lt,
                    lhs: Box::new(Expr::reg(0, 32)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                },
            },
        ];
        let before = FunctionIr::single_block(Isa::I386, before);
        let after = FunctionIr::single_block(Isa::I386, after[0].stmts.clone());
        proofs.function(format!("return address/flags/{register}"), &before, &after);
    }
    proofs.check();
}

#[test]
fn word_result_splitting_and_joining_preserve_all_bits() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for isa in [Isa::I386, Isa::Arm32] {
        let before = [Stmt::Ret {
            value: Expr::reg(0, 64),
        }];
        let mut after = vec![Stmt::Assign {
            dest: crate::ir::RegRef {
                index: pairs32::TEMPORARIES[3],
                width: 64,
            },
            value: Expr::reg(0, 64),
        }];
        after.extend(pairs32::split_result(isa));
        after.push(Stmt::Ret {
            value: pairs32::join(
                Expr::reg(0, 32),
                Expr::reg(if isa == Isa::I386 { 2 } else { 1 }, 32),
            ),
        });
        proofs.program(format!("word result/{isa:?}"), &before, &after);
    }
    proofs.check();
}

#[test]
fn rotations_and_byte_reversals_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        for right in [false, true] {
            for amount in [
                Expr::reg(1, 64),
                Expr::Const(0),
                Expr::Const(1),
                Expr::Const(u64::from(bits)),
                Expr::Const(63),
                Expr::Const(64),
                Expr::Const(u64::MAX),
            ] {
                let count = smt::term(&amount);
                let input = smt::term(&x);
                let input = format!("((_ extract {} 0) {input})", bits - 1);
                let count = format!("((_ extract {} 0) {count})", bits - 1);
                let rotated = format!(
                    "(ext_rotate_{} {input} {count})",
                    if right { "right" } else { "left" }
                );
                let expected = if bits < 64 {
                    format!("((_ zero_extend {}) {rotated})", 64 - bits)
                } else {
                    rotated
                };
                let actual = smt::low(
                    &smt::term(&rotate(x.clone(), amount.clone(), bits, right)),
                    u32::from(bits),
                );
                if matches!(amount, Expr::Reg { .. }) {
                    // Cover every count residue while keeping all upper count bits symbolic.
                    // Bind after lowering so the real variable-count expression is checked.
                    let count_bits = bits.ilog2();
                    for residue in 0..bits {
                        let count = format!(
                            "(concat ((_ extract 63 {count_bits}) r1) (_ bv{residue} {count_bits}))"
                        );
                        proofs.predicate(
                            format!("rotate/{bits}/{right}/count residue {residue}"),
                            &format!("(let ((r1 {count})) {expected})"),
                            &format!("(let ((r1 {count})) {actual})"),
                        );
                    }
                } else {
                    proofs.predicate(
                        format!("rotate/{bits}/{right}/{amount:?}"),
                        &expected,
                        &actual,
                    );
                }
            }
        }
        for chunk in [1, 2, 4, 8] {
            if chunk > bits / 8 {
                continue;
            }
            let input = smt::term(&x);
            let bytes = bits / 8;
            let mut pieces = Vec::new();
            for byte in (0..bytes).rev() {
                let source = byte / chunk * chunk + chunk - 1 - byte % chunk;
                pieces.push(format!(
                    "((_ extract {} {}) {input})",
                    u32::from(source) * 8 + 7,
                    u32::from(source) * 8
                ));
            }
            let mut expected = pieces[0].clone();
            for piece in &pieces[1..] {
                expected = format!("(concat {expected} {piece})");
            }
            if bits < 64 {
                expected = format!("((_ zero_extend {}) {expected})", 64 - bits);
            }
            let actual = smt::term(&reverse_bytes(x.clone(), bits, chunk));
            proofs.predicate(format!("reverse bytes/{bits}/{chunk}"), &expected, &actual);
        }
    }
    proofs.check();
}

#[test]
fn recovered_operands_and_partial_register_writes_are_equivalent() {
    use crate::ir::{BinOp, FunctionIr, RegRef};
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        for op in [BinOp::Add, BinOp::Sub] {
            let written = Expr::bin(op, x.clone(), Expr::reg(1, bits));
            let recovered = recover_operand(&x, &written, 0, bits).expect("invertible operand");
            let before =
                FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value: x.clone() }]);
            let after = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: 0,
                            width: bits,
                        },
                        value: written,
                    },
                    Stmt::Ret {
                        value: Expr::bin(
                            BinOp::And,
                            recovered,
                            Expr::Const(crate::ir::semantics::mask(u32::from(bits))),
                        ),
                    },
                ],
            );
            proofs.function(format!("recover operand/{bits}/{op:?}"), &before, &after);
        }
    }
    for (code, bits, offset) in [
        (vec![0x88, 0xf8, 0xc3], 8, 0),        // mov al, bh
        (vec![0x66, 0x89, 0xf8, 0xc3], 16, 0), // mov ax, di
        (vec![0x89, 0xf8, 0xc3], 32, 0),       // mov eax, edi
        (vec![0x48, 0x89, 0xf8, 0xc3], 64, 0), // mov rax, rdi
        (vec![0x40, 0x88, 0xf8, 0xc3], 8, 0),  // mov al, dil
        (vec![0x88, 0xfc, 0xc3], 8, 8),        // mov ah, bh
    ] {
        let size = code.len() as u64;
        let image = Image::from_code(Isa::X86_64, 0, code.clone());
        let mut actual = FunctionIr::single_block(Isa::X86_64, Vec::new());
        actual.blocks = lift(&image, 0, size, &HashSet::new()).expect("register move lifts");
        // BH is the second byte of RBX; the REX and wider encodings read RDI.
        let source = if code[0] == 0x88 {
            Expr::bin(BinOp::Shr, Expr::reg(3, 64), Expr::Const(8))
        } else {
            Expr::reg(7, 64)
        };
        let mask = crate::ir::semantics::mask(bits) << offset;
        let placed = Expr::bin(
            BinOp::Shl,
            Expr::bin(
                BinOp::And,
                source,
                Expr::Const(crate::ir::semantics::mask(bits)),
            ),
            Expr::Const(offset),
        );
        let value = if bits >= 32 {
            placed
        } else {
            Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!mask)),
                placed,
            )
        };
        let expected = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value }]);
        proofs.function(format!("partial write/{code:?}"), &expected, &actual);
    }
    proofs.check();
}
