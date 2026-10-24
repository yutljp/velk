use super::{
    SegmentBase, SegmentBaseRead, Symbols, callee_names, render, render_with_dependencies,
};
use crate::ir::{
    BinOp, CType, Expr, FunctionIr, Operation, Param, Precision, RegRef, Stmt, VARIABLE_BASE,
};
use crate::loader::Isa;
use std::collections::HashMap;

fn rendered(ir: &FunctionIr) -> String {
    render(ir, &[], &Symbols::default(), &[])
}

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    }
}

fn load(addr: Expr, width: u8) -> Expr {
    Expr::Load {
        addr: Box::new(addr),
        width,
        signed: false,
    }
}

fn object_access_ir(stmts: Vec<Stmt>) -> FunctionIr {
    use crate::ir::{
        AbiLocation, AbiPiece, AbiProfile, DeclaredSignature, Definition, Passing, RegisterClass,
        SignatureAbi, ValueAbi,
    };
    let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
    ir.params = vec![Param {
        index: 0,
        name: "a0".to_owned(),
        ty: CType::U64,
    }];
    ir.definitions = vec![Definition {
        name: "struct bytes".to_owned(),
        members: vec!["unsigned char bytes[24];".to_owned()],
        fields: vec!["bytes".to_owned()],
        contains: vec![],
        size: 24,
        alignment: Some(1),
        compatible_profiles: vec![AbiProfile::Aapcs64],
    }];
    ir.declared_signature = Some(DeclaredSignature {
        params: vec![("value".to_owned(), CType::Named("struct bytes".to_owned()))],
        ret: CType::U64,
        variadic: false,
        abi: Ok(SignatureAbi {
            profile: AbiProfile::Aapcs64,
            arguments: vec![ValueAbi {
                aggregate: true,
                size: 24,
                alignment: 1,
                defined_bits: vec![(0, 192)],
                passing: Passing::Indirect {
                    pointer: AbiLocation::Register(0),
                    returned_pointer: None,
                },
            }],
            result: Some(ValueAbi {
                aggregate: false,
                size: 8,
                alignment: 8,
                defined_bits: vec![(0, 64)],
                passing: Passing::Direct(vec![AbiPiece {
                    location: AbiLocation::Register(0),
                    object_offset: 0,
                    bytes: 8,
                    class: Some(RegisterClass::Integer),
                }]),
            }),
        }),
    });
    ir
}

#[test]
fn object_loads_copy_the_exact_width_and_preserve_signedness() {
    for width in [1, 2, 4, 8] {
        for signed in [false, true] {
            let mut ir = object_access_ir(vec![Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
                    width,
                    signed,
                },
            }]);
            let code = rendered(&ir);
            let ty = super::type_of(width, false);
            assert!(
                code.contains(&format!(
                    "__builtin_memcpy(({ty}[1]){{0}}, value_address + 0x1, {width})"
                )),
                "{code}"
            );
            if signed {
                assert!(code.contains(super::type_of(width, true)), "{code}");
            }
            ir.declared_signature = None;
            ir.params[0].ty = CType::pointer_to(CType::int(1, false));
            assert!(!rendered(&ir).contains("__builtin_memcpy"));
        }
    }
}

#[test]
fn overlapping_object_store_copies_its_source_before_writing() {
    let address = Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1));
    let ir = object_access_ir(vec![
        Stmt::Store {
            addr: address.clone(),
            value: load(Expr::reg(0, 64), 8),
            width: 8,
        },
        Stmt::Ret {
            value: load(address, 8),
        },
    ]);
    let code = rendered(&ir);
    let store = code
        .lines()
        .find(|line| line.contains("__builtin_memcpy(value_address + 0x1,"))
        .expect("an object store");
    assert_eq!(store.matches("__builtin_memcpy").count(), 2, "{code}");
    assert_eq!(store.matches("value_address, 8").count(), 1, "{code}");
    assert!(store.contains("&(uint64_t){"), "{code}");
}

#[test]
fn object_pointer_load_converts_copied_integer_bits() {
    let mut ir = object_access_ir(vec![Stmt::Ret {
        value: load(Expr::reg(0, 64), 8),
    }]);
    ir.declared_signature.as_mut().unwrap().ret = CType::pointer_to(CType::int(1, false));
    let code = rendered(&ir);
    assert!(
        code.contains("__builtin_memcpy((uint64_t[1]){0}, value_address, 8)"),
        "{code}"
    );
    assert!(!code.contains("*(uint8_t **)__builtin_memcpy"), "{code}");
}

#[test]
fn floating_object_loads_reinterpret_copied_bits() {
    for precision in [Precision::Single, Precision::Double] {
        let width = precision.bits() / 8;
        let ir = object_access_ir(vec![Stmt::Ret {
            value: Expr::apply(
                Operation::FloatEqual(precision),
                vec![
                    load(
                        Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1)),
                        width,
                    ),
                    Expr::Const(0),
                ],
            ),
        }]);
        let code = rendered(&ir);
        let ty = super::type_of(width, false);
        assert!(
            code.contains(&format!(
                "__builtin_memcpy(({ty}[1]){{0}}, value_address + 0x1, {width})"
            )),
            "{code}"
        );
        assert!(
            !code.contains("*(float *)") && !code.contains("*(double *)"),
            "{code}"
        );
    }
}

#[test]
fn object_compare_exchange_patterns_keep_copy_accesses() {
    let address = Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1));
    let old = VARIABLE_BASE;
    let ir = object_access_ir(vec![
        assign(old, load(address.clone(), 8)),
        Stmt::Store {
            addr: address,
            width: 8,
            value: Expr::Select {
                cond: crate::ir::Cond::Eq,
                lhs: Box::new(Expr::reg(old, 64)),
                rhs: Box::new(Expr::Const(5)),
                then: Box::new(Expr::Const(7)),
                els: Box::new(Expr::reg(old, 64)),
            },
        },
        Stmt::Ret {
            value: Expr::reg(old, 64),
        },
    ]);
    let code = rendered(&ir);
    assert_eq!(code.matches("__builtin_memcpy").count(), 2, "{code}");
    assert!(!code.contains("__sync_val_compare_and_swap"), "{code}");
}

fn scalar_stack_ir(stmts: Vec<Stmt>) -> FunctionIr {
    let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
    ir.params = [7, 6, 2, 1, 8, 9]
        .into_iter()
        .enumerate()
        .map(|(position, index)| Param {
            index,
            name: format!("a{position}"),
            ty: CType::U64,
        })
        .collect();
    ir.stack_params = (0..3)
        .map(|index| crate::ir::StackParam {
            offset: 8 * (index + 1),
            size: 8,
            name: format!("a{}", index + 6),
            ty: CType::U64,
            position: index as usize + 6,
        })
        .collect();
    ir
}

#[test]
fn crossing_stack_bytes_share_backing_and_reserve_identifiers() {
    let sp = crate::arch::stack_pointer(Isa::X86_64);
    let at = |offset| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset));
    let mut ir = scalar_stack_ir(vec![
        Stmt::Store {
            addr: at(15),
            value: load(at(12), 8),
            width: 8,
        },
        Stmt::Ret {
            value: Expr::bin(BinOp::Xor, load(at(8), 8), load(at(16), 8)),
        },
    ]);
    ir.stack_params[0].name = "incoming_bytes".to_owned();
    ir.stack_params[1].name = "uint64_t".to_owned();
    ir.stack_params[2].name = "__builtin_memcpy".to_owned();
    let code = rendered(&ir);
    assert!(
        code.contains("unsigned char incoming_bytes_2[0x18];"),
        "{code}"
    );
    assert!(code.contains("&(uint64_t){(uint64_t)uint64_t_2}"), "{code}");
    assert!(
        code.contains("&(uint64_t){(uint64_t)__builtin_memcpy_2}"),
        "{code}"
    );
    assert!(!code.contains("rsp"), "{code}");
    assert!(code.contains("incoming_bytes_2 + 0x4, 8)"), "{code}");
    assert!(
        code.contains("__builtin_memcpy(incoming_bytes_2 + 0x7,"),
        "{code}"
    );
    let body = code
        .split("&(uint64_t){(uint64_t)__builtin_memcpy_2}, 8);")
        .nth(1)
        .unwrap();
    assert!(!body.contains("&uint64_t_2"), "{code}");
    assert!(!body.contains("&incoming_bytes +"), "{code}");
}

#[test]
fn scalar_stack_parameter_parts_use_bounded_byte_copies() {
    let sp = crate::arch::stack_pointer(Isa::X86_64);
    let at = |offset| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset));
    let ir = scalar_stack_ir(vec![Stmt::Ret {
        value: Expr::bin(
            BinOp::Add,
            load(at(31), 1),
            Expr::bin(BinOp::Add, load(at(24), 4), load(at(24), 8)),
        ),
    }]);
    let code = rendered(&ir);
    assert!(code.contains("(uint8_t *)&a8 + 0x7, 1)"), "{code}");
    assert!(code.contains("(uint8_t *)&a8 + 0x0, 4)"), "{code}");
    assert_eq!(code.matches("__builtin_memcpy").count(), 2, "{code}");
    assert!(!code.contains("rsp"), "{code}");
    let full = rendered(&scalar_stack_ir(vec![Stmt::Ret {
        value: load(at(24), 8),
    }]));
    assert!(full.contains("return a8;"), "{full}");
    assert!(!full.contains("__builtin_memcpy"), "{full}");
}

#[test]
fn scalar_stack_parameter_parts_reject_unknown_or_incompatible_storage() {
    let sp = crate::arch::stack_pointer(Isa::X86_64);
    for (offset, width, ty) in [
        (31, 2, CType::U64),
        (24, 8, CType::U32),
        (28, 1, CType::U32),
        (31, 1, CType::Named("opaque_scalar".to_owned())),
    ] {
        let mut ir = scalar_stack_ir(vec![Stmt::Ret {
            value: load(
                Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset)),
                width,
            ),
        }]);
        ir.stack_params[2].ty = ty;
        let code = rendered(&ir);
        assert!(!code.contains("__builtin_memcpy"), "{code}");
        assert!(code.contains("rsp"), "{code}");
    }
    let mut ir = scalar_stack_ir(vec![Stmt::Ret {
        value: load(Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(25)), 1),
    }]);
    ir.stack_params[2].ty = CType::U32;
    let code = rendered(&ir);
    assert!(code.contains("(uint8_t *)&a8 + 0x1, 1)"), "{code}");
    assert!(!code.contains("rsp"), "{code}");
}

#[test]
fn scalar_stack_parameter_parts_reject_ambiguous_frame_addresses() {
    let sp = crate::arch::stack_pointer(Isa::X86_64);
    let address = Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(31));
    let ir = scalar_stack_ir(vec![
        assign(VARIABLE_BASE, load(address.clone(), 1)),
        assign(sp, Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8))),
        Stmt::Ret {
            value: load(address, 1),
        },
    ]);
    let frames = super::block_frames(&ir, sp);
    let locals = super::stack_locals(&ir, &frames, &Default::default(), &Default::default());
    assert!(locals.parameter_addresses.is_empty());
}

/// The condition printed for `return lhs <cond> rhs ? 1 : 0` in a
/// function whose parameters are `params` (register, type) and which
/// first assigns `copies` (variable, value).
fn compared(
    isa: Isa,
    params: &[(u16, CType)],
    copies: &[(u16, Expr)],
    cond: crate::ir::Cond,
    lhs: Expr,
    rhs: Expr,
) -> String {
    let mut stmts: Vec<Stmt> = copies
        .iter()
        .map(|(index, value)| assign(*index, value.clone()))
        .collect();
    stmts.push(Stmt::Ret {
        value: Expr::Select {
            cond,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            then: Box::new(Expr::Const(1)),
            els: Box::new(Expr::Const(0)),
        },
    });
    let mut ir = FunctionIr::single_block(isa, stmts);
    ir.params = params
        .iter()
        .enumerate()
        .map(|(position, (index, ty))| Param {
            index: *index,
            name: format!("a{position}"),
            ty: ty.clone(),
        })
        .collect();
    let text = rendered(&ir);
    let line = text
        .lines()
        .find_map(|line| {
            let Some(value) = line.trim().strip_prefix("return ") else {
                return None;
            };
            value.strip_suffix(';')
        })
        .unwrap_or_else(|| panic!("{text}"));
    line.to_owned()
}

fn mask(value: Expr, mask: u64) -> Expr {
    Expr::bin(BinOp::And, value, Expr::Const(mask))
}

#[test]
fn a_signed_comparison_of_a_masked_byte_reads_the_byte_as_signed() {
    use crate::ir::Cond;
    let byte = VARIABLE_BASE;
    let copies = [(byte, load(Expr::reg(7, 64), 1))];
    let text = compared(
        Isa::X86_64,
        &[(7, CType::pointer_to(CType::Void))],
        &copies,
        Cond::Lt,
        mask(Expr::reg(byte, 64), 0xff),
        Expr::Const(0),
    );
    // Only ever read as a signed byte, the variable is one.
    assert_eq!(text, "v1 < 0");
    // An unsigned comparison of the same byte needs no mask, as the
    // variable holds only the byte.
    let text = compared(
        Isa::X86_64,
        &[(7, CType::pointer_to(CType::Void))],
        &copies,
        Cond::Cc,
        mask(Expr::reg(byte, 64), 0xff),
        Expr::Const(0xf0),
    );
    assert_eq!(text, "v1 < 240");
    // Of a wider value, read whole elsewhere, it keeps the mask.
    let text = compared(
        Isa::X86_64,
        &[(7, CType::pointer_to(CType::Void))],
        &[(byte, load(Expr::reg(7, 64), 8)), (0, Expr::reg(byte, 64))],
        Cond::Cc,
        mask(Expr::reg(byte, 64), 0xff),
        Expr::Const(0xf0),
    );
    assert_eq!(text, "(v1 & 0xff) < 240");
}

#[test]
fn an_unsigned_comparison_of_a_signed_parameter_reads_it_unsigned() {
    use crate::ir::Cond;
    // C compares a signed parameter signed.
    let test = |cond| {
        compared(
            Isa::X86_64,
            &[(7, CType::I64)],
            &[],
            cond,
            Expr::reg(7, 64),
            Expr::Const(1),
        )
    };
    assert_eq!(test(Cond::Gt), "a0 > 1");
    assert_eq!(test(Cond::Hi), "(uint64_t)a0 > 1");
    assert_eq!(test(Cond::Cc), "(uint64_t)a0 < 1");
}

#[test]
fn a_signed_comparison_of_unsigned_memory_reads_it_as_signed() {
    use crate::ir::Cond;
    let text = compared(
        Isa::AArch64,
        &[(0, CType::pointer_to(CType::Void))],
        &[],
        Cond::Gt,
        load(Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(8)), 2),
        Expr::Const(5),
    );
    assert_eq!(text, "*(int16_t *)(a0 + 0x8) > 5");
}

#[test]
fn both_operands_of_a_signed_32_bit_comparison_are_read_as_signed() {
    use crate::ir::Cond;
    let wide = [(0, CType::U64), (1, CType::U64)];
    let text = compared(
        Isa::AArch64,
        &wide,
        &[],
        Cond::Le,
        mask(Expr::reg(0, 64), 0xffff_ffff),
        mask(
            Expr::bin(BinOp::Sub, Expr::reg(1, 64), Expr::Const(2)),
            0xffff_ffff,
        ),
    );
    assert_eq!(text, "(int32_t)a0 <= (int32_t)(a1 - 2)");
    // A 32-bit signed parameter needs no cast.
    let text = compared(
        Isa::X86_64,
        &[(
            7,
            CType::Int {
                bytes: 4,
                signed: true,
            },
        )],
        &[],
        Cond::Lt,
        Expr::reg(7, 32),
        Expr::Const(5),
    );
    assert_eq!(text, "a0 < 5");
    // Nor does one whose register is masked to its width.
    let text = compared(
        Isa::AArch64,
        &[(
            0,
            CType::Int {
                bytes: 4,
                signed: true,
            },
        )],
        &[],
        Cond::Lt,
        mask(Expr::reg(0, 64), 0xffff_ffff),
        Expr::Const(1),
    );
    assert_eq!(text, "a0 < 1");
}

#[test]
fn a_narrow_sum_compared_signed_wraps_at_its_width() {
    use crate::ir::Cond;
    let text = compared(
        Isa::X86_64,
        &[(7, CType::pointer_to(CType::Void))],
        &[],
        Cond::Ge,
        mask(
            Expr::bin(
                BinOp::Add,
                load(Expr::reg(7, 64), 1),
                load(Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)), 1),
            ),
            0xff,
        ),
        Expr::Const(0),
    );
    assert_eq!(
        text,
        "(int8_t)(*(uint8_t *)(a0) + *(uint8_t *)(a0 + 0x1)) >= 0"
    );
}

#[test]
fn an_unsigned_comparison_of_a_sign_extended_value_reads_all_64_bits() {
    use crate::ir::Cond;
    let text = compared(
        Isa::AArch64,
        &[(0, CType::U64)],
        &[],
        Cond::Cc,
        Expr::SignExtend {
            value: Box::new(Expr::reg(0, 64)),
            width: 1,
        },
        Expr::Const(0x80),
    );
    assert_eq!(text, "(uint64_t)(int8_t)a0 < 128");
}

#[test]
fn a_variable_read_narrower_than_declared_is_compared_by_that_part() {
    use crate::ir::Cond;
    let value = VARIABLE_BASE;
    let copies = [(value, load(Expr::reg(7, 64), 8))];
    let wide = Expr::bin(BinOp::Add, Expr::reg(value, 64), Expr::reg(value, 64));
    // Read whole elsewhere, the variable is 64 bits wide.
    let copies = [copies[0].clone(), (0, wide)];
    let text = compared(
        Isa::X86_64,
        &[(7, CType::U64)],
        &copies,
        Cond::Eq,
        Expr::reg(value, 32),
        Expr::Const(5),
    );
    assert_eq!(text, "(uint32_t)v1 == 5");
    let text = compared(
        Isa::X86_64,
        &[(7, CType::U64)],
        &copies,
        Cond::Lt,
        Expr::reg(value, 32),
        Expr::Const(5),
    );
    assert_eq!(text, "(int32_t)v1 < 5");
}

#[test]
fn variables_are_declared_with_the_types_their_uses_give() {
    let (sum, pointer, count) = (VARIABLE_BASE, VARIABLE_BASE + 1, VARIABLE_BASE + 2);
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(pointer, Expr::reg(7, 64)),
            assign(
                sum,
                Expr::Apply {
                    op: Operation::FloatAdd(Precision::Double),
                    args: vec![Expr::Const(0), load(Expr::reg(pointer, 64), 8)],
                },
            ),
            assign(
                count,
                Expr::bin(BinOp::Shr, Expr::reg(6, 64), Expr::Const(1)),
            ),
            assign(
                pointer,
                Expr::bin(BinOp::Add, Expr::reg(pointer, 64), Expr::reg(count, 64)),
            ),
            Stmt::Ret {
                value: Expr::reg(sum, 64),
            },
        ],
    );
    ir.ret_type = CType::Named("double".to_owned());
    let text = rendered(&ir);
    assert!(text.contains("    double v1;\n"), "{text}");
    assert!(text.contains("    double *v2;\n"), "{text}");
    assert!(text.contains("    int64_t v3;\n"), "{text}");
    // The pointer moved by bytes moves by bytes in C too.
    assert!(
        text.contains("v2 = (double *)((uint8_t *)v2 + v3);"),
        "{text}"
    );
}

#[test]
fn a_counter_kept_to_32_bits_is_a_32_bit_variable() {
    // v1 = 0; v1 = (v1 + 1) & 0xffffffff; *a0 = (int32_t)v1; return v1;
    let counter = VARIABLE_BASE;
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(counter, Expr::Const(0)),
            assign(
                counter,
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Add, Expr::reg(counter, 64), Expr::Const(1)),
                    Expr::Const(0xffff_ffff),
                ),
            ),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::SignExtend {
                    value: Box::new(Expr::reg(counter, 64)),
                    width: 4,
                },
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(counter, 64),
            },
        ],
    );
    ir.ret_type = CType::I32;
    ir.params = vec![Param {
        index: 7,
        name: "a0".to_owned(),
        ty: CType::pointer_to(CType::I64),
    }];
    let text = rendered(&ir);
    assert!(text.contains("    int32_t result;\n"), "{text}");
    assert!(text.contains("++result;"), "{text}");
    assert!(text.contains("*a0 = result;"), "{text}");
    ir.variable_registers.insert(counter, 0);
    ir.debug_registers.push((0, "total".to_owned()));
    let text = rendered(&ir);
    assert!(text.contains("    int32_t total;\n"), "{text}");
    assert!(text.contains("++total;"), "{text}");
    assert!(text.contains("*a0 = total;"), "{text}");
}

#[test]
fn a_32_bit_value_read_whole_is_a_32_bit_variable_without_a_sign() {
    // v1 = *(uint32_t *)a0; return v1 == a1;
    let value = VARIABLE_BASE;
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(value, load(Expr::reg(7, 64), 4)),
            Stmt::Ret {
                value: Expr::Select {
                    cond: crate::ir::Cond::Eq,
                    lhs: Box::new(Expr::reg(value, 64)),
                    rhs: Box::new(Expr::reg(6, 64)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                },
            },
        ],
    );
    ir.params = vec![
        Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::U32),
        },
        Param {
            index: 6,
            name: "a1".to_owned(),
            ty: CType::U64,
        },
    ];
    let text = rendered(&ir);
    assert!(text.contains("    uint32_t v1;\n"), "{text}");
    assert!(text.contains("v1 == a1"), "{text}");
}

#[test]
fn a_narrow_local_takes_its_sign_from_how_it_is_loaded() {
    // *(int32_t *)(rsp - 0x10) = a0 + 1; return it, loaded with zeros or
    // with its sign. A copy of a0 itself would read as a0.
    let slot = || {
        Expr::bin(
            BinOp::Add,
            Expr::reg(4, 64),
            Expr::Const(0xffff_ffff_ffff_fff0),
        )
    };
    let declared = |signed: bool| {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot(),
                    value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                    width: 4,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(slot()),
                        width: 4,
                        signed,
                    },
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::I32,
        }];
        ir.ret_type = CType::I64;
        let text = rendered(&ir);
        text.lines()
            .find(|line| line.contains(" local_0;"))
            .unwrap_or_else(|| panic!("{text}"))
            .trim()
            .to_owned()
    };
    assert_eq!(declared(false), "uint32_t local_0; /* [sp-10] */");
    assert_eq!(declared(true), "int32_t local_0; /* [sp-10] */");
}

#[test]
fn a_local_index_is_not_mistaken_for_a_pointer() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let index = load(slot.clone(), 8);
    for address in [
        Expr::bin(BinOp::Add, Expr::reg(7, 64), index.clone()),
        Expr::bin(BinOp::Add, index.clone(), Expr::reg(7, 64)),
        Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(!7)),
            index.clone(),
        ),
        Expr::bin(BinOp::Add, load(Expr::reg(7, 64), 8), index),
    ] {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(1)),
                    width: 8,
                },
                Stmt::Ret {
                    value: load(address, 1),
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "data".to_owned(),
                ty: CType::pointer_to(CType::int(1, false)),
            },
            Param {
                index: 6,
                name: "index".to_owned(),
                ty: CType::U64,
            },
        ];
        let text = rendered(&ir);
        assert!(text.contains("    int64_t local_0;"), "{text}");
        assert!(!text.contains("*local_0;"), "{text}");
    }
}

#[test]
fn a_local_pointer_with_only_offsets_keeps_its_pointer_type() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let pointer = load(slot.clone(), 8);
    for address in [
        pointer.clone(),
        Expr::bin(BinOp::Add, pointer.clone(), Expr::Const(4)),
        Expr::bin(BinOp::Sub, pointer.clone(), Expr::Const(4)),
        Expr::bin(
            BinOp::Add,
            pointer,
            Expr::bin(BinOp::Shl, Expr::reg(6, 64), Expr::Const(2)),
        ),
    ] {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                    width: 8,
                },
                Stmt::Ret {
                    value: load(address, 1),
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "data".to_owned(),
                ty: CType::pointer_to(CType::int(1, false)),
            },
            Param {
                index: 6,
                name: "index".to_owned(),
                ty: CType::U64,
            },
        ];
        let text = rendered(&ir);
        assert!(text.contains("    uint8_t *local_0;"), "{text}");
    }
}

#[test]
fn an_integer_local_takes_a_pointer_as_its_address() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Shr, load(slot, 8), Expr::Const(1)),
            },
        ],
    );
    ir.params = vec![Param {
        index: 7,
        name: "data".to_owned(),
        ty: CType::pointer_to(CType::int(1, false)),
    }];
    let text = rendered(&ir);
    assert!(text.contains("    uint64_t local_0;"), "{text}");
    assert!(
        text.contains("local_0 = (uintptr_t)(data + 0x1);"),
        "{text}"
    );
}

#[test]
fn a_pointer_local_takes_an_integer_with_a_cast() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::Const(0x1000),
                width: 8,
            },
            Stmt::Ret {
                value: load(load(slot, 8), 1),
            },
        ],
    );
    ir.ret_type = CType::U32;
    let text = rendered(&ir);
    assert!(text.contains("    uint8_t *local_0;"), "{text}");
    assert!(text.contains("local_0 = (uint8_t *)0x1000;"), "{text}");
}

#[test]
fn an_integer_compare_exchange_takes_a_pointer_as_its_address() {
    let old = VARIABLE_BASE;
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(old, load(Expr::reg(7, 64), 8)),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                width: 8,
                value: Expr::Select {
                    cond: crate::ir::Cond::Eq,
                    lhs: Box::new(Expr::reg(old, 64)),
                    rhs: Box::new(Expr::reg(6, 64)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::reg(old, 64)),
                },
            },
            Stmt::Ret {
                value: Expr::reg(old, 64),
            },
        ],
    );
    ir.params = vec![
        Param {
            index: 7,
            name: "cell".to_owned(),
            ty: CType::pointer_to(CType::U64),
        },
        Param {
            index: 6,
            name: "expected".to_owned(),
            ty: CType::pointer_to(CType::Void),
        },
    ];
    let text = rendered(&ir);
    assert!(
        text.contains("__sync_val_compare_and_swap((uint64_t *)cell, (uintptr_t)expected, 1)"),
        "{text}"
    );
    ir.params[0].ty = CType::pointer_to(CType::Named("struct record".to_owned()));
    ir.members.push(crate::ir::Member {
        structure: "record".to_owned(),
        offset: 0,
        name: "pointer".to_owned(),
        ty: CType::pointer_to(CType::Void),
        width: 8,
    });
    let text = rendered(&ir);
    assert!(
        text.contains("__sync_val_compare_and_swap((uint64_t *)cell, (uintptr_t)expected, 1)"),
        "{text}"
    );
}

#[test]
fn a_pointer_local_update_keeps_the_machine_byte_offset() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(7, 64),
                width: 8,
            },
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::bin(BinOp::Add, load(slot.clone(), 8), Expr::Const(1)),
                width: 8,
            },
            Stmt::Ret {
                value: load(load(slot, 8), 4),
            },
        ],
    );
    ir.params = vec![Param {
        index: 7,
        name: "data".to_owned(),
        ty: CType::pointer_to(CType::U32),
    }];
    let text = rendered(&ir);
    assert!(text.contains("    uint32_t *local_0;"), "{text}");
    assert!(
        text.contains("local_0 = (uint32_t *)((uint8_t *)local_0 + 0x1);"),
        "{text}"
    );
    assert!(!text.contains("local_0 += 0x1"), "{text}");
}

#[test]
fn an_integer_local_update_keeps_the_pointer_conversion() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::bin(BinOp::Add, load(slot.clone(), 8), Expr::reg(7, 64)),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Shr, load(slot, 8), Expr::Const(1)),
            },
        ],
    );
    ir.params = vec![Param {
        index: 7,
        name: "data".to_owned(),
        ty: CType::pointer_to(CType::int(1, false)),
    }];
    let text = rendered(&ir);
    assert!(
        text.contains("local_0 = (uintptr_t)(data + local_0);"),
        "{text}"
    );
    assert!(!text.contains("local_0 += data"), "{text}");
}

#[test]
fn compare_exchange_does_not_truncate_a_wider_comparison() {
    let old = VARIABLE_BASE;
    for signed in [false, true] {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(
                    old,
                    Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 1,
                        signed,
                    },
                ),
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    width: 1,
                    value: Expr::Select {
                        cond: crate::ir::Cond::Eq,
                        lhs: Box::new(Expr::reg(old, 64)),
                        rhs: Box::new(Expr::Const(0x101)),
                        then: Box::new(Expr::Const(2)),
                        els: Box::new(Expr::reg(old, 64)),
                    },
                },
                Stmt::Ret {
                    value: Expr::reg(old, 64),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "cell".to_owned(),
            ty: CType::pointer_to(CType::int(1, signed)),
        }];
        let text = rendered(&ir);
        assert!(!text.contains("__sync_val_compare_and_swap"), "{text}");
    }
}

#[test]
fn a_trap_after_a_call_is_left_out_and_one_alone_is_kept() {
    let call = Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: crate::ir::Convention::SysV,
        args: Some(Vec::new()),
        floats_named: false,
        outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
        clobbers: None,
        via: None,
    };
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![call, Stmt::Trap]);
    ir.ret_type = CType::Void;
    let text = rendered(&ir);
    assert!(text.contains("sub_1000();"), "{text}");
    assert!(!text.contains("__builtin_trap"), "{text}");
    let ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Trap]);
    assert!(rendered(&ir).contains("__builtin_trap();"));
}

#[test]
fn a_spilled_32_bit_parameter_reads_as_itself() {
    // *(int32_t *)(rsp - 0x10) = a0; return the slot, and a 64-bit load
    // of it, which reads bytes the spill did not write.
    let slot = || {
        Expr::bin(
            BinOp::Add,
            Expr::reg(4, 64),
            Expr::Const(0xffff_ffff_ffff_fff0),
        )
    };
    let rendered_with = |width: u8| {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot(),
                    value: Expr::reg(7, 32),
                    width: 4,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(slot()),
                        width,
                        signed: false,
                    },
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::I32,
        }];
        ir.ret_type = CType::U32;
        rendered(&ir)
    };
    let text = rendered_with(4);
    assert!(!text.contains("local_0"), "{text}");
    assert!(text.contains("return a0;"), "{text}");
    let text = rendered_with(8);
    assert!(text.contains("local_0 = a0;"), "{text}");
    // A byte of it reads the parameter's low byte.
    let text = rendered_with(1);
    assert!(!text.contains("local_0"), "{text}");
    assert!(text.contains("a0"), "{text}");
}

#[test]
fn a_pointer_to_scalars_is_indexed_by_elements() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: load(
                Expr::bin(
                    BinOp::Add,
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(7, 64),
                        Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
                    ),
                    Expr::Const(0x10),
                ),
                8,
            ),
        }],
    );
    ir.params = vec![
        Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::I64),
        },
        Param {
            index: 6,
            name: "a1".to_owned(),
            ty: CType::I64,
        },
    ];
    let text = rendered(&ir);
    assert!(text.contains("return a0[a1 + 2];"), "{text}");
}

#[test]
fn a_further_result_in_a_parameter_register_is_no_parameter() {
    // v1 = f(a0, a1); v2 = rbx; return results(v1, v2);
    let (first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1);
    let convention = crate::ir::Convention::GoAmd64;
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention,
                args: Some(vec![Expr::reg(0, 64), Expr::reg(3, 64)]),
                floats_named: false,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(convention, None),
                via: None,
            },
            assign(first, Expr::reg(0, 64)),
            assign(second, Expr::reg(3, 64)),
            Stmt::Ret {
                value: Expr::Apply {
                    op: Operation::Results,
                    args: vec![Expr::reg(first, 64), Expr::reg(second, 64)],
                },
            },
        ],
    );
    ir.convention = convention;
    ir.params = ["a0", "a1"]
        .iter()
        .zip([0, 3])
        .map(|(name, index)| Param {
            index,
            name: (*name).to_owned(),
            ty: CType::I64,
        })
        .collect();
    crate::ssa::split_variables(&mut ir, convention.results());
    crate::ssa::take_results_directly(&mut ir);
    let text = rendered(&ir);
    assert!(
        text.contains("= v15; /* also returned by the call */"),
        "{text}"
    );
    assert!(text.contains("v2 = v15;"), "{text}");
    assert!(text.contains("return v1; /* also returns v2 */"), "{text}");
}

#[test]
fn a_pointer_taken_as_an_integer_is_cast() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(
                VARIABLE_BASE,
                Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(7)),
            ),
            Stmt::Ret {
                value: Expr::Select {
                    cond: crate::ir::Cond::Ne,
                    lhs: Box::new(Expr::reg(VARIABLE_BASE, 64)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::reg(7, 64)),
                    els: Box::new(Expr::Const(0)),
                },
            },
        ],
    );
    ir.params = vec![Param {
        index: 7,
        name: "a0".to_owned(),
        ty: CType::pointer_to(CType::U32),
    }];
    ir.ret_type = CType::U64;
    let text = rendered(&ir);
    for line in [
        "    v1 = (uintptr_t)a0 & 0x7;\n",
        "    return (uintptr_t)(v1 != 0 ? a0 : 0);\n",
    ] {
        assert!(text.contains(line), "{line:?} in {text}");
    }
}

#[test]
fn an_array_of_structures_is_indexed_by_elements() {
    // struct { int64_t field_0x0; int32_t field_0x8; } of 16 bytes.
    let element = VARIABLE_BASE;
    let field = VARIABLE_BASE + 1;
    let scaled = |offset: u64| {
        Expr::bin(
            BinOp::Add,
            Expr::bin(
                BinOp::Add,
                Expr::reg(7, 64),
                Expr::bin(BinOp::Shl, Expr::reg(6, 64), Expr::Const(4)),
            ),
            Expr::Const(offset),
        )
    };
    let store = |addr: Expr, width: u8| Stmt::Store {
        addr,
        value: Expr::Const(0),
        width,
    };
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            store(scaled(8), 4),
            store(
                Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(0x28)),
                4,
            ),
            store(Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8)), 4),
            assign(element, scaled(0)),
            store(Expr::reg(element, 64), 8),
            assign(
                element,
                Expr::bin(BinOp::Add, Expr::reg(element, 64), Expr::Const(0x20)),
            ),
            assign(field, scaled(8)),
            // Four bytes into a field is no field.
            Stmt::Ret {
                value: load(scaled(0xc), 4),
            },
        ],
    );
    let name = "sub_0_a0".to_owned();
    ir.params = vec![
        Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::Named(format!("struct {name}"))),
        },
        Param {
            index: 6,
            name: "a1".to_owned(),
            ty: CType::I64,
        },
    ];
    ir.structures = vec![crate::ir::Structure {
        name,
        fields: vec![(0, CType::I64), (8, CType::I32)],
        size: Some(0x10),
        elements: vec![element],
    }];
    let text = rendered(&ir);
    for line in [
        "uint8_t gap_0xc[0x4]; };\n",
        "    struct sub_0_a0 *v1;\n",
        "    a0[a1].field_0x8 = 0;\n",
        "    a0[2].field_0x8 = 0;\n",
        "    a0->field_0x8 = 0;\n",
        "    v1 = a0 + a1;\n",
        "    v1->field_0x0 = 0;\n",
        "    v1 = v1 + 0x2;\n",
        "    v2 = (uintptr_t)&a0[a1].field_0x8;\n",
        "    return *(uint32_t *)((uint8_t *)a0 + ((uint64_t)a1 << 4) + 0xc);\n",
    ] {
        assert!(text.contains(line), "{line:?} in {text}");
    }
}

/// The function returning `value` from parameters `params` (register,
/// type), printed whole.
fn returning(params: &[(u16, CType)], ret_type: CType, value: Expr) -> String {
    let mut ir = FunctionIr::single_block(Isa::AArch64, vec![Stmt::Ret { value }]);
    ir.ret_type = ret_type;
    ir.params = params
        .iter()
        .enumerate()
        .map(|(position, (index, ty))| Param {
            index: *index,
            name: format!("a{position}"),
            ty: ty.clone(),
        })
        .collect();
    rendered(&ir)
}

/// The expression of the function's return statement.
fn returned(params: &[(u16, CType)], ret_type: CType, value: Expr) -> String {
    let text = returning(params, ret_type, value);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("return ")?.strip_suffix(';'))
        .unwrap_or_else(|| panic!("{text}"))
        .to_owned()
}

#[test]
fn a_logical_shift_of_a_signed_value_shifts_it_without_its_sign() {
    let text = returned(
        &[(0, CType::I32)],
        CType::I32,
        Expr::bin(BinOp::Shr, Expr::reg(0, 32), Expr::Const(31)),
    );
    assert_eq!(text, "(uint32_t)a0 >> 31");
    // An unsigned one needs no cast.
    let text = returned(
        &[(0, CType::U32)],
        CType::I32,
        Expr::bin(BinOp::Shr, Expr::reg(0, 32), Expr::Const(31)),
    );
    assert_eq!(text, "a0 >> 31");
}

#[test]
fn a_product_whose_high_bits_are_read_is_computed_at_64_bits() {
    let product = Expr::bin(BinOp::Mul, Expr::reg(0, 32), Expr::reg(1, 32));
    let text = returned(
        &[(0, CType::U32), (1, CType::U32)],
        CType::U32,
        mask(
            Expr::bin(BinOp::Shr, product.clone(), Expr::Const(1)),
            0xffff_ffff,
        ),
    );
    assert_eq!(text, "(uint64_t)a0 * a1 >> 1");
    // Read only in its low 32 bits, it stays as C computes it.
    let text = returned(
        &[(0, CType::U32), (1, CType::U32)],
        CType::U32,
        mask(product, 0xffff_ffff),
    );
    assert_eq!(text, "a0 * a1");
}

#[test]
fn a_zero_extended_register_in_wider_arithmetic_is_read_without_its_sign() {
    let text = returned(
        &[(0, CType::I32), (1, CType::I32)],
        CType::I64,
        Expr::bin(
            BinOp::Sub,
            Expr::SignExtend {
                value: Box::new(Expr::reg(0, 64)),
                width: 4,
            },
            Expr::reg(1, 32),
        ),
    );
    assert_eq!(text, "(int64_t)a0 - (uint32_t)a1");
}

#[test]
fn a_builtin_takes_its_argument_at_its_own_width() {
    let text = returned(
        &[(0, CType::I32)],
        CType::I32,
        Expr::Apply {
            op: Operation::PopCount(64),
            args: vec![Expr::reg(0, 32)],
        },
    );
    assert_eq!(text, "__builtin_popcountll((uint32_t)a0)");
}

#[test]
fn a_mask_stays_on_a_sum_that_can_carry_out_of_it() {
    let low = |index| mask(Expr::reg(index, 64), 0xffff_ffff);
    let text = returned(
        &[(0, CType::I64), (1, CType::I64)],
        CType::I64,
        mask(Expr::bin(BinOp::Add, low(1), low(0)), 0xffff_ffff),
    );
    assert_eq!(text, "(a1 + a0) & 0xffffffff");
    // Read in its low 32 bits only, it goes.
    let text = returned(
        &[(0, CType::I64), (1, CType::I64)],
        CType::I32,
        mask(Expr::bin(BinOp::Add, low(1), low(0)), 0xffff_ffff),
    );
    assert_eq!(text, "a1 + a0");
}

#[test]
fn a_shifted_constant_has_the_width_of_the_shift() {
    let text = returned(
        &[(0, CType::U64)],
        CType::U64,
        Expr::bin(
            BinOp::Shl,
            Expr::Const(1),
            Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0x3f)),
        ),
    );
    assert_eq!(text, "0x1ULL << (a0 & 0x3f)");
}

#[test]
fn a_register_that_is_no_parameter_is_declared() {
    let text = returning(&[], CType::I64, Expr::reg(29, 64));
    assert!(text.contains("    uint64_t v1;\n"), "{text}");
}

#[test]
fn segment_reads_have_ordered_providers_and_entry_snapshots() {
    let fs = crate::arch::x86::FS_BASE;
    let gs = crate::arch::x86::GS_BASE;
    for registers in [vec![fs], vec![gs], vec![gs, fs, fs]] {
        let value = registers
            .iter()
            .map(|index| load(Expr::reg(*index, 64), 8))
            .reduce(|lhs, rhs| Expr::bin(BinOp::Add, lhs, rhs))
            .unwrap();
        let ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value }]);
        let symbols = Symbols::default();
        let rendered = render_with_dependencies(&ir, &[], &symbols, &[]);
        assert_eq!(render(&ir, &[], &symbols, &[]), rendered.code);
        let expected: Vec<_> = [(fs, SegmentBase::Fs, "fs"), (gs, SegmentBase::Gs, "gs")]
            .into_iter()
            .filter(|(index, _, _)| registers.contains(index))
            .map(|(_, segment, base)| SegmentBaseRead {
                segment,
                provider: format!("velk_x86_{base}_base"),
            })
            .collect();
        assert_eq!(rendered.segment_bases, expected);
        for binding in &rendered.segment_bases {
            let base = match binding.segment {
                SegmentBase::Fs => "fs_base",
                SegmentBase::Gs => "gs_base",
            };
            assert!(
                rendered
                    .code
                    .contains(&format!("uint64_t {}(void);\n", binding.provider)),
                "{}",
                rendered.code
            );
            let snapshot = format!("    uint64_t {base} = {}();\n", binding.provider);
            assert_eq!(
                rendered.code.matches(&snapshot).count(),
                1,
                "{}",
                rendered.code
            );
            assert!(
                rendered.code.contains(&format!("*(uint64_t *)({base})")),
                "{}",
                rendered.code
            );
        }
    }
}

#[test]
fn segment_dependencies_only_supply_unbound_x86_inputs() {
    let fs = crate::arch::x86::FS_BASE;
    let gs = crate::arch::x86::GS_BASE;
    for (isa, index) in [(Isa::X86_64, 0), (Isa::AArch64, fs), (Isa::AArch64, gs)] {
        let ir = FunctionIr::single_block(
            isa,
            vec![Stmt::Ret {
                value: Expr::reg(index, 64),
            }],
        );
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert!(rendered.segment_bases.is_empty());
        assert!(!rendered.code.contains("velk_x86_"), "{}", rendered.code);
    }
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::bin(BinOp::Add, Expr::reg(fs, 64), Expr::reg(gs, 64)),
        }],
    );
    ir.params = vec![Param {
        index: fs,
        name: "entry_fs".to_owned(),
        ty: CType::U64,
    }];
    let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
    assert_eq!(
        rendered.segment_bases,
        vec![SegmentBaseRead {
            segment: SegmentBase::Gs,
            provider: "velk_x86_gs_base".to_owned(),
        }]
    );
    assert!(
        rendered.code.contains("uint64_t sub_0(uint64_t entry_fs)"),
        "{}",
        rendered.code
    );
    assert!(
        rendered.code.contains("return entry_fs + gs_base;"),
        "{}",
        rendered.code
    );
    assert!(
        !rendered.code.contains("velk_x86_fs_base"),
        "{}",
        rendered.code
    );
}

#[test]
fn narrow_segment_reads_truncate_the_full_width_snapshot() {
    for (width, ty) in [(8, "uint8_t"), (16, "uint16_t"), (32, "uint32_t")] {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::reg(crate::arch::x86::FS_BASE, width),
            }],
        );
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert_eq!(rendered.segment_bases.len(), 1);
        assert!(
            rendered
                .code
                .contains("uint64_t fs_base = velk_x86_fs_base();"),
            "{}",
            rendered.code
        );
        assert!(
            rendered.code.contains(&format!("return ({ty})fs_base;")),
            "{}",
            rendered.code
        );
    }
}

#[test]
fn segment_dependencies_removed_from_the_body_need_no_provider() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::unsupported("fs_base"),
            Stmt::Ret {
                value: Expr::reg(crate::arch::x86::FS_BASE, 64),
            },
        ],
    );
    ir.ret_type = CType::Void;
    let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
    assert!(
        rendered.code.contains("/* unsupported: fs_base */"),
        "{}",
        rendered.code
    );
    assert!(rendered.segment_bases.is_empty());
    assert!(
        !rendered.code.contains("velk_x86_fs_base"),
        "{}",
        rendered.code
    );
    assert!(
        !rendered.code.contains("uint64_t fs_base"),
        "{}",
        rendered.code
    );
}

#[test]
fn retained_segment_identifiers_exclude_comments_and_literals() {
    let text =
        "/* fs_base π */ \"fs_base \\\"\" 'fs_base' // fs_base\nother_fs_base + fs_base_other";
    assert!(!super::code_mentions(text, "fs_base"));
    assert!(!super::code_mentions(
        "\"fs_base\\\" still inside\"",
        "fs_base"
    ));
    assert!(super::code_mentions(
        &format!("{text}\n(uint32_t)fs_base"),
        "fs_base"
    ));
    assert!(!super::code_mentions("/* fs_base", "fs_base"));
    assert!(!super::code_mentions("\"fs_base", "fs_base"));
    assert!(!super::code_mentions(
        "p-> /* field */ fs_base = q.\nfs_base;",
        "fs_base"
    ));
    assert!(super::code_mentions("p->fs_base = fs_base;", "fs_base"));
}

#[test]
fn a_member_name_does_not_retain_an_unused_segment_snapshot() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: Expr::reg(0, 64),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(crate::arch::x86::FS_BASE, 64),
            },
        ],
    );
    ir.ret_type = CType::Void;
    ir.params = vec![Param {
        index: 0,
        name: "p".to_owned(),
        ty: CType::pointer_to(CType::Named("struct holder".to_owned())),
    }];
    ir.members.push(crate::ir::Member {
        structure: "holder".to_owned(),
        offset: 0,
        name: "fs_base".to_owned(),
        ty: CType::U64,
        width: 8,
    });
    let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
    assert!(
        rendered.code.contains("p->fs_base = 0;"),
        "{}",
        rendered.code
    );
    assert!(rendered.segment_bases.is_empty());
    assert!(
        !rendered.code.contains("velk_x86_fs_base"),
        "{}",
        rendered.code
    );
}

#[test]
fn segment_bindings_keep_real_calls_parameters_and_data_distinct() {
    let call = |target, through| Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(target),
        through,
        convention: crate::ir::Convention::SysV,
        args: Some(Vec::new()),
        floats_named: false,
        outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
        clobbers: None,
        via: None,
    };
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            call(0x40, None),
            call(0x80, Some(load(Expr::Const(0x80), 8))),
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(crate::arch::x86::FS_BASE, 64),
                        Expr::reg(0, 64),
                    ),
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(crate::arch::x86::GS_BASE, 64),
                        load(Expr::Const(0x1000), 8),
                    ),
                ),
            },
        ],
    );
    ir.params = vec![
        Param {
            index: 0,
            name: "fs_base".to_owned(),
            ty: CType::U64,
        },
        Param {
            index: 1,
            name: "velk_x86_fs_base_2".to_owned(),
            ty: CType::U64,
        },
    ];
    let symbols = Symbols {
        functions: HashMap::from([(0x40, "velk_x86_fs_base".to_owned())]),
        import_slots: HashMap::from([(0x80, "velk_x86_gs_base".to_owned())]),
        data: HashMap::from([(0x1000, "fs_base_2".to_owned())]),
        ..Symbols::default()
    };
    let rendered = render_with_dependencies(&ir, &[], &symbols, &[(0x1000, 8)]);
    assert_eq!(
        rendered.segment_bases,
        vec![
            SegmentBaseRead {
                segment: SegmentBase::Fs,
                provider: "velk_x86_fs_base_3".to_owned()
            },
            SegmentBaseRead {
                segment: SegmentBase::Gs,
                provider: "velk_x86_gs_base_2".to_owned()
            },
        ]
    );
    for text in [
        "    velk_x86_fs_base();\n",
        "fs_base = velk_x86_gs_base();",
        "    uint64_t fs_base_3 = velk_x86_fs_base_3();\n",
        "    uint64_t gs_base = velk_x86_gs_base_2();\n",
        "    uint64_t *const fs_base_2 = (uint64_t *)0x1000ULL;\n",
        "fs_base_3 + fs_base",
        "gs_base + *fs_base_2",
    ] {
        assert!(
            rendered.code.contains(text),
            "missing {text:?}: {}",
            rendered.code
        );
    }
    assert_eq!(
        rendered.code.matches("velk_x86_fs_base();").count(),
        1,
        "{}",
        rendered.code
    );
    assert_eq!(
        rendered.code.matches("= velk_x86_gs_base();").count(),
        1,
        "{}",
        rendered.code
    );
    assert!(!rendered.code.contains("call_values"), "{}", rendered.code);
    assert!(
        !rendered.code.contains("fs_base = velk_x86_fs_base();"),
        "{}",
        rendered.code
    );
    for call in &ir.blocks[0].stmts[..2] {
        assert!(
            call.call_outputs()
                .iter()
                .any(|output| output.register == crate::arch::x86::XMM0)
        );
    }
}

#[test]
fn segment_providers_do_not_replace_the_functions_own_name() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::reg(crate::arch::x86::FS_BASE, 64),
        }],
    );
    ir.name = Some("velk_x86_fs_base".to_owned());
    let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
    assert_eq!(
        rendered.segment_bases,
        vec![SegmentBaseRead {
            segment: SegmentBase::Fs,
            provider: "velk_x86_fs_base_2".to_owned(),
        }]
    );
    assert!(
        rendered.code.contains("uint64_t velk_x86_fs_base(void) {"),
        "{}",
        rendered.code
    );
    assert!(
        rendered
            .code
            .contains("uint64_t fs_base = velk_x86_fs_base_2();"),
        "{}",
        rendered.code
    );
}

#[test]
fn a_function_whose_address_is_taken_is_declared_and_read_as_a_number() {
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![Stmt::Ret {
            value: Expr::Const(0x40),
        }],
    );
    ir.ret_type = CType::I64;
    let symbols = Symbols {
        functions: HashMap::from([(0x40, "square".to_owned())]),
        ..Symbols::default()
    };
    let text = render(&ir, &[], &symbols, &[]);
    assert!(text.contains("void square(void);\n"), "{text}");
    assert!(text.contains("    return (uintptr_t)square;\n"), "{text}");
}

#[test]
fn symbol_kinds_keep_names_at_the_same_address() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alt.o");
    let mut image = crate::loader::load(&path).unwrap();
    image.functions.clear();
    for (address, name) in [
        (0x40, "owner::method"),
        (0x80, "owner__method"),
        (0xc0, "owner__method_40"),
        (0x100, "owner__method_40_2"),
    ] {
        image.functions.insert(
            address,
            crate::loader::Function {
                addr: address,
                size: None,
                size_estimated: false,
                name: Some(name.to_owned()),
                aliases: if address == 0x40 {
                    vec!["velk_x86_fs_base()".to_owned()]
                } else {
                    Vec::new()
                },
                sources: Vec::new(),
            },
        );
    }
    image.imports.clear();
    image.imports.insert(0x40, "imported_object".to_owned());
    image.data_symbols.clear();
    image.data_symbols.insert(0x40, "object".to_owned());
    let symbols = callee_names(&image);
    assert_eq!(symbols.functions[&0x40], "owner__method_40_3");
    assert_eq!(symbols.functions[&0x80], "owner__method_80");
    assert_eq!(symbols.functions[&0xc0], "owner__method_40");
    assert_eq!(symbols.functions[&0x100], "owner__method_40_2");
    assert_eq!(symbols.import_slots[&0x40], "imported_object");
    assert_eq!(symbols.data[&0x40], "object");
    for name in [
        "owner::method",
        "owner__method",
        "owner__method_40_3",
        "velk_x86_fs_base()",
        "velk_x86_fs_base__",
        "velk_x86_fs_base",
        "imported_object",
        "object",
    ] {
        assert!(symbols.reserved_names.contains(name), "missing {name}");
    }
    let ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::reg(crate::arch::x86::FS_BASE, 64),
        }],
    );
    let rendered = render_with_dependencies(&ir, &[], &symbols, &[]);
    assert_eq!(
        rendered.segment_bases,
        vec![SegmentBaseRead {
            segment: SegmentBase::Fs,
            provider: "velk_x86_fs_base_2".to_owned(),
        }]
    );
}

#[test]
fn calls_distinguish_functions_from_import_slots() {
    let call = |through| Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x40),
        through,
        convention: crate::ir::Convention::SysV,
        args: Some(Vec::new()),
        floats_named: false,
        outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
        clobbers: None,
        via: None,
    };
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            call(None),
            call(Some(load(Expr::Const(0x40), 8))),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    ir.ret_type = CType::Void;
    let symbols = Symbols {
        functions: HashMap::from([(0x40, "direct_function".to_owned())]),
        import_slots: HashMap::from([(0x40, "imported_function".to_owned())]),
        data: HashMap::from([(0x40, "data_object".to_owned())]),
        ..Symbols::default()
    };
    let text = render(&ir, &[], &symbols, &[]);
    assert!(text.contains("    direct_function();\n"), "{text}");
    assert!(text.contains("    imported_function();\n"), "{text}");
    assert!(!text.contains("data_object"), "{text}");
}

#[test]
fn a_data_address_has_no_function_prototype() {
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![Stmt::Ret {
            value: Expr::Const(0x40),
        }],
    );
    let symbols = Symbols {
        import_slots: HashMap::from([(0x40, "imported_object".to_owned())]),
        data: HashMap::from([(0x40, "data_object".to_owned())]),
        ..Symbols::default()
    };
    let text = render(&ir, &[], &symbols, &[(0x40, 8)]);
    assert!(!text.contains("void imported_object(void);"), "{text}");
    assert!(!text.contains("void data_object(void);"), "{text}");
}

#[test]
fn a_round_data_address_argument_stays_hexadecimal() {
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x40),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: Some(vec![Expr::Const(4_295_030_300), Expr::Const(300)]),
                floats_named: false,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    let text = render(&ir, &[], &Symbols::default(), &[(0x1_0000_f000, 0x1000)]);
    assert!(text.contains("sub_40(0x10000f61c"), "{text}");
    assert!(text.contains(", 300)"), "{text}");
}

#[test]
fn global_views_do_not_shadow_unnamed_functions() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x40),
                through: None,
                convention: crate::ir::Convention::SysV,
                args: Some(Vec::new()),
                floats_named: false,
                outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
                clobbers: None,
                via: None,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    load(Expr::Const(0x1000), 4),
                    load(Expr::Const(0x1004), 4),
                ),
            },
        ],
    );
    ir.addr = 0x80;
    ir.ret_type = CType::U64;
    let symbols = Symbols {
        data: HashMap::from([(0x1000, "sub_40".to_owned()), (0x1004, "sub_80".to_owned())]),
        ..Symbols::default()
    };
    let text = render(&ir, &[], &symbols, &[(0x1000, 8)]);
    assert!(text.contains("uint64_t sub_80(void) {\n"), "{text}");
    assert!(text.contains("    sub_40();\n"), "{text}");
    assert!(text.contains("uint32_t *const sub_40_1000_u32 ="), "{text}");
    assert!(text.contains("uint32_t *const sub_80_1004_u32 ="), "{text}");
}

#[test]
fn physical_call_arguments_keep_zero_extension_without_callee_width_evidence() {
    let masked = |mask| Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(mask));
    let cases = [
        (
            CType::I32,
            masked(0xffff_ffff),
            "sub_1000(a0 & 0xffffffff);",
            0xffff_ffff,
        ),
        (
            CType::I64,
            masked(0xffff_ffff),
            "sub_1000(a0 & 0xffffffff);",
            0xffff_ffff,
        ),
        (
            CType::I32,
            Expr::reg(7, 32),
            "sub_1000((uint32_t)a0);",
            0xffff_ffff,
        ),
        (
            CType::I64,
            Expr::reg(7, 32),
            "sub_1000((uint32_t)a0);",
            0xffff_ffff,
        ),
        (
            CType::U32,
            masked(0xffff_ffff),
            "sub_1000(a0);",
            0xffff_ffff,
        ),
        (CType::U32, masked(0xff), "sub_1000(a0 & 0xff);", 0xff),
        (CType::I32, Expr::reg(7, 64), "sub_1000(a0);", u64::MAX),
    ];
    for (ty, argument, expected, mask) in cases {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::SysV,
                    args: Some(vec![argument]),
                    floats_named: true,
                    outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
                    clobbers: None,
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: ty.clone(),
        }];
        ir.ret_type = CType::U64;
        let text = rendered(&ir);
        assert!(text.contains(expected), "{expected}: {text}");
        for raw in [
            0,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            0x8123_4567_89ab_cdef,
            u64::MAX,
        ] {
            let input = match ty.integer().unwrap() {
                (32, true) => (raw as u32 as i32 as i64) as u64,
                (32, false) => u64::from(raw as u32),
                _ => raw,
            };
            let outcome = crate::ir::eval::run(
                &ir,
                &crate::ir::eval::Setup {
                    seed: 1,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[(7, input)],
                    memory: &[],
                    step_limit: 100,
                },
            );
            assert_eq!(
                outcome,
                crate::ir::eval::Outcome::Return {
                    value: 0,
                    calls: vec![crate::ir::eval::Call {
                        target: Some(0x1000),
                        arguments: vec![input & mask]
                    }],
                    memory: Default::default(),
                }
            );
        }
    }
}

#[test]
fn physical_vector_widths_share_one_integer_storage_name() {
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => crate::arch::aarch64::V0,
            _ => crate::arch::x86::XMM0,
        };
        for width in [16, 32, 64] {
            let ir = FunctionIr::single_block(
                isa,
                vec![
                    assign(low, Expr::Const(0xfedc_ba98_7654_3210)),
                    Stmt::Ret {
                        value: Expr::reg(low, width),
                    },
                ],
            );
            let code = rendered(&ir);
            let name = "v1";
            assert!(code.contains(&format!("uint64_t {name};")), "{code}");
            assert!(code.contains(&format!("{name} = ")), "{code}");
            if isa == Isa::AArch64 {
                assert!(!code.contains("s0"), "{code}");
            }
        }
    }
}

#[test]
fn physical_vector_storage_preserves_upper_zero_and_name_collisions() {
    let low = crate::arch::aarch64::V0;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(low + 1, Expr::Const(u64::MAX)),
            assign(low, Expr::Const(0xbc00)),
            assign(low + 1, Expr::Const(0)),
            Stmt::Ret {
                value: Expr::bin(BinOp::Xor, Expr::reg(low, 64), Expr::reg(low + 1, 64)),
            },
        ],
    );
    ir.params.push(Param {
        index: 0,
        name: "d0".to_owned(),
        ty: CType::U64,
    });
    let code = rendered(&ir);
    assert!(code.contains("uint64_t v1;"), "{code}");
    assert!(code.contains("uint64_t v2;"), "{code}");
    assert!(code.contains("v2 = 0;"), "{code}");
    assert!(!code.contains("s0"), "{code}");
}

#[test]
fn physical_vector_float_operations_use_representation_conversions() {
    let low = crate::arch::aarch64::V0;
    let operation = Expr::Apply {
        op: Operation::FloatAdd(Precision::Single),
        args: vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
    };
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(low, Expr::Const(0x3fc0_0000)),
            assign(low + 2, Expr::Const(0x4010_0000)),
            assign(
                low + 4,
                Expr::bin(BinOp::And, operation, Expr::Const(0xffff_ffff)),
            ),
            Stmt::Ret {
                value: Expr::reg(low + 4, 64),
            },
        ],
    );
    let code = rendered(&ir);
    assert!(
        code.contains("union { uint32_t bits; float value; }"),
        "{code}"
    );
    assert!(
        code.contains("union { float value; uint32_t bits; }"),
        "{code}"
    );
    assert!(!code.contains("float d0"), "{code}");
}

#[test]
fn physical_float_formals_require_their_actual_entry_bits() {
    let low = crate::arch::aarch64::V0;
    for (width, ty) in [(32, "float"), (64, "uint64_t")] {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::reg(low, width),
            }],
        );
        ir.params.push(Param {
            index: low,
            name: "input".to_owned(),
            ty: CType::Named("float".to_owned()),
        });
        let code = rendered(&ir);
        assert!(code.contains(&format!("({ty} input)")), "{code}");
        assert_eq!(ir.params[0].ty, CType::Named("float".to_owned()));
    }
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            Stmt::unsupported("opaque"),
            Stmt::Ret {
                value: Expr::reg(low, 32),
            },
        ],
    );
    ir.params.push(Param {
        index: low,
        name: "input".to_owned(),
        ty: CType::Named("float".to_owned()),
    });
    let code = rendered(&ir);
    assert!(code.contains("(uint64_t input)"), "{code}");
}

#[test]
fn physical_vector_constants_remain_numeric_when_symbols_share_the_bits() {
    let low = crate::arch::aarch64::V0;
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(low, Expr::Const(0x1000)),
            Stmt::Ret {
                value: Expr::reg(low, 64),
            },
        ],
    );
    for function in [false, true] {
        let mut symbols = Symbols::default();
        if function {
            symbols.functions.insert(0x1000, "raw_symbol".to_owned());
        } else {
            symbols.data.insert(0x1000, "raw_symbol".to_owned());
        }
        let code = render(&ir, &[], &symbols, &[]);
        assert!(code.contains("v1 = 0x1000;"), "{code}");
        assert!(!code.contains("raw_symbol"), "{code}");
    }
}

#[test]
fn overwritten_float_formals_use_raw_storage_without_an_entry_capture() {
    let low = crate::arch::aarch64::V0;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(low, Expr::Const(0x1234_5678_3fc0_0000)),
            Stmt::Ret {
                value: Expr::reg(low, 64),
            },
        ],
    );
    ir.params.push(Param {
        index: low,
        name: "input".to_owned(),
        ty: CType::Named("float".to_owned()),
    });
    let code = rendered(&ir);
    assert!(code.contains("(float input)"), "{code}");
    assert!(code.contains("uint64_t v1;"), "{code}");
    assert!(!code.contains(".value = input"), "{code}");
    assert!(code.contains("v1 = 0x123456783fc00000"), "{code}");
    ir.landing_pads.push((0, vec![(0, 4)]));
    let code = rendered(&ir);
    assert!(code.contains("(uint64_t input)"), "{code}");
}

#[test]
fn floating_entry_is_captured_once_before_a_full_width_overwrite() {
    let low = crate::arch::aarch64::V0;
    let saved = crate::ir::VARIABLE_BASE;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: saved,
                    width: 64,
                },
                value: Expr::reg(low, 32),
            },
            assign(low, Expr::Const(0x1234_5678_3fc0_0000)),
            Stmt::Ret {
                value: Expr::bin(BinOp::Xor, Expr::reg(low, 64), Expr::reg(saved, 32)),
            },
        ],
    );
    ir.params.push(Param {
        index: low,
        name: "input".to_owned(),
        ty: CType::Named("const float".to_owned()),
    });
    let code = rendered(&ir);
    assert!(code.contains("(const float input)"), "{code}");
    assert_eq!(code.matches(".value = input").count(), 1, "{code}");
    assert!(code.contains("uint64_t v2 ="), "{code}");
    assert!(code.contains("v2 = 0x123456783fc00000"), "{code}");
    assert!(!code.contains("float v2"), "{code}");
}

#[test]
fn readonly_floating_formals_use_their_original_operand_names() {
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = if isa == Isa::AArch64 {
            crate::arch::aarch64::V0
        } else {
            crate::arch::x86::XMM0
        };
        for (precision, ty) in [(Precision::Single, "float"), (Precision::Double, "double")] {
            let mut ir = FunctionIr::single_block(
                isa,
                vec![Stmt::Ret {
                    value: Expr::apply(
                        Operation::FloatAdd(precision),
                        vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
                    ),
                }],
            );
            ir.params = [(low, "a"), (low + 2, "b")]
                .into_iter()
                .map(|(index, name)| Param {
                    index,
                    name: name.to_owned(),
                    ty: CType::Named(ty.to_owned()),
                })
                .collect();
            ir.ret_type = CType::Named(ty.to_owned());
            let before = format!("{ir:?}");
            let code = rendered(&ir);
            assert!(code.contains("return a + b;"), "{code}");
            assert!(!code.contains("uint64_t"), "{code}");
            assert!(!code.contains("union"), "{code}");
            assert_eq!(format!("{ir:?}"), before);
        }
    }
}

#[test]
fn readonly_floating_views_keep_a_capture_for_raw_integer_reads() {
    let low = crate::arch::aarch64::V0;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::Xor,
                Expr::apply(
                    Operation::FloatAdd(Precision::Single),
                    vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
                ),
                Expr::reg(low, 32),
            ),
        }],
    );
    ir.params = [(low, "a"), (low + 2, "b")]
        .into_iter()
        .map(|(index, name)| Param {
            index,
            name: name.to_owned(),
            ty: CType::Named("float".to_owned()),
        })
        .collect();
    ir.ret_type = CType::U64;
    let code = rendered(&ir);
    assert!(code.contains(".value = a + b"), "{code}");
    assert!(code.contains("uint64_t v1 ="), "{code}");
    assert_eq!(code.matches("{ .value = a }").count(), 1, "{code}");
    assert!(!code.contains("uint64_t d1"), "{code}");
}

#[test]
fn readonly_floating_views_reject_written_and_call_clobbered_formals() {
    let low = crate::arch::aarch64::V0;
    for clobber in [false, true] {
        let mut stmts = vec![Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE,
                width: 64,
            },
            value: Expr::apply(
                Operation::FloatAdd(Precision::Double),
                vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
            ),
        }];
        if clobber {
            stmts.push(Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: Some(Vec::new()),
                floats_named: true,
                outputs: Vec::new(),
                clobbers: Some([low].into_iter().collect()),
                via: None,
            });
        } else {
            stmts.push(assign(low, Expr::Const(0x401e_0000_0000_0000)));
        }
        stmts.push(Stmt::Ret {
            value: Expr::reg(VARIABLE_BASE, 64),
        });
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.params = [(low, "a"), (low + 2, "b")]
            .into_iter()
            .map(|(index, name)| Param {
                index,
                name: name.to_owned(),
                ty: CType::Named("double".to_owned()),
            })
            .collect();
        ir.ret_type = CType::Named("double".to_owned());
        let before = format!("{ir:?}");
        let code = rendered(&ir);
        assert!(code.contains("uint64_t v2 ="), "{code}");
        assert!(!code.contains(".value = a + b"), "{code}");
        assert!(!code.contains("v1 = a + b"), "{code}");
        assert_eq!(format!("{ir:?}"), before);
    }
}

#[test]
fn readonly_floating_views_reject_mismatched_or_volatile_formals() {
    let low = crate::arch::aarch64::V0;
    for ty in ["double", "volatile float", "_Atomic float"] {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::apply(
                    Operation::FloatAdd(Precision::Single),
                    vec![Expr::reg(low, 32), Expr::Const(0x4000_0000)],
                ),
            }],
        );
        ir.params.push(Param {
            index: low,
            name: "a".to_owned(),
            ty: CType::Named(ty.to_owned()),
        });
        ir.ret_type = CType::Named("float".to_owned());
        let code = rendered(&ir);
        assert!(code.contains("uint64_t v1 ="), "{code}");
        assert!(!code.contains("return a +"), "{code}");
        assert!(code.contains("uint32_t bits; float value"), "{code}");
    }
}

#[test]
fn go_return_address_and_argument_frame_have_explicit_meanings() {
    let sp = crate::arch::stack_pointer(Isa::X86_64);
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: load(Expr::reg(sp, 64), 8),
        }],
    );
    ir.convention = crate::ir::Convention::GoAmd64;
    let code = rendered(&ir);
    assert!(
        code.contains("return *velk_return_address_slot();"),
        "{code}"
    );
    assert!(!code.contains("rsp"), "{code}");
    ir.blocks[0].stmts = vec![Stmt::Ret {
        value: Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(8)),
    }];
    let code = rendered(&ir);
    assert!(code.contains("velk_return_address_slot() + 1"), "{code}");
    assert!(!code.contains("rsp"), "{code}");
    ir.blocks[0].stmts.insert(
        0,
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: sp,
                width: 64,
            },
            value: Expr::reg(0, 64),
        },
    );
    let code = rendered(&ir);
    assert!(code.contains("rsp"), "{code}");
    assert!(!code.contains("velk_return_address_slot"), "{code}");
}

#[test]
fn debug_stack_names_take_precedence_over_roles() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/metrics/arith_mixed.x86_64.O0.debug.elf");
    let mut binary = crate::service::Binary::open(&path).expect("debug fixture");
    let address = binary
        .image()
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some("sum_arr"))
        .expect("array sum")
        .addr;
    let text = binary.decompile(address, None, None).expect("decompile");
    assert!(text.contains("uint32_t total;"), "{text}");
    assert!(text.contains("int32_t i;"), "{text}");
    assert!(text.contains("for (i = 0; i < n; i++)"), "{text}");
}
