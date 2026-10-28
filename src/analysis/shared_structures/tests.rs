use super::share;
use crate::ir::{
    BinOp, CType, CallKind, CallOutput, Convention, Expr, FunctionIr, Param, RegRef, Stmt,
    VARIABLE_BASE,
};
use crate::loader::Isa;

fn put(register: u16, offset: u64, width: u8) -> Stmt {
    Stmt::Store {
        addr: Expr::bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(offset)),
        value: Expr::Const(offset + 1),
        width,
    }
}

fn function(addr: u64, fields: &[(u64, u8)]) -> FunctionIr {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        fields
            .iter()
            .map(|(offset, width)| put(7, *offset, *width))
            .collect(),
    );
    ir.addr = addr;
    ir.name = Some(format!("f{addr}"));
    ir.ret_type = CType::Void;
    ir.params.push(Param {
        index: 7,
        name: "a0".into(),
        ty: CType::pointer_to(CType::U32),
    });
    super::super::structures::recover(&mut ir);
    ir
}

fn call(target: u64, arg: Expr) -> Stmt {
    Stmt::Call {
        abi: None,
        kind: CallKind::Invoke,
        target: Some(target),
        through: None,
        convention: Convention::SysV,
        args: Some(vec![arg]),
        floats_named: true,
        outputs: Vec::new(),
        clobbers: None,
        via: None,
    }
}

fn render(ir: &FunctionIr) -> String {
    crate::render::render(ir, &[], &Default::default(), &[])
}

#[test]
fn direct_recursive_calls_union_partial_fields_and_keep_padding() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut middle = function(2, &[(16, 8)]);
    let mut last = function(3, &[(24, 4), (32, 8)]);
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    middle.blocks[0].stmts.push(call(3, Expr::reg(7, 64)));
    last.blocks[0].stmts.push(call(1, Expr::reg(7, 64)));
    share(&mut [&mut last, &mut middle, &mut first], &[]);
    for ir in [&first, &middle, &last] {
        let code = render(ir);
        assert!(
            code.contains(&format!("struct {} *a0", ir.structures[0].name)),
            "{code}"
        );
        assert_eq!(
            code.matches(&format!("struct {} {{", ir.structures[0].name))
                .count(),
            1,
            "{code}"
        );
        assert!(code.contains("gap_0xc[0x4]"), "{code}");
        assert!(code.contains("int64_t f_20;"), "{code}");
    }
    assert_eq!(first.structures[0].fields.len(), 5);
}

#[test]
fn conflicting_widths_overlaps_and_array_strides_stay_separate() {
    for (fields, size) in [
        (vec![(0, 8), (16, 4)], None),
        (vec![(2, 2), (16, 4)], None),
        (vec![(0, 4), (16, 4)], Some(24)),
    ] {
        let mut first = function(1, &[(0, 4), (8, 4)]);
        let mut second = function(2, &fields);
        second.structures[0].size = size;
        first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
        let before = (render(&first), render(&second));
        share(&mut [&mut first, &mut second], &[]);
        assert_eq!((render(&first), render(&second)), before);
    }
}

#[test]
fn a_conflicting_single_field_prevents_the_whole_merge() {
    let mut first = function(1, &[(0, 8), (8, 4)]);
    let mut second = function(2, &[(4, 4)]);
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    let before = render(&first);
    share(&mut [&mut first, &mut second], &[]);
    assert_eq!(render(&first), before);
    assert!(second.structures.is_empty());
}

#[test]
fn unknown_indirect_calls_and_offset_arguments_do_not_connect_types() {
    for indirect in [true, false] {
        let mut first = function(1, &[(0, 4), (8, 4)]);
        let mut second = function(2, &[(16, 8), (24, 4)]);
        let mut stmt = call(
            2,
            if indirect {
                Expr::reg(7, 64)
            } else {
                Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8))
            },
        );
        if let Stmt::Call {
            target, through, ..
        } = &mut stmt
            && indirect
        {
            *target = None;
            *through = Some(Expr::reg(3, 64));
        }
        first.blocks[0].stmts.push(stmt);
        share(&mut [&mut first, &mut second], &[]);
        assert_ne!(first.params[0].ty, second.params[0].ty);
        assert_eq!(first.structures[0].fields.len(), 2);
    }
}

#[test]
fn returned_pointers_and_same_global_connect_types() {
    for global in [true, false] {
        let mut first = function(1, &[(0, 4), (8, 4)]);
        let mut second = function(2, &[]);
        let variable = VARIABLE_BASE;
        second.blocks[0]
            .stmts
            .extend([put(variable, 16, 8), put(variable, 24, 4)]);
        if global {
            first.blocks[0].stmts.push(Stmt::Store {
                addr: Expr::Const(0x1000),
                value: Expr::reg(7, 64),
                width: 8,
            });
            second.blocks[0].stmts.insert(
                0,
                Stmt::Assign {
                    dest: RegRef {
                        index: variable,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(0x1000)),
                        width: 8,
                        signed: false,
                    },
                },
            );
        } else {
            first.ret_type = first.params[0].ty.clone();
            first.blocks[0].stmts.push(Stmt::Ret {
                value: Expr::reg(7, 64),
            });
            let mut stmt = call(1, Expr::reg(7, 64));
            if let Stmt::Call { outputs, .. } = &mut stmt {
                outputs.push(CallOutput {
                    register: 0,
                    dest: RegRef {
                        index: variable,
                        width: 64,
                    },
                });
            }
            second.blocks[0].stmts.insert(0, stmt);
        }
        super::super::structures::recover(&mut second);
        share(&mut [&mut first, &mut second], &[(0x1000, 8)]);
        assert_eq!(first.structures[0].name, second.structures[0].name);
        let code = render(&second);
        assert!(code.contains("int64_t f_10;"), "{code}");
        assert!(code.contains("int32_t f_0;"), "{code}");
    }
}

#[test]
fn same_static_address_connects_but_null_does_not() {
    for address in [0, 0x1000] {
        let mut first = function(1, &[(0, 4), (8, 4)]);
        let mut second = function(2, &[(16, 8), (24, 4)]);
        let mut caller = function(3, &[]);
        caller.blocks[0]
            .stmts
            .extend([call(1, Expr::Const(address)), call(2, Expr::Const(address))]);
        share(&mut [&mut first, &mut second, &mut caller], &[(0x1000, 32)]);
        assert_eq!(first.params[0].ty == second.params[0].ty, address != 0);
    }
}

#[test]
fn shared_printed_layout_compiles_and_preserves_byte_offsets() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    // The flow is checked separately from the executable bodies.
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    first.blocks[0].stmts.pop();
    let mut source =
        String::from("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n");
    source.push_str(&crate::render::combine(&format!(
        "{}{}",
        render(&first),
        render(&second)
    )));
    assert_eq!(
        source
            .matches(&format!("struct {} {{", first.structures[0].name))
            .count(),
        1
    );
    let mut independent = function(3, &[(0, 8), (8, 8)]);
    share(&mut [&mut independent], &[]);
    assert_eq!(first.structures[0].name, independent.structures[0].name);
    source = crate::render::combine(&format!("{source}{}", render(&independent)));
    source.push_str("\n_Static_assert(offsetof(struct S1_7, f_10) == 16, \"offset\");\nint main(void) {\nstruct S1_7 value; memset(&value, 0xa5, sizeof(value)); f1(&value); f2(&value);\nuint8_t expected[sizeof(value)]; memset(expected, 0xa5, sizeof(expected));\nuint32_t a=1, b=9, d=25; uint64_t c=17;\nmemcpy(expected, &a, 4); memcpy(expected+8, &b, 4); memcpy(expected+16, &c, 8); memcpy(expected+24, &d, 4);\nreturn memcmp(&value, expected, sizeof(value)) != 0; }\n");
    let source = source.replace(
        "struct S1_7",
        &format!("struct {}", first.structures[0].name),
    );
    compile_and_run(&source, &["-std=c11", "-Werror"], "velk-shared-structures");
}

#[test]
fn pointer_tail_returns_reach_the_callers_layout() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    first.ret_type = first.params[0].ty.clone();
    first.blocks[0].stmts.push(Stmt::Ret {
        value: Expr::reg(7, 64),
    });
    let mut wrapper = function(2, &[]);
    wrapper.ret_type = CType::pointer_to(CType::Void);
    let mut tail = call(1, Expr::reg(7, 64));
    if let Stmt::Call { kind, .. } = &mut tail {
        *kind = CallKind::Tail;
    }
    wrapper.blocks[0].stmts.push(tail);
    let mut caller = function(3, &[]);
    let variable = VARIABLE_BASE;
    let mut invoke = call(2, Expr::reg(7, 64));
    if let Stmt::Call { outputs, .. } = &mut invoke {
        outputs.push(CallOutput {
            register: 0,
            dest: RegRef {
                index: variable,
                width: 64,
            },
        });
    }
    caller.blocks[0]
        .stmts
        .extend([invoke, put(variable, 16, 8), put(variable, 24, 4)]);
    super::super::structures::recover(&mut caller);
    share(&mut [&mut first, &mut wrapper, &mut caller], &[]);
    assert_eq!(first.structures[0].name, caller.structures[0].name);
    assert_eq!(wrapper.ret_type, first.ret_type);
    assert!(render(&wrapper).contains(&format!("struct {} *f2", wrapper.structures[0].name)));
}

#[test]
fn redefined_parameters_do_not_connect_other_functions() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    first.blocks[0].stmts.extend([
        Stmt::Assign {
            dest: RegRef {
                index: 7,
                width: 64,
            },
            value: Expr::Const(0),
        },
        call(2, Expr::reg(7, 64)),
    ]);
    share(&mut [&mut first, &mut second], &[]);
    assert_ne!(first.params[0].ty, second.params[0].ty);
}

#[test]
fn connected_methods_use_one_generated_layout() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    first.name = Some("Square::reset()".into());
    second.name = Some("Square::update()".into());
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    for ir in [&first, &second] {
        let code = render(ir);
        assert_eq!(
            code.matches(&format!("struct {} {{", ir.structures[0].name))
                .count(),
            1,
            "{code}"
        );
        assert!(
            code.contains(&format!("struct {} *a0", ir.structures[0].name)),
            "{code}"
        );
    }
}

#[test]
fn two_single_field_functions_recover_their_combined_structure() {
    let mut first = function(1, &[(0, 4)]);
    let mut second = function(2, &[(8, 8)]);
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    for ir in [&first, &second] {
        let code = render(ir);
        assert!(
            code.contains(&format!("struct {} *a0", ir.structures[0].name)),
            "{code}"
        );
        assert!(code.contains("int32_t f_0;"), "{code}");
        assert!(code.contains("int64_t f_8;"), "{code}");
    }
}

#[test]
fn repeated_computed_pointer_arguments_share_the_pointed_to_type() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    let mut caller = function(3, &[]);
    let address = Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(16));
    caller.blocks[0]
        .stmts
        .extend([call(1, address.clone()), call(2, address)]);
    share(&mut [&mut first, &mut second, &mut caller], &[]);
    assert_eq!(first.params[0].ty, second.params[0].ty);
    assert_eq!(first.structures[0].fields.len(), 4);
    // The original pointer can still denote a different layout.
    assert_eq!(caller.params[0].ty, CType::pointer_to(CType::U32));
}

#[test]
fn invalid_class_identifiers_use_generated_names() {
    for name in ["::reset()", "struct::reset()", "1bad::reset()"] {
        let mut ir = function(1, &[(0, 4), (8, 4)]);
        ir.name = Some(name.into());
        share(&mut [&mut ir], &[]);
        assert!(render(&ir).contains(&format!("struct {} *a0", ir.structures[0].name)));
    }
}

#[test]
fn declared_named_pointer_targets_are_preserved() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    second.params[0].ty = CType::pointer_to(CType::Named("union choice".into()));
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    let before = (render(&first), render(&second));
    share(&mut [&mut first, &mut second], &[]);
    assert_eq!((render(&first), render(&second)), before);
}

#[test]
fn an_unshared_scalar_pointer_keeps_its_type() {
    let mut ir = function(1, &[]);
    ir.blocks[0].stmts.extend([
        put(7, 0, 4),
        put(7, 8, 4),
        Stmt::Ret {
            value: Expr::reg(7, 64),
        },
    ]);
    ir.ret_type = ir.params[0].ty.clone();
    let before = render(&ir);
    share(&mut [&mut ir], &[]);
    assert_eq!(render(&ir), before);
}

fn indexed_function(addr: u64, fields: &[(u64, u8)], scale: u64) -> FunctionIr {
    let mut ir = function(addr, &[]);
    ir.params.push(Param {
        index: 6,
        name: "i".into(),
        ty: CType::I64,
    });
    for (offset, width) in fields {
        let mut stmt = put(7, *offset, *width);
        if let Stmt::Store { addr, .. } = &mut stmt {
            *addr = Expr::bin(
                BinOp::Add,
                addr.clone(),
                Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(scale)),
            );
        }
        ir.blocks[0].stmts.push(stmt);
    }
    super::super::structures::recover(&mut ir);
    ir
}

#[test]
fn a_single_indexed_field_uses_the_connected_functions_stride() {
    let mut first = indexed_function(1, &[(0, 4), (8, 4)], 16);
    let mut second = indexed_function(2, &[(12, 4)], 16);
    assert!(second.structures.is_empty());
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    assert_eq!(first.params[0].ty, second.params[0].ty);
    assert_eq!(second.structures[0].size, Some(16));
    assert_eq!(second.structures[0].fields.len(), 3);
    let code = render(&second);
    assert!(code.contains("a0[i].f_c = 13;"), "{code}");
}

#[test]
fn partial_indexed_accesses_refuse_conflicting_scales_widths_and_alignment() {
    for (scale, offset, width) in [(12, 12, 4), (16, 0, 8), (16, 2, 4), (16, 14, 4)] {
        let mut first = indexed_function(1, &[(0, 4), (8, 4)], 16);
        let mut second = indexed_function(2, &[(offset, width)], scale);
        first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
        let before = (render(&first), render(&second));
        share(&mut [&mut first, &mut second], &[]);
        assert_eq!((render(&first), render(&second)), before);
    }
}

#[test]
fn shared_array_fields_compile_and_match_byte_stores_on_many_elements() {
    let mut first = indexed_function(1, &[(0, 4), (8, 4)], 16);
    let mut second = indexed_function(2, &[(12, 4)], 16);
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    first.blocks[0].stmts.pop();
    let mut source =
        String::from("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n");
    source.push_str(&crate::render::combine(&format!(
        "{}{}",
        render(&first),
        render(&second)
    )));
    assert_eq!(
        source
            .matches(&format!("struct {} {{", first.structures[0].name))
            .count(),
        1
    );
    source.push_str("\n_Static_assert(sizeof(struct S1_7) == 16, \"stride\");\n_Static_assert(offsetof(struct S1_7, f_c) == 12, \"offset\");\nint main(void) {\nstruct S1_7 values[257]; uint8_t expected[sizeof(values)];\nfor (unsigned seed=0; seed<256; seed++) {\nmemset(values, seed, sizeof(values)); memset(expected, seed, sizeof(expected));\nfor (int i=256; i>=0; i--) {\nf1(values, i); f2(values, i);\nuint32_t a=1,b=9,c=13; memcpy(expected+i*16,&a,4); memcpy(expected+i*16+8,&b,4); memcpy(expected+i*16+12,&c,4);\nif (memcmp(values, expected, sizeof(values))) return 1;\n}} return 0; }\n");
    let source = source.replace(
        "struct S1_7",
        &format!("struct {}", first.structures[0].name),
    );
    compile_and_run(
        &source,
        &["-std=c11", "-O2", "-Werror"],
        "velk-shared-arrays",
    );
}

#[test]
fn two_single_indexed_fields_establish_a_shared_array() {
    for scale in [8, 16, 24, 32, 65536] {
        let mut first = indexed_function(1, &[(0, 4)], scale);
        let mut second = indexed_function(2, &[(4, 4)], scale);
        first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
        assert!(first.structures.is_empty() && second.structures.is_empty());
        share(&mut [&mut first, &mut second], &[]);
        assert_eq!(first.params[0].ty, second.params[0].ty);
        assert_eq!(first.structures[0].size, Some(scale));
        assert!(render(&second).contains("a0[i].f_4"));
    }
}

#[test]
fn smt_shared_array_scales_preserve_addresses() {
    use crate::ir::smt::{Proofs, raw_bin};

    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for size in [8, 16, 24, 32, 65536] {
        for factor in [1, 2, 3, 17] {
            let mut first = indexed_function(1, &[(0, 4), (4, 4)], size);
            let mut second = indexed_function(2, &[(size - 4, 4)], size * factor);
            first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
            share(&mut [&mut first, &mut second], &[]);
            let layout = &second.structures[0];
            assert_eq!(layout.size, Some(size));
            let (offset, _) = layout.fields.last().unwrap();
            let original = raw_bin(
                BinOp::Add,
                Expr::reg(7, 64),
                raw_bin(
                    BinOp::Add,
                    raw_bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(size * factor)),
                    Expr::Const(size - 4),
                ),
            );
            let recovered = raw_bin(
                BinOp::Add,
                Expr::reg(7, 64),
                raw_bin(
                    BinOp::Add,
                    raw_bin(
                        BinOp::Mul,
                        raw_bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(factor)),
                        Expr::Const(layout.size.unwrap()),
                    ),
                    Expr::Const(*offset),
                ),
            );
            proofs.expression(
                format!("shared array size {size} factor {factor}"),
                &original,
                &recovered,
                64,
            );
        }
    }
    proofs.check();
}

#[test]
fn partial_array_layouts_follow_x86_64_and_aarch64_argument_registers() {
    use std::collections::HashMap;

    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::X86_64, Convention::Win64),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        let mut first = indexed_function(1, &[(0, 4), (8, 4)], 16);
        let mut second = indexed_function(2, &[(12, 4)], 16);
        first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
        let renamed = HashMap::from([
            (7, convention.arguments()[0]),
            (6, convention.arguments()[1]),
        ]);
        for ir in [&mut first, &mut second] {
            ir.isa = isa;
            for param in &mut ir.params {
                param.index = renamed[&param.index];
            }
            for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                for value in stmt.operands_mut() {
                    crate::ir::visit::rename_registers(value, &renamed);
                }
                if let Stmt::Call {
                    convention: current,
                    ..
                } = stmt
                {
                    *current = convention;
                }
            }
        }
        let before = format!("{:?}", second.blocks);
        share(&mut [&mut first, &mut second], &[]);
        assert_eq!(first.params[0].ty, second.params[0].ty);
        assert!(render(&second).contains("a0[i].f_c"));
        assert_eq!(format!("{:?}", second.blocks), before);
    }
}

#[test]
fn equal_layouts_share_one_declaration_within_a_function() {
    let mut ir = function(1, &[(0, 4), (8, 4)]);
    ir.params.push(Param {
        index: 6,
        name: "a1".into(),
        ty: CType::pointer_to(CType::U32),
    });
    ir.blocks[0].stmts.extend([put(6, 0, 4), put(6, 8, 4)]);
    super::super::structures::recover(&mut ir);
    share(&mut [&mut ir], &[]);
    let code = render(&ir);
    assert_eq!(ir.structures.len(), 1, "{code}");
    assert_eq!(
        code.matches(&format!("struct {} {{", ir.structures[0].name))
            .count(),
        1,
        "{code}"
    );
    assert!(code.contains("a0->f_8 = 9;"), "{code}");
    assert!(code.contains("a1->f_8 = 9;"), "{code}");
}

#[test]
fn adding_fields_keeps_the_tag_and_combined_declarations_are_distinct() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut middle = function(2, &[(16, 4)]);
    let mut last = function(3, &[(24, 4)]);
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    middle.blocks[0].stmts.push(call(3, Expr::reg(7, 64)));
    let mut partial = first.clone();
    let mut adjacent = middle.clone();
    share(&mut [&mut partial, &mut adjacent], &[]);
    share(&mut [&mut first, &mut middle, &mut last], &[]);
    assert_eq!(partial.structures[0].name, "S1");
    assert_eq!(partial.structures[0].name, first.structures[0].name);
    assert_eq!(first.structures[0].name, last.structures[0].name);
    let code = crate::render::combine(&format!("{}{}", render(&partial), render(&last)));
    assert!(
        code.contains(&format!("struct {} {{", partial.structures[0].name)),
        "{code}"
    );
    assert!(code.contains("struct S2 {"), "{code}");
    assert!(code.contains("f3(struct S2 *a0)"), "{code}");
}

#[test]
fn numbering_follows_addresses_and_skips_declared_tags() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(0, 8), (8, 8)]);
    let mut reversed_first = first.clone();
    let mut reversed_second = second.clone();
    share(&mut [&mut first, &mut second], &[]);
    share(&mut [&mut reversed_second, &mut reversed_first], &[]);
    assert_eq!(first.structures[0].name, "S1");
    assert_eq!(second.structures[0].name, "S2");
    assert_eq!(render(&first), render(&reversed_first));
    assert_eq!(render(&second), render(&reversed_second));
    for name in ["struct S1", "union S1"] {
        let mut declared = function(3, &[(0, 4), (8, 4)]);
        declared.definitions.push(crate::ir::Definition {
            name: name.into(),
            members: vec!["int value;".into()],
            fields: vec!["value".into()],
            contains: Vec::new(),
            size: 4,
            alignment: None,
            compatible_profiles: Vec::new(),
        });
        share(&mut [&mut declared], &[]);
        assert_eq!(declared.structures[0].name, "S2");
    }
}

fn compile_and_run(source: &str, options: &[&str], name: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let executable = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let mut child = Command::new("cc")
        .args(options)
        .args(["-x", "c", "-", "-o"])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("C compiler");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = Command::new(&executable)
        .status()
        .expect("compiled program");
    std::fs::remove_file(executable).unwrap();
    assert!(status.success(), "{source}");
}

#[test]
fn repeated_field_loads_merge_only_observed_compatible_fields() {
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::X86_64, Convention::Win64),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        for conflicting in [false, true] {
            let base = convention.arguments()[0];
            let first = VARIABLE_BASE;
            let second = VARIABLE_BASE + 1;
            let mut ir = function(1, &[]);
            ir.isa = isa;
            ir.params[0].index = base;
            for (register, offset, width) in
                [(first, 0, 8), (second, if conflicting { 4 } else { 16 }, 4)]
            {
                ir.blocks[0].stmts.push(Stmt::Assign {
                    dest: RegRef {
                        index: register,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(8))),
                        width: 8,
                        signed: false,
                    },
                });
                ir.blocks[0].stmts.push(put(register, offset, width));
                ir.pointer_values.push(register);
            }
            let before = format!("{:?}", ir.blocks);
            share(&mut [&mut ir], &[]);
            let code = render(&ir);
            assert_eq!(format!("{:?}", ir.blocks), before);
            if conflicting {
                assert!(ir.structures.is_empty(), "{code}");
            } else {
                assert_eq!(
                    ir.structures[0].fields,
                    vec![(0, CType::U64), (16, CType::U32)]
                );
                assert!(code.contains("->f_0 = 1;"), "{code}");
                assert!(code.contains("->f_10 = 17;"), "{code}");
                assert!(!code.contains("f_8;"), "{code}");
            }
        }
    }
}

#[test]
fn changing_field_bases_and_narrow_loads_do_not_connect_layouts() {
    for narrow in [false, true] {
        let mut ir = function(1, &[]);
        for (register, offset) in [(VARIABLE_BASE, 0), (VARIABLE_BASE + 1, 16)] {
            ir.blocks[0].stmts.push(Stmt::Assign {
                dest: RegRef {
                    index: register,
                    width: 64,
                },
                value: Expr::Load {
                    addr: Box::new(Expr::reg(7, 64)),
                    width: if narrow { 4 } else { 8 },
                    signed: false,
                },
            });
            ir.blocks[0].stmts.push(put(register, offset, 4));
            ir.pointer_values.push(register);
        }
        if !narrow {
            ir.blocks[0].stmts.push(Stmt::Assign {
                dest: RegRef {
                    index: 7,
                    width: 32,
                },
                value: Expr::Const(0),
            });
        }
        let before = render(&ir);
        share(&mut [&mut ir], &[]);
        assert_eq!(render(&ir), before);
    }
}

#[test]
fn shared_loaded_pointer_fields_compile_and_preserve_memory() {
    for isa in [Isa::X86_64, Isa::AArch64] {
        let mut ir = function(1, &[]);
        ir.isa = isa;
        for (register, offset, width) in [(VARIABLE_BASE, 0, 8), (VARIABLE_BASE + 1, 16, 4)] {
            ir.blocks[0].stmts.push(Stmt::Assign {
                dest: RegRef {
                    index: register,
                    width: 64,
                },
                value: Expr::Load {
                    addr: Box::new(Expr::reg(7, 64)),
                    width: 8,
                    signed: false,
                },
            });
            ir.blocks[0].stmts.push(put(register, offset, width));
            ir.pointer_values.push(register);
        }
        share(&mut [&mut ir], &[]);
        let mut source = String::from("#include <stdint.h>\n#include <string.h>\n");
        source.push_str(&render(&ir));
        source.push_str("\nint main(void) {\n_Alignas(8) unsigned char actual[32], expected[32];\nuintptr_t pointer = (uintptr_t)actual;\nfor (unsigned seed=0; seed<256; seed++) {\nmemset(actual, seed, sizeof(actual)); memset(expected, seed, sizeof(expected));\nf1((void *)&pointer);\nuint64_t a=1; uint32_t b=17; memcpy(expected,&a,8); memcpy(expected+16,&b,4);\nif (memcmp(actual,expected,sizeof(actual))) return 1;\n} return 0; }\n");
        compile_and_run(
            &source,
            &["-std=c11", "-O2", "-Werror"],
            "velk-loaded-fields",
        );
    }
}

#[test]
fn a_stored_pointer_carries_its_layout_to_a_field_load() {
    let mut ir = function(1, &[(0, 4), (8, 4)]);
    ir.params.push(Param {
        index: 6,
        name: "a1".into(),
        ty: CType::pointer_to(CType::U64),
    });
    ir.blocks[0].stmts.extend([
        Stmt::Store {
            addr: Expr::reg(6, 64),
            value: Expr::reg(7, 64),
            width: 8,
        },
        Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE,
                width: 64,
            },
            value: Expr::Load {
                addr: Box::new(Expr::reg(6, 64)),
                width: 8,
                signed: false,
            },
        },
        put(VARIABLE_BASE, 16, 8),
    ]);
    ir.pointer_values.push(VARIABLE_BASE);
    share(&mut [&mut ir], &[]);
    let code = render(&ir);
    assert_eq!(ir.structures[0].fields.len(), 3, "{code}");
    assert_eq!(ir.value_types[&VARIABLE_BASE], ir.params[0].ty);
    assert!(code.contains("->f_10 = 17;"), "{code}");
    let source = format!(
        "#include <stdint.h>\n#include <string.h>\n{code}\nint main(void) {{\n_Alignas(8) unsigned char actual[32], expected[32];\nuintptr_t pointer = 0;\nfor (unsigned seed=0; seed<256; seed++) {{\nmemset(actual,seed,sizeof(actual)); memset(expected,seed,sizeof(expected));\nf1((void *)actual,(void *)&pointer);\nuint32_t a=1,b=9; uint64_t c=17; memcpy(expected,&a,4); memcpy(expected+8,&b,4); memcpy(expected+16,&c,8);\nif (pointer != (uintptr_t)actual || memcmp(actual,expected,sizeof(actual))) return 1;\n}} return 0; }}\n"
    );
    compile_and_run(
        &source,
        &["-std=c11", "-O2", "-Werror"],
        "velk-stored-fields",
    );
}

#[test]
fn field_loads_through_a_whole_pointer_copy_share_their_layout() {
    let mut ir = function(1, &[]);
    let copy = VARIABLE_BASE;
    ir.blocks[0].stmts.push(Stmt::Assign {
        dest: RegRef {
            index: copy,
            width: 64,
        },
        value: Expr::reg(7, 64),
    });
    for (register, base, offset) in [(copy + 1, 7, 0), (copy + 2, copy, 16)] {
        ir.blocks[0].stmts.push(Stmt::Assign {
            dest: RegRef {
                index: register,
                width: 64,
            },
            value: Expr::Load {
                addr: Box::new(Expr::reg(base, 64)),
                width: 8,
                signed: false,
            },
        });
        ir.blocks[0].stmts.push(put(register, offset, 4));
        ir.pointer_values.push(register);
    }
    share(&mut [&mut ir], &[]);
    let code = render(&ir);
    assert_eq!(
        ir.structures[0].fields,
        vec![(0, CType::U32), (16, CType::U32)],
        "{code}"
    );
    assert!(code.contains("->f_10 = 17;"), "{code}");
}

#[test]
fn distinct_recovered_layouts_with_the_same_tag_compile_together() {
    for tag in ["parse_s1", "parse_a0", "Socket_s1"] {
        let first = format!(
            "/* velk prelude */\nstruct {tag} {{ uint32_t f_0; }};\n/* end velk prelude */\nuint32_t first(void) {{ struct {tag} value = {{7}}; return value.f_0; }}\n"
        );
        let second = format!(
            "/* velk prelude */\nstruct {tag} {{ uint64_t f_8; }};\n/* end velk prelude */\nuint64_t second(void) {{ struct {tag} value = {{11}}; return value.f_8; }}\n"
        );
        let code = crate::render::combine(&format!("{first}{second}"));
        assert_eq!(
            code.matches(&format!("struct {tag} {{")).count(),
            1,
            "{code}"
        );
        let source = format!(
            "#include <stdint.h>\n{code}\nint main(void) {{ return first() != 7 || second() != 11; }}\n"
        );
        compile_and_run(
            &source,
            &["-std=c11", "-O2", "-Werror"],
            "velk-structure-tags",
        );
    }
}
