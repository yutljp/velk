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
        assert!(code.contains("struct S1 *a0"), "{code}");
        assert_eq!(code.matches("struct S1 {").count(), 1, "{code}");
        assert!(code.contains("gap_0xc[0x4]"), "{code}");
        assert!(code.contains("int64_t field_0x20;"), "{code}");
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
        assert!(code.contains("int64_t field_0x10;"), "{code}");
        assert!(code.contains("int32_t field_0x0;"), "{code}");
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
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    // The flow is checked separately from the executable bodies.
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    first.blocks[0].stmts.pop();
    let mut source =
        String::from("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n");
    source.push_str(&render(&first));
    let second_code = render(&second);
    let declaration = crate::render::structure_definition(&second.structures[0]);
    source.push_str(&second_code.replace(&declaration, ""));
    source.push_str("\n_Static_assert(offsetof(struct S1, field_0x10) == 16, \"offset\");\nint main(void) {\nstruct S1 value; memset(&value, 0xa5, sizeof(value)); f1(&value); f2(&value);\nuint8_t expected[sizeof(value)]; memset(expected, 0xa5, sizeof(expected));\nuint32_t a=1, b=9, d=25; uint64_t c=17;\nmemcpy(expected, &a, 4); memcpy(expected+8, &b, 4); memcpy(expected+16, &c, 8); memcpy(expected+24, &d, 4);\nreturn memcmp(&value, expected, sizeof(value)) != 0; }\n");
    let executable =
        std::env::temp_dir().join(format!("velk-shared-structures-{}", std::process::id()));
    let mut child = Command::new("cc")
        .args(["-std=c11", "-Werror", "-x", "c", "-", "-o"])
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
    let compiled = child.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let status = Command::new(&executable)
        .status()
        .expect("compiled program");
    std::fs::remove_file(executable).unwrap();
    assert!(status.success(), "{source}");
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
    assert!(render(&wrapper).contains("struct S1 *f2"));
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
fn methods_of_one_class_use_one_class_name() {
    let mut first = function(1, &[(0, 4), (8, 4)]);
    let mut second = function(2, &[(16, 8), (24, 4)]);
    first.name = Some("Square::reset()".into());
    second.name = Some("Square::update()".into());
    first.blocks[0].stmts.push(call(2, Expr::reg(7, 64)));
    share(&mut [&mut first, &mut second], &[]);
    for ir in [&first, &second] {
        let code = render(ir);
        assert_eq!(code.matches("struct Square {").count(), 1, "{code}");
        assert!(code.contains("struct Square *a0"), "{code}");
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
        assert!(code.contains("struct S1 *a0"), "{code}");
        assert!(code.contains("int32_t field_0x0;"), "{code}");
        assert!(code.contains("int64_t field_0x8;"), "{code}");
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
        assert!(render(&ir).contains("struct S1 *a0"));
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
