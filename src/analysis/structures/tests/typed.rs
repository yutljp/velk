use super::*;

fn at(base: u16, offset: u64) -> Expr {
    Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset))
}

fn compile_and_run(name: &str, code: &str, main: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("typed-pointer-tests");
    std::fs::create_dir_all(&dir).unwrap();
    for level in ["-O0", "-O2"] {
        let executable = dir.join(format!("{name}{level}"));
        let mut compiler = Command::new("clang")
            .args([
                "-x",
                "c",
                "-std=c11",
                "-fwrapv",
                "-fno-strict-aliasing",
                level,
                "-",
                "-o",
            ])
            .arg(&executable)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        write!(
            compiler.stdin.take().unwrap(),
            "#include <stdint.h>\n#include <stddef.h>\n{code}\n{main}"
        )
        .unwrap();
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{code}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(&executable).status().unwrap().success(),
            "{code}"
        );
    }
}

#[test]
fn copies_combine_fields_and_preserve_mixed_signed_loads() {
    let copy = VARIABLE_BASE;
    let mut ir = pointer_function(vec![
        assign(copy, Expr::reg(7, 64)),
        Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                load(at(7, 4), 1, true),
                load(at(copy, 8), 2, false),
            ),
        },
    ]);
    ir.name = Some("copied_fields".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(text.contains("a0->field_0x4"), "{text}");
    assert!(text.contains("->field_0x8"), "{text}");
    assert!(!text.contains("*(uint"), "{text}");
    compile_and_run(
        "copied_fields",
        &text,
        r#"
int main(void) {
    _Static_assert(offsetof(struct copied_fields_a0, field_0x4) == 4, "offset");
    _Static_assert(offsetof(struct copied_fields_a0, field_0x8) == 8, "offset");
    struct copied_fields_a0 value = {0};
    value.field_0x4 = -128;
    value.field_0x8 = 65535;
    if (copied_fields(&value) != 65407) return 1;
    value.field_0x4 = 127;
    value.field_0x8 = 32768;
    return copied_fields(&value) != 32895;
}
"#,
    );
}

#[test]
fn a_local_structure_array_uses_the_exact_stride() {
    let pointer = VARIABLE_BASE;
    let mut ir = pointer_function(vec![
        assign(pointer, load(Expr::reg(7, 64), 8, false)),
        Stmt::Store {
            addr: element(Expr::reg(pointer, 64), Expr::reg(6, 64), 16, 0),
            value: Expr::Const(91),
            width: 8,
        },
        Stmt::Ret {
            value: load(
                element(Expr::reg(pointer, 64), Expr::reg(6, 64), 16, 8),
                4,
                true,
            ),
        },
    ]);
    ir.params.push(Param {
        index: 6,
        name: "index".into(),
        ty: CType::U64,
    });
    ir.name = Some("local_array".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(text.contains("v1[index].field_0x0 = 91;"), "{text}");
    assert!(text.contains("v1[index].field_0x8"), "{text}");
    compile_and_run(
        "local_array",
        &text,
        r#"
int main(void) {
    _Static_assert(sizeof(struct local_array_s1) == 16, "stride");
    struct local_array_s1 values[3] = {0};
    values[2].field_0x8 = -17;
    uintptr_t pointer = (uintptr_t)values;
    if (local_array((void *)&pointer, 2) != (uint64_t)-17) return 1;
    return values[0].field_0x0 != 0 || values[2].field_0x0 != 91;
}
"#,
    );
}

#[test]
fn partial_or_conflicting_copies_do_not_combine_fields() {
    for width in [32, 64] {
        let copy = VARIABLE_BASE;
        let mut stmts = vec![Stmt::Assign {
            dest: RegRef { index: copy, width },
            value: Expr::reg(7, width),
        }];
        if width == 64 {
            stmts.push(assign(copy, Expr::Const(0)));
        }
        stmts.push(Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                load(at(7, 0), 4, false),
                load(at(copy, 0), 8, false),
            ),
        });
        let mut ir = pointer_function(stmts);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
    }
}

#[test]
fn inconsistent_copy_accesses_and_unaligned_fields_keep_casts() {
    for (offset, width) in [(0, 8), (5, 4), (u64::MAX, 4)] {
        let copy = VARIABLE_BASE;
        let mut ir = pointer_function(vec![
            assign(copy, Expr::reg(7, 64)),
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    load(at(7, 0), 4, false),
                    load(at(copy, offset), width, false),
                ),
            },
        ]);
        recover(&mut ir);
        assert!(ir.params[0].ty.pointee_struct().is_none());
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(text.contains("*(uint"), "{text}");
    }
}

#[test]
fn call_result_and_copy_use_fixed_fields() {
    use crate::ir::{CallKind, CallOutput, Convention};
    let (result, copy) = (VARIABLE_BASE, VARIABLE_BASE + 1);
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                abi: None,
                kind: CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(Vec::new()),
                floats_named: true,
                outputs: vec![CallOutput {
                    register: 0,
                    dest: RegRef {
                        index: result,
                        width: 64,
                    },
                }],
                clobbers: Some([0].into_iter().collect()),
                via: None,
            },
            assign(copy, Expr::reg(result, 64)),
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    load(at(copy, 4), 4, true),
                    load(at(copy, 8), 8, false),
                ),
            },
        ],
    );
    ir.name = Some("returned_fields".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let mut symbols = crate::render::Symbols::default();
    symbols.functions.insert(0x1000, "make_pointer".into());
    symbols.function_returns.insert(0x1000, CType::U64);
    let text = crate::render::render(&ir, &[], &symbols, &[]);
    assert!(text.contains("->field_0x4"), "{text}");
    assert!(text.contains("->field_0x8"), "{text}");
    assert!(ir.value_types[&result].pointee_struct().is_some());
    compile_and_run(
        "returned_fields",
        &format!("uint64_t make_pointer(void);\n{text}"),
        r#"
static uint64_t storage[2] = {UINT64_C(0xfffffffe00000000), 71};
uint64_t make_pointer(void) { return (uintptr_t)storage; }
int main(void) { return returned_fields() != 69; }
"#,
    );
}

#[test]
fn scalar_array_types_extend_through_whole_copies() {
    let (pointer, copy) = (VARIABLE_BASE, VARIABLE_BASE + 1);
    let mut ir = pointer_function(vec![
        assign(pointer, load(Expr::reg(7, 64), 8, false)),
        assign(copy, Expr::reg(pointer, 64)),
        Stmt::Ret {
            value: load(
                element(Expr::reg(copy, 64), Expr::reg(6, 64), 8, 0),
                8,
                false,
            ),
        },
    ]);
    ir.params.push(Param {
        index: 6,
        name: "index".into(),
        ty: CType::U64,
    });
    ir.name = Some("scalar_array".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(text.contains("uint64_t *v1;"), "{text}");
    assert!(text.contains("v2 = v1;"), "{text}");
    assert!(text.contains("return v2[index];"), "{text}");
    compile_and_run(
        "scalar_array",
        &text,
        r#"
int main(void) {
    uint64_t values[3] = {0, UINT64_MAX, UINT64_C(0x8000000000000000)};
    uintptr_t pointer = (uintptr_t)values;
    for (uint64_t i = 0; i < 3; ++i)
        if (scalar_array((void *)&pointer, i) != values[i]) return 1;
    return 0;
}
"#,
    );
}

#[test]
fn a_pointer_followed_through_its_own_field_points_at_a_structure() {
    // p = *a0; total = p->next_value; p = p->link; return total + p->value,
    // as a walk along a list does.
    let pointer = VARIABLE_BASE;
    let total = VARIABLE_BASE + 1;
    let mut ir = pointer_function(vec![
        assign(pointer, load(Expr::reg(7, 64), 8, false)),
        assign(total, load(at(pointer, 8), 8, false)),
        assign(pointer, load(at(pointer, 0), 8, false)),
        Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                Expr::reg(total, 64),
                load(at(pointer, 8), 8, false),
            ),
        },
    ]);
    ir.name = Some("list_walk".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(text.contains("->field_0x8"), "{text}");
    assert!(!text.contains("*(uint64_t *)("), "{text}");
    compile_and_run(
        "list_walk",
        &text,
        r#"
int main(void) {
    _Static_assert(offsetof(struct list_walk_s1, field_0x8) == 8, "offset");
    struct list_walk_s1 second = {0}, first = {0};
    second.field_0x8 = 5;
    first.field_0x0 = &second;
    first.field_0x8 = 7;
    uintptr_t head = (uintptr_t)&first;
    return list_walk((void *)&head) != 12;
}
"#,
    );
}

#[test]
fn a_local_array_indexed_through_a_scaled_register_uses_its_elements() {
    // p = *a0; offset = index << 4; p[offset].0 = 91; return p[offset].8,
    // with the offset in a register of its own.
    let pointer = VARIABLE_BASE;
    let offset = VARIABLE_BASE + 1;
    let field = |constant: u64| {
        Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::Add, Expr::reg(pointer, 64), Expr::reg(offset, 64)),
            Expr::Const(constant),
        )
    };
    let mut ir = pointer_function(vec![
        assign(pointer, load(Expr::reg(7, 64), 8, false)),
        assign(
            offset,
            Expr::bin(BinOp::Shl, Expr::reg(6, 64), Expr::Const(4)),
        ),
        Stmt::Store {
            addr: field(0),
            value: Expr::Const(91),
            width: 8,
        },
        Stmt::Ret {
            value: load(field(8), 4, true),
        },
    ]);
    ir.params.push(Param {
        index: 6,
        name: "index".into(),
        ty: CType::U64,
    });
    ir.name = Some("scaled_array".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(text.contains("[index].field_0x0 = 91;"), "{text}");
    assert!(text.contains("[index].field_0x8"), "{text}");
    compile_and_run(
        "scaled_array",
        &text,
        r#"
int main(void) {
    _Static_assert(sizeof(struct scaled_array_s1) == 16, "stride");
    struct scaled_array_s1 values[3] = {0};
    values[2].field_0x8 = -17;
    uintptr_t pointer = (uintptr_t)values;
    if (scaled_array((void *)&pointer, 2) != (uint64_t)-17) return 1;
    return values[0].field_0x0 != 0 || values[2].field_0x0 != 91;
}
"#,
    );
}

#[test]
fn a_field_read_at_two_widths_is_a_union_member() {
    // a0->0 = 0x1234_5678_9abc_def0; return (int32_t)a0->4 + a0->8, with
    // the first eight bytes read at four bytes from their middle.
    let mut ir = pointer_function(vec![
        Stmt::Store {
            addr: at(7, 0),
            value: Expr::Const(0x1234_5678_9abc_def0),
            width: 8,
        },
        Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                load(at(7, 4), 4, true),
                load(at(7, 8), 8, false),
            ),
        },
    ]);
    ir.name = Some("cell_fields".into());
    ir.ret_type = CType::U64;
    recover(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(text.contains("union {"), "{text}");
    assert!(text.contains("a0->field_0x0.as_i64 = "), "{text}");
    assert!(text.contains("a0->field_0x0.as_i32[1]"), "{text}");
    assert!(!text.contains("*(int32_t *)"), "{text}");
    compile_and_run(
        "cell_fields",
        &text,
        r#"
int main(void) {
    _Static_assert(offsetof(struct cell_fields_a0, field_0x8) == 8, "offset");
    struct cell_fields_a0 value = {0};
    value.field_0x8 = 5;
    return cell_fields(&value) != (uint64_t)(0x12345678 + 5);
}
"#,
    );
}
