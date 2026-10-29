use super::*;

fn thunk(isa: Isa, target: &str) -> (FunctionIr, velk::render::Symbols) {
    let convention = Convention::of(isa, velk::loader::Format::Elf, false);
    let mut ir = synthetic_ir(
        "forward_import",
        vec![],
        CType::U64,
        vec![
            Stmt::Call {
                kind: velk::ir::CallKind::Tail,
                target: None,
                through: Some(Expr::Load {
                    addr: Box::new(Expr::Const(0x2000)),
                    width: if isa == Isa::I386 { 4 } else { 8 },
                    signed: false,
                }),
                convention,
                args: None,
                floats_named: false,
                abi: None,
                outputs: vec![],
                clobbers: None,
                via: None,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ],
    );
    ir.isa = isa;
    ir.convention = convention;
    let base = match target {
        "swprintf" => "snprintf",
        "swscanf" => "sscanf",
        _ => target,
    };
    let mut prototype = velk::analysis::prototypes::of(base, false)
        .expect("the test target has a library prototype")
        .clone();
    if base != target {
        for ty in &mut prototype.params {
            if let CType::Pointer(pointee) = ty {
                if **pointee == CType::Named("char".into()) {
                    **pointee = CType::Named("wchar_t".into());
                } else if **pointee == CType::Named("const char".into()) {
                    **pointee = CType::Named("const wchar_t".into());
                }
            }
        }
    }
    let symbols = velk::render::Symbols {
        import_slots: [(0x2000, target.into())].into(),
        library_prototypes: [(target.into(), prototype)].into(),
        ..Default::default()
    };
    (ir, symbols)
}

#[test]
fn variadic_import_thunks_forward_fixed_and_variable_arguments_on_each_architecture() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64] {
        for (target, counterpart, assertions) in [
            (
                "printf",
                "vprintf",
                "return forward_import(\"%s:%.1f:%d\", \"x\", 2.5, 7) != 7;",
            ),
            (
                "fprintf",
                "vfprintf",
                "FILE *f = tmpfile(); if (!f) return 1; int n = forward_import(f, \"%s:%d\", \"x\", 7); fclose(f); return n != 3;",
            ),
            (
                "sprintf",
                "vsprintf",
                "char b[64]; int n = forward_import(b, \"%s:%.1f:%d\", \"x\", 2.5, 7); return n != 7 || strcmp(b, \"x:2.5:7\");",
            ),
            (
                "snprintf",
                "vsnprintf",
                "char b[5]; int n = forward_import(b, sizeof b, \"%s:%d\", \"hello\", 7); return n != 7 || strcmp(b, \"hell\");",
            ),
            (
                "sscanf",
                "vsscanf",
                "int n = 0; double d = 0; return forward_import(\"7 2.5\", \"%d %lf\", &n, &d) != 2 || n != 7 || d != 2.5;",
            ),
        ] {
            let (ir, symbols) = thunk(isa, target);
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            assert!(code.contains(&format!(" = {counterpart}(")), "{code}");
            assert!(code.contains("va_end(args)"), "{code}");
            syntax::run_printed(
                &format!("#include <stdio.h>\n#include <string.h>\n{code}"),
                "",
                assertions,
            );
        }
        for (target, counterpart, assertions) in [
            ("scanf", "vscanf", "return forward_import(\"\") != 0;"),
            (
                "fscanf",
                "vfscanf",
                "FILE *f = tmpfile(); if (!f) return 1; fputs(\"17\", f); rewind(f); int n = 0; int count = forward_import(f, \"%d\", &n); fclose(f); return count != 1 || n != 17;",
            ),
            (
                "swscanf",
                "vswscanf",
                "int n = 0; return forward_import(L\"17\", L\"%d\", &n) != 1 || n != 17;",
            ),
            (
                "swprintf",
                "vswprintf",
                "wchar_t b[32]; int n = forward_import(b, 32, L\"%d\", 17); return n != 2 || wcscmp(b, L\"17\");",
            ),
        ] {
            let (ir, symbols) = thunk(isa, target);
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            assert!(code.contains(&format!(" = {counterpart}(")), "{code}");
            syntax::run_printed(
                &format!("#include <stdio.h>\n#include <wchar.h>\n{code}"),
                "",
                assertions,
            );
        }
        let (ir, symbols) = thunk(isa, "open");
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(
            code.contains("int forward_import(const char *a0, int a1, ...);"),
            "{code}"
        );
        assert!(code.contains("Forwards all arguments to open"), "{code}");
        assert!(!code.contains('{'), "{code}");
        syntax::run_printed(&code, "", "return 0;");
    }
}

#[test]
fn tail_calls_with_explicit_arguments_are_not_forwarding_thunks() {
    let (mut ir, symbols) = thunk(Isa::X86_64, "printf");
    let Stmt::Call { args, .. } = &mut ir.blocks[0].stmts[0] else {
        panic!("the test body starts with a call");
    };
    *args = Some(vec![Expr::Const(0x3000), Expr::Const(7)]);
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(!code.contains("va_start"), "{code}");
    assert!(code.contains("0x3000"), "{code}");
}
