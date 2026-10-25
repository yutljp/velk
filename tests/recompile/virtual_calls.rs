use super::*;

#[test]
fn printed_virtual_slots_dispatch_through_both_object_types() {
    for arch in ["x64", "a64"] {
        let fixture = format!("cpp_virtual_{arch}.elf");
        let mut binary = Binary::open(&common::fixtures_dir().join(&fixture)).unwrap();
        for (source_name, name, scaled, wrapper) in [
            ("any_area", "any_area", false, false),
            ("any_scaled", "any_scaled", true, false),
            ("Shape::scaled", "Shape__scaled", true, true),
        ] {
            let address = binary.find(source_name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            let member = if scaled && !wrapper { "scaled" } else { "area" };
            assert!(code.contains(&format!("->{member}(")), "{code}");
            assert!(code.contains(&format!("(*{member})()")), "{code}");
            assert!(!code.contains("((uint64_t (*)())"), "{code}");
            let scratch = scratch_dir(&format!("virtual-{arch}-{name}"));
            let mut text = String::from(HEADER);
            text.push_str(&code);
            text.push_str(
                r#"
static uint64_t square_area(uint64_t *obj) { return obj[1] * obj[1]; }
static uint64_t rect_area(uint64_t *obj) { return obj[1] * obj[2]; }
static uint64_t square_scaled(uint64_t *obj, uint64_t k) { return square_area(obj) * k; }
static uint64_t rect_scaled(uint64_t *obj, uint64_t k) { return rect_area(obj) * k + 1; }
int main(void) {
    uint64_t square_table[] = { 0, 0, (uintptr_t)square_area, (uintptr_t)square_scaled };
    uint64_t rect_table[] = { 0, 0, (uintptr_t)rect_area, (uintptr_t)rect_scaled };
    uint64_t obj[] = { 0, 0, 0 };
    uint64_t values[] = { 0, 1, 7, 0x7fffffff, 0x80000000, 0xffffffff };
    for (unsigned type = 0; type < 2; ++type) {
        obj[0] = (uintptr_t)(type ? rect_table : square_table);
        for (unsigned i = 0; i < 6; ++i) {
            for (unsigned j = 0; j < 6; ++j) {
                obj[1] = values[i];
                obj[2] = values[j];
                uint64_t area = type ? rect_area(obj) : square_area(obj);
"#,
            );
            let expected = if !scaled {
                "area"
            } else if wrapper {
                "area * k"
            } else {
                "area * k + type"
            };
            if scaled {
                writeln!(text, "for (unsigned n = 0; n < 6; ++n) {{ uint64_t k = values[n]; if ((uint32_t){name}(obj, k) != (uint32_t)({expected})) return 1; }}").unwrap();
            } else {
                writeln!(
                    text,
                    "if ((uint32_t){name}(obj) != (uint32_t)({expected})) return 1;"
                )
                .unwrap();
            }
            text.push_str("} } } return 0; }\n");
            let program = Program {
                text,
                ranges: vec![],
            };
            for level in LEVELS {
                let executable = build(&program, &scratch, level, &["-std=c11"]);
                assert_eq!(run(&executable, ""), "");
            }
        }
    }
}

#[test]
fn virtual_slots_without_unambiguous_names_keep_the_indirect_call() {
    for arch in ["x64", "a64"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("cpp_virtual_{arch}.elf"))).unwrap();
        let address = binary.find("any_area").unwrap().addr;
        let ir = binary.analysis(address, None).unwrap().ir.clone();
        let original = velk::render::callee_names(binary.image());
        for signature in [
            None,
            Some("different() const"),
            Some("area(int) const"),
            Some("operator()() const"),
        ] {
            let mut symbols = velk::render::callee_names(binary.image());
            let candidate = *symbols
                .cpp_methods
                .iter()
                .find(|(_, name)| name.as_str() == "area() const")
                .unwrap()
                .0;
            match signature {
                Some(signature) => {
                    symbols.cpp_methods.insert(candidate, signature.into());
                }
                None => {
                    symbols.cpp_methods.remove(&candidate);
                }
            }
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            assert!(code.contains("((uint64_t (*)())"), "{code}");
            assert!(!code.contains("_vtable {"), "{code}");
        }
        let code = velk::render::render(&ir, &[], &original, &[]);
        assert!(code.contains("->area("), "{code}");
    }
}

#[test]
fn saved_virtual_target_is_not_reloaded_after_a_store() {
    let mut binary = Binary::open(&common::fixtures_dir().join("cpp_virtual_a64.elf")).unwrap();
    let address = binary.find("any_area").unwrap().addr;
    let mut ir = binary.analysis(address, None).unwrap().ir.clone();
    let symbols = velk::render::callee_names(binary.image());
    let arg = Expr::reg(ir.params[0].index, 64);
    let block = &mut ir.blocks[0];
    let position = block
        .stmts
        .iter()
        .position(|stmt| matches!(stmt, Stmt::Call { .. }))
        .unwrap();
    block.stmts.insert(
        position,
        Stmt::Store {
            addr: arg,
            value: Expr::Const(0),
            width: 8,
        },
    );
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("((uint64_t (*)())"), "{code}");
    let mut text = String::from(HEADER);
    text.push_str(&code);
    text.push_str(
        r#"
static uint64_t area(uint64_t *obj) { return obj[1] + 7; }
int main(void) {
    uint64_t table[] = { 0, 0, (uintptr_t)area };
    uint64_t obj[] = { (uintptr_t)table, 11 };
    return any_area(obj) != 18 || obj[0] != 0;
}
"#,
    );
    let scratch = scratch_dir("saved-virtual-target");
    let program = Program {
        text,
        ranges: vec![],
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &["-std=c11"]);
        assert_eq!(run(&executable, ""), "");
    }
}

#[test]
fn constructor_vtable_stores_resolve_calls_without_symbols() {
    for arch in ["x64", "a64"] {
        let mut named =
            Binary::open(&common::fixtures_dir().join(format!("cpp_virtual_{arch}.elf"))).unwrap();
        let mut stripped =
            Binary::open(&common::fixtures_dir().join(format!("cpp_virtual_{arch}_stripped.elf")))
                .unwrap();
        for (caller, method, slot) in [
            ("square_area", "Square::area", 2),
            ("rect_scaled", "Rect::scaled", 3),
        ] {
            let address = named.find(caller).unwrap().addr;
            let target = named.find(method).unwrap().addr;
            for binary in [&mut named, &mut stripped] {
                let ir = &binary.analysis(address, None).unwrap().ir;
                assert!(ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                    matches!(stmt, Stmt::Call { target: Some(found), via: Some(via), .. }
                        if *found == target && via.table == velk::ir::Table::Vtable && via.slot == slot)
                }), "{arch}: {caller}");
            }
        }
    }
}
