use super::*;

#[test]
fn printed_atomic_layouts_preserve_adjacent_and_overlapping_fields() {
    let scratch = scratch_dir("atomic-layouts");
    let assembly = scratch.join("fields.s");
    let object = scratch.join("fields.o");
    let mut source = String::from(".text\n");
    for (name, body) in [
        ("atomic_pair", "movq 8(%rdi), %rax\nlock incq (%rdi)\nret"),
        (
            "atomic_heap",
            "movq (%rdi), %rdi\nmovq 8(%rdi), %rax\nlock incq (%rdi)\nret",
        ),
        ("atomic_offset", "movq (%rdi), %rax\nlock incq 8(%rdi)\nret"),
        (
            "atomic_overlap",
            "movq 4(%rdi), %rax\nlock incq (%rdi)\nret",
        ),
    ] {
        writeln!(
            source,
            ".globl {name}\n.type {name},@function\n{name}:\n{body}\n.size {name}, .-{name}"
        )
        .unwrap();
    }
    source.push_str(".globl atomic_callee\n.type atomic_callee,@function\natomic_callee:\npushq %rbp\nmovq %rsp, %rbp\nlock incq (%rdi)\npopq %rbp\nret\n.size atomic_callee, .-atomic_callee\n.globl atomic_caller\n.type atomic_caller,@function\natomic_caller:\npushq %rbp\nmovq %rsp, %rbp\nsubq $16, %rsp\nmovq %rsi, -8(%rbp)\ncall atomic_callee\nmovq -8(%rbp), %rax\naddq $16, %rsp\npopq %rbp\nret\n.size atomic_caller, .-atomic_caller\n");
    std::fs::write(&assembly, source).unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let mut text = String::from(HEADER);
    for name in [
        "atomic_pair",
        "atomic_heap",
        "atomic_offset",
        "atomic_overlap",
    ] {
        let address = binary.find(name).unwrap().addr;
        let mut ir = binary.analysis(address, None).unwrap().ir.clone();
        ir.name = Some(name.into());
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(code.contains("__atomic_fetch_add"), "{code}");
        if name == "atomic_overlap" {
            assert!(ir.structures.is_empty(), "{code}");
        } else {
            assert!(code.contains("field_0x8"), "{code}");
            assert!(
                code.contains("&a0->field_") || code.contains("&v1->field_"),
                "{code}"
            );
            assert!(!code.contains("(uint8_t *)"), "{code}");
        }
        text.push_str(&code.replace("struct S1", &format!("struct {name}_fields")));
    }
    let callee = binary.find("atomic_callee").unwrap().addr;
    let caller = binary.find("atomic_caller").unwrap().addr;
    let mut ir = binary.analysis(caller, None).unwrap().ir.clone();
    ir.name = Some("atomic_caller".into());
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if matches!(stmt, Stmt::Call { target: Some(target), .. } if *target == callee) {
            assert!(!stmt.call_clobbers().contains(&5), "{}", ir.render());
        }
    }
    let symbols = velk::render::Symbols {
        functions: [(callee, "atomic_callee".into())].into(),
        function_returns: [(callee, CType::Void)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(!code.contains("rbp"), "{code}");
    text.push_str("static void atomic_callee(int64_t p) { __atomic_fetch_add((uint64_t *)(uintptr_t)p, 1, __ATOMIC_SEQ_CST); }\n");
    text.push_str(&code);
    text.push_str("int main(void) {\n");
    for value in [0u64, 1, u32::MAX as u64, 1 << 63, u64::MAX] {
        writeln!(text, "{{ uint64_t x[2] = {{UINT64_C({value}), 73}}; void *p = x; if (atomic_pair((void *)x) != 73 || x[0] != UINT64_C({}) || x[1] != 73) return 1; x[0] = UINT64_C({value}); if (atomic_heap((void *)&p) != 73 || x[0] != UINT64_C({}) || x[1] != 73) return 2; x[0] = UINT64_C({value}); if (atomic_offset((void *)x) != UINT64_C({value}) || x[0] != UINT64_C({value}) || x[1] != 74) return 3; x[0] = UINT64_C({value}); x[1] = 73; uint64_t expected; __builtin_memcpy(&expected, (char *)x + 4, 8); if (atomic_overlap((void *)x) != expected || x[0] != UINT64_C({}) || x[1] != 73) return 4; }}", value.wrapping_add(1), value.wrapping_add(1), value.wrapping_add(1)).unwrap();
    }
    text.push_str(
        "{ uint64_t x = 41; if (atomic_caller((uintptr_t)&x, 73) != 73 || x != 42) return 5; }\n",
    );
    text.push_str("return 0; }\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}
