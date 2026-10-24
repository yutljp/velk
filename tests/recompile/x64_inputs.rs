use super::*;

#[test]
fn printed_x64_inputs_exclude_dead_reads_and_unused_call_positions() {
    let scratch = scratch_dir("x64-inputs");
    let assembly = scratch.join("inputs.s");
    let object = scratch.join("inputs.o");
    let mut source = String::from(".text\n");
    for (name, body) in [
        ("last_input", "movl $0, %edx\nmovq %r8, %rax\nret"),
        (
            "sets_inputs",
            "pushq %rbp\nmovq %rsp, %rbp\nmovl $8, %r8d\ncall last_input\npopq %rbp\nret",
        ),
        (
            "dead_inputs",
            "movq %rcx, %r10\naddq %rsi, %r10\nmovl $7, %eax\nret",
        ),
        ("overwritten_inputs", "movl $19, %ecx\nmovq %rcx, %rax\nret"),
        (
            "inline_probe",
            "subq $4096, %rsp\nmovq $0, (%rsp)\nsubq $4096, %rsp\nmovq $0, (%rsp)\nsubq $24, %rsp\nmovl %edi, (%rsp)\nmovl %esi, 8192(%rsp)\nmovl (%rsp), %eax\naddl 8192(%rsp), %eax\naddq $8216, %rsp\nret",
        ),
        (
            "partial_input",
            "movq %rdi, %rax\nmovb $7, %al\naddq $256, %rax\nret",
        ),
        (
            "calls_partial",
            "pushq %rbp\nmovq %rsp, %rbp\ncall partial_input\npopq %rbp\nret",
        ),
    ] {
        writeln!(
            source,
            ".globl {name}\n.type {name},@function\n{name}:\n{body}\n.size {name}, .-{name}"
        )
        .unwrap();
    }
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
    let last = binary.find("last_input").unwrap().addr;
    let partial = binary.find("partial_input").unwrap().addr;
    let symbols = velk::render::Symbols {
        functions: [
            (last, "last_input".into()),
            (partial, "partial_input".into()),
        ]
        .into(),
        ..Default::default()
    };
    let mut text = String::from(HEADER);
    text.push_str("static uint64_t last_input(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) { (void)a; (void)b; (void)c; (void)d; return e; }\nstatic uint64_t partial_input(uint64_t x) { return ((x & ~UINT64_C(255)) | 7) + 256; }\n");
    for name in [
        "sets_inputs",
        "dead_inputs",
        "overwritten_inputs",
        "inline_probe",
        "calls_partial",
    ] {
        let address = binary.find(name).unwrap().addr;
        let ir = &binary.analysis(address, None).unwrap().ir;
        let code = velk::render::render(ir, &[], &symbols, &[]);
        if name == "inline_probe" {
            assert_eq!(ir.params.len(), 2, "{code}");
            assert!(!code.contains("undefined"), "{code}");
        } else if name == "calls_partial" {
            assert!(code.contains("partial_input(a0)"), "{code}");
        } else {
            assert!(code.contains(&format!("{name}(void)")), "{code}");
        }
        if name == "sets_inputs" {
            assert!(code.contains("last_input(0, 0, 0, 0, 8)"), "{code}");
        }
        text.push_str(&code);
    }
    text.push_str("int main(void) { if (sets_inputs() != 8 || dead_inputs() != 7 || overwritten_inputs() != 19) return 1; for (uint64_t x = 0; x < 65536; ++x) { if (calls_partial(x) != (((x & ~UINT64_C(255)) | 7) + 256)) return 2; if ((uint32_t)inline_probe(x, UINT32_MAX) != (uint32_t)(x + UINT32_MAX)) return 3; } return 0; }\n");
    let program = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "", "{}", program.text);
    }
    std::fs::remove_dir_all(scratch).ok();
}
