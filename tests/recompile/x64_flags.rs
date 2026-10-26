use super::*;

#[test]
fn printed_stored_comparisons_and_carry_flags_keep_the_instruction_width() {
    let scratch = scratch_dir("x64-flags");
    let assembly = scratch.join("flags.s");
    let object = scratch.join("flags.o");
    let mut source = String::from(".text\n");
    let mut names = Vec::new();
    for (suffix, instruction, memory) in [
        ("b", "movb", "cmpb"),
        ("w", "movw", "cmpw"),
        ("l", "movl", "cmpl"),
    ] {
        for select in [false, true] {
            let name = format!("stored_{suffix}_{select}");
            let body = if select {
                format!(
                    "{instruction} $0, (%rdi)\n{memory} $-1, (%rdi)\nsetl %al\nmovzbl %al, %eax\nret"
                )
            } else {
                format!(
                    "{instruction} $0, (%rdi)\n{memory} $-1, (%rdi)\njl 1f\nmovl $0, %eax\nret\n1: movl $1, %eax\nret"
                )
            };
            writeln!(
                source,
                ".globl {name}\n.type {name},@function\n{name}:\n{body}\n.size {name}, .-{name}"
            )
            .unwrap();
            names.push(name);
        }
    }
    for (suffix, lhs, rhs) in [
        ("b", "%dil", "%sil"),
        ("w", "%di", "%si"),
        ("l", "%edi", "%esi"),
        ("q", "%rdi", "%rsi"),
    ] {
        for operation in ["adc", "sbb"] {
            let name = format!("flags_{operation}_{suffix}");
            writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\nbtl $0, %edx\n{operation}{suffix} {rhs}, {lhs}\nseto %cl\nlahf\nmovzbl %ah, %eax\nmovzbl %cl, %ecx\nshll $8, %ecx\norl %ecx, %eax\nret\n.size {name}, .-{name}").unwrap();
            names.push(name);
        }
    }
    let name = "saved_frame_after_sbb";
    writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\npushq %rbp\nmovq %rsp, %rbp\npushq %rbx\nsubq $8, %rsp\nmovq %rdi, -16(%rbp)\nmovq %rdi, %rbx\nxorl %edx, %edx\nmovl $1, %esi\ncall flags_sbb_w\nmovq -16(%rbp), %rax\naddq %rbx, %rax\naddq $8, %rsp\npopq %rbx\npopq %rbp\nret\n.size {name}, .-{name}").unwrap();
    names.push(name.into());
    common::compiler::compile_file(
        Command::new(compiler())
            .args(["--target=x86_64-unknown-linux-gnu", "-c"])
            .arg(&assembly)
            .arg("-o")
            .arg(&object),
        &assembly,
        &source,
    );
    let mut binary = Binary::open(&object).unwrap();
    let mut text = String::from(HEADER);
    for name in &names {
        let addr = binary.find(name).unwrap().addr;
        let code = binary.decompile(addr, None, None).unwrap();
        assert!(!code.contains("unsupported"), "{code}");
        text.push_str(&code);
    }
    text.push_str("static unsigned expected(uint64_t a, uint64_t b, unsigned carry, unsigned bits, unsigned sub) { uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1; a &= mask; b &= mask; uint64_t r = (sub ? a - b - carry : a + b + carry) & mask; unsigned cf = sub ? (a < b || (carry && a == b)) : (a > mask - b || (carry && a == mask - b)); uint64_t ov = sub ? ((a ^ b) & (a ^ r)) : (~(a ^ b) & (a ^ r)); unsigned parity = 0; for (unsigned i = 0; i < 8; ++i) parity ^= (r >> i) & 1; return 2 | cf | ((!parity) << 2) | ((a ^ b ^ r) & 16) | ((r == 0) << 6) | (((r >> (bits - 1)) & 1) << 7) | (((ov >> (bits - 1)) & 1) << 8); }\nint main(void) { uint64_t slot = UINT64_MAX;\n");
    for name in names.iter().filter(|name| name.starts_with("stored_")) {
        writeln!(text, "if ({name}((void *)&slot) != 0) return 1;").unwrap();
    }
    text.push_str("const uint64_t values[] = {0, 1, 2, 127, 128, 255, 256, 32767, 32768, 65535, 65536, UINT32_MAX, UINT64_C(0x7fffffff), UINT64_C(0x80000000), UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000000), UINT64_MAX};\n");
    for (suffix, bits) in [("b", 8), ("w", 16), ("l", 32), ("q", 64)] {
        for (operation, subtract) in [("adc", 0), ("sbb", 1)] {
            writeln!(text, "for (unsigned i = 0; i < sizeof(values)/sizeof(values[0]); ++i) for (unsigned j = 0; j < sizeof(values)/sizeof(values[0]); ++j) for (unsigned c = 0; c < 2; ++c) if (flags_{operation}_{suffix}(values[i], values[j], c) != expected(values[i], values[j], c, {bits}, {subtract})) return 2;").unwrap();
        }
    }
    text.push_str(
        "for (uint64_t i = 0; i < 100; ++i) if (saved_frame_after_sbb(i) != 2*i) return 5;\n",
    );
    text.push_str("for (unsigned a = 0; a < 256; ++a) for (unsigned b = 0; b < 256; ++b) for (unsigned c = 0; c < 2; ++c) { if (flags_adc_b(a,b,c) != expected(a,b,c,8,0)) return 3; if (flags_sbb_b(a,b,c) != expected(a,b,c,8,1)) return 4; } return 0; }\n");
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
