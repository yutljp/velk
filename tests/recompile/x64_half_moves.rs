use super::*;

#[test]
fn printed_half_vector_moves_preserve_the_other_half_and_store_eight_bytes() {
    let scratch = scratch_dir("x64-half-moves");
    let assembly = scratch.join("moves.s");
    let object = scratch.join("moves.o");
    let mut source = String::from(".text\n");
    for instruction in ["movlps", "movlpd", "movhps", "movhpd"] {
        for load in [false, true] {
            let name = format!("half_{instruction}_{load}");
            let body = if load {
                format!("{instruction} (%rsi), %xmm0\nmovdqu %xmm0, (%rdx)")
            } else {
                format!("{instruction} %xmm0, (%rsi)")
            };
            writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\nmovdqu (%rdi), %xmm0\n{body}\nmovl $7, %eax\nret\n.size {name}, .-{name}").unwrap();
        }
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
    for instruction in ["movlps", "movlpd", "movhps", "movhpd"] {
        for load in [false, true] {
            let name = format!("half_{instruction}_{load}");
            let address = binary.find(&name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(!code.contains("unsupported"), "{code}");
            let high = instruction.starts_with("movh");
            let checks = if load {
                let expected = if high { "a[0], b" } else { "b, a[1]" };
                format!(
                    "uint64_t expected[2] = {{{expected}}}; if ({name}((uintptr_t)a, (uintptr_t)&b, (uintptr_t)out) != 7 || memcmp(out, expected, sizeof out)) return 1;"
                )
            } else {
                let half = usize::from(high);
                format!(
                    "if ({name}((uintptr_t)a, (uintptr_t)out) != 7 || out[0] != a[{half}] || out[1] != UINT64_MAX) return 1;"
                )
            };
            syntax::run_printed(
                &code,
                "#include <string.h>\n",
                &format!(
                    "uint64_t a[2] = {{UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef)}}; uint64_t b = UINT64_C(0x8877665544332211); uint64_t out[2] = {{UINT64_MAX, UINT64_MAX}}; {checks}"
                ),
            );
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}
