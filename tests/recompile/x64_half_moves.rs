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

#[test]
fn printed_vector_extractions_select_lanes_and_zero_extend_registers() {
    let scratch = scratch_dir("x64-extractions");
    let assembly = scratch.join("extract.s");
    let object = scratch.join("extract.o");
    let mut source = String::from(".text\n");
    for (instruction, bytes) in [("pextrb", 1), ("pextrw", 2), ("pextrd", 4), ("pextrq", 8)] {
        for lane in 0..16 / bytes {
            let register = if bytes == 8 { "%rax" } else { "%eax" };
            for memory in [false, true] {
                let name = format!("extract_{instruction}_{lane}_{memory}");
                let target = if memory { "(%rsi)" } else { register };
                writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\nmovdqu (%rdi), %xmm0\nmovq $-1, %rax\n{instruction} ${lane}, %xmm0, {target}\nret\n.size {name}, .-{name}").unwrap();
            }
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
    for (instruction, bytes) in [("pextrb", 1), ("pextrw", 2), ("pextrd", 4), ("pextrq", 8)] {
        for lane in 0..16 / bytes {
            for memory in [false, true] {
                let name = format!("extract_{instruction}_{lane}_{memory}");
                let address = binary.find(&name).unwrap().addr;
                let code = binary.decompile(address, None, None).unwrap();
                assert!(!code.contains("unsupported"), "{code}");
                let output = if code.contains(" *a1") {
                    "(void *)out"
                } else {
                    "(uintptr_t)out"
                };
                let call = if memory {
                    format!("{name}((uintptr_t)a, {output});")
                } else {
                    format!("if ({name}((uintptr_t)a) != expected) return 1;")
                };
                let check = if memory {
                    format!(
                        "if (memcmp(out, a + {lane} * {bytes}, {bytes}) || out[{bytes}] != 0xa5) return 1;"
                    )
                } else {
                    String::new()
                };
                syntax::run_printed(
                    &code,
                    "#include <string.h>\n",
                    &format!(
                        "unsigned char a[16]; for (unsigned i = 0; i < 16; ++i) a[i] = 0x80 + i; unsigned char out[16]; memset(out, 0xa5, sizeof out); uint64_t expected = 0; memcpy(&expected, a + {lane} * {bytes}, {bytes}); {call} {check}"
                    ),
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_partial_writes_keep_address_derived_upper_bits_as_numbers() {
    let scratch = scratch_dir("x64-partial-address");
    let assembly = scratch.join("partial.s");
    let object = scratch.join("partial.o");
    std::fs::write(&assembly, ".text\n.globl partial_address\n.type partial_address,@function\npartial_address:\nmovabsq $0x100019118, %rax\nmovw (%rdi), %ax\nmovq %rax, (%rsi)\nxorl %eax, %eax\nret\n.size partial_address, .-partial_address\n").unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("partial_address").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("0x100010000"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "uint16_t input = 0xface; uint64_t output = 0; partial_address(&input, &output); if (output != UINT64_C(0x10001face)) return 1;",
    );
    std::fs::remove_dir_all(scratch).ok();
}
