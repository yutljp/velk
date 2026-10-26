mod common;

use std::fmt::Write as _;
use std::process::Command;

use velk::service::Binary;

#[test]
fn declared_word_pairs_compile_and_match_integer_operations() {
    check_word_pairs(/* debug */ true);
}

#[test]
fn inferred_word_pairs_compile_and_match_integer_operations() {
    check_word_pairs(/* debug */ false);
}

fn check_word_pairs(debug: bool) {
    let scratch = common::root().join(if debug {
        "target/pairs32-tests"
    } else {
        "target/pairs32-inferred-tests"
    });
    std::fs::create_dir_all(&scratch).expect("create fixture directory");
    for (target, mode) in [
        ("i386-linux-gnu", ""),
        ("armv7a-linux-gnueabihf", "-marm"),
        ("armv7a-linux-gnueabihf", "-mthumb"),
    ] {
        for level in ["-O0", "-O2"] {
            let tag = format!("{target}{mode}{level}");
            let object = scratch.join(format!("{tag}.o"));
            let mut compiler = Command::new("clang");
            compiler.args([
                "-target",
                target,
                "-c",
                "-fno-inline",
                "-fno-pic",
                "-fno-pie",
                level,
            ]);
            if debug {
                compiler.arg("-g");
            }
            if !mode.is_empty() {
                compiler.arg(mode);
            }
            let output = compiler
                .arg(common::root().join("tests/cases/pairs32.c"))
                .arg("-o")
                .arg(&object)
                .output()
                .expect("run fixture compiler");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let helpers = scratch.join(format!("{tag}-helpers.s"));
            let helpers_object = scratch.join(format!("{tag}-helpers.o"));
            let body = if target.starts_with("i386") {
                "mov 4(%esp), %eax\nmov 8(%esp), %edx\nret"
            } else {
                "bx lr"
            };
            let mut assembly = String::from(".text\n");
            for name in [
                "__udivdi3",
                "__umoddi3",
                "__aeabi_uldivmod",
                "__divdi3",
                "__moddi3",
                "__aeabi_ldivmod",
            ] {
                writeln!(assembly, ".global {name}\n.type {name}, %function\n{name}:\n{body}\n.size {name}, .-{name}").expect("writing to a String succeeds");
            }
            std::fs::write(&helpers, assembly).expect("write helper assembly");
            let output = Command::new("clang")
                .args(["-target", target, "-c"])
                .arg(&helpers)
                .arg("-o")
                .arg(&helpers_object)
                .output()
                .expect("run fixture compiler");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let image = scratch.join(format!("{tag}.so"));
            let output = Command::new("ld.lld")
                .args([
                    "-shared",
                    "-Bsymbolic",
                    "-z",
                    "notext",
                    "-m",
                    if target.starts_with("i386") {
                        "elf_i386"
                    } else {
                        "armelf_linux_eabi"
                    },
                ])
                .arg(&object)
                .arg(&helpers_object)
                .arg("-o")
                .arg(&image)
                .output()
                .expect("run fixture compiler");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut binary = Binary::open(&image).expect("open compiled fixture");
            let mut code = String::from(
                "#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <string.h>\n",
            );
            code.push_str("uint64_t __udivdi3(uint64_t a, uint64_t b) {\n    return a / b; }\nuint64_t __umoddi3(uint64_t a, uint64_t b) {\n    return a % b; }\nuint64_t __aeabi_uldivmod(uint64_t a, uint64_t b) {\n    return a / b; }\n");
            code.push_str("int64_t __divdi3(int64_t a, int64_t b) {\n    return a == INT64_MIN && b == -1 ? INT64_MIN : a / b; }\nint64_t __moddi3(int64_t a, int64_t b) {\n    return a == INT64_MIN && b == -1 ? 0 : a % b; }\nint64_t __aeabi_ldivmod(int64_t a, int64_t b) {\n    return __divdi3(a, b); }\n");
            for function in [
                "add64",
                "guarded_sub64",
                "byte64",
                "sub64",
                "mul64",
                "left64",
                "right64",
                "mixed64",
                "call64",
                "div64",
                "mod64",
                "guarded_mod64",
                "signed_div64",
                "signed_mod64",
            ] {
                let address = binary.find(function).expect("fixture function exists").addr;
                let printed = binary
                    .decompile(address, None, None)
                    .expect("decompile fixture");
                assert!(
                    !printed.contains("unsupported"),
                    "{tag} {function}: {printed}"
                );
                assert!(
                    printed.contains("uint64_t")
                        || printed.contains("int64_t")
                        || printed.contains("long long"),
                    "{printed}"
                );
                assert!(!printed.contains("velk_entry_stack_pointer"), "{printed}");
                code.push_str(&printed);
            }
            code.push_str("int main(void) {\n");
            for a in [0u64, 1, 0xffff_ffff, 0x8000_0000_0000_0000, u64::MAX] {
                for b in [0u64, 1, 0xffff_ffff, 0x1234_5678_8765_4321, u64::MAX] {
                    for (function, expected) in [
                        ("add64", a.wrapping_add(b)),
                        ("sub64", a.wrapping_sub(b)),
                        ("byte64", (a.wrapping_add(1) & !255) | (b & 255)),
                        ("guarded_mod64", if b == 0 { a } else { a % b }),
                        (
                            "guarded_sub64",
                            if ((a ^ b) & ((a ^ ((a ^ b) & (1 << 63))).wrapping_sub(b) ^ b))
                                & (1 << 63)
                                != 0
                            {
                                a
                            } else {
                                a.wrapping_sub(b)
                            },
                        ),
                        ("mul64", a.wrapping_mul(b)),
                        ("call64", a.wrapping_add(b) ^ 0x1234_5678_9abc_def0),
                    ] {
                        let argument_b = if function == "byte64" {
                            u64::from(b as u32)
                        } else {
                            b
                        };
                        writeln!(
                            code,
                            "if ({function}({a}ULL, {argument_b}ULL) != {expected}ULL) return 1;"
                        )
                        .expect("writing to a String succeeds");
                    }
                    let expected = a.wrapping_add(b).wrapping_add(24);
                    if let (Some(quotient), Some(remainder)) = (
                        (a as i64).checked_div(b as i64),
                        (a as i64).checked_rem(b as i64),
                    ) {
                        writeln!(code, "if ((uint64_t)signed_div64((int64_t){a}ULL, (int64_t){b}ULL) != {}ULL || (uint64_t)signed_mod64((int64_t){a}ULL, (int64_t){b}ULL) != {}ULL) return 5;", quotient as u64, remainder as u64).expect("writing to a String succeeds");
                    }
                    if let (Some(quotient), Some(remainder)) = (a.checked_div(b), a.checked_rem(b))
                    {
                        writeln!(code, "if (div64({a}ULL, {b}ULL) != {quotient}ULL || mod64({a}ULL, {b}ULL) != {remainder}ULL) return 4;").expect("writing to a String succeeds");
                    }
                    {
                        writeln!(
                            code,
                            "if (mixed64(7, {a}ULL, 17, {b}ULL) != {expected}ULL) return 2;"
                        )
                        .expect("writing to a String succeeds");
                    }
                }
                for n in [0, 1, 31, 32, 33, 63] {
                    writeln!(code, "if (left64({a}ULL, {n}) != {}ULL || right64({a}ULL, {n}) != {}ULL) return 3;", a << n, a >> n).expect("writing to a String succeeds");
                }
            }
            code.push_str("if (signed_div64(INT64_MIN, -1) != INT64_MIN || signed_mod64(INT64_MIN, -1) != 0) return 6;\nreturn 0;\n}\n");
            let names = velk::render::callee_names(binary.image());
            for function in [
                "signed_div64",
                "signed_mod64",
                "guarded_mod64",
                "add64",
                "guarded_sub64",
                "byte64",
                "sub64",
                "mul64",
                "left64",
                "right64",
                "mixed64",
                "call64",
                "div64",
                "mod64",
            ] {
                let address = binary.find(function).expect("fixture function exists").addr;
                code = code.replace(
                    &format!("{function}("),
                    &format!("{}(", names.functions[&address]),
                );
            }
            let source = scratch.join(format!("{tag}.c"));
            std::fs::write(&source, velk::render::combine(&code)).expect("write printed C");
            for optimization in ["-O0", "-O2"] {
                let executable = scratch.join(format!("{tag}{optimization}"));
                let output = Command::new("clang")
                    .args([
                        "-std=c17",
                        "-Werror",
                        "-Wno-unused-variable",
                        "-fsanitize=undefined",
                        "-fno-sanitize-recover=undefined",
                        optimization,
                    ])
                    .arg(&source)
                    .arg("-o")
                    .arg(&executable)
                    .output()
                    .expect("compile printed C");
                assert!(
                    output.status.success(),
                    "{tag}: {}\n{code}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let output = Command::new(&executable).output().expect("run printed C");
                assert!(output.status.success(), "{tag}: {output:?}\n{code}");
            }
        }
    }
}

#[test]
fn arm_carry_flags_and_vfp_stack_saves_match_printed_c() {
    let scratch = common::root().join("target/pairs32-instructions");
    std::fs::create_dir_all(&scratch).unwrap();
    for mode in ["arm", "thumb"] {
        let mut assembly =
            format!(".syntax unified\n.cpu cortex-a15\n.fpu neon-vfpv4\n.{mode}\n.text\n");
        if mode == "thumb" {
            assembly.push_str(".thumb_func\n");
        }
        assembly.push_str(".global keep_r4\n.type keep_r4, %function\nkeep_r4:\npush {r4, lr}\nmov r4, #37\npop {r4, pc}\n.size keep_r4, .-keep_r4\n");
        let cases = [
            ("carry_add", "adds r2, r0, r1\nadc r0, r0, r1"),
            ("carry_sub", "subs r2, r0, r1\nsbc r0, r0, r1"),
            (
                "saved_call",
                "push {r4, lr}\nmov r4, r0\nbl keep_r4\nmov r0, r4\npop {r4, pc}",
            ),
            (
                "copy_multiple",
                "push {r4, r5, r6, r7, lr}\nsub sp, sp, #32\nmov r4, sp\nstr r0, [r4]\nstr r1, [r4, #4]\nadd r5, sp, #16\nldm r4!, {r0, r1}\nstmia r5!, {r0, r1}\nsub r5, r5, #8\nldr r0, [r5]\nldr r1, [r5, #4]\neor r0, r0, r1\nadd sp, sp, #32\npop {r4, r5, r6, r7, pc}",
            ),
            (
                "or_complement",
                if mode == "thumb" {
                    "orn r0, r0, r1"
                } else {
                    "mvn r2, r1\norr r0, r0, r2"
                },
            ),
            ("shift_pair", "asrs r1, r1, #1\nrrx r0, r0"),
            ("shift_carry", "lsrs r2, r0, #1\nadc r0, r1, #0"),
            ("rotate_carry", "cmp r1, #1\nrrx r0, r0"),
            ("rotate_flags", "cmp r1, #1\nrrxs r2, r0\nadc r0, r0, #0"),
            ("count_leading", "clz r0, r0"),
            (
                "store_double_same",
                if mode == "thumb" {
                    "sub sp, sp, #8\nstrd r0, r0, [sp]\nldr r0, [sp, #4]\nadd sp, sp, #8"
                } else {
                    "sub sp, sp, #8\nstrd r0, r1, [sp]\nldr r0, [sp]\nadd sp, sp, #8"
                },
            ),
            (
                "load_literal",
                "vldr d7, 1f\nvmov r0, s14\nbx lr\n.p2align 3\n1: .quad 0x8765432112345678",
            ),
            (
                "load_double_literal",
                "ldrd r0, r1, 1f\neor r0, r0, r1\nbx lr\n.p2align 3\n1: .quad 0x8765432112345678",
            ),
            (
                "load_double_alias",
                "adr r2, 1f\nldrd r0, r1, [r2]\neor r0, r0, r1\nbx lr\n.p2align 3\n1: .quad 0x8765432112345678",
            ),
            ("multiply_high", "umull r2, r3, r0, r1\nmov r0, r3"),
            (
                "save_large_frame",
                if mode == "thumb" {
                    "push {r7, lr}\nsub.w sp, sp, #2048\nsub sp, sp, #4\nadd r7, sp, #0\nstr r0, [r7]\nldr r0, [r7]\nadd.w r7, r7, #2048\nadds r7, r7, #4\nmov sp, r7\npop {r7, pc}"
                } else {
                    "push {r7, lr}\nsub sp, sp, #2048\nsub sp, sp, #4\nadd r7, sp, #0\nstr r0, [r7]\nldr r0, [r7]\nadd r7, r7, #2048\nadds r7, r7, #4\nmov sp, r7\npop {r7, pc}"
                },
            ),
            ("multiply_bb", "smulbb r0, r0, r1"),
            ("multiply_bt", "smulbt r0, r0, r1"),
            ("multiply_tb", "smultb r0, r0, r1"),
            ("multiply_tt", "smultt r0, r0, r1"),
            (
                "save_double",
                "vmov s16, r0\nvmov s17, r1\nvpush {d8}\nvmov s16, r2\nvpop {d8}\nvmov r0, s16",
            ),
            (
                "save_single",
                "vmov s17, r0\nvpush {s17}\nvmov s17, r1\nvpop {s17}\nvmov r0, s17",
            ),
        ];
        for (name, body) in cases {
            if mode == "thumb" {
                assembly.push_str(".thumb_func\n");
            }
            writeln!(assembly, ".global {name}\n.type {name}, %function\n{name}:\n{body}\nbx lr\n.size {name}, .-{name}").unwrap();
        }
        let source = scratch.join(format!("{mode}.s"));
        let object = scratch.join(format!("{mode}.o"));
        std::fs::write(&source, assembly).unwrap();
        let output = Command::new("clang")
            .args(["--target=armv7a-linux-gnueabihf", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let linked = scratch.join(format!("{mode}.elf"));
        let output = Command::new("ld.lld")
            .args(["-m", "armelf_linux_eabi", "-e", "load_literal"])
            .arg(&object)
            .arg("-o")
            .arg(&linked)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut binary = Binary::open(&linked).unwrap();
        let mut code = String::from(
            "#include <stdint.h>\n#include <stdbool.h>\n#include <string.h>\nvoid keep_r4(uint32_t ignored) {\n}\n",
        );
        let mut checks = String::new();
        for (name, _) in cases {
            let address = binary.find(name).unwrap().addr;
            let params = binary.analysis(address, None).unwrap().ir.params.clone();
            let printed = binary.decompile(address, None, None).unwrap();
            if name == "load_literal" {
                assert!(!printed.contains("*(uint64_t *)"), "{printed}");
            }
            assert!(!printed.contains("unsupported"), "{mode}: {printed}");
            assert!(
                !printed.contains("velk_entry_stack_pointer"),
                "{mode}: {printed}"
            );
            code.push_str(&printed);
            for a in [0u32, 1, 3, 0xffff_ff80, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                for b in [0u32, 1, 3, 0xffff_ff80, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                    let expected = match name {
                        "carry_add" => a.wrapping_add(b).wrapping_add(u32::from(
                            u64::from(a) + u64::from(b) > u64::from(u32::MAX),
                        )),
                        "carry_sub" => a.wrapping_sub(b).wrapping_sub(u32::from(a < b)),
                        "conditional_flags" => {
                            if a.wrapping_add(128) == 0 && b == 3 {
                                37
                            } else {
                                11
                            }
                        }
                        "single_pop" => a.wrapping_add(1),
                        "copy_multiple" => a ^ b,
                        "or_complement" => a | !b,
                        "shift_pair" => (a >> 1) | (b << 31),
                        "shift_carry" => b.wrapping_add(a & 1),
                        "rotate_carry" => (a >> 1) | (u32::from(b >= 1) << 31),
                        "rotate_flags" => a.wrapping_add(a & 1),
                        "count_leading" => a.leading_zeros(),
                        "load_literal" => 0x1234_5678,
                        "load_double_literal" | "load_double_alias" => 0x9551_1559,
                        "multiply_high" => ((u64::from(a) * u64::from(b)) >> 32) as u32,
                        "multiply_bb" => ((a as i16 as i32) * (b as i16 as i32)) as u32,
                        "multiply_bt" => ((a as i16 as i32) * ((b >> 16) as i16 as i32)) as u32,
                        "multiply_tb" => (((a >> 16) as i16 as i32) * (b as i16 as i32)) as u32,
                        "multiply_tt" => {
                            (((a >> 16) as i16 as i32) * ((b >> 16) as i16 as i32)) as u32
                        }
                        _ => a,
                    };
                    let args: Vec<String> = params
                        .iter()
                        .map(|param| {
                            format!(
                                "{}u",
                                match param.index {
                                    0 => a,
                                    1 => b,
                                    _ => 0x1234_5678,
                                }
                            )
                        })
                        .collect();
                    writeln!(
                        checks,
                        "if ((uint32_t){name}({}) != {expected}u) return 1;",
                        args.join(", ")
                    )
                    .unwrap();
                }
            }
        }
        writeln!(code, "int main(void) {{ {checks} return 0; }}").unwrap();
        let source = scratch.join(format!("{mode}.c"));
        std::fs::write(
            &source,
            format!(
                "#include <stdint.h>\n#include <stdbool.h>\n{}",
                velk::render::combine(&code)
            ),
        )
        .unwrap();
        for level in ["-O0", "-O2"] {
            let executable = scratch.join(format!("{mode}{level}"));
            let output = Command::new("clang")
                .args(["-std=c17", level, "-Werror", "-Wno-unused-variable"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{code}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = Command::new(&executable).output().unwrap();
            assert!(output.status.success(), "{mode}: {output:?}\n{code}");
        }
    }
}

#[test]
fn arm_import_stubs_use_the_declared_argument_count() {
    let scratch = common::root().join("target/pairs32-imports");
    std::fs::create_dir_all(&scratch).unwrap();
    let source = scratch.join("copy.c");
    std::fs::write(&source, "extern void *memcpy(void *, const void *, unsigned int);\nvoid *copy_known(void *dst, const void *src) { return memcpy(dst, src, 7); }\n").unwrap();
    let object = scratch.join("copy.o");
    let image = scratch.join("copy.so");
    let output = Command::new("clang")
        .args([
            "--target=armv7a-linux-gnueabihf",
            "-O2",
            "-fno-builtin",
            "-fPIC",
            "-c",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("ld.lld")
        .args(["-shared", "-m", "armelf_linux_eabi"])
        .arg(&object)
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut binary = Binary::open(&image).unwrap();
    let address = binary.find("copy_known").unwrap().addr;
    let printed = binary.decompile(address, None, None).unwrap();
    assert!(printed.contains("memcpy("), "{printed}");
    assert!(!printed.contains("unsupported"), "{printed}");
    let source = scratch.join("check.c");
    std::fs::write(&source, format!("#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\nstatic void *copy_stub(void *dst, const void *src, size_t count) {{ return (uintptr_t)dst == 0x1000 && (uintptr_t)src == 0x2000 && count == 7 ? dst : 0; }}\n#define memcpy copy_stub\n{printed}\nint main(void) {{ return copy_known((void *)0x1000, (void *)0x2000) != (void *)0x1000; }}\n")).unwrap();
    let executable = scratch.join("check");
    let output = Command::new("clang")
        .args(["-std=c17", "-Werror", "-Wno-int-to-void-pointer-cast"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{printed}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).output().unwrap().status.success());
}

#[test]
fn word_runtime_calls_and_indexed_frames_compile_and_run() {
    let scratch = common::root().join("target/pairs32-followup");
    std::fs::create_dir_all(&scratch).unwrap();
    for (target, mode) in [
        ("i386-linux-gnu", ""),
        ("armv7a-linux-gnueabihf", "-marm"),
        ("armv7a-linux-gnueabihf", "-mthumb"),
    ] {
        for level in ["-O0", "-O2"] {
            let tag = format!("{target}{mode}{level}");
            let object = scratch.join(format!("{tag}.o"));
            let mut compiler = Command::new("clang");
            compiler.args([
                "-target",
                target,
                "-c",
                "-fno-inline",
                "-fno-pic",
                level,
                "-fno-vectorize",
                "-fno-slp-vectorize",
            ]);
            if !mode.is_empty() {
                compiler.arg(mode);
            }
            let output = compiler
                .arg(common::root().join("tests/cases/word_calls.c"))
                .arg("-o")
                .arg(&object)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let helpers = scratch.join(format!("{tag}-helpers.c"));
            let helpers_object = scratch.join(format!("{tag}-helpers.o"));
            std::fs::write(&helpers, "unsigned __aeabi_uidiv(unsigned a, unsigned b) { return a / b; }\nint __aeabi_idiv(int a, int b) { return a / b; }\nunsigned __aeabi_uidivmod(unsigned a, unsigned b) { return a / b; }\nint __aeabi_idivmod(int a, int b) { return a / b; }\n").unwrap();
            let mut compiler = Command::new("clang");
            compiler.args(["-target", target, "-c", "-fno-pic"]);
            if !target.starts_with("i386") {
                compiler.arg("-mcpu=cortex-a15");
            }
            if !mode.is_empty() {
                compiler.arg(mode);
            }
            let output = compiler
                .arg(&helpers)
                .arg("-o")
                .arg(&helpers_object)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let image = scratch.join(format!("{tag}.so"));
            let output = Command::new("ld.lld")
                .args([
                    "-shared",
                    "-Bsymbolic",
                    "-z",
                    "notext",
                    "-m",
                    if target.starts_with("i386") {
                        "elf_i386"
                    } else {
                        "armelf_linux_eabi"
                    },
                ])
                .arg(&object)
                .arg(&helpers_object)
                .arg("-o")
                .arg(&image)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut binary = Binary::open(&image).unwrap();
            let mut code = String::from("#include <stdint.h>\n#include <stdbool.h>\n");
            code.push_str("uint32_t __aeabi_uidiv(uint32_t a, uint32_t b) {\n    return a / b; }\nint32_t __aeabi_idiv(int32_t a, int32_t b) {\n    return a / b; }\nuint32_t __aeabi_uidivmod(uint32_t a, uint32_t b) {\n    return a / b; }\nint32_t __aeabi_idivmod(int32_t a, int32_t b) {\n    return a / b; }\n");
            for function in [
                "indexed_frame",
                "divide_signed",
                "divide_unsigned",
                "remainder_signed",
                "remainder_unsigned",
                "scalar_words",
                "advancing_buffers",
            ] {
                let address = binary.find(function).unwrap().addr;
                let printed = binary.decompile(address, None, None).unwrap();
                assert!(!printed.contains("unsupported"), "{tag}: {printed}");
                assert!(
                    !printed.contains("velk_entry_stack_pointer"),
                    "{tag}: {printed}"
                );
                if matches!(function, "indexed_frame" | "advancing_buffers")
                    && !target.starts_with("i386")
                {
                    let source = scratch.join(format!("{tag}-frame.c"));
                    std::fs::write(
                        &source,
                        format!("#include <stdint.h>\n#include <stdbool.h>\n{printed}"),
                    )
                    .unwrap();
                    let object = scratch.join(format!("{tag}-frame.o"));
                    let output = Command::new("clang")
                        .args([
                            "-target",
                            target,
                            "-ffreestanding",
                            "-std=c17",
                            "-Werror",
                            "-c",
                        ])
                        .arg(&source)
                        .arg("-o")
                        .arg(&object)
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "{tag}: {}\n{printed}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    code.push_str(&printed);
                }
            }
            code.push_str("int main(void) {\n");
            for n in [0u32, 1, 7, 8, 0x7fff_ffff, u32::MAX] {
                if !target.starts_with("i386") {
                    continue;
                }
                writeln!(
                    code,
                    "if (indexed_frame({n}u) != {}u || advancing_buffers({n}u) != {}u) return 1;",
                    n.wrapping_add(n & 7),
                    n.wrapping_add(n % 120).wrapping_add(n % 9).wrapping_add(3)
                )
                .unwrap();
            }
            code.push_str("if (divide_unsigned(42, 3) != 14 || divide_signed(-42, 3) != -14) return 2; if (remainder_unsigned(42, 5) != 2 || remainder_signed(-42, 5) != -2 || scalar_words(1, 2, 3, 4) != 4) return 3; return 0; }\n");
            let names = velk::render::callee_names(binary.image());
            for function in [
                "indexed_frame",
                "divide_signed",
                "divide_unsigned",
                "__aeabi_idiv",
                "__aeabi_uidiv",
                "__aeabi_uidivmod",
                "__aeabi_idivmod",
                "remainder_unsigned",
                "remainder_signed",
                "scalar_words",
                "advancing_buffers",
            ] {
                let address = binary.find(function).unwrap().addr;
                code = code.replace(
                    &format!("{function}("),
                    &format!("{}(", names.functions[&address]),
                );
            }
            let source = scratch.join(format!("{tag}.c"));
            std::fs::write(
                &source,
                format!(
                    "#include <stdint.h>\n#include <stdbool.h>\n{}",
                    velk::render::combine(&code)
                ),
            )
            .unwrap();
            let executable = scratch.join(format!("{tag}-check"));
            let output = Command::new("clang")
                .args(["-std=c17", "-O2", "-Werror", "-Wno-unused-variable"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{tag}: {}\n{code}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = Command::new(executable).output().unwrap();
            assert!(output.status.success(), "{tag}: {output:?}\n{code}");
        }
    }
}

#[test]
fn aligned_i386_frame_addresses_use_local_storage() {
    let scratch = common::root().join("target/pairs32-aligned-frame");
    std::fs::create_dir_all(&scratch).unwrap();
    let assembly = scratch.join("aligned.s");
    std::fs::write(&assembly, ".text\n.global aligned_frame\n.type aligned_frame, @function\naligned_frame:\npush %ebp\nmov %esp, %ebp\nsub $32, %esp\nmov 8(%ebp), %eax\nand $7, %eax\nlea -13(%ebp), %edx\nand $-4, %edx\nmovb $42, (%edx,%eax)\nmovzbl (%edx,%eax), %eax\nleave\nret\n.size aligned_frame, .-aligned_frame\n").unwrap();
    let mut source = std::fs::read_to_string(&assembly).unwrap();
    source.push_str(".global frame_distance\n.type frame_distance, @function\nframe_distance:\npush %ebp\nmov %esp, %ebp\nsub $32, %esp\nlea -13(%ebp), %eax\nmov %eax, %edx\nand $-4, %edx\nsub %edx, %eax\nleave\nret\n.size frame_distance, .-frame_distance\n");
    std::fs::write(&assembly, source).unwrap();
    let object = scratch.join("aligned.o");
    let output = Command::new("clang")
        .args(["-target", "i386-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut binary = Binary::open(&object).unwrap();
    let mut printed = String::new();
    for function in ["aligned_frame", "frame_distance"] {
        let address = binary.find(function).unwrap().addr;
        printed.push_str(&binary.decompile(address, None, None).unwrap());
    }
    assert!(!printed.contains("velk_entry_stack_pointer"), "{printed}");
    let source = scratch.join("check.c");
    std::fs::write(&source, format!("#include <stdint.h>\n#include <stdbool.h>\n{printed}\nint main(void) {{ for (unsigned n = 0; n < 16; ++n) {{ if (aligned_frame(n) != 42) return 1; }} return frame_distance() != 3; }}\n")).unwrap();
    let executable = scratch.join("check");
    let output = Command::new("clang")
        .args(["-std=c17", "-Werror", "-O2"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{printed}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Command::new(executable).output().unwrap().status.success(),
        "{printed}"
    );
}
