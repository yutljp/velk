mod common;

use std::fs;
use std::process::Command;
use velk::service::Binary;

const SOURCE: &str = r#"
int sum(int count, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, count);
    int total = 0;
    for (int i = 0; i < count; ++i) total += __builtin_va_arg(args, int);
    __builtin_va_end(args);
    return total;
}
"#;

#[test]
fn integer_lists_recompile_across_target_abis() {
    let dir = common::root().join("target/variadic-tests");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("input.c");
    fs::write(&source, SOURCE).unwrap();
    for (name, target) in [
        ("sysv", "x86_64-unknown-linux-gnu"),
        ("aapcs", "aarch64-unknown-linux-gnu"),
        ("apple", "arm64-apple-macos11"),
    ] {
        let object = dir.join(format!("{name}.o"));
        let output = Command::new("clang")
            .args(["-target", target, "-O0", "-g", "-c"])
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
        let mut binary = Binary::open(&object).unwrap();
        let address = binary
            .find("sum")
            .or_else(|_| binary.find("_sum"))
            .unwrap()
            .addr;
        let code = binary.decompile(address, None, None).unwrap();
        fs::write(dir.join(format!("{name}.c")), &code).unwrap();
        assert!(code.contains("va_start("), "{name}: {code}");
        assert!(code.contains("va_arg("), "{name}: {code}");
        assert!(code.contains("va_end("), "{name}: {code}");
        assert!(!code.contains("velk_entry_stack_pointer"), "{name}: {code}");
        let driver = format!(
            r#"
#include <stdint.h>
{code}
#define sum expected
{SOURCE}
#undef sum
int main(void) {{
    for (int count = -1; count <= 12; ++count) {{
        int a = sum(count, (char)-7, (short)12, -21, 33, -45, 57, -69, 81, -93, 105, -117, 129);
        int b = expected(count, (char)-7, (short)12, -21, 33, -45, 57, -69, 81, -93, 105, -117, 129);
        if (a != b) return 1;
    }}
    if (sum(8, 2147483647, 1, 2147483647, 1, -1, -1, 2147483647, 1)
        != expected(8, 2147483647, 1, 2147483647, 1, -1, -1, 2147483647, 1)) return 2;
    return 0;
}}
"#
        );
        let driver_path = dir.join(format!("{name}-driver.c"));
        fs::write(&driver_path, driver).unwrap();
        for level in ["-O0", "-O2"] {
            let executable = dir.join(format!("{name}{level}"));
            let output = Command::new("clang")
                .args([
                    level,
                    "-fwrapv",
                    "-fno-strict-aliasing",
                    "-Werror=implicit-function-declaration",
                ])
                .arg(&driver_path)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{name} {level}"
            );
        }
    }
}

#[test]
fn unoptimized_metrics_lists_use_stdarg() {
    for fixture in ["calls.x86_64.O0.debug.elf", "calls.aarch64.O0.debug.elf"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join("metrics").join(fixture)).unwrap();
        let address = binary.find("sum_varargs").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("va_arg("), "{fixture}: {code}");
    }
}

#[test]
fn uncertain_integer_layouts_keep_the_original_accesses() {
    use velk::ir::{BinOp, Expr, Stmt};
    use velk::loader::Format;
    let mut binary =
        Binary::open(&common::fixtures_dir().join("metrics/calls.x86_64.O0.debug.elf")).unwrap();
    let address = binary.find("sum_varargs").unwrap().addr;
    let original = binary.analysis(address, None).unwrap().ir.clone();
    let symbols = velk::render::callee_names(binary.image());
    for mutation in 0..9 {
        let mut ir = original.clone();
        let mut symbols = velk::render::Symbols {
            target_format: symbols.target_format,
            ..Default::default()
        };
        match mutation {
            0 => symbols.target_format = None,
            1 => symbols.target_format = Some(Format::Pe),
            2 => {
                let mut changed = false;
                for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                    if let Stmt::Brif {
                        rhs: Expr::Const(limit),
                        ..
                    } = stmt
                        && *limit == 40
                    {
                        *limit = 48;
                        changed = true;
                    }
                }
                assert!(changed);
            }
            3 => {
                let mut changed = false;
                for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                    if let Stmt::Store {
                        value:
                            Expr::Bin {
                                op: BinOp::Add,
                                rhs,
                                ..
                            },
                        width: 8,
                        ..
                    } = stmt
                        && matches!(rhs.as_ref(), Expr::Const(8))
                    {
                        **rhs = Expr::Const(16);
                        changed = true;
                    }
                }
                assert!(changed);
            }
            4 => {
                let mut changed = false;
                for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                    if let Stmt::Store {
                        value: Expr::Const(offset),
                        width: 4,
                        ..
                    } = stmt
                        && *offset == 8
                    {
                        *offset = 16;
                        changed = true;
                    }
                }
                assert!(changed);
            }
            5 => {
                let mut changed = false;
                for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                    if let Stmt::Br {
                        target: Some(target),
                    } = stmt
                    {
                        *target = u64::MAX;
                        changed = true;
                        break;
                    }
                }
                assert!(changed);
            }
            6 => {
                let mut changed = false;
                for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                    if let Stmt::Brif {
                        lhs: Expr::Bin { lhs, .. },
                        rhs: Expr::Const(40),
                        ..
                    } = stmt
                        && let Expr::Reg { width, .. } = lhs.as_mut()
                    {
                        *width = 16;
                        changed = true;
                    }
                }
                assert!(changed);
            }
            7 => {
                symbols.reserved_names.insert("va_arg".to_owned());
            }
            _ => {
                let Some(Stmt::Ret { value }) = ir
                    .blocks
                    .last_mut()
                    .and_then(|block| block.stmts.last_mut())
                else {
                    panic!("return statement");
                };
                *value = Expr::reg(u16::MAX, 64);
            }
        }
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(!code.contains("va_arg("), "mutation {mutation}: {code}");
        assert!(!code.contains("va_start("), "mutation {mutation}: {code}");
        assert!(
            code.contains("velk_entry_stack_pointer"),
            "mutation {mutation}: {code}"
        );
    }
}

#[test]
fn wider_and_aligned_arguments_do_not_trigger_partial_recovery() {
    let dir = common::root().join("target/variadic-layout-tests");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("input.c");
    fs::write(
        &source,
        r#"
long long aligned_values(int count, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, count);
    __int128 total = __builtin_va_arg(ap, int);
    for (int i = 0; i < count; ++i) total += __builtin_va_arg(ap, __int128);
    total += __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return (long long)total;
}
"#,
    )
    .unwrap();
    for (name, target) in [
        ("sysv", "x86_64-unknown-linux-gnu"),
        ("aapcs", "aarch64-unknown-linux-gnu"),
        ("apple", "arm64-apple-macos11"),
    ] {
        let object = dir.join(format!("{name}.o"));
        let output = Command::new("clang")
            .args(["-target", target, "-O0", "-g", "-c"])
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
        let mut binary = Binary::open(&object).unwrap();
        let address = binary
            .find("aligned_values")
            .or_else(|_| binary.find("_aligned_values"))
            .unwrap()
            .addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(!code.contains("va_arg("), "{name}: {code}");
        assert!(!code.contains("va_start("), "{name}: {code}");
    }
}

#[test]
fn apple_lists_require_all_named_parameters() {
    let dir = common::root().join("target/variadic-named-tests");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("input.c");
    fs::write(
        &source,
        r#"
int skipped(int count, int unused, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, unused);
    int total = 0;
    for (int i = 0; i < count; ++i) total += __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return total;
}
"#,
    )
    .unwrap();
    let object = dir.join("input.o");
    let output = Command::new("clang")
        .args(["-target", "arm64-apple-macos11", "-O2", "-g", "-c"])
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
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("_skipped").unwrap().addr;
    let ir = binary.analysis(address, None).unwrap().ir.clone();
    let symbols = velk::render::callee_names(binary.image());
    assert_eq!(symbols.variadic_functions.get(&address), Some(&2));
    assert_eq!(ir.params.len(), 1);
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("va_start("), "{code}");
    assert!(!code.contains("va_arg("), "{code}");
}

#[test]
fn eight_byte_integer_arguments_keep_their_width_and_stack_alignment() {
    let dir = common::root().join("target/variadic-wide-tests");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("input.c");
    let text = SOURCE
        .replace("int sum(", "long long sum(")
        .replace("int total =", "long long total =")
        .replace("va_arg(args, int)", "va_arg(args, long long)");
    fs::write(&source, &text).unwrap();
    for (name, target) in [
        ("sysv", "x86_64-unknown-linux-gnu"),
        ("aapcs", "aarch64-unknown-linux-gnu"),
        ("apple", "arm64-apple-macos11"),
    ] {
        let object = dir.join(format!("{name}.o"));
        let output = Command::new("clang")
            .args(["-target", target, "-O0", "-g", "-c"])
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
        let mut binary = Binary::open(&object).unwrap();
        let address = binary
            .find("sum")
            .or_else(|_| binary.find("_sum"))
            .unwrap()
            .addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(
            code.contains("va_arg(varargs, long long)"),
            "{name}: {code}"
        );
        let driver = format!(
            r#"
#include <stdint.h>
{code}
#define sum expected
{text}
#undef sum
int main(void) {{
    for (int count = 0; count <= 12; ++count) {{
        long long a = sum(count, -0x123456789LL, 0x234567890LL, -3LL, 4LL, -5LL, 6LL, -7LL, 8LL, -9LL, 10LL, -11LL, 0x345678901LL);
        long long b = expected(count, -0x123456789LL, 0x234567890LL, -3LL, 4LL, -5LL, 6LL, -7LL, 8LL, -9LL, 10LL, -11LL, 0x345678901LL);
        if (a != b) return 1;
    }}
    return 0;
}}
"#
        );
        let driver_path = dir.join(format!("{name}.c"));
        fs::write(&driver_path, driver).unwrap();
        for level in ["-O0", "-O2"] {
            let executable = dir.join(format!("{name}{level}"));
            let output = Command::new("clang")
                .args([
                    level,
                    "-fwrapv",
                    "-fno-strict-aliasing",
                    "-Werror=implicit-function-declaration",
                ])
                .arg(&driver_path)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{name} {level}"
            );
        }
    }
}

#[test]
fn promoted_floating_arguments_use_the_floating_register_state() {
    let dir = common::root().join("target/variadic-float-tests");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("input.c");
    let text = SOURCE
        .replace("int sum(", "double sum(")
        .replace("int total =", "double total =")
        .replace("va_arg(args, int)", "va_arg(args, double)");
    fs::write(&source, &text).unwrap();
    for (name, target) in [
        ("sysv", "x86_64-unknown-linux-gnu"),
        ("aapcs", "aarch64-unknown-linux-gnu"),
        ("apple", "arm64-apple-macos11"),
    ] {
        let object = dir.join(format!("{name}.o"));
        let output = Command::new("clang")
            .args(["-target", target, "-O0", "-g", "-c"])
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
        let mut binary = Binary::open(&object).unwrap();
        let address = binary
            .find("sum")
            .or_else(|_| binary.find("_sum"))
            .unwrap()
            .addr;
        let code = binary.decompile(address, None, None).unwrap();
        fs::write(dir.join(format!("{name}-output.c")), &code).unwrap();
        assert!(code.contains("va_arg(varargs, double)"), "{name}: {code}");
        let driver = format!(
            r#"
#include <stdint.h>
{code}
#define sum expected
{text}
#undef sum
int main(void) {{
    for (int count = -1; count <= 12; ++count) {{
        double a = sum(count, (float)1.25, -2.5, 3.75, -4.0, 5.25, -6.5, 7.75, -8.0, 9.25, -10.5, 11.75, -12.0);
        double b = expected(count, (float)1.25, -2.5, 3.75, -4.0, 5.25, -6.5, 7.75, -8.0, 9.25, -10.5, 11.75, -12.0);
        if (a != b) return 1;
    }}
    return 0;
}}
"#
        );
        let driver_path = dir.join(format!("{name}-driver.c"));
        fs::write(&driver_path, driver).unwrap();
        for level in ["-O0", "-O2"] {
            let executable = dir.join(format!("{name}{level}"));
            let output = Command::new("clang")
                .args([
                    level,
                    "-fwrapv",
                    "-fno-strict-aliasing",
                    "-Werror=implicit-function-declaration",
                ])
                .arg(&driver_path)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{name} {level}"
            );
        }
    }
}
