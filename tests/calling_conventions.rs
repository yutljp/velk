mod common;

use std::fs;
use std::process::Command;

use velk::service::Binary;

#[test]
fn stored_function_addresses_recompile_across_architectures() {
    let directory = common::root().join("target/stored-function-addresses");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("callbacks.c");
    fs::write(
        &source,
        r#"
int increment(int x) { return x + 7; }
int variable(int x) {
    int (*volatile function)(int) = increment;
    return function(x);
}
int structure(int x) {
    struct { int padding; int (*volatile function)(int); } callbacks;
    callbacks.padding = 0;
    callbacks.function = increment;
    return callbacks.function(x);
}
int table(int x) {
    int (*volatile callbacks[2])(int);
    callbacks[0] = increment;
    callbacks[1] = increment;
    return callbacks[1](x);
}
"#,
    )
    .unwrap();
    for target in [
        "x86_64-unknown-linux-gnu",
        "i386-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "armv7-unknown-linux-gnueabi",
        "x86_64-pc-windows-msvc",
    ] {
        let object = directory.join(format!("{target}.o"));
        let compiled = Command::new("clang")
            .args([
                "-target",
                target,
                "-O0",
                "-fno-pic",
                "-fno-pie",
                "-fno-stack-protector",
                "-c",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}");
        let mut binary = Binary::open(&object).unwrap();
        let mut code = String::from("#include <stdint.h>\n#include <stdbool.h>\n");
        for name in ["increment", "variable", "structure", "table"] {
            let address = binary.find(name).unwrap().addr;
            let summary = binary.summary(address, None).unwrap();
            assert_eq!(
                summary["signature"]["parameterCount"], 1,
                "{target} {name}: {summary}"
            );
            if name != "increment" {
                assert_eq!(
                    summary["calls"][0]["signature"]["parameterCount"], 1,
                    "{target} {name}: {summary}"
                );
                assert_eq!(
                    summary["calls"][0]["indirect"], false,
                    "{target} {name}: {summary}"
                );
            }
            code.push_str(&binary.decompile(address, None, None).unwrap());
        }
        code = velk::render::combine(&code);
        code.push_str(
            r#"
int main(void) {
    for (int x = -1024; x <= 1024; ++x) {
        if ((int32_t)variable(x) != x + 7) return 1;
        if ((int32_t)structure(x) != x + 7) return 2;
        if ((int32_t)table(x) != x + 7) return 3;
    }
    return 0;
}
"#,
        );
        let driver = directory.join(format!("{target}.c"));
        fs::write(&driver, &code).unwrap();
        for optimization in ["-O0", "-O2"] {
            let executable = directory.join(format!("{target}{optimization}"));
            let compiled = Command::new("clang")
                .args([
                    optimization,
                    "-std=c11",
                    "-Werror=implicit-function-declaration",
                ])
                .arg(&driver)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(compiled.status.success(), "{target}: {compiled:?}\n{code}");
            let result = Command::new(executable).output().unwrap();
            assert!(result.status.success(), "{target}: {result:?}\n{code}");
        }
    }
}

#[test]
fn preserved_arguments_and_boolean_guards_recompile() {
    let directory = common::root().join("target/calling-conventions");
    fs::create_dir_all(&directory).unwrap();
    let assembly = directory.join("arguments.s");
    let object = directory.join("arguments.o");
    fs::write(
        &assembly,
        r#"
.text
.globl leaf
.type leaf,@function
leaf:
    leal (%rdi,%rdi,2), %eax
    ret
.size leaf, .-leaf
.globl use
.type use,@function
use:
    call leaf
    addl %esi, %eax
    ret
.size use, .-use
.globl caller
.type caller,@function
caller:
    movl %edi, %esi
    xorl $5, %esi
    jmp use
.size caller, .-caller
.globl recursive
.type recursive,@function
recursive:
    testl %edi, %edi
    je .Lbase
    subl $1, %edi
    call recursive
    addl %esi, %eax
    ret
.Lbase:
    xorl %eax, %eax
    ret
.size recursive, .-recursive
.globl guarded
.type guarded,@function
guarded:
    xorl %edx, %edx
    movl $3, %eax
    testl %edi, %edi
    je .Ljoin
.Lloop:
    leal 7(%rax), %ecx
    movl $1, %edx
    subq $1, %rax
    jns .Lloop
.Ljoin:
    testl %esi, %esi
    jne .Lfail
    testb %dl, %dl
    je .Lzero
    movl %ecx, %eax
    ret
.Lzero:
    movl %edi, %eax
    ret
.Lfail:
    movl $-1, %eax
    ret
.size guarded, .-guarded
"#,
    )
    .unwrap();
    let compiled = Command::new("clang")
        .args(["-target", "x86_64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let mut code = String::from("#include <stdint.h>\n#include <stdbool.h>\n");
    for (name, count) in [
        ("leaf", 1),
        ("use", 2),
        ("caller", 1),
        ("guarded", 2),
        ("recursive", 2),
    ] {
        let address = binary.find(name).unwrap().addr;
        let summary = binary.summary(address, None).unwrap();
        assert_eq!(
            summary["signature"]["parameterCount"], count,
            "{name}: {summary}"
        );
        code.push_str(&binary.decompile(address, None, None).unwrap());
    }
    code = velk::render::combine(&code);
    code.push_str(
        r#"
int main(void) {
    for (int x = -1024; x <= 1024; ++x) {
        if ((int32_t)caller(x) != x * 3 + (x ^ 5)) return 1;
        for (int y = -8; y <= 8; ++y) {
            if ((int32_t)use(x, y) != x * 3 + y) return 2;
            if ((int32_t)guarded(x, y) != (y ? -1 : x ? 7 : 0)) return 3;
        }
    }
    for (int n = 0; n <= 20; ++n) {
        for (int b = -16; b <= 16; ++b) {
            if ((int32_t)recursive(n, b) != n * b) return 4;
        }
    }
    return 0;
}
"#,
    );
    let source = directory.join("arguments.c");
    fs::write(&source, &code).unwrap();
    for optimization in ["-O0", "-O2"] {
        let executable = directory.join(format!("arguments{optimization}"));
        let compiled = Command::new("clang")
            .args([
                optimization,
                "-std=c11",
                "-Werror=implicit-function-declaration",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}\n{code}");
        let result = Command::new(executable).output().unwrap();
        assert!(result.status.success(), "{result:?}\n{code}");
    }
}
