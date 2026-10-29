//! Proven entries inside a symbol extent, including code beyond the new entry.

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use object::{Object, ObjectSymbol};
use serde_json::{Value, json};
use velk::emulation::{self, Options};
use velk::service::Binary;

#[test]
fn called_and_file_entries_preserve_the_enclosing_code() {
    use std::io::Write;

    for (arch, entry, estimated, shared) in [
        ("x86_64", "caller", false, false),
        ("i386", "caller", false, false),
        ("x86_64", "called", false, false),
        ("i386", "called", false, false),
        ("x86_64", "caller", true, false),
        ("i386", "caller", true, false),
        ("x86_64", "caller", true, true),
        ("i386", "caller", true, true),
    ] {
        let directory = common::root().join(format!(
            "target/discovery-{arch}-{entry}-{estimated}-{shared}"
        ));
        fs::create_dir_all(&directory).unwrap();
        let object = directory.join("code.o");
        let mut compiler = Command::new("clang");
        if entry == "called" {
            compiler.arg("-DENTRY_ONLY");
        }
        if estimated {
            compiler.arg("-DESTIMATED");
        }
        if shared {
            compiler.arg("-DSHARED_FALLTHROUGH");
        }
        let output = compiler
            .arg(format!("--target={arch}-unknown-linux-gnu"))
            .args(["-c", "tests/data/discovery.S", "-o"])
            .arg(&object)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let path = directory.join("code.elf");
        let output = Command::new("ld.lld")
            .arg(&object)
            .args(["-e", entry, "-o"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let bytes = fs::read(&path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let address = |name| {
            file.symbols()
                .find(|symbol| symbol.name().ok() == Some(name))
                .unwrap()
                .address()
        };
        let called = address("called");
        let enclosing = address("enclosing");
        let caller = address("caller");
        let mut binary = Binary::open(&path).unwrap();
        assert_eq!(binary.image().functions.len(), 3);
        assert!(binary.image().functions.contains_key(&called));
        assert!(!binary.image().functions.contains_key(&address("uncalled")));
        assert!(binary.image().functions[&enclosing].size.unwrap() > called - enclosing);
        let printed = binary.decompile(called, None, None).unwrap();
        assert!(printed.contains("7"), "{printed}");
        let outer = binary.decompile(enclosing, None, None).unwrap();
        let outer_addend = if shared { 7 } else { 11 };
        assert!(outer.contains(&outer_addend.to_string()), "{outer}");
        let caller_code = binary.decompile(caller, None, None).unwrap();
        if entry == "caller" {
            assert!(
                caller_code.contains(&format!("sub_{called:x}(")),
                "{caller_code}"
            );
        }
        let navigation = binary.navigation(None).unwrap();
        assert_eq!(
            navigation.graph(called, true, 1).contains(&caller),
            entry == "caller"
        );
        let mut inputs: Vec<u64> = (0..256).collect();
        inputs.extend([0x7fff_ffff, 0xffff_fff5, 0xffff_ffff]);
        for input in inputs {
            for (function, addend) in [(called, 7), (caller, 7), (enclosing, outer_addend)] {
                if function == caller && entry == "called" {
                    continue;
                }
                let report = emulation::run(
                    &binary,
                    &format!("0x{function:x}"),
                    &Options {
                        arguments: vec![emulation::Word::Integer(input)],
                        ..Options::default()
                    },
                    None,
                )
                .unwrap();
                assert_eq!(
                    report.return_value,
                    format!("0x{:x}", (input as u32).wrapping_add(addend))
                );
            }
        }
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["--cache", "off", "-f", "--json"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(listed["functionCount"], 3);
        for operation in ["-D", "-d", "--callers", "--emulate"] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
            if operation == "--emulate" {
                command.arg("--json");
            }
            let output = command
                .args(["--cache", "off", operation])
                .arg(&path)
                .arg(format!("0x{called:x}"))
                .output()
                .unwrap();
            assert!(output.status.success(), "{operation}: {output:?}");
            if operation == "--emulate" {
                let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["returnValue"], "0x7");
            }
        }
        let code = format!(
            "const b=velk.open({}); if(b.functions().length!==3) throw Error('functions'); const f=b.getFunction('{}'); if(f.emulate().returnValue!=='0x7') throw Error('execution'); f.callers(); f.decompile()",
            json!(path),
            called
        );
        let result = velk::script::Engine::new().unwrap().run(&code, None);
        assert!(result.error.is_none(), "{:?}", result.error);
        assert!(result.output.contains("7"), "{}", result.output);
        let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
                child.stdin.take().unwrap(),
                "{}",
                json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code}}})
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_ne!(response["result"]["isError"], true, "{response}");
        assert!(response["result"].to_string().contains("7"), "{response}");
        // Compile the printed functions on the host; their 32-bit result wraps.
        let source = format!(
            "#include <stdint.h>\n{printed}\n{outer}\nint main(void) {{ uint32_t edges[]={{0x7fffffff,0xfffffff5,0xffffffff}}; for(unsigned i=0;i<259;i++) {{ uint32_t value=i<256?i:edges[i-256]; if((uint32_t)sub_{called:x}(value) != value+7u || (uint32_t)enclosing(value) != value+{outer_addend}u) return 1; }} return 0; }}"
        );
        let executable = directory.join("printed");
        common::compiler::compile_file(
            Command::new("clang")
                .args([
                    "-x",
                    "c",
                    "-Werror=implicit-function-declaration",
                    "-fwrapv",
                ])
                .arg(directory.join("printed.c"))
                .arg("-o")
                .arg(&executable),
            &directory.join("printed.c"),
            &source,
        );
        assert!(Command::new(&executable).status().unwrap().success());
        if entry == "caller" {
            let source = format!(
                "#include <stdint.h>\nuint64_t sub_{called:x}(int64_t value) {{ return (uint32_t)value+7u; }}\n{caller_code}\nint main(void) {{ uint32_t edges[]={{0x7fffffff,0xfffffff5,0xffffffff}}; for(unsigned i=0;i<259;i++) {{ uint32_t value=i<256?i:edges[i-256]; if((uint32_t)caller(value) != value+7u) return 1; }} return 0; }}"
            );
            common::compiler::compile_file(
                Command::new("clang")
                    .args([
                        "-std=c11",
                        "-Werror=implicit-function-declaration",
                        "-fwrapv",
                    ])
                    .arg(directory.join("caller.c"))
                    .arg("-o")
                    .arg(&executable),
                &directory.join("caller.c"),
                &source,
            );
            assert!(Command::new(&executable).status().unwrap().success());
        }
    }
}

#[test]
fn runtime_startup_proves_an_interior_entry() {
    let directory = common::root().join("target/discovery-startup");
    fs::create_dir_all(&directory).unwrap();
    let runtime = directory.join("runtime.o");
    common::compiler::compile_x86_64_assembly(
        Path::new("clang"),
        &directory.join("runtime.S"),
        &runtime,
        ".text\n.globl __libc_start_main\n.type __libc_start_main,@function\n__libc_start_main:\nret\n",
    );
    let library = directory.join("runtime.so");
    let output = Command::new("ld.lld")
        .arg("-shared")
        .arg(&runtime)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for (absolute, clobber, direct, static_runtime) in [
        (false, false, false, false),
        (true, false, false, false),
        (false, true, false, false),
        (true, true, false, false),
        (false, false, true, false),
        (false, false, true, true),
        (true, false, true, true),
    ] {
        let object = directory.join("code.o");
        let mut compiler = Command::new("clang");
        compiler.args([
            "--target=x86_64-unknown-linux-gnu",
            "-DSTARTUP",
            "-DENTRY_ONLY",
        ]);
        if absolute {
            compiler.arg("-DABSOLUTE_STARTUP");
        }
        if clobber {
            compiler.arg("-DCLOBBER_ARGUMENT");
        }
        if direct {
            compiler.arg("-DDIRECT_STARTUP");
        }
        if static_runtime {
            compiler.arg("-DSTATIC_STARTUP");
        }
        let output = compiler
            .args(["-c", "tests/data/discovery.S", "-o"])
            .arg(&object)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let path = directory.join(format!(
            "startup-{absolute}-{clobber}-{direct}-{static_runtime}.elf"
        ));
        let runtime_input = if static_runtime { &runtime } else { &library };
        let output = Command::new("ld.lld")
            .arg(&object)
            .arg(runtime_input)
            .args(["-e", "startup", "-o"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let bytes = fs::read(&path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let target = file
            .symbols()
            .find(|symbol| symbol.name().ok() == Some("called"))
            .unwrap()
            .address();
        let mut binary = Binary::open(&path).unwrap();
        assert_eq!(binary.image().functions.contains_key(&target), !clobber);
        if !clobber {
            assert_eq!(binary.find("main").unwrap().addr, target);
            let code = binary.decompile(target, None, None).unwrap();
            assert!(code.contains("7"), "{code}");
            let source = format!(
                "#include <stdint.h>\n#define main recovered_main\n{code}\n#undef main\nint main(void) {{ uint32_t edges[] = {{0, 1, 0x7fffffff, 0xffffffff}}; for (unsigned i = 0; i < 4; i++) if ((uint32_t)recovered_main((int)edges[i], 0) != edges[i] + 7u) return 1; return 0; }}\n"
            );
            let executable = directory.join("printed-startup");
            common::compiler::compile_file(
                Command::new("clang")
                    .args([
                        "-x",
                        "c",
                        "-Werror=implicit-function-declaration",
                        "-fwrapv",
                    ])
                    .arg(directory.join("printed-startup.c"))
                    .arg("-o")
                    .arg(&executable),
                &directory.join("printed-startup.c"),
                &source,
            );
            assert!(Command::new(&executable).status().unwrap().success());
            if !direct {
                let startup = binary.find("startup").unwrap().addr;
                let printed = binary.decompile(startup, None, None).unwrap();
                assert!(
                    printed.contains("int main(int, char **, char **);"),
                    "{printed}"
                );
                let printed_object = directory.join("printed-startup-call.o");
                common::compiler::compile_file(
                    Command::new("clang")
                        .args(["-x", "c", "-Werror=implicit-function-declaration", "-c"])
                        .arg(directory.join("printed-startup-call.c"))
                        .arg("-o")
                        .arg(&printed_object),
                    &directory.join("printed-startup-call.c"),
                    &printed,
                );
            }
            let output = Command::new("ld.lld")
                .arg(&object)
                .arg(runtime_input)
                .args(["-s", "-e", "startup", "-o"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let mut binary = Binary::open(&path).unwrap();
            assert!(binary.image().stripped);
            assert_eq!(binary.find("main").unwrap().addr, target);
            if !absolute && !direct {
                let printed = binary.decompile(target, None, None).unwrap();
                assert!(printed.contains("main("), "{printed}");
                let source = format!(
                    "#include <stdint.h>\n#define main recovered_main\n{printed}\n#undef main\nint main(void) {{ int values[] = {{0, 1, -1, 2147483647}}; for (unsigned i = 0; i < 4; i++) if ((uint32_t)recovered_main(values[i], 0) != (uint32_t)values[i] + 7u) return 1; return 0; }}\n"
                );
                let executable = directory.join("printed-main");
                common::compiler::compile_file(
                    Command::new("clang")
                        .args(["-std=c11", "-Werror=implicit-function-declaration"])
                        .arg(directory.join("printed-main.c"))
                        .arg("-o")
                        .arg(&executable),
                    &directory.join("printed-main.c"),
                    &source,
                );
                assert!(Command::new(&executable).status().unwrap().success());
            }
            let code = format!(
                "velk.open({}).getFunction('main').emulate().returnValue",
                json!(path)
            );
            let result = velk::script::Engine::new().unwrap().run(&code, None);
            assert!(result.error.is_none(), "{:?}", result.error);
            assert_eq!(result.output, "0x7");
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["--cache", "off", "--emulate"])
                .arg(&path)
                .args(["main", "--json"])
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["returnValue"], "0x7");
            let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code}}});
            let output = common::mcp_request(child, &request);
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_ne!(response["result"]["isError"], true, "{response}");
            assert!(response["result"].to_string().contains("0x7"), "{response}");
        }
    }
}

#[test]
fn aarch64_runtime_startup_names_main() {
    let directory = common::root().join("target/discovery-aarch64-startup");
    fs::create_dir_all(&directory).unwrap();
    let runtime_source = directory.join("runtime.S");
    let runtime = directory.join("runtime.o");
    common::compiler::compile_file(
        Command::new("clang")
            .args(["--target=aarch64-unknown-linux-gnu", "-c"])
            .arg(&runtime_source)
            .arg("-o")
            .arg(&runtime),
        &runtime_source,
        ".text\n.globl __libc_start_main\n.type __libc_start_main,%function\n__libc_start_main: ret\n",
    );
    let library = directory.join("runtime.so");
    let output = Command::new("ld.lld")
        .args(["-shared", "-o"])
        .arg(&library)
        .arg(&runtime)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let source = directory.join("startup.S");
    let object = directory.join("startup.o");
    common::compiler::compile_file(
        Command::new("clang")
            .args(["--target=aarch64-unknown-linux-gnu", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object),
        &source,
        ".text\n.globl _start\n_start:\n mov x29, #0\n mov x30, #0\n mov x5, x0\n ldr x1, [sp]\n add x2, sp, #8\n mov x6, sp\n adrp x0, called\n add x0, x0, :lo12:called\n mov x3, #0\n mov x4, #0\n bl __libc_start_main\n brk #0\n.globl called\n.type called,%function\ncalled:\n mov w0, #7\n ret\n",
    );
    let path = directory.join("startup.elf");
    let link = |strip: bool| {
        let mut command = Command::new("ld.lld");
        command.args(["--no-relax", "-e", "_start"]);
        if strip {
            command.arg("-s");
        }
        let output = command
            .arg(&object)
            .arg(&library)
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    };
    link(false);
    let bytes = fs::read(&path).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let address = file
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("called"))
        .unwrap()
        .address();
    link(true);
    let binary = Binary::open(&path).unwrap();
    assert_eq!(binary.find("main").unwrap().addr, address);
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--cache", "off", "--emulate"])
        .arg(&path)
        .args(["main", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["returnValue"], "0x7");
    let static_path = directory.join("static-startup.elf");
    let static_symbols = directory.join("static-startup-symbols.elf");
    let output = Command::new("ld.lld")
        .args(["--no-relax", "-e", "_start"])
        .arg(&object)
        .arg(&runtime)
        .arg("-o")
        .arg(&static_symbols)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let bytes = fs::read(&static_symbols).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let static_address = file
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("called"))
        .unwrap()
        .address();
    let output = Command::new("ld.lld")
        .args(["--no-relax", "-s", "-e", "_start"])
        .arg(&object)
        .arg(&runtime)
        .arg("-o")
        .arg(&static_path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let static_binary = Binary::open(&static_path).unwrap();
    assert!(static_binary.image().stripped);
    assert_eq!(static_binary.find("main").unwrap().addr, static_address);
    let report = emulation::run(&static_binary, "main", &Options::default(), None).unwrap();
    assert_eq!(report.return_value, "0x7");
    let got_source = directory.join("got.S");
    let got_object = directory.join("got.o");
    let got_assembly = fs::read_to_string(&source)
        .unwrap()
        .replace("adrp x0, called", "adrp x0, :got:called")
        .replace("add x0, x0, :lo12:called", "ldr x0, [x0, :got_lo12:called]");
    common::compiler::compile_file(
        Command::new("clang")
            .args(["--target=aarch64-unknown-linux-gnu", "-c"])
            .arg(&got_source)
            .arg("-o")
            .arg(&got_object),
        &got_source,
        &got_assembly,
    );
    let got_path = directory.join("got.elf");
    let output = Command::new("ld.lld")
        .args(["--no-relax", "-s", "-e", "_start"])
        .arg(&got_object)
        .arg(&library)
        .arg("-o")
        .arg(&got_path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let got_binary = Binary::open(&got_path).unwrap();
    assert_eq!(
        got_binary.find("main").unwrap().name.as_deref(),
        Some("main")
    );
    let report = emulation::run(&got_binary, "main", &Options::default(), None).unwrap();
    assert_eq!(report.return_value, "0x7");
}

#[test]
fn i386_runtime_startup_names_main() {
    let directory = common::root().join("target/discovery-i386-startup");
    fs::create_dir_all(&directory).unwrap();
    let runtime_source = directory.join("runtime.S");
    let runtime = directory.join("runtime.o");
    common::compiler::compile_file(
        Command::new("clang")
            .args(["--target=i386-unknown-linux-gnu", "-c"])
            .arg(&runtime_source)
            .arg("-o")
            .arg(&runtime),
        &runtime_source,
        ".text\n.globl __libc_start_main\n.type __libc_start_main,@function\n__libc_start_main: ret\n",
    );
    let library = directory.join("runtime.so");
    let output = Command::new("ld.lld")
        .args(["-shared", "-o"])
        .arg(&library)
        .arg(&runtime)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for (clobber, static_runtime) in [(false, false), (true, false), (false, true), (true, true)] {
        let source = directory.join("startup.S");
        let object = directory.join("startup.o");
        let assembly = if static_runtime {
            let extra = if clobber { "pop %eax\n" } else { "" };
            format!(
                ".text\n.globl _start\n_start:\n xor %ebp, %ebp\n pop %esi\n mov %esp, %ecx\n and $-16, %esp\n push %eax\n push %esp\n push %edx\n push $0\n push $0\n push %ecx\n push %esi\n push $called\n {extra} call __libc_start_main\n hlt\n.globl called\n.type called,@function\ncalled:\n mov $7, %eax\n ret\n"
            )
        } else {
            let extra = if clobber { "pop %eax\n" } else { "" };
            format!(
                ".text\n.globl _start\n_start:\n push $called\n {extra} call __libc_start_main@PLT\n hlt\n.globl called\n.type called,@function\ncalled:\n mov $7, %eax\n ret\n"
            )
        };
        common::compiler::compile_file(
            Command::new("clang")
                .args(["--target=i386-unknown-linux-gnu", "-c"])
                .arg(&source)
                .arg("-o")
                .arg(&object),
            &source,
            &assembly,
        );
        let path = directory.join("startup.elf");
        let mut linker = Command::new("ld.lld");
        linker.args(["-s", "-e", "_start"]).arg(&object);
        if static_runtime {
            linker.arg(&runtime);
        } else {
            linker.arg(&library);
        }
        let output = linker.arg("-o").arg(&path).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let binary = Binary::open(&path).unwrap();
        let found = binary.image().functions.values().any(|function| {
            function.name.as_deref() == Some("main")
                || function.aliases.iter().any(|name| name == "main")
        });
        assert_eq!(found, !clobber);
        if !clobber {
            let report = emulation::run(&binary, "main", &Options::default(), None).unwrap();
            assert_eq!(report.return_value, "0x7");
        }
    }
}
