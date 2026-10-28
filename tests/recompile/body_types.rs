use super::*;

fn compile_source(
    scratch: &Path,
    name: &str,
    target: &str,
    input: &Path,
    flags: &[&str],
) -> PathBuf {
    let object = scratch.join(format!("{name}.o"));
    let output = Command::new(compiler())
        .args([
            "-target",
            target,
            "-ffreestanding",
            "-fno-builtin",
            "-fno-optimize-sibling-calls",
            "-c",
        ])
        .args(flags)
        .arg(input)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("fixture compiler starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn link(scratch: &Path, name: &str, objects: &[PathBuf], shared: bool) -> PathBuf {
    let executable = scratch.join(name);
    let mut command = Command::new("ld.lld");
    if shared {
        command.arg("-shared");
    } else {
        command.args(["-e", "main"]);
    }
    let output = command
        .args(objects)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("fixture linker starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

#[test]
fn library_format_and_distant_integer_parameters_compile() {
    let scratch = scratch_dir("body-parameters");
    let object = compile_source(
        &scratch,
        "parameters",
        "x86_64-unknown-linux-gnu",
        &common::root().join("tests/data/body_types.c"),
        &["-O1", "-fPIC", "-fvisibility=hidden"],
    );
    let executable = link(&scratch, "parameters.so", &[object], /* shared */ true);
    let mut binary = Binary::open(&executable).unwrap();
    let address = binary.find("forward_format").unwrap().addr;
    let format = binary.decompile(address, None, None).unwrap();
    assert!(format.contains("const char *"), "{format}");
    assert!(format.contains("vprintf("), "{format}");
    let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["-D", "--cache", "off"])
        .arg(&executable)
        .arg("forward_format")
        .output()
        .unwrap();
    assert!(cli.status.success());
    assert_eq!(String::from_utf8_lossy(&cli.stdout).trim(), format.trim());
    let script = format!(
        "JSON.stringify({{code:velk.open({executable:?}).getFunction('forward_format').decompile()}})"
    );
    let outcome = velk::script::Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    let result: serde_json::Value = serde_json::from_str(&outcome.output).unwrap();
    assert_eq!(result["code"].as_str().unwrap().trim(), format.trim());
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let response = common::mcp_request(
        child,
        &serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{"name":"velk_run_script", "arguments":{"code":script}}
        }),
    );
    let response: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    let result: serde_json::Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["code"].as_str().unwrap().trim(), format.trim());
    let original = binary.analysis(address, None).unwrap().ir.clone();
    for recovered_parameters in [false, true] {
        let mut ir = original.clone();
        ir.params[1].ty = CType::pointer_to(CType::U64);
        let mut symbols = velk::render::callee_names(binary.image());
        if recovered_parameters {
            for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
                if let Stmt::Call {
                    target: Some(target),
                    ..
                } = stmt
                {
                    symbols.function_parameters.insert(
                        *target,
                        vec![
                            CType::pointer_to(CType::Named("const char".into())),
                            CType::pointer_to(CType::Void),
                        ],
                    );
                }
            }
        }
        let format = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(format.contains("(void *)"), "{format}");
        let source = scratch.join("format.c");
        std::fs::write(&source, &format).unwrap();
        let checked = Command::new(compiler())
            .args([
                "-target",
                if cfg!(target_os = "macos") {
                    "x86_64-apple-darwin"
                } else {
                    "x86_64-unknown-linux-gnu"
                },
                "-std=gnu11",
                "-fsyntax-only",
                "-Werror=int-conversion",
                "-Werror=incompatible-pointer-types",
            ])
            .arg(&source)
            .output()
            .unwrap();
        if cfg!(target_os = "macos") || cfg!(target_arch = "x86_64") {
            assert!(
                checked.status.success(),
                "{}\n{format}",
                String::from_utf8_lossy(&checked.stderr)
            );
        }
        let format = format.replace("vprintf(", "format_probe(");
        syntax::run_printed(
            &format!(
                "#include <stdio.h>\n#include <stdarg.h>\n#include <string.h>\nint format_probe(const char *, void *);\n{format}"
            ),
            "char actual[128]; int format_probe(const char *format, void *args) { return vsnprintf(actual, sizeof actual, format, *(va_list *)args); }\nint invoke(const char *format, ...) { va_list args; va_start(args, format); int result = forward_format(format, (void *)&args); va_end(args); return result; }",
            "char expected[128]; for(int i=-128;i<128;++i) { int n=snprintf(expected,sizeof expected,\"%d:%s\",i,\"value\"); if(invoke(\"%d:%s\",i,\"value\")!=n || strcmp(actual,expected)) return 1; } return 0;",
        );
    }
    for arch in ["x86_64", "aarch64", "i386", "armv7"] {
        let target = format!("{arch}-unknown-linux-gnu");
        let object = compile_source(
            &scratch,
            &format!("parameters-{arch}"),
            &target,
            &common::root().join("tests/data/body_types.c"),
            &["-O1", "-fPIC", "-fvisibility=hidden"],
        );
        let executable = link(
            &scratch,
            &format!("parameters-{arch}.so"),
            &[object],
            /* shared */ true,
        );
        let mut binary = Binary::open(&executable).unwrap();
        let names: Vec<_> = (0..9)
            .map(|i| format!("helper{i}"))
            .chain(["pointer_bits".into(), "main".into()])
            .collect();
        let mut definitions = Vec::new();
        for name in names {
            let address = binary.find(&name).unwrap().addr;
            definitions.push(binary.decompile(address, None, None).unwrap());
        }
        let code = velk::render::combine(&definitions.join("\n")).replace("main(", "entry_body(");
        if matches!(arch, "x86_64" | "aarch64") {
            assert!(code.contains("(uintptr_t)envp"), "{arch}: {code}");
        }
        syntax::run_printed(
            &code,
            "",
            "char *args[2]={0}; for(int i=-128;i<128;++i) if((uint32_t)entry_body(i,args,args)!=(uint32_t)(9*i+45+(uintptr_t)args+1)) return 1; return 0;",
        );
    }
}

#[test]
fn i386_stack_protected_register_inputs_preserve_bytes() {
    let scratch = scratch_dir("i386-register-inputs");
    let support = compile_source(
        &scratch,
        "support",
        "i386-unknown-linux-gnu",
        &common::root().join("tests/data/symbolic_streams.c"),
        &["-O2", "-fPIC"],
    );
    for optimization in ["-O2", "-Os"] {
        let object = compile_source(
            &scratch,
            &format!("split{optimization}"),
            "i386-unknown-linux-gnu",
            &common::root().join("tests/data/crackmes/split.c"),
            &[optimization, "-g", "-fPIE", "-fstack-protector-all"],
        );
        let executable = link(
            &scratch,
            &format!("split{optimization}"),
            &[object, support.clone()],
            /* shared */ false,
        );
        let mut binary = Binary::open(&executable).unwrap();
        let mut definitions = Vec::new();
        for name in ["first", "last", "check"] {
            let address = binary.find(name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(!code.contains("unused_arg"), "{code}");
            definitions.push(code);
        }
        let code = velk::render::combine(&definitions.join("\n"));
        let assertions = "unsigned char *s=mmap((void *)0x10000000,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON|MAP_FIXED,-1,0); if(s==MAP_FAILED) return 2; for(unsigned i=0;i<65536;++i) {s[0]=i;s[1]=i>>8;s[2]=i;s[3]=i>>8; int a=s[0]==70 && s[1]==76; int b=s[2]==65 && s[3]==71; if(first((uintptr_t)s)!=a || last((uintptr_t)s)!=b || check((uintptr_t)s)!=(a&&b)) return 1;} memcpy(s,\"FLAG\",4); return check((uintptr_t)s)!=1;";
        let program = Program {
            text: format!(
                "{HEADER}#include <sys/mman.h>\n#include <string.h>\n{code}\nint main(void) {{ {assertions} }}"
            ),
            ranges: Vec::new(),
        };
        let flags: &[&str] = if cfg!(target_os = "macos") {
            &["-arch", "x86_64", "-Wl,-pagezero_size,0x1000"]
        } else {
            &[]
        };
        for level in LEVELS {
            let executable = build(&program, &scratch, level, flags);
            let output = Command::new(executable).output().unwrap();
            assert!(output.status.success(), "{:?}\n{code}", output.status);
        }
    }
}

#[test]
fn i386_array_arguments_to_integer_stubs_compile() {
    let scratch = scratch_dir("i386-array-arguments");
    let support = compile_source(
        &scratch,
        "support",
        "i386-unknown-linux-gnu",
        &common::root().join("tests/data/symbolic_streams.c"),
        &["-O2", "-fPIC"],
    );
    let object = compile_source(
        &scratch,
        "argv",
        "i386-unknown-linux-gnu",
        &common::root().join("tests/data/crackmes/argv.c"),
        &["-O0", "-fno-pie"],
    );
    let executable = link(
        &scratch,
        "argv",
        &[object, support],
        /* shared */ false,
    );
    let mut binary = Binary::open(&executable).unwrap();
    let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
    let definitions = binary.decompile_many(&addresses, None, None).unwrap();
    let code = velk::render::combine(
        &definitions
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
            .join("\n"),
    );
    assert!(code.contains("memset_"), "{code}");
    assert!(code.contains("(uintptr_t)(local_"), "{code}");
    let path = scratch.join("argv.c");
    std::fs::write(&path, &code).unwrap();
    let output = Command::new(compiler())
        .args([
            "-std=gnu11",
            "-fsyntax-only",
            "-Werror=int-conversion",
            "-Werror=incompatible-pointer-types",
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{code}",
        String::from_utf8_lossy(&output.stderr)
    );
    let address = binary.find("memset").unwrap().addr;
    let name = velk::render::callee_names(binary.image()).functions[&address].clone();
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        &format!(
            "for(uint64_t i=0;i<65536;++i) if((uint32_t){name}(i*65537)!=(uint32_t)(i*65537)) return 1; return 0;"
        ),
    );
}
