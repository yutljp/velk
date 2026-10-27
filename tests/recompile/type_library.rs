use super::*;

#[test]
fn every_linux_header_fixture_function_compiles() {
    let scratch = scratch_dir("linux-type-library-syntax");
    let source = scratch.join("check.c");
    for arch in ["x86_64", "arm64"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("type_library_linux_{arch}")))
                .unwrap();
        let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
        assert!(!addresses.is_empty());
        for address in &addresses {
            let code = binary
                .decompile_with_dependencies(*address, None, None)
                .unwrap()
                .code;
            std::fs::write(
                &source,
                format!("#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n{code}"),
            )
            .unwrap();
            let output = Command::new(compiler())
                .args(FLAGS)
                .args(["-fsyntax-only", "-Wno-implicit-function-declaration"])
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{arch} {address:#x}:\n{code}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        eprintln!("{arch}: {0}/{0} compile", addresses.len());
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn header_prototypes_print_arguments_results_and_record_fields() {
    for arch in ["arm64", "x86_64"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("type_library_{arch}"))).unwrap();
        let address = binary.find("library_group").unwrap().addr;
        let group = binary.decompile(address, None, None).unwrap();
        assert!(group.contains("struct group *"), "{group}");
        assert!(group.contains("->gr_gid"), "{group}");
        assert!(group.contains("getgrgid_r(7,"), "{group}");
        let code = format!(
            "struct group;\nint getgrgid_r(unsigned int, struct group *, char *, size_t, struct group **);\n{group}"
        );
        syntax::run_printed(
            &code,
            "int getgrgid_r(unsigned int gid, struct group *entry, char *buffer, size_t size, struct group **result) { entry->gr_gid = (gid == 7 && !buffer && !size && !result) ? 0x80000001U : 0; return 0; }",
            "struct group entry = {0}; return (uint32_t)library_group(&entry) != 0x80000001U;",
        );
        let address = binary.find("library_group_at").unwrap().addr;
        let indexed = binary.decompile(address, None, None).unwrap();
        assert!(indexed.contains(".gr_gid"), "{indexed}");
        let combined = velk::render::combine(&format!("{group}{indexed}"));
        assert_eq!(combined.matches("struct group {").count(), 1, "{combined}");
        syntax::run_printed(
            &format!(
                "struct group;\nint getgrgid_r(unsigned int, struct group *, char *, size_t, struct group **);\n{combined}"
            ),
            "int getgrgid_r(unsigned int gid, struct group *entry, char *buffer, size_t size, struct group **result) { entry->gr_gid = gid; return buffer || size || result; }",
            "struct group entries[2] = {0}; entries[1].gr_gid = 0xfedcba98U; return (uint32_t)library_group(entries) != 7 || (uint32_t)library_group_at(entries, 0) != 7 || (uint32_t)library_group_at(entries, 1) != 0xfedcba98U;",
        );
        let address = binary.find("library_wide_length").unwrap().addr;
        let wide = binary.decompile(address, None, None).unwrap();
        assert!(wide.contains("const int *"), "{wide}");
        assert!(wide.contains("return wcslen("), "{wide}");
        assert!(wide.contains("size_t library_wide_length("), "{wide}");
        syntax::run_printed(
            &format!("size_t wcslen(const int *);\n{wide}"),
            "size_t wcslen(const int *text) { return UINT64_C(0x100000000) + (unsigned int)text[0]; }",
            "int text[] = {37, 0}; return library_wide_length(text) != UINT64_C(0x100000025);",
        );
    }
}

#[test]
fn linux_header_calls_and_layouts_compile_and_preserve_values() {
    for arch in ["x86_64", "arm64"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("type_library_linux_{arch}")))
                .unwrap();
        let address = binary.find("linux_group").unwrap().addr;
        let group = binary.decompile(address, None, None).unwrap();
        assert!(group.contains("->gr_gid"), "{group}");
        syntax::run_printed(
            &format!(
                "struct group;\nint getgrgid_r(unsigned int, struct group *, char *, size_t, struct group **);\n{group}"
            ),
            "int getgrgid_r(unsigned int gid, struct group *entry, char *buffer, size_t size, struct group **result) { entry->gr_gid = (gid == 7 && !buffer && !size && !result) ? 0xfedcba98U : 0; return 0; }",
            "struct group entry = {0}; return (uint32_t)linux_group(&entry) != 0xfedcba98U;",
        );
        for (function, declaration, support, assertions) in [
            (
                "linux_file",
                "int fsync(int);",
                "int fsync(int fd) { return fd == -7 ? -19 : 0; }",
                "return (int32_t)linux_file(-7) != -19;",
            ),
            (
                "linux_process",
                "int kill(int, int);",
                "int kill(int process, int signal) { return process == -7 && !signal ? -19 : 0; }",
                "return (int32_t)linux_process(-7) != -19;",
            ),
            (
                "linux_memory",
                "int mprotect(void *, size_t, int);",
                "int mprotect(void *address, size_t size, int protection) { return !address && size == UINT64_C(0x100000025) && protection == 1 ? -19 : 0; }",
                "return (int32_t)linux_memory(0, UINT64_C(0x100000025)) != -19;",
            ),
            (
                "linux_socket",
                "int shutdown(int, int);",
                "int shutdown(int fd, int how) { return fd == -7 && !how ? -19 : 0; }",
                "return (int32_t)linux_socket(-7) != -19;",
            ),
            (
                "linux_thread",
                "int test_pthread_kill(unsigned long, int);",
                "int test_pthread_kill(unsigned long thread, int signal) { return thread == UINT64_C(0x100000025) && !signal ? -19 : 0; }",
                "return (int32_t)linux_thread(UINT64_C(0x100000025)) != -19;",
            ),
        ] {
            let address = binary.find(function).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            // The host's pthread_t can differ from the target's integer type.
            let code = replace_c_identifier(&code, "pthread_kill", "test_pthread_kill");
            syntax::run_printed(&format!("{declaration}\n{code}"), support, assertions);
        }
    }
}

#[test]
fn windows_header_calls_compile_and_preserve_llp64_values() {
    let mut binary =
        Binary::open(&common::fixtures_dir().join("type_library_windows.win64.exe")).unwrap();
    let address = binary.find("windows_time").unwrap().addr;
    let time = binary.decompile(address, None, None).unwrap();
    assert!(time.contains("->dwHighDateTime"), "{time}");
    syntax::run_printed(
        &format!("struct _FILETIME;\nvoid GetSystemTimeAsFileTime(struct _FILETIME *);\n{time}"),
        "void GetSystemTimeAsFileTime(struct _FILETIME *time) { time->dwHighDateTime = 0xfedcba98U; }",
        "struct _FILETIME time = {0}; return (uint32_t)windows_time(&time) != 0xfedcba98U;",
    );
    for (function, declaration, support, assertions) in [
        (
            "windows_file",
            "uint32_t GetFileType(void *);",
            "uint32_t GetFileType(void *file) { return file == (void *)(uintptr_t)0x100000025 ? 0xfedcba98U : 0; }",
            "return (uint32_t)windows_file((void *)(uintptr_t)0x100000025) != 0xfedcba98U;",
        ),
        (
            "windows_process",
            "void *OpenProcess(uint32_t, int, uint32_t);",
            "void *OpenProcess(uint32_t access, int inherit, uint32_t process) { return access == 0x400 && !inherit && process == 0xfedcba98U ? (void *)(uintptr_t)0x100000025 : 0; }",
            "return (uintptr_t)windows_process(0xfedcba98U) != UINT64_C(0x100000025);",
        ),
        (
            "windows_memory",
            "void *VirtualAlloc(void *, unsigned long long, uint32_t, uint32_t);",
            "void *VirtualAlloc(void *address, unsigned long long size, uint32_t kind, uint32_t protection) { return !address && size == UINT64_C(0x100000025) && kind == 0x3000 && protection == 4 ? (void *)(uintptr_t)0x100000037 : 0; }",
            "return (uintptr_t)windows_memory(UINT64_C(0x100000025)) != UINT64_C(0x100000037);",
        ),
        (
            "windows_registry",
            "struct HKEY__;\nint32_t RegCloseKey(struct HKEY__ *);",
            "int32_t RegCloseKey(struct HKEY__ *key) { return (uintptr_t)key == UINT64_C(0x100000025) ? INT32_MIN : 0; }",
            "return (int32_t)windows_registry((void *)(uintptr_t)0x100000025) != INT32_MIN;",
        ),
        (
            "windows_socket",
            "unsigned long long socket(int, int, int);",
            "unsigned long long socket(int family, int kind, int protocol) { return family == 2 && kind == 1 && protocol == 6 ? UINT64_C(0x100000025) : 0; }",
            "return (uintptr_t)windows_socket() != UINT64_C(0x100000025);",
        ),
        (
            "windows_thread",
            "uint32_t GetCurrentThreadId(void);",
            "uint32_t GetCurrentThreadId(void) { return 0xfedcba98U; }",
            "return (uint32_t)windows_thread() != 0xfedcba98U;",
        ),
    ] {
        let address = binary.find(function).unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        if function == "windows_registry" {
            assert!(code.contains("int32_t windows_registry("), "{code}");
        }
        syntax::run_printed(&format!("{declaration}\n{code}"), support, assertions);
    }
}

#[test]
fn windows_pointer_arguments_preserve_bytes_after_a_string_terminator() {
    let binary =
        Binary::open(&common::fixtures_dir().join("type_library_windows.win64.exe")).unwrap();
    for (name, import, arguments, reference, data, support) in [
        (
            "lstrlenW",
            "kernel32.dll!lstrlenW",
            vec![Expr::Const(0x2000)],
            "BADC",
            "static const unsigned short bytes[] = {0x4142, 0x4344, 0};",
            "int lstrlenW(const unsigned short *text) { observed = text[0] == 0x4142 && text[1] == 0x4344 && text[2] == 0; return 2; }",
        ),
        (
            "send",
            "ws2_32.dll!send",
            vec![
                Expr::Const(7),
                Expr::Const(0x2000),
                Expr::Const(8),
                Expr::Const(0),
            ],
            "ABC",
            "static const char bytes[] = {65, 66, 67, 0, 91, 92, 93, 94};",
            "int send(unsigned long long socket, const char *buffer, int length, int flags) { observed = socket == 7 && length == 8 && !flags && buffer[0] == 65 && buffer[3] == 0 && buffer[7] == 94; return length; }",
        ),
    ] {
        let prototype = velk::analysis::prototypes::for_image(import, binary.image()).unwrap();
        let ir = synthetic_ir(
            "check_pointer",
            vec![],
            CType::U64,
            vec![
                Stmt::Call {
                    abi: None,
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::Win64,
                    args: Some(arguments),
                    floats_named: false,
                    outputs: vec![],
                    clobbers: Some(Default::default()),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::Const(7),
                },
            ],
        );
        let references = [velk::analysis::refs::Reference {
            guid: None,
            addr: 0x2000,
            section: ".rdata".into(),
            text: Some(reference.into()),
            pointer: None,
        }];
        let symbols = velk::render::Symbols {
            functions: [(0x1000, name.into())].into(),
            library_prototypes: [(name.into(), prototype.clone())].into(),
            target_format: Some(velk::loader::Format::Pe),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &references, &symbols, &[]);
        assert!(
            !code.lines().any(|line| !line.trim_start().starts_with("/*")
                && line.contains(&format!("\"{reference}\""))),
            "{code}"
        );
        assert!(code.contains("0x2000"), "{code}");
        let code = code.replace("0x2000", "(uintptr_t)bytes");
        syntax::run_printed(
            &format!("{data}\nstatic int observed;\n{code}"),
            support,
            "return check_pointer() != 7 || !observed;",
        );
    }
}

#[test]
fn windows_crt_calls_preserve_target_widths_and_arguments() {
    let mut binary = Binary::open(&common::fixtures_dir().join("crt_windows.x86_64.exe")).unwrap();
    for (function, declaration, support, assertions) in [
        (
            "crt_format",
            "#include <stdarg.h>\nint test_printf(const char *, ...);",
            "int test_printf(const char *format, ...) { va_list args; va_start(args, format); int value = va_arg(args, int); va_end(args); return format[0] == '%' && format[1] == 'd' ? value : 0; }",
            "return crt_format(-19) != -19;",
        ),
        (
            "crt_number",
            "int32_t strtol(const char *, char **, int);",
            "int32_t strtol(const char *text, char **end, int base) { return text && !end && base == 10 ? INT32_MIN : 0; }",
            "return crt_number(\"x\", 0) != INT32_MIN;",
        ),
        (
            "crt_wide",
            "size_t wcslen(const unsigned short *);",
            "size_t wcslen(const unsigned short *text) { return UINT64_C(0x100000000) + text[0]; }",
            "unsigned short text[] = {37, 0}; return crt_wide(text) != UINT64_C(0x100000025);",
        ),
        (
            "crt_time",
            "long long _time64(long long *);",
            "long long _time64(long long *out) { *out = -INT64_C(0x100000025); return *out; }",
            "long long out = 0; return crt_time(&out) != -INT64_C(0x100000025) || out != -INT64_C(0x100000025);",
        ),
        (
            "crt_math",
            "double sin(double);",
            "double sin(double value) { return value * 0.5; }",
            "return crt_math(3.5) != 1.75;",
        ),
        (
            "crt_secure",
            "int strcpy_s(char *, unsigned long long, const char *);",
            "int strcpy_s(char *out, unsigned long long size, const char *text) { *out = *text; return size == UINT64_C(0x100000025) ? -19 : 0; }",
            "char out = 0; return crt_secure(&out, UINT64_C(0x100000025), \"x\") != -19 || out != 'x';",
        ),
        (
            "crt_wide_secure",
            "int wcscpy_s(unsigned short *, unsigned long long, const unsigned short *);",
            "int wcscpy_s(unsigned short *out, unsigned long long size, const unsigned short *text) { *out = *text; return size == UINT64_C(0x100000025) ? -19 : 0; }",
            "unsigned short out = 0, text[] = {0x8123, 0}; return crt_wide_secure(&out, UINT64_C(0x100000025), text) != -19 || out != 0x8123;",
        ),
        (
            "crt_io",
            "int _close(int);",
            "int _close(int fd) { return fd == -7 ? -19 : 0; }",
            "return crt_io(-7) != -19;",
        ),
        (
            "crt_process",
            "int _getpid(void);",
            "int _getpid(void) { return -19; }",
            "return crt_process() != -19;",
        ),
        (
            "crt_errno",
            "int *_errno(void);",
            "static int error_value = -19; int *_errno(void) { return &error_value; }",
            "return *crt_errno() != -19;",
        ),
    ] {
        let address = binary.find(function).unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        let code = code
            .replace("sin(", "test_sin(")
            .replace("printf(", "test_printf(");
        let code = if function == "crt_format" {
            format!(
                "static const char format_text[] = \"%d\\n\";\n{}",
                code.replace("0x140002000", "(uintptr_t)format_text")
            )
        } else {
            code
        };
        let declaration = declaration.replace("sin(", "test_sin(");
        let support = support.replace("sin(", "test_sin(");
        syntax::run_printed(&format!("{declaration}\n{code}"), &support, assertions);
    }
}

#[test]
fn every_windows_header_and_crt_fixture_function_compiles() {
    let scratch = scratch_dir("windows-type-library-syntax");
    let source = scratch.join("check.c");
    for fixture in ["crt_windows.x86_64.exe", "type_library_windows.win64.exe"] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let addresses: Vec<_> = binary
            .image()
            .functions
            .values()
            .filter(|function| !function.sources.contains(&velk::loader::NameSource::Plt))
            .map(|function| function.addr)
            .collect();
        for address in &addresses {
            let code = binary.decompile(*address, None, None).unwrap();
            // The host's strtol returns an LP64 long; the target returns an LLP64 long.
            let code = replace_c_identifier(&code, "strtol", "target_strtol");
            std::fs::write(&source, format!("#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <math.h>\n#include <locale.h>\n#include <ctype.h>\n{code}")).unwrap();
            let output = Command::new(compiler())
                .args(FLAGS)
                .arg("-fsyntax-only")
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{fixture} {address:#x}:\n{code}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        eprintln!("{fixture}: {0}/{0} compile", addresses.len());
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn header_variables_keep_declared_names_and_types() {
    for fixture in ["type_library_linux_x86_64", "type_library_linux_arm64"] {
        let mut image = velk::loader::load(&common::fixtures_dir().join(fixture)).unwrap();
        for (name, width, ty, assertions) in [
            (
                "stderr",
                8,
                CType::pointer_to(CType::Named("FILE".into())),
                "return read_object() != stderr;",
            ),
            (
                "stdout",
                8,
                CType::pointer_to(CType::Named("FILE".into())),
                "return read_object() != stdout;",
            ),
            (
                "stdin",
                8,
                CType::pointer_to(CType::Named("FILE".into())),
                "return read_object() != stdin;",
            ),
            (
                "optind",
                4,
                CType::I32,
                "optind = -73; return read_object() != -73;",
            ),
        ] {
            image.data_symbols.clear();
            image.data_symbols.insert(0x9000, format!("{name}@TEST"));
            let symbols = velk::render::callee_names(&image);
            let mut ir = synthetic_ir(
                "read_object",
                vec![],
                ty,
                vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(0x9000)),
                        width,
                        signed: width == 4,
                    },
                }],
            );
            ir.isa = image.isa;
            let code = velk::render::render(&ir, &[], &symbols, &[(0x9000, 8)]);
            assert!(code.contains(&format!("return {name};")), "{code}");
            assert!(!code.contains("extern "), "{code}");
            let scratch = scratch_dir(&format!("header-variable-{fixture}-{name}"));
            assert_eq!(
                syntax::check(&code, &scratch.join("check.c"), &BTreeMap::new()),
                None,
                "{code}"
            );
            syntax::run_printed(&code, "", assertions);
            if name == "optind" {
                ir.ret_type = CType::int(1, false);
                ir.blocks[0].stmts = vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(0x9000)),
                        width: 1,
                        signed: false,
                    },
                }];
                let partial = velk::render::render(&ir, &[], &symbols, &[(0x9000, 8)]);
                assert!(!partial.contains("extern "), "{partial}");
                syntax::run_printed(
                    &partial,
                    "",
                    "optind = 0x123456ab; return read_object() != 0xab;",
                );
                ir.ret_type = CType::I32;
                ir.blocks[0].stmts.insert(
                    0,
                    Stmt::Store {
                        addr: Expr::Const(0x9000),
                        width: 1,
                        value: Expr::Const(0xcd),
                    },
                );
                ir.blocks[0].stmts[1] = Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(0x9000)),
                        width: 4,
                        signed: true,
                    },
                };
                let stored = velk::render::render(&ir, &[], &symbols, &[(0x9000, 8)]);
                syntax::run_printed(
                    &stored,
                    "",
                    "optind = 0x123456ab; return read_object() != 0x123456cd || optind != 0x123456cd;",
                );
            }
        }
    }
}

#[test]
fn copy_relocated_stream_uses_the_header_object() {
    let mut binary = Binary::open(&common::fixtures_dir().join("cold_gcc_stripped")).unwrap();
    let code = binary.decompile(0x1290, None, None).unwrap();
    assert!(
        code.contains("fputs((const char *)(local_1), stderr)"),
        "{code}"
    );
    assert!(!code.contains("data_stderr"), "{code}");
    assert!(!code.contains("(FILE *)stderr"), "{code}");
    assert!(
        !code
            .lines()
            .any(|line| line.starts_with("extern ") && line.contains("stderr")),
        "{code}"
    );
    let scratch = scratch_dir("copy-relocated-stream");
    assert_eq!(
        syntax::check(&code, &scratch.join("check.c"), &BTreeMap::new()),
        None,
        "{code}"
    );
}

#[test]
fn header_variable_import_slots_keep_address_storage() {
    let mut image =
        velk::loader::load(&common::fixtures_dir().join("type_library_linux_x86_64")).unwrap();
    image.data_symbols.clear();
    image.imports.insert(0x9000, "stderr".into());
    let symbols = velk::render::callee_names(&image);
    let ir = synthetic_ir(
        "read_slot",
        vec![],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::Const(0x9000)),
                width: 8,
                signed: false,
            },
        }],
    );
    let code = velk::render::render(&ir, &[], &symbols, &[(0x9000, 8)]);
    assert!(code.contains("extern uint64_t data_stderr_9000;"), "{code}");
    syntax::run_printed(
        &code,
        "uint64_t data_stderr_9000 = 73;",
        "return read_slot() != 73;",
    );
}
