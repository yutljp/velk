use super::*;

fn fixture_symbol(arch: &str, function: &str) -> String {
    if arch == "i686" {
        format!("_{function}")
    } else {
        function.to_owned()
    }
}

#[test]
fn com_method_printing_refuses_unsupported_uses_and_preserves_saved_tables() {
    let mut binary = Binary::open(&common::fixtures_dir().join("com_x86_64.dll")).unwrap();
    let address = binary.find("com_release").unwrap().addr;
    let original = binary.analysis(address, None).unwrap().ir.clone();
    let symbols = velk::render::callee_names(binary.image());
    let position = original.blocks[0]
        .stmts
        .iter()
        .position(|stmt| matches!(stmt, Stmt::Call { .. }))
        .unwrap();
    for variant in 0..5 {
        let mut ir = original.clone();
        match variant {
            0 => ir.params[0].ty = CType::pointer_to(CType::Void),
            1 => {
                if let Stmt::Call { convention, .. } = &mut ir.blocks[0].stmts[position] {
                    *convention = Convention::SysV;
                }
            }
            2 => {
                if let Stmt::Call {
                    args: Some(args), ..
                } = &mut ir.blocks[0].stmts[position]
                {
                    args.clear();
                }
            }
            3 => {
                let output = ir.blocks[0].stmts[position].call_outputs()[0].dest.index;
                ir.ret_type = CType::U64;
                *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::Ret {
                    value: Expr::reg(output, 64),
                    at: None,
                };
            }
            _ => {
                ir.blocks[0].stmts.insert(
                    position,
                    Stmt::Store {
                        addr: Expr::reg(ir.params[0].index, 64),
                        value: Expr::Const(0),
                        width: 8,
                        at: None,
                    },
                );
            }
        }
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(!code.contains("->lpVtbl->Release("), "{variant}: {code}");
    }
}

#[test]
fn named_guid_bytes_compile_and_preserve_the_stored_values() {
    for arch in ["x86_64", "i686"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("com_{arch}.dll"))).unwrap();
        for (function, identifier) in [
            ("com_unknown_id", "IID_IUnknown"),
            ("com_stream_id", "IID_IStream"),
            ("com_file_dialog_class", "CLSID_FileOpenDialog"),
        ] {
            let address = binary.find(function).unwrap().addr;
            let analysis = binary.analysis(address, None).unwrap().clone();
            let guid = analysis
                .references
                .iter()
                .find_map(|reference| reference.guid.as_ref())
                .unwrap();
            assert!(guid.names.iter().any(|name| name == identifier));
            let mut symbols = velk::render::callee_names(binary.image());
            symbols.data.clear();
            let ranges: Vec<_> = binary
                .image()
                .sections
                .iter()
                .filter(|section| !section.executable)
                .map(|section| (section.vaddr, section.size))
                .collect();
            let code = velk::render::render(&analysis.ir, &analysis.references, &symbols, &ranges);
            assert!(
                code.contains(&format!("extern const uint8_t {identifier}[];")),
                "{code}"
            );
            let bytes: Vec<_> = guid.bytes.iter().map(ToString::to_string).collect();
            let support = format!("const uint8_t {identifier}[16] = {{{}}};", bytes.join(", "));
            let name = fixture_symbol(arch, function);
            let assertions = format!(
                "const uint8_t *actual = (const uint8_t *){name}(); const uint8_t expected[16] = {{{}}}; for (unsigned i = 0; i < 16; ++i) if (actual[i] != expected[i]) return 1; return 0;",
                bytes.join(", ")
            );
            syntax::run_printed(&code, &support, &assertions);
        }
    }
}

#[test]
fn com_methods_compile_and_preserve_arguments_results_and_writes() {
    for arch in ["x86_64", "i686"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("com_{arch}.dll"))).unwrap();
        for (function, interface, method, guard, effect, arguments, checks) in [
            (
                "com_add_ref",
                "IUnknown",
                "AddRef",
                "p0 == expected_object",
                "",
                "object",
                "",
            ),
            (
                "com_release",
                "IUnknown",
                "Release",
                "p0 == expected_object",
                "",
                "object",
                "",
            ),
            (
                "com_query",
                "IUnknown",
                "QueryInterface",
                "p0 == expected_object && p1 == expected_iid && p2 == expected_result",
                "*p2 = p0;",
                "object, iid, result",
                "if (*result != object) return 2;",
            ),
            (
                "com_read",
                "IStream",
                "Read",
                "p0 == expected_object && p1 == expected_buffer && p2 == (current ^ 0x87654321U) && p3 == expected_count",
                "*p3 = p2 ^ current; *(unsigned char *)p1 = (unsigned char)current;",
                "object, buffer, current ^ 0x87654321U, count",
                "if (*count != 0x87654321U || *buffer != (unsigned char)current) return 2;",
            ),
            (
                "com_write",
                "IStream",
                "Write",
                "p0 == expected_object && p1 == expected_buffer && p2 == (current ^ 0x87654321U) && p3 == expected_count && *(const unsigned char *)p1 == 0x7a",
                "*p3 = p2 ^ current;",
                "object, buffer, current ^ 0x87654321U, count",
                "if (*count != 0x87654321U || *buffer != 0x7a) return 2;",
            ),
            (
                "com_type_info_count",
                "IDispatch",
                "GetTypeInfoCount",
                "p0 == expected_object && p1 == expected_count",
                "*p1 = current ^ 1U;",
                "object, count",
                "if (*count != (current ^ 1U)) return 2;",
            ),
        ] {
            let address = binary.find(function).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(
                code.contains(&format!("->lpVtbl->{method}(")),
                "{arch}: {code}"
            );
            let record = velk::analysis::prototypes::record(
                &format!("struct {interface}Vtbl"),
                binary.image(),
            )
            .unwrap();
            let signature = record
                .fields
                .iter()
                .find(|field| field.name == method)
                .unwrap()
                .function
                .as_ref()
                .unwrap();
            let params: Vec<_> = signature
                .parameters
                .iter()
                .enumerate()
                .map(|(index, ty)| format!("{ty} p{index}"))
                .collect();
            let attribute = if arch == "i686" { "stdcall" } else { "ms_abi" };
            let support = format!(
                r#"
#include <stdlib.h>
#include <sys/mman.h>
static uint32_t current;
static void *expected_object, *expected_iid, *expected_result, *expected_buffer, *expected_count;
static {} __attribute__(({attribute})) callback({}) {{
    if (!({guard})) abort();
    {effect}
    return current;
}}
"#,
                signature.return_type,
                params.join(", ")
            );
            let name = fixture_symbol(arch, function);
            let assertions = format!(
                r#"
unsigned char *memory = mmap((void *)0x10000000, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
if (memory == MAP_FAILED) return 3;
struct {interface} *object = (void *)memory;
struct {interface}Vtbl table = {{ .{method} = callback }};
object->lpVtbl = &table;
unsigned char *buffer = memory + 0x100;
unsigned int *count = (void *)(memory + 0x200);
void **result = (void *)(memory + 0x300);
struct _GUID *iid = (void *)(memory + 0x400);
expected_object = object; expected_buffer = buffer; expected_count = count; expected_result = result; expected_iid = iid;
uint32_t edges[] = {{0, 1, 0x7fffffffU, 0x80000000U, 0xfffffffeU, 0xffffffffU}};
for (unsigned i = 0; i < 262; ++i) {{
    current = i < 6 ? edges[i] : i * 0x9e3779b9U;
    *buffer = 0x7a; *count = 0; *result = 0;
    if ((uint32_t){name}({arguments}) != current) return 1;
    {checks}
}}
munmap(memory, 0x10000);
return 0;
"#
            );
            let program = Program {
                text: format!("{HEADER}{code}\n{support}\nint main(void) {{ {assertions} }}"),
                ranges: Vec::new(),
            };
            let scratch = scratch_dir(&format!("com-{arch}-{function}"));
            let flags: &[&str] = if cfg!(target_os = "macos") {
                &["-arch", "x86_64", "-Wl,-pagezero_size,0x1000"]
            } else {
                &[]
            };
            for level in LEVELS {
                let executable = build(&program, &scratch, level, flags);
                let output = Command::new(executable).output().unwrap();
                assert!(
                    output.status.success(),
                    "{arch} {function}: {:?}\n{code}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::fs::remove_dir_all(scratch).ok();
        }
    }
}

#[test]
fn every_com_fixture_function_compiles_for_its_windows_target() {
    let scratch = scratch_dir("com-syntax");
    let source = scratch.join("check.c");
    for arch in ["x86_64", "i686"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("com_{arch}.dll"))).unwrap();
        let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
        assert!(addresses.len() >= 7);
        for address in addresses {
            let code = binary
                .decompile_with_dependencies(address, None, None)
                .unwrap()
                .code;
            std::fs::write(
                &source,
                format!("#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n{code}"),
            )
            .unwrap();
            let output = Command::new(compiler())
                .args([
                    "-target",
                    &format!("{arch}-w64-mingw32"),
                    "-ffreestanding",
                    "-std=c11",
                    "-Werror",
                    "-fsyntax-only",
                ])
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{arch} {address:#x}:\n{code}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}
