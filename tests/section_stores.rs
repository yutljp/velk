//! Stores and readback in executable sections outside the text segment.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use velk::ir::Stmt;
use velk::service::Binary;

fn interfaces(path: &Path, name: &str, expected: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--cache", "off", "-D"])
        .arg(path)
        .arg(name)
        .output()
        .expect("the CLI runs");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 output")
            .trim(),
        expected.trim()
    );
    let code = format!("velk.open({path:?}).getFunction({name:?}).decompile()");
    let output = velk::script::Engine::new()
        .expect("the script engine starts")
        .run(&code, None);
    assert!(output.error.is_none(), "{:?}", output.error);
    assert_eq!(output.output.trim(), expected.trim());
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the MCP server starts");
    let request = serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"tools/call",
        "params":{"name":"velk_run_script","arguments":{"code":code,"max_output_chars":20000}}});
    let output = common::mcp_request(child, &request);
    assert!(output.status.success());
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON response");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content")
            .trim(),
        expected.trim()
    );
}

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let out = common::root()
            .join("target/section-store-tests")
            .join(std::process::id().to_string());
        let output = Command::new("bash")
            .arg(common::root().join("tools/make_section_store_fixtures.sh"))
            .arg(&out)
            .output()
            .expect("fixture builder starts");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        out
    })
}

#[test]
fn executable_section_stores_compile_and_match_native_memory() {
    for arch in ["x86_64", "i386", "aarch64", "arm", "thumb"] {
        let mut binary = Binary::open(&fixtures().join(format!("{arch}.elf"))).unwrap();
        let image = binary.image();
        let hidden = image
            .sections
            .iter()
            .find(|section| section.name == ".hidden")
            .unwrap();
        assert!(hidden.executable);
        assert_eq!(hidden.vaddr, 0x8001a0);
        let mut code = String::new();
        for name in ["text_stores", "init_stores", "fini_stores", "hidden_stores"] {
            let address = binary.find(name).unwrap().addr;
            let ir = &binary.analysis(address, None).unwrap().ir;
            let widths: Vec<u8> = ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .filter_map(|stmt| match stmt {
                    Stmt::Store { width, .. } => Some(*width),
                    _ => None,
                })
                .collect();
            for width in [1, 2, 4] {
                assert!(widths.contains(&width), "{arch}/{name}: {widths:?}");
            }
            assert!(
                widths.contains(&8) || widths.iter().filter(|width| **width == 4).count() >= 3,
                "{arch}/{name}: {widths:?}"
            );
            let rendered = binary.decompile(address, None, None).unwrap();
            interfaces(&fixtures().join(format!("{arch}.elf")), name, &rendered);
            code.push_str(&rendered);
        }
        let address = binary.find("call_hidden").unwrap().addr;
        let caller = binary.decompile(address, None, None).unwrap();
        assert!(caller.contains("hidden_stores("), "{arch}: {caller}");
        code.push_str(&caller);
        let mut code = velk::render::combine(&code);
        for name in [
            "text_stores",
            "init_stores",
            "fini_stores",
            "hidden_stores",
            "call_hidden",
        ] {
            code = code.replace(name, &format!("rendered_{name}"));
        }
        let reference = common::root().join("tests/data/section_stores.c");
        // Section placement matters only in the input ELF, not in this native reference.
        let reference = std::fs::read_to_string(reference)
            .unwrap()
            .replace("section(section_name)", "unused")
            .replace("section(\".text\")", "unused");
        code.push_str(&reference);
        code.push_str("\nvolatile uint32_t executable_data[8];\n");
        code.push_str("\n#include <string.h>\n#include <stdlib.h>\n");
        if matches!(arch, "i386" | "arm" | "thumb") {
            code.insert_str(0, "#define _GNU_SOURCE\n#include <sys/mman.h>\n");
        }
        code.push_str("int main(void) {\n");
        for name in [
            "text_stores",
            "init_stores",
            "fini_stores",
            "hidden_stores",
            "call_hidden",
        ] {
            let signature = code
                .lines()
                .find(|line| line.contains(&format!("rendered_{name}(")) && line.ends_with('{'))
                .unwrap();
            let pointer = signature
                .split('(')
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .contains('*');
            let argument = if pointer { "(void *)b" } else { "(uintptr_t)b" };
            let memory = if matches!(arch, "i386" | "arm" | "thumb") {
                "void *a = malloc(32); void *b = mmap((void *)0x300000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0); if (!a || b == MAP_FAILED) return 2;"
            } else {
                "void *a = malloc(32), *b = malloc(32); if (!a || !b) return 2;"
            };
            let release = if matches!(arch, "i386" | "arm" | "thumb") {
                "free(a); munmap(b,4096);"
            } else {
                "free(a); free(b);"
            };
            code.push_str(&format!(
                "for (uint64_t i=0; i<1024; ++i) {{\n\
                 {memory} memset(a, 0xa5, 32); memset(b, 0xa5, 32);\n\
                 uint32_t value = i < 4 ? (uint32_t[]){{0,1,0x80000000,0xffffffff}}[i] : (uint32_t)(i*2654435761U);\n\
                 uint32_t expected = {name}((void *)a, value);\n\
                 uint32_t actual = rendered_{name}({argument}, value);\n\
                 if (actual != expected || memcmp(a,b,32)) return 1; {release}\n\
                 }}\n"));
        }
        code.push_str("return 0; }\n");
        let source = fixtures().join(format!("{arch}-rendered.c"));
        let executable = fixtures().join(format!("{arch}-rendered"));
        std::fs::write(&source, &code).unwrap();
        let output = Command::new("clang")
            .args(["-std=c17", "-Werror=implicit-function-declaration", "-O0"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arch}: {}\n{code}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !cfg!(target_os = "linux") && matches!(arch, "i386" | "arm" | "thumb") {
            continue;
        }
        let output = Command::new(executable).output().unwrap();
        assert!(output.status.success(), "{arch}: {output:?}\n{code}");
    }
}

#[test]
fn caller_memory_stores_use_named_stack_arguments() {
    let mut binary = Binary::open(&fixtures().join("stack.elf")).unwrap();
    for name in ["caller_stores", "text_caller_stores", "parameter_stores"] {
        let address = binary.find(name).unwrap().addr;
        let ir = &binary.analysis(address, None).unwrap().ir;
        let stores = ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .filter(|stmt| matches!(stmt, Stmt::Store { .. }))
            .count();
        assert_eq!(stores, 4, "{name}: {}", ir.render());
        let code = binary.decompile(address, None, None).unwrap();
        interfaces(&fixtures().join("stack.elf"), name, &code);
        assert!(!code.contains("velk_entry_stack_pointer"), "{name}: {code}");
        assert!(!code.contains("rsp"), "{name}: {code}");
        assert!(code.contains("arg_8"), "{name}: {code}");
        let source = fixtures().join(format!("{name}.c"));
        let executable = fixtures().join(name);
        let (argument, byte, word, dword, qword) = if name == "parameter_stores" {
            (
                "UINT64_C(0x8123456789abcdef)",
                "0xef",
                "0xcdef",
                "0x89abcdef",
                "0x8123456789abcdef",
            )
        } else {
            ("", "0x81", "0x8234", "0x856789ab", "0x8123456789abcdef")
        };
        let source_text = format!(
            "{code}\n\
            #include <string.h>\n\
            static uint64_t memory[8];\n\
            uint8_t *{name}_{address:x}_arg_8 = (uint8_t *)memory + 8;\n\
            int main(void) {{\n\
              memset(memory,0xa5,sizeof(memory));\n\
              if ({name}({argument}) != 0) return 1;\n\
              unsigned char expected[64]; memset(expected,0xa5,sizeof(expected));\n\
              expected[8]={byte}; uint16_t w={word}; uint32_t d={dword}; uint64_t q={qword};\n\
              memcpy(expected+10,&w,2); memcpy(expected+12,&d,4); memcpy(expected+16,&q,8);\n\
              return memcmp(memory,expected,sizeof(memory)) != 0;\n\
            }}\n"
        );
        std::fs::write(&source, &source_text).unwrap();
        let output = Command::new("clang")
            .args(["-std=c17", "-Werror=implicit-function-declaration", "-O2"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{source_text}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(executable).status().unwrap().success(),
            "{source_text}"
        );
    }
}

#[test]
fn abi_spills_and_stack_outputs_compile_and_match_memory() {
    use velk::ir::{BinOp, Block, CType, Convention, Expr, Param};

    for (architecture, convention, spills, spill, output) in [
        ("x86_64", Convention::Win64, None, 8_i64, 40_i64),
        ("x86_64", Convention::GoAmd64, Some((24, 40)), 24, 8),
        ("aarch64", Convention::Aapcs64, Some((24, 40)), 24, 8),
        ("x86_64", Convention::SysV, None, -8, 8),
        ("i386", Convention::Cdecl, None, -8, 4),
        ("i386", Convention::Stdcall, None, -8, 4),
        ("arm", Convention::Aapcs32, None, -8, 0),
    ] {
        let mut binary = Binary::open(&fixtures().join(format!("{architecture}.elf"))).unwrap();
        let address = binary.find("read_executable").unwrap().addr;
        let template = binary.analysis(address, None).unwrap().ir.clone();
        let sp = velk::arch::stack_pointer(template.isa);
        let register = convention.arguments().first().copied().unwrap_or(0);
        let at = |offset: i64| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset as u64));
        let mut source =
            String::from("#include <stdint.h>\n#include <string.h>\nstatic uint8_t memory[64];\n");
        let mut checks = String::new();
        for width in [1, 2, 4, 8] {
            for read in [false, true] {
                let name = format!("stack_output_{width}_{read}");
                let mut ir = template.clone();
                ir.convention = convention;
                ir.stack_spills = spills;
                ir.stack_params.clear();
                ir.declared_signature = None;
                ir.params = vec![Param {
                    index: register,
                    name: "value".into(),
                    ty: CType::U64,
                }];
                ir.name = Some(name.clone());
                ir.ret_type = CType::U64;
                ir.blocks = vec![Block {
                    start: address,
                    stmts: vec![
                        Stmt::Store {
                            addr: at(spill),
                            value: Expr::reg(register, 64),
                            width,
                            at: None,
                        },
                        Stmt::Store {
                            addr: at(output),
                            value: Expr::reg(register, 64),
                            width,
                            at: None,
                        },
                        Stmt::Ret {
                            value: if read {
                                Expr::Load {
                                    addr: Box::new(at(spill)),
                                    width,
                                    signed: false,
                                }
                            } else {
                                Expr::Const(0)
                            },
                            at: None,
                        },
                    ],
                }];
                velk::passes::frame::drop_dead_frame_stores(&mut ir);
                assert_eq!(ir.blocks[0].stmts.len(), if read { 3 } else { 2 });
                let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                assert!(
                    !code.contains("velk_entry_stack_pointer"),
                    "{convention:?}: {code}"
                );
                assert!(
                    !code
                        .lines()
                        .filter_map(|line| line.split("/*").next())
                        .flat_map(
                            |line| line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        )
                        .any(|word| matches!(word, "rsp" | "sp" | "esp")),
                    "{convention:?}: {code}"
                );
                source.push_str(&code);
                source.push_str(&format!(
                    "\nuint8_t *{name}_{address:x}_arg_{output:x} = memory + {output};\n"
                ));
                let mask = u64::MAX >> (64 - 8 * width);
                let expected = if read {
                    format!("(value & UINT64_C({mask}))")
                } else {
                    "0".into()
                };
                checks.push_str(&format!("memset(memory,0xa5,64); memset(expected,0xa5,64); memcpy(expected+{output},&value,{width}); if ({name}(value) != {expected} || memcmp(memory,expected,64)) return 1;\n"));
            }
        }
        source.push_str(&format!("\nint main(void) {{ uint8_t expected[64]; for (uint64_t i=0;i<1024;++i) {{ uint64_t value = i<4 ? (uint64_t[]){{0,1,UINT64_C(0x8000000000000000),UINT64_MAX}}[i] : i*UINT64_C(0x9e3779b97f4a7c15); {checks} }} return 0; }}\n"));
        let name = format!("{architecture}-{convention:?}-stack");
        let input = fixtures().join(format!("{name}.c"));
        let executable = fixtures().join(name);
        std::fs::write(&input, &source).unwrap();
        let compiled = Command::new("clang")
            .args(["-std=c17", "-Werror=implicit-function-declaration", "-O2"])
            .arg(&input)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}\n{source}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            Command::new(executable).status().unwrap().success(),
            "{source}"
        );
    }
}

#[test]
fn go_register_spills_disappear_from_every_interface() {
    for (fixture, address) in [
        ("go_probe", 0x466d00),
        ("go_probe_arm64", 0x77490),
        ("go_stripped", 0x466cc0),
        ("go_stripped_arm64", 0x77430),
    ] {
        let path = common::root().join("tests/fixtures").join(fixture);
        let mut binary = Binary::open(&path).unwrap();
        let code = binary.decompile(address, None, None).unwrap();
        assert!(
            !code.contains("velk_entry_stack_pointer"),
            "{fixture}: {code}"
        );
        assert!(
            !code
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|word| matches!(word, "rsp" | "sp")),
            "{fixture}: {code}"
        );
        interfaces(&path, &format!("0x{address:x}"), &code);
        if fixture.contains("stripped") {
            continue;
        }
        let source = fixtures().join(format!("{fixture}-sum.c"));
        let executable = fixtures().join(format!("{fixture}-sum"));
        let source_text = format!(
            "{code}\nint main(void) {{ uint64_t data[64]; for (uint64_t i=0;i<1024;++i) {{ uint64_t sum=0; for (int j=0;j<64;++j) data[j]=(i+j)*UINT64_C(0x9e3779b97f4a7c15); for (int n=0;n<=64;++n) {{ if ((uint64_t)main_sumSlice(data,n) != sum) return 1; if (n<64) sum+=data[n]; }} }} return 0; }}\n"
        );
        std::fs::write(&source, &source_text).unwrap();
        let compiled = Command::new("clang")
            .args(["-std=c17", "-Werror=implicit-function-declaration", "-O2"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}\n{source_text}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            Command::new(executable).status().unwrap().success(),
            "{source_text}"
        );
    }
}

#[test]
fn executable_memory_loads_and_stores_remain() {
    use object::{Object, ObjectSegment};

    for arch in ["x86_64", "i386", "aarch64", "arm", "thumb"] {
        let path = fixtures().join(format!("{arch}.elf"));
        let bytes = std::fs::read(&path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        for address in [0x8001a0, 0x810000] {
            assert!(!file.segments().any(|segment| address >= segment.address()
                && address < segment.address().saturating_add(segment.size())));
        }
        let mut binary = Binary::open(&path).unwrap();
        let mut code = String::new();
        for name in ["write_executable", "read_executable"] {
            let address = binary.find(name).unwrap().addr;
            let rendered = binary.decompile(address, None, None).unwrap();
            assert!(rendered.contains("0x810000"), "{arch}/{name}: {rendered}");
            interfaces(&path, name, &rendered);
            code.push_str(&rendered);
        }
        code = velk::render::combine(&code);
        code.insert_str(0, "#define _GNU_SOURCE\n#include <sys/mman.h>\n");
        code.push_str("\nint main(void) {\n\
          uint32_t *memory = mmap((void *)0x810000,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);\n\
          if (memory == MAP_FAILED) return 2;\n\
          for (uint64_t i=0;i<1024;++i) {\n\
            uint32_t value = (uint32_t)(i*2654435761U); memory[1]=~value;\n\
            if (write_executable(value) != ~value || read_executable() != value || memory[0] != value) return 1;\n\
          }\nreturn 0; }\n");
        let source = fixtures().join(format!("{arch}-executable.c"));
        let executable = fixtures().join(format!("{arch}-executable"));
        std::fs::write(&source, &code).unwrap();
        let output = Command::new("clang")
            .args(["-std=c17", "-Werror=implicit-function-declaration", "-O2"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arch}: {}\n{code}",
            String::from_utf8_lossy(&output.stderr)
        );
        if cfg!(target_os = "linux") {
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{arch}: {code}"
            );
        }
    }
}

#[test]
fn stores_crossing_the_frame_boundary_keep_caller_bytes() {
    use velk::ir::{BinOp, Block, CType, Expr, Param};

    let mut code = String::new();
    let mut checks = String::new();
    for (architecture, arch) in ["x86_64", "i386", "aarch64", "arm"].into_iter().enumerate() {
        let mut binary = Binary::open(&fixtures().join(format!("{arch}.elf"))).unwrap();
        let address = binary.find("read_executable").unwrap().addr;
        let template = binary.analysis(address, None).unwrap().ir.clone();
        let sp = velk::arch::stack_pointer(template.isa);
        for width in [1, 2, 4, 8] {
            let name = format!("crossing_{architecture}_{width}");
            let mut ir = template.clone();
            ir.params = vec![Param {
                index: 0,
                name: "value".into(),
                ty: CType::int(width, false),
            }];
            let offset = if width == 1 { 0 } else { u64::MAX };
            ir.blocks = vec![Block {
                start: address,
                stmts: vec![
                    Stmt::Store {
                        addr: Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset)),
                        value: Expr::reg(0, 64),
                        width,
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::Const(0),
                        at: None,
                    },
                ],
            }];
            ir.name = Some(name.clone());
            velk::passes::frame::drop_dead_frame_stores(&mut ir);
            let rendered = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(!rendered.contains("velk_entry_stack_pointer"), "{rendered}");
            code.push_str(&format!("\nuint8_t *{name}_{address:x}_arg_0;\n"));
            code.push_str(&rendered);
            let destination = if width == 1 { 16 } else { 15 };
            checks.push_str(&format!("memset(memory,0xa5,64); memset(expected,0xa5,64); memcpy(expected+{destination},&value,{width}); {name}_{address:x}_arg_0 = (uint8_t *)memory + 16; {name}(value); if (memcmp(memory,expected,64)) return 1;\n"));
        }
    }
    code = velk::render::combine(&code);
    code.push_str(&format!("\n#include <string.h>\nstatic uint64_t memory[8];\nuint64_t velk_entry_stack_pointer(void) {{ return (uintptr_t)memory+16; }}\nint main(void) {{ unsigned char expected[64]; uint64_t value=0x8123456789abcdef; {checks} return 0; }}\n"));
    let source = fixtures().join("crossing.c");
    let executable = fixtures().join("crossing");
    std::fs::write(&source, &code).unwrap();
    let output = Command::new("clang")
        .args(["-std=c17", "-Werror=implicit-function-declaration", "-O2"])
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
    assert!(
        Command::new(executable).status().unwrap().success(),
        "{code}"
    );
}
