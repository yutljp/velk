//! Compiled memory effects and recognition data across the public interfaces.
mod common;

use std::fs;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::render::Rendered;
use velk::script::Engine;
use velk::service::Binary;

fn declared_binary(path: &std::path::Path, label: &str, name: &str, signature: &str) -> Binary {
    use sha2::Digest as _;

    let binary = Binary::open(path).expect("open compiler fixture");
    let address = binary.find_address(name).expect("fixture function exists");
    let project = json!({
        "version": 1,
        "binary_sha256": format!("{:x}", sha2::Sha256::digest(fs::read(path).expect("read compiler fixture"))),
        "annotations": [{"target": {"kind":"signature", "function":format!("0x{address:x}")}, "text":signature}]
    });
    let directory = common::root().join("target/string-function-projects");
    fs::create_dir_all(&directory).expect("create fixture declaration directory");
    let project_path = directory.join(format!("{label}.{name}.json"));
    fs::write(
        &project_path,
        serde_json::to_vec(&project).expect("serialize fixture declaration"),
    )
    .expect("write fixture declaration");
    Binary::open_with_project(path, Some(&project_path)).expect("open fixture with declaration")
}

fn fixture_binary(path: &std::path::Path, label: &str) -> Binary {
    if label.ends_with(".debug") {
        return Binary::open(path).expect("open compiler fixture");
    }
    declared_binary(
        path,
        label,
        "find",
        "unsigned char * (unsigned char *source, int value)",
    )
}

const FUNCTIONS: &[&str] = &[
    "length",
    "compare",
    "memory_compare",
    "string_compare",
    "bounded_compare",
    "find",
    "copy_literal",
    "string_copy",
    "short_compare",
    "short_string_compare",
    "word_length",
    "vector_compare",
    "vector_length",
    "length_plus_one",
    "bounded_off_by_one",
    "signed_compare",
    "copy_without_zero",
];

fn arguments(code: &str, name: &str, expressions: &[&str]) -> String {
    let marker = format!("{name}(");
    let signature = code
        .lines()
        .find(|line| line.contains(&marker) && line.ends_with(" {"))
        .unwrap_or_else(|| panic!("missing function {name}: {code}"));
    let (_, parameters) = signature.split_once('(').expect("function parameters open");
    let (parameters, _) = parameters
        .split_once(')')
        .expect("function parameters close");
    let types: Vec<_> = parameters
        .split(',')
        .map(|parameter| {
            let parameter = parameter.trim();
            let end = parameter
                .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .expect("parameter has a type and name");
            &parameter[..=end]
        })
        .collect();
    assert_eq!(types.len(), expressions.len(), "{signature}");
    types
        .iter()
        .zip(expressions)
        .map(|(ty, value)| format!("({ty})(uintptr_t)({value})"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn literal_definitions(rendered: &Rendered, binary: &Binary) -> (String, String) {
    let mut definitions = String::new();
    let mut initialization = String::new();
    for line in rendered.code.lines() {
        let Some(declaration) = line.strip_prefix("extern ") else {
            continue;
        };
        let (declaration, comment) = declaration
            .split_once(';')
            .expect("global declaration ends");
        let (ty, global) = declaration.rsplit_once(' ').expect("global type and name");
        let address = comment
            .strip_prefix(" /* address: 0x")
            .expect("global has an address")
            .strip_suffix(" */")
            .expect("address comment ends");
        let address = u64::from_str_radix(address, 16).expect("hexadecimal global address");
        if ty == "uint8_t" && global.ends_with("[]") {
            let global = global.strip_suffix("[]").expect("literal byte array");
            let bytes = binary
                .image()
                .read_vaddr(address, 16)
                .expect("sixteen literal bytes");
            let values = bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            definitions.push_str(&format!(
                "_Alignas(16) uint8_t {global}[16] = {{ {values} }};\n"
            ));
            continue;
        }
        let width = match ty {
            "double" | "uint64_t" => 8,
            "float" | "uint32_t" => 4,
            "uint16_t" => 2,
            "uint8_t" => 1,
            _ => panic!("{line}"),
        };
        let bytes = binary
            .image()
            .read_vaddr(address, width)
            .expect("fixture literal exists");
        let mut buffer = [0; 8];
        buffer[..width as usize].copy_from_slice(bytes);
        let bits = u64::from_le_bytes(buffer);
        definitions.push_str(&format!("{declaration};\n"));
        initialization.push_str(&format!(
            "{{ uint64_t bits=UINT64_C({bits}); memcpy(&{global}, &bits, {width}); }}\n"
        ));
    }
    (definitions, initialization)
}

fn execute(name: &str, rendered: &Rendered, label: &str, binary: &Binary) {
    let mut reference = String::new();
    for function in FUNCTIONS {
        reference.push_str(&format!("#define {function} reference_{function}\n"));
    }
    reference.push_str(include_str!("cases/string_functions/functions.c"));
    for function in FUNCTIONS {
        reference.push_str(&format!("\n#undef {function}\n"));
    }
    let expressions: &[&str] = match name {
        "copy_without_zero" => &["a+8", "a+48"],
        "string_copy" => &["a+8", "a+8+offset%32"],
        "compare"
        | "signed_compare"
        | "string_compare"
        | "short_compare"
        | "short_string_compare"
        | "vector_compare" => &["a", "b"],
        "memory_compare" | "bounded_compare" | "bounded_off_by_one" => &["a", "b", "offset"],
        "find" => &["a", "seed"],
        "length" | "word_length" | "vector_length" | "length_plus_one" => &["a"],
        _ => &["a+8"],
    };
    let args = arguments(&rendered.code, name, expressions);
    let check = match name {
        "length" | "word_length" | "vector_length" | "length_plus_one" => {
            format!("a[offset]=0; if ({name}({args}) != reference_{name}(a)) return 1;")
        }
        "compare"
        | "signed_compare"
        | "string_compare"
        | "short_compare"
        | "short_string_compare"
        | "vector_compare" => format!(
            "b[(seed*7)%64] ^= (unsigned char)seed; a[offset]=0; b[63-offset]=0; if ({name}({args}) != reference_{name}((void *)a,(void *)b)) return 1;"
        ),
        "memory_compare" | "bounded_compare" | "bounded_off_by_one" => format!(
            "b[(seed*7)%64] ^= (unsigned char)seed; a[offset]=0; b[63-offset]=0; if ({name}({args}) != reference_{name}(a,b,offset)) return 1;"
        ),
        "find" => format!(
            "a[offset]=0; if ((uintptr_t){name}({args}) != (uintptr_t)reference_find(a,seed)) return 1;"
        ),
        "string_copy" => format!(
            "a[63]=b[63]=0; if ((uintptr_t){name}({args}) != (uintptr_t)(a+8)) return 1; reference_{name}(b+8,b+8+offset%32); if (memcmp(a,b,96)) return 1;"
        ),
        "copy_without_zero" => format!(
            "a[63]=b[63]=0; {name}({args}); reference_{name}(b+8,b+48); if (memcmp(a,b,96)) return 1;"
        ),
        "copy_literal" => format!(
            "if ((uintptr_t){name}({args}) != (uintptr_t)(a+8)) return 1; reference_{name}(b+8); if (memcmp(a,b,96)) return 1;"
        ),
        _ => format!("{name}({args}); reference_{name}(b+8); if (memcmp(a,b,96)) return 1;"),
    };
    let (definitions, initialization) = literal_definitions(rendered, binary);
    let source = format!(
        "#include <stdint.h>\n#include <string.h>\n{reference}\n{}\n{definitions}\nint main(void) {{ {initialization} _Alignas(16) unsigned char a[96], b[96]; for (unsigned seed=0;seed<256;++seed) {{ for (unsigned offset=0;offset<64;++offset) {{ for(unsigned i=0;i<96;++i) a[i]=b[i]=(unsigned char)(1+(i*17+seed)%255); {check} }} }} return 0; }}\n",
        rendered.code
    );
    let directory = common::root()
        .join("target/string-function-tests")
        .join(label);
    fs::create_dir_all(&directory).expect("create compilation directory");
    let input = directory.join(format!("{name}.c"));
    let output = directory.join(name);
    common::compiler::compile_file(
        Command::new("cc")
            .args([
                "-std=c11",
                "-O2",
                "-Werror",
                "-fno-inline",
                "-fno-strict-aliasing",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&output),
        &input,
        &source,
    );
    assert!(
        Command::new(&output)
            .status()
            .expect("execute compiled C")
            .success(),
        "{label}: {name}"
    );
}

#[test]
fn optimized_fixtures_compile_and_match_reference_execution() {
    let mut recognized = 0;
    let mut missed = 0;
    let mut negative = 0;
    let mut report =
        String::from("# Recognition requires one call covering the complete source operation.\n");
    for architecture in ["x86_64", "aarch64"] {
        for compiler in ["clang", "gcc"] {
            for level in [2, 3] {
                for suffix in ["", ".debug"] {
                    let label = format!("{architecture}.{compiler}.O{level}{suffix}");
                    let path =
                        common::root().join(format!("tests/data/string_functions/{label}.elf"));
                    let mut binary = fixture_binary(&path, &label);
                    for name in FUNCTIONS {
                        let addr = binary.find_address(name).unwrap();
                        let rendered = binary
                            .decompile_with_dependencies(addr, None, None)
                            .unwrap();
                        let (expected_function, expected_bytes) = match *name {
                            "length" | "word_length" | "vector_length" => ("strlen", None),
                            "memory_compare" => ("memcmp", None),
                            "string_compare" => ("strcmp", None),
                            "bounded_compare" => ("strncmp", None),
                            "find" => ("strchr", None),
                            "copy_literal" => ("strcpy", Some(5)),
                            "string_copy" => ("strcpy", None),
                            "short_compare" => ("memcmp", Some(3)),
                            "short_string_compare" => ("strncmp", Some(3)),
                            "vector_compare" => ("memcmp", Some(32)),
                            _ => ("", None),
                        };
                        if expected_function.is_empty() {
                            negative += 1;
                        } else if rendered.inline_functions.iter().any(|call| {
                            call.function == expected_function && call.bytes == expected_bytes
                        }) {
                            recognized += 1;
                        } else {
                            missed += 1;
                        }
                        if expected_function.is_empty() {
                            assert!(
                                !rendered.inline_functions.iter().any(|call| matches!(
                                    call.function.as_str(),
                                    "strlen"
                                        | "strcmp"
                                        | "strncmp"
                                        | "memcmp"
                                        | "strchr"
                                        | "strcpy"
                                )),
                                "{label} {name}: {:?}",
                                rendered.inline_functions
                            );
                        }
                        execute(name, &rendered, &label, &binary);
                        report.push_str(&format!(
                            "{label} {name}: {}; {} lines\n",
                            serde_json::to_string(&rendered.inline_functions).unwrap(),
                            rendered.code.lines().count()
                        ));
                    }
                }
            }
        }
    }
    eprintln!("recognized={recognized} missed={missed} wrong=0 negatives_rejected={negative}");
    report.push_str(&format!(
        "recognized={recognized} missed={missed} wrong=0 negatives_rejected={negative}\n"
    ));
    assert!(
        common::check_expected(
            &common::root().join("tests/golden/string_functions.txt"),
            &report
        )
        .is_none(),
        "{report}"
    );
}

#[test]
fn summaries_agree_in_cli_javascript_and_mcp() {
    let mut seen = std::collections::BTreeSet::new();
    for architecture in ["x86_64", "aarch64"] {
        for compiler in ["clang", "gcc"] {
            for suffix in ["", ".debug"] {
                let path = common::root().join(format!(
                    "tests/data/string_functions/{architecture}.{compiler}.O2{suffix}.elf"
                ));
                let mut binary = Binary::open(&path).unwrap();
                for name in [
                    "length",
                    "memory_compare",
                    "string_compare",
                    "bounded_compare",
                    "find",
                    "copy_literal",
                    "short_compare",
                    "short_string_compare",
                ] {
                    let addr = binary.find_address(name).unwrap();
                    let rendered = binary
                        .decompile_with_dependencies(addr, None, None)
                        .unwrap();
                    let expected = serde_json::to_value(&rendered.inline_functions).unwrap();
                    for call in &rendered.inline_functions {
                        seen.insert(call.function.clone());
                    }
                    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                        .arg("--summary")
                        .arg(&path)
                        .arg(name)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(summary["inlineFunctions"], expected);
                    let code = format!(
                        "const b=velk.open({path:?}); b.getFunction('{name}').summary().inlineFunctions"
                    );
                    let result = Engine::new().unwrap().run(&format!("const b=velk.open({path:?}); JSON.stringify(b.getFunction('{name}').summary().inlineFunctions)"), None);
                    assert!(result.error.is_none(), "{:?}", result.error);
                    let result: Value = serde_json::from_str(&result.output).unwrap();
                    assert_eq!(result, expected);
                    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                        .arg("--mcp")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .spawn()
                        .unwrap();
                    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code}}});
                    let output = common::mcp_request(child, &request);
                    assert!(output.status.success());
                    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(response["result"]["isError"], false, "{response}");
                    let result: Value = serde_json::from_str(
                        response["result"]["content"][0]["text"].as_str().unwrap(),
                    )
                    .unwrap();
                    assert_eq!(result, expected);
                }
            }
        }
    }
    for function in ["strlen", "strcmp", "strncmp", "memcmp", "strchr", "strcpy"] {
        assert!(seen.contains(function), "{function}: {seen:?}");
    }
}

#[test]
fn byte_pairs_bounds_terminators_and_search_targets_match_native() {
    for architecture in ["x86_64", "aarch64"] {
        for compiler in ["clang", "gcc"] {
            let label = format!("{architecture}.{compiler}.O2.debug");
            let path = common::root().join(format!("tests/data/string_functions/{label}.elf"));
            let mut binary = Binary::open(&path).unwrap();
            let mut source = String::from("#include <stdint.h>\n#include <string.h>\n");
            let mut checks = String::new();
            let mut initialization = String::new();
            let mut empty_checks = String::new();
            for name in [
                "length",
                "string_compare",
                "memory_compare",
                "bounded_compare",
                "find",
                "short_compare",
                "short_string_compare",
                "copy_literal",
            ] {
                let addr = binary.find_address(name).unwrap();
                let rendered = binary
                    .decompile_with_dependencies(addr, None, None)
                    .unwrap();
                let expressions: &[&str] = match name {
                    "length" => &["a"],
                    "copy_literal" => &["destination+1"],
                    "find" => &["a", "target"],
                    "memory_compare" | "bounded_compare" => &["a", "b", "n"],
                    _ => &["a", "b"],
                };
                let args = arguments(&rendered.code, name, expressions);
                if matches!(name, "memory_compare" | "bounded_compare") {
                    if !rendered.inline_functions.is_empty() {
                        assert!(
                            rendered.code.contains("== 0) {\n        return 0;\n    }"),
                            "{}",
                            rendered.code
                        );
                    }
                    let empty_args = arguments(&rendered.code, name, &["0", "0", "0"]);
                    empty_checks.push_str(&format!("if ({name}({empty_args}) != 0) return 5;"));
                }
                let check = match name {
                    "length" => format!("if ({name}({args}) != strlen((char *)a)) return 1;"),
                    "find" => format!(
                        "for (int target=(int)y-256;target<=(int)y+256;target+=256) if ((uintptr_t){name}({args}) != (uintptr_t)strchr((char *)a,target)) return 2;"
                    ),
                    "copy_literal" => format!(
                        "memset(destination,0xab,16); {name}({args}); if(destination[0]!=0xab || memcmp(destination+1,\"copy\",5) || destination[6]!=0xab) return 3;"
                    ),
                    _ => {
                        let native = match name {
                            "string_compare" => "strcmp((char *)a,(char *)b)",
                            "memory_compare" => "memcmp(a,b,n)",
                            "bounded_compare" => "strncmp((char *)a,(char *)b,n)",
                            "short_compare" => "memcmp(a,b,3)",
                            _ => "strncmp((char *)a,(char *)b,3)",
                        };
                        format!(
                            "{{ int reference={native}; if ({name}({args}) != (reference>0)-(reference<0)) return 4; }}"
                        )
                    }
                };
                checks.push_str(&check);
                source.push_str(&rendered.code);
                let (definitions, setup) = literal_definitions(&rendered, &binary);
                source.push_str(&definitions);
                initialization.push_str(&setup);
            }
            source.push_str(&format!("int main(void) {{ {initialization} {empty_checks} _Alignas(16) unsigned char a[8],b[8],destination[16]; for(unsigned x=0;x<256;++x) for(unsigned y=0;y<256;++y) for(unsigned position=0;position<3;++position) for(unsigned zero=0;zero<4;++zero) {{ memset(a,1,8); memset(b,1,8); a[position]=x; b[position]=y; a[zero]=b[zero]=0; for(unsigned n=0;n<5;++n) {{ {checks} }} }} return 0; }}\n"));
            let directory = common::root()
                .join("target/string-function-tests")
                .join(label);
            fs::create_dir_all(&directory).unwrap();
            let input = directory.join("byte_pairs.c");
            let output = directory.join("byte_pairs");
            common::compiler::compile_file(
                Command::new("clang")
                    .args(["-std=c11", "-Werror", "-O2", "-fno-strict-aliasing"])
                    .arg(&input)
                    .arg("-o")
                    .arg(&output),
                &input,
                &source,
            );
            assert!(
                Command::new(&output).status().unwrap().success(),
                "{architecture} {compiler}"
            );
        }
    }
}

#[test]
fn pointer_typed_counts_compile_and_preserve_their_integer_value() {
    for architecture in ["x86_64", "aarch64"] {
        let label = format!("{architecture}.clang.O2.debug");
        let path = common::root().join(format!("tests/data/string_functions/{label}.elf"));
        let mut binary = declared_binary(
            &path,
            &label,
            "memory_compare",
            "int (unsigned char *a, unsigned char *b, void *n)",
        );
        let addr = binary.find_address("memory_compare").unwrap();
        let rendered = binary
            .decompile_with_dependencies(addr, None, None)
            .unwrap();
        assert!(
            rendered
                .inline_functions
                .iter()
                .any(|call| call.function == "memcmp"),
            "{}",
            rendered.code
        );
        let args = arguments(&rendered.code, "memory_compare", &["a", "b", "n"]);
        let empty = arguments(&rendered.code, "memory_compare", &["0", "0", "0"]);
        let source = format!(
            "#include <stdint.h>\n#include <string.h>\n{}\nint main(void) {{ unsigned char a[8],b[8]; if(memory_compare({empty})!=0) return 1; for(unsigned n=0;n<=8;++n) for(unsigned x=0;x<256;++x) for(unsigned position=0;position<8;++position) {{ memset(a,1,8); memset(b,1,8); a[position]=x; b[position]=255-x; int reference=memcmp(a,b,n); if(memory_compare({args})!=(reference>0)-(reference<0)) return 2; }} return 0; }}\n",
            rendered.code
        );
        let directory = common::root()
            .join("target/string-function-tests")
            .join(label);
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("pointer_count.c");
        let output = directory.join("pointer_count");
        common::compiler::compile_file(
            Command::new("clang")
                .args(["-std=c11", "-Werror", "-O2"])
                .arg(&input)
                .arg("-o")
                .arg(&output),
            &input,
            &source,
        );
        assert!(
            Command::new(&output).status().unwrap().success(),
            "{architecture}"
        );
    }
}

#[test]
fn library_names_do_not_introduce_recursive_calls() {
    for architecture in ["x86_64", "aarch64"] {
        let label = format!("{architecture}.clang.O2.debug");
        let path = common::root().join(format!("tests/data/string_functions/{label}.elf"));
        let mut binary = fixture_binary(&path, &label);
        for (original, library) in [
            ("length", "strlen"),
            ("string_compare", "strcmp"),
            ("bounded_compare", "strncmp"),
            ("memory_compare", "memcmp"),
            ("find", "strchr"),
            ("copy_literal", "strcpy"),
        ] {
            let addr = binary.find_address(original).unwrap();
            let mut ir = binary.analysis(addr, None).unwrap().ir.clone();
            for renamed in [false, true] {
                let mut symbols = velk::render::Symbols::default();
                if renamed {
                    ir.name = Some(original.to_owned());
                    symbols.functions.insert(addr, library.to_owned());
                } else {
                    ir.name = Some(library.to_owned());
                }
                let rendered = velk::render::render_with_dependencies(&ir, &[], &symbols, &[]);
                assert!(
                    !rendered
                        .inline_functions
                        .iter()
                        .any(|call| call.function == library),
                    "{}",
                    rendered.code
                );
                assert!(
                    !rendered.code.contains(&format!("__builtin_{library}(")),
                    "{}",
                    rendered.code
                );
                if library == "strlen" && renamed {
                    let args = arguments(&rendered.code, library, &["data"]);
                    let source = format!(
                        "#include <stdint.h>\n{}\nint main(void) {{ unsigned char data[8]; for(unsigned x=1;x<256;++x) for(unsigned n=0;n<8;++n) {{ for(unsigned i=0;i<8;++i) data[i]=x; data[n]=0; if(strlen({args})!=n) return 1; }} return 0; }}\n",
                        rendered.code
                    );
                    let directory = common::root()
                        .join("target/string-function-tests")
                        .join(&label);
                    fs::create_dir_all(&directory).unwrap();
                    let input = directory.join("strlen.c");
                    let output = directory.join("strlen");
                    common::compiler::compile_file(
                        Command::new("clang")
                            .args(["-std=c11", "-Werror", "-O2", "-fno-builtin"])
                            .arg(&input)
                            .arg("-o")
                            .arg(&output),
                        &input,
                        &source,
                    );
                    assert!(Command::new(&output).status().unwrap().success());
                }
            }
        }
    }
}

#[test]
fn memory_comparison_accepts_object_pointers_without_casts() {
    for architecture in ["x86_64", "aarch64"] {
        let label = format!("{architecture}.clang.O2.debug");
        let path = common::root().join(format!("tests/data/string_functions/{label}.elf"));
        let mut binary = fixture_binary(&path, &label);
        let address = binary.find_address("memory_compare").unwrap();
        let rendered = binary
            .decompile_with_dependencies(address, None, None)
            .unwrap();
        assert!(
            rendered.code.contains("__builtin_memcmp(a, b, n)"),
            "{}",
            rendered.code
        );
    }
}
