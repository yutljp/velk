//! Instruction comments checked against disassembly and native C execution.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use velk::service::Binary;

const SOURCE: &str = include_str!("cases/c/instruction_addresses.c");
const FUNCTIONS: &[&str] = &[
    "address_add",
    "address_store",
    "address_branch",
    "address_call",
];

#[test]
fn documented_commands_and_scripts_run() {
    for document in [
        include_str!("../docs/INSTRUCTION_ADDRESSES.md"),
        include_str!("../docs/INSTRUCTION_ADDRESSES.ja.md"),
    ] {
        for section in document.split("```sh\n").skip(1) {
            let commands = section.split("```").next().unwrap();
            for command in commands.lines() {
                let mut words = command.split_whitespace();
                assert_eq!(words.next(), Some("velk"));
                let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                    .args(words)
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{command}: {output:?}");
            }
        }
        for section in document.split("```js\n").skip(1) {
            let code = section.split("```").next().unwrap();
            let outcome = velk::script::Engine::new().unwrap().run(code, None);
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            assert!(outcome.output.contains("/* 0x"));
        }
    }
}

fn comment(line: &str) -> Option<(&str, u64)> {
    let Some((code, suffix)) = line.rsplit_once(" /* 0x") else {
        return None;
    };
    let Some(digits) = suffix.strip_suffix(" */") else {
        return None;
    };
    match u64::from_str_radix(digits, 16) {
        Ok(address) => Some((code.trim_end(), address)),
        Err(_) => None,
    }
}

fn exchange(mode: &str, request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stdio server starts");
    writeln!(child.stdin.take().expect("stdin is piped"), "{request}").expect("request is written");
    let output = child.wait_with_output().expect("server exits");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("response is JSON")
}

fn interfaces(object: &std::path::Path) {
    let script = format!(
        r#"
const b = velk.open({object:?}, {{cache:false}});
const f = b.getFunction('address_store');
const annotated = f.decompile({{addresses:true}});
if (!annotated.includes('/* 0x')) throw new Error('missing addresses');
if (f.decompile().includes('/* 0x')) throw new Error('option leaked');
if (!b.decompile([f], {{addresses:true}})[0].code.includes('/* 0x')) throw new Error('missing batch addresses');
if (b.decompile([f])[0].code.includes('/* 0x')) throw new Error('batch option leaked');
annotated
"#
    );
    let outcome = velk::script::Engine::new()
        .expect("JavaScript engine starts")
        .run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    let response = exchange("--serve", json!({"id":1,"code":script}));
    let code = response["result"].as_str().expect("response contains text");
    assert_eq!(code.trim(), outcome.output.trim());
    let response = exchange(
        "--mcp",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call", "params":{"name":"velk_run_script","arguments":{"code":script,"max_output_chars":20000}}}),
    );
    assert_eq!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP result contains text")
            .trim(),
        code.trim()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["-D", "--json", "--cache", "off"])
        .arg(object)
        .args(["address_add", "address_store"])
        .output()
        .expect("CLI starts");
    assert!(output.status.success(), "{output:?}");
    let response: Value = serde_json::from_slice(&output.stdout).expect("response is JSON");
    let code = response["code"].as_str().expect("response contains text");
    assert_eq!(
        response["addresses"],
        json!(velk::render::instruction_addresses(code))
    );
    assert!(
        !response["addresses"]
            .as_object()
            .expect("address map is an object")
            .is_empty()
    );
    for (line, addresses) in response["addresses"]
        .as_object()
        .expect("address map is an object")
    {
        let line: usize = line.parse().expect("line number is an integer");
        let text = code.lines().nth(line - 1).expect("mapped line exists");
        for address in addresses.as_array().expect("line addresses are a list") {
            assert!(
                text.contains(address.as_str().expect("response contains text")),
                "{text}"
            );
        }
    }
}

#[test]
fn comments_match_effect_instructions_and_native_execution() {
    for (isa, target) in [
        ("x86_64", "x86_64-unknown-linux-gnu"),
        ("i386", "i386-unknown-linux-gnu"),
        ("aarch64", "aarch64-unknown-linux-gnu"),
        ("arm32", "armv7-unknown-linux-gnueabihf"),
    ] {
        for optimization in ["O0", "O2"] {
            let directory =
                common::root().join(format!("target/instruction-addresses/{isa}/{optimization}"));
            fs::create_dir_all(&directory).unwrap();
            let source = directory.join("effects.c");
            let object = directory.join("effects.o");
            let mut compiler = Command::new("clang");
            compiler
                .arg(format!("--target={target}"))
                .args(["-ffreestanding", "-g", "-c"])
                .arg(format!("-{optimization}"))
                .arg(&source)
                .arg("-o")
                .arg(&object);
            common::compiler::compile_file(&mut compiler, &source, SOURCE);

            let mut binary = Binary::open(&object).unwrap();
            let mut printed = String::new();
            let mut pointer_arguments = BTreeMap::new();
            let mut returns = 0;
            let mut stores = 0;
            let mut calls = 0;
            let mut branches = 0;
            for &name in FUNCTIONS {
                let addr = binary.find(name).unwrap().addr;
                let baseline = binary.decompile(addr, None, None).unwrap();
                binary.set_instruction_addresses(true);
                let code = binary.decompile(addr, None, None).unwrap();
                binary.set_instruction_addresses(false);
                assert_eq!(binary.decompile(addr, None, None).unwrap(), baseline);
                let mut instructions = BTreeMap::new();
                for line in binary.disasm(addr, usize::MAX).unwrap() {
                    instructions.insert(line.addr, line.instruction);
                }
                let stripped: String = code
                    .lines()
                    .map(|line| {
                        let text = comment(line).map_or(line, |(text, _)| text);
                        format!("{text}\n")
                    })
                    .collect();
                assert_eq!(stripped, baseline, "{isa} {optimization} {name}");
                for line in code.lines() {
                    let Some((text, address)) = comment(line) else {
                        continue;
                    };
                    let instruction = instructions
                        .get(&address)
                        .unwrap_or_else(|| panic!("{line}"));
                    let mnemonic = instruction.split_whitespace().next().unwrap();
                    let predicated = isa == "arm32"
                        && [
                            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt",
                            "gt", "le",
                        ]
                        .iter()
                        .any(|suffix| mnemonic.ends_with(suffix));
                    let mnemonic = if predicated {
                        &mnemonic[..mnemonic.len() - 2]
                    } else {
                        mnemonic
                    };
                    if text.trim_start().starts_with("return ") {
                        assert!(
                            mnemonic == "ret"
                                || isa == "arm32"
                                    && (mnemonic == "bx" && instruction.contains("lr")
                                        || mnemonic == "pop" && instruction.contains("pc")),
                            "{isa} {optimization}: {line}: {instruction}"
                        );
                        returns += 1;
                    } else if text.contains("address_effect(") {
                        assert!(matches!(mnemonic, "call" | "bl"), "{line}: {instruction}");
                        calls += 1;
                    } else if text.trim_start().starts_with("if (") {
                        assert!(
                            mnemonic.starts_with('j')
                                || predicated
                                || mnemonic.starts_with("b.")
                                || isa == "arm32"
                                    && mnemonic.starts_with('b')
                                    && !matches!(mnemonic, "bl" | "bx")
                                || matches!(mnemonic, "cbz" | "cbnz" | "tbz" | "tbnz"),
                            "{line}: {instruction}"
                        );
                        branches += 1;
                    } else if text.trim_start().starts_with('*') {
                        assert!(
                            matches!(mnemonic, "mov" | "str" | "stur"),
                            "{line}: {instruction}"
                        );
                        if matches!(isa, "x86_64" | "i386") {
                            let destination = instruction.split(',').next().unwrap();
                            assert!(
                                destination.contains('[')
                                    && !destination.contains("rbp")
                                    && !destination.contains("rsp")
                                    && !destination.contains("ebp")
                                    && !destination.contains("esp"),
                                "{instruction}"
                            );
                        } else {
                            assert!(!instruction.contains("[sp"), "{instruction}");
                        }
                        if optimization == "O0" {
                            let operation = if text.contains('^') { "xor" } else { "add" };
                            let preceding: Vec<_> =
                                instructions.range(..address).rev().take(4).collect();
                            assert!(
                                preceding.iter().any(|(_, text)| {
                                    text.starts_with(operation)
                                        || operation == "xor" && text.starts_with("eor")
                                }),
                                "{line}: {preceding:?}"
                            );
                        }
                        stores += 1;
                    } else if text.contains(" = ") {
                        if text.contains('?') {
                            assert!(
                                mnemonic.starts_with("cmov")
                                    || mnemonic == "csel"
                                    || isa == "arm32"
                                        && matches!(mnemonic, "movne" | "moveq" | "mov"),
                                "{line}: {instruction}"
                            );
                        } else {
                            let arithmetic = if text.contains('^') {
                                matches!(mnemonic, "xor" | "eor" | "eors")
                            } else if text.contains("+ 3") {
                                matches!(mnemonic, "add" | "adds" | "lea")
                            } else {
                                false
                            };
                            assert!(
                                arithmetic
                                    || matches!(mnemonic, "mov" | "str" | "stur" | "ldr" | "ldur"),
                                "{line}: {instruction}"
                            );
                        }
                    } else {
                        panic!("uncovered commented statement: {isa} {optimization}: {line}");
                    }
                    assert!(!matches!(text.trim(), "{" | "}" | "} else {"), "{line}");
                }
                if matches!(name, "address_store" | "address_branch") {
                    let signature = code
                        .lines()
                        .find(|line| line.ends_with('{') && line.contains(&format!("{name}(")))
                        .unwrap();
                    let parameter = signature
                        .split_once('(')
                        .unwrap()
                        .1
                        .split(',')
                        .next()
                        .unwrap();
                    pointer_arguments.insert(
                        name,
                        if parameter.contains('*') {
                            "slot"
                        } else {
                            "(uint32_t)(uintptr_t)slot"
                        },
                    );
                }
                printed.push_str(&code);
            }
            assert!(returns >= 4, "{isa} {optimization}: {printed}");
            assert!(stores >= 2, "{isa} {optimization}: {printed}");
            assert_eq!(calls, 1, "{isa} {optimization}: {printed}");
            if optimization == "O0" {
                assert!(branches >= 1, "{isa}: {printed}");
            }

            let source = directory.join("commented.c");
            let mut compiler = Command::new("clang");
            compiler
                .arg(format!("--target={target}"))
                .args([
                    "-ffreestanding",
                    "-std=c11",
                    "-Werror=implicit-function-declaration",
                    "-c",
                ])
                .arg(&source)
                .arg("-o")
                .arg(directory.join("commented.o"));
            common::compiler::compile_file(
                &mut compiler,
                &source,
                &velk::render::combine(&printed),
            );
            let narrow = matches!(isa, "i386" | "arm32");
            let combined = velk::render::combine(&printed);
            // The callback result is unused; its host declaration must match the printed C.
            let reference = if combined.contains("uint64_t address_effect(") {
                SOURCE.replace("typedef unsigned long u64;", "typedef uint64_t u64;")
            } else {
                SOURCE.to_owned()
            };
            let mut native = format!(
                "#define _GNU_SOURCE\n#include <stdint.h>\n#include <sys/mman.h>\n#define TEST_NARROW {}\n#define STORE_POINTER {}\n#define BRANCH_POINTER {}\n",
                usize::from(narrow),
                pointer_arguments["address_store"],
                pointer_arguments["address_branch"]
            );
            for name in FUNCTIONS {
                native.push_str(&format!("#define {name} reference_{name}\n"));
            }
            native.push_str(&reference);
            for name in FUNCTIONS {
                native.push_str(&format!("#undef {name}\n"));
            }
            native.push_str(&combined);
            native.push_str(r#"
int main(void) {
    uint32_t *slot;
#if TEST_NARROW
    void *mapping = mmap((void *)0x70000000, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping != (void *)0x70000000) return 5;
    slot = mapping;
#endif
    uint32_t seed = 0x9e3779b9u;
    for (uint32_t i = 0; i < 4096; ++i) {
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        uint32_t value = i < 64 ? (i & 1 ? UINT32_MAX - i / 2 : i / 2) : seed;
        uint32_t actual = 0, expected = 0;
        if (address_add(value) != reference_address_add(value)) return 1;
#if !TEST_NARROW
        slot = &actual;
#endif
        *slot = 0;
        if (address_store(STORE_POINTER, value) != reference_address_store(&expected, value) || *slot != expected) return 2;
        if (address_branch(BRANCH_POINTER, value) != reference_address_branch(&expected, value) || *slot != expected) return 3;
        address_effect_value = ~value;
        actual = address_call(value);
        uint32_t actual_effect = address_effect_value;
        address_effect_value = ~value;
        expected = reference_address_call(value);
        if (actual != expected || actual_effect != address_effect_value || actual_effect != value) return 4;
    }
#if TEST_NARROW
    if (munmap(slot, 0x4000) != 0) return 6;
#endif
    return 0;
}
"#);
            let source = directory.join("printed.c");
            for level in ["-O0", "-O2"] {
                let executable = directory.join(format!("printed{level}"));
                let mut compiler = Command::new("clang");
                if narrow && cfg!(target_os = "macos") {
                    compiler.args(["-arch", "x86_64", "-Wl,-pagezero_size,0x1000"]);
                }
                compiler
                    .args([
                        "-std=c11",
                        "-Werror=implicit-function-declaration",
                        "-fsanitize=undefined",
                        "-fno-sanitize-recover=undefined",
                        level,
                    ])
                    .arg(&source)
                    .arg("-o")
                    .arg(&executable);
                common::compiler::compile_file(&mut compiler, &source, &native);
                let result = Command::new(&executable).output().unwrap();
                assert!(
                    result.status.success(),
                    "{isa} {optimization} {level}: {result:?}"
                );
            }

            let result = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["-D", "--addresses", "--cache", "off"])
                .arg(&object)
                .args(FUNCTIONS)
                .output()
                .unwrap();
            assert!(result.status.success(), "{result:?}");
            assert_eq!(
                String::from_utf8(result.stdout).unwrap(),
                velk::render::combine(&printed)
            );
            interfaces(&object);
        }
    }
}
