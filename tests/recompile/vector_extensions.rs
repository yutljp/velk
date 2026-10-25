use super::*;

#[test]
fn printed_packed_extensions_keep_every_lane_and_read_only_the_source_width() {
    let scratch = scratch_dir("vector-extensions");
    let assembly = scratch.join("extensions.s");
    let object = scratch.join("extensions.o");
    let mut source = String::from(".text\n");
    let forms = [
        ("bw", 8, 16),
        ("bd", 8, 32),
        ("bq", 8, 64),
        ("wd", 16, 32),
        ("wq", 16, 64),
        ("dq", 32, 64),
    ];
    for signed in [false, true] {
        for (suffix, _, _) in forms {
            for memory in [false, true] {
                let instruction = format!("pmov{}{}", if signed { "sx" } else { "zx" }, suffix);
                let name = format!("extend_{instruction}_{memory}");
                let body = if memory {
                    format!("{instruction} (%rdi), %xmm0")
                } else {
                    format!("movq (%rdi), %xmm0\n{instruction} %xmm0, %xmm0")
                };
                writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\n{body}\nmovdqu %xmm0, (%rsi)\nmovl $7, %eax\nret\n.size {name}, .-{name}").unwrap();
            }
        }
    }
    std::fs::write(&assembly, source).unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    for signed in [false, true] {
        for (suffix, from, to) in forms {
            for memory in [false, true] {
                let name = format!(
                    "extend_pmov{}{}_{memory}",
                    if signed { "sx" } else { "zx" },
                    suffix
                );
                let address = binary.find(&name).unwrap().addr;
                let input_type = binary.analysis(address, None).unwrap().ir.params[0]
                    .ty
                    .to_string();
                let code = binary.decompile(address, None, None).unwrap();
                assert!(!code.contains("unsupported"), "{code}");
                let read = if memory { 128 / to * from / 8 } else { 8 };
                let source_type = format!("{}int{from}_t", if signed { "" } else { "u" });
                let destination_type = format!("{}int{to}_t", if signed { "" } else { "u" });
                syntax::run_printed(
                    &code,
                    "#include <string.h>\n#include <sys/mman.h>\n#include <unistd.h>\n",
                    &format!(
                        "uint64_t input = UINT64_C(0x807fff01fedcba98); size_t page = sysconf(_SC_PAGESIZE); uint8_t *mapping = mmap(0, 2*page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0); if(mapping==MAP_FAILED || mprotect(mapping+page,page,PROT_NONE)) return 2; uint8_t *source = mapping+page-{read}; memcpy(source,&input,{read}); uint64_t out[2] = {{0,0}}; uint64_t expected[2] = {{0,0}}; for (unsigned i=0; i<128/{to}; ++i) {{ {source_type} lane; memcpy(&lane, (uint8_t *)&input+i*({from}/8), sizeof lane); {destination_type} wide=lane; memcpy((uint8_t *)expected+i*({to}/8), &wide, sizeof wide); }} if ({name}(({input_type})(uintptr_t)source,(uintptr_t)out)!=7 || memcmp(out,expected,16)) return 1; munmap(mapping,2*page);"
                    ),
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}
