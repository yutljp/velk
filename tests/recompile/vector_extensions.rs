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
    common::compiler::compile_x86_64_assembly(&compiler(), &assembly, &object, &source);
    let mut binary = Binary::open(&object).unwrap();
    for signed in [false, true] {
        for (suffix, source_width, destination_width) in forms {
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
                let bytes_read = if memory {
                    128 / destination_width * source_width / 8
                } else {
                    8
                };
                let source_type = format!("{}int{source_width}_t", if signed { "" } else { "u" });
                let destination_type =
                    format!("{}int{destination_width}_t", if signed { "" } else { "u" });
                syntax::run_printed(
                    &code,
                    "#include <string.h>\n#include <sys/mman.h>\n#include <unistd.h>\n",
                    &format!(
                        "uint64_t input = UINT64_C(0x807fff01fedcba98); size_t page = sysconf(_SC_PAGESIZE); uint8_t *mapping = mmap(0, 2*page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0); if(mapping==MAP_FAILED || mprotect(mapping+page,page,PROT_NONE)) return 2; uint8_t *source = mapping+page-{bytes_read}; memcpy(source,&input,{bytes_read}); uint64_t out[2] = {{0,0}}; uint64_t expected[2] = {{0,0}}; for (unsigned i=0; i<128/{destination_width}; ++i) {{ {source_type} lane; memcpy(&lane, (uint8_t *)&input+i*({source_width}/8), sizeof lane); {destination_type} wide=lane; memcpy((uint8_t *)expected+i*({destination_width}/8), &wide, sizeof wide); }} if ({name}(({input_type})(uintptr_t)source,(uintptr_t)out)!=7 || memcmp(out,expected,16)) return 1; munmap(mapping,2*page);"
                    ),
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn unsigned_dword_packing_saturates_each_lane_and_preserves_the_callers_frame() {
    let scratch = scratch_dir("unsigned-dword-packing");
    let assembly = scratch.join("packing.s");
    let object = scratch.join("packing.o");
    let mut source = String::from(".text\n");
    for (name, operand) in [("pack_register", "%xmm0"), ("pack_memory", "16(%rdi)")] {
        writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\npushq %rbp\nmovq %rsp, %rbp\nmovdqu (%rdi), %xmm0\npackusdw {operand}, %xmm0\nmovdqu %xmm0, (%rsi)\nmovl $7, %eax\npopq %rbp\nret\n.size {name}, .-{name}").unwrap();
    }
    source.push_str(".globl packing_caller\n.type packing_caller,@function\npacking_caller:\npushq %rbp\nmovq %rsp, %rbp\nsubq $16, %rsp\nmovq %rdx, -8(%rbp)\ncall pack_register\nmovq -8(%rbp), %rax\naddq $16, %rsp\npopq %rbp\nret\n.size packing_caller, .-packing_caller\n");
    common::compiler::compile_x86_64_assembly(&compiler(), &assembly, &object, &source);
    let mut binary = Binary::open(&object).unwrap();
    let mut code = String::new();
    for name in ["pack_register", "pack_memory", "packing_caller"] {
        let address = binary.find(name).unwrap().addr;
        let printed = binary.decompile(address, None, None).unwrap();
        assert!(!printed.contains("unsupported"), "{printed}");
        assert!(!printed.contains("undefined"), "{printed}");
        code.push_str(&printed);
    }
    syntax::run_printed(
        &velk::render::combine(&code),
        "#include <string.h>\n",
        "int32_t input[8] = {INT32_MIN, -1, 0, 65535, 1, 65534, 65536, INT32_MAX};
         uint16_t output[8]; uint16_t expected[8];
         for (unsigned trial = 0; trial < 8; ++trial) {
             for (unsigned i = 0; i < 8; ++i) {
                 int32_t lane = input[i % 4];
                 expected[i] = lane < 0 ? 0 : lane > 65535 ? 65535 : lane;
             }
             memset(output, 0xa5, sizeof output);
             if (pack_register((uintptr_t)input, (uintptr_t)output) != 7 || memcmp(output, expected, 16)) return 1;
             memset(output, 0xa5, sizeof output);
             if ((uint32_t)packing_caller((uintptr_t)input, (uintptr_t)output, UINT64_C(0xfedcba9876543210)) != UINT32_C(0x76543210) || memcmp(output, expected, 16)) return 2;
             for (unsigned i = 0; i < 8; ++i) {
                 int32_t lane = input[i];
                 expected[i] = lane < 0 ? 0 : lane > 65535 ? 65535 : lane;
             }
             if (pack_memory((void *)input, (uintptr_t)output) != 7 || memcmp(output, expected, 16)) return 3;
             int32_t first = input[0];
             memmove(input, input + 1, 7 * sizeof *input);
             input[7] = first;
         }",
    );
    std::fs::remove_dir_all(scratch).ok();
}
