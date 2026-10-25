use super::*;

#[test]
fn printed_byte_insertions_preserve_other_lanes_and_read_one_memory_byte() {
    let scratch = scratch_dir("byte-insertions");
    let assembly = scratch.join("insert.s");
    let object = scratch.join("insert.o");
    let mut source = String::from(".text\n");
    for memory in [false, true] {
        for lane in 0..16 {
            let name = format!("insert_{memory}_{lane}");
            let operand = if memory { "(%rsi)" } else { "%esi" };
            writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\nmovdqu (%rdi), %xmm0\npinsrb ${}, {operand}, %xmm0\nmovdqu %xmm0, (%rdx)\nmovl $7, %eax\nret\n.size {name}, .-{name}", lane + 16).unwrap();
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
    for memory in [false, true] {
        for lane in 0..16 {
            let name = format!("insert_{memory}_{lane}");
            let address = binary.find(&name).unwrap().addr;
            let ir = &binary.analysis(address, None).unwrap().ir;
            let argument_type = ir.params[1].ty.to_string();
            let code = binary.decompile(address, None, None).unwrap();
            assert!(!code.contains("unsupported"), "{code}");
            let value = if memory {
                "(uintptr_t)byte"
            } else {
                "0xffffffabU"
            };
            syntax::run_printed(
                &code,
                "#include <string.h>\n#include <sys/mman.h>\n#include <unistd.h>\n",
                &format!(
                    "size_t page = sysconf(_SC_PAGESIZE); uint8_t *p = mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0); if(p==MAP_FAILED || mprotect(p+page,page,PROT_NONE)) return 2; uint8_t *byte=p+page-1; *byte=0xab; uint8_t input[16], output[16], expected[16]; for(unsigned i=0;i<16;++i) input[i]=i*13+7; memcpy(expected,input,16); expected[{lane}]=0xab; if({name}((uintptr_t)input,({argument_type})({value}),(uintptr_t)output)!=7 || memcmp(output,expected,16)) return 1; munmap(p,2*page);"
                ),
            );
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_word_extractions_store_two_bytes_and_preserve_saved_registers() {
    let scratch = scratch_dir("word-extractions");
    let assembly = scratch.join("extract.s");
    let object = scratch.join("extract.o");
    let mut source = String::from(".text\n");
    for instruction in ["pextrw", "vpextrw"] {
        for lane in 0..8 {
            let name = format!("extract_{instruction}_{lane}");
            writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\npushq %rbp\nmovq %rsp, %rbp\nmovdqu (%rdi), %xmm0\n{instruction} ${}, %xmm0, (%rsi)\nmovl $7, %eax\npopq %rbp\nret\n.size {name}, .-{name}", lane + 8).unwrap();
        }
    }
    source.push_str(".globl extraction_caller\n.type extraction_caller,@function\nextraction_caller:\npushq %rbp\nmovq %rsp,%rbp\nsubq $16,%rsp\nmovq $123,-8(%rbp)\ncall extract_pextrw_0\nmovq -8(%rbp),%rax\naddq $16,%rsp\npopq %rbp\nret\n.size extraction_caller,.-extraction_caller\n");
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
    let mut all = String::new();
    for instruction in ["pextrw", "vpextrw"] {
        for lane in 0..8 {
            let name = format!("extract_{instruction}_{lane}");
            let address = binary.find(&name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(!code.contains("unsupported"), "{code}");
            syntax::run_printed(
                &code,
                "#include <string.h>\n",
                &format!(
                    "uint16_t input[8]={{0x807f,0x1234,0xfedc,0x4321,0xabcd,0x9876,0x1357,0x2468}}; uint16_t out[3]={{0x5555,0,0xaaaa}}; if({name}((uintptr_t)input,(uintptr_t)&out[1])!=7 || out[0]!=0x5555 || out[1]!=input[{lane}] || out[2]!=0xaaaa) return 1;"
                ),
            );
            if instruction == "pextrw" && lane == 0 {
                all.push_str(&code);
            }
        }
    }
    let address = binary.find("extraction_caller").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("undefined"), "{code}");
    all.push_str(&code);
    syntax::run_printed(
        &all,
        "",
        "uint16_t input[8]={9}; uint16_t out=0; if(extraction_caller((uintptr_t)input,(uintptr_t)&out)!=123 || out!=9) return 1;",
    );
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_dword_extractions_zero_extend_registers_and_store_four_bytes() {
    let scratch = scratch_dir("dword-extractions");
    let assembly = scratch.join("extract.s");
    let object = scratch.join("extract.o");
    let mut source = String::from(".text\n");
    for instruction in ["pextrd", "vpextrd"] {
        for memory in [false, true] {
            for lane in 0..4 {
                let name = format!("extract_{instruction}_{memory}_{lane}");
                let target = if memory { "(%rsi)" } else { "%eax" };
                let result = if memory { "movl $7,%eax\n" } else { "" };
                writeln!(source, ".globl {name}\n.type {name},@function\n{name}:\nmovdqu (%rdi),%xmm0\nmovq $-1,%rax\n{instruction} ${},%xmm0,{target}\n{result}ret\n.size {name},.-{name}",lane+4).unwrap();
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
    for instruction in ["pextrd", "vpextrd"] {
        for memory in [false, true] {
            for lane in 0..4 {
                let name = format!("extract_{instruction}_{memory}_{lane}");
                let address = binary.find(&name).unwrap().addr;
                let code = binary.decompile(address, None, None).unwrap();
                assert!(!code.contains("unsupported"), "{code}");
                let check = if memory {
                    format!(
                        "if({name}((uintptr_t)input,(uintptr_t)&out[1])!=7 || out[0]!=0x55555555 || out[1]!=input[{lane}] || out[2]!=0xaaaaaaaa) return 1;"
                    )
                } else {
                    format!("if((uint64_t){name}((uintptr_t)input)!=input[{lane}]) return 1;")
                };
                syntax::run_printed(
                    &code,
                    "",
                    &format!(
                        "uint32_t input[4]={{0x807fffff,0x12345678,0xfedcba98,0x43210123}}; uint32_t out[3]={{0x55555555,0,0xaaaaaaaa}}; {check}"
                    ),
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}
