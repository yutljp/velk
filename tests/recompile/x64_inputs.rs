use super::*;

#[test]
fn printed_x64_inputs_exclude_dead_reads_and_unused_call_positions() {
    let scratch = scratch_dir("x64-inputs");
    let assembly = scratch.join("inputs.s");
    let object = scratch.join("inputs.o");
    let mut source = String::from(".text\n");
    for (name, body) in [
        ("last_input", "movl $0, %edx\nmovq %r8, %rax\nret"),
        (
            "sets_inputs",
            "pushq %rbp\nmovq %rsp, %rbp\nmovl $8, %r8d\ncall last_input\npopq %rbp\nret",
        ),
        (
            "dead_inputs",
            "movq %rcx, %r10\naddq %rsi, %r10\nmovl $7, %eax\nret",
        ),
        ("overwritten_inputs", "movl $19, %ecx\nmovq %rcx, %rax\nret"),
        (
            "inline_probe",
            "subq $4096, %rsp\nmovq $0, (%rsp)\nsubq $4096, %rsp\nmovq $0, (%rsp)\nsubq $24, %rsp\nmovl %edi, (%rsp)\nmovl %esi, 8192(%rsp)\nmovl (%rsp), %eax\naddl 8192(%rsp), %eax\naddq $8216, %rsp\nret",
        ),
        (
            "partial_input",
            "movq %rdi, %rax\nmovb $7, %al\naddq $256, %rax\nret",
        ),
        (
            "calls_partial",
            "pushq %rbp\nmovq %rsp, %rbp\ncall partial_input\npopq %rbp\nret",
        ),
        (
            "partial_word_address",
            "movabsq $0x400000000, %rax\nmovw (%rdi), %ax\naddw $1, %ax\nmovzwl %ax, %eax\nret",
        ),
        (
            "absolute_word_loop",
            "testl %edi, %edi\njz 2f\npushq %rbx\nmovabsq $0x400000000, %rbx\nxorl %eax, %eax\n1: movzwl (%rax,%rbx), %edx\naddl $6, %edx\nmovw %dx, (%rax,%rbx)\naddq $2, %rax\ncmpq $12, %rax\njne 1b\npopq %rbx\n2: movl $111, %eax\nret",
        ),
        (
            "absolute_stride",
            "imulq $112, %rdi, %rax\nmovabsq $0x400000000, %rdx\nmovl $1, (%rax,%rdx)\nret",
        ),
    ] {
        writeln!(
            source,
            ".globl {name}\n.type {name},@function\n{name}:\n{body}\n.size {name}, .-{name}"
        )
        .unwrap();
    }
    common::compiler::compile_file(
        Command::new(compiler())
            .args(["--target=x86_64-unknown-linux-gnu", "-c"])
            .arg(&assembly)
            .arg("-o")
            .arg(&object),
        &assembly,
        &source,
    );
    let mut binary = Binary::open(&object).unwrap();
    let last = binary.find("last_input").unwrap().addr;
    let partial = binary.find("partial_input").unwrap().addr;
    let symbols = velk::render::Symbols {
        functions: [
            (last, "last_input".into()),
            (partial, "partial_input".into()),
        ]
        .into(),
        ..Default::default()
    };
    let mut text = String::from(HEADER);
    text.push_str("#include <sys/mman.h>\n");
    text.push_str("static uint64_t last_input(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) { (void)a; (void)b; (void)c; (void)d; return e; }\nstatic uint64_t partial_input(uint64_t x) { return ((x & ~UINT64_C(255)) | 7) + 256; }\n");
    for name in [
        "sets_inputs",
        "dead_inputs",
        "overwritten_inputs",
        "inline_probe",
        "calls_partial",
        "partial_word_address",
        "absolute_word_loop",
        "absolute_stride",
    ] {
        let address = binary.find(name).unwrap().addr;
        let ir = &binary.analysis(address, None).unwrap().ir;
        let code = velk::render::render(ir, &[], &symbols, &[]);
        if name == "inline_probe" {
            assert_eq!(ir.params.len(), 2, "{code}");
            assert!(!code.contains("undefined"), "{code}");
        } else if name == "calls_partial" {
            assert!(code.contains("partial_input(a0)"), "{code}");
        } else if matches!(name, "sets_inputs" | "dead_inputs" | "overwritten_inputs") {
            assert!(code.contains(&format!("{name}(void)")), "{code}");
        }
        if name == "sets_inputs" {
            assert!(code.contains("last_input(0, 0, 0, 0, 8)"), "{code}");
        }
        if name == "absolute_word_loop" {
            assert!(
                !code
                    .lines()
                    .any(|line| line.trim_start().starts_with("uint16_t *")),
                "{code}"
            );
        }
        text.push_str(&code);
    }
    text.push_str("int main(void) { if (sets_inputs() != 8 || dead_inputs() != 7 || overwritten_inputs() != 19) return 1; for (uint64_t x = 0; x < 65536; ++x) { if (calls_partial(x) != (((x & ~UINT64_C(255)) | 7) + 256)) return 2; if ((uint32_t)inline_probe(x, UINT32_MAX) != (uint32_t)(x + UINT32_MAX)) return 3; uint16_t word = x; if (partial_word_address(&word) != (uint16_t)(word + 1)) return 4; } void *p = mmap((void *)UINT64_C(0x400000000), 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0); if (p == MAP_FAILED) return 5; volatile unsigned enter = 1; if (absolute_word_loop(enter) != 111) return 8; for (unsigned i = 0; i < 6; ++i) if (((uint16_t *)p)[i] != 6) return 6; for (unsigned i = 0; i < 4; ++i) absolute_stride(i); for (unsigned i = 0; i < 4; ++i) if (*(uint32_t *)((uint8_t *)p + i * 112) != 1) return 7; munmap(p, 4096); return 0; }\n");
    let program = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "", "{}", program.text);
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_nonzero_absolute_offsets_remain_integer_counters() {
    let index = velk::ir::VARIABLE_BASE;
    let result = index + 1;
    let mut ir = synthetic_ir(
        "absolute_offsets",
        vec![],
        CType::U32,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef { index, width: 64 },
                value: Expr::Const(16),
                at: None,
            },
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: result,
                    width: 32,
                },
                value: Expr::Const(0),
                at: None,
            },
            Stmt::Br {
                target: Some(16),
                at: None,
            },
        ],
    );
    ir.blocks.push(Block {
        start: 16,
        stmts: vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: result,
                    width: 32,
                },
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::reg(result, 32),
                    Expr::Load {
                        addr: Box::new(Expr::bin(
                            BinOp::Add,
                            Expr::Const(REGION + 32),
                            Expr::reg(index, 64),
                        )),
                        width: 4,
                        signed: false,
                    },
                ),
                at: None,
            },
            Stmt::Assign {
                dest: velk::ir::RegRef { index, width: 64 },
                value: Expr::bin(BinOp::Sub, Expr::reg(index, 64), Expr::Const(4)),
                at: None,
            },
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(index, 64),
                rhs: Expr::Const((-8i64) as u64),
                target: 16,
                at: None,
            },
        ],
    });
    ir.blocks.push(Block {
        start: 32,
        stmts: vec![Stmt::Ret {
            value: Expr::reg(result, 32),
            at: None,
        }],
    });
    let candidate = printed_candidate(ir, vec![vec![]]);
    assert!(
        !candidate
            .code
            .lines()
            .any(|line| line.trim_start().starts_with("uint32_t *")),
        "{}",
        candidate.code
    );
    check_candidates("absolute-offsets", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn printed_inputs_keep_wide_reads_before_narrow_register_reuse() {
    let scratch = scratch_dir("wide-input-reuse");
    let assembly = scratch.join("reuse.s");
    let object = scratch.join("reuse.o");
    common::compiler::compile_file(
        Command::new(compiler())
            .args(["--target=x86_64-unknown-linux-gnu", "-c"])
            .arg(&assembly)
            .arg("-o")
            .arg(&object),
        &assembly,
        ".text\n.globl input_reuse\n.type input_reuse,@function\ninput_reuse:\nmovq %rdi, -8(%rsp)\nmovl $1, %edi\nmovq -8(%rsp), %rax\naddq %rdi, %rax\nret\n.size input_reuse, .-input_reuse\n",
    );
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("input_reuse").unwrap().addr;
    let analysis = binary.analysis(address, None).unwrap();
    assert!(!analysis.ir.params[0].ty.is_32_bit_int());
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        "uint64_t values[] = {0, 0xfffffff8, UINT64_C(0x100000008), UINT64_MAX}; for (unsigned i = 0; i < 4; ++i) if ((uint64_t)input_reuse(values[i]) != values[i] + 1) return 1;",
    );
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_short_arrays_include_four_byte_initializers() {
    let scratch = scratch_dir("short-array-initializers");
    let assembly = scratch.join("array.s");
    let object = scratch.join("array.o");
    common::compiler::compile_file(
        Command::new(compiler())
            .args(["--target=x86_64-unknown-linux-gnu", "-c"])
            .arg(&assembly)
            .arg("-o")
            .arg(&object),
        &assembly,
        ".text\n.globl short_array\n.type short_array,@function\nshort_array:\npushq %rbp\nmovq %rsp, %rbp\nsubq $32, %rsp\nmovabsq $0x0004000400040004, %rax\nmovq %rax, -16(%rbp)\nmovl $0x00040004, -8(%rbp)\nmovw $4, -4(%rbp)\nmovswl -16(%rbp,%rdi,2), %eax\nleave\nret\n.size short_array, .-short_array\n",
    );
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("short_array").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        "for (unsigned i = 0; i < 7; ++i) if (short_array(i) != 4) return 1;",
    );
    std::fs::remove_dir_all(scratch).ok();
}
