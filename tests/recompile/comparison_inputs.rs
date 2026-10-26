use super::*;

#[test]
fn printed_narrow_results_keep_wide_comparisons_and_preserved_arguments() {
    let scratch = scratch_dir("comparison-inputs");
    let assembly = scratch.join("inputs.s");
    let object = scratch.join("inputs.o");
    common::compiler::compile_file(
        Command::new(compiler())
            .args(["--target=aarch64-unknown-linux-gnu", "-c"])
            .arg(&assembly)
            .arg("-o")
            .arg(&object),
        &assembly,
        r#"
.text
.globl compare_wide
.type compare_wide,@function
compare_wide:
    cmp x0, #1
    cset w0, gt
    ret
.size compare_wide, .-compare_wide
.globl conditional_compare
.type conditional_compare,@function
conditional_compare:
    ldr w8, [x0]
    cmp w8, #0
    ldr x8, [x1]
    ccmp x8, #8, #2, ne
    cset w8, lo
    mov w0, w8
    ret
.size conditional_compare, .-conditional_compare
.globl conditional_sum
.type conditional_sum,@function
conditional_sum:
    ldr w8, [x0]
    cmp w8, #0
    ldr x8, [x1]
    ccmn x8, #1, #0, ne
    cset w8, eq
    mov w0, w8
    ret
.size conditional_sum, .-conditional_sum
.globl preserve_argument
.type preserve_argument,@function
preserve_argument:
    mov w8, #7
    str w8, [x1]
    ret
.size preserve_argument, .-preserve_argument
.globl saved_address
.type saved_address,@function
saved_address:
    stp x22, x30, [sp, #-16]!
    mov x22, x0
    bl local_bits
    ldr w0, [x22]
    ldp x22, x30, [sp], #16
    ret
.size saved_address, .-saved_address
.globl local_bits
.type local_bits,@function
local_bits:
    sub sp, sp, #48
    stp x22, x30, [sp, #32]
    add x8, sp, #16
    orr x8, x8, #6
    str x8, [sp, #8]
    mov x0, x8
    bl read_byte
    ldp x22, x30, [sp, #32]
    add sp, sp, #48
    ret
.size local_bits, .-local_bits
.globl read_byte
.type read_byte,@function
read_byte:
    ldrb w0, [x0]
    ret
.size read_byte, .-read_byte
.globl calls_third
.type calls_third,@function
calls_third:
    stp x29, x30, [sp, #-16]!
    bl changes_first_two
    mov w2, #42
    bl only_third
    ldp x29, x30, [sp], #16
    ret
.size calls_third, .-calls_third
.globl changes_first_two
.type changes_first_two,@function
changes_first_two:
    mov w0, #9
    mov w1, #99
    ret
.size changes_first_two, .-changes_first_two
.globl only_third
.type only_third,@function
only_third:
    mov x0, x2
    ret
.size only_third, .-only_third
"#,
    );
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("compare_wide").unwrap().addr;
    let ir = &binary.analysis(address, None).unwrap().ir;
    assert_eq!(ir.params[0].ty.integer().unwrap().0, 64);
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        "int64_t inputs[] = {0,1,2,INT64_C(0x100000000),INT64_C(0x100000001),INT64_MAX,INT64_MIN,-1}; for(unsigned i=0;i<sizeof inputs/sizeof *inputs;++i) if(compare_wide(inputs[i])!=(inputs[i]>1)) return 1;",
    );
    let address = binary.find("conditional_compare").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        "uint64_t values[] = {0,1,7,8,UINT64_C(0x100000000),UINT64_MAX}; for(uint32_t first=0;first<3;++first) for(unsigned i=0;i<sizeof values/sizeof *values;++i) if(conditional_compare(&first,&values[i])!=(first!=0 && values[i]<8)) return 1;",
    );
    let address = binary.find("conditional_sum").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        "uint64_t values[] = {0,1,7,8,UINT64_C(0x100000000),UINT64_MAX}; for(uint32_t first=0;first<3;++first) for(unsigned i=0;i<sizeof values/sizeof *values;++i) if(conditional_sum(&first,&values[i])!=(first!=0 && values[i]==UINT64_MAX)) return 1;",
    );
    let address = binary.find("preserve_argument").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("void preserve_argument"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "uint32_t value=0; if ((uint64_t)preserve_argument(UINT64_C(0x123456789abcdef0), &value)!=UINT64_C(0x123456789abcdef0) || value!=7) return 1;",
    );
    let address = binary.find("saved_address").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("undefined"), "{code}");
    let code = format!("static uint64_t local_bits(void) {{ return 0; }}\n{code}");
    syntax::run_printed(
        &code,
        "",
        "uint32_t value=0x12345678; if(saved_address(&value)!=value) return 1;",
    );
    let address = binary.find("calls_third").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("also returned by the call"), "{code}");
    let code = format!(
        "static uint64_t changes_first_two(void) {{ return 9; }}\nstatic uint64_t only_third(uint64_t a, uint64_t b, uint64_t c) {{ (void)a; (void)b; return c; }}\n{code}"
    );
    syntax::run_printed(&code, "", "if(calls_third()!=42) return 1;");
    std::fs::remove_dir_all(scratch).ok();
}
