use super::*;

#[test]
fn printed_arm64_stores_preserve_the_incoming_result() {
    let scratch = scratch_dir("arm64-preserved-result");
    let source = scratch.join("results.s");
    let object = scratch.join("results.o");
    std::fs::write(
        &source,
        ".text
.globl clear_byte
.type clear_byte,@function
clear_byte:
strb wzr, [x1]
ret
.size clear_byte, .-clear_byte
.globl compare_store
.type compare_store,@function
compare_store:
cmp w1, #1
cset w8, hi
str x8, [x2]
ret
.size compare_store, .-compare_store
.globl dead_epilogue
.type dead_epilogue,@function
dead_epilogue:
stp x29, x30, [sp, #-16]!
mov x29, sp
sub sp, sp, #32
str w0, [sp, #28]
ldr w0, [sp, #28]
add sp, sp, #32
ldp x29, x30, [sp], #16
ret
ldr w0, [sp, #28]
add sp, sp, #32
ret
.size dead_epilogue, .-dead_epilogue
",
    )
    .unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=aarch64-unknown-linux-gnu", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let mut code = String::new();
    for name in ["clear_byte", "compare_store", "dead_epilogue"] {
        let address = binary.find(name).unwrap().addr;
        let printed = binary.decompile(address, None, None).unwrap();
        assert!(!printed.contains("velk_entry_stack_pointer"), "{printed}");
        assert!(!printed.contains(&format!("void {name}(")), "{printed}");
        assert!(printed.contains("a0"), "{printed}");
        code.push_str(&printed);
    }
    syntax::run_printed(
        &code,
        "",
        "uint8_t byte = 255; uint64_t value = 0;
         uint64_t inputs[] = {0, 1, 0xffffffff, 0x8000000000000000ULL, UINT64_MAX};
         for (unsigned i = 0; i < 5; ++i) {
             byte = 255;
             if ((uint64_t)clear_byte(inputs[i], &byte) != inputs[i] || byte != 0) __builtin_trap();
             for (unsigned j = 0; j < 4; ++j) {
                 value = 99;
                 if ((uint64_t)compare_store(inputs[i], j, &value) != inputs[i] || value != (j > 1)) __builtin_trap();
             }
             if ((uint32_t)dead_epilogue(inputs[i]) != (uint32_t)inputs[i]) __builtin_trap();
         }",
    );
    std::fs::remove_dir_all(scratch).ok();
}
