use super::*;

#[test]
fn unsigned_vector_maximum_clears_upper_bits_and_preserves_saved_registers() {
    let scratch = scratch_dir("arm64-unsigned-maximum");
    let assembly = scratch.join("maximum.s");
    let object = scratch.join("maximum.o");
    let mut source = String::from(".text\n");
    let forms = [
        ("8b", "b", 8, 8),
        ("16b", "b", 8, 16),
        ("4h", "h", 16, 4),
        ("8h", "h", 16, 8),
        ("4s", "s", 32, 4),
    ];
    for (index, (lanes, scalar, _, _)) in forms.iter().enumerate() {
        writeln!(source, ".globl maximum_{index}\n.type maximum_{index},@function\nmaximum_{index}:\nldr q0, [x0]\numaxv {scalar}0, v0.{lanes}\nstr q0, [x1]\numov w0, v0.{scalar}[0]\nret\n.size maximum_{index}, .-maximum_{index}").unwrap();
    }
    source.push_str(".globl preserved_maximum\n.type preserved_maximum,@function\npreserved_maximum:\nstp x19, x30, [sp, #-16]!\nmov x19, x2\nbl maximum_0\nmov x0, x19\nldp x19, x30, [sp], #16\nret\n.size preserved_maximum, .-preserved_maximum\n");
    std::fs::write(&assembly, source).unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=aarch64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    for (index, (_, _, bits, count)) in forms.iter().enumerate() {
        let name = format!("maximum_{index}");
        let address = binary.find(&name).unwrap().addr;
        let printed = binary.decompile(address, None, None).unwrap();
        assert!(!printed.contains("unsupported"), "{printed}");
        let mut assertions = String::new();
        writeln!(assertions, "for (unsigned position = 0; position < {count}; ++position) {{\nstruct S1 input = {{0, 0}}; struct S2 output = {{-1, -1}};\nfor (unsigned byte = 0; byte < {bits} / 8; ++byte) ((uint8_t *)&input)[position * ({bits} / 8) + byte] = 255;\nif ((uint32_t){name}(&input, &output) != (uint{bits}_t)~0U || (uint64_t)output.field_0x0 != (uint{bits}_t)~0U || output.field_0x8 != 0) __builtin_trap();\n}}").unwrap();
        writeln!(assertions, "for (unsigned trial = 0; trial < 32; ++trial) {{
struct S1 input = {{-1, -1}}; struct S2 output = {{-1, -1}};
uint64_t expected = 0;
for (unsigned lane = 0; lane < {count}; ++lane) {{
    uint64_t value = (uint{bits}_t)((trial + lane) * 0x9876543U);
    if (value > expected) expected = value;
    for (unsigned byte = 0; byte < {bits} / 8; ++byte)
        ((uint8_t *)&input)[lane * ({bits} / 8) + byte] = value >> (byte * 8);
}}
if ((uint32_t){name}(&input, &output) != expected || (uint64_t)output.field_0x0 != expected || output.field_0x8 != 0) __builtin_trap();
}}").unwrap();
        syntax::run_printed(&printed, "", &assertions);
    }
    let address = binary.find("preserved_maximum").unwrap().addr;
    let printed = binary.decompile(address, None, None).unwrap();
    assert!(!printed.contains("undefined"), "{printed}");
    let code =
        format!("static void maximum_0(int64_t a, int64_t b) {{ (void)a; (void)b; }}\n{printed}");
    syntax::run_printed(
        &code,
        "",
        "if ((uint32_t)preserved_maximum(0, 0, 0xabcdef12U) != 0xabcdef12U) __builtin_trap();",
    );
    std::fs::remove_dir_all(scratch).ok();
}

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

#[test]
fn constant_address_spills_are_rematerialized_across_frame_only_calls() {
    let scratch = scratch_dir("arm64-constant-spill");
    let assembly = scratch.join("spill.s");
    let object = scratch.join("spill.o");
    std::fs::write(
        &assembly,
        ".text
.globl spill_helper
.type spill_helper,@function
spill_helper:
sub sp, sp, #16
str w0, [sp, #12]
ldr w0, [sp, #12]
add w0, w0, #1
add sp, sp, #16
ret
.size spill_helper, .-spill_helper
.globl spilled_address
.type spilled_address,@function
spilled_address:
stp x29, x30, [sp, #-64]!
mov x29, sp
mov x8, #0x400000000
str x8, [sp, #16]
mov w0, #1
bl spill_helper
ldr x8, [sp, #16]
ldr w0, [x8, #16]
ldp x29, x30, [sp], #64
ret
.size spilled_address, .-spilled_address
.globl write_spill
.type write_spill,@function
write_spill:
mov x1, #0x500000000
str x1, [x0]
ret
.size write_spill, .-write_spill
.globl changed_address
.type changed_address,@function
changed_address:
stp x29, x30, [sp, #-64]!
mov x29, sp
mov x8, #0x400000000
str x8, [sp, #16]
add x0, sp, #16
bl write_spill
ldr x8, [sp, #16]
ldr w0, [x8, #16]
ldp x29, x30, [sp], #64
ret
.size changed_address, .-changed_address
.globl replaced_address
.type replaced_address,@function
replaced_address:
stp x29, x30, [sp, #-64]!
mov x29, sp
mov x8, #0x400000000
str x8, [sp, #16]
add x0, sp, #16
bl write_spill
mov x8, #0x400000000
str x8, [sp, #16]
mov w0, #1
bl spill_helper
ldr x8, [sp, #16]
ldr w0, [x8, #16]
ldp x29, x30, [sp], #64
ret
.size replaced_address, .-replaced_address
",
    )
    .unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=aarch64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("spilled_address").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("0x400000000"), "{code}");
    assert!(code.contains("0x400000010"), "{code}");
    let changed = binary.find("changed_address").unwrap().addr;
    let changed_code = binary.decompile(changed, None, None).unwrap();
    assert!(!changed_code.contains("0x400000010"), "{changed_code}");
    let replaced = binary.find("replaced_address").unwrap().addr;
    let replaced_code = binary.decompile(replaced, None, None).unwrap();
    assert!(replaced_code.contains("0x400000010"), "{replaced_code}");
    let text = format!(
        "#include <sys/mman.h>\nstatic void spill_helper(uint64_t x) {{ (void)x; }}\nstatic void write_spill(uint64_t *p) {{ *p = 0x500000000ULL; }}\n{code}\n{changed_code}\n{replaced_code}"
    );
    syntax::run_printed(
        &text,
        "",
        "void *page = mmap((void *)0x400000000ULL, 16384,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (page == MAP_FAILED) __builtin_trap();
        for (uint32_t i = 0; i < 20; ++i) {
            *(uint32_t *)((uint8_t *)page + 16) = i * 0x9876543U;
            if ((uint32_t)spilled_address() != i * 0x9876543U) __builtin_trap();
        }
        void *other = mmap((void *)0x500000000ULL, 16384,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (other == MAP_FAILED) __builtin_trap();
        *(uint32_t *)((uint8_t *)other + 16) = 123;
        if ((uint32_t)changed_address() != 123) __builtin_trap();
        if ((uint32_t)replaced_address() != 19 * 0x9876543U) __builtin_trap();
        munmap(other, 16384);
        munmap(page, 16384);",
    );
    std::fs::remove_dir_all(scratch).ok();
}
