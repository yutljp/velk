use super::*;

/// A callee that saves the frame pointer and restores it from its own slot
/// keeps it, although a local's address escapes and a reference count is
/// updated atomically: the caller's frame stays named storage after the call.
#[test]
fn a_frame_survives_a_call_to_a_callee_with_escaping_locals_and_atomics() {
    let mut binary = Binary::open(&common::fixtures_dir().join("rust_probe")).unwrap();
    // rustc_demangle::try_demangle, whose callee keeps rbp only through its save.
    let code = binary.decompile(0x45fcf, None, None).unwrap();
    assert!(!code.contains("undefined"), "{code}");
    assert!(!code.contains("(-0x"), "{code}");
    assert!(!code.contains("(uintptr_t)&local"), "{code}");
    // The local the callee fills ends where the saved registers start.
    assert!(code.contains("int64_t f_38; } local_0;"), "{code}");
}

/// A callee that hands the address of its spilled arguments to a closure
/// returns what the closure left there, not its arguments.
#[test]
fn spilled_arguments_written_through_their_address_are_results() {
    let mut binary = Binary::open(&common::fixtures_dir().join("go_probe")).unwrap();
    // runtime.traceWriter.ensure returns what runtime.traceWriter.refill returns.
    let code = binary.decompile(0x452100, None, None).unwrap();
    assert!(code.contains("= runtime_traceWriter_refill("), "{code}");
}

#[test]
fn saved_registers_survive_partial_pointer_bits_and_register_frame_offsets() {
    for (target, source, name, expected) in [
        (
            "x86_64-unknown-linux-gnu",
            ".text
.globl mask_callee
.type mask_callee,@function
mask_callee:
pushq %rbx
subq $32, %rsp
leaq 8(%rsp), %rbx
movb $1, %bl
movzbl %bl, %eax
movq %rax, (%rdi)
addq $32, %rsp
popq %rbx
ret
.size mask_callee, .-mask_callee
.globl mask_caller
.type mask_caller,@function
mask_caller:
pushq %r14
movl %edi, %r14d
movq %rsi, %rdi
call mask_callee
movl %r14d, %eax
popq %r14
ret
.size mask_caller, .-mask_caller
",
            "mask_caller",
            "static void mask_callee(int64_t p) { *(uint64_t *)(uintptr_t)p = 1; }",
        ),
        (
            "aarch64-unknown-linux-gnu",
            ".text
.globl offset_callee
.type offset_callee,@function
offset_callee:
stp x19, x30, [sp, #-64]!
add x9, sp, #16
mov x8, #10
orr x8, x9, x8
str x8, [sp, #32]
mov x19, #7
ldr x8, [sp, #32]
strb wzr, [x8]
ldp x19, x30, [sp], #64
ret
.size offset_callee, .-offset_callee
.globl offset_caller
.type offset_caller,@function
offset_caller:
stp x19, x30, [sp, #-16]!
mov x19, x0
bl offset_callee
mov x0, x19
ldp x19, x30, [sp], #16
ret
.size offset_caller, .-offset_caller
",
            "offset_caller",
            "static void offset_callee(void) {}",
        ),
    ] {
        let scratch = scratch_dir(name);
        let assembly = scratch.join("saved.s");
        let object = scratch.join("saved.o");
        std::fs::write(&assembly, source).unwrap();
        let compiled = Command::new(compiler())
            .args(["-target", target, "-c"])
            .arg(&assembly)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}");
        let mut binary = Binary::open(&object).unwrap();
        let address = binary.find(name).unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("a0"), "{code}");
        assert!(!code.contains("undefined"), "{code}");
        let driver = if name == "mask_caller" {
            "uint64_t p = 0; for (uint32_t i = 0; i < 20; ++i) {
                 if ((uint32_t)mask_caller(i * 0x1234567U, (int64_t)(uintptr_t)&p) != i * 0x1234567U || p != 1) __builtin_trap();
             }"
        } else {
            "uint64_t inputs[] = {0, 1, UINT64_MAX, 0x8000000000000000ULL};
             for (unsigned i = 0; i < 4; ++i) {
                 if ((uint32_t)offset_caller(inputs[i]) != (uint32_t)inputs[i]) __builtin_trap();
             }"
        };
        syntax::run_printed(&format!("{expected}\n{code}"), "", driver);
        std::fs::remove_dir_all(scratch).ok();
    }
}
