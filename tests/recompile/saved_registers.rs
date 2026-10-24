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
