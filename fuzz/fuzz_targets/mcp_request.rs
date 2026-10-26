#![no_main]

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let engine = velk::script::Engine::new().expect("create bounded script runtime");
    velk::mcp::fuzz_request(&engine, bytes);
});
