#![no_main]

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let _ = serde_json::from_slice::<velk::script::ops::Request>(bytes);
});
