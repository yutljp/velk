#![no_main]

mod input;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(binary) = velk::service::Binary::open(input::path(bytes)) {
        let _ = binary.functions();
    }
});
