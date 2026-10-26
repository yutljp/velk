#![no_main]

mod input;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let _ = velk::loader::load(input::path(bytes));
});
