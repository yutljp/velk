#![no_main]

mod input;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(mut binary) = velk::service::Binary::open(input::path(bytes)) {
        let functions = binary.functions();
        if let Some(function) = functions.first() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
            let _ = binary.decompile(function.addr, None, Some(deadline));
        }
    }
});
