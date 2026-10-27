use super::*;

fn fixture() -> Image {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/seh.O2.dll");
    super::super::load(&path).unwrap()
}

fn write_word(image: &mut Image, address: u64, value: u32) {
    let offset = image.virtual_offset(address).unwrap() as usize;
    image.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn bad_scope_rows_and_counts_preserve_later_tables() {
    let original = fixture();
    let first = &original.exception_handlers[0];
    let table = first.data;
    let function = first.function;
    let later = original.exception_handlers[1].function;
    assert_eq!(first.scopes.len(), 1);
    for (offset, value) in [
        (0, u32::MAX),
        (4, 0),
        (8, u32::MAX),
        (12, 0x7fff_ffff),
        (16, u32::MAX),
    ] {
        let mut image = fixture();
        write_word(&mut image, table + offset, value);
        let handlers = read(&image);
        assert!(
            handlers
                .iter()
                .find(|h| h.function == function)
                .is_none_or(|h| h.scopes.is_empty()),
            "offset {offset}"
        );
        assert_eq!(
            handlers
                .iter()
                .find(|h| h.function == later)
                .unwrap()
                .scopes
                .len(),
            1
        );
    }
}

#[test]
fn unknown_personalities_are_not_read_as_scope_tables() {
    let mut image = fixture();
    let table = image.exception_handlers[0].data;
    let address = image.exception_handlers[0].address;
    image.functions.get_mut(&address).unwrap().name = Some("unknown_personality*/".to_owned());
    let handlers = read(&image);
    assert!(handlers.iter().all(|h| h.scopes.is_empty()));
    let output = crate::render::seh::comments(&handlers, handlers[0].function);
    assert!(!output.contains("unknown_personality"));
    assert!(output.contains("unknown (tables not decoded)"));
    // The count is not interpreted for an unidentified personality.
    write_word(&mut image, table, u32::MAX);
    assert_eq!(read(&image).len(), handlers.len());
}

#[test]
fn only_one_is_a_constant_filter_and_invalid_filter_addresses_are_rejected() {
    for value in [0, 1, u32::MAX] {
        let mut image = fixture();
        let table = image.exception_handlers[0].data;
        let address = image.exception_handlers[0].function;
        write_word(&mut image, table + 12, value);
        let handlers = read(&image);
        let output = crate::render::seh::comments(&handlers, address);
        if value == 1 {
            assert_eq!(handlers[0].scopes[0].filter, 1);
            assert!(output.contains("__except (1)"));
        } else {
            assert!(handlers[0].scopes.is_empty());
            assert!(!output.contains("__except ("));
        }
        image.exception_handlers = handlers;
        let filter_name = "seh_except__except_filter_0";
        image
            .functions
            .retain(|_, f| f.name.as_deref() != Some(filter_name));
        discover(&mut image);
        assert!(
            !image
                .functions
                .values()
                .any(|f| f.name.as_deref() == Some(filter_name))
        );
    }
}

#[test]
fn malformed_cpp_tables_are_bounded() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/seh_cpp.O2.dll");
    for offset in [0, 12, 16] {
        let mut image = super::super::load(&path).unwrap();
        let function_info_address = image.exception_handlers[0].data;
        write_word(&mut image, function_info_address + offset, u32::MAX);
        let handlers = read(&image);
        assert!(!handlers.is_empty());
        assert!(handlers.iter().all(|h| h.catches.is_empty()));
    }
}
