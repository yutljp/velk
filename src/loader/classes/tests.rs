use super::*;
use object::Object;

fn fixture(format: &str) -> Image {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/cpp/rtti.stripped.{format}"));
    crate::loader::load(&path).unwrap()
}

fn patch(image: &mut Image, address: u64, bytes: &[u8]) {
    let offset = image.virtual_offset(address).unwrap() as usize;
    image.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn bad_itanium_counts_and_base_pointers_preserve_later_classes() {
    let image = fixture("elf");
    let multiple = image
        .classes()
        .iter()
        .find(|class| class.name == "Multiple")
        .unwrap()
        .type_info;
    for count in [u32::MAX, 4097] {
        let mut image = fixture("elf");
        patch(&mut image, multiple + 20, &count.to_le_bytes());
        let classes = itanium::read(&image);
        assert!(!classes.iter().any(|class| class.name == "Multiple"));
        assert!(classes.iter().any(|class| class.name == "Virtual"));
        assert!(classes.iter().any(|class| class.name == "Error"));
    }
    let mut image = fixture("elf");
    patch(&mut image, multiple + 24, &u64::MAX.to_le_bytes());
    let classes = itanium::read(&image);
    assert!(!classes.iter().any(|class| class.name == "Multiple"));
    assert!(classes.iter().any(|class| class.name == "Virtual"));
}

#[test]
fn invalid_locator_and_hierarchy_counts_do_not_attach_pe_tables() {
    let image = fixture("dll");
    let multiple = image
        .classes()
        .iter()
        .find(|class| class.name == "Multiple")
        .unwrap();
    let point = multiple.vtables[0].address;
    let locator = word(&image, point - 8, 8).unwrap();
    let base = object::File::parse(image.bytes.as_slice())
        .unwrap()
        .relative_address_base();
    let hierarchy = base + word(&image, locator + 16, 4).unwrap();
    for (at, value) in [
        (locator, 0),
        (locator + 20, u32::MAX),
        (hierarchy + 8, u32::MAX),
    ] {
        let mut image = fixture("dll");
        patch(&mut image, at, &value.to_le_bytes());
        let classes = msvc::read(&image);
        assert!(
            classes
                .iter()
                .all(|class| class.vtables.iter().all(|table| table.address != point))
        );
        assert!(
            classes
                .iter()
                .any(|class| class.name == "Single" && !class.vtables.is_empty())
        );
    }
}

#[test]
fn data_imports_do_not_become_virtual_methods() {
    let image = fixture("elf");
    let other = image
        .classes()
        .iter()
        .find(|class| class.name == "Other")
        .unwrap();
    assert_eq!(other.vtables[0].methods.len(), 3);
    assert!(
        other.vtables[0]
            .methods
            .iter()
            .all(|method| method.address != 0)
    );
}

#[test]
fn truncated_and_overflowing_type_names_are_unknown() {
    let mut image = Image::from_code(Isa::X86_64, u64::MAX - 16, vec![0; 16]);
    assert_eq!(itanium::type_name(&image, u64::MAX), None);
    assert_eq!(msvc::type_name(&image, u64::MAX), None);
    image.bytes.fill(b'a');
    assert_eq!(text(&image, u64::MAX - 16), None);
}

#[test]
fn runtime_type_names_cannot_start_a_c_identifier_with_a_digit() {
    let mut image = fixture("elf");
    let root = image
        .classes()
        .iter()
        .find(|class| class.name == "Root")
        .unwrap();
    let name = word(&image, root.type_info + 8, 8).unwrap();
    let table = root.vtables[0].address;
    patch(&mut image, name, b"11\0");
    image.classes = Default::default();
    let symbols = crate::render::callee_names(&image);
    assert!(
        symbols
            .data
            .get(&table)
            .is_none_or(|name| name == "data_1_vtable_0")
    );
}
