use super::*;

fn image() -> Image {
    let mut image = Image::from_code(
        Isa::X86_64,
        0x1000,
        vec![0x48, 0x8b, 0x31, 0x24, 0, 0x80, 0xff, 0x7f],
    );
    image.sections[0].name = ".data".to_owned();
    image.sections[0].executable = false;
    image
}

#[test]
fn searches_overlap_and_honor_complete_range_and_section() {
    let image = image();
    let options = Search::default();
    let result = search(&image, "48 8b ?? 24", &options, None).unwrap();
    assert_eq!(result["matches"][0]["addr"], "0x1000");
    assert_eq!(result["matches"][0]["section"], ".data");
    let options = Search {
        end: Some("0x1003".to_owned()),
        ..Search::default()
    };
    assert!(
        search(&image, "48 8b ?? 24", &options, None).unwrap()["matches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let options = Search {
        section: Some("missing".to_owned()),
        ..Search::default()
    };
    assert!(search(&image, "48", &options, None).is_err());
    for text in ["", "4", "gg", "?", "48xx", "+1"] {
        assert!(search(&image, text, &Search::default(), None).is_err());
    }
    for (order, value) in [("little", "0x2448"), ("big", "0x4824")] {
        let options = Search {
            encoding: "integer".to_owned(),
            width: Some(2),
            byte_order: order.to_owned(),
            ..Search::default()
        };
        assert!(
            search(&image, value, &options, None).unwrap()["matches"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(search(&image, "65536", &options, None).is_err());
    }
    let options = Search {
        start: Some("10".to_owned()),
        end: Some("1".to_owned()),
        ..Search::default()
    };
    assert!(search(&image, "48", &options, None).is_err());
}

#[test]
fn values_are_signed_and_section_bounded() {
    let image = image();
    assert_eq!(
        read(&image, 0x1005, "i8", 1, None).unwrap()["values"],
        json!([-128])
    );
    assert_eq!(
        read(&image, 0x1006, "i16", 1, None).unwrap()["values"],
        json!([32767])
    );
    assert_eq!(
        read(&image, 0x1000, "u8[4]", 1, None).unwrap()["values"],
        json!([[72, 139, 49, 36]])
    );
    for (address, name, count) in [
        (0x1007, "u16", 1),
        (u64::MAX, "u64", 2),
        (0x1007, "cstring", 1),
        (0x1008, "u8", 1),
        (0x1000, "u64", u64::MAX),
        (0x1000, "u8[65536][65536]", 1),
    ] {
        assert!(
            read(&image, address, name, count, None).is_err(),
            "{address:x} {name}"
        );
    }
    // The following byte exists in the file, but lies beyond the section.
    let mut shortened = image;
    shortened.sections[0].size = 2;
    assert!(read(&shortened, 0x1001, "u16", 1, None).is_err());
    assert_eq!(
        search(&shortened, "8b 31", &Search::default(), None).unwrap()["matches"],
        json!([])
    );
}

#[test]
fn floating_strings_and_pointer_width_follow_the_image() {
    let mut data = 1.5f32.to_le_bytes().to_vec();
    data.extend_from_slice(&(-2.5f64).to_le_bytes());
    data.extend_from_slice(&[0x00, 0xd8, 0x00, 0xdc, 0, 0]);
    data.extend_from_slice(b"abc\0def\0");
    let image = Image::from_code(Isa::I386, 0, data);
    assert_eq!(
        read(&image, 0, "f32", 1, None).unwrap()["values"],
        json!([1.5])
    );
    assert_eq!(
        read(&image, 4, "f64", 1, None).unwrap()["values"],
        json!([-2.5])
    );
    assert_eq!(
        read(&image, 12, "utf16", 1, None).unwrap()["values"],
        json!(["𐀀"])
    );
    assert!(read(&image, 14, "utf16", 1, None).is_err());
    assert_eq!(
        read(&image, 18, "cstring", 2, None).unwrap()["values"],
        json!(["abc", "def"])
    );
    assert_eq!(read(&image, 0, "pointer", 1, None).unwrap()["bytes"], 4);
}

#[test]
fn multidimensional_arrays_follow_c_dimension_order() {
    let image = Image::from_code(Isa::X86_64, 0, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(
        read(&image, 0, "u8[2][3]", 1, None).unwrap()["values"],
        json!([[[1, 2, 3], [4, 5, 6]]])
    );
    assert!(read(&image, 0, "u8[3]broken[2]", 1, None).is_err());
    assert!(read(&image, 0, "char", 1, None).is_err());
    assert!(
        read(
            &image,
            0,
            "u8",
            0,
            Some(Instant::now() - std::time::Duration::from_secs(1))
        )
        .is_err()
    );
}

#[test]
fn negative_integer_patterns_and_zero_initialized_sections_are_bounded() {
    let mut image = image();
    let options = Search {
        encoding: "integer".to_owned(),
        width: Some(1),
        ..Search::default()
    };
    assert_eq!(
        search(&image, "-128", &options, None).unwrap()["matches"][0]["addr"],
        "0x1005"
    );
    assert!(search(&image, "-129", &options, None).is_err());
    image.sections[0].file_offset = None;
    image.sections[0].file_size = 0;
    assert_eq!(
        read(&image, 0x1000, "u32", 2, None).unwrap()["values"],
        json!([0, 0])
    );
    assert_eq!(
        search(&image, "00 ??", &Search::default(), None).unwrap()["matches"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    image.sections[0].size = u64::MAX - 0x1000;
    assert!(search(&image, "??", &Search::default(), None).is_err());
    assert!(read(&image, 0x1000, "u64", u64::MAX, None).is_err());
}
