use super::*;

#[test]
fn debug_fixtures_supply_names_signatures_and_fixed_locals() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codeview");
    for extension in ["obj", "dll"] {
        for level in [0, 2] {
            let image = crate::loader::load(&root.join(format!("loops.O{level}.{extension}")))
                .expect("fixture");
            assert_eq!(image.codeview.procedures.len(), 4, "{extension} O{level}");
            let function = image
                .functions
                .values()
                .find(|f| f.name.as_deref() == Some("count_bits"))
                .expect("count_bits");
            let types = image
                .codeview
                .function_types(&image, function.addr)
                .expect("signature");
            assert_eq!(
                types.params,
                [(Some("x".into()), Some(crate::ir::CType::U32))]
            );
            assert_eq!(types.ret, Some(crate::ir::CType::I32));
            if level == 0 {
                assert!(
                    types
                        .locals
                        .iter()
                        .any(|var| var.name == "n" && var.slot == -8 && var.size == 4),
                    "{extension}: {:?}",
                    types.locals
                );
            }
        }
    }
}

#[test]
fn record_readers_bound_untrusted_lengths() {
    for len in 0..128 {
        let bytes = vec![0xff; len];
        assert!(msf::Msf::open(&bytes).is_none());
        let _ = records::records(&bytes).collect::<Vec<_>>();
        let _ = type_stream(&bytes);
    }
    let mut types = types::Types::default();
    types
        .0
        .insert(0x1000, (0x1001, 0x1000u32.to_le_bytes().to_vec()));
    assert!(types.spelling(0x1000, 16).is_none());
    assert!(types.layout(0x1000, 16).is_none());
}

fn record(kind: u16, bytes: &[u8]) -> Vec<u8> {
    let mut record = ((bytes.len() + 2) as u16).to_le_bytes().to_vec();
    record.extend_from_slice(&kind.to_le_bytes());
    record.extend_from_slice(bytes);
    record
}

fn procedure(kind: u16, address: u32) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&0x1001u32.to_le_bytes());
    bytes.extend_from_slice(&address.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(b"calculate\0");
    record(kind, &bytes)
}

fn scalar_types() -> types::Types {
    let mut args = 1u32.to_le_bytes().to_vec();
    args.extend_from_slice(&0x74u32.to_le_bytes());
    let mut procedure = 0x74u32.to_le_bytes().to_vec();
    procedure.extend_from_slice(&[0, 0, 1, 0]);
    procedure.extend_from_slice(&0x1000u32.to_le_bytes());
    types::Types::read(
        &[record(0x1201, &args), record(0x1008, &procedure)].concat(),
        0x1000,
    )
}

#[test]
fn malformed_symbols_do_not_hide_valid_procedures_or_reassign_locations() {
    let mut local = 0x74u32.to_le_bytes().to_vec();
    local.extend_from_slice(&0u16.to_le_bytes());
    local.extend_from_slice(b"counter\0");
    let mut range = 334u16.to_le_bytes().to_vec();
    range.extend_from_slice(&0u16.to_le_bytes());
    range.extend_from_slice(&0u32.to_le_bytes());
    range.extend_from_slice(&1u16.to_le_bytes());
    range.extend_from_slice(&16u16.to_le_bytes());
    let records = [
        record(0x1110, &[0]),
        procedure(0x110f, 0),
        record(0x113e, &local),
        record(0x113e, &[0]),
        record(0x1141, &range),
        record(6, &[]),
        procedure(0x1110, 16),
    ]
    .concat();
    let mut data = CodeViewData {
        types: scalar_types(),
        ..Default::default()
    };
    symbols::read(&mut data, &records, &[(0x1000, 32)], false);
    assert_eq!(data.procedures.len(), 2);
    assert!(
        data.procedures[0]
            .signature
            .as_ref()
            .unwrap()
            .registers
            .is_empty()
    );
    assert_eq!(data.procedures[1].addr, 0x1010);
    let mut overflow = CodeViewData::default();
    symbols::read(
        &mut overflow,
        &procedure(0x1110, 1),
        &[(u64::MAX, 32)],
        false,
    );
    assert!(overflow.procedures.is_empty());
}

#[test]
fn legacy_frame_locations_and_full_register_ranges_are_read() {
    for kind in [0x110b, 0x1111] {
        let mut variable = (-4i32).to_le_bytes().to_vec();
        variable.extend_from_slice(&0x74u32.to_le_bytes());
        if kind == 0x1111 {
            variable.extend_from_slice(&334u16.to_le_bytes());
        }
        variable.extend_from_slice(b"counter\0");
        let mut data = CodeViewData {
            types: scalar_types(),
            ..Default::default()
        };
        symbols::read(
            &mut data,
            &[procedure(0x110f, 0), record(kind, &variable)].concat(),
            &[(0x1000, 32)],
            false,
        );
        assert_eq!(
            data.procedures[0].variables,
            [("counter".into(), 0x74, 334, -4)]
        );
    }
    let mut local = 0x74u32.to_le_bytes().to_vec();
    local.extend_from_slice(&0u16.to_le_bytes());
    local.extend_from_slice(b"counter\0");
    let mut range = 20u16.to_le_bytes().to_vec();
    range.extend_from_slice(&0u16.to_le_bytes());
    range.extend_from_slice(&0u32.to_le_bytes());
    range.extend_from_slice(&1u16.to_le_bytes());
    range.extend_from_slice(&16u16.to_le_bytes());
    let mut data = CodeViewData {
        types: scalar_types(),
        ..Default::default()
    };
    symbols::read(
        &mut data,
        &[
            procedure(0x1110, 0),
            record(0x113e, &local),
            record(0x1141, &range),
        ]
        .concat(),
        &[(0x1000, 32)],
        false,
    );
    assert_eq!(
        data.procedures[0].signature.as_ref().unwrap().registers,
        [(3, "counter".into())]
    );
}

#[test]
fn damaged_msf_pages_and_type_streams_are_bounded() {
    let bytes = include_bytes!("../../../tests/fixtures/codeview/loops.O0.pdb");
    assert!(msf::Msf::open(bytes).is_some());
    for end in (0..bytes.len()).step_by(257) {
        if let Some(msf) = msf::Msf::open(&bytes[..end]) {
            let _ = msf.modules();
            let _ = msf.stream(2);
        }
    }
    for at in [32, 40, 44, 52, 3 * 4096, 3 * 4096 + 4] {
        let mut damaged = bytes.to_vec();
        damaged[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        if let Some(msf) = msf::Msf::open(&damaged) {
            let _ = msf.modules();
        }
    }
    let mut types = scalar_types();
    types.0.insert(
        0x1002,
        (
            0x1001,
            [0x1002u32.to_le_bytes().as_slice(), &[0, 0]].concat(),
        ),
    );
    assert!(types.spelling(0x1002, 16).is_none());
    assert!(types.layout(0x1002, 16).is_none());
    assert!(types.spelling(0xffff_ffff, 16).is_none());
    assert!(types.procedure(0x1001).is_some());
}

#[test]
fn codeview_callee_declarations_use_the_shared_abi_consumer() {
    for extension in ["obj", "dll"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/codeview/structs.O0.{extension}"));
        let image = crate::loader::load(&path).unwrap();
        for name in ["point_add", "rect_area", "big_sum"] {
            let function = image
                .functions
                .values()
                .find(|f| f.name.as_deref() == Some(name))
                .unwrap();
            let declaration = crate::analysis::calls::declaration(&image, function.addr)
                .expect("read declaration")
                .expect("declaration");
            assert!(
                declaration.signature.abi.is_ok(),
                "{name}: {:?}",
                declaration.signature
            );
        }
    }
}

#[test]
fn partial_frame_register_writes_and_unknown_allocations_are_rejected() {
    let image = Image::from_code(
        crate::loader::Isa::X86_64,
        0x1000,
        vec![
            0x55, 0x48, 0x89, 0xe5, 0x31, 0xed, 0x48, 0x83, 0xec, 0x20, 0xc3,
        ],
    );
    assert_eq!(locations::frame(&image, 0x1000, 11, 40), Some((-40, None)));
    let image = Image::from_code(
        crate::loader::Isa::X86_64,
        0x1000,
        vec![0x48, 0x29, 0xc4, 0xc3],
    );
    assert_eq!(locations::frame(&image, 0x1000, 4, 32), None);
}

#[test]
fn arrays_preserve_element_counts_and_reject_fractional_sizes() {
    let mut data = scalar_types();
    let mut array = 0x74u32.to_le_bytes().to_vec();
    array.extend_from_slice(&0x75u32.to_le_bytes());
    array.extend_from_slice(&12u16.to_le_bytes());
    array.push(0);
    data.0.insert(0x1002, (0x1503, array.clone()));
    let layout = data.layout(0x1002, 16).expect("array layout");
    assert!(matches!(
        layout.kind,
        crate::ir::abi::LayoutKind::Array { count: 3, .. }
    ));
    assert_eq!(
        data.spelling(0x1002, 16),
        Some(crate::ir::CType::Array(Box::new(crate::ir::CType::I32)))
    );
    array[8..10].copy_from_slice(&11u16.to_le_bytes());
    data.0.insert(0x1003, (0x1503, array));
    assert!(data.layout(0x1003, 16).is_none());
}

#[test]
fn missing_mismatched_and_damaged_sidecars_leave_the_image_loadable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scratch = root.join("target/codeview-sidecar");
    std::fs::create_dir_all(&scratch).unwrap();
    let image = scratch.join("loops.O0.dll");
    let pdb = scratch.join("loops.O0.pdb");
    std::fs::copy(root.join("tests/fixtures/codeview/loops.O0.dll"), &image).unwrap();
    let _ = std::fs::remove_file(&pdb);
    assert!(
        crate::loader::load(&image)
            .unwrap()
            .codeview
            .procedures
            .is_empty()
    );
    for bytes in [
        include_bytes!("../../../tests/fixtures/codeview/structs.O0.pdb").as_slice(),
        b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0",
    ] {
        std::fs::write(&pdb, bytes).unwrap();
        assert!(
            crate::loader::load(&image)
                .unwrap()
                .codeview
                .procedures
                .is_empty()
        );
    }
    std::fs::remove_file(pdb).unwrap();
}

#[test]
fn dwarf_callee_declarations_remain_available_for_windows_images() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/metrics/integers.x86_64.O0.debug.elf");
    let mut image = crate::loader::load(&path).unwrap();
    let expected = crate::loader::dwarf::calls::call_index(&image)
        .unwrap()
        .addresses;
    assert!(!expected.is_empty());
    for format in [crate::loader::Format::Pe, crate::loader::Format::Coff] {
        image.format = format;
        assert_eq!(
            crate::loader::dwarf::calls::call_index(&image)
                .unwrap()
                .addresses,
            expected
        );
    }
}

#[test]
fn shared_type_references_cannot_expand_without_a_work_bound() {
    fn number(value: u32) -> Vec<u8> {
        if value < 0x8000 {
            return (value as u16).to_le_bytes().to_vec();
        }
        [0x8004u16.to_le_bytes().as_slice(), &value.to_le_bytes()].concat()
    }
    let mut types = types::Types::default();
    let mut previous = 0x74u32;
    let mut size = 4;
    for level in 0..14 {
        let field_index = 0x2000 + level * 2;
        let structure_index = field_index + 1;
        let mut fields = Vec::new();
        for (name, offset) in [("left", 0), ("right", size)] {
            let mut field = 0x150du16.to_le_bytes().to_vec();
            field.extend_from_slice(&3u16.to_le_bytes());
            field.extend_from_slice(&previous.to_le_bytes());
            field.extend(number(offset));
            field.extend(name.as_bytes());
            field.push(0);
            let padding = (4 - field.len() % 4) % 4;
            field.extend((1..=padding).rev().map(|n| 0xf0 + n as u8));
            fields.extend(field);
        }
        types.0.insert(field_index, (0x1203, fields));
        size *= 2;
        let mut structure = 2u16.to_le_bytes().to_vec();
        structure.extend_from_slice(&0u16.to_le_bytes());
        structure.extend_from_slice(&field_index.to_le_bytes());
        structure.extend_from_slice(&[0; 8]);
        structure.extend(number(size));
        structure.extend(format!("tree_{level}\0").as_bytes());
        types.0.insert(structure_index, (0x1505, structure));
        previous = structure_index;
    }
    assert_eq!(types.layout(0x2007, 16).unwrap().size, 64);
    assert!(types.layout(previous, 16).is_none());
    let mut budget = 64;
    assert!(
        types
            .layout_with_budget(previous, 16, &mut budget)
            .is_none()
    );
    assert_eq!(budget, 0);
}
