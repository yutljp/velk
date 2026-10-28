use super::*;

#[test]
fn unnamed_candidates_preserve_size_limits_and_arm_discovery() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut image = Image::from_code(isa, 0x1000, Vec::new());
        assert!(!has_unnamed_candidates(&image));
        image.functions.insert(
            0x1000,
            crate::loader::Function {
                addr: 0x1000,
                size: None,
                size_estimated: false,
                name: None,
                aliases: Vec::new(),
                sources: Vec::new(),
                library: None,
            },
        );
        for size in [
            None,
            Some(0),
            Some(31),
            Some(32),
            Some(MAX_BYTES),
            Some(MAX_BYTES + 1),
            Some(u64::MAX),
        ] {
            image.functions.get_mut(&0x1000).unwrap().size = size;
            assert_eq!(
                has_unnamed_candidates(&image),
                isa == Isa::Arm32 || size.is_some_and(|size| (32..=MAX_BYTES).contains(&size)),
                "{isa:?}: {size:?}",
            );
            image.functions.get_mut(&0x1000).unwrap().name = Some("known".to_owned());
            assert!(!has_unnamed_candidates(&image));
            image.functions.get_mut(&0x1000).unwrap().name = None;
        }
    }
}

#[test]
fn call_entries_need_independent_naming_evidence() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64] {
        let mut code = if isa == Isa::AArch64 {
            let mut bytes = 0x9100_0400u32.to_le_bytes().repeat(10);
            bytes.extend(0xd65f_03c0u32.to_le_bytes());
            bytes
        } else {
            let mut bytes = [0x83, 0xc0, 1].repeat(14);
            bytes.push(0xc3);
            bytes
        };
        let size = code.len() as u64;
        let body = normalize(isa, &code, 0x1000, &HashSet::new()).unwrap();
        let database = Database::new(vec![make_entry(
            "leaf".to_owned(),
            isa,
            body,
            Vec::new(),
            Vec::new(),
        )]);
        let mut image = Image::from_code(isa, 0x1000, code.clone());
        let function = Function {
            addr: 0x1000,
            size: Some(size),
            size_estimated: true,
            name: None,
            aliases: Vec::new(),
            sources: vec![NameSource::Call],
            library: None,
        };
        image.functions.insert(function.addr, function.clone());
        assert!(has_unnamed_candidates(&image));
        let matches = identify(&image, &database, None, MatchScope::Unnamed).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.certainty, crate::sigs::Certainty::Exact);

        let mut enclosing = function.clone();
        enclosing.addr = 0x800;
        enclosing.name = Some("outer".to_owned());
        enclosing.sources = vec![NameSource::Symtab];
        enclosing.size = Some(0x800 + size);
        image.functions.insert(enclosing.addr, enclosing);
        assert!(!has_unnamed_candidates(&image));
        assert!(
            identify(&image, &database, None, MatchScope::Unnamed)
                .unwrap()
                .is_empty()
        );
        image.functions.get_mut(&0x800).unwrap().size = Some(0x800);
        assert!(has_unnamed_candidates(&image));

        // An estimated extent can include padding after a short linkage jump.
        if isa == Isa::AArch64 {
            code = 0xd503_201fu32.to_le_bytes().repeat(11);
            code[..4].copy_from_slice(&0x1400_1000u32.to_le_bytes());
        } else {
            code.fill(0x90);
            code[..5].copy_from_slice(&[0xe9, 0, 1, 0, 0]);
        }
        let mut stub = Image::from_code(isa, 0x1000, code);
        stub.functions.insert(function.addr, function);
        assert!(!has_unnamed_candidates(&stub));
    }
}

#[test]
fn short_functions_are_not_signatures() {
    assert!(normalize(Isa::X86_64, &[0x90; 31], 0, &HashSet::new()).is_none());
    assert!(normalize(Isa::AArch64, &[0; 28], 0, &HashSet::new()).is_none());
}

#[test]
fn aarch64_big_endian_objects_do_not_use_little_endian_sets() {
    use object::write::{Object, Symbol, SymbolSection};
    let mut object = Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::Aarch64,
        object::Endianness::Big,
    );
    let section = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
    let mut bytes = 0x91000400u32.to_le_bytes().repeat(9);
    bytes.extend(0xd65f03c0u32.to_le_bytes());
    object.append_section_data(section, &bytes, 4);
    object.add_symbol(Symbol {
        name: b"leaf".to_vec(),
        value: 0,
        size: bytes.len() as u64,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: object::SymbolFlags::None,
    });
    let object_bytes = object.write().unwrap();
    let file = object::File::parse(object_bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    assert!(entries.is_empty());
    let directory = std::path::Path::new("target/signature-big-endian-test");
    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("leaf.o");
    std::fs::write(&path, object_bytes).unwrap();
    let image = crate::loader::load(&path).unwrap();
    assert!(image_entries(&image, None).unwrap().is_empty());
    let body = normalize(Isa::AArch64, &bytes, 0, &HashSet::new()).unwrap();
    let database = Database::new(vec![make_entry(
        "leaf".to_owned(),
        Isa::AArch64,
        body,
        Vec::new(),
        Vec::new(),
    )]);
    assert!(
        identify(&image, &database, None, MatchScope::All)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn relocation_preserves_opcodes_and_constants() {
    let mut bytes = vec![0x90; 40];
    bytes[..5].copy_from_slice(&[0xe8, 0x40, 0, 0, 0]);
    bytes[5..10].copy_from_slice(&[0xb8, 7, 0, 0, 0]);
    bytes[10..].copy_from_slice(&[0x83, 0xc0, 1].repeat(10));
    let body = normalize(Isa::X86_64, &bytes, 0x1000, &HashSet::new()).unwrap();
    assert_eq!(&body.bytes[..10], &[0xe8, 0, 0, 0, 0, 0xb8, 7, 0, 0, 0]);
    assert_eq!(
        body.calls,
        vec![DirectCall {
            offset: 1,
            width: 4,
            target: 0x1045
        }]
    );
    bytes[1] = 0x50;
    assert_eq!(
        body.bytes,
        normalize(Isa::X86_64, &bytes, 0x2000, &HashSet::new())
            .unwrap()
            .bytes
    );
    bytes[6] = 8;
    assert_ne!(
        body.bytes,
        normalize(Isa::X86_64, &bytes, 0x2000, &HashSet::new())
            .unwrap()
            .bytes
    );
}

#[test]
fn arm_branch_relocation_keeps_link_bit() {
    let mut bytes = 0x91000400u32.to_le_bytes().repeat(10);
    bytes[..4].copy_from_slice(&0x94000010u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    let body = normalize(Isa::AArch64, &bytes, 0x1000, &HashSet::new()).unwrap();
    assert_eq!(&body.bytes[..4], &0x94000000u32.to_le_bytes());
    assert_eq!(
        body.calls,
        vec![DirectCall {
            offset: 0,
            width: 4,
            target: 0x1040
        }]
    );
    bytes[..4].copy_from_slice(&0x14000010u32.to_le_bytes());
    assert_ne!(
        body.bytes,
        normalize(Isa::AArch64, &bytes, 0x1000, &HashSet::new())
            .unwrap()
            .bytes
    );
}

#[test]
fn indirect_register_operands_are_preserved_and_overflow_is_rejected() {
    let mut bytes = vec![0xff, 0xd0];
    bytes.extend_from_slice(&[0x83, 0xc0, 1].repeat(14));
    let body = normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).unwrap();
    bytes[1] = 0xd1;
    let other = normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).unwrap();
    assert_ne!(body.bytes, other.bytes);
    assert!(normalize(Isa::X86_64, &[0x90; 40], u64::MAX, &HashSet::new()).is_none());
}

#[test]
fn fixed_width_indirect_register_operands_are_preserved() {
    for (isa, first, other, rest) in [
        (Isa::AArch64, 0xd63f0000u32, 0xd63f0020u32, 0x91000400u32),
        (Isa::Arm32, 0xe12fff30u32, 0xe12fff31u32, 0xe2800001u32),
    ] {
        let mut bytes = first.to_le_bytes().to_vec();
        bytes.extend(rest.to_le_bytes().repeat(10));
        let body = normalize(isa, &bytes, 0x1000, &HashSet::new()).unwrap();
        bytes[..4].copy_from_slice(&other.to_le_bytes());
        assert_ne!(
            body.bytes,
            normalize(isa, &bytes, 0x1000, &HashSet::new())
                .unwrap()
                .bytes
        );
    }
}

#[test]
fn short_callees_confirm_callers_without_receiving_names() {
    let bytes = branch_object(-4, object::SymbolKind::Text);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    let mut bytes = vec![0xb8, 7, 0, 0, 0, 0xc3];
    let leaf = normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).unwrap();
    assert!(!leaf.name_eligible);
    let caller = entries
        .iter_mut()
        .find(|entry| entry.name == "caller")
        .unwrap();
    // The call at address six returns to address eleven and targets zero.
    let mut code = caller.bytes.clone();
    code[1..5].copy_from_slice(&(-11i32).to_le_bytes());
    bytes.extend_from_slice(&code);
    entries.retain(|entry| entry.name == "caller");
    entries.push(make_entry(
        "leaf".to_owned(),
        Isa::X86_64,
        leaf,
        Vec::new(),
        Vec::new(),
    ));
    let mut image = Image::from_code(Isa::X86_64, 0, bytes);
    for (addr, size) in [(0, 6), (6, code.len() as u64)] {
        image.functions.insert(
            addr,
            crate::loader::Function {
                addr,
                size: Some(size),
                size_estimated: false,
                name: None,
                aliases: Vec::new(),
                sources: Vec::new(),
                library: None,
            },
        );
    }
    let result = identify(&image, &Database::new(entries), None, MatchScope::All).unwrap();
    assert!(result.iter().all(|(addr, _)| *addr != 0));
    assert_eq!(
        result
            .iter()
            .find(|(addr, _)| *addr == 6)
            .unwrap()
            .1
            .certainty,
        crate::sigs::Certainty::Exact
    );
}

#[test]
fn aarch64_literal_loads_preserve_width_and_check_values() {
    for (opcode, size) in [
        (0x18000000u32, 4),
        (0x58000000, 8),
        (0x98000000, 4),
        (0x1c000000, 4),
        (0x5c000000, 8),
        (0x9c000000, 16),
    ] {
        let mut bytes = (opcode | (16 << 5)).to_le_bytes().to_vec();
        bytes.extend(0x91000400u32.to_le_bytes().repeat(8));
        bytes.extend(0xd65f03c0u32.to_le_bytes());
        let body = normalize(Isa::AArch64, &bytes, 0x1000, &HashSet::new()).unwrap();
        assert_eq!(body.references.len(), 1);
        assert_eq!(body.references[0].target, 0x1040);
        assert_eq!(body.references[0].size, size);
        bytes[..4].copy_from_slice(&(opcode | (32 << 5)).to_le_bytes());
        let moved = normalize(Isa::AArch64, &bytes, 0x2000, &HashSet::new()).unwrap();
        assert_eq!(body.bytes, moved.bytes);
        assert_eq!(moved.references[0].target, 0x2080);
    }
}

#[test]
fn aarch64_literal_values_must_agree_in_read_only_data() {
    let image = |value: u64, read_only| {
        let mut bytes = (0x58000000u32 | (16 << 5)).to_le_bytes().to_vec();
        bytes.extend(0x91000400u32.to_le_bytes().repeat(8));
        bytes.extend(0xd65f03c0u32.to_le_bytes());
        bytes.resize(64, 0);
        bytes.extend(value.to_le_bytes());
        let mut image = Image::from_code(Isa::AArch64, 0x1000, bytes);
        image.sections[0].size = 40;
        image.sections.push(crate::loader::Section {
            name: ".rodata".to_owned(),
            vaddr: 0x1040,
            size: 8,
            file_offset: Some(64),
            file_size: 8,
            executable: false,
            loaded: true,
            read_only,
        });
        image.functions.insert(
            0x1000,
            crate::loader::Function {
                addr: 0x1000,
                size: Some(40),
                size_estimated: false,
                name: Some("read_literal".to_owned()),
                aliases: Vec::new(),
                sources: Vec::new(),
                library: None,
            },
        );
        image
    };
    let entries = image_entries(&image(17, true), None).unwrap();
    assert_eq!(entries.len(), 1);
    let database = Database::new(entries);
    for (value, read_only, expected) in [(17, true, 1), (18, true, 0), (17, false, 0)] {
        let matches = identify(&image(value, read_only), &database, None, MatchScope::All).unwrap();
        assert_eq!(matches.len(), expected);
    }
}

#[test]
fn arm_exception_index_seeds_require_a_complete_signature() {
    let mut leaf = 0xe2800001u32.to_le_bytes().repeat(9);
    leaf.extend(0xe12fff1eu32.to_le_bytes());
    let body = normalize(Isa::Arm32, &leaf, 0x1020, &HashSet::new()).unwrap();
    let database = Database::new(vec![make_entry(
        "leaf".to_owned(),
        Isa::Arm32,
        body,
        Vec::new(),
        Vec::new(),
    )]);
    let make_image = |valid: bool, first_word: u32| {
        let mut bytes = vec![0; 32];
        bytes.extend_from_slice(&leaf);
        if !valid {
            bytes[32] = 2;
        }
        bytes.extend(first_word.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        let mut image = Image::from_code(Isa::Arm32, 0x1000, bytes);
        image
            .arm_modes
            .insert(0x1000, crate::loader::ArmMode::Thumb);
        image.sections[0].size = 72;
        image.sections.push(crate::loader::Section {
            name: ".ARM.exidx".to_owned(),
            vaddr: 0x1048,
            size: 8,
            file_offset: Some(72),
            file_size: 8,
            executable: false,
            loaded: true,
            read_only: true,
        });
        image
    };
    let mut image = make_image(true, 0x7fffffd8);
    let discovered = discover::arm32(&mut image, &database, None).unwrap();
    assert_eq!(discovered, vec![0x1020]);
    assert_eq!(image.arm_mode(0x1020), crate::loader::ArmMode::Arm);
    assert_eq!(image.arm_mode(0x1048), crate::loader::ArmMode::Thumb);
    for mut image in [
        make_image(false, 0x7fffffd8),
        make_image(true, 0xffff_ffd8),
        make_image(true, 0x0000_1000),
    ] {
        assert!(
            discover::arm32(&mut image, &database, None)
                .unwrap()
                .is_empty()
        );
        assert!(image.functions.is_empty());
    }
}

fn branch_object(addend: i64, kind: object::SymbolKind) -> Vec<u8> {
    use object::write::{Object, Relocation, Symbol, SymbolSection};
    let mut object = Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    let section = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
    let mut bytes = [0x31, 0xc0].repeat(17);
    bytes.extend_from_slice(&[0xb8, 7, 0, 0, 0, 0xc3]);
    bytes.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0x83, 0xc0, 1].repeat(11));
    bytes.extend_from_slice(&[0x90, 0xc3]);
    object.append_section_data(section, &bytes, 16);
    let leaf = object.add_symbol(Symbol {
        name: b"leaf".to_vec(),
        value: 0,
        size: 40,
        kind,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: object::SymbolFlags::None,
    });
    object.add_symbol(Symbol {
        name: b"caller".to_vec(),
        value: 40,
        size: 40,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: object::SymbolFlags::None,
    });
    object
        .add_relocation(
            section,
            Relocation {
                offset: 41,
                symbol: leaf,
                addend,
                flags: object::RelocationFlags::Generic {
                    kind: object::RelocationKind::Relative,
                    encoding: object::RelocationEncoding::X86Branch,
                    size: 32,
                },
            },
        )
        .unwrap();
    object.write().unwrap()
}

#[test]
fn object_branch_relocations_preserve_destination_names() {
    let bytes = branch_object(-4, object::SymbolKind::Text);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].calls, vec!["leaf"]);
    assert_eq!(&entries[1].bytes[..5], &[0xe8, 0, 0, 0, 0]);
}

#[test]
fn pc_relative_data_is_not_wildcarded() {
    let mut bytes = vec![0x90; 40];
    bytes[..7].copy_from_slice(&[0x48, 0x8d, 0x05, 0, 0, 0, 0]);
    assert!(normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).is_none());
    let mut bytes = 0xd503201fu32.to_le_bytes().repeat(10);
    bytes[..4].copy_from_slice(&0x90000000u32.to_le_bytes());
    assert!(normalize(Isa::AArch64, &bytes, 0, &HashSet::new()).is_none());
}

#[test]
fn archive_build_records_members_and_relocations() {
    let dir = Path::new("target/signature-archive-test");
    std::fs::create_dir_all(dir).unwrap();
    let archive = dir.join("calls.a");
    let member = branch_object(-4, object::SymbolKind::Text);
    let mut archive_bytes = b"!<arch>\n".to_vec();
    archive_bytes.extend_from_slice(
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "calls.o/",
            0,
            0,
            0,
            "100644",
            member.len()
        )
        .as_bytes(),
    );
    archive_bytes.extend_from_slice(&member);
    if !member.len().is_multiple_of(2) {
        archive_bytes.push(b'\n');
    }
    std::fs::write(&archive, archive_bytes).unwrap();
    let database = build(&archive, None).unwrap();
    assert_eq!(database.entries.len(), 2);
    assert_eq!(database.sources, vec!["calls.a:calls.o"]);
    assert_eq!(
        database
            .entries
            .iter()
            .find(|entry| entry.name == "caller")
            .unwrap()
            .calls,
        vec!["leaf"]
    );
    assert!(matches!(
        build(&archive, Some(Instant::now())),
        Err(Error::TimedOut)
    ));
}

#[test]
fn alignment_padding_does_not_make_short_functions_matchable() {
    let mut bytes = vec![0x90; 40];
    bytes[34..40].copy_from_slice(&[0xb8, 7, 0, 0, 0, 0xc3]);
    assert!(
        !normalize(Isa::X86_64, &bytes, 0, &HashSet::new())
            .unwrap()
            .name_eligible
    );
    bytes[0] = 0xc3;
    assert!(
        !normalize(Isa::X86_64, &bytes, 0, &HashSet::new())
            .unwrap()
            .name_eligible
    );
    let mut bytes = 0xd503201fu32.to_le_bytes().repeat(10);
    bytes[32..36].copy_from_slice(&0x52800000u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    assert!(
        !normalize(Isa::AArch64, &bytes, 0, &HashSet::new())
            .unwrap()
            .name_eligible
    );
    bytes[..4].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    assert!(
        !normalize(Isa::AArch64, &bytes, 0, &HashSet::new())
            .unwrap()
            .name_eligible
    );
}

#[test]
fn relocations_into_a_symbol_are_not_calls_to_its_start() {
    for addend in [-2, 0, 4] {
        let bytes = branch_object(addend, object::SymbolKind::Text);
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut entries = Vec::new();
        object_entries(&file, &mut entries, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "leaf");
    }
}

#[test]
fn branch_relocations_to_data_are_rejected() {
    let bytes = branch_object(-4, object::SymbolKind::Data);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    assert!(entries.is_empty());
}

fn constant_object(value: u32) -> Vec<u8> {
    use object::write::{Object, Relocation, Symbol, SymbolSection};
    let mut object = Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
    let data_section = object.add_section(
        Vec::new(),
        b".rodata".to_vec(),
        object::SectionKind::ReadOnlyData,
    );
    object.append_section_data(data_section, &value.to_le_bytes(), 4);
    let mut bytes = vec![0x8b, 0x05, 0, 0, 0, 0];
    bytes.extend_from_slice(&[0x83, 0xc0, 1].repeat(12));
    bytes.push(0xc3);
    object.append_section_data(text, &bytes, 16);
    let constant = object.add_symbol(Symbol {
        name: b"constant".to_vec(),
        value: 0,
        size: 4,
        kind: object::SymbolKind::Data,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(data_section),
        flags: object::SymbolFlags::None,
    });
    object.add_symbol(Symbol {
        name: b"read_constant".to_vec(),
        value: 0,
        size: bytes.len() as u64,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: object::SymbolFlags::None,
    });
    object
        .add_relocation(
            text,
            Relocation {
                offset: 2,
                symbol: constant,
                addend: -4,
                flags: object::RelocationFlags::Generic {
                    kind: object::RelocationKind::Relative,
                    encoding: object::RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )
        .unwrap();
    object.write().unwrap()
}

#[test]
fn pc_relative_reads_require_exact_read_only_constants() {
    let bytes = constant_object(0x12345678);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].constants, vec![vec![0x78, 0x56, 0x34, 0x12]]);
    let database = Database::new(entries);
    let directory = Path::new("target/signature-constant-test");
    std::fs::create_dir_all(directory).unwrap();
    for value in [0x12345678, 0x87654321] {
        let path = directory.join(format!("constant-{value:x}.o"));
        std::fs::write(&path, constant_object(value)).unwrap();
        let image = crate::loader::load(&path).unwrap();
        let matches = identify(&image, &database, None, MatchScope::All).unwrap();
        assert_eq!(matches.len(), usize::from(value == 0x12345678));
        let mut writable = image;
        for section in &mut writable.sections {
            section.read_only = false;
        }
        assert!(
            identify(&writable, &database, None, MatchScope::All)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn call_destinations_distinguish_identical_normalized_callers() {
    let bytes = branch_object(-4, object::SymbolKind::Text);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    let mut alternative = entries
        .iter()
        .find(|entry| entry.name == "caller")
        .unwrap()
        .clone();
    alternative.name = "other_caller".into();
    alternative.calls = vec!["other_leaf".into()];
    entries.push(alternative);
    let directory = Path::new("target/signature-graph-test");
    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("calls.o");
    std::fs::write(&path, bytes).unwrap();
    let image = crate::loader::load(&path).unwrap();
    let matches = identify(&image, &Database::new(entries), None, MatchScope::All).unwrap();
    let caller = matches.iter().find(|(addr, _)| *addr == 40).unwrap();
    assert_eq!(caller.1.certainty, crate::sigs::Certainty::Exact);
    assert_eq!(caller.1.candidates[0].name, "caller");
}

#[test]
fn branches_into_an_instruction_are_rejected() {
    let mut bytes = [0x83, 0xc0, 1].repeat(12);
    bytes.extend_from_slice(&[0xeb, 0xdb]);
    assert!(normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).is_none());
}

#[test]
fn a_name_at_an_ambiguous_address_is_not_unique_elsewhere() {
    let bytes = branch_object(-4, object::SymbolKind::Text);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    let mut duplicate = entries
        .iter()
        .find(|entry| entry.name == "caller")
        .unwrap()
        .clone();
    duplicate.name = "leaf".into();
    entries.push(duplicate);
    let directory = Path::new("target/signature-duplicate-test");
    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("calls.o");
    std::fs::write(&path, bytes).unwrap();
    let image = crate::loader::load(&path).unwrap();
    let results = identify(&image, &Database::new(entries), None, MatchScope::All).unwrap();
    assert!(
        results
            .iter()
            .all(|(_, evidence)| evidence.certainty != crate::sigs::Certainty::Exact)
    );
}

#[test]
fn provenance_excludes_sets_with_unconfirmed_destinations() {
    let bytes = branch_object(-4, object::SymbolKind::Text);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    let mut alternate_leaf = entries
        .iter()
        .find(|entry| entry.name == "leaf")
        .unwrap()
        .clone();
    alternate_leaf.name = "other_leaf".into();
    let caller = entries
        .iter_mut()
        .find(|entry| entry.name == "caller")
        .unwrap();
    caller.set = Some("confirmed".into());
    let mut alternate_caller = caller.clone();
    alternate_caller.calls = vec!["other_leaf".into()];
    alternate_caller.set = Some("unconfirmed".into());
    entries.extend([alternate_leaf, alternate_caller]);
    let directory = Path::new("target/signature-provenance-test");
    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("calls.o");
    std::fs::write(&path, bytes).unwrap();
    let image = crate::loader::load(&path).unwrap();
    let results = identify(&image, &Database::new(entries), None, MatchScope::All).unwrap();
    let caller = results.iter().find(|(addr, _)| *addr == 40).unwrap();
    assert_eq!(caller.1.certainty, crate::sigs::Certainty::Exact);
    assert_eq!(caller.1.candidates.len(), 1);
    assert_eq!(caller.1.candidates[0].set, "confirmed");
}

#[test]
fn unreachable_arm_call_bytes_do_not_create_function_starts() {
    let leaf = [0x00, 0x00, 0x80, 0xe2].repeat(9);
    let mut leaf = leaf;
    leaf.extend_from_slice(&0xe12fff1eu32.to_le_bytes());
    let body = normalize(Isa::Arm32, &leaf, 32, &HashSet::new()).unwrap();
    let database = Database::new(vec![make_entry(
        "leaf".into(),
        Isa::Arm32,
        body,
        Vec::new(),
        Vec::new(),
    )]);
    let mut bytes = 0xeafffffeu32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&0xeb000005u32.to_le_bytes());
    bytes.resize(32, 0);
    bytes.extend_from_slice(&leaf);
    let mut image = crate::loader::Image::from_code(Isa::Arm32, 0, bytes);
    image.functions.insert(
        0,
        crate::loader::Function {
            addr: 0,
            size: Some(4),
            size_estimated: false,
            name: None,
            aliases: Vec::new(),
            sources: vec![crate::loader::NameSource::Entry],
            library: None,
        },
    );
    assert!(
        discover::arm32(&mut image, &database, None)
            .unwrap()
            .is_empty()
    );
    assert!(!image.functions.contains_key(&32));
}

#[test]
fn unaligned_arm_function_addresses_are_rejected() {
    let arm = 0xe2800001u32.to_le_bytes().repeat(10);
    let aarch64 = 0x91000400u32.to_le_bytes().repeat(10);
    for addr in [1, 2, 3] {
        assert!(normalize(Isa::Arm32, &arm, addr, &HashSet::new()).is_none());
        assert!(normalize(Isa::AArch64, &aarch64, addr, &HashSet::new()).is_none());
    }
}

#[test]
fn an_existing_symbol_at_another_address_prevents_a_duplicate_name() {
    let bytes = branch_object(-4, object::SymbolKind::Text);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let mut entries = Vec::new();
    object_entries(&file, &mut entries, None).unwrap();
    entries.retain(|entry| entry.name == "leaf");
    entries[0].name = "caller".into();
    let directory = Path::new("target/signature-symbol-collision-test");
    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("calls.o");
    std::fs::write(&path, bytes).unwrap();
    let mut image = crate::loader::load(&path).unwrap();
    image.functions.get_mut(&0).unwrap().name = None;
    let results = identify(&image, &Database::new(entries), None, MatchScope::Unnamed).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1.certainty, crate::sigs::Certainty::Unconfirmed);
}
