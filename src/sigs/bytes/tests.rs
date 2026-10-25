use super::*;

#[test]
fn short_functions_are_not_signatures() {
    assert!(normalize(Isa::X86_64, &[0x90; 31], 0, &HashSet::new()).is_none());
    assert!(normalize(Isa::AArch64, &[0; 28], 0, &HashSet::new()).is_none());
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
fn indirect_calls_and_overflow_are_rejected() {
    let mut bytes = vec![0x90; 40];
    bytes[..2].copy_from_slice(&[0xff, 0xd0]);
    assert!(normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).is_none());
    assert!(normalize(Isa::X86_64, &[0x90; 40], u64::MAX, &HashSet::new()).is_none());
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
    let mut data = b"!<arch>\n".to_vec();
    data.extend_from_slice(
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
    data.extend_from_slice(&member);
    if !member.len().is_multiple_of(2) {
        data.push(b'\n');
    }
    std::fs::write(&archive, data).unwrap();
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
    assert!(normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).is_none());
    bytes[0] = 0xc3;
    assert!(normalize(Isa::X86_64, &bytes, 0, &HashSet::new()).is_none());
    let mut bytes = 0xd503201fu32.to_le_bytes().repeat(10);
    bytes[32..36].copy_from_slice(&0x52800000u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    assert!(normalize(Isa::AArch64, &bytes, 0, &HashSet::new()).is_none());
    bytes[..4].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    assert!(normalize(Isa::AArch64, &bytes, 0, &HashSet::new()).is_none());
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
