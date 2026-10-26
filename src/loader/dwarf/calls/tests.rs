use super::super::tests::{image, information};

use gimli::SectionId;
#[test]
fn generated_member_recipes_preserve_existing_field_and_gap_choices() {
    let mut field_count = 0;
    let mut gap_count = 0;
    for (fixture, function) in [
        ("metrics/structs.x86_64.O0.debug.elf", "flags_level"),
        ("member_types_x64.elf", "read_outer"),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture);
        let binary = crate::service::Binary::open(&path).expect("fixture");
        let image = binary.image();
        let address = binary.find(function).expect("function").addr;
        let index = call_index(image).expect("index");
        let source = index.addresses[&address][0];
        let found = call_unit(image, source.unit).expect("source unit");
        let dwarf = call_dwarf(image).expect("dwarf");
        let mut units = dwarf.units();
        let mut inspected = false;
        while let Some(header) = units.next().expect("header") {
            let unit = dwarf.unit(header).expect("unit");
            if source_id(&unit, gimli::UnitOffset(0)).map(|id| id.unit) != Some(source.unit) {
                continue;
            }
            inspected = true;
            assert_eq!(
                found.graph.generated_members.len(),
                found.graph.definitions.len()
            );
            for (id, members) in &found.graph.generated_members {
                let definition = &found.graph.definitions[id];
                let rendered: Vec<_> = members
                    .iter()
                    .map(|member| match member {
                        CallMember::Field {
                            name,
                            ty,
                            offset,
                            bytes,
                        } => {
                            field_count += 1;
                            assert!(
                                *bytes > 0
                                    && offset
                                        .checked_add(*bytes)
                                        .is_some_and(|end| end <= definition.size)
                            );
                            assert_eq!(found.graph.types[ty].layout.as_ref().unwrap().size, *bytes);
                            assert_eq!(ty.unit, source.unit);
                            layout::declaration(&dwarf, &unit, gimli::UnitOffset(ty.die), name, 16)
                                .expect("same source declaration")
                        }
                        CallMember::Bytes { offset, bytes } => {
                            gap_count += 1;
                            assert!(
                                *bytes > 0
                                    && offset
                                        .checked_add(*bytes)
                                        .is_some_and(|end| end <= definition.size)
                            );
                            format!("uint8_t gap_0x{offset:x}[0x{bytes:x}];")
                        }
                    })
                    .collect();
                assert_eq!(
                    rendered, definition.members,
                    "{fixture}: {}",
                    definition.name
                );
            }
        }
        assert!(inspected);
    }
    assert!(field_count > 0);
    assert!(gap_count > 0);
}

use super::*;
use crate::ir::calls::CallMember;
use crate::loader::dwarf::functions;

fn abbreviations() -> Vec<u8> {
    let mut bytes = Vec::new();
    type Abbreviation = (u8, u8, bool, &'static [(u8, u8)]);
    let entries: &[Abbreviation] = &[
        (1, 0x11, true, &[(0x13, 0x05)]),
        (2, 0x2e, true, &[(0x11, 0x01), (0x31, 0x13)]),
        (3, 0x2e, true, &[(0x27, 0x0c), (0x49, 0x13), (0x36, 0x0b)]),
        (4, 0x05, false, &[(0x49, 0x13)]),
        (5, 0x05, false, &[(0x31, 0x13)]),
        (6, 0x24, false, &[(0x03, 0x08), (0x0b, 0x0b), (0x3e, 0x0b)]),
        (7, 0x2e, false, &[(0x55, 0x17), (0x27, 0x0c), (0x49, 0x13)]),
        (8, 0x2e, true, &[(0x11, 0x01), (0x31, 0x10)]),
        (
            9,
            0x2e,
            false,
            &[(0x55, 0x17), (0x27, 0x0c), (0x49, 0x13), (0x52, 0x01)],
        ),
        (10, 0x2e, false, &[(0x11, 0x01), (0x27, 0x0c), (0x49, 0x13)]),
        (11, 0x0f, false, &[(0x49, 0x13)]),
        (12, 0x01, true, &[(0x49, 0x13)]),
        (13, 0x21, false, &[(0x37, 0x0b)]),
        (14, 0x13, true, &[(0x03, 0x08), (0x0b, 0x0b)]),
        (
            15,
            0x0d,
            false,
            &[(0x03, 0x08), (0x49, 0x13), (0x6b, 0x0b), (0x0d, 0x0b)],
        ),
        (16, 0x04, true, &[(0x03, 0x08), (0x49, 0x13)]),
        (17, 0x28, false, &[(0x03, 0x08), (0x1c, 0x0b)]),
    ];
    for (code, tag, children, attributes) in entries {
        bytes.extend([*code, *tag, u8::from(*children)]);
        for (name, form) in *attributes {
            bytes.extend([*name, *form]);
        }
        bytes.extend([0, 0]);
    }
    bytes.push(0);
    bytes
}

fn dwarf<'a>(
    info: &'a [u8],
    abbrev: &'a [u8],
    ranges: &'a [u8],
) -> Dwarf<EndianSlice<'a, LittleEndian>> {
    Dwarf::load(|id| -> Result<_, gimli::Error> {
        Ok(EndianSlice::new(
            match id {
                SectionId::DebugInfo => info,
                SectionId::DebugAbbrev => abbrev,
                SectionId::DebugRanges => ranges,
                _ => &[],
            },
            LittleEndian,
        ))
    })
    .unwrap()
}

fn reference(dies: &mut Vec<u8>) -> usize {
    let at = dies.len();
    dies.extend(0u32.to_le_bytes());
    at
}

fn patch(dies: &mut [u8], at: usize, target: usize) {
    dies[at..at + 4].copy_from_slice(&u32::try_from(target).unwrap().to_le_bytes());
}

#[derive(Clone, Copy)]
enum Origin {
    Cyclic,
    Declaration,
}

#[derive(Clone, Copy)]
enum UnitReference {
    CrossUnit,
    Local,
}

#[derive(Clone, Copy)]
enum Parameters {
    Extra,
    Inherited,
}

#[derive(Clone, Copy)]
enum Prototype {
    Present,
    Absent,
}

#[derive(Clone, Copy)]
enum CallingConvention {
    Normal,
    Unsupported,
}

fn inherited(
    cycle: Origin,
    cross_unit: UnitReference,
    extra_parameter: Parameters,
    prototyped: Prototype,
    normal: CallingConvention,
) -> (Vec<u8>, gimli::UnitOffset<usize>, gimli::UnitOffset<usize>) {
    let normal = matches!(normal, CallingConvention::Normal);
    let prototyped = matches!(prototyped, Prototype::Present);
    let extra_parameter = matches!(extra_parameter, Parameters::Extra);
    let cross_unit = matches!(cross_unit, UnitReference::CrossUnit);
    let cycle = matches!(cycle, Origin::Cyclic);
    let mut dies = vec![1, 2, 0];
    let declaration = dies.len() + 11;
    dies.extend([3, u8::from(prototyped)]);
    let result = reference(&mut dies);
    dies.push(if normal { 1 } else { 3 });
    let parameter = dies.len() + 11;
    dies.push(4);
    let argument = reference(&mut dies);
    dies.push(0);
    let function = dies.len() + 11;
    dies.push(if cross_unit { 8 } else { 2 });
    dies.extend(0x1000u64.to_le_bytes());
    let origin = reference(&mut dies);
    dies.push(5);
    let parameter_origin = reference(&mut dies);
    let extra = if extra_parameter {
        dies.push(5);
        Some(reference(&mut dies))
    } else {
        None
    };
    dies.push(0);
    let integer = dies.len() + 11;
    dies.push(6);
    dies.extend(b"unsigned long\0");
    dies.extend([8, 7, 0]);
    patch(&mut dies, result, integer);
    patch(&mut dies, argument, integer);
    patch(
        &mut dies,
        origin,
        if cycle { function } else { declaration },
    );
    patch(&mut dies, parameter_origin, parameter);
    if let Some(extra) = extra {
        patch(&mut dies, extra, parameter);
    }
    (
        information(&dies),
        gimli::UnitOffset(function),
        gimli::UnitOffset(integer),
    )
}

#[test]
fn inherited_call_declaration_keeps_return_and_parameter_types() {
    let (info, function, integer) = inherited(
        Origin::Declaration,
        UnitReference::Local,
        Parameters::Inherited,
        Prototype::Present,
        CallingConvention::Normal,
    );
    let abbrev = abbreviations();
    let dwarf = dwarf(&info, &abbrev, &[]);
    let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
    let entry = unit.entry(function).unwrap();
    layout::function_profile(&unit, &entry).unwrap();
    let types = call_function_types(&dwarf, &unit, &entry, AbiProfile::Aapcs64).unwrap();
    assert_ne!(types.ret, Some(CType::Void));
    assert_eq!(types.params.len(), 1);
    assert_eq!(types.source.result, source_id(&unit, integer));
    assert_eq!(types.source.parameters, vec![source_id(&unit, integer)]);
    assert!(types.ret_layout.unwrap().is_some());
    assert_eq!(call_entry(&dwarf, &unit, &entry).unwrap().0, Some(0x1000));
}

#[test]
fn cyclic_and_cross_unit_origins_do_not_become_void_declarations() {
    for (cycle, cross_unit) in [(true, false), (false, true)] {
        let (info, function, _) = inherited(
            if cycle {
                Origin::Cyclic
            } else {
                Origin::Declaration
            },
            if cross_unit {
                UnitReference::CrossUnit
            } else {
                UnitReference::Local
            },
            Parameters::Inherited,
            Prototype::Present,
            CallingConvention::Normal,
        );
        let abbrev = abbreviations();
        let dwarf = dwarf(&info, &abbrev, &[]);
        let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
        let entry = unit.entry(function).unwrap();
        assert!(matches!(
            call_function_types(&dwarf, &unit, &entry, AbiProfile::Aapcs64),
            Err(AbiIssue::UnknownLayout)
        ));
    }
}

#[test]
fn inconsistent_inherited_parameter_lists_are_unknown() {
    let (info, function, _) = inherited(
        Origin::Declaration,
        UnitReference::Local,
        Parameters::Extra,
        Prototype::Present,
        CallingConvention::Normal,
    );
    let abbrev = abbreviations();
    let dwarf = dwarf(&info, &abbrev, &[]);
    let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
    let entry = unit.entry(function).unwrap();
    assert!(matches!(
        call_function_types(&dwarf, &unit, &entry, AbiProfile::Aapcs64),
        Err(AbiIssue::UnknownLayout)
    ));
}

#[test]
fn inherited_prototype_and_calling_convention_remain_required() {
    for (prototyped, normal) in [(false, true), (true, false)] {
        let (info, function, _) = inherited(
            Origin::Declaration,
            UnitReference::Local,
            Parameters::Inherited,
            if prototyped {
                Prototype::Present
            } else {
                Prototype::Absent
            },
            if normal {
                CallingConvention::Normal
            } else {
                CallingConvention::Unsupported
            },
        );
        let abbrev = abbreviations();
        let dwarf = dwarf(&info, &abbrev, &[]);
        let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
        let entry = unit.entry(function).unwrap();
        assert!(matches!(
            call_function_types(&dwarf, &unit, &entry, AbiProfile::Aapcs64),
            Err(AbiIssue::UnsupportedProfile)
        ));
    }
}

#[test]
fn range_only_functions_have_an_entry_and_keep_explicit_entry_pc() {
    for explicit in [false, true] {
        let mut dies = vec![1, 2, 0];
        let function = gimli::UnitOffset(dies.len() + 11);
        dies.push(if explicit { 9 } else { 7 });
        dies.extend(0u32.to_le_bytes());
        dies.push(1);
        let result = reference(&mut dies);
        if explicit {
            dies.extend(0x1008u64.to_le_bytes());
        }
        let integer = dies.len() + 11;
        dies.push(6);
        dies.extend(b"unsigned long\0");
        dies.extend([8, 7, 0]);
        patch(&mut dies, result, integer);
        let info = information(&dies);
        let abbrev = abbreviations();
        let ranges: Vec<_> = [0x1000u64, 0x1010, 0x2000, 0x2010, 0, 0]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let dwarf = dwarf(&info, &abbrev, &ranges);
        let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
        let entry = unit.entry(function).unwrap();
        let (address, ranges) = call_entry(&dwarf, &unit, &entry).unwrap();
        assert_eq!(address, Some(if explicit { 0x1008 } else { 0x1000 }));
        assert_eq!(ranges, vec![0x1000..0x1010, 0x2000..0x2010]);
        let types = call_function_types(&dwarf, &unit, &entry, AbiProfile::Aapcs64).unwrap();
        assert_ne!(types.ret, Some(CType::Void));
    }
}
fn function(dies: &mut Vec<u8>) -> usize {
    dies.push(10);
    dies.extend(0x1000u64.to_le_bytes());
    dies.push(1);
    reference(dies)
}

#[test]
fn pointer_array_shapes_are_read_without_byte_size_and_conflicts_are_rejected() {
    for shapes in [(vec![2u8], vec![3u8]), (vec![2, 6], vec![3, 4])] {
        let mut dies = vec![1, 2, 0];
        let functions = [function(&mut dies), function(&mut dies)];
        let mut arrays = Vec::new();
        let mut element_refs = Vec::new();
        for (result, dimensions) in functions.into_iter().zip([&shapes.0, &shapes.1]) {
            let pointer = dies.len() + 11;
            dies.push(11);
            let target = reference(&mut dies);
            let array = dies.len() + 11;
            arrays.push(array);
            dies.push(12);
            element_refs.push(reference(&mut dies));
            for count in dimensions {
                dies.extend([13, *count]);
            }
            dies.push(0);
            patch(&mut dies, result, pointer);
            patch(&mut dies, target, array);
        }
        let integer = dies.len() + 11;
        dies.push(6);
        dies.extend(b"unsigned long\0");
        dies.extend([8, 7, 0]);
        for at in element_refs {
            patch(&mut dies, at, integer);
        }
        let info = information(&dies);
        let abbrev = abbreviations();
        let image = image(&info, &abbrev);
        let unit = call_unit(&image, 0).unwrap();
        for (offset, expected) in arrays.into_iter().zip([&shapes.0, &shapes.1]) {
            let node = &unit.graph.types[&TypeSource {
                unit: 0,
                die: offset,
            }];
            assert_eq!(node.size, None);
            assert_eq!(
                node.dimensions,
                expected.iter().copied().map(u64::from).collect::<Vec<_>>()
            );
            assert!(node.layout.is_ok());
        }
        assert!(matches!(
            crate::analysis::calls::declaration(&image, 0x1000),
            Err(AbiIssue::IncompatibleDefinition)
        ));
    }
}

#[test]
fn pointer_bitfield_positions_are_read_and_conflicting_declarations_rejected() {
    let mut dies = vec![1, 2, 0];
    let functions = [function(&mut dies), function(&mut dies)];
    let mut integer_refs = Vec::new();
    let mut structures = Vec::new();
    for (result, positions) in functions.into_iter().zip([[0u8, 4], [4, 0]]) {
        let pointer = dies.len() + 11;
        dies.push(11);
        let target = reference(&mut dies);
        let structure = dies.len() + 11;
        structures.push(structure);
        dies.push(14);
        dies.extend(b"shared\0");
        dies.push(8);
        for (name, offset) in [b"a\0", b"b\0"].into_iter().zip(positions) {
            dies.push(15);
            dies.extend(name);
            integer_refs.push(reference(&mut dies));
            dies.extend([offset, 4]);
        }
        dies.push(0);
        patch(&mut dies, result, pointer);
        patch(&mut dies, target, structure);
    }
    let integer = dies.len() + 11;
    dies.push(6);
    dies.extend(b"unsigned long\0");
    dies.extend([8, 7, 0]);
    for at in integer_refs {
        patch(&mut dies, at, integer);
    }
    let info = information(&dies);
    let abbrev = abbreviations();
    let image = image(&info, &abbrev);
    let unit = call_unit(&image, 0).unwrap();
    let layouts: Vec<_> = structures
        .into_iter()
        .map(|die| {
            unit.graph.types[&TypeSource { unit: 0, die }]
                .layout
                .clone()
                .unwrap()
        })
        .collect();
    assert_ne!(layouts[0], layouts[1]);
    assert!(matches!(
        crate::analysis::calls::declaration(&image, 0x1000),
        Err(AbiIssue::IncompatibleDefinition)
    ));
}

#[test]
fn enum_constants_are_read_and_conflicting_declarations_rejected() {
    let mut dies = vec![1, 2, 0];
    let functions = [function(&mut dies), function(&mut dies)];
    let mut integers = Vec::new();
    let mut enums = Vec::new();
    for (result, value) in functions.into_iter().zip([1u8, 2]) {
        let enumeration = dies.len() + 11;
        enums.push(enumeration);
        dies.push(16);
        dies.extend(b"choice\0");
        integers.push(reference(&mut dies));
        dies.push(17);
        dies.extend(b"only\0");
        dies.extend([value, 0]);
        patch(&mut dies, result, enumeration);
    }
    let integer = dies.len() + 11;
    dies.push(6);
    dies.extend(b"unsigned long\0");
    dies.extend([8, 7, 0]);
    for at in integers {
        patch(&mut dies, at, integer);
    }
    let info = information(&dies);
    let abbrev = abbreviations();
    let image = image(&info, &abbrev);
    let unit = call_unit(&image, 0).unwrap();
    for (die, value) in enums.into_iter().zip([1i128, 2]) {
        let node = &unit.graph.types[&TypeSource { unit: 0, die }];
        assert_eq!(node.enumerators, vec![("only".to_owned(), value)]);
    }
    assert!(matches!(
        crate::analysis::calls::declaration(&image, 0x1000),
        Err(AbiIssue::IncompatibleDefinition)
    ));
}

#[test]
fn function_ranges_distinguish_address_and_constant_high_pc() {
    use object::write::Object;
    use object::{Architecture, BinaryFormat, Endianness, SectionKind};

    let (abbrev, dies) = super::super::tests::function_range_data();
    let info = information(&dies);
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    for (name, bytes) in [
        (".debug_info", info.as_slice()),
        (".debug_abbrev", abbrev.as_slice()),
    ] {
        let section = object.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Debug);
        object.set_section_data(section, bytes, 1);
    }
    let path = std::env::temp_dir().join(format!("velk-dwarf-high-pc-{}.o", std::process::id()));
    std::fs::write(&path, object.write().unwrap()).unwrap();
    let loaded = crate::loader::load(&path);
    std::fs::remove_file(&path).unwrap();
    let image = loaded.unwrap();
    let ranges: Vec<_> = functions(&image)
        .into_iter()
        .map(|function| (function.name, function.addr, function.size))
        .collect();
    assert_eq!(
        ranges,
        vec![
            ("relative_larger_than_low".to_owned(), 0x30, 0x3d),
            ("absolute".to_owned(), 0x50, 0x24),
            ("relative_smaller_than_low".to_owned(), 0x1000, 0x20),
        ]
    );
}
