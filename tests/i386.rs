mod common;

use velk::loader::Isa;

#[test]
fn fixtures_load_and_lift_in_i386_mode() {
    let mut count = 0;
    let fixtures = common::fixtures();
    let fixtures = fixtures.into_iter().filter(|path| {
        let name = path.to_string_lossy();
        name.contains(".i386.") || name.contains(".win32.")
    });
    for path in fixtures {
        let image = velk::loader::load(&common::fixtures_dir().join(&path)).unwrap();
        assert_eq!(image.isa, Isa::I386, "{}", path.display());
        for function in image.functions.values() {
            let blocks = velk::lift::lift(
                &image,
                function.addr,
                function.size.unwrap(),
                &Default::default(),
            )
            .unwrap();
            assert!(
                !blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(stmt, velk::ir::Stmt::Unsupported { .. })),
                "{} {:?}",
                path.display(),
                function.name
            );
        }
        count += 1;
    }
    assert!(count >= 20);
}

#[test]
fn elf32_rel_and_pe32_import_slots_have_four_byte_width() {
    for opt in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let image = velk::loader::load(
                &common::fixtures_dir()
                    .join(format!("metrics/relocations.i386.{opt}.{variant}.elf")),
            )
            .unwrap();
            for (name, expected) in [("selected", None), ("bias_pointer", Some(11))] {
                let address = *image
                    .data_symbols
                    .iter()
                    .find(|(_, symbol)| *symbol == name)
                    .unwrap()
                    .0;
                let pointer =
                    u32::from_le_bytes(image.read_vaddr(address, 4).unwrap().try_into().unwrap())
                        as u64;
                if let Some(expected) = expected {
                    let value = u32::from_le_bytes(
                        image.read_vaddr(pointer, 4).unwrap().try_into().unwrap(),
                    );
                    assert_eq!(value, expected);
                } else {
                    assert_eq!(image.functions[&pointer].name.as_deref(), Some("add_bias"));
                }
            }
            assert!(image.imports.values().any(|name| name == "abs"));
            let image = velk::loader::load(
                &common::fixtures_dir().join(format!("metrics/imports.win32.{opt}.{variant}.dll")),
            )
            .unwrap();
            assert_eq!(image.imports.len(), 1);
            assert!(image.imports.values().any(|name| name == "abs"));
            let (&slot, _) = image.imports.iter().next().unwrap();
            assert_eq!(slot % 4, 0);
            assert!(image.read_vaddr(slot, 4).is_some());
        }
    }
}

#[test]
fn lifted_fixture_arithmetic_matches_reference_semantics() {
    use velk::ir::eval;
    use velk::service::Binary;
    let fixtures = common::fixtures();
    let fixtures = fixtures.into_iter().filter(|path| {
        let name = path.to_string_lossy();
        name.contains("l0_arith.") && (name.contains(".i386.") || name.contains(".win32."))
    });
    for path in fixtures {
        let mut binary = Binary::open(&common::fixtures_dir().join(&path)).unwrap();
        for name in ["add3", "scale", "pick", "negate"] {
            let function = binary.find(name).unwrap().clone();
            let mut ir = binary.analysis(function.addr, None).unwrap().ir.clone();
            ir.blocks = velk::lift::lift(
                binary.image(),
                function.addr,
                function.size.unwrap(),
                &Default::default(),
            )
            .unwrap();
            for x in [0i32, 1, -1, i32::MIN, i32::MAX, 0x12345678] {
                let arguments = [x, -7, 31];
                let sp = eval::stack_top(Isa::I386);
                let memory: Vec<_> = arguments
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (sp + 4 + 4 * index as u64, *value as u32 as u64))
                    .collect();
                let setup = eval::Setup {
                    seed: 0,
                    convention: eval::Convention {
                        arguments: &[],
                        clobbered: &[0, 1, 2],
                    },
                    registers: &[],
                    memory: &memory,
                    step_limit: 1000,
                };
                let expected = match name {
                    "add3" => x.wrapping_add(-7).wrapping_add(31),
                    "scale" => x.wrapping_mul(7).wrapping_add(3),
                    "pick" => x.max(-7),
                    "negate" => x.wrapping_neg(),
                    _ => unreachable!(),
                };
                match eval::run(&ir, &setup) {
                    eval::Outcome::Return { value, .. } => assert_eq!(
                        value as u32,
                        expected as u32,
                        "{} {name} {x}",
                        path.display()
                    ),
                    outcome => panic!("{} {name}: {outcome:?}", path.display()),
                }
            }
        }
    }
}

#[test]
fn elf32_jump_slot_replaces_the_implicit_plt_address() {
    use object::{Object, ObjectSymbol};
    for opt in ["O0", "O2"] {
        let path = common::fixtures_dir().join(format!("metrics/relocations.i386.{opt}.debug.elf"));
        let bytes = std::fs::read(&path).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let image = velk::loader::load(&path).unwrap();
        let address = image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some("add_bias"))
            .unwrap()
            .addr;
        let mut checked = 0;
        for (slot, relocation) in object.dynamic_relocations().unwrap() {
            if relocation.flags()
                != (object::RelocationFlags::Elf {
                    r_type: object::elf::R_386_JMP_SLOT,
                })
            {
                continue;
            }
            let object::RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let symbol = object
                .dynamic_symbols()
                .find(|symbol| symbol.index() == index)
                .unwrap();
            if symbol.name().unwrap() != "add_bias" {
                continue;
            }
            let pointer =
                u32::from_le_bytes(image.read_vaddr(slot, 4).unwrap().try_into().unwrap());
            assert_eq!(u64::from(pointer), address);
            checked += 1;
        }
        assert_eq!(checked, 1);
    }
}

#[test]
fn unknown_i386_call_arguments_are_refused() {
    let mut object = object::write::Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::I386,
        object::Endianness::Little,
    );
    let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
    object.append_section_data(text, &[0xff, 0xd0, 0xc3], 1);
    object.add_symbol(object::write::Symbol {
        name: b"unknown_call".to_vec(),
        value: 0,
        size: 3,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(text),
        flags: object::SymbolFlags::None,
    });
    let directory = common::root().join("target/tmp");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("unknown-i386-{}.o", std::process::id()));
    std::fs::write(&path, object.write().unwrap()).unwrap();
    let mut binary = velk::service::Binary::open(&path).unwrap();
    let address = binary.find("unknown_call").unwrap().addr;
    let error = binary
        .decompile(address, None, None)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("call argument count in the block at 0x"),
        "{error}"
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn pe32_import_uses_windows_header_types() {
    let image = velk::loader::load(&common::fixtures_dir().join("windows_types.pe32.dll")).unwrap();
    assert_eq!(image.isa, Isa::I386);
    assert_eq!(image.imports.len(), 2);
    let mut slots: Vec<_> = image.imports.keys().copied().collect();
    slots.sort_unstable();
    assert_eq!(slots[1] - slots[0], 4);
    let prototype = velk::analysis::prototypes::for_image("GetFileType", &image).unwrap();
    assert_eq!(prototype.params.len(), 1);
    assert!(prototype.params[0].is_pointer());
    assert_eq!(prototype.ret.integer(), Some((32, false)));
    let error = velk::analysis::prototypes::for_image("GetLastError", &image).unwrap();
    assert!(error.params.is_empty());
    assert_eq!(error.ret.integer(), Some((32, false)));
    assert!(velk::analysis::prototypes::for_image("arithmetic.dll!GetFileType", &image).is_none());
    let allocation =
        velk::analysis::prototypes::for_image("kernel32.dll!VirtualAlloc", &image).unwrap();
    assert_eq!(allocation.params[1].integer(), Some((32, false)));
    let mut binary =
        velk::service::Binary::open(&common::fixtures_dir().join("windows_types.pe32.dll"))
            .unwrap();
    let address = binary.find("windows_file").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("uint32_t (GetFileType)(void *);"), "{code}");
}
