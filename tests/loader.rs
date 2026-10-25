//! What the loader reads where the program reads it: pointers a dynamic
//! loader fills, and data a damaged header places out of reach.

mod common;

use velk::service::Binary;

#[test]
fn macho_function_starts_separate_adjacent_leaf_functions() {
    for fixture in ["rust_probe_arm64", "rust_probe_arm64_stripped"] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        assert_eq!(binary.image().entry, Some(0x10000094c), "{fixture}");
        let first = &binary.image().functions[&0x10002e658];
        assert_eq!(first.size, Some(20), "{fixture}");
        assert!(
            first
                .sources
                .contains(&velk::loader::NameSource::FunctionStarts)
        );
        assert!(binary.image().functions.contains_key(&0x10002e66c));
        let code = binary.decompile(0x10002e658, None, None).unwrap();
        assert!(!code.contains("L_10002e66c"), "{code}");
        let next = binary.decompile(0x10002e66c, None, None).unwrap();
        assert!(next.contains("a0"), "{next}");
    }
}

#[test]
fn malformed_macho_function_start_deltas_do_not_panic() {
    let mut bytes =
        std::fs::read(common::fixtures_dir().join("rust_probe_arm64_stripped")).unwrap();
    let object::File::MachO64(file) = object::File::parse(bytes.as_slice()).unwrap() else {
        panic!("Mach-O fixture");
    };
    let mut commands = file.macho_load_commands().unwrap();
    let mut range = None;
    while let Some(command) = commands.next().unwrap() {
        if let object::read::macho::LoadCommandVariant::LinkeditData(command) =
            command.variant().unwrap()
            && command.cmd.get(file.endian()) == object::macho::LC_FUNCTION_STARTS
        {
            let start = command.dataoff.get(file.endian()) as usize;
            range = Some(start..start + command.datasize.get(file.endian()) as usize);
            break;
        }
    }
    bytes[range.expect("function starts")].fill(0xff);
    let path = common::root().join("target/malformed-macho-starts");
    std::fs::write(&path, bytes).unwrap();
    Binary::open(&path).expect("damaged start deltas leave other function sources usable");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn debug_members_keep_their_declared_types_and_widths() {
    for isa in ["aarch64", "x86_64"] {
        for level in ["O0", "O2"] {
            let fixture = format!("metrics/structs.{isa}.{level}.debug.elf");
            let binary = Binary::open(&common::fixtures_dir().join(&fixture))
                .unwrap_or_else(|error| panic!("{fixture}: {error}"));
            let function = binary.find("rect_area").expect("rect_area");
            let types = velk::loader::dwarf::function_types(binary.image(), function.addr)
                .expect("debug types");
            for (name, offset) in [("min.x", 0), ("min.y", 4), ("max.x", 8), ("max.y", 12)] {
                let member = types
                    .members
                    .iter()
                    .find(|member| member.structure == "rect" && member.name == name)
                    .unwrap_or_else(|| panic!("{fixture}: rect.{name}"));
                assert_eq!(member.offset, offset, "{fixture}: {name}");
                assert_eq!(member.width, 4, "{fixture}: {name}");
                assert_eq!(member.ty.integer(), Some((32, true)), "{fixture}: {name}");
            }
            let count = types
                .members
                .iter()
                .find(|member| member.structure == "record" && member.name == "count")
                .expect("record.count");
            assert_eq!(count.offset, 16, "{fixture}");
            assert_eq!(count.width, 2, "{fixture}");
            assert_eq!(count.ty.integer(), Some((16, true)), "{fixture}");
            let word = types
                .members
                .iter()
                .find(|member| member.structure == "word")
                .expect("word member");
            assert_eq!(word.name, "u", "{fixture}");
            assert_eq!(word.width, 4, "{fixture}");
            assert_eq!(word.ty.integer(), Some((32, false)), "{fixture}");
            assert!(
                types
                    .members
                    .iter()
                    .all(|member| member.structure != "flags"),
                "{fixture}"
            );
        }
    }
}

#[test]
fn nested_debug_types_leave_later_members_with_their_parent() {
    for isa in ["a64", "x64"] {
        let fixture = format!("member_types_{isa}.elf");
        let binary = Binary::open(&common::fixtures_dir().join(&fixture))
            .unwrap_or_else(|error| panic!("{fixture}: {error}"));
        let function = binary.find("read_outer").expect("read_outer");
        let types = velk::loader::dwarf::function_types(binary.image(), function.addr)
            .expect("debug types");
        let member = |structure: &str, name: &str| {
            types
                .members
                .iter()
                .find(|member| member.structure == structure && member.name == name)
                .unwrap_or_else(|| panic!("{fixture}: {structure}.{name}"))
        };
        let head = member("outer", "first.head");
        assert_eq!(head.offset, 0, "{fixture}");
        assert_eq!(head.width, 4, "{fixture}");
        assert_eq!(head.ty.integer(), Some((32, false)), "{fixture}");
        let next = member("outer", "next");
        assert_eq!(next.offset, 8, "{fixture}");
        assert_eq!(next.width, 8, "{fixture}");
        let velk::ir::CType::Pointer(target) = &next.ty else {
            panic!("{fixture}: next is not a pointer: {:?}", next.ty);
        };
        assert_eq!(target.integer(), Some((32, true)), "{fixture}");
        let count = member("outer", "count");
        assert_eq!(count.offset, 16, "{fixture}");
        assert_eq!(count.width, 2, "{fixture}");
        assert_eq!(count.ty.integer(), Some((16, true)), "{fixture}");
        assert_eq!(member("inner", "head").width, 4, "{fixture}");
        assert!(
            types
                .members
                .iter()
                .filter(|member| member.structure == "inner")
                .all(|member| member.name == "head"),
            "{fixture}"
        );
    }
}

#[test]
fn file_metadata_does_not_occupy_virtual_memory() {
    for (fixture, metadata) in [("go_probe", ".shstrtab"), ("rust_probe", ".debug_info")] {
        let binary = Binary::open(&common::fixtures_dir().join(fixture))
            .unwrap_or_else(|error| panic!("{error}"));
        let image = binary.image();
        let section = image
            .sections
            .iter()
            .find(|section| section.name == metadata)
            .expect("file metadata");
        assert_eq!(section.vaddr, 0, "{fixture}");
        assert!(section.size > 0, "{fixture}");
        assert!(!section.loaded, "{fixture}");
        assert!(image.section_data(metadata).is_some(), "{fixture}");
        assert!(image.section_at(0).is_none(), "{fixture}");
        assert!(image.read_vaddr(0, 1).is_none(), "{fixture}");
        assert!(
            velk::render::data_ranges(image)
                .iter()
                .all(|(start, _)| *start != 0),
            "{fixture}"
        );
    }
}

#[test]
fn relocated_objects_keep_their_loaded_sections_at_zero() {
    for fixture in ["l4_memory_a64.o", "l4_memory_x64.o", "pe64.obj"] {
        let binary = Binary::open(&common::fixtures_dir().join(fixture))
            .unwrap_or_else(|error| panic!("{error}"));
        let image = binary.image();
        let text = image.section_at(0).expect("code mapped at zero");
        assert_eq!(text.name, ".text", "{fixture}");
        assert!(text.loaded, "{fixture}");
        assert!(image.read_vaddr(0, 1).is_some(), "{fixture}");
        let data = image
            .sections
            .iter()
            .find(|section| section.name == ".data" && section.size > 0)
            .expect("loaded data");
        assert!(data.loaded, "{fixture}");
        assert!(velk::render::data_ranges(image).contains(&(data.vaddr, data.size)));
    }
}

/// Dynamic relocations name symbols by their place in the dynamic symbol
/// table, which the full table, with static functions in it, numbers apart.
#[test]
fn dynamic_relocations_fill_the_symbols_they_name() {
    let binary = Binary::open(&common::fixtures_dir().join("shared_pointers_x64.so"))
        .unwrap_or_else(|error| panic!("{error}"));
    let image = binary.image();
    let address = |name: &str| {
        image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .map(|function| function.addr)
            .or_else(|| {
                image
                    .data_symbols
                    .iter()
                    .find(|(_, symbol)| *symbol == name)
                    .map(|(addr, _)| *addr)
            })
            .unwrap_or_else(|| panic!("no symbol {name}"))
    };
    let word = |addr: u64| {
        u64::from_le_bytes(
            image
                .read_vaddr(addr, 8)
                .expect("readable")
                .try_into()
                .expect("8 bytes"),
        )
    };
    let (target, pointer) = (address("target"), address("table_ptr"));
    assert_eq!(word(pointer), target, "table_ptr holds target");
    let got = image
        .sections
        .iter()
        .find(|section| section.name == ".got")
        .expect("a .got");
    assert!(
        (got.vaddr..got.vaddr + got.size)
            .step_by(8)
            .any(|slot| word(slot) == pointer),
        "a .got slot holds table_ptr"
    );
}

/// The ELF section header of `name` given the address `addr`.
fn place_section(bytes: &mut [u8], name: &[u8], addr: u64) {
    let read = |bytes: &[u8], at: usize, size: usize| {
        bytes[at..at + size]
            .iter()
            .rev()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte))
    };
    let headers = read(bytes, 0x28, 8) as usize;
    let entry = read(bytes, 0x3a, 2) as usize;
    let count = read(bytes, 0x3c, 2) as usize;
    let names = read(bytes, 0x3e, 2) as usize;
    let strings = read(bytes, headers + names * entry + 0x18, 8) as usize;
    for index in 0..count {
        let header = headers + index * entry;
        let start = strings + read(bytes, header, 4) as usize;
        if bytes[start..].starts_with(name) && bytes[start + name.len()] == 0 {
            bytes[header + 0x10..header + 0x18].copy_from_slice(&addr.to_le_bytes());
        }
    }
}

/// Code a damaged header places at the end of the address space loads,
/// lists and analyzes without overflowing an address.
#[test]
fn a_section_past_the_address_space_is_left_out() {
    for fixture in ["cpp_virtual_x64.elf", "l5_switch.elf", "cold_gcc"] {
        let mut bytes = std::fs::read(common::fixtures_dir().join(fixture)).expect("a fixture");
        place_section(&mut bytes, b".text", 0xffff_ffff_ffff_fff0);
        let path =
            std::env::temp_dir().join(format!("velk-placed-{}-{fixture}", std::process::id()));
        std::fs::write(&path, &bytes).expect("a scratch file");
        if let Ok(mut binary) = Binary::open(&path) {
            let addrs: Vec<u64> = binary.image().functions.keys().copied().collect();
            for addr in addrs {
                let _ = binary.decompile(addr, None, None);
            }
        }
        std::fs::remove_file(&path).ok();
    }
}

const MACHO_BASE: u64 = 0x1_0000_0000;
const MACHO_TEXT: u64 = 0x1000;
const MACHO_F: u64 = 0;
const MACHO_LOOP: u64 = 0x28;
const MACHO_LARGE: u64 = 0x30;
/// Past the 16 KB a size estimate between two unnamed starts may take.
const MACHO_LARGE_SIZE: u64 = 0x4008;
const MACHO_CALLER: u64 = MACHO_LARGE + MACHO_LARGE_SIZE;
const MACHO_STUBS: u64 = MACHO_CALLER + 0x24;
const MACHO_GOT: u64 = MACHO_STUBS + 0xc;

/// A linked arm64 Mach-O executable: `_f` calls `memset_pattern16` through
/// its stub, `_loop` is `b .`, `_large` is larger than 16 KB and returns 1
/// from its end, and `_caller` keeps its result in its frame.
fn macho_executable(import: &str) -> Vec<u8> {
    let at = |offset: u64| MACHO_BASE + MACHO_TEXT + offset;
    let bl = |from: u64, to: u64| {
        0x9400_0000 | ((at(to).wrapping_sub(at(from)) >> 2) as u32 & 0x03ff_ffff)
    };
    let mut code: Vec<u32> = vec![
        0xa9bf_7bfd, // stp x29, x30, [sp, #-0x10]!
        0x9100_03fd, // mov x29, sp
        0xd100_83ff, // sub sp, sp, #0x20
        0x9100_03e0, // mov x0, sp
        0xd280_0001, // mov x1, #0
        0xd280_0402, // mov x2, #0x20
        bl(MACHO_F + 0x18, MACHO_STUBS),
        0x9100_83ff, // add sp, sp, #0x20
        0xa8c1_7bfd, // ldp x29, x30, [sp], #0x10
        0xd65f_03c0, // ret
        0x1400_0000, // b .
        0xd503_201f, // nop
    ];
    code.push(0x1400_0000 | ((MACHO_LARGE_SIZE - 8) >> 2) as u32);
    code.resize(
        ((MACHO_LARGE + MACHO_LARGE_SIZE - 8) / 4) as usize,
        0xd503_201f,
    );
    code.extend([0x5280_0020, 0xd65f_03c0]); // mov w0, #1; ret
    code.extend([
        0xd100_83ff, // sub sp, sp, #0x20
        0xa901_7bfd, // stp x29, x30, [sp, #0x10]
        0x9100_43fd, // add x29, sp, #0x10
        bl(MACHO_CALLER + 0xc, MACHO_LARGE),
        0xb900_0fe0, // str w0, [sp, #0xc]
        0xb940_0fe0, // ldr w0, [sp, #0xc]
        0xa941_7bfd, // ldp x29, x30, [sp, #0x10]
        0x9100_83ff, // add sp, sp, #0x20
        0xd65f_03c0, // ret
    ]);
    let pages = ((at(MACHO_GOT) >> 12) - (at(MACHO_STUBS) >> 12)) as u32;
    code.extend([
        0x9000_0010 | (pages & 3) << 29 | (pages >> 2) << 5, // adrp x16, got
        0xf940_0210 | ((at(MACHO_GOT) & 0xfff) as u32 / 8) << 10, // ldr x16, [x16, got]
        0xd61f_0200,                                         // br x16
        0,
        0,
    ]);
    assert_eq!(code.len() as u64 * 4, MACHO_GOT + 8);

    let symbols: [(&str, u8, u8, u64); 5] = [
        (import, 0x01, 0, 0),
        ("_f", 0x0f, 1, at(MACHO_F)),
        ("_loop", 0x0f, 1, at(MACHO_LOOP)),
        ("_large", 0x0f, 1, at(MACHO_LARGE)),
        ("_caller", 0x0f, 1, at(MACHO_CALLER)),
    ];
    let symoff = MACHO_TEXT + MACHO_GOT + 8;
    let indirect = symoff + 16 * symbols.len() as u64;
    let stroff = indirect + 8;
    let mut strings = vec![0u8];
    let mut table = Vec::new();
    for (name, kind, section, value) in symbols {
        table.extend((strings.len() as u32).to_le_bytes());
        table.extend([kind, section]);
        table.extend(0u16.to_le_bytes());
        table.extend(value.to_le_bytes());
        strings.extend(name.as_bytes());
        strings.push(0);
    }

    let mut bytes = Vec::new();
    let words = |bytes: &mut Vec<u8>, values: &[u32]| {
        for value in values {
            bytes.extend(value.to_le_bytes());
        }
    };
    let name = |bytes: &mut Vec<u8>, text: &str| {
        let mut field = [0u8; 16];
        field[..text.len()].copy_from_slice(text.as_bytes());
        bytes.extend(field);
    };
    let segment = 72 + 3 * 80;
    // mach_header_64: arm64, MH_EXECUTE, three load commands.
    words(
        &mut bytes,
        &[0xfeed_facf, 0x0100_000c, 0, 2, 3, segment + 24 + 80, 0, 0],
    );
    // LC_SEGMENT_64 __TEXT over the whole file.
    words(&mut bytes, &[0x19, segment]);
    name(&mut bytes, "__TEXT");
    for value in [
        MACHO_BASE,
        stroff + strings.len() as u64,
        0,
        stroff + strings.len() as u64,
    ] {
        bytes.extend(value.to_le_bytes());
    }
    words(&mut bytes, &[5, 5, 3, 0]);
    // section_64: the code, the stubs (S_SYMBOL_STUBS, 12 bytes each, from
    // indirect entry 0) and the slots (S_NON_LAZY_SYMBOL_POINTERS, from 1).
    for (section, start, size, flags, first, stub) in [
        ("__text", 0, MACHO_STUBS, 0x8000_0400, 0, 0),
        ("__stubs", MACHO_STUBS, 0xc, 0x8000_0408, 0, 0xc),
        ("__got", MACHO_GOT, 8, 0x6, 1, 0),
    ] {
        name(&mut bytes, section);
        name(&mut bytes, "__TEXT");
        bytes.extend(at(start).to_le_bytes());
        bytes.extend(size.to_le_bytes());
        words(
            &mut bytes,
            &[(MACHO_TEXT + start) as u32, 2, 0, 0, flags, first, stub, 0],
        );
    }
    // LC_SYMTAB
    words(
        &mut bytes,
        &[
            2,
            24,
            symoff as u32,
            symbols.len() as u32,
            stroff as u32,
            strings.len() as u32,
        ],
    );
    // LC_DYSYMTAB: only the two indirect symbol entries.
    let mut dysymtab = [0u32; 20];
    dysymtab[..2].copy_from_slice(&[0xb, 80]);
    dysymtab[14..16].copy_from_slice(&[indirect as u32, 2]);
    words(&mut bytes, &dysymtab);
    bytes.resize(MACHO_TEXT as usize, 0);
    words(&mut bytes, &code);
    bytes.extend(table);
    words(&mut bytes, &[0, 0]);
    bytes.extend(strings);
    bytes
}

fn open_macho(test: &str) -> Binary {
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("macho-{}-{test}", std::process::id()));
    std::fs::write(&path, macho_executable("_memset_pattern16")).expect("a scratch file");
    let binary = Binary::open(&path).unwrap_or_else(|error| panic!("{error}"));
    std::fs::remove_file(&path).ok();
    binary
}

fn decompiled(binary: &mut Binary, name: &str) -> String {
    let addr = binary.find(name).expect("a function").addr;
    binary
        .decompile(addr, None, None)
        .unwrap_or_else(|error| panic!("{error}"))
}

/// Whether clang accepts the printed C with the declarations it relies on.
fn compiles(code: &str) -> bool {
    use std::io::Write as _;
    let mut compiler = std::process::Command::new("clang")
        .args(["-fsyntax-only", "-w", "-x", "c", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("clang");
    let prelude = "#include <stdint.h>\n\
                   void memset_pattern16(void *, const void *, unsigned long);\n\
                   int32_t large(void);\n";
    compiler
        .stdin
        .take()
        .expect("standard input")
        .write_all(format!("{prelude}{code}").as_bytes())
        .expect("writing to clang");
    let output = compiler.wait_with_output().expect("clang");
    if !output.status.success() {
        eprintln!("{code}\n{}", String::from_utf8_lossy(&output.stderr));
    }
    output.status.success()
}

/// Mach-O names its stubs and slots by the indirect symbol table, so a call
/// to an import that returns nothing is a statement.
#[test]
fn macho_stubs_name_their_imports() {
    let mut binary = open_macho("stubs");
    let image = binary.image();
    let stub = MACHO_BASE + MACHO_TEXT + MACHO_STUBS;
    let got = MACHO_BASE + MACHO_TEXT + MACHO_GOT;
    assert_eq!(
        image.functions[&stub].name.as_deref(),
        Some("_memset_pattern16")
    );
    assert_eq!(
        image.imports.get(&got).map(String::as_str),
        Some("_memset_pattern16")
    );
    let code = decompiled(&mut binary, "_f");
    assert!(code.contains("void f("), "{code}");
    assert!(code.contains("    memset_pattern16(local_"), "{code}");
    assert!(!code.contains("= memset_pattern16"), "{code}");
    assert!(!code.contains("return memset_pattern16"), "{code}");
    assert!(compiles(&code));
}

#[test]
fn c_symbol_prefixes_depend_on_the_binary_format() {
    let path = common::fixtures_dir().join("arm64_macho.o");
    let mut image = velk::loader::load(&path).unwrap();
    let address = image
        .functions
        .values()
        .find(|f| f.name.as_deref() == Some("_sum3"))
        .unwrap()
        .addr;
    image.imports.insert(0x10000, "_memcpy".to_owned());
    image.data_symbols.insert(0x20000, "_object".to_owned());
    for (format, prefix) in [
        (velk::loader::Format::MachO, ""),
        (velk::loader::Format::Elf, "_"),
        (velk::loader::Format::Pe, "_"),
    ] {
        image.format = format;
        let symbols = velk::render::callee_names(&image);
        assert_eq!(symbols.functions[&address], format!("{prefix}sum3"));
        assert_eq!(symbols.import_slots[&0x10000], format!("{prefix}memcpy"));
        assert_eq!(symbols.data[&0x20000], format!("{prefix}object"));
    }
}

#[test]
fn macho_library_calls_compile_with_c_headers() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("macho-c-names-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("calls");
    for call in ["memcpy", "memset"] {
        std::fs::write(&executable, macho_executable(&format!("_{call}"))).unwrap();
        let mut binary = Binary::open(&executable).unwrap();
        let name = "f";
        let address = binary.find(name).unwrap().addr;
        assert_eq!(binary.find(&format!("_{name}")).unwrap().addr, address);
        assert_eq!(
            binary.image().functions[&address].name.as_deref(),
            Some(format!("_{name}").as_str())
        );
        let code = decompiled(&mut binary, name);
        assert!(code.contains(&format!("{call}(")), "{code}");
        assert!(!code.contains(&format!("_{call}(")), "{code}");
        use std::io::Write as _;
        let mut compiler = std::process::Command::new("clang")
            .args([
                "-fsyntax-only",
                "-Werror=implicit-function-declaration",
                "-x",
                "c",
                "-",
            ])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(format!("#include <stdint.h>\n#include <string.h>\n{code}").as_bytes())
            .unwrap();
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{code}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// Reading x0 after a void import produces an explicit undefined value.
#[test]
fn void_stub_clobbered_register_is_undefined() {
    let mut bytes = macho_executable("_memset_pattern16");
    let offset = (MACHO_TEXT + MACHO_F + 0x1c) as usize;
    // str x0, [sp], #0x20: consume x0 and restore the stack pointer.
    bytes[offset..offset + 4].copy_from_slice(&0xf802_07e0u32.to_le_bytes());
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("macho-{}-void-read", std::process::id()));
    std::fs::write(&path, bytes).expect("a scratch file");
    let mut binary = Binary::open(&path).expect("a Mach-O executable");
    std::fs::remove_file(&path).ok();
    let code = decompiled(&mut binary, "_f");
    assert!(code.contains("0 /* undefined */"), "{code}");
    assert!(!code.contains("also returned by the call"), "{code}");
    assert!(!code.contains("= x0;"), "{code}");
    assert!(compiles(&code));
}

/// A branch to itself in a linked image is an endless loop.
#[test]
fn a_linked_branch_to_itself_loops() {
    let code = decompiled(&mut open_macho("loop"), "_loop");
    assert!(code.contains("for (;;) {"), "{code}");
    assert!(!code.contains("sub_<dynamic>"), "{code}");
    assert!(compiles(&code));
}

/// A function larger than 16 KB between two symbols is lifted whole, so
/// its callers see it return and settle their own frames.
#[test]
fn a_large_function_between_symbols_returns() {
    let mut binary = open_macho("large");
    let large = binary.find("_large").expect("a function");
    assert_eq!(large.size, Some(MACHO_LARGE_SIZE));
    let code = decompiled(&mut binary, "_large");
    assert!(code.contains("return 1;"), "{code}");
    let code = decompiled(&mut binary, "_caller");
    let statements: String = code
        .lines()
        .map(|line| line.split("/*").next().unwrap_or(line))
        .collect();
    assert!(
        !statements
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|word| word == "sp"),
        "{code}"
    );
    assert!(code.contains("large()"), "{code}");
    assert!(compiles(&code));
}
