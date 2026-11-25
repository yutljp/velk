//! Exercises bounded ELF and PE unpacking through the CLI, script API, MCP, and serve API.

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::loader::OpenOptions;
use velk::service::Binary;
use velk::unpack;

fn directory(name: &str) -> PathBuf {
    let directory = common::root()
        .join("target/unpack-tests")
        .join(std::process::id().to_string())
        .join(name);
    fs::create_dir_all(&directory).expect("creating unpack test directory");
    directory
}

fn compile(source: &Path, target: &str, entry: &str, output: &Path) {
    compile_with_args(source, target, entry, output, &[]);
}

fn compile_with_args(
    source: &Path,
    target: &str,
    entry: &str,
    output: &Path,
    extra_args: &[String],
) {
    let mut command = Command::new("clang");
    command.args([
        "-target",
        target,
        "-fuse-ld=lld",
        "-nostdlib",
        "-static",
        "-Wl,--build-id=none",
    ]);
    command.arg(format!("-Wl,-e,{entry}"));
    command.args(extra_args);
    let result = command
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("running clang and ld.lld");
    assert!(result.status.success(), "{result:?}");
}

fn fixture(name: &str) -> PathBuf {
    common::root().join("tests/unpack/fixtures").join(name)
}

fn unpack_options(options: unpack::Options) -> OpenOptions {
    OpenOptions {
        unpack: Some(options),
        ..OpenOptions::default()
    }
}

#[test]
fn encrypted_entry_code_is_recovered_for_each_linux_architecture() {
    let directory = directory("entry");
    for (name, target, expected) in [
        (
            "x86_64",
            "x86_64-unknown-linux-gnu",
            vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xb8, 42, 0, 0, 0, 0xc3],
        ),
        (
            "i386",
            "i686-unknown-linux-gnu",
            vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xb8, 42, 0, 0, 0, 0xc3],
        ),
        (
            "aarch64",
            "aarch64-unknown-linux-gnu",
            vec![
                0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03,
                0x5f, 0xd6,
            ],
        ),
    ] {
        let input = directory.join(format!("{name}.elf"));
        let reference = directory.join(format!("{name}-reference.elf"));
        compile(
            &fixture(&format!("unpack_{name}.S")),
            target,
            "_start",
            &input,
        );
        compile(
            &fixture(&format!("unpack_reference_{name}.S")),
            target,
            "target",
            &reference,
        );

        let original = Binary::open(&input).expect("opening packed fixture");
        let target_address = original.find("target").expect("finding target symbol").addr;
        let reference = Binary::open(&reference).expect("opening reference fixture");
        let reference_address = reference
            .find("target")
            .expect("finding reference symbol")
            .addr;
        let original_function = reference
            .image()
            .read_vaddr(reference_address, expected.len() as u64)
            .expect("reading reference function");
        assert_eq!(original_function, expected, "{name}");

        let mut binary =
            Binary::open_input(&input, None, &unpack_options(unpack::Options::default()))
                .expect("unpacking fixture");
        let report = binary.image().unpacking.as_ref().expect("unpack report");
        assert_eq!(report.status, "unpacked", "{name}: {report:?}");
        assert_eq!(report.stop_reason, "written code reached", "{name}");
        assert_eq!(
            report.new_entry.as_deref(),
            Some(velk::addr::format(target_address).as_str())
        );
        assert!(report.steps > 0, "{name}");
        assert!(!report.mapped_regions.is_empty(), "{name}");
        assert!(
            report.written_regions.iter().any(|region| {
                region.address == velk::addr::format(target_address)
                    && region.size == expected.len() as u64
            }),
            "{name}: {report:?}"
        );
        assert!(
            report.executed_regions.iter().any(|region| {
                target_address >= velk::addr::parse(&region.address).unwrap_or(u64::MAX)
                    && target_address
                        .saturating_sub(velk::addr::parse(&region.address).unwrap_or(u64::MAX))
                        < region.size
            }),
            "{name}: {report:?}"
        );
        let recovered = binary
            .image()
            .read_vaddr(target_address, expected.len() as u64)
            .expect("reading recovered function");
        assert_eq!(recovered, expected, "{name}");

        let printed = binary
            .decompile(target_address, None, None)
            .expect("decompiling recovered function");
        assert!(printed.contains("return 42"), "{name}: {printed}");
        let executable = directory.join(format!("{name}-printed-c"));
        let source = format!("{printed}\nint main(void) {{ return target() != 42; }}\n");
        let compiled = common::compiler::run(
            Command::new("clang")
                .args(["-x", "c", "-o"])
                .arg(&executable)
                .arg("-"),
            Some(&source),
        );
        assert!(compiled.status.success(), "{name}: {compiled:?}\n{printed}");
        assert!(
            Command::new(&executable).status().unwrap().success(),
            "{name}"
        );

        let dumped = directory.join(format!("{name}-unpacked.elf"));
        binary
            .image()
            .save_unpacked(&dumped)
            .expect("saving recovered ELF");
        let dumped_bytes = fs::read(&dumped).expect("reading saved ELF");
        let dumped_file = object::File::parse(dumped_bytes.as_slice()).expect("parsing saved ELF");
        use object::{Object as _, ObjectSegment as _};
        assert!(
            dumped_file
                .segments()
                .any(|segment| segment.address() <= target_address
                    && target_address.saturating_sub(segment.address()) < segment.size()),
            "{name}: saved ELF has no PT_LOAD for the recovered function"
        );
        let mut reopened = Binary::open(&dumped).expect("opening recovered ELF");
        assert!(reopened.find("target").is_ok(), "{name}");
        assert!(
            reopened
                .decompile(target_address, None, None)
                .expect("decompiling saved function")
                .contains("return 42"),
            "{name}"
        );
    }
}

#[test]
fn rc4_lz_and_two_stage_stubs_are_recovered_for_each_linux_architecture() {
    let directory = directory("algorithms");
    for (name, target) in [
        ("x86_64", "x86_64-unknown-linux-gnu"),
        ("i386", "i686-unknown-linux-gnu"),
        ("aarch64", "aarch64-unknown-linux-gnu"),
    ] {
        let reference_path = directory.join(format!("{name}-reference.elf"));
        compile(
            &fixture(&format!("unpack_reference_{name}.S")),
            target,
            "target",
            &reference_path,
        );
        let reference = Binary::open(&reference_path).expect("opening reference fixture");
        let reference_address = reference.find("target").expect("finding target").addr;
        let expected = reference
            .image()
            .read_vaddr(reference_address, if name == "aarch64" { 16 } else { 12 })
            .expect("reading reference function");

        for (algorithm, mode) in [("rc4", 1), ("lz", 2), ("two-stage", 3)] {
            let input = directory.join(format!("{name}-{algorithm}.elf"));
            let mode_arg = format!("-DUNPACK_MODE={mode}");
            let extra_args = vec![
                "-O1".to_owned(),
                "-fno-builtin".to_owned(),
                "-fno-stack-protector".to_owned(),
                "-fno-pie".to_owned(),
                mode_arg,
            ];
            compile_with_args(
                &fixture("unpack_algorithms.c"),
                target,
                "_start",
                &input,
                &extra_args,
            );
            let original = Binary::open(&input).expect("opening algorithm fixture");
            let target_address = original.find("target").expect("finding target").addr;
            let mut binary =
                Binary::open_input(&input, None, &unpack_options(unpack::Options::default()))
                    .expect("unpacking algorithm fixture");
            let report = binary.image().unpacking.as_ref().expect("unpack report");
            assert_eq!(report.status, "unpacked", "{name} {algorithm}: {report:?}");
            let recovered = binary
                .image()
                .read_vaddr(target_address, expected.len() as u64)
                .expect("reading recovered function");
            assert_eq!(recovered, expected, "{name} {algorithm}");
            assert!(
                binary
                    .decompile(target_address, None, None)
                    .expect("decompiling recovered function")
                    .contains("return 42"),
                "{name} {algorithm}"
            );
        }
    }
}

/// A Windows program for `architecture` whose start is `start`, a fixture
/// that restores the section `.payload` and runs it, with that section
/// packed as its start restores it.
fn packed_pe(directory: &Path, architecture: &str, start: &str) -> PathBuf {
    let (machine, target) = match architecture {
        "x86_64" => ("x64", "x86_64-pc-windows-msvc"),
        _ => ("x86", "i686-pc-windows-msvc"),
    };
    let run = |command: &mut Command| {
        let result = command.output().expect("running the Windows toolchain");
        assert!(result.status.success(), "{command:?}: {result:?}");
    };
    // The functions the start imports; 32-bit names carry the bytes of
    // their arguments.
    let mut definition = String::from("LIBRARY kernel32.dll\nEXPORTS\n");
    for (name, bytes) in [
        ("LoadLibraryA", 4),
        ("GetProcAddress", 8),
        ("VirtualProtect", 16),
        ("VirtualAlloc", 16),
        ("GetTickCount", 0),
    ] {
        if machine == "x86" {
            definition.push_str(&format!("_{name}@{bytes} EXPORTAS {name}\n"));
        } else {
            definition.push_str(&format!("{name}\n"));
        }
    }
    let file = |name: &str| directory.join(format!("{architecture}-{name}"));
    fs::write(file("kernel32.def"), definition).expect("writing the import definitions");
    run(Command::new("lld-link")
        .arg("/lib")
        .arg(format!("/def:{}", file("kernel32.def").display()))
        .arg(format!("/machine:{machine}"))
        .arg(format!("/out:{}", file("kernel32.lib").display())));
    for (source, object) in [(start, "start.obj"), ("unpack_pe_payload.S", "payload.obj")] {
        run(Command::new("clang")
            .arg(format!("--target={target}"))
            .args(["-O1", "-fno-builtin", "-fno-stack-protector", "-c"])
            .arg(fixture(source))
            .arg("-o")
            .arg(file(object)));
    }
    let linked = file("linked.exe");
    run(Command::new("lld-link")
        .args([
            "/entry:entry",
            "/subsystem:console",
            "/nodefaultlib",
            "/fixed",
            "/Brepro",
            "/safeseh:no",
        ])
        .arg(format!("/out:{}", linked.display()))
        .arg(file("start.obj"))
        .arg(file("payload.obj"))
        .arg(file("kernel32.lib")));
    let mut bytes = fs::read(&linked).expect("reading the linked program");
    let word = |bytes: &[u8], at: usize, width: usize| {
        let mut value = [0u8; 8];
        value[..width].copy_from_slice(&bytes[at..at + width]);
        u64::from_le_bytes(value) as usize
    };
    let header = word(&bytes, 0x3c, 4);
    let table = header + 24 + word(&bytes, header + 20, 2);
    let mut packed = false;
    for index in 0..word(&bytes, header + 6, 2) {
        let section = table + index * 40;
        if &bytes[section..section + 8] != b".payload" {
            continue;
        }
        let size = word(&bytes, section + 8, 4).min(word(&bytes, section + 16, 4));
        let offset = word(&bytes, section + 20, 4);
        for byte in &mut bytes[offset..offset + size] {
            *byte ^= 0x5a;
        }
        packed = true;
    }
    assert!(packed, "{architecture}: no section to pack");
    let output = file("packed.exe");
    fs::write(&output, bytes).expect("writing the packed program");
    output
}

#[test]
fn windows_programs_are_recovered_with_the_imports_they_resolve() {
    use object::{Object as _, ObjectSection as _};

    let directory = directory("windows");
    for architecture in ["x86_64", "i386"] {
        let input = packed_pe(&directory, architecture, "unpack_pe_stub.c");
        let packed = Binary::open(&input).expect("opening the packed program");
        let payload = packed
            .image()
            .sections
            .iter()
            .find(|section| section.name == ".payload")
            .expect("the packed section")
            .vaddr;
        // Packed, the section does not read as the function it holds.
        assert_ne!(
            packed.image().read_vaddr(payload, 1),
            Some(&[if architecture == "x86_64" { 0x48 } else { 0xff }][..]),
            "{architecture}"
        );

        let mut binary =
            Binary::open_input(&input, None, &unpack_options(unpack::Options::default()))
                .expect("unpacking the program");
        let report = binary.image().unpacking.as_ref().expect("unpack report");
        assert_eq!(report.status, "unpacked", "{architecture}: {report:?}");
        assert_eq!(report.stop_reason, "written code reached", "{architecture}");
        assert_eq!(
            report.new_entry.as_deref(),
            Some(velk::addr::format(payload).as_str()),
            "{architecture}"
        );
        assert!(
            report
                .written_regions
                .iter()
                .any(|region| region.address == velk::addr::format(payload)),
            "{architecture}: {report:?}"
        );
        // The function the program resolved by name is called by name.
        let printed = binary
            .decompile(payload, None, None)
            .expect("decompiling the recovered function");
        assert!(
            printed.contains("GetTickCount()") && printed.contains("+ 42"),
            "{architecture}: {printed}"
        );

        let dumped = directory.join(format!("{architecture}-unpacked.exe"));
        binary
            .image()
            .save_unpacked(&dumped)
            .expect("saving the recovered program");
        let dumped_bytes = fs::read(&dumped).expect("reading the saved program");
        let file = object::File::parse(dumped_bytes.as_slice()).expect("parsing the saved program");
        assert_eq!(file.entry(), payload, "{architecture}");
        assert!(
            file.sections()
                .any(|section| section.name() == Ok(".idata")),
            "{architecture}"
        );
        let imports: Vec<(String, String)> = file
            .imports()
            .expect("reading the saved imports")
            .map(|import| {
                let import = import.expect("reading a saved import");
                let name = match import.name() {
                    object::NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
                    object::NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                (String::from_utf8_lossy(import.library()).into_owned(), name)
            })
            .collect();
        // The imports of the start, then those it resolved, in the order
        // of their slots.
        let expected = [
            ("kernel32.dll", "LoadLibraryA"),
            ("kernel32.dll", "GetProcAddress"),
            ("kernel32.dll", "VirtualProtect"),
            ("user32.dll", "MessageBoxA"),
            ("user32.dll", "GetDesktopWindow"),
            ("kernel32.dll", "GetTickCount"),
        ];
        for (library, name) in expected {
            assert!(
                imports
                    .iter()
                    .any(|(found, function)| found == library && function == name),
                "{architecture}: {library}!{name} in {imports:?}"
            );
        }
        let resolved: Vec<&str> = imports
            .iter()
            .rev()
            .take(3)
            .rev()
            .map(|(_, name)| name.as_str())
            .collect();
        assert_eq!(
            resolved,
            ["MessageBoxA", "GetDesktopWindow", "GetTickCount"],
            "{architecture}"
        );
        let mut reopened = Binary::open(&dumped).expect("opening the saved program");
        assert!(
            reopened
                .decompile(payload, None, None)
                .expect("decompiling the saved function")
                .contains("GetTickCount()"),
            "{architecture}"
        );
    }
}

#[test]
fn code_a_windows_program_runs_from_allocated_memory_is_followed() {
    let directory = directory("windows-stage");
    for architecture in ["x86_64", "i386"] {
        let input = packed_pe(&directory, architecture, "unpack_pe_stage.S");
        let payload = Binary::open(&input)
            .expect("opening the packed program")
            .image()
            .sections
            .iter()
            .find(|section| section.name == ".payload")
            .expect("the packed section")
            .vaddr;
        let mut binary =
            Binary::open_input(&input, None, &unpack_options(unpack::Options::default()))
                .expect("unpacking through the copied code");
        let report = binary.image().unpacking.as_ref().expect("report");
        assert_eq!(
            report.stop_reason, "written code reached",
            "{architecture}: {report:?}"
        );
        assert_eq!(
            report.new_entry.as_deref(),
            Some(velk::addr::format(payload).as_str()),
            "{architecture}: {report:?}"
        );
        // The copy in allocated memory is no part of the recovered program.
        assert!(
            report.mapped_regions.iter().all(|region| {
                velk::addr::parse(&region.address)
                    .is_some_and(|address| binary.image().section_at(address).is_some())
            }),
            "{architecture}: {report:?}"
        );
        let printed = binary
            .decompile(payload, None, None)
            .expect("decompiling the recovered function");
        assert!(printed.contains("+ 42"), "{architecture}: {printed}");
    }
}

/// A program that carries `unpack_pe_inner.c`, linked on its own, in its
/// data and maps it into memory it allocates; with it, that file.
fn carrying_pe(directory: &Path, architecture: &str) -> (PathBuf, PathBuf) {
    // The import library of the other fixtures serves both programs.
    let _ = packed_pe(directory, architecture, "unpack_pe_stage.S");
    let (target, prefix) = match architecture {
        "x86_64" => ("x86_64-pc-windows-msvc", ""),
        _ => ("i686-pc-windows-msvc", "_"),
    };
    let run = |command: &mut Command| {
        let result = command.output().expect("running the Windows toolchain");
        assert!(result.status.success(), "{command:?}: {result:?}");
    };
    let file = |name: &str| directory.join(format!("{architecture}-{name}"));
    let compile = |source: &Path, object: &str| {
        run(Command::new("clang")
            .arg(format!("--target={target}"))
            .args(["-O1", "-fno-builtin", "-fno-stack-protector", "-c"])
            .arg(source)
            .arg("-o")
            .arg(file(object)));
    };
    let link = |entry: &str, objects: &[&str], output: &Path, fixed: bool| {
        let mut command = Command::new("lld-link");
        command.arg(format!("/entry:{entry}"));
        command.args([
            "/subsystem:console",
            "/nodefaultlib",
            "/Brepro",
            "/safeseh:no",
            if fixed { "/fixed" } else { "/dynamicbase" },
        ]);
        command.arg(format!("/out:{}", output.display()));
        for object in objects {
            command.arg(file(object));
        }
        run(command.arg(file("kernel32.lib")));
    };
    compile(&fixture("unpack_pe_inner.c"), "inner.obj");
    let inner = file("inner.exe");
    link("inner", &["inner.obj"], &inner, false);
    let embedded = file("embedded.S");
    fs::write(
        &embedded,
        format!(
            ".section .rdata,\"dr\"\n.globl {prefix}inner_image\n{prefix}inner_image:\n.incbin \"{}\"\n",
            inner.display()
        ),
    )
    .expect("writing the carried program");
    compile(&embedded, "embedded.obj");
    compile(&fixture("unpack_pe_map.c"), "map.obj");
    let output = file("carrying.exe");
    link("entry", &["map.obj", "embedded.obj"], &output, true);
    (output, inner)
}

#[test]
fn a_program_mapped_into_allocated_memory_is_recovered() {
    use object::{Object as _, ObjectSection as _};

    let directory = directory("windows-mapped");
    for architecture in ["x86_64", "i386"] {
        let (input, inner) = carrying_pe(&directory, architecture);
        let inner_bytes = fs::read(&inner).expect("reading the carried program");
        let carried = object::File::parse(inner_bytes.as_slice()).expect("the carried program");
        let entry = carried.entry() - carried.relative_address_base();

        let mut binary =
            Binary::open_input(&input, None, &unpack_options(unpack::Options::default()))
                .expect("unpacking the carried program");
        let report = binary.image().unpacking.clone().expect("report");
        assert_eq!(report.status, "unpacked", "{architecture}: {report:?}");
        assert_eq!(report.stop_reason, "written code reached", "{architecture}");
        let reached = report
            .new_entry
            .as_deref()
            .and_then(velk::addr::parse)
            .expect("the entry reached");
        // One region: the program where it was mapped, away from where
        // its file asks to be loaded.
        let [region] = report.mapped_regions.as_slice() else {
            panic!("{architecture}: {report:?}");
        };
        let base = velk::addr::parse(&region.address).expect("the base");
        assert_ne!(base, carried.relative_address_base(), "{architecture}");
        assert_eq!(reached, base + entry, "{architecture}: {report:?}");
        let printed = binary
            .decompile(reached, None, None)
            .expect("decompiling the recovered function");
        assert!(
            printed.contains("GetTickCount()"),
            "{architecture}: {printed}"
        );

        let dumped = directory.join(format!("{architecture}-recovered.exe"));
        binary
            .image()
            .save_unpacked(&dumped)
            .expect("saving the recovered program");
        let dumped_bytes = fs::read(&dumped).expect("reading the saved program");
        let file = object::File::parse(dumped_bytes.as_slice()).expect("parsing the saved program");
        assert_eq!(file.entry(), reached, "{architecture}");
        assert_eq!(file.relative_address_base(), base, "{architecture}");
        let names: Vec<String> = carried
            .sections()
            .map(|section| section.name().expect("a name").to_owned())
            .collect();
        for name in &names {
            assert!(
                file.section_by_name(name).is_some(),
                "{architecture}: {name}"
            );
        }
        // The import the carrying program resolved is the one the file
        // lists, once.
        let imports: Vec<(String, String)> = file
            .imports()
            .expect("reading the saved imports")
            .map(|import| {
                let import = import.expect("reading a saved import");
                let name = match import.name() {
                    object::NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
                    object::NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                (String::from_utf8_lossy(import.library()).into_owned(), name)
            })
            .collect();
        assert_eq!(
            imports,
            [("kernel32.dll".to_owned(), "GetTickCount".to_owned())],
            "{architecture}"
        );
        let mut reopened = Binary::open(&dumped).expect("opening the saved program");
        assert!(
            reopened
                .decompile(reached, None, None)
                .expect("decompiling the saved function")
                .contains("GetTickCount()"),
            "{architecture}"
        );
    }
}

#[test]
fn user_stop_and_non_packed_bounds_are_reported() {
    let directory = directory("bounds");
    let input = directory.join("x86_64.elf");
    compile(
        &fixture("unpack_x86_64.S"),
        "x86_64-unknown-linux-gnu",
        "_start",
        &input,
    );
    let original = Binary::open(&input).expect("opening fixture");
    let target = original.find("target").expect("finding target").addr;
    let options = unpack::Options {
        stop_address: Some(velk::addr::format(target)),
        ..unpack::Options::default()
    };
    let binary = Binary::open_input(&input, None, &unpack_options(options)).expect("stop address");
    let report = binary.image().unpacking.as_ref().expect("report");
    assert_eq!(report.status, "unpacked");
    assert_eq!(report.stop_reason, "requested address");
    assert_eq!(
        report.new_entry.as_deref(),
        Some(velk::addr::format(target).as_str())
    );

    let mut sectionless_bytes = fs::read(&input).expect("reading fixture ELF");
    sectionless_bytes
        .get_mut(40..48)
        .expect("ELF64 section table offset")
        .fill(0);
    sectionless_bytes
        .get_mut(60..64)
        .expect("ELF64 section table counts")
        .fill(0);
    let sectionless = directory.join("sectionless.elf");
    fs::write(&sectionless, sectionless_bytes).expect("writing sectionless ELF");
    let binary = Binary::open_input(
        &sectionless,
        None,
        &unpack_options(unpack::Options::default()),
    )
    .expect("unpacking ELF without section headers");
    let report = binary.image().unpacking.as_ref().expect("report");
    assert_eq!(report.status, "unpacked", "{report:?}");
    assert_eq!(report.stop_reason, "written code reached");
    assert_eq!(
        binary
            .image()
            .read_vaddr(target, 12)
            .expect("reading recovered sectionless function"),
        [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xb8, 42, 0, 0, 0, 0xc3]
    );

    let plain = directory.join("plain.elf");
    compile(
        &fixture("unpack_plain_x86_64.S"),
        "x86_64-unknown-linux-gnu",
        "_start",
        &plain,
    );
    let options = unpack::Options {
        step_limit: 8,
        ..unpack::Options::default()
    };
    let binary = Binary::open_input(&plain, None, &unpack_options(options)).expect("bounded run");
    let report = binary.image().unpacking.as_ref().expect("report");
    assert_eq!(report.status, "no unpacking observed");
    assert_eq!(report.stop_reason, "step limit");
    assert!(!report.unpacked);
    assert!(
        binary
            .image()
            .save_unpacked(&directory.join("not-unpacked.elf"))
            .is_err()
    );
}

#[test]
fn written_heap_code_is_included_in_the_rebuilt_elf() {
    let directory = directory("heap");
    let input = directory.join("heap.elf");
    compile(
        &fixture("unpack_heap_x86_64.S"),
        "x86_64-unknown-linux-gnu",
        "_start",
        &input,
    );
    let binary = Binary::open_input(&input, None, &unpack_options(unpack::Options::default()))
        .expect("unpacking heap code");
    let report = binary.image().unpacking.as_ref().expect("unpack report");
    assert_eq!(report.status, "unpacked", "{report:?}");
    assert_eq!(report.new_entry.as_deref(), Some("0x10000000"));
    assert!(
        report
            .written_regions
            .iter()
            .any(|region| { region.address == "0x10000000" && region.size == 12 })
    );
    assert!(
        report
            .mapped_regions
            .iter()
            .any(|region| { region.address == "0x10000000" && region.size == 4096 })
    );
    assert!(
        report
            .executed_regions
            .iter()
            .any(|region| { region.address == "0x10000000" && region.size == 4096 })
    );

    let saved = directory.join("heap-unpacked.elf");
    binary
        .image()
        .save_unpacked(&saved)
        .expect("saving heap ELF");
    let mut reopened = Binary::open(&saved).expect("opening heap ELF");
    assert_eq!(
        reopened
            .image()
            .read_vaddr(0x10000000, 12)
            .expect("reading decoded heap code"),
        [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xb8, 42, 0, 0, 0, 0xc3]
    );
    assert!(
        reopened
            .image()
            .section_at(0x10000000)
            .is_some_and(|section| section.executable)
    );
    assert!(
        reopened
            .decompile(0x10000000, None, None)
            .expect("decompiling heap code")
            .contains("return 42")
    );

    let options = unpack::Options {
        stop_address: Some("0x10000000".to_owned()),
        ..unpack::Options::default()
    };
    let stopped = Binary::open_input(&input, None, &unpack_options(options))
        .expect("stopping at a mapped heap address");
    let report = stopped.image().unpacking.as_ref().expect("unpack report");
    assert_eq!(report.stop_reason, "requested address");
    assert_eq!(report.new_entry.as_deref(), Some("0x10000000"));
}

#[test]
fn cli_script_mcp_and_serve_return_unpack_reports() {
    let directory = directory("interfaces");
    let input = directory.join("program.elf");
    compile(
        &fixture("unpack_x86_64.S"),
        "x86_64-unknown-linux-gnu",
        "_start",
        &input,
    );
    let path = serde_json::to_string(&input).expect("JSON path");
    let opening = format!("const b=velk.open({path},{{cache:false,unpack:{{stepLimit:1000}}}})");
    let script = format!("{opening}; JSON.stringify(b.unpacking)");

    let command = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--unpack", "-D"])
        .arg(&input)
        .arg("target")
        .output()
        .expect("running CLI");
    assert!(command.status.success(), "{command:?}");
    assert!(String::from_utf8_lossy(&command.stdout).contains("return 42"));
    assert!(String::from_utf8_lossy(&command.stderr).contains("wrote 12 bytes"));

    let target = Binary::open(&input)
        .expect("opening CLI stop-address fixture")
        .find("target")
        .expect("finding CLI stop address")
        .addr;
    let stop_address = velk::addr::format(target);
    let command = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--unpack", "--unpack-at"])
        .arg(stop_address)
        .args(["-D"])
        .arg(&input)
        .arg("target")
        .output()
        .expect("running CLI with a stop address");
    assert!(command.status.success(), "{command:?}");
    assert!(String::from_utf8_lossy(&command.stderr).contains("stop reason: requested address"));

    for operation in ["--iocs", "--strings"] {
        let command = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--unpack")
            .arg(operation)
            .arg(&input)
            .output()
            .expect("running analysis on unpacked image");
        assert!(command.status.success(), "{command:?}");
        assert!(String::from_utf8_lossy(&command.stderr).contains("unpacking unpacked"));
    }

    let saved = directory.join("cli-unpacked.elf");
    let command = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--unpack", "--save-unpacked"])
        .arg(&saved)
        .arg("--sections")
        .arg(&input)
        .output()
        .expect("saving unpacked ELF through CLI");
    assert!(command.status.success(), "{command:?}");
    assert!(saved.is_file());
    assert!(
        Binary::open(&saved)
            .expect("opening CLI-saved ELF")
            .find("target")
            .is_ok()
    );

    let script_path = directory.join("analysis.js");
    fs::write(
        &script_path,
        format!("{opening}; console.log(JSON.stringify(b.unpacking))"),
    )
    .expect("writing script");
    let command = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--run")
        .arg(&script_path)
        .output()
        .expect("running JavaScript API");
    assert!(command.status.success(), "{command:?}");
    let script_report: Value = serde_json::from_slice(&command.stdout).expect("script JSON");
    assert_eq!(script_report["status"], "unpacked");
    assert_eq!(script_report["stopReason"], "written code reached");

    let mut server = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("starting serve API");
    let mut server_input = server.stdin.take().expect("serve stdin");
    let mut server_output = BufReader::new(server.stdout.take().expect("serve stdout"));
    writeln!(server_input, "{}", json!({"id": 1, "code": script})).expect("serve request");
    server_input.flush().expect("flush serve request");
    let mut line = String::new();
    server_output.read_line(&mut line).expect("serve reply");
    let serve_reply: Value = serde_json::from_str(&line).expect("serve JSON");
    let serve_report: Value =
        serde_json::from_str(serve_reply["result"].as_str().expect("serve report text"))
            .expect("serve report JSON");
    assert_eq!(serve_report["status"], "unpacked");
    drop(server_input);
    assert!(server.wait().expect("serve exit").success());

    let mut mcp = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("starting MCP API");
    writeln!(
        mcp.stdin.take().expect("MCP stdin"),
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":script}}})
    )
    .expect("MCP request");
    let response: Value =
        serde_json::from_slice(&mcp.wait_with_output().expect("MCP reply").stdout)
            .expect("MCP JSON");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("MCP report text");
    let mcp_report: Value = serde_json::from_str(text).expect("MCP report JSON");
    assert_eq!(mcp_report["status"], "unpacked");
    assert_eq!(mcp_report["stopReason"], "written code reached");
}
