use super::*;

#[test]
#[ignore = "rebuilds and syntax-checks crackme functions with and without stack protection"]
fn crackme_fixture_functions_compile() {
    let scratch = scratch_dir("crackme-syntax");
    let mut fixtures = Vec::new();
    for (name, flags) in [
        ("unprotected", vec!["-g0"]),
        ("protected", vec!["-g0", "-fstack-protector-all"]),
        ("debug-unprotected", vec![]),
        ("debug-protected", vec!["-fstack-protector-all"]),
    ] {
        let directory = scratch.join(name);
        let output = Command::new("bash")
            .arg(common::root().join("tests/scripts/make_crackme_fixtures.sh"))
            .arg(&directory)
            .args(flags)
            .output()
            .expect("fixture compiler starts");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for entry in std::fs::read_dir(directory).expect("fixture directory") {
            let path = entry.expect("fixture entry").path();
            if path.extension().is_some_and(|extension| extension == "elf") {
                fixtures.push(path);
            }
        }
    }
    fixtures.sort();
    let mut failed = 0;
    let mut total = 0;
    let mut combined_failed = 0;
    let mut binaries = 0;
    for fixture in fixtures {
        let mut binary = Binary::open(&fixture).expect("fixture opens");
        let functions: Vec<_> = binary.image().functions.values().cloned().collect();
        let mut combined = String::new();
        let mut providers = BTreeSet::new();
        for function in functions {
            let rendered = binary
                .decompile_with_dependencies(function.addr, None, None)
                .expect("function decompiles");
            providers.extend(
                rendered
                    .segment_bases
                    .iter()
                    .map(|dependency| dependency.provider.clone()),
            );
            let code = rendered.code;
            if !function.sources.contains(&velk::loader::NameSource::Plt) {
                combined.push_str(&code);
            }
            let path = scratch.join(format!("function-{total}.c"));
            std::fs::write(&path, &code).expect("saved C");
            let output = Command::new(compiler())
                .args(["-fwrapv", "-fno-strict-aliasing"])
                .args([
                    "-std=gnu11",
                    "-fno-builtin",
                    "-fsyntax-only",
                    "-ferror-limit=0",
                    "-Werror=implicit-function-declaration",
                    "-Werror=incompatible-pointer-types",
                ])
                .arg(&path)
                .output()
                .expect("compiler starts");
            if !output.status.success() {
                failed += 1;
                eprintln!(
                    "{} {}: {}",
                    fixture.display(),
                    function.name.as_deref().unwrap_or("unknown"),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            total += 1;
        }
        let code = velk::render::combine(&combined);
        let path = scratch.join(format!("binary-{binaries}.c"));
        std::fs::write(&path, &code).expect("saved combined C");
        let output = Command::new(compiler())
            .args(["-fwrapv", "-fno-strict-aliasing"])
            .args([
                "-std=gnu11",
                "-fno-builtin",
                "-fsyntax-only",
                "-ferror-limit=0",
                "-Werror=implicit-function-declaration",
                "-Werror=incompatible-pointer-types",
            ])
            .arg(&path)
            .output()
            .expect("compiler starts");
        if !output.status.success() {
            combined_failed += 1;
            eprintln!(
                "{}: {}",
                fixture.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            compare_reference(
                &mut binary,
                &fixture,
                &code,
                &providers,
                &scratch.join(format!("execution-{binaries}")),
            );
        }
        binaries += 1;
    }
    eprintln!(
        "{failed}/{total} functions failed; {combined_failed}/{binaries} combined binaries failed"
    );
    assert_eq!(failed, 0);
    assert_eq!(combined_failed, 0);
}

fn compare_reference(
    binary: &mut Binary,
    fixture: &Path,
    code: &str,
    providers: &BTreeSet<String>,
    directory: &Path,
) {
    std::fs::create_dir_all(directory).expect("execution directory");
    let stem = fixture
        .file_stem()
        .expect("fixture file name")
        .to_str()
        .expect("ASCII fixture name");
    let name = stem.rsplit('-').next().expect("source name in fixture");
    let source = common::root().join(format!("tests/data/crackmes/{name}.c"));
    let reference = directory.join("reference.o");
    let output = Command::new(compiler())
        .args([
            "-O2",
            "-fno-builtin",
            "-Dcheck=reference_check",
            "-Dmain=reference_main",
            "-Dsuccess=reference_success",
            "-Dfailure=reference_failure",
            "-c",
        ])
        .arg(source)
        .arg("-o")
        .arg(&reference)
        .output()
        .expect("reference compiler starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut bound = String::from(
        "#include <stdint.h>\n#ifdef __APPLE__\nvoid *stdin;\n#endif\nstatic uint64_t test_guard;\nstatic uint64_t test_segment[16];\n",
    );
    for provider in providers {
        writeln!(
            bound,
            "uint64_t {provider}(void) {{ return (uintptr_t)test_segment; }}"
        )
        .expect("writing to a String");
    }
    let mut objects = 0;
    for line in code.lines() {
        let Some((declaration, address)) = line.split_once("; /* address: 0x") else {
            writeln!(bound, "{line}").expect("writing to a String");
            continue;
        };
        let declaration = declaration
            .strip_prefix("extern ")
            .expect("external object declaration");
        let address = u64::from_str_radix(
            address
                .strip_suffix(" */")
                .expect("address comment terminator"),
            16,
        )
        .expect("hexadecimal object address");
        let (ty, name) = declaration.rsplit_once(' ').expect("object type and name");
        if name.starts_with("__stack_chk_guard_") {
            writeln!(bound, "{ty} {name} = (uintptr_t)&test_guard;").expect("writing to a String");
            continue;
        }
        let mut bytes = Vec::new();
        for offset in 0..256 {
            let Some(address) = address.checked_add(offset) else {
                break;
            };
            let Some(value) = binary.image().read_vaddr(address, 1) else {
                break;
            };
            bytes.push(value[0].to_string());
        }
        assert!(!bytes.is_empty(), "global bytes at {address:x}");
        writeln!(
            bound,
            "_Alignas(16) static uint8_t object_{objects}[] = {{{}}};",
            bytes.join(",")
        )
        .expect("writing to a String");
        if let Some(name) = name.strip_suffix("[]") {
            writeln!(bound, "#define {name} (({ty} *)object_{objects})")
                .expect("writing to a String");
        } else {
            writeln!(bound, "#define {name} (*({ty} *)object_{objects})")
                .expect("writing to a String");
        }
        objects += 1;
    }
    let mut address_objects = String::new();
    let marker = "(const void *)0x";
    let mut search = 0;
    while let Some(relative) = bound[search..].find(marker) {
        let start = search + relative;
        let digits = start + marker.len();
        let end = bound[digits..]
            .find(|character: char| !character.is_ascii_hexdigit())
            .map_or(bound.len(), |offset| digits + offset);
        let address = u64::from_str_radix(&bound[digits..end], 16).expect("address literal");
        let mut bytes = Vec::new();
        for offset in 0..256 {
            let Some(address) = address.checked_add(offset) else {
                break;
            };
            let Some(value) = binary.image().read_vaddr(address, 1) else {
                break;
            };
            bytes.push(value[0].to_string());
        }
        assert!(!bytes.is_empty(), "literal bytes at {address:x}");
        let name = format!("literal_{objects}");
        writeln!(
            address_objects,
            "static uint8_t {name}[] = {{{}}};",
            bytes.join(",")
        )
        .expect("writing to a String");
        bound.replace_range(start..end, &name);
        search = start + name.len();
        objects += 1;
    }
    bound = format!("#include <stdint.h>\n{address_objects}{bound}");
    let check = binary.find("check").expect("check function").addr;
    let analysis = binary.analysis(check, None).expect("check analysis");
    let argument = if analysis.ir.params[0].ty.is_pointer() {
        "(void *)input"
    } else {
        "(uintptr_t)input"
    };
    bound = replace_c_identifier(&bound, "main", "printed_main");
    writeln!(bound, "int reference_check(const unsigned char *);\nint main(void) {{\nunsigned char input[32] = {{0}};\nconst char examples[][5] = {{\"FLAG\", \"face\", \"FACE\", \"\", \"0000\", \"FFFF\"}};\nfor (unsigned trial=0; trial<1030; ++trial) {{\nfor (unsigned i=0; i<4; ++i) input[i] = trial < 6 ? (unsigned char)examples[trial][i] : (uint8_t)((trial * 0x1234567U) >> (i*8));\nif ((uint32_t)check({argument}) != (uint32_t)reference_check(input)) return 1;\n}} return 0; }}").expect("writing to a String");
    let path = directory.join("execution.c");
    std::fs::write(&path, bound).expect("execution source");
    for level in LEVELS {
        let executable = directory.join(format!("execution{level}"));
        let output = Command::new(compiler())
            .args(["-fwrapv", "-fno-strict-aliasing"])
            .arg(level)
            .arg("-Werror=incompatible-pointer-types")
            .arg(&path)
            .arg(&reference)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("execution compiler starts");
        assert!(
            output.status.success(),
            "{}: {}",
            fixture.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(executable)
                .status()
                .expect("execution starts")
                .success(),
            "{} {level}",
            fixture.display()
        );
    }
}
