mod common;

use velk::loader::NameSource;
use velk::service::Binary;

#[test]
fn objc_methods_and_selectors() {
    for arch in ["arm64", "x86_64"] {
        for level in ["O0", "O2"] {
            let mut send_address = None;
            for suffix in ["", "_stripped"] {
                let fixture = format!("objc_{arch}_{level}{suffix}");
                let mut binary = Binary::open(&common::fixtures_dir().join(&fixture)).unwrap();
                for name in [
                    "-[Counter add:with:]",
                    "+[Counter answer]",
                    "-[Counter value]",
                    "-[Counter setValue:]",
                    "-[Counter twice:]",
                ] {
                    let method = binary
                        .image()
                        .functions
                        .values()
                        .find(|function| {
                            function.name.as_deref() == Some(name)
                                || function.aliases.iter().any(|alias| alias == name)
                        })
                        .unwrap_or_else(|| panic!("{fixture}: {name}"));
                    assert!(
                        method.sources.contains(&NameSource::Objc),
                        "{fixture}: {name}"
                    );
                }
                assert!(
                    binary
                        .image()
                        .objc_selectors
                        .values()
                        .any(|selector| selector == "add:with:")
                );
                {
                    if suffix.is_empty() {
                        send_address = Some(binary.find("send_value").unwrap().addr);
                    }
                    let address = send_address.unwrap();
                    let code = binary.decompile(address, None, None).unwrap();
                    assert!(code.contains("@selector(add:with:)"), "{fixture}: {code}");
                    let mut symbols = velk::render::callee_names(binary.image());
                    let ranges = velk::render::data_ranges(binary.image());
                    let analysis = binary.analysis(address, None).unwrap();
                    let annotated =
                        velk::render::render(&analysis.ir, &analysis.references, &symbols, &ranges);
                    symbols.objc_selectors.clear();
                    let plain =
                        velk::render::render(&analysis.ir, &analysis.references, &symbols, &ranges);
                    assert_eq!(annotated.replace(" /* @selector(add:with:) */", ""), plain);
                    let source =
                        common::root().join(format!("target/objc_{arch}_{level}{suffix}.c"));
                    std::fs::write(&source, format!("#include <stdint.h>\nextern int32_t objc_msgSend(int64_t, int64_t, ...);\n{code}")).unwrap();
                    let output = std::process::Command::new("clang")
                        .args([
                            "-x",
                            "c",
                            "-fsyntax-only",
                            "-Werror=implicit-function-declaration",
                        ])
                        .arg(&source)
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "{code}\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_objc_pointers_are_skipped() {
    use object::{Object, ObjectSection};
    let mut bytes = std::fs::read(common::fixtures_dir().join("objc_arm64_O0_stripped")).unwrap();
    let ranges: Vec<_> = {
        let file = object::File::parse(bytes.as_slice()).unwrap();
        file.sections()
            .filter(|section| {
                matches!(
                    section.name().unwrap(),
                    "__objc_classlist" | "__objc_catlist" | "__objc_selrefs"
                )
            })
            .map(|section| section.file_range().unwrap())
            .collect()
    };
    for (offset, size) in ranges {
        bytes[offset as usize..(offset + size) as usize].fill(0xff);
    }
    let path = common::root().join("target/objc_malformed");
    std::fs::write(&path, bytes).unwrap();
    let binary = Binary::open(&path).unwrap();
    assert!(binary.image().objc_selectors.is_empty());
    assert!(
        !binary
            .image()
            .functions
            .values()
            .any(|function| function.sources.contains(&NameSource::Objc))
    );
}

#[test]
fn objc_names_leave_other_functions_discoverable() {
    let mut bytes = std::fs::read(common::fixtures_dir().join("objc_x86_64_O0_stripped")).unwrap();
    let mut offset = 32usize;
    let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    for _ in 0..count {
        let command = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if command == object::macho::LC_FUNCTION_STARTS.0 {
            bytes[offset..offset + 4]
                .copy_from_slice(&object::macho::LC_CODE_SIGNATURE.0.to_le_bytes());
            break;
        }
        offset += size;
    }
    let path = common::root().join("target/objc_no_starts");
    std::fs::write(&path, bytes).unwrap();
    let binary = Binary::open(&path).unwrap();
    assert!(
        binary
            .image()
            .functions
            .values()
            .any(|function| function.sources.contains(&NameSource::Objc))
    );
    assert!(binary.image().functions.values().any(
        |function| function.name.is_none() && function.sources.contains(&NameSource::Prologue)
    ));
}
