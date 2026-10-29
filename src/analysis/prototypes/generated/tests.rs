use super::*;

#[test]
fn unknown_generic_prototypes_leave_linux_library_unloaded() {
    if std::env::var_os("VELK_GENERIC_LOOKUP_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "analysis::prototypes::generated::tests::unknown_generic_prototypes_leave_linux_library_unloaded",
            ])
            .env("VELK_GENERIC_LOOKUP_CHILD", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    assert!(LINUX.get().is_none());
    assert!(crate::analysis::prototypes::of("unknown_function", false).is_none());
    assert!(LINUX.get().is_none());
    let prototype = crate::analysis::prototypes::of("memcpy", false).unwrap();
    assert_eq!(prototype.parameter_names, ["__dest", "__src", "__n"]);
    assert!(LINUX.get().is_some());
}

#[test]
fn target_library_entries_parse_only_when_looked_up() {
    let libraries = targets(include_str!("../linux.json"));
    let library = &libraries["x86_64-linux-gnu"].library;
    assert!(
        library
            .functions
            .values()
            .all(|function| function.prototype.get().is_none())
    );
    assert!(
        library
            .records
            .values()
            .all(|record| record.record.get().is_none())
    );

    let prototype = library.prototype("memcpy").unwrap();
    assert_eq!(prototype.parameter_names, ["__dest", "__src", "__n"]);
    for (name, function) in &library.functions {
        if *name != "memcpy" {
            assert!(function.prototype.get().is_none());
        }
    }
    assert!(
        library
            .records
            .values()
            .all(|record| record.record.get().is_none())
    );

    let (name, record) = library.records.iter().next().unwrap();
    let name = *name;
    assert!(library.record(name).is_some());
    assert!(record.record.get().is_some());
    for (record_name, record) in &library.records {
        if *record_name != name {
            assert!(record.record.get().is_none());
        }
    }
}

#[test]
fn unqualified_windows_names_leave_type_library_unloaded() {
    use crate::loader::{Function, NameSource};

    if std::env::var_os("VELK_PROTOTYPE_LOOKUP_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                concat!(
                    "analysis::prototypes::generated::tests::",
                    "unqualified_windows_names_leave_type_library_unloaded",
                ),
                "--nocapture",
            ])
            .env("VELK_PROTOTYPE_LOOKUP_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
        );
        return;
    }
    assert!(WINDOWS.get().is_none());
    for isa in [Isa::I386, Isa::X86_64] {
        let mut image = Image::from_code(isa, 0x1000, vec![0xc3]);
        image.format = Format::Pe;
        image.functions.insert(
            0x1000,
            Function {
                addr: 0x1000,
                size: Some(1),
                size_estimated: false,
                name: Some("reg_div".to_owned()),
                aliases: Vec::new(),
                sources: vec![NameSource::Symtab],
                library: None,
            },
        );
        let symbols = crate::render::callee_names(&image);
        assert_eq!(symbols.functions[&0x1000], "reg_div");
        assert!(WINDOWS.get().is_none());
    }
}

#[test]
fn guid_matches_require_complete_read_only_windows_data() {
    let datasets = targets(include_str!("../windows.json"));
    assert!(datasets["i686-w64-mingw32"].guids.len() >= 600);
    assert_eq!(
        datasets["i686-w64-mingw32"].guids,
        datasets["x86_64-w64-mingw32"].guids
    );
    for arch in ["x86_64", "i686"] {
        let mut image = crate::loader::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("tests/fixtures/com_{arch}.dll")),
        )
        .unwrap();
        let address = *image
            .data_symbols
            .iter()
            .find(|(_, name)| name.trim_start_matches('_') == "IID_IUnknown")
            .unwrap()
            .0;
        let guid = guid_at(&image, address).unwrap();
        assert!(guid.names.iter().any(|name| name == "IID_IUnknown"));
        assert_eq!(guid.value, "00000000-0000-0000-c000-000000000046");
        assert_eq!(
            guid.bytes,
            [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]
        );
        let start = image.section_at(address).unwrap().vaddr;
        let section = image
            .sections
            .iter()
            .position(|section| section.vaddr == start)
            .unwrap();
        let size = image.sections[section].size;
        let file_size = image.sections[section].file_size;
        image.sections[section].size = address - start + 15;
        assert!(guid_at(&image, address).is_none());
        image.sections[section].size = size;
        image.sections[section].file_size = address - start + 15;
        assert!(guid_at(&image, address).is_none());
        image.sections[section].file_size = file_size;
        image.sections[section].read_only = false;
        assert!(guid_at(&image, address).is_none());
        image.sections[section].read_only = true;
        image.sections[section].executable = true;
        assert!(guid_at(&image, address).is_none());
        image.sections[section].executable = false;
        image.format = Format::Elf;
        assert!(guid_at(&image, address).is_none());
        assert!(guid_at(&image, u64::MAX).is_none());
    }
}

#[test]
fn windows_vtables_retain_typed_methods_and_target_layouts() {
    let libraries = targets(include_str!("../windows.json"));
    for (target, data) in libraries {
        let width = if target.starts_with("i686") { 4 } else { 8 };
        let convention = if width == 4 {
            crate::ir::Convention::Stdcall
        } else {
            crate::ir::Convention::Win64
        };
        for interface in ["IUnknown", "IDispatch", "IStream"] {
            let name = format!("struct {interface}Vtbl");
            let record = &data.library.records[name.as_str()];
            assert!(record.fields.len() >= 3, "{target}: {name}");
            for (slot, method) in ["QueryInterface", "AddRef", "Release"].iter().enumerate() {
                let field = &record.fields[slot];
                assert_eq!(field.name, *method, "{target}: {name}");
                assert_eq!(field.offset, slot as u64 * width);
                assert_eq!(field.width, width);
                let CType::Pointer(ty) = super::super::parse_type(field.ty) else {
                    panic!("{}", field.ty)
                };
                let CType::Function {
                    params,
                    ret,
                    convention: actual,
                    variadic,
                } = *ty
                else {
                    panic!("{}", field.ty)
                };
                assert_eq!(actual, convention);
                assert!(!variadic);
                assert_eq!(params.len(), if slot == 0 { 3 } else { 1 });
                assert_eq!(params[0].pointee_struct(), Some(interface));
                assert_eq!(ret.integer(), Some((32, slot == 0)));
            }
        }
        let stream = &data.library.records["struct IStreamVtbl"];
        assert_eq!(stream.fields.len(), 14, "{target}");
        assert!(
            stream
                .fields
                .iter()
                .any(|field| field.name == "Read" && field.offset == 3 * width)
        );
    }
}

#[test]
fn rendered_windows_function_pointer_declarations_compile_for_both_targets() {
    use std::process::Command;

    for (target, data) in targets(include_str!("../windows.json")) {
        let mut pending = Vec::new();
        let mut declarations = Vec::new();
        for record in data.library.records.values() {
            for field in &record.fields {
                let ty = super::super::parse_type(field.ty);
                if !field.ty.contains("(*") {
                    continue;
                }
                record_dependencies(&ty, &mut pending);
                let name = format!("callback_{}", declarations.len());
                declarations.push(format!(
                    "typedef {};\n",
                    crate::render::declaration(&ty, &name)
                ));
            }
        }
        assert!(
            declarations.len() > 1000,
            "{target}: {}",
            declarations.len()
        );
        pending.sort();
        pending.dedup();
        let mut text = String::from("#include <stdint.h>\n#include <stddef.h>\n");
        for tag in pending {
            text.push_str(&format!("{tag};\n"));
        }
        text.extend(declarations);
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/library-function-fields");
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join(format!("{target}.c"));
        std::fs::write(&source, text).unwrap();
        let output = Command::new("clang")
            .args([
                "-target",
                target,
                "-ffreestanding",
                "-std=c11",
                "-fsyntax-only",
                "-Werror",
            ])
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn i386_stdcall_import_cleanup_preserves_following_arguments() {
    let code = vec![
        0x6a, 7, 0xff, 0x15, 0x00, 0x20, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x04, 0x50, 0xff, 0x15,
        0x00, 0x20, 0x00, 0x00, 0xc3,
    ];
    let size = code.len() as u64;
    let mut image = Image::from_code(Isa::I386, 0x1000, code);
    image.format = Format::Pe;
    image.imports.insert(0x2000, "GetFileType".into());
    image
        .qualified_imports
        .insert(0x2000, "kernel32.dll!GetFileType".into());
    let function = crate::loader::Function {
        addr: 0x1000,
        size: Some(size),
        size_estimated: false,
        name: Some("two_calls".into()),
        aliases: Vec::new(),
        library: None,
        sources: Vec::new(),
    };
    image.functions.insert(function.addr, function.clone());
    let analysis = crate::analysis::analyze(&image, &function, None).unwrap();
    let code = crate::render::render(&analysis.ir, &[], &crate::render::callee_names(&image), &[]);
    assert!(code.contains("GetFileType((void *)0x7)"), "{code}");
    assert!(code.contains("GetFileType((void *)a0)"), "{code}");
    assert!(!code.contains("esp"), "{code}");
}

#[test]
fn i386_import_conventions_and_cleanup_use_the_target_library() {
    let mut image = Image::from_code(Isa::I386, 0x1000, Vec::new());
    image.format = Format::Pe;
    assert_eq!(
        i386_import(&image, "kernel32.dll!GetFileType"),
        Some((crate::ir::Convention::Stdcall, 4))
    );
    assert_eq!(
        i386_import(&image, "kernel32.dll!GetLastError"),
        Some((crate::ir::Convention::Stdcall, 0))
    );
    assert_eq!(
        i386_import(&image, "msvcrt.dll!calloc"),
        Some((crate::ir::Convention::Cdecl, 0))
    );
    assert_eq!(
        i386_import(&image, "kernel32.dll!VirtualAlloc"),
        Some((crate::ir::Convention::Stdcall, 16))
    );
    assert_eq!(i386_import(&image, "other.dll!GetFileType"), None);
    assert_eq!(
        for_image("msvcrt.dll!time", &image).unwrap().ret.integer(),
        Some((32, true))
    );
    image.isa = Isa::X86_64;
    assert_eq!(
        for_image("msvcrt.dll!time", &image).unwrap().ret.integer(),
        Some((64, true))
    );
    assert_eq!(i386_import(&image, "kernel32.dll!GetFileType"), None);
}

#[test]
fn target_libraries_do_not_cross_formats_or_architectures() {
    let mut image = Image::from_code(Isa::X86_64, 0x1000, Vec::new());
    assert_eq!(
        for_image("umask", &image).unwrap().ret.integer(),
        Some((32, false))
    );
    assert!(!for_image("pthread_self", &image).unwrap().ret.is_pointer());
    assert!(for_image("kernel32.dll!OpenProcess", &image).is_none());
    image.format = Format::Pe;
    assert!(for_image("getgrgid_r", &image).is_none());
    assert!(for_image("OpenProcess", &image).is_none());
    assert!(
        for_image("KERNEL32.DLL!OpenProcess", &image)
            .unwrap()
            .ret
            .is_pointer()
    );
    assert!(for_image("other.dll!OpenProcess", &image).is_none());
    assert!(for_image("kernel32.dll!#1", &image).is_none());
    assert_eq!(
        for_image("kernel32.dll!_lclose", &image)
            .unwrap()
            .ret
            .integer(),
        Some((32, true))
    );
    assert_eq!(
        for_image("user32.dll!GetWindowLongW", &image)
            .unwrap()
            .ret
            .integer(),
        Some((32, true))
    );
    let wide = for_image("kernel32.dll!lstrlenW", &image).unwrap();
    assert_eq!(
        wide.params[0],
        CType::pointer_to(CType::Named("const unsigned short".into()))
    );
    assert_eq!(
        for_image("kernel32.dll!GetModuleHandleW", &image)
            .unwrap()
            .parameter_names,
        ["lpModuleName"]
    );
    image.isa = Isa::AArch64;
    assert!(for_image("kernel32.dll!OpenProcess", &image).is_none());
    image.format = Format::Elf;
    assert_eq!(
        for_image("umask", &image).unwrap().ret.integer(),
        Some((32, false))
    );
    image.isa = Isa::Unsupported;
    assert!(for_image("umask", &image).is_none());
}

#[test]
fn windows_crt_dll_names_and_forwarders_preserve_signatures() {
    let mut image = Image::from_code(Isa::X86_64, 0x1000, Vec::new());
    image.format = Format::Pe;
    for dll in [
        "MSVCRT.DLL",
        "UCRTBASE.DLL",
        "API-MS-WIN-CRT-STRING-L1-1-0.DLL",
    ] {
        let prototype = for_image(&format!("{dll}!wcscpy_s"), &image).unwrap();
        assert_eq!(prototype.fixed(), 3);
        assert_eq!(prototype.params[1].integer(), Some((64, false)));
        assert_eq!(
            prototype.params[0],
            CType::pointer_to(CType::Named("unsigned short".into()))
        );
        assert!(for_image(&format!("{dll}!#42"), &image).is_none());
    }
    assert!(for_image("other.dll!wcscpy_s", &image).is_none());
    assert!(for_image("msvcrt.dll!WCSCPY_S", &image).is_none());
    let number = for_image("msvcrt.dll!strtol", &image).unwrap();
    assert_eq!(number.ret.integer(), Some((32, true)));
    assert!(for_image("api-ms-win-core-file-l1-1-0.dll!GetFileType", &image).is_some());
    assert!(for_image("api-ms-win-security-base-l1-1-0.dll!RegCloseKey", &image).is_some());
    image.imports.insert(0x2000, "wcscpy_s".into());
    image
        .qualified_imports
        .insert(0x2000, "MsVcRt.DlL!wcscpy_s".into());
    assert_eq!(for_image("wcscpy_s", &image).unwrap().fixed(), 3);
    assert!(for_image("msvcrt.dll!printf", &image).is_none());
    assert!(super::super::for_image("printf", &image).unwrap().variadic);
    let windows = WINDOWS.get().unwrap();
    let x86 = &windows["i686-w64-mingw32"];
    let name = windows_import_name(x86, "msvcrt.dll!wcscpy_s").unwrap();
    let copy = &x86.library.functions[name];
    assert_eq!(copy.params[1].integer(), Some((32, false)));
}

#[test]
fn shared_library_records_require_matching_definitions_without_dependencies() {
    library();
    let mut definition = Definition {
        name: "struct iovec".into(),
        members: vec!["void *iov_base;".into(), "size_t iov_len;".into()],
        fields: vec!["iov_base".into(), "iov_len".into()],
        contains: Vec::new(),
        size: 16,
        alignment: Some(8),
        compatible_profiles: vec![AbiProfile::SysV, AbiProfile::Aapcs64],
    };
    assert!(is_library_record(&definition));
    definition.contains.push("struct custom".into());
    assert!(!is_library_record(&definition));
    definition.contains.clear();
    definition.members[0] = "struct custom iov_base;".into();
    assert!(!is_library_record(&definition));
}

#[test]
fn generated_signatures_have_supported_scalar_abi_types() {
    assert!(library().functions.len() > 800);
    for (name, prototype) in &library().functions {
        let text: &'static str = serde_json::from_str(prototype.text.get()).unwrap();
        assert_eq!(super::super::parse(text).0, *name);
        assert!(prototype.fixed() <= 6 && prototype.floats() <= 8, "{name}");
        assert!(
            prototype.params.iter().all(CType::is_sse_float)
                || prototype.params.iter().all(|ty| !ty.is_sse_float()),
            "{name}"
        );
        let types = prototype.params.iter().chain([&prototype.ret]);
        for ty in types {
            assert!(
                matches!(ty, CType::Void | CType::Pointer(_))
                    || ty.integer().is_some()
                    || ty.is_sse_float(),
                "{name}: {ty}"
            );
        }
    }
    let mask = of("umask").unwrap();
    assert_eq!(mask.ret.integer(), Some((16, false)));
    assert_eq!(
        crate::analysis::prototypes::of("memcpy", false)
            .unwrap()
            .parameter_names,
        ["__dest", "__src", "__n"]
    );
    assert!(
        of("div").is_none(),
        "aggregate return needs ABI classification"
    );
}

#[test]
fn all_target_declarations_use_supported_scalar_types_and_fitted_fields() {
    for text in [
        include_str!("../windows.json"),
        include_str!("../linux.json"),
    ] {
        let targets = targets(text);
        assert_eq!(targets.len(), 2);
        for (target, data) in targets {
            assert!(!data.library.functions.is_empty(), "{target}");
            for (name, prototype) in &data.library.functions {
                let text: &'static str = serde_json::from_str(prototype.text.get()).unwrap();
                assert_eq!(super::super::parse(text).0, *name, "{target}: {name}");
                for ty in prototype.params.iter().chain([&prototype.ret]) {
                    assert!(
                        matches!(ty, CType::Void | CType::Pointer(_))
                            || ty.integer().is_some()
                            || ty.is_sse_float(),
                        "{target}: {name}: {ty}"
                    );
                }
            }
            for (name, record) in &data.library.records {
                assert!(record.align.is_power_of_two(), "{target}: {name}");
                assert!(record.size.is_multiple_of(record.align), "{target}: {name}");
                let mut end = 0;
                for field in &record.fields {
                    assert!(field.offset >= end && field.width > 0, "{target}: {name}");
                    end = field.offset.checked_add(field.width).unwrap();
                    assert!(end <= record.size, "{target}: {name}");
                }
            }
        }
    }
}

#[test]
fn generated_fields_fit_the_record_without_overlap() {
    assert!(library().records["struct sigaction"].opaque);
    assert!(
        library().records["struct iovec"]
            .fields
            .iter()
            .any(|field| field.offset == 8
                && field.name == "iov_len"
                && field.ty == "size_t"
                && field.width == 8)
    );
    for (name, record) in &library().records {
        assert!(record.align.is_power_of_two());
        assert!(record.size.is_multiple_of(record.align));
        let mut end = 0;
        for field in &record.fields {
            let ty = super::super::parse_type(field.ty);
            assert!(
                field.offset >= end && field.width > 0,
                "{name}: {}",
                field.ty
            );
            assert!(ty.is_pointer() || ty.integer().is_some() || ty.is_sse_float());
            end = field.offset.checked_add(field.width).unwrap();
            assert!(end <= record.size);
        }
    }
}

#[test]
fn macos_declarations_do_not_supply_other_platforms() {
    assert!(super::super::of("getgrgid_r", false).is_none());
    assert_eq!(super::super::of("_getgrgid_r", true).unwrap().fixed(), 5);
    assert_eq!(
        super::super::of("_pthread_self", true).unwrap().pointers(),
        0
    );
    assert!(
        super::super::of("_pthread_self", true)
            .unwrap()
            .ret
            .is_pointer()
    );
}
