mod common;

use velk::{loader, service::Session};

#[test]
fn printed_seh_regions_and_discovered_functions() {
    for opt in ["O0", "O2"] {
        let path = common::fixtures_dir().join(format!("seh.{opt}.dll"));
        let mut session = Session::default();
        let binary = session.open(&path).unwrap();
        for (name, region, count) in [
            ("seh_except", "__except (filter at ", 1),
            ("seh_finally", "__finally (termination handler at ", 1),
            ("seh_nested", "__except (1)", 3),
        ] {
            let function = binary
                .image()
                .functions
                .values()
                .find(|f| f.name.as_deref() == Some(name))
                .unwrap();
            let address = function.addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(
                code.contains("Windows x64 exception handler: __C_specific_handler"),
                "{opt}: {code}"
            );
            assert_eq!(code.matches("/* __try [").count(), count, "{opt}: {code}");
            assert!(code.contains(region), "{opt}: {code}");
            assert!(code.contains("exception dispatch is not represented by standard C"));
            if opt == "O2" && name == "seh_except" {
                assert!(code.contains("/* __try [0x18000101d, 0x180001024): __except (filter at 0x180001040); handler block at 0x18000102a. */"), "{code}");
            }
            if name == "seh_nested" {
                assert!(code.contains("__finally (termination handler at "));
            }
            // SEH syntax occurs only in comments, preserving standard-C syntax.
            for line in code.lines().filter(|line| {
                line.contains("__try") || line.contains("__except") || line.contains("__finally")
            }) {
                assert!(line.starts_with("/*"), "{line}");
            }
        }
        for name in [
            "seh_except__except_filter_0",
            "seh_finally__finally_0",
            "seh_nested__finally_0",
        ] {
            let function = binary
                .image()
                .functions
                .values()
                .find(|f| {
                    f.name.as_deref() == Some(name) || f.aliases.iter().any(|alias| alias == name)
                })
                .unwrap_or_else(|| panic!("{opt}: missing {name}"));
            assert!(function.sources.contains(&loader::NameSource::Unwind));
            assert!(binary.decompile(function.addr, None, None).is_ok());
        }
    }
}

#[test]
fn cpp_frame_handler3_catches_are_printed_and_named() {
    for opt in ["O0", "O2"] {
        let path = common::fixtures_dir().join(format!("seh_cpp.{opt}.dll"));
        let mut session = Session::default();
        let binary = session.open(&path).unwrap();
        let function = binary
            .image()
            .functions
            .values()
            .find(|f| f.name.as_deref() == Some("cpp_catch"))
            .unwrap();
        let address = function.addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("__CxxFrameHandler3"), "{opt}: {code}");
        assert!(
            code.contains("C++ try states [0, 0]: catch handler at "),
            "{opt}: {code}"
        );
        let catch = binary
            .image()
            .functions
            .values()
            .find(|f| f.name.as_deref() == Some("cpp_catch__catch_0"))
            .unwrap();
        assert!(code.contains(&format!("catch handler at {:#x}", catch.addr)));
    }
}
