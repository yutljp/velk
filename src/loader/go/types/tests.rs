use super::*;

#[test]
fn reads_runtime_types_in_both_go_fixtures() {
    for fixture in ["go_probe", "go_stripped"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture);
        let image = crate::loader::load(&path).unwrap();
        let types = read(&image);
        assert!(!types.layouts.is_empty(), "{fixture}");
    }
}

fn sample() -> Image {
    let mut bytes = vec![0; 2048];
    for (at, value) in [
        (0, 64u64),
        (56, 0x1100),
        (64, 4),
        (72, 4),
        (256, 0x1200),
        (264, 0x1300),
        (272, 0),
        (280, 0x1210),
        (288, 0x1340),
        (296, 16),
        (304, 0x1220),
        (312, 0x1380),
        (320, 40),
        (328, 0x1230),
        (336, 0x13c0),
        (344, 56),
    ] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[20] = 2;
    bytes[21] = 8;
    bytes[22] = 8;
    bytes[23] = 25;
    bytes[40..44].copy_from_slice(&0x240i32.to_le_bytes());
    for (at, name) in [
        (0x200, "Title"),
        (0x210, "Items"),
        (0x220, "Value"),
        (0x230, "Count"),
        (0x240, "*demo.Record"),
    ] {
        bytes[at + 1] = name.len() as u8;
        bytes[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (at, kind, size) in [
        (0x300, 24, 16u64),
        (0x340, 23, 24),
        (0x380, 20, 16),
        (0x3c0, 6, 8),
    ] {
        bytes[at..at + 8].copy_from_slice(&size.to_le_bytes());
        bytes[at + 21] = 8;
        bytes[at + 22] = 8;
        bytes[at + 23] = kind;
    }
    Image::from_code(Isa::X86_64, 0x1000, bytes)
}

#[test]
fn structure_names_fields_and_shape_offsets_are_exact() {
    let image = sample();
    let reader = Reader {
        image: &image,
        start: 0x1000,
        end: 0x1800,
    };
    let layout = reader.structure(0x1000).unwrap();
    assert_eq!(layout.definition.name, "struct go_demo_Record_1000");
    assert_eq!(layout.definition.size, 64);
    assert_eq!(
        layout
            .members
            .iter()
            .map(|member| (member.name.as_str(), member.offset))
            .collect::<Vec<_>>(),
        [
            ("Title.ptr", 0),
            ("Title.len", 8),
            ("Items.ptr", 16),
            ("Items.len", 24),
            ("Items.cap", 32),
            ("Value.type", 40),
            ("Value.data", 48),
            ("Count", 56)
        ]
    );
    assert!(reader.structure(u64::MAX - 8).is_none());
    assert!(reader.name(u64::MAX).is_none());
}

#[test]
fn malformed_layouts_are_refused() {
    for (at, bytes) in [
        (272, 1u64.to_le_bytes().to_vec()),
        (296, 0u64.to_le_bytes().to_vec()),
        (64, u64::MAX.to_le_bytes().to_vec()),
        (21, vec![16]),
        (0x241, vec![255; 5]),
        (344, u64::MAX.to_le_bytes().to_vec()),
    ] {
        let mut image = sample();
        image.bytes[at..at + bytes.len()].copy_from_slice(&bytes);
        let reader = Reader {
            image: &image,
            start: 0x1000,
            end: 0x1800,
        };
        assert!(reader.structure(0x1000).is_none(), "offset {at}");
    }
}

#[test]
fn standalone_shapes_require_valid_runtime_types() {
    use crate::ir::{BinOp, Expr, FunctionIr, Param, Stmt};

    let image = sample();
    let types = Types {
        start: 0x1000,
        end: 0x1800,
        ..Types::default()
    };
    for (addr, name, fields) in [
        (0x1300, "struct go_string", vec!["ptr", "len"]),
        (0x1340, "struct go_slice", vec!["ptr", "len", "cap"]),
        (0x1380, "struct go_iface", vec!["type", "data"]),
    ] {
        let layout = types.layout(&image, addr).unwrap();
        assert_eq!(layout.definition.name, name);
        assert_eq!(
            layout
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            fields
        );
        assert!(
            layout
                .members
                .iter()
                .all(|member| member.structure == name[7..])
        );
        for (index, field) in fields.iter().enumerate() {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::bin(
                            BinOp::Add,
                            Expr::reg(7, 64),
                            Expr::Const(index as u64 * 8),
                        )),
                        width: 8,
                        signed: false,
                    },
                }],
            );
            ir.name = Some("read_value".into());
            ir.ret_type = CType::U64;
            ir.params.push(Param {
                index: 7,
                name: "value".into(),
                ty: CType::pointer_to(CType::Named(name.into())),
            });
            ir.members = layout.members.clone();
            ir.definitions.push(layout.definition.clone());
            let code = crate::render::render(&ir, &[], &Default::default(), &[]);
            assert!(code.contains(&format!("value->{field}")), "{code}");
            let source = format!(
                "#include <stdint.h>\n#include <string.h>\n{code}\nint main(void) {{ {name} value; for (uint64_t i = 0; i < 100; ++i) {{ uint64_t bits = i * UINT64_C(0xfedcba987654321); memcpy((char *)&value + {}, &bits, 8); if (read_value(&value) != bits) return 1; }} return 0; }}\n",
                index * 8
            );
            let scratch = std::env::temp_dir().join(format!(
                "velk-go-shape-{}-{addr:x}-{index}",
                std::process::id()
            ));
            std::fs::create_dir_all(&scratch).unwrap();
            let input = scratch.join("shape.c");
            std::fs::write(&input, &source).unwrap();
            for level in ["-O0", "-O2"] {
                let executable = scratch.join(level);
                let output = std::process::Command::new("clang")
                    .args(["-fwrapv", "-fno-strict-aliasing", level])
                    .arg(&input)
                    .arg("-o")
                    .arg(&executable)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{source}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    std::process::Command::new(executable)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            std::fs::remove_dir_all(scratch).unwrap();
        }
    }
    assert!(types.layout(&image, 0x13c0).is_none());
    assert!(types.layout(&image, u64::MAX).is_none());
}

#[test]
fn printed_shapes_and_record_layout_compile_with_exact_offsets() {
    use crate::ir::{BinOp, Expr, FunctionIr, Param, Stmt};
    let image = sample();
    let reader = Reader {
        image: &image,
        start: 0x1000,
        end: 0x1800,
    };
    let layout = reader.structure(0x1000).unwrap();
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(56))),
                width: 8,
                signed: false,
            },
        }],
    );
    ir.name = Some("record_count".into());
    ir.ret_type = CType::U64;
    ir.params.push(Param {
        index: 7,
        name: "record".into(),
        ty: CType::pointer_to(CType::Named(layout.definition.name.clone())),
    });
    ir.members = layout.members;
    ir.definitions = shapes();
    ir.definitions.push(layout.definition);
    let code = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("record->Count"), "{code}");
    let mut prelude = crate::render::Prelude::default();
    prelude.extract(&code);
    prelude.extract(&code);
    let definitions = prelude.render();
    assert_eq!(definitions.matches("struct go_string {").count(), 1);
    let source = format!(
        "#include <stdint.h>\n#include <stddef.h>\n{definitions}\n_Static_assert(sizeof(struct go_demo_Record_1000) == 64, \"size\");\n_Static_assert(offsetof(struct go_demo_Record_1000, Items.cap) == 32, \"capacity\");\n_Static_assert(offsetof(struct go_demo_Record_1000, Value.data) == 48, \"data\");\n"
    );
    let scratch = std::env::temp_dir().join(format!("velk-go-layout-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let input = scratch.join("layout.c");
    std::fs::write(&input, &source).unwrap();
    let output = std::process::Command::new("clang")
        .args(["-std=c11", "-fsyntax-only"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{source}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(scratch).unwrap();
}
