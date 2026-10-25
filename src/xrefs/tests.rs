use super::*;
use crate::loader::{Function, Isa};
use std::collections::HashMap;

fn image(code: Vec<u8>) -> Image {
    let size = code.len() as u64;
    let mut image = Image::from_code(Isa::X86_64, 0x1000, code);
    image.functions.insert(
        0x1000,
        Function {
            addr: 0x1000,
            size: Some(size),
            size_estimated: false,
            name: Some("entry".into()),
            aliases: Vec::new(),
            sources: vec![crate::loader::NameSource::Symtab],
        },
    );
    image
}

#[test]
fn strings_decode_all_encodings_and_odd_alignment() {
    let mut bytes = b"hello\0caf\xc3\xa9\0\0".to_vec();
    let start = bytes.len();
    bytes.extend("wide\u{1f600}".encode_utf16().flat_map(u16::to_le_bytes));
    bytes.extend([0, 0]);
    let mut result = Vec::new();
    extract(&bytes, 0x100, ".data", &mut result);
    for (text, encoding) in [("hello", "ascii"), ("café", "utf8"), ("wide😀", "utf16le")] {
        let literal = result
            .iter()
            .find(|s| s.text == text && s.encoding == encoding)
            .unwrap();
        if encoding == "utf16le" {
            assert_eq!(literal.addr, 0x100 + start as u64);
        }
    }
    let mut overflow = Vec::new();
    extract(b"\0hello\0", u64::MAX, ".data", &mut overflow);
    assert!(overflow.is_empty());
}

#[test]
fn loads_are_not_repeated_when_their_results_are_used() {
    // mov rax,[0x1000]; add rax,1; ret
    let image = image(vec![
        0x48, 0xa1, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x48, 0x83, 0xc0, 1, 0xc3, 0x90, 0x90,
    ]);
    let index = Index::build(&image, None).unwrap();
    assert_eq!(
        index.xrefs.iter().filter(|x| x.kind == Kind::Read).count(),
        1
    );
}

#[test]
fn immediate_search_does_not_match_data_or_branch_displacements() {
    let image = image(vec![
        0xb8, 0x78, 0x56, 0x34, 0x12, 0xe8, 0x78, 0x56, 0x34, 0x12, 0xc3,
    ]);
    let matches = constants::search(&image, 0x12345678, None).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].instruction, 0x1000);
}

#[test]
fn direct_recursion_is_an_edge_but_not_an_infinite_walk() {
    let image = image(vec![0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3]);
    let index = Index::build(&image, None).unwrap();
    assert_eq!(index.graph(0x1000, false, usize::MAX), [0x1000]);
    assert_eq!(index.graph(0x1000, true, 1), [0x1000]);
    assert!(index.graph(0x1000, true, 0).is_empty());
}

#[test]
fn data_reads_writes_and_string_addresses_keep_their_access_kind() {
    let mut code = vec![
        0x48, 0xa1, 0x00, 0x11, 0, 0, 0, 0, 0, 0, // mov rax,[0x1100]
        0x48, 0xa3, 0x08, 0x11, 0, 0, 0, 0, 0, 0, // mov [0x1108],rax
        0x48, 0x8d, 0x0d, 0xf5, 0, 0, 0, // lea rcx,[0x1110]
        0xc3,
    ];
    let size = code.len();
    code.resize(0x110, 0);
    code.extend(b"known string\0");
    let mut image = image(code);
    image.functions.get_mut(&0x1000).unwrap().size = Some(size as u64);
    image.sections[0].size = 0x100;
    image.sections.push(crate::loader::Section {
        name: ".data".into(),
        vaddr: 0x1100,
        size: 0x1d,
        file_offset: Some(0x100),
        executable: false,
        loaded: true,
        read_only: false,
    });
    let index = Index::build(&image, None).unwrap();
    assert!(index.to(0x1100).iter().any(|xref| xref.kind == Kind::Read));
    assert!(index.to(0x1108).iter().any(|xref| xref.kind == Kind::Write));
    let literal = index
        .strings()
        .iter()
        .find(|s| s.text == "known string")
        .unwrap();
    assert!(
        literal
            .xrefs
            .iter()
            .any(|xref| xref.kind == Kind::Address && xref.target == 0x1110)
    );
}

#[test]
fn narrow_register_reads_and_writes_do_not_reuse_a_full_address() {
    let values = HashMap::from([(0, Expr::Const(0x12345678))]);
    assert_eq!(
        crate::analysis::navigation::resolve(&Expr::reg(0, 8), &values),
        Expr::Const(0x78)
    );
    // mov eax,0x1100; mov ah,0x12; mov byte ptr[rax],1; ret
    let mut code = vec![0xb8, 0x00, 0x11, 0, 0, 0xb4, 0x12, 0xc6, 0x00, 1, 0xc3];
    code.resize(0x300, 0);
    let image = image(code);
    let index = Index::build(&image, None).unwrap();
    assert!(!index.to(0x1100).iter().any(|xref| xref.kind == Kind::Write));
}

#[test]
fn malformed_function_does_not_hide_valid_functions() {
    let mut image = image(vec![0xc3]);
    let mut invalid = image.functions[&0x1000].clone();
    invalid.addr = u64::MAX;
    invalid.size = Some(u64::MAX);
    image.functions.insert(u64::MAX, invalid);
    let index = Index::build(&image, None).unwrap();
    assert_eq!(index.failures.len(), 1);
    assert_eq!(index.failures[0].function, u64::MAX);
}

#[test]
fn stub_calls_also_reference_the_named_import() {
    let mut code = vec![0xe8, 0x0b, 0, 0, 0, 0xc3];
    code.resize(0x10, 0x90);
    code.extend([0xff, 0x25, 0xea, 0, 0, 0]);
    code.resize(0x108, 0);
    let mut image = image(code);
    image.functions.get_mut(&0x1000).unwrap().size = Some(6);
    let mut stub = image.functions[&0x1000].clone();
    stub.addr = 0x1010;
    stub.name = Some("api".into());
    stub.sources = vec![crate::loader::NameSource::Plt];
    image.functions.insert(stub.addr, stub);
    image.imports.insert(0x1100, "api".into());
    let index = Index::build(&image, None).unwrap();
    assert!(
        index
            .from(0x1000)
            .iter()
            .any(|x| x.target == 0x1010 && x.kind == Kind::Call)
    );
    assert!(
        index
            .from(0x1000)
            .iter()
            .any(|x| x.target == 0x1100 && x.kind == Kind::ResolvedCall)
    );
    assert!(index.graph(0x1100, true, 1).contains(&0x1000));
}

#[test]
fn i386_immediates_use_32_bit_operand_and_address_defaults() {
    // inc eax; mov eax,0x12345678; add eax,-1; mov ax,0xabcd;
    // mov eax,[0x12345678]; jmp +0x12; ret
    let code = vec![
        0x40, 0xb8, 0x78, 0x56, 0x34, 0x12, 0x83, 0xc0, 0xff, 0x66, 0xb8, 0xcd, 0xab, 0xa1, 0x78,
        0x56, 0x34, 0x12, 0xeb, 0x12, 0xc3,
    ];
    let image = Image::from_code(Isa::I386, 0x1000, code);
    for (value, address) in [
        (0x12345678, 0x1001),
        (0xffff_ffff, 0x1006),
        (0xabcd, 0x1009),
    ] {
        let found = constants::search(&image, value, None).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].instruction, address);
        assert_eq!(found[0].operand, 1);
    }
    for value in [u64::MAX, 0x12, 0x1026] {
        assert!(constants::search(&image, value, None).unwrap().is_empty());
    }
}

#[test]
fn aarch64_immediates_include_the_encoded_shift() {
    let code = [0xd2a24680u32, 0x91001400, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let image = Image::from_code(Isa::AArch64, 0x1000, code);
    assert_eq!(
        constants::search(&image, 0x12340000, None).unwrap()[0].instruction,
        0x1000
    );
    assert_eq!(
        constants::search(&image, 5, None).unwrap()[0].instruction,
        0x1004
    );
    assert!(constants::search(&image, 0x1234, None).unwrap().is_empty());
}

#[test]
fn address_constants_must_agree_on_all_predecessors() {
    use crate::ir::{Block, Cond, RegRef};
    let image = image(vec![0xc3]);
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: 0,
            width: 64,
        },
        value: Expr::Const(value),
    };
    let mut blocks = vec![
        Block {
            start: 0x10,
            stmts: vec![
                assign(0x1100),
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(1, 64),
                    rhs: Expr::Const(0),
                    target: 0x30,
                },
            ],
        },
        Block {
            start: 0x20,
            stmts: vec![Stmt::Br { target: Some(0x30) }],
        },
        Block {
            start: 0x30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(0, 64),
            }],
        },
    ];
    let entries = crate::analysis::navigation::constants(&blocks, &image);
    assert_eq!(entries[2].get(&0), Some(&Expr::Const(0x1100)));
    blocks[1].stmts.insert(0, assign(0x1200));
    let entries = crate::analysis::navigation::constants(&blocks, &image);
    assert!(!entries[2].contains_key(&0));
}

#[test]
fn tail_calls_do_not_propagate_addresses_to_the_next_block() {
    use crate::ir::{Block, Convention, RegRef};
    let image = image(vec![0xc3]);
    let blocks = vec![
        Block {
            start: 0x1000,
            stmts: vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 3,
                        width: 64,
                    },
                    value: Expr::Const(0x1100),
                },
                Stmt::Call {
                    kind: CallKind::Tail,
                    target: Some(0x2000),
                    through: None,
                    convention: Convention::SysV,
                    args: None,
                    floats_named: false,
                    abi: None,
                    outputs: Vec::new(),
                    clobbers: None,
                    via: None,
                },
            ],
        },
        Block {
            start: 0x1010,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(3, 64),
            }],
        },
    ];
    assert!(crate::analysis::navigation::constants(&blocks, &image)[1].is_empty());
}

#[test]
fn arm32_immediates_follow_modes_and_exclude_data_and_branches() {
    use crate::loader::ArmMode;

    // A32 modified immediate, MOVW, MOVT; T32 MOVS, modified immediate, MOVW, MOVT.
    let mut code = vec![
        0xff, 0x04, 0xa0, 0xe3, 0x34, 0x02, 0x01, 0xe3, 0x78, 0x06, 0x45, 0xe3, 0x2a, 0x20, 0x4f,
        0xf0, 0xff, 0x20, 0x41, 0xf2, 0x34, 0x20, 0xc5, 0xf2, 0x78, 0x60,
    ];
    code.extend([0x2a, 0x20]); // Data that resembles MOVS.
    code.extend([0x2a, 0xe0]); // Thumb branch displacement.
    let mut image = Image::from_code(Isa::Arm32, 0x1000, code);
    image.arm_modes.insert(0x100c, ArmMode::Thumb);
    image.arm_modes.insert(0x101a, ArmMode::Data);
    image.arm_modes.insert(0x101c, ArmMode::Thumb);
    for (value, addresses) in [
        (0xff000000, vec![0x1000]),
        (0x1234, vec![0x1004, 0x1012]),
        (0x56780000, vec![0x1008, 0x1016]),
        (42, vec![0x100c]),
        (0xff00ff00, vec![0x100e]),
        (0x5678, vec![]),
    ] {
        let found = constants::search(&image, value, None).unwrap();
        assert_eq!(
            found
                .iter()
                .map(|entry| entry.instruction)
                .collect::<Vec<_>>(),
            addresses
        );
    }
    assert!(constants::search(&image, 1, Some(std::time::Instant::now())).is_err());
}
