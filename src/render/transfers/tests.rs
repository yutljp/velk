use super::filled_range;
use crate::ir::{BinOp, CType, Expr, FunctionIr, Param, Stmt};
use crate::loader::Isa;
use crate::render::{InlineFunction, Symbols, render_with_dependencies};

fn address(offset: u64) -> Expr {
    Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(offset))
}

#[test]
fn overlapping_fill_ranges_preserve_symbolic_memory() {
    use crate::ir::smt::Proofs;

    assert!(Proofs::available(), "fill equivalence requires z3");
    let mut proofs = Proofs::default();
    let store = |mut memory: String, offset: u64, width: u64| {
        for byte in offset..offset + width {
            memory = format!("(store {memory} (bvadd r0 (_ bv{byte} 64)) ((_ extract 7 0) r1))");
        }
        memory
    };
    for first_width in [1, 2, 4, 8] {
        for width in [1, 2, 4, 8] {
            for offset in 0..=first_width {
                for reverse in [false, true] {
                    let first = address(if reverse { offset } else { 0 });
                    let next = address(if reverse { 0 } else { offset });
                    let (first_offset, next_offset, first_width, width) = if reverse {
                        (offset, 0, width, first_width)
                    } else {
                        (0, offset, first_width, width)
                    };
                    let range = filled_range(&first, &next, first_width, width as u8).unwrap();
                    let start = if range.start == &first {
                        first_offset
                    } else {
                        next_offset
                    };
                    let before = store(
                        store("memory".to_owned(), first_offset, first_width),
                        next_offset,
                        width,
                    );
                    let after = store("memory".to_owned(), start, range.bytes);
                    proofs.predicate(
                        format!("fill-{first_width}-{width}-{offset}-{reverse}"),
                        &before,
                        &after,
                    );
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn fill_extents_exhaustively_preserve_small_byte_arrays() {
    for first_width in [1, 2, 4, 8] {
        for width in [1, 2, 4, 8] {
            for first_offset in 0..=10 {
                for offset in 0..=10 {
                    let first = address(first_offset);
                    let next = address(offset);
                    let extent = filled_range(&first, &next, first_width, width);
                    assert_eq!(
                        extent.is_some(),
                        offset <= first_offset + first_width
                            && offset + u64::from(width) >= first_offset
                    );
                    let Some(extent) = extent else { continue };
                    let start = first_offset.min(offset) as usize;
                    for byte in 0..=255u8 {
                        let mut original = [0x5a; 32];
                        original[first_offset as usize..(first_offset + first_width) as usize]
                            .fill(byte);
                        original[offset as usize..offset as usize + usize::from(width)].fill(byte);
                        let mut replacement = [0x5a; 32];
                        replacement[start..start + extent.bytes as usize].fill(byte);
                        assert_eq!(original, replacement);
                    }
                }
            }
        }
    }
    assert!(filled_range(&address(0), &Expr::reg(1, 64), 8, 8).is_none());
    assert!(filled_range(&address(0), &address(u64::MAX - 8), 8, 8).is_none());
    assert!(filled_range(&address(i64::MAX as u64), &address(0), 8, 8).is_none());
    assert!(filled_range(&address(0), &address(0), u64::MAX, 8).is_none());
}

fn fill_ir(isa: Isa, name: &str, first: u8, second: u8, offset: u64) -> FunctionIr {
    let mut ir = FunctionIr::single_block(
        isa,
        vec![
            Stmt::Store {
                addr: address(0),
                value: Expr::Const(0xabababababababab),
                width: first,
                at: None,
            },
            Stmt::Store {
                addr: address(offset),
                value: Expr::Const(0xabababababababab),
                width: second,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ],
    );
    ir.name = Some(name.to_owned());
    ir.ret_type = CType::Void;
    ir.params = vec![Param {
        index: 0,
        name: "data".to_owned(),
        ty: CType::pointer_to(CType::Int {
            bytes: 1,
            signed: false,
        }),
    }];
    ir
}

#[test]
fn literal_store_widths_have_symbolic_memory_proofs() {
    use crate::ir::smt::Proofs;

    assert!(Proofs::available(), "literal store equivalence requires z3");
    let mut proofs = Proofs::default();
    for isa in [Isa::X86_64, Isa::AArch64] {
        for width in [1, 2, 4, 8] {
            for reverse in [false, true] {
                let mut before = fill_ir(isa, "literal", width, 1, u64::from(width));
                let Stmt::Store { value, .. } = &mut before.blocks[0].stmts[1] else {
                    unreachable!()
                };
                *value = Expr::Const(0);
                if reverse {
                    before.blocks[0].stmts.swap(0, 1)
                }
                let mut after = before.clone();
                after.blocks[0].stmts.clear();
                for offset in 0..=width {
                    after.blocks[0].stmts.push(Stmt::Store {
                        addr: address(u64::from(offset)),
                        value: Expr::Const(if offset == width { 0 } else { 0xab }),
                        width: 1,
                        at: None,
                    });
                }
                after.blocks[0].stmts.push(Stmt::Ret {
                    value: Expr::Const(0),
                    at: None,
                });
                proofs.function(
                    format!("literal bytes/{isa:?}/{width}/{reverse}"),
                    &before,
                    &after,
                );
            }
        }
    }
    proofs.check();
}

#[test]
fn terminated_literal_stores_compile_and_preserve_all_bytes() {
    let mut source = String::from("#include <stdint.h>\n#include <string.h>\n");
    for (index, isa) in [Isa::X86_64, Isa::AArch64].into_iter().enumerate() {
        for reverse in [false, true] {
            let name = format!("literal_{index}_{}", u8::from(reverse));
            let mut ir = fill_ir(isa, &name, 4, 2, 4);
            ir.params[0].name = "__builtin_strcpy".to_owned();
            for (position, value) in [(0, 0x39225c3f), (1, 0x0061)] {
                let Stmt::Store { value: stored, .. } = &mut ir.blocks[0].stmts[position] else {
                    unreachable!()
                };
                *stored = Expr::Const(value);
            }
            if reverse {
                ir.blocks[0].stmts.swap(0, 1)
            }
            let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
            assert_eq!(
                rendered.inline_functions,
                vec![InlineFunction {
                    function: "strcpy".to_owned(),
                    bytes: Some(6)
                }],
                "{}",
                rendered.code
            );
            assert!(
                rendered.code.contains("__builtin_strcpy((char *)"),
                "{}",
                rendered.code
            );
            source.push_str(&rendered.code);
        }
        for byte in 1..=255 {
            let name = format!("byte_{index}_{byte}");
            let mut ir = fill_ir(isa, &name, 2, 2, 2);
            for (position, value) in [(0, 0x6261), (1, byte)] {
                let Stmt::Store { value: stored, .. } = &mut ir.blocks[0].stmts[position] else {
                    unreachable!()
                };
                *stored = Expr::Const(value);
            }
            let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
            let expected = if (0x20..0x7f).contains(&byte) || byte == 9 {
                vec![InlineFunction {
                    function: "strcpy".to_owned(),
                    bytes: Some(4),
                }]
            } else {
                Vec::new()
            };
            assert_eq!(rendered.inline_functions, expected, "{}", rendered.code);
            source.push_str(&rendered.code);
        }
    }
    source.push_str("int main(void) { _Alignas(8) unsigned char bytes[8]; unsigned char expected[8]={63,92,34,57,97,0,171,171};");
    for index in 0..2 {
        for reverse in 0..2 {
            source.push_str(&format!("memset(bytes,171,8); literal_{index}_{reverse}(bytes); if(memcmp(bytes,expected,8)) return 1;"));
        }
        for byte in 1..=255 {
            source.push_str(&format!("memset(bytes,171,8); byte_{index}_{byte}(bytes); if(bytes[0]!=97 || bytes[1]!=98 || bytes[2]!={byte} || bytes[3]!=0 || bytes[4]!=171) return 2;"));
        }
    }
    source.push_str("return 0;}\n");
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/string-function-tests");
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("literals.c");
    let output = directory.join("literals");
    std::fs::write(&input, &source).unwrap();
    let compiled = std::process::Command::new("clang")
        .args(["-std=c11", "-Werror", "-O2", "-fno-strict-aliasing"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        std::process::Command::new(&output)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn gaps_embedded_zeros_and_missing_terminators_keep_literal_stores() {
    for kind in 0..4 {
        let mut ir = fill_ir(Isa::X86_64, "bytes", 4, 2, if kind == 0 { 5 } else { 4 });
        for (position, value) in [
            (0, if kind == 1 { 0x61620064 } else { 0x61626364 }),
            (1, if kind == 2 { 0x6566 } else { 0x0066 }),
        ] {
            let Stmt::Store { value: stored, .. } = &mut ir.blocks[0].stmts[position] else {
                unreachable!()
            };
            *stored = Expr::Const(value);
        }
        if kind == 3 {
            ir.blocks[0].stmts[0] = Stmt::Store {
                addr: address(0),
                value: Expr::Const(0x01010101),
                width: 4,
                at: None,
            };
            ir.blocks[0].stmts[1] = Stmt::Store {
                addr: address(4),
                value: Expr::Const(1),
                width: 2,
                at: None,
            };
        }
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert!(
            !rendered
                .inline_functions
                .iter()
                .any(|call| call.function == "strcpy"),
            "{kind}: {}",
            rendered.code
        );
    }
}

#[test]
fn overlapping_fills_print_compile_and_execute_for_both_architectures() {
    let mut source = String::from("#include <stdint.h>\n#include <string.h>\n");
    let mut checks = String::new();
    let mut count = 0;
    for isa in [Isa::X86_64, Isa::AArch64] {
        for first in [1, 2, 4, 8] {
            for second in [1, 2, 4, 8] {
                for offset in 0..=u64::from(first) {
                    for reverse in [false, true] {
                        let name = format!("fill_{count}");
                        let mut ir = fill_ir(isa, &name, first, second, offset);
                        if count == 0 {
                            ir.params[0].name = "__builtin_memset".to_owned();
                        }
                        if reverse {
                            ir.blocks[0].stmts.swap(0, 1);
                        }
                        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
                        let bytes = u64::from(first).max(offset + u64::from(second));
                        assert!(
                            rendered.code.contains("__builtin_memset"),
                            "{}",
                            rendered.code
                        );
                        assert_eq!(
                            rendered.inline_functions,
                            vec![InlineFunction {
                                function: "memset".to_owned(),
                                bytes: Some(bytes),
                            }]
                        );
                        source.push_str(&rendered.code);
                        checks.push_str(&format!(
                        "memset(a, seed, sizeof a); memset(b, seed, sizeof b); {name}(a+8); memset(b+8, 0xab, {first}); memset(b+8+{offset}, 0xab, {second}); if (memcmp(a,b,sizeof a)) return 1;\n"
                    ));
                        count += 1;
                    }
                }
            }
        }
    }
    for (index, isa) in [Isa::X86_64, Isa::AArch64].into_iter().enumerate() {
        let name = format!("move_{index}");
        let mut ir = fill_ir(isa, &name, 8, 8, 8);
        ir.params[0].name = "__builtin_memmove".to_owned();
        ir.params.push(Param {
            index: 1,
            name: "source".to_owned(),
            ty: ir.params[0].ty.clone(),
        });
        let mut statements = Vec::new();
        for offset in [0, 8] {
            statements.push(Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: crate::ir::VARIABLE_BASE + offset as u16,
                    width: 64,
                },
                value: Expr::Load {
                    addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(1, 64), Expr::Const(offset))),
                    width: 8,
                    signed: false,
                },
                at: None,
            });
        }
        for offset in [0, 8] {
            statements.push(Stmt::Store {
                addr: address(offset),
                value: Expr::reg(crate::ir::VARIABLE_BASE + offset as u16, 64),
                width: 8,
                at: None,
            });
        }
        statements.push(Stmt::Ret {
            value: Expr::Const(0),
            at: None,
        });
        ir.blocks[0].stmts = statements;
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert!(
            rendered.code.contains("__builtin_memmove("),
            "{}",
            rendered.code
        );
        assert_eq!(
            rendered.inline_functions,
            vec![InlineFunction {
                function: "memmove".to_owned(),
                bytes: Some(16)
            }]
        );
        source.push_str(&rendered.code);
        checks.push_str(&format!("for(unsigned i=0;i<40;++i) a[i]=b[i]=(unsigned char)(i+seed); {name}(a+8,a); memmove(b+8,b,16); if(memcmp(a,b,sizeof a)) return 2;\n"));
    }
    source.push_str(&format!("int main(void) {{ unsigned char a[40], b[40]; for (int seed=0; seed<256; ++seed) {{ {checks} }} return 0; }}\n"));
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/fill-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("fills.c");
    let output = dir.join("fills");
    std::fs::write(&input, &source).unwrap();
    let compiled = std::process::Command::new("cc")
        .args(["-std=c11", "-Werror", "-O2", "-fno-inline"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        std::process::Command::new(output)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn gaps_and_different_bytes_keep_separate_stores() {
    for isa in [Isa::X86_64, Isa::AArch64] {
        let mut ir = fill_ir(isa, "fill", 8, 8, 9);
        for gap in [true, false] {
            if !gap {
                ir.blocks[0].stmts[1] = Stmt::Store {
                    addr: address(4),
                    value: Expr::Const(0xcdcdcdcdcdcdcdcd),
                    width: 8,
                    at: None,
                };
            }
            let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
            assert!(
                !rendered.code.contains("__builtin_memset"),
                "{}",
                rendered.code
            );
            assert!(rendered.inline_functions.is_empty());
        }
    }
}
