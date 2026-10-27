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
            },
            Stmt::Store {
                addr: address(offset),
                value: Expr::Const(0xabababababababab),
                width: second,
            },
            Stmt::Ret {
                value: Expr::Const(0),
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
            });
        }
        for offset in [0, 8] {
            statements.push(Stmt::Store {
                addr: address(offset),
                value: Expr::reg(crate::ir::VARIABLE_BASE + offset as u16, 64),
                width: 8,
            });
        }
        statements.push(Stmt::Ret {
            value: Expr::Const(0),
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
