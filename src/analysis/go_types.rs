//! Types proven by Go runtime allocation descriptors.

use std::collections::{BTreeMap, HashMap};

use crate::ir::{CType, Expr, FunctionIr, Stmt};
use crate::loader::Image;

pub(super) fn apply(ir: &mut FunctionIr, image: &Image) {
    if !image.go {
        return;
    }
    let types = image
        .go_types
        .get_or_init(|| crate::loader::go::types::read(image));
    // Only a variable with exactly one definition can keep an allocation's type
    // throughout the function, including across branches and loops.
    let mut writes = HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for index in crate::ir::visit::statement_registers(stmt).0 {
            *writes.entry(index).or_default() += 1;
        }
    }
    let mut layouts = BTreeMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let Stmt::Call {
            target: Some(target),
            args: Some(args),
            ..
        } = stmt
        else {
            continue;
        };
        if image
            .functions
            .get(target)
            .and_then(|function| function.name.as_deref())
            != Some("runtime.newobject")
        {
            continue;
        }
        let (Some(Expr::Const(descriptor)), Some(output)) =
            (args.first(), stmt.primary_call_output())
        else {
            continue;
        };
        if output.dest.width != 64 || writes.get(&output.dest.index) != Some(&1) {
            continue;
        }
        let Some(layout) = types.layout(image, *descriptor) else {
            continue;
        };
        let ty = CType::pointer_to(CType::Named(layout.definition.name.clone()));
        ir.value_types.insert(output.dest.index, ty);
        ir.pointer_values.push(output.dest.index);
        layouts.insert(*descriptor, layout);
    }
    for layout in layouts.into_values() {
        ir.members.extend(layout.members);
        ir.definitions.push(layout.definition);
    }
    if ir
        .definitions
        .iter()
        .any(|definition| definition.name.starts_with("struct go_"))
    {
        for definition in crate::loader::go::types::shapes() {
            if !ir
                .definitions
                .iter()
                .any(|existing| existing.name == definition.name)
            {
                ir.definitions.push(definition);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CallKind, CallOutput, Convention, RegRef, VARIABLE_BASE};
    use crate::loader::Isa;

    #[test]
    fn allocated_runtime_record_fields_compile_and_preserve_bits() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go_stripped");
        let image = crate::loader::load(&path).unwrap();
        let types = crate::loader::go::types::read(&image);
        let (descriptor, layout, member) = types
            .layouts
            .iter()
            .find_map(|(addr, layout)| {
                layout
                    .members
                    .iter()
                    .find(|member| {
                        member.width == 8
                            && member.ty.integer().is_some()
                            && !member.name.contains('.')
                    })
                    .map(|member| (*addr, layout, member))
            })
            .expect("a scalar field in a runtime record");
        let target = image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some("runtime.newobject"))
            .unwrap()
            .addr;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    kind: CallKind::Invoke,
                    target: Some(target),
                    through: None,
                    convention: Convention::GoAmd64,
                    args: Some(vec![Expr::Const(descriptor)]),
                    floats_named: true,
                    abi: None,
                    outputs: vec![CallOutput {
                        register: 0,
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                    }],
                    clobbers: Some([0].into_iter().collect()),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::bin(
                            crate::ir::BinOp::Add,
                            Expr::reg(VARIABLE_BASE, 64),
                            Expr::Const(member.offset as u64),
                        )),
                        width: 8,
                        signed: false,
                    },
                },
            ],
        );
        ir.name = Some("read_record".into());
        ir.ret_type = CType::U64;
        ir.convention = Convention::GoAmd64;
        apply(&mut ir, &image);
        assert_eq!(
            ir.value_types[&VARIABLE_BASE],
            CType::pointer_to(CType::Named(layout.definition.name.clone()))
        );
        let symbols = crate::render::Symbols {
            functions: [(target, "runtime_newobject".into())].into(),
            function_returns: [(target, CType::pointer_to(CType::Void))].into(),
            ..Default::default()
        };
        let code = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains(&format!("->{}", member.name)), "{code}");
        let source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n_Alignas(8) static uint8_t storage[{}];\nstatic void *runtime_newobject(uint64_t t) {{ (void)t; return storage; }}\n{code}\nint main(void) {{ for (uint64_t i = 0; i < 100; ++i) {{ uint64_t value = i * UINT64_C(0xfedcba987654321); memcpy(storage + {}, &value, 8); if (read_record() != value) return 1; }} return 0; }}\n",
            layout.definition.size, member.offset
        );
        let scratch = std::env::temp_dir().join(format!("velk-go-types-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let input = scratch.join("record.c");
        std::fs::write(&input, &source).unwrap();
        for level in ["-O0", "-O2"] {
            let executable = scratch.join(format!("record{level}"));
            let output = std::process::Command::new("clang")
                .args([
                    "-fwrapv",
                    "-fno-strict-aliasing",
                    "-Werror=implicit-function-declaration",
                    level,
                ])
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
