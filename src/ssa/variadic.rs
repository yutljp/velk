//! Stack arguments of i386 calls with constant format strings.

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::loader::Image;

pub(super) fn recover_i386_arguments(ir: &mut FunctionIr, image: &Image) {
    let mut pending = Vec::new();
    for (block, contents) in ir.blocks.iter().enumerate() {
        let mut call_index = 0;
        for (position, stmt) in contents.stmts.iter().enumerate() {
            if !matches!(stmt, Stmt::Call { .. }) {
                continue;
            }
            let ordinal = call_index;
            call_index += 1;
            let Some(prototype) = crate::analysis::prototypes::called(image, stmt) else {
                continue;
            };
            let Some(format) = prototype.format else {
                continue;
            };
            if !matches!(stmt, Stmt::Call { args: None, .. }) {
                continue;
            }
            pending.push((block, position, ordinal, format, prototype));
        }
    }
    for (block, position, ordinal, format, prototype) in pending {
        let mut candidate = ir.clone();
        let Stmt::Call {
            kind,
            convention,
            args,
            ..
        } = &mut candidate.blocks[block].stmts[position]
        else {
            continue;
        };
        *args = crate::lift::arguments(*kind, *convention, ir.isa, Some(prototype.fixed()), 0);
        crate::passes::frame_slots::settle_i386(&mut candidate);
        crate::passes::memory::forward_stored_values(&mut candidate);
        super::propagate_constants(&mut candidate);
        crate::passes::memory::forward_stored_values(&mut candidate);
        crate::passes::simplify::simplify(&mut candidate);
        let mut calls = candidate.blocks[block]
            .stmts
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Call { .. }));
        let Some(Stmt::Call {
            args: Some(args), ..
        }) = calls.nth(ordinal)
        else {
            continue;
        };
        let Some(Expr::Const(address)) = args.get(format) else {
            continue;
        };
        let Some(text) = super::c_string(image, *address) else {
            continue;
        };
        let conversions = crate::analysis::prototypes::all_conversion_types(&text, prototype.scans);
        if conversions
            .iter()
            .any(|ty| !ty.is_pointer() && ty.integer().is_none_or(|(bits, _)| bits > 32))
        {
            continue;
        }
        let slots = prototype.fixed().saturating_add(conversions.len());
        let Stmt::Call {
            kind,
            convention,
            args,
            ..
        } = &mut ir.blocks[block].stmts[position]
        else {
            continue;
        };
        *args = crate::lift::arguments(*kind, *convention, ir.isa, Some(slots), 0);
    }
}

#[cfg(test)]
mod tests {
    use crate::loader::{Function, Image, Isa};

    #[test]
    fn unsupported_stack_format_types_do_not_drop_arguments() {
        for format in ["%f", "%Lf", "%lld"] {
            let mut bytes = vec![
                0x6a, 0, 0x6a, 0, 0x68, 0x40, 0x10, 0, 0, 0xff, 0x15, 0, 0x20, 0, 0, 0x83, 0xc4,
                12, 0xc3,
            ];
            let size = bytes.len() as u64;
            bytes.resize(0x40, 0);
            bytes.extend_from_slice(format.as_bytes());
            bytes.push(0);
            let mut image = Image::from_code(Isa::I386, 0x1000, bytes);
            image.imports.insert(0x2000, "printf".into());
            let function = Function {
                addr: 0x1000,
                size: Some(size),
                size_estimated: false,
                name: Some("format_call".into()),
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            };
            image.functions.insert(function.addr, function.clone());
            let analysis = crate::analysis::analyze(&image, &function, None)
                .expect("unknown arguments must remain printable");
            assert!(analysis.ir.blocks.iter().any(|block| {
                block
                    .stmts
                    .iter()
                    .any(|stmt| matches!(stmt, crate::ir::Stmt::Call { args: None, .. }))
            }));
            let text = crate::render::render(&analysis.ir, &[], &Default::default(), &[]);
            assert!(
                text.contains("/* unknown call arguments */"),
                "{format}: {text}"
            );
        }
    }
}
