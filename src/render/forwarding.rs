//! Variadic import thunks preserve all arguments through a library counterpart.

use crate::ir::{CType, CallKind, Expr, FunctionIr, Stmt};

use super::{Symbols, declaration, sanitize};

pub(super) fn render(ir: &FunctionIr, symbols: &Symbols) -> Option<String> {
    let [block] = ir.blocks.as_slice() else {
        return None;
    };
    let [
        Stmt::Call {
            kind: CallKind::Tail,
            through: Some(Expr::Load { addr, .. }),
            args: None,
            ..
        },
        Stmt::Ret { .. },
    ] = block.stmts.as_slice()
    else {
        return None;
    };
    let Expr::Const(slot) = addr.as_ref() else {
        return None;
    };
    let Some(import) = symbols.import_name(slot) else {
        return None;
    };
    let target = sanitize(import);
    let Some(prototype) = symbols.library_prototypes.get(&target) else {
        return None;
    };
    if !prototype.variadic {
        return None;
    }
    let name = sanitize(
        symbols
            .functions
            .get(&ir.addr)
            .map(String::as_str)
            .unwrap_or(ir.name.as_deref().unwrap_or("function")),
    );
    let mut names = Vec::new();
    let mut params = Vec::new();
    for (position, ty) in prototype.params.iter().enumerate() {
        let name = if prototype.format == Some(position) {
            "format".to_owned()
        } else {
            format!("a{position}")
        };
        params.push(declaration(ty, &name));
        names.push(name);
    }
    params.push("...".to_owned());
    let signature = declaration(&prototype.ret, &format!("{name}({})", params.join(", ")));
    let counterpart = crate::analysis::prototypes::va_list_counterpart(&target);
    let (Some((counterpart, header)), Some(last)) = (counterpart, names.last()) else {
        return Some(format!(
            "{signature}; /* Forwards all arguments to {target}. */\n"
        ));
    };
    let mut code = format!("{signature} {{\n    va_list args;\n    va_start(args, {last});\n");
    let arguments = names.join(", ");
    if prototype.ret == CType::Void {
        code.push_str(&format!(
            "    {counterpart}({arguments}, args);\n    va_end(args);\n"
        ));
    } else {
        code.push_str(&format!(
            "    {} = {counterpart}({arguments}, args);\n    va_end(args);\n    return result;\n",
            declaration(&prototype.ret, "result")
        ));
    }
    code.push_str("}\n");
    Some(format!(
        "{}{code}",
        super::prelude::section(&format!("#include <stdarg.h>\n#include <{header}>\n"))
    ))
}

#[cfg(test)]
mod tests {
    use crate::loader::{Function, Image, Isa};

    #[test]
    fn machine_import_tail_jumps_use_the_variadic_prototype_on_each_architecture() {
        for (isa, bytes) in [
            (Isa::I386, vec![0xff, 0x25, 0x00, 0x20, 0x00, 0x00]),
            (Isa::X86_64, vec![0xff, 0x25, 0xfa, 0x0f, 0x00, 0x00]),
            (
                Isa::AArch64,
                vec![
                    0x10, 0x00, 0x00, 0xb0, 0x10, 0x02, 0x40, 0xf9, 0x00, 0x02, 0x1f, 0xd6,
                ],
            ),
        ] {
            let function = Function {
                addr: 0x1000,
                size: Some(bytes.len() as u64),
                size_estimated: false,
                name: Some("forward_import".into()),
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            };
            let mut image = Image::from_code(isa, function.addr, bytes);
            image.imports.insert(0x2000, "printf".into());
            image.functions.insert(function.addr, function.clone());
            let analysis = crate::analysis::analyze(&image, &function, None)
                .expect("a variadic import tail jump must be available");
            let code = super::super::render(
                &analysis.ir,
                &analysis.references,
                &super::super::callee_names(&image),
                &[],
            );
            assert!(
                code.contains("int forward_import(const char *format, ...)"),
                "{isa}: {code}"
            );
            assert!(code.contains("vprintf(format, args)"), "{isa}: {code}");
            image.imports.insert(0x2000, "open".into());
            let analysis = crate::analysis::analyze(&image, &function, None)
                .expect("an import thunk without a counterpart must be available");
            let code = super::super::render(
                &analysis.ir,
                &analysis.references,
                &super::super::callee_names(&image),
                &[],
            );
            assert!(
                code.contains("int forward_import(const char *a0, int a1, ...);"),
                "{isa}: {code}"
            );
            assert!(
                code.contains("Forwards all arguments to open"),
                "{isa}: {code}"
            );
        }
    }
}
