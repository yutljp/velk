//! Analysis dependencies and parameter evidence for call declarations.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::Analysis;
use crate::ir::{CType, Expr, Stmt};
use crate::loader::Image;

pub(super) fn callers(image: &Image, root: &Analysis) -> BTreeSet<u64> {
    if image.go {
        return BTreeSet::new();
    }
    let mut targets = BTreeSet::from([root.ir.addr]);
    let mut operands: Vec<_> = root
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(Stmt::operands)
        .collect();
    while let Some(value) = operands.pop() {
        operands.extend(crate::ir::visit::children(value));
        if let Expr::Const(address) = value
            && image.functions.contains_key(address)
        {
            targets.insert(*address);
        }
    }
    for stmt in root.ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Call {
            target: Some(target),
            through: None,
            ..
        } = stmt
        {
            targets.insert(*target);
        }
    }
    let mut addresses = BTreeSet::new();
    for target in targets {
        if unknown_import(image, target) {
            addresses.extend(crate::analysis::results::callers(image, target));
            continue;
        }
        if target != root.ir.addr
            && image
                .functions
                .get(&target)
                .is_some_and(|function| !function.sources.contains(&crate::loader::NameSource::Plt))
        {
            addresses.insert(target);
        }
        let summary = crate::analysis::summary::summary(image, target);
        if summary.arity.is_some_and(|count| count != 0)
            || summary.floats.is_some_and(|count| count != 0)
            || summary.stack != 0
            || !image.functions.contains_key(&target)
            || image.functions[&target]
                .sources
                .contains(&crate::loader::NameSource::Plt)
        {
            continue;
        }
        addresses.insert(target);
        addresses.extend(crate::analysis::results::callers(image, target));
    }
    addresses
}

pub(super) fn recover(image: &Image, functions: &mut [Analysis]) {
    if image.go {
        return;
    }
    let available: BTreeSet<_> = functions.iter().map(|analysis| analysis.ir.addr).collect();
    let imports = import_parameters(image, functions, &available);
    let targets: BTreeSet<_> = functions
        .iter()
        .filter_map(|analysis| {
            let ir = &analysis.ir;
            (ir.params.is_empty()
                && ir.stack_params.is_empty()
                && !ir.variadic
                && ir.declared_signature.is_none()
                && crate::analysis::results::callers(image, ir.addr)
                    .iter()
                    .all(|address| available.contains(address))
                && !image.functions.get(&ir.addr).is_some_and(|function| {
                    function.sources.contains(&crate::loader::NameSource::Plt)
                }))
            .then_some(ir.addr)
        })
        .collect();
    let mut parameters: BTreeMap<u64, Vec<CType>> = BTreeMap::new();
    for analysis in functions.iter() {
        for stmt in analysis.ir.blocks.iter().flat_map(|block| &block.stmts) {
            let Stmt::Call {
                target: Some(target),
                through: None,
                args: Some(args),
                ..
            } = stmt
            else {
                continue;
            };
            if !targets.contains(target) {
                continue;
            }
            let types = parameters.entry(*target).or_default();
            for (position, arg) in args.iter().enumerate() {
                let ty = argument_type(image, analysis, arg);
                if let Some(previous) = types.get_mut(position) {
                    *previous = merge(previous, &ty);
                } else {
                    types.push(ty);
                }
            }
        }
    }
    let returns: BTreeMap<_, _> = functions
        .iter()
        .map(|analysis| (analysis.ir.addr, analysis.ir.ret_type.clone()))
        .collect();
    for analysis in functions {
        analysis.import_parameters.extend(imports.clone());
        for (&target, types) in &parameters {
            let Some(callee) = returns.get(&target) else {
                continue;
            };
            analysis.unused_parameters.insert(
                target,
                crate::analysis::prototypes::Prototype {
                    params: types.clone(),
                    ret: callee.clone(),
                    variadic: false,
                    format: None,
                    scans: false,
                },
            );
        }
    }
}

fn unknown_import(image: &Image, target: u64) -> bool {
    if image.isa == crate::loader::Isa::I386
        && matches!(
            image.format,
            crate::loader::Format::Pe | crate::loader::Format::Coff
        )
    {
        return false;
    }
    let Some(function) = image.functions.get(&target) else {
        return false;
    };
    function.sources.contains(&crate::loader::NameSource::Plt)
        && function
            .name
            .as_ref()
            .is_some_and(|name| crate::analysis::prototypes::for_image(name, image).is_none())
}

fn import_parameters(
    image: &Image,
    functions: &[Analysis],
    available: &BTreeSet<u64>,
) -> BTreeMap<u64, Vec<CType>> {
    let mut found: BTreeMap<u64, Option<Vec<CType>>> = BTreeMap::new();
    let mut seen: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for analysis in functions {
        for stmt in analysis.ir.blocks.iter().flat_map(|block| &block.stmts) {
            let Stmt::Call {
                target: Some(target),
                through: None,
                args,
                ..
            } = stmt
            else {
                continue;
            };
            if !unknown_import(image, *target)
                || !crate::analysis::results::callers(image, *target)
                    .iter()
                    .all(|caller| available.contains(caller))
            {
                continue;
            }
            seen.entry(*target).or_default().insert(analysis.ir.addr);
            let types = args.as_ref().and_then(|args| {
                args.iter()
                    .map(|arg| import_argument_type(image, analysis, arg, Some(stmt)))
                    .collect()
            });
            found
                .entry(*target)
                .and_modify(|previous| {
                    if *previous != types {
                        *previous = None;
                    }
                })
                .or_insert(types);
        }
    }
    found
        .into_iter()
        .filter_map(|(target, types)| {
            let callers = crate::analysis::results::callers(image, target);
            if !callers.iter().all(|caller| {
                seen.get(&target)
                    .is_some_and(|addresses| addresses.contains(caller))
            }) {
                return None;
            }
            types.map(|types| (target, types))
        })
        .collect()
}

fn import_argument_type(
    image: &Image,
    analysis: &Analysis,
    arg: &Expr,
    call: Option<&Stmt>,
) -> Option<CType> {
    match arg {
        Expr::Const(value)
            if analysis.references.iter().any(|reference| {
                reference.addr == *value && reference.pointer.is_none() && reference.text.is_some()
            }) =>
        {
            Some(CType::pointer_to(CType::Named("char".into())))
        }
        Expr::Const(value)
            if image.section_at(*value).is_none()
                && !image.functions.contains_key(value)
                && !image.data_symbols.contains_key(value)
                && !image.imports.contains_key(value) =>
        {
            if *value <= i32::MAX as u64 || (*value >= 1 << 63 && value.wrapping_neg() < 1 << 31) {
                Some(CType::I32)
            } else if *value <= u32::MAX as u64 {
                Some(CType::U32)
            } else if *value <= i64::MAX as u64 {
                Some(CType::I64)
            } else {
                Some(CType::U64)
            }
        }
        Expr::Reg { index, width: 64 }
            if !analysis
                .ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| {
                    !call.is_some_and(|call| std::ptr::eq(call, stmt))
                        && crate::ir::visit::statement_registers(stmt)
                            .0
                            .contains(index)
                }) =>
        {
            analysis
                .ir
                .params
                .iter()
                .find(|param| param.index == *index)
                .and_then(|param| match &param.ty {
                    CType::Int { bytes: 1 | 2, .. } => Some(CType::I32),
                    CType::Int { bytes: 4 | 8, .. } => Some(param.ty.clone()),
                    CType::Named(name) if name == "_Bool" => Some(CType::I32),
                    CType::Pointer(inner)
                        if match inner.as_ref() {
                            CType::Void | CType::Int { .. } => true,
                            CType::Named(name) => matches!(
                                name.as_str(),
                                "char" | "const char" | "void" | "const void"
                            ),
                            _ => false,
                        } =>
                    {
                        Some(param.ty.clone())
                    }
                    _ => None,
                })
        }
        _ => None,
    }
}

fn argument_type(image: &Image, analysis: &Analysis, value: &Expr) -> CType {
    let ir = &analysis.ir;
    if let Expr::Const(address) = value
        && analysis.references.iter().any(|reference| {
            reference.addr == *address && reference.pointer.is_none() && reference.text.is_some()
        })
    {
        return CType::pointer_to(CType::Named("const void".into()));
    }
    if let Expr::Const(address) = value {
        if *address != 0
            && image
                .functions
                .get(address)
                .is_some_and(|function| function.name.is_some())
            || image.data_symbols.contains_key(address)
            || image.imports.contains_key(address)
        {
            return CType::pointer_to(CType::Named("const void".into()));
        }
        if image.section_at(*address).is_some() {
            return CType::Named("_Bool".into());
        }
    }
    if let Expr::Reg { index, .. } = value {
        if *index == crate::arch::stack_pointer(ir.isa) {
            return CType::Named("_Bool".into());
        }
        if let Some(ty) = ir.value_types.get(index) {
            return ty.clone();
        }
        if let Some(param) = ir.params.iter().find(|param| param.index == *index) {
            return param.ty.clone();
        }
        if ir.pointer_values.contains(index) {
            return CType::pointer_to(CType::Named("const void".into()));
        }
    }
    if let Expr::Bin {
        op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
        lhs,
        ..
    } = value
    {
        let ty = argument_type(image, analysis, lhs);
        if ty.is_pointer() {
            return CType::pointer_to(CType::Named("const void".into()));
        }
        if ty == CType::Named("_Bool".into()) {
            return ty;
        }
    }
    if let Expr::Select { then, els, .. } = value {
        return merge(
            &argument_type(image, analysis, then),
            &argument_type(image, analysis, els),
        );
    }
    CType::U64
}

fn merge(left: &CType, right: &CType) -> CType {
    if left == &CType::Named("_Bool".into()) || right == &CType::Named("_Bool".into()) {
        return CType::Named("_Bool".into());
    }
    if left == right {
        return left.clone();
    }
    if left.is_pointer() && right.is_pointer() {
        return CType::pointer_to(CType::Named("const void".into()));
    }
    if left.integer().is_some() && right.integer().is_some() {
        return CType::U64;
    }
    if !left.is_pointer() && !right.is_pointer() && (left.is_sse_float() || right.is_sse_float()) {
        return CType::Named("double".into());
    }
    // Boolean conversion accepts both pointers and arithmetic values. These
    // parameters are never read, so the conversion cannot change the body.
    CType::Named("_Bool".into())
}

#[cfg(test)]
mod tests;
