//! Conversion and assignment of call results.

use std::collections::HashSet;

use super::{expression, identity_output, only_word, return_type, scalar_fusion, scalar_output};
use crate::ir::{CallOutput, Expr, Stmt, VARIABLE_BASE};
use crate::render::expr::Ctx;

pub(super) fn precision(ty: Option<&crate::ir::CType>) -> Option<crate::ir::Precision> {
    let Some(ty) = ty else { return None };
    match ty.to_string().as_str() {
        "float" => Some(crate::ir::Precision::Single),
        "double" => Some(crate::ir::Precision::Double),
        _ => None,
    }
}

enum ValueType {
    Integer {
        bits: u32,
        signed: bool,
        zero_extended: bool,
    },
    Pointer(String),
    Float(crate::ir::Precision),
}

impl ValueType {
    fn returned(call: &Stmt, ctx: &Ctx<'_>) -> Self {
        let ty = return_type(call, ctx);
        if let Some(precision) = precision(ty) {
            Self::Float(precision)
        } else if let Some(ty) = ty.filter(|ty| ty.is_pointer()) {
            Self::Pointer(ty.to_string().trim_end().to_owned())
        } else {
            let (bits, signed) = ty
                .and_then(crate::ir::CType::integer)
                .unwrap_or((64, false));
            Self::Integer {
                bits,
                signed,
                zero_extended: ctx.virtual_tables.signature(call, ctx).is_some()
                    || matches!(call, Stmt::Call { target: Some(target), through: None, .. } if ctx.callee_signatures.contains_key(target) || *target == ctx.ir.addr),
            }
        }
    }

    fn register(index: u16, ctx: &Ctx<'_>) -> Self {
        if let Some(precision) = ctx.floats.get(&index) {
            Self::Float(*precision)
        } else if let Some(ty) = ctx.pointer_types.get(&index) {
            Self::Pointer(ty.clone())
        } else {
            let declared = ctx.declared.get(&index);
            Self::Integer {
                bits: declared.map_or(64, |ty| ty.bits),
                signed: declared.is_some_and(|ty| ty.signed),
                zero_extended: false,
            }
        }
    }
}

fn bits(text: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Float(precision) => crate::render::expr::float_bits(text, *precision).text,
        ValueType::Pointer(_) => format!("(uint64_t){text}"),
        ValueType::Integer { .. } => text,
    }
}

fn projected(value: String, width: u8, ty: &ValueType) -> String {
    let value = bits(value, ty);
    if let ValueType::Integer {
        bits: 32,
        signed: true,
        zero_extended: true,
    } = ty
        && width == 64
    {
        return format!("(uint32_t)({value})");
    }
    if matches!(ty, ValueType::Integer { bits, signed: false, .. } if *bits == u32::from(width)) {
        return value;
    }
    match width {
        64 => value,
        width @ (8 | 16 | 32) => format!("({})({value})", crate::render::type_of(width / 8, false)),
        width => format!(
            "((uint64_t)({value}) & 0x{:x})",
            crate::ir::semantics::mask(u32::from(width))
        ),
    }
}

fn assigned_value(output: &CallOutput, value: String, ty: &ValueType, ctx: &Ctx<'_>) -> String {
    if let ValueType::Integer { bits, signed, .. } = ty
        && u32::from(output.dest.width) >= *bits
        && ctx.declared.get(&output.dest.index).is_some_and(|stored| {
            stored.integer && stored.bits == *bits && stored.signed == *signed
        })
    {
        return value;
    }
    if let ValueType::Float(precision) = ty
        && output.dest.width >= precision.bits()
        && ctx.floats.get(&output.dest.index) == Some(precision)
    {
        return value;
    }
    if output.dest.width == 64
        && let ValueType::Pointer(source) = ty
        && let Some(target) = ctx.pointer_types.get(&output.dest.index)
    {
        return if source == target {
            value
        } else {
            format!("({target})({value})")
        };
    }
    let value = projected(value, output.dest.width, ty);
    if let Some(precision) = ctx.floats.get(&output.dest.index) {
        crate::render::expr::bits_to_float(
            crate::render::int::Printed::opaque(value, 13),
            *precision,
        )
    } else if let Some(target) = ctx.pointer_types.get(&output.dest.index) {
        if matches!(output.dest.width, 8 | 16 | 32)
            || matches!(ty, ValueType::Integer { bits, .. } if *bits < 64)
            || matches!(ty, ValueType::Float(crate::ir::Precision::Single))
        {
            format!("({target})(uintptr_t)({value})")
        } else {
            format!("({target})({value})")
        }
    } else {
        value
    }
}

fn render_assignment(output: &CallOutput, value: String, ty: &ValueType, ctx: &Ctx<'_>) -> String {
    let value = assigned_value(output, value, ty, ctx);
    format!(
        "{} = {value};",
        ctx.register(output.dest.index, output.dest.width)
    )
}

pub(in crate::render) fn captured(call: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
    let Some(dest) = scalar_fusion(call, ctx) else {
        return None;
    };
    if ctx.floats.contains_key(&dest.index) {
        return None;
    }
    let Some(output) = scalar_output(call, ctx) else {
        return None;
    };
    let value = expression(call, ctx);
    let ty = ValueType::returned(call, ctx);
    if let Some(declared) = ctx.declared.get(&dest.index)
        && declared.integer
        && (declared.bits < 64 || dest.width < 64)
    {
        let value = if declared.bits <= u32::from(dest.width) {
            bits(value, &ty)
        } else {
            projected(value, dest.width, &ty)
        };
        if u32::from(dest.width) >= declared.bits
            && matches!(ty, ValueType::Integer { bits, signed, .. } if bits == declared.bits && signed == declared.signed)
        {
            return Some(value);
        }
        return Some(format!(
            "({})({value})",
            crate::render::type_of((declared.bits / 8) as u8, declared.signed)
        ));
    }
    let value = assigned_value(output, value, &ty, ctx);
    // Substitution must keep the integer promotion supplied by the temporary.
    if let Some(declared) = ctx.declared.get(&dest.index)
        && declared.integer
        && declared.bits == 64
        && return_type(call, ctx)
            .and_then(crate::ir::CType::integer)
            .is_none_or(|(bits, signed)| bits != declared.bits || signed != declared.signed)
    {
        return Some(format!(
            "({})({value})",
            crate::render::type_of(8, declared.signed)
        ));
    }
    Some(value)
}

pub(in crate::render) fn returned(call: &Stmt, value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    let Some(dest) = scalar_fusion(call, ctx) else {
        return None;
    };
    if let Expr::Reg { index, width } = value
        && *index == dest.index
        && let Some(returned) = ctx.returned
        && returned.integer
        && returned.bits == 32
        && u32::from(*width) >= returned.bits
        && *width <= dest.width
        && ctx
            .declared
            .get(index)
            .is_some_and(|stored| stored.integer && stored.bits >= returned.bits)
    {
        let value = bits(expression(call, ctx), &ValueType::returned(call, ctx));
        return Some(format!("return {value};"));
    }
    if *value != Expr::reg(dest.index, dest.width) || ctx.void_return || ctx.float_return.is_some()
    {
        return None;
    }
    if dest.width == 64
        && let Some(pointer) = &ctx.return_pointer_type
        && ctx.pointer_types.get(&dest.index) == Some(pointer)
    {
        let Some(value) = captured(call, ctx) else {
            return None;
        };
        return Some(format!("return {value};"));
    }
    if let (Some(returned), Some(stored)) = (ctx.returned, ctx.declared.get(&dest.index))
        && returned.integer
        && stored.integer
        && matches!(returned.bits, 32 | 64)
        && u32::from(dest.width) >= returned.bits
        && stored.bits >= returned.bits
    {
        let value = expression(call, ctx);
        let ty = ValueType::returned(call, ctx);
        let value = if returned.bits == 64 {
            projected(value, 64, &ty)
        } else {
            bits(value, &ty)
        };
        return Some(format!("return {value};"));
    }
    if let (Some(returned), Some(stored)) = (ctx.returned, ctx.declared.get(&dest.index))
        && returned.integer
        && stored.integer
        && matches!(returned.bits, 32 | 64)
        && dest.width < 64
        && stored.bits >= u32::from(dest.width)
    {
        return Some(format!(
            "return {};",
            projected(
                expression(call, ctx),
                dest.width,
                &ValueType::returned(call, ctx)
            )
        ));
    }
    let text = crate::render::returned(value, ctx);
    let name = ctx.register(dest.index, dest.width);
    let Some(at) = only_word(&text, &name) else {
        return None;
    };
    let Some(value) = captured(call, ctx) else {
        return None;
    };
    Some(format!(
        "return {}({value}){};",
        &text[..at],
        &text[at + name.len()..]
    ))
}

pub(in crate::render) fn render(call: &Stmt, ctx: &Ctx<'_>) -> String {
    let used: Vec<_> = call
        .call_outputs()
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            ctx.call_outputs.used(call, output) && !identity_output(call, output, ctx)
        })
        .collect();
    let void = return_type(call, ctx) == Some(&crate::ir::CType::Void);
    let undefined =
        crate::render::render_value(&Expr::apply(crate::ir::Operation::Undefined, vec![]), ctx);
    let text = expression(call, ctx);
    if used.is_empty() {
        return format!("{text};");
    }
    let scalar = scalar_output(call, ctx);
    let preserved = call.preserved_output_sources();
    let scalar_type = ValueType::returned(call, ctx);
    if let [(index, output)] = used.as_slice()
        && scalar == Some(*output)
        && !preserved.iter().any(|(preserved, _)| preserved == index)
    {
        return render_assignment(output, text, &scalar_type, ctx);
    }
    let (_, mut reads) = crate::ir::visit::statement_registers(call);
    reads.extend(
        call.call_outputs()
            .iter()
            .filter_map(|output| (scalar != Some(output)).then_some(output.register)),
    );
    let mut destinations = HashSet::new();
    if used.iter().all(|(_, output)| {
        output.dest.index >= VARIABLE_BASE
            && !ctx
                .declared
                .get(&output.dest.index)
                .is_some_and(|ty| ty.param)
            && destinations.insert(output.dest.index)
            && !reads.contains(&output.dest.index)
    }) {
        let primary = scalar.filter(|output| {
            used.iter()
                .any(|(index, used)| used == output && !preserved.iter().any(|(at, _)| at == index))
        });
        let mut lines = match primary {
            Some(output) => vec![render_assignment(output, text, &scalar_type, ctx)],
            None => vec![format!("{text};")],
        };
        for (index, output) in &used {
            if primary == Some(*output) {
                continue;
            }
            let (source, ty) = match preserved.iter().find(|(at, _)| at == index) {
                Some((_, source)) if ctx.names.contains_key(source) => {
                    (ctx.register(*source, 64), ValueType::register(*source, ctx))
                }
                _ if void && !preserved.iter().any(|(at, _)| at == index) => (
                    undefined.clone(),
                    ValueType::Integer {
                        bits: 64,
                        signed: false,
                        zero_extended: false,
                    },
                ),
                _ => (
                    ctx.call_outputs.sources[&output.register].clone(),
                    ValueType::Integer {
                        bits: 64,
                        signed: false,
                        zero_extended: false,
                    },
                ),
            };
            lines.push(format!(
                "{}{}",
                render_assignment(output, source, &ty, ctx),
                if void || preserved.iter().any(|(at, _)| at == index) {
                    ""
                } else {
                    " /* also returned by the call */"
                },
            ));
        }
        return lines.join("\n");
    }
    let temporary = &ctx.call_outputs.temporary;
    ctx.call_outputs
        .snapshot_sizes
        .borrow_mut()
        .insert(used.len());
    let mut lines = vec![
        "{".to_owned(),
        format!("    uint64_t {temporary}[{}];", used.len()),
    ];
    for (at, (index, _)) in used.iter().enumerate() {
        if let Some((_, source)) = preserved.iter().find(|(preserved, _)| preserved == index) {
            let value = match ctx.names.get(source) {
                Some(_) => bits(
                    ctx.register(*source, 64),
                    &ValueType::register(*source, ctx),
                ),
                None => ctx.call_outputs.sources[source].clone(),
            };
            lines.push(format!("    {temporary}[{at}] = {value};"));
        }
    }
    let scalar_at = used.iter().enumerate().find(|(_, (index, output))| {
        scalar == Some(*output) && !preserved.iter().any(|(preserved, _)| preserved == index)
    });
    match scalar_at {
        Some((at, _)) => lines.push(format!(
            "    {temporary}[{at}] = {};",
            bits(text, &scalar_type)
        )),
        None => lines.push(format!("    {text};")),
    }
    for (at, (index, output)) in used.iter().enumerate() {
        if preserved.iter().any(|(preserved, _)| preserved == index) || scalar == Some(*output) {
            continue;
        }
        let (source, comment) = if void {
            (undefined.clone(), "")
        } else {
            (
                ctx.call_outputs.sources[&output.register].clone(),
                " /* also returned by the call */",
            )
        };
        lines.push(format!("    {temporary}[{at}] = {source};{comment}"));
    }
    for (at, (_, output)) in used.iter().enumerate() {
        lines.push(format!(
            "    {}",
            render_assignment(
                output,
                format!("{temporary}[{at}]"),
                &ValueType::Integer {
                    bits: 64,
                    signed: false,
                    zero_extended: false
                },
                ctx
            )
        ));
    }
    lines.push("}".to_owned());
    lines.join("\n")
}
