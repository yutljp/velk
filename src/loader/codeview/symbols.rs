//! Procedure declarations and fixed storage from `CodeView` symbols.

use super::{
    Data, Procedure, locations,
    records::{Reader, records, u32_at},
    types::{Types, name},
};
use crate::ir::calls::{FunctionSource, TypeSource};
use crate::ir::{AbiIssue, CType, DebugLocal};
use crate::loader::{Image, dwarf::FunctionTypes};

#[derive(Debug)]
struct Variable {
    name: String,
    ty: u32,
    parameter: bool,
    location: Option<(u16, i64)>,
    ranges: usize,
    register: Option<u16>,
}

#[derive(Debug)]
struct Pending {
    addr: u64,
    size: u64,
    name: String,
    ty: u32,
    total: Option<u32>,
    flags: u32,
    variables: Vec<Variable>,
    depth: usize,
    current: Option<usize>,
    inlined: Option<usize>,
}

pub(super) fn read(data: &mut Data, bytes: &[u8], sections: &[(u64, u64)], ids: bool) {
    let mut pending: Option<Pending> = None;
    let mut budget = bytes.len() / 4;
    for (kind, bytes) in records(bytes) {
        let mut reader = Reader(bytes);
        if !matches!(kind, 0x113f..=0x1145)
            && let Some(function) = pending.as_mut()
        {
            function.current = None;
        }
        match kind {
            0x110f | 0x1110 | 0x1146 | 0x1147 => {
                if let Some(function) = pending.take() {
                    finish(data, function, &mut budget);
                }
                if reader.take(12).is_none() {
                    continue;
                }
                let Some(size) = reader.u32() else { continue };
                if reader.take(8).is_none() {
                    continue;
                }
                let (Some(mut ty), Some(offset), Some(segment)) =
                    (reader.u32(), reader.u32(), reader.u16())
                else {
                    continue;
                };
                if reader.take(1).is_none() {
                    continue;
                }
                let Some(text) = reader.name() else { continue };
                let Some((base, length)) = segment
                    .checked_sub(1)
                    .and_then(|i| sections.get(usize::from(i)))
                    .copied()
                else {
                    continue;
                };
                if u64::from(offset).saturating_add(u64::from(size)) > length || size == 0 {
                    continue;
                }
                let Some(addr) = base.checked_add(u64::from(offset)) else {
                    continue;
                };
                if matches!(kind, 0x1146 | 0x1147) {
                    let types = if ids { &data.ids } else { &data.types };
                    ty = match types.record(ty) {
                        Some((0x1601, mut record)) => {
                            if record.u32().is_some() {
                                record.u32().unwrap_or(u32::MAX)
                            } else {
                                u32::MAX
                            }
                        }
                        _ => u32::MAX,
                    };
                }
                pending = Some(Pending {
                    addr,
                    size: u64::from(size),
                    name: text,
                    ty,
                    total: None,
                    flags: 0,
                    variables: Vec::new(),
                    depth: 0,
                    current: None,
                    inlined: None,
                });
            }
            0x0006 | 0x114e | 0x114f => {
                let Some(function) = pending.as_mut() else {
                    continue;
                };
                if function.depth > 0 {
                    if function.inlined == Some(function.depth) {
                        function.inlined = None;
                    }
                    function.depth -= 1;
                } else if let Some(function) = pending.take() {
                    finish(data, function, &mut budget);
                }
            }
            0x1103 | 0x114d | 0x115d => {
                if let Some(function) = pending.as_mut() {
                    function.depth = function.depth.saturating_add(1);
                    if kind != 0x1103 && function.inlined.is_none() {
                        function.inlined = Some(function.depth);
                    }
                }
            }
            0x1012 => {
                let Some(function) = pending.as_mut() else {
                    continue;
                };
                let Some(flags) = u32_at(bytes, 22) else {
                    function.total = None;
                    continue;
                };
                function.total = reader.u32();
                function.flags = flags;
            }
            0x113e => {
                let Some(function) = pending.as_mut() else {
                    continue;
                };
                if function.inlined.is_some() {
                    continue;
                }
                let (Some(ty), Some(flags), Some(text)) =
                    (reader.u32(), reader.u16(), reader.name())
                else {
                    continue;
                };
                function.variables.push(Variable {
                    name: text,
                    ty,
                    parameter: flags & 1 != 0 && function.depth == 0,
                    location: None,
                    ranges: if flags & !3 == 0 { 0 } else { 2 },
                    register: None,
                });
                function.current = Some(function.variables.len() - 1);
            }
            0x1141 => {
                let Some(function) = pending.as_mut() else {
                    continue;
                };
                let Some(variable) = function
                    .current
                    .and_then(|index| function.variables.get_mut(index))
                else {
                    continue;
                };
                variable.ranges += 1;
                variable.location = None;
                variable.register = None;
                let (Some(register), Some(attributes), Some(start), Some(segment), Some(length)) = (
                    reader.u16(),
                    reader.u16(),
                    reader.u32(),
                    reader.u16(),
                    reader.u16(),
                ) else {
                    continue;
                };
                if attributes != 0 || !reader.0.is_empty() || variable.ranges != 1 {
                    continue;
                }
                let Some((base, _)) = segment
                    .checked_sub(1)
                    .and_then(|i| sections.get(usize::from(i)))
                else {
                    continue;
                };
                if base.checked_add(u64::from(start)) != Some(function.addr)
                    || u64::from(length) < function.size
                {
                    continue;
                }
                variable.register = register_index(register);
            }
            0x1142 | 0x1144 => {
                let Some(function) = pending.as_mut() else {
                    continue;
                };
                let flags = function.flags;
                let size = function.size;
                let Some(variable) = function
                    .current
                    .and_then(|index| function.variables.get_mut(index))
                else {
                    continue;
                };
                variable.ranges += 1;
                variable.location = None;
                variable.register = None;
                let Some(offset) = reader.u32().map(|n| i64::from(n as i32)) else {
                    continue;
                };
                let base = (flags >> if variable.parameter { 16 } else { 14 }) & 3;
                let register = match base {
                    1 => 335,
                    2 => 334,
                    _ => continue,
                };
                if kind == 0x1142 {
                    let (Some(start), Some(segment), Some(length)) =
                        (reader.u32(), reader.u16(), reader.u16())
                    else {
                        continue;
                    };
                    if !reader.0.is_empty() {
                        continue;
                    }
                    let Some((base, _)) = segment
                        .checked_sub(1)
                        .and_then(|i| sections.get(usize::from(i)))
                    else {
                        continue;
                    };
                    let Some(start) = base.checked_add(u64::from(start)) else {
                        continue;
                    };
                    // A short lifetime cannot name a slot for the entire function.
                    if start < function.addr
                        || start > function.addr.saturating_add(128)
                        || start.saturating_add(u64::from(length))
                            < function.addr.saturating_add(size)
                    {
                        continue;
                    }
                }
                if variable.ranges == 1 {
                    variable.location = Some((register, offset));
                }
            }
            0x1111 | 0x110b => {
                let Some(function) = pending.as_mut() else {
                    continue;
                };
                let (Some(offset), Some(ty)) = (reader.u32(), reader.u32()) else {
                    continue;
                };
                let register = if kind == 0x1111 {
                    reader.u16()
                } else {
                    Some(334)
                };
                let (Some(register), Some(text)) = (register, reader.name()) else {
                    continue;
                };
                function.variables.push(Variable {
                    name: text,
                    ty,
                    parameter: false,
                    location: Some((register, i64::from(offset as i32))),
                    ranges: 1,
                    register: None,
                });
            }
            0x113f..=0x1145 => {
                if let Some(function) = pending.as_mut()
                    && let Some(variable) = function
                        .current
                        .and_then(|index| function.variables.get_mut(index))
                {
                    variable.ranges += 1;
                    variable.location = None;
                    variable.register = None;
                }
            }
            _ => {}
        }
    }
    if let Some(function) = pending {
        finish(data, function, &mut budget);
    }
}

fn register_index(register: u16) -> Option<u16> {
    match register {
        17..=24 => Some(register - 17),
        328..=335 => [0, 3, 1, 2, 6, 7, 5, 4]
            .get(usize::from(register - 328))
            .copied(),
        336..=343 => Some(register - 328),
        154..=161 => Some(crate::arch::x86::XMM0 + (register - 154) * 2),
        _ => None,
    }
}

fn source(index: u32) -> TypeSource {
    TypeSource {
        unit: super::SOURCE,
        die: index as usize,
    }
}

fn finish(data: &mut Data, function: Pending, budget: &mut usize) {
    let types = &data.types;
    let signature = types
        .procedure(function.ty)
        .filter(|(_, args, _)| {
            if *budget == 0 || args.len() > *budget {
                return false;
            }
            *budget -= args.len();
            true
        })
        .map(|(ret, args, variadic)| {
            let parameters: Vec<_> = function
                .variables
                .iter()
                .filter(|var| var.parameter)
                .collect();
            FunctionTypes {
                globals: Vec::new(),
                locals: Vec::new(),
                registers: function
                    .variables
                    .iter()
                    .filter(|var| name(&var.name))
                    .filter_map(|var| var.register.map(|reg| (reg, var.name.clone())))
                    .collect(),
                params: args
                    .iter()
                    .enumerate()
                    .map(|(i, ty)| {
                        (
                            parameters
                                .get(i)
                                .filter(|var| {
                                    parameters.len() == args.len()
                                        && types.spelling(var.ty, 16) == types.spelling(*ty, 16)
                                        && name(&var.name)
                                })
                                .map(|var| var.name.clone()),
                            types.spelling(*ty, 16),
                        )
                    })
                    .collect(),
                ret: types.spelling(ret, 16),
                ret_aggregate_size: aggregate(types, ret),
                param_aggregate_sizes: args.iter().map(|ty| aggregate(types, *ty)).collect(),
                variadic,
                members: Vec::new(),
                definitions: Vec::new(),
                param_layouts: args
                    .iter()
                    .map(|ty| {
                        types
                            .layout_with_budget(*ty, 16, budget)
                            .ok_or(AbiIssue::UnknownLayout)
                    })
                    .collect(),
                ret_layout: if ret == 3 {
                    Ok(None)
                } else {
                    types
                        .layout_with_budget(ret, 16, budget)
                        .map(Some)
                        .ok_or(AbiIssue::UnknownLayout)
                },
                abi_profile: Ok(crate::ir::AbiProfile::Win64),
                source: FunctionSource {
                    function: TypeSource {
                        unit: super::SOURCE,
                        die: data.procedures.len(),
                    },
                    parameters: args.iter().map(|ty| Some(source(*ty))).collect(),
                    result: (ret != 3).then(|| source(ret)),
                },
            }
        });
    data.procedures.push(Procedure {
        addr: function.addr,
        size: function.size,
        name: function.name,
        signature,
        total: function.total,
        variables: function
            .variables
            .into_iter()
            .filter_map(|var| {
                if !name(&var.name) {
                    return None;
                }
                var.location
                    .map(|(register, offset)| (var.name, var.ty, register, offset))
            })
            .collect(),
    });
}

fn aggregate(types: &Types, index: u32) -> Option<u64> {
    match types.spelling(index, 16) {
        Some(CType::Named(text)) if text.starts_with("struct ") => {
            types.layout(index, 16).map(|layout| layout.size)
        }
        _ => None,
    }
}

pub(super) fn locals(data: &Data, image: &Image, procedure: &Procedure) -> Vec<DebugLocal> {
    let Some(total) = procedure.total else {
        return Vec::new();
    };
    let Some((sp, bp)) = locations::frame(image, procedure.addr, procedure.size, total) else {
        return Vec::new();
    };
    procedure
        .variables
        .iter()
        .filter_map(|(name, ty, register, offset)| {
            let base = match register {
                335 => Some(sp),
                334 => bp,
                _ => None,
            };
            let Some(slot) = base.and_then(|base| base.checked_add(*offset)) else {
                return None;
            };
            let (Some(ty), Some(layout)) =
                (data.types.spelling(*ty, 16), data.types.layout(*ty, 16))
            else {
                return None;
            };
            Some(DebugLocal {
                name: name.clone(),
                ty,
                slot,
                size: layout.size,
            })
        })
        .collect()
}
