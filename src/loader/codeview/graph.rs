//! Source identities for debug callee declarations.

use super::SOURCE;
use super::types::Types;
use crate::ir::calls::{CallMember, CallType, TypeGraph, TypeSource};
use crate::ir::{AbiIssue, CType};

fn source(index: u32) -> TypeSource {
    TypeSource {
        unit: SOURCE,
        die: index as usize,
    }
}

pub(super) fn read(types: &Types) -> TypeGraph {
    let mut graph = TypeGraph::default();
    let (definitions, _) = types.definitions();
    let mut budget = types
        .0
        .values()
        .map(|(_, bytes)| bytes.len() / 4)
        .sum::<usize>()
        .saturating_add(4096);
    let type_indices = (0..0x1000).chain(types.0.keys().copied());
    for index in type_indices {
        let Some(spelling) = types.spelling(index, 16) else {
            continue;
        };
        let layout = types
            .layout_with_budget(index, 16, &mut budget)
            .ok_or(AbiIssue::UnknownLayout);
        let mut references = Vec::new();
        let mut members = Vec::new();
        let mut dimensions = Vec::new();
        let modifier = types.record(index).is_some_and(|(kind, _)| kind == 0x1001);
        let pointer = spelling.is_pointer() && !modifier;
        let aggregate =
            !modifier && matches!(&spelling, CType::Named(text) if text.starts_with("struct "));
        let mut tag = gimli::DW_TAG_base_type.0;
        let mut encoding = match &spelling {
            CType::Int { signed: true, .. } => Some(u16::from(gimli::DW_ATE_signed.0)),
            CType::Int { signed: false, .. } => Some(u16::from(gimli::DW_ATE_unsigned.0)),
            CType::Named(text) if matches!(text.as_str(), "float" | "double") => {
                Some(u16::from(gimli::DW_ATE_float.0))
            }
            _ => None,
        };
        let mut generated = Vec::new();
        if pointer {
            tag = gimli::DW_TAG_pointer_type.0;
            let target = if index < 0x1000 {
                Some(index & 0xff)
            } else {
                types.record(index).and_then(|(_, mut data)| data.u32())
            };
            if let Some(target) = target {
                references.push(source(target));
            }
        } else if aggregate {
            tag = gimli::DW_TAG_structure_type.0;
            if let Some(complete) = types.complete(index)
                && let Some((_, fields, _, _)) = types.structure(complete)
                && let Some(fields) = types.fields(fields)
            {
                for (text, ty, offset) in fields {
                    references.push(source(ty));
                    members.push((Some(text.clone()), source(ty)));
                    if let Some(layout) = types.layout(ty, 16) {
                        generated.push(CallMember::Field {
                            name: text,
                            ty: source(ty),
                            offset,
                            bytes: layout.size,
                        });
                    }
                }
            }
            if let Some(definition) = definitions.iter().find(
                |definition| matches!(&spelling, CType::Named(name) if definition.name == *name),
            ) {
                graph.definitions.insert(source(index), definition.clone());
                graph.generated_members.insert(source(index), generated);
            }
        } else if let Some((kind, mut record_reader)) = types.record(index) {
            match kind {
                0x1001 => {
                    tag = gimli::DW_TAG_const_type.0;
                    encoding = None;
                    if let Some(inner) = record_reader.u32() {
                        references.push(source(inner));
                    }
                }
                0x1503 => {
                    tag = gimli::DW_TAG_array_type.0;
                    if let Some(inner) = record_reader.u32() {
                        references.push(source(inner));
                    }
                    if let Ok(layout) = &layout
                        && let crate::ir::abi::LayoutKind::Array { count, .. } = layout.kind
                    {
                        dimensions.push(count);
                    }
                }
                _ => {}
            }
        }
        graph.types.insert(
            source(index),
            CallType {
                tag,
                name: Some(spelling.to_string()),
                spelling: Some(spelling),
                size: layout.as_ref().ok().map(|layout| layout.size),
                encoding,
                complete: layout.is_ok(),
                layout,
                dimensions,
                enumerators: Vec::new(),
                references,
                members,
                pointer,
                aggregate,
            },
        );
    }
    graph
}
