//! Resolving a callee's declaration and binding it to a call's registers
//! and stack slots.
// Not yet run on lifted functions outside tests.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ir::calls::{
    CallAbi, CallDeclaration, CallFallback, CallInput, CallInputPiece, CallMember, CallSource,
    CallTransport, FunctionSource, TypeSource,
};
use crate::ir::{AbiIssue, AbiProfile, CType, DeclaredSignature, Definition};
use crate::loader::Image;
use crate::loader::dwarf::calls::{self as dwarf, CallIndex, CallUnit};

type Answer = Result<Option<Arc<CallDeclaration>>, AbiIssue>;
type AddressCell = Arc<OnceLock<Answer>>;
type UnitCell = Arc<OnceLock<Result<Arc<CallUnit>, AbiIssue>>>;

#[derive(Debug, Default)]
pub(crate) struct Declarations {
    index: OnceLock<Result<CallIndex, AbiIssue>>,
    units: Mutex<HashMap<u64, UnitCell>>,
    addresses: Mutex<HashMap<u64, AddressCell>>,
}

pub(crate) fn declaration(image: &Image, address: u64) -> Answer {
    let cell = {
        let mut addresses = image
            .call_declarations
            .addresses
            .lock()
            .expect("call declarations lock");
        addresses.entry(address).or_default().clone()
    };
    cell.get_or_init(|| resolve(image, address)).clone()
}

pub(crate) fn attach_outputs(image: &Image, blocks: &mut [crate::ir::Block]) {
    if image.go {
        return;
    }
    let Ok(profile) = crate::ir::abi::profile(image.isa, image.format) else {
        return;
    };
    let convention = super::abi::convention(profile);
    for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        let crate::ir::Stmt::Call {
            target: Some(address),
            through: None,
            convention: called,
            outputs,
            ..
        } = stmt
        else {
            continue;
        };
        if *called != convention {
            continue;
        }
        // This hook precedes SSA; a renamed or shared destination is not a physical output.
        if outputs.iter().enumerate().any(|(at, output)| {
            output.dest.index != output.register
                || output.dest.width != 64
                || !crate::arch::machine_registers().contains(&output.register)
                || outputs[..at].iter().any(|before| {
                    before.register == output.register || before.dest.index == output.dest.index
                })
        }) {
            continue;
        }
        let Ok(Some(declaration)) = declaration(image, *address) else {
            continue;
        };
        let Ok(binding) = &declaration.signature.abi else {
            continue;
        };
        if binding.profile != profile {
            continue;
        }
        let Some(value) = &binding.result else {
            continue;
        };
        let Some(registers) = result_registers(value) else {
            continue;
        };
        for register in registers {
            if !outputs.iter().any(|output| output.register == register) {
                outputs.push(crate::ir::CallOutput {
                    register,
                    dest: crate::ir::RegRef {
                        index: register,
                        width: 64,
                    },
                });
            }
        }
    }
}

pub(crate) fn attach_inputs(image: &Image, blocks: &mut [crate::ir::Block]) {
    if image.go {
        return;
    }
    let Ok(profile) = crate::ir::abi::profile(image.isa, image.format) else {
        return;
    };
    let expected = super::abi::convention(profile);
    for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        let crate::ir::Stmt::Call {
            target: Some(target),
            through: None,
            kind,
            convention,
            args,
            floats_named,
            outputs,
            abi,
            ..
        } = stmt
        else {
            continue;
        };
        if abi.is_some() || *convention != expected {
            continue;
        }
        if outputs.iter().enumerate().any(|(at, output)| {
            output.dest.index != output.register
                || output.dest.width != 64
                || !crate::arch::machine_registers().contains(&output.register)
                || outputs[..at].iter().any(|before| {
                    before.register == output.register || before.dest.index == output.dest.index
                })
        }) {
            continue;
        }
        let Ok(Some(record)) = declaration(image, *target) else {
            continue;
        };
        let fallback = match args {
            Some(args) => CallFallback::Named {
                count: args.len(),
                floats_named: *floats_named,
            },
            None => CallFallback::Implicit {
                floats_named: *floats_named,
            },
        };
        let Ok(candidate) = input_binding(
            record,
            *target,
            *kind,
            image.isa,
            *convention,
            crate::arch::stack_pointer(image.isa),
            fallback,
        ) else {
            continue;
        };
        let Ok(binding) = &candidate.declaration.signature.abi else {
            continue;
        };
        if binding.result.as_ref().is_some_and(|value| {
            result_registers(value).is_none_or(|registers| {
                registers
                    .iter()
                    .any(|register| !outputs.iter().any(|out| out.register == *register))
            })
        }) {
            continue;
        }
        *abi = Some(Arc::new(candidate));
    }
}

fn input_binding(
    declaration: Arc<CallDeclaration>,
    target: u64,
    kind: crate::ir::CallKind,
    isa: crate::loader::Isa,
    convention: crate::ir::Convention,
    sp: u16,
    fallback: CallFallback,
) -> Result<CallAbi, AbiIssue> {
    use crate::ir::{AbiLocation, Passing};
    let binding = declaration.signature.abi.as_ref().map_err(|issue| *issue)?;
    if super::abi::convention(binding.profile) != convention
        || declaration.signature.variadic
        || binding.arguments.len() != declaration.signature.params.len()
        || !crate::arch::machine_registers().contains(&sp)
        || sp != crate::arch::stack_pointer(isa)
        || kind == crate::ir::CallKind::Syscall
        || kind.push_bytes(isa, convention).is_none()
    {
        return Err(AbiIssue::UnknownLayout);
    }
    // Callee stack effects use the stack pointer before the call.
    let mut dependencies = vec![sp];
    let mut registers = HashSet::new();
    let mut count = 0;
    let mut transport = |location: AbiLocation, bytes: u8| -> Result<CallTransport, AbiIssue> {
        if bytes == 0 || bytes > 8 {
            return Err(AbiIssue::UnknownLayout);
        }
        count += 1;
        if count > 65536 {
            return Err(AbiIssue::UnknownLayout);
        }
        Ok(match location {
            AbiLocation::Register(register) => {
                if !crate::arch::machine_registers().contains(&register)
                    || !registers.insert(register)
                {
                    return Err(AbiIssue::UnknownLayout);
                }
                dependencies.push(register);
                CallTransport::Register { register, bytes }
            }
            AbiLocation::Stack(offset) => {
                if !matches!(bytes, 1 | 2 | 4 | 8)
                    || offset
                        < convention
                            .stack_arguments()
                            .ok_or(AbiIssue::UnknownLayout)?
                {
                    return Err(AbiIssue::UnknownLayout);
                }
                let offset = kind
                    .stack_offset(isa, convention, offset)
                    .ok_or(AbiIssue::UnknownLayout)?;
                offset
                    .checked_add(i64::from(bytes))
                    .ok_or(AbiIssue::UnknownLayout)?;
                dependencies.push(sp);
                CallTransport::Stack { offset, bytes }
            }
        })
    };
    let mut deferred_memory = false;
    let mut arguments = Vec::new();
    for value in &binding.arguments {
        value.validate()?;
        arguments.push(match &value.passing {
            Passing::Direct(pieces) => {
                let mut mapped = Vec::new();
                for piece in pieces {
                    match piece.location {
                        AbiLocation::Register(_) => mapped.push(CallInputPiece {
                            object_offset: piece.object_offset,
                            source: transport(
                                piece.location,
                                piece
                                    .bytes
                                    .try_into()
                                    .map_err(|_| AbiIssue::UnknownLayout)?,
                            )?,
                        }),
                        AbiLocation::Stack(offset) => {
                            deferred_memory = true;
                            let mut done = 0;
                            while done < piece.bytes {
                                let remaining = piece.bytes - done;
                                let bytes = [8, 4, 2, 1]
                                    .into_iter()
                                    .find(|width| *width <= remaining)
                                    .ok_or(AbiIssue::UnknownLayout)?;
                                let location = AbiLocation::Stack(
                                    offset
                                        .checked_add(
                                            i64::try_from(done)
                                                .map_err(|_| AbiIssue::UnknownLayout)?,
                                        )
                                        .ok_or(AbiIssue::UnknownLayout)?,
                                );
                                mapped.push(CallInputPiece {
                                    object_offset: piece
                                        .object_offset
                                        .checked_add(done)
                                        .ok_or(AbiIssue::UnknownLayout)?,
                                    source: transport(location, bytes as u8)?,
                                });
                                done = done.checked_add(bytes).ok_or(AbiIssue::UnknownLayout)?;
                            }
                        }
                    }
                }
                CallInput::Direct(mapped)
            }
            Passing::Indirect {
                pointer,
                returned_pointer,
            } => {
                if returned_pointer.is_some() {
                    return Err(AbiIssue::UnknownLayout);
                }
                deferred_memory = true;
                CallInput::Indirect {
                    pointer: transport(*pointer, 8)?,
                }
            }
        });
    }
    let hidden_result = match &binding.result {
        Some(value) => {
            value.validate()?;
            match value.passing {
                Passing::Indirect { pointer, .. } => {
                    deferred_memory = true;
                    Some(transport(pointer, 8)?)
                }
                Passing::Direct(_) => None,
            }
        }
        None => None,
    };
    dependencies.sort_unstable();
    dependencies.dedup();
    Ok(CallAbi {
        kind,
        declaration,
        target,
        convention,
        arguments,
        hidden_result,
        dependencies,
        deferred_memory,
        fallback,
    })
}

fn result_registers(value: &crate::ir::ValueAbi) -> Option<Vec<u16>> {
    value.validate().ok()?;
    let candidates = match &value.passing {
        crate::ir::Passing::Direct(pieces) => pieces
            .iter()
            .map(|piece| match piece.location {
                crate::ir::AbiLocation::Register(register) => Some(register),
                crate::ir::AbiLocation::Stack(_) => None,
            })
            .collect::<Option<Vec<_>>>()?,
        crate::ir::Passing::Indirect {
            returned_pointer, ..
        } => returned_pointer.iter().copied().collect(),
    };
    let mut registers = Vec::new();
    for register in candidates {
        if !crate::arch::machine_registers().contains(&register) || registers.contains(&register) {
            return None;
        }
        registers.push(register);
    }
    Some(registers)
}

fn unit(image: &Image, source: u64) -> Result<Arc<CallUnit>, AbiIssue> {
    let cell = {
        let mut units = image
            .call_declarations
            .units
            .lock()
            .expect("call type units lock");
        units.entry(source).or_default().clone()
    };
    cell.get_or_init(|| dwarf::call_unit(image, source).map(Arc::new))
        .clone()
}

fn resolve(image: &Image, address: u64) -> Answer {
    if image.go {
        return Err(AbiIssue::UnsupportedProfile);
    }
    crate::ir::abi::profile(image.isa, image.format)?;
    let index = image
        .call_declarations
        .index
        .get_or_init(|| dwarf::call_index(image))
        .as_ref()
        .map_err(|issue| *issue)?;
    let Some(candidates) = index.addresses.get(&address) else {
        return if index
            .unresolved_ranges
            .iter()
            .any(|range| range.contains(&address))
        {
            Err(AbiIssue::UnknownLayout)
        } else {
            Ok(None)
        };
    };
    let mut found: Option<CallDeclaration> = None;
    for candidate in candidates {
        let unit = unit(image, candidate.unit)?;
        let types = unit
            .functions
            .get(candidate)
            .ok_or(AbiIssue::UnknownLayout)?
            .as_ref()
            .map_err(|issue| *issue)?;
        let signature = super::abi::callee_declaration(types);
        let profile = signature.abi.as_ref().map_err(|issue| *issue)?.profile;
        if types.source.parameters.len() != signature.params.len()
            || types.source.parameters.iter().any(Option::is_none)
            || (signature.ret != CType::Void && types.source.result.is_none())
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let (required_types, required_definitions) = required(&unit, &types.source, profile)?;
        let source = CallSource {
            source: types.source.clone(),
            graph: unit.graph.clone(),
            required_types,
            required_definitions,
        };
        match &mut found {
            None => {
                found = Some(CallDeclaration {
                    signature,
                    sources: vec![source],
                })
            }
            Some(before) => {
                if !same_signature(&before.signature, &signature)
                    || !same_types(&before.sources[0], &source)
                {
                    return Err(AbiIssue::IncompatibleDefinition);
                }
                before.sources.push(source);
            }
        }
    }
    Ok(found.map(Arc::new))
}

fn required(
    unit: &CallUnit,
    source: &FunctionSource,
    profile: AbiProfile,
) -> Result<(Vec<TypeSource>, Vec<TypeSource>), AbiIssue> {
    let mut pending: Vec<_> = source
        .parameters
        .iter()
        .copied()
        .flatten()
        .chain(source.result)
        .map(|id| (id, true))
        .collect();
    let mut seen = BTreeSet::new();
    let mut types = BTreeSet::new();
    let mut definitions = BTreeSet::new();
    while let Some((id, by_value)) = pending.pop() {
        if !seen.insert((id, by_value)) {
            continue;
        }
        if seen.len() > 65536 {
            return Err(AbiIssue::UnknownLayout);
        }
        let node = unit.graph.types.get(&id).ok_or(AbiIssue::UnknownLayout)?;
        if !node.complete || node.spelling.is_none() {
            return Err(AbiIssue::UnknownLayout);
        }
        if node.pointer {
            let target = match node.references.as_slice() {
                [] => &CType::Void,
                [target] => unit
                    .graph
                    .types
                    .get(target)
                    .and_then(|node| node.spelling.as_ref())
                    .ok_or(AbiIssue::UnknownLayout)?,
                _ => return Err(AbiIssue::UnknownLayout),
            };
            if node.spelling.as_ref() != Some(&CType::pointer_to(target.clone())) {
                return Err(AbiIssue::UnknownLayout);
            }
        }
        types.insert(id);
        if by_value && node.aggregate {
            let definition = unit
                .graph
                .definitions
                .get(&id)
                .ok_or(AbiIssue::IncompatibleDefinition)?;
            if !definition.compatible_profiles.contains(&profile) {
                return Err(AbiIssue::IncompatibleDefinition);
            }
            definitions.insert(id);
        }
        pending.extend(
            node.references
                .iter()
                .map(|next| (*next, by_value && !node.pointer)),
        );
    }
    Ok((
        types.into_iter().collect(),
        definitions.into_iter().collect(),
    ))
}

fn same_signature(left: &DeclaredSignature, right: &DeclaredSignature) -> bool {
    left.ret == right.ret
        && left.variadic == right.variadic
        && left.abi == right.abi
        && left.params.len() == right.params.len()
        && left
            .params
            .iter()
            .zip(&right.params)
            .all(|((_, left), (_, right))| left == right)
}

fn same_definition(left: Option<&Definition>, right: Option<&Definition>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.name == right.name
                && left.members == right.members
                && left.fields == right.fields
                && left.contains == right.contains
                && left.size == right.size
                && left.alignment == right.alignment
                && left.compatible_profiles == right.compatible_profiles
        }
        _ => false,
    }
}

fn same_types(left: &CallSource, right: &CallSource) -> bool {
    if left.source.parameters.len() != right.source.parameters.len()
        || left.source.result.is_some() != right.source.result.is_some()
    {
        return false;
    }
    let mut pending: Vec<_> = left
        .source
        .parameters
        .iter()
        .copied()
        .flatten()
        .zip(right.source.parameters.iter().copied().flatten())
        .collect();
    if let (Some(left), Some(right)) = (left.source.result, right.source.result) {
        pending.push((left, right));
    }
    let mut seen = HashSet::new();
    while let Some((left_id, right_id)) = pending.pop() {
        if !seen.insert((left_id, right_id)) {
            continue;
        }
        if seen.len() > 65536 {
            return false;
        }
        let (Some(a), Some(b)) = (
            left.graph.types.get(&left_id),
            right.graph.types.get(&right_id),
        ) else {
            return false;
        };
        if a.tag != b.tag
            || a.name != b.name
            || a.spelling != b.spelling
            || a.size != b.size
            || a.encoding != b.encoding
            || a.layout != b.layout
            || a.dimensions != b.dimensions
            || a.enumerators != b.enumerators
            || a.complete != b.complete
            || a.pointer != b.pointer
            || a.aggregate != b.aggregate
            || a.references.len() != b.references.len()
            || a.members
                .iter()
                .map(|(name, _)| name)
                .ne(b.members.iter().map(|(name, _)| name))
            || !same_definition(
                left.graph.definitions.get(&left_id),
                right.graph.definitions.get(&right_id),
            )
        {
            return false;
        }
        match (
            left.graph.generated_members.get(&left_id),
            right.graph.generated_members.get(&right_id),
        ) {
            (None, None) => {}
            (Some(a), Some(b)) if a.len() == b.len() => {
                for (a, b) in a.iter().zip(b) {
                    match (a, b) {
                        (
                            CallMember::Field {
                                name: a,
                                ty: left,
                                offset: x,
                                bytes: n,
                            },
                            CallMember::Field {
                                name: b,
                                ty: right,
                                offset: y,
                                bytes: m,
                            },
                        ) if a == b && x == y && n == m => pending.push((*left, *right)),
                        (
                            CallMember::Bytes {
                                offset: a,
                                bytes: x,
                            },
                            CallMember::Bytes {
                                offset: b,
                                bytes: y,
                            },
                        ) if a == b && x == y => {}
                        _ => return false,
                    }
                }
            }
            _ => return false,
        }
        pending.extend(
            a.references
                .iter()
                .copied()
                .zip(b.references.iter().copied()),
        );
    }
    true
}

#[cfg(test)]
mod tests;
