//! Resolving a callee's declaration and binding it to a call's registers
//! and stack slots.
// Declarations are looked up for printing; binding them to calls runs in
// tests only.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(test)]
use crate::ir::calls::{CallAbi, CallFallback, CallInput, CallInputPiece, CallTransport};
use crate::ir::calls::{CallDeclaration, CallMember, CallSource, FunctionSource, TypeSource};
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

#[cfg(test)]
fn physical_outputs(outputs: &[crate::ir::CallOutput]) -> bool {
    !outputs.iter().enumerate().any(|(at, output)| {
        output.dest.index != output.register
            || output.dest.width != 64
            || !crate::arch::machine_registers().contains(&output.register)
            || outputs[..at].iter().any(|before| {
                before.register == output.register || before.dest.index == output.dest.index
            })
    })
}

#[cfg(test)]
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
        if !physical_outputs(outputs) {
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

#[cfg(test)]
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
        if !physical_outputs(outputs) {
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

#[cfg(test)]
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

#[cfg(test)]
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

/// Declarations usable for direct calls and function addresses: nonvariadic,
/// with whole scalar parameters in the named arguments' order and a scalar
/// result in the first result register under the call's convention.
pub(crate) fn printable_signatures(
    image: &Image,
    ir: &crate::ir::FunctionIr,
) -> std::collections::BTreeMap<u64, DeclaredSignature> {
    let mut found = std::collections::BTreeMap::new();
    if image.go {
        return found;
    }
    let mut refused = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let crate::ir::Stmt::Call {
            target: Some(target),
            through: None,
            convention,
            args,
            ..
        } = stmt
        else {
            continue;
        };
        if refused.contains(target) {
            continue;
        }
        let Ok(Some(declaration)) = declaration(image, *target) else {
            continue;
        };
        let signature = &declaration.signature;
        // A call of the function itself is printed with the types its
        // definition is printed with, when those are the declared ones.
        let compatible = *target != ir.addr
            || (ir.ret_type == signature.ret
                && ir.params.len() == signature.params.len()
                && ir
                    .params
                    .iter()
                    .zip(&signature.params)
                    .all(|(param, (_, ty))| param.ty == *ty));
        if compatible
            && args
                .as_ref()
                .is_some_and(|args| args.len() == signature.params.len())
            && printable(signature, *convention)
            // A 32-bit declaration alone says nothing about the upper
            // return-register bits that the caller may still read.
            && (!signature.ret.integer().is_some_and(|(bits, _)| bits == 32)
                || super::summary::summary(image, *target).narrow_return)
        {
            found.insert(*target, signature.clone());
        } else {
            // Every call sharing the prototype must fit it.
            found.remove(target);
            refused.insert(*target);
        }
    }
    // An address of the same function needs the same prototype when
    // standalone outputs are combined.
    let mut pending: Vec<_> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(crate::ir::Stmt::operands)
        .collect();
    while let Some(value) = pending.pop() {
        pending.extend(crate::ir::visit::children(value));
        let crate::ir::Expr::Const(target) = value else {
            continue;
        };
        if *target == 0
            || *target == ir.addr
            || found.contains_key(target)
            || refused.contains(target)
            || !image.functions.contains_key(target)
        {
            continue;
        }
        let Ok(Some(declaration)) = declaration(image, *target) else {
            continue;
        };
        if printable(&declaration.signature, image.convention_of(*target)) {
            found.insert(*target, declaration.signature.clone());
        }
    }
    found
}

fn printable(signature: &DeclaredSignature, convention: crate::ir::Convention) -> bool {
    use crate::ir::{AbiLocation, Passing, RegisterClass};
    let Ok(abi) = &signature.abi else {
        return false;
    };
    // A void prototype cannot represent a live return-register value.
    if signature.ret == CType::Void {
        return false;
    }
    if signature.variadic || super::abi::convention(abi.profile) != convention {
        return false;
    }
    let scalar = |ty: &CType| {
        let mut target = ty;
        while let CType::Pointer(inner) = target {
            target = inner;
        }
        (*target == CType::Void && ty.is_pointer())
            || target
                .integer()
                .is_some_and(|(bits, _)| matches!(bits, 8 | 16 | 32 | 64))
    };
    let size_matches = |ty: &CType, value: &crate::ir::ValueAbi| {
        let bytes = if ty.is_pointer() {
            Some(8)
        } else {
            ty.integer().map(|(bits, _)| u64::from(bits / 8))
        };
        bytes == Some(value.size)
            && !matches!(ty, CType::Named(name) if name.split_whitespace().any(|word| matches!(word, "bool" | "_Bool")))
    };
    let location = |value: &crate::ir::ValueAbi| match &value.passing {
        Passing::Direct(pieces) if !value.aggregate => match pieces.as_slice() {
            [piece]
                if value.validate().is_ok()
                    && piece.object_offset == 0
                    && piece.bytes == value.size
                    && match piece.location {
                        AbiLocation::Register(_) => piece.class == Some(RegisterClass::Integer),
                        AbiLocation::Stack(_) => piece.class.is_none(),
                    } =>
            {
                Some(piece.location)
            }
            _ => None,
        },
        _ => None,
    };
    let arguments = convention.arguments();
    let params = signature.params.len() == abi.arguments.len()
        && signature.params.iter().zip(&abi.arguments).enumerate().all(
            |(position, ((_, ty), value))| {
                scalar(ty)
                    && size_matches(ty, value)
                    && location(value).is_some_and(|at| {
                        if let Some(register) = arguments.get(position) {
                            return at == AbiLocation::Register(*register);
                        }
                        let offset = i64::try_from(position - arguments.len())
                            .ok()
                            .and_then(|slot| slot.checked_mul(8))
                            .and_then(|offset| {
                                convention
                                    .stack_arguments()
                                    .and_then(|start| start.checked_add(offset))
                            });
                        offset.is_some_and(|offset| at == AbiLocation::Stack(offset))
                    })
            },
        );
    let result = match (&abi.result, &signature.ret) {
        (Some(value), ty) => {
            scalar(ty)
                && size_matches(ty, value)
                && (ty.is_pointer() || ty.integer().is_some_and(|(bits, _)| bits >= 32))
                && location(value).is_some_and(|at| {
                    convention
                        .results()
                        .first()
                        .is_some_and(|register| at == AbiLocation::Register(*register))
                })
        }
        _ => false,
    };
    params && result
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
