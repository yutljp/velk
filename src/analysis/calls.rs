//! Resolving a callee's declaration for printing. Binding a declaration to
//! a call's registers and stack slots runs in the tests only and lives there.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

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

/// Scalar virtual-call declarations with object pointers represented as void pointers.
pub(crate) fn virtual_signature(image: &Image, address: u64) -> Option<DeclaredSignature> {
    let Some(types) = crate::loader::dwarf::virtual_calls::function_types(image, address) else {
        return None;
    };
    let mut signature = super::abi::callee_declaration(&types);
    for (_, ty) in &mut signature.params {
        if ty.is_pointer() {
            *ty = CType::Pointer(Box::new(CType::Void));
        }
    }
    if !printable(&signature, image.convention_of(address))
        || (signature.ret.integer().is_some_and(|(bits, _)| bits == 32)
            && !super::summary::summary(image, address).narrow_return)
    {
        return None;
    }
    Some(signature)
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
