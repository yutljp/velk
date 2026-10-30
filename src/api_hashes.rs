//! Export-name candidates connected to hash resolver results.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use serde::Serialize;

use crate::emulation::{Memory, MemoryWrite, Options, Word};
use crate::ir::{BinOp, CType, Cond, Expr, FunctionIr, Stmt};
use crate::loader::Image;
use crate::ssa::Ssa;

const EXPORT_NAMES: &str = include_str!("api_hashes/exports.txt");

/// A hash comparison connected to a returned address or indirect invocation.
/// Names are candidates, not proof of the module present at runtime.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiHash {
    /// Basic block containing the lookup or indirect call.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub block: u64,
    /// Statement within the optimized block, not a machine address.
    pub statement: usize,
    /// True for an indirect invocation; false for a returned lookup result.
    pub indirect_call: bool,
    /// Function returning the address used by the indirect call.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub resolver: u64,
    /// Function evaluated for each name, or the resolver when velk emulates the lookup.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub routine: u64,
    /// Compared constant, in hexadecimal.
    pub hash: String,
    /// Names found by evaluation; resolver emulation reports the export it returned.
    pub candidates: Vec<String>,
    /// Whether the evaluation covered its full search domain.
    pub complete: bool,
}

struct Flow<'a> {
    assignments: HashMap<u16, (&'a Expr, u8)>,
    calls: HashMap<u16, (u64, &'a [Expr])>,
}

impl<'a> Flow<'a> {
    fn new(ssa: &'a Ssa) -> Self {
        let mut flow = Self {
            assignments: HashMap::new(),
            calls: HashMap::new(),
        };
        for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
            match stmt {
                Stmt::Assign { dest, value, .. } => {
                    flow.assignments.insert(dest.index, (value, dest.width));
                }
                Stmt::Call {
                    target: Some(target),
                    args: Some(args),
                    outputs,
                    through: None,
                    ..
                } => {
                    for output in outputs {
                        if output.register == crate::arch::RETURN {
                            flow.calls.insert(output.dest.index, (*target, args));
                        }
                    }
                }
                _ => {}
            }
        }
        flow
    }

    fn root<'e>(&'e self, mut value: &'e Expr) -> &'e Expr {
        for _ in 0..64 {
            match value {
                Expr::Reg { index, .. } => match self.assignments.get(index) {
                    Some((assigned, 64)) => value = assigned,
                    _ => return value,
                },
                _ => return value,
            }
        }
        value
    }

    fn call(&self, value: &Expr) -> Option<(u64, &'a [Expr])> {
        let Expr::Reg { index, .. } = self.root(value) else {
            return None;
        };
        self.calls.get(index).copied()
    }

    fn comparison_source_and_mask<'e>(&'e self, mut value: &'e Expr) -> (&'e Expr, u64) {
        let mut mask = u64::MAX;
        for _ in 0..64 {
            match value {
                Expr::Reg { index, width } => {
                    if *width < 64 {
                        mask &= (1u64 << width) - 1;
                    }
                    match self.assignments.get(index) {
                        Some((assigned, written)) => {
                            if *written < 32 && *width > *written {
                                return (value, mask);
                            }
                            if *written < 64 {
                                mask &= (1u64 << written) - 1;
                            }
                            value = assigned;
                        }
                        None => return (value, mask),
                    }
                }
                Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                } => {
                    let Expr::Const(bits) = rhs.as_ref() else {
                        return (value, mask);
                    };
                    mask &= bits;
                    value = lhs;
                }
                Expr::Load {
                    width,
                    signed: false,
                    ..
                } if *width < 8 => {
                    mask &= (1u64 << (u32::from(*width) * 8)) - 1;
                    return (value, mask);
                }
                _ => return (value, mask),
            }
        }
        (value, mask)
    }

    fn constant(&self, value: &Expr, remaining: &mut usize) -> Option<u64> {
        if *remaining == 0 {
            return None;
        }
        *remaining -= 1;
        let (value, mask) = self.comparison_source_and_mask(value);
        match value {
            Expr::Const(value) => Some(*value & mask),
            Expr::Bin { op, lhs, rhs } => {
                let (Some(lhs), Some(rhs)) =
                    (self.constant(lhs, remaining), self.constant(rhs, remaining))
                else {
                    return None;
                };
                match Expr::bin(*op, Expr::Const(lhs), Expr::Const(rhs)) {
                    Expr::Const(value) => Some(value & mask),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn loaded(&self, value: &Expr, node_limit: usize) -> bool {
        let mut pending = vec![value];
        let mut visited = HashSet::new();
        for _ in 0..node_limit {
            let Some(value) = pending.pop() else {
                return false;
            };
            match value {
                Expr::Reg { index, .. } => {
                    if visited.insert(*index)
                        && let Some((assigned, _)) = self.assignments.get(index)
                    {
                        pending.push(assigned);
                    }
                }
                Expr::Load { .. } => return true,
                _ => pending.extend(crate::ir::visit::children(value)),
            }
        }
        false
    }
}

pub(crate) fn recover(image: &Image, ir: &FunctionIr, deadline: Option<Instant>) -> Vec<ApiHash> {
    if image.go
        || !matches!(
            image.isa,
            crate::loader::Isa::X86_64 | crate::loader::Isa::I386 | crate::loader::Isa::AArch64
        )
    {
        return Vec::new();
    }
    if !ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Call {
                target: None,
                through: Some(_),
                ..
            }
        )
    }) && !(ir.isa == crate::loader::Isa::I386 && ir.blocks.iter().flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::Call { target: Some(_), args: Some(args), .. } if args.iter().any(|arg| matches!(arg, Expr::Const(_)))))) {
        return Vec::new();
    }
    let mut calls = ir.blocks.iter().flat_map(|block| &block.stmts);
    if !calls.any(|stmt| {
        matches!(stmt,
        Stmt::Call { target: Some(target), through: None, args: Some(_), .. }
            if image.functions.contains_key(target))
    }) {
        return Vec::new();
    }
    let Some(ssa) = prepare_ssa(ir) else {
        return Vec::new();
    };
    let flow = Flow::new(&ssa);
    let mut budget = 2_000_000usize;
    let mut results = Vec::new();
    for block in &ssa.ir.blocks {
        let mut call_index = 0;
        for stmt in &block.stmts {
            if !matches!(stmt, Stmt::Call { .. }) {
                continue;
            }
            let original = ir
                .blocks
                .iter()
                .find(|original| original.start == block.start);
            let position = original.and_then(|original| {
                original
                    .stmts
                    .iter()
                    .enumerate()
                    .filter(|(_, stmt)| matches!(stmt, Stmt::Call { .. }))
                    .nth(call_index)
                    .map(|(position, _)| position)
            });
            call_index += 1;
            let Some(statement) = position else {
                continue;
            };
            let pointer_mask = if crate::arch::pointer_bytes(ir.isa) == 4 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            let (resolver, arguments, indirect_call) = match stmt {
                Stmt::Call {
                    target: None,
                    through: Some(through),
                    ..
                } => {
                    let (through, mask) = flow.comparison_source_and_mask(through);
                    if mask & pointer_mask != pointer_mask {
                        continue;
                    }
                    let Some((resolver, arguments)) = flow.call(through) else {
                        continue;
                    };
                    (resolver, arguments, true)
                }
                Stmt::Call {
                    target: Some(target),
                    args: Some(args),
                    ..
                } if ir.isa == crate::loader::Isa::I386 => {
                    let returned =
                        ssa.ir
                            .blocks
                            .iter()
                            .flat_map(|block| &block.stmts)
                            .any(|stmt| {
                                let Stmt::Ret { value, .. } = stmt else {
                                    return false;
                                };
                                let (value, mask) = flow.comparison_source_and_mask(value);
                                mask & pointer_mask == pointer_mask
                                    && flow.call(value) == Some((*target, args.as_slice()))
                            });
                    if !returned {
                        continue;
                    }
                    (*target, args.as_slice(), false)
                }
                _ => continue,
            };
            if !resolve(
                image,
                ir,
                &flow,
                CallCandidate {
                    resolver,
                    arguments,
                    block_start: block.start,
                    statement,
                    indirect_call,
                },
                deadline,
                &mut budget,
                &mut results,
            ) {
                return results;
            }
        }
    }
    results
}

struct CallCandidate<'a> {
    resolver: u64,
    arguments: &'a [Expr],
    block_start: u64,
    statement: usize,
    indirect_call: bool,
}

fn resolve(
    image: &Image,
    ir: &FunctionIr,
    flow: &Flow<'_>,
    candidate: CallCandidate<'_>,
    deadline: Option<Instant>,
    budget: &mut usize,
    results: &mut Vec<ApiHash>,
) -> bool {
    let CallCandidate {
        resolver,
        arguments,
        block_start,
        statement,
        indirect_call,
    } = candidate;
    if crate::deadline::passed(deadline).is_err() {
        return false;
    }
    let Some(function) = image.functions.get(&resolver) else {
        return true;
    };
    let Ok(analysis) = crate::analysis::analyze(image, function, deadline) else {
        return true;
    };
    let Some(resolver_ssa) = prepare_ssa(&analysis.ir) else {
        return true;
    };
    let resolver_flow = Flow::new(&resolver_ssa);
    let cyclic = crate::ir::cfg::cyclic_blocks(&resolver_ssa.ir);
    if cyclic.is_empty() {
        return true;
    }
    let cyclic_blocks = &cyclic;
    let comparisons = resolver_ssa
        .ir
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(index, block)| {
            block
                .stmts
                .iter()
                .map(move |stmt| (cyclic_blocks.contains(&index), stmt))
        });
    for (cyclic_comparison, comparison) in comparisons {
        if !cyclic_comparison {
            continue;
        }
        let Stmt::Brif {
            cond: Cond::Eq | Cond::Ne,
            lhs,
            rhs,
            ..
        } = comparison
        else {
            continue;
        };
        for (hashed, wanted) in [(lhs, rhs), (rhs, lhs)] {
            let (hashed, hash_mask) = resolver_flow.comparison_source_and_mask(hashed);
            let (wanted, wanted_mask) = resolver_flow.comparison_source_and_mask(wanted);
            if hash_mask != wanted_mask || hash_mask == 0 {
                continue;
            }
            if resolver_flow.call(hashed).is_none() && has_load(&resolver_ssa.ir) {
                let Some(position) =
                    parameter_position(wanted, &analysis.ir, &resolver_ssa, &resolver_flow)
                else {
                    continue;
                };
                let Some(values) = constant_call_arguments(arguments, &analysis.ir, flow)
                    .filter(|values| values.get(position).is_some())
                    .or_else(|| raw_call_arguments(image, ir, resolver, &analysis.ir, deadline))
                else {
                    continue;
                };
                let Some(hash) = values.get(position).copied() else {
                    continue;
                };
                let Some(candidate) = evaluate_resolver(image, resolver, &values, deadline, budget)
                else {
                    continue;
                };
                let complete = candidate.is_none();
                results.push(ApiHash {
                    block: block_start,
                    statement,
                    indirect_call,
                    resolver,
                    routine: resolver,
                    hash: crate::addr::format(hash & hash_mask),
                    candidates: candidate.into_iter().collect(),
                    complete,
                });
                continue;
            }
            let Some((routine, hash_args)) = resolver_flow.call(hashed) else {
                continue;
            };
            let mut call_arguments = Vec::with_capacity(hash_args.len());
            let mut string_argument = None;
            let mut wide_string = false;
            let mut supported = true;
            for (argument_index, hash_argument) in hash_args.iter().enumerate() {
                if resolver_flow.loaded(hash_argument, 32) {
                    if string_argument.replace(argument_index).is_some() {
                        supported = false;
                        break;
                    }
                    call_arguments.push(None);
                    continue;
                }
                if let Some(value) = resolver_flow.constant(hash_argument, &mut 128) {
                    call_arguments.push(Some(value));
                    continue;
                }
                let parameter = match resolver_flow.root(hash_argument) {
                    Expr::Reg { index, .. } => analysis.ir.params.iter().position(|param| {
                        param.index == *index || resolver_ssa.entry.get(&param.index) == Some(index)
                    }),
                    _ => None,
                };
                let Some(value) = parameter
                    .and_then(|position| arguments.get(position))
                    .and_then(|value| flow.constant(value, &mut 128))
                else {
                    supported = false;
                    break;
                };
                call_arguments.push(Some(value));
            }
            let Some(string_argument) = string_argument else {
                continue;
            };
            if !supported {
                continue;
            }
            wide_string |= wide_routine(image, routine, deadline);
            let parameter = match resolver_flow.root(wanted) {
                Expr::Reg { index, .. } => analysis.ir.params.iter().position(|param| {
                    param.index == *index || resolver_ssa.entry.get(&param.index) == Some(index)
                }),
                Expr::Load { addr, .. } => {
                    let sp = crate::arch::stack_pointer(ir.isa);
                    let offset = crate::passes::frame_slots::frame_slot(addr, 0, sp);
                    analysis
                        .ir
                        .stack_params
                        .iter()
                        .find(|param| Some(param.offset) == offset)
                        .map(|param| param.position)
                }
                _ => None,
            };
            let Some(argument) = parameter.and_then(|position| arguments.get(position)) else {
                continue;
            };
            let Some(hash) = flow.constant(argument, &mut 128) else {
                continue;
            };
            let mask = hash_mask;
            let (candidates, complete) = evaluate(
                image,
                Evaluation {
                    routine,
                    hash: hash & mask,
                    mask,
                    arguments: &call_arguments,
                    string_argument,
                    wide_string,
                },
                deadline,
                budget,
            );
            results.push(ApiHash {
                block: block_start,
                statement,
                indirect_call,
                resolver,
                routine,
                hash: crate::addr::format(hash & mask),
                candidates,
                complete,
            });
        }
    }
    true
}

fn parameter_position(value: &Expr, ir: &FunctionIr, ssa: &Ssa, flow: &Flow<'_>) -> Option<usize> {
    match flow.root(value) {
        Expr::Reg { index, .. } => ir
            .params
            .iter()
            .position(|param| param.index == *index || ssa.entry.get(&param.index) == Some(index)),
        Expr::Load { addr, .. } => {
            let sp = crate::arch::stack_pointer(ir.isa);
            let offset = crate::passes::frame_slots::frame_slot(addr, 0, sp);
            ir.stack_params
                .iter()
                .find(|param| Some(param.offset) == offset)
                .map(|param| param.position)
        }
        _ => None,
    }
}

fn constant_call_arguments(
    arguments: &[Expr],
    callee: &FunctionIr,
    caller: &Flow<'_>,
) -> Option<Vec<u64>> {
    let count = arguments.len().max(callee.params.len());
    let mut values = Vec::with_capacity(count);
    for position in 0..count {
        let value = arguments
            .get(position)
            .and_then(|argument| caller.constant(argument, &mut 128));
        let Some(value) = value else {
            return None;
        };
        values.push(value);
    }
    Some(values)
}

fn raw_call_arguments(
    image: &Image,
    caller: &FunctionIr,
    target: u64,
    callee: &FunctionIr,
    deadline: Option<Instant>,
) -> Option<Vec<u64>> {
    if crate::deadline::passed(deadline).is_err() {
        return None;
    }
    let Some(function) = image.functions.get(&caller.addr) else {
        return None;
    };
    let stack_count = callee
        .stack_params
        .iter()
        .filter_map(|parameter| parameter.position.checked_add(1))
        .max()
        .unwrap_or(callee.params.len())
        .saturating_sub(callee.params.len());
    let summaries = |called| {
        if called == target {
            crate::loader::Summary {
                arity: Some(callee.params.len()),
                stack: stack_count,
                ..crate::analysis::summary(image, called)
            }
        } else {
            crate::analysis::summary(image, called)
        }
    };
    let Ok(blocks) = crate::lift::lift_with(
        image,
        caller.addr,
        function.size.unwrap_or(caller.size),
        &HashSet::new(),
        &summaries,
    ) else {
        return None;
    };
    let mut found = None;
    for block in &blocks {
        for (position, stmt) in block.stmts.iter().enumerate() {
            let Stmt::Call {
                target: Some(called),
                args: Some(arguments),
                ..
            } = stmt
            else {
                continue;
            };
            if *called != target {
                continue;
            }
            if found.is_some() {
                return None;
            }
            let mut assignments = HashMap::new();
            let mut stores: HashMap<i64, (u8, Option<u64>)> = HashMap::new();
            let sp = crate::arch::stack_pointer(caller.isa);
            for earlier in &block.stmts[..position] {
                match earlier {
                    Stmt::Assign { dest, value, .. } => {
                        assignments.insert(dest.index, (value, dest.width));
                    }
                    Stmt::Store {
                        addr, value, width, ..
                    } => {
                        if let Some(offset) = crate::passes::frame_slots::frame_slot(addr, 0, sp) {
                            let flow = Flow {
                                assignments: assignments.clone(),
                                calls: HashMap::new(),
                            };
                            let constant = flow.constant(value, &mut 128);
                            stores.insert(offset, (*width, constant));
                        }
                    }
                    _ => {}
                }
            }
            let flow = Flow {
                assignments,
                calls: HashMap::new(),
            };
            let mut values = Vec::with_capacity(arguments.len());
            for (argument_index, argument) in arguments.iter().enumerate() {
                let value = match argument {
                    Expr::Load { addr, .. } => {
                        let offset = crate::passes::frame_slots::frame_slot(addr, 0, sp);
                        offset.and_then(|offset| {
                            constant_stack_argument(offset, argument_index, callee, &stores)
                        })
                    }
                    _ => flow.constant(argument, &mut 128),
                };
                let Some(value) = value else {
                    return None;
                };
                values.push(value);
            }
            found = Some(values);
        }
    }
    found
}

fn constant_stack_argument(
    offset: i64,
    position: usize,
    callee: &FunctionIr,
    stores: &HashMap<i64, (u8, Option<u64>)>,
) -> Option<u64> {
    let Some(parameter) = callee
        .stack_params
        .iter()
        .find(|parameter| parameter.position == position)
    else {
        return None;
    };
    let Ok(bytes) = u8::try_from(parameter.size) else {
        return None;
    };
    if !matches!(bytes, 1 | 2 | 4 | 8) {
        return None;
    }
    let Some((stored_bytes, Some(value))) = stores.get(&offset).copied() else {
        return None;
    };
    if stored_bytes < bytes {
        return None;
    }
    let bits = u32::from(bytes) * 8;
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let value = value & mask;
    let signed = matches!(&parameter.ty, CType::Int { signed: true, .. });
    if signed && bits < 64 && value & (1u64 << (bits - 1)) != 0 {
        return Some(value | !mask);
    }
    Some(value)
}

fn statement_expressions(stmt: &Stmt) -> Vec<&Expr> {
    match stmt {
        Stmt::Machine { inputs, .. } => inputs.iter().collect(),
        Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => vec![value],
        Stmt::Store { addr, value, .. } => vec![addr, value],
        Stmt::Brif { lhs, rhs, .. } => vec![lhs, rhs],
        Stmt::BrIndirect { target, .. } => vec![target],
        Stmt::Switch { index, .. } => vec![index],
        Stmt::Call { through, args, .. } => through.iter().chain(args.iter().flatten()).collect(),
        _ => Vec::new(),
    }
}

fn has_load(ir: &FunctionIr) -> bool {
    for block in &ir.blocks {
        for stmt in &block.stmts {
            for expression in statement_expressions(stmt) {
                let mut pending = vec![expression];
                while let Some(expression) = pending.pop() {
                    if matches!(expression, Expr::Load { .. }) {
                        return true;
                    }
                    pending.extend(crate::ir::visit::children(expression));
                }
            }
        }
    }
    false
}

fn evaluate_resolver(
    image: &Image,
    resolver: u64,
    arguments: &[u64],
    deadline: Option<Instant>,
    budget: &mut usize,
) -> Option<Option<String>> {
    if *budget == 0 || crate::deadline::passed(deadline).is_err() {
        return None;
    }
    let options = Options {
        arguments: arguments
            .iter()
            .map(|value| Word::Text(crate::addr::format(*value)))
            .collect(),
        step_limit: (*budget).min(200_000),
        time_limit_ms: 100,
        ..Options::default()
    };
    let Ok(report) = crate::ir::eval::emulation::run_bounded(image, resolver, &options, deadline)
    else {
        return None;
    };
    *budget = (*budget).saturating_sub(report.steps);
    if report.reason != "return" {
        return None;
    }
    let Some(address) = crate::addr::parse(&report.return_value) else {
        return None;
    };
    if address == 0 {
        return Some(None);
    }
    let name = report
        .windows_exports
        .get(&address)
        .and_then(|qualified| qualified.rsplit_once('!').map(|(_, name)| name.to_owned()))
        .or_else(|| {
            image
                .functions
                .get(&address)
                .and_then(|function| function.name.clone())
        });
    name.map(Some)
}

fn wide_routine(image: &Image, routine: u64, deadline: Option<Instant>) -> bool {
    let Some(function) = image.functions.get(&routine) else {
        return false;
    };
    let Ok(analysis) = crate::analysis::analyze(image, function, deadline) else {
        return false;
    };
    analysis
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| {
            statement_expressions(stmt).into_iter().any(|expression| {
                let mut pending = vec![expression];
                while let Some(expression) = pending.pop() {
                    if matches!(expression, Expr::Load { width: 2, .. }) {
                        return true;
                    }
                    pending.extend(crate::ir::visit::children(expression));
                }
                false
            })
        })
}

fn prepare_ssa(ir: &FunctionIr) -> Option<Ssa> {
    let mut normalized = ir.clone();
    crate::passes::frame::drop_dead_frame_stores(&mut normalized);
    crate::passes::memory::promote_frame_slots(&mut normalized);
    crate::passes::memory::forward_stored_values(&mut normalized);
    let Some(mut ssa) = crate::ssa::build(&normalized) else {
        return None;
    };
    let sp = crate::arch::stack_pointer(ir.isa);
    if let Some(entry) = ssa.entry.get(&sp).copied() {
        let values = [(entry, Expr::reg(sp, 64))];
        for block in &mut ssa.ir.blocks {
            for stmt in &mut block.stmts {
                crate::ir::visit::replace_reads(stmt, &values);
            }
        }
    }
    let mut inputs = Vec::new();
    for param in &ir.params {
        if let Some(entry) = ssa.entry.get(&param.index).copied() {
            inputs.push(Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: entry,
                    width: 64,
                },
                value: Expr::reg(param.index, 64),
                at: None,
            });
        }
    }
    if let Some(block) = ssa.ir.blocks.first_mut() {
        inputs.append(&mut block.stmts);
        block.stmts = inputs;
    }
    crate::passes::memory::forward_spilled_variables(&mut ssa.ir);
    crate::passes::memory::forward_stored_values(&mut ssa.ir);
    Some(ssa)
}

struct Evaluation<'a> {
    routine: u64,
    hash: u64,
    mask: u64,
    arguments: &'a [Option<u64>],
    string_argument: usize,
    wide_string: bool,
}

fn evaluate(
    image: &Image,
    evaluation: Evaluation<'_>,
    deadline: Option<Instant>,
    budget: &mut usize,
) -> (Vec<String>, bool) {
    let Evaluation {
        routine,
        hash,
        mask,
        arguments,
        string_argument,
        wide_string,
    } = evaluation;
    let Ok(memory) = Memory::new(image) else {
        return (Vec::new(), false);
    };
    let address = memory.heap_base;
    let mut candidates = Vec::new();
    let mut complete = true;
    for name in EXPORT_NAMES.lines() {
        if *budget == 0 || crate::deadline::passed(deadline).is_err() {
            return (candidates, false);
        }
        let bytes = if wide_string {
            let mut bytes = Vec::with_capacity(name.len().saturating_mul(2).saturating_add(2));
            for unit in name.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&[0, 0]);
            bytes
        } else {
            let mut bytes = name.as_bytes().to_vec();
            bytes.push(0);
            bytes
        };
        let mut call_arguments = Vec::with_capacity(arguments.len());
        for (index, argument) in arguments.iter().enumerate() {
            let value = if index == string_argument {
                address
            } else if let Some(value) = argument {
                *value
            } else {
                complete = false;
                break;
            };
            call_arguments.push(Word::Text(crate::addr::format(value)));
        }
        if call_arguments.len() != arguments.len() {
            continue;
        }
        let options = Options {
            arguments: call_arguments,
            memory: vec![MemoryWrite {
                address: Word::Text(crate::addr::format(address)),
                bytes: Some(bytes),
                value: None,
                width: None,
            }],
            step_limit: (*budget).min(10_000),
            ..Options::default()
        };
        *budget -= 1;
        match crate::ir::eval::emulation::run_bounded(image, routine, &options, deadline) {
            Ok(report) if report.reason == "return" => {
                *budget = budget.saturating_sub(report.steps);
                let Some(value) = crate::addr::parse(&report.return_value) else {
                    complete = false;
                    continue;
                };
                if value & mask == hash {
                    candidates.push(name.to_owned());
                }
            }
            Ok(report) => {
                *budget = budget.saturating_sub(report.steps);
                complete = false;
            }
            Err(_) => complete = false,
        }
    }
    (candidates, complete)
}

pub(crate) fn annotate(code: &mut String, hashes: &[ApiHash]) {
    for hash in hashes {
        if hash.candidates.is_empty() {
            continue;
        }
        let comment = comment(hash);
        if !code.contains(&comment) {
            code.push_str(comment.trim_start());
            code.push('\n');
        }
    }
}

fn comment(hash: &ApiHash) -> String {
    format!(
        " /* API hash {} at block 0x{:x}, statement {}: candidates {}{} */",
        hash.hash,
        hash.block,
        hash.statement,
        hash.candidates.join(", "),
        if hash.complete {
            ""
        } else {
            " (incomplete search)"
        },
    )
}

pub(crate) fn add_comments(
    hashes: &[ApiHash],
    ir: &FunctionIr,
    symbols: &mut crate::render::Symbols,
) {
    for hash in hashes {
        if hash.candidates.is_empty() {
            continue;
        }
        let call = ir
            .blocks
            .iter()
            .find(|block| block.start == hash.block)
            .and_then(|block| block.stmts.get(hash.statement));
        if let Some(Stmt::Call {
            target: None,
            through: Some(through),
            ..
        }) = call
        {
            let occurrences = ir.blocks.iter().flat_map(|block| &block.stmts).filter(|stmt| {
                matches!(stmt, Stmt::Call { target: None, through: Some(other), .. } if other == through)
            }).count();
            if occurrences != 1 {
                continue;
            }
            symbols
                .api_hash_comments
                .insert((ir.addr, through.clone()), comment(hash));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_arguments_keep_read_widths_and_masks() {
        let value = Expr::Const(0x1234_5678_9abc_def0);
        let flow = Flow {
            assignments: HashMap::from([(1, (&value, 64))]),
            calls: HashMap::new(),
        };
        for (width, expected) in [
            (8, 0xf0),
            (16, 0xdef0),
            (32, 0x9abc_def0),
            (64, 0x1234_5678_9abc_def0),
        ] {
            assert_eq!(
                flow.constant(&Expr::reg(1, width), &mut 128),
                Some(expected)
            );
        }
        let masked = Expr::bin(BinOp::And, Expr::reg(1, 64), Expr::Const(0xff));
        assert_eq!(flow.constant(&masked, &mut 128), Some(0xf0));
        assert_eq!(flow.constant(&masked, &mut 0), None);
        let flow = Flow {
            assignments: HashMap::from([(1, (&value, 32))]),
            calls: HashMap::new(),
        };
        assert_eq!(
            flow.constant(&Expr::reg(1, 64), &mut 128),
            Some(0x9abc_def0)
        );
        let flow = Flow {
            assignments: HashMap::from([(1, (&value, 16))]),
            calls: HashMap::new(),
        };
        assert_eq!(flow.constant(&Expr::reg(1, 64), &mut 128), None);
        assert_eq!(flow.constant(&Expr::reg(1, 16), &mut 128), Some(0xdef0));
    }

    #[test]
    fn cyclic_assignments_do_not_produce_a_constant_or_load() {
        let value = Expr::reg(1, 64);
        let flow = Flow {
            assignments: HashMap::from([(1, (&value, 64))]),
            calls: HashMap::new(),
        };
        assert_eq!(flow.constant(&value, &mut 128), None);
        assert!(!flow.loaded(&value, 128));
    }

    #[test]
    fn stack_arguments_accept_narrow_constant_stores() {
        let mut callee = FunctionIr::single_block(crate::loader::Isa::X86_64, Vec::new());
        callee.stack_params.push(crate::ir::StackParam {
            offset: 8,
            size: 4,
            name: "a6".to_owned(),
            ty: CType::U32,
            position: 6,
        });
        let stores = HashMap::from([(0, (4, Some(0x7c9c_7b11)))]);
        assert_eq!(
            constant_stack_argument(0, 6, &callee, &stores),
            Some(0x7c9c_7b11)
        );

        callee.stack_params[0].ty = CType::I32;
        let stores = HashMap::from([(0, (4, Some(0x8000_0000)))]);
        assert_eq!(
            constant_stack_argument(0, 6, &callee, &stores),
            Some(0xffff_ffff_8000_0000)
        );

        let stores = HashMap::from([(0, (2, Some(0x7b11)))]);
        assert_eq!(constant_stack_argument(0, 6, &callee, &stores), None);
    }
}
