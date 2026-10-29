use std::collections::{BTreeMap, HashSet};

use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
use crate::render::{Symbols, structure::Node};

#[derive(Clone, PartialEq, Eq)]
pub(in crate::render) enum NamedPlace {
    Register(u16),
    Slot(Expr),
}

fn reads(expr: &Expr, counter: &NamedPlace) -> bool {
    match (counter, expr) {
        (NamedPlace::Register(index), Expr::Reg { index: read, .. }) => index == read,
        (NamedPlace::Slot(addr), Expr::Load { addr: read, .. }) if addr == read.as_ref() => true,
        _ => crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| reads(child, counter)),
    }
}

fn loop_counter(init: &Stmt, looped: &Node) -> Option<NamedPlace> {
    match looped {
        Node::While {
            prefix,
            lhs,
            rhs,
            body,
            ..
        } if prefix.is_empty() => counted_name(init, lhs, rhs, body),
        Node::DoWhile { lhs, rhs, body, .. } => counted_name(init, lhs, rhs, body),
        Node::If { then, els, .. } if els.is_empty() => {
            let [looped @ Node::DoWhile { .. }] = then.as_slice() else {
                return None;
            };
            loop_counter(init, looped)
        }
        _ => None,
    }
}

pub(in crate::render) fn counted(
    init: &Stmt,
    lhs: &Expr,
    rhs: &Expr,
    body: &[Node],
) -> Option<NamedPlace> {
    let Some((Node::Stmt(step), _)) = body.split_last() else {
        return None;
    };
    let counter = match init {
        Stmt::Assign { dest, .. } => NamedPlace::Register(dest.index),
        Stmt::Store { addr, .. } => NamedPlace::Slot(addr.clone()),
        _ => return None,
    };
    let steps = match (&counter, step) {
        (NamedPlace::Register(index), Stmt::Assign { dest, value, .. }) => {
            dest.index == *index && reads(value, &counter)
        }
        (
            NamedPlace::Slot(addr),
            Stmt::Store {
                addr: written,
                value,
                ..
            },
        ) => written == addr && reads(value, &counter),
        _ => false,
    };
    (steps && (reads(lhs, &counter) || reads(rhs, &counter))).then_some(counter)
}

fn counted_name(init: &Stmt, lhs: &Expr, rhs: &Expr, body: &[Node]) -> Option<NamedPlace> {
    let Some(counter) = counted(init, lhs, rhs, body) else {
        return None;
    };
    let Some(Node::Stmt(step)) = body.last() else {
        return None;
    };
    let (Stmt::Assign { value, .. } | Stmt::Store { value, .. }) = step else {
        return None;
    };
    if non_counting_step(value, &counter) || reads(lhs, &counter) == reads(rhs, &counter) {
        return None;
    }
    Some(counter)
}

fn non_counting_step(value: &Expr, counter: &NamedPlace) -> bool {
    match value {
        Expr::SignExtend { value, .. } => non_counting_step(value, counter),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if is_width_mask(rhs) => non_counting_step(lhs, counter),
        Expr::Bin {
            op: BinOp::Shr,
            lhs,
            ..
        } => matches_place(lhs, counter),
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => matches_place(lhs, counter) && shifted_counter(rhs, counter),
        _ => false,
    }
}

fn shifted_counter(expr: &Expr, counter: &NamedPlace) -> bool {
    match expr {
        Expr::SignExtend { value, .. } => shifted_counter(value, counter),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if is_width_mask(rhs) => shifted_counter(lhs, counter),
        Expr::Bin {
            op: BinOp::Shr,
            lhs,
            ..
        } => matches_place(lhs, counter),
        _ => false,
    }
}

fn matches_place(expr: &Expr, place: &NamedPlace) -> bool {
    match (place, expr) {
        (NamedPlace::Register(index), Expr::Reg { index: read, .. }) => index == read,
        (NamedPlace::Slot(addr), Expr::Load { addr: read, .. }) => addr == read.as_ref(),
        (_, Expr::SignExtend { value, .. }) => matches_place(value, place),
        (
            _,
            Expr::Bin {
                op: BinOp::And,
                lhs,
                ..
            },
        ) => matches_place(lhs, place),
        _ => false,
    }
}

fn is_width_mask(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(mask)
        if *mask == u64::MAX || mask.checked_add(1).is_some_and(u64::is_power_of_two))
}

#[derive(Default)]
pub(in crate::render) struct Roles {
    candidates: Vec<(NamedPlace, Option<String>)>,
}

impl Roles {
    fn suggest_first(&mut self, place: NamedPlace, name: impl Into<String>) {
        if !self.candidates.iter().any(|(key, _)| *key == place) {
            self.candidates.push((place, Some(name.into())));
        }
    }

    fn prefer(&mut self, other: Self) {
        self.candidates
            .retain(|(key, _)| !other.candidates.iter().any(|(other, _)| key == other));
        self.candidates.extend(other.candidates);
    }

    pub(in crate::render) fn register(&self, index: u16) -> Option<&str> {
        self.candidates.iter().find_map(|(key, name)| {
            (*key == NamedPlace::Register(index))
                .then_some(name.as_deref())
                .flatten()
        })
    }

    pub(in crate::render) fn slot(&self, addr: &Expr) -> Option<&str> {
        self.candidates.iter().find_map(|(key, name)| {
            matches!(key, NamedPlace::Slot(key) if key == addr)
                .then_some(name.as_deref())
                .flatten()
        })
    }
}

fn named_place(expr: &Expr) -> Option<NamedPlace> {
    match expr {
        Expr::Reg { index, .. } => Some(NamedPlace::Register(*index)),
        Expr::Load { addr, .. } => Some(NamedPlace::Slot(addr.as_ref().clone())),
        Expr::SignExtend { value, .. } => named_place(value),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if is_width_mask(rhs) => named_place(lhs),
        _ => None,
    }
}

fn integer_or_unknown(
    ir: &FunctionIr,
    symbols: &Symbols,
    types: &std::collections::BTreeMap<u16, CType>,
    slot_types: &mut Option<Vec<(Expr, CType)>>,
    place: &NamedPlace,
) -> bool {
    match place {
        NamedPlace::Register(index) => {
            if let Some(param) = ir.params.iter().find(|param| param.index == *index) {
                return param.ty.integer().is_some();
            }
            match types.get(index) {
                Some(ty) => ty.integer().is_some(),
                None => true,
            }
        }
        NamedPlace::Slot(addr) => {
            let slot_types = slot_types
                .get_or_insert_with(|| crate::render::locals::stack_slot_types(ir, symbols));
            slot_types
                .iter()
                .find(|(address, _)| address == addr)
                .is_none_or(|(_, ty)| ty.integer().is_some())
        }
    }
}

fn suggest_loop_names(
    nodes: &[Node],
    depth: usize,
    candidates: &mut Vec<(NamedPlace, &'static str)>,
) {
    for (position, node) in nodes.iter().enumerate() {
        if let Node::Stmt(init) = node
            && let Some(looped) = nodes.get(position + 1)
            && let Some(counter) = loop_counter(init, looped)
            && !candidates.iter().any(|(place, _)| *place == counter)
        {
            candidates.push((counter, ["i", "j", "k"][depth.min(2)]));
        }
        match node {
            Node::While { body, .. } | Node::DoWhile { body, .. } | Node::Forever { body } => {
                suggest_loop_names(body, depth.saturating_add(1), candidates);
            }
            Node::If { then, els, .. } => {
                suggest_loop_names(then, depth, candidates);
                suggest_loop_names(els, depth, candidates);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    suggest_loop_names(body, depth, candidates);
                }
                if let Some(body) = default {
                    suggest_loop_names(body, depth, candidates);
                }
            }
            _ => {}
        }
    }
}

pub(in crate::render) fn infer(ir: &FunctionIr, symbols: &Symbols) -> Roles {
    infer_with_nodes(ir, symbols, &crate::render::structure_best(ir))
}

pub(in crate::render) fn infer_with_nodes(
    ir: &FunctionIr,
    symbols: &Symbols,
    nodes: &[Node],
) -> Roles {
    let mut roles = Roles::default();
    let mut writes = BTreeMap::<u16, usize>::new();
    let mut returned = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, .. } = stmt {
            *writes.entry(dest.index).or_default() += 1;
        }
        if let Stmt::Ret { value: expr, .. } = stmt {
            returned.push(named_place(expr));
        }
        let Stmt::Call {
            target,
            through,
            args,
            outputs,
            convention,
            ..
        } = stmt
        else {
            continue;
        };
        let name = target
            .and_then(|address| symbols.original_or_printed_function_name(address))
            .or_else(|| match through {
                Some(Expr::Load { addr, width: 8, .. }) => match addr.as_ref() {
                    Expr::Const(slot) => symbols.import_name(slot),
                    _ => None,
                },
                _ => None,
            });
        let signature = target
            .and_then(|target| ir.callee_signatures.get(&target))
            .or_else(|| target.and_then(|target| symbols.cpp_signatures.get(&target)));
        let callee = name.map(|name| name.strip_prefix('_').unwrap_or(name));
        let prototype = target
            .and_then(|target| symbols.unused_parameters.get(&target))
            .or_else(|| {
                callee.and_then(|name| {
                    symbols
                        .library_prototypes
                        .get(&crate::render::sanitize(name))
                        .or_else(|| {
                            crate::analysis::prototypes::of(
                                name,
                                symbols.target_format == Some(crate::loader::Format::MachO),
                            )
                        })
                })
            });
        let hints = callee.and_then(crate::analysis::prototypes::effects::lookup);
        let naming = hints.and_then(|effects| effects.naming.as_ref());
        if let Some(args) = args {
            for (position, arg) in args.iter().enumerate() {
                if let Some(counter) = named_place(arg) {
                    let source_name = signature
                        .and_then(|signature| signature.params.get(position))
                        .map(|(name, _)| name.as_str())
                        .and_then(usable_parameter_name)
                        .or_else(|| {
                            naming
                                .and_then(|naming| naming.parameters.get(position))
                                .copied()
                                .and_then(usable_parameter_name)
                        })
                        .or_else(|| {
                            prototype
                                .and_then(|prototype| prototype.parameter_names.get(position))
                                .map(String::as_str)
                                .and_then(usable_parameter_name)
                        });
                    if let Some(name) = source_name {
                        roles.suggest_first(counter, name);
                    }
                }
            }
        }
        if let Some(name) = naming.and_then(|naming| naming.result) {
            for output in outputs {
                if convention.results().first() == Some(&output.register) {
                    roles.suggest_first(NamedPlace::Register(output.dest.index), name);
                }
            }
        }
    }
    if let Some(Some(counter)) = returned.first()
        && returned.iter().all(|other| other.as_ref() == Some(counter))
    {
        let assigned = match counter {
            NamedPlace::Register(index) => {
                if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                    stmt.call_outputs()
                        .iter()
                        .any(|output| output.dest.index == *index)
                }) {
                    0
                } else {
                    writes.get(index).copied().unwrap_or(0)
                }
            }
            NamedPlace::Slot(addr) => ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .filter(|stmt| matches!(stmt, Stmt::Store { addr: written, .. } if written == addr))
                .count(),
        };
        if assigned > 1 {
            roles.suggest_first(counter.clone(), "result");
        }
    }
    let mut candidates = Vec::new();
    suggest_loop_names(nodes, 0, &mut candidates);
    let mut types = None;
    let mut slot_types = None;
    let mut counters = Roles::default();
    for (counter, name) in candidates {
        if integer_or_unknown(
            ir,
            symbols,
            types.get_or_insert_with(|| crate::render::function::variable_types(ir)),
            &mut slot_types,
            &counter,
        ) {
            counters.suggest_first(counter, name);
        }
    }
    roles.prefer(counters);
    roles
}

fn usable_parameter_name(name: &str) -> Option<&str> {
    if crate::render::globals::identifier(name) != name
        || name.strip_prefix('a').is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
        })
        || name.strip_prefix('v').is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
        })
        || name.strip_prefix("local_").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
        })
    {
        return None;
    }
    Some(name)
}

pub(in crate::render) fn reserved(ir: &FunctionIr, symbols: &Symbols) -> HashSet<String> {
    let mut names: HashSet<_> = ir
        .params
        .iter()
        .map(|param| param.name.clone())
        .chain(ir.stack_params.iter().map(|param| param.name.clone()))
        .chain(
            symbols
                .functions
                .values()
                .map(|name| crate::render::sanitize(name)),
        )
        .chain(
            symbols
                .import_slots
                .values()
                .map(|name| crate::render::sanitize(name)),
        )
        .chain(
            symbols
                .data
                .values()
                .map(|name| crate::render::sanitize(name)),
        )
        .chain(symbols.reserved_names.iter().cloned())
        .collect();
    if let Some(name) = &ir.name {
        names.insert(crate::render::sanitize(name));
    }
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        names.extend(
            writes
                .into_iter()
                .chain(reads)
                .map(|index| crate::ir::reg_name(ir.isa, index, 64)),
        );
    }
    for ty in ir
        .value_types
        .values()
        .chain(ir.params.iter().map(|param| &param.ty))
        .chain(ir.stack_params.iter().map(|param| &param.ty))
        .chain(ir.members.iter().map(|member| &member.ty))
        .chain(
            ir.structures
                .iter()
                .flat_map(|structure| structure.fields.iter().map(|(_, ty)| ty)),
        )
        .chain(std::iter::once(&ir.ret_type))
    {
        names.extend(
            ty.to_string()
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
        );
    }
    for definition in &ir.definitions {
        names.extend(definition.name.split_whitespace().map(str::to_owned));
    }
    names
}

pub(in crate::render) fn name_parameters(ir: &mut FunctionIr, symbols: &Symbols) {
    // A source declaration owns its parameter names, including names like a0.
    if ir.declared_signature.is_some()
        || !ir
            .params
            .iter()
            .enumerate()
            .any(|(position, param)| param.name == format!("a{position}"))
    {
        return;
    }
    let roles = infer(ir, symbols);
    let mut reserved = reserved(ir, symbols);
    for (position, param) in ir.params.iter_mut().enumerate() {
        if param.name == format!("a{position}")
            && let Some(role) = roles.register(param.index)
        {
            param.name = crate::render::vacant_name(role, &mut reserved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        AbiIssue, BinOp, CType, CallKind, CallOutput, DeclaredSignature, Param, RegRef,
        VARIABLE_BASE,
    };
    use crate::loader::Isa;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
            at: None,
        }
    }

    fn call(ir: &FunctionIr, target: u64, args: Vec<Expr>, dest: u16) -> Stmt {
        Stmt::Call {
            abi: None,
            kind: CallKind::Invoke,
            target: Some(target),
            through: None,
            convention: ir.convention,
            args: Some(args),
            floats_named: true,
            outputs: vec![CallOutput {
                register: ir.convention.results()[0],
                dest: RegRef {
                    index: dest,
                    width: 64,
                },
            }],
            clobbers: None,
            via: None,
            at: None,
        }
    }

    fn signature(name: &str) -> DeclaredSignature {
        DeclaredSignature {
            params: vec![(name.to_owned(), CType::U64)],
            ret: CType::U64,
            variadic: false,
            abi: Err(AbiIssue::UnknownLayout),
        }
    }

    #[test]
    fn known_calls_name_values_and_avoid_symbols() {
        let index = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.params = vec![Param {
            index: 7,
            name: "a0".into(),
            ty: CType::pointer_to(CType::int(1, false)),
        }];
        ir.blocks[0].stmts = vec![
            call(&ir, 42, vec![Expr::reg(7, 64)], index),
            assign(
                index + 1,
                Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::reg(index, 64)),
            ),
            Stmt::Ret {
                value: Expr::reg(index + 1, 64),
                at: None,
            },
        ];
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "strlen".into());
        symbols.data.insert(99, "len".into());
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("*s)"), "{text}");
        assert!(text.contains("len_2 = strlen((const char *)s);"), "{text}");
        assert!(text.contains("len_2 +"), "{text}");
        ir.params[0].name = "text".into();
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("strlen((const char *)text)"), "{text}");
    }

    #[test]
    fn conflicting_call_arguments_use_first_name() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.params = vec![Param {
            index: 7,
            name: "a0".into(),
            ty: CType::pointer_to(CType::int(1, false)),
        }];
        ir.blocks[0].stmts = vec![
            call(&ir, 42, vec![Expr::reg(7, 64)], VARIABLE_BASE),
            call(&ir, 43, vec![Expr::reg(7, 64)], VARIABLE_BASE + 1),
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ];
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "strlen".into());
        symbols.functions.insert(43, "free".into());
        assert_eq!(infer(&ir, &symbols).register(7), Some("s"));
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("strlen((const char *)s)"), "{text}");
        assert!(text.contains("free(s)"), "{text}");
    }

    #[test]
    fn declared_and_library_prototypes_supply_parameter_names() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.blocks[0].stmts = vec![
            call(&ir, 42, vec![Expr::reg(7, 64)], VARIABLE_BASE),
            call(&ir, 43, vec![Expr::reg(8, 64)], VARIABLE_BASE + 1),
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ];
        ir.callee_signatures.insert(42, signature("hFile"));
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "read_handle".into());
        symbols.functions.insert(43, "ReadBuffer".into());
        symbols.library_prototypes.insert(
            "ReadBuffer".into(),
            crate::analysis::prototypes::Prototype {
                params: vec![CType::U64],
                parameter_names: vec!["buffer".into()],
                ret: CType::U64,
                variadic: false,
                format: None,
                scans: false,
            },
        );
        let roles = infer(&ir, &symbols);
        assert_eq!(roles.register(7), Some("hFile"));
        assert_eq!(roles.register(8), Some("buffer"));
    }

    #[test]
    fn cpp_unused_and_bundled_prototypes_supply_parameter_names() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.params = (7..11)
            .map(|index| Param {
                index,
                name: format!("a{}", index - 7),
                ty: CType::U64,
            })
            .collect();
        ir.blocks[0].stmts = vec![
            call(&ir, 42, vec![Expr::reg(7, 64)], VARIABLE_BASE),
            call(&ir, 43, vec![Expr::reg(8, 64)], VARIABLE_BASE + 1),
            call(
                &ir,
                44,
                vec![Expr::reg(9, 64), Expr::reg(10, 64)],
                VARIABLE_BASE + 2,
            ),
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ];
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "cpp_function".into());
        symbols.functions.insert(43, "unused_function".into());
        symbols.functions.insert(44, "setlocale".into());
        symbols.cpp_signatures.insert(42, signature("cppCount"));
        symbols.unused_parameters.insert(
            43,
            crate::analysis::prototypes::Prototype {
                params: vec![CType::U64],
                parameter_names: vec!["unusedPath".into()],
                ret: CType::U64,
                variadic: false,
                format: None,
                scans: false,
            },
        );

        let roles = infer(&ir, &symbols);
        assert_eq!(roles.register(7), Some("cppCount"));
        assert_eq!(roles.register(8), Some("unusedPath"));
        assert_eq!(roles.register(9), Some("__category"));
        assert_eq!(roles.register(10), Some("__locale"));

        let text = crate::render::render(&ir, &[], &symbols, &[]);
        for name in ["cppCount", "unusedPath", "__category", "__locale"] {
            assert!(text.contains(name), "{text}");
        }
    }

    #[test]
    fn unusable_parameter_names_are_rejected() {
        for name in ["", "a0", "v12", "local_4", "for", "1value", "not-a-name"] {
            assert_eq!(usable_parameter_name(name), None);
        }
        assert_eq!(usable_parameter_name("__fd"), Some("__fd"));
    }

    #[test]
    fn prototype_names_reach_width_masked_arguments() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.blocks[0].stmts = vec![
            call(
                &ir,
                42,
                vec![Expr::bin(
                    BinOp::And,
                    Expr::reg(7, 64),
                    Expr::Const(0xffff_ffff),
                )],
                VARIABLE_BASE,
            ),
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ];
        ir.callee_signatures.insert(42, signature("dwProcessId"));
        assert_eq!(
            infer(&ir, &Symbols::default()).register(7),
            Some("dwProcessId")
        );
    }

    #[test]
    fn first_declared_parameter_name_wins_and_names_are_unique() {
        let first = VARIABLE_BASE;
        let second = first + 1;
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.blocks[0].stmts = vec![
            assign(first, Expr::Const(1)),
            assign(second, Expr::Const(2)),
            call(
                &ir,
                42,
                vec![Expr::reg(first, 64), Expr::reg(second, 64)],
                first + 2,
            ),
            call(&ir, 43, vec![Expr::reg(first, 64)], first + 3),
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ];
        ir.callee_signatures.insert(
            42,
            DeclaredSignature {
                params: vec![("handle".into(), CType::U64), ("handle".into(), CType::U64)],
                ret: CType::U64,
                variadic: false,
                abi: Err(AbiIssue::UnknownLayout),
            },
        );
        ir.callee_signatures.insert(43, signature("path"));
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "first_call".into());
        symbols.functions.insert(43, "second_call".into());
        assert_eq!(infer(&ir, &symbols).register(first), Some("handle"));
        assert_eq!(infer(&ir, &symbols).register(second), Some("handle"));

        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("handle"), "{text}");
        assert!(text.contains("handle_2"), "{text}");
    }

    #[test]
    fn repeated_return_assignments_use_result() {
        let index = VARIABLE_BASE;
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(index, Expr::Const(1)),
                assign(
                    index,
                    Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::Const(2)),
                ),
                Stmt::Ret {
                    value: Expr::reg(index, 64),
                    at: None,
                },
            ],
        );
        let text = crate::render::render(&ir, &[], &Symbols::default(), &[]);
        assert!(text.contains("uint64_t result = 1;"), "{text}");
        assert!(text.contains("return result + 2;"), "{text}");
    }
    #[test]
    fn counted_register_and_stack_loops_use_i_in_printed_c() {
        use crate::ir::{Block, Cond};
        for stack in [false, true] {
            let index = VARIABLE_BASE;
            let addr = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
            let read = || {
                if stack {
                    Expr::Load {
                        addr: Box::new(addr.clone()),
                        width: 8,
                        signed: false,
                    }
                } else {
                    Expr::reg(index, 64)
                }
            };
            let set = |value| {
                if stack {
                    Stmt::Store {
                        addr: addr.clone(),
                        width: 8,
                        value,
                        at: None,
                    }
                } else {
                    assign(index, value)
                }
            };
            let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
            ir.blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![
                        set(Expr::Const(0)),
                        Stmt::Br {
                            target: Some(10),
                            at: None,
                        },
                    ],
                },
                Block {
                    start: 10,
                    stmts: vec![Stmt::Brif {
                        cond: Cond::Cc,
                        lhs: read(),
                        rhs: Expr::Const(10),
                        target: 30,
                        at: None,
                    }],
                },
                Block {
                    start: 20,
                    stmts: vec![
                        set(Expr::bin(BinOp::Add, read(), Expr::Const(1))),
                        Stmt::Br {
                            target: Some(10),
                            at: None,
                        },
                    ],
                },
                Block {
                    start: 30,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(0),
                        at: None,
                    }],
                },
            ];
            let text = crate::render::render(&ir, &[], &Symbols::default(), &[]);
            assert!(
                text.lines()
                    .any(|line| line.trim_start().starts_with("for (") && line.contains("i = 0;")),
                "{text}"
            );
            assert!(text.contains("i++)"), "{text}");
        }
    }

    #[test]
    fn pointer_loop_values_do_not_receive_counter_names() {
        use crate::render::structure::Node;

        let index = 7;
        let init = assign(index, Expr::Const(0));
        let step = assign(
            index,
            Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::Const(1)),
        );
        let looped = Node::While {
            prefix: Vec::new(),
            cond: crate::ir::Cond::Cc,
            lhs: Expr::reg(index, 64),
            rhs: Expr::Const(10),
            body: vec![Node::Stmt(step.clone())],
            at: None,
        };
        let nodes = vec![Node::Stmt(init.clone()), looped];
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![init, step]);
        ir.params = vec![Param {
            index,
            name: "a0".into(),
            ty: CType::pointer_to(CType::int(1, false)),
        }];
        assert_eq!(
            infer_with_nodes(&ir, &Symbols::default(), &nodes).register(index),
            None
        );

        ir.params.clear();
        assert_eq!(
            infer_with_nodes(&ir, &Symbols::default(), &nodes).register(index),
            Some("i")
        );

        let addr = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
        let load = || Expr::Load {
            addr: Box::new(addr.clone()),
            width: 8,
            signed: false,
        };
        let init = Stmt::Store {
            addr: addr.clone(),
            width: 8,
            value: Expr::reg(index, 64),
            at: None,
        };
        let step = Stmt::Store {
            addr: addr.clone(),
            width: 8,
            value: Expr::bin(BinOp::Add, load(), Expr::Const(1)),
            at: None,
        };
        let looped = Node::While {
            prefix: Vec::new(),
            cond: crate::ir::Cond::Cc,
            lhs: load(),
            rhs: Expr::Const(10),
            body: vec![Node::Stmt(step.clone())],
            at: None,
        };
        let nodes = vec![Node::Stmt(init.clone()), looped];
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![init, step]);
        ir.params = vec![Param {
            index,
            name: "a0".into(),
            ty: CType::pointer_to(CType::int(1, false)),
        }];
        assert_eq!(
            infer_with_nodes(&ir, &Symbols::default(), &nodes).slot(&addr),
            None
        );
    }

    #[test]
    fn counter_names_keep_unknown_integer_steps() {
        use crate::render::structure::Node;

        let index = VARIABLE_BASE;
        let init = assign(index, Expr::Const(0));
        let step = assign(
            index,
            Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::reg(8, 64)),
        );
        let looped = Node::While {
            prefix: Vec::new(),
            cond: crate::ir::Cond::Cc,
            lhs: Expr::reg(index, 64),
            rhs: Expr::Const(10),
            body: vec![Node::Stmt(step.clone())],
            at: None,
        };
        let nodes = vec![Node::Stmt(init.clone()), looped];
        let ir = FunctionIr::single_block(Isa::X86_64, vec![init, step]);
        assert_eq!(
            infer_with_nodes(&ir, &Symbols::default(), &nodes).register(index),
            Some("i")
        );
    }

    #[test]
    fn bit_shifts_and_binary_search_spans_are_not_counter_names() {
        use crate::render::structure::Node;

        let index = VARIABLE_BASE;
        for value in [
            Expr::bin(BinOp::Shr, Expr::reg(index, 64), Expr::Const(4)),
            Expr::bin(
                BinOp::Sub,
                Expr::reg(index, 64),
                Expr::bin(BinOp::Shr, Expr::reg(index, 64), Expr::Const(1)),
            ),
        ] {
            let init = assign(index, Expr::Const(0));
            let step = assign(index, value);
            let looped = Node::While {
                prefix: Vec::new(),
                cond: crate::ir::Cond::Cc,
                lhs: Expr::reg(index, 64),
                rhs: Expr::Const(10),
                body: vec![Node::Stmt(step.clone())],
                at: None,
            };
            let nodes = vec![Node::Stmt(init.clone()), looped];
            let ir = FunctionIr::single_block(Isa::X86_64, vec![init, step]);
            assert_eq!(
                infer_with_nodes(&ir, &Symbols::default(), &nodes).register(index),
                None
            );
        }
    }

    #[test]
    fn counter_names_accept_masked_constant_steps() {
        use crate::render::structure::Node;

        let index = VARIABLE_BASE;
        let init = assign(index, Expr::Const(0));
        let stepped = Expr::bin(
            BinOp::And,
            Expr::SignExtend {
                value: Box::new(Expr::bin(
                    BinOp::Add,
                    Expr::SignExtend {
                        value: Box::new(Expr::bin(
                            BinOp::And,
                            Expr::reg(index, 32),
                            Expr::reg(index + 1, 32),
                        )),
                        width: 4,
                    },
                    Expr::Const(1),
                )),
                width: 4,
            },
            Expr::Const(0xffff_ffff),
        );
        let step = assign(index, stepped);
        let looped = Node::While {
            prefix: Vec::new(),
            cond: crate::ir::Cond::Cc,
            lhs: Expr::reg(index, 64),
            rhs: Expr::Const(10),
            body: vec![Node::Stmt(step.clone())],
            at: None,
        };
        let nodes = vec![Node::Stmt(init.clone()), looped];
        let ir = FunctionIr::single_block(Isa::X86_64, vec![init, step]);
        assert_eq!(
            infer_with_nodes(&ir, &Symbols::default(), &nodes).register(index),
            Some("i")
        );
    }
}
