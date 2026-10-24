use std::collections::{BTreeMap, HashSet};

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::render::{Symbols, structure::Node};

#[derive(Clone, PartialEq, Eq)]
pub(in crate::render) enum Counter {
    Register(u16),
    Slot(Expr),
}

fn reads(expr: &Expr, counter: &Counter) -> bool {
    match (counter, expr) {
        (Counter::Register(index), Expr::Reg { index: read, .. }) => index == read,
        (Counter::Slot(addr), Expr::Load { addr: read, .. }) if addr == read.as_ref() => true,
        _ => crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| reads(child, counter)),
    }
}

fn loop_counter(init: &Stmt, looped: &Node) -> Option<Counter> {
    match looped {
        Node::While {
            prefix,
            lhs,
            rhs,
            body,
            ..
        } if prefix.is_empty() => counted(init, lhs, rhs, body),
        Node::DoWhile { lhs, rhs, body, .. } => counted(init, lhs, rhs, body),
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
) -> Option<Counter> {
    let Some((Node::Stmt(step), _)) = body.split_last() else {
        return None;
    };
    let counter = match init {
        Stmt::Assign { dest, .. } => Counter::Register(dest.index),
        Stmt::Store { addr, .. } => Counter::Slot(addr.clone()),
        _ => return None,
    };
    let steps = match (&counter, step) {
        (Counter::Register(index), Stmt::Assign { dest, value }) => {
            dest.index == *index && reads(value, &counter)
        }
        (
            Counter::Slot(addr),
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

#[derive(Default)]
pub(in crate::render) struct Roles {
    candidates: Vec<(Counter, Option<&'static str>)>,
}

impl Roles {
    fn suggest(&mut self, counter: Counter, name: &'static str) {
        if let Some((_, previous)) = self.candidates.iter_mut().find(|(key, _)| *key == counter) {
            if *previous != Some(name) {
                *previous = None;
            }
        } else {
            self.candidates.push((counter, Some(name)));
        }
    }

    fn prefer(&mut self, other: Self) {
        self.candidates
            .retain(|(key, _)| !other.candidates.iter().any(|(other, _)| key == other));
        self.candidates.extend(other.candidates);
    }

    pub(in crate::render) fn register(&self, index: u16) -> Option<&'static str> {
        self.candidates.iter().find_map(|(key, name)| {
            (*key == Counter::Register(index))
                .then_some(*name)
                .flatten()
        })
    }

    pub(in crate::render) fn slot(&self, addr: &Expr) -> Option<&'static str> {
        self.candidates.iter().find_map(|(key, name)| {
            matches!(key, Counter::Slot(key) if key == addr)
                .then_some(*name)
                .flatten()
        })
    }
}

fn value(expr: &Expr) -> Option<Counter> {
    match expr {
        Expr::Reg { index, .. } => Some(Counter::Register(*index)),
        Expr::Load { addr, .. } => Some(Counter::Slot(addr.as_ref().clone())),
        _ => None,
    }
}

fn loops(nodes: &[Node], depth: usize, roles: &mut Roles) {
    for (position, node) in nodes.iter().enumerate() {
        if let Node::Stmt(init) = node
            && let Some(looped) = nodes.get(position + 1)
            && let Some(counter) = loop_counter(init, looped)
        {
            roles.suggest(counter, ["i", "j", "k"][depth.min(2)]);
        }
        match node {
            Node::While { body, .. } | Node::DoWhile { body, .. } | Node::Forever { body } => {
                loops(body, depth.saturating_add(1), roles);
            }
            Node::If { then, els, .. } => {
                loops(then, depth, roles);
                loops(els, depth, roles);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    loops(body, depth, roles);
                }
                if let Some(body) = default {
                    loops(body, depth, roles);
                }
            }
            _ => {}
        }
    }
}

pub(in crate::render) fn infer(ir: &FunctionIr, symbols: &Symbols) -> Roles {
    let mut roles = Roles::default();
    let mut call_results = Roles::default();
    let mut writes = BTreeMap::<u16, usize>::new();
    let mut returned = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, .. } = stmt {
            *writes.entry(dest.index).or_default() += 1;
        }
        if let Stmt::Ret { value: expr } = stmt {
            returned.push(value(expr));
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
            .and_then(|address| symbols.functions.get(&address))
            .or_else(|| match through {
                Some(Expr::Load { addr, width: 8, .. }) => match addr.as_ref() {
                    Expr::Const(slot) => symbols.import_slots.get(slot),
                    _ => None,
                },
                _ => None,
            });
        let Some(name) = name else {
            continue;
        };
        let name = name.strip_prefix('_').unwrap_or(name);
        let (params, result): (&[&str], Option<&str>) = match name {
            "strlen" => (&["s"], Some("len")),
            "strnlen" => (&["s", "n"], Some("len")),
            "memcpy" | "memmove" => (&["dst", "src", "n"], None),
            "memset" => (&["dst", "c", "n"], None),
            "strcmp" => (&["s1", "s2"], None),
            "strncmp" => (&["s1", "s2", "n"], None),
            "malloc" => (&["size"], Some("p")),
            "calloc" => (&["n", "size"], Some("buf")),
            "realloc" => (&["ptr", "size"], Some("buf")),
            "free" => (&["ptr"], None),
            "open" => (&["path", "flags"], Some("fd")),
            "read" => (&["fd", "buf", "n"], Some("n")),
            "write" => (&["fd", "buf", "n"], Some("n")),
            _ => continue,
        };
        if let Some(args) = args {
            for (arg, name) in args.iter().zip(params) {
                if let Some(counter) = value(arg) {
                    roles.suggest(counter, name);
                }
            }
        }
        if let Some(name) = result {
            for output in outputs {
                if convention.results().first() == Some(&output.register) {
                    call_results.suggest(Counter::Register(output.dest.index), name);
                }
            }
        }
    }
    roles.prefer(call_results);
    if let Some(Some(counter)) = returned.first()
        && returned.iter().all(|other| other.as_ref() == Some(counter))
    {
        let assigned = match counter {
            Counter::Register(index) => {
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
            Counter::Slot(addr) => ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .filter(|stmt| matches!(stmt, Stmt::Store { addr: written, .. } if written == addr))
                .count(),
        };
        if assigned > 1 {
            roles.suggest(counter.clone(), "result");
        }
    }
    let mut counters = Roles::default();
    loops(&crate::render::structure_best(ir), 0, &mut counters);
    roles.prefer(counters);
    roles
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
    if ir.declared_signature.is_some() {
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
    use crate::ir::{BinOp, CType, CallKind, CallOutput, Param, RegRef, VARIABLE_BASE};
    use crate::loader::Isa;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn call(ir: &FunctionIr, target: u64, args: Vec<Expr>, dest: u16) -> Stmt {
        Stmt::Call {
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
            },
        ];
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "strlen".into());
        symbols.data.insert(99, "len".into());
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("*s)"), "{text}");
        assert!(text.contains("len_2 = strlen(s);"), "{text}");
        assert!(text.contains("len_2 +"), "{text}");
        ir.params[0].name = "text".into();
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("strlen(text)"), "{text}");
    }

    #[test]
    fn conflicting_roles_keep_generic_names() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.blocks[0].stmts = vec![
            call(&ir, 42, vec![Expr::reg(7, 64)], VARIABLE_BASE),
            call(&ir, 43, vec![Expr::reg(7, 64)], VARIABLE_BASE + 1),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ];
        let mut symbols = Symbols::default();
        symbols.functions.insert(42, "strlen".into());
        symbols.functions.insert(43, "free".into());
        assert_eq!(infer(&ir, &symbols).register(7), None);
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
                },
            ],
        );
        let text = crate::render::render(&ir, &[], &Symbols::default(), &[]);
        assert!(text.contains("int64_t result;"), "{text}");
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
                    }
                } else {
                    assign(index, value)
                }
            };
            let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
            ir.blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![set(Expr::Const(0)), Stmt::Br { target: Some(10) }],
                },
                Block {
                    start: 10,
                    stmts: vec![Stmt::Brif {
                        cond: Cond::Cc,
                        lhs: read(),
                        rhs: Expr::Const(10),
                        target: 30,
                    }],
                },
                Block {
                    start: 20,
                    stmts: vec![
                        set(Expr::bin(BinOp::Add, read(), Expr::Const(1))),
                        Stmt::Br { target: Some(10) },
                    ],
                },
                Block {
                    start: 30,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(0),
                    }],
                },
            ];
            let text = crate::render::render(&ir, &[], &Symbols::default(), &[]);
            assert!(text.contains("for (i = 0;"), "{text}");
            assert!(text.contains("i++)"), "{text}");
        }
    }
}
