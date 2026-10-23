//! A call whose result only the statement right after it reads, written
//! into that statement: `v3 = f(a0); g(v3, 0x1);` reads `g(f(a0), 0x1);`.

use std::collections::{HashMap, HashSet};

use crate::ir::{BinOp, CallOutput, Cond, Expr, FunctionIr, Stmt, VARIABLE_BASE};
use crate::passes::copies::reads_memory;
use crate::render::expr::Ctx;
use crate::render::structure::Node;

/// The longest statement, without its indentation, a call may be written
/// into.
const LINE: usize = 100;
/// The longest call a condition may take in.
const CONDITION_CALL: usize = 60;

type Bindings = Vec<(u16, u16, u8)>;

#[derive(PartialEq, Eq, Hash)]
struct CallKey {
    target: Option<u64>,
    through: Option<Expr>,
    convention: std::mem::Discriminant<crate::ir::Convention>,
    args: Option<Vec<Expr>>,
    floats_named: bool,
    clobbers: Option<crate::ir::Registers>,
    outputs: Bindings,
}

#[derive(Default)]
pub(super) struct Outputs {
    live: HashMap<CallKey, HashSet<u16>>,
    pub(super) sources: HashMap<u16, String>,
    pub(super) declarations: Vec<String>,
    pub(super) temporary: String,
}

fn key(stmt: &Stmt) -> CallKey {
    let Stmt::Call {
        target,
        through,
        convention,
        args,
        floats_named,
        clobbers,
        ..
    } = stmt
    else {
        unreachable!("a call key requires a call");
    };
    let outputs = stmt
        .call_outputs()
        .iter()
        .map(|output| (output.register, output.dest.index, output.dest.width))
        .collect();
    CallKey {
        target: *target,
        through: through.clone(),
        convention: std::mem::discriminant(convention),
        args: args.clone(),
        floats_named: *floats_named,
        clobbers: *clobbers,
        outputs,
    }
}

impl Outputs {
    pub(super) fn new(
        ir: &FunctionIr,
        machine: &[(u16, String)],
        reserved: &mut HashSet<String>,
    ) -> Self {
        let mut outputs = Self::default();
        if !ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Call { .. }))
        {
            return outputs;
        }
        outputs.temporary = super::vacant_name("call_values", reserved);
        let incoming = crate::ir::cfg::live_in(ir);
        for (index, block) in ir.blocks.iter().enumerate() {
            let mut live = crate::ir::cfg::live_out(ir, &incoming, index);
            for stmt in block.stmts.iter().rev() {
                if matches!(stmt, Stmt::Call { .. }) {
                    let used = outputs.live.entry(key(stmt)).or_default();
                    used.extend(
                        stmt.call_outputs()
                            .iter()
                            .filter(|output| live.contains(&output.dest.index))
                            .map(|output| output.dest.index),
                    );
                }
                let (writes, reads) = crate::ir::visit::statement_registers(stmt);
                live.retain(|register| !writes.contains(register));
                live.extend(reads);
            }
        }
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            for output in stmt.call_outputs() {
                if !outputs.used(stmt, output) || outputs.sources.contains_key(&output.register) {
                    continue;
                }
                let name = match machine
                    .iter()
                    .find(|(register, _)| *register == output.register)
                {
                    Some((_, name)) => name.clone(),
                    None => {
                        let name = super::vacant_name(
                            &crate::ir::reg_name(ir.isa, output.register, 64),
                            reserved,
                        );
                        outputs.declarations.push(name.clone());
                        name
                    }
                };
                outputs.sources.insert(output.register, name);
            }
        }
        outputs
    }

    pub(super) fn used(&self, stmt: &Stmt, output: &CallOutput) -> bool {
        self.live
            .get(&key(stmt))
            .is_none_or(|live| live.contains(&output.dest.index))
    }
}

pub(super) fn scalar_output<'a>(call: &'a Stmt, ctx: &Ctx<'_>) -> Option<&'a CallOutput> {
    match return_type(call, ctx) {
        Some(ty) => crate::analysis::prototypes::scalar_call_output(call, ty),
        None => call.primary_call_output(),
    }
}

fn return_type<'a>(call: &Stmt, ctx: &'a Ctx<'_>) -> Option<&'a crate::ir::CType> {
    let Stmt::Call {
        target, through, ..
    } = call
    else {
        return None;
    };
    match through {
        Some(Expr::Load { addr, width: 8, .. }) if let Expr::Const(slot) = addr.as_ref() => {
            ctx.symbols.import_returns.get(slot)
        }
        Some(_) => None,
        None => ctx.symbols.function_returns.get(&(*target)?),
    }
}

pub(super) fn scalar_fusion(call: &Stmt, ctx: &Ctx<'_>) -> Option<crate::ir::RegRef> {
    let output = scalar_output(call, ctx)?;
    if !matches!(output.dest.width, 32 | 64)
        || ctx
            .declared
            .get(&output.dest.index)
            .is_some_and(|declared| declared.integer && !matches!(declared.bits, 32 | 64))
        || precision(return_type(call, ctx)).is_some()
        || call
            .preserved_output_sources()
            .iter()
            .any(|(index, _)| call.call_outputs()[*index] == *output)
        || call.call_outputs().iter().any(|other| {
            other != output
                && ctx.call_outputs.used(call, other)
                && !identity_output(call, other, ctx)
        })
    {
        return None;
    }
    Some(output.dest)
}

fn identity_output(call: &Stmt, output: &CallOutput, ctx: &Ctx<'_>) -> bool {
    if output.dest.width != 64 {
        return false;
    }
    let preserved = call.preserved_output_sources();
    let source = preserved
        .iter()
        .find(|(index, _)| call.call_outputs()[*index] == *output)
        .map(|(_, register)| ctx.register(*register, 64));
    if source.is_none() && scalar_output(call, ctx) == Some(output) {
        return false;
    }
    let source = source
        .as_ref()
        .or_else(|| ctx.call_outputs.sources.get(&output.register));
    let target = ctx.register(output.dest.index, 64);
    source == Some(&target)
        && !call.call_outputs().iter().any(|other| {
            other != output && ctx.register(other.dest.index, other.dest.width) == target
        })
}

pub(super) fn expression(call: &Stmt, ctx: &Ctx<'_>) -> String {
    let Stmt::Call {
        target,
        through,
        args,
        convention,
        ..
    } = call
    else {
        unreachable!("a call expression requires a call");
    };
    let number = match args.as_ref().and_then(|values| values.first()) {
        Some(Expr::Const(number)) => super::system_call_name(*convention, *number),
        _ => None,
    };
    let mut args: Vec<String> = args
        .iter()
        .flatten()
        .map(|arg| super::argument(arg, ctx))
        .collect();
    if let (Some(name), Some(first)) = (number, args.first_mut()) {
        *first = format!("SYS_{name}");
    }
    let callee = match (through, target) {
        _ if matches!(
            convention,
            crate::ir::Convention::SyscallX86 | crate::ir::Convention::SyscallArm
        ) =>
        {
            "syscall".to_owned()
        }
        (Some(Expr::Load { addr, width: 8, .. }), _)
            if let Expr::Const(slot) = addr.as_ref()
                && let Some(name) = ctx.symbols.import_slots.get(slot) =>
        {
            super::sanitize(name)
        }
        (Some(through), _) => {
            let text = super::render_value(through, ctx);
            if text.contains(char::is_whitespace) {
                format!("((uint64_t (*)())({text}))")
            } else {
                format!("((uint64_t (*)()){text})")
            }
        }
        (None, Some(target)) => ctx
            .symbols
            .functions
            .get(target)
            .map_or_else(|| format!("sub_{target:x}"), |name| super::sanitize(name)),
        (None, None) => "sub_<dynamic>".to_owned(),
    };
    format!("{callee}({})", args.join(", "))
}

fn precision(ty: Option<&crate::ir::CType>) -> Option<crate::ir::Precision> {
    match ty?.to_string().as_str() {
        "float" => Some(crate::ir::Precision::Single),
        "double" => Some(crate::ir::Precision::Double),
        _ => None,
    }
}

fn bits(text: String, index: u16, ctx: &Ctx<'_>) -> String {
    if let Some(precision) = ctx.floats.get(&index) {
        super::expr::float_bits(text, *precision).text
    } else if ctx.pointer_types.contains_key(&index) {
        format!("(uint64_t)(uintptr_t){text}")
    } else {
        text
    }
}

fn projected(value: String, width: u8) -> String {
    match width {
        64 => value,
        width @ (8 | 16 | 32) => format!("({})({value})", super::type_of(width / 8, false)),
        width => format!(
            "((uint64_t)({value}) & 0x{:x})",
            crate::ir::semantics::mask(u32::from(width))
        ),
    }
}

fn assigned_value(output: &CallOutput, value: String, ctx: &Ctx<'_>) -> String {
    let value = projected(value, output.dest.width);
    if let Some(precision) = ctx.floats.get(&output.dest.index) {
        let (float, integer) = match precision {
            crate::ir::Precision::Single => ("float", "uint32_t"),
            crate::ir::Precision::Double => ("double", "uint64_t"),
        };
        format!("((union {{ {integer} bits; {float} value; }}){{ .bits = {value} }}).value")
    } else if let Some(ty) = ctx.pointer_types.get(&output.dest.index) {
        format!("({ty})(uintptr_t)({value})")
    } else {
        value
    }
}

fn commit(output: &CallOutput, value: String, ctx: &Ctx<'_>) -> String {
    let value = assigned_value(output, value, ctx);
    format!(
        "{} = {value};",
        ctx.register(output.dest.index, output.dest.width)
    )
}

pub(super) fn captured(call: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
    let dest = scalar_fusion(call, ctx)?;
    if ctx.floats.contains_key(&dest.index) {
        return None;
    }
    let output = scalar_output(call, ctx)?;
    let value = expression(call, ctx);
    let value = if return_type(call, ctx).is_some_and(crate::ir::CType::is_pointer) {
        format!("(uint64_t)(uintptr_t){value}")
    } else {
        value
    };
    if let Some(declared) = ctx.declared.get(&dest.index)
        && declared.integer
        && (declared.bits < 64 || dest.width < 64)
    {
        let value = if declared.bits <= u32::from(dest.width) {
            value
        } else {
            projected(value, dest.width)
        };
        return Some(format!(
            "({})({value})",
            super::type_of((declared.bits / 8) as u8, declared.signed)
        ));
    }
    Some(assigned_value(output, value, ctx))
}

pub(super) fn returned(call: &Stmt, value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    let dest = scalar_fusion(call, ctx)?;
    if *value != Expr::reg(dest.index, dest.width) || ctx.void_return || ctx.float_return.is_some()
    {
        return None;
    }
    if let (Some(returned), Some(stored)) = (ctx.returned, ctx.declared.get(&dest.index))
        && returned.integer
        && stored.integer
        && matches!(returned.bits, 32 | 64)
        && u32::from(dest.width) >= returned.bits
        && stored.bits >= returned.bits
    {
        return Some(format!("return {};", expression(call, ctx)));
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
            projected(expression(call, ctx), dest.width)
        ));
    }
    let text = super::returned(value, ctx);
    let name = ctx.register(dest.index, dest.width);
    let at = only_word(&text, &name)?;
    let value = captured(call, ctx)?;
    Some(format!(
        "return {}({value}){};",
        &text[..at],
        &text[at + name.len()..]
    ))
}

pub(super) fn render(call: &Stmt, ctx: &Ctx<'_>) -> String {
    let used: Vec<_> = call
        .call_outputs()
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            ctx.call_outputs.used(call, output) && !identity_output(call, output, ctx)
        })
        .collect();
    let text = expression(call, ctx);
    if used.is_empty() {
        return format!("{text};");
    }
    let scalar = scalar_output(call, ctx);
    let preserved = call.preserved_output_sources();
    let scalar_bits = || match precision(return_type(call, ctx)) {
        Some(precision) => super::expr::float_bits(text.clone(), precision).text,
        None if return_type(call, ctx).is_some_and(crate::ir::CType::is_pointer) => {
            format!("(uint64_t)(uintptr_t){text}")
        }
        None => text.clone(),
    };
    if let [(index, output)] = used.as_slice()
        && scalar == Some(*output)
        && !preserved.iter().any(|(preserved, _)| preserved == index)
    {
        if precision(return_type(call, ctx)) == ctx.floats.get(&output.dest.index).copied()
            && return_type(call, ctx).is_some_and(crate::ir::CType::is_pointer)
                == ctx.pointer_types.contains_key(&output.dest.index)
            && output.dest.width == 64
        {
            return format!(
                "{} = {text};",
                ctx.register(output.dest.index, output.dest.width)
            );
        }
        return commit(output, scalar_bits(), ctx);
    }
    let temporary = &ctx.call_outputs.temporary;
    let mut lines = vec![
        "{".to_owned(),
        format!("    uint64_t {temporary}[{}];", used.len()),
    ];
    for (at, (index, _)) in used.iter().enumerate() {
        if let Some((_, source)) = preserved.iter().find(|(preserved, _)| preserved == index) {
            let value = match ctx.names.get(source) {
                Some(_) => bits(ctx.register(*source, 64), *source, ctx),
                None => ctx.call_outputs.sources[source].clone(),
            };
            lines.push(format!("    {temporary}[{at}] = {value};"));
        }
    }
    let scalar_at = used.iter().enumerate().find(|(_, (index, output))| {
        scalar == Some(*output) && !preserved.iter().any(|(preserved, _)| preserved == index)
    });
    match scalar_at {
        Some((at, _)) => lines.push(format!("    {temporary}[{at}] = {};", scalar_bits())),
        None => lines.push(format!("    {text};")),
    }
    for (at, (index, output)) in used.iter().enumerate() {
        if preserved.iter().any(|(preserved, _)| preserved == index) || scalar == Some(*output) {
            continue;
        }
        let source = &ctx.call_outputs.sources[&output.register];
        lines.push(format!(
            "    {temporary}[{at}] = {source}; /* also returned by the call */"
        ));
    }
    for (at, (_, output)) in used.iter().enumerate() {
        lines.push(format!(
            "    {}",
            commit(output, format!("{temporary}[{at}]"), ctx)
        ));
    }
    lines.push("}".to_owned());
    lines.join("\n")
}

/// The variables the structured function reads exactly once.
pub(super) fn read_once(nodes: &[Node]) -> HashSet<u16> {
    let mut counts = HashMap::new();
    count_nodes(nodes, &mut counts);
    counts
        .into_iter()
        .filter(|(_, count)| *count == 1)
        .map(|(register, _)| register)
        .collect()
}

fn count_nodes(nodes: &[Node], counts: &mut HashMap<u16, usize>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => {
                for operand in stmt.operands() {
                    count_expr(operand, counts);
                }
                for (_, source) in stmt.preserved_output_sources() {
                    *counts.entry(source).or_default() += 1;
                }
            }
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                count_expr(lhs, counts);
                count_expr(rhs, counts);
                count_nodes(then, counts);
                count_nodes(els, counts);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                count_expr(lhs, counts);
                count_expr(rhs, counts);
                count_nodes(body, counts);
            }
            Node::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                count_nodes(prefix, counts);
                count_expr(lhs, counts);
                count_expr(rhs, counts);
                count_nodes(body, counts);
            }
            Node::Forever { body } => count_nodes(body, counts),
            Node::Switch {
                index,
                arms,
                default,
            } => {
                count_expr(index, counts);
                for (_, body) in arms {
                    count_nodes(body, counts);
                }
                if let Some(body) = default {
                    count_nodes(body, counts);
                }
            }
            Node::Label(_) | Node::Break | Node::Continue => {}
        }
    }
}

fn count_expr(expr: &Expr, counts: &mut HashMap<u16, usize>) {
    match expr {
        Expr::Reg { index, .. } => *counts.entry(*index).or_default() += 1,
        _ => {
            for child in crate::ir::visit::children(expr) {
                count_expr(child, counts);
            }
        }
    }
}

/// `call` written into `next`, the node after it, when `next` is the one
/// reader of the call's result and takes it whole, as an argument, a stored
/// or returned value, or one side of an equality test. No other part of
/// `next` reads memory, which the call may change, so the order C leaves
/// open among them does not matter.
pub(super) fn call_in_reader(
    call: &Stmt,
    next: &Node,
    depth: usize,
    ctx: &Ctx<'_>,
) -> Option<String> {
    if !matches!(call, Stmt::Call { args: Some(_), .. }) {
        return None;
    }
    let result = scalar_fusion(call, ctx)?;
    let dest = result.index;
    if dest < VARIABLE_BASE || !ctx.read_once.contains(&dest) {
        return None;
    }
    let declared = ctx.declared.get(&dest)?;
    if !declared.integer {
        return None;
    }
    let whole = |expr: &Expr| match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => {
            *lhs.as_ref() == Expr::reg(dest, result.width)
        }
        _ => *expr == Expr::reg(dest, result.width),
    };
    let apart = |exprs: &[&Expr]| exprs.iter().all(|expr| !reads_memory(expr));
    let condition = match next {
        Node::Stmt(Stmt::Call {
            through,
            args: Some(args),
            ..
        }) => {
            let at = args.iter().position(whole)?;
            let others: Vec<&Expr> = through
                .iter()
                .chain(
                    args.iter()
                        .enumerate()
                        .filter(|(position, _)| *position != at)
                        .map(|(_, arg)| arg),
                )
                .collect();
            if !apart(&others) {
                return None;
            }
            false
        }
        Node::Stmt(Stmt::Store { addr, value, .. }) if whole(value) && apart(&[addr]) => false,
        Node::Stmt(Stmt::Assign { value, .. } | Stmt::Ret { value }) if whole(value) => false,
        Node::If {
            cond: Cond::Eq | Cond::Ne,
            lhs,
            rhs,
            ..
        } if (whole(lhs) && apart(&[rhs])) || (whole(rhs) && apart(&[lhs])) => true,
        _ => return None,
    };
    if !super::via_comment(call, ctx).is_empty() {
        return None;
    }
    let text = captured(call, ctx)?;
    if condition && text.len() > CONDITION_CALL {
        return None;
    }
    let mut rendered = String::new();
    super::render_node(next, depth, &mut rendered, ctx);
    let (first, rest) = rendered.split_once('\n')?;
    if !condition && !rest.is_empty() {
        return None;
    }
    let name = ctx.register(dest, 64);
    let at = only_word(first, &name)?;
    let text = if text.starts_with('(') {
        format!("({text})")
    } else {
        text
    };
    let line = format!("{}{text}{}", &first[..at], &first[at + name.len()..]);
    if line.trim_start().len() > LINE {
        return None;
    }
    Some(format!("{line}\n{rest}"))
}

/// Where `word` stands in `line` as a whole word, when it does just once.
fn only_word(line: &str, word: &str) -> Option<usize> {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut found = line.match_indices(word).filter(|(at, _)| {
        !line[..*at].ends_with(part) && !line[at + word.len()..].starts_with(part)
    });
    let (at, _) = found.next()?;
    found.next().is_none().then_some(at)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::ir::{CType, Convention, Expr, FunctionIr, Param, RegRef, Stmt, VARIABLE_BASE};
    use crate::loader::Isa;

    fn call(target: u64, args: Vec<Expr>) -> Stmt {
        Stmt::Call {
            target: Some(target),
            through: None,
            convention: Convention::SysV,
            args: Some(args),
            floats_named: true,
            outputs: crate::ir::fallback_call_outputs(Convention::SysV, None),
            clobbers: None,
            via: None,
        }
    }

    /// `v1 = f(a0); g(v1, second); return 0;` as the output prints it.
    fn rendered(second: Expr) -> String {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call(0x1000, vec![Expr::reg(7, 64)]),
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::reg(0, 64),
                },
                call(0x2000, vec![Expr::reg(VARIABLE_BASE, 64), second]),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::I64,
            },
            Param {
                index: 6,
                name: "a1".to_owned(),
                ty: CType::pointer_to(CType::I64),
            },
        ];
        crate::ssa::split_variables(&mut ir, Convention::SysV.results());
        crate::ssa::take_results_directly(&mut ir);
        crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[])
    }

    #[test]
    fn a_result_read_once_reads_as_the_call() {
        let text = rendered(Expr::Const(1));
        assert!(text.contains("sub_2000(sub_1000(a0), 0x1);"), "{text}");
        assert!(!text.contains("v1"), "{text}");
    }

    #[test]
    fn a_result_stays_named_beside_a_read_of_memory() {
        let load = Expr::Load {
            addr: Box::new(Expr::reg(6, 64)),
            width: 8,
            signed: false,
        };
        let text = rendered(load);
        assert!(text.contains("v1 = sub_1000(a0);"), "{text}");
    }

    fn output(register: u16, dest: u16, width: u8) -> crate::ir::CallOutput {
        crate::ir::CallOutput {
            register,
            dest: RegRef { index: dest, width },
        }
    }

    #[test]
    fn reordered_outputs_keep_the_primary_and_narrow_secondary_destinations() {
        let (first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut call = call(0x1000, vec![]);
        if let Stmt::Call { outputs, .. } = &mut call {
            *outputs = vec![output(2, second, 32), output(0, first, 64)];
        }
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::bin(
                        crate::ir::BinOp::Add,
                        Expr::reg(first, 64),
                        Expr::reg(second, 64),
                    ),
                },
            ],
        );
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        for expected in [
            " v1;",
            " v2;",
            "uint64_t rdx;",
            "call_values[1] = sub_1000();",
            "call_values[0] = rdx;",
            "v2 = (uint32_t)(call_values[0]);",
            "v1 = call_values[1];",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert!(!text.contains("return sub_1000()"), "{text}");
        assert_eq!(text.matches("sub_1000()").count(), 1, "{text}");
        let setup = crate::ir::eval::Setup {
            seed: 1,
            convention: crate::ir::eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[],
            memory: &[],
            step_limit: 100,
        };
        let state = crate::ir::eval::registers_after(&ir, &setup).expect("call must return");
        let mut wide = ir.clone();
        wide.blocks[0].stmts[0].call_outputs_mut()[0].dest.width = 64;
        let wide_state =
            crate::ir::eval::registers_after(&wide, &setup).expect("wide call must return");
        assert!(wide_state[&second] > u64::from(u32::MAX));
        assert_eq!(state[&second], wide_state[&second] & u64::from(u32::MAX));
        assert_eq!(state[&first], wide_state[&first]);
    }

    #[test]
    fn preserved_output_swaps_snapshot_every_source_before_destination_writes() {
        let mut call = call(0x1000, vec![Expr::reg(7, 64), Expr::reg(6, 64)]);
        if let Stmt::Call {
            outputs, clobbers, ..
        } = &mut call
        {
            *outputs = vec![output(7, 6, 64), output(6, 7, 64)];
            *clobbers = Some(crate::ir::Registers(0));
        }
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::bin(crate::ir::BinOp::Sub, Expr::reg(7, 64), Expr::reg(6, 64)),
                },
            ],
        );
        ir.params = [(7, "left"), (6, "right")]
            .into_iter()
            .map(|(index, name)| Param {
                index,
                name: name.to_owned(),
                ty: CType::U64,
            })
            .collect();
        let outcome = crate::ir::eval::run(
            &ir,
            &crate::ir::eval::Setup {
                seed: 1,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(7, 0x31), (6, 0x17)],
                memory: &[],
                step_limit: 100,
            },
        );
        assert_eq!(
            outcome,
            crate::ir::eval::Outcome::Return {
                value: 0x17u64.wrapping_sub(0x31),
                calls: vec![crate::ir::eval::Call {
                    target: Some(0x1000),
                    arguments: vec![0x31, 0x17]
                }],
                memory: Default::default(),
            }
        );
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        let mut previous = 0;
        for expected in [
            "call_values[0] = left;",
            "call_values[1] = right;",
            "sub_1000(left, right);",
            "right = call_values[0];",
            "left = call_values[1];",
        ] {
            let at = text
                .find(expected)
                .unwrap_or_else(|| panic!("{expected}: {text}"));
            assert!(at >= previous, "{text}");
            previous = at;
        }
        assert_eq!(text.matches("sub_1000(left, right)").count(), 1, "{text}");
    }

    #[test]
    fn known_float_returns_use_the_recorded_output_register_without_guessing_from_names() {
        let (integer, float) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut call = call(0x1000, vec![]);
        if let Stmt::Call { outputs, .. } = &mut call {
            *outputs = vec![
                output(0, integer, 64),
                output(crate::arch::x86::XMM0, float, 64),
            ];
        }
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(float, 64),
                },
            ],
        );
        ir.ret_type = CType::Named("double".to_owned());
        let symbols = crate::render::Symbols {
            functions: HashMap::from([(0x1000, "strtod".to_owned())]),
            function_returns: HashMap::from([(0x1000, CType::Named("double".to_owned()))]),
            ..Default::default()
        };
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(text.contains("v2 = strtod();"), "{text}");
        assert!(!text.contains("v1 = strtod()"), "{text}");
        let symbols = crate::render::Symbols {
            function_returns: Default::default(),
            ..symbols
        };
        let text = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(!text.contains("v2 = strtod();"), "{text}");
        assert!(text.contains("also returned by the call"), "{text}");
    }

    #[test]
    fn preserved_physical_sources_do_not_capture_another_parameters_name() {
        let mut call = call(0x1000, vec![]);
        if let Stmt::Call {
            outputs, clobbers, ..
        } = &mut call
        {
            *outputs = vec![output(2, VARIABLE_BASE, 64)];
            *clobbers = Some(crate::ir::Registers(0));
        }
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "rdx".to_owned(),
            ty: CType::U64,
        }];
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(text.contains("uint64_t rdx_2;"), "{text}");
        assert!(text.contains("call_values[0] = rdx_2;"), "{text}");
        assert!(!text.contains("call_values[0] = rdx;"), "{text}");
    }

    #[test]
    fn narrow_call_outputs_keep_truncation_when_returned_as_u64() {
        let make = |width| {
            let mut call = call(0x1000, vec![]);
            if let Stmt::Call { outputs, .. } = &mut call {
                *outputs = vec![output(0, VARIABLE_BASE, width)];
            }
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    call,
                    Stmt::Ret {
                        value: Expr::reg(VARIABLE_BASE, width),
                    },
                ],
            );
            ir.ret_type = CType::U64;
            ir
        };
        let (narrow, wide) = (make(32), make(64));
        let mut observed_high = false;
        for seed in 0..4 {
            let setup = crate::ir::eval::Setup {
                seed,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            let crate::ir::eval::Outcome::Return {
                value: narrow_value,
                ..
            } = crate::ir::eval::run(&narrow, &setup)
            else {
                panic!("narrow call must return");
            };
            let crate::ir::eval::Outcome::Return {
                value: wide_value, ..
            } = crate::ir::eval::run(&wide, &setup)
            else {
                panic!("wide call must return");
            };
            observed_high |= wide_value > u64::from(u32::MAX);
            assert_eq!(narrow_value, wide_value & u64::from(u32::MAX));
        }
        assert!(observed_high);
        let text = crate::render::render(&narrow, &[], &Default::default(), &[]);
        assert!(text.contains("return (uint32_t)(sub_1000());"), "{text}");
        assert!(!text.contains(" v1;"), "{text}");
        assert!(!text.contains("return sub_1000();"), "{text}");
    }

    #[test]
    fn full_width_self_copies_disappear_but_narrow_copies_keep_their_effect() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::reg(7, 64),
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 32,
                    },
                    value: Expr::reg(VARIABLE_BASE, 32),
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "input".to_owned(),
            ty: CType::U64,
        }];
        ir.ret_type = CType::U64;
        let result = crate::ir::eval::run(
            &ir,
            &crate::ir::eval::Setup {
                seed: 1,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(7, 0x1_0000_0005)],
                memory: &[],
                step_limit: 100,
            },
        );
        assert_eq!(
            result,
            crate::ir::eval::Outcome::Return {
                value: 5,
                calls: vec![],
                memory: Default::default()
            }
        );
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!text.contains("v1 = v1;"), "{text}");
        assert!(text.contains("v1 = (uint32_t)v1;"), "{text}");
    }

    #[test]
    fn distinct_call_contents_do_not_share_live_outputs() {
        for (target, argument, shared) in
            [(0x2000, 1, false), (0x1000, 2, false), (0x1000, 1, true)]
        {
            let mut first = call(0x1000, vec![Expr::Const(1)]);
            if let Stmt::Call { outputs, .. } = &mut first {
                *outputs = vec![output(2, 2, 64)];
            }
            let mut second = first.clone();
            if let Stmt::Call {
                target: called,
                args,
                ..
            } = &mut second
            {
                *called = Some(target);
                *args = Some(vec![Expr::Const(argument)]);
            }
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    first,
                    Stmt::Store {
                        addr: Expr::Const(0x10000),
                        value: Expr::reg(2, 64),
                        width: 8,
                    },
                    second,
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            );
            let outputs = super::Outputs::new(&ir, &[], &mut HashSet::new());
            let first = &ir.blocks[0].stmts[0];
            let second = &ir.blocks[0].stmts[2];
            assert!(outputs.used(first, &first.call_outputs()[0]));
            assert_eq!(outputs.used(second, &second.call_outputs()[0]), shared);
            assert_eq!(first.call_outputs().len(), 1);
            assert_eq!(second.call_outputs().len(), 1);
        }
    }

    #[test]
    fn canonical_physical_outputs_keep_definitions_without_identity_moves() {
        for width in [32, 64] {
            let mut call = call(0x1000, vec![]);
            if let Stmt::Call { outputs, .. } = &mut call {
                *outputs = vec![output(2, 2, width)];
            }
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    call,
                    Stmt::Ret {
                        value: Expr::reg(2, 64),
                    },
                ],
            );
            let text = crate::render::render(&ir, &[], &Default::default(), &[]);
            assert_eq!(text.matches("sub_1000()").count(), 1, "{text}");
            assert_eq!(text.contains("call_values"), width == 32, "{text}");
            if width == 32 {
                assert!(text.contains("rdx = (uint32_t)(call_values[0]);"), "{text}");
            }
            assert_eq!(ir.blocks[0].stmts[0].call_outputs(), &[output(2, 2, width)]);
        }
    }

    #[test]
    fn fresh_physical_destinations_use_reserved_names_when_parameters_collide() {
        let mut call = call(0x1000, vec![Expr::reg(7, 64)]);
        if let Stmt::Call { outputs, .. } = &mut call {
            *outputs = vec![output(crate::arch::x86::XMM0, crate::arch::x86::XMM0, 64)];
        }
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(crate::arch::x86::XMM0, 64),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "xmm0".to_owned(),
            ty: CType::U64,
        }];
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(text.contains("uint64_t xmm0_2;"), "{text}");
        assert!(text.contains("sub_1000(xmm0);"), "{text}");
        assert!(text.contains("return xmm0_2;"), "{text}");
        assert!(!text.contains("xmm0 ="), "{text}");
        assert!(!text.contains("return xmm0;"), "{text}");
    }

    #[test]
    fn canonical_general_register_destinations_do_not_merge_with_parameters() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call(0x1000, vec![Expr::reg(7, 64)]),
                Stmt::Ret {
                    value: Expr::reg(2, 64),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "rdx".to_owned(),
            ty: CType::U64,
        }];
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        for expected in ["uint64_t rdx_2;", "sub_1000(rdx);", "return rdx_2;"] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert!(!text.contains("rdx ="), "{text}");
        assert_eq!(text.matches("uint64_t rdx;").count(), 0, "{text}");
        assert!(
            ir.blocks[0].stmts[0]
                .call_outputs()
                .iter()
                .any(|output| output.register == 2 && output.dest.index == 2)
        );
    }

    #[test]
    fn projected_call_returns_keep_low_bits_and_natural_signed_return_widths() {
        for ty in [CType::I32, CType::U32, CType::I64, CType::U64] {
            let mut call = call(0x1000, vec![]);
            if let Stmt::Call { outputs, .. } = &mut call {
                *outputs = vec![output(0, VARIABLE_BASE, 32)];
            }
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    call,
                    Stmt::Ret {
                        value: Expr::reg(VARIABLE_BASE, 32),
                    },
                ],
            );
            ir.ret_type = ty.clone();
            let text = crate::render::render(&ir, &[], &Default::default(), &[]);
            let narrow_return = ty.integer().unwrap().0 == 32;
            assert!(
                text.contains(if narrow_return {
                    "return sub_1000();"
                } else {
                    "return (uint32_t)(sub_1000());"
                }),
                "{text}"
            );
            let mut wide = ir.clone();
            wide.blocks[0].stmts[0].call_outputs_mut()[0].dest.width = 64;
            wide.blocks[0].stmts[1] = Stmt::Ret {
                value: Expr::reg(VARIABLE_BASE, 64),
            };
            let mut signs = [false; 2];
            for seed in 0..64 {
                let setup = crate::ir::eval::Setup {
                    seed,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[],
                    memory: &[],
                    step_limit: 100,
                };
                let crate::ir::eval::Outcome::Return { value, .. } =
                    crate::ir::eval::run(&ir, &setup)
                else {
                    panic!("projected call must return");
                };
                let crate::ir::eval::Outcome::Return { value: raw, .. } =
                    crate::ir::eval::run(&wide, &setup)
                else {
                    panic!("wide call must return");
                };
                signs[((raw as u32) >> 31) as usize] = true;
                assert_eq!(value, u64::from(raw as u32));
            }
            assert_eq!(signs, [true, true]);
            ir.blocks[0].stmts[1] = Stmt::Ret {
                value: Expr::reg(VARIABLE_BASE, 64),
            };
            ir.ret_type = CType::U64;
            let text = crate::render::render(&ir, &[], &Default::default(), &[]);
            assert!(text.contains("= (uint32_t)(sub_1000());"), "{text}");
            assert!(!text.contains("return sub_1000();"), "{text}");
        }
    }
}
