//! Properties every decompiled function should have. Current violations are
//! listed in tests/golden/invariants.txt: a new one fails the test, and a fixed
//! one must be removed from the list with `VELK_BLESS=1 cargo test --test invariants`.

mod common;

use std::collections::HashSet;
use std::path::Path;

use velk::ir::{CType, Expr, FunctionIr, Stmt};
use velk::loader::{Function, Isa};
use velk::render::structure::{Node, structure_best};
use velk::service::Binary;

const BUDGETS: [usize; 4] = [0, 96, 240, 2000];

#[test]
fn decompiled_functions_keep_their_invariants() {
    let fixtures = common::fixtures();
    let found: Vec<Vec<String>> = common::in_parallel(&fixtures, |fixture| {
        violations(&common::fixtures_dir().join(fixture), fixture)
    });
    let mut actual = String::new();
    for line in found.into_iter().flatten() {
        actual.push_str(&line);
        actual.push('\n');
    }
    let expected = common::root().join("tests/golden/invariants.txt");
    if let Some(difference) = common::check_expected(&expected, &actual) {
        panic!("the invariant violations changed; fix the new ones, or bless a fix:\n{difference}");
    }
}

fn violations(path: &Path, fixture: &Path) -> Vec<String> {
    let mut binary = Binary::open(path).unwrap_or_else(|error| panic!("{error}"));
    let functions: Vec<Function> = binary.image().functions.values().cloned().collect();
    let isa = binary.image().isa;
    let mut found = Vec::new();
    for function in &functions {
        let label = format!(
            "{} {} {}",
            fixture.display(),
            velk::addr::format(function.addr),
            function.name.as_deref().unwrap_or("-")
        );
        for budget in BUDGETS {
            let card = binary
                .card(function.addr, budget, None)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            if card.approx_tokens > budget.max(96) {
                found.push(format!(
                    "{label}: card of {} tokens over a budget of {budget}",
                    card.approx_tokens
                ));
            }
        }
        let Ok(text) = binary.decompile(function.addr, None) else {
            continue;
        };
        // A jump out of the function has no label to find; it is a tail call
        // or a sign that the function's extent is wrong.
        let end = function.addr.saturating_add(function.size.unwrap_or(0));
        found.extend(
            missing_labels(&text)
                .into_iter()
                .filter(|target| {
                    u64::from_str_radix(target.trim_start_matches("L_"), 16)
                        .is_ok_and(|address| (function.addr..end).contains(&address))
                })
                .map(|target| format!("{label}: goto {target} has no label")),
        );
        if text.matches('{').count() != text.matches('}').count() {
            found.push(format!("{label}: unbalanced braces"));
        }
        let analysis = binary
            .analysis(function.addr)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        for effect in dropped_effects(&analysis.ir) {
            found.push(format!("{label}: the pseudo-C drops `{effect}`"));
        }
        if !ir_runs_off_the_end(&analysis.ir) && falls_through(&structure_best(&analysis.ir)) {
            found.push(format!(
                "{label}: the pseudo-C runs off the end without a return"
            ));
        }
        // Go's internal calling convention and runtime registers are not modeled.
        if fixture.to_string_lossy().starts_with("go_") {
            continue;
        }
        let mut unassigned: Vec<u16> = unassigned_reads(&analysis.ir, isa).into_iter().collect();
        unassigned.sort_unstable();
        for register in unassigned {
            found.push(format!(
                "{label}: reads {} without assigning it",
                velk::ir::reg_name(isa, register, 64)
            ));
        }
    }
    found
}

/// True when a reachable path leaves the last block without a return, jump
/// or trap, as after a call that does not return.
fn ir_runs_off_the_end(ir: &FunctionIr) -> bool {
    let last = ir.blocks.len().saturating_sub(1);
    reachable(ir).contains(&last)
        && !matches!(
            ir.blocks[last].stmts.last(),
            Some(
                Stmt::Ret { .. }
                    | Stmt::Trap
                    | Stmt::Br { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. }
            )
        )
}

/// True when execution can reach the end of the nodes.
fn falls_through(nodes: &[Node]) -> bool {
    fn breaks(nodes: &[Node]) -> bool {
        nodes.iter().any(|node| match node {
            Node::Break => true,
            Node::If { then, els, .. } => breaks(then) || breaks(els),
            Node::Switch { arms, default, .. } => {
                arms.iter().any(|(_, body)| breaks(body)) || default.as_deref().is_some_and(breaks)
            }
            _ => false,
        })
    }
    match nodes.last() {
        None | Some(Node::Break) => true,
        Some(Node::Label(_)) => true,
        Some(Node::Continue) => false,
        // A body that ends in a call ends in one that does not return.
        Some(Node::Stmt(stmt)) => !matches!(
            stmt,
            Stmt::Ret { .. }
                | Stmt::Call { .. }
                | Stmt::Trap
                | Stmt::Br { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::Switch { .. }
        ),
        Some(Node::If { then, els, .. }) => falls_through(then) || falls_through(els),
        Some(Node::DoWhile { .. } | Node::While { .. }) => true,
        Some(Node::Forever { body }) => breaks(body),
        // A case that falls through runs into the next one, and the last into
        // the default, which follows the cases.
        Some(Node::Switch { arms, default, .. }) => match default {
            Some(default) => {
                falls_through(default)
                    || breaks(default)
                    || arms.iter().any(|(_, body)| breaks(body))
            }
            // No other value reaches a switch without a default.
            None => arms.iter().any(|(_, body)| breaks(body)),
        },
    }
}

/// The blocks reachable from the entry through direct branches.
fn reachable(ir: &FunctionIr) -> HashSet<usize> {
    let position = |target: &u64| ir.blocks.iter().position(|block| block.start == *target);
    let mut seen = HashSet::new();
    let mut pending = vec![0];
    while let Some(index) = pending.pop() {
        if index >= ir.blocks.len() || !seen.insert(index) {
            continue;
        }
        let next = index + 1;
        match ir.blocks[index].stmts.last() {
            Some(Stmt::Br { target }) => pending.extend(target.as_ref().and_then(position)),
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => {
                pending.extend(position(target));
                pending.push(next);
            }
            Some(Stmt::Switch { cases, default, .. }) => {
                pending.extend(cases.iter().filter_map(|(_, target)| position(target)));
                pending.extend(default.as_ref().and_then(position));
            }
            Some(Stmt::Ret { .. } | Stmt::BrIndirect { .. } | Stmt::Trap) => {}
            _ => pending.push(next),
        }
    }
    seen
}

/// The stores, calls, returns and unsupported instructions of the reachable
/// IR that the structured body leaves out; folding may rewrite assignments
/// and branches, but never drops an effect or an exit.
fn dropped_effects(ir: &FunctionIr) -> Vec<String> {
    fn collect(nodes: &[Node], kept: &mut HashSet<String>) {
        for node in nodes {
            match node {
                Node::Stmt(stmt) => {
                    kept.insert(format!("{stmt:?}"));
                }
                Node::If { then, els, .. } => {
                    collect(then, kept);
                    collect(els, kept);
                }
                Node::DoWhile { body, .. } | Node::Forever { body } => collect(body, kept),
                Node::While { prefix, body, .. } => {
                    collect(prefix, kept);
                    collect(body, kept);
                }
                Node::Switch { arms, default, .. } => {
                    for (_, body) in arms {
                        collect(body, kept);
                    }
                    collect(default.as_deref().unwrap_or_default(), kept);
                }
                Node::Label(_) | Node::Break | Node::Continue => {}
            }
        }
    }
    let mut kept = HashSet::new();
    collect(&structure_best(ir), &mut kept);
    let reachable = reachable(ir);
    let mut dropped: Vec<String> = ir
        .blocks
        .iter()
        .enumerate()
        .filter(|(index, _)| reachable.contains(index))
        .flat_map(|(_, block)| &block.stmts)
        .filter(|stmt| {
            matches!(
                stmt,
                Stmt::Store { .. }
                    | Stmt::Call { .. }
                    | Stmt::Unsupported { .. }
                    | Stmt::Trap
                    | Stmt::Ret { .. }
            )
        })
        .map(|stmt| format!("{stmt:?}"))
        .filter(|effect| !kept.contains(effect))
        .collect();
    dropped.sort();
    dropped.dedup();
    dropped
}

fn missing_labels(text: &str) -> Vec<String> {
    let mut targets: Vec<String> = text
        .split("goto ")
        .skip(1)
        .filter_map(|rest| rest.split(';').next())
        .filter(|target| target.starts_with("L_"))
        .map(str::to_owned)
        .collect();
    targets.sort();
    targets.dedup();
    targets
        .into_iter()
        .filter(|target| !text.lines().any(|line| line.trim() == format!("{target}:")))
        .collect()
}

/// Registers the body reads that are neither parameters nor assigned
/// anywhere, apart from the stack, frame and link registers and the
/// callee-saved registers a prologue spills. A void function's return reads
/// nothing. An unsupported instruction may write any register, so a body with
/// one is not checked.
fn unassigned_reads(ir: &FunctionIr, isa: Isa) -> HashSet<u16> {
    let stmts = || ir.blocks.iter().flat_map(|block| &block.stmts);
    if stmts().any(|stmt| matches!(stmt, Stmt::Unsupported { .. })) {
        return HashSet::new();
    }
    let mut written: HashSet<u16> = ir.params.iter().map(|param| param.index).collect();
    // A landing pad receives the exception and its selector.
    written.extend([velk::ir::EXCEPTION, velk::ir::SELECTOR]);
    // A variadic function's further arguments arrive in the argument
    // registers its declaration leaves unnamed.
    if ir.variadic {
        written.extend(ir.convention.arguments());
        written.extend(ir.convention.float_arguments());
    }
    let mut read = HashSet::new();
    for stmt in stmts() {
        match stmt {
            Stmt::Assign { dest, value } => {
                written.insert(dest.index);
                reads(value, &mut read);
            }
            Stmt::Store { addr, value, .. } => {
                reads(addr, &mut read);
                reads(value, &mut read);
            }
            Stmt::Brif { lhs, rhs, .. } => {
                reads(lhs, &mut read);
                reads(rhs, &mut read);
            }
            Stmt::BrIndirect { target } => reads(target, &mut read),
            Stmt::Switch { index, .. } => reads(index, &mut read),
            Stmt::Ret { value } if ir.ret_type != CType::Void => reads(value, &mut read),
            // A call leaves its results in the registers it may overwrite,
            // and in the variable that takes its value; it reads its arguments.
            Stmt::Call {
                convention,
                through,
                args,
                result,
                ..
            } => {
                written.extend(convention.clobbered());
                written.extend(result.map(|result| result.index));
                for value in through.iter().chain(args.iter().flatten()) {
                    reads(value, &mut read);
                }
            }
            Stmt::Ret { .. }
            | Stmt::BrifFlags { .. }
            | Stmt::Br { .. }
            | Stmt::Unsupported { .. }
            | Stmt::Trap => {}
        }
    }
    let exempt: &[u16] = match isa {
        // x8 the indirect result address, x19-x28 callee-saved, x29 frame,
        // x30 link, 31 stack, v0-v7, which carry floating-point arguments,
        // and the low halves of the callee-saved v8-v15.
        Isa::AArch64 => &[
            8, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47, 48, 50, 52, 54, 56, 58, 60, 62,
        ],
        // rax, whose al counts a variadic call's vector arguments and whose
        // other bits a partial write keeps; rbx, rsp, rbp, r12-r15, the fs and
        // gs segment bases, and xmm0-xmm7, which carry floating-point arguments.
        Isa::X86_64 => &[
            0, 3, 4, 5, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
            31, 32, 33,
        ],
        Isa::Unsupported => &[],
    };
    read.retain(|register| !written.contains(register) && !exempt.contains(register));
    read
}

fn reads(expr: &Expr, into: &mut HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            into.insert(*index);
        }
        Expr::Const(_) => {}
        Expr::Bin { lhs, rhs, .. } => {
            reads(lhs, into);
            reads(rhs, into);
        }
        Expr::Load { addr, .. } => reads(addr, into),
        Expr::SignExtend { value, .. } => reads(value, into),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            reads(lhs, into);
            reads(rhs, into);
            reads(then, into);
            reads(els, into);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                reads(arg, into);
            }
        }
    }
}
