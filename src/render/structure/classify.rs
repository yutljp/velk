//! Sorts the gotos structuring leaves by what in the control flow causes
//! them, following the kinds of unstructured flow optimizing compilers are
//! known to make: threaded jumps, merged common tails, lowered switches,
//! rotated loops, merged returns, short-circuit conditions and irreducible
//! loops, besides the exits a structurer cannot write without a goto, as
//! leaving more than one loop at once. Inlined code leaves no trace of its
//! own in a binary without debug information, so it counts under whichever
//! of the others its shape matches.
//!
//! The ignored `goto_causes` test checks every fixture with recorded gotos.
//! `VELK_FIXTURES` can select a comma-separated subset instead. Counts use the
//! chosen printed C and its structure before variable lowering changes addresses.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::Node;
use crate::ir::{FunctionIr, Stmt};
use crate::render::structure::compare_chain::successors;

/// What makes a goto, tried in this order: the first that fits counts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) enum Cause {
    /// A jump the lifter left on flags or through a computed address.
    Unresolved,
    /// To a block made by copying or merging, with no address of its own.
    Synthetic,
    /// To code that blocks the entry does not reach, as a landing pad,
    /// also go to.
    Handler,
    /// Into a cycle that has more than one entry.
    Irreducible,
    /// To where an enclosing loop or switch other than the innermost goes
    /// on, or to an outer loop's header.
    MultiLevel,
    /// To where a test that only completes another one also goes.
    ShortCircuit,
    /// Past a test the jump's path already decided.
    Threading,
    /// To a loop's test at its bottom, past the code before it.
    Rotation,
    /// To code that returns or ends in a call that does not return.
    ReturnMerge,
    /// To one of the places a loop leaves to, when there are several.
    LoopExits,
    /// To a case, or out of a switch arm.
    Switch,
    /// To any other code that several paths share.
    CommonTail,
    /// Back to code above, outside the loops.
    Backward,
    Other,
}

impl Cause {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Cause::Unresolved => "unresolved branch (flags, indirect)",
            Cause::Synthetic => "synthetic block (copy or merged test)",
            Cause::Handler => "join with unwind/handler code",
            Cause::Irreducible => "irreducible loop",
            Cause::MultiLevel => "multi-level break/continue",
            Cause::ShortCircuit => "short-circuit condition",
            Cause::Threading => "jump threading",
            Cause::Rotation => "loop rotation (bottom test)",
            Cause::ReturnMerge => "early return / noreturn merging",
            Cause::LoopExits => "loop with several exits",
            Cause::Switch => "switch lowering",
            Cause::CommonTail => "common tail merging",
            Cause::Backward => "backward jump",
            Cause::Other => "other",
        }
    }
}

/// One goto of the structured code, and what surrounds it.
struct Site {
    stmt: Stmt,
    /// The loops and switches around it, innermost last.
    frames: Vec<Frame>,
}

#[derive(Clone, Copy)]
struct Frame {
    is_loop: bool,
    header: Option<u64>,
    follow: Option<u64>,
}

fn collect_branch_sites(
    nodes: &[Node],
    next: Option<u64>,
    frames: &mut Vec<Frame>,
    out: &mut Vec<Site>,
) {
    for (position, node) in nodes.iter().enumerate() {
        let after = match nodes.get(position + 1) {
            Some(Node::Label(label)) => Some(*label),
            Some(_) => None,
            None => next,
        };
        let header = match position.checked_sub(1).map(|before| &nodes[before]) {
            Some(Node::Label(label)) => Some(*label),
            _ => None,
        };
        match node {
            Node::Stmt(
                stmt @ (Stmt::Br { .. }
                | Stmt::Brif { .. }
                | Stmt::BrifFlags { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::Switch { .. }),
            ) => out.push(Site {
                stmt: stmt.clone(),
                frames: frames.clone(),
            }),
            Node::If { then, els, .. } => {
                collect_branch_sites(then, after, frames, out);
                collect_branch_sites(els, after, frames, out);
            }
            Node::Forever { body } | Node::DoWhile { body, .. } => {
                frames.push(Frame {
                    is_loop: true,
                    header,
                    follow: after,
                });
                collect_branch_sites(body, header, frames, out);
                frames.pop();
            }
            Node::While { prefix, body, .. } => {
                frames.push(Frame {
                    is_loop: true,
                    header,
                    follow: after,
                });
                collect_branch_sites(prefix, None, frames, out);
                collect_branch_sites(body, header, frames, out);
                frames.pop();
            }
            Node::Switch { arms, default, .. } => {
                frames.push(Frame {
                    is_loop: false,
                    header: None,
                    follow: after,
                });
                for body in arms.iter().map(|(_, body)| body).chain(default.iter()) {
                    collect_branch_sites(body, None, frames, out);
                }
                frames.pop();
            }
            _ => {}
        }
    }
}

/// What the classifier needs of the function's control flow.
struct Flow<'a> {
    ir: &'a FunctionIr,
    index: HashMap<u64, usize>,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    idom: Vec<Option<usize>>,
    /// The strongly connected component of each block that lies on a cycle.
    component: Vec<Option<usize>>,
    /// Components entered at more than one block.
    irreducible: HashSet<usize>,
    /// Blocks a back edge leaves from, with the header it goes to.
    latches: HashMap<usize, usize>,
    /// Blocks a path from the entry reaches.
    reached: Vec<bool>,
}

impl<'a> Flow<'a> {
    fn new(ir: &'a FunctionIr) -> Flow<'a> {
        let count = ir.blocks.len();
        let index = ir
            .blocks
            .iter()
            .enumerate()
            .map(|(position, block)| (block.start, position))
            .collect();
        let successors: Vec<Vec<usize>> = (0..count).map(|at| successors(ir, at)).collect();
        let mut predecessors = vec![Vec::new(); count];
        for (from, next) in successors.iter().enumerate() {
            for to in next {
                predecessors[*to].push(from);
            }
        }
        let idom = crate::ssa::dom::dominators(&successors).idom;
        let component = components(&successors);
        let mut reached = vec![false; count];
        let mut pending = vec![0];
        while let Some(at) = pending.pop() {
            if at < count && !std::mem::replace(&mut reached[at], true) {
                pending.extend(successors[at].iter().copied());
            }
        }
        let mut entries: HashMap<usize, HashSet<usize>> = HashMap::new();
        for (block, own) in component.iter().enumerate() {
            let Some(own) = own else { continue };
            if block == 0
                || predecessors[block]
                    .iter()
                    .any(|from| reached[*from] && component[*from] != Some(*own))
            {
                entries.entry(*own).or_default().insert(block);
            }
        }
        let irreducible = entries
            .into_iter()
            .filter(|(_, blocks)| blocks.len() > 1)
            .map(|(own, _)| own)
            .collect();
        let mut flow = Flow {
            ir,
            index,
            successors,
            predecessors,
            idom,
            component,
            irreducible,
            latches: HashMap::new(),
            reached,
        };
        for (from, next) in flow.successors.iter().enumerate() {
            for to in next {
                if flow.dominates(*to, from) {
                    flow.latches.insert(from, *to);
                }
            }
        }
        flow
    }

    fn dominates(&self, upper: usize, mut lower: usize) -> bool {
        for _ in 0..=self.idom.len() {
            if upper == lower {
                return true;
            }
            match self.idom[lower] {
                Some(up) => lower = up,
                None => return false,
            }
        }
        false
    }

    fn through_jumps(&self, mut block: usize) -> usize {
        for _ in 0..8 {
            match self.ir.blocks[block].stmts.as_slice() {
                [
                    Stmt::Br {
                        target: Some(target),
                    },
                ] => match self.index.get(target) {
                    Some(next) => block = *next,
                    None => break,
                },
                _ => break,
            }
        }
        block
    }

    /// The statements from `block` on that run without a branch, and how
    /// they end in a return or a trap.
    fn straight_tail(&self, mut block: usize) -> bool {
        let mut seen = HashSet::new();
        while seen.insert(block) {
            let stmts = &self.ir.blocks[block].stmts;
            match stmts.last() {
                Some(Stmt::Ret { .. } | Stmt::Trap) => return true,
                Some(Stmt::Br {
                    target: Some(target),
                }) => match self.index.get(target) {
                    Some(next) => block = *next,
                    None => return false,
                },
                Some(Stmt::Brif { .. } | Stmt::BrifFlags { .. } | Stmt::Switch { .. })
                | Some(Stmt::BrIndirect { .. } | Stmt::Br { target: None }) => {
                    return false;
                }
                _ if block + 1 < self.ir.blocks.len() => block += 1,
                _ => return false,
            }
        }
        false
    }

    /// Whether `target_block` is where a loop with exits to more than one place
    /// leaves to.
    fn is_multiple_loop_exit(&self, target_block: usize) -> bool {
        let headers: HashSet<usize> = self.latches.values().copied().collect();
        headers.into_iter().any(|header| {
            let mut body = vec![false; self.ir.blocks.len()];
            body[header] = true;
            let mut work: Vec<usize> = self
                .latches
                .iter()
                .filter(|(_, to)| **to == header)
                .map(|(from, _)| *from)
                .collect();
            while let Some(block) = work.pop() {
                if !std::mem::replace(&mut body[block], true) {
                    work.extend(self.predecessors[block].iter().copied());
                }
            }
            let exits: HashSet<usize> = (0..body.len())
                .filter(|block| body[*block])
                .flat_map(|block| self.successors[block].iter().copied())
                .filter(|exit| !body[*exit])
                .map(|exit| self.through_jumps(exit))
                .collect();
            exits.len() > 1 && exits.contains(&self.through_jumps(target_block))
        })
    }

    fn branch_operands(&self, block: usize) -> Option<(&crate::ir::Expr, &crate::ir::Expr)> {
        match self.ir.blocks[block].stmts.last() {
            Some(Stmt::Brif { lhs, rhs, .. }) => Some((lhs, rhs)),
            _ => None,
        }
    }

    /// A block that only tests, after at most a few assignments.
    fn is_short_conditional_block(&self, block: usize) -> bool {
        let stmts = &self.ir.blocks[block].stmts;
        matches!(stmts.last(), Some(Stmt::Brif { .. }))
            && stmts.len() <= 4
            && stmts[..stmts.len() - 1]
                .iter()
                .all(|stmt| matches!(stmt, Stmt::Assign { .. }))
    }

    fn classify(&self, site: &Site) -> Cause {
        let target = match &site.stmt {
            Stmt::Br {
                target: Some(target),
            }
            | Stmt::Brif { target, .. } => *target,
            _ => return Cause::Unresolved,
        };
        let Some(&target_block) = self.index.get(&target) else {
            return Cause::Synthetic;
        };
        if self.predecessors[target_block]
            .iter()
            .any(|from| !self.reached[*from])
        {
            return Cause::Handler;
        }
        if self.component[target_block].is_some_and(|own| self.irreducible.contains(&own)) {
            return Cause::Irreducible;
        }
        let innermost = site.frames.len().checked_sub(1);
        let innermost_loop = site.frames.iter().rposition(|frame| frame.is_loop);
        for (depth, frame) in site.frames.iter().enumerate() {
            let breaks_here = Some(depth) == innermost;
            let continues_here = Some(depth) == innermost_loop;
            if (frame.follow == Some(target) && !breaks_here)
                || (frame.is_loop && frame.header == Some(target) && !continues_here)
            {
                return Cause::MultiLevel;
            }
        }
        let predecessors = &self.predecessors[target_block];
        // p tests and goes to t or to c, which only tests again and also
        // goes to t: `if (a && b)` or `if (a || b)`.
        let short_circuit = predecessors.iter().any(|conditional_block| {
            self.is_short_conditional_block(*conditional_block)
                && self.predecessors[*conditional_block]
                    .iter()
                    .any(|preceding_block| {
                        self.branch_operands(*preceding_block).is_some()
                            && self.successors[*preceding_block].contains(&target_block)
                    })
        });
        if short_circuit {
            return Cause::ShortCircuit;
        }
        // c tests and goes to t; p reaches t too without passing c, below a
        // block that made the same test.
        let threaded = predecessors.iter().any(|conditional_block| {
            let Some(tested) = self.branch_operands(*conditional_block) else {
                return false;
            };
            predecessors.iter().any(|alternate_predecessor| {
                alternate_predecessor != conditional_block
                    && !self.dominates(*conditional_block, *alternate_predecessor)
                    && {
                        let mut up = self.idom[*alternate_predecessor];
                        let mut found = false;
                        while let Some(block) = up {
                            if block != *conditional_block
                                && self.branch_operands(block) == Some(tested)
                            {
                                found = true;
                                break;
                            }
                            up = self.idom[block];
                        }
                        found
                    }
            })
        });
        if threaded {
            return Cause::Threading;
        }
        if self.latches.get(&target_block).is_some_and(|header| {
            *header != target_block && self.branch_operands(target_block).is_some()
        }) {
            return Cause::Rotation;
        }
        let end = self.through_jumps(target_block);
        if self.straight_tail(end) {
            return Cause::ReturnMerge;
        }
        if self.is_multiple_loop_exit(target_block) {
            return Cause::LoopExits;
        }
        if site.frames.last().is_some_and(|frame| !frame.is_loop)
            || predecessors.iter().any(|from| {
                matches!(
                    self.ir.blocks[*from].stmts.last(),
                    Some(Stmt::Switch { .. })
                )
            })
        {
            return Cause::Switch;
        }
        if predecessors.len() > 1 {
            return Cause::CommonTail;
        }
        if !site.frames.iter().any(|frame| frame.is_loop) && self.component[target_block].is_some()
        {
            return Cause::Backward;
        }
        Cause::Other
    }
}

/// The strongly connected components of the graph that hold a cycle.
fn components(successors: &[Vec<usize>]) -> Vec<Option<usize>> {
    let count = successors.len();
    // Kosaraju: finishing order on the graph, then the reversed graph.
    let mut finished = Vec::with_capacity(count);
    let mut visited = vec![false; count];
    for root in 0..count {
        if visited[root] {
            continue;
        }
        visited[root] = true;
        let mut stack = vec![(root, 0usize)];
        while let Some((block, next)) = stack.last_mut() {
            if let Some(successor) = successors[*block].get(*next).copied() {
                *next += 1;
                if !visited[successor] {
                    visited[successor] = true;
                    stack.push((successor, 0));
                }
            } else {
                finished.push(*block);
                stack.pop();
            }
        }
    }
    let mut reverse = vec![Vec::new(); count];
    for (from, next) in successors.iter().enumerate() {
        for to in next {
            reverse[*to].push(from);
        }
    }
    let mut component = vec![None; count];
    let mut assigned = vec![false; count];
    let mut number = 0;
    for root in finished.into_iter().rev() {
        if assigned[root] {
            continue;
        }
        let mut members = vec![root];
        assigned[root] = true;
        component[root] = Some(number);
        let mut pending = vec![root];
        while let Some(block) = pending.pop() {
            for from in &reverse[block] {
                if !assigned[*from] {
                    assigned[*from] = true;
                    component[*from] = Some(number);
                    members.push(*from);
                    pending.push(*from);
                }
            }
        }
        let cyclic = members.len() > 1 || successors[root].contains(&root);
        if !cyclic {
            component[root] = None;
        }
        number += 1;
    }
    component
}

/// The cause of each goto the structured code `nodes` of `ir` holds.
pub(crate) fn causes(ir: &FunctionIr, nodes: &[Node]) -> Vec<(Cause, u64)> {
    let mut found = Vec::new();
    collect_branch_sites(nodes, None, &mut Vec::new(), &mut found);
    let flow = Flow::new(ir);
    found
        .iter()
        .map(|site| {
            let target = match &site.stmt {
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. }
                | Stmt::BrifFlags { target, .. } => *target,
                _ => 0,
            };
            (flow.classify(site), target)
        })
        .collect()
}

struct Capture {
    code: String,
    ir: FunctionIr,
    nodes: Vec<Node>,
}

thread_local! {
    static CAPTURES: std::cell::RefCell<Option<Vec<Capture>>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(crate) fn record(ir: &FunctionIr, nodes: &[Node], code: &str) {
    CAPTURES.with_borrow_mut(|captures| {
        if let Some(captures) = captures
            && code.contains("goto ")
        {
            captures.push(Capture {
                code: code.to_owned(),
                ir: ir.clone(),
                nodes: nodes.to_vec(),
            });
        }
    });
}

fn printed_causes(code: &str, fixture: &str) -> Vec<(Cause, u64)> {
    let captures = CAPTURES
        .with_borrow_mut(Option::take)
        .expect("capture was enabled");
    let selected = captures
        .into_iter()
        .rev()
        .find(|capture| code.ends_with(&capture.code));
    if let Some(capture) = &selected
        && let Ok(directory) = std::env::var("VELK_DUMP")
    {
        use std::io::Write as _;

        let mut shape = String::new();
        sketch(&capture.nodes, 0, &mut shape);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::path::Path::new(&directory).join("cfg.txt"))
            .expect("a CFG dump file");
        writeln!(
            file,
            "==== {fixture} {} @ {:#x}\n{}\n{shape}",
            capture.ir.name.as_deref().unwrap_or("unnamed"),
            capture.ir.addr,
            capture.ir.render(),
        )
        .expect("writing the CFG and structured shape");
    }
    let mut sites = selected.map_or_else(Vec::new, |capture| causes(&capture.ir, &capture.nodes));
    let mut printed = Vec::new();
    for (offset, _) in code.match_indices("goto ") {
        let target = &code[offset + "goto ".len()..];
        let target = target.strip_prefix("L_").expect("a printed direct branch");
        let end = target.find(';').expect("a branch terminator");
        let target = u64::from_str_radix(&target[..end], 16).expect("a label address");
        let position = sites
            .iter()
            .position(|(_, address)| *address == target)
            .expect("every printed goto has a structured branch");
        printed.push(sites.remove(position));
    }
    printed
}

#[test]
#[ignore]
fn goto_causes() {
    use std::fmt::Write as _;
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let selected = std::env::var("VELK_FIXTURES");
    let fixtures = selected.clone().unwrap_or_else(|_| {
        let path = root.join("tests/golden/readability.txt");
        let text = std::fs::read_to_string(&path).expect("recorded fixture readability");
        let mut fixtures = Vec::new();
        for line in text.lines() {
            if line.starts_with('#') || line.contains(", 0 gotos,") {
                continue;
            }
            if let Some((fixture, _)) = line.split_once(": ") {
                fixtures.push(fixture);
            }
        }
        fixtures.join(",")
    });
    let examples: usize = std::env::var("VELK_EXAMPLES")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(3);
    let mut table: BTreeMap<Cause, BTreeMap<String, usize>> = BTreeMap::new();
    // Per cause, one goto of each function: its size, fixture, function,
    // target and text.
    type Example = (usize, String, String, u64, std::rc::Rc<String>);
    let mut found: BTreeMap<Cause, Vec<Example>> = BTreeMap::new();
    let mut report = String::new();
    let mut every = String::new();
    let mut texts = String::new();
    for fixture in fixtures.split(',') {
        let mut binary = crate::service::Binary::open(&root.join("tests/fixtures").join(fixture))
            .unwrap_or_else(|error| panic!("{error}"));
        let addresses: Vec<u64> = binary.image().functions.keys().copied().collect();
        let (mut lines, mut printed) = (0, 0);
        let mut heaviest: Vec<(usize, String)> = Vec::new();
        for addr in addresses {
            CAPTURES.with_borrow_mut(|captures| *captures = Some(Vec::new()));
            let Ok(text) = binary.decompile(addr, None, None) else {
                CAPTURES.with_borrow_mut(|captures| *captures = None);
                continue;
            };
            let classified = printed_causes(&text, fixture);
            lines += text.lines().count();
            let gotos = text.matches("goto ").count();
            printed += gotos;
            let name = binary
                .function(addr)
                .ok()
                .and_then(|function| function.name.clone())
                .unwrap_or_else(|| crate::addr::format(addr));
            if gotos > 0 {
                write!(texts, "==== {fixture} {name}\n{text}\n").expect("writing to a String");
                heaviest.push((gotos, format!("{name} ({} lines)", text.lines().count())));
            }
            let text = std::rc::Rc::new(text);
            let mut seen = HashSet::new();
            for (cause, target) in classified {
                writeln!(
                    every,
                    "{fixture} {name} {} lines -> L_{target:x}: {cause:?}",
                    text.lines().count()
                )
                .expect("writing to a String");
                *table
                    .entry(cause)
                    .or_default()
                    .entry(fixture.to_owned())
                    .or_default() += 1;
                if seen.insert(cause) {
                    found.entry(cause).or_default().push((
                        text.len(),
                        fixture.to_owned(),
                        name.clone(),
                        target,
                        text.clone(),
                    ));
                }
            }
        }
        heaviest.sort_by(|a, b| b.cmp(a));
        writeln!(
            report,
            "{fixture}: {lines} lines, {printed} gotos printed; most in"
        )
        .expect("writing to a String");
        for (gotos, name) in heaviest.iter().take(8) {
            writeln!(report, "    {gotos} {name}").expect("writing to a String");
        }
        eprintln!("{fixture}: {printed} printed gotos classified");
    }
    // The shortest functions show each cause most plainly.
    for (cause, list) in &mut found {
        list.sort_by_key(|example| example.0);
        writeln!(report, "{} in {} functions:", cause.describe(), list.len())
            .expect("writing to a String");
        for (_, fixture, name, target, text) in list.iter().take(examples) {
            writeln!(report, "  {fixture} {name} -> L_{target:x}").expect("writing to a String");
            if let Ok(dir) = std::env::var("VELK_DUMP") {
                let path = std::path::Path::new(&dir).join(format!("{cause:?}.txt").to_lowercase());
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .expect("a dump file");
                std::io::Write::write_all(
                    &mut file,
                    format!("==== {fixture} {name} -> L_{target:x}\n{text}\n").as_bytes(),
                )
                .expect("writing the dump");
            }
        }
    }
    if let Ok(dir) = std::env::var("VELK_DUMP") {
        std::fs::write(std::path::Path::new(&dir).join("all.txt"), &every)
            .expect("writing the list");
        std::fs::write(std::path::Path::new(&dir).join("gotos.c"), &texts)
            .expect("writing the code");
    }
    println!("{report}");
    let names: Vec<&str> = fixtures.split(',').collect();
    println!("cause | {} | total", names.join(" | "));
    for (cause, counts) in &table {
        let row: Vec<String> = names
            .iter()
            .map(|name| counts.get(*name).copied().unwrap_or(0).to_string())
            .collect();
        println!(
            "{} | {} | {}",
            cause.describe(),
            row.join(" | "),
            counts.values().sum::<usize>()
        );
    }
    let mut summary = String::from(
        "# Every printed goto, counted once by the first matching control-flow shape.\n\
         # Reproduce: cargo test --release --lib goto_causes -- --ignored --nocapture\n\
         # Includes named, stripped, x86-64, AArch64 and ARM fixtures.\n\
         # These are structural classifications, not recovered source constructs.\n\
         shape | Rust | Go | C/C++ | total\n",
    );
    for (cause, counts) in &table {
        let mut groups = [0; 3];
        for (fixture, count) in counts {
            let group = if fixture.starts_with("rust_") {
                0
            } else if fixture.starts_with("go_") {
                1
            } else {
                2
            };
            groups[group] += count;
        }
        writeln!(
            summary,
            "{} | {} | {} | {} | {}",
            cause.describe(),
            groups[0],
            groups[1],
            groups[2],
            groups.iter().sum::<usize>()
        )
        .expect("writing to a String");
    }
    summary.push_str("\n# One example per shape: fixture, function, destination.\n");
    for (cause, examples) in &found {
        if let Some((_, fixture, name, target, _)) = examples.first() {
            writeln!(
                summary,
                "{}: {fixture} {name} -> L_{target:x}",
                cause.describe()
            )
            .expect("writing to a String");
        }
    }
    println!("{summary}");
    if let Ok(dir) = std::env::var("VELK_DUMP") {
        std::fs::write(std::path::Path::new(&dir).join("report.txt"), &summary)
            .expect("writing the counts and examples");
    }
    if selected.is_err() && std::env::var("VELK_BLESS").as_deref() == Ok("1") {
        std::fs::write(root.join("tests/golden/goto_shapes.txt"), &summary)
            .expect("writing the recorded counts and examples");
    }
}

/// The shape of structured code, statements left out but jumps kept.
fn sketch(nodes: &[Node], depth: usize, out: &mut String) {
    use std::fmt::Write as _;
    let pad = "  ".repeat(depth);
    for node in nodes {
        match node {
            Node::Label(label) => writeln!(out, "{pad}L_{label:x}:"),
            Node::Stmt(Stmt::Br {
                target: Some(target),
            }) => writeln!(out, "{pad}goto L_{target:x}"),
            Node::Stmt(stmt) => writeln!(out, "{pad}{}", stmt_kind(stmt)),
            Node::Break => writeln!(out, "{pad}break"),
            Node::Continue => writeln!(out, "{pad}continue"),
            Node::If {
                cond, then, els, ..
            } => {
                writeln!(out, "{pad}if {cond:?} {{").expect("writing");
                sketch(then, depth + 1, out);
                if !els.is_empty() {
                    writeln!(out, "{pad}}} else {{").expect("writing");
                    sketch(els, depth + 1, out);
                }
                writeln!(out, "{pad}}}")
            }
            Node::Forever { body } => {
                writeln!(out, "{pad}loop {{").expect("writing");
                sketch(body, depth + 1, out);
                writeln!(out, "{pad}}}")
            }
            Node::DoWhile { body, .. } => {
                writeln!(out, "{pad}do {{").expect("writing");
                sketch(body, depth + 1, out);
                writeln!(out, "{pad}}} while")
            }
            Node::While { prefix, body, .. } => {
                writeln!(out, "{pad}while ({} before) {{", prefix.len()).expect("writing");
                sketch(body, depth + 1, out);
                writeln!(out, "{pad}}}")
            }
            Node::Switch { arms, default, .. } => {
                writeln!(out, "{pad}switch {{").expect("writing");
                for (values, body) in arms {
                    writeln!(out, "{pad}case {values:?}:").expect("writing");
                    sketch(body, depth + 1, out);
                }
                if let Some(body) = default {
                    writeln!(out, "{pad}default:").expect("writing");
                    sketch(body, depth + 1, out);
                }
                writeln!(out, "{pad}}}")
            }
        }
        .expect("writing");
    }
}

fn stmt_kind(stmt: &Stmt) -> &'static str {
    match stmt {
        Stmt::Assign { .. } => "=",
        Stmt::Store { .. } => "store",
        Stmt::Call { .. } => "call",
        Stmt::Ret { .. } => "return",
        Stmt::Trap => "trap",
        Stmt::Brif { .. } => "if goto",
        Stmt::BrifFlags { .. } => "if flags goto",
        Stmt::Switch { .. } => "switch goto",
        Stmt::BrIndirect { .. } => "goto *",
        Stmt::Br { .. } => "goto ?",
        Stmt::Machine { .. } => "machine",
        Stmt::Unsupported { .. } => "unsupported",
    }
}

/// Prints the shape the structurer gives one function, before and after
/// its variants and cleanups, with the blocks the chosen one structured:
/// `VELK_FIXTURE=go_probe VELK_FUNCTION=0x45eec0 cargo test --release --lib structure_sketch -- --ignored --nocapture`
#[test]
#[ignore]
fn structure_sketch() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = std::env::var("VELK_FIXTURE").expect("set VELK_FIXTURE");
    let addr = std::env::var("VELK_FUNCTION").expect("set VELK_FUNCTION");
    let addr = crate::addr::parse(&addr).expect("VELK_FUNCTION is an address");
    let mut binary = crate::service::Binary::open(&root.join("tests/fixtures").join(fixture))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut ir = binary.analysis(addr, None).expect("lifts").ir.clone();
    crate::render::params::fold_saved_parameters(&mut ir);
    let mut out = String::new();
    let raw = super::dominance::structure(&ir).expect("structures");
    out.push_str("== by dominance, untidied\n");
    sketch(&raw, 0, &mut out);
    let (best, chosen) = super::best_structure(&ir);
    out.push_str("== best\n");
    sketch(&best, 0, &mut out);
    out.push_str(&format!("== its blocks\n{}", chosen.render()));
    println!("{out}");
}
