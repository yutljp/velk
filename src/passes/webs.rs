//! Splitting a parameter register into the variables it holds: once a
//! function overwrites a parameter it no longer reads, the register holds
//! another variable, such as a loop counter, and takes a name of its own.

use std::collections::{HashMap, HashSet};

use crate::ir::cfg::successors;
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt, VARIABLE_BASE};

/// A definition of the register: the function's entry, or a statement.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Def {
    Entry,
    At(usize, usize),
}

pub fn split_parameter_webs(ir: &mut FunctionIr) {
    // An unknown successor could read any register.
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::BrIndirect { .. } | Stmt::Br { target: None }))
    {
        return;
    }
    let mut next = VARIABLE_BASE;
    let registers: Vec<u16> = ir.params.iter().map(|param| param.index).collect();
    for register in registers {
        for web in renamable_webs(ir, register) {
            rename(ir, register, next, &web);
            next += 1;
        }
    }
}

/// The statements defining one variable a register holds, and those reading it.
#[derive(Default)]
struct Web {
    defs: HashSet<(usize, usize)>,
    reads: HashSet<(usize, usize)>,
}

/// The webs of `register` the entry value does not reach, when every
/// statement in them names the register.
fn renamable_webs(ir: &FunctionIr, register: u16) -> Vec<Web> {
    let count = ir.blocks.len();
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let last_def: Vec<Option<Def>> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(block, contents)| {
            contents
                .stmts
                .iter()
                .rposition(|stmt| statement_registers(stmt).0.contains(&register))
                .map(|position| Def::At(block, position))
        })
        .collect();
    if last_def.iter().all(Option::is_none) {
        return Vec::new();
    }
    // The definitions reaching the start of each block; the sets only grow.
    let mut reaching: Vec<HashSet<Def>> = vec![HashSet::new(); count];
    reaching[0].insert(Def::Entry);
    loop {
        let mut changed = false;
        for block in 0..count {
            let out: HashSet<Def> = match last_def[block] {
                Some(def) => HashSet::from([def]),
                None => reaching[block].clone(),
            };
            for next in &successors[block] {
                for def in &out {
                    changed |= reaching[*next].insert(*def);
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Each read joins the definitions reaching it into one web.
    let mut parent: HashMap<Def, Def> = HashMap::new();
    fn find(parent: &mut HashMap<Def, Def>, def: Def) -> Def {
        let up = *parent.entry(def).or_insert(def);
        if up == def {
            return def;
        }
        let root = find(parent, up);
        parent.insert(def, root);
        root
    }
    let mut reads: Vec<((usize, usize), Def)> = Vec::new();
    let mut pinned: HashSet<Def> = HashSet::from([Def::Entry]);
    for (block, contents) in ir.blocks.iter().enumerate() {
        let mut current = reaching[block].clone();
        // Code nothing reaches keeps the register as it is.
        if current.is_empty() {
            current.insert(Def::Entry);
        }
        for (position, stmt) in contents.stmts.iter().enumerate() {
            let (writes, read) = statement_registers(stmt);
            if read.contains(&register) {
                let mut defs = current.iter().copied();
                let first = defs.next().expect("a definition reaches every read");
                for def in defs {
                    let (a, b) = (find(&mut parent, first), find(&mut parent, def));
                    parent.insert(a, b);
                }
                // A call reads its arguments without naming them.
                if matches!(stmt, Stmt::Call { .. }) {
                    pinned.insert(first);
                }
                reads.push(((block, position), first));
            }
            if writes.contains(&register) {
                let def = Def::At(block, position);
                if !matches!(stmt, Stmt::Assign { dest, .. } if dest.index == register) {
                    pinned.insert(def);
                }
                find(&mut parent, def);
                current = HashSet::from([def]);
            }
        }
    }

    let pinned: HashSet<Def> = pinned
        .into_iter()
        .map(|def| find(&mut parent, def))
        .collect();
    let mut webs: HashMap<Def, Web> = HashMap::new();
    let defs: Vec<Def> = parent.keys().copied().collect();
    for def in defs {
        if let Def::At(block, position) = def {
            let root = find(&mut parent, def);
            webs.entry(root).or_default().defs.insert((block, position));
        }
    }
    for (site, def) in reads {
        let root = find(&mut parent, def);
        webs.entry(root).or_default().reads.insert(site);
    }
    let mut webs: Vec<(Def, Web)> = webs
        .into_iter()
        .filter(|(root, _)| !pinned.contains(root))
        .collect();
    // In code order, so the names number the variables as they appear.
    webs.sort_by_key(|(_, web)| web.defs.iter().min().copied());
    webs.into_iter().map(|(_, web)| web).collect()
}

fn rename(ir: &mut FunctionIr, register: u16, to: u16, web: &Web) {
    fn renamed(expr: &mut Expr, register: u16, to: u16) {
        match expr {
            Expr::Reg { index, .. } if *index == register => *index = to,
            Expr::Reg { .. } | Expr::Const(_) => {}
            Expr::Bin { lhs, rhs, .. } => {
                renamed(lhs, register, to);
                renamed(rhs, register, to);
            }
            Expr::Load { addr, .. } => renamed(addr, register, to),
            Expr::SignExtend { value, .. } => renamed(value, register, to),
            Expr::Select {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                for expr in [lhs, rhs, then, els] {
                    renamed(expr, register, to);
                }
            }
        }
    }
    for (block, position) in &web.defs {
        if let Stmt::Assign { dest, .. } = &mut ir.blocks[*block].stmts[*position] {
            dest.index = to;
        }
    }
    for (block, position) in &web.reads {
        match &mut ir.blocks[*block].stmts[*position] {
            Stmt::Assign { value, .. } => renamed(value, register, to),
            Stmt::Store { addr, value, .. } => {
                renamed(addr, register, to);
                renamed(value, register, to);
            }
            Stmt::Brif { lhs, rhs, .. } => {
                renamed(lhs, register, to);
                renamed(rhs, register, to);
            }
            Stmt::Ret { value } => renamed(value, register, to),
            Stmt::Switch { index, .. } => renamed(index, register, to),
            Stmt::BrIndirect { target } => renamed(target, register, to),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_parameter_webs;
    use crate::ir::VARIABLE_BASE;
    use crate::ir::{BinOp, Block, CType, Cond, Expr, FunctionIr, Param, RegRef, Stmt};
    use crate::loader::Isa;

    const RSI: u16 = 6;

    fn function(blocks: Vec<Vec<Stmt>>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(index, stmts)| Block {
                start: 0x10 * index as u64,
                stmts,
            })
            .collect();
        ir.params = vec![Param {
            index: RSI,
            name: "n".to_owned(),
            ty: CType::U64,
        }];
        ir
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn counting_loop(start: Stmt) -> FunctionIr {
        let rsi = Expr::reg(RSI, 64);
        function(vec![
            vec![assign(0, rsi.clone()), start],
            vec![
                assign(RSI, Expr::bin(BinOp::Add, rsi.clone(), Expr::Const(1))),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: rsi.clone(),
                    rhs: Expr::reg(0, 64),
                    target: 0x10,
                },
            ],
            vec![Stmt::Ret { value: rsi }],
        ])
    }

    #[test]
    fn a_counter_reusing_a_dead_parameter_is_a_variable_of_its_own() {
        let mut ir = counting_loop(assign(RSI, Expr::Const(0)));
        split_parameter_webs(&mut ir);
        let variable = Expr::reg(VARIABLE_BASE, 64);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { value, .. } if *value == Expr::reg(RSI, 64))
        );
        assert!(
            matches!(&ir.blocks[0].stmts[1], Stmt::Assign { dest, .. } if dest.index == VARIABLE_BASE)
        );
        assert!(
            matches!(&ir.blocks[2].stmts[0], Stmt::Ret { value } if *value == variable),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_parameter_the_loop_updates_keeps_its_register() {
        // The loop starts from the parameter itself.
        let mut ir = counting_loop(assign(1, Expr::Const(0)));
        let before = ir.render();
        split_parameter_webs(&mut ir);
        assert_eq!(ir.render(), before);
    }
}
