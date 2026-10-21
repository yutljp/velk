//! The registers a function may return with changed. A walk over its blocks
//! follows what each register holds (its value on entry, an address in the
//! frame, or anything else) and what each frame slot holds, so a register
//! stored on entry and loaded back before every return, as a push and a pop
//! or a pair store and a pair load do, keeps its value for the caller.

use std::collections::{BTreeMap, HashMap};

use crate::ir::{BinOp, Block, Convention, Expr, Registers, Stmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    /// What the register held on entry.
    Entry(u16),
    /// The stack pointer on entry, plus an offset.
    Frame(i64),
    Other,
}

/// How many machine registers there are.
const MACHINE: usize = crate::arch::aarch64::V0 as usize + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    /// What each machine register holds.
    machine: [Value; MACHINE],
    /// What the lifter's other registers, as those it keeps flag operands
    /// in, hold where it is known; one not listed holds nothing known,
    /// which is never any machine register's entry value either.
    others: BTreeMap<u16, Value>,
    /// What each 8-byte frame slot holds, by its offset from the stack
    /// pointer on entry; a slot not listed holds nothing known.
    slots: BTreeMap<i64, Value>,
}

impl State {
    fn entry(sp: u16) -> Self {
        State {
            machine: std::array::from_fn(|index| {
                if index == usize::from(sp) {
                    Value::Frame(0)
                } else {
                    Value::Entry(index as u16)
                }
            }),
            others: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn register(&self, index: u16) -> Value {
        match self.machine.get(usize::from(index)) {
            Some(value) => *value,
            None => self.others.get(&index).copied().unwrap_or(Value::Other),
        }
    }

    fn set(&mut self, index: u16, value: Value) {
        match self.machine.get_mut(usize::from(index)) {
            Some(held) => *held = value,
            None if value == Value::Other => {
                self.others.remove(&index);
            }
            None => {
                self.others.insert(index, value);
            }
        }
    }

    fn value(&self, expr: &Expr) -> Value {
        let offset = |base: &Expr, delta: i64| match self.value(base) {
            Value::Frame(at) => Value::Frame(at.wrapping_add(delta)),
            _ => Value::Other,
        };
        match expr {
            Expr::Reg { index, width: 64 } => self.register(*index),
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (base, Expr::Const(delta)) | (Expr::Const(delta), base) => {
                    offset(base, *delta as i64)
                }
                _ => Value::Other,
            },
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(delta) => offset(lhs, (*delta as i64).wrapping_neg()),
                _ => Value::Other,
            },
            Expr::Load { addr, width: 8, .. } => match self.value(addr) {
                Value::Frame(at) => self.slots.get(&at).copied().unwrap_or(Value::Other),
                _ => Value::Other,
            },
            _ => Value::Other,
        }
    }

    /// Takes in what `other` may hold too; whether anything changed.
    fn join(&mut self, other: &State) -> bool {
        let mut changed = false;
        for (held, came) in self.machine.iter_mut().zip(&other.machine) {
            if held != came && *held != Value::Other {
                *held = Value::Other;
                changed = true;
            }
        }
        let before = (self.others.len(), self.slots.len());
        self.others
            .retain(|index, value| other.others.get(index) == Some(value));
        self.slots
            .retain(|at, value| other.slots.get(at) == Some(value));
        changed || before != (self.others.len(), self.slots.len())
    }

    /// The frame slots a store of `width` bytes at `at` overlaps.
    fn forget_slots(&mut self, at: i64, width: u8) {
        let end = at.wrapping_add(i64::from(width));
        self.slots
            .retain(|slot, _| *slot >= end || slot.wrapping_add(8) <= at);
    }
}

/// How far the walk may go, in block visits per block, before it gives up.
const VISITS_PER_BLOCK: usize = 64;

/// The registers the function `blocks` lift may return with changed, under
/// its own `convention`; None when some way out of it is not known, as a
/// jump through a register, or the stack pointer is not back where it was.
pub(crate) fn clobbers(blocks: &[Block], convention: Convention, sp: u16) -> Option<Registers> {
    clobbers_knowing(blocks, convention, sp, &|_| None)
}

/// `clobbers`, a call to a function `known` names changing what it says
/// in place of what the call holds.
pub(crate) fn clobbers_knowing(
    blocks: &[Block],
    convention: Convention,
    sp: u16,
    known: &dyn Fn(u64) -> Option<Option<Registers>>,
) -> Option<Registers> {
    if blocks.is_empty() {
        return None;
    }
    let starts: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let mut entering: Vec<Option<State>> = vec![None; blocks.len()];
    entering[0] = Some(State::entry(sp));
    let mut pending = std::collections::BTreeSet::from([0]);
    let mut changed = Registers::default();
    let mut visits = 0;
    while let Some(index) = pending.pop_first() {
        visits += 1;
        if visits > VISITS_PER_BLOCK * blocks.len() {
            return None;
        }
        let mut state = entering[index]
            .clone()
            .expect("a block is queued once entered");
        let mut flows: Vec<(u64, State)> = Vec::new();
        let mut ended = false;
        for stmt in &blocks[index].stmts {
            match stmt {
                Stmt::Assign { dest, value } => {
                    let value = if dest.width == 64 {
                        state.value(value)
                    } else {
                        Value::Other
                    };
                    state.set(dest.index, value);
                }
                Stmt::Store { addr, value, width } => {
                    if let Value::Frame(at) = state.value(addr) {
                        state.forget_slots(at, *width);
                        if *width == 8 {
                            let value = state.value(value);
                            state.slots.insert(at, value);
                        }
                    }
                }
                Stmt::Call {
                    target,
                    convention,
                    result,
                    clobbers,
                    ..
                } => {
                    match target.and_then(known).unwrap_or(*clobbers) {
                        Some(clobbers) => {
                            for register in clobbers.iter() {
                                state.set(register, Value::Other);
                            }
                        }
                        None => {
                            for register in convention.clobbered() {
                                state.set(*register, Value::Other);
                            }
                        }
                    }
                    if let Some(result) = result {
                        state.set(result.index, Value::Other);
                    }
                    // The callee's frame lies below the stack pointer.
                    match state.register(sp) {
                        Value::Frame(top) => state.slots.retain(|slot, _| *slot >= top),
                        _ => state.slots.clear(),
                    }
                }
                Stmt::Unsupported { writes, .. } => match writes {
                    Some(writes) => {
                        for register in writes {
                            state.set(*register, Value::Other);
                        }
                    }
                    None => state.machine = [Value::Other; MACHINE],
                },
                Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } => {
                    flows.push((*target, state.clone()));
                }
                Stmt::Br {
                    target: Some(target),
                } => {
                    flows.push((*target, state.clone()));
                    ended = true;
                    break;
                }
                Stmt::Switch { cases, default, .. } => {
                    for target in cases.iter().map(|(_, target)| target).chain(default) {
                        flows.push((*target, state.clone()));
                    }
                    ended = true;
                    break;
                }
                Stmt::Ret { .. } => {
                    if state.register(sp) != Value::Frame(0) {
                        return None;
                    }
                    let entry = State::entry(sp);
                    for (index, (held, was)) in state.machine.iter().zip(&entry.machine).enumerate()
                    {
                        if held != was {
                            changed.insert(index as u16);
                        }
                    }
                    ended = true;
                    break;
                }
                Stmt::Trap => {
                    ended = true;
                    break;
                }
                Stmt::Br { target: None } | Stmt::BrIndirect { .. } => return None,
            }
        }
        if !ended {
            // Code that runs off the end of what was lifted may go anywhere.
            let next = blocks.get(index + 1)?;
            flows.push((next.start, state));
        }
        for (target, state) in flows {
            let target = *starts.get(&target)?;
            let grew = match &mut entering[target] {
                Some(known) => known.join(&state),
                none => {
                    *none = Some(state);
                    true
                }
            };
            if grew {
                pending.insert(target);
            }
        }
    }
    for register in convention.fixed() {
        changed.0 &= !(1 << register);
    }
    Some(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::RegRef;

    const RSP: u16 = 4;
    const RBX: u16 = 3;
    const RBP: u16 = 5;

    fn reg(index: u16) -> Expr {
        Expr::reg(index, 64)
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn push(index: u16) -> [Stmt; 2] {
        [
            assign(RSP, Expr::bin(BinOp::Sub, reg(RSP), Expr::Const(8))),
            Stmt::Store {
                addr: reg(RSP),
                value: reg(index),
                width: 8,
            },
        ]
    }

    fn pop(index: u16) -> [Stmt; 2] {
        [
            assign(
                index,
                Expr::Load {
                    addr: Box::new(reg(RSP)),
                    width: 8,
                    signed: false,
                },
            ),
            assign(RSP, Expr::bin(BinOp::Add, reg(RSP), Expr::Const(8))),
        ]
    }

    fn call() -> Stmt {
        Stmt::Call {
            target: Some(0x2000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            result: None,
            clobbers: None,
            via: None,
        }
    }

    fn ret() -> Stmt {
        Stmt::Ret { value: reg(0) }
    }

    fn block(start: u64, stmts: Vec<Stmt>) -> Block {
        Block { start, stmts }
    }

    #[test]
    fn a_register_pushed_and_popped_back_is_kept() {
        let mut stmts: Vec<Stmt> = push(RBX).into();
        stmts.push(assign(RBX, Expr::Const(7)));
        stmts.push(assign(0, reg(RBX)));
        stmts.extend(pop(RBX));
        stmts.push(ret());
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert_eq!(changed.iter().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn a_register_restored_on_one_path_only_is_changed() {
        let mut first: Vec<Stmt> = push(RBX).into();
        first.push(assign(RBX, Expr::Const(7)));
        first.push(Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: reg(7),
            rhs: Expr::Const(0),
            target: 0x1020,
        });
        let mut restoring: Vec<Stmt> = pop(RBX).into();
        restoring.push(ret());
        let leaving = vec![
            assign(RSP, Expr::bin(BinOp::Add, reg(RSP), Expr::Const(8))),
            ret(),
        ];
        let blocks = [
            block(0x1000, first),
            block(0x1010, restoring),
            block(0x1020, leaving),
        ];
        let changed = clobbers(&blocks, Convention::SysV, RSP).unwrap();
        assert!(changed.contains(RBX));
    }

    #[test]
    fn a_call_changes_what_its_callee_does_and_a_save_survives_it() {
        let mut stmts: Vec<Stmt> = push(RBP).into();
        stmts.push(call());
        stmts.extend(pop(RBP));
        stmts.push(ret());
        let changed = clobbers(&[block(0x1000, stmts.clone())], Convention::SysV, RSP).unwrap();
        assert!(!changed.contains(RBP) && !changed.contains(RBX));
        assert!(changed.contains(0) && changed.contains(11));
        // A callee known to change only rbx changes only rbx.
        stmts[2] = Stmt::Call {
            target: Some(0x2000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            result: None,
            clobbers: Some([RBX].into_iter().collect()),
            via: None,
        };
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert_eq!(changed.iter().collect::<Vec<_>>(), vec![RBX]);
    }

    #[test]
    fn an_unknown_way_out_leaves_the_registers_unknown() {
        let blocks = [block(0x1000, vec![Stmt::BrIndirect { target: reg(0) }])];
        assert_eq!(clobbers(&blocks, Convention::SysV, RSP), None);
        // So does a return with the stack pointer elsewhere.
        let blocks = [block(
            0x1000,
            push(RBX).into_iter().chain([ret()]).collect(),
        )];
        assert_eq!(clobbers(&blocks, Convention::SysV, RSP), None);
    }
}
