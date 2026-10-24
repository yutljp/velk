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
    escaped: bool,
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
            escaped: false,
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
        let loses_frame = |a: Value, b: Value| {
            a != b && (matches!(a, Value::Frame(_)) || matches!(b, Value::Frame(_)))
        };
        let ambiguous_frame = self
            .machine
            .iter()
            .zip(&other.machine)
            .any(|(a, b)| loses_frame(*a, *b))
            || self
                .others
                .iter()
                .chain(&other.others)
                .any(|(index, _)| loses_frame(self.register(*index), other.register(*index)))
            || self.slots.iter().chain(&other.slots).any(|(slot, _)| {
                loses_frame(
                    self.slots.get(slot).copied().unwrap_or(Value::Other),
                    other.slots.get(slot).copied().unwrap_or(Value::Other),
                )
            });
        if (other.escaped || ambiguous_frame) && !self.escaped {
            self.escaped = true;
            changed = true;
        }
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
        let Some(end) = at.checked_add(i64::from(width)) else {
            self.slots.clear();
            return;
        };
        self.slots
            .retain(|slot, _| *slot >= end || slot.checked_add(8).is_some_and(|end| end <= at));
    }

    fn exposes_frame(&self, expr: &Expr) -> bool {
        if matches!(self.value(expr), Value::Frame(_)) {
            return true;
        }
        !matches!(expr, Expr::Load { .. })
            && crate::ir::visit::children(expr)
                .into_iter()
                .any(|child| self.exposes_frame(child))
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
                Stmt::Machine {
                    instruction,
                    inputs,
                    outputs,
                } => {
                    if let crate::ir::MachineInstruction::Atomic { width, .. } = instruction {
                        state.escaped |= inputs
                            .iter()
                            .skip(1)
                            .any(|value| state.exposes_frame(value));
                        state.escaped |= inputs.first().is_some_and(|addr| {
                            state.exposes_frame(addr)
                                && !matches!(state.value(addr), Value::Frame(_))
                        });
                        if state.escaped {
                            state.slots.clear();
                        } else {
                            // Ordering does not change the saved registers in an
                            // unescaped frame. The atomic's own write still does.
                            if let Some(addr) = inputs.first()
                                && let Value::Frame(at) = state.value(addr)
                            {
                                state.forget_slots(at, *width);
                            }
                            state
                                .slots
                                .retain(|slot, _| slot.checked_add(8).is_some_and(|end| end <= 0));
                        }
                    } else {
                        state.escaped |= inputs.iter().any(|value| state.exposes_frame(value));
                    }
                    for output in outputs {
                        state.set(output.index, Value::Other);
                    }
                }
                Stmt::Assign { dest, value } => {
                    if state.exposes_frame(value)
                        && (dest.width != 64 || !matches!(state.value(value), Value::Frame(_)))
                    {
                        state.escaped = true;
                    }
                    let value = if dest.width == 64 {
                        state.value(value)
                    } else {
                        Value::Other
                    };
                    state.set(dest.index, value);
                }
                Stmt::Store { addr, value, width } => {
                    state.escaped |= state.exposes_frame(value);
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
                    outputs,
                    clobbers,
                    args,
                    ..
                } => {
                    state.escaped |= args.is_none()
                        || stmt
                            .operands()
                            .iter()
                            .any(|value| state.exposes_frame(value))
                        || stmt
                            .unnamed_call_reads()
                            .iter()
                            .any(|index| matches!(state.register(*index), Value::Frame(_)));
                    let physical = target
                        .and_then(known)
                        .unwrap_or(*clobbers)
                        .unwrap_or_else(|| convention.clobbered().iter().copied().collect());
                    let values: Vec<_> = outputs
                        .iter()
                        .map(|output| {
                            let value =
                                if !physical.contains(output.register) && output.dest.width == 64 {
                                    state.register(output.register)
                                } else {
                                    Value::Other
                                };
                            (output.dest.index, value)
                        })
                        .collect();
                    for register in physical.iter() {
                        state.set(register, Value::Other);
                    }
                    for (destination, value) in values {
                        state.set(destination, value);
                    }
                    // The callee's frame lies below the stack pointer.
                    match state.register(sp) {
                        Value::Frame(top) => state.slots.retain(|slot, _| *slot >= top),
                        _ => state.slots.clear(),
                    }
                }
                Stmt::Unsupported { writes, .. } => {
                    state.escaped = true;
                    match writes {
                        Some(writes) => {
                            for register in writes {
                                state.set(*register, Value::Other);
                            }
                        }
                        None => state.machine = [Value::Other; MACHINE],
                    }
                }
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
            let Some(next) = blocks.get(index + 1) else {
                return None;
            };
            flows.push((next.start, state));
        }
        for (target, state) in flows {
            let Some(&target) = starts.get(&target) else {
                return None;
            };
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
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x2000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            outputs: crate::ir::fallback_call_outputs(Convention::SysV, None),
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
    fn atomic_heap_accesses_preserve_saved_registers_but_overlaps_and_escapes_do_not() {
        use crate::ir::{AtomicOp, MachineInstruction, Ordering};

        for ordering in [
            Ordering::Relaxed,
            Ordering::Acquire,
            Ordering::Release,
            Ordering::AcqRel,
            Ordering::SeqCst,
        ] {
            for case in 0..7 {
                let mut stmts: Vec<_> = push(RBX).into();
                stmts.push(assign(RBX, Expr::Const(7)));
                if case == 2 {
                    stmts.push(Stmt::Store {
                        addr: reg(7),
                        value: reg(RSP),
                        width: 8,
                    });
                }
                if case == 3 {
                    let mut called = call();
                    if let Stmt::Call { args, .. } = &mut called {
                        *args = Some(vec![reg(RSP)]);
                    }
                    stmts.push(called);
                }
                if case >= 5 {
                    if case == 6 {
                        stmts.push(assign(7, reg(RSP)));
                    }
                    let mut called = call();
                    if let Stmt::Call { args, .. } = &mut called {
                        *args = None;
                    }
                    stmts.push(called);
                }
                let addr = match case {
                    1 => reg(RSP),
                    4 => Expr::bin(BinOp::Add, reg(RSP), Expr::Const(4)),
                    _ => reg(7),
                };
                stmts.push(Stmt::Machine {
                    instruction: MachineInstruction::Atomic {
                        op: AtomicOp::Add,
                        width: 8,
                        ordering,
                    },
                    inputs: vec![addr, Expr::Const(1)],
                    outputs: Vec::new(),
                });
                stmts.extend(pop(RBX));
                stmts.push(ret());
                let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
                assert_eq!(
                    changed.contains(RBX),
                    case != 0,
                    "case {case}, {ordering:?}"
                );
            }
        }
    }

    #[test]
    fn joined_frame_pointers_keep_atomic_aliasing_conservative() {
        use crate::ir::{AtomicOp, MachineInstruction, Ordering};

        let mut entry: Vec<_> = push(RBX).into();
        entry.push(Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: reg(0),
            rhs: Expr::Const(0),
            target: 0x1020,
        });
        let mut exit = vec![
            Stmt::Store {
                addr: reg(7),
                value: reg(6),
                width: 8,
            },
            Stmt::Machine {
                instruction: MachineInstruction::Atomic {
                    op: AtomicOp::Add,
                    width: 8,
                    ordering: Ordering::SeqCst,
                },
                inputs: vec![reg(7), Expr::Const(1)],
                outputs: Vec::new(),
            },
        ];
        exit.extend(pop(RBX));
        exit.push(ret());
        let blocks = vec![
            block(0x1000, entry),
            block(
                0x1010,
                vec![
                    assign(6, reg(RSP)),
                    Stmt::Br {
                        target: Some(0x1030),
                    },
                ],
            ),
            block(
                0x1020,
                vec![
                    assign(6, Expr::Const(0)),
                    Stmt::Br {
                        target: Some(0x1030),
                    },
                ],
            ),
            block(0x1030, exit),
        ];
        assert!(
            clobbers(&blocks, Convention::SysV, RSP)
                .unwrap()
                .contains(RBX)
        );
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
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x2000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            outputs: crate::ir::fallback_call_outputs(
                Convention::SysV,
                Some([RBX].into_iter().collect()),
            ),
            clobbers: Some([RBX].into_iter().collect()),
            via: None,
        };
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert_eq!(changed.iter().collect::<Vec<_>>(), vec![RBX]);
    }

    #[test]
    fn precise_callee_effects_override_stale_fallback_outputs() {
        let blocks = [block(0x1000, vec![call(), ret()])];
        let changed = super::clobbers_knowing(&blocks, Convention::SysV, RSP, &|_| {
            Some(Some(Registers::default()))
        })
        .unwrap();
        assert_eq!(changed, Registers::default());
    }

    #[test]
    fn named_outputs_do_not_hide_physical_callee_effects() {
        let mut called = call();
        let Stmt::Call {
            outputs, clobbers, ..
        } = &mut called
        else {
            unreachable!()
        };
        *clobbers = Some([2].into_iter().collect());
        *outputs = vec![crate::ir::CallOutput {
            register: 2,
            dest: RegRef {
                index: crate::ir::VARIABLE_BASE,
                width: 64,
            },
        }];
        let changed =
            super::clobbers(&[block(0x1000, vec![called, ret()])], Convention::SysV, RSP).unwrap();
        assert_eq!(changed.iter().collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn preserved_output_destinations_use_one_pre_call_snapshot() {
        let mut called = call();
        let Stmt::Call {
            outputs, clobbers, ..
        } = &mut called
        else {
            unreachable!()
        };
        *clobbers = Some(Registers::default());
        *outputs = vec![
            crate::ir::CallOutput {
                register: 0,
                dest: RegRef {
                    index: 2,
                    width: 64,
                },
            },
            crate::ir::CallOutput {
                register: 2,
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
            },
        ];
        let changed =
            super::clobbers(&[block(0x1000, vec![called, ret()])], Convention::SysV, RSP).unwrap();
        assert_eq!(changed.iter().collect::<Vec<_>>(), vec![0, 2]);
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
