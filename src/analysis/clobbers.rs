//! The registers a function may return with changed. A walk over its blocks
//! follows what each register holds (its value on entry, an address in the
//! frame, or anything else) and what each frame slot holds, so a register
//! stored on entry and loaded back before every return, as a push and a pop
//! or a pair store and a pair load do, keeps its value for the caller.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ir::{BinOp, Block, Convention, Expr, Registers, Stmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    /// What the register held on entry.
    Entry(u16),
    /// The stack pointer on entry, plus an offset.
    Frame(i64),
    /// Bits still computed from a frame address, possibly pointing anywhere in it.
    Derived(u64),
    Constant(u64),
    Other,
}

/// How many machine registers there are.
const MACHINE: usize = crate::arch::aarch64::V0 as usize + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    sp: u16,
    narrow: bool,
    /// What each machine register holds.
    machine: [Value; MACHINE],
    /// What the lifter's other registers, as those it keeps flag operands
    /// in, hold where it is known; one not listed holds nothing known,
    /// which is never any machine register's entry value either.
    others: BTreeMap<u16, Value>,
    /// What each saved frame slot holds, by its offset from the stack
    /// pointer on entry; a slot not listed holds nothing known.
    slots: BTreeMap<i64, (u8, Value)>,
    /// The frame offsets an address the walk no longer follows may point
    /// at: one stored, passed on, offset by an unknown index, or held
    /// differently on the ways into a join.
    exposed: BTreeSet<i64>,
    /// Whether a frame address was let go at an offset not known.
    lost: bool,
}

impl State {
    fn forget_above_entry(&mut self) {
        self.slots.retain(|slot, (width, _)| {
            slot.checked_add(i64::from(*width))
                .is_some_and(|end| end <= 0)
        });
    }

    fn entry(sp: u16, narrow: bool) -> Self {
        State {
            sp,
            narrow,
            machine: std::array::from_fn(|index| {
                if index == usize::from(sp) {
                    Value::Frame(0)
                } else {
                    Value::Entry(index as u16)
                }
            }),
            others: BTreeMap::new(),
            slots: BTreeMap::new(),
            exposed: BTreeSet::new(),
            lost: false,
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
        self.class(expr).0
    }

    /// Whether `expr` is computed from a frame address, other than by
    /// reading memory through one.
    fn involves_frame(&self, expr: &Expr) -> bool {
        let (value, indexed) = self.class(expr);
        indexed || matches!(value, Value::Frame(_) | Value::Derived(_))
    }

    /// What `expr` holds, and whether it is a frame address plus an index
    /// not known: an address into an object of the frame, which no write
    /// through it leaves, as one through any address the walk does not
    /// follow.
    fn class(&self, expr: &Expr) -> (Value, bool) {
        match expr {
            Expr::Const(value) => return (Value::Constant(*value), false),
            Expr::Bin {
                op: op @ (BinOp::And | BinOp::Or | BinOp::Xor),
                lhs,
                rhs,
            } => {
                let left = self.class(lhs);
                let right = self.class(rhs);
                if let (Value::Constant(a), Value::Constant(b)) = (left.0, right.0) {
                    let value = match op {
                        BinOp::And => a & b,
                        BinOp::Or => a | b,
                        _ => a ^ b,
                    };
                    return (Value::Constant(value), false);
                }
                if self.narrow
                    && *op == BinOp::And
                    && (right.0 == Value::Constant(0xffff_ffff))
                    && matches!(left.0, Value::Frame(_) | Value::Entry(0..=15))
                {
                    return left;
                }
                if *op == BinOp::Or
                    && let (Value::Frame(at), Value::Constant(mask))
                    | (Value::Constant(mask), Value::Frame(at)) = (left.0, right.0)
                {
                    let address = Expr::bin(BinOp::Or, Expr::reg(self.sp, 64), Expr::Const(mask));
                    if let Some(offset) =
                        crate::passes::frame_slots::frame_slot(&address, at, self.sp)
                    {
                        return (Value::Frame(offset), false);
                    }
                }
                let bits = |value| match value {
                    (_, true) | (Value::Frame(_), _) => u64::MAX,
                    (Value::Derived(bits), _) => bits,
                    _ => 0,
                };
                let mut derived = bits(left) | bits(right);
                if *op == BinOp::And {
                    if let Value::Constant(mask) = right.0 {
                        derived = bits(left) & mask;
                    } else if let Value::Constant(mask) = left.0 {
                        derived = bits(right) & mask;
                    }
                }
                return if derived == 0 {
                    (Value::Other, false)
                } else {
                    (Value::Derived(derived), false)
                };
            }
            Expr::Reg { index, width }
                if *width == 64 || (self.narrow && *width == 32 && *index < 16) =>
            {
                return (self.register(*index), false);
            }
            Expr::Load { addr, width, .. } => {
                let value = match (width, self.value(addr)) {
                    (width, Value::Frame(at)) => self
                        .slots
                        .get(&at)
                        .filter(|(saved_width, _)| *saved_width == *width)
                        .map_or(Value::Other, |(_, value)| *value),
                    _ => Value::Other,
                };
                return (value, false);
            }
            Expr::Bin { op, lhs, rhs } if matches!(op, BinOp::Add | BinOp::Sub) => {
                let (left, right) = (self.class(lhs), self.class(rhs));
                let based =
                    |(value, indexed): (Value, bool)| indexed || matches!(value, Value::Frame(_));
                let involved = |(value, indexed): (Value, bool)| {
                    indexed || matches!(value, Value::Frame(_) | Value::Derived(_))
                };
                match (op, left.0, right.0) {
                    (BinOp::Add, Value::Frame(at), Value::Constant(delta))
                    | (BinOp::Add, Value::Constant(delta), Value::Frame(at)) => {
                        return (Value::Frame(at.wrapping_add(delta as i64)), false);
                    }
                    (BinOp::Sub, Value::Frame(at), Value::Constant(delta)) => {
                        return (Value::Frame(at.wrapping_sub(delta as i64)), false);
                    }
                    _ => {}
                }
                let indexed = match op {
                    BinOp::Add => {
                        (based(left) && !involved(right)) || (based(right) && !involved(left))
                    }
                    _ => based(left) && !involved(right),
                };
                if indexed {
                    return (Value::Other, true);
                }
                if involved(left) || involved(right) {
                    return (Value::Derived(u64::MAX), false);
                }
                return (Value::Other, false);
            }
            _ => {}
        }
        // Anything else computed from a frame address may still point into
        // the frame, at an offset the walk does not know.
        let constant = |index| match self.register(index) {
            Value::Constant(value) => Some(value),
            _ => None,
        };
        if let Some(value) = crate::ir::semantics::evaluate(expr, &constant) {
            return (Value::Constant(value), false);
        }
        let derived = crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| self.involves_frame(child));
        if derived {
            (Value::Derived(u64::MAX), false)
        } else {
            (Value::Other, false)
        }
    }

    /// Takes in what `other` may hold too; whether anything changed.
    fn join(&mut self, other: &State) -> bool {
        let mut changed = false;
        // A frame address held on one way in only is no longer followed; a
        // register keeps one computed from it as such, other storage not.
        for (held, came) in self.machine.iter_mut().zip(&other.machine) {
            if held == came {
                continue;
            }
            for value in [*held, *came] {
                if let Value::Frame(at) = value {
                    changed |= self.exposed.insert(at);
                }
            }
            let joined = if matches!(held, Value::Derived(_)) || matches!(came, Value::Derived(_)) {
                Value::Derived(u64::MAX)
            } else {
                Value::Other
            };
            if *held != joined {
                *held = joined;
                changed = true;
            }
        }
        let mut dropped: Vec<(Value, Value)> = self
            .others
            .keys()
            .chain(other.others.keys())
            // Flag operands describe comparisons, never addresses used by memory operations.
            .filter(|index| {
                !crate::ir::FLAG_OPERANDS.contains(index)
                    && !crate::ir::FLAG_CARRIED.contains(index)
            })
            .map(|index| (self.register(*index), other.register(*index)))
            .collect();
        dropped.extend(self.slots.keys().chain(other.slots.keys()).map(|slot| {
            (
                self.slots
                    .get(slot)
                    .map_or(Value::Other, |(_, value)| *value),
                other
                    .slots
                    .get(slot)
                    .map_or(Value::Other, |(_, value)| *value),
            )
        }));
        let mut lost = other.lost;
        for (a, b) in dropped {
            if a == b {
                continue;
            }
            for value in [a, b] {
                match value {
                    Value::Frame(at) => changed |= self.exposed.insert(at),
                    Value::Derived(_) => lost = true,
                    _ => {}
                }
            }
        }
        for at in &other.exposed {
            changed |= self.exposed.insert(*at);
        }
        if lost && !self.lost {
            self.lost = true;
            changed = true;
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
        self.slots.retain(|slot, (width, _)| {
            *slot >= end
                || slot
                    .checked_add(i64::from(*width))
                    .is_some_and(|end| end <= at)
        });
    }

    /// Takes note of the frame addresses `expr` lets out of the walk's view.
    fn expose(&mut self, expr: &Expr) {
        if let Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } = expr
        {
            self.lost |= self.involves_frame(lhs) || self.involves_frame(rhs);
            self.expose(then);
            self.expose(els);
            return;
        }
        match self.value(expr) {
            Value::Frame(at) => {
                self.exposed.insert(at);
            }
            Value::Derived(_) => self.lost = true,
            _ => {}
        }
    }
    /// A write at `addr` other than into a slot the walk follows.
    fn write_through(&mut self, addr: &Expr, width: u8, clobbered: &[u16]) {
        match self.value(addr) {
            Value::Frame(at) => self.forget_slots(at, width),
            Value::Derived(_) => {
                self.slots.clear();
                self.lost |= self.narrow;
            }
            _ => self.write_unplaced(clobbered),
        }
    }

    /// A write the walk cannot place, as through an exposed address: that
    /// reaches the object there and so the slots from it up, but not a slot
    /// below the entry stack pointer saving a register the convention
    /// preserves, which belongs to no object, unless the address is the
    /// slot's own. Once a frame address was lost it may reach any slot.
    fn write_unplaced(&mut self, clobbered: &[u16]) {
        if self.lost {
            self.slots.clear();
            return;
        }
        let exposed = &self.exposed;
        self.slots.retain(|slot, (width, value)| {
            let end = slot.saturating_add(i64::from(*width));
            let save = end <= 0
                && matches!(value, Value::Entry(register) if !clobbered.contains(register));
            if save {
                exposed.range(*slot..end).next().is_none()
            } else {
                exposed.range(..end).next().is_none()
            }
        });
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
    let clobbered = convention.clobbered();
    let narrow = matches!(
        convention,
        Convention::Cdecl
            | Convention::Stdcall
            | Convention::Fastcall
            | Convention::Thiscall
            | Convention::Aapcs32
    );
    let starts: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let mut entering: Vec<Option<State>> = vec![None; blocks.len()];
    entering[0] = Some(State::entry(sp, narrow));
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
                    if *instruction == crate::ir::MachineInstruction::ArmCacheZero {
                        state.slots.clear();
                    }
                    if let crate::ir::MachineInstruction::ArmExclusive {
                        load: false,
                        width,
                        pair,
                        ..
                    } = instruction
                    {
                        for value in inputs.iter().skip(1) {
                            state.expose(value);
                        }
                        match inputs.first() {
                            Some(addr) => state.write_through(
                                addr,
                                width.saturating_mul(if *pair { 2 } else { 1 }),
                                clobbered,
                            ),
                            None => state.slots.clear(),
                        }
                    }
                    if let crate::ir::MachineInstruction::Atomic { width, .. } = instruction {
                        for value in inputs.iter().skip(1) {
                            state.expose(value);
                        }
                        // An atomic writes its own address, as a store does;
                        // its ordering only makes visible what other threads
                        // write, which reaches no slot an address of the
                        // function's own does not.
                        match inputs.first() {
                            Some(addr) => state.write_through(addr, *width, clobbered),
                            None => state.write_unplaced(clobbered),
                        }
                        // The caller's frame above the entry stack pointer is
                        // memory another thread may share.
                        state.forget_above_entry();
                    } else {
                        for value in inputs {
                            state.expose(value);
                        }
                        if matches!(
                            instruction,
                            crate::ir::MachineInstruction::ArmBarrier { .. }
                                | crate::ir::MachineInstruction::ArmLoadAcquire { .. }
                                | crate::ir::MachineInstruction::ArmExclusive { .. }
                        ) {
                            state.forget_above_entry();
                        }
                    }
                    for output in outputs {
                        state.set(output.index, Value::Other);
                    }
                }
                Stmt::Assign { dest, value } => {
                    // A choice between frame addresses is followed as each of them.
                    let value = if dest.width == 64 && !matches!(value, Expr::Select { .. }) {
                        state.value(value)
                    } else {
                        state.expose(value);
                        Value::Other
                    };
                    state.set(dest.index, value);
                }
                Stmt::Store { addr, value, width } => {
                    state.expose(value);
                    match state.value(addr) {
                        Value::Frame(at) => {
                            state.forget_slots(at, *width);
                            if *width == 8 || (state.narrow && *width == 4) {
                                let value = state.value(value);
                                state.slots.insert(at, (*width, value));
                            }
                        }
                        _ => state.write_through(addr, *width, clobbered),
                    }
                }
                Stmt::Call {
                    target,
                    convention,
                    outputs,
                    clobbers,
                    ..
                } => {
                    for value in stmt.operands() {
                        state.expose(value);
                    }
                    for index in stmt.unnamed_call_reads() {
                        state.expose(&Expr::reg(index, 64));
                    }
                    state.write_unplaced(clobbered);
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
                    state.lost = true;
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
                    if state.register(sp) != Value::Frame(0) || (state.narrow && state.lost) {
                        return None;
                    }
                    let entry = State::entry(sp, narrow);
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
            abi: None,
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
    fn joined_flag_operands_do_not_expose_saved_register_slots() {
        let mut temporaries = crate::ir::FLAG_OPERANDS.to_vec();
        temporaries.extend(crate::ir::FLAG_CARRIED);
        temporaries.push(crate::ir::EXCHANGE);
        for temporary in temporaries {
            let mut entry = push(RBP).to_vec();
            entry.push(assign(temporary, reg(RSP)));
            entry.push(Stmt::Br {
                target: Some(0x1010),
            });
            let mut exit = vec![Stmt::Store {
                addr: reg(7),
                value: Expr::Const(19),
                width: 4,
            }];
            exit.extend(pop(RBP));
            exit.push(ret());
            let blocks = [
                block(0x1000, entry),
                block(
                    0x1010,
                    vec![
                        assign(temporary, Expr::Const(2)),
                        Stmt::Brif {
                            cond: crate::ir::Cond::Eq,
                            lhs: reg(0),
                            rhs: Expr::Const(0),
                            target: 0x1010,
                        },
                    ],
                ),
                block(0x1020, exit),
            ];
            let changed = clobbers(&blocks, Convention::SysV, RSP).unwrap();
            assert_eq!(changed.contains(RBP), temporary == crate::ir::EXCHANGE);
        }
    }

    #[test]
    fn atomic_heap_accesses_preserve_saved_registers_but_writes_reaching_their_slots_do_not() {
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
                    !matches!(case, 0 | 5),
                    "case {case}, {ordering:?}"
                );
            }
        }
    }

    #[test]
    fn cache_zeroing_invalidates_saved_registers_in_the_same_block() {
        let mut stmts = Vec::from(push(RBX));
        stmts.push(Stmt::Machine {
            instruction: crate::ir::MachineInstruction::ArmCacheZero,
            inputs: vec![Expr::bin(BinOp::Add, reg(RSP), Expr::Const(8))],
            outputs: vec![],
        });
        stmts.extend(pop(RBX));
        stmts.push(ret());
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert!(changed.contains(RBX));
    }

    fn atomic_add(addr: Expr) -> Stmt {
        use crate::ir::{AtomicOp, MachineInstruction, Ordering};
        Stmt::Machine {
            instruction: MachineInstruction::Atomic {
                op: AtomicOp::Add,
                width: 8,
                ordering: Ordering::SeqCst,
            },
            inputs: vec![addr, Expr::Const(1)],
            outputs: Vec::new(),
        }
    }

    #[test]
    fn an_atomic_on_other_memory_keeps_the_saves_of_a_frame_whose_locals_escape() {
        // push rbx; sub rsp, 0x20; f(&local); rbx = 7; atomic add [rax];
        // add rsp, 0x20; pop rbx; ret
        let mut stmts: Vec<Stmt> = push(RBX).into();
        stmts.push(assign(
            RSP,
            Expr::bin(BinOp::Sub, reg(RSP), Expr::Const(0x20)),
        ));
        let mut called = call();
        if let Stmt::Call { args, .. } = &mut called {
            *args = Some(vec![Expr::bin(BinOp::Add, reg(RSP), Expr::Const(8))]);
        }
        stmts.push(called);
        stmts.push(assign(RBX, Expr::Const(7)));
        stmts.push(atomic_add(reg(0)));
        stmts.push(assign(
            RSP,
            Expr::bin(BinOp::Add, reg(RSP), Expr::Const(0x20)),
        ));
        stmts.extend(pop(RBX));
        stmts.push(ret());
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert!(!changed.contains(RBX));
    }

    #[test]
    fn an_index_into_a_local_does_not_reach_the_saves() {
        let mut stmts: Vec<Stmt> = push(RBX).into();
        stmts.push(assign(
            RSP,
            Expr::bin(BinOp::Sub, reg(RSP), Expr::Const(0x20)),
        ));
        stmts.push(assign(0, Expr::bin(BinOp::Add, reg(RSP), reg(1))));
        stmts.push(Stmt::Store {
            addr: reg(0),
            value: Expr::Const(0),
            width: 1,
        });
        stmts.push(assign(RBX, Expr::Const(7)));
        stmts.push(atomic_add(reg(7)));
        stmts.push(assign(
            RSP,
            Expr::bin(BinOp::Add, reg(RSP), Expr::Const(0x20)),
        ));
        stmts.extend(pop(RBX));
        stmts.push(ret());
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert!(!changed.contains(RBX));
    }

    #[test]
    fn a_save_slot_address_kept_in_memory_is_still_written_through() {
        // push rbx; [rdi] = rsp; rsi = [rdi]; [rsi] = 0; pop rbx; ret
        for atomic in [false, true] {
            let mut stmts: Vec<Stmt> = push(RBX).into();
            stmts.push(Stmt::Store {
                addr: reg(7),
                value: reg(RSP),
                width: 8,
            });
            stmts.push(assign(
                6,
                Expr::Load {
                    addr: Box::new(reg(7)),
                    width: 8,
                    signed: false,
                },
            ));
            stmts.push(if atomic {
                atomic_add(reg(6))
            } else {
                Stmt::Store {
                    addr: reg(6),
                    value: Expr::Const(0),
                    width: 8,
                }
            });
            stmts.extend(pop(RBX));
            stmts.push(ret());
            let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
            assert!(changed.contains(RBX), "atomic {atomic}");
        }
    }

    #[test]
    fn a_save_slot_address_held_on_one_way_into_a_join_is_still_written_through() {
        let mut entry: Vec<_> = push(RBX).into();
        entry.push(Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: reg(0),
            rhs: Expr::Const(0),
            target: 0x1020,
        });
        let mut exit = vec![Stmt::Store {
            addr: reg(6),
            value: Expr::Const(0),
            width: 8,
        }];
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
                    assign(6, reg(7)),
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
    fn an_exposed_address_reaches_the_rest_of_its_object() {
        // Registers spilled above the return address, as Go spills its
        // arguments, are one object with the slot whose address a callee
        // gets: it may change them all.
        let at = |offset: u64| Expr::bin(BinOp::Add, reg(RSP), Expr::Const(offset));
        let mut called = call();
        if let Stmt::Call { args, .. } = &mut called {
            *args = Some(vec![at(8)]);
        }
        let stmts = vec![
            Stmt::Store {
                addr: at(8),
                value: reg(0),
                width: 8,
            },
            Stmt::Store {
                addr: at(16),
                value: reg(RBX),
                width: 8,
            },
            called,
            assign(
                RBX,
                Expr::Load {
                    addr: Box::new(at(16)),
                    width: 8,
                    signed: false,
                },
            ),
            ret(),
        ];
        let changed = clobbers(&[block(0x1000, stmts)], Convention::SysV, RSP).unwrap();
        assert!(changed.contains(RBX));
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
            abi: None,
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
