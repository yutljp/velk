//! Word pairs observed at direct calls. Adjacent loads alone do not identify a scalar object.
//!
//! A stack pair must be the unmodified low and high words of the same eight-byte load,
//! declared scalar object, or declared call result at every observed call. Stores invalidate
//! overlapping object snapshots. Unsupported or missing callers refuse the join. With the
//! target ABI's placement, joining and extracting the words preserves every input bit; the
//! callee and all calls use the same recovered declaration.
//!
//! A caller reading the high result after a call is evidence of a second result word.
//! Merely leaving that register defined at a callee's return is not such evidence.

use std::collections::{HashMap, HashSet};

use crate::ir::{BinOp, Convention, Expr, Stmt};
use crate::loader::{Image, Isa};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Evidence {
    pub pairs: u64,
    pub high_result: bool,
}

#[derive(Debug, Default)]
pub(super) struct CallEvidence {
    pairs: u64,
    high_result: bool,
    sources: [Vec<u64>; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Address {
    Frame(i64),
    Absolute(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Object {
    Memory(Address, usize),
    Load(usize),
    Input(u16),
    Result(u64, usize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Value {
    #[default]
    Unknown,
    Constant(u64),
    Frame(i64),
    Whole(Object),
    Word(Object, bool),
}

#[derive(Clone, Default)]
struct State {
    registers: HashMap<u16, Value>,
    stack: HashMap<i64, Value>,
    objects: HashMap<Address, usize>,
    epoch: usize,
    serial: usize,
}

impl State {
    fn register(&self, register: u16) -> Value {
        self.registers.get(&register).copied().unwrap_or_default()
    }

    fn load(&self, address: Value, width: u8) -> Value {
        let location = match address {
            Value::Frame(offset) => Address::Frame(offset),
            Value::Constant(address) => Address::Absolute(address),
            _ => return Value::Unknown,
        };
        if width == 4 {
            for high in [false, true] {
                let base = match location {
                    Address::Frame(offset) => offset
                        .checked_sub(if high { 4 } else { 0 })
                        .map(Address::Frame),
                    Address::Absolute(address) => address
                        .checked_sub(if high { 4 } else { 0 })
                        .map(Address::Absolute),
                };
                if let Some(base) = base
                    && let Some(version) = self.objects.get(&base)
                {
                    return Value::Word(Object::Memory(base, *version), high);
                }
            }
            if let Address::Frame(offset) = location {
                return self.stack.get(&offset).copied().unwrap_or_default();
            }
        }
        Value::Unknown
    }

    fn eval(&self, expr: &Expr, results: &mut HashSet<u64>) -> Value {
        match expr {
            Expr::Const(value) => Value::Constant(*value),
            Expr::Reg { index, .. } => self.register(*index),
            Expr::Load { addr, width, .. } => {
                let address = self.eval(addr, results);
                use_result(address, results);
                if *width == 8 {
                    return Value::Whole(Object::Load(self.serial));
                }
                self.load(address, *width)
            }
            Expr::Bin { op, lhs, rhs } => {
                let left = self.eval(lhs, results);
                let right = self.eval(rhs, results);
                match (op, left, right) {
                    (BinOp::And, Value::Whole(object), Value::Constant(0xffff_ffff)) => {
                        return Value::Word(object, false);
                    }
                    (BinOp::Shr, Value::Whole(object), Value::Constant(32)) => {
                        return Value::Word(object, true);
                    }
                    (
                        BinOp::And,
                        value @ (Value::Word(..) | Value::Frame(..)),
                        Value::Constant(0xffff_ffff),
                    ) => return value,
                    (BinOp::Add, Value::Frame(offset), Value::Constant(delta)) => {
                        return offset
                            .checked_add(delta as i64)
                            .map_or(Value::Unknown, Value::Frame);
                    }
                    (BinOp::Sub, Value::Frame(offset), Value::Constant(delta)) => {
                        return offset
                            .checked_sub(delta as i64)
                            .map_or(Value::Unknown, Value::Frame);
                    }
                    (_, Value::Constant(a), Value::Constant(b)) => {
                        return match op {
                            BinOp::Add => Value::Constant(a.wrapping_add(b)),
                            BinOp::Sub => Value::Constant(a.wrapping_sub(b)),
                            BinOp::And => Value::Constant(a & b),
                            _ => Value::Unknown,
                        };
                    }
                    _ => {}
                }
                use_result(left, results);
                use_result(right, results);
                Value::Unknown
            }
            Expr::SignExtend { value, .. } => {
                let value = self.eval(value, results);
                use_result(value, results);
                Value::Unknown
            }
            _ => Value::Unknown,
        }
    }

    fn store(&mut self, address: Value, value: Value, width: u8) {
        // A write invalidates snapshots of typed objects, including writes through unknown pointers.
        self.epoch += 1;
        for (object, version) in &mut self.objects {
            let overlap = match (*object, address) {
                (Address::Frame(base), Value::Frame(offset)) => {
                    base.checked_add(8).is_none_or(|end| offset < end)
                        && offset
                            .checked_add(i64::from(width))
                            .is_none_or(|end| base < end)
                }
                (Address::Absolute(base), Value::Constant(offset)) => {
                    base.checked_add(8).is_none_or(|end| offset < end)
                        && offset
                            .checked_add(u64::from(width))
                            .is_none_or(|end| base < end)
                }
                (_, Value::Unknown | Value::Word(..) | Value::Whole(..)) => true,
                _ => false,
            };
            if overlap {
                *version = self.epoch;
            }
        }
        let Value::Frame(offset) = address else {
            self.stack.clear();
            return;
        };
        let Some(end) = offset.checked_add(i64::from(width)) else {
            self.stack.clear();
            return;
        };
        self.stack.retain(|slot, _| {
            *slot >= end || slot.checked_add(4).is_some_and(|last| last <= offset)
        });
        if width == 4 {
            let value = match value {
                Value::Whole(object) => Value::Word(object, false),
                value => value,
            };
            self.stack.insert(offset, value);
        } else if width == 8
            && let Value::Whole(object) = value
        {
            self.stack.insert(offset, Value::Word(object, false));
            if let Some(high) = offset.checked_add(4) {
                self.stack.insert(high, Value::Word(object, true));
            }
        }
    }

    fn clobber(&mut self, convention: Convention) {
        for register in convention.clobbered() {
            self.registers.remove(register);
        }
        self.epoch += 1;
        for version in self.objects.values_mut() {
            *version = self.epoch;
        }
        self.stack.clear();
    }
}

fn use_result(value: Value, results: &mut HashSet<u64>) {
    if let Value::Word(Object::Result(target, _), true) = value {
        results.insert(target);
    }
}

fn pair(low: Value, high: Value) -> Option<Object> {
    match (low, high) {
        (Value::Word(a, false), Value::Word(b, true)) if a == b => Some(a),
        _ => None,
    }
}

pub(super) fn evidence(image: &Image, target: u64, depth: u8) -> Evidence {
    let Some(observed) = image
        .word_pairs
        .callers
        .get_or_init(|| collect(image))
        .get(&target)
    else {
        return Evidence::default();
    };
    let mut pairs = observed.pairs;
    let sources_by_word = observed.sources.iter().enumerate();
    for (word, sources) in sources_by_word {
        if pairs & (1 << word) == 0 {
            continue;
        }
        for source in sources {
            let ret = match super::declared_types(image, *source) {
                Some((_, ret)) => Some(ret),
                None if depth > 0 && *source != target => {
                    super::inference::declaration(image, *source, depth - 1)
                        .and_then(|declaration| declaration.ret)
                }
                None => None,
            };
            if !ret.as_ref().is_some_and(super::wide) {
                pairs &= !(1 << word);
                break;
            }
        }
    }
    Evidence {
        pairs,
        high_result: observed.high_result,
    }
}

fn collect(image: &Image) -> HashMap<u64, CallEvidence> {
    let mut calls = HashMap::<u64, CallEvidence>::new();
    let mut results = HashSet::new();
    let mut returned = HashMap::<u64, HashSet<u64>>::new();
    let mut observed = HashSet::new();
    let mut complete_image = true;
    for function in image.functions.values() {
        if function.sources.contains(&crate::loader::NameSource::Plt) {
            continue;
        }
        let Some(size) = function.size.filter(|size| *size > 0 && *size <= 0x20000) else {
            complete_image = false;
            continue;
        };
        let Ok(blocks) =
            super::super::lift_unpaired(image, function.addr, size, &HashSet::new(), &|_| {
                crate::loader::Summary::default()
            })
        else {
            complete_image = false;
            continue;
        };
        if blocks.is_empty()
            || blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                matches!(
                    stmt,
                    Stmt::Unsupported { .. }
                        | Stmt::Machine { .. }
                        | Stmt::BrIndirect { .. }
                        | Stmt::Br { target: None }
                )
            })
        {
            complete_image = false;
        }
        let mut entry = State::default();
        entry
            .registers
            .insert(crate::arch::stack_pointer(image.isa), Value::Frame(0));
        if let Some(types) = crate::loader::dwarf::function_types(image, function.addr) {
            for (address, ty, size) in types.globals {
                if size == 8 && super::wide(&ty) {
                    entry.objects.insert(Address::Absolute(address), 0);
                }
            }
            for local in types.locals {
                if local.size == 8 && super::wide(&local.ty) {
                    entry.objects.insert(Address::Frame(local.slot), 0);
                }
            }
        }
        if let Some((params, _)) = super::declared_types(image, function.addr)
            && matches!(
                image.convention_of(function.addr),
                Convention::Cdecl | Convention::Aapcs32
            )
            && let Some(locations) = super::locations(image.isa, &params)
        {
            for (location, wide) in locations {
                if !wide {
                    continue;
                }
                match location {
                    super::Location::Register(register) => {
                        entry
                            .registers
                            .insert(register, Value::Word(Object::Input(register), false));
                        entry
                            .registers
                            .insert(register + 1, Value::Word(Object::Input(register), true));
                    }
                    super::Location::Stack(offset) => {
                        entry.objects.insert(Address::Frame(offset), 0);
                    }
                }
            }
        }
        // Only a complete straight-line body authorizes parameter changes. Branches can hide
        // another call or a store between the two loads.
        let complete = blocks.len() == 1
            && blocks
                .first()
                .is_some_and(|block| matches!(block.stmts.last(), Some(Stmt::Ret { .. })))
            && !blocks[0].stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    Stmt::Unsupported { .. } | Stmt::Machine { .. } | Stmt::BrIndirect { .. }
                )
            });
        let examined = blocks.iter().take(if complete { 1 } else { blocks.len() });
        for block in examined {
            let mut state = entry.clone();
            for stmt in &block.stmts {
                state.serial += 1;
                match stmt {
                    Stmt::Assign { dest, value } => {
                        let value = state.eval(value, &mut results);
                        use_result(value, &mut results);
                        state.registers.insert(dest.index, value);
                    }
                    Stmt::Store { addr, value, width } => {
                        let address = state.eval(addr, &mut results);
                        let value = state.eval(value, &mut results);
                        use_result(value, &mut results);
                        state.store(address, value, *width);
                    }
                    Stmt::Call {
                        target,
                        kind,
                        convention,
                        ..
                    } => {
                        let Some(target) = target else {
                            state = State::default();
                            continue;
                        };
                        observed.insert((function.addr, *target));
                        let mut pairs = 0;
                        let mut sources = Vec::new();
                        if complete && matches!(convention, Convention::Cdecl | Convention::Aapcs32)
                        {
                            for word in 0..16u16 {
                                let read = |word: u16| {
                                    if image.isa == Isa::Arm32 && word < 4 {
                                        return state.register(word);
                                    }
                                    let offset = if image.isa == Isa::I386 {
                                        i64::from(word) * 4 + 4
                                    } else {
                                        i64::from(word - 4) * 4
                                    };
                                    let Some(offset) =
                                        kind.stack_offset(image.isa, *convention, offset)
                                    else {
                                        return Value::Unknown;
                                    };
                                    let Value::Frame(stack) =
                                        state.register(crate::arch::stack_pointer(image.isa))
                                    else {
                                        return Value::Unknown;
                                    };
                                    let Some(offset) = stack.checked_add(offset) else {
                                        return Value::Unknown;
                                    };
                                    state.load(Value::Frame(offset), 4)
                                };
                                if (image.isa != Isa::Arm32 || word % 2 == 0)
                                    && let Some(object) = pair(read(word), read(word + 1))
                                {
                                    pairs |= 1 << word;
                                    if let Object::Result(source, _) = object {
                                        sources.push((word, source));
                                    }
                                }
                            }
                        }
                        calls
                            .entry(*target)
                            .and_modify(|evidence| evidence.pairs &= pairs)
                            .or_insert(CallEvidence {
                                pairs,
                                ..CallEvidence::default()
                            });
                        for (word, source) in sources {
                            calls.get_mut(target).expect("call was inserted").sources
                                [usize::from(word)]
                            .push(source);
                        }
                        state.clobber(*convention);
                        let object = Object::Result(*target, state.serial);
                        state.registers.insert(0, Value::Word(object, false));
                        if super::declared_types(image, *target)
                            .is_none_or(|(_, ret)| super::wide(&ret))
                        {
                            state.registers.insert(
                                if image.isa == Isa::I386 { 2 } else { 1 },
                                Value::Word(object, true),
                            );
                        }
                    }
                    Stmt::Ret { .. } => {
                        if let Value::Word(Object::Result(target, _), true) =
                            state.register(if image.isa == Isa::I386 { 2 } else { 1 })
                        {
                            returned.entry(function.addr).or_default().insert(target);
                            if super::declared_types(image, function.addr)
                                .is_some_and(|(_, ret)| super::wide(&ret))
                            {
                                results.insert(target);
                            }
                        }
                    }
                    Stmt::Unsupported { .. } | Stmt::Machine { .. } => {
                        state = State::default();
                    }
                    other => {
                        for operand in other.operands() {
                            state.eval(operand, &mut results);
                        }
                        for register in crate::ir::visit::statement_registers(other).0 {
                            state.registers.remove(&register);
                        }
                    }
                }
            }
        }
    }
    loop {
        let mut changed = false;
        for (caller, targets) in &returned {
            if results.contains(caller) {
                for target in targets {
                    changed |= results.insert(*target);
                }
            }
        }
        if !changed {
            break;
        }
    }
    for (target, evidence) in &mut calls {
        evidence.high_result = results.contains(target);
        let callers = crate::analysis::results::callers(image, *target);
        let unowned = image
            .branches_to
            .get()
            .and_then(|index| index.get(target))
            .is_some_and(|sites| {
                sites.iter().any(|site| {
                    let Some((start, function)) = image.functions.range(..=*site).next_back()
                    else {
                        return true;
                    };
                    function
                        .size
                        .is_none_or(|size| size == 0 || *site >= start.saturating_add(size))
                })
            });
        if (image.isa == Isa::Arm32 && !complete_image)
            || unowned
            || callers
                .iter()
                .any(|caller| !observed.contains(&(*caller, *target)))
        {
            evidence.pairs = 0;
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_untyped_words_do_not_prove_an_object() {
        let mut state = State::default();
        state.stack.insert(4, Value::Constant(17));
        state.stack.insert(8, Value::Constant(23));
        assert_eq!(
            pair(
                state.load(Value::Frame(4), 4),
                state.load(Value::Frame(8), 4)
            ),
            None
        );
    }

    #[test]
    fn object_halves_must_be_read_without_an_overlapping_write() {
        let mut state = State::default();
        state.objects.insert(Address::Frame(4), 0);
        let low = state.load(Value::Frame(4), 4);
        state.store(Value::Frame(-16), Value::Constant(3), 4);
        let high = state.load(Value::Frame(8), 4);
        assert!(pair(low, high).is_some());
        for (offset, width) in [(4, 1), (7, 2), (8, 4), (0, 8)] {
            let mut changed = state.clone();
            changed.store(Value::Frame(offset), Value::Constant(3), width);
            assert_eq!(pair(low, changed.load(Value::Frame(8), 4)), None);
        }
        state.store(Value::Unknown, Value::Constant(3), 4);
        assert_eq!(pair(low, state.load(Value::Frame(8), 4)), None);
    }

    #[test]
    fn copied_words_keep_their_original_object_and_order() {
        let mut state = State::default();
        state.store(Value::Frame(-16), Value::Whole(Object::Load(1)), 8);
        let low = state.load(Value::Frame(-16), 4);
        let high = state.load(Value::Frame(-12), 4);
        assert!(pair(low, high).is_some());
        assert_eq!(pair(high, low), None);
        assert_eq!(pair(low, Value::Word(Object::Load(2), true)), None);
        state.store(Value::Frame(-13), Value::Constant(3), 1);
        assert_eq!(pair(state.load(Value::Frame(-16), 4), high), None);
    }

    #[test]
    fn calls_invalidate_vector_values_and_keep_saved_registers() {
        let mut state = State::default();
        let value = Value::Whole(Object::Load(1));
        state.registers.insert(18, value);
        state.registers.insert(3, value);
        state.clobber(Convention::Cdecl);
        assert_eq!(state.register(18), Value::Unknown);
        assert_eq!(state.register(3), value);
        state.registers.insert(64, value);
        state.registers.insert(72, value);
        state.clobber(Convention::Aapcs32);
        assert_eq!(state.register(64), Value::Unknown);
        assert_eq!(state.register(72), value);
    }
}
