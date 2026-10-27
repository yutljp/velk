//! Word pairs established by carry arithmetic and compiler-runtime arguments.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Mutex, OnceLock};

use crate::ir::{BinOp, CType, Cond, Expr, Stmt};
use crate::loader::{Image, Isa};

#[derive(Clone)]
pub(super) struct Declaration {
    params: Vec<CType>,
    pub(super) ret: Option<CType>,
}

impl fmt::Debug for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Preserve the tuple formatting exposed by Image's debug output.
        fmt::Debug::fmt(&(&self.params, &self.ret), f)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Cache {
    types: Mutex<HashMap<(u64, u64, u8), Option<Declaration>>>,
    pub(super) callers: OnceLock<HashMap<u64, super::callers::CallEvidence>>,
}

pub(super) fn types(image: &Image, address: u64) -> Option<(Vec<CType>, CType)> {
    let Some(Declaration { params, ret }) = declaration(image, address, 2) else {
        return None;
    };
    ret.map(|ret| (params, ret))
}

pub(crate) fn parameters(image: &Image, address: u64) -> Option<Vec<CType>> {
    declaration(image, address, 2).map(|declaration| declaration.params)
}

pub(super) fn declaration(image: &Image, address: u64, depth: u8) -> Option<Declaration> {
    if !matches!(image.isa, Isa::I386 | Isa::Arm32) || image.go {
        return None;
    }
    let Some(function) = image.functions.get(&address) else {
        return None;
    };
    if function.sources.contains(&crate::loader::NameSource::Plt) {
        return None;
    }
    let Some(size) = function.size else {
        return None;
    };
    // An incomplete or unsupported declaration does not authorize a different scalar ABI.
    if crate::loader::dwarf::function_types(image, address).is_some() {
        return None;
    }
    if size > 0x20000
        || !matches!(
            image.convention_of(address),
            crate::ir::Convention::Cdecl | crate::ir::Convention::Aapcs32
        )
    {
        return None;
    }
    let key = (address, size, depth);
    if let Some(types) = image
        .word_pairs
        .types
        .lock()
        .expect("word-pair cache lock")
        .get(&key)
    {
        return types.clone();
    }
    let inferred = infer(image, address, size, depth);
    image
        .word_pairs
        .types
        .lock()
        .expect("word-pair cache lock")
        .insert(key, inferred.clone());
    inferred
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Value {
    inputs: u64,
    word: Option<u32>,
    wide_words: Option<u32>,
    products: u64,
    high_products: u64,
    left_shifts: u64,
    right_shifts: u64,
    count_inputs: u64,
    shift: Option<u64>,
    constant: Option<u64>,
    frame: Option<i64>,
    known: bool,
    known_bits: u64,
    boolean: bool,
    carry: bool,
    high: bool,
    narrow: bool,
}

impl Value {
    fn constant(value: u64) -> Self {
        Self {
            constant: Some(value),
            known: true,
            boolean: value <= 1,
            ..Self::default()
        }
    }

    fn input(index: u32) -> Self {
        Self {
            inputs: 1u64 << index,
            word: Some(index),
            known: true,
            ..Self::default()
        }
    }

    fn bits(self) -> u64 {
        if self.known {
            u64::MAX
        } else {
            self.known_bits
        }
    }

    fn merge(self, other: Self) -> Self {
        Self {
            inputs: self.inputs | other.inputs,
            products: self.products | other.products,
            high_products: self.high_products | other.high_products,
            left_shifts: self.left_shifts | other.left_shifts,
            right_shifts: self.right_shifts | other.right_shifts,
            count_inputs: self.count_inputs | other.count_inputs,
            shift: self.shift.filter(|shift| Some(*shift) == other.shift),
            word: self.word.filter(|word| Some(*word) == other.word),
            wide_words: self
                .wide_words
                .filter(|word| Some(*word) == other.wide_words),
            constant: self.constant.filter(|value| Some(*value) == other.constant),
            frame: self.frame.filter(|value| Some(*value) == other.frame),
            known: self.known && other.known,
            known_bits: self.bits() & other.bits(),
            boolean: self.boolean && other.boolean,
            carry: self.carry && other.carry,
            high: self.high && other.high,
            narrow: self.narrow && other.narrow,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    registers: HashMap<u16, Value>,
    stack: HashMap<i64, Value>,
    expressions: Vec<(u16, Expr)>,
    unknown_stack: bool,
}

impl State {
    fn invalidate_call_registers(&mut self, convention: crate::ir::Convention) {
        for register in convention.clobbered() {
            self.registers.remove(register);
        }
    }
}

#[derive(Clone)]
struct Condition {
    cond: Cond,
    lhs: Expr,
    rhs: Expr,
    taken: bool,
}

struct CallEffects {
    partial: bool,
    narrow: bool,
}

struct Evidence {
    isa: Isa,
    used: u64,
    reads: u64,
    pairs: u64,
    parameter_pairs: u64,
}

impl Evidence {
    fn pair(&mut self, low: Value, high: Value) -> u64 {
        if low.known && high.known && (high.high || low.inputs & high.inputs == 0) {
            let pairs = low.inputs & (high.inputs >> 1) & !(low.inputs >> 1);
            let aligned = if self.isa == Isa::Arm32 {
                0x5555_5555_5555_5555
            } else {
                u64::MAX
            };
            let proven = pairs & aligned;
            self.pairs |= proven;
            return proven;
        }
        0
    }

    fn eval(&mut self, expr: &Expr, state: &State) -> Value {
        let value = match expr {
            Expr::Const(value) => Value::constant(*value),
            Expr::Reg { index, .. } => state.registers.get(index).copied().unwrap_or_default(),
            Expr::Load { addr, width: 8, .. } => {
                let load = |address| Expr::Load {
                    addr: Box::new(address),
                    width: 4,
                    signed: false,
                };
                let low = self.eval(&load(*addr.clone()), state);
                let high = self.eval(
                    &load(Expr::bin(BinOp::Add, *addr.clone(), Expr::constant(4))),
                    state,
                );
                Value {
                    inputs: low.inputs | high.inputs,
                    known: low.known && high.known,
                    wide_words: low.word.filter(|word| high.word == Some(word + 1)),
                    ..Value::default()
                }
            }
            Expr::Load { addr, width, .. } if matches!(width, 1 | 2 | 4) => {
                let address = self.eval(addr, state);
                let Some(offset) = address.frame else {
                    return Value {
                        known: address.constant.is_some(),
                        ..Value::default()
                    };
                };
                if let Some(value) = state.stack.get(&offset) {
                    let mut value = *value;
                    if *width != 4 {
                        let mask = (1u64 << (u32::from(*width) * 8)) - 1;
                        value.known = value.bits() & mask == mask;
                        value.word = None;
                        value.frame = None;
                        value.constant = value.constant.map(|constant| constant & mask);
                    }
                    value
                } else if let Some(value) = state.stack.get(&(offset & !3)).filter(|_| *width != 4)
                {
                    let shift = (offset & 3) as u32 * 8;
                    if shift + u32::from(*width) * 8 > 32 {
                        return Value::default();
                    }
                    let value = *value;
                    let mask = ((1u64 << (u32::from(*width) * 8)) - 1) << shift;
                    Value {
                        inputs: value.inputs,
                        known: value.bits() & mask == mask,
                        ..Value::default()
                    }
                } else {
                    if state.unknown_stack {
                        return Value::default();
                    }
                    let first = if self.isa == Isa::I386 { 4 } else { 0 };
                    let registers = if self.isa == Isa::I386 { 0 } else { 4 };
                    if offset < first || offset - first >= 128 {
                        return Value::default();
                    }
                    {
                        let mut value = Value::input(((offset - first) / 4 + registers) as u32);
                        if *width != 4 || (offset - first) % 4 != 0 {
                            value.word = None;
                        }
                        value
                    }
                }
            }
            Expr::Bin { op, lhs, rhs } => {
                let left = self.eval(lhs, state);
                let right = self.eval(rhs, state);
                self.binary(op, left, right)
            }
            Expr::Select {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                let a = self.eval(lhs, state);
                let b = self.eval(rhs, state);
                let yes = self.eval(then, state);
                let no = self.eval(els, state);
                let mut value = yes.merge(no);
                value.inputs |= a.inputs | b.inputs;

                value.known &= a.known && b.known;
                value
            }
            Expr::SignExtend { value, .. } => self.eval(value, state),
            _ => Value::default(),
        };
        self.reads |= value.inputs;
        value
    }

    fn call(
        &mut self,
        image: &Image,
        stmt: &Stmt,
        state: &mut State,
        depth: u8,
    ) -> Option<CallEffects> {
        let Stmt::Call {
            target,
            kind,
            convention,
            ..
        } = stmt
        else {
            return None;
        };
        let declared = target
            .and_then(|target| super::declared_types(image, target))
            .map(|(params, ret)| Declaration {
                params,
                ret: Some(ret),
            })
            .or_else(|| {
                if depth == 0 {
                    None
                } else {
                    target.and_then(|target| declaration(image, target, depth - 1))
                }
            });
        let Some(Declaration { params, ret }) = declared else {
            state.invalidate_call_registers(*convention);
            return Some(CallEffects {
                partial: true,
                narrow: false,
            });
        };
        let Some(locations) = super::locations(image.isa, &params) else {
            return None;
        };
        let narrow = ret
            .as_ref()
            .is_some_and(|ret| ret.integer().is_some() && !super::wide(ret))
            && params.iter().all(|ty| ty.integer().is_some());
        let mut inputs = 0;
        for (location, pair) in locations {
            let (low, high) = match location {
                super::Location::Register(register) => (
                    state.registers.get(&register).copied().unwrap_or_default(),
                    state
                        .registers
                        .get(&(register + 1))
                        .copied()
                        .unwrap_or_default(),
                ),
                super::Location::Stack(offset) => {
                    let Some(offset) = kind.stack_offset(image.isa, *convention, offset) else {
                        return None;
                    };
                    (
                        self.eval(&super::stack_word(image.isa, offset), state),
                        self.eval(
                            &super::stack_word(
                                image.isa,
                                match offset.checked_add(4) {
                                    Some(high) => high,
                                    None => return None,
                                },
                            ),
                            state,
                        ),
                    )
                }
            };
            inputs |= low.inputs;
            if pair {
                let proven = self.pair(low, high);
                self.parameter_pairs |= proven;
                inputs |= high.inputs;
            }
        }
        self.used |= inputs;
        state.invalidate_call_registers(*convention);
        state.registers.insert(
            0,
            Value {
                inputs,
                known: true,
                ..Value::default()
            },
        );
        if ret.as_ref().is_some_and(super::wide) {
            state.registers.insert(
                if image.isa == Isa::I386 { 2 } else { 1 },
                Value {
                    inputs,
                    known: true,
                    high: true,
                    ..Value::default()
                },
            );
        }
        if ret.as_ref().is_some_and(|ret| !super::wide(ret))
            && let Some(value) = state.registers.get_mut(&0)
        {
            value.narrow = true;
        }
        let runtime = runtime_result(image, *target);
        if runtime == Some(RuntimeResult::WordRemainder) {
            state.registers.insert(
                1,
                Value {
                    inputs,
                    known: true,
                    narrow: true,
                    ..Value::default()
                },
            );
        }
        if ret.is_none() {
            state.registers.remove(&0);
        }
        if runtime == Some(RuntimeResult::WideRemainder) {
            state.registers.insert(
                2,
                Value {
                    inputs,
                    known: true,
                    ..Value::default()
                },
            );
            state.registers.insert(
                3,
                Value {
                    inputs,
                    known: true,
                    high: true,
                    ..Value::default()
                },
            );
        }
        Some(CallEffects {
            partial: ret.is_none(),
            narrow,
        })
    }

    fn binary(&mut self, op: &BinOp, left: Value, right: Value) -> Value {
        let constant = match (left.constant, right.constant) {
            (Some(a), Some(b)) => match op {
                BinOp::Add => Some(a.wrapping_add(b)),
                BinOp::Sub => Some(a.wrapping_sub(b)),
                BinOp::And => Some(a & b),
                BinOp::Or => Some(a | b),
                BinOp::Xor => Some(a ^ b),
                BinOp::Shl if b < 64 => Some(a << b),
                BinOp::Shr if b < 64 => Some(a >> b),
                _ => None,
            },
            _ => None,
        };
        let frame = match op {
            BinOp::Add => left
                .frame
                .and_then(|offset| {
                    right
                        .constant
                        .and_then(|delta| offset.checked_add(delta as i64))
                })
                .or_else(|| {
                    right.frame.and_then(|offset| {
                        left.constant
                            .and_then(|delta| offset.checked_add(delta as i64))
                    })
                }),
            BinOp::Sub => left.frame.and_then(|offset| {
                right
                    .constant
                    .and_then(|delta| offset.checked_sub(delta as i64))
            }),
            BinOp::And if right.constant == Some(0xffff_ffff) => left.frame,
            _ => None,
        };
        let known_bits = match op {
            BinOp::And => match (left.constant, right.constant) {
                (_, Some(mask)) => left.bits() | !mask,
                (Some(mask), _) => right.bits() | !mask,
                _ => left.bits() & right.bits(),
            },
            BinOp::Or => match (left.constant, right.constant) {
                (_, Some(mask)) => left.bits() | mask,
                (Some(mask), _) => right.bits() | mask,
                _ => left.bits() & right.bits(),
            },
            _ if left.known && right.known => u64::MAX,
            _ => 0,
        };
        let carry = matches!(op, BinOp::Add | BinOp::Sub) && right.carry;
        if carry {
            self.pair(right, left);
        }
        let mut products = 0;
        let mut high_products = 0;
        let mut multiplication = false;
        if *op == BinOp::Mul
            && let (Some(a), Some(b)) = (left.word, right.word)
            && a < 8
            && b < 8
        {
            products = 1 << (a.min(b) * 8 + a.max(b));
        } else if matches!(op, BinOp::Add | BinOp::Or | BinOp::And | BinOp::Shr) {
            products = left.products | right.products;
            high_products = left.high_products | right.high_products;
            if *op == BinOp::Shr && right.constant == Some(32) {
                high_products |= left.products;
            }
            if *op == BinOp::Add {
                for a in 0..8u32 {
                    for b in a..8 {
                        if high_products & (1 << (a * 8 + b)) == 0 {
                            continue;
                        }
                        for (low, other) in [(a, b), (b, a)] {
                            if low < 7
                                && products
                                    & (1 << ((low + 1).min(other) * 8 + (low + 1).max(other)))
                                    != 0
                            {
                                self.pair(Value::input(low), Value::input(low + 1));
                                multiplication = true;
                            }
                        }
                    }
                }
            }
        }
        let shifted_word = left.word.map_or(0, |word| 1 << word);
        let (left_shifts, right_shifts, count_inputs, shift) = match op {
            BinOp::Shl => (shifted_word, 0, right.inputs, right.constant),
            BinOp::Shr | BinOp::Sar => (0, shifted_word, right.inputs, right.constant),
            BinOp::Or => (
                left.left_shifts | right.left_shifts,
                left.right_shifts | right.right_shifts,
                left.count_inputs | right.count_inputs,
                None,
            ),
            BinOp::And if right.constant == Some(0xffff_ffff) => (
                left.left_shifts,
                left.right_shifts,
                left.count_inputs,
                left.shift,
            ),
            _ => (0, 0, 0, None),
        };
        let funnel = *op == BinOp::Or
            && ((left.count_inputs != 0 && left.count_inputs == right.count_inputs)
                || left
                    .shift
                    .zip(right.shift)
                    .is_some_and(|(a, b)| a.checked_add(b) == Some(32)));
        if funnel {
            let pairs = (left_shifts & (right_shifts >> 1)) | (right_shifts & (left_shifts >> 1));
            for word in 0..32 {
                if pairs & (1 << word) != 0 {
                    self.pair(Value::input(word), Value::input(word + 1));
                }
            }
        }
        Value {
            inputs: left.inputs | right.inputs,
            wide_words: None,
            products,
            high_products,
            left_shifts,
            right_shifts,
            count_inputs,
            shift,
            word: if *op == BinOp::And && right.constant == Some(0xffff_ffff) {
                left.word
            } else {
                None
            },
            constant,
            frame,
            known: known_bits == u64::MAX,
            known_bits,
            carry: left.carry && right.constant.is_some() && matches!(op, BinOp::And | BinOp::Xor),
            boolean: constant.is_some_and(|value| value <= 1)
                || (*op == BinOp::And && (left.constant == Some(1) || right.constant == Some(1)))
                || (matches!(op, BinOp::And | BinOp::Or | BinOp::Xor)
                    && left.boolean
                    && right.boolean),
            narrow: left.narrow
                && right.constant.is_some()
                && matches!(op, BinOp::And | BinOp::Xor | BinOp::Or),
            high: carry
                || (*op == BinOp::Add && (left.high || right.high))
                || multiplication
                || funnel
                || (right.constant.is_some() && left.high)
                || (left.constant.is_some() && right.high),
        }
    }
}

fn infer(image: &Image, address: u64, size: u64, depth: u8) -> Option<Declaration> {
    let Ok(blocks) = crate::lift::lift_unpaired(image, address, size, &HashSet::new(), &|_| {
        crate::loader::Summary::default()
    }) else {
        return None;
    };
    if blocks.is_empty()
        || blocks.len() > 2048
        || blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            matches!(
                stmt,
                Stmt::Unsupported { .. }
                    | Stmt::Machine { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Br { target: None }
                    | Stmt::BrifFlags { .. }
            )
        })
    {
        return None;
    }
    let mut evidence = Evidence {
        isa: image.isa,
        used: 0,
        reads: 0,
        pairs: 0,
        parameter_pairs: 0,
    };
    let mut entry = State::default();
    entry.registers.insert(
        crate::arch::stack_pointer(image.isa),
        Value {
            frame: Some(0),
            known: true,
            ..Value::default()
        },
    );
    if image.isa == Isa::Arm32 {
        for index in 0..4 {
            entry
                .registers
                .insert(index, Value::input(u32::from(index)));
        }
    }
    let mut pending = vec![(0, entry, HashSet::new(), Vec::<Condition>::new())];
    let mut returns = Vec::new();
    let mut visited = 0;
    let mut narrow_call = false;
    let mut partial = blocks.len() > 64;
    let mut seen = HashSet::new();
    while let Some((index, mut state, mut path, mut conditions)) = pending.pop() {
        visited += 1;
        if visited > 4096 {
            partial = true;
            break;
        }
        if !path.insert(index) {
            partial = true;
            continue;
        }
        if blocks.len() > 64 && !seen.insert(index) {
            continue;
        }
        let block = &blocks[index];
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { dest, value } => {
                    let expression =
                        crate::ir::visit::substitute_values(value.clone(), &state.expressions);
                    state.expressions.retain(|(register, expression)| {
                        *register != dest.index
                            && crate::ir::visit::count_register(expression, dest.index) == 0
                    });
                    let mut pending = vec![&expression];
                    let mut count = 0;
                    while let Some(expr) = pending.pop() {
                        count += 1;
                        if count > 64 {
                            break;
                        }
                        pending.extend(crate::ir::visit::children(expr));
                    }
                    if count <= 64 && crate::ir::visit::count_register(&expression, dest.index) == 0
                    {
                        state.expressions.push((dest.index, expression));
                    }
                    conditions.retain(|condition| {
                        crate::ir::visit::count_register(&condition.lhs, dest.index) == 0
                            && crate::ir::visit::count_register(&condition.rhs, dest.index) == 0
                    });
                    let mut value = evidence.eval(value, &state);
                    if dest.index == crate::ir::EXCHANGE && value.boolean {
                        value.carry = true;
                    }
                    state.registers.insert(dest.index, value);
                }
                Stmt::Store {
                    addr,
                    value,
                    width: 8,
                } => {
                    conditions.clear();
                    state.expressions.clear();
                    let address = evidence.eval(addr, &state);
                    let value = evidence.eval(value, &state);
                    if let Some(offset) = address.frame {
                        let Some(high_offset) = offset.checked_add(4) else {
                            return None;
                        };
                        if let Some(word) = value.wide_words {
                            state.stack.insert(offset, Value::input(word));
                            state.stack.insert(high_offset, Value::input(word + 1));
                        } else {
                            state.stack.insert(offset, value);
                            state.stack.insert(high_offset, value);
                        }
                    } else {
                        evidence.used |= address.inputs | value.inputs;
                    }
                }
                Stmt::Store {
                    addr,
                    value,
                    width: 4,
                } => {
                    conditions.clear();
                    state.expressions.clear();
                    let address = evidence.eval(addr, &state);
                    let value = evidence.eval(value, &state);
                    if let Some(offset) = address.frame {
                        state.stack.insert(offset, value);
                    } else {
                        evidence.used |= address.inputs | value.inputs;
                    }
                }
                Stmt::Store { addr, value, width } => {
                    if !matches!(width, 1 | 2) {
                        return None;
                    }
                    conditions.clear();
                    state.expressions.clear();
                    let address = evidence.eval(addr, &state);
                    let value = evidence.eval(value, &state);
                    evidence.used |= address.inputs | value.inputs;
                    let Some(offset) = address.frame else {
                        if address.constant.is_none() {
                            state.unknown_stack = true;
                            for value in state.stack.values_mut() {
                                *value = Value::default();
                            }
                        }
                        continue;
                    };
                    for byte in 0..*width {
                        let Some(address) = offset.checked_add(i64::from(byte)) else {
                            return None;
                        };
                        let slot = address & !3;
                        let stored = state.stack.get(&slot).copied().unwrap_or_default();
                        let shift = (address & 3) as u32 * 8;
                        let known = (value.bits() >> (u32::from(byte) * 8)) & 0xff;
                        let known_bits = (stored.bits() & !(0xff << shift)) | (known << shift);
                        state.stack.insert(
                            slot,
                            Value {
                                inputs: stored.inputs | value.inputs,
                                known: known_bits & 0xffff_ffff == 0xffff_ffff,
                                known_bits,
                                ..Value::default()
                            },
                        );
                    }
                }
                Stmt::Call { .. } => {
                    conditions.clear();
                    state.expressions.clear();
                    let Some(effects) = evidence.call(image, stmt, &mut state, depth) else {
                        return None;
                    };
                    partial |= effects.partial;
                    narrow_call |= effects.narrow;
                }
                Stmt::Ret { .. } => {
                    evidence.used |= state.registers.get(&0).copied().unwrap_or_default().inputs;
                    returns.push((
                        state.registers.get(&0).copied().unwrap_or_default(),
                        state
                            .registers
                            .get(&(if image.isa == Isa::I386 { 2 } else { 1 }))
                            .copied()
                            .unwrap_or_default(),
                    ));
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    let a = evidence.eval(lhs, &state);
                    let b = evidence.eval(rhs, &state);
                    evidence.used |= a.inputs | b.inputs;
                }
                _ => {}
            }
        }
        for next in crate::ir::cfg::block_successors(&blocks, index) {
            let mut next_conditions = conditions.clone();
            if let Some(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) = block.stmts.last()
                && blocks
                    .get(index + 1)
                    .is_none_or(|block| block.start != *target)
            {
                let taken = blocks[next].start == *target;
                let lhs = crate::ir::visit::substitute_values(lhs.clone(), &state.expressions);
                let rhs = crate::ir::visit::substitute_values(rhs.clone(), &state.expressions);
                let contradicts = conditions.iter().any(|condition| {
                    condition.lhs == lhs
                        && condition.rhs == rhs
                        && ((*cond == condition.cond && taken != condition.taken)
                            || (*cond == condition.cond.invert() && taken == condition.taken))
                });
                if contradicts {
                    continue;
                }
                next_conditions.push(Condition {
                    cond: *cond,
                    lhs,
                    rhs,
                    taken,
                });
            }
            pending.push((next, state.clone(), path.clone(), next_conditions));
        }
    }
    if evidence.reads >> 16 != 0 || evidence.pairs & (evidence.pairs << 1) != 0 {
        return None;
    }
    let mut caller_evidence = super::callers::evidence(image, address, depth);
    let words_read = 64 - evidence.reads.leading_zeros();
    let candidates = if words_read == 0 {
        0
    } else {
        (1u64 << words_read) - 1
    };
    caller_evidence.pairs &= candidates & 0x7fff;
    evidence.pairs |= caller_evidence.pairs;
    evidence.parameter_pairs |= caller_evidence.pairs;
    evidence.used |= caller_evidence.pairs | (caller_evidence.pairs << 1);
    if evidence.pairs & (evidence.pairs << 1) != 0 {
        return None;
    }
    let changes_high =
        image.isa != Isa::Arm32 || returns.iter().any(|(_, high)| high.word != Some(1));
    let ret = if !partial
        && !returns.is_empty()
        && caller_evidence.high_result
        && changes_high
        && returns.iter().all(|(low, high)| low.known && high.known)
    {
        for (_, high) in &returns {
            evidence.used |= high.inputs;
        }
        Some(CType::U64)
    } else if !partial
        && !returns.is_empty()
        && evidence.pairs == 0
        && narrow_call
        && returns
            .iter()
            .all(|(low, high)| low.known && (!high.known || high.word.is_some() || high.narrow))
    {
        Some(CType::U32)
    } else {
        None
    };
    if ret.is_none() {
        evidence.pairs &= evidence.parameter_pairs;
        if evidence.pairs == 0 {
            return None;
        }
        let signature = crate::analysis::signature::recover_with(
            &blocks,
            &[],
            image.isa,
            image.convention_of(address),
            false,
            &|stmt| crate::analysis::prototypes::called(image, stmt),
        );
        let registers = if image.isa == Isa::I386 {
            0
        } else {
            signature.params.len()
        };
        let first = if image.isa == Isa::I386 { 4 } else { 0 };
        let stack = signature.stack.iter().max().map_or(0, |offset| {
            (offset.saturating_sub(first).max(0) / 4 + 1) as usize
        });
        let count = registers + stack;
        if count > 16 {
            return None;
        }
        evidence.used |= if count == 0 { 0 } else { (1 << count) - 1 };
        evidence.used |= evidence.reads;
    }
    let words = 64 - evidence.used.leading_zeros();
    let mut params = Vec::new();
    let mut index = 0;
    while index < words {
        if image.isa == Isa::Arm32
            && index % 2 == 1
            && evidence.reads & (1 << index) == 0
            && evidence.pairs & (1 << (index + 1)) != 0
        {
            index += 1;
            continue;
        }
        let wide = evidence.pairs & (1 << index) != 0;
        params.push(if wide { CType::U64 } else { CType::U32 });
        index += if wide { 2 } else { 1 };
    }
    Some(Declaration { params, ret })
}

#[derive(PartialEq)]
enum RuntimeResult {
    WordRemainder,
    WideRemainder,
}

fn runtime_result(image: &Image, target: Option<u64>) -> Option<RuntimeResult> {
    let name = target
        .and_then(|target| image.functions.get(&target))
        .and_then(|function| function.name.as_deref());
    match name {
        Some("__aeabi_idivmod" | "__aeabi_uidivmod") => Some(RuntimeResult::WordRemainder),
        Some("__aeabi_ldivmod" | "__aeabi_uldivmod") => Some(RuntimeResult::WideRemainder),
        _ => None,
    }
}
