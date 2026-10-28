//! Indirect calls whose callee the binary fixes. A forward pass over the
//! lifted blocks follows what each register and each word of memory the
//! function stores holds: a constant, or an unknown value plus an offset,
//! named for where it came from. A call whose address comes out as a known
//! function's becomes a direct call to it, so the callee's summary gives
//! the arguments, and keeps the table it read in a comment. One that loads
//! the address from a slot of the table the object starts with is marked
//! with the slot, and the functions the C++ tables hold there.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::ir::{BinOp, Block, Convention, Expr, Stmt, Table, Via};
use crate::loader::Image;

/// Where an unknown value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Base {
    /// A register as the function received it.
    Entry(u16),
    /// A register on entry to a block whose predecessors leave different
    /// values in it.
    Join(u32, u16),
    /// What a statement loads, by block, statement and which of its
    /// loads, or what a call returns.
    Def(u32, u32, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Value {
    Unknown,
    /// A constant, with the table and offset it was read from when
    /// constant data holds it.
    Const(u64, Option<(u64, u64)>),
    Sym(Base, u64),
    /// The function an import's slot holds, by the slot.
    Import(u64),
}

impl Value {
    /// The address as a key, whatever it was read from.
    fn key(self) -> Value {
        match self {
            Value::Const(value, _) => Value::Const(value, None),
            other => other,
        }
    }
}

/// What the registers the state does not list hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rest {
    Entry,
    Join(u32),
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
struct State {
    regs: BTreeMap<u16, Value>,
    rest: Rest,
    /// The words the function stored, by address and width in bytes.
    memory: BTreeMap<(Value, u8), Value>,
}

impl State {
    fn entry() -> Self {
        State {
            regs: BTreeMap::new(),
            rest: Rest::Entry,
            memory: BTreeMap::new(),
        }
    }

    fn reg(&self, index: u16) -> Value {
        if let Some(value) = self.regs.get(&index) {
            return *value;
        }
        match self.rest {
            Rest::Entry => Value::Sym(Base::Entry(index), 0),
            Rest::Join(block) => Value::Sym(Base::Join(block, index), 0),
            Rest::Unknown => Value::Unknown,
        }
    }

    /// The state on entry to `block` from two predecessors: what both
    /// leave the same, and a name of its own for each register they do not.
    fn meet(&self, other: &State, block: u32) -> State {
        let rest = match (self.rest, other.rest) {
            (a, b) if a == b && a != Rest::Unknown => a,
            _ => Rest::Join(block),
        };
        let mut merged = State {
            regs: BTreeMap::new(),
            rest,
            memory: BTreeMap::new(),
        };
        let indices: BTreeSet<u16> = self.regs.keys().chain(other.regs.keys()).copied().collect();
        for index in indices {
            let value = match (self.reg(index), other.reg(index)) {
                (Value::Const(a, from_a), Value::Const(b, from_b)) if a == b => {
                    Value::Const(a, if from_a == from_b { from_a } else { None })
                }
                (a, b) if a == b && a != Value::Unknown => a,
                _ => Value::Sym(Base::Join(block, index), 0),
            };
            if value != merged.reg(index) {
                merged.regs.insert(index, value);
            }
        }
        for (key, value) in &self.memory {
            if other.memory.get(key) == Some(value) {
                merged.memory.insert(*key, *value);
            }
        }
        merged
    }
}

/// What the pass decides for one call.
enum Decision {
    Direct(u64, Via),
    /// A call to the import whose slot the address was loaded from.
    Import(u64),
    Slot(Via),
}

struct Tracker<'a> {
    image: &'a Image,
    sp: u16,
    /// The address each named load reads.
    loads: std::cell::RefCell<HashMap<Base, Value>>,
    /// Calls to constructors leave their table in the object.
    constructors: bool,
    returns: Option<std::cell::RefCell<HashMap<u64, Option<u64>>>>,
}

impl Tracker<'_> {
    fn pointer_value(&self, value: Value) -> Value {
        if crate::arch::pointer_bytes(self.image.isa) != 4 {
            return value;
        }
        match value {
            Value::Const(value, from) => Value::Const(u64::from(value as u32), from),
            Value::Sym(base, offset) => Value::Sym(base, u64::from(offset as u32)),
            other => other,
        }
    }

    fn returned(&self, target: u64, convention: Convention) -> Option<u64> {
        let Some(returns) = self.returns.as_ref() else {
            return None;
        };
        if self.image.convention_of(target) != convention {
            return None;
        }
        if let Some(known) = returns.borrow().get(&target) {
            return *known;
        }
        let found = returned_by(self.image, target);
        returns.borrow_mut().insert(target, found);
        found
    }

    /// Whether a value is the address of a table of code, which the C++
    /// object model lets no call or store through another pointer change
    /// once the object holds it.
    fn durable(&self, value: &Value) -> bool {
        matches!(value, Value::Const(table, _)
            if read_only_word(self.image, *table)
                .is_some_and(|word| self.image.functions.contains_key(&word)))
    }

    fn on_stack(&self, value: Value) -> bool {
        matches!(value, Value::Sym(Base::Entry(index), _) if index == self.sp)
    }

    /// Whether a store of `width` bytes at `addr` may change the stored
    /// `stored_width` bytes at `stored`.
    fn may_alias(&self, stored: Value, stored_width: u8, addr: Value, width: u8) -> bool {
        let overlap = |a: u64, b: u64| {
            let distance = if crate::arch::pointer_bytes(self.image.isa) == 4 {
                i64::from((a as u32).wrapping_sub(b as u32) as i32)
            } else {
                a.wrapping_sub(b) as i64
            };
            distance < i64::from(width) && distance > -i64::from(stored_width)
        };
        match (stored, addr) {
            (Value::Sym(a, x), Value::Sym(b, y)) if a == b => overlap(x, y),
            (Value::Const(x, _), Value::Const(y, _)) => overlap(x, y),
            (_, Value::Unknown) => true,
            // The frame is the function's own: no pointer it was given
            // reaches it.
            (a, b) => self.on_stack(a) == self.on_stack(b),
        }
    }

    fn narrow(&self, value: Value, width: u8) -> Value {
        match (value, width) {
            (value, 64) => value,
            (Value::Const(value, _), width) => {
                Value::Const(value & crate::ir::semantics::mask(u32::from(width)), None)
            }
            (value @ Value::Sym(..), 32) if crate::arch::pointer_bytes(self.image.isa) == 4 => {
                self.pointer_value(value)
            }
            _ => Value::Unknown,
        }
    }

    fn eval(&self, state: &State, expr: &Expr, site: (u32, u32), loads: &mut u32) -> Value {
        match expr {
            Expr::Reg { index, width } => self.narrow(state.reg(*index), *width),
            Expr::Const(value) => Value::Const(*value, None),
            Expr::Bin { op, lhs, rhs } => {
                let a = self.eval(state, lhs, site, loads);
                let b = self.eval(state, rhs, site, loads);
                match (op, a, b) {
                    (BinOp::Add, Value::Sym(base, offset), Value::Const(value, _))
                    | (BinOp::Add, Value::Const(value, _), Value::Sym(base, offset)) => {
                        Value::Sym(base, offset.wrapping_add(value))
                    }
                    (BinOp::Sub, Value::Sym(base, offset), Value::Const(value, _)) => {
                        Value::Sym(base, offset.wrapping_sub(value))
                    }
                    (BinOp::And, value, Value::Const(0xffff_ffff, _))
                    | (BinOp::And, Value::Const(0xffff_ffff, _), value)
                        if crate::arch::pointer_bytes(self.image.isa) == 4 =>
                    {
                        self.pointer_value(value)
                    }
                    (_, Value::Const(a, _), Value::Const(b, _)) => {
                        match Expr::bin(*op, Expr::Const(a), Expr::Const(b)) {
                            Expr::Const(value) => Value::Const(value, None),
                            _ => Value::Unknown,
                        }
                    }
                    _ => Value::Unknown,
                }
            }
            Expr::Load { addr, width, .. } => {
                let (table, offset) = match addr.as_ref() {
                    Expr::Bin {
                        op: BinOp::Add,
                        lhs,
                        rhs,
                    } if let Expr::Const(offset) = rhs.as_ref() => {
                        (self.eval(state, lhs, site, loads), *offset)
                    }
                    other => (self.eval(state, other, site, loads), 0),
                };
                let addr = self.pointer_value(match table {
                    Value::Const(table, _) => Value::Const(table.wrapping_add(offset), None),
                    Value::Sym(base, at) => Value::Sym(base, at.wrapping_add(offset)),
                    Value::Unknown | Value::Import(_) => Value::Unknown,
                });
                let name = Base::Def(site.0, site.1, *loads);
                *loads += 1;
                self.loads.borrow_mut().insert(name, addr);
                if *width == crate::arch::pointer_bytes(self.image.isa) {
                    if let Value::Const(slot, _) = addr
                        && self.image.imports.contains_key(&slot)
                        && self
                            .image
                            .import_addends
                            .get(&slot)
                            .is_none_or(|addend| *addend == 0)
                    {
                        return Value::Import(slot);
                    }
                    if let Some(value) = state.memory.get(&(addr.key(), *width)) {
                        return *value;
                    }
                    if let (Value::Const(at, _), Value::Const(table, _)) = (addr, table)
                        && let Some(word) = read_only_word(self.image, at)
                    {
                        return Value::Const(word, Some((table, offset)));
                    }
                }
                Value::Sym(name, 0)
            }
            _ => Value::Unknown,
        }
    }

    /// Keeps of memory what a store of `width` bytes at `addr` leaves as
    /// it was; with no address, what a call or an unmodeled instruction
    /// leaves.
    fn forget(&self, state: &mut State, addr: Option<(Value, u8)>) {
        state
            .memory
            .retain(|(stored, stored_width), value| match addr {
                Some((addr, width)) => {
                    let same_object = match (stored, addr) {
                        (Value::Sym(a, _), Value::Sym(b, _)) => *a == b,
                        (Value::Const(..), Value::Const(..)) => true,
                        _ => false,
                    };
                    !self.may_alias(*stored, *stored_width, addr, width)
                        || (!same_object && self.durable(value))
                }
                None => !self.on_stack(*stored) && self.durable(value),
            });
    }

    fn step(&self, state: &mut State, stmt: &Stmt, site: (u32, u32)) {
        let mut loads = 0;
        match stmt {
            Stmt::Machine {
                instruction,
                outputs,
                ..
            } => {
                if matches!(
                    instruction,
                    crate::ir::MachineInstruction::Atomic { .. }
                        | crate::ir::MachineInstruction::ArmBarrier { .. }
                        | crate::ir::MachineInstruction::ArmLoadAcquire { .. }
                        | crate::ir::MachineInstruction::ArmExclusive { .. }
                        | crate::ir::MachineInstruction::ArmCacheZero
                ) {
                    state.memory.clear();
                }
                for output in outputs {
                    state.regs.insert(output.index, Value::Unknown);
                }
            }
            Stmt::Assign { dest, value } => {
                let value = self.narrow(self.eval(state, value, site, &mut loads), dest.width);
                let value = if dest.index < 16 {
                    self.pointer_value(value)
                } else {
                    value
                };
                state.regs.insert(dest.index, value);
            }
            Stmt::Store { addr, value, width } => {
                let addr = self.pointer_value(self.eval(state, addr, site, &mut loads));
                let value = self.eval(state, value, site, &mut loads);
                let value = if *width == 4 {
                    self.pointer_value(value)
                } else {
                    value
                };
                self.forget(state, Some((addr, *width)));
                if addr != Value::Unknown && value != Value::Unknown {
                    state.memory.insert((addr.key(), *width), value);
                }
            }
            Stmt::Call {
                target, convention, ..
            } => {
                let first = convention
                    .arguments()
                    .first()
                    .map(|register| state.reg(*register));
                let physical = stmt.call_clobbers();
                let primary = convention.results().first();
                let returned = target.and_then(|target| {
                    stmt.primary_call_output()
                        .filter(|output| {
                            output.dest.width == 64 && physical.contains(&output.register)
                        })
                        .and_then(|_| self.returned(target, *convention))
                });
                let outputs: Vec<_> = stmt
                    .call_outputs()
                    .iter()
                    .map(|output| {
                        let value = if !physical.contains(&output.register) {
                            state.reg(output.register)
                        } else if Some(&output.register) == primary
                            && output.dest.width == 64
                            && let Some(value) = returned
                        {
                            Value::Const(value, None)
                        } else {
                            Value::Sym(
                                Base::Def(site.0, site.1, u32::MAX - u32::from(output.register)),
                                0,
                            )
                        };
                        let value = match (value, output.dest.width) {
                            (value, 64) => value,
                            (Value::Const(value, _), width) => Value::Const(
                                value & crate::ir::semantics::mask(u32::from(width)),
                                None,
                            ),
                            _ => Value::Unknown,
                        };
                        (output.dest.index, value)
                    })
                    .collect();
                self.forget(state, None);
                for register in crate::ir::visit::statement_registers(stmt).0 {
                    state.regs.insert(register, Value::Unknown);
                }
                state.regs.extend(outputs);
                if self.constructors
                    && let (Some(target), Some(object)) = (target, first)
                    && object != Value::Unknown
                    && let Some(table) = installed_table(self.image, *target)
                {
                    state
                        .memory
                        .insert((object.key(), 8), Value::Const(table, None));
                }
            }
            Stmt::Unsupported { writes, .. } => {
                self.forget(state, None);
                match writes {
                    Some(writes) => {
                        for register in writes {
                            state.regs.insert(*register, Value::Unknown);
                        }
                    }
                    None => {
                        state.regs.clear();
                        state.rest = Rest::Unknown;
                    }
                }
            }
            _ => {}
        }
    }

    /// The state on entry to each block, `None` for one no path reaches.
    /// A block ending in a call that unwinds into a landing pad goes there
    /// too.
    fn solve(&self, blocks: &[Block], pads: &[(u64, Vec<(u64, u64)>)]) -> Vec<Option<State>> {
        let mut entry: Vec<Option<State>> = vec![None; blocks.len()];
        if blocks.is_empty() {
            return entry;
        }
        entry[0] = Some(State::entry());
        let mut pending = vec![0];
        // Blocks only an exception or an unresolved jump reaches start
        // knowing nothing, once the rest has settled.
        let mut unreached = (1..blocks.len()).rev();
        loop {
            while let Some(index) = pending.pop() {
                let mut state = entry[index].clone().expect("a reached block");
                for (position, stmt) in blocks[index].stmts.iter().enumerate() {
                    self.step(&mut state, stmt, (index as u32, position as u32));
                }
                for next in successors(blocks, pads, index) {
                    let merged = match &entry[next] {
                        Some(old) => old.meet(&state, next as u32),
                        None => state.clone(),
                    };
                    if entry[next].as_ref() != Some(&merged) {
                        entry[next] = Some(merged);
                        pending.push(next);
                    }
                }
            }
            let Some(index) = unreached.find(|index| entry[*index].is_none()) else {
                return entry;
            };
            entry[index] = Some(State {
                regs: BTreeMap::new(),
                rest: Rest::Join(index as u32),
                memory: BTreeMap::new(),
            });
            pending.push(index);
        }
    }
}

fn successors(blocks: &[Block], pads: &[(u64, Vec<(u64, u64)>)], index: usize) -> Vec<usize> {
    let mut out = crate::ir::cfg::block_successors(blocks, index);
    let start = blocks[index].start;
    let end = blocks.get(index + 1).map_or(u64::MAX, |next| next.start);
    for (pad, sites) in pads {
        if sites
            .iter()
            .any(|(from, to)| start < *to && *to <= end && *from < end)
            && let Some(position) = blocks.iter().position(|block| block.start == *pad)
            && !out.contains(&position)
        {
            out.push(position);
        }
    }
    out
}

/// The word at `addr` in constant data.
fn read_only_word(image: &Image, addr: u64) -> Option<u64> {
    let Some(section) = image.section_at(addr) else {
        return None;
    };
    if !section.read_only {
        return None;
    }
    match image.read_pointer(addr) {
        Some(crate::loader::Pointer::Address(address)) => Some(address),
        _ => None,
    }
}

fn is_code(image: &Image, word: Option<u64>) -> bool {
    word.is_some_and(|word| image.functions.contains_key(&word))
}

/// The address points of the C++ virtual tables: where the symbols say
/// they are, else where code takes the address of words of code after
/// the offset to the object's top and the type information.
fn vtables(image: &Image) -> &BTreeSet<u64> {
    image.vtables.get_or_init(|| {
        let mut found: BTreeSet<u64> = image
            .data_symbols
            .iter()
            .filter(|(_, name)| name.trim_start_matches('_').starts_with("ZTV"))
            .filter_map(|(addr, _)| addr.checked_add(16))
            .filter(|point| read_only_word(image, *point).is_some())
            .collect();
        for class in image.classes() {
            for table in &class.vtables {
                found.insert(table.address);
            }
        }
        if found.is_empty() && !image.go {
            let addressed = image
                .addressed
                .get_or_init(|| super::jump_table::referenced_addresses(image));
            found.extend(addressed.iter().copied().filter(|point| {
                let word = |offset: u64| read_only_word(image, point.wrapping_sub(offset));
                is_code(image, read_only_word(image, *point))
                    && word(16).is_some_and(|top| (-0x1_0000..=0).contains(&(top as i64)))
                    && word(8).is_some_and(|info| {
                        info == 0 || image.section_at(info).is_some_and(|s| !s.executable)
                    })
            }));
        }
        found
    })
}

/// The functions slot `slot` holds in the C++ tables long enough to have
/// it, but the handler a pure virtual slot holds, which does not return.
fn candidates(image: &Image, slot: u64) -> Vec<u64> {
    let mut found: Vec<u64> = vtables(image)
        .iter()
        .filter(|point| {
            (0..slot).all(|earlier| {
                read_only_word(image, *point + 8 * earlier)
                    .is_some_and(|word| word == 0 || image.functions.contains_key(&word))
            })
        })
        .filter_map(|point| read_only_word(image, point + 8 * slot))
        .filter(|word| image.functions.contains_key(word))
        .filter(|word| !super::summary(image, *word).noreturn)
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// Candidate sets larger than this are left out of the comment.
const MAX_CANDIDATES: usize = 4;

/// What kind of table the word at `table + offset` belongs to.
fn via(image: &Image, from: Option<(u64, u64)>) -> Via {
    let make = |table, slot| Via {
        table,
        slot,
        candidates: Vec::new(),
    };
    let Some((table, offset)) = from else {
        return make(Table::Register, 0);
    };
    let word = |at: u64| read_only_word(image, table.wrapping_add(at));
    let data = |word: Option<u64>| {
        word.is_some_and(|word| image.section_at(word).is_some_and(|s| !s.executable))
    };
    if vtables(image).contains(&table) && offset % 8 == 0 {
        return make(Table::Vtable, offset / 8);
    }
    let method = offset >= 0x18 && offset % 8 == 0;
    if image.go {
        if offset == 0 {
            return make(Table::FuncValue, 0);
        }
        if method && data(word(0)) && data(word(8)) {
            return make(Table::Itab, (offset - 0x18) / 8);
        }
    } else if method
        && word(0).is_some_and(|drop| drop == 0 || image.functions.contains_key(&drop))
        && word(8).is_some_and(|size| size < 1 << 32 && !image.functions.contains_key(&size))
        && word(16).is_some_and(|align| align.is_power_of_two() && align <= 1 << 16)
    {
        return make(Table::TraitObject, (offset - 0x18) / 8);
    }
    make(Table::Pointer, table.wrapping_add(offset))
}

/// The table the function at `addr` leaves at offset 0 of the object its
/// first argument points to, on every path that returns.
fn installed_table(image: &Image, addr: u64) -> Option<u64> {
    if let Some(known) = image.installs.lock().expect("installs lock").get(&addr) {
        return *known;
    }
    let found = find_installed_table(image, addr);
    image
        .installs
        .lock()
        .expect("installs lock")
        .insert(addr, found);
    found
}

/// Constructors are short; longer functions are not looked into.
const MAX_ANALYZED_FUNCTION_SIZE: u64 = 512;

fn find_installed_table(image: &Image, addr: u64) -> Option<u64> {
    let function = image.functions.get(&addr)?;
    let size = function
        .size
        .filter(|size| *size <= MAX_ANALYZED_FUNCTION_SIZE)?;
    let blocks = crate::lift::lift(image, addr, size, &HashSet::new()).ok()?;
    let first = *image.convention_of(addr).arguments().first()?;
    let tracker = Tracker {
        image,
        sp: crate::arch::stack_pointer(image.isa),
        loads: Default::default(),
        constructors: false,
        returns: None,
    };
    let entry = tracker.solve(&blocks, &[]);
    let mut table = None;
    for (index, block) in blocks.iter().enumerate() {
        let Some(mut state) = entry[index].clone() else {
            continue;
        };
        for (position, stmt) in block.stmts.iter().enumerate() {
            if let Stmt::Ret { .. } = stmt {
                let left = state.memory.get(&(Value::Sym(Base::Entry(first), 0), 8));
                match (left, table) {
                    (Some(Value::Const(left, _)), None)
                        if tracker.durable(&Value::Const(*left, None)) =>
                    {
                        table = Some(*left)
                    }
                    (Some(Value::Const(left, _)), Some(table)) if *left == table => {}
                    _ => return None,
                }
            }
            tracker.step(&mut state, stmt, (index as u32, position as u32));
        }
    }
    table
}

fn returned_by(image: &Image, addr: u64) -> Option<u64> {
    let function = image.functions.get(&addr)?;
    if function.size_estimated {
        return None;
    }
    let size = function
        .size
        .filter(|size| *size != 0 && *size <= MAX_ANALYZED_FUNCTION_SIZE)?;
    let end = addr.checked_add(size)?;
    let convention = image.convention_of(addr);
    if !matches!(
        convention,
        Convention::SysV | Convention::Win64 | Convention::Aapcs64 | Convention::GoAmd64
    ) {
        return None;
    }
    let primary = *convention.results().first()?;
    let blocks = crate::lift::lift_shared(image, addr, size, &|_| Default::default()).ok()?;
    returned_from(image, addr, end, primary, &blocks)
}

fn returned_from(
    image: &Image,
    addr: u64,
    end: u64,
    primary: u16,
    blocks: &[Block],
) -> Option<u64> {
    let Some(first) = blocks.first() else {
        return None;
    };
    if first.start != addr
        || !closed_normal_flow(blocks, Edges::Forward)
        || blocks.iter().any(|block| {
            block.start < addr
                || block.start >= end
                || block.stmts.iter().any(|stmt| {
                    matches!(
                        stmt,
                        Stmt::Call { .. }
                            | Stmt::Store { .. }
                            | Stmt::Machine { .. }
                            | Stmt::Unsupported { .. }
                    )
                })
        })
    {
        return None;
    }
    let tracker = Tracker {
        image,
        sp: crate::arch::stack_pointer(image.isa),
        loads: Default::default(),
        constructors: false,
        returns: None,
    };
    let entry = tracker.solve(blocks, &[]);
    let mut returned = None;
    for (index, block) in blocks.iter().enumerate() {
        let Some(mut state) = entry[index].clone() else {
            return None;
        };
        for (position, stmt) in block.stmts.iter().enumerate() {
            if matches!(stmt, Stmt::Ret { .. }) {
                match (state.reg(primary), returned) {
                    (Value::Const(value, _), None)
                        if image.functions.contains_key(&value)
                            || image
                                .section_at(value)
                                .is_some_and(|section| section.read_only) =>
                    {
                        returned = Some(value);
                    }
                    (Value::Const(value, _), Some(known)) if value == known => {}
                    _ => return None,
                }
            }
            tracker.step(&mut state, stmt, (index as u32, position as u32));
        }
    }
    returned
}

#[derive(PartialEq)]
enum Edges {
    Forward,
    Any,
}

fn closed_normal_flow(blocks: &[Block], edges: Edges) -> bool {
    !blocks.is_empty()
        && blocks.iter().enumerate().all(|(index, block)| {
            if index != 0 && blocks[index - 1].start >= block.start {
                return false;
            }
            let Some((last, prefix)) = block.stmts.split_last() else {
                return false;
            };
            if prefix.iter().any(|stmt| {
                matches!(
                    stmt,
                    Stmt::Brif { .. }
                        | Stmt::BrifFlags { .. }
                        | Stmt::Br { .. }
                        | Stmt::BrIndirect { .. }
                        | Stmt::Switch { .. }
                        | Stmt::Ret { .. }
                        | Stmt::Trap
                )
            }) {
                return false;
            }
            let known = |target| {
                blocks.iter().enumerate().any(|(next, block)| {
                    (edges == Edges::Any || next > index) && block.start == target
                })
            };
            match last {
                Stmt::Ret { .. } | Stmt::Trap => true,
                Stmt::Br {
                    target: Some(target),
                } => known(*target),
                Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } => {
                    known(*target) && index + 1 < blocks.len()
                }
                Stmt::Switch {
                    cases,
                    default: Some(default),
                    ..
                } => known(*default) && cases.iter().all(|(_, target)| known(*target)),
                Stmt::Assign { .. }
                | Stmt::Store { .. }
                | Stmt::Call { .. }
                | Stmt::Machine { .. }
                | Stmt::Unsupported { .. } => index + 1 < blocks.len(),
                _ => false,
            }
        })
}

/// Turns the indirect calls whose callee the code fixes into direct calls,
/// and marks those through a slot of an object's table with the slot.
pub(crate) fn resolve(blocks: &mut [Block], pads: &[(u64, Vec<(u64, u64)>)], image: &Image) {
    let indirect = |stmt: &Stmt| {
        matches!(stmt, Stmt::Call { target: None, through: Some(through), convention, .. }
            if !stmt.has_declared_call()
                && !matches!(convention, Convention::SyscallX86 | Convention::SyscallArm)
                && crate::lift::import_name(image, through).is_none())
    };
    if !blocks.iter().flat_map(|block| &block.stmts).any(indirect) {
        return;
    }
    let tracker = Tracker {
        image,
        sp: crate::arch::stack_pointer(image.isa),
        loads: Default::default(),
        constructors: !vtables(image).is_empty(),
        returns: (pads.is_empty() && closed_normal_flow(blocks, Edges::Any)).then(Default::default),
    };
    let types = if image.classes().is_empty() {
        None
    } else {
        blocks.first().and_then(|block| {
            crate::loader::dwarf::virtual_calls::function_types(image, block.start)
        })
    };
    let entry = tracker.solve(blocks, pads);
    let mut decisions = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(mut state) = entry[index].clone() else {
            continue;
        };
        for (position, stmt) in block.stmts.iter().enumerate() {
            let site = (index as u32, position as u32);
            if indirect(stmt)
                && let Stmt::Call {
                    through: Some(through),
                    ..
                } = stmt
                && let Some(decision) = decide(&tracker, &state, through, site, types.as_ref())
            {
                decisions.push((index, position, decision));
            }
            tracker.step(&mut state, stmt, site);
        }
    }
    let summaries = |target| super::summary(image, target);
    for (index, position, decision) in decisions.into_iter().rev() {
        let stmts = &mut blocks[index].stmts;
        let Stmt::Call {
            kind,
            through: Some(through),
            ..
        } = &stmts[position]
        else {
            continue;
        };
        let kind = *kind;
        let through = through.clone();
        match decision {
            Decision::Direct(target, found) => {
                let mut call = crate::lift::call(kind, image, &summaries, Some(target));
                if let Stmt::Call { via, .. } = &mut call {
                    *via = Some(Box::new(found));
                }
                stmts[position] = call;
                // A tail call's results go to this function's caller.
                if kind == crate::ir::CallKind::Invoke {
                    let results = crate::lift::stack_results(image, &summaries, target);
                    stmts.splice(position + 1..position + 1, results);
                }
                remove_call_target_assignments(stmts, position, &through);
            }
            Decision::Import(slot) => {
                let imported = Expr::Load {
                    addr: Box::new(Expr::Const(slot)),
                    width: crate::arch::pointer_bytes(image.isa),
                    signed: false,
                };
                stmts[position] = crate::lift::call_through(kind, image, imported);
                remove_call_target_assignments(stmts, position, &through);
            }
            Decision::Slot(found) => {
                let arity = common_arity(image, &found.candidates);
                if let Stmt::Call {
                    via,
                    args,
                    convention,
                    ..
                } = &mut stmts[position]
                {
                    if args.is_none() && arity.is_some() {
                        *args = crate::lift::arguments(kind, *convention, image.isa, arity, 0);
                    }
                    *via = Some(Box::new(found));
                }
            }
        }
    }
}

/// The number of register arguments every candidate takes, when they agree.
fn common_arity(image: &Image, candidates: &[u64]) -> Option<usize> {
    let mut arity = None;
    for candidate in candidates {
        let summary = super::summary(image, *candidate);
        if summary.stack != 0 || summary.floats.is_some_and(|floats| floats != 0) {
            return None;
        }
        match (arity, summary.arity) {
            (_, None) => return None,
            (None, found) => arity = found,
            (Some(known), Some(found)) if known != found => return None,
            _ => {}
        }
    }
    arity
}

/// Drops the statements that only computed the address an indirect call,
/// now direct, went through: each assignment of a register the address
/// read, last before the call, that nothing reads before the call or the
/// block's code after it writes the register again or returns.
fn remove_call_target_assignments(stmts: &mut Vec<Stmt>, mut position: usize, through: &Expr) {
    let mut pending = HashSet::new();
    crate::ir::visit::collect_reads(through, &mut pending);
    while let Some(register) = pending.iter().next().copied() {
        pending.remove(&register);
        let overwritten = match stmts[position + 1..]
            .iter()
            .map(crate::ir::visit::statement_registers)
            .find(|(writes, reads)| writes.contains(&register) || reads.contains(&register))
        {
            Some((_, reads)) => !reads.contains(&register),
            None => matches!(stmts.last(), Some(Stmt::Ret { .. } | Stmt::Trap)),
        };
        if !crate::ir::visit::statement_registers(&stmts[position])
            .0
            .contains(&register)
            && !overwritten
        {
            continue;
        }
        let Some(at) = stmts[..position].iter().rposition(|stmt| {
            crate::ir::visit::statement_registers(stmt)
                .0
                .contains(&register)
        }) else {
            continue;
        };
        let Stmt::Assign { value, .. } = &stmts[at] else {
            continue;
        };
        let read_later = stmts[at + 1..=position].iter().any(|stmt| {
            crate::ir::visit::statement_registers(stmt)
                .1
                .contains(&register)
        });
        if read_later {
            continue;
        }
        crate::ir::visit::collect_reads(value, &mut pending);
        stmts.remove(at);
        position -= 1;
    }
}

fn decide(
    tracker: &Tracker<'_>,
    state: &State,
    through: &Expr,
    site: (u32, u32),
    types: Option<&crate::loader::dwarf::FunctionTypes>,
) -> Option<Decision> {
    let image = tracker.image;
    let mut loads = 0;
    match tracker.eval(state, through, site, &mut loads) {
        Value::Const(target, from) if image.functions.contains_key(&image.code_address(target)) => {
            Some(Decision::Direct(
                image.code_address(target),
                via(image, from),
            ))
        }
        Value::Import(slot) => Some(Decision::Import(slot)),
        // A slot of the table the object starts with.
        Value::Sym(name @ Base::Def(..), 0) if !vtables(image).is_empty() => {
            let loaded = tracker.loads.borrow();
            let Some(Value::Sym(table @ Base::Def(..), offset)) = loaded.get(&name).copied() else {
                return None;
            };
            if offset % 8 != 0 || !matches!(loaded.get(&table), Some(Value::Sym(_, 0))) {
                return None;
            }
            let slot = offset / 8;
            let mut candidates = candidates(image, slot);
            let mut typed = false;
            if let Some(Value::Sym(Base::Entry(register), 0)) = loaded.get(&table)
                && let Some(types) = types
                && !types.variadic
                && types.ret.as_ref().is_some_and(|ty| {
                    ty.is_pointer()
                        || ty.integer().is_some_and(|(bits, _)| bits <= 64)
                        || *ty == crate::ir::CType::Void
                })
                && types.params.iter().all(|(_, ty)| {
                    ty.as_ref().is_some_and(|ty| {
                        ty.is_pointer() || ty.integer().is_some_and(|(bits, _)| bits <= 64)
                    })
                })
                && let Ok(profile) = types.abi_profile
                && let Some(position) = super::abi::convention(profile)
                    .arguments()
                    .iter()
                    .position(|arg| arg == register)
                && let Some((_, Some(ty))) = types.params.get(position)
                && let Some(name) = ty.pointee_struct()
                && image.classes().iter().any(|class| class.name == name)
            {
                let targets = crate::loader::classes::virtual_targets(image.classes(), name, slot);
                candidates.retain(|candidate| targets.contains(candidate));
                typed = true;
            }
            if !typed && candidates.len() > MAX_CANDIDATES {
                candidates.clear();
            }
            Some(Decision::Slot(Via {
                table: Table::Vtable,
                slot,
                candidates,
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
