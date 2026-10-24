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
            let distance = a.wrapping_sub(b) as i64;
            distance < i64::from(width) && -distance < i64::from(stored_width)
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

    fn eval(&self, state: &State, expr: &Expr, site: (u32, u32), loads: &mut u32) -> Value {
        match expr {
            Expr::Reg { index, width } => match (state.reg(*index), *width) {
                (value, 64) => value,
                (Value::Const(value, _), width) => {
                    Value::Const(value & crate::ir::semantics::mask(u32::from(width)), None)
                }
                _ => Value::Unknown,
            },
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
                let addr = match table {
                    Value::Const(table, _) => Value::Const(table.wrapping_add(offset), None),
                    Value::Sym(base, at) => Value::Sym(base, at.wrapping_add(offset)),
                    Value::Unknown | Value::Import(_) => Value::Unknown,
                };
                let name = Base::Def(site.0, site.1, *loads);
                *loads += 1;
                self.loads.borrow_mut().insert(name, addr);
                if *width == 8 {
                    if let Value::Const(slot, _) = addr
                        && self.image.imports.contains_key(&slot)
                    {
                        return Value::Import(slot);
                    }
                    if let Some(value) = state.memory.get(&(addr.key(), 8)) {
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
            Stmt::Machine { outputs, .. } => {
                for output in outputs {
                    state.regs.insert(output.index, Value::Unknown);
                }
            }
            Stmt::Assign { dest, value } => {
                let value = match (self.eval(state, value, site, &mut loads), dest.width) {
                    (value, 64) => value,
                    (Value::Const(value, _), width) => {
                        Value::Const(value & crate::ir::semantics::mask(u32::from(width)), None)
                    }
                    _ => Value::Unknown,
                };
                state.regs.insert(dest.index, value);
            }
            Stmt::Store { addr, value, width } => {
                let addr = self.eval(state, addr, site, &mut loads);
                let value = self.eval(state, value, site, &mut loads);
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
                    && let Some(table) = installed(self.image, *target)
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
    let section = image.section_at(addr)?;
    if !section.read_only || addr.checked_add(8)? > section.vaddr.saturating_add(section.size) {
        return None;
    }
    let bytes = image.read_vaddr(addr, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
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
            .map(|(addr, _)| addr + 16)
            .filter(|point| read_only_word(image, *point).is_some())
            .collect();
        if found.is_empty() && !image.go {
            let addressed = image
                .addressed
                .get_or_init(|| super::jump_table::addressed(image));
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
fn installed(image: &Image, addr: u64) -> Option<u64> {
    if let Some(known) = image.installs.lock().expect("installs lock").get(&addr) {
        return *known;
    }
    let found = installed_by(image, addr);
    image
        .installs
        .lock()
        .expect("installs lock")
        .insert(addr, found);
    found
}

/// Constructors are short; longer functions are not looked into.
const CONSTRUCTOR_SIZE: u64 = 512;

fn installed_by(image: &Image, addr: u64) -> Option<u64> {
    let function = image.functions.get(&addr)?;
    let size = function.size.filter(|size| *size <= CONSTRUCTOR_SIZE)?;
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
        .filter(|size| *size != 0 && *size <= CONSTRUCTOR_SIZE)?;
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
        || !closed_normal_flow(blocks, true)
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

fn closed_normal_flow(blocks: &[Block], forward_only: bool) -> bool {
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
                blocks
                    .iter()
                    .enumerate()
                    .any(|(next, block)| (!forward_only || next > index) && block.start == target)
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
            if !matches!(convention, Convention::SyscallX86 | Convention::SyscallArm)
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
        returns: (pads.is_empty() && closed_normal_flow(blocks, false)).then(Default::default),
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
                && let Some(decision) = decide(&tracker, &state, through, site)
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
                drop_feeding(stmts, position, &through);
            }
            Decision::Import(slot) => {
                let through = Expr::Load {
                    addr: Box::new(Expr::Const(slot)),
                    width: 8,
                    signed: false,
                };
                stmts[position] = crate::lift::call_through(kind, image, through.clone());
                drop_feeding(stmts, position, &through);
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
fn drop_feeding(stmts: &mut Vec<Stmt>, mut position: usize, through: &Expr) {
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
) -> Option<Decision> {
    let image = tracker.image;
    let mut loads = 0;
    match tracker.eval(state, through, site, &mut loads) {
        Value::Const(target, from) if image.functions.contains_key(&target) => {
            Some(Decision::Direct(target, via(image, from)))
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
            if candidates.len() > MAX_CANDIDATES {
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
mod tests {
    use super::*;
    use crate::ir::{CallOutput, RegRef, VARIABLE_BASE};
    use crate::loader::{Function, Isa, Section};

    fn pointer_factory(isa: Isa, table: bool, factory: Vec<u8>) -> (Image, Vec<Block>) {
        let (caller, target) = match isa {
            Isa::X86_64 => (
                vec![
                    0x48,
                    0x83,
                    0xec,
                    8,
                    0xe8,
                    0x37,
                    0,
                    0,
                    0,
                    0xff,
                    if table { 0x10 } else { 0xd0 },
                    0x48,
                    0x83,
                    0xc4,
                    8,
                    0xc3,
                ],
                vec![0xb8, 7, 0, 0, 0, 0xc3],
            ),
            Isa::AArch64 => (
                [
                    0xa9bf7bfdu32,
                    0x9400000f,
                    if table { 0xf9400008 } else { 0xaa0003e8 },
                    0xd63f0100,
                    0xa8c17bfd,
                    0xd65f03c0,
                ]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
                [0x528000e0u32, 0xd65f03c0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            ),
            Isa::Unsupported => unreachable!(),
        };
        let mut code = vec![0; 0x90];
        code[..caller.len()].copy_from_slice(&caller);
        code[0x40..0x40 + factory.len()].copy_from_slice(&factory);
        code[0x80..0x80 + target.len()].copy_from_slice(&target);
        code.extend_from_slice(&0x80u64.to_le_bytes());
        let mut image = Image::from_code(isa, 0, code);
        image.sections[0].size = 0x90;
        image.sections.push(Section {
            name: ".rodata".to_owned(),
            vaddr: 0x1000,
            size: 8,
            file_offset: Some(0x90),
            executable: false,
            loaded: true,
            read_only: true,
        });
        for (addr, size, name) in [
            (0, caller.len(), "caller"),
            (0x40, factory.len(), "factory"),
            (0x80, target.len(), "target"),
        ] {
            image.functions.insert(
                addr,
                Function {
                    addr,
                    size: Some(size as u64),
                    size_estimated: false,
                    name: Some(name.to_owned()),
                    aliases: Vec::new(),
                    sources: Vec::new(),
                },
            );
        }
        let blocks =
            crate::lift::lift_shared(&image, 0, caller.len() as u64, &|_| Default::default())
                .expect("caller lifts");
        (image, std::sync::Arc::unwrap_or_clone(blocks))
    }

    fn constant_factory(isa: Isa, value: u32) -> Vec<u8> {
        match isa {
            Isa::X86_64 => {
                let mut code = vec![0xb8];
                code.extend_from_slice(&value.to_le_bytes());
                code.push(0xc3);
                code
            }
            Isa::AArch64 => [0xd2800000u32 | value << 5, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
            Isa::Unsupported => unreachable!(),
        }
    }

    #[test]
    fn a_resolved_tail_call_stays_a_tail_call() {
        let (image, mut blocks) =
            pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        let Some(Stmt::Call { kind, .. }) = blocks
            .iter_mut()
            .flat_map(|block| &mut block.stmts)
            .find(|stmt| {
                matches!(
                    stmt,
                    Stmt::Call {
                        through: Some(_),
                        ..
                    }
                )
            })
        else {
            panic!("an indirect call");
        };
        *kind = crate::ir::CallKind::Tail;
        resolve(&mut blocks, &[], &image);
        let resolved = blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .find_map(|stmt| match stmt {
                Stmt::Call {
                    kind,
                    target: Some(0x80),
                    ..
                } => Some(*kind),
                _ => None,
            });
        assert_eq!(resolved, Some(crate::ir::CallKind::Tail));
    }

    #[test]
    fn returned_pointer_factories_resolve_their_exact_callee() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            for table in [false, true] {
                let address = if table { 0x1000 } else { 0x80 };
                let (image, mut blocks) =
                    pointer_factory(isa, table, constant_factory(isa, address));
                let factory = crate::lift::lift_shared(
                    &image,
                    0x40,
                    image.functions[&0x40].size.unwrap(),
                    &|_| Default::default(),
                )
                .expect("factory lifts");
                let mut ir = crate::ir::FunctionIr::single_block(isa, Vec::new());
                ir.blocks = std::sync::Arc::unwrap_or_clone(factory);
                let setup = crate::ir::eval::Setup {
                    seed: 9,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[(0, 0xdead_beef)],
                    memory: &[],
                    step_limit: 100,
                };
                match crate::ir::eval::run(&ir, &setup) {
                    crate::ir::eval::Outcome::Return { value, .. } => {
                        assert_eq!(value, u64::from(address))
                    }
                    other => panic!("{other:?}"),
                }
                let factory_before = blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .find(|stmt| {
                        matches!(
                            stmt,
                            Stmt::Call {
                                target: Some(0x40),
                                ..
                            }
                        )
                    })
                    .map(|stmt| format!("{stmt:?}"))
                    .expect("factory call");
                resolve(&mut blocks, &[], &image);
                let calls: Vec<_> = blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .filter(|stmt| matches!(stmt, Stmt::Call { .. }))
                    .collect();
                assert_eq!(calls.len(), 2);
                assert_eq!(format!("{:?}", calls[0]), factory_before);
                let Stmt::Call {
                    target: Some(0x80),
                    via: Some(via),
                    ..
                } = calls[1]
                else {
                    panic!("{isa:?}: {calls:?}");
                };
                assert!(via.candidates.is_empty());
                if table {
                    assert_eq!(via.table, Table::Pointer);
                    assert_eq!(via.slot, 0x1000);
                }
            }
        }
    }

    #[test]
    fn go_function_value_factories_keep_the_existing_table_provenance() {
        let (mut image, _) =
            pointer_factory(Isa::X86_64, true, constant_factory(Isa::X86_64, 0x1000));
        image.go = true;
        image.lifts = Default::default();
        let blocks =
            crate::lift::lift_shared(&image, 0, image.functions[&0].size.unwrap(), &|_| {
                Default::default()
            })
            .expect("Go caller lifts");
        let mut blocks = std::sync::Arc::unwrap_or_clone(blocks);
        resolve(&mut blocks, &[], &image);
        let calls: Vec<_> = blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .filter(|stmt| matches!(stmt, Stmt::Call { .. }))
            .collect();
        assert_eq!(calls.len(), 2);
        let Stmt::Call {
            target: Some(0x80),
            convention: Convention::GoAmd64,
            via: Some(via),
            ..
        } = calls[1]
        else {
            panic!("{calls:?}");
        };
        assert_eq!(via.table, Table::FuncValue);
        assert!(via.candidates.is_empty());
    }

    #[test]
    fn constant_returns_require_agreement_from_symbolic_entries() {
        let mut same = vec![0x85, 0xff, 0x75, 6];
        same.extend(constant_factory(Isa::X86_64, 0x1000));
        same.extend(constant_factory(Isa::X86_64, 0x1000));
        let (image, _) = pointer_factory(Isa::X86_64, true, same.clone());
        assert_eq!(returned_by(&image, 0x40), Some(0x1000));

        let mut different = same[..10].to_vec();
        different.extend(constant_factory(Isa::X86_64, 0x80));
        let (image, _) = pointer_factory(Isa::X86_64, true, different);
        assert_eq!(returned_by(&image, 0x40), None);

        let mut argument = same[..10].to_vec();
        argument.extend([0x48, 0x89, 0xf8, 0xc3]);
        let (image, _) = pointer_factory(Isa::X86_64, true, argument);
        assert_eq!(returned_by(&image, 0x40), None);
        let (image, _) = pointer_factory(Isa::X86_64, true, vec![0x48, 0x89, 0xf8, 0xc3]);
        assert_eq!(returned_by(&image, 0x40), None);

        let mut joined = vec![0x85, 0xff, 0x75, 7];
        joined.extend(&constant_factory(Isa::X86_64, 0x1000)[..5]);
        joined.extend([0xeb, 5]);
        joined.extend(constant_factory(Isa::X86_64, 0x1000));
        let (image, _) = pointer_factory(Isa::X86_64, true, joined.clone());
        assert_eq!(returned_by(&image, 0x40), Some(0x1000));
        joined[12..16].copy_from_slice(&0x80u32.to_le_bytes());
        let (image, _) = pointer_factory(Isa::X86_64, true, joined);
        assert_eq!(returned_by(&image, 0x40), None);
    }

    #[test]
    fn constant_returns_reject_mutation_calls_and_unmodeled_instructions() {
        for prefix in [
            vec![0x48, 0x89, 7],
            vec![0xe8, 0x3b, 0, 0, 0],
            vec![0x0f, 0xa2],
        ] {
            let mut code = prefix;
            code.extend(constant_factory(Isa::X86_64, 0x1000));
            let (image, mut caller) = pointer_factory(Isa::X86_64, true, code);
            assert_eq!(returned_by(&image, 0x40), None);
            resolve(&mut caller, &[], &image);
            assert!(
                caller
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(
                        stmt,
                        Stmt::Call {
                            target: None,
                            through: Some(_),
                            ..
                        }
                    ))
            );
        }
    }

    #[test]
    fn constant_returns_only_read_immutable_in_bounds_words() {
        let mut code = vec![0x48, 0xa1];
        code.extend_from_slice(&0x1000u64.to_le_bytes());
        code.push(0xc3);
        let (mut image, _) = pointer_factory(Isa::X86_64, false, code);
        assert_eq!(returned_by(&image, 0x40), Some(0x80));
        image.sections[1].read_only = false;
        assert_eq!(returned_by(&image, 0x40), None);
        image.sections[1].read_only = true;
        image.sections[1].size = 7;
        assert_eq!(returned_by(&image, 0x40), None);

        let (mut image, mut caller) =
            pointer_factory(Isa::X86_64, true, constant_factory(Isa::X86_64, 0x1000));
        image.sections[1].read_only = false;
        resolve(&mut caller, &[], &image);
        assert!(
            caller
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(
                    stmt,
                    Stmt::Call {
                        target: None,
                        through: Some(_),
                        ..
                    }
                ))
        );
    }

    #[test]
    fn constant_returns_require_exact_bounded_extents() {
        let (mut image, _) =
            pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        assert_eq!(returned_by(&image, 0x40), Some(0x80));
        image.functions.get_mut(&0x40).unwrap().size_estimated = true;
        assert_eq!(returned_by(&image, 0x40), None);
        image.functions.get_mut(&0x40).unwrap().size_estimated = false;
        for size in [None, Some(0), Some(CONSTRUCTOR_SIZE + 1)] {
            image.functions.get_mut(&0x40).unwrap().size = size;
            assert_eq!(returned_by(&image, 0x40), None);
        }
        assert_eq!(returned_by(&image, 0x1234), None);
    }

    #[test]
    fn constant_return_cfg_checks_every_exit_and_return() {
        use crate::ir::Cond;
        let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        let assign = Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value: Expr::Const(0x80),
        };
        let ret = Stmt::Ret {
            value: Expr::reg(0, 64),
        };
        let branch = Stmt::Brif {
            cond: Cond::Ne,
            lhs: Expr::reg(7, 64),
            rhs: Expr::Const(0),
            target: 0x48,
        };
        let valid = vec![
            Block {
                start: 0x40,
                stmts: vec![assign.clone(), branch],
            },
            Block {
                start: 0x44,
                stmts: vec![ret.clone()],
            },
            Block {
                start: 0x48,
                stmts: vec![ret.clone()],
            },
        ];
        assert_eq!(returned_from(&image, 0x40, 0x50, 0, &valid), Some(0x80));
        for last in [
            Stmt::Br { target: None },
            Stmt::Br { target: Some(0x40) },
            Stmt::Br { target: Some(0x46) },
            Stmt::Br { target: Some(0x80) },
            Stmt::BrIndirect {
                target: Expr::reg(7, 64),
            },
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(7, 64),
                rhs: Expr::Const(0),
                target: 0x46,
            },
            Stmt::BrifFlags {
                cond: Cond::Ne,
                target: 0x46,
            },
            Stmt::Switch {
                index: Expr::reg(7, 64),
                cases: vec![(0, 0x44)],
                default: None,
            },
            Stmt::Switch {
                index: Expr::reg(7, 64),
                cases: vec![(0, 0x46)],
                default: Some(0x48),
            },
            Stmt::Switch {
                index: Expr::reg(7, 64),
                cases: vec![(0, 0x44)],
                default: Some(0x46),
            },
        ] {
            let mut blocks = valid.clone();
            blocks[0].stmts[1] = last;
            assert_eq!(
                returned_from(&image, 0x40, 0x50, 0, &blocks),
                None,
                "{blocks:?}"
            );
        }
        let mut trap = valid.clone();
        trap[2].stmts = vec![Stmt::Trap];
        assert_eq!(returned_from(&image, 0x40, 0x50, 0, &trap), Some(0x80));
        let mut conflict = valid.clone();
        conflict[2].stmts.insert(
            0,
            Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::Const(0x1000),
            },
        );
        assert_eq!(returned_from(&image, 0x40, 0x50, 0, &conflict), None);
        let mut unreached = valid.clone();
        unreached.push(Block {
            start: 0x4c,
            stmts: vec![ret.clone()],
        });
        assert_eq!(returned_from(&image, 0x40, 0x50, 0, &unreached), None);
        for stmts in [
            vec![assign.clone()],
            vec![Stmt::Trap],
            vec![],
            vec![ret.clone(), ret],
        ] {
            assert_eq!(
                returned_from(&image, 0x40, 0x50, 0, &[Block { start: 0x40, stmts }]),
                None
            );
        }
    }

    #[test]
    fn constant_return_outputs_use_provenance_and_simultaneous_sources() {
        let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        let tracker = Tracker {
            image: &image,
            sp: 4,
            loads: Default::default(),
            constructors: false,
            returns: Some(Default::default()),
        };
        let changed = Some([0, 2].into_iter().collect());
        let mut call = Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x40),
            through: None,
            convention: Convention::SysV,
            args: Some(vec![Expr::reg(7, 64)]),
            floats_named: true,
            outputs: vec![
                CallOutput {
                    register: 2,
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                },
                CallOutput {
                    register: 0,
                    dest: RegRef {
                        index: 3,
                        width: 64,
                    },
                },
                CallOutput {
                    register: 3,
                    dest: RegRef {
                        index: 0,
                        width: 64,
                    },
                },
            ],
            clobbers: changed,
            via: None,
        };
        for _ in 0..2 {
            let mut state = State::entry();
            state.regs.insert(3, Value::Const(0x1234, None));
            tracker.step(&mut state, &call, (0, 0));
            assert_eq!(state.reg(3), Value::Const(0x80, None));
            assert_eq!(state.reg(0), Value::Const(0x1234, None));
            assert_eq!(
                state.reg(VARIABLE_BASE),
                Value::Sym(Base::Def(0, 0, u32::MAX - 2), 0)
            );
            let Stmt::Call { outputs, .. } = &mut call else {
                unreachable!()
            };
            outputs.reverse();
        }
        let output = call
            .call_outputs_mut()
            .iter_mut()
            .find(|output| output.register == 0)
            .unwrap();
        output.dest.index = VARIABLE_BASE + 1;
        output.dest.width = 32;
        let mut state = State::entry();
        tracker.step(&mut state, &call, (0, 0));
        assert_eq!(state.reg(VARIABLE_BASE + 1), Value::Unknown);
        let Stmt::Call {
            outputs, clobbers, ..
        } = &mut call
        else {
            unreachable!()
        };
        outputs
            .iter_mut()
            .find(|output| output.register == 0)
            .unwrap()
            .dest
            .width = 64;
        *clobbers = Some([2].into_iter().collect());
        state.regs.insert(0, Value::Const(0x3456, None));
        tracker.step(&mut state, &call, (0, 1));
        assert_eq!(state.reg(VARIABLE_BASE + 1), Value::Const(0x3456, None));
        let Stmt::Call {
            convention,
            clobbers,
            ..
        } = &mut call
        else {
            unreachable!()
        };
        *convention = Convention::Win64;
        *clobbers = changed;
        tracker.step(&mut state, &call, (0, 2));
        assert_eq!(
            state.reg(VARIABLE_BASE + 1),
            Value::Sym(Base::Def(0, 2, u32::MAX), 0)
        );
    }

    #[test]
    fn returned_pointer_facts_do_not_cross_register_clobbers() {
        let (image, _) = pointer_factory(Isa::X86_64, true, constant_factory(Isa::X86_64, 0x1000));
        let tracker = Tracker {
            image: &image,
            sp: 4,
            loads: Default::default(),
            constructors: false,
            returns: Some(Default::default()),
        };
        let factory = crate::lift::call(
            crate::ir::CallKind::Invoke,
            &image,
            &|_| Default::default(),
            Some(0x40),
        );
        let mut state = State::entry();
        tracker.step(&mut state, &factory, (0, 0));
        let load = |register| Expr::Load {
            addr: Box::new(Expr::reg(register, 64)),
            width: 8,
            signed: false,
        };
        assert!(matches!(
            decide(&tracker, &state, &load(0), (0, 1)),
            Some(Decision::Direct(0x80, _))
        ));
        let mut assigned = state.clone();
        tracker.step(
            &mut assigned,
            &Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::reg(7, 64),
            },
            (0, 1),
        );
        assert!(decide(&tracker, &assigned, &load(0), (0, 2)).is_none());
        tracker.step(
            &mut state,
            &Stmt::Assign {
                dest: RegRef {
                    index: 3,
                    width: 64,
                },
                value: Expr::reg(0, 64),
            },
            (0, 1),
        );
        let unknown = crate::lift::call(
            crate::ir::CallKind::Invoke,
            &image,
            &|_| Default::default(),
            None,
        );
        tracker.step(&mut state, &unknown, (0, 2));
        assert!(decide(&tracker, &state, &load(0), (0, 3)).is_none());
        assert!(matches!(
            decide(&tracker, &state, &load(3), (0, 3)),
            Some(Decision::Direct(0x80, _))
        ));
    }

    #[test]
    fn returned_pointer_facts_require_a_closed_caller_cfg() {
        use crate::ir::Cond;
        let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        let factory = crate::lift::call(
            crate::ir::CallKind::Invoke,
            &image,
            &|_| Default::default(),
            Some(0x40),
        );
        let indirect =
            crate::lift::call_through(crate::ir::CallKind::Invoke, &image, Expr::reg(0, 64));
        let ret = Stmt::Ret {
            value: Expr::reg(0, 64),
        };
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(7, 64),
                    rhs: Expr::Const(0),
                    target: 16,
                }],
            },
            Block {
                start: 8,
                stmts: vec![factory.clone(), Stmt::Br { target: Some(24) }],
            },
            Block {
                start: 16,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: 0,
                            width: 64,
                        },
                        value: Expr::Const(0x1234),
                    },
                    Stmt::BrIndirect {
                        target: Expr::reg(6, 64),
                    },
                ],
            },
            Block {
                start: 24,
                stmts: vec![indirect.clone(), ret.clone()],
            },
        ];
        for exit in [
            Stmt::BrIndirect {
                target: Expr::reg(6, 64),
            },
            Stmt::Br { target: None },
            Stmt::Br { target: Some(0x80) },
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(7, 64),
                rhs: Expr::Const(0),
                target: 0x80,
            },
            Stmt::Switch {
                index: Expr::reg(7, 64),
                cases: vec![(0, 24)],
                default: None,
            },
        ] {
            let mut caller = blocks.clone();
            caller[2].stmts[1] = exit;
            assert!(!closed_normal_flow(&caller, false));
            resolve(&mut caller, &[], &image);
            assert!(matches!(
                caller[3].stmts[0],
                Stmt::Call {
                    target: None,
                    through: Some(_),
                    ..
                }
            ));
        }
        let mut known_join = blocks;
        known_join[2].stmts[1] = Stmt::Br { target: Some(24) };
        assert!(closed_normal_flow(&known_join, false));
        resolve(&mut known_join, &[], &image);
        assert!(matches!(
            known_join[3].stmts[0],
            Stmt::Call {
                target: None,
                through: Some(_),
                ..
            }
        ));

        let mut looped = vec![
            Block {
                start: 0,
                stmts: vec![factory, Stmt::Br { target: Some(8) }],
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(7, 64),
                    rhs: Expr::Const(0),
                    target: 8,
                }],
            },
            Block {
                start: 16,
                stmts: vec![indirect, ret],
            },
        ];
        assert!(closed_normal_flow(&looped, false));
        resolve(&mut looped, &[], &image);
        assert!(matches!(
            looped[2].stmts[0],
            Stmt::Call {
                target: Some(0x80),
                ..
            }
        ));
        let mut missing_return = looped.clone();
        missing_return[2].stmts.pop();
        assert!(!closed_normal_flow(&missing_return, false));
        let mut early_terminator = looped;
        early_terminator[1].stmts.push(Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value: Expr::Const(0x80),
        });
        assert!(!closed_normal_flow(&early_terminator, false));
    }

    #[test]
    fn returned_pointer_facts_do_not_flow_through_exception_edges() {
        let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        let ret = Stmt::Ret {
            value: Expr::reg(0, 64),
        };
        let mut blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    crate::lift::call(
                        crate::ir::CallKind::Invoke,
                        &image,
                        &|_| Default::default(),
                        Some(0x40),
                    ),
                    Stmt::Br { target: Some(16) },
                ],
            },
            Block {
                start: 8,
                stmts: vec![
                    crate::lift::call_through(
                        crate::ir::CallKind::Invoke,
                        &image,
                        Expr::reg(0, 64),
                    ),
                    ret.clone(),
                ],
            },
            Block {
                start: 16,
                stmts: vec![ret],
            },
        ];
        let pads = vec![(8, vec![(0, 4)])];
        assert!(closed_normal_flow(&blocks, false));
        resolve(&mut blocks, &pads, &image);
        assert!(matches!(
            blocks[1].stmts[0],
            Stmt::Call {
                target: None,
                through: Some(_),
                ..
            }
        ));
        blocks[1].stmts[0] =
            crate::lift::call_through(crate::ir::CallKind::Invoke, &image, Expr::Const(0x80));
        resolve(&mut blocks, &pads, &image);
        assert!(matches!(
            blocks[1].stmts[0],
            Stmt::Call {
                target: Some(0x80),
                ..
            }
        ));
    }

    #[test]
    fn indirect_tracking_uses_output_provenance_and_preserved_snapshots() {
        let image = Image::from_code(Isa::X86_64, 0, Vec::new());
        let tracker = Tracker {
            image: &image,
            sp: 4,
            loads: Default::default(),
            constructors: false,
            returns: None,
        };
        let changed = Some([2].into_iter().collect());
        let mut call = Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: true,
            outputs: crate::ir::fallback_call_outputs(Convention::SysV, changed),
            clobbers: changed,
            via: None,
        };
        call.call_outputs_mut()[0].dest.index = VARIABLE_BASE;
        let mut state = State::entry();
        state.regs.insert(0, Value::Const(0x1111, None));
        state.regs.insert(2, Value::Const(0x2222, None));
        tracker.step(&mut state, &call, (0, 3));
        assert_eq!(state.reg(0), Value::Const(0x1111, None));
        assert_eq!(state.reg(2), Value::Const(0x2222, None));
        assert_eq!(
            state.reg(VARIABLE_BASE),
            Value::Sym(Base::Def(0, 3, u32::MAX - 2), 0)
        );

        let Stmt::Call { outputs, .. } = &mut call else {
            unreachable!()
        };
        *outputs = vec![
            CallOutput {
                register: 2,
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
            },
            CallOutput {
                register: 0,
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
            },
        ];
        let mut state = State::entry();
        state.regs.insert(0, Value::Const(0x1111, None));
        tracker.step(&mut state, &call, (0, 3));
        assert_eq!(state.reg(0), Value::Sym(Base::Def(0, 3, u32::MAX - 2), 0));
        assert_eq!(state.reg(VARIABLE_BASE), Value::Const(0x1111, None));
    }
}
