use std::collections::{BTreeMap, HashSet};

use crate::ir::{BinOp, Convention, Expr, FunctionIr, Stmt};
use crate::loader::{Format, Isa};

use super::Symbols;

mod optimized;

const TOP: u16 = u16::MAX;
const STACK: u16 = u16::MAX - 1;

pub(super) struct Plan {
    pub register: u16,
    pub floating: bool,
    pub name: String,
    pub last: String,
    pub result: String,
}

#[derive(Clone, Copy)]
enum Layout {
    SysV,
    Aapcs64,
    Apple,
}

struct LayoutDescriptor {
    offsets: [Option<i64>; 2],
    stack: i64,
    tops: [i64; 2],
    limits: [i64; 2],
    fields: &'static [(i64, u8)],
    size: i64,
}

impl Layout {
    fn descriptor(self) -> LayoutDescriptor {
        match self {
            Self::SysV => LayoutDescriptor {
                offsets: [Some(0), Some(4)],
                stack: 8,
                tops: [16, 16],
                limits: [48, 176],
                fields: &[(0, 4), (4, 4), (8, 8), (16, 8)],
                size: 24,
            },
            Self::Aapcs64 => LayoutDescriptor {
                offsets: [Some(24), Some(28)],
                stack: 0,
                tops: [8, 16],
                limits: [0, 0],
                fields: &[(0, 8), (8, 8), (16, 8), (24, 4), (28, 4)],
                size: 32,
            },
            Self::Apple => LayoutDescriptor {
                offsets: [None, None],
                stack: 0,
                tops: [8, 16],
                limits: [0, 0],
                fields: &[(0, 8)],
                size: 8,
            },
        }
    }
}

struct List {
    floating: bool,
    layout: Layout,
    base: i64,
    sp: u16,
    named: i64,
}

impl List {
    fn offset(&self) -> Option<i64> {
        let Some(offset) = self.layout.descriptor().offsets[usize::from(self.floating)] else {
            return None;
        };
        self.base.checked_add(offset)
    }

    fn gp_offset(&self) -> i64 {
        self.base + self.layout.descriptor().offsets[0].unwrap_or(0)
    }

    fn step(&self) -> i64 {
        if self.floating { 16 } else { 8 }
    }

    fn stack(&self) -> i64 {
        self.base + self.layout.descriptor().stack
    }

    fn fields(&self) -> Vec<(i64, u8)> {
        self.layout
            .descriptor()
            .fields
            .iter()
            .map(|(offset, width)| (self.base + offset, *width))
            .collect()
    }

    fn states(&self) -> Vec<i64> {
        let limit = self.layout.descriptor().limits[usize::from(self.floating)];
        match self.layout {
            Layout::SysV if self.floating => (48..=limit).step_by(16).collect(),
            Layout::SysV => (self.named * 8..=limit).step_by(8).collect(),
            Layout::Aapcs64 if self.floating => (-128..=limit).step_by(16).collect(),
            Layout::Aapcs64 => ((self.named - 8) * 8..=limit).step_by(8).collect(),
            Layout::Apple => vec![0],
        }
    }
}

fn address(sp: u16, offset: i64) -> Expr {
    Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset as u64))
}

fn slot(expr: &Expr, sp: u16) -> Option<i64> {
    match expr {
        Expr::Reg { index, width: 64 } if *index == sp => Some(0),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            let Expr::Const(offset) = rhs.as_ref() else {
                return None;
            };
            let Some(base) = slot(lhs, sp) else {
                return None;
            };
            base.checked_add(*offset as i64)
        }
        _ => None,
    }
}

fn add(lhs: Expr, rhs: Expr) -> Expr {
    if matches!(lhs, Expr::Const(_)) && !matches!(rhs, Expr::Const(_)) {
        return add(rhs, lhs);
    }
    if let Expr::Bin {
        op: BinOp::Add,
        lhs: base,
        rhs: offset,
    } = &lhs
        && let (Expr::Const(a), Expr::Const(b)) = (offset.as_ref(), &rhs)
    {
        return Expr::bin(BinOp::Add, *base.clone(), Expr::Const(a.wrapping_add(*b)));
    }
    Expr::bin(BinOp::Add, lhs, rhs)
}

#[derive(Clone, Default)]
struct State {
    regs: BTreeMap<u16, Expr>,
    memory: BTreeMap<(i64, u8), Expr>,
    writes: HashSet<(i64, u8)>,
    registers: HashSet<u16>,
    argument: Option<Expr>,
}

impl State {
    fn read(&self, offset: i64, width: u8) -> Option<Expr> {
        if let Some(value) = self.memory.get(&(offset, width)) {
            return Some(value.clone());
        }
        for (&(start, size), value) in &self.memory {
            let Some(end) = start.checked_add(i64::from(size)) else {
                continue;
            };
            let Some(read_end) = offset.checked_add(i64::from(width)) else {
                continue;
            };
            if offset >= start
                && read_end <= end
                && let Expr::Const(value) = value
            {
                let shift = (offset - start) * 8;
                return Some(Expr::Const(
                    (value >> shift) & crate::ir::semantics::mask(u32::from(width) * 8),
                ));
            }
        }
        None
    }

    fn store(&mut self, offset: i64, width: u8, value: Expr) -> Option<()> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return None;
        }
        let Some(end) = offset.checked_add(i64::from(width)) else {
            return None;
        };
        self.memory.retain(|&(start, size), _| {
            start
                .checked_add(i64::from(size))
                .is_some_and(|stop| stop <= offset || start >= end)
        });
        self.memory.insert((offset, width), value);
        self.writes.insert((offset, width));
        Some(())
    }

    fn eval(
        &mut self,
        expr: &Expr,
        list: &List,
        expected: Option<&Expr>,
        register: u16,
    ) -> Option<Expr> {
        match expr {
            Expr::Const(_) => Some(expr.clone()),
            Expr::Reg { index, width } => {
                if !matches!(width, 32 | 64) {
                    return None;
                }
                let value = self
                    .regs
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| expr.clone());
                if *width == 32
                    && let Expr::Const(value) = value
                {
                    return Some(Expr::Const(value & 0xffff_ffff));
                }
                Some(if *width == 32 {
                    Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff))
                } else {
                    value
                })
            }
            Expr::Bin { op, lhs, rhs } => {
                let Some(lhs) = self.eval(lhs, list, expected, register) else {
                    return None;
                };
                let Some(rhs) = self.eval(rhs, list, expected, register) else {
                    return None;
                };
                Some(if *op == BinOp::Add {
                    add(lhs, rhs)
                } else {
                    Expr::bin(*op, lhs, rhs)
                })
            }
            Expr::SignExtend { value, width } => {
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return None;
                }
                let Some(value) = self.eval(value, list, expected, register) else {
                    return None;
                };
                match value {
                    Expr::Const(value) => Some(Expr::Const(crate::ir::semantics::sign_extend(
                        value,
                        u32::from(*width) * 8,
                    ) as u64)),
                    _ => Some(Expr::SignExtend {
                        value: Box::new(value),
                        width: *width,
                    }),
                }
            }
            Expr::Load {
                addr,
                width,
                signed,
            } => {
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return None;
                }
                let Some(addr) = self.eval(addr, list, expected, register) else {
                    return None;
                };
                if let Some(offset) = slot(&addr, list.sp) {
                    let value = self.read(offset, *width).unwrap_or(Expr::Load {
                        addr: Box::new(addr),
                        width: *width,
                        signed: *signed,
                    });
                    if *signed && let Expr::Const(value) = value {
                        return Some(Expr::Const(crate::ir::semantics::sign_extend(
                            value,
                            u32::from(*width) * 8,
                        ) as u64));
                    }
                    return Some(value);
                }
                if expected == Some(&addr)
                    && (if list.floating {
                        *width == 8
                    } else {
                        matches!(width, 4 | 8)
                    })
                    && self.argument.is_none()
                {
                    let value = Expr::Load {
                        addr: Box::new(Expr::reg(register, 64)),
                        width: *width,
                        signed: *signed,
                    };
                    self.argument = Some(value.clone());
                    return Some(value);
                }
                None
            }
            Expr::Apply { op, args } => {
                let mut values = Vec::new();
                for arg in args {
                    let Some(value) = self.eval(arg, list, expected, register) else {
                        return None;
                    };
                    values.push(value);
                }
                Some(Expr::apply(*op, values))
            }
            _ => None,
        }
    }
}

/// Recover only a complete, nonescaping list whose argument access paths agree
/// for every reachable register offset, including the exhausted state.
pub(super) fn prepare(ir: &mut FunctionIr, symbols: &Symbols) -> Option<Plan> {
    if (!ir.variadic && symbols.variadic_functions.get(&ir.addr) != Some(&ir.params.len()))
        || !ir.stack_params.is_empty()
        || !ir.landing_pads.is_empty()
        || (ir.ret_type.integer().is_none() && !ir.ret_type.is_sse_float())
        || ir.params.is_empty()
        || ir.blocks.is_empty()
        || ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            !matches!(
                stmt,
                Stmt::Assign { .. }
                    | Stmt::Store { .. }
                    | Stmt::Br { target: Some(_) }
                    | Stmt::Brif { .. }
                    | Stmt::Ret { .. }
            )
        })
    {
        return None;
    }
    if ir.params.iter().any(|param| param.name == "va_list")
        || ["va_list", "va_start", "va_arg", "va_end", "va_copy"]
            .iter()
            .any(|name| {
                symbols.reserved_names.contains(*name)
                    || ir
                        .name
                        .as_ref()
                        .is_some_and(|function| super::sanitize(function) == *name)
            })
    {
        return None;
    }
    if ir.declared_signature.as_ref().is_some_and(|signature| {
        (signature.ret.integer().is_none() && !signature.ret.is_sse_float())
            || signature
                .params
                .iter()
                .any(|(_, ty)| !matches!(ty.integer(), Some((32 | 64, _))))
    }) {
        return None;
    }
    for (index, block) in ir.blocks.iter().enumerate() {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. }
                    if !ir.blocks.iter().any(|block| block.start == *target) =>
                {
                    return None;
                }
                Stmt::Ret {
                    value:
                        Expr::Apply {
                            op: crate::ir::Operation::Results,
                            ..
                        },
                } => return None,
                _ => {}
            }
        }
        if index + 1 == ir.blocks.len()
            && !matches!(
                block.stmts.last(),
                Some(Stmt::Ret { .. } | Stmt::Br { target: Some(_) })
            )
        {
            return None;
        }
    }
    let layout = match (ir.isa, ir.convention, symbols.target_format) {
        (Isa::X86_64, Convention::SysV, Some(Format::Elf | Format::MachO | Format::Raw)) => {
            Layout::SysV
        }
        (Isa::AArch64, Convention::Aapcs64, Some(Format::Elf | Format::Raw)) => Layout::Aapcs64,
        (Isa::AArch64, Convention::Aapcs64, Some(Format::MachO)) => Layout::Apple,
        _ => return None,
    };
    if ir.params.iter().enumerate().any(|(position, param)| {
        ir.convention.arguments().get(position) != Some(&param.index)
            || !matches!(param.ty.integer(), Some((32 | 64, _)))
    }) {
        return None;
    }
    let mut candidate = ir.clone();
    candidate.variadic = true;
    let sp = crate::arch::stack_pointer(ir.isa);
    let mut used = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        used.extend(writes);
        used.extend(reads);
    }
    if used.contains(&TOP) || used.contains(&STACK) {
        return None;
    }
    let Some(register) =
        (crate::ir::VARIABLE_BASE..crate::ir::VALUE_BASE).find(|index| !used.contains(index))
    else {
        return None;
    };
    // Propagate frame addresses only when their definition is unique.
    let mut aliases = Vec::new();
    let entry_blocks = if matches!(layout, Layout::SysV) { 3 } else { 1 };
    for (block, contents) in ir.blocks.iter().enumerate().take(entry_blocks) {
        if block == 1 && matches!(layout, Layout::SysV) {
            continue;
        }
        for (position, stmt) in contents.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, value } = stmt
                && dest.width == 64
                && slot(value, sp).is_some()
                && ir
                    .blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .filter(|stmt| {
                        crate::ir::visit::statement_registers(stmt)
                            .0
                            .contains(&dest.index)
                    })
                    .count()
                    == 1
            {
                if ir
                    .blocks
                    .iter()
                    .enumerate()
                    .take(block + 1)
                    .any(|(b, contents)| {
                        contents.stmts.iter().enumerate().any(|(p, stmt)| {
                            (b < block || p < position)
                                && crate::ir::visit::statement_reads(stmt).contains(&dest.index)
                        })
                    })
                {
                    continue;
                }
                aliases.push((dest.index, value.clone()));
            }
        }
    }
    for stmt in candidate
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.stmts)
    {
        crate::ir::visit::replace_reads(stmt, &aliases);
        for expr in stmt.operands_mut() {
            normalize_frame(expr, sp);
        }
    }
    let saves = crate::analysis::variadic::register_saves(&candidate);
    if !matches!(layout, Layout::Apple) && saves.is_none() {
        return None;
    }
    let init_blocks = if saves.as_ref().is_some_and(|saves| saves.guard) {
        3
    } else {
        1
    };
    let predecessors = super::structure::compare_chain::predecessors(&candidate);
    if predecessors
        .get(&candidate.blocks[0].start)
        .copied()
        .unwrap_or(0)
        != 0
    {
        return None;
    }
    if init_blocks == 3
        && ({
            let mut edges = crate::ir::cfg::successors(&candidate, 0);
            edges.sort_unstable();
            edges != vec![1, 2]
        } || crate::ir::cfg::successors(&candidate, 1) != vec![2]
            || predecessors.get(&candidate.blocks[1].start) != Some(&1)
            || predecessors.get(&candidate.blocks[2].start) != Some(&2))
    {
        return None;
    }
    let mut initial = State::default();
    let dummy = List {
        floating: false,
        layout,
        base: 0,
        sp,
        named: ir.params.len() as i64,
    };
    for block in candidate.blocks.iter().take(init_blocks) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { dest, value } => {
                    let Some(value) = initial.eval(value, &dummy, None, register) else {
                        return None;
                    };
                    let value = match dest.width {
                        32 => Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff)),
                        64 => value,
                        _ => return None,
                    };
                    initial.regs.insert(dest.index, value);
                }
                Stmt::Store { addr, value, width } => {
                    let Some(addr) = initial.eval(addr, &dummy, None, register) else {
                        return None;
                    };
                    let Some(offset) = slot(&addr, sp) else {
                        return None;
                    };
                    let Some(value) = initial.eval(value, &dummy, None, register) else {
                        return None;
                    };
                    if initial.store(offset, *width, value).is_none() {
                        return None;
                    }
                }
                Stmt::Brif { .. } | Stmt::Br { .. } => {}
                _ => return None,
            }
        }
    }
    let incoming = address(sp, layout.descriptor().stack);
    for (&(stack, width), value) in &initial.memory {
        if width != 8 || *value != incoming {
            continue;
        }
        let Some(base) = stack.checked_sub(layout.descriptor().stack) else {
            continue;
        };
        // Keep every subsequent field and extent calculation in range.
        if base.checked_add(32).is_none() {
            continue;
        }
        for floating in [false, true] {
            let list = List {
                floating,
                layout,
                base,
                sp,
                named: ir.params.len() as i64,
            };
            if !valid_initial(&candidate, &initial, &list) {
                continue;
            }
            let mut rewritten = candidate.clone();
            let mut count = usize::from(optimized::recover(&mut rewritten, &list, register));
            loop {
                let mut found = false;
                for start in init_blocks..rewritten.blocks.len() {
                    if recover_access(&mut rewritten, &list, start, register) {
                        count += 1;
                        found = true;
                        break;
                    }
                }
                if !found {
                    break;
                }
            }
            if count == 0 {
                continue;
            }
            crate::analysis::variadic::drop_register_saves(&mut rewritten);
            for block in rewritten.blocks.iter_mut().take(init_blocks) {
                block.stmts.retain(|stmt| !matches!(stmt, Stmt::Store { addr, width, .. }
                if slot(addr, sp).is_some_and(|offset| list.fields().iter().any(|(field, size)|
                    offset >= *field && offset.checked_add(i64::from(*width)).is_some_and(|end| end <= field + i64::from(*size))
                ) || (matches!(layout, Layout::SysV | Layout::Aapcs64) && *width == 8 && offset == list.gp_offset()))));
            }
            crate::passes::dce::dce_flow(&mut rewritten);
            let saved_ranges: Vec<_> = saves
                .as_ref()
                .into_iter()
                .flat_map(|saves| &saves.stores)
                .filter_map(
                    |(block, position)| match &candidate.blocks[*block].stmts[*position] {
                        Stmt::Store { addr, width, .. } => {
                            slot(addr, sp).map(|offset| (offset, *width))
                        }
                        _ => None,
                    },
                )
                .collect();
            drop_unused_addresses(&mut rewritten, sp, &saved_ranges);
            if rewritten
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| {
                    stmt.operands()
                        .into_iter()
                        .any(|expr| references_ranges(expr, sp, &saved_ranges))
                })
            {
                continue;
            }
            // Nothing may still observe the removed list or its address.
            if rewritten
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| {
                    stmt.operands()
                        .iter()
                        .any(|expr| mentions_list(expr, &list))
                })
            {
                continue;
            }
            let mut reserved = symbols.reserved_names.clone();
            reserved.extend(symbols.functions.values().cloned());
            reserved.extend(symbols.data.values().cloned());
            reserved.extend(symbols.import_slots.values().cloned());
            reserved.extend(ir.debug_registers.iter().map(|(_, name)| name.clone()));
            reserved.extend(ir.params.iter().map(|param| param.name.clone()));
            reserved.extend(ir.debug_locals.iter().map(|local| local.name.clone()));
            for index in &used {
                reserved.insert(crate::ir::reg_name(ir.isa, *index, 64));
            }
            let name = super::vacant_name("varargs", &mut reserved);
            let result = super::vacant_name("variadic_result", &mut reserved);
            let Some(last) = ir.params.last().map(|param| param.name.clone()) else {
                continue;
            };
            *ir = rewritten;
            return Some(Plan {
                floating,
                register,
                name,
                last,
                result,
            });
        }
    }
    None
}

fn valid_initial(ir: &FunctionIr, initial: &State, list: &List) -> bool {
    if matches!(list.layout, Layout::Apple) {
        return true;
    }
    let Some(saves) = crate::analysis::variadic::register_saves(ir) else {
        return false;
    };
    let saved = |register| {
        saves.stores.iter().find_map(|(block, position)| {
            match &ir.blocks[*block].stmts[*position] {
                Stmt::Store {
                    addr,
                    value: Expr::Reg { index, .. },
                    ..
                } if *index == register => slot(addr, list.sp),
                _ => None,
            }
        })
    };
    if saves.unnamed != ir.convention.arguments()[ir.params.len()..] {
        return false;
    }
    let Some(&first) = saves.unnamed.first() else {
        return false;
    };
    let Some(gp) = saved(first) else {
        return false;
    };
    let Some(fp) = saved(ir.convention.float_arguments()[0]) else {
        return false;
    };
    let (offset, float_offset, gp_top, fp_top) = match list.layout {
        Layout::SysV => (list.named * 8, 48, gp.checked_sub(list.named * 8), Some(fp)),
        Layout::Aapcs64 => (
            (list.named - 8) * 8,
            -128,
            gp.checked_add((8 - list.named) * 8),
            fp.checked_add(128),
        ),
        Layout::Apple => return false,
    };
    let (Some(gp_top), Some(fp_top)) = (gp_top, fp_top) else {
        return false;
    };
    if matches!(list.layout, Layout::SysV) && gp_top.checked_add(48) != Some(fp_top) {
        return false;
    }
    let descriptor = list.layout.descriptor();
    let [gp_field, fp_field] = descriptor.tops;
    let Some(fp_offset_field) = descriptor.offsets[1] else {
        return false;
    };
    if saves.stores.iter().any(|(block, position)| {
        let Stmt::Store { addr, value, width } = &ir.blocks[*block].stmts[*position] else {
            return true;
        };
        let Some(offset) = slot(addr, list.sp) else {
            return true;
        };
        initial.read(offset, *width).as_ref() != Some(value)
    }) {
        return false;
    }
    initial.read(list.gp_offset(), 4) == Some(Expr::Const(offset as u32 as u64))
        && initial.read(list.base + fp_offset_field, 4)
            == Some(Expr::Const(float_offset as u32 as u64))
        && initial.read(list.base + gp_field, 8) == Some(address(list.sp, gp_top))
        && (!matches!(list.layout, Layout::Aapcs64)
            || initial.read(list.base + fp_field, 8) == Some(address(list.sp, fp_top)))
}

fn mentions_list(expr: &Expr, list: &List) -> bool {
    if let Some(offset) = slot(expr, list.sp)
        && offset >= list.base
        && offset < list.base + list.layout.descriptor().size
    {
        return true;
    }
    crate::ir::visit::children(expr)
        .into_iter()
        .any(|expr| mentions_list(expr, list))
}

struct Access {
    positions: HashSet<(usize, usize)>,
    stop: (usize, usize),
    replacement: Stmt,
    writes: HashSet<(i64, u8)>,
    registers: HashSet<u16>,
}

fn trace(ir: &FunctionIr, list: &List, start: usize, offset: i64, register: u16) -> Option<Access> {
    let mut state = State::default();
    state.memory.insert((list.stack(), 8), Expr::reg(STACK, 64));
    if let Some(field) = list.offset() {
        state
            .memory
            .insert((field, 4), Expr::Const(offset as u32 as u64));
    }
    let descriptor = list.layout.descriptor();
    let top_field = list.base + descriptor.tops[usize::from(list.floating)];
    if !matches!(list.layout, Layout::Apple) {
        state.memory.insert((top_field, 8), Expr::reg(TOP, 64));
    }
    let in_register = match list.layout {
        Layout::SysV | Layout::Aapcs64 => offset < descriptor.limits[usize::from(list.floating)],
        Layout::Apple => false,
    };
    let expected = if in_register {
        address(TOP, offset)
    } else {
        Expr::reg(STACK, 64)
    };
    let mut positions = HashSet::new();
    let mut block = start;
    for _ in 0..32 {
        let mut next = block.checked_add(1);
        let Some(contents) = ir.blocks.get(block) else {
            return None;
        };
        for (position, stmt) in contents.stmts.iter().enumerate() {
            let mut replacement = stmt.clone();
            let mut failed = false;
            for operand in replacement.operands_mut() {
                match state.eval(operand, list, Some(&expected), register) {
                    Some(value) => *operand = value,
                    None => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                return None;
            }
            if state.argument.is_some() {
                let expected_offset = if in_register {
                    offset + list.step()
                } else {
                    offset
                };
                if let Some(field) = list.offset()
                    && state.read(field, 4) != Some(Expr::Const(expected_offset as u32 as u64))
                {
                    return None;
                }
                let stack = if in_register {
                    Expr::reg(STACK, 64)
                } else {
                    address(STACK, 8)
                };
                if state.read(list.stack(), 8) != Some(stack) {
                    return None;
                }
                return Some(Access {
                    positions,
                    stop: (block, position),
                    replacement,
                    writes: state.writes,
                    registers: state.registers,
                });
            }
            if !positions.insert((block, position)) {
                return None;
            }
            match replacement {
                Stmt::Assign { dest, value } if matches!(dest.width, 32 | 64) => {
                    let value = if dest.width == 32 {
                        Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff))
                    } else {
                        value
                    };
                    state.regs.insert(dest.index, value);
                    state.registers.insert(dest.index);
                }
                Stmt::Store { addr, value, width } => {
                    let Some(offset) = slot(&addr, list.sp) else {
                        return None;
                    };
                    if list.fields().iter().any(|(field, size)| {
                        offset
                            .checked_add(i64::from(width))
                            .is_none_or(|end| offset < field + i64::from(*size) && end > *field)
                    }) && !((Some(offset) == list.offset() && width == 4)
                        || (offset == list.stack() && width == 8))
                    {
                        return None;
                    }
                    if state.store(offset, width, value).is_none() {
                        return None;
                    }
                }
                Stmt::Br {
                    target: Some(target),
                } => {
                    next = ir.blocks.iter().position(|block| block.start == target);
                    break;
                }
                Stmt::Brif {
                    cond,
                    lhs: Expr::Const(lhs),
                    rhs: Expr::Const(rhs),
                    target,
                } => {
                    let bits = match stmt {
                        Stmt::Brif { lhs, rhs, .. } => {
                            crate::ir::semantics::operand_width(lhs, rhs)
                        }
                        _ => 64,
                    };
                    if crate::ir::semantics::holds(cond, lhs, rhs, bits) {
                        next = ir.blocks.iter().position(|block| block.start == target);
                    }
                    break;
                }
                _ => return None,
            }
        }
        let Some(next) = next else {
            return None;
        };
        block = next;
    }
    None
}

fn recover_access(ir: &mut FunctionIr, list: &List, start: usize, register: u16) -> bool {
    if matches!(list.layout, Layout::Apple) {
        return recover_apple(ir, list, start, register);
    }
    let mut accesses = Vec::new();
    for offset in list.states() {
        let Some(access) = trace(ir, list, start, offset, register) else {
            return false;
        };
        accesses.push(access);
    }
    let Some(first) = accesses.first() else {
        return false;
    };
    if accesses.iter().any(|access| {
        access.stop != first.stop || access.replacement.operands() != first.replacement.operands()
    }) {
        return false;
    }
    let mut positions: HashSet<_> = accesses
        .iter()
        .flat_map(|access| access.positions.iter().copied())
        .collect();
    if positions.is_empty() {
        return false;
    }
    let registers: HashSet<_> = accesses
        .iter()
        .flat_map(|access| access.registers.iter().copied())
        .collect();
    let writes: HashSet<_> = accesses
        .iter()
        .flat_map(|access| access.writes.iter().copied())
        .collect();
    let stop = first.stop;
    let replacement = first.replacement.clone();
    // A branch block that no valid offset takes can still enter the expansion.
    // Include these empty paths in the checks for external predecessors.
    let mut targets: HashSet<u64> = positions
        .iter()
        .filter(|(block, _)| *block != start)
        .map(|(block, _)| ir.blocks[*block].start)
        .chain(std::iter::once(ir.blocks[stop.0].start))
        .collect();
    loop {
        let before = positions.len();
        for (block, contents) in ir.blocks.iter().enumerate() {
            if block == 0 || block == start || block == stop.0 {
                continue;
            }
            if let [
                Stmt::Br {
                    target: Some(target),
                },
            ] = contents.stmts.as_slice()
                && targets.contains(target)
            {
                positions.insert((block, 0));
                targets.insert(contents.start);
            }
        }
        if positions.len() == before {
            break;
        }
    }
    // Every deleted definition must be used entirely inside the expansion.
    let temporaries: Vec<_> = writes
        .iter()
        .filter(|(offset, _)| !list.fields().iter().any(|(field, _)| field == offset))
        .copied()
        .collect();
    for (b, block) in ir.blocks.iter().enumerate() {
        for (p, stmt) in block.stmts.iter().enumerate() {
            if positions.contains(&(b, p)) {
                continue;
            }
            let stmt = if (b, p) == stop { &replacement } else { stmt };
            if crate::ir::visit::statement_reads(stmt)
                .iter()
                .any(|index| registers.contains(index))
            {
                return false;
            }
            if stmt
                .operands()
                .iter()
                .any(|expr| references_ranges(expr, list.sp, &temporaries))
            {
                return false;
            }
            if stmt
                .operands()
                .iter()
                .any(|expr| reads_slots(expr, list.sp, &writes))
            {
                return false;
            }
        }
    }
    let removed: HashSet<_> = positions
        .iter()
        .map(|(block, _)| *block)
        .filter(|block| *block != start && *block != stop.0)
        .collect();
    for &block in &removed {
        if ir.blocks[block]
            .stmts
            .iter()
            .enumerate()
            .any(|(position, _)| !positions.contains(&(block, position)))
        {
            return false;
        }
    }
    let predecessors = super::structure::compare_chain::predecessors(ir);
    for block in removed.iter().copied().chain(std::iter::once(stop.0)) {
        if block == start {
            return false;
        }
        let internal = removed
            .iter()
            .copied()
            .chain(std::iter::once(start))
            .filter(|pred| crate::ir::cfg::successors(ir, *pred).contains(&block))
            .count();
        if predecessors
            .get(&ir.blocks[block].start)
            .copied()
            .unwrap_or(0)
            != internal
        {
            return false;
        }
    }
    let target = ir.blocks[stop.0].start;
    ir.blocks[stop.0].stmts[stop.1] = replacement;
    for (block, contents) in ir.blocks.iter_mut().enumerate() {
        let mut p = 0;
        contents.stmts.retain(|_| {
            let keep = !positions.contains(&(block, p));
            p += 1;
            keep
        });
    }
    ir.blocks[start].stmts.push(Stmt::Br {
        target: Some(target),
    });
    let mut b = 0;
    ir.blocks.retain(|_| {
        let keep = !removed.contains(&b);
        b += 1;
        keep
    });
    true
}

fn reads_slots(expr: &Expr, sp: u16, writes: &HashSet<(i64, u8)>) -> bool {
    if let Expr::Load { addr, width, .. } = expr
        && slot(addr, sp).is_some_and(|offset| {
            writes.iter().any(|(start, size)| {
                offset
                    .checked_add(i64::from(*width))
                    .is_none_or(|end| offset < start + i64::from(*size) && end > *start)
            })
        })
    {
        return true;
    }
    crate::ir::visit::children(expr)
        .into_iter()
        .any(|expr| reads_slots(expr, sp, writes))
}

fn recover_apple(ir: &mut FunctionIr, list: &List, block: usize, register: u16) -> bool {
    let types = super::function::variable_types(ir);
    for position in 0..ir.blocks[block].stmts.len().saturating_sub(2) {
        let stmts = &ir.blocks[block].stmts[position..position + 3];
        let [
            Stmt::Assign {
                dest: cursor,
                value: Expr::Load { addr, width: 8, .. },
            },
            Stmt::Assign {
                dest,
                value:
                    Expr::Load {
                        addr: argument,
                        width,
                        signed,
                    },
            },
            Stmt::Store {
                addr: updated,
                value,
                width: 8,
            },
        ] = stmts
        else {
            continue;
        };
        let floating = types.get(&dest.index).is_some_and(|ty| ty.is_sse_float());
        if !matches!(width, 4 | 8) || floating != list.floating || (floating && *width != 8) {
            continue;
        }
        if cursor.width != 64
            || slot(addr, list.sp) != Some(list.base)
            || **argument != Expr::reg(cursor.index, 64)
            || slot(updated, list.sp) != Some(list.base)
            || *value != address(cursor.index, 8)
            || dest.index == cursor.index
        {
            continue;
        }
        if ir.blocks.iter().enumerate().any(|(b, contents)| {
            contents.stmts.iter().enumerate().any(|(p, stmt)| {
                !(b == block && (position..position + 3).contains(&p))
                    && crate::ir::visit::statement_reads(stmt).contains(&cursor.index)
            })
        }) {
            continue;
        }
        let replacement = Stmt::Assign {
            dest: *dest,
            value: Expr::Load {
                addr: Box::new(Expr::reg(register, 64)),
                width: *width,
                signed: *signed,
            },
        };
        ir.blocks[block]
            .stmts
            .splice(position..position + 3, [replacement]);
        return true;
    }
    false
}

fn normalize_frame(expr: &mut Expr, sp: u16) {
    for child in crate::ir::visit::children_mut(expr) {
        normalize_frame(child, sp);
    }
    if let Some(offset) = slot(expr, sp) {
        *expr = address(sp, offset);
    }
}

fn references_ranges(expr: &Expr, sp: u16, ranges: &[(i64, u8)]) -> bool {
    if let Some(offset) = slot(expr, sp)
        && ranges.iter().any(|(start, width)| {
            offset >= *start
                && start
                    .checked_add(i64::from(*width))
                    .is_some_and(|end| offset < end)
        })
    {
        return true;
    }
    crate::ir::visit::children(expr)
        .into_iter()
        .any(|expr| references_ranges(expr, sp, ranges))
}

fn drop_unused_addresses(ir: &mut FunctionIr, sp: u16, saved: &[(i64, u8)]) {
    let mut omitted = ir.clone();
    let mut slots = HashSet::new();
    for block in &mut omitted.blocks {
        block.stmts.retain(|stmt| {
            let Stmt::Store { addr, value, width } = stmt else {
                return true;
            };
            let Some(offset) = slot(addr, sp) else {
                return true;
            };
            if offset >= 0
                || offset
                    .checked_add(i64::from(*width))
                    .is_none_or(|end| end > 0)
                || !references_ranges(value, sp, saved)
            {
                return true;
            }
            slots.insert((offset, *width));
            false
        });
    }
    if slots.is_empty() || crate::passes::memory::frame_address_escapes(&omitted, sp) {
        return;
    }
    let ranges: Vec<_> = slots.iter().copied().collect();
    if omitted
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| {
            stmt.operands()
                .into_iter()
                .any(|expr| references_ranges(expr, sp, &ranges) || reads_slots(expr, sp, &slots))
        })
    {
        return;
    }
    *ir = omitted;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_fields_and_exhausted_states_keep_their_offsets() {
        let cases = [
            (
                Layout::SysV,
                false,
                Some(100),
                100,
                108,
                116,
                vec![(100, 4), (104, 4), (108, 8), (116, 8)],
                vec![16, 24, 32, 40, 48],
            ),
            (
                Layout::SysV,
                true,
                Some(104),
                100,
                108,
                116,
                vec![(100, 4), (104, 4), (108, 8), (116, 8)],
                vec![48, 64, 80, 96, 112, 128, 144, 160, 176],
            ),
            (
                Layout::Aapcs64,
                false,
                Some(124),
                124,
                100,
                108,
                vec![(100, 8), (108, 8), (116, 8), (124, 4), (128, 4)],
                vec![-48, -40, -32, -24, -16, -8, 0],
            ),
            (
                Layout::Aapcs64,
                true,
                Some(128),
                124,
                100,
                116,
                vec![(100, 8), (108, 8), (116, 8), (124, 4), (128, 4)],
                vec![-128, -112, -96, -80, -64, -48, -32, -16, 0],
            ),
            (
                Layout::Apple,
                false,
                None,
                100,
                100,
                108,
                vec![(100, 8)],
                vec![0],
            ),
            (
                Layout::Apple,
                true,
                None,
                100,
                100,
                116,
                vec![(100, 8)],
                vec![0],
            ),
        ];
        for (layout, floating, offset, gp, stack, top, fields, states) in cases {
            let list = List {
                floating,
                layout,
                base: 100,
                sp: 0,
                named: 2,
            };
            assert_eq!(list.offset(), offset);
            assert_eq!(list.gp_offset(), gp);
            assert_eq!(list.stack(), stack);
            assert_eq!(
                list.base + layout.descriptor().tops[usize::from(floating)],
                top
            );
            assert_eq!(list.fields(), fields);
            assert_eq!(list.states(), states);
        }
    }
}
