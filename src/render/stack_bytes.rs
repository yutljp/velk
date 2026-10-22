use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};

const LIMIT: usize = 64 * 8;
type Origins = BTreeMap<u16, Option<i64>>;
type Written = [bool; LIMIT];

#[derive(Clone, Copy)]
struct Frame {
    sp: u16,
    start: i64,
    limit: i64,
}

pub(super) struct Plan {
    pub register: u16,
    pub name: String,
    pub size: usize,
    pub seeds: Vec<(usize, String)>,
    pub accesses: BTreeSet<(usize, u8)>,
}

impl Plan {
    pub fn declarations(&self) -> Vec<String> {
        let mut lines = vec![format!("unsigned char {}[0x{:x}];", self.name, self.size)];
        lines.extend(self.seeds.iter().map(|(offset, name)| {
            format!(
                "__builtin_memcpy({} + 0x{offset:x}, &(uint64_t){{(uint64_t){name}}}, 8);",
                self.name
            )
        }));
        lines
    }

    pub fn address(&self, offset: usize) -> Expr {
        address(self.register, offset as i64)
    }
}

/// Normalize proven frame addresses, adding storage only for crossing accesses.
pub(super) fn prepare(ir: &mut FunctionIr) -> Option<Plan> {
    let mut rewritten = ir.clone();
    let plan = prepare_inner(&mut rewritten)?;
    *ir = rewritten;
    plan
}

fn prepare_inner(ir: &mut FunctionIr) -> Option<Option<Plan>> {
    if ir.blocks.is_empty() || !ir.landing_pads.is_empty() || ir.variadic {
        return None;
    }
    let start = ir.convention.stack_arguments()?;
    let limit = start.checked_add(LIMIT as i64)?;
    let sp = crate::arch::stack_pointer(ir.isa);
    let frame = Frame { sp, start, limit };
    let mut entry = Origins::from([(sp, Some(0))]);
    for (&variable, &register) in &ir.variable_registers {
        if register == sp && variable != sp {
            entry.insert(variable, None);
        }
    }
    let entries = origins(ir, &entry)?;
    let mut seeds = Vec::new();
    let mut initialized = [false; LIMIT];
    let mut size = 0;
    for param in &ir.stack_params {
        if param.size != 8 || !matches!(param.ty, CType::Int { bytes: 8, .. }) {
            return None;
        }
        let offset = usize::try_from(param.offset.checked_sub(start)?).ok()?;
        let end = offset.checked_add(8)?;
        if offset % 8 != 0 || end > LIMIT || initialized[offset..end].iter().any(|bit| *bit) {
            return None;
        }
        initialized[offset..end].fill(true);
        seeds.push((offset, param.name.clone()));
        size = size.max(end);
    }
    let mut used = BTreeSet::new();
    used.extend(ir.params.iter().map(|param| param.index));
    used.extend(ir.variable_registers.keys().copied());
    used.extend(ir.variable_registers.values().copied());
    used.extend(ir.value_types.keys().copied());
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        used.extend(writes);
        used.extend(reads);
    }
    let register = used
        .last()
        .copied()?
        .max(crate::ir::VARIABLE_BASE)
        .checked_add(1)?;
    if register >= crate::ir::VALUE_BASE {
        return None;
    }
    let mut plan = Plan {
        register,
        name: String::new(),
        size,
        seeds,
        accesses: BTreeSet::new(),
    };
    let mut crossing = false;
    let mut facts = Vec::new();
    let variable_registers = &ir.variable_registers;
    for (block, body) in ir.blocks.iter_mut().enumerate() {
        let mut state = entries[block].clone()?;
        let mut rewritten = Vec::new();
        let mut block_facts = Vec::new();
        for mut stmt in std::mem::take(&mut body.stmts) {
            let unnamed = stmt.unnamed_call_reads();
            if state.keys().any(|register| {
                unnamed.contains(register)
                    || variable_registers
                        .get(register)
                        .is_some_and(|physical| unnamed.contains(physical))
            }) {
                return None;
            }
            let original = stmt.clone();
            let mut accesses = Vec::new();
            let remove = if let Stmt::Assign { dest, value } = &stmt {
                match origin(value, &state) {
                    Some(Some(_)) if dest.width == 64 => true,
                    Some(_) => return None,
                    None if dest.index == sp => return None,
                    None => false,
                }
            } else {
                false
            };
            if !remove {
                match &mut stmt {
                    Stmt::Store { addr, value, width } => {
                        rewrite_value(value, &state, frame, &mut plan, &mut accesses)?;
                        if let Some(offset) =
                            rewrite_address(addr, *width, &state, frame, &mut plan, &mut accesses)?
                        {
                            accesses.push((offset, *width, true));
                        }
                    }
                    Stmt::Call { args: None, .. } => return None,
                    Stmt::Unsupported { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Br { target: None } => return None,
                    _ => {
                        for value in stmt.operands_mut() {
                            rewrite_value(value, &state, frame, &mut plan, &mut accesses)?;
                        }
                    }
                }
                for &(offset, width, _) in &accesses {
                    crossing |= offset % 8 + usize::from(width) > 8;
                }
                block_facts.extend(accesses);
                rewritten.push(stmt);
            }
            transfer(&original, &mut state);
        }
        body.stmts = rewritten;
        facts.push(block_facts);
    }
    initialized_reads(ir, &facts, initialized)?;
    if !crossing {
        if plan.accesses.is_empty()
            || plan.accesses.iter().any(|&(offset, width)| {
                !plan
                    .seeds
                    .iter()
                    .any(|&(start, _)| start <= offset && offset + usize::from(width) <= start + 8)
            })
        {
            return None;
        }
        let root = Origins::from([(plan.register, Some(start))]);
        for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            for value in stmt.operands_mut() {
                restore_frame(value, &root, sp)?;
            }
        }
        return Some(None);
    }
    protect_parameter_names(ir);
    plan.seeds = ir
        .stack_params
        .iter()
        .map(|param| {
            (
                usize::try_from(param.offset - start).expect("validated incoming offset"),
                param.name.clone(),
            )
        })
        .collect();
    Some(Some(plan))
}

fn restore_frame(expr: &mut Expr, root: &Origins, sp: u16) -> Option<()> {
    if let Some(offset) = origin(expr, root) {
        *expr = address(sp, offset?);
        return Some(());
    }
    for child in crate::ir::visit::children_mut(expr) {
        restore_frame(child, root, sp)?;
    }
    Some(())
}

fn protect_parameter_names(ir: &mut FunctionIr) {
    let protected: BTreeSet<_> = [
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uintptr_t",
        "bool",
        "__builtin_memcpy",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut reserved: std::collections::HashSet<_> = protected
        .iter()
        .cloned()
        .chain(ir.params.iter().map(|param| super::sanitize(&param.name)))
        .chain(
            ir.stack_params
                .iter()
                .map(|param| super::sanitize(&param.name)),
        )
        .collect();
    for name in ir
        .params
        .iter_mut()
        .map(|param| &mut param.name)
        .chain(ir.stack_params.iter_mut().map(|param| &mut param.name))
    {
        if protected.contains(name) {
            *name = super::vacant_name(name, &mut reserved);
        }
    }
}

fn origin(expr: &Expr, state: &Origins) -> Option<Option<i64>> {
    match expr {
        Expr::Reg { index, width: 64 } => state.get(index).copied(),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (value, Expr::Const(delta)) | (Expr::Const(delta), value) => origin(value, state)
                .map(|base| base.and_then(|base| base.checked_add(*delta as i64))),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => {
            let Expr::Const(delta) = rhs.as_ref() else {
                return None;
            };
            origin(lhs, state).map(|base| base.and_then(|base| base.checked_sub(*delta as i64)))
        }
        _ => None,
    }
}

fn contains_origin(expr: &Expr, state: &Origins) -> bool {
    match expr {
        Expr::Reg { index, .. } => state.contains_key(index),
        _ => crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| contains_origin(child, state)),
    }
}

fn transfer(stmt: &Stmt, state: &mut Origins) {
    let assigned = match stmt {
        Stmt::Assign { dest, value } if dest.width == 64 => origin(value, state),
        Stmt::Assign { value, .. } if contains_origin(value, state) => Some(None),
        _ => None,
    };
    for register in crate::ir::visit::statement_registers(stmt).0 {
        if let Some(origin) = state.get_mut(&register) {
            *origin = None;
        }
    }
    if let Stmt::Assign { dest, .. } = stmt {
        if let Some(value) = assigned {
            state.insert(dest.index, value);
        } else {
            state.remove(&dest.index);
        }
    }
}

fn origins(ir: &FunctionIr, entry: &Origins) -> Option<Vec<Option<Origins>>> {
    let mut entries = vec![None; ir.blocks.len()];
    entries[0] = Some(entry.clone());
    let mut pending = VecDeque::from([0]);
    while let Some(block) = pending.pop_front() {
        let mut state = entries[block].clone()?;
        for stmt in &ir.blocks[block].stmts {
            transfer(stmt, &mut state);
        }
        for next in crate::ir::cfg::successors(ir, block) {
            let changed = match &mut entries[next] {
                None => {
                    entries[next] = Some(state.clone());
                    true
                }
                Some(previous) => {
                    let keys: BTreeSet<_> = previous.keys().chain(state.keys()).copied().collect();
                    let mut changed = false;
                    for register in keys {
                        if previous.get(&register) != state.get(&register)
                            && previous.get(&register) != Some(&None)
                        {
                            previous.insert(register, None);
                            changed = true;
                        }
                    }
                    changed
                }
            };
            if changed && !pending.contains(&next) {
                pending.push_back(next);
            }
        }
    }
    Some(entries)
}

fn rewrite_value(
    expr: &mut Expr,
    state: &Origins,
    frame: Frame,
    plan: &mut Plan,
    facts: &mut Vec<(usize, u8, bool)>,
) -> Option<()> {
    if let Expr::Load { addr, width, .. } = expr {
        if let Some(offset) = rewrite_address(addr, *width, state, frame, plan, facts)? {
            facts.push((offset, *width, false));
        }
        return Some(());
    }
    if matches!(expr, Expr::Reg { index, .. } if state.contains_key(index)) {
        return None;
    }
    for child in crate::ir::visit::children_mut(expr) {
        rewrite_value(child, state, frame, plan, facts)?;
    }
    Some(())
}

fn rewrite_address(
    expr: &mut Expr,
    width: u8,
    state: &Origins,
    frame: Frame,
    plan: &mut Plan,
    facts: &mut Vec<(usize, u8, bool)>,
) -> Option<Option<usize>> {
    match origin(expr, state) {
        Some(Some(offset)) => {
            if !matches!(width, 1 | 2 | 4 | 8) {
                return None;
            }
            let end = offset.checked_add(i64::from(width))?;
            if offset < frame.start {
                if end > frame.start {
                    return None;
                }
                *expr = address(frame.sp, offset);
                return Some(None);
            }
            if end > frame.limit {
                return None;
            }
            let offset = usize::try_from(offset.checked_sub(frame.start)?).ok()?;
            plan.size = plan.size.max(offset.checked_add(usize::from(width))?);
            plan.accesses.insert((offset, width));
            *expr = plan.address(offset);
            Some(Some(offset))
        }
        Some(None) => None,
        None => {
            // A non-frame address may itself be loaded from the incoming frame.
            rewrite_value(expr, state, frame, plan, facts)?;
            Some(None)
        }
    }
}

fn address(register: u16, offset: i64) -> Expr {
    if offset == 0 {
        Expr::reg(register, 64)
    } else {
        Expr::bin(
            BinOp::Add,
            Expr::reg(register, 64),
            Expr::Const(offset as u64),
        )
    }
}

fn initialized_reads(
    ir: &FunctionIr,
    facts: &[Vec<(usize, u8, bool)>],
    seeded: Written,
) -> Option<()> {
    let mut entries = vec![None; ir.blocks.len()];
    entries[0] = Some(seeded);
    let mut pending = VecDeque::from([0]);
    while let Some(block) = pending.pop_front() {
        let mut written = entries[block]?;
        for &(offset, width, store) in &facts[block] {
            if store {
                written[offset..offset + usize::from(width)].fill(true);
            }
        }
        for next in crate::ir::cfg::successors(ir, block) {
            let merged = match entries[next] {
                None => written,
                Some(previous) => std::array::from_fn(|byte| previous[byte] && written[byte]),
            };
            if entries[next] != Some(merged) {
                entries[next] = Some(merged);
                pending.push_back(next);
            }
        }
    }
    for (block, accesses) in facts.iter().enumerate() {
        let mut written = entries[block]?;
        for &(offset, width, store) in accesses {
            let bytes = &mut written[offset..offset + usize::from(width)];
            if store {
                bytes.fill(true);
            } else if bytes.iter().any(|bit| !*bit) {
                return None;
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Block, Convention, RegRef, StackParam, eval};
    use crate::loader::Isa;

    fn at(register: u16, offset: i64) -> Expr {
        address(register, offset)
    }

    fn load(offset: i64, width: u8) -> Expr {
        Expr::Load {
            addr: Box::new(at(31, offset)),
            width,
            signed: false,
        }
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn function(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.convention = Convention::Aapcs64;
        ir.stack_params = (0..3)
            .map(|slot| StackParam {
                offset: slot * 8,
                size: 8,
                name: format!("a{slot}"),
                ty: if slot == 1 { CType::I64 } else { CType::U64 },
                position: slot as usize,
            })
            .collect();
        ir
    }

    fn outcome(ir: &FunctionIr, root: u16) -> eval::Outcome {
        eval::run(
            ir,
            &eval::Setup {
                seed: 13,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(root, eval::STACK_TOP)],
                memory: &[
                    (eval::STACK_TOP, 0x7766_5544_3322_1100),
                    (eval::STACK_TOP + 8, 0xffee_ddcc_bbaa_9988),
                    (eval::STACK_TOP + 16, 0x0123_4567_89ab_cdef),
                ],
                step_limit: 1000,
            },
        )
    }

    #[test]
    fn held_parameter_addresses_keep_reads_before_writes_without_an_array() {
        let held = crate::ir::VARIABLE_BASE;
        let saved = held + 1;
        let indirect = || Expr::Load {
            addr: Box::new(Expr::reg(held, 64)),
            width: 8,
            signed: false,
        };
        let written = 0x0123_4567_89ab_cdef;
        let original = function(vec![
            assign(held, at(31, 8)),
            assign(saved, indirect()),
            Stmt::Store {
                addr: Expr::reg(held, 64),
                value: Expr::Const(written),
                width: 8,
            },
            Stmt::Store {
                addr: Expr::Const(0x1000),
                value: indirect(),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(saved, 64),
            },
        ]);
        let expected = eval::Outcome::Return {
            value: 0xffee_ddcc_bbaa_9988,
            calls: Vec::new(),
            memory: written
                .to_le_bytes()
                .into_iter()
                .enumerate()
                .map(|(byte, value)| (0x1000 + byte as u64, value))
                .collect(),
        };
        assert_eq!(outcome(&original, u16::MAX), expected);
        let mut normalized = original.clone();
        assert!(prepare(&mut normalized).is_none());
        assert_eq!(outcome(&normalized, u16::MAX), expected);
        assert_eq!(normalized.stack_params, original.stack_params);
        assert!(
            !normalized.blocks[0]
                .stmts
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == held))
        );
        let code = crate::render::render(&original, &[], &super::super::Symbols::default(), &[]);
        assert!(!code.contains("incoming_bytes"), "{code}");
        assert!(!code.contains("(sp"), "{code}");
    }

    #[test]
    fn held_scalar_parts_preserve_signed_extension_without_an_array() {
        let held = crate::ir::VARIABLE_BASE;
        for signed in [false, true] {
            let original = function(vec![
                assign(held, at(31, 8)),
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(at(held, 4)),
                        width: 4,
                        signed,
                    },
                },
            ]);
            let expected = eval::Outcome::Return {
                value: if signed {
                    (0xffee_ddccu32 as i32) as i64 as u64
                } else {
                    0xffee_ddcc
                },
                calls: Vec::new(),
                memory: Default::default(),
            };
            assert_eq!(outcome(&original, u16::MAX), expected);
            let mut normalized = original.clone();
            assert!(prepare(&mut normalized).is_none());
            assert_eq!(outcome(&normalized, u16::MAX), expected);
            let code =
                crate::render::render(&original, &[], &super::super::Symbols::default(), &[]);
            assert!(!code.contains("incoming_bytes"), "{code}");
            assert!(!code.contains("(sp"), "{code}");
        }
    }

    #[test]
    fn held_and_current_frame_addresses_keep_distinct_offsets_without_an_array() {
        let held = crate::ir::VARIABLE_BASE;
        let original = function(vec![
            assign(held, at(31, 8)),
            assign(31, at(31, 8)),
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::Load {
                        addr: Box::new(Expr::reg(held, 64)),
                        width: 8,
                        signed: false,
                    },
                    load(8, 8),
                ),
            },
        ]);
        let expected = eval::Outcome::Return {
            value: 0xffee_ddcc_bbaa_9988 ^ 0x0123_4567_89ab_cdef,
            calls: Vec::new(),
            memory: Default::default(),
        };
        assert_eq!(outcome(&original, u16::MAX), expected);
        let mut normalized = original;
        assert!(prepare(&mut normalized).is_none());
        assert_eq!(outcome(&normalized, u16::MAX), expected);
        assert_eq!(normalized.blocks[0].stmts.len(), 1);
    }

    #[test]
    fn unbound_wide_or_escaping_held_accesses_do_not_commit() {
        let held = crate::ir::VARIABLE_BASE;
        let indirect = |width| Expr::Load {
            addr: Box::new(Expr::reg(held, 64)),
            width,
            signed: false,
        };
        for stmts in [
            vec![assign(held, at(31, 24)), Stmt::Ret { value: indirect(8) }],
            vec![
                assign(held, at(31, 24)),
                Stmt::Store {
                    addr: Expr::reg(held, 64),
                    value: Expr::Const(17),
                    width: 8,
                },
                Stmt::Ret { value: indirect(8) },
            ],
            vec![
                assign(held, at(31, 0)),
                Stmt::Ret {
                    value: indirect(16),
                },
            ],
            vec![
                assign(held, at(31, 0)),
                Stmt::Ret {
                    value: Expr::reg(held, 64),
                },
            ],
        ] {
            let mut ir = function(stmts);
            let before = format!("{ir:?}");
            assert!(prepare(&mut ir).is_none());
            assert_eq!(format!("{ir:?}"), before);
        }
    }

    #[test]
    fn crossing_reads_and_overlapping_writes_preserve_all_words() {
        for width in [2, 4, 8] {
            let original = function(vec![
                Stmt::Store {
                    addr: at(31, 7),
                    value: load(4, width),
                    width,
                },
                Stmt::Store {
                    addr: Expr::Const(0x1000),
                    value: load(0, 8),
                    width: 8,
                },
                Stmt::Store {
                    addr: Expr::Const(0x1008),
                    value: load(8, 8),
                    width: 8,
                },
                Stmt::Store {
                    addr: Expr::Const(0x1010),
                    value: load(16, 8),
                    width: 8,
                },
                Stmt::Ret { value: load(4, 8) },
            ]);
            let mut rewritten = original.clone();
            let plan = prepare(&mut rewritten).expect("complete raw words");
            assert_eq!(
                outcome(&original, plan.register),
                outcome(&rewritten, plan.register)
            );
            assert_eq!(rewritten.stack_params, original.stack_params);
            assert!(rewritten.declared_signature.is_none());
        }
    }

    #[test]
    fn frame_and_held_addresses_are_normalized_at_their_uses() {
        let held = crate::ir::VARIABLE_BASE;
        let original = function(vec![
            assign(
                31,
                Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(32)),
            ),
            assign(29, Expr::reg(31, 64)),
            assign(held, at(29, 36)),
            assign(31, at(31, 16)),
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::reg(held, 64)),
                    width: 8,
                    signed: false,
                },
            },
        ]);
        let mut rewritten = original.clone();
        let plan = prepare(&mut rewritten).unwrap();
        assert_eq!(
            outcome(&original, plan.register),
            outcome(&rewritten, plan.register)
        );
        assert_eq!(rewritten.blocks[0].stmts.len(), 1);
    }

    #[test]
    fn the_same_address_text_at_different_frame_heights_is_not_conflated() {
        let original = function(vec![
            assign(crate::ir::VARIABLE_BASE, load(4, 8)),
            assign(31, at(31, 8)),
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::reg(crate::ir::VARIABLE_BASE, 64),
                    load(4, 8),
                ),
            },
        ]);
        let mut rewritten = original.clone();
        let plan = prepare(&mut rewritten).unwrap();
        assert!(plan.accesses.contains(&(4, 8)));
        assert!(plan.accesses.contains(&(12, 8)));
        assert_eq!(
            outcome(&original, plan.register),
            outcome(&rewritten, plan.register)
        );
    }

    fn diamond(write_right: bool) -> FunctionIr {
        let store = || Stmt::Store {
            addr: at(31, 8),
            value: Expr::Const(17),
            width: 8,
        };
        let mut ir = function(Vec::new());
        ir.stack_params.truncate(1);
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(0),
                    target: 20,
                }],
            },
            Block {
                start: 10,
                stmts: vec![store(), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 20,
                stmts: if write_right {
                    vec![store(), Stmt::Br { target: Some(30) }]
                } else {
                    vec![Stmt::Br { target: Some(30) }]
                },
            },
            Block {
                start: 30,
                stmts: vec![Stmt::Ret { value: load(4, 8) }],
            },
        ];
        ir
    }

    #[test]
    fn unseeded_bytes_require_initialization_on_every_path() {
        assert!(prepare(&mut diamond(true)).is_some());
        let mut partial = diamond(false);
        let before = format!("{partial:?}");
        assert!(prepare(&mut partial).is_none());
        assert_eq!(format!("{partial:?}"), before);
        let mut stored = function(vec![
            Stmt::Store {
                addr: at(31, 4),
                value: Expr::Const(0x8877_6655_4433_2211),
                width: 8,
            },
            Stmt::Ret { value: load(4, 8) },
        ]);
        stored.stack_params.clear();
        let original = stored.clone();
        let plan = prepare(&mut stored).unwrap();
        assert!(plan.seeds.is_empty());
        assert_eq!(
            outcome(&original, plan.register),
            outcome(&stored, plan.register)
        );
    }

    #[test]
    fn held_origins_merge_only_when_their_offsets_agree() {
        let held = crate::ir::VARIABLE_BASE;
        for right in [4, 12] {
            let mut ir = function(Vec::new());
            ir.blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![Stmt::Brif {
                        cond: crate::ir::Cond::Eq,
                        lhs: Expr::reg(0, 64),
                        rhs: Expr::Const(0),
                        target: 20,
                    }],
                },
                Block {
                    start: 10,
                    stmts: vec![assign(held, at(31, 4)), Stmt::Br { target: Some(30) }],
                },
                Block {
                    start: 20,
                    stmts: vec![assign(held, at(31, right)), Stmt::Br { target: Some(30) }],
                },
                Block {
                    start: 30,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(Expr::reg(held, 64)),
                            width: 8,
                            signed: false,
                        },
                    }],
                },
            ];
            assert_eq!(prepare(&mut ir).is_some(), right == 4);
        }
    }

    #[test]
    fn invalid_storage_bounds_and_address_uses_leave_the_ir_unchanged() {
        let cases = [
            vec![Stmt::Ret { value: load(-1, 8) }],
            vec![Stmt::Ret {
                value: load(508, 8),
            }],
            vec![Stmt::Ret { value: load(4, 3) }],
            vec![
                Stmt::Store {
                    addr: Expr::Const(0x1000),
                    value: at(31, 4),
                    width: 8,
                },
                Stmt::Ret { value: load(4, 8) },
            ],
            vec![
                assign(
                    31,
                    Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::reg(0, 64)),
                ),
                Stmt::Ret { value: load(4, 8) },
            ],
            vec![
                assign(crate::ir::VARIABLE_BASE, Expr::reg(31, 32)),
                Stmt::Ret { value: load(4, 8) },
            ],
        ];
        for stmts in cases {
            let mut ir = function(stmts);
            let before = format!("{ir:?}");
            assert!(prepare(&mut ir).is_none());
            assert_eq!(format!("{ir:?}"), before);
        }
        for ty in [CType::U32, CType::Named("unknown".to_owned())] {
            let mut ir = function(vec![Stmt::Ret { value: load(4, 8) }]);
            ir.stack_params[1].ty = ty;
            assert!(prepare(&mut ir).is_none());
        }
    }

    #[test]
    fn known_value_only_calls_survive_but_frame_arguments_do_not() {
        let call = |argument| Stmt::Call {
            target: Some(0x4000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(vec![argument]),
            outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
            clobbers: None,
            floats_named: false,
            via: None,
        };
        let original = function(vec![call(load(4, 8)), Stmt::Ret { value: load(8, 8) }]);
        let mut rewritten = original.clone();
        let plan = prepare(&mut rewritten).unwrap();
        assert_eq!(
            outcome(&original, plan.register),
            outcome(&rewritten, plan.register)
        );
        assert!(matches!(rewritten.blocks[0].stmts[0], Stmt::Call { .. }));
        let mut escaping = function(vec![call(at(31, 4)), Stmt::Ret { value: load(4, 8) }]);
        assert!(prepare(&mut escaping).is_none());
        for overwrite in [false, true] {
            let mut stmts = vec![assign(10, at(31, 4)), call(Expr::Const(7))];
            if overwrite {
                stmts.push(assign(10, Expr::Const(0x1000)));
            }
            stmts.push(assign(crate::ir::VARIABLE_BASE, load(4, 8)));
            stmts.push(Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::reg(10, 64)),
                    width: 8,
                    signed: false,
                },
            });
            assert_eq!(prepare(&mut function(stmts)).is_some(), overwrite);
        }
    }

    #[test]
    fn hidden_call_reads_reject_frame_addresses_and_unknown_origins() {
        let call = |floats_named| Stmt::Call {
            target: Some(0x4000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(vec![]),
            outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
            clobbers: None,
            floats_named,
            via: None,
        };
        for (register, floats_named) in [(8, true), (32, false)] {
            for overwritten in [false, true] {
                let mut stmts = vec![assign(register, at(31, 4))];
                if overwritten {
                    stmts.push(assign(register, Expr::Const(0x1000)));
                }
                stmts.extend([call(floats_named), Stmt::Ret { value: load(4, 8) }]);
                let mut ir = function(stmts);
                let before = format!("{ir:?}");
                assert_eq!(prepare(&mut ir).is_some(), overwritten);
                if !overwritten {
                    assert_eq!(format!("{ir:?}"), before);
                }
            }
        }
        let mut ir = function(Vec::new());
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(0),
                    target: 20,
                }],
            },
            Block {
                start: 10,
                stmts: vec![assign(8, at(31, 4)), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 20,
                stmts: vec![assign(8, at(31, 12)), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 30,
                stmts: vec![call(true), Stmt::Ret { value: load(4, 8) }],
            },
        ];
        let before = format!("{ir:?}");
        assert!(prepare(&mut ir).is_none());
        assert_eq!(format!("{ir:?}"), before);
    }

    #[test]
    fn hidden_call_reads_also_reject_mapped_frame_origins() {
        let variable = crate::ir::VARIABLE_BASE;
        let call = |floats_named| Stmt::Call {
            target: Some(0x4000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(vec![]),
            outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
            clobbers: None,
            floats_named,
            via: None,
        };
        for (physical, floats_named) in [(8, true), (32, false)] {
            for overwritten in [false, true] {
                let mut stmts = vec![assign(variable, at(31, 4))];
                if overwritten {
                    stmts.push(assign(variable, Expr::Const(0x1000)));
                }
                stmts.extend([call(floats_named), Stmt::Ret { value: load(4, 8) }]);
                let mut ir = function(stmts);
                ir.variable_registers.insert(variable, physical);
                let before = format!("{ir:?}");
                assert_eq!(prepare(&mut ir).is_some(), overwritten);
                if !overwritten {
                    assert_eq!(format!("{ir:?}"), before);
                }
            }
        }
        let mut ir = function(Vec::new());
        ir.variable_registers.insert(variable, 8);
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(0),
                    target: 20,
                }],
            },
            Block {
                start: 10,
                stmts: vec![assign(variable, at(31, 4)), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 20,
                stmts: vec![assign(variable, at(31, 12)), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 30,
                stmts: vec![call(true), Stmt::Ret { value: load(4, 8) }],
            },
        ];
        let before = format!("{ir:?}");
        assert!(prepare(&mut ir).is_none());
        assert_eq!(format!("{ir:?}"), before);
        let mut old_alias = function(vec![
            assign(variable, at(31, 4)),
            assign(8, Expr::Const(0x1000)),
            call(true),
            Stmt::Ret { value: load(4, 8) },
        ]);
        old_alias.variable_registers.insert(variable, 8);
        assert!(prepare(&mut old_alias).is_none());
    }
}
