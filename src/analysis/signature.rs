//! Heuristic calling-convention and parameter recovery from lifted IR.

use std::collections::{HashMap, HashSet};

use crate::ir::{Access, Block, CType, Expr, Param, Stmt};
use crate::loader::{Format, Isa};

#[derive(Debug, Clone)]
pub struct Signature {
    pub params: Vec<Param>,
    pub ret: CType,
    pub accesses: Vec<Access>,
    /// Argument registers a signed comparison reads: the parameter is signed.
    pub signed: HashSet<u16>,
}

fn argument_registers(isa: Isa, format: Format, go: bool) -> &'static [u16] {
    match isa {
        Isa::AArch64 => &[0, 1, 2, 3, 4, 5, 6, 7],
        // Go's register ABI passes integer arguments in rax, rbx, rcx, rdi,
        // rsi, r8, r9, r10, r11.
        Isa::X86_64 if go => &[0, 3, 1, 7, 6, 8, 9, 10, 11],
        Isa::X86_64 => match format {
            Format::Pe | Format::Coff => &[1, 2, 8, 9],
            _ => &[7, 6, 2, 1, 8, 9],
        },
        Isa::Unsupported => &[],
    }
}

fn reads(expr: &Expr, into: &mut HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            into.insert(*index);
        }
        Expr::Bin { lhs, rhs, .. } => {
            reads(lhs, into);
            reads(rhs, into);
        }
        Expr::Load { addr, .. } => reads(addr, into),
        Expr::SignExtend { value, .. } => reads(value, into),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            reads(lhs, into);
            reads(rhs, into);
            reads(then, into);
            reads(els, into);
        }
        Expr::Const(_) => {}
    }
}

/// The condition kinds only a signed comparison produces.
fn signed_cond(cond: crate::ir::Cond) -> bool {
    matches!(
        cond,
        crate::ir::Cond::Lt | crate::ir::Cond::Gt | crate::ir::Cond::Le | crate::ir::Cond::Ge
    )
}

fn note_signed_cond(cond: crate::ir::Cond, operands: &[&Expr], signed: &mut HashSet<u16>) {
    if !signed_cond(cond) {
        return;
    }
    for expr in operands {
        reads(expr, signed);
    }
}

/// Walks an expression for selects whose condition is signed.
fn signed_in_expr(expr: &Expr, signed: &mut HashSet<u16>) {
    match expr {
        Expr::Bin { lhs, rhs, .. } => {
            signed_in_expr(lhs, signed);
            signed_in_expr(rhs, signed);
        }
        Expr::Load { addr, .. } => signed_in_expr(addr, signed),
        Expr::SignExtend { value, .. } => signed_in_expr(value, signed),
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            note_signed_cond(*cond, &[lhs, rhs], signed);
            signed_in_expr(lhs, signed);
            signed_in_expr(rhs, signed);
            signed_in_expr(then, signed);
            signed_in_expr(els, signed);
        }
        Expr::Reg { .. } | Expr::Const(_) => {}
    }
}

pub fn recover(blocks: &[Block], isa: Isa, format: Format, go: bool) -> Signature {
    let arguments = argument_registers(isa, format, go);
    let universe: HashSet<u16> = arguments.iter().copied().collect();

    // Registers written on every path to each block; a register read before
    // it is written is an argument.
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        let Some(last) = block.stmts.last() else {
            continue;
        };
        let mut targets = Vec::new();
        let falls_through = match last {
            Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } => {
                targets.push(*target);
                true
            }
            Stmt::Br {
                target: Some(target),
            } => {
                targets.push(*target);
                false
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, target) in cases {
                    targets.push(*target);
                }
                if let Some(target) = default {
                    targets.push(*target);
                }
                false
            }
            Stmt::Ret { .. } | Stmt::BrIndirect { .. } => false,
            _ => true,
        };
        if falls_through && index + 1 < blocks.len() {
            predecessors[index + 1].push(index);
        }
        for target in targets {
            if let Some(destination) = blocks.iter().position(|block| block.start == target) {
                predecessors[destination].push(index);
            }
        }
    }

    let writes: Vec<HashSet<u16>> = blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .filter_map(|stmt| match stmt {
                    Stmt::Assign { dest, .. } => Some(dest.index),
                    _ => None,
                })
                .collect()
        })
        .collect();
    let mut entry: Vec<HashSet<u16>> = vec![universe.clone(); blocks.len()];
    if !entry.is_empty() {
        entry[0] = HashSet::new();
    }
    loop {
        let mut changed = false;
        for index in 0..blocks.len() {
            if index == 0 {
                continue;
            }
            let preds = &predecessors[index];
            if preds.is_empty() {
                continue;
            }
            let mut merged: Option<HashSet<u16>> = None;
            for pred in preds {
                let exit: HashSet<u16> = entry[*pred].union(&writes[*pred]).copied().collect();
                merged = Some(match merged {
                    None => exit,
                    Some(current) => current.intersection(&exit).copied().collect(),
                });
            }
            let merged = merged.unwrap_or_default();
            if merged != entry[index] {
                entry[index] = merged;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut inputs: HashSet<u16> = HashSet::new();
    for (index, block) in blocks.iter().enumerate() {
        let mut written = entry[index].clone();
        for stmt in &block.stmts {
            let mut used = HashSet::new();
            match stmt {
                Stmt::Assign { value, .. } => reads(value, &mut used),
                Stmt::Store { addr, value, .. } => {
                    reads(addr, &mut used);
                    reads(value, &mut used);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    reads(lhs, &mut used);
                    reads(rhs, &mut used);
                }
                Stmt::Ret { value } => reads(value, &mut used),
                Stmt::BrIndirect { target } => reads(target, &mut used),
                Stmt::Switch { index, .. } => reads(index, &mut used),
                _ => {}
            }
            for register in used {
                if !written.contains(&register) {
                    inputs.insert(register);
                }
            }
            if let Stmt::Assign { dest, .. } = stmt {
                written.insert(dest.index);
            }
        }
    }

    let mut params = Vec::new();
    for register in arguments {
        if inputs.contains(register) {
            params.push(Param {
                index: *register,
                name: format!("a{}", params.len()),
                ty: CType::U64,
            });
        } else {
            break;
        }
    }

    // Which argument each register is derived from through copies and
    // base-preserving arithmetic, so loads through it type that argument.
    let mut origin: HashMap<u16, u16> = HashMap::new();
    for param in &params {
        origin.insert(param.index, param.index);
    }
    loop {
        let mut changed = false;
        for block in blocks {
            for stmt in &block.stmts {
                let Stmt::Assign { dest, value } = stmt else {
                    continue;
                };
                if origin.contains_key(&dest.index) {
                    continue;
                }
                if let Some(source) = base_origin(value, &origin) {
                    origin.insert(dest.index, source);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut pointer_widths: HashMap<u16, u8> = HashMap::new();
    let note = |addr: &Expr, width: u8, widths: &mut HashMap<u16, u8>| {
        if let Some(base) = base_register(addr)
            && let Some(param) = origin.get(&base)
        {
            widths.entry(*param).or_insert(width);
        }
    };
    for block in blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { value, .. } => {
                    if let Some((addr, width)) = load_of(value) {
                        note(addr, width, &mut pointer_widths);
                    }
                }
                Stmt::Store { addr, width, .. } => {
                    note(addr, *width, &mut pointer_widths);
                }
                _ => {}
            }
        }
    }
    for param in &mut params {
        if let Some(width) = pointer_widths.get(&param.index) {
            param.ty = CType::pointer_to(CType::int(*width, false));
        }
    }

    // Signedness is visible only in comparison conditions.
    let mut signed: HashSet<u16> = HashSet::new();
    for block in blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Brif { cond, lhs, rhs, .. } => {
                    note_signed_cond(*cond, &[lhs, rhs], &mut signed);
                }
                Stmt::Assign { value, .. } => signed_in_expr(value, &mut signed),
                Stmt::Store { addr, value, .. } => {
                    signed_in_expr(addr, &mut signed);
                    signed_in_expr(value, &mut signed);
                }
                Stmt::Ret { value } => signed_in_expr(value, &mut signed),
                Stmt::Switch { index, .. } => signed_in_expr(index, &mut signed),
                _ => {}
            }
        }
    }
    let signed_args: HashSet<u16> = signed
        .iter()
        .filter_map(|register| origin.get(register).copied())
        .collect();

    let mut ret = CType::U64;
    for block in blocks.iter().rev() {
        if let Some(Stmt::Ret { value }) = block.stmts.last() {
            ret = expression_type(value);
            break;
        }
    }

    let mut offsets: HashMap<u16, std::collections::BTreeMap<u64, u8>> = HashMap::new();
    for block in blocks {
        for stmt in &block.stmts {
            let (addr, width) = match stmt {
                Stmt::Assign { value, .. } => match load_of(value) {
                    Some((addr, width)) => (addr, width),
                    None => continue,
                },
                Stmt::Store { addr, width, .. } => (addr, *width),
                _ => continue,
            };
            let Some((base, offset)) = split_address(addr) else {
                continue;
            };
            let Some(param) = origin.get(&base) else {
                continue;
            };
            offsets
                .entry(*param)
                .or_default()
                .entry(offset)
                .or_insert(width);
        }
    }
    let accesses = params
        .iter()
        .filter_map(|param| {
            let fields = offsets.get(&param.index)?;
            Some(Access {
                register: param.index,
                fields: fields
                    .iter()
                    .map(|(offset, width)| (*offset, CType::int(*width, false)))
                    .collect(),
            })
        })
        .collect();

    Signature {
        params,
        ret,
        accesses,
        signed: signed_args,
    }
}

fn expression_type(expr: &Expr) -> CType {
    match expr {
        Expr::SignExtend { width, .. } => CType::int(*width, true),
        Expr::Load { width, signed, .. } => CType::int(*width, *signed),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            ..
        } => expression_type(lhs),
        Expr::Select { then, .. } => expression_type(then),
        _ => CType::U64,
    }
}

fn split_address(expr: &Expr) -> Option<(u16, u64)> {
    match expr {
        Expr::Reg { index, .. } => Some((*index, 0)),
        Expr::Const(_) => None,
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (split_address(lhs), split_address(rhs)) {
            (Some((base, offset)), None) => {
                let constant = match rhs.as_ref() {
                    Expr::Const(value) => *value,
                    _ => return None,
                };
                Some((base, offset.wrapping_add(constant)))
            }
            (None, Some((base, offset))) => {
                let constant = match lhs.as_ref() {
                    Expr::Const(value) => *value,
                    _ => return None,
                };
                Some((base, offset.wrapping_add(constant)))
            }
            _ => None,
        },
        _ => None,
    }
}

fn base_origin(expr: &Expr, origin: &HashMap<u16, u16>) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => origin.get(index).copied(),
        Expr::Bin {
            op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
            lhs,
            ..
        } => base_origin(lhs, origin),
        _ => None,
    }
}

fn base_register(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::Bin {
            op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
            lhs,
            ..
        } => base_register(lhs),
        _ => None,
    }
}

fn load_of(expr: &Expr) -> Option<(&Expr, u8)> {
    match expr {
        Expr::Load { addr, width, .. } => Some((addr.as_ref(), *width)),
        Expr::SignExtend { value, .. } => load_of(value),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            ..
        } => load_of(lhs),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::recover;
    use crate::ir::{Block, Expr, RegRef, Stmt};
    use crate::loader::{Format, Isa};

    #[test]
    fn a_register_written_in_an_earlier_block_is_not_an_argument() {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Assign {
                    dest: RegRef {
                        index: 1,
                        width: 64,
                    },
                    value: Expr::Const(7),
                }],
            },
            Block {
                start: 4,
                stmts: vec![Stmt::Ret {
                    value: Expr::bin(crate::ir::BinOp::Add, Expr::reg(0, 64), Expr::reg(1, 64)),
                }],
            },
        ];

        let signature = recover(&blocks, Isa::AArch64, Format::Elf, false);

        let params: Vec<u16> = signature.params.iter().map(|param| param.index).collect();
        assert_eq!(params, vec![0]);
    }
}
