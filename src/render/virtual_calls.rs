use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::{BinOp, Expr, FunctionIr, Stmt, Table};

use super::{Symbols, expr::Ctx};

fn method(call: &Stmt, symbols: &Symbols) -> Option<(u64, String)> {
    let Stmt::Call {
        target: None,
        through: Some(_),
        via: Some(via),
        ..
    } = call
    else {
        return None;
    };
    if via.table != Table::Vtable || call.has_declared_call() {
        return None;
    }
    let mut signature = None;
    for candidate in &via.candidates {
        let Some(source) = symbols.cpp_methods.get(candidate) else {
            return None;
        };
        if signature.is_some_and(|known| known != source) {
            return None;
        }
        signature = Some(source);
    }
    let Some(signature) = signature else {
        return None;
    };
    let Some((name, _)) = signature.split_once('(') else {
        return None;
    };
    if name.is_empty() || super::sanitize(name) != name || super::globals::reserved_identifier(name)
    {
        return None;
    }
    Some((via.slot, name.to_owned()))
}

pub(super) fn prepare(ir: &mut FunctionIr, symbols: &Symbols) {
    let mut reads = HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).1 {
            *reads.entry(register).or_default() += 1;
        }
    }
    for block in &mut ir.blocks {
        for position in (1..block.stmts.len()).rev() {
            if method(&block.stmts[position], symbols).is_none() {
                continue;
            }
            let Stmt::Assign { dest, value } = &block.stmts[position - 1] else {
                continue;
            };
            let overwritten = block.stmts[position]
                .call_outputs()
                .iter()
                .any(|output| output.dest.index == dest.index && output.dest.width == 64);
            if dest.width != 64
                || (reads.get(&dest.index) != Some(&1) && !overwritten)
                || !matches!(value, Expr::Load { width: 8, .. })
            {
                continue;
            }
            let Stmt::Call {
                through: Some(through),
                args: Some(_),
                ..
            } = &block.stmts[position]
            else {
                continue;
            };
            let mut without_target = block.stmts[position].clone();
            if let Stmt::Call { through, .. } = &mut without_target {
                *through = None;
            }
            let arguments = crate::ir::visit::statement_registers(&without_target).1;
            if *through != Expr::reg(dest.index, 64) || arguments.contains(&dest.index) {
                continue;
            }
            let value = value.clone();
            if let Stmt::Call { through, .. } = &mut block.stmts[position] {
                *through = Some(value);
            }
            block.stmts.remove(position - 1);
        }
    }
}

#[derive(Default)]
pub(super) struct Tables {
    views: BTreeMap<(u64, String), (String, String)>,
}

impl Tables {
    pub(super) fn new(ir: &FunctionIr, symbols: &Symbols, reserved: &mut HashSet<String>) -> Self {
        reserved.extend(
            ir.structures
                .iter()
                .map(|structure| super::sanitize(&structure.name)),
        );
        let mut tables = Self::default();
        for call in ir.blocks.iter().flat_map(|block| &block.stmts) {
            let Some(key @ (slot, _)) = method(call, symbols) else {
                continue;
            };
            if slot > 4096 || tables.views.contains_key(&key) {
                continue;
            }
            let base = format!("velk_{}_slot_{slot}", key.1);
            let table = super::vacant_name(&format!("{base}_vtable"), reserved);
            let object = super::vacant_name(&format!("{base}_object"), reserved);
            tables.views.insert(key, (table, object));
        }
        tables
    }

    pub(super) fn declarations(&self, body: &str) -> String {
        let mut out = String::new();
        for ((slot, method), (table, object)) in &self.views {
            if !body.contains(&format!("struct {table} *"))
                && !body.contains(&format!("struct {object} *"))
            {
                continue;
            }
            let padding = if *slot == 0 {
                String::new()
            } else {
                let padding = if method == "slots" {
                    "padding"
                } else {
                    "slots"
                };
                format!("uint64_t {padding}[{slot}]; ")
            };
            // Keep the full register return and the existing argument promotions.
            out.push_str(&format!(
                "struct {table} {{ {padding}uint64_t (*{method})(); }};\n"
            ));
            if body.contains(&format!("struct {object} *")) {
                out.push_str(&format!("struct {object} {{ struct {table} *vtable; }};\n"));
            }
        }
        out
    }

    pub(super) fn callee(&self, call: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
        let Some(key @ (slot, _)) = method(call, ctx.symbols) else {
            return None;
        };
        let Some((table, object)) = self.views.get(&key) else {
            return None;
        };
        let Stmt::Call {
            through: Some(Expr::Load { addr, width: 8, .. }),
            ..
        } = call
        else {
            return None;
        };
        let Some(offset) = slot.checked_mul(8) else {
            return None;
        };
        let base = match addr.as_ref() {
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } if **rhs == Expr::Const(offset) => lhs.as_ref(),
            base if offset == 0 => base,
            _ => return None,
        };
        let name = &key.1;
        if let Expr::Load { addr, width: 8, .. } = base {
            let text = super::render_value(addr, ctx);
            return Some(format!("((struct {object} *)({text}))->vtable->{name}"));
        }
        let text = super::render_value(base, ctx);
        Some(format!("((struct {table} *)({text}))->{name}"))
    }
}
