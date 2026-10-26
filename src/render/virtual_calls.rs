use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::{BinOp, Expr, FunctionIr, Stmt, Table};

use super::{Symbols, expr::Ctx};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Method {
    slot: u64,
    name: String,
    class: Option<usize>,
}

fn method(call: &Stmt, symbols: &Symbols) -> Option<Method> {
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
    let mut owner = None;
    let mut ambiguous = via.candidates.is_empty();
    for candidate in &via.candidates {
        let mut owners = symbols.cpp_classes.iter().enumerate().filter(|(_, class)| {
            class.vtables.iter().any(|table| {
                table.offset == 0
                    && table
                        .methods
                        .iter()
                        .any(|method| method.slot == via.slot && method.address == *candidate)
            })
        });
        let Some((index, _)) = owners.next() else {
            ambiguous = true;
            break;
        };
        if owners.next().is_some() || owner.is_some_and(|owner| owner != index) {
            ambiguous = true;
            break;
        }
        owner = Some(index);
    }
    let owner = (!ambiguous).then_some(owner).flatten();
    let mut signature = None;
    for candidate in &via.candidates {
        let Some(source) = symbols.cpp_methods.get(candidate) else {
            return owner.map(|class| Method {
                slot: via.slot,
                name: format!("method_{}", via.slot),
                class: Some(class),
            });
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
    Some(Method {
        slot: via.slot,
        name: name.to_owned(),
        class: owner,
    })
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
    views: BTreeMap<Method, (String, String)>,
    bases: BTreeMap<String, Vec<(String, String, i64)>>,
}

impl Tables {
    pub(super) fn new(ir: &FunctionIr, symbols: &Symbols, reserved: &mut HashSet<String>) -> Self {
        reserved.extend(
            ir.structures
                .iter()
                .map(|structure| super::sanitize(&structure.name)),
        );
        reserved.extend(
            ir.definitions
                .iter()
                .map(|definition| super::sanitize(&definition.name)),
        );
        reserved.extend(symbols.user_definitions.iter().cloned());
        let mut tables = Self::default();
        for call in ir.blocks.iter().flat_map(|block| &block.stmts) {
            let Some(key) = method(call, symbols) else {
                continue;
            };
            let slot = key.slot;
            if slot > 4096 || tables.views.contains_key(&key) {
                continue;
            }
            let class = key.class.map(|index| &symbols.cpp_classes[index]);
            let base = class.map_or_else(
                || format!("velk_{}_slot_{slot}", key.name),
                |class| super::globals::identifier(&class.name),
            );
            let table = super::vacant_name(&format!("{base}_vtable"), reserved);
            let object_base = if class.is_some() {
                base.clone()
            } else {
                format!("{base}_object")
            };
            let object = super::vacant_name(&object_base, reserved);
            if let Some(class) = class {
                let mut bases = Vec::new();
                let mut fields = HashSet::from(["vtable".to_owned()]);
                for base in &class.bases {
                    let Some(offset) = base.offset else {
                        continue;
                    };
                    // A pointer-sized prefix can represent only disjoint, aligned bases.
                    if offset < 0 || offset % 8 != 0 || offset > 0x100_0000 {
                        continue;
                    }
                    let name = super::sanitize(&base.name);
                    let field = super::vacant_name(&format!("base_{name}"), &mut fields);
                    let tag = super::vacant_name(&format!("{name}_base"), reserved);
                    bases.push((field, tag, offset));
                }
                bases.sort_by_key(|(_, _, offset)| *offset);
                tables.bases.insert(object.clone(), bases);
            }
            tables.views.insert(key, (table, object));
        }
        tables
    }

    pub(super) fn declarations(&self, body: &str) -> String {
        let mut out = String::new();
        for (key, (table, object)) in &self.views {
            let slot = key.slot;
            let method = &key.name;
            if !body.contains(&format!("struct {table} *"))
                && !body.contains(&format!("struct {object} *"))
            {
                continue;
            }
            let padding = if slot == 0 {
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
                let mut fields = format!("struct {table} *vtable;");
                let mut end = 8;
                if let Some(bases) = self.bases.get(object) {
                    for (index, (field, tag, offset)) in bases.iter().enumerate() {
                        out.push_str(&format!("struct {tag} {{ unsigned char bytes[8]; }};\n"));
                        if *offset == 0 && index == 0 {
                            fields = format!(
                                "union {{ struct {table} *vtable; struct {tag} {field}; }};"
                            );
                        } else if *offset >= end {
                            if *offset > end {
                                fields.push_str(&format!(
                                    " unsigned char padding_{index}[{}];",
                                    offset - end
                                ));
                            }
                            fields.push_str(&format!(" struct {tag} {field};"));
                            end = offset + 8;
                        }
                    }
                }
                out.push_str(&format!("struct {object} {{ {fields} }};\n"));
            }
        }
        out
    }

    pub(super) fn callee(&self, call: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
        let Some(key) = method(call, ctx.symbols) else {
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
        let Some(offset) = key.slot.checked_mul(8) else {
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
        let name = &key.name;
        if let Expr::Load { addr, width: 8, .. } = base {
            let text = super::render_value(addr, ctx);
            return Some(format!("((struct {object} *)({text}))->vtable->{name}"));
        }
        let text = super::render_value(base, ctx);
        Some(format!("((struct {table} *)({text}))->{name}"))
    }
}
