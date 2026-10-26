//! Runtime class names in object initialization and destruction.

use std::collections::HashSet;
use std::fmt::Write;

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::loader::Image;

use super::Symbols;

pub(super) fn name_tables(image: &Image, symbols: &mut Symbols) {
    let mut reserved: HashSet<_> = symbols
        .data
        .values()
        .map(|name| super::sanitize(name))
        .collect();
    reserved.extend(symbols.functions.values().cloned());
    for class in image.classes() {
        for table in &class.vtables {
            if symbols.data.contains_key(&table.address) {
                continue;
            }
            let name = super::vacant_name(
                &super::globals::identifier(&format!("{}_vtable_{}", class.name, table.offset)),
                &mut reserved,
            );
            symbols.data.insert(table.address, name);
        }
    }
}

pub(crate) fn comments(ir: &FunctionIr, image: &Image) -> String {
    let mut output = String::new();
    let mut seen = HashSet::new();
    for statement in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let Stmt::Store {
            value: Expr::Const(address),
            width: 8,
            ..
        } = statement
        else {
            continue;
        };
        if !seen.insert(*address) {
            continue;
        }
        for class in image.classes() {
            if class.vtables.iter().any(|table| table.address == *address) {
                let name = class.name.replace("*/", "* /");
                let _ = writeln!(
                    output,
                    "/* C++ object initialization or destruction: {name} vtable at {address:#x}. */"
                );
            }
        }
    }
    output
}
