use std::collections::BTreeMap;

use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt, Structure};

/// Gives a pointer parameter read or written at several fixed offsets a
/// structure of its own, one field per offset, when the accesses agree on
/// each field's width and no two overlap. A pointer the body indexes or
/// moves points into an array instead, and keeps its scalar type.
pub(crate) fn recover(ir: &mut FunctionIr) {
    let function = crate::render::sanitize(
        &ir.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", ir.addr)),
    );
    let mut accesses = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, width, .. } = stmt {
            accesses.push((addr.clone(), *width, false));
        }
        for value in stmt.operands() {
            loads(value, &mut accesses);
        }
    }
    let assigned: std::collections::HashSet<u16> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, .. } => Some(dest.index),
            _ => None,
        })
        .collect();
    let mut structures = Vec::new();
    for param in &mut ir.params {
        let CType::Pointer(target) = &param.ty else {
            continue;
        };
        if !matches!(target.as_ref(), CType::Int { .. }) || assigned.contains(&param.index) {
            continue;
        }
        let Some(fields) = layout(param.index, &accesses) else {
            continue;
        };
        let name = format!("{function}_{}", param.name);
        param.ty = CType::pointer_to(CType::Named(format!("struct {name}")));
        structures.push(Structure { name, fields });
    }
    ir.structures = structures;
}

/// The fields at the fixed offsets `base` is accessed at, or `None` when it
/// is accessed at one offset only, indexed, or inconsistently.
fn layout(base: u16, accesses: &[(Expr, u8, bool)]) -> Option<Vec<(u64, CType)>> {
    let mut fields: BTreeMap<u64, (u8, bool)> = BTreeMap::new();
    for (addr, width, signed) in accesses {
        let mut read = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(addr, &mut read);
        if !read.contains(&base) {
            continue;
        }
        let offset = match addr {
            Expr::Reg { index, .. } if *index == base => 0,
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, .. }, Expr::Const(offset))
                | (Expr::Const(offset), Expr::Reg { index, .. })
                    if *index == base && *offset < 1 << 31 =>
                {
                    *offset
                }
                _ => return None,
            },
            _ => return None,
        };
        let field = fields.entry(offset).or_insert((*width, *signed));
        if field.0 != *width {
            return None;
        }
        field.1 |= *signed;
    }
    if fields.len() < 2 {
        return None;
    }
    let mut end = 0;
    for (offset, (width, _)) in &fields {
        if *offset < end {
            return None;
        }
        end = offset + u64::from(*width);
    }
    // A narrow load says by its extension whether the field is signed; a
    // full-width one says nothing, and C's integers are signed by default.
    Some(
        fields
            .into_iter()
            .map(|(offset, (width, signed))| {
                (
                    offset,
                    CType::Int {
                        bytes: width,
                        signed: signed || width >= 4,
                    },
                )
            })
            .collect(),
    )
}

fn loads(expr: &Expr, out: &mut Vec<(Expr, u8, bool)>) {
    if let Expr::Load {
        addr,
        width,
        signed,
    } = expr
    {
        out.push((addr.as_ref().clone(), *width, *signed));
    }
    for child in crate::ir::visit::children(expr) {
        loads(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::recover;
    use crate::ir::{BinOp, CType, Expr, FunctionIr, Param, Stmt};
    use crate::loader::Isa;

    fn store(offset: u64, width: u8) -> Stmt {
        Stmt::Store {
            addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset)),
            value: Expr::Const(0),
            width,
        }
    }

    fn pointer_function(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::U32),
        }];
        ir
    }

    #[test]
    fn fields_at_fixed_offsets_make_a_structure() {
        let mut ir = pointer_function(vec![store(0, 4), store(8, 8)]);
        recover(&mut ir);
        assert_eq!(ir.params[0].ty.to_string(), "struct sub_0_a0 *");
        assert_eq!(
            ir.structures[0].fields,
            vec![(0, CType::I32), (8, CType::I64)]
        );
    }

    #[test]
    fn overlapping_fields_make_no_structure() {
        let mut ir = pointer_function(vec![store(0, 8), store(4, 4)]);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
        assert_eq!(ir.params[0].ty, CType::pointer_to(CType::U32));
    }
}
