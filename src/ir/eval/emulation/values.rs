//! Preserves known register bits across partial writes after modeled calls.

use crate::ir::{BinOp, Expr, RegRef};
use crate::ssa::ranges;
use crate::ssa::ranges::Fact;

use super::{Runner, Stop};

impl Runner<'_> {
    pub(super) fn register_fact(&self, register: u16, bits: u32) -> Result<Fact, Stop> {
        let bits = if (self.image.isa == crate::loader::Isa::I386 && register < 8)
            || (self.image.isa == crate::loader::Isa::Arm32 && register < 16)
        {
            bits.min(32)
        } else {
            bits
        };
        if let Some(fact) = self.facts.get(&register) {
            return Ok(fact.truncate(bits));
        }
        match self.machine.registers.get(&register) {
            Some(value) => Ok(Fact::constant(*value).truncate(bits)),
            None => Err(Stop::Error("read of an undefined register".to_owned())),
        }
    }

    pub(super) fn assign_fact(&mut self, dest: RegRef, fact: Fact) {
        let fact = fact.truncate(u32::from(dest.width));
        self.machine.assign(dest, fact.ones);
        if fact.singleton().is_some() {
            self.facts.remove(&dest.index);
        } else {
            self.facts.insert(dest.index, fact);
        }
    }

    pub(super) fn value_fact(&self, expression: &Expr) -> Result<Fact, Stop> {
        match expression {
            Expr::Reg { index, width } => self.register_fact(*index, u32::from(*width)),
            Expr::Const(value) => Ok(Fact::constant(*value)),
            Expr::Load {
                addr,
                width,
                signed,
            } => {
                let address = match self.eval(addr) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let load = Expr::Load {
                    addr: Box::new(Expr::Const(address)),
                    width: *width,
                    signed: *signed,
                };
                match self.concrete(&load) {
                    Ok(value) => Ok(Fact::constant(value)),
                    Err(stop) => Err(stop),
                }
            }
            Expr::SignExtend { value, width } => match self.value_fact(value) {
                Ok(value) => Ok(value.sign_extend(u32::from(*width) * 8)),
                Err(stop) => Err(stop),
            },
            Expr::Select {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => {
                let left = match self.eval(lhs) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let right = match self.eval(rhs) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                if super::super::holds(*cond, left, right, super::super::operand_width(lhs, rhs)) {
                    self.value_fact(then)
                } else {
                    self.value_fact(els)
                }
            }
            Expr::Apply { op, args } => {
                let mut values = Vec::new();
                for arg in args {
                    match self.eval(arg) {
                        Ok(value) => values.push(Expr::Const(value)),
                        Err(stop) => return Err(stop),
                    }
                }
                match self.concrete(&Expr::Apply {
                    op: *op,
                    args: values,
                }) {
                    Ok(value) => Ok(Fact::constant(value)),
                    Err(stop) => Err(stop),
                }
            }
            Expr::Bin { op, lhs, rhs } => {
                let left = match self.value_fact(lhs) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let right = match self.value_fact(rhs) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let bits = if matches!(op, BinOp::Sar | BinOp::DivS | BinOp::ModS) {
                    super::super::operand_width(lhs, rhs) as u8
                } else {
                    64
                };
                let operation = Expr::Bin {
                    op: *op,
                    lhs: Box::new(Expr::reg(0, bits)),
                    rhs: Box::new(Expr::reg(1, bits)),
                };
                if let (Some(left), Some(right)) = (left.singleton(), right.singleton()) {
                    return match crate::ir::semantics::evaluate(&operation, &|index| {
                        Some(if index == 0 { left } else { right })
                    }) {
                        Some(value) => Ok(Fact::constant(value)),
                        None => Err(Stop::Error("division by zero".to_owned())),
                    };
                }
                if matches!(op, BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU) {
                    return Err(Stop::Error(
                        "division uses an undefined register".to_owned(),
                    ));
                }
                let result = ranges::expression(&operation, &|index, _| {
                    Some(if index == 0 { left } else { right })
                });
                Ok(result.unwrap_or(Fact::TOP))
            }
        }
    }
}
