//! How wide an integer variable needs to be. One whose readers never look
//! above its low 8, 16 or 32 bits is declared with that many, and one that
//! only ever holds values of 32 bits with 32, so that C computes on it at
//! that width and the printer needs no masks or casts to bring its value
//! back to it.

use std::collections::{HashMap, HashSet};

use crate::ir::semantics::operand_width;
use crate::ir::{BinOp, Expr, FunctionIr, Operation, Stmt};

/// How a narrow variable holds its values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Narrow {
    /// Every reader looks at no more than the low `bits`, so the variable
    /// may take either sign; `extended` when some reader extends them with
    /// zeros, as a variable of no sign does by itself.
    Read { bits: u32, extended: bool },
    /// Every value assigned fits in 32 bits, which only a 32-bit variable
    /// of no sign gives back whole to a reader that looks further.
    Held,
}

impl Narrow {
    pub(crate) fn bits(self) -> u32 {
        match self {
            Narrow::Read { bits, .. } => bits,
            Narrow::Held => 32,
        }
    }
}

/// The integer variables among `ints` that take fewer than 64 bits.
/// `narrow` are those the body never reads wider than 32 bits, and
/// `pointers` the registers holding addresses, a sum with which the
/// printer prints whole.
pub(crate) fn narrow_variables(
    ir: &FunctionIr,
    ints: &HashSet<u16>,
    narrow: &HashSet<u16>,
    pointers: &HashSet<u16>,
) -> HashMap<u16, Narrow> {
    let held = crate::render::int::value_bits(ir);
    let holds_32 = |index: u16| held.get(&index).is_some_and(|bits| *bits <= 32);
    let saved = saved(ir);
    let decide = |readers: &Readers| -> HashMap<u16, Narrow> {
        ints.iter()
            .filter_map(|index| {
                // A narrow variable saves a cast or a mask where the body
                // takes or reads a narrow part of it, and costs a cast where
                // C would compute on it narrower than the reader looks.
                let widened = readers.widened.get(index).copied().unwrap_or(0);
                if widened > 0 && widened >= saved.get(index).copied().unwrap_or(0) {
                    return None;
                }
                // One nothing reads is as wide as an `int`; one the body
                // reads at no more than 32 bits, but for a whole register
                // a callee takes at its own width, is 32 bits wide.
                let bits = match readers.bits.get(index) {
                    None => Some(32),
                    Some(read) => [8, 16, 32].into_iter().find(|bits| read <= bits),
                }
                .or(narrow.contains(index).then_some(32));
                let kind = if let Some(bits) = bits {
                    Narrow::Read {
                        bits,
                        extended: readers.extended.contains(&(*index, bits)),
                    }
                } else if holds_32(*index) {
                    Narrow::Held
                } else {
                    return None;
                };
                Some((*index, kind))
            })
            .collect()
    };
    // Each round reads the assignments at the widths the last one gave
    // their destinations, which only grow, until they no longer change.
    let mut decided = decide(&Readers::default());
    for _ in 0..=ints.len() + 1 {
        let next = decide(&read_bits(ir, &decided, ints, pointers));
        if next == decided {
            return decided;
        }
        decided = next;
    }
    HashMap::new()
}

/// For each register, the places a 64-bit variable would go through a mask
/// or a cast to fewer bits and a narrow one would not: an assignment of a
/// value masked to them or of a register read narrower, and a narrower
/// read of the register itself.
fn saved(ir: &FunctionIr) -> HashMap<u16, usize> {
    fn reads(expr: &Expr, counts: &mut HashMap<u16, usize>) {
        match expr {
            Expr::Reg { index, width } if *width < 64 => *counts.entry(*index).or_insert(0) += 1,
            Expr::SignExtend { value, .. }
                if let Expr::Reg { index, width: 64 } = value.as_ref() =>
            {
                *counts.entry(*index).or_insert(0) += 1;
            }
            _ => {
                for child in crate::ir::visit::children(expr) {
                    reads(child, counts);
                }
            }
        }
    }
    let mut counts = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, value } = stmt
            && match value {
                Expr::Bin {
                    op: BinOp::And,
                    rhs,
                    ..
                } => matches!(rhs.as_ref(), Expr::Const(0xff | 0xffff | 0xffff_ffff)),
                Expr::Reg { width, .. } => *width < 64,
                _ => false,
            }
        {
            *counts.entry(dest.index).or_insert(0) += 1;
        }
        for value in stmt.operands() {
            reads(value, &mut counts);
        }
    }
    counts
}

/// What the readers of each register ask of it.
#[derive(Default)]
pub(crate) struct Readers {
    /// The most low bits any reader looks at.
    pub(crate) bits: HashMap<u16, u32>,
    /// The readers that would compute on a narrow value at 64 bits, which
    /// C does only once the value is cast to a 64-bit type: a sum, a
    /// difference, a product or a left shift of it with a constant or
    /// another integer variable, its negation or its complement, whose
    /// result is read beyond 32 bits.
    pub(crate) widened: HashMap<u16, usize>,
    /// The registers some reader extends with zeros from the low bits
    /// given, reading further.
    pub(crate) extended: HashSet<(u16, u32)>,
}

/// The most low bits of each register any reader looks at, as the printer
/// asks for them, when the variables in `narrow` are as narrow as it says.
pub(crate) fn read_bits(
    ir: &FunctionIr,
    narrow: &HashMap<u16, Narrow>,
    ints: &HashSet<u16>,
    pointers: &HashSet<u16>,
) -> Readers {
    let mut reads = Reads {
        readers: Readers::default(),
        ints,
        pointers,
        narrow_params: ir
            .params
            .iter()
            .filter(|param| param.ty.integer().is_some_and(|(bits, _)| bits <= 32))
            .map(|param| param.index)
            .collect(),
    };
    let returned = match ir.ret_type {
        crate::ir::CType::Void => 0,
        ref ty => ty.integer().map_or(64, |(bits, _)| bits),
    };
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign { dest, value } => {
                let bits = if let Some(narrow) = narrow.get(&dest.index) {
                    narrow.bits()
                } else {
                    ir.params
                        .iter()
                        .find(|param| param.index == dest.index)
                        .and_then(|param| param.ty.integer())
                        .map_or(64, |(bits, _)| bits)
                };
                reads.expr(value, bits);
            }
            // A choice stored in place is printed as a compare-and-exchange,
            // which reads its values whole.
            Stmt::Store {
                addr,
                value: value @ Expr::Select { .. },
                ..
            } => {
                reads.expr(addr, 64);
                reads.expr(value, 64);
            }
            Stmt::Store { addr, value, width } => {
                reads.expr(addr, 64);
                reads.expr(value, u32::from(*width) * 8);
            }
            Stmt::Brif { lhs, rhs, .. } => reads.compared(lhs, rhs),
            Stmt::Switch { index, .. } => reads.compared(index, &Expr::Const(0)),
            Stmt::Ret { value } => match value {
                Expr::Apply {
                    op: Operation::Results,
                    args,
                } => {
                    for (at, arg) in args.iter().enumerate() {
                        reads.expr(arg, if at == 0 { returned } else { 64 });
                    }
                }
                _ => reads.expr(value, returned),
            },
            _ => {
                for value in stmt.operands() {
                    reads.expr(value, 64);
                }
            }
        }
    }
    reads.readers
}

struct Reads<'a> {
    readers: Readers,
    ints: &'a HashSet<u16>,
    pointers: &'a HashSet<u16>,
    /// The parameters of integer types no wider than 32 bits.
    narrow_params: HashSet<u16>,
}

impl Reads<'_> {
    fn note(&mut self, index: u16, bits: u32) {
        let entry = self.readers.bits.entry(index).or_insert(0);
        *entry = (*entry).max(bits);
    }

    /// Counts the reader of `expr`, an operand of an operation C computes
    /// at the type of its operands, when it is a register read whole, or
    /// some of its bits that C computes at its type, and the other operand,
    /// `other`, gives C no wider type. A register read narrower is cast
    /// whatever its type.
    fn widens(&mut self, expr: &Expr, other: Option<&Expr>, bits: u32) {
        fn register(expr: &Expr) -> Option<u16> {
            match expr {
                Expr::Reg { index, width: 64 } => Some(*index),
                Expr::Bin {
                    op: BinOp::And | BinOp::Shr,
                    lhs,
                    rhs,
                } if matches!(rhs.as_ref(), Expr::Const(_)) => register(lhs),
                _ => None,
            }
        }
        let Some(index) = register(expr) else {
            return;
        };
        let narrow_other = match other {
            None | Some(Expr::Const(_)) => true,
            Some(Expr::Reg { index, .. }) => {
                self.ints.contains(index) || self.narrow_params.contains(index)
            }
            Some(_) => false,
        };
        if bits > 32 && narrow_other {
            *self.readers.widened.entry(index).or_insert(0) += 1;
        }
    }

    /// The operands of a comparison at the wider of their widths. A narrow
    /// variable compared whole with a narrow parameter, which may differ in
    /// sign, is compared through a cast.
    fn compared(&mut self, lhs: &Expr, rhs: &Expr) {
        let bits = operand_width(lhs, rhs);
        for (side, other) in [(lhs, rhs), (rhs, lhs)] {
            if matches!(other, Expr::Reg { index, .. } if self.narrow_params.contains(index)) {
                self.widens(side, Some(other), bits);
            }
        }
        self.expr(lhs, bits);
        self.expr(rhs, bits);
    }

    /// The registers `expr` reads, when its reader looks at its low `bits`.
    fn expr(&mut self, expr: &Expr, bits: u32) {
        let bits = bits.min(64);
        match expr {
            Expr::Reg { index, width } => self.note(*index, bits.min(u32::from(*width))),
            Expr::Const(_) => {}
            Expr::Load { addr, .. } => self.expr(addr, 64),
            Expr::SignExtend { value, width } => self.expr(value, u32::from(*width) * 8),
            Expr::Select {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                self.compared(lhs, rhs);
                self.expr(then, bits);
                self.expr(els, bits);
            }
            Expr::Apply { op, args } => {
                let bits = match op {
                    Operation::CountLeadingZeros(bits)
                    | Operation::CountTrailingZeros(bits)
                    | Operation::PopCount(bits) => {
                        if *bits == 64 {
                            64
                        } else {
                            32
                        }
                    }
                    Operation::ReverseBits(bits) => u32::from(*bits),
                    _ => 64,
                };
                for arg in args {
                    self.expr(arg, bits);
                }
            }
            Expr::Bin { op, lhs, rhs } => match op {
                BinOp::And
                    if let Expr::Const(mask) = rhs.as_ref()
                        && mask.wrapping_add(1).is_power_of_two()
                        && *mask != 0 =>
                {
                    if bits > mask.count_ones()
                        && let Expr::Reg { index, .. } = lhs.as_ref()
                    {
                        self.readers.extended.insert((*index, mask.count_ones()));
                    }
                    self.expr(lhs, bits.min(mask.count_ones()));
                }
                // A sum through a pointer or a frame address is printed as
                // an index or an offset, whole.
                BinOp::Add | BinOp::Sub if bits < 64 && self.addresses(expr) => {
                    self.expr(lhs, 64);
                    self.expr(rhs, 64);
                }
                BinOp::Sub if matches!(lhs.as_ref(), Expr::Const(0)) => {
                    self.widens(rhs, None, bits);
                    self.expr(rhs, bits);
                }
                BinOp::Xor if matches!(rhs.as_ref(), Expr::Const(u64::MAX)) => {
                    self.widens(lhs, None, bits);
                    self.expr(lhs, bits);
                }
                BinOp::Add | BinOp::Sub | BinOp::Mul => {
                    self.widens(lhs, Some(rhs), bits);
                    self.widens(rhs, Some(lhs), bits);
                    self.expr(lhs, bits);
                    self.expr(rhs, bits);
                }
                BinOp::And | BinOp::Or | BinOp::Xor => {
                    self.expr(lhs, bits);
                    self.expr(rhs, bits);
                }
                BinOp::Shl => {
                    self.widens(lhs, None, bits);
                    let kept = match rhs.as_ref() {
                        Expr::Const(amount) if *amount < 64 => bits.saturating_sub(*amount as u32),
                        _ => bits,
                    };
                    self.expr(lhs, kept);
                    self.expr(rhs, 64);
                }
                BinOp::Shr => {
                    let needed = match rhs.as_ref() {
                        Expr::Const(amount) => bits.saturating_add((*amount).min(64) as u32),
                        _ => 64,
                    };
                    self.expr(lhs, needed);
                    self.expr(rhs, 64);
                }
                BinOp::Sar => {
                    self.expr(lhs, operand_width(lhs, rhs));
                    self.expr(rhs, 64);
                }
                BinOp::DivS | BinOp::ModS => {
                    let width = operand_width(lhs, rhs);
                    self.expr(lhs, width);
                    self.expr(rhs, width);
                }
                BinOp::DivU | BinOp::ModU | BinOp::MulHigh | BinOp::MulHighS => {
                    self.expr(lhs, 64);
                    self.expr(rhs, 64);
                }
            },
        }
    }

    /// Whether a term of the sum `expr` is a pointer, or a 64-bit value
    /// loaded from memory that may be one.
    fn addresses(&self, expr: &Expr) -> bool {
        let mut terms = Vec::new();
        crate::render::naming::sum_terms(expr, false, &mut terms);
        terms.iter().any(|(term, _)| match term {
            Expr::Reg { index, .. } => self.pointers.contains(index),
            Expr::Load { width: 8, .. } => true,
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CType, RegRef, VARIABLE_BASE};

    const V1: u16 = VARIABLE_BASE + 1;
    const V2: u16 = VARIABLE_BASE + 2;

    fn function(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(crate::loader::Isa::X86_64, stmts);
        ir.ret_type = CType::I32;
        ir
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn narrow(ir: &FunctionIr) -> HashMap<u16, Narrow> {
        let ints = [V1, V2].into_iter().collect();
        narrow_variables(ir, &ints, &HashSet::new(), &HashSet::new())
    }

    #[test]
    fn a_counter_masked_to_32_bits_takes_32() {
        // v1 = (v1 + 1) & 0xffffffff, stored as 32 bits and returned as an int.
        let ir = function(vec![
            assign(V1, Expr::Const(0)),
            assign(
                V1,
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Add, Expr::reg(V1, 64), Expr::Const(1)),
                    Expr::Const(0xffff_ffff),
                ),
            ),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(V1, 64),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::reg(V1, 64),
            },
        ]);
        assert_eq!(
            narrow(&ir).get(&V1),
            Some(&Narrow::Read {
                bits: 32,
                extended: false
            })
        );
    }

    #[test]
    fn a_32_bit_value_read_whole_takes_32_bits_without_a_sign() {
        // v1 holds a zero-extended 32-bit load and is compared at 64 bits.
        let ir = function(vec![
            assign(
                V1,
                Expr::Load {
                    addr: Box::new(Expr::reg(7, 64)),
                    width: 4,
                    signed: false,
                },
            ),
            Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(V1, 64),
                rhs: Expr::reg(6, 64),
                target: 0x1000,
            },
        ]);
        assert_eq!(narrow(&ir).get(&V1), Some(&Narrow::Held));
    }

    #[test]
    fn a_wide_value_read_whole_stays_wide() {
        let ir = function(vec![
            assign(V1, Expr::reg(6, 64)),
            Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(V1, 64),
                rhs: Expr::Const(0),
                target: 0x1000,
            },
        ]);
        assert_eq!(narrow(&ir).get(&V1), None);
    }

    #[test]
    fn a_copy_read_whole_keeps_its_source_wide() {
        // v2 = v1 is compared whole, so v1, which v2 is assigned from at
        // 64 bits, is read whole as well.
        let ir = function(vec![
            assign(V1, Expr::reg(6, 64)),
            assign(V2, Expr::reg(V1, 64)),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(V1, 64),
                width: 4,
            },
            Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(V2, 64),
                rhs: Expr::Const(0),
                target: 0x1000,
            },
        ]);
        let narrow = narrow(&ir);
        assert_eq!(narrow.get(&V1), None);
        assert_eq!(narrow.get(&V2), None);
    }

    #[test]
    fn an_index_added_to_a_pointer_is_read_whole() {
        let pointers: HashSet<u16> = [7].into_iter().collect();
        let sum = Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::reg(V1, 64)),
            Expr::Const(0xffff_ffff),
        );
        let ir = function(vec![Stmt::Ret { value: sum }]);
        let readers = read_bits(&ir, &HashMap::new(), &HashSet::new(), &pointers);
        assert_eq!(readers.bits.get(&V1), Some(&64));
    }

    #[test]
    fn a_value_only_stored_as_a_byte_takes_8_bits() {
        let ir = function(vec![
            assign(V1, Expr::reg(6, 64)),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(V1, 64),
                width: 1,
            },
        ]);
        assert_eq!(
            narrow(&ir).get(&V1),
            Some(&Narrow::Read {
                bits: 8,
                extended: false
            })
        );
    }

    #[test]
    fn a_value_extended_with_zeros_by_its_reader_reads_as_unsigned() {
        // v1 is only read as (v1 & 0xffffffff) | ... at 64 bits.
        let ir = function(vec![
            assign(V1, Expr::reg(6, 64)),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(V1, 64), Expr::Const(0xffff_ffff)),
                    Expr::reg(2, 64),
                ),
                width: 8,
            },
        ]);
        assert_eq!(
            narrow(&ir).get(&V1),
            Some(&Narrow::Read {
                bits: 32,
                extended: true
            })
        );
    }

    #[test]
    fn a_32_bit_value_shifted_into_the_high_half_stays_wide() {
        // v1 = load32; stored as v1 << 32, which C would compute at 32 bits
        // for a 32-bit variable, and saved no cast anywhere.
        let ir = function(vec![
            assign(
                V1,
                Expr::Load {
                    addr: Box::new(Expr::reg(7, 64)),
                    width: 4,
                    signed: false,
                },
            ),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::bin(BinOp::Shl, Expr::reg(V1, 64), Expr::Const(32)),
                width: 8,
            },
        ]);
        assert_eq!(narrow(&ir).get(&V1), None);
    }

    #[test]
    fn a_shift_of_a_value_read_at_32_bits_costs_nothing_more() {
        // v1 << 2 reads v1 at 32 bits, which a 64-bit variable casts too.
        let ir = function(vec![
            assign(
                V1,
                Expr::Load {
                    addr: Box::new(Expr::reg(7, 64)),
                    width: 4,
                    signed: false,
                },
            ),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::bin(BinOp::Shl, Expr::reg(V1, 32), Expr::Const(2)),
                width: 8,
            },
        ]);
        assert_eq!(
            narrow(&ir).get(&V1),
            Some(&Narrow::Read {
                bits: 32,
                extended: false
            })
        );
    }
}
