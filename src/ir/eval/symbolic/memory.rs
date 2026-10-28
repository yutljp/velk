//! Finite loads from constant tables without splitting execution paths.

use super::{State, Term};
use crate::error::Result;
use crate::ir::semantics;
use crate::ir::smt;
use crate::service::Binary;

impl State {
    pub(super) fn table_load(
        &self,
        binary: &Binary,
        address: &Term,
        candidates: &[u64],
        width: u8,
        signed: bool,
    ) -> Result<Option<Term>> {
        let image = binary.image();
        let Some(&minimum) = candidates.first() else {
            return Ok(None);
        };
        let Some(section) = image.section_at(minimum) else {
            return Ok(None);
        };
        if !section.read_only {
            return Ok(None);
        }
        let maximum = match self.extreme(address, &self.constraints, /* maximum */ true) {
            Ok(Some(maximum)) => maximum,
            Ok(None) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(span) = maximum.checked_sub(minimum).filter(|span| *span < 256) else {
            return Ok(None);
        };
        let Some(end) = maximum.checked_add(u64::from(width)) else {
            return Ok(None);
        };
        let Some(section_end) = section.vaddr.checked_add(section.size) else {
            return Ok(None);
        };
        if end > section_end {
            return Ok(None);
        }
        // The unsigned extrema prove that every feasible address is in this range.
        // Read-only memory cannot have been replaced by symbolic stores or inputs.
        let mut entries = Vec::new();
        for offset in 0..=span {
            let at = minimum + offset;
            let bytes = match self.read_memory(binary, at, usize::from(width)) {
                Ok(bytes) => bytes,
                Err(error) => return Err(error),
            };
            let mut value = 0u64;
            for (index, byte) in bytes.iter().enumerate() {
                let Some(byte) = byte.concrete else {
                    return Ok(None);
                };
                value |= byte << (index * 8);
            }
            if signed {
                value = semantics::sign_extend(value, u32::from(width) * 8) as u64;
            }
            entries.push((at, value));
        }
        self.bind(table_value(&address.text, &entries)).map(Some)
    }
}

fn table_value(address: &str, entries: &[(u64, u64)]) -> String {
    let mut text = smt::constant(0);
    for &(at, value) in entries.iter().rev() {
        text = format!(
            "(ite (= {address} {}) {} {text})",
            smt::constant(at),
            smt::constant(value)
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smt_table_selection_matches_array_reads() {
        if !smt::Proofs::available() {
            return;
        }
        let mut proofs = smt::Proofs::default();
        for base in [0, 0x400000, u64::MAX - 255] {
            for count in [1, 8, 16, 32] {
                let mut entries = Vec::new();
                let mut reference = format!(
                    "((as const (Array (_ BitVec 64) (_ BitVec 64))) {})",
                    smt::constant(0)
                );
                for index in 0..count {
                    let at = base + index;
                    let value = index.wrapping_mul(0x123456789abcdef).wrapping_sub(128);
                    entries.push((at, value));
                    reference = format!(
                        "(store {reference} {} {})",
                        smt::constant(at),
                        smt::constant(value)
                    );
                }
                proofs.predicate(
                    format!("table {base:x} {count}"),
                    &table_value("r0", &entries),
                    &format!("(select {reference} r0)"),
                );
            }
        }
        proofs.predicate(
            "one table entry replaces the previous value at its address",
            "(ite (= r0 r1) r2 r3)",
            "(select (store ((as const (Array (_ BitVec 64) (_ BitVec 64))) r3) r1 r2) r0)",
        );
        proofs.counterexample(
            "nonzero table byte is retained",
            &table_value("r0", &[(42, 255)]),
            &smt::constant(0),
        );
        proofs.check();
    }
}
