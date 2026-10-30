//! UCRT integer formatting and scanning through its exported stdio entry points.

use crate::ir::{CallKind, Convention};
use crate::loader::Isa;

use super::{Arguments, Runner, Stop, address, error};

impl Runner<'_> {
    // A bad option, locale, argument or memory range stops the complete UCRT call.
    pub(in crate::ir::eval::emulation) fn windows_ucrt_io(
        &mut self,
        name: &str,
        values: &[u64],
    ) -> Result<u64, Stop> {
        let options = values[0];
        let values = &values[1..];
        let output = name == "__stdio_common_vsprintf";
        let scan = name == "__stdio_common_vsscanf";
        if options & !if output { 3 } else { 0 } != 0 || options == 3 {
            return Err(error(format!("{name}: unsupported options 0x{options:x}")));
        }
        let format_index = if output || scan { 2 } else { 1 };
        if values[format_index + 1] != 0 {
            return Err(error(format!("{name}: explicit locales are unsupported")));
        }
        let convention = if self.image.isa == Isa::I386 {
            Convention::Cdecl
        } else {
            Convention::Win64
        };
        let mut args = Arguments::new(convention, CallKind::Invoke);
        args.set_list(self, values[format_index + 2])?;
        let format = self.bytes_at(values[format_index], None)?;
        if scan {
            let unlimited = if self.image.isa == Isa::I386 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            if values[1] != unlimited {
                return Err(error(format!("{name}: bounded input is unsupported")));
            }
            let input = self.bytes_at(values[0], None)?;
            return self
                .scan_input(&format, &input, &mut args)
                .map(|(count, _)| count);
        }
        let bytes = self.format_output(&format, &mut args)?;
        if !output {
            let stream = self.stream(values[0], /* input */ false)?;
            self.windows_crt_write(stream, &bytes)?;
            return Ok(bytes.len() as u64);
        }
        let capacity = values[1];
        if capacity == 0 && options & 2 != 0 {
            return Ok(bytes.len() as u64);
        }
        if capacity == 0 || values[0] == 0 {
            return Err(error(format!("{name}: invalid output buffer")));
        }
        let truncated = bytes.len() as u64 >= capacity;
        if truncated && options & 2 == 0 {
            return Err(error(format!(
                "{name}: truncation without standard snprintf options is unsupported"
            )));
        }
        let count = (bytes.len() as u64).min(capacity - 1) as usize;
        self.store_bytes(values[0], &bytes[..count])?;
        self.store_bytes(address(values[0], count)?, &[0])?;
        Ok(bytes.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ucrt_termination_bounds_smt() {
        use crate::ir::smt::{self, Proofs};

        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for width in [32, 64] {
            let length = smt::low("r0", width);
            let capacity = smt::low("r1", width);
            let zero = smt::constant(0);
            let one = smt::constant(1);
            let available = format!("(bvsub {capacity} {one})");
            let count = format!("(ite (bvult {length} {available}) {length} {available})");
            proofs.predicate(
                format!("{width}-bit snprintf terminator fits nonzero capacity"),
                &format!("(or (= {capacity} {zero}) (bvult {count} {capacity}))"),
                "true",
            );
            proofs.predicate(
                format!("{width}-bit snprintf copies at most the formatted length"),
                &format!("(or (= {capacity} {zero}) (bvule {count} {length}))"),
                "true",
            );
            let wrong = format!("(ite (bvult {length} {capacity}) {length} {capacity})");
            proofs.counterexample(
                format!("{width}-bit snprintf must reserve the terminator byte"),
                &format!("(or (= {capacity} {zero}) (bvult {wrong} {capacity}))"),
                "true",
            );
        }
        proofs.check();
    }
}
