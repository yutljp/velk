//! Bounded memory inspection independent of the execution step budget.

use crate::emulation::{ReadFormat, ReadResult};

use super::{HEAP_SIZE, Runner};

impl Runner<'_> {
    pub(super) fn read_results(&mut self) -> Result<Vec<ReadResult>, String> {
        let mut results = Vec::new();
        // Reads use a separate bounded budget, even when execution exhausted its budget.
        let mut budget = HEAP_SIZE as usize;
        for read in &self.options.reads {
            if usize::from(read.address.is_some())
                + usize::from(read.symbol.is_some())
                + usize::from(read.register.is_some())
                != 1
            {
                return Err("a read needs exactly one of address, symbol or register".into());
            }
            let base = if let Some(word) = &read.address {
                match word.value() {
                    Ok(value) => value,
                    Err(cause) => return Err(cause.to_string()),
                }
            } else if let Some(symbol) = &read.symbol {
                let mut found = self
                    .image
                    .data_symbols
                    .iter()
                    .filter(|(_, name)| *name == symbol);
                let Some((&base, _)) = found.next() else {
                    return Err(format!("unknown data symbol {symbol}"));
                };
                if found.next().is_some() {
                    return Err(format!("ambiguous data symbol {symbol}"));
                }
                base
            } else {
                let name = read.register.as_ref().expect("validated read selector");
                let found = super::physical_registers(self.image.isa)
                    .into_iter()
                    .find(|&index| crate::ir::reg_name(self.image.isa, index, 64) == *name);
                let Some(index) = found else {
                    return Err(format!("unknown full register {name}"));
                };
                match self
                    .register_fact(index, 64)
                    .ok()
                    .and_then(crate::ssa::ranges::Fact::singleton)
                {
                    Some(value) => value,
                    None => return Err(format!("undefined register {name}")),
                }
            };
            let length = read.length;
            if length.is_some_and(|length| length > budget) {
                return Err("requested reads exceed 16 MiB".into());
            }
            let mut bytes = Vec::new();
            let mut terminated = false;
            for offset in 0..length.unwrap_or(budget) {
                let Some(location) = base.checked_add(offset as u64) else {
                    return Err("read address overflows".into());
                };
                let byte = self.machine.load(location, 1) as u8;
                if let Err(stop) = self.memory_error() {
                    return Err(format!("{stop:?}"));
                }
                if length.is_none() && byte == 0 {
                    terminated = true;
                    break;
                }
                bytes.push(byte);
            }
            if length.is_none() && !terminated {
                return Err("read has no terminating NUL within budget".into());
            }
            budget = budget.saturating_sub(bytes.len().max(1));
            let value = match read.format {
                ReadFormat::String => serde_json::json!(String::from_utf8_lossy(&bytes)),
                ReadFormat::Bytes => serde_json::json!(bytes),
                ReadFormat::Hex => {
                    let hex: Vec<String> = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                    serde_json::json!(hex.join(" "))
                }
                ReadFormat::Integers => {
                    let Some(width @ (1 | 2 | 4 | 8)) = read.width else {
                        return Err("integer reads need width 1, 2, 4 or 8".into());
                    };
                    if !bytes.len().is_multiple_of(width as usize) {
                        return Err("integer read length must be a multiple of width".into());
                    }
                    let mut values = Vec::new();
                    for chunk in bytes.chunks_exact(width as usize) {
                        let mut value = [0; 8];
                        value[..chunk.len()].copy_from_slice(chunk);
                        values.push(u64::from_le_bytes(value).to_string());
                    }
                    serde_json::json!(values)
                }
            };
            results.push(ReadResult {
                address: crate::addr::format(base),
                bytes,
                value,
            });
        }
        Ok(results)
    }
}
