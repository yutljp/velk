//! MSF 7 stream directories and PDB module symbol streams.

use super::records::{Reader, u32_at};

pub(super) struct Msf<'a> {
    bytes: &'a [u8],
    block_size: usize,
    sizes: Vec<usize>,
    blocks: Vec<Vec<u32>>,
}

impl<'a> Msf<'a> {
    pub fn open(bytes: &'a [u8]) -> Option<Self> {
        if !bytes.starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0") {
            return None;
        }
        let Some(block_size) = u32_at(bytes, 32).map(|n| n as usize) else {
            return None;
        };
        if !matches!(block_size, 512 | 1024 | 2048 | 4096) {
            return None;
        }
        let Some(count) = u32_at(bytes, 40).map(|n| n as usize) else {
            return None;
        };
        if count > bytes.len() / block_size {
            return None;
        }
        let Some(size) = u32_at(bytes, 44).map(|n| n as usize) else {
            return None;
        };
        if size > bytes.len() {
            return None;
        }
        let Some(map) = u32_at(bytes, 52).and_then(|n| (n as usize).checked_mul(block_size)) else {
            return None;
        };
        let directory_blocks = size.div_ceil(block_size);
        if directory_blocks > block_size / 4 {
            return None;
        }
        let mut directory = Vec::new();
        for i in 0..directory_blocks {
            let Some(block) = u32_at(bytes, map.saturating_add(i * 4)) else {
                return None;
            };
            let Some(start) = (block as usize).checked_mul(block_size) else {
                return None;
            };
            let Some(data) = bytes.get(start..start.saturating_add(block_size)) else {
                return None;
            };
            directory.extend_from_slice(data);
        }
        directory.truncate(size);
        let mut reader = Reader(&directory);
        let Some(streams) = reader.u32().map(|n| n as usize) else {
            return None;
        };
        if streams > reader.0.len() / 4 {
            return None;
        }
        let mut sizes = Vec::new();
        for _ in 0..streams {
            let Some(size) = reader.u32() else {
                return None;
            };
            sizes.push(if size == u32::MAX { 0 } else { size as usize });
        }
        let mut blocks = Vec::new();
        for size in &sizes {
            if *size > bytes.len() {
                return None;
            }
            let count = size.div_ceil(block_size);
            if count > reader.0.len() / 4 {
                return None;
            }
            let mut stream = Vec::new();
            for _ in 0..count {
                let Some(block) = reader.u32() else {
                    return None;
                };
                stream.push(block);
            }
            blocks.push(stream);
        }
        Some(Self {
            bytes,
            block_size,
            sizes,
            blocks,
        })
    }

    pub fn stream(&self, index: usize) -> Option<Vec<u8>> {
        let Some(size) = self.sizes.get(index).copied() else {
            return None;
        };
        self.prefix(index, size)
    }

    fn prefix(&self, index: usize, size: usize) -> Option<Vec<u8>> {
        if self.sizes.get(index).is_none_or(|length| size > *length) {
            return None;
        }
        let mut out = Vec::new();
        for block in self.blocks[index]
            .iter()
            .take(size.div_ceil(self.block_size))
        {
            let Some(start) = (*block as usize).checked_mul(self.block_size) else {
                return None;
            };
            let Some(bytes) = self.bytes.get(start..start.saturating_add(self.block_size)) else {
                return None;
            };
            out.extend_from_slice(bytes);
        }
        out.truncate(size);
        Some(out)
    }

    pub fn modules(&self) -> Vec<Vec<u8>> {
        let Some(dbi) = self.stream(3) else {
            return Vec::new();
        };
        let Some(size) = u32_at(&dbi, 24).map(|n| n as usize) else {
            return Vec::new();
        };
        let Some(modules) = dbi.get(64..64usize.saturating_add(size)) else {
            return Vec::new();
        };
        let mut reader = Reader(modules);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut budget = self.bytes.len();
        while reader.0.len() >= 64 {
            let Some(header) = reader.take(64) else { break };
            let stream = u16::from_le_bytes([header[34], header[35]]);
            let Some(size) = u32_at(header, 36).map(|n| n as usize) else {
                break;
            };
            if reader.name().is_none() || reader.name().is_none() {
                break;
            }
            let used = modules.len() - reader.0.len();
            if reader.take((4 - used % 4) % 4).is_none() {
                break;
            }
            if size > budget || !seen.insert(stream) {
                continue;
            }
            budget -= size;
            let Some(symbols) = self.prefix(usize::from(stream), size) else {
                continue;
            };
            if u32_at(&symbols, 0) != Some(4) {
                continue;
            }
            if let Some(data) = symbols.get(4..size) {
                out.push(data.to_vec());
            }
        }
        out
    }
}
