//! UPX ELF block layout and reconstruction of the original file ranges.

use super::format::{Checksum, number, slice};
use super::{DecodeError, MAX_FILE_SIZE, decompress, filter};

struct Segment {
    offset: usize,
    size: usize,
    flags: usize,
}

struct Header {
    end: usize,
    machine: usize,
    format: u8,
    segments: Vec<Segment>,
}

fn header(bytes: &[u8]) -> Result<Header, DecodeError> {
    let identity = slice(bytes, 0, 6)?;
    if &identity[..4] != b"\x7fELF" || identity[5] != 1 || !matches!(identity[4], 1 | 2) {
        return Err(DecodeError::Unsupported(
            "ELF class or byte order".to_owned(),
        ));
    }
    let machine = number(bytes, 18, 2)?;
    let (size, word, format) = match (identity[4], machine) {
        (2, 62) => (64, 8, 22),
        (2, 183) => (64, 8, 42),
        (1, 3) => (52, 4, 12),
        (1, 40) => (52, 4, 23),
        _ => {
            return Err(DecodeError::Unsupported(format!(
                "ELF class {} machine {machine}",
                identity[4]
            )));
        }
    };
    let offset = number(bytes, if word == 8 { 32 } else { 28 }, word)?;
    let width = number(bytes, size - 10, 2)?;
    let count = number(bytes, size - 8, 2)?;
    if offset != size || width != if word == 8 { 56 } else { 32 } || count == 0 || count > 128 {
        return Err(DecodeError::Unsupported(
            "ELF program header layout".to_owned(),
        ));
    }
    let end = offset + width * count;
    slice(bytes, 0, end)?;
    let mut segments = Vec::new();
    for index in 0..count {
        let start = offset + width * index;
        if number(bytes, start, 4)? != 1 {
            continue;
        }
        let offset = number(bytes, start + if word == 8 { 8 } else { 4 }, word)?;
        let size = number(bytes, start + if word == 8 { 32 } else { 16 }, word)?;
        let memory_size = number(bytes, start + if word == 8 { 40 } else { 20 }, word)?;
        let address = number(bytes, start + if word == 8 { 16 } else { 8 }, word)?;
        if memory_size < size || address.checked_add(memory_size).is_none() {
            return Err(DecodeError::invalid(
                start,
                "invalid ELF segment memory range",
            ));
        }
        if offset > MAX_FILE_SIZE as usize || size > MAX_FILE_SIZE as usize - offset {
            return Err(DecodeError::invalid(start, "ELF segment exceeds 128 MiB"));
        }
        segments.push(Segment {
            offset,
            size,
            flags: number(bytes, start + if word == 8 { 4 } else { 24 }, 4)?,
        });
    }
    Ok(Header {
        end,
        machine,
        format,
        segments,
    })
}

/// The fixed layout also recognizes files whose identification magic was overwritten.
pub(super) fn recognizes(bytes: &[u8]) -> bool {
    let Ok(header) = header(bytes) else {
        return false;
    };
    let offset = header.end;
    let Ok(info) = slice(bytes, offset, 36) else {
        return false;
    };
    info[10] == 14
        && info[11] == header.format
        && matches!(info[32], 2 | 3 | 5 | 6 | 8 | 9 | 14)
        && number(info, 16, 4).is_ok_and(|size| (64..=MAX_FILE_SIZE as usize).contains(&size))
        && number(info, 24, 4).is_ok_and(|size| size >= header.end)
}

struct Stream<'input> {
    input: &'input [u8],
    position: usize,
    block_size: usize,
    machine: usize,
    compressed: Checksum,
    uncompressed: Checksum,
}

impl Stream<'_> {
    fn block(&mut self, limit: usize) -> Result<Vec<u8>, DecodeError> {
        let start = self.position;
        let info = slice(self.input, start, 12)?;
        let size = number(info, 0, 4)?;
        let compressed = number(info, 4, 4)?;
        let supported_filter = match self.machine {
            3 | 62 => matches!(info[9], 0 | 0x26 | 0x46 | 0x49),
            40 => matches!(info[9], 0 | 0x50),
            183 => matches!(info[9], 0 | 0x52),
            _ => false,
        };
        if !supported_filter {
            return Err(DecodeError::Unsupported(format!(
                "filter 0x{:02x} for ELF machine {}",
                info[9], self.machine
            )));
        }
        if info[11] != 0 {
            return Err(DecodeError::Unsupported(format!(
                "UPX block reserved byte 0x{:02x}",
                info[11]
            )));
        }
        if size == 0 || size > limit.min(self.block_size) || compressed == 0 || compressed > size {
            return Err(DecodeError::invalid(start, "invalid UPX block sizes"));
        }
        let data = slice(self.input, start + 12, compressed)?;
        self.position = start + 12 + compressed;
        self.compressed.update(data);
        let mut output = if compressed == size {
            data.to_vec()
        } else {
            decompress(data, size, info[8])?
        };
        filter::decode(&mut output, info[9], info[10])?;
        self.uncompressed.update(&output);
        Ok(output)
    }

    fn fill(&mut self, output: &mut [u8]) -> Result<(), DecodeError> {
        let mut offset = 0;
        while offset < output.len() {
            let block = self.block(output.len() - offset)?;
            output[offset..offset + block.len()].copy_from_slice(&block);
            offset += block.len();
        }
        Ok(())
    }
}

pub(super) fn unpack(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let packed = header(bytes)?;
    let info = slice(bytes, packed.end, 24)?;
    if info[10] != 14 || info[11] != packed.format {
        return Err(DecodeError::Unsupported(format!(
            "ELF UPX version {} format {}",
            info[10], info[11]
        )));
    }
    let size = number(info, 16, 4)?;
    let block_size = number(info, 20, 4)?;
    if !(64..=MAX_FILE_SIZE as usize).contains(&size) || block_size == 0 || block_size > size {
        return Err(DecodeError::invalid(
            packed.end + 12,
            "invalid UPX file or block size",
        ));
    }
    let Some(pack_offset) = bytes.len().checked_sub(36) else {
        return Err(DecodeError::invalid(bytes.len(), "missing UPX PackHeader"));
    };
    let pack = slice(bytes, pack_offset, 36)?;
    if pack[30] != 0 {
        return Err(DecodeError::Unsupported(format!(
            "UPX PackHeader parameter at byte 30: 0x{:02x}",
            pack[30]
        )));
    }
    let checksum: u32 = pack[4..31].iter().map(|byte| u32::from(*byte)).sum();
    if checksum % 251 != u32::from(pack[31])
        || pack[4] != info[10]
        || pack[5] != info[11]
        || number(pack, 16, 4)? != size
        || number(pack, 24, 4)? != size
        || number(pack, 20, 4)? != pack_offset
        || number(pack, 32, 4)? != packed.end + 12
        || number(info, 8, 2)? == 0
        || number(info, 8, 2)? > bytes.len()
    {
        return Err(DecodeError::invalid(
            pack_offset,
            "UPX PackHeader size or checksum mismatch",
        ));
    }
    let mut stream = Stream {
        input: bytes,
        position: packed.end + 24,
        block_size,
        machine: packed.machine,
        compressed: Checksum::new(),
        uncompressed: Checksum::new(),
    };
    let first = stream.block(size)?;
    let original = header(&first)?;
    if original.machine != packed.machine || first.len() != original.end {
        return Err(DecodeError::invalid(
            stream.position,
            "invalid recovered ELF program headers",
        ));
    }
    if original
        .segments
        .first()
        .is_none_or(|segment| segment.offset != 0)
    {
        return Err(DecodeError::Unsupported(
            "ELF headers outside the first load segment".to_owned(),
        ));
    }
    let mut output = vec![0; size];
    output[..first.len()].copy_from_slice(&first);
    let mut end = 0;
    for segment in &original.segments {
        if segment.offset < end || segment.offset + segment.size > size {
            return Err(DecodeError::Unsupported(
                "overlapping or unordered ELF segments".to_owned(),
            ));
        }
        let start = if segment.offset == 0 {
            first.len()
        } else {
            segment.offset
        };
        end = segment.offset + segment.size;
        if start > end {
            return Err(DecodeError::invalid(
                start,
                "ELF headers exceed the first segment",
            ));
        }
        stream.fill(&mut output[start..end])?;
    }
    let Some(loader) = packed
        .segments
        .iter()
        .find(|segment| segment.flags & 1 != 0)
    else {
        return Err(DecodeError::invalid(0, "UPX ELF has no load segments"));
    };
    slice(bytes, loader.offset, loader.size)?;
    if stream.position > loader.offset + loader.size {
        return Err(DecodeError::invalid(
            stream.position,
            "UPX blocks exceed the loader segment",
        ));
    }
    stream.position = (loader.offset + loader.size + 3) & !3;
    end = 0;
    for segment in &original.segments {
        stream.fill(&mut output[end..segment.offset])?;
        end = segment.offset + segment.size;
    }
    stream.fill(&mut output[end..])?;
    if number(pack, 8, 4)? != stream.uncompressed.value()
        || number(pack, 12, 4)? != stream.compressed.value()
    {
        return Err(DecodeError::invalid(
            pack_offset,
            "UPX PackHeader size or checksum mismatch",
        ));
    }
    Ok(output)
}
