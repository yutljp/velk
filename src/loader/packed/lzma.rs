//! Decode the UPX LZMA properties used by the checked fixtures with a bounded sink.

use std::io;

use super::DecodeError;

struct Output {
    bytes: Vec<u8>,
    limit: usize,
}

impl io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZMA output exceeds block size",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn decode(input: &[u8], size: usize) -> Result<Vec<u8>, DecodeError> {
    if size > super::MAX_FILE_SIZE as usize || input.len() < 7 {
        return Err(DecodeError::invalid(0, "invalid UPX LZMA block size"));
    }
    if input[..2] != [0x1a, 3] {
        return Err(DecodeError::Unsupported(format!(
            "UPX LZMA properties {:02x?}",
            &input[..2]
        )));
    }
    let dictionary = size.max(4096);
    let mut stream = Vec::with_capacity(input.len() + 3);
    stream.push(0x5d);
    stream.extend_from_slice(&(dictionary as u32).to_le_bytes());
    stream.extend_from_slice(&input[2..]);
    let mut reader = io::Cursor::new(stream);
    let mut output = Output {
        bytes: Vec::new(),
        limit: size,
    };
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(size as u64)),
        memlimit: Some(dictionary),
        allow_incomplete: false,
    };
    if let Err(error) = lzma_rs::lzma_decompress_with_options(&mut reader, &mut output, &options) {
        return Err(DecodeError::invalid(
            reader.position() as usize,
            &format!("invalid UPX LZMA stream: {error}"),
        ));
    }
    if output.bytes.len() != size || reader.position() as usize != reader.get_ref().len() {
        return Err(DecodeError::invalid(
            reader.position() as usize,
            "LZMA size or end mismatch",
        ));
    }
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_streams_have_bounded_output_and_dictionary() {
        let mut state = 0x918fb2c4u32;
        let mut input = [0u8; 128];
        for iteration in 0..4096 {
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            input[..2].copy_from_slice(&[0x1a, 3]);
            let length = iteration % (input.len() + 1);
            let size = (state & 4095) as usize;
            if let Ok(output) = decode(&input[..length], size) {
                assert_eq!(output.len(), size);
            }
            assert!(decode(&input[..length], usize::MAX).is_err());
        }
    }
}
