use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use yaxpeax_arch::{Decoder as _, ReaderBuilder};
use yaxpeax_arm::armv8::a64;

use crate::error::LiftError;
use crate::loader::{Image, Isa};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Extent {
    /// Ends at the first return or unconditional jump.
    FirstExit,
    Whole,
}

pub fn listing(
    image: &Image,
    addr: u64,
    len: u64,
    max_lines: usize,
) -> Result<Vec<String>, LiftError> {
    disassemble(image, addr, len, max_lines, Extent::Whole)
}

/// The opening instructions up to the first exit; empty when the bytes cannot be read.
pub fn preview(image: &Image, addr: u64, len: u64, max_lines: usize) -> Vec<String> {
    disassemble(image, addr, len, max_lines, Extent::FirstExit).unwrap_or_default()
}

fn disassemble(
    image: &Image,
    addr: u64,
    len: u64,
    max_lines: usize,
    extent: Extent,
) -> Result<Vec<String>, LiftError> {
    let addr = image.code_address(addr);
    let Some(bytes) = image.read_vaddr(addr, len) else {
        return Err(LiftError::Unreadable);
    };
    match image.isa {
        Isa::I386 => Ok(x86_64(bytes, addr, max_lines, extent, 32)),
        Isa::X86_64 => Ok(x86_64(bytes, addr, max_lines, extent, 64)),
        Isa::AArch64 => Ok(aarch64(bytes, addr, max_lines, extent)),
        Isa::Arm32
            if image.format == crate::loader::Format::Elf
                && image.byte_order() == Some(object::Endianness::Little) =>
        {
            Ok(crate::lift::arm32_listing(image, bytes, addr, max_lines))
        }
        Isa::Arm32 => Err(LiftError::UnsupportedIsa),
        Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

fn x86_64(bytes: &[u8], addr: u64, max_lines: usize, extent: Extent, bitness: u32) -> Vec<String> {
    let mut decoder = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut lines = Vec::new();
    while lines.len() < max_lines && decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        lines.push(format!("0x{:<12x} {}", instruction.ip(), instruction));
        let exits = matches!(
            instruction.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::Exception
                | FlowControl::Interrupt
        );
        if extent == Extent::FirstExit && exits {
            break;
        }
    }
    lines
}

fn aarch64(bytes: &[u8], addr: u64, max_lines: usize, extent: Extent) -> Vec<String> {
    let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
    let decoder = a64::InstDecoder::default();
    let mut lines = Vec::new();
    for index in 0..(bytes.len() / 4).min(max_lines) {
        let pc = addr + 4 * index as u64;
        match decoder.decode(&mut reader) {
            Ok(instruction) => {
                lines.push(format!("0x{pc:<12x} {instruction}"));
                if extent == Extent::FirstExit && instruction.opcode == a64::Opcode::RET {
                    break;
                }
            }
            Err(error) => {
                lines.push(format!("0x{pc:<12x} (undecodable: {error})"));
                break;
            }
        }
    }
    lines
}
