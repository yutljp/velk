//! Decoded instruction immediates, excluding data and branch displacements.
use crate::deadline::passed;
use crate::error::Result;
use crate::loader::{Image, Isa};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use serde::Serialize;
use std::time::Instant;
use yaxpeax_arch::{Decoder as _, ReaderBuilder};
use yaxpeax_arm::armv8::a64;

#[derive(Debug, Serialize)]
pub struct Constant {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub instruction: u64,
    #[serde(serialize_with = "crate::addr::serialize")]
    pub value: u64,
    pub operand: usize,
    #[serde(serialize_with = "crate::addr::serialize_option")]
    pub function: Option<u64>,
}

pub fn search(image: &Image, value: u64, deadline: Option<Instant>) -> Result<Vec<Constant>> {
    let mut result = Vec::new();
    for section in image.sections.iter().filter(|s| s.executable && s.loaded) {
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        let mut add = |instruction, operand, immediate| {
            if immediate != value {
                return;
            }
            let function = image
                .functions
                .range(..=instruction)
                .next_back()
                .filter(|(addr, f)| {
                    instruction
                        < addr.saturating_add(f.size.unwrap_or(crate::analysis::UNKNOWN_SIZE))
                })
                .map(|(addr, _)| *addr);
            result.push(Constant {
                instruction,
                operand,
                value,
                function,
            });
        };
        match image.isa {
            Isa::X86_64 => {
                let mut decoder = Decoder::with_ip(64, bytes, section.vaddr, DecoderOptions::NONE);
                let mut count = 0usize;
                while decoder.can_decode() {
                    if count.is_multiple_of(1024)
                        && let Err(error) = passed(deadline)
                    {
                        return Err(error);
                    }
                    count += 1;
                    let instruction = decoder.decode();
                    if instruction.is_invalid() {
                        continue;
                    }
                    for operand in 0..instruction.op_count() {
                        let immediate = match instruction.op_kind(operand) {
                            OpKind::Immediate8 => instruction.immediate8() as u64,
                            OpKind::Immediate8_2nd => instruction.immediate8_2nd() as u64,
                            OpKind::Immediate16 => instruction.immediate16() as u64,
                            OpKind::Immediate32 => instruction.immediate32() as u64,
                            OpKind::Immediate64 => instruction.immediate64(),
                            OpKind::Immediate8to16 => instruction.immediate8to16() as u16 as u64,
                            OpKind::Immediate8to32 => instruction.immediate8to32() as u32 as u64,
                            OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
                            OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
                            _ => continue,
                        };
                        add(instruction.ip(), operand as usize, immediate);
                    }
                }
            }
            Isa::AArch64 => {
                let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
                let decoder = a64::InstDecoder::default();
                for offset in 0..bytes.len() / 4 {
                    if offset.is_multiple_of(1024)
                        && let Err(error) = passed(deadline)
                    {
                        return Err(error);
                    }
                    let Some(pc) = section.vaddr.checked_add((offset as u64).saturating_mul(4))
                    else {
                        break;
                    };
                    let Ok(instruction) = decoder.decode(&mut reader) else {
                        continue;
                    };
                    for (operand, arg) in instruction.operands.iter().enumerate() {
                        match arg {
                            a64::Operand::Immediate(immediate) => {
                                add(pc, operand, *immediate as u64)
                            }
                            a64::Operand::Imm64(immediate) => add(pc, operand, *immediate),
                            a64::Operand::ImmShift(immediate, shift) => {
                                if let Some(immediate) =
                                    (*immediate as u64).checked_shl(*shift as u32)
                                {
                                    add(pc, operand, immediate);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Isa::Unsupported => {}
        }
    }
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    Ok(result)
}
