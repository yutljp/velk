//! Instruction normalization for byte signatures.
use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};
use yaxpeax_arm::armv8::a64;

use super::{Body, DirectCall, MAX_BYTES, MIN_BYTES};
use crate::loader::Isa;

pub(super) fn normalize(
    isa: Isa,
    bytes: &[u8],
    addr: u64,
    relocated: &HashSet<usize>,
) -> Option<Body> {
    if bytes.len() < MIN_BYTES || bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    let Some(end) = addr.checked_add(bytes.len() as u64) else {
        return None;
    };
    let mut information = 0usize;
    let mut body = Body {
        bytes: bytes.to_vec(),
        calls: Vec::new(),
    };
    match isa {
        Isa::X86_64 => {
            let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
            let mut last_code_end = 0;
            let mut last_flow = FlowControl::Next;
            let mut local_targets = Vec::new();
            while decoder.can_decode() {
                let offset = decoder.position();
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    return None;
                }
                if instruction.is_ip_rel_memory_operand() {
                    return None;
                }
                let flow = instruction.flow_control();
                if !matches!(instruction.mnemonic(), Mnemonic::Nop | Mnemonic::Int3) {
                    information += instruction.len();
                    last_code_end = decoder.position();
                    last_flow = flow;
                }
                if matches!(
                    flow,
                    FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                ) {
                    let target = instruction.near_branch_target();
                    if (addr..end).contains(&target) {
                        local_targets.push(target);
                    } else if flow == FlowControl::ConditionalBranch {
                        return None;
                    }
                }
                if matches!(
                    flow,
                    FlowControl::IndirectCall | FlowControl::IndirectBranch
                ) {
                    return None;
                }
                if matches!(flow, FlowControl::Call | FlowControl::UnconditionalBranch) {
                    let target = instruction.near_branch_target();
                    let constants = decoder.get_constant_offsets(&instruction);
                    let Some(start) = offset.checked_add(constants.immediate_offset()) else {
                        return None;
                    };
                    let width = constants.immediate_size();
                    if flow == FlowControl::Call
                        || !(addr..end).contains(&target)
                        || relocated.contains(&start)
                    {
                        if width == 0 {
                            return None;
                        }
                        let Some(end) = start.checked_add(width) else {
                            return None;
                        };
                        let Some(destination) = body.bytes.get_mut(start..end) else {
                            return None;
                        };
                        destination.fill(0);
                        body.calls.push(DirectCall {
                            offset: start,
                            width,
                            target,
                        });
                    }
                }
            }
            if matches!(
                last_flow,
                FlowControl::Return | FlowControl::UnconditionalBranch
            ) {
                let Some(code_end) = addr.checked_add(last_code_end as u64) else {
                    return None;
                };
                if local_targets.iter().any(|target| *target >= code_end) {
                    return None;
                }
                body.bytes.truncate(last_code_end);
            }
        }
        Isa::AArch64 => {
            use yaxpeax_arch::{Decoder as _, ReaderBuilder};
            if !bytes.len().is_multiple_of(4) {
                return None;
            }
            let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
            let decoder = a64::InstDecoder::default();
            let mut last_code_end = 0;
            let mut last_terminal = false;
            let mut local_targets = Vec::new();
            let chunks = bytes.as_chunks::<4>().0;
            for (index, chunk) in chunks.iter().enumerate() {
                let Ok(instruction) = decoder.decode(&mut reader) else {
                    return None;
                };
                if matches!(
                    instruction.opcode,
                    a64::Opcode::BR
                        | a64::Opcode::BLR
                        | a64::Opcode::BRAA
                        | a64::Opcode::BRAAZ
                        | a64::Opcode::BRAB
                        | a64::Opcode::BRABZ
                        | a64::Opcode::BLRAA
                        | a64::Opcode::BLRAAZ
                        | a64::Opcode::BLRAB
                        | a64::Opcode::BLRABZ
                ) {
                    return None;
                }
                let offset = index * 4;
                let word = u32::from_le_bytes(*chunk);
                if word != 0xd503_201f && word != 0 {
                    information += 4;
                    last_code_end = offset + 4;
                    last_terminal = word & 0xfc00_0000 == 0x1400_0000
                        || matches!(
                            instruction.opcode,
                            a64::Opcode::RET | a64::Opcode::RETAA | a64::Opcode::RETAB
                        );
                }
                // PC-relative data can change independently of the function body.
                if word & 0x1f00_0000 == 0x1000_0000 || word & 0x3b00_0000 == 0x1800_0000 {
                    return None;
                }
                let conditional =
                    word & 0xff00_0010 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000;
                let test_bit = word & 0x7e00_0000 == 0x3600_0000;
                if conditional || test_bit {
                    let delta = if test_bit {
                        (((word >> 5) & 0x3fff) << 18) as i32 >> 16
                    } else {
                        (((word >> 5) & 0x7ffff) << 13) as i32 >> 11
                    };
                    let Some(target) = addr
                        .checked_add(offset as u64)
                        .and_then(|pc| pc.checked_add_signed(i64::from(delta)))
                    else {
                        return None;
                    };
                    if !(addr..end).contains(&target) {
                        return None;
                    }
                    local_targets.push(target);
                }
                if word & 0x7c00_0000 == 0x1400_0000 {
                    let delta = ((word << 6) as i32 >> 4) as i64;
                    let Some(target) = addr
                        .checked_add(offset as u64)
                        .and_then(|pc| pc.checked_add_signed(delta))
                    else {
                        return None;
                    };
                    if (addr..end).contains(&target) {
                        local_targets.push(target);
                    }
                    if word & 0x8000_0000 != 0
                        || !(addr..end).contains(&target)
                        || relocated.contains(&offset)
                    {
                        body.bytes[offset..offset + 4]
                            .copy_from_slice(&(word & 0xfc00_0000).to_le_bytes());
                        body.calls.push(DirectCall {
                            offset,
                            width: 4,
                            target,
                        });
                    }
                }
            }
            if last_terminal {
                let Some(code_end) = addr.checked_add(last_code_end as u64) else {
                    return None;
                };
                if local_targets.iter().any(|target| *target >= code_end) {
                    return None;
                }
                body.bytes.truncate(last_code_end);
            }
        }
        Isa::I386 | Isa::Arm32 | Isa::Unsupported => return None,
    }
    if body.bytes.len() < MIN_BYTES {
        return None;
    }
    if information.saturating_sub(body.calls.iter().map(|call| call.width).sum()) < 24 {
        return None;
    }
    Some(body)
}
