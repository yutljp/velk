//! Instruction normalization for byte signatures.
use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess};
use yaxpeax_arm::armv8::a64;

use super::{Body, ConstantRead, DirectCall, MAX_BYTES, MIN_BYTES, MIN_NAMED_BYTES};
use crate::loader::Isa;

mod arm32;

pub(super) fn normalize(
    isa: Isa,
    bytes: &[u8],
    addr: u64,
    relocated: &HashSet<usize>,
) -> Option<Body> {
    normalize_checked(isa, bytes, addr, relocated).ok()
}

pub(super) fn normalize_checked(
    isa: Isa,
    bytes: &[u8],
    addr: u64,
    relocated: &HashSet<usize>,
) -> Result<Body, &'static str> {
    if bytes.len() < MIN_BYTES || bytes.len() as u64 > MAX_BYTES {
        return Err("function size outside limits");
    }
    let Some(end) = addr.checked_add(bytes.len() as u64) else {
        return Err("invalid instruction or boundary");
    };
    if isa == Isa::I386 && end > u64::from(u32::MAX) {
        return Err("invalid instruction or boundary");
    }
    if matches!(isa, Isa::AArch64 | Isa::Arm32) && !addr.is_multiple_of(4) {
        return Err("invalid instruction or boundary");
    }
    let mut informative_bytes = 0usize;
    let mut body = Body {
        bytes: bytes.to_vec(),
        calls: Vec::new(),
        references: Vec::new(),
        name_eligible: false,
    };
    match isa {
        Isa::X86_64 | Isa::I386 => {
            let mut decoder = Decoder::with_ip(
                if isa == Isa::I386 { 32 } else { 64 },
                bytes,
                addr,
                DecoderOptions::NONE,
            );
            let mut factory = InstructionInfoFactory::new();
            let mut last_code_end = 0;
            let mut last_flow = FlowControl::Next;
            let mut local_targets = Vec::new();
            let mut starts = HashSet::new();
            while decoder.can_decode() {
                let offset = decoder.position();
                starts.insert(addr + offset as u64);
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    return Err("invalid instruction or boundary");
                }
                if instruction.is_ip_rel_memory_operand() {
                    let instruction_info = factory.info(&instruction);
                    let reads = instruction_info.used_memory();
                    let size = instruction.memory_size().size();
                    if reads.len() != 1
                        || reads[0].access() != OpAccess::Read
                        || !(1..=32).contains(&size)
                    {
                        return Err("unsupported PC-relative operand");
                    }
                    let constants = decoder.get_constant_offsets(&instruction);
                    let Some(start) = offset.checked_add(constants.displacement_offset()) else {
                        return Err("invalid instruction or boundary");
                    };
                    if constants.displacement_size() != 4 {
                        return Err("invalid instruction or boundary");
                    }
                    let Some(end) = start.checked_add(4) else {
                        return Err("invalid instruction or boundary");
                    };
                    let Some(displacement) = body.bytes.get_mut(start..end) else {
                        return Err("invalid instruction or boundary");
                    };
                    displacement.fill(0);
                    body.references.push(ConstantRead {
                        offset: start,
                        next: decoder.position(),
                        target: instruction.ip_rel_memory_address(),
                        size,
                    });
                }
                let flow = instruction.flow_control();
                if !matches!(instruction.mnemonic(), Mnemonic::Nop | Mnemonic::Int3) {
                    informative_bytes += instruction.len();
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
                    }
                }
                if matches!(
                    flow,
                    FlowControl::Call
                        | FlowControl::UnconditionalBranch
                        | FlowControl::ConditionalBranch
                ) {
                    let target = instruction.near_branch_target();
                    let constants = decoder.get_constant_offsets(&instruction);
                    let Some(start) = offset.checked_add(constants.immediate_offset()) else {
                        return Err("invalid instruction or boundary");
                    };
                    let width = constants.immediate_size();
                    if flow == FlowControl::Call
                        || !(addr..end).contains(&target)
                        || relocated.contains(&start)
                    {
                        if width == 0 {
                            return Err("invalid instruction or boundary");
                        }
                        let Some(end) = start.checked_add(width) else {
                            return Err("invalid instruction or boundary");
                        };
                        let Some(destination) = body.bytes.get_mut(start..end) else {
                            return Err("invalid instruction or boundary");
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
            if local_targets.iter().any(|target| !starts.contains(target)) {
                return Err("invalid instruction or boundary");
            }
            if matches!(
                last_flow,
                FlowControl::Return | FlowControl::UnconditionalBranch
            ) {
                let Some(code_end) = addr.checked_add(last_code_end as u64) else {
                    return Err("invalid instruction or boundary");
                };
                if local_targets.iter().any(|target| *target >= code_end) {
                    return Err("invalid instruction or boundary");
                }
                body.bytes.truncate(last_code_end);
            }
        }
        Isa::AArch64 => {
            use yaxpeax_arch::{Decoder as _, ReaderBuilder};
            if !bytes.len().is_multiple_of(4) {
                return Err("invalid instruction or boundary");
            }
            let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
            let decoder = a64::InstDecoder::default();
            let mut last_code_end = 0;
            let mut last_terminal = false;
            let mut local_targets = Vec::new();
            let chunks = bytes.as_chunks::<4>().0;
            for (index, chunk) in chunks.iter().enumerate() {
                let Ok(instruction) = decoder.decode(&mut reader) else {
                    return Err("invalid instruction or boundary");
                };
                let offset = index * 4;
                let word = u32::from_le_bytes(*chunk);
                if word != 0xd503_201f && word != 0 {
                    informative_bytes += 4;
                    last_code_end = offset + 4;
                    last_terminal = word & 0xfc00_0000 == 0x1400_0000
                        || matches!(
                            instruction.opcode,
                            a64::Opcode::RET | a64::Opcode::RETAA | a64::Opcode::RETAB
                        );
                }
                if word & 0x1f00_0000 == 0x1000_0000 {
                    return Err("unsupported PC-relative operand");
                }
                if word & 0x3b00_0000 == 0x1800_0000 {
                    let size = match (word >> 30, word & 0x0400_0000 != 0) {
                        (0, _) | (2, false) => 4,
                        (1, _) => 8,
                        (2, true) => 16,
                        _ => return Err("unsupported PC-relative operand"),
                    };
                    let delta = i64::from((((word >> 5) & 0x7ffff) << 13) as i32 >> 11);
                    let Some(target) = addr
                        .checked_add(offset as u64)
                        .and_then(|pc| pc.checked_add_signed(delta))
                    else {
                        return Err("invalid instruction or boundary");
                    };
                    body.bytes[offset..offset + 4]
                        .copy_from_slice(&(word & !0x00ff_ffe0).to_le_bytes());
                    body.references.push(ConstantRead {
                        offset,
                        next: offset + 4,
                        target,
                        size,
                    });
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
                        return Err("invalid instruction or boundary");
                    };
                    if !(addr..end).contains(&target) {
                        return Err("invalid instruction or boundary");
                    }
                    local_targets.push(target);
                }
                if word & 0x7c00_0000 == 0x1400_0000 {
                    let delta = ((word << 6) as i32 >> 4) as i64;
                    let Some(target) = addr
                        .checked_add(offset as u64)
                        .and_then(|pc| pc.checked_add_signed(delta))
                    else {
                        return Err("invalid instruction or boundary");
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
                    return Err("invalid instruction or boundary");
                };
                if local_targets.iter().any(|target| *target >= code_end) {
                    return Err("invalid instruction or boundary");
                }
                body.bytes.truncate(last_code_end);
            }
        }
        Isa::Arm32 => {
            if !arm32::normalize(&mut body, addr, end, relocated, &mut informative_bytes) {
                return Err("unsupported ARM operand or boundary");
            }
        }
        Isa::Unsupported => return Err("unsupported architecture"),
    }
    if body.bytes.len() < MIN_BYTES {
        return Err("function size outside limits");
    }
    let informative_bytes =
        informative_bytes.saturating_sub(body.calls.iter().map(|call| call.width).sum());
    if informative_bytes < MIN_BYTES {
        return Err("insufficient non-address bytes");
    }
    body.name_eligible = body.bytes.len() >= MIN_NAMED_BYTES && informative_bytes >= 24;
    Ok(body)
}
