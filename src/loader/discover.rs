use std::collections::BTreeMap;

use crate::loader::Function;
use crate::loader::Section;

/// Function starts in a stripped AArch64 image: the first non-padding
/// instruction after a return, trap or tail call, unless a branch targets it.
pub(crate) fn aarch64_prologues(
    bytes: &[u8],
    base: u64,
    relocated: &std::collections::HashSet<u64>,
) -> Vec<u64> {
    let targets = aarch64_branch_targets(bytes, base);
    let mut starts = Vec::new();
    let mut offset = 0usize;
    let mut closed = false;
    while offset + 4 <= bytes.len() {
        let Some(word) = read_word(bytes, offset) else {
            offset += 4;
            continue;
        };
        let padding = is_aarch64_padding(word);
        if closed && !padding {
            // A branch target after a return is still part of the same function.
            if !targets.contains(&(base + offset as u64)) {
                starts.push(base + offset as u64);
            }
            closed = false;
        }
        if padding {
            offset += 4;
            continue;
        }
        // `ret`, `retaa`, `brk #0` and `br` (an indirect tail call) end a function.
        if matches!(word, 0xd65f_03c0 | 0xd65f_0bff | 0xd420_0000)
            || word & 0xffff_fc1f == 0xd61f_0000
        {
            closed = true;
        } else if let Some(target) = aarch64_tail_jump(word, base + offset as u64) {
            let pc = base + offset as u64;
            // A branch to itself or one with a pending relocation is an
            // unresolved call; one leaving the section is a tail call.
            if target == pc
                || !(base..base + bytes.len() as u64).contains(&target)
                || relocated.contains(&pc)
            {
                closed = true;
            }
        }
        offset += 4;
    }
    starts.dedup();
    starts
}

/// The target of a `b` instruction (unconditional, no link).
fn aarch64_tail_jump(word: u32, pc: u64) -> Option<u64> {
    // `b`: bits 31..26 = 000101
    if word >> 26 != 0b000101 {
        return None;
    }
    let imm26 = (word & 0x03ff_ffff) as i64;
    let signed = (imm26 << 6) >> 6;
    Some(pc.wrapping_add((signed * 4) as u64))
}

fn aarch64_branch_targets(bytes: &[u8], base: u64) -> std::collections::HashSet<u64> {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{self, Opcode, Operand};
    let decoder = a64::InstDecoder::default();
    let mut targets = std::collections::HashSet::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let mut reader = yaxpeax_arch::U8Reader::new(&bytes[offset..]);
        let Ok(instruction) = decoder.decode(&mut reader) else {
            offset += 4;
            continue;
        };
        let pc = base + offset as u64;
        let branch = match instruction.opcode {
            Opcode::B | Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ => {
                Some(instruction.operands[0])
            }
            Opcode::TBZ | Opcode::TBNZ => Some(instruction.operands[2]),
            _ => None,
        };
        if let Some(operand) = branch
            && let Operand::PCOffset(delta) = operand
        {
            targets.insert(pc.wrapping_add(delta as u64));
        }
        // Every AArch64 instruction is one word.
        offset += 4;
    }
    targets
}

pub(crate) fn read_word(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(crate) fn is_aarch64_padding(word: u32) -> bool {
    matches!(
        word,
        0xd503_201f // nop
            | 0xd503_233f // paciasp
            | 0xd503_237f // pacibsp
            | 0xd503_245f // bti c
            | 0xd503_249f // bti j
            | 0x0000_0000
    )
}

/// True when `target` decodes to padding, where an unresolved jump lands.
fn x86_is_padding(bytes: &[u8], base: u64, target: u64) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    if target < base {
        return false;
    }
    let offset = (target - base) as usize;
    let Some(rest) = bytes.get(offset..) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, rest, target, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return false;
    }
    matches!(decoder.decode().mnemonic(), Mnemonic::Nop | Mnemonic::Int3)
}

/// Function starts in a stripped x86-64 image: the first non-padding
/// instruction after a return or tail jump, unless a branch targets it.
pub(crate) fn x86_prologues(bytes: &[u8], base: u64) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut starts = Vec::new();
    let mut targets = std::collections::HashSet::new();
    let mut closed = false;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        let ip = instruction.ip();
        if closed && !targets.contains(&ip) && ip != base && !x86_is_padding(bytes, base, ip) {
            starts.push(ip);
            closed = false;
        } else if closed && targets.contains(&ip) && !x86_is_padding(bytes, base, ip) {
            // A branch target of the previous function: it continues here.
            closed = false;
        }
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                let target = instruction.near_branch_target();
                if !x86_is_padding(bytes, base, target) {
                    targets.insert(target);
                }
            }
            FlowControl::UnconditionalBranch => {
                let target = instruction.near_branch_target();
                if !x86_is_padding(bytes, base, target) {
                    targets.insert(target);
                }
                // A jump to itself or to padding is unresolved; one leaving
                // the section is a tail call. All end the function.
                if target == ip
                    || !(base..base + bytes.len() as u64).contains(&target)
                    || x86_is_padding(bytes, base, target)
                {
                    closed = true;
                }
            }
            FlowControl::Return | FlowControl::IndirectBranch => closed = true,
            _ => {}
        }
    }
    starts
}

pub(crate) fn estimate_sizes(sections: &[Section], functions: &mut BTreeMap<u64, Function>) {
    let addrs: Vec<u64> = functions.keys().copied().collect();

    for addr in &addrs {
        let Some(func) = functions.get(addr) else {
            continue;
        };
        if func.size.is_some() {
            continue;
        }
        let Some(section) = sections
            .iter()
            .find(|s| s.executable && *addr >= s.vaddr && *addr < s.vaddr.saturating_add(s.size))
        else {
            continue;
        };
        let end = addrs
            .iter()
            .copied()
            .filter(|a| *a > *addr && *a < section.vaddr.saturating_add(section.size))
            .min()
            .unwrap_or_else(|| section.vaddr.saturating_add(section.size));
        let delta = end - addr;
        if (1..=0x4000).contains(&delta) {
            let func = functions.get_mut(addr).expect("entry exists");
            func.size = Some(delta);
            func.size_estimated = true;
        }
    }
}
