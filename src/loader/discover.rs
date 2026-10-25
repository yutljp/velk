use std::collections::BTreeMap;

use crate::loader::Function;
use crate::loader::NameSource;
use crate::loader::Section;

/// Function starts in a stripped `AArch64` image: the first non-padding
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
        // `ret`, `retaa` and `brk #0` end a function. So does `br`, an
        // indirect tail call, unless it dispatches a jump table, whose cases
        // follow it.
        if matches!(word, 0xd65f_03c0 | 0xd65f_0bff | 0xd420_0000) {
            closed = true;
        } else if word & 0xffff_fc1f == 0xd61f_0000 {
            let previous = offset.checked_sub(4).and_then(|at| read_word(bytes, at));
            closed = !previous.is_some_and(|previous| aarch64_table_dispatch(previous, word))
                || read_word(bytes, offset + 4).is_none_or(is_aarch64_padding);
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

/// A jump table's `br` takes the address the instruction before computes as
/// a base plus a scaled entry: `add xd, xbase, xentry, lsl #k` or with an
/// extended register.
fn aarch64_table_dispatch(previous: u32, br: u32) -> bool {
    let added = previous & 0xff20_0000 == 0x8b00_0000 || previous & 0xffe0_0000 == 0x8b20_0000;
    added && previous & 0x1f == (br >> 5) & 0x1f
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
            Opcode::B | Opcode::Bcc(_) => Some(instruction.operands[0]),
            Opcode::CBZ | Opcode::CBNZ => Some(instruction.operands[1]),
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
fn x86_is_padding(bytes: &[u8], base: u64, target: u64, bitness: u32) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    if target < base {
        return false;
    }
    let offset = (target - base) as usize;
    let Some(rest) = bytes.get(offset..) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(bitness, rest, target, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return false;
    }
    matches!(decoder.decode().mnemonic(), Mnemonic::Nop | Mnemonic::Int3)
}

/// Function starts in a stripped x86 image: the first non-padding
/// instruction after a return or tail jump, unless a branch targets it.
/// An indirect jump ends a function unless it dispatches a jump table.
pub(crate) fn x86_prologues(bytes: &[u8], base: u64, bitness: u32) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};
    // Every conditional branch target, wherever the branch: a later loop
    // may jump back into code an earlier return seemed to end.
    let mut targets = std::collections::HashSet::new();
    // Call targets are function starts, so a jump to one is a tail call.
    let mut called = std::collections::HashSet::new();
    let mut decoder = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                targets.insert(instruction.near_branch_target());
            }
            FlowControl::Call => {
                called.insert(instruction.near_branch_target());
            }
            _ => {}
        }
    }
    let mut decoder = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut starts = Vec::new();
    let mut closed = false;
    let mut previous: Option<iced_x86::Instruction> = None;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        let ip = instruction.ip();
        let continued = targets.contains(&ip) && !called.contains(&ip);
        if closed && !continued && ip != base && !x86_is_padding(bytes, base, ip, bitness) {
            starts.push(ip);
            closed = false;
        } else if closed && continued && !x86_is_padding(bytes, base, ip, bitness) {
            // A branch target of the previous function: it continues here.
            closed = false;
        }
        match instruction.flow_control() {
            FlowControl::UnconditionalBranch => {
                let target = instruction.near_branch_target();
                if !x86_is_padding(bytes, base, target, bitness) {
                    targets.insert(target);
                }
                // A jump to itself or to padding is unresolved; one leaving
                // the section or to a called function is a tail call. All
                // end the function.
                if target == ip
                    || !(base..base.saturating_add(bytes.len() as u64)).contains(&target)
                    || x86_is_padding(bytes, base, target, bitness)
                    || called.contains(&target)
                {
                    closed = true;
                }
            }
            // A jump through a table, or to a register just computed as a
            // table's base plus an entry, dispatches cases that follow.
            FlowControl::IndirectBranch => {
                let through_table = instruction.op0_kind() == iced_x86::OpKind::Memory
                    && instruction.memory_index() != iced_x86::Register::None;
                let computed = instruction.op0_kind() == iced_x86::OpKind::Register
                    && previous.is_some_and(|previous| {
                        previous.mnemonic() == iced_x86::Mnemonic::Add
                            && previous.op0_kind() == iced_x86::OpKind::Register
                            && previous.op0_register() == instruction.op0_register()
                    });
                // Padding after it ends the function all the same: the
                // table held functions, as for a call through a table.
                closed = !(through_table || computed)
                    || x86_is_padding(bytes, base, instruction.next_ip(), bitness);
            }
            FlowControl::Return => closed = true,
            // A trap or halt ends a function, as after a call that does not
            // return.
            _ if matches!(
                instruction.mnemonic(),
                iced_x86::Mnemonic::Int3 | iced_x86::Mnemonic::Ud2 | iced_x86::Mnemonic::Hlt
            ) =>
            {
                closed = true
            }
            _ => {}
        }
        previous = Some(instruction);
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
        let next = addrs
            .iter()
            .copied()
            .filter(|a| *a > *addr && *a < section.vaddr.saturating_add(section.size))
            .min();
        let end = next.unwrap_or_else(|| section.vaddr.saturating_add(section.size));
        let delta = end - addr;
        // Code between two starts the symbol table gives belongs to the
        // first, however large.
        let named = |start: &u64| {
            functions
                .get(start)
                .is_some_and(|function| function.sources.contains(&NameSource::Symtab))
        };
        let bounded = named(addr) && next.as_ref().is_some_and(named);
        if delta >= 1 && (bounded || delta <= 0x4000) {
            let func = functions.get_mut(addr).expect("entry exists");
            func.size = Some(delta);
            func.size_estimated = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{aarch64_prologues, x86_prologues};

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn a_jump_table_case_after_the_dispatch_is_no_function() {
        // add rax, rcx; jmp rax; (case) ret; int3
        let code = [0x48, 0x01, 0xc8, 0xff, 0xe0, 0xc3, 0xcc];
        assert!(x86_prologues(&code, 0, 64).is_empty());
    }

    #[test]
    fn a_function_after_a_call_that_does_not_return_is_found() {
        // call 0; int3; (next function) ret
        let code = [0xe8, 0xfb, 0xff, 0xff, 0xff, 0xcc, 0xc3];
        assert_eq!(x86_prologues(&code, 0, 64), vec![6]);
    }

    #[test]
    fn a_function_after_a_halt_is_found() {
        // hlt; (next function) ret
        assert_eq!(x86_prologues(&[0xf4, 0xc3], 0, 64), vec![1]);
    }

    #[test]
    fn a_called_function_is_found_though_a_tail_jump_targets_it() {
        // jmp 3; int3; (3) ret; (4) call 3; ret
        let code = [0xeb, 0x01, 0xcc, 0xc3, 0xe8, 0xfa, 0xff, 0xff, 0xff, 0xc3];
        assert_eq!(x86_prologues(&code, 0, 64), vec![3, 4]);
    }

    #[test]
    fn a_function_after_an_indirect_tail_call_is_found() {
        // AArch64: mov x2, x0; br x2; (next function) ret
        let code = words(&[0xaa00_03e2, 0xd61f_0040, 0xd65f_03c0]);
        assert_eq!(aarch64_prologues(&code, 0, &Default::default()), vec![8]);
    }

    #[test]
    fn code_a_later_cbz_targets_continues_the_function() {
        // ret; (0x4, reached only by the cbz below) mov x0, #0; cbz x0, -4
        let code = words(&[0xd65f_03c0, 0xd280_0000, 0xb4ff_ffe0]);
        let starts = aarch64_prologues(&code, 0, &Default::default());
        assert!(!starts.contains(&4), "{starts:?}");
    }
}

#[cfg(test)]
mod i386_tests {
    #[test]
    fn function_discovery_decodes_legacy_increment_opcodes() {
        let code = [0xc3, 0x40, 0x90, 0xc3];
        assert_eq!(super::x86_prologues(&code, 0, 32), vec![1]);
        assert_eq!(super::x86_prologues(&code, 0, 64), vec![3]);
    }
}
