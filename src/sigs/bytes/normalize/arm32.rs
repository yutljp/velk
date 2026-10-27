//! Conservative A32 normalization; Thumb and PC-relative data are not accepted.

use std::collections::HashSet;

use yaxpeax_arch::{Decoder as _, ReaderBuilder};
use yaxpeax_arm::armv7::{InstDecoder, Opcode, Operand, RegShift, RegShiftStyle};

use super::super::{Body, DirectCall};

pub(super) fn normalize(
    body: &mut Body,
    addr: u64,
    end: u64,
    relocated: &HashSet<usize>,
    information: &mut usize,
) -> bool {
    if !body.bytes.len().is_multiple_of(4) || end > u64::from(u32::MAX) {
        return false;
    }
    let decoder = InstDecoder::default().allow_nonconforming(false);
    let mut last_end = 0;
    let mut terminal = false;
    let mut local_targets = Vec::new();
    for offset in (0..body.bytes.len()).step_by(4) {
        let chunk: [u8; 4] = body.bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte word");
        let word = u32::from_le_bytes(chunk);
        if word == 0xe320_f000 || word == 0xe1a0_0000 || word == 0 {
            continue;
        }
        *information += 4;
        last_end = offset + 4;
        terminal = false;
        let mut reader = ReaderBuilder::<u32, u8>::read_at(chunk.as_slice(), 0);
        let instruction = match decoder.decode(&mut reader) {
            Ok(instruction) => instruction,
            Err(_) if crate::lift::arm32_position_independent_instruction(&chunk) => continue,
            Err(_) => return false,
        };
        let return_branch = instruction.opcode == Opcode::BX
            && matches!(instruction.operands[0], Operand::Reg(reg) if reg.number() == 14);
        let return_load = matches!(instruction.opcode, Opcode::POP | Opcode::LDM(..))
            && instruction
                .operands
                .iter()
                .any(|operand| matches!(operand, Operand::RegList(list) if list & 0x8000 != 0));
        terminal = word >> 28 == 14 && (return_branch || return_load);
        if return_branch || return_load {
            continue;
        }
        if matches!(instruction.opcode, Opcode::BX | Opcode::BLX) {
            if !matches!(instruction.operands[0], Operand::Reg(reg) if reg.number() != 15) {
                return false;
            }
            terminal = instruction.opcode == Opcode::BX && word >> 28 == 14;
            continue;
        }
        if matches!(instruction.opcode, Opcode::B | Opcode::BL) {
            let delta = i64::from(((word << 8) as i32) >> 6) + 8;
            let Some(target) = addr
                .checked_add(offset as u64)
                .and_then(|pc| pc.checked_add_signed(delta))
            else {
                return false;
            };
            let external = !(addr..end).contains(&target) || relocated.contains(&offset);
            if instruction.opcode == Opcode::BL || external {
                body.bytes[offset..offset + 4].copy_from_slice(&(word & 0xff00_0000).to_le_bytes());
                body.calls.push(DirectCall {
                    offset,
                    width: 4,
                    target,
                });
            } else {
                local_targets.push(target);
            }
            terminal = instruction.opcode == Opcode::B && word >> 28 == 14;
            continue;
        }
        // PC reads include literal loads and address construction. Only operands
        // independent of the instruction's address may survive normalization.
        for operand in &instruction.operands {
            let independent = match operand {
                Operand::Reg(reg) | Operand::RegWBack(reg, _) | Operand::RegDeref(reg) => {
                    reg.number() != 15
                }
                Operand::RegList(list) => list & 0x8000 == 0,
                Operand::RegShift(shift) => independent_shift(shift),
                Operand::RegDerefPreindexRegShift(reg, shift, ..)
                | Operand::RegDerefPostindexRegShift(reg, shift, ..) => {
                    reg.number() != 15 && independent_shift(shift)
                }
                Operand::RegDerefPreindexReg(base, index, ..)
                | Operand::RegDerefPostindexReg(base, index, ..) => {
                    base.number() != 15 && index.number() != 15
                }
                Operand::RegDerefPreindexOffset(reg, ..)
                | Operand::RegDerefPostindexOffset(reg, ..) => reg.number() != 15,
                Operand::Imm12(_) | Operand::Imm32(_) | Operand::Nothing => true,
                // Unhandled addressing modes are refused rather than wildcarded.
                _ => false,
            };
            if !independent {
                return false;
            }
        }
    }
    if local_targets
        .iter()
        .any(|target| !(target - addr).is_multiple_of(4))
    {
        return false;
    }
    if terminal {
        if local_targets
            .iter()
            .any(|target| *target >= addr + last_end as u64)
        {
            return false;
        }
        body.bytes.truncate(last_end);
    }
    true
}

fn independent_shift(shift: &RegShift) -> bool {
    match shift.into_shift() {
        RegShiftStyle::RegImm(shift) => shift.shiftee().number() != 15,
        RegShiftStyle::RegReg(shift) => {
            shift.shiftee().number() != 15 && shift.shifter().number() != 15
        }
    }
}
