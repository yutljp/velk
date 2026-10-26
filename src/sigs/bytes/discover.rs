//! A32 direct-call targets whose complete bodies occur in a signature set.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use std::time::Instant;
use yaxpeax_arch::{Decoder as _, ReaderBuilder};
use yaxpeax_arm::armv7::{InstDecoder, Opcode, Operand};

use super::{MIN_BYTES, normalize};
use crate::deadline::passed;
use crate::error::Result;
use crate::loader::{ArmMode, Function, Image, Isa, NameSource};
use crate::sigs::Database;

mod unwind;

pub(crate) fn arm32(
    image: &mut Image,
    database: &Database,
    deadline: Option<Instant>,
) -> Result<Vec<u64>> {
    if image.isa != Isa::Arm32 || image.byte_order() != Some(object::Endianness::Little) {
        return Ok(Vec::new());
    }
    let targets = match call_targets(image, deadline) {
        Ok(targets) => targets,
        Err(error) => return Err(error),
    };
    let mut sizes_by_prefix: HashMap<Vec<u32>, BTreeSet<usize>> = HashMap::new();
    let mut bodies = HashSet::new();
    for entry in &database.entries {
        if entry.isa == Isa::Arm32 && entry.bytes.len() >= MIN_BYTES {
            let prefix = prefix(&entry.bytes);
            sizes_by_prefix
                .entry(prefix)
                .or_default()
                .insert(entry.bytes.len());
            bodies.insert(entry.bytes.as_slice());
        }
    }
    let mut discovered = Vec::new();
    for target in targets {
        if image.functions.contains_key(&target)
            || image
                .arm_modes
                .get(&target)
                .is_some_and(|mode| *mode != ArmMode::Arm)
        {
            continue;
        }
        let mut lengths = BTreeSet::<usize>::new();
        for size in [4, 8, 12, 16] {
            if let Some(first) = image.read_vaddr(target, size)
                && let Some(found) = sizes_by_prefix.get(&prefix(first))
            {
                lengths.extend(found);
            }
        }
        let mut sizes = BTreeSet::new();
        for length in &lengths {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            let Some(bytes) = image.read_vaddr(target, *length as u64) else {
                continue;
            };
            let Some(body) = normalize::normalize(Isa::Arm32, bytes, target, &Default::default())
            else {
                continue;
            };
            if bodies.contains(body.bytes.as_slice()) {
                sizes.insert(body.bytes.len() as u64);
            }
        }
        if sizes.len() == 1 {
            discovered.push(Function {
                addr: target,
                size: sizes.first().copied(),
                size_estimated: false,
                name: None,
                aliases: Vec::new(),
                sources: vec![NameSource::Signature],
                library: None,
            });
        }
    }
    let addresses: Vec<u64> = discovered.iter().map(|function| function.addr).collect();
    for function in discovered {
        let end = function.addr.saturating_add(function.size.unwrap_or(0));
        let next_mode = image.arm_mode(end);
        image.arm_modes.entry(end).or_insert(next_mode);
        image.arm_modes.insert(function.addr, ArmMode::Arm);
        image.functions.insert(function.addr, function);
    }
    Ok(addresses)
}

fn prefix(bytes: &[u8]) -> Vec<u32> {
    let mut words = Vec::new();
    for chunk in bytes[..bytes.len().min(16)].as_chunks::<4>().0 {
        let word = u32::from_le_bytes(*chunk);
        words.push(if word & 0x0e00_0000 == 0x0a00_0000 {
            word & 0xff00_0000
        } else {
            word
        });
    }
    words
}

fn call_targets(image: &Image, deadline: Option<Instant>) -> Result<BTreeSet<u64>> {
    let mut pending: VecDeque<u64> = image
        .functions
        .keys()
        .copied()
        .filter(|address| image.arm_mode(*address) == ArmMode::Arm)
        .collect();
    match unwind::arm_starts(image, deadline) {
        Ok(starts) => pending.extend(starts),
        Err(error) => return Err(error),
    }
    let mut visited = HashSet::new();
    let mut targets: BTreeSet<_> = pending.iter().copied().collect();
    let decoder = InstDecoder::default().allow_nonconforming(false);
    while let Some(pc) = pending.pop_front() {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if !pc.is_multiple_of(4)
            || image
                .arm_modes
                .get(&pc)
                .is_some_and(|mode| *mode != ArmMode::Arm)
            || !visited.insert(pc)
        {
            continue;
        }
        if !image.sections.iter().any(|section| {
            section.executable
                && pc >= section.vaddr
                && pc < section.vaddr.saturating_add(section.size)
        }) {
            continue;
        }
        let Some(bytes) = image.read_vaddr(pc, 4) else {
            continue;
        };
        let mut reader = ReaderBuilder::<u32, u8>::read_at(bytes, 0);
        let instruction = match decoder.decode(&mut reader) {
            Ok(instruction) => instruction,
            Err(_) if crate::lift::arm32_position_independent_instruction(bytes) => {
                if let Some(next) = pc.checked_add(4) {
                    pending.push_back(next);
                }
                continue;
            }
            Err(_) => continue,
        };
        let word = u32::from_le_bytes(bytes.try_into().expect("four bytes were read"));
        if matches!(instruction.opcode, Opcode::B | Opcode::BL) {
            let delta = i64::from(((word << 8) as i32) >> 6) + 8;
            if let Some(target) = pc.checked_add_signed(delta) {
                pending.push_back(target);
                if instruction.opcode == Opcode::BL {
                    targets.insert(target);
                }
            }
            if instruction.opcode == Opcode::B && word >> 28 == 14 {
                continue;
            }
        } else {
            let return_load = matches!(instruction.opcode, Opcode::POP | Opcode::LDM(..))
                && instruction
                    .operands
                    .iter()
                    .any(|operand| matches!(operand, Operand::RegList(list) if list & 0x8000 != 0));
            let unknown_jump = instruction.opcode == Opcode::BX
                || matches!(instruction.operands[0], Operand::Reg(reg) if reg.number() == 15);
            if (return_load || unknown_jump) && word >> 28 == 14 {
                continue;
            }
        }
        if let Some(next) = pc.checked_add(4) {
            pending.push_back(next);
        }
    }
    Ok(targets)
}
