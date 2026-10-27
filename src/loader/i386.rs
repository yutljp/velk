use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpAccess, Register};

use super::Image;
use crate::ir::Convention;

pub(super) fn properties(image: &Image, addr: u64) -> (Convention, Option<u16>) {
    let Some(function) = image.functions.get(&addr) else {
        return (Convention::Cdecl, None);
    };
    if function.sources.contains(&super::NameSource::Plt)
        && let Some(properties) = function
            .name
            .as_deref()
            .and_then(|name| crate::analysis::prototypes::i386_import(image, name))
    {
        return (properties.0, Some(properties.1));
    }
    let named = function
        .name
        .iter()
        .chain(&function.aliases)
        .find_map(|name| {
            let Some((prefix, bytes)) = name.rsplit_once('@') else {
                return None;
            };
            if bytes.parse::<u16>().is_err() {
                return None;
            }
            if prefix.starts_with('@') {
                Some(Convention::Fastcall)
            } else if prefix.starts_with('_') {
                Some(Convention::Stdcall)
            } else {
                None
            }
        });
    let Some(bytes) = function.size.and_then(|size| image.read_vaddr(addr, size)) else {
        return (named.unwrap_or(Convention::Cdecl), None);
    };
    let instructions: Vec<_> = Decoder::with_ip(32, bytes, addr, DecoderOptions::NONE)
        .into_iter()
        .collect();
    let indices: HashMap<_, _> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.ip(), index))
        .collect();
    let mut instruction_info_factory = InstructionInfoFactory::new();
    let mut reads = vec![0u8; instructions.len()];
    let mut writes = reads.clone();
    let mut successors = vec![Vec::new(); instructions.len()];
    let mut cleanup = None;
    let mut conflicting = false;
    for (index, instruction) in instructions.iter().enumerate() {
        for used in instruction_info_factory.info(instruction).used_registers() {
            let shift = match used.register().full_register() {
                Register::RCX => 0,
                Register::RDX => 4,
                _ => continue,
            };
            let bytes = match used.register() {
                Register::CH | Register::DH => 2,
                register => (1u8 << register.size().min(4)) - 1,
            };
            let bits = bytes << shift;
            if matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                reads[index] |= bits;
            }
            if matches!(used.access(), OpAccess::Write | OpAccess::ReadWrite) {
                writes[index] |= bits;
            }
        }
        match instruction.flow_control() {
            FlowControl::Return => {
                let value = if instruction.op_count() == 0 {
                    0
                } else {
                    instruction.immediate16()
                };
                conflicting |= cleanup.is_some_and(|previous| previous != value);
                cleanup = Some(value);
            }
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                if let Some(next) = indices.get(&instruction.near_branch_target()) {
                    successors[index].push(*next);
                }
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                writes[index] = 0xff;
            }
            _ => {}
        }
        if !matches!(
            instruction.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Exception
        ) && index + 1 < instructions.len()
        {
            successors[index].push(index + 1);
        }
    }
    let mut incoming = vec![0; instructions.len()];
    loop {
        let mut changed = false;
        for index in (0..instructions.len()).rev() {
            let live = successors[index]
                .iter()
                .fold(0, |live, next| live | incoming[*next]);
            let value = reads[index] | (live & !writes[index]);
            changed |= incoming[index] != value;
            incoming[index] = value;
        }
        if !changed {
            break;
        }
    }
    let convention = named.unwrap_or_else(|| match incoming.first().copied().unwrap_or(0) {
        mask if mask & 0xf0 != 0 => Convention::Fastcall,
        mask if mask & 15 != 0 => Convention::Thiscall,
        _ if cleanup.is_some_and(|bytes| bytes > 0) => Convention::Stdcall,
        _ => Convention::Cdecl,
    });
    (convention, if conflicting { None } else { cleanup })
}
