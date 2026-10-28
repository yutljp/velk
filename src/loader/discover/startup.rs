//! Constant entry addresses passed to the C runtime by ELF startup code.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};

use crate::loader::{Format, Image, Isa, NameSource};

pub(super) fn discover(image: &mut Image) {
    if image.format != Format::Elf || image.isa != Isa::X86_64 {
        return;
    }
    let Some(entry) = image.entry else {
        return;
    };
    let Some(section) = image.section_at(entry).filter(|section| section.executable) else {
        return;
    };
    let size = section.file_size.saturating_sub(entry - section.vaddr);
    let Some(bytes) = image.read_vaddr(entry, size) else {
        return;
    };
    let mut decoder = Decoder::with_ip(64, bytes, entry, DecoderOptions::NONE);
    let mut info = InstructionInfoFactory::new();
    let mut argument = None;
    let mut target = None;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            let name = if instruction.flow_control() == FlowControl::Call {
                image
                    .functions
                    .get(&instruction.near_branch_target())
                    .filter(|function| function.sources.contains(&NameSource::Plt))
                    .and_then(|function| function.name.as_deref())
            } else if instruction.is_ip_rel_memory_operand()
                && !matches!(instruction.segment_prefix(), Register::FS | Register::GS)
                && image
                    .import_addends
                    .get(&instruction.ip_rel_memory_address())
                    .is_none_or(|addend| *addend == 0)
            {
                image
                    .imports
                    .get(&instruction.ip_rel_memory_address())
                    .map(String::as_str)
            } else {
                None
            };
            if name == Some("__libc_start_main") {
                target = argument;
            }
            break;
        }
        if instruction.flow_control() != FlowControl::Next {
            break;
        }
        for used in info.info(&instruction).used_registers() {
            if used.register().full_register() == Register::RDI
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
            {
                argument = None;
            }
        }
        if instruction.op0_kind() != OpKind::Register {
            continue;
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_register() == Register::RDI
            && instruction.is_ip_rel_memory_operand()
        {
            argument = Some(instruction.ip_rel_memory_address());
        } else if instruction.mnemonic() == Mnemonic::Mov
            && matches!(instruction.op0_register(), Register::RDI | Register::EDI)
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate64 | OpKind::Immediate32to64 | OpKind::Immediate32
            )
        {
            argument = Some(instruction.immediate(1));
        }
    }
    if let Some(target) = target
        && image
            .section_at(target)
            .is_some_and(|section| section.executable)
        && image.fragment_at(target).is_none()
    {
        super::add_entry(image, target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_arguments_require_a_known_value_and_runtime_call() {
        for load in [
            vec![0x48, 0xc7, 0xc7, 0x40, 0, 0, 0], // mov rdi, 64
            vec![0xbf, 0x40, 0, 0, 0],             // mov edi, 64
            vec![0x48, 0x8d, 0x3d, 0x39, 0, 0, 0], // lea rdi, [rip+57]
        ] {
            for (intervening, expected) in [
                (vec![], true),
                (vec![0x48, 0x89, 0xf7], false), // mov rdi, rsi
                (vec![0x40, 0xb7, 1], false),    // mov dil, 1
                (vec![0x66, 0xbf, 1, 0], false), // mov di, 1
                (vec![0x74, 0], false),          // conditional control flow
                (vec![0xe8, 0, 0, 0, 0], false), // another call
            ] {
                for name in ["__libc_start_main", "unknown"] {
                    let mut code = load.clone();
                    code.extend_from_slice(&intervening);
                    let slot = code.len() as u64 + 6;
                    code.extend_from_slice(&[0xff, 0x15, 0, 0, 0, 0]);
                    code.resize(65, 0xc3);
                    let mut image = Image::from_code(Isa::X86_64, 0, code);
                    image.format = Format::Elf;
                    image.entry = Some(0);
                    image.imports.insert(slot, name.to_owned());
                    discover(&mut image);
                    assert_eq!(
                        image.functions.contains_key(&64),
                        expected && name == "__libc_start_main"
                    );
                }
            }
        }
    }
}
