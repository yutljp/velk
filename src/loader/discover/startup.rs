//! Constant entry addresses passed to the C runtime by ELF startup code.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};

use crate::loader::{Format, Image, Isa, NameSource};

pub(super) fn discover(image: &mut Image) {
    if image.format != Format::Elf {
        return;
    }
    if image.isa == Isa::AArch64 {
        discover_aarch64(image);
        return;
    }
    if image.isa == Isa::I386 {
        discover_i386(image);
        return;
    }
    if image.isa != Isa::X86_64 {
        return;
    }
    let Some(mut decoder) = entry_decoder(image, 64) else {
        return;
    };
    let mut info = InstructionInfoFactory::new();
    let mut argument = None;
    let mut startup_arguments = 0u8;
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
            if name == Some("__libc_start_main") || startup_arguments == 0b1_1111 {
                name_main(image, argument);
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
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
        {
            match (instruction.op0_register(), instruction.op1_register()) {
                (Register::R9, Register::RDX) => startup_arguments |= 1,
                (Register::RDX, Register::RSP) => startup_arguments |= 4,
                _ => {}
            }
        } else if instruction.mnemonic() == Mnemonic::Pop
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::RSI
        {
            startup_arguments |= 2;
        } else if instruction.mnemonic() == Mnemonic::Xor
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register() == instruction.op1_register()
        {
            match instruction.op0_register() {
                Register::ECX | Register::RCX => startup_arguments |= 8,
                Register::R8D | Register::R8 => startup_arguments |= 16,
                _ => {}
            }
        }
    }
}

fn discover_i386(image: &mut Image) {
    let Some(mut decoder) = entry_decoder(image, 32) else {
        return;
    };
    let mut info = InstructionInfoFactory::new();
    let mut argument = None;
    let mut startup_arguments = 0u8;
    let mut startup_pushes = 0u8;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return;
        }
        if instruction.flow_control() == FlowControl::Call {
            let name = image
                .functions
                .get(&instruction.near_branch_target())
                .and_then(|function| function.name.as_deref());
            if name == Some("__libc_start_main") || (startup_arguments == 3 && startup_pushes >= 6)
            {
                name_main(image, argument);
            }
            return;
        }
        if instruction.flow_control() != FlowControl::Next {
            return;
        }
        let used = info.info(&instruction);
        if instruction.mnemonic() == Mnemonic::Push {
            startup_pushes = startup_pushes.saturating_add(1);
            argument = match instruction.op0_kind() {
                OpKind::Immediate32 | OpKind::Immediate8to32 => {
                    Some(instruction.immediate(0) as u32 as u64)
                }
                _ => None,
            };
        } else if used.used_registers().iter().any(|register| {
            register.register().full_register() == Register::RSP
                && matches!(
                    register.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        }) || used.used_memory().iter().any(|memory| {
            matches!(
                memory.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
        }) {
            argument = None;
        }
        if instruction.mnemonic() != Mnemonic::Push {
            startup_pushes = 0;
        }
        if instruction.mnemonic() == Mnemonic::Pop
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::ESI
        {
            startup_arguments |= 1;
        } else if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::ECX
            && instruction.op1_kind() == OpKind::Register
            && instruction.op1_register() == Register::ESP
        {
            startup_arguments |= 2;
        }
    }
}

fn entry_decoder(image: &Image, bitness: u32) -> Option<Decoder<'_>> {
    let entry = image.entry?;
    let section = image
        .section_at(entry)
        .filter(|section| section.executable)?;
    let size = section.file_size.saturating_sub(entry - section.vaddr);
    let bytes = image.read_vaddr(entry, size)?;
    Some(Decoder::with_ip(
        bitness,
        bytes,
        entry,
        DecoderOptions::NONE,
    ))
}

fn name_main(image: &mut Image, target: Option<u64>) {
    if let Some(target) = target
        && image
            .section_at(target)
            .is_some_and(|section| section.executable)
    {
        if image.fragment_at(target).is_none() {
            super::add_entry(image, target);
        }
        if let Some(function) = image.functions.get_mut(&target) {
            function.merge(Some("main".to_owned()), None, NameSource::Call);
        }
    }
}

fn discover_aarch64(image: &mut Image) {
    if image.byte_order() != Some(object::Endianness::Little) {
        return;
    }
    let Some(mut pc) = image.entry else {
        return;
    };
    let read = |image: &Image, address: u64| {
        image
            .section_at(address)
            .filter(|section| section.executable)?;
        let bytes = image.read_vaddr(address, 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    };
    if read(image, pc) == Some(0xd503201f) {
        let Some(next) = pc.checked_add(4) else {
            return;
        };
        pc = next;
    }
    for expected in [
        0xd280001d, 0xd280001e, 0xaa0003e5, 0xf94003e1, 0x910023e2, 0x910003e6,
    ] {
        if read(image, pc) != Some(expected) {
            return;
        }
        let Some(next) = pc.checked_add(4) else {
            return;
        };
        pc = next;
    }
    let Some(adrp) = read(image, pc) else { return };
    if adrp & 0x9f00_001f != 0x9000_0000 {
        return;
    }
    let immediate = (((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29) & 3) as i64;
    let pages = (immediate << 43) >> 43;
    let Some(page) = (pc & !0xfff).checked_add_signed(pages << 12) else {
        return;
    };
    let Some(next) = pc.checked_add(4) else {
        return;
    };
    pc = next;
    let Some(load) = read(image, pc) else { return };
    let argument = if load & 0xffc0_03ff == 0xf940_0000 {
        let Some(slot) = page.checked_add(u64::from((load >> 10) & 0xfff) * 8) else {
            return;
        };
        if image.imports.contains_key(&slot) {
            return;
        }
        let Some(bytes) = image.read_vaddr(slot, 8) else {
            return;
        };
        let Ok(bytes) = bytes.try_into() else { return };
        u64::from_le_bytes(bytes)
    } else if load & 0xffc0_03ff == 0x9100_0000 {
        let Some(address) = page.checked_add(u64::from((load >> 10) & 0xfff)) else {
            return;
        };
        address
    } else {
        return;
    };
    for expected in [0xd2800003, 0xd2800004] {
        let Some(next) = pc.checked_add(4) else {
            return;
        };
        pc = next;
        if read(image, pc) != Some(expected) {
            return;
        }
    }
    let Some(next) = pc.checked_add(4) else {
        return;
    };
    pc = next;
    let Some(call) = read(image, pc) else { return };
    if call & 0xfc00_0000 != 0x9400_0000 {
        return;
    }
    name_main(image, Some(argument));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freestanding_entry_does_not_prove_main() {
        let mut code = vec![
            0xe8, 59, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0xbf, 0, 0, 0, 0, 0x0f, 0x05,
        ];
        code.resize(65, 0xc3);
        let mut image = Image::from_code(Isa::X86_64, 0, code);
        image.format = Format::Elf;
        image.entry = Some(0);
        discover(&mut image);
        assert_ne!(
            image
                .functions
                .get(&64)
                .and_then(|function| function.name.as_deref()),
            Some("main")
        );
    }

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
