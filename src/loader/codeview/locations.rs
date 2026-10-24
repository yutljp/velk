//! Entry-relative frame offsets for fixed x64 prologues.

use crate::loader::{Image, Isa};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, Register,
};

pub(super) fn frame(
    image: &Image,
    start: u64,
    size: u64,
    total: u32,
) -> Option<(i64, Option<i64>)> {
    if image.isa != Isa::X86_64 || size > 1 << 20 {
        return None;
    }
    let Some(bytes) = image.read_vaddr(start, size) else {
        return None;
    };
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    let mut sp = 0i64;
    let mut bp = None;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        let before = sp;
        match instruction.mnemonic() {
            Mnemonic::Push if instruction.op0_register().size() == 8 => {
                let Some(next) = sp.checked_sub(8) else {
                    return None;
                };
                sp = next;
            }
            Mnemonic::Sub if instruction.op0_register() == Register::RSP => {
                let amount = match instruction.op1_kind() {
                    iced_x86::OpKind::Immediate8to64 => instruction.immediate8to64(),
                    iced_x86::OpKind::Immediate32to64 => instruction.immediate32to64(),
                    _ => return None,
                };
                if amount < 0 {
                    return None;
                }
                let Some(next) = sp.checked_sub(amount) else {
                    return None;
                };
                sp = next;
            }
            Mnemonic::Mov
                if instruction.op0_register() == Register::RBP
                    && instruction.op1_register() == Register::RSP =>
            {
                bp = Some(sp)
            }
            Mnemonic::Lea
                if instruction.op0_register() == Register::RBP
                    && instruction.memory_base() == Register::RSP
                    && instruction.memory_index() == Register::None =>
            {
                bp = sp.checked_add(instruction.memory_displacement64() as i64);
            }
            _ => {
                for used in factory.info(&instruction).used_registers() {
                    if matches!(
                        used.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    ) {
                        match used.register().full_register() {
                            Register::RSP => return None,
                            Register::RBP => bp = None,
                            _ => {}
                        }
                    }
                }
            }
        }
        if sp < -i64::from(total) {
            return None;
        }
        // Only a straight-line prefix can establish a common frame base.
        if instruction.flow_control() != FlowControl::Next {
            break;
        }
        if sp == -i64::from(total) && before != sp {
            // RBP, when used, is often set immediately after allocation.
            if decoder.can_decode() {
                let mut next = Decoder::with_ip(
                    64,
                    &bytes[decoder.position()..],
                    decoder.ip(),
                    DecoderOptions::NONE,
                );
                let instruction = next.decode();
                if matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
                    && instruction.op0_register() == Register::RBP
                {
                    continue;
                }
            }
            return Some((sp, bp));
        }
        if decoder.position() > 128 {
            break;
        }
    }
    (sp == -i64::from(total)).then_some((sp, bp))
}
