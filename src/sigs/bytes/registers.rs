//! Equivalent allocation of x86-64 scratch registers in leaf functions.

use iced_x86::{
    Decoder, DecoderOptions, Encoder, FlowControl, InstructionInfoFactory, OpAccess, OpKind,
    Register,
};

use super::Body;
use crate::loader::Isa;

pub(super) fn alternative(isa: Isa, body: &Body) -> Option<Vec<u8>> {
    if isa != Isa::X86_64 || !body.calls.is_empty() {
        return None;
    }
    let mut decoder = Decoder::new(64, &body.bytes, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    let mut initialized = [false; 2];
    let mut branched = false;
    let mut output = Vec::with_capacity(body.bytes.len());
    while decoder.can_decode() {
        let start = decoder.position();
        let mut instruction = decoder.decode();
        if instruction.is_invalid()
            || matches!(
                instruction.flow_control(),
                FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::IndirectBranch
                    | FlowControl::Interrupt
                    | FlowControl::XbeginXabortXend
                    | FlowControl::Exception
            )
        {
            return None;
        }
        let instruction_info = factory.info(&instruction);
        for (index, full) in [Register::R10, Register::R11].iter().enumerate() {
            let uses: Vec<_> = instruction_info
                .used_registers()
                .iter()
                .filter(|used| used.register().full_register() == *full)
                .collect();
            if uses.is_empty() {
                continue;
            }
            let explicit = instruction.memory_base().full_register() == *full
                || instruction.memory_index().full_register() == *full
                || (0..instruction.op_count()).any(|operand| {
                    instruction.op_kind(operand) == OpKind::Register
                        && instruction.op_register(operand).full_register() == *full
                });
            if !explicit {
                return None;
            }
            if !initialized[index] {
                if branched
                    || uses
                        .iter()
                        .any(|used| used.access() != OpAccess::Write || used.register().size() < 4)
                {
                    return None;
                }
                initialized[index] = true;
            }
        }
        branched |= !matches!(
            instruction.flow_control(),
            FlowControl::Next | FlowControl::Return
        );
        let mut encoder = Encoder::new(64);
        if encoder.encode(&instruction, start as u64).is_err()
            || encoder.take_buffer() != body.bytes[start..decoder.position()]
        {
            return None;
        }
        for operand in 0..instruction.op_count() {
            if instruction.op_kind(operand) == OpKind::Register {
                instruction.set_op_register(operand, swapped(instruction.op_register(operand)));
            }
        }
        instruction.set_memory_base(swapped(instruction.memory_base()));
        instruction.set_memory_index(swapped(instruction.memory_index()));
        if encoder.encode(&instruction, start as u64).is_err() {
            return None;
        }
        let bytes = encoder.take_buffer();
        if bytes.len() != decoder.position() - start {
            return None;
        }
        output.extend(bytes);
    }
    (initialized.iter().any(|initialized| *initialized) && output != body.bytes).then_some(output)
}

fn swapped(register: Register) -> Register {
    match register {
        Register::R10 => Register::R11,
        Register::R11 => Register::R10,
        Register::R10D => Register::R11D,
        Register::R11D => Register::R10D,
        Register::R10W => Register::R11W,
        Register::R11W => Register::R10W,
        Register::R10L => Register::R11L,
        Register::R11L => Register::R10L,
        _ => register,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Stmt;
    use crate::ir::smt::Proofs;

    fn make_body(bytes: Vec<u8>) -> Body {
        Body {
            bytes,
            calls: Vec::new(),
            references: Vec::new(),
            name_eligible: true,
        }
    }

    #[test]
    fn scratch_register_permutation_keeps_abi_registers_and_widths() {
        // mov r10,rdi; mov r11d,esi; add r10,r11; mov rax,r10; ret.
        let bytes = vec![
            0x49, 0x89, 0xfa, 0x41, 0x89, 0xf3, 0x4d, 0x01, 0xda, 0x4c, 0x89, 0xd0, 0xc3,
        ];
        let body = make_body(bytes);
        let swapped = alternative(Isa::X86_64, &body).unwrap();
        assert_eq!(
            alternative(Isa::X86_64, &make_body(swapped)).unwrap(),
            body.bytes
        );
    }

    #[test]
    fn input_registers_conditional_initialization_and_calls_are_refused() {
        for bytes in [
            vec![0x4c, 0x89, 0xd0, 0xc3],
            vec![0x74, 0x03, 0x49, 0x89, 0xfa, 0x4c, 0x89, 0xd0, 0xc3],
            vec![0x49, 0x89, 0xfa, 0xff, 0xd0, 0xc3],
            vec![0x41, 0xb2, 0x01, 0x4c, 0x89, 0xd0, 0xc3],
            vec![0x0f, 0x05, 0xc3],
        ] {
            assert!(alternative(Isa::X86_64, &make_body(bytes)).is_none());
        }
    }

    #[test]
    fn smt_scratch_register_permutation_preserves_the_returned_value() {
        if !Proofs::available() {
            return;
        }
        let bytes = vec![
            0x49, 0x89, 0xfa, 0x41, 0x89, 0xf3, 0x4d, 0x01, 0xda, 0x4c, 0x89, 0xd0, 0xc3,
        ];
        let swapped = alternative(Isa::X86_64, &make_body(bytes.clone())).unwrap();
        let lift = |bytes: Vec<u8>| {
            let size = bytes.len() as u64;
            let image = crate::loader::Image::from_code(Isa::X86_64, 0, bytes);
            let blocks = crate::lift::lift(&image, 0, size, &Default::default()).unwrap();
            assert_eq!(blocks.len(), 1);
            let mut statements = blocks[0].stmts.clone();
            statements.retain(|statement| !matches!(statement, Stmt::Ret { .. }));
            statements.push(Stmt::Ret {
                value: crate::ir::Expr::reg(0, 64),
            });
            statements
        };
        let mut proofs = Proofs::default();
        proofs.program(
            "x86 scratch allocation".to_owned(),
            &lift(bytes),
            &lift(swapped),
        );
        proofs.check();
    }
}
