use crate::ir::FunctionIr;
use crate::ir::eval;
use crate::loader::{Image, Isa};

fn execute_return_value(code: &[u8], registers: &[(u16, u64)], memory: &[(u64, u64)]) -> u32 {
    let image = Image::from_code(Isa::I386, 0, code.to_vec());
    let blocks = crate::lift::lift(&image, 0, code.len() as u64, &Default::default()).unwrap();
    let mut ir = FunctionIr::single_block(Isa::I386, vec![]);
    ir.blocks = blocks;
    let setup = eval::Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[0, 1, 2],
        },
        registers,
        memory,
        step_limit: 1000,
    };
    match eval::run_with_machine(&ir, &setup, &|instruction, inputs| {
        if instruction == crate::ir::MachineInstruction::ReadFlags {
            Ok(vec![(0x202 & !inputs[0]) | inputs[1]])
        } else {
            Err("machine state unavailable")
        }
    }) {
        eval::Outcome::Return { value, .. } => value as u32,
        outcome => panic!("{outcome:?}"),
    }
}

#[test]
fn decoder_uses_i386_defaults_and_prefixes() {
    // 0x40 is inc eax, not a prefix; 0x66 selects a partial 16-bit write.
    assert_eq!(
        execute_return_value(&[0x40, 0xc3], &[(0, 0xffff_ffff)], &[]),
        0
    );
    assert_eq!(
        execute_return_value(&[0x66, 0xb8, 0x34, 0x12, 0xc3], &[(0, 0xabcd_ffff)], &[]),
        0xabcd_1234
    );
    assert_eq!(
        execute_return_value(&[0xb4, 0x12, 0xc3], &[(0, 0xabcd_ff56)], &[]),
        0xabcd_1256
    );
    // Address arithmetic wraps at 32 bits; 0x67 selects 16-bit addressing.
    assert_eq!(
        execute_return_value(&[0x8b, 0x43, 0x04, 0xc3], &[(3, 0xffff_fffe)], &[(2, 73)]),
        73
    );
    assert_eq!(
        execute_return_value(
            &[0x67, 0x8b, 0x00, 0xc3],
            &[(3, 0xffff_fff0), (6, 0x20)],
            &[(0x10, 91)]
        ),
        91
    );
}

#[test]
fn stack_operations_use_four_bytes_and_operand_overrides() {
    assert_eq!(
        execute_return_value(&[0x53, 0x58, 0xc3], &[(3, 0xabcd_1234)], &[]),
        0xabcd_1234
    );
    assert_eq!(
        execute_return_value(
            &[0x66, 0x53, 0x66, 0x58, 0xc3],
            &[(0, 0xabcd_0000), (3, 0xffff_1234)],
            &[]
        ),
        0xabcd_1234
    );
    let sp = eval::stack_top(Isa::I386);
    // An immediate with an operand override also moves ESP by two bytes.
    for push in [&[0x66, 0x68, 0x34, 0x12][..], &[0x66, 0x6a, 0x7f][..]] {
        let mut code = push.to_vec();
        code.extend_from_slice(&[0x8b, 0x44, 0x24, 0x02, 0xc3]);
        assert_eq!(execute_return_value(&code, &[], &[(sp, 73)]), 73);
    }
    assert_eq!(
        execute_return_value(&[0x8b, 0x44, 0x24, 0x04, 0xc3], &[], &[(sp + 4, 123)]),
        123
    );
}

#[test]
fn flags_and_string_instructions_use_i386_stack_and_count_widths() {
    // pushfd/pop eax; bit 1 of EFLAGS is always set.
    assert_eq!(
        execute_return_value(&[0x9c, 0x58, 0x83, 0xe0, 2, 0xc3], &[], &[]),
        2
    );
    // rep stosd; mov eax,[ebx]. The interpreter truncates ECX to 32 bits.
    assert_eq!(
        execute_return_value(
            &[0xf3, 0xab, 0x8b, 0x03, 0xc3],
            &[(0, 73), (1, 1), (7, 0x100), (3, 0x100)],
            &[]
        ),
        73
    );
}

#[test]
fn pop_memory_uses_the_incremented_stack_pointer() {
    let sp = eval::stack_top(Isa::I386);
    // pop [esp]; mov eax,[esp] reads the value just moved up the stack.
    assert_eq!(
        execute_return_value(
            &[0x8f, 0x04, 0x24, 0x8b, 0x04, 0x24, 0xc3],
            &[],
            &[(sp, 73)]
        ),
        73
    );
}

#[test]
fn position_independent_code_reads_the_instruction_pointer_without_a_call() {
    assert_eq!(
        execute_return_value(&[0xe8, 0, 0, 0, 0, 0x58, 0xc3], &[], &[]),
        5
    );
}
