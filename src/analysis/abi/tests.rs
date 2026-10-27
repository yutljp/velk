use super::allocate;
use crate::ir::abi::{LayoutField, LayoutKind, TypeLayout};
use crate::ir::{AbiIssue, AbiLocation, AbiProfile, Passing, Precision, RegisterClass};

fn integer() -> TypeLayout {
    TypeLayout {
        size: 8,
        alignment: Some(8),
        kind: LayoutKind::Integer,
        trivial: true,
    }
}

fn float() -> TypeLayout {
    TypeLayout {
        size: 8,
        alignment: Some(8),
        kind: LayoutKind::Float(Precision::Double),
        trivial: true,
    }
}

fn object(members: Vec<TypeLayout>) -> TypeLayout {
    let mut size = 0;
    let fields = members
        .into_iter()
        .map(|layout| {
            let bit_offset = size * 8;
            size += layout.size;
            LayoutField {
                bit_offset,
                bit_size: None,
                defined: true,
                layout,
            }
        })
        .collect();
    TypeLayout {
        size,
        alignment: Some(8),
        kind: LayoutKind::Struct(fields),
        trivial: true,
    }
}

fn locations(passing: &Passing) -> Vec<AbiLocation> {
    match passing {
        Passing::Direct(pieces) => pieces.iter().map(|piece| piece.location).collect(),
        Passing::Indirect { pointer, .. } => vec![*pointer],
    }
}

#[test]
fn sysv_mixed_pieces_use_independent_banks_and_result_registers() {
    let mixed = object(vec![float(), integer()]);
    let abi = allocate(
        AbiProfile::SysV,
        &[mixed.clone(), integer(), float()],
        Some(&mixed),
    )
    .unwrap();
    assert_eq!(
        locations(&abi.arguments[0].passing),
        [AbiLocation::Register(18), AbiLocation::Register(7)]
    );
    assert_eq!(
        locations(&abi.arguments[1].passing),
        [AbiLocation::Register(6)]
    );
    assert_eq!(
        locations(&abi.arguments[2].passing),
        [AbiLocation::Register(20)]
    );
    assert_eq!(
        locations(&abi.result.unwrap().passing),
        [AbiLocation::Register(18), AbiLocation::Register(0)]
    );
}

#[test]
fn sysv_spilled_aggregate_rolls_back_both_banks() {
    let mut arguments = vec![integer(); 5];
    arguments.extend([object(vec![integer(), integer()]), integer()]);
    let abi = allocate(AbiProfile::SysV, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[5].passing),
        [AbiLocation::Stack(8)]
    );
    assert_eq!(
        locations(&abi.arguments[6].passing),
        [AbiLocation::Register(9)]
    );

    let mut arguments = vec![float(); 8];
    arguments.extend([object(vec![float(), integer()]), integer()]);
    let abi = allocate(AbiProfile::SysV, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[8].passing),
        [AbiLocation::Stack(8)]
    );
    assert_eq!(
        locations(&abi.arguments[9].passing),
        [AbiLocation::Register(7)]
    );
}

#[test]
fn aapcs_spilled_aggregate_exhausts_only_its_bank() {
    let mut arguments = vec![integer(); 7];
    arguments.extend([object(vec![integer(), integer()]), integer(), float()]);
    let abi = allocate(AbiProfile::Aapcs64, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[7].passing),
        [AbiLocation::Stack(0)]
    );
    assert_eq!(
        locations(&abi.arguments[8].passing),
        [AbiLocation::Stack(16)]
    );
    assert_eq!(
        locations(&abi.arguments[9].passing),
        [AbiLocation::Register(32)]
    );

    let mut arguments = vec![float(); 7];
    arguments.extend([object(vec![float(), float()]), float(), integer()]);
    let abi = allocate(AbiProfile::Aapcs64, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[7].passing),
        [AbiLocation::Stack(0)]
    );
    assert_eq!(
        locations(&abi.arguments[8].passing),
        [AbiLocation::Stack(16)]
    );
    assert_eq!(
        locations(&abi.arguments[9].passing),
        [AbiLocation::Register(0)]
    );
}

#[test]
fn aapcs_alignment_rounds_register_and_stack_cursors() {
    let mut member = integer();
    member.size = 16;
    member.alignment = Some(16);
    let mut aligned = object(vec![member]);
    aligned.alignment = Some(16);
    let abi = allocate(
        AbiProfile::Aapcs64,
        &[integer(), aligned.clone(), integer()],
        None,
    )
    .unwrap();
    assert_eq!(
        locations(&abi.arguments[1].passing),
        [AbiLocation::Register(2), AbiLocation::Register(3)]
    );
    assert_eq!(
        locations(&abi.arguments[2].passing),
        [AbiLocation::Register(4)]
    );

    let mut arguments = vec![integer(); 9];
    arguments.push(aligned);
    let abi = allocate(AbiProfile::Aapcs64, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[8].passing),
        [AbiLocation::Stack(0)]
    );
    assert_eq!(
        locations(&abi.arguments[9].passing),
        [AbiLocation::Stack(16)]
    );
}

#[test]
fn aapcs_aggregate_alignment_attribute_does_not_skip_registers_or_stack_slots() {
    let mut aligned = object(vec![integer(), integer()]);
    aligned.alignment = Some(16);
    let abi = allocate(
        AbiProfile::Aapcs64,
        &[integer(), aligned.clone(), integer()],
        None,
    )
    .unwrap();
    assert_eq!(
        locations(&abi.arguments[1].passing),
        [AbiLocation::Register(1), AbiLocation::Register(2)]
    );
    assert_eq!(
        locations(&abi.arguments[2].passing),
        [AbiLocation::Register(3)]
    );
    let mut arguments = vec![integer(); 9];
    arguments.push(aligned);
    let abi = allocate(AbiProfile::Aapcs64, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[9].passing),
        [AbiLocation::Stack(8)]
    );
}

#[test]
fn hfa_result_keeps_all_four_low_vector_halves() {
    let hfa = object(vec![float(); 4]);
    let abi = allocate(AbiProfile::Aapcs64, std::slice::from_ref(&hfa), Some(&hfa)).unwrap();
    let expected = [32, 34, 36, 38].map(AbiLocation::Register);
    assert_eq!(locations(&abi.arguments[0].passing), expected);
    let result = abi.result.unwrap();
    assert_eq!(locations(&result.passing), expected);
    let Passing::Direct(pieces) = result.passing else {
        panic!("expected direct result")
    };
    assert!(
        pieces
            .iter()
            .all(|piece| piece.class == Some(RegisterClass::Simd))
    );
    assert_eq!(
        pieces
            .iter()
            .map(|piece| piece.object_offset)
            .collect::<Vec<_>>(),
        [0, 8, 16, 24]
    );
}

#[test]
fn indirect_results_reserve_the_correct_register_without_a_source_parameter() {
    let big = object(vec![integer(); 4]);
    for (profile, pointer, echo, first) in [
        (AbiProfile::SysV, 7, Some(0), 6),
        (AbiProfile::Win64, 1, Some(0), 2),
        (AbiProfile::Aapcs64, 8, None, 0),
    ] {
        let abi = allocate(profile, &[integer()], Some(&big)).unwrap();
        assert_eq!(abi.arguments.len(), 1);
        assert_eq!(
            locations(&abi.arguments[0].passing),
            [AbiLocation::Register(first)]
        );
        assert_eq!(
            abi.result.unwrap().passing,
            Passing::Indirect {
                pointer: AbiLocation::Register(pointer),
                returned_pointer: echo,
            }
        );
    }
}

#[test]
fn windows_indirect_stack_argument_occupies_a_pointer_slot() {
    let big = object(vec![integer(); 4]);
    let mut arguments = vec![integer(); 4];
    arguments.extend([big, integer(), float()]);
    let abi = allocate(AbiProfile::Win64, &arguments, None).unwrap();
    assert_eq!(
        abi.arguments[4].passing,
        Passing::Indirect {
            pointer: AbiLocation::Stack(40),
            returned_pointer: None,
        }
    );
    assert_eq!(
        locations(&abi.arguments[5].passing),
        [AbiLocation::Stack(48)]
    );
    assert_eq!(
        locations(&abi.arguments[6].passing),
        [AbiLocation::Stack(56)]
    );
}

#[test]
fn windows_float_arguments_follow_source_positions() {
    let abi = allocate(
        AbiProfile::Win64,
        &[integer(), float(), integer(), float()],
        None,
    )
    .unwrap();
    assert_eq!(
        locations(&abi.arguments[0].passing),
        [AbiLocation::Register(1)]
    );
    assert_eq!(
        locations(&abi.arguments[1].passing),
        [AbiLocation::Register(20)]
    );
    assert_eq!(
        locations(&abi.arguments[2].passing),
        [AbiLocation::Register(8)]
    );
    assert_eq!(
        locations(&abi.arguments[3].passing),
        [AbiLocation::Register(24)]
    );
}

fn byte_object(alignment: Option<u64>) -> TypeLayout {
    TypeLayout {
        size: 16,
        alignment,
        kind: LayoutKind::Struct(vec![LayoutField {
            bit_offset: 0,
            bit_size: None,
            defined: true,
            layout: TypeLayout {
                size: 16,
                alignment: Some(1),
                kind: LayoutKind::Array {
                    element: Box::new(TypeLayout {
                        size: 1,
                        alignment: Some(1),
                        kind: LayoutKind::Integer,
                        trivial: true,
                    }),
                    count: 16,
                },
                trivial: true,
            },
        }]),
        trivial: true,
    }
}

#[test]
fn sysv_stack_alignment_is_relative_to_the_entry_argument_area() {
    let mut arguments = vec![integer(); 7];
    arguments.extend([byte_object(Some(16)), integer()]);
    let abi = allocate(AbiProfile::SysV, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[6].passing),
        [AbiLocation::Stack(8)]
    );
    assert_eq!(
        locations(&abi.arguments[7].passing),
        [AbiLocation::Stack(24)]
    );
    assert_eq!(
        locations(&abi.arguments[8].passing),
        [AbiLocation::Stack(40)]
    );
}

#[test]
fn unknown_alignment_is_rejected_when_stack_placement_changes() {
    let mut arguments = vec![integer(); 7];
    arguments.extend([byte_object(None), integer()]);
    assert_eq!(
        allocate(AbiProfile::SysV, &arguments, None),
        Err(AbiIssue::UnknownLayout)
    );
}

#[test]
fn aapcs_unknown_aggregate_alignment_uses_member_alignment() {
    let mut pair = object(vec![integer(), integer()]);
    pair.alignment = None;
    let abi = allocate(AbiProfile::Aapcs64, &[integer(), pair, integer()], None).unwrap();
    assert_eq!(
        locations(&abi.arguments[1].passing),
        [AbiLocation::Register(1), AbiLocation::Register(2)]
    );
    assert_eq!(
        locations(&abi.arguments[2].passing),
        [AbiLocation::Register(3)]
    );
    let mut arguments = vec![integer(); 9];
    arguments.push(byte_object(None));
    let abi = allocate(AbiProfile::Aapcs64, &arguments, None).unwrap();
    assert_eq!(
        locations(&abi.arguments[9].passing),
        [AbiLocation::Stack(8)]
    );
}

#[test]
fn unknown_alignment_keeps_invariant_register_arguments_and_results() {
    let mut point = object(vec![
        TypeLayout {
            size: 4,
            alignment: Some(4),
            kind: LayoutKind::Integer,
            trivial: true,
        };
        2
    ]);
    point.alignment = None;
    for profile in [AbiProfile::SysV, AbiProfile::Aapcs64, AbiProfile::Win64] {
        let abi = allocate(profile, &[point.clone(), integer()], Some(&point)).unwrap();
        assert_eq!(abi.arguments[0].alignment, 4);
        assert_eq!(abi.result.as_ref().unwrap().alignment, 4);
    }
}

#[test]
fn unknown_bit_field_alignment_keeps_defined_bits_and_natural_representative() {
    let field = TypeLayout {
        size: 4,
        alignment: Some(4),
        kind: LayoutKind::Integer,
        trivial: true,
    };
    let flags = TypeLayout {
        size: 4,
        alignment: None,
        kind: LayoutKind::Struct(
            [(0, 1), (1, 3), (4, 4)]
                .into_iter()
                .map(|(bit_offset, bits)| LayoutField {
                    bit_offset,
                    bit_size: Some(bits),
                    defined: true,
                    layout: field.clone(),
                })
                .collect(),
        ),
        trivial: true,
    };
    for profile in [AbiProfile::SysV, AbiProfile::Aapcs64, AbiProfile::Win64] {
        let abi = allocate(profile, std::slice::from_ref(&flags), None).unwrap();
        assert_eq!(abi.arguments[0].alignment, 4);
        assert_eq!(abi.arguments[0].defined_bits, [(0, 8)]);
    }
}

#[test]
fn unknown_result_alignment_preserves_hidden_result_and_argument_shift() {
    let mut big = object(vec![integer(); 4]);
    big.alignment = None;
    for (profile, first) in [
        (AbiProfile::SysV, 6),
        (AbiProfile::Win64, 2),
        (AbiProfile::Aapcs64, 0),
    ] {
        let abi = allocate(profile, &[integer()], Some(&big)).unwrap();
        assert_eq!(
            locations(&abi.arguments[0].passing),
            [AbiLocation::Register(first)]
        );
        assert!(matches!(
            abi.result.unwrap().passing,
            Passing::Indirect { .. }
        ));
    }
}
