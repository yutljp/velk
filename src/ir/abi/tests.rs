use super::*;
use crate::ir::RegisterClass::{Integer, Simd};

fn integer(size: u64) -> TypeLayout {
    TypeLayout {
        size,
        alignment: Some(size),
        kind: LayoutKind::Integer,
        trivial: true,
    }
}

fn float(precision: Precision) -> TypeLayout {
    let size = u64::from(precision.bits() / 8);
    TypeLayout {
        size,
        alignment: Some(size),
        kind: LayoutKind::Float(precision),
        trivial: true,
    }
}

fn field(byte_offset: u64, layout: TypeLayout) -> LayoutField {
    LayoutField {
        bit_offset: byte_offset * 8,
        bit_size: None,
        defined: true,
        layout,
    }
}

fn structure(size: u64, alignment: u64, fields: Vec<LayoutField>) -> TypeLayout {
    TypeLayout {
        size,
        alignment: Some(alignment),
        kind: LayoutKind::Struct(fields),
        trivial: true,
    }
}

fn array(element: TypeLayout, count: u64) -> TypeLayout {
    TypeLayout {
        size: element.size * count,
        alignment: element.alignment,
        kind: LayoutKind::Array {
            element: Box::new(element),
            count,
        },
        trivial: true,
    }
}

fn piece(object_offset: u64, bytes: u64, class: crate::ir::RegisterClass) -> ClassPiece {
    ClassPiece {
        object_offset,
        bytes,
        class,
    }
}

#[test]
fn sysv_classifies_each_eightbyte_from_its_members() {
    for (fields, classes) in [
        (
            vec![field(0, integer(8)), field(8, integer(8))],
            [Integer, Integer],
        ),
        (
            vec![
                field(0, float(Precision::Double)),
                field(8, float(Precision::Double)),
            ],
            [Simd, Simd],
        ),
        (
            vec![field(0, float(Precision::Double)), field(8, integer(8))],
            [Simd, Integer],
        ),
    ] {
        let value = classify(AbiProfile::SysV, &structure(16, 8, fields)).unwrap();
        assert!(value.aggregate);
        assert_eq!(value.defined_bits, vec![(0, 128)]);
        assert_eq!(
            value.passing,
            ValueClass::Registers(vec![piece(0, 8, classes[0]), piece(8, 8, classes[1])])
        );
    }
}

#[test]
fn sysv_integer_union_alternative_overrides_sse() {
    let mut layout = structure(4, 4, vec![]);
    layout.kind = LayoutKind::Union(vec![
        field(0, float(Precision::Single)),
        field(0, integer(4)),
    ]);
    let value = classify(AbiProfile::SysV, &layout).unwrap();
    assert_eq!(value.defined_bits, vec![(0, 32)]);
    assert_eq!(
        value.passing,
        ValueClass::Registers(vec![piece(0, 4, Integer)])
    );
}

#[test]
fn sysv_unaligned_member_requires_memory() {
    let layout = structure(9, 1, vec![field(0, integer(1)), field(1, integer(8))]);
    assert_eq!(
        classify(AbiProfile::SysV, &layout).unwrap().passing,
        ValueClass::Memory
    );
}

#[test]
fn sysv_short_final_eightbyte_stays_inside_object() {
    let layout = structure(9, 1, vec![field(0, array(integer(1), 9))]);
    assert_eq!(
        classify(AbiProfile::SysV, &layout).unwrap().passing,
        ValueClass::Registers(vec![piece(0, 8, Integer), piece(8, 1, Integer)])
    );
}

#[test]
fn aapcs_hfa_uses_one_simd_piece_per_element_before_large_object_rule() {
    for precision in [Precision::Single, Precision::Double] {
        let element = float(precision);
        for count in 1..=4 {
            let size = element.size * count;
            let layout = structure(
                size,
                element.size,
                vec![field(0, array(element.clone(), count))],
            );
            let value = classify(AbiProfile::Aapcs64, &layout).unwrap();
            let pieces = (0..count)
                .map(|n| piece(n * element.size, element.size, Simd))
                .collect();
            assert_eq!(value.passing, ValueClass::Registers(pieces));
        }
    }
}

#[test]
fn aapcs_overaligned_float_aggregates_with_tail_padding_are_not_hfas() {
    for fields in [
        vec![
            field(0, float(Precision::Single)),
            field(4, float(Precision::Single)),
        ],
        vec![field(0, array(float(Precision::Single), 3))],
    ] {
        let value = classify(AbiProfile::Aapcs64, &structure(16, 16, fields)).unwrap();
        assert_eq!(value.alignment, 16);
        assert_eq!(value.natural_alignment, 4);
        assert_eq!(
            value.passing,
            ValueClass::Registers(vec![piece(0, 8, Integer), piece(8, 8, Integer)])
        );
    }
}

#[test]
fn aapcs_natural_alignment_follows_nested_members_and_elements() {
    let mut layout = structure(16, 16, vec![field(0, array(integer(8), 2))]);
    assert_eq!(
        classify(AbiProfile::Aapcs64, &layout)
            .unwrap()
            .natural_alignment,
        8
    );
    assert_eq!(
        classify(AbiProfile::Aapcs64, &array(layout.clone(), 1))
            .unwrap()
            .natural_alignment,
        16
    );
    layout.kind = LayoutKind::Union(vec![field(0, layout.clone())]);
    assert_eq!(
        classify(AbiProfile::Aapcs64, &layout)
            .unwrap()
            .natural_alignment,
        16
    );
    assert_eq!(
        classify(AbiProfile::Aapcs64, &array(layout, 1))
            .unwrap()
            .natural_alignment,
        16
    );
}

#[test]
fn aapcs_nested_hfa_preserves_element_offsets() {
    let pair = structure(
        16,
        8,
        vec![
            field(0, float(Precision::Double)),
            field(8, float(Precision::Double)),
        ],
    );
    let layout = structure(
        24,
        8,
        vec![field(0, pair), field(16, float(Precision::Double))],
    );
    assert_eq!(
        classify(AbiProfile::Aapcs64, &layout).unwrap().passing,
        ValueClass::Registers(vec![
            piece(0, 8, Simd),
            piece(8, 8, Simd),
            piece(16, 8, Simd)
        ])
    );
}

#[test]
fn aapcs_nonhomogeneous_and_five_element_aggregates_are_not_hfas() {
    let mut union = structure(8, 8, vec![]);
    union.kind = LayoutKind::Union(vec![
        field(0, float(Precision::Double)),
        field(0, float(Precision::Single)),
    ]);
    assert_eq!(
        classify(AbiProfile::Aapcs64, &union).unwrap().passing,
        ValueClass::Registers(vec![piece(0, 8, Integer)])
    );
    let five = structure(20, 4, vec![field(0, array(float(Precision::Single), 5))]);
    assert_eq!(
        classify(AbiProfile::Aapcs64, &five).unwrap().passing,
        ValueClass::Indirect
    );
}

#[test]
fn ordinary_large_aggregate_has_profile_specific_transport() {
    let layout = structure(24, 8, vec![field(0, array(integer(8), 3))]);
    assert_eq!(
        classify(AbiProfile::SysV, &layout).unwrap().passing,
        ValueClass::Memory
    );
    assert_eq!(
        classify(AbiProfile::Aapcs64, &layout).unwrap().passing,
        ValueClass::Indirect
    );
    assert_eq!(
        classify(AbiProfile::Win64, &layout).unwrap().passing,
        ValueClass::Indirect
    );
    let two_words = structure(16, 8, vec![field(0, array(integer(8), 2))]);
    assert_eq!(
        classify(AbiProfile::Aapcs64, &two_words).unwrap().passing,
        ValueClass::Registers(vec![piece(0, 8, Integer), piece(8, 8, Integer)])
    );
}

#[test]
fn win64_only_power_of_two_aggregate_sizes_up_to_eight_are_direct() {
    for size in [1, 2, 3, 4, 5, 8, 16] {
        let layout = structure(size, 1, vec![field(0, array(integer(1), size))]);
        let expected = if matches!(size, 1 | 2 | 4 | 8) {
            ValueClass::Registers(vec![piece(0, size, Integer)])
        } else {
            ValueClass::Indirect
        };
        assert_eq!(
            classify(AbiProfile::Win64, &layout).unwrap().passing,
            expected
        );
    }
    let scalar = float(Precision::Single);
    let wrapper = structure(4, 4, vec![field(0, scalar.clone())]);
    assert_eq!(
        classify(AbiProfile::Win64, &scalar).unwrap().passing,
        ValueClass::Registers(vec![piece(0, 4, Simd)])
    );
    assert_eq!(
        classify(AbiProfile::Win64, &wrapper).unwrap().passing,
        ValueClass::Registers(vec![piece(0, 4, Integer)])
    );
}

#[test]
fn defined_bits_exclude_padding_and_unused_bitfield_storage() {
    let padded = structure(8, 4, vec![field(0, integer(1)), field(4, integer(2))]);
    assert_eq!(
        classify(AbiProfile::SysV, &padded).unwrap().defined_bits,
        vec![(0, 8), (32, 16)]
    );
    let flags = structure(
        4,
        4,
        vec![
            LayoutField {
                bit_offset: 0,
                bit_size: Some(1),
                defined: true,
                layout: integer(4),
            },
            LayoutField {
                bit_offset: 1,
                bit_size: Some(3),
                defined: false,
                layout: integer(4),
            },
            LayoutField {
                bit_offset: 4,
                bit_size: Some(4),
                defined: true,
                layout: integer(4),
            },
        ],
    );
    let value = classify(AbiProfile::SysV, &flags).unwrap();
    assert_eq!(value.defined_bits, vec![(0, 1), (4, 4)]);
    assert_eq!(
        value.passing,
        ValueClass::Registers(vec![piece(0, 4, Integer)])
    );
}

#[test]
fn unresolved_and_nontrivial_layouts_are_rejected() {
    for profile in [AbiProfile::SysV, AbiProfile::Aapcs64, AbiProfile::Win64] {
        let mut layout = structure(8, 8, vec![field(0, integer(8))]);
        layout.alignment = None;
        assert_eq!(
            classify(profile, &layout).unwrap_err(),
            AbiIssue::UnknownLayout
        );
        layout.alignment = Some(8);
        layout.trivial = false;
        assert_eq!(
            classify(profile, &layout).unwrap_err(),
            AbiIssue::NonTrivial
        );
        layout.trivial = true;
        layout.kind = LayoutKind::Float(Precision::Single);
        assert_eq!(
            classify(profile, &layout).unwrap_err(),
            AbiIssue::UnsupportedType
        );
        let malformed = structure(4, 4, vec![field(0, integer(8))]);
        assert!(classify(profile, &malformed).is_err());
        let mut invalid_alignment = integer(8);
        invalid_alignment.alignment = Some(1 << 63);
        let malformed = structure(8, 8, vec![field(0, invalid_alignment)]);
        assert_eq!(
            classify(profile, &malformed).unwrap_err(),
            AbiIssue::UnknownLayout
        );
    }
}

#[test]
fn declaration_compatibility_checks_size_and_register_classes() {
    let original = structure(8, 8, vec![field(0, float(Precision::Double))]);
    let opaque = structure(8, 8, vec![field(0, array(integer(1), 8))]);
    assert_eq!(
        compatible(AbiProfile::SysV, &original, &opaque),
        Err(AbiIssue::IncompatibleDefinition)
    );
    let padded = structure(8, 8, vec![field(0, integer(4))]);
    let storage = structure(8, 8, vec![field(0, integer(8))]);
    assert_eq!(compatible(AbiProfile::SysV, &padded, &storage), Ok(()));
    let mut different_alignment = storage.clone();
    different_alignment.alignment = Some(4);
    assert_eq!(
        compatible(AbiProfile::SysV, &storage, &different_alignment),
        Ok(())
    );
    let larger = structure(16, 8, vec![field(0, array(integer(8), 2))]);
    assert_eq!(
        compatible(AbiProfile::SysV, &storage, &larger),
        Err(AbiIssue::IncompatibleDefinition)
    );
}

#[test]
fn boolean_layout_defines_only_its_value_bit() {
    let layout = TypeLayout {
        size: 1,
        alignment: Some(1),
        kind: LayoutKind::Boolean,
        trivial: true,
    };
    for profile in [AbiProfile::SysV, AbiProfile::Aapcs64, AbiProfile::Win64] {
        let value = classify(profile, &layout).unwrap();
        assert_eq!(value.defined_bits, vec![(0, 1)]);
        assert_eq!(
            value.passing,
            ValueClass::Registers(vec![piece(0, 1, Integer)])
        );
        let mut malformed = layout.clone();
        malformed.size = 2;
        assert_eq!(
            classify(profile, &malformed),
            Err(AbiIssue::UnsupportedType)
        );
    }
}

#[test]
fn declaration_compatibility_preserves_every_defined_bit() {
    let boolean = TypeLayout {
        size: 1,
        alignment: Some(1),
        kind: LayoutKind::Boolean,
        trivial: true,
    };
    let original = TypeLayout {
        size: 4,
        alignment: Some(4),
        kind: LayoutKind::Union(vec![
            LayoutField {
                bit_offset: 0,
                bit_size: Some(3),
                defined: true,
                layout: integer(4),
            },
            field(0, boolean.clone()),
        ]),
        trivial: true,
    };
    let generated = TypeLayout {
        kind: LayoutKind::Union(vec![field(0, boolean)]),
        ..original.clone()
    };
    for profile in [AbiProfile::SysV, AbiProfile::Aapcs64, AbiProfile::Win64] {
        assert_eq!(
            compatible(profile, &original, &generated),
            Err(AbiIssue::IncompatibleDefinition)
        );
        assert_eq!(compatible(profile, &generated, &original), Ok(()));
        let complete = structure(4, 1, vec![field(0, array(integer(1), 4))]);
        let gaps = structure(4, 1, vec![field(0, integer(1)), field(2, integer(1))]);
        assert_eq!(
            compatible(profile, &complete, &gaps),
            Err(AbiIssue::IncompatibleDefinition)
        );
        assert_eq!(compatible(profile, &gaps, &complete), Ok(()));
    }
}

#[test]
fn unknown_point_alignment_preserves_equivalent_classification() {
    let generated = structure(8, 4, vec![field(0, integer(4)), field(4, integer(4))]);
    let mut original = generated.clone();
    original.alignment = None;
    let mut alignments = alternatives(&original)
        .unwrap()
        .iter()
        .map(|layout| layout.alignment.unwrap())
        .collect::<Vec<_>>();
    alignments.sort_unstable();
    assert_eq!(alignments, vec![1, 2, 4, 8]);
    assert_eq!(canonical(&original).unwrap(), generated);
    assert_eq!(compatible(AbiProfile::SysV, &original, &generated), Ok(()));
}

#[test]
fn unknown_alignment_keeps_overaligned_candidates_and_explicit_values() {
    let mut original = structure(16, 1, vec![field(0, array(integer(1), 16))]);
    original.alignment = None;
    let mut alignments = alternatives(&original)
        .unwrap()
        .iter()
        .map(|layout| layout.alignment.unwrap())
        .collect::<Vec<_>>();
    alignments.sort_unstable();
    assert_eq!(alignments, vec![1, 2, 4, 8, 16]);
    assert_eq!(canonical(&original).unwrap().alignment, Some(1));
    original.alignment = Some(16);
    assert_eq!(alternatives(&original).unwrap(), vec![original.clone()]);
    assert_eq!(canonical(&original).unwrap(), original);
    assert_eq!(compatible(AbiProfile::SysV, &original, &original), Ok(()));
    let mut scalar = integer(8);
    scalar.alignment = None;
    assert_eq!(alternatives(&scalar), Err(AbiIssue::UnknownLayout));
    assert_eq!(canonical(&scalar), Err(AbiIssue::UnknownLayout));
}

#[test]
fn unknown_nested_struct_and_array_alignments_form_all_combinations() {
    let mut element = structure(8, 4, vec![field(0, integer(4)), field(4, integer(4))]);
    element.alignment = None;
    let mut elements = array(element, 2);
    elements.alignment = None;
    let mut original = structure(16, 4, vec![field(0, elements)]);
    original.alignment = None;
    let choices = alternatives(&original).unwrap();
    assert_eq!(choices.len(), 100);
    let mut combinations = choices
        .iter()
        .map(|layout| {
            let LayoutKind::Struct(fields) = &layout.kind else {
                panic!("expected structure")
            };
            let LayoutKind::Array { element, .. } = &fields[0].layout.kind else {
                panic!("expected array")
            };
            (
                layout.alignment.unwrap(),
                fields[0].layout.alignment.unwrap(),
                element.alignment.unwrap(),
            )
        })
        .collect::<Vec<_>>();
    combinations.sort_unstable();
    combinations.dedup();
    assert_eq!(combinations.len(), 100);
    assert!(combinations.contains(&(16, 16, 8)));
    assert!(combinations.contains(&(1, 1, 1)));
}

#[test]
fn unknown_nested_alignment_cannot_hide_a_sysv_memory_class() {
    let inner = structure(8, 4, vec![field(0, integer(4)), field(4, integer(4))]);
    let generated = structure(
        16,
        4,
        vec![field(0, integer(4)), field(4, inner), field(12, integer(4))],
    );
    let mut original = generated.clone();
    let LayoutKind::Struct(fields) = &mut original.kind else {
        panic!("expected structure")
    };
    fields[1].layout.alignment = None;
    let classes = alternatives(&original)
        .unwrap()
        .iter()
        .map(|layout| classify(AbiProfile::SysV, layout).unwrap().passing)
        .collect::<Vec<_>>();
    assert!(classes.contains(&ValueClass::Memory));
    assert!(classes.contains(&ValueClass::Registers(vec![
        piece(0, 8, Integer),
        piece(8, 8, Integer)
    ])));
    assert_eq!(
        compatible(AbiProfile::SysV, &original, &generated),
        Err(AbiIssue::IncompatibleDefinition)
    );
}

#[test]
fn alignment_alternatives_are_bounded_without_silent_truncation() {
    let mut layout = integer(8);
    for _ in 0..4 {
        layout = structure(8, 8, vec![field(0, layout)]);
        layout.alignment = None;
    }
    assert_eq!(alternatives(&layout).unwrap().len(), 256);
    let mut excessive = structure(8, 8, vec![field(0, layout)]);
    excessive.alignment = None;
    assert_eq!(alternatives(&excessive), Err(AbiIssue::UnknownLayout));
}
