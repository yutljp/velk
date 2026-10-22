use crate::ir::abi::{
    ClassifiedValue, LayoutKind, TypeLayout, ValueClass, alternatives, canonical, classify,
};
use crate::ir::{
    AbiIssue, AbiLocation, AbiPiece, AbiProfile, CType, Convention, DeclaredSignature, Passing,
    RegisterClass, SignatureAbi, ValueAbi,
};
use crate::loader::dwarf::FunctionTypes;

fn aggregate(layout: &TypeLayout) -> bool {
    matches!(
        layout.kind,
        LayoutKind::Array { .. } | LayoutKind::Struct(_) | LayoutKind::Union(_)
    )
}

pub(crate) fn has_aggregate(types: &FunctionTypes) -> bool {
    let named = |ty: &CType| {
        matches!(ty, CType::Array(_))
            || matches!(ty, CType::Named(name) if name.starts_with("struct ") || name.starts_with("union "))
    };
    types.ret_aggregate_size.is_some()
        || types.param_aggregate_sizes.iter().any(Option::is_some)
        || types.ret.as_ref().is_some_and(named)
        || types
            .params
            .iter()
            .any(|(_, ty)| ty.as_ref().is_some_and(named))
        || types
            .param_layouts
            .iter()
            .any(|layout| layout.as_ref().is_ok_and(aggregate))
        || types
            .ret_layout
            .as_ref()
            .is_ok_and(|layout| layout.as_ref().is_some_and(aggregate))
}

pub(crate) fn declaration(types: &FunctionTypes) -> Option<DeclaredSignature> {
    if !has_aggregate(types) {
        return None;
    }
    let abi = (|| {
        let profile = types.abi_profile?;
        if types.variadic {
            return Err(AbiIssue::UnsupportedProfile);
        }
        if types.params.len() != types.param_layouts.len()
            || types.params.iter().any(|(_, ty)| ty.is_none())
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let arguments: Result<Vec<_>, _> = types.param_layouts.iter().cloned().collect();
        let result = types.ret_layout.as_ref().map_err(|issue| *issue)?;
        if result.is_some() && types.ret.is_none() {
            return Err(AbiIssue::UnknownLayout);
        }
        allocate(profile, &arguments?, result.as_ref())
    })();
    Some(DeclaredSignature {
        params: types
            .params
            .iter()
            .enumerate()
            .map(|(position, (name, ty))| {
                (
                    name.clone().unwrap_or_else(|| format!("a{position}")),
                    ty.clone().unwrap_or(CType::U64),
                )
            })
            .collect(),
        ret: types.ret.clone().unwrap_or(CType::Void),
        variadic: types.variadic,
        abi,
    })
}

fn convention(profile: AbiProfile) -> Convention {
    match profile {
        AbiProfile::SysV => Convention::SysV,
        AbiProfile::Aapcs64 => Convention::Aapcs64,
        AbiProfile::Win64 => Convention::Win64,
    }
}

fn value(classified: &ClassifiedValue, passing: Passing) -> Result<ValueAbi, AbiIssue> {
    let value = ValueAbi {
        aggregate: classified.aggregate,
        size: classified.size,
        alignment: classified.alignment,
        defined_bits: classified.defined_bits.clone(),
        passing,
    };
    value.validate()?;
    Ok(value)
}

fn rounded(value: u64, alignment: u64) -> Result<u64, AbiIssue> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(AbiIssue::UnknownLayout)
}

fn result(profile: AbiProfile, classified: &ClassifiedValue) -> Result<ValueAbi, AbiIssue> {
    let passing = match &classified.passing {
        ValueClass::Registers(pieces) => {
            let integers: &[u16] = match profile {
                AbiProfile::SysV => &[0, 2],
                AbiProfile::Aapcs64 => &[0, 1],
                AbiProfile::Win64 => &[0],
            };
            let floats: &[u16] = match profile {
                AbiProfile::SysV => &[18, 20],
                AbiProfile::Aapcs64 => &[32, 34, 36, 38],
                AbiProfile::Win64 => &[18],
            };
            let (mut integer, mut float) = (0, 0);
            let pieces: Result<Vec<_>, _> = pieces
                .iter()
                .map(|piece| {
                    let register = match piece.class {
                        RegisterClass::Integer => {
                            let register = integers.get(integer).copied();
                            integer += 1;
                            register
                        }
                        RegisterClass::Simd => {
                            let register = floats.get(float).copied();
                            float += 1;
                            register
                        }
                    }
                    .ok_or(AbiIssue::UnsupportedType)?;
                    Ok(AbiPiece {
                        location: AbiLocation::Register(register),
                        object_offset: piece.object_offset,
                        bytes: piece.bytes,
                        class: Some(piece.class),
                    })
                })
                .collect();
            Passing::Direct(pieces?)
        }
        ValueClass::Memory | ValueClass::Indirect => Passing::Indirect {
            pointer: AbiLocation::Register(match profile {
                AbiProfile::SysV => 7,
                AbiProfile::Aapcs64 => 8,
                AbiProfile::Win64 => 1,
            }),
            returned_pointer: (profile != AbiProfile::Aapcs64).then_some(0),
        },
    };
    value(classified, passing)
}

#[derive(Clone, PartialEq, Eq)]
struct Allocation {
    profile: AbiProfile,
    integer: usize,
    float: usize,
    position: usize,
    stack: u64,
}

impl Allocation {
    fn stack(&mut self, bytes: u64, alignment: u64) -> Result<AbiLocation, AbiIssue> {
        let bias = u64::from(self.profile == AbiProfile::SysV) * 8;
        let alignment = if self.profile == AbiProfile::Aapcs64 {
            alignment.clamp(8, 16)
        } else {
            alignment.max(8)
        };
        let offset = rounded(
            self.stack
                .checked_sub(bias)
                .ok_or(AbiIssue::UnknownLayout)?,
            alignment,
        )?
        .checked_add(bias)
        .ok_or(AbiIssue::UnknownLayout)?;
        self.stack = offset
            .checked_add(rounded(bytes, 8)?)
            .ok_or(AbiIssue::UnknownLayout)?;
        Ok(AbiLocation::Stack(
            i64::try_from(offset).map_err(|_| AbiIssue::UnknownLayout)?,
        ))
    }

    fn pointer(&mut self) -> Result<AbiLocation, AbiIssue> {
        let integers = convention(self.profile).arguments();
        if let Some(register) = integers.get(self.integer) {
            self.integer += 1;
            Ok(AbiLocation::Register(*register))
        } else {
            self.stack(8, 8)
        }
    }

    fn argument(&mut self, classified: &ClassifiedValue) -> Result<ValueAbi, AbiIssue> {
        if self.profile == AbiProfile::Win64 {
            return self.windows(classified);
        }
        let passing = match &classified.passing {
            ValueClass::Indirect => Passing::Indirect {
                pointer: self.pointer()?,
                returned_pointer: None,
            },
            ValueClass::Memory => Passing::Direct(vec![AbiPiece {
                location: self.stack(classified.size, classified.alignment)?,
                object_offset: 0,
                bytes: classified.size,
                class: None,
            }]),
            ValueClass::Registers(pieces) => {
                let integers = convention(self.profile).arguments();
                let floats = convention(self.profile).float_arguments();
                let integer_count = pieces
                    .iter()
                    .filter(|piece| piece.class == RegisterClass::Integer)
                    .count();
                let float_count = pieces.len() - integer_count;
                let next_integer = if self.profile == AbiProfile::Aapcs64
                    && integer_count > 0
                    && classified.alignment >= 16
                {
                    self.integer.next_multiple_of(2)
                } else {
                    self.integer
                };
                if next_integer + integer_count <= integers.len()
                    && self.float + float_count <= floats.len()
                {
                    self.integer = next_integer;
                    Passing::Direct(
                        pieces
                            .iter()
                            .map(|piece| {
                                let register = match piece.class {
                                    RegisterClass::Integer => {
                                        let register = integers[self.integer];
                                        self.integer += 1;
                                        register
                                    }
                                    RegisterClass::Simd => {
                                        let register = floats[self.float];
                                        self.float += 1;
                                        register
                                    }
                                };
                                AbiPiece {
                                    location: AbiLocation::Register(register),
                                    object_offset: piece.object_offset,
                                    bytes: piece.bytes,
                                    class: Some(piece.class),
                                }
                            })
                            .collect(),
                    )
                } else {
                    if self.profile == AbiProfile::Aapcs64 {
                        if integer_count > 0 {
                            self.integer = integers.len();
                        }
                        if float_count > 0 {
                            self.float = floats.len();
                        }
                    }
                    Passing::Direct(vec![AbiPiece {
                        location: self.stack(classified.size, classified.alignment)?,
                        object_offset: 0,
                        bytes: classified.size,
                        class: None,
                    }])
                }
            }
        };
        value(classified, passing)
    }

    fn windows(&mut self, classified: &ClassifiedValue) -> Result<ValueAbi, AbiIssue> {
        let position = self.position;
        self.position += 1;
        let indirect = matches!(
            classified.passing,
            ValueClass::Indirect | ValueClass::Memory
        );
        let class = match &classified.passing {
            ValueClass::Registers(pieces) if pieces.len() == 1 => pieces[0].class,
            ValueClass::Registers(_) => return Err(AbiIssue::UnsupportedType),
            _ => RegisterClass::Integer,
        };
        let location = if position < 4 {
            let registers = if class == RegisterClass::Simd {
                Convention::Win64.float_arguments()
            } else {
                Convention::Win64.arguments()
            };
            AbiLocation::Register(registers[position])
        } else {
            self.stack(8, 8)?
        };
        let passing = if indirect {
            Passing::Indirect {
                pointer: location,
                returned_pointer: None,
            }
        } else {
            Passing::Direct(vec![AbiPiece {
                location,
                object_offset: 0,
                bytes: classified.size,
                class: matches!(location, AbiLocation::Register(_)).then_some(class),
            }])
        };
        value(classified, passing)
    }
}

pub(crate) fn allocate(
    profile: AbiProfile,
    arguments: &[TypeLayout],
    returned: Option<&TypeLayout>,
) -> Result<SignatureAbi, AbiIssue> {
    let result = returned
        .map(|layout| {
            let representative = canonical(layout)?;
            let binding = result(profile, &classify(profile, &representative)?)?;
            for alternative in alternatives(layout)? {
                let alternative = result(profile, &classify(profile, &alternative)?)?;
                if !same_binding(&binding, &alternative) {
                    return Err(AbiIssue::UnknownLayout);
                }
            }
            Ok(binding)
        })
        .transpose()?;
    let hidden = result
        .as_ref()
        .is_some_and(|value| matches!(value.passing, Passing::Indirect { .. }));
    let mut allocation = Allocation {
        profile,
        integer: usize::from(hidden && profile == AbiProfile::SysV),
        float: 0,
        position: usize::from(hidden && profile == AbiProfile::Win64),
        stack: match profile {
            AbiProfile::SysV => 8,
            AbiProfile::Aapcs64 => 0,
            AbiProfile::Win64 => 40,
        },
    };
    let mut bindings = Vec::with_capacity(arguments.len());
    for layout in arguments {
        let before = allocation.clone();
        let representative = canonical(layout)?;
        let binding = allocation.argument(&classify(profile, &representative)?)?;
        for alternative in alternatives(layout)? {
            let mut state = before.clone();
            let alternative = state.argument(&classify(profile, &alternative)?)?;
            if !same_binding(&binding, &alternative) || state != allocation {
                return Err(AbiIssue::UnknownLayout);
            }
        }
        bindings.push(binding);
    }
    Ok(SignatureAbi {
        profile,
        arguments: bindings,
        result,
    })
}

fn same_binding(left: &ValueAbi, right: &ValueAbi) -> bool {
    left.aggregate == right.aggregate
        && left.size == right.size
        && left.defined_bits == right.defined_bits
        && left.passing == right.passing
}

#[cfg(test)]
mod tests {
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
    fn unknown_alignment_is_rejected_when_the_following_register_changes() {
        let mut pair = object(vec![integer(), integer()]);
        pair.alignment = None;
        assert_eq!(
            allocate(AbiProfile::Aapcs64, &[integer(), pair, integer()], None),
            Err(AbiIssue::UnknownLayout)
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
}
