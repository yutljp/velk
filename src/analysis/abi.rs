use crate::ir::abi::{
    ClassifiedValue, LayoutKind, TypeLayout, ValueClass, alternatives, canonical, classify,
};
use crate::ir::{
    AbiIssue, AbiLocation, AbiPiece, AbiProfile, CType, Convention, DeclaredSignature, Passing,
    RegisterClass, SignatureAbi, ValueAbi,
};
use crate::loader::dwarf::FunctionTypes;

pub(crate) fn aapcs32_words(types: &FunctionTypes) -> bool {
    let word = |ty: &CType| {
        ty.integer().is_some_and(|(bits, _)| bits <= 64) || ty.is_pointer() || *ty == CType::Void
    };
    types
        .params
        .iter()
        .filter_map(|(_, ty)| ty.as_ref())
        .chain(types.ret.iter())
        .all(word)
        && types.ret_aggregate_size.is_none()
        && types.param_aggregate_sizes.iter().all(Option::is_none)
}

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
    Some(callee_declaration(types))
}

/// The declaration `types` give a function, whether or not it passes an
/// aggregate.
pub(crate) fn callee_declaration(types: &FunctionTypes) -> DeclaredSignature {
    let abi = (|| {
        let profile = match types.abi_profile {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if types.variadic {
            return Err(AbiIssue::UnsupportedProfile);
        }
        if types.params.len() != types.param_layouts.len()
            || types.params.iter().any(|(_, ty)| ty.is_none())
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let arguments: Result<Vec<_>, _> = types.param_layouts.iter().cloned().collect();
        let result = match types.ret_layout.as_ref().map_err(|issue| *issue) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if result.is_some() && types.ret.is_none() {
            return Err(AbiIssue::UnknownLayout);
        }
        let arguments = match arguments {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        allocate(profile, &arguments, result.as_ref())
    })();
    DeclaredSignature {
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
    }
}

pub(crate) fn convention(profile: AbiProfile) -> Convention {
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
    if let Err(error) = value.validate() {
        return Err(error);
    }
    Ok(value)
}

fn rounded(value: u64, alignment: u64) -> Result<u64, AbiIssue> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(AbiIssue::UnknownLayout)
}

fn result_binding(profile: AbiProfile, classified: &ClassifiedValue) -> Result<ValueAbi, AbiIssue> {
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
                    let register = match match piece.class {
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
                    .ok_or(AbiIssue::UnsupportedType)
                    {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    Ok(AbiPiece {
                        location: AbiLocation::Register(register),
                        object_offset: piece.object_offset,
                        bytes: piece.bytes,
                        class: Some(piece.class),
                    })
                })
                .collect();
            let pieces = match pieces {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Passing::Direct(pieces)
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
        let lowered_stack = match self.stack.checked_sub(bias).ok_or(AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let aligned = match rounded(lowered_stack, alignment) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let offset = match aligned.checked_add(bias).ok_or(AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let rounded_size = match rounded(bytes, 8) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.stack = match offset
            .checked_add(rounded_size)
            .ok_or(AbiIssue::UnknownLayout)
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let value = match i64::try_from(offset).map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Ok(AbiLocation::Stack(value))
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
        let alignment = if self.profile == AbiProfile::Aapcs64 {
            classified.natural_alignment
        } else {
            classified.alignment
        };
        let passing = match &classified.passing {
            ValueClass::Indirect => {
                let hidden_pointer = match self.pointer() {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                Passing::Indirect {
                    pointer: hidden_pointer,
                    returned_pointer: None,
                }
            }
            ValueClass::Memory => {
                let location = match self.stack(classified.size, alignment) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                Passing::Direct(vec![AbiPiece {
                    location,
                    object_offset: 0,
                    bytes: classified.size,
                    class: None,
                }])
            }
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
                    && alignment >= 16
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

                    let location = match self.stack(classified.size, alignment) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    Passing::Direct(vec![AbiPiece {
                        location,
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
            match self.stack(8, 8) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
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
    let result = match returned
        .map(|layout| {
            let representative = match canonical(layout) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let classified = match classify(profile, &representative) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let binding = match result_binding(profile, &classified) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let alternative_layouts = match alternatives(layout) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            for alternative in alternative_layouts {
                let classified = match classify(profile, &alternative) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let alternative = match result_binding(profile, &classified) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if !same_binding(&binding, &alternative) {
                    return Err(AbiIssue::UnknownLayout);
                }
            }
            Ok(binding)
        })
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
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
        let representative = match canonical(layout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let representative_class = match classify(profile, &representative) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let binding = match allocation.argument(&representative_class) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let alternatives = match alternatives(layout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        for alternative in alternatives {
            let mut state = before.clone();
            let classified = match classify(profile, &alternative) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let alternative = match state.argument(&classified) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
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
mod tests;
