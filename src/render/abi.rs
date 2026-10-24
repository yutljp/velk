use std::collections::HashSet;

use crate::ir::{
    AbiLocation, AbiPiece, CType, FunctionIr, Param, Passing, RegisterClass, Stmt, ValueAbi,
};

use super::{Symbols, abi_objects, declaration, sanitize, vacant_name};

mod fields;

pub(super) struct Capture {
    pub register: u16,
    pub name: String,
    pub object: String,
    pub piece: AbiPiece,
    parameter: usize,
    field: Option<String>,
    parts: Vec<crate::ir::Member>,
}

pub(super) struct ResultObject {
    pub name: String,
    pub ty: CType,
    pub pieces: Vec<(AbiPiece, String)>,
    pub indirect: bool,
    pub fields: Vec<String>,
    pub parts: Vec<Vec<crate::ir::Member>>,
}

pub(super) struct Plan {
    pub params: Vec<(String, CType)>,
    pub variadic: bool,
    pub captures: Vec<Capture>,
    pub pointers: Vec<abi_objects::Binding>,
    pub result: Option<ResultObject>,
    pointer_parameters: Vec<Option<usize>>,
}

pub(super) fn mask(value: &ValueAbi, piece: &AbiPiece) -> u64 {
    let start = piece.object_offset * 8;
    let end = start + piece.bytes * 8;
    let mut mask = 0;
    for &(offset, count) in &value.defined_bits {
        let low = offset.max(start);
        let high = (offset + count).min(end);
        if low < high {
            let bits = high - low;
            let range = u64::MAX >> (64 - bits);
            mask |= range << (low - start);
        }
    }
    mask
}

fn logical_type(ty: &CType, value: &ValueAbi, returned: bool) -> Option<CType> {
    if value.aggregate {
        return Some(ty.clone());
    }
    let wide_signed = match ty {
        CType::Int { bytes: 16, signed } => Some(*signed),
        CType::Named(name) => match name.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["__int128"] | ["signed", "__int128"] | ["__int128", "signed"] => Some(true),
            ["unsigned", "__int128"] | ["__int128", "unsigned"] => Some(false),
            _ => None,
        },
        _ => None,
    };
    if value.size > 8 || wide_signed.is_some() {
        let Some(signed) = wide_signed else {
            return None;
        };
        if value.size != 16
            || value.alignment != 16
            || !matches!(value.defined_bits.as_slice(), [(0, 128)])
        {
            return None;
        }
        let Passing::Direct(pieces) = &value.passing else {
            return None;
        };
        let registers = pieces.len() == 2
            && pieces[0].location != pieces[1].location
            && pieces.iter().enumerate().all(|(index, piece)| {
                matches!(piece.location, AbiLocation::Register(_))
                    && piece.class == Some(RegisterClass::Integer)
                    && piece.object_offset == index as u64 * 8
                    && piece.bytes == 8
            });
        let stack = !returned
            && matches!(
                pieces.as_slice(),
                [AbiPiece {
                    location: AbiLocation::Stack(_),
                    object_offset: 0,
                    bytes: 16,
                    class: None,
                }]
            );
        if !registers && !stack {
            return None;
        }
        return Some(CType::Named(
            if signed {
                "__int128"
            } else {
                "unsigned __int128"
            }
            .to_owned(),
        ));
    }
    if ty
        .integer()
        .is_some_and(|(bits, _)| u64::from(bits) != value.size * 8)
    {
        return None;
    }
    Some(ty.clone())
}

pub(super) fn prepare(ir: &mut FunctionIr, symbols: &Symbols) -> Option<Plan> {
    let Some(signature) = ir.declared_signature.as_ref() else {
        return None;
    };
    let Ok(abi) = signature.abi.as_ref() else {
        return None;
    };
    if signature.params.len() != abi.arguments.len()
        || !abi
            .arguments
            .iter()
            .chain(&abi.result)
            .any(|value| value.aggregate)
        || signature.variadic
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Call { .. }))
    {
        return None;
    }
    for (ty, value) in signature
        .params
        .iter()
        .map(|(_, ty)| ty)
        .zip(&abi.arguments)
        .chain(abi.result.iter().map(|value| (&signature.ret, value)))
    {
        if value.validate().is_err() {
            return None;
        }
        if value.aggregate {
            let Some(definition) = ir
                .definitions
                .iter()
                .find(|definition| definition.name == ty.to_string())
            else {
                return None;
            };
            if definition.size != value.size
                || definition.alignment != Some(value.alignment)
                || !definition.compatible_profiles.contains(&abi.profile)
            {
                return None;
            }
        }
    }
    let params: Option<Vec<_>> = signature
        .params
        .iter()
        .zip(&abi.arguments)
        .map(|((name, ty), value)| logical_type(ty, value, false).map(|ty| (sanitize(name), ty)))
        .collect();
    let Some(params) = params else { return None };
    let ret = match &abi.result {
        Some(value) => match logical_type(&signature.ret, value, true) {
            Some(ty) => ty,
            None => return None,
        },
        None => signature.ret.clone(),
    };
    if abi.result.as_ref().is_some_and(|value| matches!(&value.passing, Passing::Direct(pieces) if pieces.iter().any(|piece| !matches!(piece.location, AbiLocation::Register(_))))) {
        return None;
    }
    let return_masks: Vec<_> = match abi.result.as_ref().map(|value| (&value.passing, value)) {
        Some((Passing::Direct(pieces), value)) => {
            pieces.iter().map(|piece| mask(value, piece)).collect()
        }
        _ => vec![0],
    };
    let Some(demanded) = crate::ssa::entry_demands(ir, &return_masks) else {
        return None;
    };
    let mut captured = HashSet::new();
    for value in &abi.arguments {
        if let Passing::Direct(pieces) = &value.passing {
            for piece in pieces {
                if let AbiLocation::Register(index) = piece.location
                    && (!captured.insert(index)
                        || demanded.get(&index).copied().unwrap_or(0) & !mask(value, piece) != 0)
                {
                    return None;
                }
            }
        }
    }
    let mut reserved: HashSet<String> = ir
        .params
        .iter()
        .map(|param| param.name.clone())
        .chain(ir.stack_params.iter().map(|param| param.name.clone()))
        .chain(signature.params.iter().map(|(name, _)| sanitize(name)))
        .chain(symbols.reserved_names.iter().cloned())
        .chain(symbols.functions.values().cloned())
        .chain(symbols.data.values().cloned())
        .chain(
            ir.definitions
                .iter()
                .flat_map(|definition| definition.fields.iter().cloned()),
        )
        .collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, .. } = stmt {
            reserved.insert(crate::ir::reg_name(ir.isa, dest.index, 64));
        }
    }
    let mut objects = Vec::new();
    let mut pointer_parameters = Vec::new();
    let mut captures = Vec::new();
    for (parameter, ((object, _), value)) in params.iter().zip(&abi.arguments).enumerate() {
        match &value.passing {
            Passing::Direct(pieces) => {
                let mut stack_base = None;
                for piece in pieces {
                    match piece.location {
                        AbiLocation::Register(register) => captures.push(Capture {
                            register,
                            name: vacant_name(&format!("{object}_bits"), &mut reserved),
                            object: object.clone(),
                            piece: piece.clone(),
                            parameter,
                            field: None,
                            parts: Vec::new(),
                        }),
                        AbiLocation::Stack(offset) => {
                            let Ok(object_offset) = i64::try_from(piece.object_offset) else {
                                return None;
                            };
                            let Some(base) = offset.checked_sub(object_offset) else {
                                return None;
                            };
                            if stack_base
                                .replace(base)
                                .is_some_and(|previous| previous != base)
                            {
                                return None;
                            }
                        }
                    }
                }
                if let Some(offset) = stack_base {
                    if pieces
                        .iter()
                        .any(|piece| matches!(piece.location, AbiLocation::Register(_)))
                    {
                        return None;
                    }
                    objects.push(abi_objects::Object {
                        name: object.clone(),
                        size: value.size,
                        defined_bits: value.defined_bits.clone(),
                        source: abi_objects::Source::Stack(offset),
                        output: false,
                    });
                    pointer_parameters.push(Some(parameter));
                }
            }
            Passing::Indirect { pointer, .. } => {
                objects.push(abi_objects::Object {
                    name: object.clone(),
                    size: value.size,
                    defined_bits: value.defined_bits.clone(),
                    source: match pointer {
                        AbiLocation::Register(index) => abi_objects::Source::Register(*index),
                        AbiLocation::Stack(_) => return None,
                    },
                    output: false,
                });
                pointer_parameters.push(Some(parameter));
            }
        }
    }
    let result = match &abi.result {
        Some(value) if value.aggregate || value.size == 16 => {
            let name = vacant_name("result", &mut reserved);
            let (pieces, indirect) = match &value.passing {
                Passing::Direct(pieces) => (
                    pieces
                        .iter()
                        .map(|piece| (piece.clone(), vacant_name("result_bits", &mut reserved)))
                        .collect(),
                    false,
                ),
                Passing::Indirect {
                    pointer: AbiLocation::Register(index),
                    ..
                } => {
                    objects.push(abi_objects::Object {
                        name: name.clone(),
                        size: value.size,
                        defined_bits: value.defined_bits.clone(),
                        source: abi_objects::Source::Register(*index),
                        output: true,
                    });
                    pointer_parameters.push(None);
                    (Vec::new(), true)
                }
                _ => return None,
            };
            Some(ResultObject {
                name,
                ty: ret.clone(),
                pieces,
                indirect,
                fields: Vec::new(),
                parts: Vec::new(),
            })
        }
        _ => None,
    };
    let variadic = signature.variadic;
    let mut rewritten = ir.clone();
    let Some(pointers) = abi_objects::prepare(&mut rewritten, &objects) else {
        return None;
    };
    if pointers.iter().any(|binding| {
        symbols.reserved_names.contains(&binding.name)
            || symbols
                .functions
                .values()
                .chain(symbols.data.values())
                .any(|name| sanitize(name) == binding.name)
    }) {
        return None;
    }
    let pointer_regs: HashSet<_> = pointers.iter().map(|binding| binding.register).collect();
    if rewritten.params.iter().any(|param| {
        !captured.contains(&param.index)
            && !pointer_regs.contains(&param.index)
            && demanded.get(&param.index).copied().unwrap_or(0) != 0
    }) {
        return None;
    }
    rewritten.params = captures
        .iter()
        .map(|capture| Param {
            index: capture.register,
            name: capture.name.clone(),
            ty: CType::U64,
        })
        .chain(pointers.iter().map(|binding| Param {
            index: binding.register,
            name: binding.name.clone(),
            ty: CType::pointer_to(CType::int(1, false)),
        }))
        .collect();
    rewritten.stack_params.clear();
    rewritten.ret_type = ret;
    let mut plan = Plan {
        params,
        variadic,
        captures,
        pointers,
        result,
        pointer_parameters,
    };
    fields::project(&mut rewritten, &mut plan, reserved);
    fields::captures(&rewritten, &mut plan);
    *ir = rewritten;
    Some(plan)
}

impl Plan {
    pub fn resolve_names(
        &mut self,
        mut reserved: HashSet<String>,
        types: impl IntoIterator<Item = String>,
    ) {
        reserved.extend(self.captures.iter().map(|capture| capture.name.clone()));
        reserved.extend(self.pointers.iter().map(|binding| binding.name.clone()));
        reserved.extend(
            self.result
                .iter()
                .flat_map(|result| result.pieces.iter().map(|(_, name)| name.clone())),
        );
        for ty in types
            .into_iter()
            .chain(self.params.iter().map(|(_, ty)| ty.to_string()))
            .chain(self.result.iter().map(|result| result.ty.to_string()))
        {
            let mut tag = false;
            for word in ty
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .filter(|word| !word.is_empty())
            {
                if tag {
                    tag = false;
                } else if matches!(word, "struct" | "union" | "enum") {
                    tag = true;
                } else {
                    reserved.insert(word.to_owned());
                }
            }
        }
        let mut rename = Vec::new();
        for (position, (name, _)) in self.params.iter_mut().enumerate() {
            if name.is_empty() || name.starts_with(|character: char| character.is_ascii_digit()) {
                *name = format!("arg_{position}");
                rename.push(position);
                continue;
            }
            if !reserved.insert(name.clone()) || super::globals::reserved_identifier(name) {
                rename.push(position);
            }
        }
        for position in rename {
            let name = &mut self.params[position].0;
            *name = vacant_name(name, &mut reserved);
        }
        if let Some(result) = &mut self.result {
            result.name = vacant_name(&result.name, &mut reserved);
        }
        for capture in &mut self.captures {
            capture.object = self.params[capture.parameter].0.clone();
        }
        for (binding, parameter) in self.pointers.iter_mut().zip(&self.pointer_parameters) {
            binding.object = match parameter {
                Some(parameter) => self.params[*parameter].0.clone(),
                None => self
                    .result
                    .as_ref()
                    .expect("an indirect result object")
                    .name
                    .clone(),
            };
        }
    }

    pub fn reserved_names(&self) -> Vec<String> {
        self.params
            .iter()
            .map(|(name, _)| name.clone())
            .chain(self.result.iter().map(|result| result.name.clone()))
            .chain(
                self.result
                    .iter()
                    .flat_map(|result| result.pieces.iter().map(|(_, name)| name.clone())),
            )
            .collect()
    }
    pub fn signature(&self) -> String {
        let mut params: Vec<_> = self
            .params
            .iter()
            .map(|(name, ty)| declaration(ty, name))
            .collect();
        if self.variadic {
            params.push("...".to_owned());
        }
        if params.is_empty() {
            "void".to_owned()
        } else {
            params.join(", ")
        }
    }

    pub fn declarations(&self) -> Vec<String> {
        let mut declarations = Vec::new();
        if let Some(result) = &self.result {
            declarations.push(format!(
                "{} = {{0}};",
                declaration(&result.ty, &result.name)
            ));
        }
        for capture in &self.captures {
            if let Some(field) = &capture.field {
                declarations.push(format!(
                    "uint64_t {} = (uint32_t){}.{};",
                    capture.name, capture.object, field
                ));
                continue;
            }
            let ty = &self.params[capture.parameter].1;
            if let Some((bits, signed)) = ty.integer()
                && matches!(bits, 8 | 16 | 32 | 64)
                && !matches!(ty, CType::Named(name) if name.split_whitespace().any(|word| matches!(word, "bool" | "_Bool")))
                && capture.piece.object_offset == 0
                && capture.piece.bytes == u64::from(bits / 8)
            {
                let value = if signed && bits < 64 {
                    format!(
                        "({}){}",
                        super::expr::type_of((bits / 8) as u8, false),
                        capture.object
                    )
                } else {
                    capture.object.clone()
                };
                declarations.push(format!("uint64_t {} = {value};", capture.name));
                continue;
            }
            if !capture.parts.is_empty() {
                let parts: Vec<_> = capture
                    .parts
                    .iter()
                    .map(|member| {
                        let access = format!("{}.{}", capture.object, member.name);
                        let unsigned = super::expr::type_of(member.width as u8, false);
                        let value = if member.width != 8
                            && member.ty.integer().is_some_and(|(_, signed)| signed)
                        {
                            format!("({unsigned}){access}")
                        } else {
                            access
                        };
                        let shift = (member.offset as u64 - capture.piece.object_offset) * 8;
                        if shift == 0 {
                            value
                        } else {
                            format!("(uint64_t){value} << {shift}")
                        }
                    })
                    .collect();
                declarations.push(format!(
                    "uint64_t {} = {};",
                    capture.name,
                    parts.join(" | ")
                ));
                continue;
            }
            declarations.push(format!(
                "uint64_t {} = *(uint64_t *)__builtin_memcpy((uint64_t[1]){{0}}, (unsigned char *)&{} + 0x{:x}, {});",
                capture.name,
                capture.object,
                capture.piece.object_offset,
                capture.piece.bytes
            ));
        }
        for binding in &self.pointers {
            declarations.push(format!(
                "uint8_t *{} = (uint8_t *)&{};",
                binding.name, binding.object
            ));
        }
        declarations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        AbiProfile, DeclaredSignature, Definition, Expr, Operation, RegisterClass, SignatureAbi,
    };
    use crate::loader::Isa;

    fn value(size: u64, register: u16, aggregate: bool) -> ValueAbi {
        ValueAbi {
            aggregate,
            size,
            alignment: 1,
            defined_bits: vec![(0, size * 8)],
            passing: Passing::Direct(vec![AbiPiece {
                location: AbiLocation::Register(register),
                object_offset: 0,
                bytes: size,
                class: Some(crate::ir::RegisterClass::Integer),
            }]),
        }
    }

    fn function(size: u64, returned: Expr) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value: returned }]);
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::U64,
        }];
        ir.definitions = vec![Definition {
            name: "struct bytes".to_owned(),
            members: vec![format!("unsigned char bytes[{size}];")],
            fields: vec!["bytes".to_owned()],
            contains: vec![],
            size,
            alignment: Some(1),
            compatible_profiles: vec![AbiProfile::SysV],
        }];
        ir.declared_signature = Some(DeclaredSignature {
            params: vec![("object".to_owned(), CType::Named("struct bytes".to_owned()))],
            ret: CType::U64,
            variadic: false,
            abi: Ok(SignatureAbi {
                profile: AbiProfile::SysV,
                arguments: vec![value(size, 7, true)],
                result: Some(value(8, 0, false)),
            }),
        });
        ir
    }

    #[test]
    fn partial_entry_capture_requires_only_defined_bits() {
        let mut ir = function(
            1,
            Expr::bin(crate::ir::BinOp::And, Expr::reg(7, 64), Expr::Const(0xff)),
        );
        let plan = prepare(&mut ir, &Symbols::default()).unwrap();
        assert_eq!(ir.params[0].ty, CType::U64);
        assert!(
            plan.declarations()[0]
                .contains("__builtin_memcpy((uint64_t[1]){0}, (unsigned char *)&object + 0x0, 1)")
        );
        assert_eq!(
            plan.declarations()[0].matches("__builtin_memcpy").count(),
            1
        );
        let mut ir = function(1, Expr::reg(7, 64));
        assert!(prepare(&mut ir, &Symbols::default()).is_none());
        assert_eq!(ir.params[0].name, "a0");
    }

    #[test]
    fn partial_object_padding_is_not_a_register_guarantee() {
        let mut ir = function(8, Expr::reg(7, 64));
        ir.declared_signature
            .as_mut()
            .unwrap()
            .abi
            .as_mut()
            .unwrap()
            .arguments[0]
            .defined_bits = vec![(0, 8), (32, 32)];
        assert!(prepare(&mut ir, &Symbols::default()).is_none());
    }

    #[test]
    fn incompatible_definition_keeps_the_physical_signature() {
        let mut ir = function(8, Expr::reg(7, 64));
        ir.definitions[0].compatible_profiles.clear();
        assert!(prepare(&mut ir, &Symbols::default()).is_none());
        assert_eq!(ir.params[0].ty, CType::U64);
    }

    #[test]
    fn aggregate_result_keeps_every_piece() {
        let mut ir = function(
            8,
            Expr::Apply {
                op: Operation::Results,
                args: vec![Expr::Const(1), Expr::Const(2)],
            },
        );
        ir.definitions[0].size = 16;
        ir.definitions[0].members = vec!["unsigned char bytes[16];".to_owned()];
        let signature = ir.declared_signature.as_mut().unwrap();
        signature.params.clear();
        signature.ret = CType::Named("struct bytes".to_owned());
        let abi = signature.abi.as_mut().unwrap();
        abi.arguments.clear();
        abi.result = Some(ValueAbi {
            aggregate: true,
            size: 16,
            alignment: 1,
            defined_bits: vec![(0, 128)],
            passing: Passing::Direct(vec![
                AbiPiece {
                    location: AbiLocation::Register(0),
                    object_offset: 0,
                    bytes: 8,
                    class: Some(RegisterClass::Integer),
                },
                AbiPiece {
                    location: AbiLocation::Register(2),
                    object_offset: 8,
                    bytes: 8,
                    class: Some(RegisterClass::Integer),
                },
            ]),
        });
        ir.params.clear();
        let output = super::super::render(&ir, &[], &Symbols::default(), &[]);
        assert!(output.contains("result_bits = 1"), "{output}");
        assert!(output.contains("result_bits_2 = 2"), "{output}");
        assert!(
            output.contains("__builtin_memcpy((unsigned char *)&result + 0x0, &result_bits, 8);"),
            "{output}"
        );
        assert!(
            output.contains("__builtin_memcpy((unsigned char *)&result + 0x8, &result_bits_2, 8);"),
            "{output}"
        );
        assert!(output.contains("return result;"), "{output}");
        assert!(!output.contains("also returns"), "{output}");
    }

    #[test]
    fn a_partial_float_register_read_reinterprets_only_the_read_bits() {
        use crate::ir::{Precision, RegRef, VARIABLE_BASE};
        let pattern = 0x3ff0_0000_3ff0_0001;
        let low = 0x3ff0_0001;
        for (floating_consumer, masked) in [(false, false), (true, false), (true, true)] {
            let first = VARIABLE_BASE;
            let second = first + 1;
            let read = if masked {
                Expr::bin(
                    crate::ir::BinOp::And,
                    Expr::reg(first, 64),
                    Expr::Const(0xffff_ffff),
                )
            } else {
                Expr::reg(first, 32)
            };
            let mut ir = function(8, read.clone());
            ir.blocks[0].stmts.insert(
                0,
                Stmt::Assign {
                    dest: RegRef {
                        index: first,
                        width: 64,
                    },
                    value: Expr::Apply {
                        op: Operation::FloatAdd(Precision::Double),
                        args: vec![Expr::Const(pattern), Expr::Const(0)],
                    },
                },
            );
            if floating_consumer {
                ir.blocks[0].stmts.insert(
                    1,
                    Stmt::Assign {
                        dest: RegRef {
                            index: second,
                            width: 64,
                        },
                        value: Expr::Apply {
                            op: Operation::FloatAdd(Precision::Double),
                            args: vec![read, Expr::Const(0)],
                        },
                    },
                );
                *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::Ret {
                    value: Expr::reg(second, 64),
                };
            }
            let observed = crate::ir::eval::run(
                &ir,
                &crate::ir::eval::Setup {
                    seed: 1,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[],
                    memory: &[],
                    step_limit: 32,
                },
            );
            assert!(
                matches!(observed, crate::ir::eval::Outcome::Return { value, .. } if value == low),
                "{observed:?}"
            );
            let output = super::super::render(&ir, &[], &Symbols::default(), &[]);
            assert!(output.contains("double v1;"), "{output}");
            if masked {
                assert!(output.contains("0xffffffff"), "{output}");
            } else {
                assert!(output.contains("(uint32_t)"), "{output}");
            }
            assert!(output.contains(".bits"), "{output}");
            if floating_consumer {
                assert!(output.contains(".value"), "{output}");
            }
        }
    }

    #[test]
    fn logical_parameter_names_avoid_c_keywords() {
        for name in [
            "true",
            "false",
            "nullptr",
            "typeof",
            "static_assert",
            "thread_local",
            "alignas",
            "alignof",
            "constexpr",
        ] {
            let mut ir = function(8, Expr::reg(7, 64));
            ir.declared_signature.as_mut().unwrap().params[0].0 = name.to_owned();
            let mut plan = prepare(&mut ir, &Symbols::default()).unwrap();
            plan.resolve_names(HashSet::new(), Vec::new());
            assert_eq!(plan.params[0].0, format!("{name}_2"));
            assert_eq!(plan.captures[0].object, format!("{name}_2"));
        }
    }

    #[test]
    fn logical_names_reserve_real_locals_and_keep_struct_tags_available() {
        let mut ir = function(8, Expr::reg(7, 64));
        ir.declared_signature.as_mut().unwrap().params[0].0 = "local_0".to_owned();
        let mut plan = prepare(&mut ir, &Symbols::default()).unwrap();
        plan.resolve_names(HashSet::from(["local_0".to_owned()]), Vec::new());
        assert_eq!(plan.params[0].0, "local_0_2");
        assert_eq!(plan.captures[0].object, "local_0_2");

        ir.declared_signature.as_mut().unwrap().params[0].0 = "uint64_t".to_owned();
        let mut plan = prepare(&mut ir, &Symbols::default()).unwrap();
        plan.resolve_names(HashSet::new(), Vec::new());
        assert_eq!(plan.params[0].0, "uint64_t_2");
        assert_eq!(plan.captures[0].object, "uint64_t_2");

        ir.declared_signature.as_mut().unwrap().params[0].0 = "bytes".to_owned();
        let mut plan = prepare(&mut ir, &Symbols::default()).unwrap();
        plan.resolve_names(HashSet::new(), Vec::new());
        assert_eq!(plan.params[0].0, "bytes");
        assert_eq!(plan.captures[0].object, "bytes");
    }

    #[test]
    fn sanitized_names_keep_each_capture_bound_to_its_parameter() {
        let mut ir = function(
            8,
            Expr::bin(crate::ir::BinOp::Add, Expr::reg(7, 64), Expr::reg(6, 64)),
        );
        ir.params.push(Param {
            index: 6,
            name: "a1".to_owned(),
            ty: CType::U64,
        });
        let signature = ir.declared_signature.as_mut().unwrap();
        signature.params = vec![
            (
                "value.x".to_owned(),
                CType::Named("struct bytes".to_owned()),
            ),
            (
                "value-x".to_owned(),
                CType::Named("struct bytes".to_owned()),
            ),
        ];
        signature
            .abi
            .as_mut()
            .unwrap()
            .arguments
            .push(value(8, 6, true));
        let mut plan = prepare(&mut ir, &Symbols::default()).unwrap();
        plan.resolve_names(HashSet::new(), Vec::new());
        assert_eq!(plan.params[0].0, "value_x");
        assert_eq!(plan.params[1].0, "value_x_2");
        assert_eq!(plan.captures[0].object, "value_x");
        assert_eq!(plan.captures[1].object, "value_x_2");
    }

    #[test]
    fn a_collision_does_not_take_an_available_later_source_name() {
        let mut ir = function(8, Expr::reg(7, 64));
        let signature = ir.declared_signature.as_mut().unwrap();
        signature.params[0].0 = "local_0".to_owned();
        signature.params.push(("local_0_2".to_owned(), CType::U64));
        signature
            .abi
            .as_mut()
            .unwrap()
            .arguments
            .push(value(8, 6, false));
        let mut plan = prepare(&mut ir, &Symbols::default()).unwrap();
        plan.resolve_names(HashSet::from(["local_0".to_owned()]), Vec::new());
        assert_eq!(plan.params[0].0, "local_0_3");
        assert_eq!(plan.params[1].0, "local_0_2");
        assert_eq!(plan.captures[0].object, "local_0_3");
        assert_eq!(plan.captures[1].object, "local_0_2");
    }

    fn wide_result() -> ValueAbi {
        ValueAbi {
            aggregate: false,
            size: 16,
            alignment: 16,
            defined_bits: vec![(0, 128)],
            passing: Passing::Direct(vec![
                AbiPiece {
                    location: AbiLocation::Register(0),
                    object_offset: 0,
                    bytes: 8,
                    class: Some(RegisterClass::Integer),
                },
                AbiPiece {
                    location: AbiLocation::Register(2),
                    object_offset: 8,
                    bytes: 8,
                    class: Some(RegisterClass::Integer),
                },
            ]),
        }
    }

    #[test]
    fn wide_scalar_results_keep_both_words_in_a_valid_c_type() {
        for (ty, expected) in [
            (
                CType::Named("__int128 unsigned".to_owned()),
                "unsigned __int128",
            ),
            (
                CType::Int {
                    bytes: 16,
                    signed: true,
                },
                "__int128",
            ),
        ] {
            let mut ir = function(
                8,
                Expr::Apply {
                    op: Operation::Results,
                    args: vec![Expr::Const(1), Expr::Const(2)],
                },
            );
            let signature = ir.declared_signature.as_mut().unwrap();
            signature.ret = ty;
            signature.abi.as_mut().unwrap().result = Some(wide_result());
            let output = super::super::render(&ir, &[], &Symbols::default(), &[]);
            assert!(output.contains(&format!("{expected} sub_0(")), "{output}");
            assert!(
                output.contains(&format!("{expected} result = {{0}};")),
                "{output}"
            );
            assert!(output.contains("result_bits = 1"), "{output}");
            assert!(output.contains("result_bits_2 = 2"), "{output}");
            assert!(
                output
                    .contains("__builtin_memcpy((unsigned char *)&result + 0x0, &result_bits, 8);"),
                "{output}"
            );
            assert!(
                output.contains(
                    "__builtin_memcpy((unsigned char *)&result + 0x8, &result_bits_2, 8);"
                ),
                "{output}"
            );
            assert!(output.contains("return result;"), "{output}");
            assert!(!output.contains("also returns"), "{output}");
        }
    }

    #[test]
    fn wide_scalar_types_require_a_known_spelling_and_matching_layout() {
        let value = wide_result();
        for name in [
            "uint128_t",
            "u128",
            "i128",
            "unknown",
            "long double",
            "__float128",
        ] {
            assert!(logical_type(&CType::Named(name.to_owned()), &value, true).is_none());
            let mut ir = function(
                8,
                Expr::Apply {
                    op: Operation::Results,
                    args: vec![Expr::Const(1), Expr::Const(2)],
                },
            );
            let signature = ir.declared_signature.as_mut().unwrap();
            signature.ret = CType::Named(name.to_owned());
            signature.abi.as_mut().unwrap().result = Some(value.clone());
            assert!(prepare(&mut ir, &Symbols::default()).is_none());
            assert_eq!(ir.params[0].name, "a0");
            assert_eq!(ir.ret_type, CType::U64);
        }
        for name in ["__int128", "signed __int128", "__int128 signed"] {
            assert_eq!(
                logical_type(&CType::Named(name.to_owned()), &value, true),
                Some(CType::Named("__int128".to_owned()))
            );
        }
        let ty = CType::Named("unsigned __int128".to_owned());
        let mut malformed = value.clone();
        malformed.size = 8;
        assert!(logical_type(&ty, &malformed, true).is_none());
        malformed = value.clone();
        malformed.alignment = 8;
        assert!(logical_type(&ty, &malformed, true).is_none());
        malformed = value.clone();
        malformed.defined_bits = vec![(0, 64)];
        assert!(logical_type(&ty, &malformed, true).is_none());
        malformed = value.clone();
        if let Passing::Direct(pieces) = &mut malformed.passing {
            pieces[1].class = Some(RegisterClass::Simd);
        }
        assert!(logical_type(&ty, &malformed, true).is_none());
        let mut stack = value;
        stack.passing = Passing::Direct(vec![AbiPiece {
            location: AbiLocation::Stack(8),
            object_offset: 0,
            bytes: 16,
            class: None,
        }]);
        assert_eq!(logical_type(&ty, &stack, false), Some(ty.clone()));
        assert!(logical_type(&ty, &stack, true).is_none());
    }
}
