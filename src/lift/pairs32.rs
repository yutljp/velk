//! Scalar integer declarations whose values occupy two 32-bit words.

mod callers;
pub(crate) mod inference;

use crate::ir::{BinOp, CType, Expr, Stmt};
use crate::loader::{Image, Isa, NameSource};

pub(crate) const PARAMETER_BASE: u16 = crate::ir::TEMP_BASE + 0x60;

pub(crate) const TEMPORARIES: [u16; 4] = [
    crate::ir::TEMP_BASE + 0x50,
    crate::ir::TEMP_BASE + 0x51,
    crate::ir::TEMP_BASE + 0x52,
    crate::ir::TEMP_BASE + 0x53,
];

pub(crate) fn types(image: &Image, address: u64) -> Option<(Vec<CType>, CType)> {
    declared_types(image, address).or_else(|| inference::types(image, address))
}

pub(crate) fn definition_types(image: &Image, address: u64) -> Option<(Vec<CType>, CType)> {
    let Some(types) = types(image, address) else {
        return None;
    };
    if image
        .functions
        .get(&address)
        .is_some_and(|function| function.sources.contains(&NameSource::Plt))
        && !wide(&types.1)
    {
        return None;
    }
    Some(types)
}

fn declared_types(image: &Image, address: u64) -> Option<(Vec<CType>, CType)> {
    if !matches!(image.isa, Isa::I386 | Isa::Arm32) {
        return None;
    }
    if let Some(types) = crate::loader::dwarf::function_types(image, address) {
        if types.variadic || crate::analysis::abi::has_aggregate(&types) {
            return None;
        }
        let params: Option<Vec<CType>> = types.params.into_iter().map(|(_, ty)| ty).collect();
        let (Some(params), Some(ret)) = (params, types.ret) else {
            return None;
        };
        if params.iter().chain([&ret]).all(supported) {
            return Some((params, ret));
        }
        return None;
    }
    let Some(function) = image.functions.get(&address) else {
        return None;
    };
    let Some(name) = function.name.as_deref() else {
        return None;
    };
    let prototype = if function.sources.contains(&NameSource::Plt) {
        crate::analysis::prototypes::for_image(name, image)
            .or_else(|| crate::analysis::prototypes::runtime(name))
    } else {
        crate::analysis::prototypes::runtime(name)
    };
    if let Some(prototype) = prototype
        && !prototype.variadic
        && prototype
            .params
            .iter()
            .chain([&prototype.ret])
            .all(supported)
    {
        return Some((prototype.params.clone(), prototype.ret.clone()));
    }
    None
}

fn supported(ty: &CType) -> bool {
    ty.is_pointer() || *ty == CType::Void || ty.integer().is_some_and(|(bits, _)| bits <= 64)
}

pub(crate) fn wide(ty: &CType) -> bool {
    if let CType::Named(name) = ty {
        let name = name.trim();
        let longs = name
            .split_whitespace()
            .filter(|word| *word == "long")
            .count();
        return ty.integer().is_some_and(|(bits, _)| bits == 64)
            && (longs == 2
                || name.ends_with("64_t")
                || matches!(
                    name,
                    "i64" | "u64" | "intmax_t" | "uintmax_t" | "__int64" | "unsigned __int64"
                ));
    }
    ty.integer().is_some_and(|(bits, _)| bits == 64)
}

#[derive(Clone, Copy)]
pub(crate) enum Location {
    Register(u16),
    Stack(i64),
}

pub(crate) fn locations(isa: Isa, params: &[CType]) -> Option<Vec<(Location, bool)>> {
    let mut register = 0u16;
    let mut stack = if isa == Isa::I386 { 4i64 } else { 0 };
    let mut result = Vec::new();
    for ty in params {
        if !supported(ty) || *ty == CType::Void {
            return None;
        }
        let pair = wide(ty);
        if isa == Isa::Arm32 && pair {
            register = (register + 1) & !1;
        }
        let words = if pair { 2 } else { 1 };
        if isa == Isa::Arm32 && register < 4 {
            result.push((Location::Register(register), pair));
            register += words;
        } else {
            if isa == Isa::Arm32 && pair {
                let Some(aligned) = stack.checked_add(7) else {
                    return None;
                };
                stack = aligned & !7;
            }
            result.push((Location::Stack(stack), pair));
            let Some(next) = stack.checked_add(i64::from(words) * 4) else {
                return None;
            };
            stack = next;
        }
    }
    Some(result)
}

pub(crate) fn join(low: Expr, high: Expr) -> Expr {
    Expr::bin(
        BinOp::Or,
        super::arm32::low(low),
        Expr::bin(BinOp::Shl, super::arm32::low(high), Expr::constant(32)),
    )
}

pub(super) fn call(image: &Image, target: Option<u64>, stmt: &mut Stmt) -> bool {
    let Some(target) = target else { return false };
    // A local i386 function may use register arguments even when its source
    // declaration uses cdecl. Keep the physical arguments recovered from its body.
    if image.isa == Isa::I386
        && matches!(stmt, Stmt::Call { args: Some(args), .. }
            if args.iter().any(|arg| matches!(arg, Expr::Reg { .. })))
    {
        return false;
    }
    let inferred = types(image, target);
    let (params, ret) = match inferred {
        Some((params, ret)) => (params, Some(ret)),
        None => match inference::parameters(image, target) {
            Some(params) => (params, None),
            None => return false,
        },
    };
    let Some(locations) = locations(image.isa, &params) else {
        return false;
    };
    let Stmt::Call {
        kind,
        convention,
        args,
        ..
    } = stmt
    else {
        return false;
    };
    if !matches!(
        *convention,
        crate::ir::Convention::Cdecl | crate::ir::Convention::Aapcs32
    ) {
        return false;
    }
    let mut values = Vec::new();
    for (location, pair) in locations {
        let value = match location {
            Location::Register(register) => {
                if pair {
                    join(Expr::reg(register, 32), Expr::reg(register + 1, 32))
                } else {
                    Expr::reg(register, 32)
                }
            }
            Location::Stack(offset) => {
                let Some(offset) = kind.stack_offset(image.isa, *convention, offset) else {
                    return false;
                };
                if pair {
                    let Some(high) = offset.checked_add(4) else {
                        return false;
                    };
                    join(stack_word(image.isa, offset), stack_word(image.isa, high))
                } else {
                    stack_word(image.isa, offset)
                }
            }
        };
        values.push(value);
    }
    *args = Some(values);
    if ret.as_ref().is_some_and(wide) {
        logical_result(stmt, 64);
        return true;
    }
    false
}

fn stack_word(isa: Isa, offset: i64) -> Expr {
    Expr::Load {
        addr: Box::new(Expr::bin(
            BinOp::Add,
            Expr::reg(crate::arch::stack_pointer(isa), 64),
            Expr::constant(offset as u64),
        )),
        width: 4,
        signed: false,
    }
}

fn logical_result(stmt: &mut Stmt, width: u8) {
    let Stmt::Call {
        outputs, clobbers, ..
    } = stmt
    else {
        return;
    };
    // The logical result replaces the low register even if its physical word was preserved.
    if let Some(clobbers) = clobbers {
        clobbers.insert(0);
    }
    outputs.retain(|output| output.register == 0);
    if let Some(output) = outputs.first_mut() {
        output.dest.index = TEMPORARIES[3];
        output.dest.width = width;
    } else {
        outputs.push(crate::ir::CallOutput {
            register: 0,
            dest: crate::ir::RegRef {
                index: TEMPORARIES[3],
                width,
            },
        });
    }
}

pub(super) fn word_remainder(image: &Image, target: Option<u64>, stmt: &mut Stmt) -> bool {
    if image.isa != Isa::Arm32 {
        return false;
    }
    let name = target
        .and_then(|target| image.functions.get(&target))
        .and_then(|function| function.name.as_deref());
    if !matches!(name, Some("__aeabi_idivmod" | "__aeabi_uidivmod")) {
        return false;
    }
    logical_result(stmt, 32);
    true
}

pub(super) fn split_word_result() -> [Stmt; 2] {
    [
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 0,
                width: 64,
            },
            value: super::arm32::low(Expr::reg(TEMPORARIES[3], 64)),
            at: None,
        },
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 1,
                width: 64,
            },
            value: super::arm32::low(Expr::reg(TEMPORARIES[2], 64)),
            at: None,
        },
    ]
}

pub(super) fn split_result(isa: Isa) -> [Stmt; 2] {
    let high = if isa == Isa::I386 { 2 } else { 1 };
    [
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: high,
                width: 64,
            },
            value: Expr::bin(
                BinOp::Shr,
                Expr::reg(TEMPORARIES[3], 64),
                Expr::constant(32),
            ),
            at: None,
        },
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 0,
                width: 64,
            },
            value: super::arm32::low(Expr::reg(TEMPORARIES[3], 64)),
            at: None,
        },
    ]
}

pub(super) fn remainder_arguments(
    image: &Image,
    target: Option<u64>,
    stmt: &mut Stmt,
) -> Option<[Stmt; 2]> {
    let Some(target) = target else { return None };
    let Some(name) = image
        .functions
        .get(&target)
        .and_then(|function| function.name.as_deref())
    else {
        return None;
    };
    if !matches!(
        name,
        "__aeabi_ldivmod" | "__aeabi_uldivmod" | "__aeabi_idivmod" | "__aeabi_uidivmod"
    ) {
        return None;
    }
    let Stmt::Call {
        args: Some(args), ..
    } = stmt
    else {
        return None;
    };
    let [left, right] = args.as_mut_slice() else {
        return None;
    };
    let captures = [
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: TEMPORARIES[0],
                width: 64,
            },
            value: std::mem::replace(left, Expr::reg(TEMPORARIES[0], 64)),
            at: None,
        },
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: TEMPORARIES[1],
                width: 64,
            },
            value: std::mem::replace(right, Expr::reg(TEMPORARIES[1], 64)),
            at: None,
        },
    ];
    Some(captures)
}

pub(super) fn remainder_value() -> Stmt {
    Stmt::Assign {
        dest: crate::ir::RegRef {
            index: TEMPORARIES[2],
            width: 64,
        },
        value: Expr::bin(
            BinOp::Sub,
            Expr::reg(TEMPORARIES[0], 64),
            Expr::bin(
                BinOp::Mul,
                Expr::reg(TEMPORARIES[3], 64),
                Expr::reg(TEMPORARIES[1], 64),
            ),
        ),
        at: None,
    }
}

pub(super) fn split_remainder() -> [Stmt; 2] {
    [
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 2,
                width: 64,
            },
            value: super::arm32::low(Expr::reg(TEMPORARIES[2], 64)),
            at: None,
        },
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 3,
                width: 64,
            },
            value: Expr::bin(
                BinOp::Shr,
                Expr::reg(TEMPORARIES[2], 64),
                Expr::constant(32),
            ),
            at: None,
        },
    ]
}
