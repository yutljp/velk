//! Integer argument slots in direct and `va_list` calls.

use crate::ir::{CallKind, Convention};
use crate::loader::{Format, Isa};

use super::{Runner, Stop, address, error};

pub(super) struct Arguments {
    pub(super) index: usize,
    pub(super) convention: Convention,
    pub(super) kind: CallKind,
    list: Option<Variadic>,
}

enum Variadic {
    Linear { next: u64, slot: u8, alignment: u8 },
    SysV { offset: u32, stack: u64, saved: u64 },
    Aapcs64 { offset: i32, stack: u64, top: u64 },
}

fn load(runner: &Runner<'_>, location: u64, width: u8) -> Result<u64, Stop> {
    let value = runner.machine.load(location, width);
    match runner.memory_error() {
        Ok(()) => Ok(value),
        Err(stop) => Err(stop),
    }
}

impl Arguments {
    pub(super) fn new(convention: Convention, kind: CallKind) -> Self {
        Self {
            index: 0,
            convention,
            kind,
            list: None,
        }
    }

    // An invalid va_list prevents the entire hook from executing.
    pub(super) fn set_list(&mut self, runner: &Runner<'_>, base: u64) -> Result<(), Stop> {
        self.list = Some(match runner.image.isa {
            Isa::X86_64 if self.convention == Convention::SysV => {
                let offset = load(runner, base, 4)? as u32;
                if offset > 48 || !offset.is_multiple_of(8) {
                    return Err(error("invalid va_list general register offset"));
                }
                Variadic::SysV {
                    offset,
                    stack: load(runner, address(base, 8)?, 8)?,
                    saved: load(runner, address(base, 16)?, 8)?,
                }
            }
            Isa::AArch64 if runner.image.format == Format::Elf => {
                let offset = load(runner, address(base, 24)?, 4)? as u32 as i32;
                if !(-64..=0).contains(&offset) || offset % 8 != 0 {
                    return Err(error("invalid va_list general register offset"));
                }
                Variadic::Aapcs64 {
                    offset,
                    stack: load(runner, base, 8)?,
                    top: load(runner, address(base, 8)?, 8)?,
                }
            }
            Isa::X86_64 | Isa::AArch64 => Variadic::Linear {
                next: base,
                slot: 8,
                alignment: 8,
            },
            Isa::I386 => Variadic::Linear {
                next: base,
                slot: 4,
                alignment: 4,
            },
            Isa::Arm32 => Variadic::Linear {
                next: base,
                slot: 4,
                alignment: 8,
            },
            Isa::Unsupported => return Err(error("unsupported va_list architecture")),
        });
        Ok(())
    }

    // An unavailable argument aborts the entire hook; no guessed values are used.
    pub(super) fn next(&mut self, runner: &Runner<'_>, width: u8) -> Result<u64, Stop> {
        if let Some(list) = &mut self.list {
            let location = match list {
                Variadic::Linear {
                    next,
                    slot,
                    alignment,
                } => {
                    let align = u64::from(width.min(*alignment).max(*slot));
                    let Some(location) =
                        next.checked_add(align - 1).map(|next| next & !(align - 1))
                    else {
                        return Err(error("va_list alignment overflows"));
                    };
                    *next = match location.checked_add(u64::from(width.max(*slot))) {
                        Some(next) => next,
                        None => return Err(error("va_list address overflows")),
                    };
                    location
                }
                Variadic::SysV { offset, saved, .. } if *offset < 48 => {
                    let location = address(*saved, *offset as usize)?;
                    *offset += 8;
                    location
                }
                Variadic::Aapcs64 { offset, top, .. } if *offset < 0 => {
                    let Some(location) = top.checked_add_signed(i64::from(*offset)) else {
                        return Err(error("va_list register address overflows"));
                    };
                    *offset += 8;
                    location
                }
                Variadic::SysV { stack, .. } | Variadic::Aapcs64 { stack, .. } => {
                    let Some(location) = stack.checked_add(7).map(|stack| stack & !7) else {
                        return Err(error("va_list stack alignment overflows"));
                    };
                    *stack = match location.checked_add(8) {
                        Some(next) => next,
                        None => return Err(error("va_list stack address overflows")),
                    };
                    location
                }
            };
            return load(runner, location, width);
        }
        let pointer_bytes = crate::arch::pointer_bytes(runner.image.isa);
        if width == 8 && pointer_bytes == 4 && runner.image.isa == Isa::Arm32 {
            self.index = (self.index + 1) & !1;
        }
        let value = match runner.argument(self.index, self.convention, self.kind) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        self.index += 1;
        if width == 8 && pointer_bytes == 4 {
            let high = match runner.argument(self.index, self.convention, self.kind) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            self.index += 1;
            return Ok((value as u32 as u64) | (high << 32));
        }
        Ok(value)
    }
}
