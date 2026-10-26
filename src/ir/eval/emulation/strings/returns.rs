//! Checks the actual return destination before accepting an execution result.

use crate::ir::Expr;
use crate::loader::{ArmMode, Isa};

use super::super::{Runner, Stop};

pub(super) struct ReturnAddress {
    stack: u64,
    target: u64,
}

impl Runner<'_> {
    pub(in super::super) fn recovery_control_store(&mut self, address: u64, width: u8) {
        if let Some(recovery) = &mut self.recovery {
            for offset in 0..u64::from(width) {
                if let Some(at) = address.checked_add(offset) {
                    recovery.memory.remove(&at);
                }
            }
        }
    }

    pub(in super::super) fn recovery_entry(&mut self, depth: usize) -> Result<(), Stop> {
        if self.recovery.is_none() {
            return Ok(());
        }
        let width = crate::arch::pointer_bytes(self.image.isa);
        let stack = match self.eval(&Expr::reg(
            crate::arch::stack_pointer(self.image.isa),
            width * 8,
        )) {
            Ok(stack) => stack,
            Err(stop) => return Err(stop),
        };
        let target = if matches!(self.image.isa, Isa::X86_64 | Isa::I386) {
            match self.recovery_load(stack, width, false) {
                Ok(fact) => fact.singleton(),
                Err(stop) => return Err(stop),
            }
        } else {
            self.register_fact(if self.image.isa == Isa::Arm32 { 14 } else { 30 }, 64)
                .ok()
                .and_then(|fact| fact.singleton())
        };
        let Some(target) = target else {
            return Err(Stop::Error("unknown return address".to_owned()));
        };
        self.recovery
            .as_mut()
            .expect("automatic execution state")
            .returns
            .insert(depth, ReturnAddress { stack, target });
        Ok(())
    }

    pub(in super::super) fn check_recovery_return(&self, depth: usize) -> Result<(), Stop> {
        let Some(recovery) = &self.recovery else {
            return Ok(());
        };
        let Some(expected) = recovery.returns.get(&depth) else {
            return Err(Stop::Error("missing return address".to_owned()));
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        let stack = match self.eval(&Expr::reg(
            crate::arch::stack_pointer(self.image.isa),
            width * 8,
        )) {
            Ok(stack) => stack,
            Err(stop) => return Err(stop),
        };
        let actual = match self.image.isa {
            Isa::X86_64 | Isa::I386 if stack == expected.stack => self
                .recovery_load(stack, width, false)
                .ok()
                .and_then(|fact| fact.singleton()),
            Isa::AArch64 => {
                let Some(bytes) = self.image.read_vaddr(self.address, 4) else {
                    return Err(Stop::Error("missing return instruction".to_owned()));
                };
                let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if word & 0xffff_fc1f != 0xd65f_0000 {
                    return Err(Stop::Error("unsupported return authentication".to_owned()));
                }
                self.register_fact(((word >> 5) & 31) as u16, 64)
                    .ok()
                    .and_then(|fact| fact.singleton())
            }
            Isa::Arm32 => self.arm_return_target(stack),
            _ => None,
        };
        if actual != Some(expected.target) {
            return Err(Stop::Error("changed or unknown return address".to_owned()));
        }
        Ok(())
    }

    fn arm_return_target(&self, stack: u64) -> Option<u64> {
        let Some(bytes) = self.image.read_vaddr(self.address, 4) else {
            return None;
        };
        let half = u16::from_le_bytes([bytes[0], bytes[1]]);
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let load = |address| {
            self.recovery_load(address, 4, false)
                .ok()
                .and_then(|fact| fact.singleton())
        };
        let link = || {
            self.register_fact(14, 32)
                .ok()
                .and_then(|fact| fact.singleton())
        };
        match self.image.arm_mode(self.address) {
            ArmMode::Arm => {
                if word & 0x0fff_ffff == 0x012f_ff1e || word & 0x0fff_ffff == 0x01a0_f00e {
                    return link();
                }
                if word & 0x0fff_ffff == 0x049d_f004 {
                    return stack.checked_sub(4).and_then(load);
                }
                if word & 0x0e1f_8000 == 0x081d_8000 {
                    let count = u64::from((word & 0xffff).count_ones()) * 4;
                    let add = word & (1 << 23) != 0;
                    let pre = word & (1 << 24) != 0;
                    let old_stack = if word & (1 << 21) == 0 {
                        stack
                    } else if add {
                        match stack.checked_sub(count) {
                            Some(value) => value,
                            None => return None,
                        }
                    } else {
                        match stack.checked_add(count) {
                            Some(value) => value,
                            None => return None,
                        }
                    };
                    let offset = if add {
                        count as i64 - if pre { 0 } else { 4 }
                    } else if pre {
                        -4
                    } else {
                        0
                    };
                    return old_stack.checked_add_signed(offset).and_then(load);
                }
                None
            }
            ArmMode::Thumb => {
                if half == 0x4770 || half == 0x46f7 {
                    return link();
                }
                if half & 0xff00 == 0xbd00 || (half == 0xe8bd && word & 0x8000_0000 != 0) {
                    return stack.checked_sub(4).and_then(load);
                }
                None
            }
            ArmMode::Data => None,
        }
    }
}
