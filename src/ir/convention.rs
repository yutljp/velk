use super::{Expr, Registers};

/// The integer calling convention a call follows: which registers carry
/// its arguments and which it may overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Convention {
    Aapcs64,
    SysV,
    Win64,
    /// Go's internal register ABI on x86-64.
    GoAmd64,
    /// A Linux system call on x86-64: the number in rax, then the
    /// arguments; it overwrites rax, rcx and r11.
    SyscallX86,
    /// A Linux system call on AArch64: the number in x8, then the
    /// arguments; it overwrites x0.
    SyscallArm,
    /// Go's write barrier on x86-64: it takes nothing, keeps every other
    /// register, and returns in r11 where to record the pointers about to
    /// be written.
    GoWriteBarrier,
    /// Go's assembly ABI on x86-64: arguments and results on the stack.
    GoAbi0,
}

impl Convention {
    pub fn of(isa: crate::loader::Isa, format: crate::loader::Format, go: bool) -> Self {
        use crate::loader::{Format, Isa};
        match isa {
            Isa::AArch64 => Self::Aapcs64,
            _ if go => Self::GoAmd64,
            _ if matches!(format, Format::Pe | Format::Coff) => Self::Win64,
            _ => Self::SysV,
        }
    }

    /// Integer argument registers, in order.
    pub fn arguments(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[0, 1, 2, 3, 4, 5, 6, 7],
            Self::SysV => &[7, 6, 2, 1, 8, 9],
            Self::Win64 => &[1, 2, 8, 9],
            // rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11.
            Self::GoAmd64 => &[0, 3, 1, 7, 6, 8, 9, 10, 11],
            Self::SyscallX86 => &[0, 7, 6, 2, 10, 8, 9],
            Self::SyscallArm => &[8, 0, 1, 2, 3, 4, 5],
            Self::GoWriteBarrier | Self::GoAbi0 => &[],
        }
    }

    /// Where the arguments past the registers start, from the stack pointer
    /// on entry: past the return address on x86-64, and past the space
    /// Windows reserves for the register ones.
    pub fn stack_arguments(self) -> Option<i64> {
        match self {
            Self::SysV => Some(8),
            Self::Win64 => Some(40),
            Self::Aapcs64 => Some(0),
            Self::GoAbi0 | Self::GoAmd64 => Some(8),
            Self::SyscallX86 | Self::SyscallArm | Self::GoWriteBarrier => None,
        }
    }

    /// Bytes a call pushes before the callee runs: the return address.
    pub fn pushed_by_call(self) -> i64 {
        match self {
            Self::Aapcs64 | Self::SyscallX86 | Self::SyscallArm => 0,
            Self::SysV | Self::Win64 | Self::GoAmd64 | Self::GoWriteBarrier | Self::GoAbi0 => 8,
        }
    }

    /// Floating-point argument registers, in order: the low halves of xmm0
    /// to xmm7 (xmm3 on Windows, xmm14 in Go's ABI), or of v0 to v7.
    pub fn float_arguments(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[32, 34, 36, 38, 40, 42, 44, 46],
            Self::SysV => &[18, 20, 22, 24, 26, 28, 30, 32],
            Self::Win64 => &[18, 20, 22, 24],
            Self::GoAmd64 => &[18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46],
            Self::SyscallX86 | Self::SyscallArm | Self::GoWriteBarrier | Self::GoAbi0 => &[],
        }
    }

    /// Registers a call may read: its arguments, the floating-point ones,
    /// and the ones in `call_extra`.
    pub fn call_reads(self) -> impl Iterator<Item = u16> {
        self.arguments()
            .iter()
            .chain(self.float_arguments())
            .chain(self.call_extra())
            .copied()
    }

    /// The registers a call of unknown arguments through `through` may read.
    /// One holding the address called is no vector count: a variadic call
    /// sets al after choosing another register for the address.
    /// With `floats_named`, the floating-point arguments are named apart.
    pub fn call_reads_through(self, through: Option<&Expr>, floats_named: bool) -> Vec<u16> {
        let mut addressing = std::collections::HashSet::new();
        if let Some(through) = through {
            crate::ir::visit::collect_reads(through, &mut addressing);
        }
        let floats: &[u16] = if floats_named {
            &[]
        } else {
            self.float_arguments()
        };
        self.arguments()
            .iter()
            .chain(floats)
            .copied()
            .chain(
                self.call_extra()
                    .iter()
                    .copied()
                    .filter(|register| !addressing.contains(register)),
            )
            .collect()
    }

    /// Registers a call whose integer arguments are named still reads: the
    /// floating-point arguments and AArch64's indirect result register.
    /// SysV's vector count in al is left out: only a variadic callee reads
    /// it, and the pseudo-C leaves its setting out. With `floats_named`, the
    /// floating-point arguments are named too.
    pub fn unnamed_reads(self, floats_named: bool) -> Vec<u16> {
        let extra: &[u16] = match self {
            Self::SysV => &[],
            other => other.call_extra(),
        };
        let floats: &[u16] = if floats_named {
            &[]
        } else {
            self.float_arguments()
        };
        floats.iter().chain(extra).copied().collect()
    }

    /// Registers a call may read besides its arguments: AArch64's indirect
    /// result register and the vector count a variadic SysV call takes in al.
    pub fn call_extra(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[8],
            Self::SysV => &[0],
            Self::Win64
            | Self::GoAmd64
            | Self::SyscallX86
            | Self::SyscallArm
            | Self::GoWriteBarrier
            | Self::GoAbi0 => &[],
        }
    }

    /// Registers a call returns values in, integer and floating-point: the
    /// first, and those that carry a second half or further results. A
    /// call into Go's assembly ABI returns on the stack; the lifter moves
    /// its results there from the registers Go's register ABI returns
    /// integers in, which the call leaves changed.
    pub fn results(self) -> &'static [u16] {
        match self {
            Self::SysV => &[0, 2, 18, 20],
            Self::Win64 => &[0, 18],
            Self::Aapcs64 => &[0, 1, 32, 34],
            Self::GoAmd64 => &[0, 3, 1, 7, 6, 8, 9, 10, 11, 18, 20, 22, 24],
            Self::SyscallX86 | Self::SyscallArm => &[0],
            Self::GoWriteBarrier => &[11],
            Self::GoAbi0 => &[0, 3, 1, 7, 6, 8, 9, 10, 11],
        }
    }

    /// Registers a call may leave changed: those the callee's summary
    /// names, when it knows them, or else those the convention lets it.
    pub fn clobbered_by(self, known: Option<Registers>) -> Vec<u16> {
        match known {
            Some(known) => known.iter().collect(),
            None => self.clobbered().to_vec(),
        }
    }

    /// Registers the convention keeps whatever the callee does: the stack
    /// pointer, and under Go's register ABI the goroutine in r14 and the
    /// zero in xmm15.
    pub fn fixed(self) -> &'static [u16] {
        match self {
            Self::GoAmd64 => &[4, 14, 48, 49],
            Self::Aapcs64 | Self::SyscallArm => &[31],
            Self::SysV | Self::Win64 | Self::SyscallX86 | Self::GoWriteBarrier | Self::GoAbi0 => {
                &[4]
            }
        }
    }

    /// Registers a call may leave changed.
    pub fn clobbered(self) -> &'static [u16] {
        match self {
            // And the link register x30, v0 to v7 and v16 to v31, and the
            // high halves of v8 to v15.
            Self::Aapcs64 => &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30, 32, 33, 34,
                35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 49, 51, 53, 55, 57, 59, 61, 63,
                64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
                85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
            ],
            // And every xmm and ymm register.
            Self::SysV => &[
                0, 1, 2, 6, 7, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
                73, 74, 75, 76, 77, 78, 79, 80, 81,
            ],
            // And xmm0 to xmm5, and the upper halves of every ymm register.
            Self::Win64 => &[
                0, 1, 2, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
                74, 75, 76, 77, 78, 79, 80, 81,
            ],
            // Everything but rsp, rbp, r14 (the goroutine), r15 and xmm15,
            // which stays zero.
            Self::GoAmd64 | Self::GoAbi0 => &[
                0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 50, 51,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
                73, 74, 75, 76, 77, 78, 79, 80, 81,
            ],
            Self::SyscallX86 => &[0, 1, 11],
            Self::SyscallArm => &[0],
            Self::GoWriteBarrier => &[11],
        }
    }
}

/// How control reaches a callee, which decides what the transfer pushes
/// on the stack before the callee's first instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// A call that returns here.
    Invoke,
    /// A jump to the callee in place of this function's return: the callee
    /// finds the stack as this function found it.
    Tail,
    /// A system call, which takes nothing on the stack.
    Syscall,
}

impl CallKind {
    /// Bytes the transfer pushes before the callee runs; None when the kind
    /// does not go with the ISA and convention.
    pub fn push_bytes(self, isa: crate::loader::Isa, convention: Convention) -> Option<i64> {
        use crate::loader::Isa;
        let syscall = match (isa, convention) {
            (Isa::AArch64, Convention::Aapcs64) => false,
            (
                Isa::X86_64,
                Convention::SysV
                | Convention::Win64
                | Convention::GoAmd64
                | Convention::GoWriteBarrier
                | Convention::GoAbi0,
            ) => false,
            (Isa::AArch64, Convention::SyscallArm) | (Isa::X86_64, Convention::SyscallX86) => true,
            _ => return None,
        };
        match (self, syscall) {
            (Self::Invoke, false) => Some(convention.pushed_by_call()),
            (Self::Tail, false) | (Self::Syscall, true) => Some(0),
            _ => None,
        }
    }

    /// Where the stack slot the callee finds at `callee_offset` from its
    /// entry stack pointer lies from the stack pointer at the transfer;
    /// None for a system call, a kind that does not fit, or an overflow.
    pub fn stack_offset(
        self,
        isa: crate::loader::Isa,
        convention: Convention,
        callee_offset: i64,
    ) -> Option<i64> {
        if self == Self::Syscall {
            return None;
        }
        let Some(pushed) = self.push_bytes(isa, convention) else {
            return None;
        };
        callee_offset.checked_sub(pushed)
    }
}

#[cfg(test)]
mod tests {
    use super::{CallKind, Convention};
    use crate::loader::Isa;

    #[test]
    fn call_stack_coordinates_distinguish_invoke_tail_and_syscall() {
        for (isa, convention, entry, invoke) in [
            (Isa::X86_64, Convention::SysV, 8, 0),
            (Isa::X86_64, Convention::Win64, 40, 32),
            (Isa::X86_64, Convention::GoAbi0, 8, 0),
            (Isa::AArch64, Convention::Aapcs64, 0, 0),
        ] {
            assert_eq!(
                CallKind::Invoke.stack_offset(isa, convention, entry),
                Some(invoke)
            );
            assert_eq!(
                CallKind::Tail.stack_offset(isa, convention, entry),
                Some(entry)
            );
            assert_eq!(CallKind::Tail.push_bytes(isa, convention), Some(0));
        }
        for (isa, convention) in [
            (Isa::X86_64, Convention::SyscallX86),
            (Isa::AArch64, Convention::SyscallArm),
        ] {
            assert_eq!(CallKind::Syscall.push_bytes(isa, convention), Some(0));
            assert_eq!(CallKind::Syscall.stack_offset(isa, convention, 0), None);
            assert_eq!(CallKind::Invoke.push_bytes(isa, convention), None);
            assert_eq!(CallKind::Tail.push_bytes(isa, convention), None);
        }
    }

    #[test]
    fn call_stack_coordinates_refuse_a_mismatch_and_an_overflow() {
        for convention in [
            Convention::SysV,
            Convention::Win64,
            Convention::GoAmd64,
            Convention::GoAbi0,
            Convention::GoWriteBarrier,
        ] {
            assert_eq!(CallKind::Invoke.push_bytes(Isa::AArch64, convention), None);
        }
        for (kind, isa, convention) in [
            (CallKind::Invoke, Isa::X86_64, Convention::Aapcs64),
            (CallKind::Syscall, Isa::X86_64, Convention::SyscallArm),
            (CallKind::Syscall, Isa::AArch64, Convention::SyscallX86),
            (CallKind::Invoke, Isa::Unsupported, Convention::SysV),
            (CallKind::Syscall, Isa::X86_64, Convention::SysV),
        ] {
            assert_eq!(kind.push_bytes(isa, convention), None);
        }
        assert_eq!(
            CallKind::Invoke.stack_offset(Isa::X86_64, Convention::SysV, i64::MIN),
            None
        );
        assert_eq!(
            CallKind::Tail.stack_offset(Isa::X86_64, Convention::SysV, i64::MIN),
            Some(i64::MIN)
        );
    }
}
