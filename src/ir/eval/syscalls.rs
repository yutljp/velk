//! Linux system calls with deterministic standard stream models.

use crate::ir::Convention;

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Read,
    Write,
    Exit,
}

pub(super) fn operation(convention: Convention, number: u64) -> Option<Operation> {
    use Operation::*;
    match (convention, number) {
        (Convention::SyscallX86, 0)
        | (Convention::SyscallI386, 3)
        | (Convention::SyscallArm, 63) => Some(Read),
        (Convention::SyscallX86, 1)
        | (Convention::SyscallI386, 4)
        | (Convention::SyscallArm, 64) => Some(Write),
        (Convention::SyscallX86, 60 | 231)
        | (Convention::SyscallI386, 1 | 252)
        | (Convention::SyscallArm, 93 | 94) => Some(Exit),
        _ => None,
    }
}
