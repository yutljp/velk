//! Instruction locations for strict execution, without changing block boundaries.

use super::{Block, Expr, Machine, RegRef, Stmt, flags};

pub(crate) const DIRECTION: u16 = super::x86_64::DIRECTION;

pub(crate) const ADDRESS: u16 = u16::MAX;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Analysis,
    Execution,
}

pub(super) struct Located<M> {
    inner: M,
    mode: Mode,
    pending: Vec<Stmt>,
    address: u64,
}

impl<M: Machine> Located<M> {
    pub(super) fn new(inner: M, mode: Mode) -> Self {
        Self {
            inner,
            mode,
            pending: Vec::new(),
            address: 0,
        }
    }
}

fn marker(address: u64) -> Stmt {
    Stmt::Assign {
        dest: RegRef {
            index: ADDRESS,
            width: 64,
        },
        value: Expr::Const(address),
    }
}

impl<M: Machine> Machine for Located<M> {
    type Instruction = M::Instruction;

    fn branch_target(&self, instruction: &Self::Instruction, pc: u64) -> Option<u64> {
        self.inner.branch_target(instruction, pc)
    }

    fn step(&mut self, instruction: &Self::Instruction, pc: u64) -> bool {
        if self.mode == Mode::Analysis {
            return self.inner.step(instruction, pc);
        }
        self.pending.extend(self.inner.take_statements());
        self.pending.push(marker(pc));
        self.address = pc;
        let ends = self.inner.step(instruction, pc);
        self.pending.extend(self.inner.take_statements());
        ends
    }

    fn take_statements(&mut self) -> Vec<Stmt> {
        if self.mode == Mode::Analysis {
            return self.inner.take_statements();
        }
        self.pending.extend(self.inner.take_statements());
        std::mem::take(&mut self.pending)
    }

    fn block_ended(&mut self) {
        self.inner.block_ended();
    }
    fn block_split(&mut self) {
        self.inner.block_split();
    }
    fn exit_flags(&self) -> Option<flags::Flags> {
        self.inner.exit_flags()
    }
    fn flags_touched(&self) -> bool {
        self.inner.flags_touched()
    }
    fn enter_block(&mut self, flags: Option<flags::Flags>) {
        self.inner.enter_block(flags);
    }

    fn take_extra_blocks(&mut self) -> Vec<Block> {
        let mut blocks = self.inner.take_extra_blocks();
        if self.mode == Mode::Execution {
            for block in &mut blocks {
                block.stmts.insert(0, marker(self.address));
            }
        }
        blocks
    }
}
