//! An interpreter for checking that optimization passes preserve a function's
//! behavior. Values the function did not produce (registers it reads before
//! writing, memory it never stored) come from a seeded hash, so two runs with
//! the same seed see the same inputs.
//!
//! Signed operations act at their operands' width, so a signed division or
//! comparison of two 32-bit registers behaves as a 32-bit instruction does.

use std::collections::{BTreeMap, HashMap};

pub(crate) mod emulation;
mod stdio;
pub(crate) mod symbolic;
mod syscalls;

use super::semantics::{holds, mask, operand_width, sign_extend};
use super::{Block, Expr, FunctionIr, RegRef, Stmt};

pub const STACK_TOP: u64 = 0x7fff_ff00_0000;
pub(crate) const STACK_SPAN: u64 = 1 << 24;

/// The initial stack address, within the architecture's address space.
#[must_use]
pub fn stack_top(isa: crate::loader::Isa) -> u64 {
    if crate::arch::pointer_bytes(isa) == 4 {
        0x7f00_0000
    } else {
        STACK_TOP
    }
}

/// The registers a call reads its arguments from and the ones it may overwrite.
pub struct Convention<'a> {
    pub arguments: &'a [u16],
    pub clobbered: &'a [u16],
}

pub struct Setup<'a> {
    pub seed: u64,
    pub convention: Convention<'a>,
    /// Initial register values; any other register reads a hashed value.
    pub registers: &'a [(u16, u64)],
    /// Initial little-endian 64-bit words; other memory reads hashed bytes.
    pub memory: &'a [(u64, u64)],
    pub step_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub target: Option<u64>,
    pub arguments: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Return {
        value: u64,
        calls: Vec<Call>,
        /// Final bytes at every address outside the stack the function wrote.
        memory: BTreeMap<u64, u8>,
    },
    Trap {
        calls: Vec<Call>,
        memory: BTreeMap<u64, u8>,
    },
    /// The run left what the interpreter can model.
    Unknown(&'static str),
}

enum Flow {
    Block(usize),
    Return(u64),
}

struct Machine<'a> {
    strict_memory: Option<crate::emulation::Memory<'a>>,
    source: Option<&'a MachineSource<'a>>,
    isa: crate::loader::Isa,
    convention: &'a Convention<'a>,
    seed: u64,
    registers: HashMap<u16, u64>,
    memory: HashMap<u64, u8>,
    calls: Vec<Call>,
    blocks: &'a [Block],
    block_indices_by_address: HashMap<u64, usize>,
}

/// Supplies raw instruction outputs in their declared order. For `WriteFlags`,
/// return the effective flags after privilege and reserved-bit restrictions.
pub type MachineSource<'a> =
    dyn Fn(super::MachineInstruction, &[u64]) -> Result<Vec<u64>, &'static str> + 'a;

#[must_use]
pub fn run(ir: &FunctionIr, setup: &Setup<'_>) -> Outcome {
    run_with_machine(ir, setup, &|_, _| Err("machine state unavailable"))
}

pub fn run_with_machine(ir: &FunctionIr, setup: &Setup<'_>, source: &MachineSource<'_>) -> Outcome {
    let mut machine = Machine::new(ir, setup);
    machine.source = Some(source);
    match machine.execute(setup.step_limit) {
        Ok(Some(value)) => Outcome::Return {
            value,
            calls: machine.calls,
            memory: memory_outside_stack(&machine.memory, ir.isa),
        },
        Ok(None) => Outcome::Trap {
            calls: machine.calls,
            memory: memory_outside_stack(&machine.memory, ir.isa),
        },
        Err(reason) => Outcome::Unknown(reason),
    }
}

/// The registers after running `ir` to a return or a trap, for comparing
/// lifted code with the processor running it.
pub fn registers_after(
    ir: &FunctionIr,
    setup: &Setup<'_>,
) -> Result<HashMap<u16, u64>, &'static str> {
    Ok(state_after(ir, setup)?.0)
}

/// Registers by index and memory by address.
pub type State = (HashMap<u16, u64>, HashMap<u64, u8>);

/// The registers and every byte of memory the run wrote, or that the setup
/// gave, after running `ir`.
pub fn state_after(ir: &FunctionIr, setup: &Setup<'_>) -> Result<State, &'static str> {
    state_after_with_machine(ir, setup, &|_, _| Err("machine state unavailable"))
}

pub fn state_after_with_machine(
    ir: &FunctionIr,
    setup: &Setup<'_>,
    source: &MachineSource<'_>,
) -> Result<State, &'static str> {
    let mut machine = Machine::new(ir, setup);
    machine.source = Some(source);
    if let Err(reason) = machine.execute(setup.step_limit) {
        return Err(reason);
    }
    Ok((machine.registers, machine.memory))
}

impl<'a> Machine<'a> {
    fn new(ir: &'a FunctionIr, setup: &'a Setup<'a>) -> Self {
        let mut machine = Machine {
            strict_memory: None,
            source: None,
            isa: ir.isa,
            convention: &setup.convention,
            seed: setup.seed,
            registers: setup.registers.iter().copied().collect(),
            memory: HashMap::new(),
            calls: Vec::new(),
            blocks: &ir.blocks,
            block_indices_by_address: ir
                .blocks
                .iter()
                .enumerate()
                .map(|(index, block)| (block.start, index))
                .collect(),
        };
        for param in &ir.params {
            if let Some(register) = super::trials::register_pair(ir, param)
                && !machine.registers.contains_key(&param.index)
            {
                let value = super::trials::pair_input(register, setup.registers, setup.seed);
                machine.registers.insert(param.index, value);
            }
        }
        machine
            .registers
            .insert(crate::arch::stack_pointer(ir.isa), stack_top(ir.isa));
        for (addr, value) in setup.memory {
            machine.store(*addr, *value, 8);
        }
        machine
    }
}

fn memory_outside_stack(memory: &HashMap<u64, u8>, isa: crate::loader::Isa) -> BTreeMap<u64, u8> {
    let top = stack_top(isa);
    memory
        .iter()
        .filter(|(addr, _)| !(top - STACK_SPAN..top + STACK_SPAN).contains(*addr))
        .map(|(addr, byte)| (*addr, *byte))
        .collect()
}

/// The NaN an x86 SSE operation gives, where the processor running the
/// tests would give its own: the first NaN operand made quiet, or with none
/// the negative quiet NaN x86 calls indefinite.
fn x86_nan(op: super::Operation, args: &[u64], result: u64) -> u64 {
    use super::{Operation, Precision};
    let (Operation::FloatAdd(precision)
    | Operation::FloatSub(precision)
    | Operation::FloatMul(precision)
    | Operation::FloatDiv(precision)
    | Operation::FloatSqrt(precision)
    | Operation::FloatMulAdd(precision)) = op
    else {
        return result;
    };
    let (nan, quiet, indefinite) = match precision {
        Precision::Double => (
            (|bits: u64| f64::from_bits(bits).is_nan()) as fn(u64) -> bool,
            1u64 << 51,
            0xfff8_0000_0000_0000,
        ),
        Precision::Single => (
            (|bits: u64| f32::from_bits(bits as u32).is_nan()) as fn(u64) -> bool,
            1 << 22,
            0xffc0_0000,
        ),
    };
    if !nan(result) {
        return result;
    }
    let low = |bits: u64| match precision {
        Precision::Double => bits,
        Precision::Single => bits & 0xffff_ffff,
    };
    match args.iter().find(|arg| nan(**arg)) {
        Some(first) => low(*first) | quiet,
        None => indefinite,
    }
}

/// A well-mixed 64-bit value derived from the seed and `key`.
#[must_use]
pub fn hash(seed: u64, key: u64) -> u64 {
    let mut value = seed ^ key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

impl Machine<'_> {
    fn register(&self, index: u16) -> u64 {
        let value = self
            .registers
            .get(&index)
            .copied()
            .unwrap_or_else(|| hash(self.seed, 0x1_0000 + u64::from(index)));
        if (self.isa == crate::loader::Isa::Arm32 && index < 16)
            || (self.isa == crate::loader::Isa::I386 && index < 8)
        {
            value & 0xffff_ffff
        } else {
            value
        }
    }

    fn byte(&self, addr: u64) -> u8 {
        self.memory
            .get(&addr)
            .copied()
            .unwrap_or_else(|| match &self.strict_memory {
                Some(memory) => memory.byte(addr),
                None => hash(self.seed, addr) as u8,
            })
    }

    fn load(&self, addr: u64, bytes: u8) -> u64 {
        if let Some(memory) = &self.strict_memory
            && !memory.check(addr, u64::from(bytes), /* write */ false)
        {
            return 0;
        }
        (0..u64::from(bytes)).fold(0, |value, offset| {
            value | (u64::from(self.byte(addr.wrapping_add(offset))) << (8 * offset))
        })
    }

    fn store(&mut self, addr: u64, value: u64, bytes: u8) {
        if let Some(memory) = &self.strict_memory
            && !memory.check(addr, u64::from(bytes), /* write */ true)
        {
            return;
        }
        for offset in 0..u64::from(bytes) {
            self.memory
                .insert(addr.wrapping_add(offset), (value >> (8 * offset)) as u8);
        }
    }

    fn eval(&self, expr: &Expr) -> Result<u64, &'static str> {
        self.eval_resolved(expr, &[])
    }

    fn eval_resolved(&self, expr: &Expr, resolved: &[(&Expr, u64)]) -> Result<u64, &'static str> {
        for (operand, value) in resolved {
            if std::ptr::eq(*operand, expr) {
                return Ok(*value);
            }
        }
        Ok(match expr {
            Expr::Apply { op, args } => {
                let mut values = Vec::new();
                for arg in args {
                    match self.eval_resolved(arg, resolved) {
                        Ok(value) => values.push(value),
                        Err(reason) => return Err(reason),
                    }
                }
                if self.strict_memory.is_some() && *op == super::Operation::Undefined {
                    return Err("undefined operation result");
                }
                if super::semantics::faults(*op, &values) {
                    return Err("division by zero");
                }
                let result = super::semantics::apply(*op, &values);
                if self.isa == crate::loader::Isa::X86_64 {
                    x86_nan(*op, &values, result)
                } else {
                    result
                }
            }
            Expr::Reg { index, width } => {
                if self.strict_memory.is_some() && !self.registers.contains_key(index) {
                    return Err("read of an undefined register");
                }
                self.register(*index) & mask(u32::from(*width))
            }
            Expr::Const(value) => *value,
            Expr::Load {
                addr,
                width,
                signed,
            } => {
                let value = self.load(
                    match self.eval_resolved(addr, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    },
                    *width,
                );
                if *signed {
                    sign_extend(value, u32::from(*width) * 8) as u64
                } else {
                    value
                }
            }
            Expr::SignExtend { value, width } => sign_extend(
                match self.eval_resolved(value, resolved) {
                    Ok(value) => value,
                    Err(reason) => return Err(reason),
                },
                u32::from(*width) * 8,
            ) as u64,
            Expr::Select {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => {
                let bits = operand_width(lhs, rhs);
                if holds(
                    *cond,
                    match self.eval_resolved(lhs, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    },
                    match self.eval_resolved(rhs, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    },
                    bits,
                ) {
                    match self.eval_resolved(then, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    }
                } else {
                    match self.eval_resolved(els, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    }
                }
            }
            Expr::Bin { op, lhs, rhs } => {
                let (a, b) = (
                    match self.eval_resolved(lhs, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    },
                    match self.eval_resolved(rhs, resolved) {
                        Ok(value) => value,
                        Err(reason) => return Err(reason),
                    },
                );
                let bits = operand_width(lhs, rhs);
                match super::semantics::scalar(*op, a, b, bits) {
                    Some(value) => value,
                    None => return Err("division by zero"),
                }
            }
        })
    }

    fn assign(&mut self, dest: RegRef, value: u64) {
        self.registers
            .insert(dest.index, value & mask(u32::from(dest.width)));
    }

    /// A branch to a block, or out of the function: a tail call that returns its callee's result.
    fn jump(&mut self, target: u64) -> Flow {
        match self.block_indices_by_address.get(&target) {
            Some(index) => Flow::Block(*index),
            None => {
                self.call(Some(target));
                Flow::Return(self.register(crate::arch::RETURN))
            }
        }
    }

    /// A call the code leaves by, passing what the convention passes; it
    /// changes what the convention lets it.
    fn call(&mut self, target: Option<u64>) {
        let target = target.map(|target| crate::arch::code_address(self.isa, target));
        let arguments = self
            .convention
            .arguments
            .iter()
            .map(|index| self.register(*index))
            .collect();
        self.calls.push(Call { target, arguments });
        let ordinal = self.calls.len() as u64;
        for index in self.convention.clobbered {
            self.registers.insert(
                *index,
                hash(self.seed ^ ordinal, 0x2_0000 + u64::from(*index)),
            );
        }
    }

    /// Executes from the entry block; `Ok(None)` is a trap.
    fn execute(&mut self, step_limit: usize) -> Result<Option<u64>, &'static str> {
        let mut block = 0;
        let mut visits: HashMap<u64, u64> = HashMap::new();
        // How often each flag-only branch, by its target, has been decided:
        // the decision depends on that, not on where the branch sits.
        let mut branch_decisions_by_target: HashMap<u64, u64> = HashMap::new();
        let mut steps = 0;
        let mut last_was_call = false;
        while let Some(current) = self.blocks.get(block) {
            *visits.entry(current.start).or_insert(0) += 1;
            let mut next = block + 1;
            for stmt in &current.stmts {
                last_was_call = matches!(stmt, Stmt::Call { .. });
                steps += 1;
                if steps > step_limit {
                    return Err("step limit");
                }
                match stmt {
                    Stmt::Assign { dest, value } => {
                        let value = match self.eval(value) {
                            Ok(value) => value,
                            Err(reason) => return Err(reason),
                        };
                        self.assign(*dest, value);
                    }
                    Stmt::Store { addr, value, width } => {
                        let (addr, value) = (
                            match self.eval(addr) {
                                Ok(value) => value,
                                Err(reason) => return Err(reason),
                            },
                            match self.eval(value) {
                                Ok(value) => value,
                                Err(reason) => return Err(reason),
                            },
                        );
                        self.store(addr, value, *width);
                    }
                    Stmt::Brif {
                        cond,
                        lhs,
                        rhs,
                        target,
                    } => {
                        let bits = operand_width(lhs, rhs);
                        if holds(
                            *cond,
                            match self.eval(lhs) {
                                Ok(value) => value,
                                Err(reason) => return Err(reason),
                            },
                            match self.eval(rhs) {
                                Ok(value) => value,
                                Err(reason) => return Err(reason),
                            },
                            bits,
                        ) {
                            next = match self.jump(*target) {
                                Flow::Block(index) => index,
                                Flow::Return(value) => return Ok(Some(value)),
                            };
                            break;
                        }
                    }
                    Stmt::BrifFlags { target, .. } => {
                        let count = branch_decisions_by_target.entry(*target).or_insert(0);
                        *count += 1;
                        if hash(self.seed, *target ^ (*count << 48)) & 1 == 1 {
                            next = match self.jump(*target) {
                                Flow::Block(index) => index,
                                Flow::Return(value) => return Ok(Some(value)),
                            };
                            break;
                        }
                    }
                    Stmt::Br {
                        target: Some(target),
                    } => {
                        next = match self.jump(*target) {
                            Flow::Block(index) => index,
                            Flow::Return(value) => return Ok(Some(value)),
                        };
                        break;
                    }
                    Stmt::Br { target: None } => return Err("dynamic branch"),
                    Stmt::BrIndirect { target } => {
                        let target = match self.eval(target) {
                            Ok(value) => value,
                            Err(reason) => return Err(reason),
                        };
                        let target = crate::arch::code_address(self.isa, target);
                        match self.jump(target) {
                            Flow::Block(index) => {
                                next = index;
                                break;
                            }
                            Flow::Return(value) => return Ok(Some(value)),
                        }
                    }
                    Stmt::Switch {
                        index,
                        cases,
                        default,
                    } => {
                        let index = match self.eval(index) {
                            Ok(value) => value,
                            Err(reason) => return Err(reason),
                        } as i64;
                        let Some(target) = cases
                            .iter()
                            .find(|(value, _)| *value == index)
                            .map(|(_, target)| *target)
                            .or(*default)
                        else {
                            return Err("switch without a matching case");
                        };
                        next = match self.jump(target) {
                            Flow::Block(index) => index,
                            Flow::Return(value) => return Ok(Some(value)),
                        };
                        break;
                    }
                    Stmt::Call {
                        target,
                        through,
                        args,
                        outputs,
                        convention,
                        clobbers,
                        ..
                    } => {
                        let target = match through {
                            Some(through) => Some(match self.eval(through) {
                                Ok(value) => value,
                                Err(reason) => return Err(reason),
                            }),
                            None => *target,
                        }
                        .map(|target| crate::arch::code_address(self.isa, target));
                        let arguments = match args {
                            Some(args) => {
                                match args
                                    .iter()
                                    .map(|arg| self.eval(arg))
                                    .collect::<Result<Vec<u64>, _>>()
                                {
                                    Ok(arguments) => arguments,
                                    Err(reason) => return Err(reason),
                                }
                            }
                            // The registers its own convention passes, as a
                            // system call's number and arguments.
                            None => convention
                                .arguments()
                                .iter()
                                .map(|index| self.register(*index))
                                .collect(),
                        };
                        self.calls.push(Call { target, arguments });
                        // A register it changes holds a result, or else a
                        // value the caller cannot rely on, read as zero as
                        // the undefined value is.
                        let ordinal = self.calls.len() as u64;
                        let changed = convention.clobbered_by(*clobbers);
                        let effects: Vec<(u16, u64)> = changed
                            .iter()
                            .map(|index| {
                                let value =
                                    if outputs.iter().any(|output| output.register == *index) {
                                        hash(self.seed ^ ordinal, 0x2_0000 + u64::from(*index))
                                    } else {
                                        0
                                    };
                                (*index, value)
                            })
                            .collect();
                        let values: Vec<_> = outputs
                            .iter()
                            .map(|output| {
                                let value = effects
                                    .iter()
                                    .find(|(index, _)| *index == output.register)
                                    .map_or_else(
                                        || self.register(output.register),
                                        |(_, value)| *value,
                                    );
                                (output.dest, value)
                            })
                            .collect();
                        for (index, value) in effects {
                            if !outputs.iter().any(|output| output.register == index) {
                                self.registers.insert(index, value);
                            }
                        }
                        for (dest, value) in values {
                            self.assign(dest, value);
                        }
                    }
                    Stmt::Ret { value } => {
                        return Ok(Some(match self.eval(value) {
                            Ok(value) => value,
                            Err(reason) => return Err(reason),
                        }));
                    }
                    Stmt::Trap => return Ok(None),
                    Stmt::Machine {
                        instruction,
                        inputs,
                        outputs,
                    } => {
                        if *instruction == super::MachineInstruction::ArmCacheZero {
                            return Err("cache maintenance requires external memory state");
                        }
                        if matches!(instruction, super::MachineInstruction::ArmExclusive { .. }) {
                            return Err("exclusive access requires an external memory monitor");
                        }
                        if let super::MachineInstruction::ArmLoadAcquire { width } = instruction {
                            let Some(input) = inputs.first() else {
                                return Err("missing acquire-load address");
                            };
                            let address = match self.eval(input) {
                                Ok(address) => address,
                                Err(reason) => return Err(reason),
                            };
                            let value = self.load(address, *width);
                            for output in outputs {
                                self.assign(*output, value);
                            }
                            continue;
                        }
                        if let super::MachineInstruction::Atomic { op, width, .. } = instruction {
                            use super::AtomicOp;
                            let mut args = Vec::new();
                            for input in inputs {
                                match self.eval(input) {
                                    Ok(value) => args.push(value),
                                    Err(reason) => return Err(reason),
                                }
                            }
                            if outputs.len() == 2 {
                                let half = *width / 2;
                                let upper = args[0].wrapping_add(u64::from(half));
                                let low = self.load(args[0], half);
                                let high = self.load(upper, half);
                                let bits = u32::from(half) * 8;
                                if low == args[2] & mask(bits) && high == args[4] & mask(bits) {
                                    self.store(args[0], args[1], half);
                                    self.store(upper, args[3], half);
                                }
                                self.assign(outputs[0], low);
                                self.assign(outputs[1], high);
                                continue;
                            }
                            let old = self.load(args[0], *width);
                            let operand = args.get(1).copied().unwrap_or(0);
                            let value = match op {
                                AtomicOp::Add => old.wrapping_add(operand),
                                AtomicOp::Sub => old.wrapping_sub(operand),
                                AtomicOp::And => old & operand,
                                AtomicOp::Or => old | operand,
                                AtomicOp::Xor => old ^ operand,
                                AtomicOp::Exchange | AtomicOp::Store => operand,
                                AtomicOp::CompareExchange
                                    if old == args[2] & mask(u32::from(*width) * 8) =>
                                {
                                    operand
                                }
                                AtomicOp::CompareExchange | AtomicOp::Load => old,
                            };
                            if *op != AtomicOp::Load {
                                self.store(args[0], value, *width);
                            }
                            if let Some(dest) = outputs.first() {
                                self.assign(*dest, old);
                            }
                            continue;
                        }
                        let Some(source) = self.source else {
                            return Err("machine state unavailable");
                        };
                        let mut arguments = Vec::new();
                        for input in inputs {
                            match self.eval(input) {
                                Ok(value) => arguments.push(value),
                                Err(reason) => return Err(reason),
                            }
                        }
                        let mut values = match source(*instruction, &arguments) {
                            Ok(values) => values,
                            Err(reason) => return Err(reason),
                        };
                        if values.len() != outputs.len() {
                            return Err("invalid machine-state output count");
                        }
                        if *instruction == super::MachineInstruction::ReadFlags {
                            values[0] = (values[0] & !(arguments[0] | 0x30000)) | arguments[1];
                        }
                        for (dest, value) in outputs.iter().zip(values) {
                            self.assign(*dest, value);
                        }
                    }
                    Stmt::Unsupported { .. } => return Err("unsupported instruction"),
                }
            }
            block = next;
        }
        // Code after a call that does not return is not part of the function.
        if last_was_call {
            Ok(None)
        } else {
            Err("ran past the last block")
        }
    }
}
