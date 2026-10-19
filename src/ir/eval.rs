//! An interpreter for checking that optimization passes preserve a function's
//! behavior. Values the function did not produce (registers it reads before
//! writing, memory it never stored) come from a seeded hash, so two runs with
//! the same seed see the same inputs.
//!
//! Signed operations act at their operands' width, so a signed division or
//! comparison of two 32-bit registers behaves as a 32-bit instruction does.

use std::collections::{BTreeMap, HashMap};

use super::semantics::{holds, mask, operand_width, sign_extend};
use super::{BinOp, Block, Expr, FunctionIr, RegRef, Stmt};

pub const STACK_TOP: u64 = 0x7fff_ff00_0000;
const STACK_SPAN: u64 = 1 << 24;

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
    isa: crate::loader::Isa,
    convention: &'a Convention<'a>,
    seed: u64,
    registers: HashMap<u16, u64>,
    memory: HashMap<u64, u8>,
    calls: Vec<Call>,
    blocks: &'a [Block],
    starts: HashMap<u64, usize>,
}

pub fn run(ir: &FunctionIr, setup: &Setup<'_>) -> Outcome {
    let mut machine = Machine::new(ir, setup);
    match machine.execute(setup.step_limit) {
        Ok(Some(value)) => Outcome::Return {
            value,
            calls: machine.calls,
            memory: visible(&machine.memory),
        },
        Ok(None) => Outcome::Trap {
            calls: machine.calls,
            memory: visible(&machine.memory),
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
    let mut machine = Machine::new(ir, setup);
    machine.execute(setup.step_limit)?;
    Ok((machine.registers, machine.memory))
}

impl<'a> Machine<'a> {
    fn new(ir: &'a FunctionIr, setup: &'a Setup<'a>) -> Self {
        let mut machine = Machine {
            isa: ir.isa,
            convention: &setup.convention,
            seed: setup.seed,
            registers: setup.registers.iter().copied().collect(),
            memory: HashMap::new(),
            calls: Vec::new(),
            blocks: &ir.blocks,
            starts: ir
                .blocks
                .iter()
                .enumerate()
                .map(|(index, block)| (block.start, index))
                .collect(),
        };
        machine
            .registers
            .insert(crate::arch::stack_pointer(ir.isa), STACK_TOP);
        for (addr, value) in setup.memory {
            machine.store(*addr, *value, 8);
        }
        machine
    }
}

fn visible(memory: &HashMap<u64, u8>) -> BTreeMap<u64, u8> {
    memory
        .iter()
        .filter(|(addr, _)| !(STACK_TOP - STACK_SPAN..STACK_TOP + STACK_SPAN).contains(*addr))
        .map(|(addr, byte)| (*addr, *byte))
        .collect()
}

/// The NaN an x86 SSE operation gives, where the processor running the
/// tests would give its own: the first NaN operand made quiet, or with none
/// the negative quiet NaN x86 calls indefinite.
fn x86_nan(op: super::Operation, args: &[u64], result: u64) -> u64 {
    use super::{Operation, Precision};
    let precision = match op {
        Operation::FloatAdd(p)
        | Operation::FloatSub(p)
        | Operation::FloatMul(p)
        | Operation::FloatDiv(p)
        | Operation::FloatSqrt(p)
        | Operation::FloatMulAdd(p) => p,
        _ => return result,
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
pub fn hash(seed: u64, key: u64) -> u64 {
    let mut value = seed ^ key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

impl Machine<'_> {
    fn register(&self, index: u16) -> u64 {
        self.registers
            .get(&index)
            .copied()
            .unwrap_or_else(|| hash(self.seed, 0x1_0000 + u64::from(index)))
    }

    fn byte(&self, addr: u64) -> u8 {
        self.memory
            .get(&addr)
            .copied()
            .unwrap_or_else(|| hash(self.seed, addr) as u8)
    }

    fn load(&self, addr: u64, bytes: u8) -> u64 {
        (0..u64::from(bytes)).fold(0, |value, offset| {
            value | (u64::from(self.byte(addr.wrapping_add(offset))) << (8 * offset))
        })
    }

    fn store(&mut self, addr: u64, value: u64, bytes: u8) {
        for offset in 0..u64::from(bytes) {
            self.memory
                .insert(addr.wrapping_add(offset), (value >> (8 * offset)) as u8);
        }
    }

    fn eval(&self, expr: &Expr) -> Result<u64, &'static str> {
        Ok(match expr {
            Expr::Apply { op, args } => {
                let values = args
                    .iter()
                    .map(|arg| self.eval(arg))
                    .collect::<Result<Vec<u64>, _>>()?;
                let result = super::semantics::apply(*op, &values);
                if self.isa == crate::loader::Isa::X86_64 {
                    x86_nan(*op, &values, result)
                } else {
                    result
                }
            }
            Expr::Reg { index, width } => self.register(*index) & mask(u32::from(*width)),
            Expr::Const(value) => *value,
            Expr::Load {
                addr,
                width,
                signed,
            } => {
                let value = self.load(self.eval(addr)?, *width);
                if *signed {
                    sign_extend(value, u32::from(*width) * 8) as u64
                } else {
                    value
                }
            }
            Expr::SignExtend { value, width } => {
                sign_extend(self.eval(value)?, u32::from(*width) * 8) as u64
            }
            Expr::Select {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => {
                let bits = operand_width(lhs, rhs);
                if holds(*cond, self.eval(lhs)?, self.eval(rhs)?, bits) {
                    self.eval(then)?
                } else {
                    self.eval(els)?
                }
            }
            Expr::Bin { op, lhs, rhs } => {
                let (a, b) = (self.eval(lhs)?, self.eval(rhs)?);
                let bits = operand_width(lhs, rhs);
                match op {
                    BinOp::Add => a.wrapping_add(b),
                    BinOp::Sub => a.wrapping_sub(b),
                    BinOp::Mul => a.wrapping_mul(b),
                    BinOp::MulHigh => ((u128::from(a) * u128::from(b)) >> 64) as u64,
                    BinOp::MulHighS => ((i128::from(a as i64) * i128::from(b as i64)) >> 64) as u64,
                    BinOp::And => a & b,
                    BinOp::Or => a | b,
                    BinOp::Xor => a ^ b,
                    BinOp::Shl => a.wrapping_shl(b as u32),
                    BinOp::Shr => a.wrapping_shr(b as u32),
                    BinOp::Sar => (sign_extend(a, bits).wrapping_shr(b as u32) as u64) & mask(bits),
                    BinOp::DivU | BinOp::ModU if b == 0 => return Err("division by zero"),
                    BinOp::DivU => a / b,
                    BinOp::ModU => a % b,
                    BinOp::DivS | BinOp::ModS => {
                        let (sa, sb) = (sign_extend(a, bits), sign_extend(b, bits));
                        if sb == 0 {
                            return Err("division by zero");
                        }
                        let result = if *op == BinOp::DivS {
                            sa.wrapping_div(sb)
                        } else {
                            sa.wrapping_rem(sb)
                        };
                        result as u64 & mask(bits)
                    }
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
        match self.starts.get(&target) {
            Some(index) => Flow::Block(*index),
            None => {
                self.call(Some(target));
                Flow::Return(self.register(crate::arch::RETURN))
            }
        }
    }

    fn call(&mut self, target: Option<u64>) {
        let arguments = self
            .convention
            .arguments
            .iter()
            .map(|index| self.register(*index))
            .collect();
        self.call_with(target, arguments);
    }

    /// A call passing `arguments`; it clobbers what the convention lets it.
    fn call_with(&mut self, target: Option<u64>, arguments: Vec<u64>) {
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
        let mut decided: HashMap<u64, u64> = HashMap::new();
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
                        let value = self.eval(value)?;
                        self.assign(*dest, value);
                    }
                    Stmt::Store { addr, value, width } => {
                        let (addr, value) = (self.eval(addr)?, self.eval(value)?);
                        self.store(addr, value, *width);
                    }
                    Stmt::Brif {
                        cond,
                        lhs,
                        rhs,
                        target,
                    } => {
                        let bits = operand_width(lhs, rhs);
                        if holds(*cond, self.eval(lhs)?, self.eval(rhs)?, bits) {
                            next = match self.jump(*target) {
                                Flow::Block(index) => index,
                                Flow::Return(value) => return Ok(Some(value)),
                            };
                            break;
                        }
                    }
                    Stmt::BrifFlags { target, .. } => {
                        let count = decided.entry(*target).or_insert(0);
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
                    // A jump through a register the analysis could not
                    // resolve leaves the function, whatever address it holds.
                    Stmt::BrIndirect { target } => {
                        let target = self.eval(target)?;
                        self.call(Some(target));
                        return Ok(Some(self.register(crate::arch::RETURN)));
                    }
                    Stmt::Switch {
                        index,
                        cases,
                        default,
                    } => {
                        let index = self.eval(index)? as i64;
                        let target = cases
                            .iter()
                            .find(|(value, _)| *value == index)
                            .map(|(_, target)| *target)
                            .or(*default)
                            .ok_or("switch without a matching case")?;
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
                        result,
                        ..
                    } => {
                        let target = match through {
                            Some(through) => Some(self.eval(through)?),
                            None => *target,
                        };
                        match args {
                            Some(args) => {
                                let values = args
                                    .iter()
                                    .map(|arg| self.eval(arg))
                                    .collect::<Result<Vec<u64>, _>>()?;
                                self.call_with(target, values)
                            }
                            None => self.call(target),
                        }
                        if let Some(result) = result {
                            let value = self.register(crate::arch::RETURN);
                            self.assign(*result, value);
                        }
                    }
                    Stmt::Ret { value } => return Ok(Some(self.eval(value)?)),
                    Stmt::Trap => return Ok(None),
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
