mod aarch64;
mod x86_64;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::visit::{children, expr_reads, expr_width};
use crate::ir::{Block, Convention, Expr, FLAG_OPERANDS, RegRef, Stmt};
use crate::loader::{Image, Isa};

const MAX_INSTRUCTIONS: usize = 8192;

struct Decoded<I> {
    pc: u64,
    next: u64,
    instruction: I,
}

trait Machine {
    type Instruction;

    fn branch_target(&self, instruction: &Self::Instruction, pc: u64) -> Option<u64>;
    /// Appends the instruction's statements and reports whether it ends the block.
    fn step(&mut self, instruction: &Self::Instruction, pc: u64) -> bool;
    fn take_statements(&mut self) -> Vec<Stmt>;
    /// The previous instruction ended its block.
    fn block_ended(&mut self);
    /// A branch target splits the block; the fall-through path continues into it.
    fn block_split(&mut self);
}

/// Splits the function at `addr` into basic blocks; `extra_targets` adds
/// block starts the branches alone do not show, such as jump-table cases.
pub fn lift(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    let bytes = image.read_vaddr(addr, size).ok_or(LiftError::Unreadable)?;
    match image.isa {
        Isa::AArch64 => {
            let (decoded, stop) = aarch64::decode(bytes, addr);
            build(
                image,
                aarch64::Lifter::new(image, addr),
                addr,
                &decoded,
                stop,
                extra_targets,
            )
        }
        Isa::X86_64 => {
            let (decoded, stop) = x86_64::decode(bytes, addr);
            build(
                image,
                x86_64::Lifter::new(image, addr),
                addr,
                &decoded,
                stop,
                extra_targets,
            )
        }
        Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

/// What an instruction is about to overwrite.
enum Write<'a> {
    /// A register and, when the register then holds exactly it, the value it receives.
    Register(u16, Option<&'a Expr>),
    Memory,
}

/// Before a write, keeps the pending compare testing the values its flags
/// were set from: an operand equal to the value written reads the register
/// afterwards, the operand of a written sum or difference is recovered from
/// the register, and any other operand reading what is overwritten moves into
/// a register of its own.
fn preserve_compare(compare: &mut Option<(Expr, Expr)>, write: Write<'_>, stmts: &mut Vec<Stmt>) {
    let Some((lhs, rhs)) = compare else {
        return;
    };
    let clobbered = |expr: &Expr| match write {
        Write::Register(index, _) => {
            let mut reads = HashSet::new();
            expr_reads(expr, &mut reads);
            reads.contains(&index)
        }
        Write::Memory => reads_memory(expr),
    };
    if !clobbered(lhs) && !clobbered(rhs) {
        return;
    }
    for (slot, operand) in FLAG_OPERANDS.into_iter().zip([lhs, rhs]) {
        if !clobbered(operand) {
            continue;
        }
        let width = expr_width(operand).unwrap_or(64);
        if let Write::Register(index, Some(value)) = write {
            if operand == value {
                *operand = Expr::reg(index, width);
                continue;
            }
            if let Some(recovered) = recover_operand(operand, value, index, width) {
                *operand = recovered;
                continue;
            }
        }
        stmts.push(Stmt::Assign {
            dest: RegRef {
                index: slot,
                width: 64,
            },
            value: operand.clone(),
        });
        *operand = Expr::reg(slot, width);
    }
}

/// `a` from the register that receives `a - b` or `a + b`, when `b` does
/// not read that register.
fn recover_operand(operand: &Expr, value: &Expr, index: u16, width: u8) -> Option<Expr> {
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    let inverse = match op {
        crate::ir::BinOp::Sub => crate::ir::BinOp::Add,
        crate::ir::BinOp::Add => crate::ir::BinOp::Sub,
        _ => return None,
    };
    let mut reads = HashSet::new();
    expr_reads(rhs, &mut reads);
    (**lhs == *operand && !reads.contains(&index))
        .then(|| Expr::bin(inverse, Expr::reg(index, width), rhs.as_ref().clone()))
}

fn reads_memory(expr: &Expr) -> bool {
    matches!(expr, Expr::Load { .. }) || children(expr).into_iter().any(reads_memory)
}

fn call(image: &Image, target: Option<u64>) -> Stmt {
    Stmt::Call {
        target,
        convention: Convention::of(image.isa, image.format, image.go),
    }
}

/// A jump out of the function: the callee's result is this function's.
fn tail_call(image: &Image, target: Option<u64>) -> [Stmt; 2] {
    [
        call(image, target),
        Stmt::Ret {
            value: Expr::reg(crate::arch::RETURN, 64),
        },
    ]
}

fn build<M: Machine>(
    image: &Image,
    mut machine: M,
    start: u64,
    decoded: &[Decoded<M::Instruction>],
    stop: Option<String>,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    if decoded.is_empty() {
        return Err(LiftError::NoInstructions);
    }
    let mut targets: HashSet<u64> = decoded
        .iter()
        .filter_map(|d| machine.branch_target(&d.instruction, d.pc))
        .collect();
    targets.extend(extra_targets);

    let mut blocks = Vec::new();
    let mut block_start = start;
    let mut pending = Vec::new();
    for d in decoded {
        if d.pc != block_start && targets.contains(&d.pc) {
            pending.extend(machine.take_statements());
            // Instructions without statements, such as padding, leave no block.
            if !pending.is_empty() {
                blocks.push(Block {
                    start: block_start,
                    stmts: std::mem::take(&mut pending),
                });
            }
            block_start = d.pc;
            machine.block_split();
        }
        if machine.step(&d.instruction, d.pc) {
            pending.extend(machine.take_statements());
            blocks.push(Block {
                start: block_start,
                stmts: std::mem::take(&mut pending),
            });
            block_start = d.next;
            machine.block_ended();
        }
    }
    pending.extend(machine.take_statements());
    if let Some(text) = stop {
        pending.push(Stmt::Unsupported { text });
    }
    if !pending.is_empty() {
        blocks.push(Block {
            start: block_start,
            stmts: pending,
        });
    }
    add_exits(image, start, &mut blocks);
    Ok(blocks)
}

/// Gives each branch out of the function a block of its own holding the tail
/// call, so the arguments it passes stay visible to the passes. When the
/// extent is only estimated, a branch past it may mean the estimate is short,
/// so only a branch to another known function counts.
fn add_exits(image: &Image, function: u64, blocks: &mut Vec<Block>) {
    let exact = image
        .functions
        .get(&function)
        .is_some_and(|function| function.size.is_some() && !function.size_estimated);
    let starts: HashSet<u64> = blocks.iter().map(|block| block.start).collect();
    let mut exits: Vec<u64> = blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Brif { target, .. }
            | Stmt::BrifFlags { target, .. }
            | Stmt::Br {
                target: Some(target),
            } => Some(*target),
            _ => None,
        })
        .filter(|target| {
            !starts.contains(target) && (exact || image.functions.contains_key(target))
        })
        .collect();
    if exits.is_empty() {
        return;
    }
    exits.sort_unstable();
    exits.dedup();
    // The last block must not fall through into the exits; past its end
    // is code that a call which does not return never reaches.
    if let Some(last) = blocks.last_mut()
        && !matches!(
            last.stmts.last(),
            Some(
                Stmt::Ret { .. }
                    | Stmt::Br { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. }
                    | Stmt::Trap
            )
        )
    {
        last.stmts.push(Stmt::Trap);
    }
    for target in exits {
        blocks.push(Block {
            start: target,
            stmts: tail_call(image, Some(target)).into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::lift;
    use crate::analysis::analyze;
    use crate::ir::eval::{self, hash};
    use crate::ir::visit::expr_width;
    use crate::ir::{Expr, FunctionIr, Stmt};
    use crate::loader::{Function, Image, Isa};

    /// Runs the lifted code with the given registers and returns its result.
    fn returns(isa: Isa, code: Vec<u8>, registers: &[(u16, u64)]) -> u64 {
        let len = code.len() as u64;
        let image = Image::from_code(isa, 0, code);
        let mut ir = FunctionIr::single_block(isa, Vec::new());
        ir.blocks = lift(&image, 0, len, &HashSet::new()).expect("lifts");
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers,
            memory: &[],
            step_limit: 100,
        };
        match eval::run(&ir, &setup) {
            eval::Outcome::Return { value, .. } => value,
            other => panic!("{other:?}\n{}", ir.render()),
        }
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn a_branch_tests_the_operands_a_flag_setting_write_replaced() {
        // subs w8, w8, w9; b.gt +12; mov w0, #0; ret; mov w0, #1; ret
        let code = words(&[
            0x6b090108, 0x5400006c, 0x52800000, 0xd65f03c0, 0x52800020, 0xd65f03c0,
        ]);
        assert_eq!(returns(Isa::AArch64, code, &[(8, 5), (9, 3)]), 1);
        // dec ecx; jne +6; mov eax, 0; ret; mov eax, 1; ret
        let code = vec![
            0xff, 0xc9, 0x75, 0x06, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ];
        assert_eq!(returns(Isa::X86_64, code, &[(1, 1)]), 0);
    }

    #[test]
    fn pop_reads_the_slot_push_wrote() {
        // push rbx; pop rax; ret
        assert_eq!(returns(Isa::X86_64, vec![0x53, 0x58, 0xc3], &[(3, 7)]), 7);
    }

    #[test]
    fn a_branch_target_after_padding_starts_a_block() {
        // jmp 3; nop; ret
        let image = Image::from_code(Isa::X86_64, 0, vec![0xeb, 0x01, 0x90, 0xc3]);
        let blocks = lift(&image, 0, 4, &HashSet::new()).expect("lifts");
        assert!(blocks.iter().any(|block| block.start == 3), "{:?}", blocks);
    }

    #[test]
    fn a_store_of_the_zero_register_is_kept() {
        // str wzr, [sp, #8]; ret
        let code = words(&[0xb9000bff, 0xd65f03c0]);
        let image = Image::from_code(Isa::AArch64, 0, code);
        let blocks = lift(&image, 0, 8, &HashSet::new()).expect("lifts");
        assert!(
            matches!(
                blocks[0].stmts.first(),
                Some(Stmt::Store {
                    value: Expr::Const(0),
                    width: 4,
                    ..
                })
            ),
            "{:?}",
            blocks[0]
        );
    }

    #[test]
    fn a_cbnz_target_starts_a_block() {
        // mov x8, xzr; loop: ldrb w9, [x0, x8]; add x8, x8, #1; cbnz w9, loop; ret
        let code = words(&[0xaa1f03e8, 0x38686809, 0x91000508, 0x35ffffc9, 0xd65f03c0]);
        let image = Image::from_code(Isa::AArch64, 0, code);
        let blocks = lift(&image, 0, 20, &HashSet::new()).expect("lifts");
        assert!(blocks.iter().any(|block| block.start == 4), "{blocks:?}");
    }

    #[test]
    fn cbz_on_a_w_register_tests_the_low_half() {
        // cbz w0, #8; ret; ret
        let code = words(&[0x34000040, 0xd65f03c0, 0xd65f03c0]);
        let image = Image::from_code(Isa::AArch64, 0, code);
        let blocks = lift(&image, 0, 12, &HashSet::new()).expect("lifts");
        let Some(Stmt::Brif { lhs, .. }) = blocks[0].stmts.last() else {
            panic!("a conditional branch: {:?}", blocks[0]);
        };
        assert_eq!(expr_width(lhs), Some(32), "{lhs:?}");
    }

    /// Random bytes may decode to anything; analysis and rendering must still finish.
    #[test]
    fn random_code_never_panics() {
        for isa in [Isa::AArch64, Isa::X86_64] {
            for seed in 0..300u64 {
                let len = 4 + (hash(seed, 0) % 508) as usize;
                let code: Vec<u8> = (0..len as u64)
                    .map(|offset| hash(seed, offset + 1) as u8)
                    .collect();
                let function = Function {
                    addr: 0,
                    size: Some(len as u64),
                    size_estimated: false,
                    name: None,
                    aliases: Vec::new(),
                    sources: Vec::new(),
                };
                let image = Image::from_code(isa, 0, code);
                if let Ok(analysis) = analyze(&image, &function) {
                    crate::render::render(&analysis.ir, &analysis.references, &HashMap::new(), &[]);
                }
            }
        }
    }
}
