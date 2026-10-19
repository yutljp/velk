mod aarch64;
mod x86_64;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::visit::{children, expr_reads, expr_width};
use crate::ir::{Block, Convention, Expr, FLAG_OPERANDS, RegRef, Stmt};
use crate::loader::{Image, Isa, Summary};

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

/// What lifting needs to know of the functions a body calls.
pub type Summaries<'a> = &'a dyn Fn(u64) -> Summary;

/// Splits the function at `addr` into basic blocks; `extra_targets` adds
/// block starts the branches alone do not show, such as jump-table cases.
/// What each callee takes and whether it returns comes from its summary.
pub fn lift(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    lift_with(image, addr, size, extra_targets, &|target| {
        crate::analysis::summary(image, target)
    })
}

/// `lift`, knowing of callees only what `summaries` says.
pub fn lift_with(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
    summaries: Summaries<'_>,
) -> Result<Vec<Block>, LiftError> {
    let bytes = image.read_vaddr(addr, size).ok_or(LiftError::Unreadable)?;
    match image.isa {
        Isa::AArch64 => {
            let machine = aarch64::Lifter::new(image, addr, summaries);
            let (decoded, stop) =
                decode_with_fragments(image, &machine, addr, bytes, aarch64::decode);
            build(
                image,
                summaries,
                machine,
                addr,
                &decoded,
                stop,
                extra_targets,
            )
        }
        Isa::X86_64 => {
            let machine = x86_64::Lifter::new(image, addr, summaries);
            let (decoded, stop) =
                decode_with_fragments(image, &machine, addr, bytes, x86_64::decode);
            build(
                image,
                summaries,
                machine,
                addr,
                &decoded,
                stop,
                extra_targets,
            )
        }
        Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

/// `value`, `width` bits wide, rotated by `amount`, which wraps at the width,
/// towards the low bits or the high ones. Bits above the width are left for
/// the write to clear.
fn rotate(value: Expr, amount: Expr, width: u8, right: bool) -> Expr {
    use crate::ir::BinOp;
    let bits = u64::from(width);
    let (amount, back) = match amount {
        Expr::Const(amount) => match amount % bits {
            0 => return value,
            amount => (Expr::constant(amount), Expr::constant(bits - amount)),
        },
        amount => {
            let amount = Expr::bin(BinOp::And, amount, Expr::constant(bits - 1));
            // A rotation by zero shifts back by zero too, not by the width.
            let back = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Sub, Expr::constant(bits), amount.clone()),
                Expr::constant(bits - 1),
            );
            (amount, back)
        }
    };
    let (towards, from) = if right {
        (BinOp::Shr, BinOp::Shl)
    } else {
        (BinOp::Shl, BinOp::Shr)
    };
    Expr::bin(
        BinOp::Or,
        Expr::bin(towards, value.clone(), amount),
        Expr::bin(from, value, back),
    )
}

/// `value`, `width` bits wide, with the order of the bytes reversed within
/// each `chunk` bytes.
fn reverse_bytes(value: Expr, width: u8, chunk: u8) -> Expr {
    use crate::ir::BinOp;
    let bytes = width / 8;
    (0..bytes)
        .map(|byte| {
            let start = byte - byte % chunk;
            let target = start + (chunk - 1 - byte % chunk);
            let field = Expr::bin(
                BinOp::And,
                Expr::bin(
                    BinOp::Shr,
                    value.clone(),
                    Expr::constant(8 * u64::from(byte)),
                ),
                Expr::constant(0xff),
            );
            Expr::bin(BinOp::Shl, field, Expr::constant(8 * u64::from(target)))
        })
        .reduce(|all, field| Expr::bin(BinOp::Or, all, field))
        .unwrap_or(value)
}

type Decoder<I> = fn(&[u8], u64) -> (Vec<Decoded<I>>, Option<String>);

/// The function's instructions, followed by those of every fragment split
/// off it, such as a cold part, that its branches reach.
fn decode_with_fragments<M: Machine>(
    image: &Image,
    machine: &M,
    addr: u64,
    bytes: &[u8],
    decode: Decoder<M::Instruction>,
) -> (Vec<Decoded<M::Instruction>>, Option<String>) {
    let (mut decoded, stop) = decode(bytes, addr);
    let mut included = HashSet::new();
    let mut scanned = 0;
    while scanned < decoded.len() {
        let reached: Vec<(u64, u64)> = decoded[scanned..]
            .iter()
            .filter_map(|d| machine.branch_target(&d.instruction, d.pc))
            .filter(|target| !image.functions.contains_key(target))
            .filter_map(|target| image.fragment_at(target))
            .filter(|(start, _)| included.insert(*start))
            .collect();
        scanned = decoded.len();
        for (start, size) in reached {
            if let Some(bytes) = image.read_vaddr(start, size) {
                decoded.extend(decode(bytes, start).0);
            }
        }
    }
    (decoded, stop)
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

/// The argument registers a call to `target` passes, when the number the
/// callee takes is known.
fn arguments(convention: Convention, count: Option<usize>) -> Option<Vec<Expr>> {
    let count = count?;
    Some(
        convention.arguments()[..count.min(convention.arguments().len())]
            .iter()
            .map(|register| Expr::reg(*register, 64))
            .collect(),
    )
}

fn call(image: &Image, summaries: Summaries<'_>, target: Option<u64>) -> Stmt {
    let convention = Convention::of(image.isa, image.format, image.go);
    Stmt::Call {
        target,
        through: None,
        convention,
        args: target.and_then(|target| arguments(convention, summaries(target).arity)),
        result: None,
    }
}

/// A call to the address `through` computes.
fn call_through(image: &Image, through: Expr) -> Stmt {
    Stmt::Call {
        target: None,
        through: Some(through),
        convention: Convention::of(image.isa, image.format, image.go),
        args: None,
        result: None,
    }
}

/// A jump out of the function: the callee's result is this function's,
/// unless the callee never returns.
fn tail_call(image: &Image, summaries: Summaries<'_>, target: Option<u64>) -> [Stmt; 2] {
    if target.is_some_and(|target| summaries(target).noreturn) {
        return [call(image, summaries, target), Stmt::Trap];
    }
    [
        call(image, summaries, target),
        Stmt::Ret {
            value: Expr::reg(crate::arch::RETURN, 64),
        },
    ]
}

fn build<M: Machine>(
    image: &Image,
    summaries: Summaries<'_>,
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
    let mut expected = start;
    for d in decoded {
        // A fragment follows the code before it in the list, not in memory:
        // code running off the end goes on at the next address.
        if d.pc != expected {
            pending.extend(machine.take_statements());
            if block_start != expected || !pending.is_empty() {
                pending.push(Stmt::Br {
                    target: Some(expected),
                });
                blocks.push(Block {
                    start: block_start,
                    stmts: std::mem::take(&mut pending),
                });
                machine.block_ended();
            }
            block_start = d.pc;
        }
        expected = d.next;
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
    // Code that ends in a call, with nothing after it, never returns from it.
    if let Some(last) = blocks.last_mut()
        && matches!(last.stmts.last(), Some(Stmt::Call { .. }))
    {
        last.stmts.push(Stmt::Trap);
    }
    add_exits(image, summaries, start, &mut blocks);
    drop_unread_compare_operands(&mut blocks);
    Ok(blocks)
}

/// Removes the copies of compare operands no branch went on to read: most
/// instructions set flags that nothing tests.
fn drop_unread_compare_operands(blocks: &mut [Block]) {
    let mut read = HashSet::new();
    for stmt in blocks.iter().flat_map(|block| &block.stmts) {
        read.extend(
            crate::ir::visit::statement_registers(stmt)
                .1
                .into_iter()
                .filter(|register| FLAG_OPERANDS.contains(register)),
        );
    }
    for block in blocks {
        block.stmts.retain(|stmt| {
            !matches!(stmt, Stmt::Assign { dest, .. }
                if FLAG_OPERANDS.contains(&dest.index) && !read.contains(&dest.index))
        });
    }
}

/// Gives each branch out of the function a block of its own holding the tail
/// call, so the arguments it passes stay visible to the passes. When the
/// extent is only estimated, a branch past it may mean the estimate is short,
/// so only a branch to another known function counts.
fn add_exits(image: &Image, summaries: Summaries<'_>, function: u64, blocks: &mut Vec<Block>) {
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
            stmts: tail_call(image, summaries, Some(target)).into(),
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
        returns_with(isa, code, registers, &[])
    }

    fn returns_with(
        isa: Isa,
        code: Vec<u8>,
        registers: &[(u16, u64)],
        memory: &[(u64, u64)],
    ) -> u64 {
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
            memory,
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
    fn flags_of_tst_and_cmn_test_the_result() {
        // tst w0, w1; b.eq +12; mov w0, #0; ret; mov w0, #1; ret
        let tst = words(&[
            0x6a01_001f,
            0x5400_0060,
            0x5280_0000,
            0xd65f_03c0,
            0x5280_0020,
            0xd65f_03c0,
        ]);
        // 6 & 9 is zero although 6 != 9.
        assert_eq!(returns(Isa::AArch64, tst, &[(0, 6), (1, 9)]), 1);
        // cmn w0, #8; b.le +12; ...: -8 + 8 <= 0.
        let cmn = words(&[
            0x3100_201f,
            0x5400_006d,
            0x5280_0000,
            0xd65f_03c0,
            0x5280_0020,
            0xd65f_03c0,
        ]);
        assert_eq!(returns(Isa::AArch64, cmn, &[(0, 0xffff_fff8)]), 1);
    }

    #[test]
    fn an_unsigned_test_after_sub_compares_the_operands() {
        // sub edi, 9; ja +6; mov eax, 0; ret; mov eax, 1; ret
        let code = vec![
            0x83, 0xef, 0x09, 0x77, 0x06, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ];
        // 5 - 9 is nonzero, but 5 is not above 9.
        assert_eq!(returns(Isa::X86_64, code, &[(7, 5)]), 0);
    }

    #[test]
    fn a_call_through_a_register_keeps_its_target() {
        // call rax; ret
        let image = Image::from_code(Isa::X86_64, 0, vec![0xff, 0xd0, 0xc3]);
        let blocks = lift(&image, 0, 3, &HashSet::new()).expect("lifts");
        assert!(
            matches!(
                blocks[0].stmts.first(),
                Some(Stmt::Call {
                    target: None,
                    through: Some(Expr::Reg { index: 0, .. }),
                    ..
                })
            ),
            "{blocks:?}"
        );
    }

    #[test]
    fn bitfield_moves_extract_and_insert() {
        let ret = 0xd65f_03c0;
        // ubfx w0, w1, #4, #4
        let ubfx = words(&[0x5304_1c20, ret]);
        assert_eq!(returns(Isa::AArch64, ubfx, &[(1, 0xab)]), 0xa);
        // sxtw x0, w1
        let sxtw = words(&[0x9340_7c20, ret]);
        assert_eq!(returns(Isa::AArch64, sxtw, &[(1, 0xffff_ffff)]), u64::MAX);
        // ubfiz w0, w1, #1, #3
        let ubfiz = words(&[0x531f_0820, ret]);
        assert_eq!(returns(Isa::AArch64, ubfiz, &[(1, 0xff)]), 0xe);
    }

    #[test]
    fn integer_division_and_unscaled_loads_lift() {
        // sdiv w0, w0, w1; ret: -7 / 2 is -3.
        let sdiv = words(&[0x1ac1_0c00, 0xd65f_03c0]);
        let quotient = returns(Isa::AArch64, sdiv, &[(0, (-7i32) as u32 as u64), (1, 2)]);
        assert_eq!(quotient as u32, (-3i32) as u32);
        // ldur w0, [x1, #-4]; ret
        let ldur = words(&[0xb85f_c020, 0xd65f_03c0]);
        assert_eq!(
            returns_with(Isa::AArch64, ldur, &[(1, 0x1004)], &[(0x1000, 0x2a)]),
            0x2a
        );
        // mov eax, edi; xor edx, edx; div esi; ret
        let div = vec![0x89, 0xf8, 0x31, 0xd2, 0xf7, 0xf6, 0xc3];
        assert_eq!(returns(Isa::X86_64, div, &[(7, 7), (6, 2)]), 3);
    }

    #[test]
    fn moves_after_one_compare_all_test_it() {
        // mov ecx, 9; cmp edi, esi; cmovl eax, ecx; cmovl eax, edx; ret
        let code = vec![
            0xb9, 0x09, 0x00, 0x00, 0x00, 0x39, 0xf7, 0x0f, 0x4c, 0xc1, 0x0f, 0x4c, 0xc2, 0xc3,
        ];
        assert_eq!(returns(Isa::X86_64, code, &[(7, 1), (6, 2), (2, 4)]), 4);
    }

    #[test]
    fn vector_moves_copy_both_halves() {
        // movups xmm0, [rdi]; movups [rsi], xmm0; mov rax, [rsi + 8]; ret
        let code = vec![
            0x0f, 0x10, 0x07, 0x0f, 0x11, 0x06, 0x48, 0x8b, 0x46, 0x08, 0xc3,
        ];
        let registers = [(7, 0x100), (6, 0x200)];
        assert_eq!(
            returns_with(Isa::X86_64, code, &registers, &[(0x108, 0x55)]),
            0x55
        );
        // xorps xmm0, xmm0; movq rax, xmm0; ret
        let code = vec![0x0f, 0x57, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3];
        assert_eq!(returns(Isa::X86_64, code, &[(18, 5)]), 0);
    }

    #[test]
    fn rotations_and_byte_reversals_lift() {
        let x = 0x1122_3344_5566_7788;
        // mov rax, rdi; rol rax, 8; ret
        let rol = vec![0x48, 0x89, 0xf8, 0x48, 0xc1, 0xc0, 0x08, 0xc3];
        assert_eq!(returns(Isa::X86_64, rol, &[(7, x)]), 0x2233_4455_6677_8811);
        // mov eax, edi; ror eax, cl; ret
        let ror = vec![0x89, 0xf8, 0xd3, 0xc8, 0xc3];
        let rotated = |count| returns(Isa::X86_64, ror.clone(), &[(7, 0x1234_5678), (1, count)]);
        assert_eq!(rotated(4), 0x8123_4567);
        assert_eq!(rotated(0), 0x1234_5678);
        // mov rax, rdi; bswap rax; ret
        let bswap = vec![0x48, 0x89, 0xf8, 0x48, 0x0f, 0xc8, 0xc3];
        assert_eq!(
            returns(Isa::X86_64, bswap, &[(7, x)]),
            0x8877_6655_4433_2211
        );
        // mov rax, rdi; shrd rax, rsi, 8; ret
        let shrd = vec![0x48, 0x89, 0xf8, 0x48, 0x0f, 0xac, 0xf0, 0x08, 0xc3];
        assert_eq!(
            returns(Isa::X86_64, shrd, &[(7, x), (6, 0xaabb)]),
            0xbb11_2233_4455_6677
        );
        let ret = 0xd65f_03c0;
        let a64 = |word: u32, registers: &[(u16, u64)]| {
            returns(Isa::AArch64, words(&[word, ret]), registers)
        };
        // ror x0, x1, #8
        assert_eq!(a64(0x93c1_2020, &[(1, x)]), 0x8811_2233_4455_6677);
        // orr x0, xzr, x1, ror #8
        assert_eq!(a64(0xaac1_23e0, &[(1, x)]), 0x8811_2233_4455_6677);
        // rorv w0, w1, w2
        assert_eq!(a64(0x1ac2_2c20, &[(1, 0x1234_5678), (2, 36)]), 0x8123_4567);
        // rev x0, x1; rev16 w0, w1
        assert_eq!(a64(0xdac0_0c20, &[(1, x)]), 0x8877_6655_4433_2211);
        assert_eq!(a64(0x5ac0_0420, &[(1, 0x1122_3344)]), 0x2211_4433);
        // orn x0, x1, x2
        assert_eq!(a64(0xaa22_0020, &[(1, 0xf0), (2, !0x0f)]), 0xff);
    }

    #[test]
    fn exchanges_return_the_old_value() {
        // mov eax, 5; xchg rax, rdi; ret
        let xchg = vec![0xb8, 0x05, 0x00, 0x00, 0x00, 0x48, 0x97, 0xc3];
        assert_eq!(returns(Isa::X86_64, xchg, &[(7, 9)]), 9);
        // mov eax, 3; lock xadd [rdi], rax; ret
        let xadd = vec![
            0xb8, 0x03, 0x00, 0x00, 0x00, 0xf0, 0x48, 0x0f, 0xc1, 0x07, 0xc3,
        ];
        assert_eq!(
            returns_with(Isa::X86_64, xadd, &[(7, 0x100)], &[(0x100, 10)]),
            10
        );
        // mov eax, 10; lock cmpxchg [rdi], rsi; ret: a mismatch loads rax.
        let cmpxchg = vec![
            0xb8, 0x0a, 0x00, 0x00, 0x00, 0xf0, 0x48, 0x0f, 0xb1, 0x37, 0xc3,
        ];
        let registers = [(7, 0x100), (6, 42)];
        assert_eq!(
            returns_with(Isa::X86_64, cmpxchg, &registers, &[(0x100, 7)]),
            7
        );
        // The same, then mov rax, [rdi]: a match stores rsi.
        let stored = vec![
            0xb8, 0x0a, 0x00, 0x00, 0x00, 0xf0, 0x48, 0x0f, 0xb1, 0x37, 0x48, 0x8b, 0x07, 0xc3,
        ];
        assert_eq!(
            returns_with(Isa::X86_64, stored, &registers, &[(0x100, 10)]),
            42
        );
        // xor eax, eax; bt rdi, 3; setb al; ret
        let bt = vec![
            0x31, 0xc0, 0x48, 0x0f, 0xba, 0xe7, 0x03, 0x0f, 0x92, 0xc0, 0xc3,
        ];
        assert_eq!(returns(Isa::X86_64, bt.clone(), &[(7, 8)]), 1);
        assert_eq!(returns(Isa::X86_64, bt, &[(7, 7)]), 0);
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
