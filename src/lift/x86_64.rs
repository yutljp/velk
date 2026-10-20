use crate::arch::x86::{RAX, RDX, RSP};
use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, EncodingKind, FlowControl, Instruction, Mnemonic,
    OpKind, Register,
};

use super::flags::{Flags, Test};
use super::{
    Decoded, MAX_INSTRUCTIONS, Machine, Write, call, call_through, preserve_compare, tail_call,
};
use crate::ir::{
    BinOp, Block, Cond, EXCHANGE, Expr, LaneOp, Operation, Precision, RegRef, Rounding, Stmt,
};
use crate::loader::Image;

pub(super) struct Lifter<'a> {
    stmts: Vec<Stmt>,
    last_compare: Option<Flags>,
    /// Whether the instruction being lifted set `last_compare`.
    flags_written: bool,
    /// Whether an operand of the instruction being lifted was one the lifter
    /// cannot express, so that its effect would be lost.
    incomplete: bool,
    /// What each instruction reads and writes, for the registers an
    /// unsupported one may change.
    info: iced_x86::InstructionInfoFactory,
    /// Whether an instruction of the current block may have changed the flags.
    flags_touched: bool,
    /// The body of a `rep` string instruction's loop, after its test.
    extra: Vec<Block>,
    extended_dividend: Option<u8>,
    /// The width of the high half of an unsigned dividend the previous
    /// instruction cleared (`xor edx, edx`).
    zeroed_dividend: Option<u8>,
    image: &'a Image,
    summaries: super::Summaries<'a>,
    function: u64,
}

impl<'a> Lifter<'a> {
    pub(super) fn new(image: &'a Image, function: u64, summaries: super::Summaries<'a>) -> Self {
        Self {
            stmts: Vec::new(),
            last_compare: None,
            flags_written: false,
            incomplete: false,
            info: iced_x86::InstructionInfoFactory::new(),
            flags_touched: false,
            extra: Vec::new(),
            extended_dividend: None,
            zeroed_dividend: None,
            image,
            summaries,
            function,
        }
    }

    fn set_flags(&mut self, flags: Flags) {
        self.last_compare = Some(flags);
        self.flags_written = true;
    }

    /// `cond` under the flags; flags set in another block are unknown.
    fn test(&self, cond: Cond) -> Test {
        self.last_compare.as_ref().map_or(Test::Unknown, |flags| {
            flags.test(cond, crate::loader::Isa::X86_64)
        })
    }

    /// The condition code `code` under the flags.
    fn condition_test(&self, code: ConditionCode) -> Test {
        let parity = |even| {
            self.last_compare
                .as_ref()
                .map_or(Test::Unknown, |flags| flags.parity(even))
        };
        match code {
            ConditionCode::p => parity(true),
            ConditionCode::np => parity(false),
            code => condition(code).map_or(Test::Unknown, |cond| self.test(cond)),
        }
    }

    /// The carry flag as one or zero, when the flags here decide it.
    fn carry(&self) -> Option<Expr> {
        self.test(Cond::Cc)
            .select(Expr::constant(1), Expr::constant(0))
    }

    fn read_reg(index: u16, width: u8) -> Expr {
        let slot = Expr::reg(index, 64);
        match width {
            32 => Expr::bin(BinOp::And, slot, Expr::constant(0xffff_ffff)),
            16 => Expr::bin(BinOp::And, slot, Expr::constant(0xffff)),
            8 => Expr::bin(BinOp::And, slot, Expr::constant(0xff)),
            _ => slot,
        }
    }

    fn assign(&mut self, index: u16, width: u8, value: Expr) {
        preserve_compare(
            &mut self.last_compare,
            // A partial write keeps the register's other bits.
            Write::Register(index, matches!(width, 32 | 64).then_some(&value)),
            &mut self.stmts,
        );
        let value = match width {
            32 => Expr::bin(BinOp::And, value, Expr::constant(0xffff_ffff)),
            16 | 8 => {
                let bits = if width == 16 { 16 } else { 8 };
                let mask = (1u64 << bits) - 1;
                let keep = Expr::bin(BinOp::And, Expr::reg(index, 64), Expr::constant(!mask));
                let inserted = Expr::bin(BinOp::And, value, Expr::constant(mask));
                Expr::bin(BinOp::Or, keep, inserted)
            }
            _ => value,
        };
        self.stmts.push(Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        });
    }
}

fn gpr(reg: Register) -> Option<(u16, u8)> {
    use Register::*;
    let pair = match reg {
        RAX => (0, 64),
        EAX => (0, 32),
        AX => (0, 16),
        AL => (0, 8),
        RCX => (1, 64),
        ECX => (1, 32),
        CX => (1, 16),
        CL => (1, 8),
        RDX => (2, 64),
        EDX => (2, 32),
        DX => (2, 16),
        DL => (2, 8),
        RBX => (3, 64),
        EBX => (3, 32),
        BX => (3, 16),
        BL => (3, 8),
        RSP => (4, 64),
        ESP => (4, 32),
        SP => (4, 16),
        SPL => (4, 8),
        RBP => (5, 64),
        EBP => (5, 32),
        BP => (5, 16),
        BPL => (5, 8),
        RSI => (6, 64),
        ESI => (6, 32),
        SI => (6, 16),
        SIL => (6, 8),
        RDI => (7, 64),
        EDI => (7, 32),
        DI => (7, 16),
        DIL => (7, 8),
        R8 => (8, 64),
        R8D => (8, 32),
        R8W => (8, 16),
        R8L => (8, 8),
        R9 => (9, 64),
        R9D => (9, 32),
        R9W => (9, 16),
        R9L => (9, 8),
        R10 => (10, 64),
        R10D => (10, 32),
        R10W => (10, 16),
        R10L => (10, 8),
        R11 => (11, 64),
        R11D => (11, 32),
        R11W => (11, 16),
        R11L => (11, 8),
        R12 => (12, 64),
        R12D => (12, 32),
        R12W => (12, 16),
        R12L => (12, 8),
        R13 => (13, 64),
        R13D => (13, 32),
        R13W => (13, 16),
        R13L => (13, 8),
        R14 => (14, 64),
        R14D => (14, 32),
        R14W => (14, 16),
        R14L => (14, 8),
        R15 => (15, 64),
        R15D => (15, 32),
        R15W => (15, 16),
        R15L => (15, 8),
        _ => return Option::None,
    };
    Option::Some(pair)
}

/// The registers, as the IR numbers them, an instruction may write.
fn written_registers(info: &mut iced_x86::InstructionInfoFactory, ins: &Instruction) -> Vec<u16> {
    use iced_x86::OpAccess;
    let mut out = Vec::new();
    for used in info.info(ins).used_registers() {
        if !matches!(
            used.access(),
            OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
        ) {
            continue;
        }
        let register = used.register();
        if let Some((index, _)) = gpr(register.full_register()) {
            out.push(index);
        } else if (register.is_xmm() || register.is_ymm() || register.is_zmm())
            && register.number() < 16
        {
            let slot = crate::arch::x86::XMM0 + 2 * register.number() as u16;
            out.extend([slot, slot + 1]);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The register whose second byte `reg` names (`ah`, `ch`, `dh`, `bh`).
fn high_byte(reg: Register) -> Option<u16> {
    match reg {
        Register::AH => Some(0),
        Register::CH => Some(1),
        Register::DH => Some(2),
        Register::BH => Some(3),
        _ => None,
    }
}

fn memory_width(ins: &Instruction) -> Option<u8> {
    Some(match ins.memory_size().size() {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => return None,
    })
}

fn memory_address(ins: &Instruction) -> Option<Expr> {
    if ins.memory_base() == Register::RIP {
        return Some(Expr::constant(ins.ip_rel_memory_address()));
    }
    let mut address: Option<Expr> = None;
    if let Some((index, _)) = gpr(ins.memory_base()) {
        address = Some(Expr::reg(index, 64));
    }
    if let Some((index, _)) = gpr(ins.memory_index()) {
        let mut value = Expr::reg(index, 64);
        let scale = ins.memory_index_scale();
        if scale > 1 {
            value = Expr::bin(BinOp::Mul, value, Expr::constant(scale as u64));
        }
        address = Some(match address {
            Some(base) => Expr::bin(BinOp::Add, base, value),
            None => value,
        });
    }
    let displacement = ins.memory_displacement64();
    if displacement != 0 {
        address = Some(match address {
            Some(base) => Expr::bin(BinOp::Add, base, Expr::constant(displacement)),
            None => Expr::constant(displacement),
        });
    }
    let segment = match ins.memory_segment() {
        Register::FS => Some(crate::arch::x86::FS_BASE),
        Register::GS => Some(crate::arch::x86::GS_BASE),
        _ => None,
    };
    match (segment, address) {
        (Some(segment), Some(address)) => {
            Some(Expr::bin(BinOp::Add, Expr::reg(segment, 64), address))
        }
        (Some(segment), None) => Some(Expr::reg(segment, 64)),
        // No base, index or displacement addresses zero.
        (None, None) => Some(Expr::constant(0)),
        (None, address) => address,
    }
}

/// The slot holding the low half of an xmm register.
fn xmm(reg: Register) -> Option<u16> {
    (reg.is_xmm() && reg.number() < 16).then(|| crate::arch::x86::XMM0 + 2 * reg.number() as u16)
}

fn load_at(addr: Expr, width: u8) -> Expr {
    Expr::Load {
        addr: Box::new(addr),
        width,
        signed: false,
    }
}

/// 64 bits of `parts` (halves, lowest first) starting at bit `start`, with
/// zeros past the end.
fn window(parts: &[Expr], start: u64) -> Expr {
    let (index, offset) = ((start / 64) as usize, start % 64);
    let Some(first) = parts.get(index) else {
        return Expr::constant(0);
    };
    let low = Expr::bin(BinOp::Shr, first.clone(), Expr::constant(offset));
    match parts.get(index + 1) {
        Some(next) if offset > 0 => Expr::bin(
            BinOp::Or,
            low,
            Expr::bin(BinOp::Shl, next.clone(), Expr::constant(64 - offset)),
        ),
        _ => low,
    }
}

/// Lane `index` of `bits` from a vector's halves, at the bottom.
fn lane_of((low, high): &(Expr, Expr), index: u64, bits: u64) -> Expr {
    let per_half = 64 / bits;
    let half = if index < per_half { low } else { high };
    let shifted = Expr::bin(
        BinOp::Shr,
        half.clone(),
        Expr::constant((index % per_half) * bits),
    );
    Expr::bin(BinOp::And, shifted, Expr::constant((1 << bits) - 1))
}

/// Lanes placed from the bottom of a half.
fn pack(lanes: Vec<Expr>, bits: u64) -> Expr {
    lanes
        .into_iter()
        .enumerate()
        .map(|(index, lane)| Expr::bin(BinOp::Shl, lane, Expr::constant(index as u64 * bits)))
        .reduce(|out, lane| Expr::bin(BinOp::Or, out, lane))
        .unwrap_or_else(|| Expr::constant(0))
}

/// The packed SSE instructions, on each 64-bit half: integer lanes, packed
/// doubles and singles, shuffles, and sign masks.
fn lift_packed(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let destination = xmm(ins.op0_register());
    // The halves of an xmm operand or of the 16 bytes at a memory one.
    let halves = |index: u32| -> Option<(Expr, Expr)> {
        match ins.op_kind(index) {
            OpKind::Register => {
                let slot = xmm(ins.op_register(index))?;
                Some((Expr::reg(slot, 64), Expr::reg(slot + 1, 64)))
            }
            OpKind::Memory => {
                let addr = memory_address(ins)?;
                let high = Expr::bin(BinOp::Add, addr.clone(), Expr::constant(8));
                Some((load_at(addr, 8), load_at(high, 8)))
            }
            _ => None,
        }
    };
    let lanes = |op, bits, a: Expr, b: Expr| Expr::apply(Operation::Lanes(op, bits), vec![a, b]);
    let write = |lifter: &mut Lifter, (low, high): (Expr, Expr)| -> Option<()> {
        let slot = destination?;
        // The high half may read the low one it replaces.
        let high = hold(lifter, high);
        lifter.assign(slot, 64, low);
        lifter.assign(slot + 1, 64, high);
        Some(())
    };
    let lane_op = match ins.mnemonic() {
        Paddb | Paddw | Paddd => Some(LaneOp::Add),
        Psubb | Psubw | Psubd => Some(LaneOp::Sub),
        Pmullw => Some(LaneOp::Mul),
        Pcmpeqb | Pcmpeqw | Pcmpeqd | Pcmpeqq => Some(LaneOp::Equal),
        Pcmpgtb | Pcmpgtw | Pcmpgtd => Some(LaneOp::GreaterSigned),
        Pminub | Pminuw | Pminud => Some(LaneOp::MinUnsigned),
        Pmaxub | Pmaxuw | Pmaxud => Some(LaneOp::MaxUnsigned),
        Pminsb | Pminsw | Pminsd => Some(LaneOp::MinSigned),
        Pmaxsb | Pmaxsw | Pmaxsd => Some(LaneOp::MaxSigned),
        Paddsb | Paddsw => Some(LaneOp::AddSaturatingSigned),
        Paddusb | Paddusw => Some(LaneOp::AddSaturatingUnsigned),
        Psubsb | Psubsw => Some(LaneOp::SubSaturatingSigned),
        Psubusb | Psubusw => Some(LaneOp::SubSaturatingUnsigned),
        Pavgb | Pavgw => Some(LaneOp::Average),
        Pmulhw => Some(LaneOp::MulHighSigned),
        Pmulhuw => Some(LaneOp::MulHighUnsigned),
        _ => None,
    };
    let lane_bits = |mnemonic: Mnemonic| -> u8 {
        let name = format!("{mnemonic:?}");
        match name.chars().last() {
            Some('b') => 8,
            Some('w') => 16,
            Some('d') => 32,
            _ => 64,
        }
    };
    match ins.mnemonic() {
        _ if lane_op.is_some() => {
            let op = lane_op?;
            let bits = lane_bits(ins.mnemonic());
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (lanes(op, bits, a.0, b.0), lanes(op, bits, a.1, b.1)),
            )?;
        }
        // An AES round reads the whole state and key for each half.
        Aesenc | Aesenclast | Aesdec | Aesdeclast => {
            let round = match ins.mnemonic() {
                Aesenc => crate::ir::AesRound::Encrypt,
                Aesenclast => crate::ir::AesRound::EncryptLast,
                Aesdec => crate::ir::AesRound::Decrypt,
                _ => crate::ir::AesRound::DecryptLast,
            };
            let (state, key) = (halves(0)?, halves(1)?);
            let half = |high| {
                Expr::apply(
                    Operation::Aes { round, high },
                    vec![
                        state.0.clone(),
                        state.1.clone(),
                        key.0.clone(),
                        key.1.clone(),
                    ],
                )
            };
            write(lifter, (half(false), half(true)))?;
        }
        // Narrowing two sources' lanes into one register, the first's low.
        Packsswb | Packuswb | Packssdw => {
            let (from, unsigned) = match ins.mnemonic() {
                Packsswb => (16, false),
                Packuswb => (16, true),
                _ => (32, false),
            };
            let (a, b) = (halves(0)?, halves(1)?);
            let pack = |(low, high): (Expr, Expr)| {
                Expr::apply(Operation::Pack { from, unsigned }, vec![low, high])
            };
            write(lifter, (pack(a), pack(b)))?;
        }
        Pmaddwd | Psadbw => {
            let op = if ins.mnemonic() == Pmaddwd {
                Operation::MultiplyAddPairs
            } else {
                Operation::SumAbsoluteDifferences
            };
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (
                    Expr::apply(op, vec![a.0, b.0]),
                    Expr::apply(op, vec![a.1, b.1]),
                ),
            )?;
        }
        Paddq | Psubq | Pmuludq | Pandn => {
            let (a, b) = (halves(0)?, halves(1)?);
            let combine = |x: Expr, y: Expr| match ins.mnemonic() {
                Paddq => Expr::bin(BinOp::Add, x, y),
                Psubq => Expr::bin(BinOp::Sub, x, y),
                // The low 32 bits of each 64-bit lane, multiplied whole.
                Pmuludq => Expr::bin(
                    BinOp::Mul,
                    Expr::bin(BinOp::And, x, Expr::constant(0xffff_ffff)),
                    Expr::bin(BinOp::And, y, Expr::constant(0xffff_ffff)),
                ),
                _ => Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                ),
            };
            write(lifter, (combine(a.0, b.0), combine(a.1, b.1)))?;
        }
        // Shifts of each lane by an immediate or by the low 64 bits of a
        // register.
        Psllw | Pslld | Psllq | Psrlw | Psrld | Psrlq | Psraw | Psrad => {
            let bits = lane_bits(ins.mnemonic());
            let a = halves(0)?;
            let count = match ins.op1_kind() {
                OpKind::Immediate8 => Expr::constant(u64::from(ins.immediate8())),
                _ => halves(1)?.0,
            };
            let op = match ins.mnemonic() {
                Psllw | Pslld | Psllq => LaneOp::ShiftLeft,
                Psrlw | Psrld | Psrlq => LaneOp::ShiftRight,
                _ => LaneOp::ShiftRightSigned,
            };
            let shifted = |half: Expr| {
                if bits == 64 && op != LaneOp::ShiftRightSigned {
                    lanes(op, 64, half, count.clone())
                } else {
                    lanes(op, bits, half, count.clone())
                }
            };
            write(lifter, (shifted(a.0), shifted(a.1)))?;
        }
        // Whole-register byte shifts.
        Pslldq | Psrldq => {
            let (low, high) = halves(0)?;
            let bytes = u64::from(ins.immediate8()).min(16) * 8;
            let result = if ins.mnemonic() == Psrldq {
                let parts = [low, high];
                (window(&parts, bytes), window(&parts, bytes + 64))
            } else {
                let parts = [Expr::constant(0), Expr::constant(0), low, high];
                (window(&parts, 128 - bytes), window(&parts, 192 - bytes))
            };
            write(lifter, result)?;
        }
        Pshufd => {
            let source = halves(1)?;
            let order = u64::from(ins.immediate8());
            let pick = |index: u64| lane_of(&source, (order >> (2 * index)) & 3, 32);
            write(
                lifter,
                (
                    pack(vec![pick(0), pick(1)], 32),
                    pack(vec![pick(2), pick(3)], 32),
                ),
            )?;
        }
        Pshuflw | Pshufhw => {
            let source = halves(1)?;
            let order = u64::from(ins.immediate8());
            let high_half = ins.mnemonic() == Pshufhw;
            let words = if high_half { &source.1 } else { &source.0 };
            let words = (words.clone(), Expr::constant(0));
            let shuffled = pack(
                (0..4)
                    .map(|index| lane_of(&words, (order >> (2 * index)) & 3, 16))
                    .collect(),
                16,
            );
            let result = if high_half {
                (source.0, shuffled)
            } else {
                (shuffled, source.1)
            };
            write(lifter, result)?;
        }
        Punpcklbw | Punpcklwd | Punpckldq | Punpckhbw | Punpckhwd | Punpckhdq => {
            let (a, b) = (halves(0)?, halves(1)?);
            let name = format!("{:?}", ins.mnemonic());
            let bits = match &name[name.len() - 2..] {
                "bw" => 8,
                "wd" => 16,
                _ => 32,
            };
            let (x, y) = if name.starts_with("Punpckh") {
                (a.1, b.1)
            } else {
                (a.0, b.0)
            };
            let interleave = |op| Expr::apply(op, vec![x.clone(), y.clone()]);
            write(
                lifter,
                (
                    interleave(Operation::InterleaveLow(bits)),
                    interleave(Operation::InterleaveHigh(bits)),
                ),
            )?;
        }
        Punpcklqdq | Unpcklpd | Movlhps => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (a.0, b.0))?;
        }
        Punpckhqdq | Unpckhpd => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (a.1, b.1))?;
        }
        Movhlps => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (b.1, a.1))?;
        }
        // The VEX forms on an xmm register write a general one, as these do.
        Pmovmskb | Movmskpd | Movmskps | Vpmovmskb | Vmovmskpd | Vmovmskps => {
            let source = halves(1)?;
            let bits = match ins.mnemonic() {
                Pmovmskb | Vpmovmskb => 8,
                Movmskps | Vmovmskps => 32,
                _ => 64,
            };
            let signs = |half| Expr::apply(Operation::SignBits(bits), vec![half]);
            let mask = Expr::bin(
                BinOp::Or,
                signs(source.0),
                Expr::bin(
                    BinOp::Shl,
                    signs(source.1),
                    Expr::constant(u64::from(64 / bits)),
                ),
            );
            let (index, width) = gpr(ins.op0_register())?;
            lifter.assign(index, width, mask);
        }
        // The first unless the comparison prefers the second, which a NaN
        // on either side makes it.
        Maxpd | Minpd | Maxps | Minps => {
            let single = matches!(ins.mnemonic(), Maxps | Minps);
            let precision = if single {
                Precision::Single
            } else {
                Precision::Double
            };
            let minimum = matches!(ins.mnemonic(), Minpd | Minps);
            let choose = |x: Expr, y: Expr| {
                let (smaller, larger) = if minimum {
                    (x.clone(), y.clone())
                } else {
                    (y.clone(), x.clone())
                };
                Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::apply(
                        Operation::FloatLess(precision),
                        vec![smaller, larger],
                    )),
                    rhs: Box::new(Expr::constant(0)),
                    then: Box::new(x),
                    els: Box::new(y),
                }
            };
            let each = |x: &Expr, y: &Expr| {
                if single {
                    let lane =
                        |half: &Expr, index| lane_of(&(half.clone(), Expr::constant(0)), index, 32);
                    pack(
                        (0..2)
                            .map(|index| choose(lane(x, index), lane(y, index)))
                            .collect(),
                        32,
                    )
                } else {
                    choose(x.clone(), y.clone())
                }
            };
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (each(&a.0, &b.0), each(&a.1, &b.1)))?;
        }
        Andnpd | Andnps => {
            let (a, b) = (halves(0)?, halves(1)?);
            let andn = |x: Expr, y: Expr| {
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                )
            };
            write(lifter, (andn(a.0, b.0), andn(a.1, b.1)))?;
        }
        // Each source's two doubles summed (or subtracted) into one.
        Haddpd | Hsubpd => {
            let op = if ins.mnemonic() == Haddpd {
                Operation::FloatAdd(Precision::Double)
            } else {
                Operation::FloatSub(Precision::Double)
            };
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (
                    Expr::apply(op, vec![a.0, a.1]),
                    Expr::apply(op, vec![b.0, b.1]),
                ),
            )?;
        }
        Addsubpd => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (
                    Expr::apply(Operation::FloatSub(Precision::Double), vec![a.0, b.0]),
                    Expr::apply(Operation::FloatAdd(Precision::Double), vec![a.1, b.1]),
                ),
            )?;
        }
        // Conversions lane by lane, widening from the low half or narrowing
        // into it.
        Cvtdq2pd | Cvtps2pd => {
            let source = halves(1)?;
            let convert = |index| {
                let lane = lane_of(&source, index, 32);
                if ins.mnemonic() == Cvtdq2pd {
                    Expr::apply(
                        Operation::IntToFloat {
                            signed: true,
                            bits: 32,
                            to: Precision::Double,
                        },
                        vec![lane],
                    )
                } else {
                    Expr::apply(
                        Operation::FloatConvert {
                            from: Precision::Single,
                            to: Precision::Double,
                        },
                        vec![lane],
                    )
                }
            };
            write(lifter, (convert(0), convert(1)))?;
        }
        Cvtpd2ps | Cvtpd2dq | Cvttpd2dq => {
            let source = halves(1)?;
            let convert = |half: Expr| match ins.mnemonic() {
                Cvtpd2ps => Expr::apply(
                    Operation::FloatConvert {
                        from: Precision::Double,
                        to: Precision::Single,
                    },
                    vec![half],
                ),
                mnemonic => Expr::apply(
                    Operation::FloatToInt {
                        signed: true,
                        bits: 32,
                        from: Precision::Double,
                        saturating: false,
                        rounding: if mnemonic == Cvttpd2dq {
                            Rounding::TowardZero
                        } else {
                            Rounding::NearestEven
                        },
                    },
                    vec![half],
                ),
            };
            write(
                lifter,
                (
                    pack(vec![convert(source.0), convert(source.1)], 32),
                    Expr::constant(0),
                ),
            )?;
        }
        Cvtdq2ps | Cvtps2dq | Cvttps2dq => {
            let source = halves(1)?;
            let convert = |lane: Expr| match ins.mnemonic() {
                Cvtdq2ps => Expr::apply(
                    Operation::IntToFloat {
                        signed: true,
                        bits: 32,
                        to: Precision::Single,
                    },
                    vec![lane],
                ),
                mnemonic => Expr::apply(
                    Operation::FloatToInt {
                        signed: true,
                        bits: 32,
                        from: Precision::Single,
                        saturating: false,
                        rounding: if mnemonic == Cvttps2dq {
                            Rounding::TowardZero
                        } else {
                            Rounding::NearestEven
                        },
                    },
                    vec![lane],
                ),
            };
            let half = |index: u64| {
                pack(
                    vec![
                        convert(lane_of(&source, index, 32)),
                        convert(lane_of(&source, index + 1, 32)),
                    ],
                    32,
                )
            };
            write(lifter, (half(0), half(2)))?;
        }
        Addpd | Subpd | Mulpd | Divpd | Addps | Subps | Mulps | Divps | Sqrtpd | Sqrtps => {
            let single = matches!(ins.mnemonic(), Addps | Subps | Mulps | Divps | Sqrtps);
            let precision = if single {
                Precision::Single
            } else {
                Precision::Double
            };
            let op = match ins.mnemonic() {
                Addpd | Addps => Operation::FloatAdd(precision),
                Subpd | Subps => Operation::FloatSub(precision),
                Mulpd | Mulps => Operation::FloatMul(precision),
                Divpd | Divps => Operation::FloatDiv(precision),
                _ => Operation::FloatSqrt(precision),
            };
            let unary = matches!(ins.mnemonic(), Sqrtpd | Sqrtps);
            let b = halves(1)?;
            let a = if unary { b.clone() } else { halves(0)? };
            // A double fills a half; singles take its two 32-bit lanes.
            let each = |x: &Expr, y: &Expr| {
                let args = |x: Expr, y: Expr| if unary { vec![y] } else { vec![x, y] };
                if single {
                    let lane =
                        |half: &Expr, index| lane_of(&(half.clone(), Expr::constant(0)), index, 32);
                    pack(
                        (0..2)
                            .map(|index| Expr::apply(op, args(lane(x, index), lane(y, index))))
                            .collect(),
                        32,
                    )
                } else {
                    Expr::apply(op, args(x.clone(), y.clone()))
                }
            };
            write(lifter, (each(&a.0, &b.0), each(&a.1, &b.1)))?;
        }
        _ => return None,
    }
    Some(())
}

/// The scalar SSE floating-point instructions: arithmetic on the low double
/// or single of an xmm register, which keeps the register's other bits,
/// conversions, and the compares that set the flags.
fn lift_float(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let precision = match ins.mnemonic() {
        Addsd | Subsd | Mulsd | Divsd | Sqrtsd | Minsd | Maxsd | Ucomisd | Comisd | Cvtsi2sd
        | Cvttsd2si | Cvtsd2si | Cvtsd2ss | Roundsd => Precision::Double,
        Addss | Subss | Mulss | Divss | Sqrtss | Minss | Maxss | Ucomiss | Comiss | Cvtsi2ss
        | Cvttss2si | Cvtss2si | Cvtss2sd | Roundss => Precision::Single,
        _ => return None,
    };
    // An xmm operand's low bits, or a value loaded from memory.
    let float_operand = |index: u32, precision: Precision| -> Option<Expr> {
        match ins.op_kind(index) {
            OpKind::Register => {
                let slot = xmm(ins.op_register(index))?;
                Some(Lifter::read_reg(slot, precision.bits()))
            }
            OpKind::Memory => Some(load_at(memory_address(ins)?, precision.bits() / 8)),
            _ => None,
        }
    };
    // The low bits of the destination receive `value`; the rest stay.
    let write_low = |lifter: &mut Lifter, value: Expr, precision: Precision| -> Option<()> {
        let slot = xmm(ins.op0_register())?;
        let merged = match precision {
            Precision::Double => value,
            Precision::Single => Expr::bin(
                BinOp::Or,
                Expr::bin(
                    BinOp::And,
                    Lifter::read_reg(slot, 64),
                    Expr::constant(!0xffff_ffff),
                ),
                value,
            ),
        };
        lifter.assign(slot, 64, merged);
        Some(())
    };
    match ins.mnemonic() {
        Addsd | Addss | Subsd | Subss | Mulsd | Mulss | Divsd | Divss => {
            let op = match ins.mnemonic() {
                Addsd | Addss => Operation::FloatAdd(precision),
                Subsd | Subss => Operation::FloatSub(precision),
                Mulsd | Mulss => Operation::FloatMul(precision),
                _ => Operation::FloatDiv(precision),
            };
            let (a, b) = (float_operand(0, precision)?, float_operand(1, precision)?);
            write_low(lifter, Expr::apply(op, vec![a, b]), precision)?;
        }
        Sqrtsd | Sqrtss => {
            let a = float_operand(1, precision)?;
            write_low(
                lifter,
                Expr::apply(Operation::FloatSqrt(precision), vec![a]),
                precision,
            )?;
        }
        // The second operand unless the first is strictly smaller (larger),
        // which a NaN or two zeros never are.
        Minsd | Minss | Maxsd | Maxss => {
            let (a, b) = (float_operand(0, precision)?, float_operand(1, precision)?);
            let (smaller, larger) = if matches!(ins.mnemonic(), Minsd | Minss) {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            };
            let first = Expr::Select {
                cond: Cond::Ne,
                lhs: Box::new(Expr::apply(
                    Operation::FloatLess(precision),
                    vec![smaller, larger],
                )),
                rhs: Box::new(Expr::constant(0)),
                then: Box::new(a),
                els: Box::new(b),
            };
            write_low(lifter, first, precision)?;
        }
        Ucomisd | Comisd | Ucomiss | Comiss => {
            let (a, b) = (float_operand(0, precision)?, float_operand(1, precision)?);
            lifter.set_flags(Flags::float_compare(a, b, precision));
        }
        Cvtsi2sd | Cvtsi2ss => {
            let bits = operand_width(ins, 1)?;
            let value = operand(lifter, ins, 1)?;
            let converted = Expr::apply(
                Operation::IntToFloat {
                    signed: true,
                    bits,
                    to: precision,
                },
                vec![value],
            );
            write_low(lifter, converted, precision)?;
        }
        // The rounding ones round as the default mode does.
        Cvttsd2si | Cvttss2si | Cvtsd2si | Cvtss2si => {
            let (index, bits) = gpr(ins.op0_register())?;
            let value = float_operand(1, precision)?;
            let rounding = match ins.mnemonic() {
                Cvttsd2si | Cvttss2si => Rounding::TowardZero,
                _ => Rounding::NearestEven,
            };
            let converted = Expr::apply(
                Operation::FloatToInt {
                    signed: true,
                    bits,
                    from: precision,
                    saturating: false,
                    rounding,
                },
                vec![value],
            );
            lifter.assign(index, bits, converted);
        }
        // The immediate names the rounding, or with bit 2 the current mode.
        Roundsd | Roundss => {
            let value = float_operand(1, precision)?;
            let rounding = match ins.immediate8() {
                mode if mode & 4 != 0 => Rounding::NearestEven,
                mode => match mode & 3 {
                    0 => Rounding::NearestEven,
                    1 => Rounding::Down,
                    2 => Rounding::Up,
                    _ => Rounding::TowardZero,
                },
            };
            let rounded = Expr::apply(Operation::FloatRound(precision, rounding), vec![value]);
            write_low(lifter, rounded, precision)?;
        }
        Cvtsd2ss | Cvtss2sd => {
            let to = match precision {
                Precision::Double => Precision::Single,
                Precision::Single => Precision::Double,
            };
            let value = float_operand(1, precision)?;
            let converted = Expr::apply(
                Operation::FloatConvert {
                    from: precision,
                    to,
                },
                vec![value],
            );
            write_low(lifter, converted, to)?;
        }
        _ => return None,
    }
    Some(())
}

/// The vector moves and bitwise operations: on the halves of an xmm
/// register, or the quarters of a ymm one. A VEX instruction that writes an
/// xmm register clears the bits above it. None, with nothing lifted, for
/// any other instruction.
fn lift_vector(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use crate::arch::x86::upper;
    let clear_upper = |lifter: &mut Lifter, slot: u16| {
        lifter.assign(upper(slot), 64, Expr::constant(0));
        lifter.assign(upper(slot) + 1, 64, Expr::constant(0));
    };
    match ins.mnemonic() {
        Mnemonic::Vzeroupper => {
            for register in 0..16 {
                clear_upper(lifter, crate::arch::x86::XMM0 + 2 * register);
            }
            return Some(());
        }
        Mnemonic::Vzeroall => {
            for register in 0..16 {
                let slot = crate::arch::x86::XMM0 + 2 * register;
                lifter.assign(slot, 64, Expr::constant(0));
                lifter.assign(slot + 1, 64, Expr::constant(0));
                clear_upper(lifter, slot);
            }
            return Some(());
        }
        _ => {}
    }
    if (0..ins.op_count()).any(|index| {
        ins.op_kind(index) == OpKind::Register
            && (ins.op_register(index).is_ymm() || ins.op_register(index).is_zmm())
    }) {
        return lift_ymm(lifter, ins);
    }
    lift_xmm(lifter, ins)?;
    if ins.encoding() != EncodingKind::Legacy
        && ins.op0_kind() == OpKind::Register
        && let Some(slot) = xmm(ins.op0_register())
    {
        clear_upper(lifter, slot);
    }
    Some(())
}

/// The ymm register's slots, lowest quarter first.
fn ymm(reg: Register) -> Option<[u16; 4]> {
    (reg.is_ymm() && reg.number() < 16).then(|| {
        let low = crate::arch::x86::XMM0 + 2 * reg.number() as u16;
        let high = crate::arch::x86::upper(low);
        [low, low + 1, high, high + 1]
    })
}

/// The 256-bit moves, bitwise operations and byte compares, each quarter
/// from the same quarter of the sources.
fn lift_ymm(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    // The quarters of a ymm operand or of the 32 bytes at a memory one.
    let quarters = |index: u32| -> Option<[Expr; 4]> {
        match ins.op_kind(index) {
            OpKind::Register => {
                Some(ymm(ins.op_register(index))?.map(|slot| Lifter::read_reg(slot, 64)))
            }
            OpKind::Memory => {
                let addr = memory_address(ins)?;
                Some(std::array::from_fn(|quarter| {
                    load_at(
                        Expr::bin(BinOp::Add, addr.clone(), Expr::constant(8 * quarter as u64)),
                        8,
                    )
                }))
            }
            _ => None,
        }
    };
    let write = |lifter: &mut Lifter, values: [Expr; 4]| -> Option<()> {
        let slots = ymm(ins.op0_register())?;
        for (slot, value) in slots.into_iter().zip(values) {
            lifter.assign(slot, 64, value);
        }
        Some(())
    };
    match ins.mnemonic() {
        Vmovdqu | Vmovdqu8 | Vmovdqu16 | Vmovdqu32 | Vmovdqu64 | Vmovdqa | Vmovdqa32
        | Vmovdqa64 | Vmovntdq | Vmovups | Vmovaps | Vmovupd | Vmovapd | Vmovntps | Vmovntpd
        | Vlddqu => match ins.op0_kind() {
            OpKind::Memory => {
                let addr = memory_address(ins)?;
                let values = quarters(1)?;
                preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
                for (quarter, value) in values.into_iter().enumerate() {
                    lifter.stmts.push(Stmt::Store {
                        addr: Expr::bin(
                            BinOp::Add,
                            addr.clone(),
                            Expr::constant(8 * quarter as u64),
                        ),
                        value,
                        width: 8,
                    });
                }
            }
            _ => write(lifter, quarters(1)?)?,
        },
        Vpxor | Vpand | Vpor | Vpandn | Vxorps | Vxorpd | Vandps | Vandpd | Vorps | Vorpd
        | Vpcmpeqb | Vpcmpeqw | Vpcmpeqd | Vpcmpeqq | Vpaddb | Vpaddw | Vpaddd | Vpaddq
        | Vpsubb | Vpsubw | Vpsubd | Vpsubq | Vpminub | Vpmaxub
            if ins.op_count() == 3 =>
        {
            let (a, b) = (quarters(1)?, quarters(2)?);
            let mnemonic = ins.mnemonic();
            let combine = |x: Expr, y: Expr| match mnemonic {
                Vpxor | Vxorps | Vxorpd => Expr::bin(BinOp::Xor, x, y),
                Vpand | Vandps | Vandpd => Expr::bin(BinOp::And, x, y),
                Vpandn => Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                ),
                Vpor | Vorps | Vorpd => Expr::bin(BinOp::Or, x, y),
                Vpaddq => Expr::bin(BinOp::Add, x, y),
                Vpsubq => Expr::bin(BinOp::Sub, x, y),
                other => {
                    let (op, bits) = match other {
                        Vpcmpeqb => (LaneOp::Equal, 8),
                        Vpcmpeqw => (LaneOp::Equal, 16),
                        Vpcmpeqd => (LaneOp::Equal, 32),
                        Vpcmpeqq => (LaneOp::Equal, 64),
                        Vpaddb => (LaneOp::Add, 8),
                        Vpaddw => (LaneOp::Add, 16),
                        Vpaddd => (LaneOp::Add, 32),
                        Vpsubb => (LaneOp::Sub, 8),
                        Vpsubw => (LaneOp::Sub, 16),
                        Vpsubd => (LaneOp::Sub, 32),
                        Vpminub => (LaneOp::MinUnsigned, 8),
                        _ => (LaneOp::MaxUnsigned, 8),
                    };
                    Expr::apply(Operation::Lanes(op, bits), vec![x, y])
                }
            };
            let [a0, a1, a2, a3] = a;
            let [b0, b1, b2, b3] = b;
            write(
                lifter,
                [
                    combine(a0, b0),
                    combine(a1, b1),
                    combine(a2, b2),
                    combine(a3, b3),
                ],
            )?;
        }
        // The top bit of each byte, lowest byte first.
        Vpmovmskb => {
            let (index, width) = gpr(ins.op0_register())?;
            let [q0, q1, q2, q3] = quarters(1)?;
            let mask = |quarter: Expr, shift: u64| {
                Expr::bin(
                    BinOp::Shl,
                    Expr::apply(Operation::SignBits(8), vec![quarter]),
                    Expr::constant(shift),
                )
            };
            let value = [mask(q1, 8), mask(q2, 16), mask(q3, 24)].into_iter().fold(
                Expr::apply(Operation::SignBits(8), vec![q0]),
                |sum, part| Expr::bin(BinOp::Or, sum, part),
            );
            lifter.assign(index, width, value);
        }
        // The low byte of the source in every byte.
        Vpbroadcastb => {
            let byte = match ins.op1_kind() {
                OpKind::Register => Lifter::read_reg(xmm(ins.op1_register())?, 64),
                OpKind::Memory => load_at(memory_address(ins)?, 1),
                _ => return None,
            };
            let spread = Expr::bin(
                BinOp::Mul,
                Expr::bin(BinOp::And, byte, Expr::constant(0xff)),
                Expr::constant(0x0101_0101_0101_0101),
            );
            write(lifter, std::array::from_fn(|_| spread.clone()))?;
        }
        _ => return None,
    }
    Some(())
}

/// The SSE moves and bitwise operations, on the 64-bit halves of each xmm
/// register. None, with nothing lifted, for any other instruction.
fn lift_xmm(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let destination = xmm(ins.op0_register());
    let source = xmm(ins.op1_register());
    let address = || memory_address(ins);
    let offset = |addr: Expr| Expr::bin(BinOp::Add, addr, Expr::constant(8));
    let low = |slot: u16| Lifter::read_reg(slot, 64);
    let store = |lifter: &mut Lifter, addr: Expr, value: Expr, width: u8| {
        preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
        lifter.stmts.push(Stmt::Store { addr, value, width });
    };
    // A VEX move of a 128-bit register, or a non-temporal one, moves as the
    // plain one does; the IR keeps no bits above 128.
    let narrow = (0..ins.op_count()).all(|index| {
        ins.op_kind(index) != OpKind::Register
            || !ins.op_register(index).is_ymm() && !ins.op_register(index).is_zmm()
    });
    let mnemonic = match ins.mnemonic() {
        Vmovdqu | Vmovdqu8 | Vmovdqu16 | Vmovdqu32 | Vmovdqu64 if narrow => Movdqu,
        Vmovdqa | Vmovdqa32 | Vmovdqa64 | Vmovntdq | Movntdq if narrow => Movdqa,
        Vmovups if narrow => Movups,
        Vmovaps | Vmovntps | Movntps if narrow => Movaps,
        Vmovupd if narrow => Movupd,
        Vmovapd | Vmovntpd | Movntpd if narrow => Movapd,
        other => other,
    };
    match (mnemonic, ins.op0_kind(), ins.op1_kind()) {
        // A VEX bitwise operation names two sources apart from its destination.
        (
            Vpxor | Vpand | Vpor | Vpandn | Vxorps | Vxorpd | Vandps | Vandpd | Vorps | Vorpd,
            OpKind::Register,
            OpKind::Register,
        ) if narrow && ins.op_count() == 3 => {
            let (to, first) = (destination?, source?);
            let (second_low, second_high) = match ins.op2_kind() {
                OpKind::Register => {
                    let slot = xmm(ins.op2_register())?;
                    (low(slot), low(slot + 1))
                }
                OpKind::Memory => {
                    let addr = address()?;
                    (load_at(addr.clone(), 8), load_at(offset(addr), 8))
                }
                _ => return None,
            };
            let combine = |a: Expr, b: Expr| match mnemonic {
                Vpxor | Vxorps | Vxorpd => Expr::bin(BinOp::Xor, a, b),
                Vpand | Vandps | Vandpd => Expr::bin(BinOp::And, a, b),
                Vpandn => Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, a, Expr::constant(u64::MAX)),
                    b,
                ),
                _ => Expr::bin(BinOp::Or, a, b),
            };
            let low_half = combine(low(first), second_low);
            let high_half = hold(lifter, combine(low(first + 1), second_high));
            lifter.assign(to, 64, low_half);
            lifter.assign(to + 1, 64, high_half);
        }
        // One 16-bit lane written from a general register or memory, or read
        // out to a general register.
        (Pinsrw | Vpinsrw, OpKind::Register, _) if narrow => {
            let to = destination?;
            let value_index = if mnemonic == Vpinsrw { 2 } else { 1 };
            let value = match ins.op_kind(value_index) {
                OpKind::Memory => load_at(address()?, 2),
                _ => operand(lifter, ins, value_index)?,
            };
            let lane = u64::from(ins.immediate8()) & 7;
            let (slot, shift) = (to + (lane / 4) as u16, (lane % 4) * 16);
            let base = if mnemonic == Vpinsrw {
                low(source? + (lane / 4) as u16)
            } else {
                low(slot)
            };
            let merged = Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::And, base, Expr::constant(!(0xffff << shift))),
                Expr::bin(
                    BinOp::Shl,
                    Expr::bin(BinOp::And, value, Expr::constant(0xffff)),
                    Expr::constant(shift),
                ),
            );
            if mnemonic == Vpinsrw {
                let from = source?;
                let other = hold(lifter, low(from + 1 - (lane / 4) as u16));
                lifter.assign(slot, 64, merged);
                lifter.assign(to + 1 - (lane / 4) as u16, 64, other);
            } else {
                lifter.assign(slot, 64, merged);
            }
        }
        (Pextrw | Vpextrw, OpKind::Register, OpKind::Register) if narrow && source.is_some() => {
            let from = source?;
            let lane = u64::from(ins.immediate8()) & 7;
            let value = Expr::bin(
                BinOp::And,
                Expr::bin(
                    BinOp::Shr,
                    low(from + (lane / 4) as u16),
                    Expr::constant((lane % 4) * 16),
                ),
                Expr::constant(0xffff),
            );
            let (index, width) = gpr(ins.op0_register())?;
            lifter.assign(index, width, value);
        }
        (
            Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa,
            OpKind::Register,
            OpKind::Register,
        ) => {
            let (to, from) = (destination?, source?);
            lifter.assign(to, 64, low(from));
            lifter.assign(to + 1, 64, low(from + 1));
        }
        (Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa, OpKind::Register, OpKind::Memory) => {
            let (to, addr) = (destination?, address()?);
            lifter.assign(to, 64, load_at(addr.clone(), 8));
            lifter.assign(to + 1, 64, load_at(offset(addr), 8));
        }
        (Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa, OpKind::Memory, OpKind::Register) => {
            let (from, addr) = (source?, address()?);
            store(lifter, addr.clone(), low(from), 8);
            store(lifter, offset(addr), low(from + 1), 8);
        }
        (Xorps | Xorpd | Pxor | Andps | Andpd | Pand | Orps | Orpd | Por, OpKind::Register, _) => {
            let to = destination?;
            let op = match ins.mnemonic() {
                Xorps | Xorpd | Pxor => BinOp::Xor,
                Andps | Andpd | Pand => BinOp::And,
                _ => BinOp::Or,
            };
            let (first, second) = match ins.op1_kind() {
                OpKind::Register => {
                    let from = source?;
                    (low(from), low(from + 1))
                }
                OpKind::Memory => {
                    let addr = address()?;
                    (load_at(addr.clone(), 8), load_at(offset(addr), 8))
                }
                _ => return None,
            };
            let cleared =
                op == BinOp::Xor && ins.op1_kind() == OpKind::Register && source == destination;
            let combine = |slot: u16, value: Expr| {
                if cleared {
                    Expr::constant(0)
                } else {
                    Expr::bin(op, low(slot), value)
                }
            };
            let (first, second) = (combine(to, first), combine(to + 1, second));
            lifter.assign(to, 64, first);
            lifter.assign(to + 1, 64, second);
        }
        // A scalar load clears the rest of the register; a move between
        // registers keeps it.
        (Movq | Movd | Movsd | Movss, OpKind::Register, OpKind::Register | OpKind::Memory)
            if destination.is_some() =>
        {
            let to = destination?;
            let width = match ins.mnemonic() {
                Movd | Movss => 4,
                _ => 8,
            };
            let value = match (ins.op1_kind(), source) {
                (OpKind::Memory, _) => load_at(address()?, width),
                (_, Some(from)) => Lifter::read_reg(from, width * 8),
                (_, None) => operand(lifter, ins, 1)?,
            };
            let keeps = source.is_some() && matches!(ins.mnemonic(), Movsd | Movss);
            let value = if keeps && width == 4 {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, low(to), Expr::constant(!0xffff_ffff)),
                    value,
                )
            } else {
                value
            };
            lifter.assign(to, 64, value);
            if !keeps {
                lifter.assign(to + 1, 64, Expr::constant(0));
            }
        }
        (Movq | Movd | Movsd | Movss, OpKind::Register | OpKind::Memory, OpKind::Register)
            if source.is_some() =>
        {
            let from = source?;
            let width = match ins.mnemonic() {
                Movd | Movss => 4,
                _ => 8,
            };
            let value = Lifter::read_reg(from, width * 8);
            match ins.op0_kind() {
                OpKind::Memory => store(lifter, address()?, value, width),
                _ => {
                    let (index, register_width) = gpr(ins.op0_register())?;
                    lifter.assign(index, register_width, value);
                }
            }
        }
        _ => return None,
    }
    Some(())
}

fn load(ins: &Instruction) -> Option<Expr> {
    Some(Expr::Load {
        addr: Box::new(memory_address(ins)?),
        width: memory_width(ins)?,
        signed: false,
    })
}

fn immediate(ins: &Instruction, index: u32) -> Option<Expr> {
    let value = match ins.op_kind(index) {
        OpKind::Immediate8 => ins.immediate8() as u64,
        OpKind::Immediate8_2nd => ins.immediate8_2nd() as u64,
        OpKind::Immediate8to16 => ins.immediate8to16() as u16 as u64,
        OpKind::Immediate8to32 => ins.immediate8to32() as i64 as u64,
        OpKind::Immediate8to64 => ins.immediate8to64() as u64,
        OpKind::Immediate16 => ins.immediate16() as u64,
        OpKind::Immediate32 => ins.immediate32() as u64,
        OpKind::Immediate32to64 => ins.immediate32to64() as u64,
        OpKind::Immediate64 => ins.immediate64(),
        OpKind::NearBranch64 => ins.near_branch_target(),
        _ => return None,
    };
    Some(Expr::constant(value))
}

fn operand(lifter: &mut Lifter, ins: &Instruction, index: u32) -> Option<Expr> {
    let value = match ins.op_kind(index) {
        OpKind::Register => {
            let register = ins.op_register(index);
            if register == Register::None {
                return None;
            }
            match (gpr(register), high_byte(register)) {
                (Some((register, width)), _) => Some(Lifter::read_reg(register, width)),
                (None, Some(register)) => Some(Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Shr, Expr::reg(register, 64), Expr::constant(8)),
                    Expr::constant(0xff),
                )),
                _ => None,
            }
        }
        OpKind::Memory => load(ins),
        _ if index >= ins.op_count() => return None,
        _ => immediate(ins, index),
    };
    if value.is_none() {
        lifter.incomplete = true;
    }
    value
}

fn write_destination(lifter: &mut Lifter, ins: &Instruction, value: Expr) {
    write_operand(lifter, ins, 0, value);
}

fn write_operand(lifter: &mut Lifter, ins: &Instruction, index: u32, value: Expr) {
    match ins.op_kind(index) {
        OpKind::Register => {
            let register = ins.op_register(index);
            match (gpr(register), high_byte(register)) {
                (Some((index, width)), _) => lifter.assign(index, width, value),
                // The second byte replaces bits 8..16 and keeps the rest.
                (None, Some(index)) => {
                    let kept = Expr::bin(BinOp::And, Expr::reg(index, 64), Expr::constant(!0xff00));
                    let placed = Expr::bin(
                        BinOp::Shl,
                        Expr::bin(BinOp::And, value, Expr::constant(0xff)),
                        Expr::constant(8),
                    );
                    lifter.assign(index, 64, Expr::bin(BinOp::Or, kept, placed));
                }
                _ => lifter.incomplete = true,
            }
        }
        OpKind::Memory => {
            if let (Some(addr), Some(width)) = (memory_address(ins), memory_width(ins)) {
                preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
                lifter.stmts.push(Stmt::Store { addr, value, width });
            } else {
                lifter.incomplete = true;
            }
        }
        _ => lifter.incomplete = true,
    }
}

/// The width in bits of a general register or memory operand.
fn operand_width(ins: &Instruction, index: u32) -> Option<u8> {
    match ins.op_kind(index) {
        OpKind::Register if high_byte(ins.op_register(index)).is_some() => Some(8),
        OpKind::Register => gpr(ins.op_register(index)).map(|(_, width)| width),
        OpKind::Memory => memory_width(ins).map(|bytes| bytes * 8),
        _ => None,
    }
}

/// Copies `value` into the exchange register, for an instruction that
/// overwrites what it read before writing it elsewhere.
/// A division of the dividend in rdx:rax (or ah:al for bytes) by `divisor`
/// of `width` bits: the quotient into rax (al) and the remainder into rdx
/// (ah).
fn wide_divide(lifter: &mut Lifter, signed: bool, width: u8, divisor: Expr) {
    let divide = |remainder, high: Expr, low: Expr| {
        Expr::apply(
            Operation::WideDivide {
                signed,
                remainder,
                bits: width,
            },
            vec![high, low, divisor.clone()],
        )
    };
    if width == 8 {
        let ax = Lifter::read_reg(RAX, 16);
        let high = Expr::bin(BinOp::Shr, ax.clone(), Expr::constant(8));
        let low = Expr::bin(BinOp::And, ax, Expr::constant(0xff));
        let quotient = divide(false, high.clone(), low.clone());
        let remainder = divide(true, high, low);
        // ax takes the remainder above the quotient.
        let joined = Expr::bin(
            BinOp::Or,
            Expr::bin(BinOp::Shl, remainder, Expr::constant(8)),
            quotient,
        );
        lifter.assign(RAX, 16, joined);
        return;
    }
    let (high, low) = (Lifter::read_reg(RDX, width), Lifter::read_reg(RAX, width));
    let quotient = divide(false, high.clone(), low.clone());
    // Both read the dividend, so the quotient waits while rdx changes.
    let quotient = hold(lifter, quotient);
    lifter.assign(RDX, width, divide(true, high, low));
    lifter.assign(RAX, width, quotient);
}

fn hold(lifter: &mut Lifter, value: Expr) -> Expr {
    preserve_compare(
        &mut lifter.last_compare,
        Write::Register(EXCHANGE, None),
        &mut lifter.stmts,
    );
    lifter.stmts.push(Stmt::Assign {
        dest: RegRef {
            index: EXCHANGE,
            width: 64,
        },
        value,
    });
    Expr::reg(EXCHANGE, 64)
}

/// `xchg`, `xadd` and `cmpxchg`, whose destination is the first operand
/// (the memory one, if any) and whose source register receives the old value.
fn lift_exchange(lifter: &mut Lifter, ins: &Instruction) {
    let (Some(current), Some(source), Some(width)) = (
        operand(lifter, ins, 0),
        operand(lifter, ins, 1),
        operand_width(ins, 0),
    ) else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        )));
        return;
    };
    let same_register = ins.op0_kind() == OpKind::Register
        && ins.op1_kind() == OpKind::Register
        && ins.op0_register() == ins.op1_register();
    match ins.mnemonic() {
        Mnemonic::Xchg if same_register => {}
        Mnemonic::Xchg => {
            let old = hold(lifter, current);
            write_operand(lifter, ins, 0, source);
            write_operand(lifter, ins, 1, old);
        }
        Mnemonic::Xadd if same_register => {
            lifter.set_flags(Flags::sum(current.clone(), source.clone()));
            let sum = Expr::bin(BinOp::Add, current, source);
            write_destination(lifter, ins, sum);
        }
        Mnemonic::Xadd => {
            let old = hold(lifter, current);
            lifter.set_flags(Flags::sum(old.clone(), source.clone()));
            let sum = Expr::bin(BinOp::Add, old.clone(), source);
            write_destination(lifter, ins, sum);
            write_operand(lifter, ins, 1, old);
        }
        // The destination receives the source if it held the accumulator,
        // and the accumulator receives the destination if it did not.
        _ => {
            let expected = Lifter::read_reg(RAX, width);
            let old = hold(lifter, current);
            let select = |then: Expr, els: Expr| Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(old.clone()),
                rhs: Box::new(expected.clone()),
                then: Box::new(then),
                els: Box::new(els),
            };
            write_destination(lifter, ins, select(source, old.clone()));
            // The flags compare the accumulator with the old value.
            lifter.set_flags(Flags::difference(expected.clone(), old.clone()));
            let mismatch = if width >= 32 {
                old.clone()
            } else {
                let mask = (1u64 << width) - 1;
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(RAX, 64), Expr::constant(!mask)),
                    old.clone(),
                )
            };
            lifter.assign(RAX, 64, select(Expr::reg(RAX, 64), mismatch));
        }
    }
}

/// `rol`, `ror`, `rcl`, `rcr`, `shld`, `shrd`, `bswap` and `bt`.
fn lift_bits(lifter: &mut Lifter, ins: &Instruction) {
    let (Some(value), Some(width)) = (operand(lifter, ins, 0), operand_width(ins, 0)) else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        )));
        return;
    };
    let bits = u64::from(width);
    match ins.mnemonic() {
        // The result of swapping a 16-bit register is undefined.
        Mnemonic::Bswap if width == 16 => lifter.stmts.push(Stmt::unsupported(format!(
            "bswap of a 16-bit register at 0x{:x}",
            ins.ip()
        ))),
        Mnemonic::Bswap => {
            let swapped = super::reverse_bytes(value, width, width / 8);
            write_destination(lifter, ins, swapped);
        }
        // A rotate through the carry by one, with the carry known: the
        // carry comes in at one end and the bit at the other goes out to it.
        Mnemonic::Rcl | Mnemonic::Rcr
            if matches!(operand(lifter, ins, 1), Some(Expr::Const(1)))
                && lifter.carry().is_some() =>
        {
            let carry = lifter.carry().expect("a known carry");
            let (rotated, out) = if ins.mnemonic() == Mnemonic::Rcr {
                (
                    Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::Shr, value.clone(), Expr::constant(1)),
                        Expr::bin(BinOp::Shl, carry, Expr::constant(bits - 1)),
                    ),
                    Expr::bin(BinOp::And, value, Expr::constant(1)),
                )
            } else {
                (
                    Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::Shl, value.clone(), Expr::constant(1)),
                        carry,
                    ),
                    Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Shr, value, Expr::constant(bits - 1)),
                        Expr::constant(1),
                    ),
                )
            };
            let rotated = if bits == 64 {
                rotated
            } else {
                Expr::bin(BinOp::And, rotated, Expr::constant((1u64 << bits) - 1))
            };
            lifter.set_flags(Flags::carry(out));
            write_destination(lifter, ins, rotated);
        }
        Mnemonic::Rcl | Mnemonic::Rcr => lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        ))),
        Mnemonic::Rol | Mnemonic::Ror => {
            let Some(amount) = operand(lifter, ins, 1) else {
                return;
            };
            let amount = shift_count(amount, width);
            let right = ins.mnemonic() == Mnemonic::Ror;
            write_destination(lifter, ins, super::rotate(value, amount, width, right));
        }
        // A bit string in memory may lie past the addressed operand.
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
            if ins.op0_kind() == OpKind::Memory && ins.op1_kind() == OpKind::Register =>
        {
            lifter
                .stmts
                .push(Stmt::unsupported(format!("bt at 0x{:x}", ins.ip())));
        }
        // The carry holds the bit; zero is left as it was. bts, btr and btc
        // then set, clear or flip it.
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            let Some(bit) = operand(lifter, ins, 1) else {
                return;
            };
            let bit = Expr::bin(BinOp::And, bit, Expr::constant(bits - 1));
            let flag = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, value.clone(), bit.clone()),
                Expr::constant(1),
            );
            lifter.set_flags(Flags::carry(flag));
            let single = Expr::bin(BinOp::Shl, Expr::constant(1), bit);
            let changed = match ins.mnemonic() {
                Mnemonic::Bts => Expr::bin(BinOp::Or, value, single),
                Mnemonic::Btr => Expr::bin(
                    BinOp::And,
                    value,
                    Expr::bin(BinOp::Xor, single, Expr::constant(u64::MAX)),
                ),
                Mnemonic::Btc => Expr::bin(BinOp::Xor, value, single),
                _ => return,
            };
            write_destination(lifter, ins, changed);
        }
        _ => {
            let (Some(source), Some(count)) = (operand(lifter, ins, 1), operand(lifter, ins, 2))
            else {
                return;
            };
            if width < 32 {
                lifter.stmts.push(Stmt::unsupported(format!(
                    "{:?} at 0x{:x}",
                    ins.mnemonic(),
                    ins.ip()
                )));
                return;
            }
            let (towards, from) = match ins.mnemonic() {
                Mnemonic::Shld => (BinOp::Shl, BinOp::Shr),
                _ => (BinOp::Shr, BinOp::Shl),
            };
            let shifted = |amount: Expr, back: Expr| {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(towards, value.clone(), amount),
                    Expr::bin(from, source.clone(), back),
                )
            };
            lifter.last_compare = None;
            let value = match count {
                Expr::Const(count) => match count & (bits - 1) {
                    0 => return,
                    count => shifted(Expr::constant(count), Expr::constant(bits - count)),
                },
                count => {
                    let count = Expr::bin(BinOp::And, count, Expr::constant(bits - 1));
                    Expr::Select {
                        cond: Cond::Eq,
                        lhs: Box::new(count.clone()),
                        rhs: Box::new(Expr::constant(0)),
                        then: Box::new(value.clone()),
                        els: Box::new(shifted(
                            count.clone(),
                            Expr::bin(BinOp::Sub, Expr::constant(bits), count),
                        )),
                    }
                }
            };
            write_destination(lifter, ins, value);
        }
    }
}

/// One-operand `mul` and `imul`: the accumulator times the operand, with
/// the product's low half in the accumulator and its high half in rdx (edx,
/// dx), or the whole product in ax for bytes.
fn lift_mul_high(lifter: &mut Lifter, ins: &Instruction, signed: bool) {
    let (Some(source), Some(width)) = (operand(lifter, ins, 0), operand_width(ins, 0)) else {
        lifter.incomplete = true;
        return;
    };
    let multiplicand = Lifter::read_reg(RAX, width);
    if width == 64 {
        // The operand may be rdx, which the high half overwrites first.
        let source = hold(lifter, source);
        let high_op = if signed {
            BinOp::MulHighS
        } else {
            BinOp::MulHigh
        };
        lifter.assign(
            RDX,
            64,
            Expr::bin(high_op, multiplicand.clone(), source.clone()),
        );
        lifter.assign(RAX, 64, Expr::bin(BinOp::Mul, multiplicand, source));
        lifter.set_flags(Flags::carry_overflow(lost_high(RDX, RAX, 64, signed)));
        return;
    }
    let widen = |value: Expr| {
        if signed {
            Expr::SignExtend {
                value: Box::new(value),
                width: width / 8,
            }
        } else {
            value
        }
    };
    let product = Expr::bin(BinOp::Mul, widen(multiplicand), widen(source));
    if width == 8 {
        lifter.assign(RAX, 16, product);
        // ah against what al's sign (or zero) would put there.
        let ax = Lifter::read_reg(RAX, 16);
        let low = Expr::bin(BinOp::And, ax.clone(), Expr::constant(0xff));
        let expected = if signed {
            Expr::SignExtend {
                value: Box::new(low),
                width: 1,
            }
        } else {
            low
        };
        let lost = Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Xor, ax, expected),
            Expr::constant(0xffff),
        );
        lifter.set_flags(Flags::carry_overflow(lost));
        return;
    }
    let product = hold(lifter, product);
    lifter.assign(
        RDX,
        width,
        Expr::bin(
            BinOp::Shr,
            product.clone(),
            Expr::constant(u64::from(width)),
        ),
    );
    lifter.assign(RAX, width, product);
    lifter.set_flags(Flags::carry_overflow(lost_high(RDX, RAX, width, signed)));
}

/// Nonzero when the signed product of `a` and `b` does not fit in `width`
/// bits: the full product against its truncation, sign-extended.
fn signed_product_lost(a: &Expr, b: &Expr, width: u8) -> Expr {
    if width == 64 {
        let product = Expr::bin(BinOp::Mul, a.clone(), b.clone());
        return Expr::bin(
            BinOp::Xor,
            Expr::bin(BinOp::MulHighS, a.clone(), b.clone()),
            Expr::bin(BinOp::Sar, product, Expr::constant(63)),
        );
    }
    let extend = |value: Expr, bytes: u8| Expr::SignExtend {
        value: Box::new(value),
        width: bytes,
    };
    let bytes = width / 8;
    let full = Expr::bin(
        BinOp::Mul,
        extend(a.clone(), bytes),
        extend(b.clone(), bytes),
    );
    let truncated = Expr::bin(
        BinOp::And,
        full.clone(),
        Expr::constant((1u64 << width) - 1),
    );
    Expr::bin(BinOp::Xor, full, extend(truncated, bytes))
}

/// What a multiply's high half `high` holds beyond what its low half
/// `low` implies, zero or its sign: nonzero when the product did not fit.
fn lost_high(high: u16, low: u16, width: u8, signed: bool) -> Expr {
    let high = Lifter::read_reg(high, width);
    let expected = if signed {
        Expr::bin(
            BinOp::Sar,
            Lifter::read_reg(low, width),
            Expr::constant(u64::from(width) - 1),
        )
    } else {
        Expr::constant(0)
    };
    let lost = Expr::bin(BinOp::Xor, high, expected);
    if width == 64 {
        lost
    } else {
        Expr::bin(BinOp::And, lost, Expr::constant((1u64 << width) - 1))
    }
}

fn binary(lifter: &mut Lifter, ins: &Instruction, op: BinOp) {
    let (Some(lhs), Some(rhs)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) else {
        return;
    };
    // `xor r, r` and `sub r, r` clear the register without depending on its value.
    let value = if matches!(op, BinOp::Xor | BinOp::Sub) && lhs == rhs {
        Expr::constant(0)
    } else {
        Expr::bin(op, lhs.clone(), rhs.clone())
    };
    lifter.set_flags(match op {
        BinOp::Sub => Flags::difference(lhs, rhs),
        BinOp::Add => Flags::sum(lhs, rhs),
        _ => Flags::logic(value.clone()),
    });
    write_destination(lifter, ins, value);
}

fn select(lifter: &mut Lifter, ins: &Instruction, then: Expr, els: Expr) -> Option<Expr> {
    lifter
        .condition_test(ins.condition_code())
        .select(then, els)
}

fn shift(lifter: &mut Lifter, ins: &Instruction, op: BinOp) {
    let (Some(value), Some(amount), Some(width)) = (
        operand(lifter, ins, 0),
        operand(lifter, ins, 1),
        operand_width(ins, 0),
    ) else {
        return;
    };
    let amount = shift_count(amount, width);
    // A shift by zero leaves the flags as they were.
    let counted = matches!(amount, Expr::Const(count) if count != 0);
    let value = Expr::bin(op, value, amount);
    if counted {
        lifter.set_flags(Flags::result(value.clone()));
    }
    write_destination(lifter, ins, value);
}

/// `tzcnt`, `lzcnt`, `popcnt`, and `bsf` and `bsr`, which leave the
/// destination as it was for a zero source (as processors do, though Intel
/// leaves it undefined), all 64 bits of it even for a 32-bit operand, and
/// set the zero flag for it.
fn lift_count(lifter: &mut Lifter, ins: &Instruction) {
    let (Some(source), Some(width)) = (operand(lifter, ins, 1), operand_width(ins, 1)) else {
        return;
    };
    let count = |op| Expr::apply(op, vec![source.clone()]);
    let zero = || Expr::constant(0);
    // One when the source is zero.
    let empty = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(source.clone()),
        rhs: Box::new(zero()),
        then: Box::new(Expr::constant(1)),
        els: Box::new(zero()),
    };
    let (value, flags) = match ins.mnemonic() {
        Mnemonic::Tzcnt => (
            count(Operation::CountTrailingZeros(width)),
            Flags::carry(empty),
        ),
        Mnemonic::Lzcnt => (
            count(Operation::CountLeadingZeros(width)),
            Flags::carry(empty),
        ),
        // Zero follows the source; carry, sign and overflow are clear, as
        // after comparing the small count with zero.
        Mnemonic::Popcnt => {
            let value = count(Operation::PopCount(width));
            (value.clone(), Flags::difference(value, zero()))
        }
        _ => {
            let Some(old) = operand(lifter, ins, 0) else {
                return;
            };
            // A 32-bit destination left as it was keeps its high half too.
            let whole = match (width, gpr(ins.op0_register())) {
                (32, Some((index, _))) if ins.op0_kind() == OpKind::Register => Some(index),
                _ => None,
            };
            let old = whole.map_or(old, |index| Lifter::read_reg(index, 64));
            let found = if ins.mnemonic() == Mnemonic::Bsf {
                count(Operation::CountTrailingZeros(width))
            } else {
                Expr::bin(
                    BinOp::Sub,
                    Expr::constant(u64::from(width) - 1),
                    count(Operation::CountLeadingZeros(width)),
                )
            };
            let value = Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(source.clone()),
                rhs: Box::new(zero()),
                then: Box::new(old),
                els: Box::new(found),
            };
            lifter.set_flags(Flags::result(source.clone()));
            match whole {
                Some(index) => lifter.assign(index, 64, value),
                None => write_destination(lifter, ins, value),
            }
            return;
        }
    };
    lifter.set_flags(flags);
    write_destination(lifter, ins, value);
}

/// The bytes a string instruction moves at a time; None for a form the
/// lifter does not model, such as a 32-bit address size.
fn string_size(ins: &Instruction) -> Option<u8> {
    use Mnemonic::*;
    let size = match ins.mnemonic() {
        Movsb | Stosb | Lodsb => 1,
        Movsw | Stosw | Lodsw => 2,
        Movsd | Stosd | Lodsd => 4,
        Movsq | Stosq | Lodsq => 8,
        _ => return None,
    };
    let wide_addresses = (0..ins.op_count()).all(|index| match ins.op_kind(index) {
        OpKind::MemorySegRSI | OpKind::MemorySegDI | OpKind::MemoryESRDI => true,
        OpKind::MemoryESEDI | OpKind::MemorySegESI | OpKind::MemorySegEDI => false,
        _ => true,
    });
    (wide_addresses && !ins.has_repne_prefix()).then_some(size)
}

/// `movs`, `stos` and `lods`: one element moved, and the pointers past it,
/// with the direction flag clear. With `rep`, a loop: the instruction's own
/// block tests the count and leaves when it is zero, and a body after it
/// moves one element, counts it, and goes back to the test.
fn lift_string(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use Mnemonic::*;
    let Some(size) = string_size(ins) else {
        return false;
    };
    let (rsi, rdi, rcx) = (6, 7, 1);
    // The pointers and the count may be what the flags were set from.
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    for index in [rsi, rdi, rcx, RAX] {
        preserve_compare(
            &mut lifter.last_compare,
            Write::Register(index, None),
            &mut lifter.stmts,
        );
    }
    let advance = |index: u16| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value: Expr::bin(
            BinOp::Add,
            Expr::reg(index, 64),
            Expr::constant(u64::from(size)),
        ),
    };
    let mut step = Vec::new();
    match ins.mnemonic() {
        Movsb | Movsw | Movsd | Movsq => {
            step.push(Stmt::Store {
                addr: Expr::reg(rdi, 64),
                value: load_at(Expr::reg(rsi, 64), size),
                width: size,
            });
            step.extend([advance(rsi), advance(rdi)]);
        }
        Stosb | Stosw | Stosd | Stosq => {
            step.push(Stmt::Store {
                addr: Expr::reg(rdi, 64),
                value: Lifter::read_reg(RAX, size * 8),
                width: size,
            });
            step.push(advance(rdi));
        }
        _ => {
            let before = lifter.stmts.len();
            lifter.assign(RAX, size * 8, load_at(Expr::reg(rsi, 64), size));
            step.extend(lifter.stmts.drain(before..));
            step.push(advance(rsi));
        }
    }
    if !ins.has_rep_prefix() {
        lifter.stmts.extend(step);
        return false;
    }
    lifter.stmts.push(Stmt::Brif {
        cond: Cond::Eq,
        lhs: Expr::reg(rcx, 64),
        rhs: Expr::constant(0),
        target: ins.next_ip(),
    });
    step.push(Stmt::Assign {
        dest: RegRef {
            index: rcx,
            width: 64,
        },
        value: Expr::bin(BinOp::Sub, Expr::reg(rcx, 64), Expr::constant(1)),
    });
    step.push(Stmt::Br {
        target: Some(ins.ip()),
    });
    lifter.extra.push(Block {
        start: ins.ip() + 1,
        stmts: step,
    });
    true
}

/// `adc` and `sbb`: a sum with the carry, or a difference less it. The
/// flags keep only the carry out.
fn with_carry(lifter: &mut Lifter, ins: &Instruction, subtract: bool) {
    let (Some(a), Some(b), Some(width)) = (
        operand(lifter, ins, 0),
        operand(lifter, ins, 1),
        operand_width(ins, 0),
    ) else {
        return;
    };
    let Some(carry) = lifter.carry() else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} on a carry not modelled at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        )));
        return;
    };
    // The carry may read registers that keep the earlier flags' operands,
    // which keeping the new flags' operands overwrites.
    let carry = hold(lifter, carry);
    let (out, value) = if subtract {
        (
            super::flags::borrow_out(&a, &b, carry.clone()),
            Expr::bin(BinOp::Sub, Expr::bin(BinOp::Sub, a, b), carry),
        )
    } else {
        (
            super::flags::carry_out(&a, &b, carry.clone(), u32::from(width)),
            Expr::bin(BinOp::Add, Expr::bin(BinOp::Add, a, b), carry),
        )
    };
    lifter.set_flags(Flags::carry(out));
    write_destination(lifter, ins, value);
}

/// The count a shift or rotate uses: its low six bits for a 64-bit operand,
/// its low five bits otherwise.
fn shift_count(amount: Expr, width: u8) -> Expr {
    let mask = if width == 64 { 63 } else { 31 };
    match amount {
        Expr::Const(count) => Expr::constant(count & mask),
        amount => Expr::bin(BinOp::And, amount, Expr::constant(mask)),
    }
}

fn condition(code: ConditionCode) -> Option<Cond> {
    use ConditionCode::*;
    Some(match code {
        e => Cond::Eq,
        ne => Cond::Ne,
        l => Cond::Lt,
        le => Cond::Le,
        g => Cond::Gt,
        ge => Cond::Ge,
        b => Cond::Cc,
        be => Cond::Ls,
        a => Cond::Hi,
        ae => Cond::Cs,
        s => Cond::Mi,
        ns => Cond::Pl,
        o => Cond::Vs,
        no => Cond::Vc,
        _ => return Option::None,
    })
}

/// The value with each read of the stack pointer offset by `delta`, for a
/// value read before the stack pointer moves down by `delta`.
fn stack_reads_before(value: Expr, delta: u64) -> Expr {
    match value {
        Expr::Reg {
            index: RSP,
            width: 64,
        } => Expr::bin(BinOp::Add, Lifter::read_reg(RSP, 64), Expr::constant(delta)),
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            op,
            stack_reads_before(*lhs, delta),
            stack_reads_before(*rhs, delta),
        ),
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(stack_reads_before(*addr, delta)),
            width,
            signed,
        },
        other => other,
    }
}

fn stack_adjust(lifter: &mut Lifter, delta: i64) {
    let current = Lifter::read_reg(RSP, 64);
    let value = Expr::bin(BinOp::Add, current, Expr::constant(delta as u64));
    lifter.assign(RSP, 64, value);
}

fn is_cmov(mnemonic: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        mnemonic,
        Cmovo
            | Cmovno
            | Cmovb
            | Cmovae
            | Cmove
            | Cmovne
            | Cmovbe
            | Cmova
            | Cmovs
            | Cmovns
            | Cmovp
            | Cmovnp
            | Cmovl
            | Cmovge
            | Cmovle
            | Cmovg
    )
}

fn is_setcc(mnemonic: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        mnemonic,
        Seto | Setno
            | Setb
            | Setae
            | Sete
            | Setne
            | Setbe
            | Seta
            | Sets
            | Setns
            | Setp
            | Setnp
            | Setl
            | Setge
            | Setle
            | Setg
    )
}

fn resolved_target(ins: &Instruction, relocation_target: Option<u64>) -> u64 {
    relocation_target.unwrap_or_else(|| ins.near_branch_target())
}

fn lift_instruction(
    lifter: &mut Lifter,
    ins: &Instruction,
    relocation_target: Option<u64>,
    tail_call: bool,
) -> bool {
    let was_extended = lifter.extended_dividend.take();
    let was_zeroed = lifter.zeroed_dividend.take();
    if is_cmov(ins.mnemonic()) {
        let Some(source) = operand(lifter, ins, 1) else {
            return false;
        };
        let Some(current) = operand(lifter, ins, 0) else {
            return false;
        };
        match select(lifter, ins, source, current) {
            Some(value) => write_destination(lifter, ins, value),
            None => lifter.stmts.push(Stmt::unsupported(format!(
                "cmov without compare at 0x{:x}",
                ins.ip()
            ))),
        }
        return false;
    }
    if is_setcc(ins.mnemonic()) {
        let width = match ins.op0_kind() {
            OpKind::Memory => memory_width(ins).unwrap_or(1),
            _ => 1,
        };
        let bits = width * 8;
        // Flags from another block are unknown here.
        let Some(value) = lifter
            .condition_test(ins.condition_code())
            .select(Expr::constant(1), Expr::constant(0))
        else {
            lifter.stmts.push(Stmt::unsupported(format!(
                "setcc without compare at 0x{:x}",
                ins.ip()
            )));
            return false;
        };
        let value = Expr::bin(BinOp::And, value, Expr::constant((1u64 << bits) - 1));
        write_destination(lifter, ins, value);
        return false;
    }

    if lift_vector(lifter, ins).is_some()
        || lift_float(lifter, ins).is_some()
        || lift_packed(lifter, ins).is_some()
    {
        return false;
    }

    match ins.mnemonic() {
        Mnemonic::Mov => {
            if let Some(value) = operand(lifter, ins, 1) {
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Lea => {
            if let (OpKind::Register, Some(addr)) = (ins.op0_kind(), memory_address(ins))
                && let Some((index, width)) = gpr(ins.op0_register())
            {
                lifter.assign(index, width, addr);
            }
        }
        Mnemonic::Mul => lift_mul_high(lifter, ins, false),
        Mnemonic::Add => binary(lifter, ins, BinOp::Add),
        Mnemonic::Sub => binary(lifter, ins, BinOp::Sub),
        Mnemonic::And => binary(lifter, ins, BinOp::And),
        Mnemonic::Or => binary(lifter, ins, BinOp::Or),
        Mnemonic::Xor => {
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register()
                && let Some((2, _)) = gpr(ins.op0_register())
            {
                // `xor edx, edx` clears all of rdx.
                lifter.zeroed_dividend = Some(64);
            }
            binary(lifter, ins, BinOp::Xor)
        }
        Mnemonic::Imul => match ins.op_count() {
            1 => lift_mul_high(lifter, ins, true),
            2 | 3 => {
                let first = ins.op_count() - 2;
                if let (Some(a), Some(b), Some(width)) = (
                    operand(lifter, ins, first),
                    operand(lifter, ins, first + 1),
                    operand_width(ins, 0),
                ) {
                    lifter.set_flags(Flags::carry_overflow(signed_product_lost(&a, &b, width)));
                    let value = Expr::bin(BinOp::Mul, a, b);
                    write_destination(lifter, ins, value);
                }
            }
            _ => lifter
                .stmts
                .push(Stmt::unsupported(format!("imul at 0x{:x}", ins.ip()))),
        },
        Mnemonic::Cmp => {
            if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                lifter.set_flags(Flags::difference(a, b));
            }
        }
        Mnemonic::Test => {
            if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                let masked = Expr::bin(BinOp::And, a, b);
                lifter.set_flags(Flags::logic(masked));
            }
        }
        Mnemonic::Shl | Mnemonic::Sal => shift(lifter, ins, BinOp::Shl),
        Mnemonic::Shr => shift(lifter, ins, BinOp::Shr),
        Mnemonic::Sar => shift(lifter, ins, BinOp::Sar),
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            if let Some(value) = operand(lifter, ins, 1) {
                let source_width = match ins.op1_kind() {
                    OpKind::Memory => memory_width(ins).unwrap_or(4),
                    OpKind::Register => gpr(ins.op1_register()).map(|(_, w)| w).unwrap_or(32) / 8,
                    _ => 4,
                };
                let value = Expr::SignExtend {
                    value: Box::new(value),
                    width: source_width,
                };
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Cdqe => {
            let value = Expr::SignExtend {
                value: Box::new(Lifter::read_reg(RAX, 32)),
                width: 4,
            };
            lifter.assign(RAX, 64, value);
        }
        Mnemonic::Cwde => {
            let value = Expr::SignExtend {
                value: Box::new(Lifter::read_reg(RAX, 16)),
                width: 2,
            };
            lifter.assign(RAX, 32, value);
        }
        Mnemonic::Cbw => {
            let value = Expr::SignExtend {
                value: Box::new(Lifter::read_reg(RAX, 8)),
                width: 1,
            };
            lifter.assign(RAX, 16, value);
        }
        Mnemonic::Neg => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            lifter.set_flags(Flags::difference(Expr::constant(0), value.clone()));
            let negated = Expr::bin(BinOp::Sub, Expr::constant(0), value);
            write_destination(lifter, ins, negated);
        }
        Mnemonic::Not => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = match ins.op0_kind() {
                OpKind::Memory => memory_width(ins).unwrap_or(8),
                OpKind::Register => gpr(ins.op0_register()).map(|(_, w)| w).unwrap_or(64) / 8,
                _ => 8,
            };
            let mask = if width >= 8 {
                u64::MAX
            } else {
                (1u64 << (width * 8)) - 1
            };
            let inverted = Expr::bin(BinOp::Xor, value, Expr::constant(mask));
            write_destination(lifter, ins, inverted);
        }
        Mnemonic::Inc | Mnemonic::Dec => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            // Both leave the carry as it was.
            let (op, flags) = if ins.mnemonic() == Mnemonic::Inc {
                (BinOp::Add, Flags::sum(value.clone(), Expr::constant(1)))
            } else {
                (
                    BinOp::Sub,
                    Flags::difference(value.clone(), Expr::constant(1)),
                )
            };
            lifter.set_flags(flags.keeping_carry());
            let updated = Expr::bin(op, value, Expr::constant(1));
            write_destination(lifter, ins, updated);
        }
        // rdx (edx, dx) receives copies of the accumulator's sign bit.
        Mnemonic::Cwd | Mnemonic::Cdq | Mnemonic::Cqo => {
            let width = match ins.mnemonic() {
                Mnemonic::Cwd => 16,
                Mnemonic::Cdq => 32,
                _ => 64,
            };
            let sign = Expr::bin(
                BinOp::Sar,
                Lifter::read_reg(RAX, width),
                Expr::constant(u64::from(width) - 1),
            );
            lifter.assign(RDX, width, sign);
            lifter.extended_dividend = Some(width);
        }
        Mnemonic::Idiv => {
            let Some(divisor) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = match ins.op0_kind() {
                OpKind::Memory => memory_width(ins).unwrap_or(8) * 8,
                OpKind::Register => gpr(ins.op0_register()).map(|(_, w)| w).unwrap_or(64),
                _ => 64,
            };
            if was_extended != Some(width.min(64)) && was_extended.is_none() {
                wide_divide(lifter, true, width, divisor);
                return false;
            }
            let dividend = Lifter::read_reg(RAX, width);
            let quotient = Expr::bin(BinOp::DivS, dividend.clone(), divisor.clone());
            let remainder = Expr::bin(BinOp::ModS, dividend, divisor);
            // Both results read the original rax, so rdx (the remainder) is
            // written before rax (the quotient).
            lifter.assign(2, width, remainder);
            lifter.assign(RAX, width, quotient);
        }
        // An unsigned division whose high half rdx was just cleared divides
        // rax alone; otherwise the 128-bit dividend is not modeled.
        Mnemonic::Div => {
            let Some(divisor) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = match ins.op0_kind() {
                OpKind::Memory => memory_width(ins).unwrap_or(8) * 8,
                OpKind::Register => gpr(ins.op0_register()).map(|(_, w)| w).unwrap_or(64),
                _ => 64,
            };
            if was_zeroed.is_none() || !matches!(width, 32 | 64) {
                wide_divide(lifter, false, width, divisor);
                return false;
            }
            let dividend = Lifter::read_reg(RAX, width);
            let quotient = Expr::bin(BinOp::DivU, dividend.clone(), divisor.clone());
            let remainder = Expr::bin(BinOp::ModU, dividend, divisor);
            lifter.assign(2, width, remainder);
            lifter.assign(RAX, width, quotient);
        }
        Mnemonic::Leave => {
            let base = Lifter::read_reg(5, 64);
            lifter.assign(RSP, 64, base.clone());
            let value = Expr::Load {
                addr: Box::new(base),
                width: 8,
                signed: false,
            };
            lifter.assign(5, 64, value);
            stack_adjust(lifter, 8);
        }
        Mnemonic::Movzx => {
            if let Some(value) = operand(lifter, ins, 1) {
                let width = match ins.op1_kind() {
                    OpKind::Memory => memory_width(ins).unwrap_or(1),
                    OpKind::Register => gpr(ins.op1_register()).map(|(_, w)| w).unwrap_or(4) / 8,
                    _ => 1,
                };
                let mask = if width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (width * 8)) - 1
                };
                let value = Expr::bin(BinOp::And, value, Expr::constant(mask));
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Call => {
            if matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                let target = resolved_target(ins, relocation_target);
                let made = call(lifter.image, lifter.summaries, Some(target));
                lifter.stmts.push(made);
                if (lifter.summaries)(target).noreturn {
                    lifter.stmts.push(Stmt::Trap);
                    return true;
                }
            } else if let Some(through) = operand(lifter, ins, 0) {
                // A pointer the image fills itself is a call to its function.
                if let Some(target) = super::pointer_target(lifter.image, &through) {
                    lifter
                        .stmts
                        .push(call(lifter.image, lifter.summaries, Some(target)));
                    if (lifter.summaries)(target).noreturn {
                        lifter.stmts.push(Stmt::Trap);
                        return true;
                    }
                } else {
                    lifter.stmts.push(call_through(lifter.image, through));
                }
            } else {
                let made = call(lifter.image, lifter.summaries, None);
                lifter.stmts.push(made);
            }
        }
        Mnemonic::Jmp => {
            if ins.op0_kind() == OpKind::NearBranch64 {
                let target = resolved_target(ins, relocation_target);
                if tail_call {
                    lifter.stmts.extend(self::tail_call(
                        lifter.image,
                        lifter.summaries,
                        Some(target),
                    ));
                } else {
                    lifter.stmts.push(Stmt::Br {
                        target: Some(target),
                    });
                }
            } else if let Some(target) = operand(lifter, ins, 0) {
                match super::pointer_target(lifter.image, &target) {
                    Some(target) => lifter.stmts.extend(self::tail_call(
                        lifter.image,
                        lifter.summaries,
                        Some(target),
                    )),
                    None => lifter.stmts.push(Stmt::BrIndirect { target }),
                }
            }
            return true;
        }
        Mnemonic::Ret => {
            lifter.stmts.push(Stmt::Ret {
                value: Lifter::read_reg(RAX, 64),
            });
            return true;
        }
        Mnemonic::Push => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            // The value is read before the stack pointer moves.
            let value = stack_reads_before(value, 8);
            stack_adjust(lifter, -8);
            let address = Lifter::read_reg(RSP, 64);
            preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
            lifter.stmts.push(Stmt::Store {
                addr: address,
                value,
                width: 8,
            });
        }
        Mnemonic::Pop => {
            let address = Lifter::read_reg(RSP, 64);
            let value = Expr::Load {
                addr: Box::new(address),
                width: 8,
                signed: false,
            };
            match gpr(ins.op0_register()) {
                // `pop rsp` leaves the loaded value in place of the increment.
                Some((RSP, width)) if ins.op0_kind() == OpKind::Register => {
                    lifter.assign(RSP, width, value)
                }
                Some((index, width)) if ins.op0_kind() == OpKind::Register => {
                    lifter.assign(index, width, value);
                    stack_adjust(lifter, 8);
                }
                _ => stack_adjust(lifter, 8),
            }
        }
        Mnemonic::Xchg | Mnemonic::Xadd | Mnemonic::Cmpxchg => lift_exchange(lifter, ins),
        Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr
        | Mnemonic::Shld
        | Mnemonic::Shrd
        | Mnemonic::Bswap
        | Mnemonic::Bt
        | Mnemonic::Bts
        | Mnemonic::Btr
        | Mnemonic::Btc => lift_bits(lifter, ins),
        Mnemonic::Movsb
        | Mnemonic::Movsw
        | Mnemonic::Movsd
        | Mnemonic::Movsq
        | Mnemonic::Stosb
        | Mnemonic::Stosw
        | Mnemonic::Stosd
        | Mnemonic::Stosq
        | Mnemonic::Lodsb
        | Mnemonic::Lodsw
        | Mnemonic::Lodsd
        | Mnemonic::Lodsq
            if string_size(ins).is_some() =>
        {
            return lift_string(lifter, ins);
        }
        Mnemonic::Tzcnt | Mnemonic::Lzcnt | Mnemonic::Popcnt | Mnemonic::Bsf | Mnemonic::Bsr => {
            lift_count(lifter, ins)
        }
        // The Castagnoli checksum, updated with the source's bytes.
        Mnemonic::Crc32 => {
            if let (Some(crc), Some(data), Some(bits)) = (
                operand(lifter, ins, 0),
                operand(lifter, ins, 1),
                operand_width(ins, 1),
            ) {
                let crc = Expr::bin(BinOp::And, crc, Expr::constant(0xffff_ffff));
                let value = Expr::apply(
                    Operation::Crc32 {
                        castagnoli: true,
                        bits,
                    },
                    vec![crc, data],
                );
                write_destination(lifter, ins, value);
            }
        }
        // Hints and fences change nothing a single thread sees.
        Mnemonic::Nop
        | Mnemonic::Endbr64
        | Mnemonic::Reservednop
        | Mnemonic::Pause
        | Mnemonic::Wait
        | Mnemonic::Cld
        | Mnemonic::Prefetchnta
        | Mnemonic::Prefetcht0
        | Mnemonic::Prefetcht1
        | Mnemonic::Prefetcht2
        | Mnemonic::Prefetchw
        | Mnemonic::Sfence
        | Mnemonic::Lfence
        | Mnemonic::Mfence => {}
        Mnemonic::Adc => with_carry(lifter, ins, false),
        Mnemonic::Sbb => with_carry(lifter, ins, true),
        Mnemonic::Clc => lifter.set_flags(Flags::carry(Expr::constant(0))),
        Mnemonic::Stc => lifter.set_flags(Flags::carry(Expr::constant(1))),
        Mnemonic::Cmc => {
            if let Some(carry) = lifter.carry() {
                let flipped = Expr::bin(BinOp::Xor, carry, Expr::constant(1));
                lifter.set_flags(Flags::carry(flipped));
            }
        }
        // The kernel's call: its number and arguments in registers.
        Mnemonic::Syscall => lifter.stmts.push(Stmt::Call {
            target: None,
            through: None,
            convention: crate::ir::Convention::SyscallX86,
            args: None,
            // The kernel reads no floating-point register.
            floats_named: true,
            result: None,
        }),
        Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Hlt => {
            lifter.stmts.push(Stmt::Trap);
            return true;
        }
        other => {
            if ins.flow_control() == FlowControl::ConditionalBranch {
                // Only a condition the flags here leave open names itself in the branch.
                let cond = condition(ins.condition_code()).unwrap_or(Cond::Eq);
                let target = resolved_target(ins, relocation_target);
                let test = lifter.condition_test(ins.condition_code());
                lifter.stmts.extend(test.branch(cond, target));
                return true;
            }
            lifter
                .stmts
                .push(Stmt::unsupported(format!("{other:?} at 0x{:x}", ins.ip())));
        }
    }
    false
}

fn branch_target(ins: &Instruction, relocation_target: Option<u64>) -> Option<u64> {
    // A repeated string instruction loops back to its own test.
    if string_size(ins).is_some() && ins.has_rep_prefix() {
        return Some(ins.ip());
    }
    match ins.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            Some(resolved_target(ins, relocation_target))
        }
        _ => None,
    }
}

pub(super) fn decode(bytes: &[u8], addr: u64) -> (Vec<Decoded<Instruction>>, Option<String>) {
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut decoded = Vec::new();
    while decoder.can_decode() {
        if decoded.len() == MAX_INSTRUCTIONS {
            return (
                decoded,
                Some(format!("stopped after {MAX_INSTRUCTIONS} instructions")),
            );
        }
        let instruction = decoder.decode();
        decoded.push(Decoded {
            pc: instruction.ip(),
            next: instruction.next_ip(),
            instruction,
        });
    }
    (decoded, None)
}

impl Machine for Lifter<'_> {
    type Instruction = Instruction;

    fn branch_target(&self, instruction: &Instruction, pc: u64) -> Option<u64> {
        branch_target(instruction, self.image.relocations.get(&pc).copied())
    }

    fn step(&mut self, instruction: &Instruction, pc: u64) -> bool {
        let relocation_target = self.image.relocations.get(&pc).copied();
        let tail_call = instruction.mnemonic() == Mnemonic::Jmp
            && instruction.op0_kind() == OpKind::NearBranch64
            && {
                let target = resolved_target(instruction, relocation_target);
                target != self.function && self.image.functions.contains_key(&target)
            };
        self.flags_written = false;
        self.incomplete = false;
        let first = self.stmts.len();
        let ended = lift_instruction(self, instruction, relocation_target, tail_call);
        if self.incomplete {
            self.stmts.push(Stmt::unsupported(format!(
                "{:?} operands at 0x{:x}",
                instruction.mnemonic(),
                instruction.ip()
            )));
        }
        if self.stmts[first..]
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Unsupported { writes: None, .. }))
        {
            let changed = written_registers(&mut self.info, instruction);
            for stmt in &mut self.stmts[first..] {
                if let Stmt::Unsupported { writes, .. } = stmt
                    && writes.is_none()
                {
                    *writes = Some(changed.clone());
                }
            }
        }
        // Flags the instruction sets in a way not modelled are unknown.
        if instruction.rflags_modified() != 0 && !self.flags_written {
            self.last_compare = None;
        }
        self.flags_touched |= instruction.rflags_modified() != 0
            || self.flags_written
            || self.stmts[first..]
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Unsupported { .. }));
        ended
    }

    fn take_statements(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }

    fn block_ended(&mut self) {
        self.last_compare = None;
    }

    fn block_split(&mut self) {
        self.last_compare = None;
    }

    fn exit_flags(&self) -> Option<Flags> {
        self.last_compare.clone()
    }

    fn enter_block(&mut self, flags: Option<Flags>) {
        self.last_compare = flags;
        self.flags_touched = false;
    }

    fn flags_touched(&self) -> bool {
        self.flags_touched
    }

    fn take_extra_blocks(&mut self) -> Vec<Block> {
        std::mem::take(&mut self.extra)
    }
}
