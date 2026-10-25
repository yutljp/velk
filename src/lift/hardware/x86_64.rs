//! x86-64 instructions that read and write only general registers and
//! flags, run by a small program built for x86-64 (`x86_64.c`). On an
//! `AArch64` Mac the system runs that program by translation.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind,
    Register, RflagsBits,
};

use super::{
    Findings, branches_on_unknown_flags, condition_differs, float_bits, lifted,
    register_differences, same_float_bits, unsupported, value,
};
use crate::ir::eval::{self, hash};
use crate::loader::Isa;

const RSP: u16 = 4;
const R15: u16 = 15;

/// The general registers a case may use: the runner keeps the stack in rsp
/// and its state pointer in r15.
fn usable(index: u16) -> bool {
    index != RSP && index != R15
}

fn name(index: u16) -> String {
    if index >= crate::arch::x86::XMM0 {
        return crate::ir::reg_name(crate::loader::Isa::X86_64, index, 64);
    }
    NAMES[usize::from(index)].to_owned()
}

const NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// The buffer the runner maps for cases that address memory, and the flag
/// on a case's length that sends its contents.
const BUFFER: u64 = 0x6000_0000_0000;
const BUFFER_SIZE: usize = 8192;
const WITH_MEMORY: u32 = 0x8000_0000;

/// The flags a case starts from: carry, parity, adjust, zero, sign and
/// overflow, with the bit that is always set.
const ARITHMETIC_FLAGS: u64 = 0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x800;

struct Case {
    code: Vec<u8>,
    registers: [u64; 16],
    flags: u64,
    /// xmm0 to xmm7, as halves, low first, then the upper halves of ymm0
    /// to ymm7 the same way.
    vectors: [u64; 32],
    /// The buffer's contents, for a case that reads or writes memory.
    memory: Option<Vec<u8>>,
}

struct Outcome {
    registers: [u64; 16],
    flags: u64,
    vectors: [u64; 32],
    memory: Option<Vec<u8>>,
    /// The signal the code raised, or zero.
    signal: u8,
}

/// Where a vector slot of the IR lies among the case's vector words: the
/// xmm halves first, then the ymm upper halves.
fn vector_word(index: u16) -> Option<usize> {
    use crate::arch::x86::{XMM0, YMM_UPPER};
    match index {
        _ if (XMM0..XMM0 + 16).contains(&index) => Some(usize::from(index - XMM0)),
        _ if (YMM_UPPER..YMM_UPPER + 16).contains(&index) => {
            Some(16 + usize::from(index - YMM_UPPER))
        }
        _ => None,
    }
}

/// The vector slots a case sets and compares: xmm0 to xmm7 and the upper
/// halves of ymm0 to ymm7.
fn vector_slots() -> impl Iterator<Item = u16> {
    use crate::arch::x86::{XMM0, YMM_UPPER};
    (XMM0..XMM0 + 16).chain(YMM_UPPER..YMM_UPPER + 16)
}

/// Builds the runner once for every test, or None when this machine has
/// no compiler for it. Test processes running at once each compile to a
/// file of their own and rename it into place, so none runs a runner
/// another is still writing.
fn runner() -> Option<Command> {
    static BUILT: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    let translated = cfg!(target_arch = "aarch64");
    let built = BUILT.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/hardware");
        if std::fs::create_dir_all(&dir).is_err() {
            return None;
        }
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lift/hardware/x86_64.c");
        let binary = dir.join("x86_64_runner");
        let partial = dir.join(format!("x86_64_runner.{}", std::process::id()));
        let mut compile = Command::new(if translated { "clang" } else { "cc" });
        if translated {
            compile.args(["-arch", "x86_64"]);
        }
        let compiled = compile
            .arg("-O1")
            .arg("-o")
            .arg(&partial)
            .arg(&source)
            .status()
            .is_ok_and(|status| status.success());
        if !compiled || std::fs::rename(&partial, &binary).is_err() {
            std::fs::remove_file(&partial).ok();
            return None;
        }
        Some(binary)
    });
    let Some(binary) = built.clone() else {
        return None;
    };
    Some(if translated {
        let mut command = Command::new("arch");
        command.arg("-x86_64").arg(binary);
        command
    } else {
        Command::new(binary)
    })
}

fn run(mut runner: Command, cases: &[Case]) -> Vec<Outcome> {
    let mut input = Vec::new();
    for case in cases {
        let flag = if case.memory.is_some() {
            WITH_MEMORY
        } else {
            0
        };
        input.extend((case.code.len() as u32 | flag).to_le_bytes());
        input.extend(&case.code);
        for register in case.registers {
            input.extend(register.to_le_bytes());
        }
        input.extend(case.flags.to_le_bytes());
        for half in case.vectors {
            input.extend(half.to_le_bytes());
        }
        if let Some(memory) = &case.memory {
            input.extend(memory);
        }
    }
    let mut child = runner
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("starting the x86-64 runner");
    let mut stdin = child.stdin.take().expect("runner input");
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output().expect("running the x86-64 runner");
    writer.join().expect("writer").expect("writing cases");
    assert!(output.status.success(), "the x86-64 runner failed");
    let mut outcomes = Vec::new();
    let mut rest = output.stdout.as_slice();
    for case in cases {
        let state = 49 * 8;
        let size = state + case.memory.as_ref().map_or(0, Vec::len) + 1;
        let (chunk, tail) = rest.split_at(size);
        rest = tail;
        let word = |index: usize| {
            u64::from_le_bytes(chunk[index * 8..index * 8 + 8].try_into().expect("8 bytes"))
        };
        outcomes.push(Outcome {
            registers: std::array::from_fn(word),
            flags: word(16),
            vectors: std::array::from_fn(|half| word(17 + half)),
            memory: case
                .memory
                .as_ref()
                .map(|memory| chunk[state..state + memory.len()].to_vec()),
            signal: chunk[size - 1],
        });
    }
    assert!(rest.is_empty(), "the x86-64 runner wrote too much");
    outcomes
}

fn decode(code: &[u8]) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (!instruction.is_invalid()).then_some(instruction)
}

/// Whether `instruction` touches only usable general registers and
/// immediates, carries on to the next instruction, and needs no privilege.
fn register_only(instruction: &Instruction, info: &mut InstructionInfoFactory) -> bool {
    // `movsxd` without REX.W is a plain move on the processor; the
    // translation that runs x86-64 code on AArch64 sign-extends it.
    if instruction.mnemonic() == Mnemonic::Movsxd && instruction.op0_register().size() != 8 {
        return false;
    }
    if instruction.flow_control() != FlowControl::Next
        || instruction.is_privileged()
        || matches!(
            instruction.mnemonic(),
            Mnemonic::Cpuid
                | Mnemonic::Rdtsc
                | Mnemonic::Rdtscp
                | Mnemonic::Rdrand
                | Mnemonic::Rdseed
                | Mnemonic::Rdpid
                | Mnemonic::Rdpmc
                | Mnemonic::Xgetbv
        )
    {
        return false;
    }
    let operands_plain = (0..instruction.op_count()).all(|index| {
        matches!(
            instruction.op_kind(index),
            OpKind::Register
                | OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        )
    });
    let info = info.info(instruction);
    operands_plain
        && info.used_memory().is_empty()
        && info.used_registers().iter().all(|used| {
            let register = used.register();
            (register.is_gpr()
                && !matches!(register.full_register(), Register::RSP | Register::R15))
                || ((register.is_xmm() || register.is_ymm()) && register.number() < 8)
        })
}

/// A random instruction of up to 15 bytes, decoded from random bytes with an
/// operand-size or REX prefix now and then.
fn instruction(seed: u64, info: &mut InstructionInfoFactory) -> Option<(Vec<u8>, Instruction)> {
    // Scalar SSE: a mandatory prefix, an opcode of the floating-point
    // groups and a register-to-register operand byte.
    const SSE: [u8; 18] = [
        0x10, 0x11, 0x28, 0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x51, 0x54, 0x57, 0x58, 0x59, 0x5a, 0x5c,
        0x5d, 0x5e, 0x5f,
    ];
    let mut bytes: Vec<u8> = (0..15)
        .map(|index| hash(seed, 0x40 + index) as u8)
        .collect();
    match hash(seed, 0x30) % 9 {
        // Integer and packed SSE: 66 0F with an opcode of those groups, a
        // register operand byte and an immediate for the ones that take one.
        // AVX on registers: VEX moves, bitwise and lane operations of 128
        // or 256 bits, the byte mask, the broadcast, and clearing the upper
        // halves.
        8 if hash(seed, 0x3f).is_multiple_of(3) => {
            const OPCODES: [(u8, u8); 18] = [
                (0x6f, 2),
                (0x6f, 1),
                (0xef, 1),
                (0xdb, 1),
                (0xeb, 1),
                (0xdf, 1),
                (0x74, 1),
                (0x75, 1),
                (0x76, 1),
                (0xfc, 1),
                (0xfe, 1),
                (0xd4, 1),
                (0xf8, 1),
                (0xfb, 1),
                (0xda, 1),
                (0xde, 1),
                (0xd7, 1),
                (0x77, 0),
            ];
            let (opcode, prefix) = OPCODES[(hash(seed, 0x3b) % OPCODES.len() as u64) as usize];
            let wide = !hash(seed, 0x3c).is_multiple_of(3);
            let source = (hash(seed, 0x3d) % 8) as u8;
            let modrm = 0xc0 | (hash(seed, 0x34) as u8 & 0x3f);
            let code: Vec<u8> = match (opcode, prefix) {
                // vzeroupper.
                (0x77, _) => vec![0xc5, 0xf8, 0x77],
                // vpmovmskb names no second source.
                (0xd7, _) => vec![0xc5, 0xf9 | if wide { 0x04 } else { 0 }, 0xd7, modrm],
                _ if hash(seed, 0x3e).is_multiple_of(8) => {
                    // vpbroadcastb from an xmm register.
                    vec![0xc4, 0xe2, 0x79 | if wide { 0x04 } else { 0 }, 0x78, modrm]
                }
                _ => {
                    let unused = if opcode == 0x6f { 0xf } else { !source & 0xf };
                    vec![
                        0xc5,
                        0x80 | (unused << 3) | if wide { 0x04 } else { 0 } | prefix,
                        opcode,
                        modrm,
                    ]
                }
            };
            bytes.splice(0..code.len(), code);
        }
        // AES rounds: 66 0F 38 DC to DF on two xmm registers.
        7 if hash(seed, 0x3e).is_multiple_of(4) => {
            let code = [
                0x66,
                0x0f,
                0x38,
                0xdc + (hash(seed, 0x3b) % 4) as u8,
                0xc0 | (hash(seed, 0x34) as u8 & 0x3f),
            ];
            bytes.splice(0..code.len(), code);
        }
        7 | 8 => {
            let opcode = match hash(seed, 0x3a) % 4 {
                0 => 0x60 + (hash(seed, 0x3b) % 0x20) as u8,
                1 => 0xd0 + (hash(seed, 0x3b) % 0x30) as u8,
                2 => 0x50 + (hash(seed, 0x3b) % 0x10) as u8,
                // pinsrw and pextrw.
                _ => 0xc4 + (hash(seed, 0x3b) % 2) as u8,
            };
            let prefix = if hash(seed, 0x3c).is_multiple_of(4) {
                0xf3
            } else {
                0x66
            };
            let code = [
                prefix,
                0x0f,
                opcode,
                0xc0 | (hash(seed, 0x34) as u8 & 0x3f),
                hash(seed, 0x3d) as u8,
            ];
            bytes.splice(0..code.len(), code);
        }
        // Bit scans and counts: bsf, bsr, and with F3 popcnt, tzcnt, lzcnt.
        6 => {
            let (prefix, opcode) = [
                (None, 0xbc),
                (None, 0xbd),
                (Some(0xf3), 0xb8),
                (Some(0xf3), 0xbc),
                (Some(0xf3), 0xbd),
                // bt, bts, btr and btc with a register bit number.
                (None, 0xa3),
                (None, 0xab),
                (None, 0xb3),
                (None, 0xbb),
            ][(hash(seed, 0x35) % 9) as usize];
            let mut code: Vec<u8> = prefix.into_iter().collect();
            if hash(seed, 0x36) & 1 == 1 {
                code.push(0x48 | (hash(seed, 0x37) as u8 & 0x05));
            }
            code.extend([0x0f, opcode, 0xc0 | (hash(seed, 0x34) as u8 & 0x3f)]);
            bytes.splice(0..code.len(), code);
        }
        0 => bytes[0] = 0x48 | (bytes[0] & 0x07),
        1 => bytes[0] = 0x66,
        // roundsd and roundss, with an immediate rounding.
        5 => {
            let opcode = [0x0a, 0x0b][(hash(seed, 0x38) & 1) as usize];
            let code = [
                0x66,
                0x0f,
                0x3a,
                opcode,
                0xc0 | (hash(seed, 0x34) as u8 & 0x3f),
                hash(seed, 0x39) as u8 & 0x07,
            ];
            bytes.splice(0..code.len(), code);
        }
        2 | 3 => {
            let prefix = [0xf2, 0xf3, 0x66, 0xf2][(hash(seed, 0x31) % 4) as usize];
            let opcode = SSE[(hash(seed, 0x32) % SSE.len() as u64) as usize];
            let rex = hash(seed, 0x33).is_multiple_of(3);
            let mut sse = vec![prefix];
            if rex {
                // A 64-bit general operand for the integer conversions.
                sse.push(0x48);
            }
            sse.extend([0x0f, opcode, 0xc0 | (hash(seed, 0x34) as u8 & 0x3f)]);
            bytes.splice(0..sse.len(), sse);
        }
        _ => {}
    }
    let decoded = decode(&bytes)?;
    if !register_only(&decoded, info) {
        return None;
    }
    bytes.truncate(decoded.len());
    Some((bytes, decoded))
}

/// `cmp a, b` on two usable registers at 32 or 64 bits.
fn compare(seed: u64) -> Vec<u8> {
    let register = |key| {
        let index = (hash(seed, key) % 16) as u8;
        if usable(u16::from(index)) { index } else { 0 }
    };
    let (a, b) = (register(0x10), register(0x11));
    let wide = hash(seed, 0x12) & 1 == 1;
    let rex = 0x40 | u8::from(wide) << 3 | (b >> 3) << 2 | a >> 3;
    vec![rex, 0x39, 0xc0 | (b & 7) << 3 | (a & 7)]
}

/// The flags each condition code reads, and whether it holds for `flags`.
fn condition(code: u8, flags: u64) -> (u32, bool) {
    let bit = |shift: u32| flags >> shift & 1 == 1;
    let (cf, pf, zf, sf, of) = (bit(0), bit(2), bit(6), bit(7), bit(11));
    let (reads, base) = match code >> 1 {
        0 => (RflagsBits::OF, of),
        1 => (RflagsBits::CF, cf),
        2 => (RflagsBits::ZF, zf),
        3 => (RflagsBits::CF | RflagsBits::ZF, cf || zf),
        4 => (RflagsBits::SF, sf),
        5 => (RflagsBits::PF, pf),
        6 => (RflagsBits::SF | RflagsBits::OF, sf != of),
        _ => (
            RflagsBits::ZF | RflagsBits::SF | RflagsBits::OF,
            zf || sf != of,
        ),
    };
    (reads, if code & 1 == 1 { !base } else { base })
}

struct Prepared {
    seed: u64,
    body: Vec<u8>,
    instructions: Vec<Instruction>,
    /// Flags the processor leaves undefined after the body.
    undefined: u32,
    registers: Vec<(u16, u64)>,
}

fn prepare(seed: u64, info: &mut InstructionInfoFactory) -> Option<Prepared> {
    let mut body = compare(seed);
    let Some(decoded) = decode(&body) else {
        return None;
    };
    let mut instructions = vec![decoded];
    for (index, salt) in [0, 0x5eed].into_iter().enumerate() {
        if index == 1 && hash(seed, 7) & 1 == 0 {
            break;
        }
        let Some((bytes, decoded)) = instruction(seed ^ salt, info) else {
            return None;
        };
        body.extend(bytes);
        instructions.push(decoded);
    }
    let undefined = instructions.iter().fold(0, |undefined, instruction| {
        let defined =
            instruction.rflags_written() | instruction.rflags_cleared() | instruction.rflags_set();
        (undefined & !defined) | instruction.rflags_undefined()
    });
    let registers = (0..16u16)
        .filter(|index| usable(*index))
        .map(|index| (index, value(seed, 0x100 + u64::from(index))))
        .chain(vector_slots().map(|slot| (slot, float_bits(seed, 0x200 + u64::from(slot)))))
        .collect();
    Some(Prepared {
        seed,
        body,
        instructions,
        undefined,
        registers,
    })
}

#[test]
fn lifted_instructions_match_the_processor() {
    let Some(runner) = runner() else {
        eprintln!("no compiler for x86-64 here; the comparison did not run");
        return;
    };
    let mut info = InstructionInfoFactory::new();
    let mut findings = Findings::default();
    let mut prepared = Vec::new();
    for seed in 0..60_000 {
        let Some(case) = prepare(seed, &mut info) else {
            continue;
        };
        let Some(ir) = lifted(Isa::X86_64, [case.body.as_slice(), &[0xc3]].concat()) else {
            continue;
        };
        if let Some(name) = unsupported(&ir) {
            *findings.unsupported.entry(name).or_default() += 1;
            continue;
        }
        prepared.push(case);
    }
    let cases: Vec<Case> = prepared
        .iter()
        .map(|case| {
            let (mut registers, mut vectors) = ([0; 16], [0; 32]);
            for (index, value) in &case.registers {
                match vector_word(*index) {
                    Some(word) => vectors[word] = *value,
                    None => registers[usize::from(*index)] = *value,
                }
            }
            Case {
                code: case.body.clone(),
                registers,
                flags: 0x2 | (hash(case.seed, 6) & ARITHMETIC_FLAGS),
                vectors,
                memory: None,
            }
        })
        .collect();
    let outcomes = run(runner, &cases);
    for (case, outcome) in prepared.iter().zip(outcomes) {
        if outcome.signal != 0 {
            findings.undefined += 1;
            continue;
        }
        findings.tried += 1;
        let kind = case.instructions[1..]
            .iter()
            .map(|instruction| format!("{:?}", instruction.mnemonic()))
            .collect::<Vec<_>>()
            .join(" then ");
        let describe = || {
            let code: Vec<String> = case.instructions.iter().map(|i| i.to_string()).collect();
            let inputs: Vec<String> = case
                .registers
                .iter()
                .map(|(index, value)| format!("{}={value:#x}", name(*index)))
                .collect();
            format!("{}\n  in: {}", code.join(" ; "), inputs.join(" "))
        };
        let ir = lifted(Isa::X86_64, [case.body.as_slice(), &[0xc3]].concat()).expect("lifted");
        if let Some(differ) = register_differences(
            &ir,
            &case.registers,
            |index| match vector_word(index) {
                Some(word) => outcome.vectors[word],
                None => outcome.registers[usize::from(index)],
            },
            name,
            |index, a, b| {
                if index >= crate::arch::x86::XMM0 {
                    same_float_bits(a, b)
                } else {
                    a == b
                }
            },
        ) {
            Findings::note(&mut findings.registers, kind, || {
                format!("{}\n{}\n  {differ}", describe(), ir.render())
            });
            continue;
        }
        // j<cc> +6; mov eax, 0; ret; mov eax, 1; ret
        for code in 0..16u8 {
            let (reads, expected) = condition(code, outcome.flags);
            if reads & case.undefined != 0 {
                continue;
            }
            let tail = [
                0x70 | code,
                6,
                0xb8,
                0,
                0,
                0,
                0,
                0xc3,
                0xb8,
                1,
                0,
                0,
                0,
                0xc3,
            ];
            let Some(ir) = lifted(Isa::X86_64, [case.body.as_slice(), &tail].concat()) else {
                continue;
            };
            if branches_on_unknown_flags(&ir) {
                continue;
            }
            if let Some(differ) = condition_differs(&ir, &case.registers, expected) {
                Findings::note(
                    &mut findings.conditions,
                    format!("{kind}, condition {code}"),
                    || {
                        format!(
                            "{}\n  condition {code}: {differ}\n{}",
                            describe(),
                            ir.render()
                        )
                    },
                );
            }
        }
    }
    findings.assert_agreement();
}

/// The registers memory cases address through, pointing into the middle
/// of the buffer; every other register holds a small value.
const POINTERS: [u16; 4] = [3, 6, 7, 12];

/// One of the instructions that take a memory operand, addressed through
/// a pointer register with a small index and displacement: the opcode
/// bytes, then `modrm` with a SIB byte, a byte displacement and room for
/// an immediate.
fn memory_instruction(
    seed: u64,
    info: &mut InstructionInfoFactory,
) -> Option<(Vec<u8>, Instruction)> {
    const OPCODES: &[&[u8]] = &[
        &[0x00],
        &[0x01],
        &[0x02],
        &[0x03],
        &[0x08],
        &[0x09],
        &[0x0a],
        &[0x0b],
        &[0x10],
        &[0x11],
        &[0x13],
        &[0x19],
        &[0x1b],
        &[0x20],
        &[0x21],
        &[0x23],
        &[0x28],
        &[0x29],
        &[0x2b],
        &[0x30],
        &[0x31],
        &[0x33],
        &[0x38],
        &[0x39],
        &[0x3b],
        &[0x80],
        &[0x81],
        &[0x83],
        &[0x84],
        &[0x85],
        &[0x86],
        &[0x87],
        &[0x88],
        &[0x89],
        &[0x8a],
        &[0x8b],
        &[0x8d],
        &[0xc0],
        &[0xc1],
        &[0xc6],
        &[0xc7],
        &[0xd0],
        &[0xd1],
        &[0xd3],
        &[0xf6],
        &[0xf7],
        &[0xfe],
        &[0xff],
        &[0x0f, 0xaf],
        &[0x0f, 0xb6],
        &[0x0f, 0xb7],
        &[0x0f, 0xbe],
        &[0x0f, 0xbf],
        &[0x0f, 0x44],
        &[0x0f, 0x4c],
        &[0x0f, 0x94],
        &[0x0f, 0x9f],
        &[0x0f, 0xb1],
        &[0x0f, 0xc1],
        &[0x63],
        &[0xf2, 0x0f, 0x10],
        &[0xf2, 0x0f, 0x11],
        &[0xf3, 0x0f, 0x10],
        &[0xf3, 0x0f, 0x11],
        &[0x66, 0x0f, 0x6f],
        &[0x66, 0x0f, 0x7f],
        &[0xf3, 0x0f, 0x6f],
        &[0xf3, 0x0f, 0x7f],
        &[0x0f, 0x10],
        &[0x0f, 0x11],
        &[0x66, 0x0f, 0xd6],
        &[0x66, 0x0f, 0x6e],
        &[0x66, 0x0f, 0x7e],
        &[0xf2, 0x0f, 0x58],
        &[0xf2, 0x0f, 0x59],
        &[0xf3, 0x0f, 0x5c],
        &[0x66, 0x0f, 0xfe],
        &[0x66, 0x0f, 0xef],
        &[0x66, 0x0f, 0x74],
    ];
    let pick = |key: u64, count: u64| hash(seed, key) % count;
    let opcode = OPCODES[pick(0x50, OPCODES.len() as u64) as usize];
    let base = POINTERS[pick(0x51, 4) as usize] as u8;
    let index = pick(0x52, 16) as u8;
    let (wide, operand_high) = (pick(0x53, 2) == 1, pick(0x54, 2) as u8);
    let rex = 0x40 | u8::from(wide) << 3 | operand_high << 2 | (index >> 3) << 1 | base >> 3;
    // A mandatory prefix comes before REX, the escape after it.
    let (prefix, rest) = match opcode {
        [first @ (0xf2 | 0xf3 | 0x66), rest @ ..] => (Some(*first), rest),
        rest => (None, rest),
    };
    let mut bytes: Vec<u8> = prefix.into_iter().collect();
    if pick(0x55, 8) == 0 && prefix.is_none() {
        bytes.push(0x66);
    }
    bytes.push(rex);
    bytes.extend(rest);
    let modrm = 0x40 | (pick(0x56, 8) as u8) << 3 | 0b100;
    let sib = (pick(0x57, 4) as u8) << 6 | (index & 7) << 3 | (base & 7);
    bytes.extend([modrm, sib, hash(seed, 0x58) as u8]);
    bytes.extend((0..4).map(|key| hash(seed, 0x59 + key) as u8));
    let decoded = decode(&bytes)?;
    bytes.truncate(decoded.len());
    // movsxd without REX.W runs differently under translation (see
    // `register_only`).
    if decoded.flow_control() != FlowControl::Next
        || decoded.is_privileged()
        || matches!(
            decoded.mnemonic(),
            Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
        )
        || decoded.mnemonic() == Mnemonic::Movsxd && decoded.op0_register().size() != 8
    {
        return None;
    }
    let details = info.info(&decoded);
    let addressed = details.used_memory().iter().all(|memory| {
        POINTERS.contains(&gpr(memory.base()).map_or(u16::MAX, |(index, _)| index))
            && (memory.index() == Register::None
                || gpr(memory.index())
                    .is_some_and(|(index, _)| !POINTERS.contains(&index) && usable(index)))
            && (memory.displacement() as i64).unsigned_abs() <= 1024
            && memory.segment() == Register::DS
    });
    let registers = details.used_registers().iter().all(|used| {
        let register = used.register();
        (register.is_gpr() && !matches!(register.full_register(), Register::RSP | Register::R15))
            || ((register.is_xmm() || register.is_ymm()) && register.number() < 8)
    });
    (addressed && registers && !details.used_memory().is_empty()).then_some((bytes, decoded))
}

fn gpr(register: Register) -> Option<(u16, u8)> {
    (register.is_gpr()).then(|| {
        (
            register.full_register().number() as u16,
            (register.size() * 8) as u8,
        )
    })
}

#[test]
fn lifted_memory_operands_match_the_processor() {
    let Some(runner) = runner() else {
        eprintln!("no compiler for x86-64 here; the comparison did not run");
        return;
    };
    let mut info = InstructionInfoFactory::new();
    let mut findings = Findings::default();
    let mut cases = Vec::new();
    let mut prepared = Vec::new();
    for seed in 0..40_000u64 {
        let Some((instruction, decoded)) = memory_instruction(seed, &mut info) else {
            continue;
        };
        // After a compare, so an instruction that reads the flags reads
        // known ones.
        let code = [compare(seed), instruction].concat();
        let Some(ir) = lifted(Isa::X86_64, [code.as_slice(), &[0xc3]].concat()) else {
            continue;
        };
        if let Some(name) = unsupported(&ir) {
            *findings.unsupported.entry(name).or_default() += 1;
            continue;
        }
        let mut registers = [0u64; 16];
        for (index, slot) in registers.iter_mut().enumerate() {
            *slot = if POINTERS.contains(&(index as u16)) {
                BUFFER + (BUFFER_SIZE / 2) as u64 + hash(seed, 0x300 + index as u64) % 256
            } else {
                hash(seed, 0x100 + index as u64) % 64
            };
        }
        let vectors: [u64; 32] = std::array::from_fn(|word| float_bits(seed, 0x200 + word as u64));
        let memory: Vec<u8> = (0..BUFFER_SIZE)
            .map(|index| hash(seed, 0x400 + index as u64) as u8)
            .collect();
        cases.push(Case {
            code: code.clone(),
            registers,
            flags: 0x2 | (hash(seed, 6) & ARITHMETIC_FLAGS),
            vectors,
            memory: Some(memory),
        });
        prepared.push((code, decoded, ir));
    }
    let outcomes = run(runner, &cases);
    for ((code, decoded, ir), (case, outcome)) in prepared.iter().zip(cases.iter().zip(outcomes)) {
        if outcome.signal != 0 {
            findings.undefined += 1;
            continue;
        }
        findings.tried += 1;
        let registers: Vec<(u16, u64)> = (0..16u16)
            .filter(|index| usable(*index))
            .map(|index| (index, case.registers[usize::from(index)]))
            .chain(vector_slots().map(|slot| {
                (
                    slot,
                    case.vectors[vector_word(slot).expect("a vector slot")],
                )
            }))
            .collect();
        let before = case.memory.as_ref().expect("memory");
        let words: Vec<(u64, u64)> = before
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| {
                (
                    BUFFER + index as u64 * 8,
                    u64::from_le_bytes(chunk.try_into().expect("8 bytes")),
                )
            })
            .collect();
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &registers,
            memory: &words,
            step_limit: 100,
        };
        let kind = format!("{:?}", decoded.mnemonic());
        let describe = || format!("{decoded} ({code:02x?})\n{}", ir.render());
        let (after, memory) = match eval::state_after(ir, &setup) {
            Ok(state) => state,
            Err("division by zero") => {
                findings.undefined += 1;
                continue;
            }
            Err(reason) => {
                Findings::note(&mut findings.registers, kind, || {
                    format!("{}\n  {reason}", describe())
                });
                continue;
            }
        };
        let real = |index: u16| match vector_word(index) {
            Some(word) => outcome.vectors[word],
            None => outcome.registers[usize::from(index)],
        };
        let mut differ: Vec<String> = registers
            .iter()
            .filter_map(|(index, start)| {
                let lifted = after.get(index).copied().unwrap_or(*start);
                let same = if *index >= crate::arch::x86::XMM0 {
                    same_float_bits(lifted, real(*index))
                } else {
                    lifted == real(*index)
                };
                (!same).then(|| {
                    format!(
                        "{}: lifted {lifted:#x}, processor {:#x}",
                        name(*index),
                        real(*index)
                    )
                })
            })
            .collect();
        let after_memory = outcome.memory.as_ref().expect("memory back");
        for (offset, real) in after_memory.iter().enumerate() {
            let lifted = memory
                .get(&(BUFFER + offset as u64))
                .copied()
                .unwrap_or(before[offset]);
            if lifted != *real {
                differ.push(format!(
                    "byte {offset:#x}: lifted {lifted:#x}, processor {real:#x}"
                ));
            }
        }
        if !differ.is_empty() {
            Findings::note(&mut findings.registers, kind, || {
                format!("{}\n  {}", describe(), differ.join("\n  "))
            });
        }
    }
    findings.assert_agreement();
}

#[test]
fn fixture_simd_flags_and_reverse_strings_match_the_processor() {
    let runner = runner().expect("an x86-64 compiler is required");
    let mut codes = vec![
        vec![0x66, 0x0f, 0x38, 0x00, 0xc1], // pshufb xmm0, xmm1
        vec![0x66, 0x0f, 0x38, 0x00, 0x03], // pshufb xmm0, [rbx]
        vec![0x66, 0x0f, 0x38, 0x17, 0xc1], // ptest xmm0, xmm1
        vec![0xc4, 0xe2, 0x79, 0x17, 0xc1], // vptest xmm0, xmm1
        vec![0xc4, 0xe2, 0x7d, 0x17, 0xc1], // vptest ymm0, ymm1
        vec![0xc4, 0xe2, 0x7d, 0x17, 0x03], // vptest ymm0, [rbx]
        vec![0x66, 0x0f, 0x38, 0x00, 0xc0], // pshufb xmm0, xmm0
    ];
    for lane in 0..4 {
        for source in [0xc1, 0x03] {
            codes.push(vec![0x66, 0x0f, 0x3a, 0x22, source, 0xfc | lane]);
        }
    }
    // Record the condition flags in registers for comparison.
    for (kind, code) in codes.iter_mut().enumerate() {
        code.splice(0..0, [0x48, 0x39, 0xd0]); // cmp rax, rdx
        if cfg!(target_arch = "aarch64") && (2..=5).contains(&kind) {
            // Translation leaves some flags that PTEST specifies as zero
            // unchanged. Compare CF and ZF here; native x86 checks all six.
            code.extend([0x0f, 0x92, 0xc0, 0x0f, 0x94, 0xc1]);
        } else {
            code.extend([0x9f, 0x0f, 0x90, 0xc1]); // lahf; seto cl
        }
    }
    codes.extend([
        // Different-width compares meet at sete al.
        vec![
            0x48, 0x85, 0xd2, 0x74, 5, 0x48, 0x39, 0xd8, 0xeb, 2, 0x39, 0xd8, 0x0f, 0x94, 0xc0,
        ],
        // A variable shift preserves ZF for an effective count of zero.
        vec![0x48, 0x39, 0xd8, 0x48, 0xd3, 0xe0, 0x0f, 0x94, 0xc2],
        vec![0x48, 0x39, 0xd8, 0xd3, 0xe0, 0x0f, 0x94, 0xc2],
        vec![0x48, 0x39, 0xd8, 0x66, 0xd3, 0xe0, 0x0f, 0x94, 0xc2],
        vec![0x48, 0x39, 0xd8, 0xd2, 0xe0, 0x0f, 0x94, 0xc2],
        // Direction set in another block, then restored after the copy.
        vec![0xfd, 0xeb, 0, 0xf3, 0xa4, 0xfc],
        vec![0xfd, 0xeb, 0, 0xf3, 0x48, 0xa5, 0xfc],
        vec![0xfd, 0xeb, 0, 0xf3, 0xaa, 0xfc],
        vec![0xfd, 0xeb, 0, 0xf3, 0xac, 0xfc],
    ]);
    let mut cases = Vec::new();
    for (kind, code) in codes.iter().enumerate() {
        for seed in 0..256 {
            let mut registers = std::array::from_fn(|index| value(seed, index as u64));
            registers[3] = BUFFER + 4096;
            registers[6] = BUFFER + 5000;
            registers[7] = BUFFER + 6000;
            registers[1] = seed % 80;
            registers[2] = seed % 3;
            let mut vectors = std::array::from_fn(|index| hash(seed, index as u64));
            if seed % 4 == 0 {
                vectors.fill(0);
            }
            if seed % 4 == 1 {
                vectors.fill(u64::MAX);
            }
            let memory = (0..BUFFER_SIZE)
                .map(|index| hash(seed, index as u64) as u8)
                .collect();
            cases.push((
                kind,
                Case {
                    code: code.clone(),
                    registers,
                    vectors,
                    flags: 0x202 | (hash(seed, 42) & ARITHMETIC_FLAGS),
                    memory: Some(memory),
                },
            ));
        }
    }
    let outcomes = run(
        runner,
        &cases
            .iter()
            .map(|(_, case)| Case {
                code: case.code.clone(),
                registers: case.registers,
                vectors: case.vectors,
                flags: case.flags,
                memory: case.memory.clone(),
            })
            .collect::<Vec<_>>(),
    );
    for ((kind, case), outcome) in cases.iter().zip(outcomes) {
        assert_eq!(outcome.signal, 0, "instruction case {kind}");
        let ir = lifted(Isa::X86_64, [case.code.as_slice(), &[0xc3]].concat()).expect("lifted");
        assert!(unsupported(&ir).is_none(), "{}", ir.render());
        let registers: Vec<_> = (0..16u16)
            .filter(|index| usable(*index))
            .map(|index| (index, case.registers[usize::from(index)]))
            .chain(vector_slots().map(|index| (index, case.vectors[vector_word(index).unwrap()])))
            .collect();
        let before = case.memory.as_ref().unwrap();
        let words: Vec<_> = before
            .chunks(8)
            .enumerate()
            .map(|(index, bytes)| {
                (
                    BUFFER + index as u64 * 8,
                    u64::from_le_bytes(bytes.try_into().unwrap()),
                )
            })
            .collect();
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &registers,
            memory: &words,
            step_limit: 1000,
        };
        let (after, memory) = eval::state_after(&ir, &setup).expect("interpreted");
        for (index, initial) in &registers {
            let actual = match vector_word(*index) {
                Some(word) => outcome.vectors[word],
                None => outcome.registers[usize::from(*index)],
            };
            assert_eq!(
                after.get(index).unwrap_or(initial),
                &actual,
                "case {kind}, register {}\n{}",
                name(*index),
                ir.render()
            );
        }
        for (offset, actual) in outcome.memory.as_ref().unwrap().iter().enumerate() {
            assert_eq!(
                *memory
                    .get(&(BUFFER + offset as u64))
                    .unwrap_or(&before[offset]),
                *actual,
                "case {kind}, byte {offset}"
            );
        }
    }
}

#[test]
fn explicit_breakpoint_interrupt_matches_the_processor() {
    let runner = runner().expect("an x86-64 compiler is required");
    let cases: Vec<_> = [vec![0xcc], vec![0xcd, 3]]
        .into_iter()
        .map(|code| Case {
            code,
            registers: [0; 16],
            flags: 0x202,
            vectors: [0; 32],
            memory: None,
        })
        .collect();
    for (case, outcome) in cases.iter().zip(run(runner, &cases)) {
        assert_eq!(outcome.signal, 5);
        let ir = lifted(Isa::X86_64, case.code.clone()).expect("lifted");
        assert!(unsupported(&ir).is_none());
        assert!(matches!(
            eval::run(&ir, &super::setup(&[])),
            eval::Outcome::Trap { .. }
        ));
    }
}
