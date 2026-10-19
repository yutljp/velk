//! x86-64 instructions that read and write only general registers and
//! flags, run by a small program built for x86-64 (`x86_64.c`). On an
//! AArch64 Mac the system runs that program by translation.

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
use crate::ir::eval::hash;
use crate::loader::Isa;

const RSP: u16 = 4;
const R15: u16 = 15;

/// The general registers a case may use: the runner keeps the stack in rsp
/// and its state pointer in r15.
fn usable(index: u16) -> bool {
    index != RSP && index != R15
}

fn name(index: u16) -> String {
    match index.checked_sub(crate::arch::x86::XMM0) {
        Some(half) if half % 2 == 1 => format!("xmm{}_hi", half / 2),
        Some(half) => format!("xmm{}", half / 2),
        None => NAMES[usize::from(index)].to_owned(),
    }
}

const NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// The flags a case starts from: carry, parity, adjust, zero, sign and
/// overflow, with the bit that is always set.
const ARITHMETIC_FLAGS: u64 = 0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x800;

struct Case {
    code: Vec<u8>,
    registers: [u64; 16],
    flags: u64,
    /// xmm0 to xmm7, as halves, low first.
    vectors: [u64; 16],
}

struct Outcome {
    registers: [u64; 16],
    flags: u64,
    vectors: [u64; 16],
    /// The signal the code raised, or zero.
    signal: u8,
}

/// Builds the runner, or None when this machine has no compiler for it.
fn runner() -> Option<Command> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/hardware");
    std::fs::create_dir_all(&dir).ok()?;
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lift/hardware/x86_64.c");
    let binary = dir.join("x86_64_runner");
    let translated = cfg!(target_arch = "aarch64");
    let mut compile = Command::new(if translated { "clang" } else { "cc" });
    if translated {
        compile.args(["-arch", "x86_64"]);
    }
    let built = compile
        .arg("-O1")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()?
        .success();
    if !built {
        return None;
    }
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
        input.extend((case.code.len() as u32).to_le_bytes());
        input.extend(&case.code);
        for register in case.registers {
            input.extend(register.to_le_bytes());
        }
        input.extend(case.flags.to_le_bytes());
        for half in case.vectors {
            input.extend(half.to_le_bytes());
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
    let record = 33 * 8 + 1;
    assert_eq!(output.stdout.len(), cases.len() * record);
    output
        .stdout
        .chunks(record)
        .map(|chunk| {
            let word = |index: usize| {
                u64::from_le_bytes(chunk[index * 8..index * 8 + 8].try_into().expect("8 bytes"))
            };
            Outcome {
                registers: std::array::from_fn(word),
                flags: word(16),
                vectors: std::array::from_fn(|half| word(17 + half)),
                signal: chunk[record - 1],
            }
        })
        .collect()
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
                || (register.is_xmm() && register.number() < 8)
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
    match hash(seed, 0x30) % 7 {
        // Bit scans and counts: bsf, bsr, and with F3 popcnt, tzcnt, lzcnt.
        6 => {
            let (prefix, opcode) = [
                (None, 0xbc),
                (None, 0xbd),
                (Some(0xf3), 0xb8),
                (Some(0xf3), 0xbc),
                (Some(0xf3), 0xbd),
            ][(hash(seed, 0x35) % 5) as usize];
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
    let mut instructions = vec![decode(&body)?];
    for (index, salt) in [0, 0x5eed].into_iter().enumerate() {
        if index == 1 && hash(seed, 7) & 1 == 0 {
            break;
        }
        let (bytes, decoded) = instruction(seed ^ salt, info)?;
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
        .chain((0..16u16).map(|half| {
            (
                crate::arch::x86::XMM0 + half,
                float_bits(seed, 0x200 + u64::from(half)),
            )
        }))
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
            let (mut registers, mut vectors) = ([0; 16], [0; 16]);
            for (index, value) in &case.registers {
                match index.checked_sub(crate::arch::x86::XMM0) {
                    Some(half) => vectors[usize::from(half)] = *value,
                    None => registers[usize::from(*index)] = *value,
                }
            }
            Case {
                code: case.body.clone(),
                registers,
                flags: 0x2 | (hash(case.seed, 6) & ARITHMETIC_FLAGS),
                vectors,
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
            |index| match index.checked_sub(crate::arch::x86::XMM0) {
                Some(half) => outcome.vectors[usize::from(half)],
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
