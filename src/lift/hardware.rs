//! Checks the AArch64 lifter against the processor running the tests: random
//! data-processing instructions run once natively and once as lifted code in
//! the interpreter, from the same registers, and must leave the same
//! registers and satisfy the same conditions.
//!
//! Each case follows a flag-setting compare, so an instruction that reads
//! the flags reads ones the lifter knows.

use std::collections::{BTreeMap, HashSet};
use std::ffi::c_void;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use yaxpeax_arch::{Decoder, ReaderBuilder};
use yaxpeax_arm::armv8::a64::{self, Operand};

use super::lift;
use crate::ir::eval::{self, hash};
use crate::ir::{FunctionIr, Stmt};
use crate::loader::{Image, Isa};

/// The general registers a case may use: the harness keeps its state
/// pointer in x28, x18 belongs to the platform, and x29, x30 and sp hold
/// the frame.
fn usable(index: u16) -> bool {
    !matches!(index, 18 | 28 | 29 | 30)
}

/// Saves the callee-saved registers, keeps the state pointer in x28, and
/// loads NZCV and x0–x27 (but x18) from it.
const PROLOGUE: [u32; 23] = [
    0xa9ba_7bfd,
    0xa901_53f3,
    0xa902_5bf5,
    0xa903_63f7,
    0xa904_6bf9,
    0xa905_73fb,
    0xaa00_03fc,
    0xf940_7380,
    0xd51b_4200,
    0xa940_0780,
    0xa941_0f82,
    0xa942_1784,
    0xa943_1f86,
    0xa944_2788,
    0xa945_2f8a,
    0xa946_378c,
    0xa947_3f8e,
    0xa948_4790,
    0xa949_d393,
    0xa94a_db95,
    0xa94b_e397,
    0xa94c_eb99,
    0xf940_6f9b,
];

/// Stores x0–x27 (but x18) and NZCV back and returns.
const EPILOGUE: [u32; 23] = [
    0xa900_0780,
    0xa901_0f82,
    0xa902_1784,
    0xa903_1f86,
    0xa904_2788,
    0xa905_2f8a,
    0xa906_378c,
    0xa907_3f8e,
    0xa908_4790,
    0xa909_d393,
    0xa90a_db95,
    0xa90b_e397,
    0xa90c_eb99,
    0xf900_6f9b,
    0xd53b_4200,
    0xf900_7380,
    0xa941_53f3,
    0xa942_5bf5,
    0xa943_63f7,
    0xa944_6bf9,
    0xa945_73fb,
    0xa8c6_7bfd,
    0xd65f_03c0,
];

const RET: u32 = 0xd65f_03c0;
const NZCV: usize = 28;

/// x0–x27 by index, then NZCV, as the prologue and epilogue lay them out.
type State = [u64; 29];

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn pthread_jit_write_protect_np(enabled: i32);
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
    fn sigaction(signal: i32, action: *const SignalAction, old: *mut SignalAction) -> i32;
}

#[repr(C)]
struct SignalAction {
    handler: usize,
    mask: u32,
    flags: i32,
}

const SIGILL: i32 = 4;

/// The code page of the case running now, and whether its instruction
/// turned out to be one the processor does not define.
static RUNNING: AtomicUsize = AtomicUsize::new(0);
static UNDEFINED: AtomicBool = AtomicBool::new(false);

/// Steps over an undefined instruction in the case's code, so the case
/// ends and reports it; a fault anywhere else stays fatal.
extern "C" fn on_illegal(_: i32, _: *mut c_void, context: *mut c_void) {
    // The Darwin arm64 layout: the machine context pointer sits 48 bytes
    // into the user context, and its program counter 272 bytes into that.
    // SAFETY: the kernel passes a valid user context to the handler.
    unsafe {
        let machine = *(context.cast::<u8>().add(48).cast::<*mut u8>());
        let pc = machine.add(272).cast::<u64>();
        let base = RUNNING.load(Ordering::SeqCst) as u64;
        if base != 0 && (base..base + PAGE as u64).contains(&*pc) {
            *pc += 4;
            UNDEFINED.store(true, Ordering::SeqCst);
        } else {
            let default = SignalAction {
                handler: 0,
                mask: 0,
                flags: 0,
            };
            sigaction(SIGILL, &default, std::ptr::null_mut());
        }
    }
}

const PAGE: usize = 1 << 14;

/// A page the thread can write code into and run.
struct Page {
    base: *mut u32,
    len: usize,
}

impl Page {
    fn new() -> Self {
        const PROT_ALL: i32 = 1 | 2 | 4;
        const MAP_PRIVATE_ANON_JIT: i32 = 0x0002 | 0x1000 | 0x0800;
        let len = PAGE;
        static HANDLER: Once = Once::new();
        HANDLER.call_once(|| {
            const SA_SIGINFO: i32 = 0x40;
            let action = SignalAction {
                handler: on_illegal as *const () as usize,
                mask: 0,
                flags: SA_SIGINFO,
            };
            // SAFETY: installs a handler that only touches the case's state.
            unsafe { sigaction(SIGILL, &action, std::ptr::null_mut()) };
        });
        // SAFETY: an anonymous mapping, checked below.
        let base = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                PROT_ALL,
                MAP_PRIVATE_ANON_JIT,
                -1,
                0,
            )
        };
        assert!(base as isize != -1, "mapping a code page");
        Self {
            base: base.cast(),
            len,
        }
    }

    /// Runs `body` between the prologue and epilogue on `state`; false when
    /// the processor does not define one of its instructions.
    fn run(&self, body: &[u32], state: &mut State) -> bool {
        let code: Vec<u32> = PROLOGUE
            .iter()
            .chain(body)
            .chain(&EPILOGUE)
            .copied()
            .collect();
        assert!(code.len() * 4 <= self.len);
        // SAFETY: the page is this thread's to write while write protection
        // is off, and the code saves and restores what the calling
        // convention requires.
        unsafe {
            pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(code.as_ptr(), self.base, code.len());
            pthread_jit_write_protect_np(1);
            sys_icache_invalidate(self.base.cast(), code.len() * 4);
            let entry: extern "C" fn(*mut u64) = std::mem::transmute(self.base);
            UNDEFINED.store(false, Ordering::SeqCst);
            RUNNING.store(self.base as usize, Ordering::SeqCst);
            entry(state.as_mut_ptr());
            RUNNING.store(0, Ordering::SeqCst);
        }
        !UNDEFINED.load(Ordering::SeqCst)
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: the mapping made in `new`.
        unsafe { munmap(self.base.cast(), self.len) };
    }
}

fn decode(word: u32) -> Option<a64::Instruction> {
    let bytes = word.to_le_bytes();
    let mut reader = ReaderBuilder::<u64, u8>::read_from(&bytes[..]);
    a64::InstDecoder::default().decode(&mut reader).ok()
}

/// Whether every operand is a usable register, a condition or an immediate.
fn register_only(instruction: &a64::Instruction) -> bool {
    instruction.operands.iter().all(|operand| match *operand {
        Operand::Nothing
        | Operand::ConditionCode(_)
        | Operand::Immediate(_)
        | Operand::Imm64(_)
        | Operand::Imm16(_)
        | Operand::ImmShift(..) => true,
        Operand::Register(_, index) | Operand::RegShift(_, _, _, index) => {
            index == 31 || usable(index)
        }
        Operand::RegisterOrSP(_, index) => index != 31 && usable(index),
        _ => false,
    })
}

/// A random instruction from the data-processing groups, which read and
/// write only registers and flags.
fn instruction(seed: u64) -> Option<(u32, a64::Instruction)> {
    let bits = hash(seed, 1) as u32;
    let word = if hash(seed, 2) & 1 == 0 {
        (bits & !(0b111 << 26)) | (0b100 << 26)
    } else {
        (bits & !(0b111 << 25)) | (0b101 << 25)
    };
    let decoded = decode(word)?;
    register_only(&decoded).then_some((word, decoded))
}

/// A compare that sets every flag from two usable registers: `cmp`, `cmn`
/// or `tst`, at either width.
fn compare(seed: u64) -> u32 {
    const FORMS: [u32; 6] = [
        0xeb00_001f,
        0x6b00_001f,
        0xab00_001f,
        0x2b00_001f,
        0xea00_001f,
        0x6a00_001f,
    ];
    let register = |key| {
        let index = (hash(seed, key) % 28) as u32;
        if index == 18 { 0 } else { index }
    };
    FORMS[(hash(seed, 3) % 6) as usize] | register(4) << 16 | register(5) << 5
}

/// Register values that reach the edges of the arithmetic often.
fn value(seed: u64, key: u64) -> u64 {
    const EDGES: [u64; 9] = [
        0,
        1,
        u64::MAX,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0x1_0000_0000,
    ];
    let pick = hash(seed, key);
    match pick % 4 {
        0 => EDGES[(pick >> 8) as usize % EDGES.len()],
        1 => (pick >> 8) % 64,
        2 => (pick >> 8) as u32 as u64,
        _ => hash(seed, key ^ 0x55),
    }
}

fn lifted(words: &[u32]) -> Option<FunctionIr> {
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let len = code.len() as u64;
    let image = Image::from_code(Isa::AArch64, 0, code);
    let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
    ir.blocks = lift(&image, 0, len, &HashSet::new()).ok()?;
    Some(ir)
}

fn setup<'a>(registers: &'a [(u16, u64)]) -> eval::Setup<'a> {
    eval::Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers,
        memory: &[],
        step_limit: 100,
    }
}

/// Whether the condition with encoding `code` holds for `nzcv` as the
/// processor reads it.
fn condition(code: u32, nzcv: u64) -> bool {
    let (n, z, c, v) = (
        nzcv >> 31 & 1 == 1,
        nzcv >> 30 & 1 == 1,
        nzcv >> 29 & 1 == 1,
        nzcv >> 28 & 1 == 1,
    );
    let base = match code >> 1 {
        0 => z,
        1 => c,
        2 => n,
        3 => v,
        4 => c && !z,
        5 => n == v,
        _ => n == v && !z,
    };
    if code & 1 == 1 { !base } else { base }
}

#[derive(Default)]
struct Findings {
    unsupported: BTreeMap<String, usize>,
    /// Disagreements by kind, each with how often it occurred and one example.
    registers: BTreeMap<String, (usize, String)>,
    conditions: BTreeMap<String, (usize, String)>,
    tried: usize,
    /// Encodings the decoder accepts but the processor does not define.
    undefined: usize,
}

fn note(
    kinds: &mut BTreeMap<String, (usize, String)>,
    kind: String,
    example: impl FnOnce() -> String,
) {
    kinds.entry(kind).or_insert_with(|| (0, example())).0 += 1;
}

fn check(page: &Page, seed: u64, findings: &mut Findings) {
    // One random instruction, or two, so that one can read the flags or
    // overwrite the operands of the other.
    let mut instructions = Vec::new();
    for (index, salt) in [0, 0x5eed].into_iter().enumerate() {
        if index == 1 && hash(seed, 7) & 1 == 0 {
            break;
        }
        let Some(instruction) = instruction(seed ^ salt) else {
            return;
        };
        instructions.push(instruction);
    }
    let setter = compare(seed);
    let body: Vec<u32> = std::iter::once(setter)
        .chain(instructions.iter().map(|(word, _)| *word))
        .collect();
    let kind = instructions
        .iter()
        .map(|(_, decoded)| format!("{:?}", decoded.opcode))
        .collect::<Vec<_>>()
        .join(" then ");
    let Some(ir) = lifted(&[body.as_slice(), &[RET]].concat()) else {
        return;
    };
    if let Some(text) = ir
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .find_map(|stmt| match stmt {
            Stmt::Unsupported { text } => Some(text.clone()),
            _ => None,
        })
    {
        let name = text.split(' ').next().unwrap_or(&text).to_owned();
        *findings.unsupported.entry(name).or_default() += 1;
        return;
    }
    let mut state: State = [0; 29];
    for (index, slot) in state.iter_mut().enumerate().take(28) {
        if usable(index as u16) {
            *slot = value(seed, 0x100 + index as u64);
        }
    }
    state[NZCV] = (hash(seed, 6) & 0xf) << 28;
    let initial = state;
    if !page.run(&body, &mut state) {
        findings.undefined += 1;
        return;
    }
    findings.tried += 1;

    let registers: Vec<(u16, u64)> = (0..28u16)
        .filter(|index| usable(*index))
        .map(|index| (index, initial[usize::from(index)]))
        .collect();
    let describe = || {
        let inputs: Vec<String> = registers
            .iter()
            .map(|(index, value)| format!("x{index}={value:#x}"))
            .collect();
        let code: Vec<String> = body
            .iter()
            .map(|word| {
                let text = decode(*word).map(|d| d.to_string()).unwrap_or_default();
                format!("{text} ({word:#010x})")
            })
            .collect();
        format!(
            "{}\n  in: {}\n{}",
            code.join(" ; "),
            inputs.join(" "),
            ir.render()
        )
    };
    match eval::registers_after(&ir, &setup(&registers)) {
        Ok(after) => {
            let differ: Vec<String> = registers
                .iter()
                .filter_map(|(index, start)| {
                    let modelled = after.get(index).copied().unwrap_or(*start);
                    let real = state[usize::from(*index)];
                    (modelled != real)
                        .then(|| format!("x{index}: lifted {modelled:#x}, processor {real:#x}"))
                })
                .collect();
            if !differ.is_empty() {
                note(&mut findings.registers, kind, || {
                    format!("{}\n  {}", describe(), differ.join("\n  "))
                });
                return;
            }
        }
        // AArch64 divides by zero to zero, which C leaves undefined and the
        // IR does too.
        Err("division by zero") => {
            findings.undefined += 1;
            return;
        }
        Err(reason) => {
            note(&mut findings.registers, kind, || {
                format!("{}\n  {reason}", describe())
            });
            return;
        }
    }

    // b.<cond> +12; mov x0, #0; ret; mov x0, #1; ret
    let setter_kind = decode(setter).map_or(String::new(), |d| format!("{:?}", d.opcode));
    for code in 0..14 {
        let tail = [0x5400_0060 | code, 0xd280_0000, RET, 0xd280_0020, RET];
        let Some(ir) = lifted(&[body.as_slice(), &tail].concat()) else {
            continue;
        };
        // Flags the lifter does not know are left to the branch.
        let unknown = ir
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|stmt| matches!(stmt, Stmt::BrifFlags { .. }));
        if unknown {
            continue;
        }
        let expected = condition(code, state[NZCV]);
        match eval::run(&ir, &setup(&registers)) {
            eval::Outcome::Return { value, .. } if (value == 1) == expected => {}
            outcome => note(
                &mut findings.conditions,
                format!("{setter_kind} then {kind}, condition {code}"),
                || {
                    format!(
                        "{}\n  condition {code}: processor {expected}, lifted {outcome:?}\n{}",
                        describe(),
                        ir.render()
                    )
                },
            ),
        }
    }
}

#[test]
fn lifted_instructions_match_the_processor() {
    let page = Page::new();
    let mut findings = Findings::default();
    for seed in 0..100_000 {
        check(&page, seed, &mut findings);
    }
    let shown = |kinds: &BTreeMap<String, (usize, String)>| {
        kinds
            .iter()
            .map(|(kind, (count, example))| format!("{kind}: {count} cases, as in\n{example}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    assert!(
        findings.registers.is_empty() && findings.conditions.is_empty(),
        "of {} cases, {} kinds leave different registers and {} decide a condition differently\n\n{}\n\n{}\n\nunsupported: {:?}",
        findings.tried,
        findings.registers.len(),
        findings.conditions.len(),
        shown(&findings.registers),
        shown(&findings.conditions),
        findings.unsupported,
    );
    eprintln!(
        "{} cases agree, {} undefined; unsupported: {:?}",
        findings.tried, findings.undefined, findings.unsupported
    );
}
