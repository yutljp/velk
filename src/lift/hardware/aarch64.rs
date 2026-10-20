//! AArch64 data-processing instructions, run natively from a code page.

use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Once;

use yaxpeax_arch::{Decoder, ReaderBuilder};
use yaxpeax_arm::armv8::a64::{self, Operand};

use super::{
    Findings, branches_on_unknown_flags, condition_differs, float_bits, lifted,
    register_differences, same_float_bits, unsupported, value,
};
use crate::ir::FunctionIr;
use crate::ir::eval::{self, hash};
use crate::loader::Isa;

/// The general registers a case may use: the harness keeps its state
/// pointer in x28, x18 belongs to the platform, and x29, x30 and sp hold
/// the frame.
fn usable(index: u16) -> bool {
    !matches!(index, 18 | 28 | 29 | 30)
}

/// Saves the callee-saved registers, keeps the state pointer in x28, and
/// loads v0–v7, NZCV and x0–x27 (but x18) from it.
const PROLOGUE: [u32; 27] = [
    0xa9ba_7bfd,
    0xa901_53f3,
    0xa902_5bf5,
    0xa903_63f7,
    0xa904_6bf9,
    0xa905_73fb,
    0xaa00_03fc,
    0xad47_8780,
    0xad48_8f82,
    0xad49_9784,
    0xad4a_9f86,
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

/// Stores v0–v7, x0–x27 (but x18) and NZCV back and returns.
const EPILOGUE: [u32; 27] = [
    0xad07_8780,
    0xad08_8f82,
    0xad09_9784,
    0xad0a_9f86,
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

/// x0–x27 by index, then NZCV, a word of padding, and the halves of v0–v7
/// from word 30, as the prologue and epilogue lay them out.
type State = [u64; 46];

const VECTORS: usize = 30;

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
const SIGBUS: i32 = 10;
const SIGSEGV: i32 = 11;

thread_local! {
    /// The code page of the case this thread runs now, and whether its
    /// instruction turned out to be one the processor does not define or
    /// an access it faults on.
    static RUNNING: Cell<usize> = const { Cell::new(0) };
    static UNDEFINED: Cell<bool> = const { Cell::new(false) };
}

/// Steps over an undefined instruction or a faulting access in the case's
/// code, so the case ends and reports it; a fault anywhere else stays fatal.
extern "C" fn on_illegal(signal: i32, _: *mut c_void, context: *mut c_void) {
    // The Darwin arm64 layout: the machine context pointer sits 48 bytes
    // into the user context, and its program counter 272 bytes into that.
    // SAFETY: the kernel passes a valid user context to the handler.
    unsafe {
        let machine = *(context.cast::<u8>().add(48).cast::<*mut u8>());
        let pc = machine.add(272).cast::<u64>();
        let base = RUNNING.with(Cell::get) as u64;
        if base != 0 && (base..base + PAGE as u64).contains(&*pc) {
            *pc += 4;
            UNDEFINED.with(|undefined| undefined.set(true));
        } else {
            let default = SignalAction {
                handler: 0,
                mask: 0,
                flags: 0,
            };
            sigaction(signal, &default, std::ptr::null_mut());
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
            for signal in [SIGILL, SIGBUS, SIGSEGV] {
                unsafe { sigaction(signal, &action, std::ptr::null_mut()) };
            }
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
            UNDEFINED.with(|undefined| undefined.set(false));
            RUNNING.with(|running| running.set(self.base as usize));
            entry(state.as_mut_ptr());
            RUNNING.with(|running| running.set(0));
        }
        !UNDEFINED.with(Cell::get)
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

/// Whether every operand is a usable register, a condition or an immediate;
/// vector registers only from v0 to v7, which the harness loads.
fn register_only(instruction: &a64::Instruction) -> bool {
    instruction.operands.iter().all(|operand| match *operand {
        Operand::Nothing
        | Operand::ConditionCode(_)
        | Operand::Immediate(_)
        | Operand::Imm64(_)
        | Operand::Imm16(_)
        | Operand::ImmediateDouble(_)
        | Operand::ImmShift(..) => true,
        Operand::SIMDRegister(_, number)
        | Operand::SIMDRegisterElements(_, number, _)
        | Operand::SIMDRegisterElementsLane(_, number, ..) => number < 8,
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
    let word = match hash(seed, 2) % 6 {
        // Advanced SIMD on vectors, and on scalars.
        4 => (bits & !(0b1111 << 25 | 1 << 31)) | (0b0111 << 25),
        5 => (bits & !(0b11 << 30 | 0b1111 << 25)) | (0b01 << 30 | 0b1111 << 25),
        0 => (bits & !(0b111 << 26)) | (0b100 << 26),
        1 => (bits & !(0b111 << 25)) | (0b101 << 25),
        // Scalar floating point: data processing and conversions, and the
        // fused multiply-adds.
        2 => (bits & !(0b1_1111 << 24 | 1 << 30)) | (0b1_1110 << 24),
        _ => (bits & !(0b1_1111 << 24 | 1 << 30)) | (0b1_1111 << 24),
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

fn lift_words(words: &[u32]) -> Option<FunctionIr> {
    lifted(
        Isa::AArch64,
        words.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )
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
    let Some(ir) = lift_words(&[body.as_slice(), &[RET]].concat()) else {
        return;
    };
    let mut state: State = [0; 46];
    for (index, slot) in state.iter_mut().enumerate().take(28) {
        if usable(index as u16) {
            *slot = value(seed, 0x100 + index as u64);
        }
    }
    for half in 0..16 {
        state[VECTORS + half] = float_bits(seed, 0x200 + half as u64);
    }
    state[NZCV] = (hash(seed, 6) & 0xf) << 28;
    let initial = state;
    if !page.run(&body, &mut state) {
        findings.undefined += 1;
        return;
    }
    // Only an instruction the processor defines counts as one to lift.
    if let Some(name) = unsupported(&ir) {
        *findings.unsupported.entry(name).or_default() += 1;
        return;
    }
    findings.tried += 1;

    let vector_slot = |half: usize| crate::arch::aarch64::V0 + half as u16;
    let registers: Vec<(u16, u64)> = (0..28u16)
        .filter(|index| usable(*index))
        .map(|index| (index, initial[usize::from(index)]))
        .chain((0..16).map(|half| (vector_slot(half), initial[VECTORS + half])))
        .collect();
    let processor = |index: u16| match index.checked_sub(crate::arch::aarch64::V0) {
        Some(half) => state[VECTORS + usize::from(half)],
        None => state[usize::from(index)],
    };
    let name = |index: u16| match index.checked_sub(crate::arch::aarch64::V0) {
        Some(half) if half % 2 == 1 => format!("v{}_hi", half / 2),
        Some(half) => format!("d{}", half / 2),
        None => format!("x{index}"),
    };
    let describe = || {
        let inputs: Vec<String> = registers
            .iter()
            .map(|(index, value)| format!("{}={value:#x}", name(*index)))
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
    if let Some(differ) = register_differences(&ir, &registers, processor, name, |index, a, b| {
        if index >= crate::arch::aarch64::V0 {
            same_float_bits(a, b)
        } else {
            a == b
        }
    }) {
        Findings::note(&mut findings.registers, kind, || {
            format!("{}\n  {differ}", describe())
        });
        return;
    }

    // b.<cond> +12; mov x0, #0; ret; mov x0, #1; ret
    let setter_kind = decode(setter).map_or(String::new(), |d| format!("{:?}", d.opcode));
    for code in 0..14 {
        let tail = [0x5400_0060 | code, 0xd280_0000, RET, 0xd280_0020, RET];
        let Some(ir) = lift_words(&[body.as_slice(), &tail].concat()) else {
            continue;
        };
        // Flags the lifter does not know are left to the branch.
        if branches_on_unknown_flags(&ir) {
            continue;
        }
        let expected = condition(code, state[NZCV]);
        if let Some(differ) = condition_differs(&ir, &registers, expected) {
            Findings::note(
                &mut findings.conditions,
                format!("{setter_kind} then {kind}, condition {code}"),
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

#[test]
fn lifted_instructions_match_the_processor() {
    let page = Page::new();
    let mut findings = Findings::default();
    for seed in 0..200_000 {
        check(&page, seed, &mut findings);
    }
    findings.assert_agreement();
}

/// The pointer registers memory cases address through; they point into the
/// middle of the buffer, and every other register holds a small value.
const POINTERS: [u16; 4] = [1, 2, 3, 4];
const BUFFER: usize = 8192;

/// Whether a load or store addresses only through a pointer register, by
/// an offset that stays within the buffer, and is not one whose result the
/// architecture leaves unpredictable (a written-back base that is also
/// loaded or stored).
fn buffer_access(instruction: &a64::Instruction) -> bool {
    use a64::Opcode as O;
    let plain = matches!(
        instruction.opcode,
        O::LDR
            | O::LDRB
            | O::LDRH
            | O::LDRSB
            | O::LDRSH
            | O::LDRSW
            | O::STR
            | O::STRB
            | O::STRH
            | O::LDUR
            | O::LDURB
            | O::LDURH
            | O::LDURSB
            | O::LDURSH
            | O::LDURSW
            | O::STUR
            | O::STURB
            | O::STURH
            | O::LDP
            | O::STP
            | O::LDPSW
            | O::LDNP
            | O::STNP
    );
    let mut base = None;
    let mut writeback = false;
    let mut data = Vec::new();
    let operands_fit = instruction.operands.iter().all(|operand| match *operand {
        Operand::Nothing => true,
        Operand::Register(_, index) | Operand::RegisterOrSP(_, index) => {
            data.push(index);
            index == 31 || usable(index) && !POINTERS.contains(&index)
        }
        Operand::SIMDRegister(_, number) => number < 8,
        Operand::RegPreIndex(reg, offset, back) => {
            base = Some(reg);
            writeback = back;
            offset.unsigned_abs() <= 2048
        }
        Operand::RegPostIndex(reg, offset) => {
            base = Some(reg);
            writeback = true;
            offset.unsigned_abs() <= 2048
        }
        Operand::RegRegOffset(reg, index, ..) => {
            base = Some(reg);
            usable(index) && !POINTERS.contains(&index) && index != 31
        }
        _ => false,
    });
    let pair_loads_one = matches!(instruction.opcode, O::LDP | O::LDPSW | O::LDNP)
        && data.len() == 2
        && data[0] == data[1];
    plain
        && operands_fit
        && !pair_loads_one
        && base.is_some_and(|base| POINTERS.contains(&base))
        && !(writeback && base.is_some_and(|base| data.contains(&base)))
}

fn memory_instruction(seed: u64) -> Option<(u32, a64::Instruction)> {
    // Loads and stores: bit 27 set and bit 25 clear, with a pointer register
    // as the base every form names in bits 5 to 9.
    let base = POINTERS[(hash(seed, 2) % 4) as usize] as u32;
    let word = ((hash(seed, 1) as u32 | 1 << 27) & !(1 << 25) & !(0x1f << 5)) | base << 5;
    let decoded = decode(word)?;
    buffer_access(&decoded).then_some((word, decoded))
}

#[test]
fn lifted_memory_accesses_match_the_processor() {
    let page = Page::new();
    let mut findings = Findings::default();
    let mut buffer = vec![0u8; BUFFER];
    let middle = buffer.as_ptr() as u64 + (BUFFER / 2) as u64;
    for seed in 0..60_000u64 {
        let Some((word, decoded)) = memory_instruction(seed) else {
            continue;
        };
        let Some(ir) = lift_words(&[word, RET]) else {
            continue;
        };
        if let Some(name) = unsupported(&ir) {
            *findings.unsupported.entry(name).or_default() += 1;
            continue;
        }
        let mut state: State = [0; 46];
        for (index, slot) in state.iter_mut().enumerate().take(28) {
            if POINTERS.contains(&(index as u16)) {
                *slot = middle + hash(seed, 0x300 + index as u64) % 256;
            } else if usable(index as u16) {
                *slot = hash(seed, 0x100 + index as u64) % 64;
            }
        }
        for half in 0..16 {
            state[VECTORS + half] = float_bits(seed, 0x200 + half as u64);
        }
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = hash(seed, 0x400 + index as u64) as u8;
        }
        let initial = state;
        let before = buffer.clone();
        if !page.run(&[word], &mut state) {
            findings.undefined += 1;
            continue;
        }
        findings.tried += 1;
        let registers: Vec<(u16, u64)> = (0..28u16)
            .filter(|index| usable(*index))
            .map(|index| (index, initial[usize::from(index)]))
            .chain((0..16).map(|half| {
                (
                    crate::arch::aarch64::V0 + half as u16,
                    initial[VECTORS + half],
                )
            }))
            .collect();
        let words: Vec<(u64, u64)> = before
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| {
                (
                    buffer.as_ptr() as u64 + index as u64 * 8,
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
        let kind = format!("{:?}", decoded.opcode);
        let describe = || format!("{decoded} ({word:#010x})\n{}", ir.render());
        let (after, memory) = match eval::state_after(&ir, &setup) {
            Ok(state) => state,
            Err(reason) => {
                Findings::note(&mut findings.registers, kind, || {
                    format!("{}\n  {reason}", describe())
                });
                continue;
            }
        };
        let processor = |index: u16| match index.checked_sub(crate::arch::aarch64::V0) {
            Some(half) => state[VECTORS + usize::from(half)],
            None => state[usize::from(index)],
        };
        let mut differ: Vec<String> = registers
            .iter()
            .filter_map(|(index, start)| {
                let lifted = after.get(index).copied().unwrap_or(*start);
                (lifted != processor(*index)).then(|| {
                    format!(
                        "register {index}: lifted {lifted:#x}, processor {:#x}",
                        processor(*index)
                    )
                })
            })
            .collect();
        for (offset, real) in buffer.iter().enumerate() {
            let address = buffer.as_ptr() as u64 + offset as u64;
            let lifted = memory.get(&address).copied().unwrap_or(before[offset]);
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
