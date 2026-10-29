//! Strict execution using the interpreter's expression and register semantics.

mod cxx;
pub(crate) mod hooks;
mod imports;
pub(crate) mod io;
mod reads;
mod strings;
pub(crate) use strings::recover_strings;
mod values;
mod windows;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::emulation::{HEAP_SIZE, Memory, Options, Report, invalid};
use crate::error::Result;
use crate::ir::{Block, CallKind, CallOutput, Convention, Expr, RegRef, Stmt};
use crate::loader::{Image, Isa};
use crate::ssa::ranges::Fact;

use super::Machine;

const MAX_CODE_SIZE: u64 = 1 << 16;

struct Runner<'a> {
    files: super::stdio::Files<u8>,
    streams: [u64; 3],
    input: Vec<u8>,
    input_position: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    machine: Machine<'a>,
    facts: HashMap<u16, Fact>,
    image: &'a Image,
    options: &'a Options,
    deadline: Option<Instant>,
    steps: usize,
    instructions: u64,
    address: u64,
    ends: HashSet<u64>,
    trace: Vec<String>,
    heap_base: u64,
    heap_next: u64,
    signal_handlers: BTreeMap<u32, u64>,
    ptrace_traceme_count: u8,
    anti_analysis: Vec<String>,
    alarm: u64,
    random: super::random::Random,
    cxx_locale: Option<super::cxx::Locale>,
    return_cleanup: u64,
    allocations: HashSet<u64>,
    code: HashMap<u64, Vec<Block>>,
    recovery: Option<strings::Recovery>,
    windows: Option<windows::Process>,
    api_calls: Vec<crate::emulation::ApiCall>,
}

#[derive(Debug)]
enum Stop {
    Return,
    Exit,
    End,
    Trap,
    StackCheckFail,
    Steps,
    Time,
    Error(String),
}

pub(crate) fn physical_registers(isa: Isa) -> Vec<u16> {
    match isa {
        Isa::X86_64 => (0..82).collect(),
        Isa::I386 => (0..8).chain(16..82).collect(),
        Isa::AArch64 => (0..97).collect(),
        Isa::Arm32 => (0..16).chain(64..96).collect(),
        Isa::Unsupported => Vec::new(),
    }
}

pub(crate) fn run(
    image: &Image,
    start: u64,
    options: &Options,
    deadline: Option<Instant>,
) -> Result<Report> {
    let Some(limit) = Instant::now().checked_add(Duration::from_millis(options.time_limit_ms))
    else {
        return Err(invalid("timeLimitMs overflows the clock"));
    };
    let deadline = Some(deadline.map_or(limit, |end| end.min(limit)));
    run_with_recovery(image, start, options, deadline, None).map(|(report, _)| report)
}

pub(crate) fn run_bounded(
    image: &Image,
    start: u64,
    options: &Options,
    deadline: Option<Instant>,
) -> Result<Report> {
    run_with_recovery(image, start, options, deadline, None).map(|(report, _)| report)
}

fn run_with_recovery(
    image: &Image,
    start: u64,
    options: &Options,
    deadline: Option<Instant>,
    recovery: Option<strings::Recovery>,
) -> Result<(Report, Option<strings::Recovery>)> {
    if image.isa == Isa::Unsupported || image.byte_order() == Some(object::Endianness::Big) {
        return Err(invalid(
            "execution requires a supported little-endian architecture",
        ));
    }
    let strict = match Memory::with_tls(
        image,
        match &options.tls_base {
            Some(word) => match word.value() {
                Ok(value) => Some(value),
                Err(error) => return Err(error),
            },
            None => None,
        },
    ) {
        Ok(memory) => memory,
        Err(error) => return Err(invalid(error)),
    };
    let heap_base = strict.heap_base;
    let convention = super::Convention {
        arguments: &[],
        clobbered: &[],
    };
    let mut machine = Machine {
        strict_memory: Some(strict),
        source: None,
        isa: image.isa,
        convention: &convention,
        seed: 0,
        registers: HashMap::new(),
        memory: HashMap::new(),
        calls: Vec::new(),
        blocks: &[],
        block_indices_by_address: HashMap::new(),
    };
    let physical = physical_registers(image.isa);
    let stack = match initialize_registers(&mut machine, image, options, &physical) {
        Ok(stack) => stack,
        Err(error) => return Err(error),
    };
    let width = crate::arch::pointer_bytes(image.isa);
    if let Err(error) = initialize_arguments(&mut machine, image, start, options, stack, width) {
        return Err(error);
    }
    let mut ends = HashSet::new();
    for end in &options.end {
        match end.value() {
            Ok(value) => {
                ends.insert(image.code_address(value));
            }
            Err(error) => return Err(error),
        }
    }
    let input = match &options.stdin {
        Some(input) => match input.bytes() {
            Ok(bytes) => bytes,
            Err(error) => return Err(error),
        },
        None => Vec::new(),
    };
    // Caller-provided heap bytes are reserved before malloc starts allocating.
    let mut heap_next = heap_base;
    for &address in machine.memory.keys() {
        if (heap_base..heap_base + HEAP_SIZE).contains(&address) {
            heap_next = heap_next.max(address + 1);
        }
    }
    for write in &options.memory {
        let address = match write.address.value() {
            Ok(address) => address,
            Err(error) => return Err(error),
        };
        let size = write
            .bytes
            .as_ref()
            .map_or(u64::from(write.width.unwrap_or(0)), |bytes| {
                bytes.len() as u64
            });
        let end = address.saturating_add(size);
        if size != 0 && address < heap_base + HEAP_SIZE && end > heap_base {
            heap_next = heap_next.max(end.min(heap_base + HEAP_SIZE));
        }
    }
    let mut files = options.files.clone();
    let tracer_process_id = if options.anti_analysis.debugger_present {
        options.anti_analysis.tracer_process_id
    } else {
        0
    };
    let status = format!(
        "Name:\tprogram\nState:\tR (running)\nPid:\t1000\nPPid:\t{}\nTracerPid:\t{}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
        options.anti_analysis.parent_process_id, tracer_process_id
    );
    files
        .entry("/proc/self/status".to_owned())
        .or_insert_with(|| status.into_bytes());
    files.entry("/proc/self/maps".to_owned()).or_insert_with(|| {
        b"00400000-00401000 r-xp 00000000 00:00 0 [program]\n7fff0000-80000000 rw-p 00000000 00:00 0 [stack]\n".to_vec()
    });
    let mut runner = Runner {
        files: match super::stdio::Files::new(files) {
            Ok(files) => files,
            Err(error) => return Err(invalid(error)),
        },
        streams: [0; 3],
        input,
        input_position: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
        machine,
        facts: HashMap::new(),
        image,
        options,
        deadline,
        steps: 0,
        instructions: 0,
        address: image.code_address(start),
        ends,
        trace: Vec::new(),
        heap_base,
        heap_next,
        signal_handlers: BTreeMap::new(),
        ptrace_traceme_count: 0,
        anti_analysis: Vec::new(),
        alarm: 0,
        random: super::random::Random::default(),
        cxx_locale: None,
        return_cleanup: 0,
        allocations: HashSet::new(),
        code: HashMap::new(),
        recovery,
        windows: None,
        api_calls: Vec::new(),
    };
    if let Err(error) = runner.initialize_windows() {
        return Err(invalid(error));
    }
    if let Err(error) = initialize_memory(&mut runner.machine, options) {
        return Err(error);
    }
    if let Err(error) = runner.initialize_io(start, stack) {
        return Err(invalid(error));
    }
    let before = runner.machine.memory.clone();
    if runner.recovery.is_some() {
        let sp = crate::arch::stack_pointer(image.isa);
        for &register in &physical {
            if register != sp {
                runner.facts.insert(register, Fact::TOP);
            }
        }
        if matches!(image.isa, Isa::Arm32 | Isa::AArch64) {
            runner.assign_fact(
                RegRef {
                    index: if image.isa == Isa::Arm32 { 14 } else { 30 },
                    width: width * 8,
                },
                Fact::constant(0),
            );
        } else {
            runner.machine.store(stack, 0, width);
        }
    }
    let stopped = match runner.windows_callbacks() {
        Ok(()) => runner.execute(start, 0),
        Err(stop) => stop,
    };
    Ok(runner.report(stopped, &before, stack, &physical))
}

fn initialize_registers(
    machine: &mut Machine<'_>,
    image: &Image,
    options: &Options,
    physical: &[u16],
) -> Result<u64> {
    for &register in physical {
        machine.registers.insert(register, 0);
    }
    if matches!(image.isa, Isa::X86_64 | Isa::I386) {
        // The C calling conventions enter with the direction flag clear.
        machine
            .registers
            .insert(crate::lift::execution::DIRECTION, 0);
    }
    let sp = crate::arch::stack_pointer(image.isa);
    let width = crate::arch::pointer_bytes(image.isa);
    let stack = super::stack_top(image.isa)
        - if matches!(image.isa, Isa::X86_64 | Isa::I386) {
            u64::from(width)
        } else {
            0
        };
    machine.registers.insert(sp, stack);
    let memory = machine
        .strict_memory
        .as_ref()
        .expect("execution uses mapped memory");
    let initial = match crate::emulation::tls::initial(image, memory, options.canary.as_ref()) {
        Ok(initial) => initial,
        Err(error) => return Err(invalid(error)),
    };
    if let Some(register) = crate::emulation::tls::register(image) {
        machine.registers.insert(register, memory.tls_base);
    }
    machine.memory.extend(initial);
    for (name, word) in &options.registers {
        let found = physical
            .iter()
            .find(|&&index| crate::ir::reg_name(image.isa, index, 64) == *name);
        let Some(&index) = found else {
            return Err(invalid(format!("unknown full register name: {name}")));
        };
        let value = match word.value() {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        machine.assign(
            RegRef {
                index,
                width: if width == 4 && index < 16 { 32 } else { 64 },
            },
            value,
        );
    }
    Ok(machine.register(sp))
}

fn initialize_arguments(
    machine: &mut Machine<'_>,
    image: &Image,
    start: u64,
    options: &Options,
    stack: u64,
    width: u8,
) -> Result<()> {
    let abi = image.convention_of(start);
    if image.go && !options.arguments.is_empty() {
        return Err(invalid(
            "Go arguments require explicit registers and memory",
        ));
    }
    for (index, word) in options.arguments.iter().enumerate() {
        let value = match word.value() {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Some(&register) = abi.arguments().get(index) {
            machine.assign(
                RegRef {
                    index: register,
                    width: width * 8,
                },
                value,
            );
        } else {
            let Some(base) = abi.stack_arguments() else {
                return Err(invalid("convention has no stack arguments"));
            };
            let offset = (index - abi.arguments().len()) as u64;
            let address = stack_argument_address(stack.checked_add(base as u64), offset, width);
            let Some(address) = address else {
                return Err(invalid("argument address overflows"));
            };
            machine.store(address, value, width);
        }
    }
    Ok(())
}

pub(super) fn stack_argument_address(base: Option<u64>, position: u64, width: u8) -> Option<u64> {
    position
        .checked_mul(u64::from(width))
        .and_then(|position| base.and_then(|base| base.checked_add(position)))
}

fn initialize_memory(machine: &mut Machine<'_>, options: &Options) -> Result<()> {
    let mut total = 0usize;
    for write in &options.memory {
        let address = match write.address.value() {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let bytes = match (&write.bytes, &write.value, write.width) {
            (Some(bytes), None, None) => bytes.clone(),
            (None, Some(value), Some(width @ (1 | 2 | 4 | 8))) => {
                let value = match value.value() {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                value.to_le_bytes()[..usize::from(width)].to_vec()
            }
            _ => {
                return Err(invalid(
                    "memory write needs bytes, or value and width (1, 2, 4, 8)",
                ));
            }
        };
        total = total.saturating_add(bytes.len());
        if total > HEAP_SIZE as usize {
            return Err(invalid("initial memory writes exceed 16 MiB"));
        }
        if !machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .check(address, bytes.len() as u64, /* write */ true)
        {
            break;
        }
        for (offset, byte) in bytes.into_iter().enumerate() {
            machine.memory.insert(address + offset as u64, byte);
        }
    }
    if let Some(error) = machine
        .strict_memory
        .as_ref()
        .expect("strict memory")
        .fault
        .borrow_mut()
        .take()
    {
        return Err(invalid(format!("initial state: {error}")));
    }
    Ok(())
}

impl Runner<'_> {
    fn report(
        mut self,
        stopped: Stop,
        before: &HashMap<u64, u8>,
        stack: u64,
        physical: &[u16],
    ) -> (Report, Option<strings::Recovery>) {
        let observed = self
            .machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .observed_reads
            .borrow()
            .clone();
        self.anti_analysis.extend(observed);
        let (mut reason, mut error) = match stopped {
            Stop::Return => ("return", None),
            Stop::Exit => ("exit", None),
            Stop::End => ("end address", None),
            Stop::StackCheckFail => ("stack check failed", None),
            Stop::Trap => ("trap", None),
            Stop::Steps => ("step limit", None),
            Stop::Time => ("time limit", None),
            Stop::Error(error) => (
                "error",
                Some(format!("instruction 0x{:x}: {error}", self.address)),
            ),
        };
        if self.image.isa == Isa::Arm32 {
            let pc = if reason == "return" {
                self.register_fact(14, 32)
                    .ok()
                    .and_then(Fact::singleton)
                    .map(|value| value & !1)
            } else {
                Some(self.address)
            };
            match pc {
                Some(pc) => self.assign_fact(
                    RegRef {
                        index: 15,
                        width: 32,
                    },
                    Fact::constant(pc),
                ),
                None => self.assign_fact(
                    RegRef {
                        index: 15,
                        width: 32,
                    },
                    Fact::TOP,
                ),
            }
        }
        let mut registers = BTreeMap::new();
        for &register in physical {
            let value = self
                .register_fact(register, 64)
                .ok()
                .and_then(Fact::singleton);
            registers.insert(
                crate::ir::reg_name(self.image.isa, register, 64),
                value.map_or_else(|| "unknown".to_owned(), crate::addr::format),
            );
        }
        let memory = self
            .machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .changes(before, &self.machine.memory);
        let reads = match self.read_results() {
            Ok(reads) => reads,
            Err(message) => {
                reason = "error";
                error = Some(match error {
                    Some(cause) => format!("{cause}; post-run read: {message}"),
                    None => format!("post-run read: {message}"),
                });
                Vec::new()
            }
        };
        let mut files = self.files.committed.clone();
        for path in ["/proc/self/status", "/proc/self/maps"] {
            if !self.options.files.contains_key(path) {
                files.remove(path);
            }
        }
        let report = Report {
            files,
            stdout: String::from_utf8_lossy(&self.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.stderr).into_owned(),
            reads,
            registers,
            return_value: self
                .register_fact(crate::arch::RETURN, 64)
                .ok()
                .and_then(Fact::singleton)
                .map_or_else(|| "unknown".to_owned(), crate::addr::format),
            memory,
            steps: self.steps,
            reason: reason.to_owned(),
            address: crate::addr::format(self.address),
            error,
            trace: self.trace,
            heap_base: crate::addr::format(self.heap_base),
            heap_size: HEAP_SIZE,
            stack_pointer: crate::addr::format(stack),
            anti_analysis: self.anti_analysis,
            api_calls: self.api_calls,
        };
        (report, self.recovery)
    }

    fn tick(&mut self) -> std::result::Result<(), Stop> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(Stop::Time);
        }
        if self.steps >= self.options.step_limit {
            return Err(Stop::Steps);
        }
        self.steps += 1;
        Ok(())
    }

    fn memory_error(&self) -> std::result::Result<(), Stop> {
        match self
            .machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .fault
            .borrow_mut()
            .take()
        {
            Some(error) => Err(Stop::Error(error)),
            None => Ok(()),
        }
    }

    fn eval(&self, expression: &Expr) -> std::result::Result<u64, Stop> {
        if self.facts.is_empty() && self.recovery.is_none() {
            return self.evaluate_concrete(expression);
        }
        match self.value_fact(expression) {
            Ok(fact) => match fact.singleton() {
                Some(value) => Ok(value),
                None => Err(Stop::Error("read of an undefined register".to_owned())),
            },
            Err(stop) => Err(stop),
        }
    }

    fn evaluate_concrete(&self, expression: &Expr) -> std::result::Result<u64, Stop> {
        let result = self.machine.eval(expression);
        if let Err(stop) = self.memory_error() {
            return Err(stop);
        }
        match result {
            Ok(value) => Ok(value),
            Err(error) => Err(Stop::Error(error.to_owned())),
        }
    }

    fn lift(&mut self, address: u64) -> std::result::Result<Vec<Block>, Stop> {
        if let Some(blocks) = self.code.get(&address) {
            return Ok(blocks.clone());
        }
        let Some(section) = self.image.section_at(address) else {
            return Err(Stop::Error(format!("unmapped code at 0x{address:x}")));
        };
        if !section.executable {
            return Err(Stop::Error(format!("non-executable code at 0x{address:x}")));
        }
        let available = section.size.saturating_sub(address - section.vaddr);
        let function = self
            .image
            .functions
            .range(..=address)
            .next_back()
            .map(|(_, function)| function);
        let mut size = function
            .and_then(|function| {
                function
                    .size
                    .and_then(|size| function.addr.checked_add(size))
            })
            .filter(|end| *end > address)
            .map_or(available, |end| available.min(end - address));
        if let Some(end) = self.ends.iter().filter(|end| **end > address).max() {
            size = size.min(*end - address);
        }
        if size > MAX_CODE_SIZE {
            return Err(Stop::Error(
                "code range exceeds 64 KiB; choose a smaller function".to_owned(),
            ));
        }
        let mut targets = self.ends.clone();
        targets.retain(|target| *target >= address && *target < address.saturating_add(size));
        let mut blocks = match crate::lift::lift_for_execution(self.image, address, size, &targets)
        {
            Ok(blocks) => blocks,
            Err(error) => return Err(Stop::Error(error.to_string())),
        };
        if self.ends.contains(&address.saturating_add(size)) {
            blocks.push(Block {
                start: address + size,
                stmts: Vec::new(),
            });
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(Stop::Time);
        }
        self.code.insert(address, blocks.clone());
        Ok(blocks)
    }

    fn execute(&mut self, address: u64, depth: usize) -> Stop {
        if let Some(recovery) = &mut self.recovery {
            recovery.depth = depth;
        }
        if depth > 128 {
            return Stop::Error("call depth exceeds 128".to_owned());
        }
        if self.ends.contains(&self.image.code_address(address)) {
            return Stop::End;
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Stop::Time;
        }
        if self.steps >= self.options.step_limit {
            return Stop::Steps;
        }
        if let Err(stop) = self.recovery_entry(depth) {
            return stop;
        }
        let blocks = match self.lift(self.image.code_address(address)) {
            Ok(blocks) => blocks,
            Err(stop) => return stop,
        };
        let mut starts = HashMap::new();
        for (index, block) in blocks.iter().enumerate() {
            starts.insert(block.start, index);
        }
        let mut index = 0;
        while let Some(block) = blocks.get(index) {
            if self.ends.contains(&block.start) {
                self.address = block.start;
                return Stop::End;
            }
            let mut next = index + 1;
            for statement in &block.stmts {
                if let Stmt::Assign {
                    dest,
                    value: Expr::Const(address),
                    ..
                } = statement
                    && dest.index == crate::lift::execution::ADDRESS
                {
                    self.instructions = self.instructions.saturating_add(1);
                    self.address = *address;
                    if self.ends.contains(address) {
                        return Stop::End;
                    }
                    if self
                        .deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        return Stop::Time;
                    }
                    if self.steps >= self.options.step_limit {
                        return Stop::Steps;
                    }
                    if self.options.trace {
                        self.trace.push(crate::addr::format(*address));
                    }
                    continue;
                }
                if let Err(stop) = self.tick() {
                    return stop;
                }
                match self.statement(statement, depth) {
                    Ok(Some(target)) => {
                        let target = self.image.code_address(target);
                        if self.ends.contains(&target) {
                            self.address = target;
                            return Stop::End;
                        }
                        if let Some(result) = self.windows_call(target, None, None, CallKind::Tail)
                        {
                            if let Err(stop) = result {
                                return stop;
                            }
                            let value = Expr::reg(
                                crate::arch::RETURN,
                                crate::arch::pointer_bytes(self.image.isa) * 8,
                            );
                            return match self.return_statement(&value, depth) {
                                Err(stop) => stop,
                                Ok(_) => unreachable!("a return statement stops execution"),
                            };
                        }
                        if self.image.isa == Isa::Arm32 {
                            let imported = match self.imported_target(target) {
                                Ok(target) => target,
                                Err(stop) => return stop,
                            };
                            if imported != target || self.image.imports.contains_key(&target) {
                                return match self.call(
                                    imported,
                                    self.image.convention_of(target),
                                    CallKind::Tail,
                                    depth,
                                ) {
                                    Ok(()) => Stop::Return,
                                    Err(stop) => stop,
                                };
                            }
                        }
                        if let Some(&index) = starts.get(&target) {
                            next = index;
                            break;
                        }
                        return self.execute(target, depth + 1);
                    }
                    Ok(None) => {}
                    Err(stop) => return stop,
                }
                if let Err(stop) = self.memory_error() {
                    return stop;
                }
            }
            index = next;
        }
        Stop::Error("execution ran past the lifted code".to_owned())
    }

    fn x86_instruction(&self) -> std::result::Result<iced_x86::Instruction, Stop> {
        x86_instruction_at(self.image, self.address).map_err(Stop::Error)
    }

    fn statement(
        &mut self,
        statement: &Stmt,
        depth: usize,
    ) -> std::result::Result<Option<u64>, Stop> {
        // Every error here stops this instruction and the entire run.
        match statement {
            Stmt::Assign { dest, value, .. } => {
                let origin = self.origin(value);
                if self.facts.is_empty() && self.recovery.is_none() {
                    let value = match self.evaluate_concrete(value) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    self.machine.assign(*dest, value);
                } else {
                    let fact = match self.value_fact(value) {
                        Ok(fact) => fact,
                        Err(stop) => return Err(stop),
                    };
                    if self.recovery.is_none()
                        && (fact.zeros | fact.ones) & super::mask(u32::from(dest.width)) == 0
                    {
                        return Err(Stop::Error("read of an undefined register".to_owned()));
                    }
                    self.assign_fact(*dest, fact);
                }
                if let Some(recovery) = &mut self.recovery {
                    recovery.registers.insert(dest.index, origin);
                }
            }
            Stmt::Store {
                addr, value, width, ..
            } => {
                let address = match self.eval(addr) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let fact = match self.value_fact(value) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                if self.recovery.is_some() {
                    let origin = self.origin(value);
                    if let Err(stop) = self.recovery_store(address, *width, fact, origin) {
                        return Err(stop);
                    }
                } else {
                    let Some(value) = fact.singleton() else {
                        return Err(Stop::Error("read of an undefined register".to_owned()));
                    };
                    self.machine.store(address, value, *width);
                }
            }
            Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
                ..
            } => {
                let bits = super::operand_width(lhs, rhs);
                if super::holds(
                    *cond,
                    match self.eval(lhs) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    },
                    match self.eval(rhs) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    },
                    bits,
                ) {
                    return Ok(Some(*target));
                }
            }
            Stmt::Br {
                target: Some(target),
                ..
            } => return Ok(Some(*target)),
            Stmt::BrIndirect { target, .. } => {
                return Ok(Some(match self.eval(target) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                }));
            }
            Stmt::Switch {
                index,
                cases,
                default,
                ..
            } => {
                let value = match self.eval(index) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                } as i64;
                match cases
                    .iter()
                    .find(|(case, _)| *case == value)
                    .map(|(_, target)| *target)
                    .or(*default)
                {
                    Some(target) => return Ok(Some(target)),
                    None => return Err(Stop::Error("switch has no matching case".to_owned())),
                }
            }
            Stmt::Ret { value, .. } => return self.return_statement(value, depth),
            Stmt::Call {
                kind,
                target,
                through,
                convention,
                outputs,
                ..
            } => {
                if let Err(stop) = self.call_statement(
                    *kind,
                    *target,
                    through.as_ref(),
                    *convention,
                    outputs,
                    depth,
                ) {
                    return Err(stop);
                }
            }
            Stmt::Trap { .. } => {
                let handler = self.signal_handlers.get(&5).copied();
                let breakpoint = self.image.format == crate::loader::Format::Elf
                    && self.image.isa == Isa::X86_64
                    && self.x86_instruction().is_ok_and(|instruction| {
                        instruction.mnemonic() == iced_x86::Mnemonic::Int3
                    });
                if let Some(handler) = handler.filter(|_| breakpoint) {
                    let convention = self.image.convention_of(handler);
                    let Some(&argument) = convention.arguments().first() else {
                        return Err(Stop::Error(
                            "SIGTRAP handler has no argument register".to_owned(),
                        ));
                    };
                    self.assign_fact(
                        RegRef {
                            index: argument,
                            width: 64,
                        },
                        Fact::constant(5),
                    );
                    if let Err(stop) = self.call(handler, convention, CallKind::Invoke, depth) {
                        return Err(stop);
                    }
                } else {
                    return Err(Stop::Trap);
                }
            }
            Stmt::Unsupported { text, .. } => {
                if text.starts_with("undecodable") {
                    for word in text.split_whitespace() {
                        if word.starts_with("0x")
                            && let Some(address) = crate::addr::parse(word.trim_end_matches(':'))
                        {
                            self.address = address;
                            break;
                        }
                    }
                }
                return Err(Stop::Error(format!("unsupported instruction: {text}")));
            }
            Stmt::BrifFlags { .. } => {
                return Err(Stop::Error(
                    "branch depends on unavailable flags".to_owned(),
                ));
            }
            Stmt::Br { target: None, .. } => {
                return Err(Stop::Error("branch target is unknown".to_owned()));
            }
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::ArmLoadAcquire { width },
                inputs,
                outputs,
                ..
            } => {
                let Some(input) = inputs.first() else {
                    return Err(Stop::Error("missing acquire-load address".to_owned()));
                };
                let address = match self.eval(input) {
                    Ok(address) => address,
                    Err(stop) => return Err(stop),
                };
                let value = self.machine.load(address, *width);
                if let Err(stop) = self.memory_error() {
                    return Err(stop);
                }
                if let Some(&output) = outputs.first() {
                    self.assign_fact(output, Fact::constant(value));
                }
            }
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Atomic { op, width, .. },
                inputs,
                outputs,
                ..
            } => {
                use crate::ir::AtomicOp;

                let mut args = Vec::with_capacity(inputs.len());
                for input in inputs {
                    args.push(self.eval(input)?);
                }
                if outputs.len() == 2 {
                    let half = *width / 2;
                    let upper = args[0].wrapping_add(u64::from(half));
                    let low = self.machine.load(args[0], half);
                    let high = self.machine.load(upper, half);
                    self.memory_error()?;
                    let bits = u32::from(half) * 8;
                    if low == args[2] & super::mask(bits) && high == args[4] & super::mask(bits) {
                        self.machine.store(args[0], args[1], half);
                        self.machine.store(upper, args[3], half);
                        self.memory_error()?;
                    }
                    self.assign_fact(outputs[0], Fact::constant(low));
                    self.assign_fact(outputs[1], Fact::constant(high));
                } else {
                    let Some(&address) = args.first() else {
                        return Err(Stop::Error("missing atomic memory address".to_owned()));
                    };
                    let old = self.machine.load(address, *width);
                    self.memory_error()?;
                    let operand = args.get(1).copied().unwrap_or(0);
                    let value = match op {
                        AtomicOp::Add => old.wrapping_add(operand),
                        AtomicOp::Sub => old.wrapping_sub(operand),
                        AtomicOp::And => old & operand,
                        AtomicOp::Or => old | operand,
                        AtomicOp::Xor => old ^ operand,
                        AtomicOp::Exchange | AtomicOp::Store => operand,
                        AtomicOp::CompareExchange
                            if args.get(2).is_some_and(|expected| {
                                old == expected & super::mask(u32::from(*width) * 8)
                            }) =>
                        {
                            operand
                        }
                        AtomicOp::CompareExchange | AtomicOp::Load => old,
                    } & super::mask(u32::from(*width) * 8);
                    if *op != AtomicOp::Load && (*op != AtomicOp::CompareExchange || value != old) {
                        self.machine.store(address, value, *width);
                        self.memory_error()?;
                    }
                    if let Some(&dest) = outputs.first() {
                        self.assign_fact(dest, Fact::constant(old));
                    }
                }
            }
            Stmt::Machine {
                instruction:
                    crate::ir::MachineInstruction::ArmSystem {
                        register: 0x5e82,
                        write,
                    },
                inputs,
                outputs,
                ..
            } if self.image.isa == Isa::AArch64 => {
                let register = crate::arch::aarch64::TPIDR_EL0;
                if *write {
                    let value = match self.eval(&inputs[0]) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    self.assign_fact(
                        RegRef {
                            index: register,
                            width: 64,
                        },
                        Fact::constant(value),
                    );
                } else {
                    let value = match self.register_fact(register, 64) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    self.assign_fact(outputs[0], value);
                }
            }
            Stmt::Machine {
                instruction:
                    crate::ir::MachineInstruction::ArmSystem {
                        register: 0xdf02,
                        write: false,
                    },
                outputs,
                ..
            } if self.image.isa == Isa::AArch64 => {
                let value = self
                    .instructions
                    .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction);
                self.assign_fact(outputs[0], Fact::constant(value));
                self.anti_analysis.push("cntvct_el0".to_owned());
            }
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Rdtsc,
                outputs,
                ..
            }
            | Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Rdtscp,
                outputs,
                ..
            } if self.image.isa == Isa::X86_64 || self.image.isa == Isa::I386 => {
                let value = self
                    .instructions
                    .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction);
                self.assign_fact(outputs[0], Fact::constant(value));
                if outputs.len() > 1 {
                    self.assign_fact(outputs[1], Fact::constant(0));
                }
                self.anti_analysis.push(if outputs.len() > 1 {
                    "rdtscp".to_owned()
                } else {
                    "rdtsc".to_owned()
                });
            }
            Stmt::Machine { .. } => {
                return Err(Stop::Error(
                    "instruction requires external machine state".to_owned(),
                ));
            }
        }
        Ok(None)
    }

    fn call_statement(
        &mut self,
        kind: CallKind,
        target: Option<u64>,
        through: Option<&Expr>,
        convention: Convention,
        outputs: &[CallOutput],
        depth: usize,
    ) -> std::result::Result<(), Stop> {
        if kind == CallKind::Syscall {
            if self.image.format != crate::loader::Format::Elf || self.recovery.is_some() {
                return Err(Stop::Error(
                    "Linux syscalls require explicit ELF emulation".into(),
                ));
            }
            let number = match self.eval(&Expr::reg(convention.arguments()[0], 64)) {
                Ok(number) => number,
                Err(stop) => return Err(stop),
            };
            let Some(operation) = super::syscalls::operation(convention, number) else {
                return Err(Stop::Error(format!("unsupported Linux syscall {number}")));
            };
            let operation = match operation {
                super::syscalls::Operation::Read => io::Operation::Read,
                super::syscalls::Operation::Write => io::Operation::Write,
                super::syscalls::Operation::Exit => return Err(Stop::Exit),
            };
            let value = match self.io_hook(operation, convention, kind) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            for &register in convention.clobbered() {
                self.assign_fact(
                    RegRef {
                        index: register,
                        width: 64,
                    },
                    Fact::TOP,
                );
            }
            self.assign_fact(
                RegRef {
                    index: 0,
                    width: 64,
                },
                Fact::constant(value),
            );
            for output in outputs {
                if output.register == 0 {
                    self.assign_fact(output.dest, Fact::constant(value));
                }
            }
            return Ok(());
        }
        let original = target;
        let target = match target {
            Some(target) => target,
            None => {
                let Some(through) = through else {
                    return Err(Stop::Error("call target is unknown".to_owned()));
                };
                if let Expr::Load { addr, .. } = through
                    && let Expr::Const(slot) = addr.as_ref()
                    && self.image.imports.contains_key(slot)
                {
                    *slot
                } else {
                    match self.eval(through) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    }
                }
            }
        };
        let target = match self.imported_target(target) {
            Ok(target) => target,
            Err(stop) => return Err(stop),
        };
        if depth == 0 {
            self.recover_inline(target, convention, kind);
        }
        let result = match self.windows_call(target, original, through, kind) {
            Some(result) => result,
            None => self.call(target, convention, kind, depth),
        };
        if let Err(stop) = result {
            return Err(stop);
        }
        let mut values = Vec::new();
        for output in outputs {
            let value = match self.register_fact(output.register, 64) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            values.push((
                output.dest,
                value,
                self.recovery
                    .as_ref()
                    .and_then(|r| r.registers.get(&output.register))
                    .copied()
                    .unwrap_or(0),
            ));
        }
        for (dest, value, origin) in values {
            self.assign_fact(dest, value);
            if let Some(recovery) = &mut self.recovery {
                recovery.registers.insert(dest.index, origin);
            }
        }
        Ok(())
    }

    fn return_statement(
        &mut self,
        value: &Expr,
        depth: usize,
    ) -> std::result::Result<Option<u64>, Stop> {
        if let Err(stop) = self.check_recovery_return(depth) {
            return Err(stop);
        }
        let value = match self.value_fact(value) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        if matches!(self.image.isa, Isa::X86_64 | Isa::I386) {
            let instruction = match self.x86_instruction() {
                Ok(instruction) => instruction,
                Err(stop) => return Err(stop),
            };
            let width = crate::arch::pointer_bytes(self.image.isa);
            let sp = crate::arch::stack_pointer(self.image.isa);
            let address = match self.eval(&Expr::reg(sp, width * 8)) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            self.machine.load(address, width);
            match self.memory_error() {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            let cleanup = if instruction.mnemonic() == iced_x86::Mnemonic::Ret {
                if instruction.op_count() == 0 {
                    0
                } else {
                    u64::from(instruction.immediate16())
                }
            } else {
                self.return_cleanup
            };
            self.return_cleanup = cleanup;
            let Some(stack) = address
                .checked_add(u64::from(width))
                .and_then(|stack| stack.checked_add(cleanup))
            else {
                return Err(Stop::Error("return stack address overflows".to_owned()));
            };
            self.machine.assign(
                RegRef {
                    index: sp,
                    width: width * 8,
                },
                stack,
            );
        }
        self.assign_fact(
            RegRef {
                index: crate::arch::RETURN,
                width: 64,
            },
            value,
        );
        Err(Stop::Return)
    }

    fn imported_target(&self, target: u64) -> std::result::Result<u64, Stop> {
        let mut slot = self
            .image
            .imports
            .contains_key(&target)
            .then_some(target)
            .or_else(|| imports::arm32_slot(self.image, target));
        if slot.is_none()
            && let Some(function) = self.image.functions.get(&target)
            && function.sources.contains(&crate::loader::NameSource::Plt)
            && let Some(name) = &function.name
        {
            let name = super::cxx::imported_name(self.image, name).unwrap_or(name);
            for (&address, imported) in &self.image.imports {
                if imported != name {
                    continue;
                }
                if slot.replace(address).is_some() {
                    return Err(Stop::Error(format!("multiple import slots match {name}")));
                }
            }
            if slot.is_none() {
                return Err(Stop::Error(format!("no import slot for {name}")));
            }
        }
        let Some(slot) = slot else {
            return Ok(target);
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        let value = if self.recovery.is_some() {
            match self.recovery_load(slot, width, false) {
                Ok(fact) => match fact.singleton() {
                    Some(value) => value,
                    None => {
                        return Err(Stop::Error(
                            "import target depends on unknown input".to_owned(),
                        ));
                    }
                },
                Err(stop) => return Err(stop),
            }
        } else {
            self.machine.load(slot, width)
        };
        if let Err(stop) = self.memory_error() {
            return Err(stop);
        }
        for offset in 0..u64::from(width) {
            if let Some(address) = slot.checked_add(offset)
                && self.machine.memory.contains_key(&address)
            {
                return Ok(value);
            }
        }
        Ok(slot)
    }

    fn external_result(&mut self, convention: Convention, value: Option<u64>) {
        if let Some(recovery) = &mut self.recovery {
            for &register in convention.clobbered() {
                recovery.registers.remove(&register);
            }
            recovery.registers.remove(&crate::arch::RETURN);
        }
        for &register in convention.clobbered() {
            self.assign_fact(
                RegRef {
                    index: register,
                    width: 64,
                },
                Fact::TOP,
            );
        }
        if let Some(value) = value {
            self.assign_fact(
                RegRef {
                    index: crate::arch::RETURN,
                    width: 64,
                },
                Fact::constant(value),
            );
        }
    }

    fn call(
        &mut self,
        target: u64,
        convention: Convention,
        kind: CallKind,
        depth: usize,
    ) -> std::result::Result<(), Stop> {
        self.return_cleanup = 0;
        let name = self
            .image
            .imports
            .get(&target)
            .map(String::as_str)
            .or_else(|| self.cxx_locale.and_then(|locale| locale.method(target)))
            .or_else(|| super::cxx::local_name(self.image, target));
        let key = crate::addr::format(target);
        if let Some(value) = name
            .and_then(|name| self.options.call_returns.get(name))
            .or_else(|| self.options.call_returns.get(&key))
        {
            return match value.value() {
                Ok(value) => {
                    self.external_result(convention, Some(value));
                    Ok(())
                }
                Err(error) => Err(Stop::Error(error.to_string())),
            };
        }
        if let Some(name) = name {
            if let Some(call) = super::cxx::find(name)
                && (!matches!(call, super::cxx::Call::Unsupported) || !self.options.skip_calls)
            {
                return match self.cxx(call, convention, kind) {
                    Ok(value) => {
                        self.external_result(convention, Some(value));
                        Ok(())
                    }
                    Err(Stop::Error(message)) => Err(Stop::Error(format!("{message}: {name}"))),
                    Err(stop) => Err(stop),
                };
            }
            if let Some(hook) = hooks::find(name)
                && (!matches!(hook, hooks::Hook::Unsupported(_)) || !self.options.skip_calls)
            {
                return match self.hook(hook, convention, kind) {
                    Ok(value) => {
                        self.external_result(
                            convention,
                            if matches!(hook, hooks::Hook::Free) {
                                None
                            } else {
                                Some(value)
                            },
                        );
                        Ok(())
                    }
                    Err(stop) => Err(stop),
                };
            }
            if self.options.skip_calls {
                self.external_result(convention, Some(0));
                return Ok(());
            }
            return Err(Stop::Error(format!(
                "unhandled imported call {name} at 0x{target:x}; supply callReturns or skipCalls"
            )));
        }
        if self.options.skip_calls
            && !self
                .image
                .section_at(target)
                .is_some_and(|section| section.executable)
        {
            self.external_result(convention, Some(0));
            return Ok(());
        }
        let sp = crate::arch::stack_pointer(self.image.isa);
        let old_sp = match self.eval(&Expr::reg(
            sp,
            crate::arch::pointer_bytes(self.image.isa) * 8,
        )) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        let candidate = if depth == 0 {
            self.recovery_candidate(convention, kind, old_sp)
        } else {
            None
        };
        let pushed = if kind == CallKind::Invoke {
            convention.pushed_by_call() as u64
        } else {
            0
        };
        let Some(callee_sp) = old_sp.checked_sub(pushed) else {
            return Err(Stop::Error("call stack underflows".to_owned()));
        };
        self.machine.registers.insert(sp, callee_sp);
        if pushed != 0 {
            let instruction = match self.x86_instruction() {
                Ok(instruction) => instruction,
                Err(stop) => return Err(stop),
            };
            let next = instruction.next_ip();
            self.machine.store(callee_sp, next, pushed as u8);
            self.recovery_control_store(callee_sp, pushed as u8);
        }
        match self.memory_error() {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        let temporaries: HashMap<u16, u64> = self
            .machine
            .registers
            .iter()
            .filter(|(index, _)| {
                **index >= crate::ir::TEMP_BASE && **index != crate::lift::execution::DIRECTION
            })
            .map(|(&index, &value)| (index, value))
            .collect();
        self.machine.registers.retain(|index, _| {
            *index < crate::ir::TEMP_BASE || *index == crate::lift::execution::DIRECTION
        });
        let mut temporary_facts = HashMap::new();
        for (&register, &fact) in &self.facts {
            if register >= crate::ir::TEMP_BASE && register != crate::lift::execution::DIRECTION {
                temporary_facts.insert(register, fact);
            }
        }
        self.facts.retain(|register, _| {
            *register < crate::ir::TEMP_BASE || *register == crate::lift::execution::DIRECTION
        });
        let caller = self.address;
        let temporary_origins: HashMap<_, _> =
            self.recovery
                .as_ref()
                .map_or_else(HashMap::new, |recovery| {
                    recovery
                        .registers
                        .iter()
                        .filter(|(index, _)| **index >= crate::ir::TEMP_BASE)
                        .map(|(&index, &origin)| (index, origin))
                        .collect()
                });
        let stopped = self.execute(target, depth + 1);
        if !matches!(stopped, Stop::Return) {
            return Err(stopped);
        }
        self.address = caller;
        if let Some(recovery) = &mut self.recovery {
            recovery.depth = depth;
        }
        self.finish_candidate(candidate, target, caller, callee_sp);
        self.machine.registers.retain(|index, _| {
            *index < crate::ir::TEMP_BASE || *index == crate::lift::execution::DIRECTION
        });
        self.machine.registers.extend(temporaries);
        self.facts.retain(|register, _| {
            *register < crate::ir::TEMP_BASE || *register == crate::lift::execution::DIRECTION
        });
        self.facts.extend(temporary_facts);
        if let Some(recovery) = &mut self.recovery {
            recovery
                .registers
                .retain(|index, _| *index < crate::ir::TEMP_BASE);
            recovery.registers.extend(temporary_origins);
        }
        self.machine.registers.insert(sp, old_sp);
        Ok(())
    }
}

pub(crate) fn x86_instruction_at(
    image: &Image,
    address: u64,
) -> std::result::Result<iced_x86::Instruction, String> {
    let Some(section) = image.section_at(address) else {
        return Err(format!("unmapped instruction at 0x{address:x}"));
    };
    let available = section.size.saturating_sub(address - section.vaddr).min(15);
    let Some(bytes) = image.read_vaddr(address, available) else {
        return Err(format!("missing instruction bytes at 0x{address:x}"));
    };
    let bits = if image.isa == Isa::I386 { 32 } else { 64 };
    let instruction =
        iced_x86::Decoder::with_ip(bits, bytes, address, iced_x86::DecoderOptions::NONE).decode();
    if instruction.is_invalid() {
        return Err("invalid x86 instruction".to_owned());
    }
    Ok(instruction)
}
