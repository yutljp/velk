//! Bounded C library effects on symbolic byte and integer terms.

mod stdio;

use super::{Evaluation, Failure, State, Term};
use crate::ir::eval::emulation::hooks::{self, Hook};
use crate::ir::eval::emulation::io;
use crate::ir::smt;
use crate::ir::{Convention, Expr};
use crate::service::Binary;
use crate::symbolic::invalid;

#[derive(Clone, Copy)]
enum IntegerKind {
    Scan,
    Strtol,
    Strtoll,
    Strtoul,
    Strtoull,
}

#[derive(Clone, Copy)]
enum PredicatePreference {
    FalseFirst,
    TrueFirst,
}

#[derive(Clone, Copy)]
enum ScanIntegerType {
    Signed,
    Unsigned,
}

#[derive(Clone, Copy)]
enum IntegerSign {
    Negative,
    Nonnegative,
}

#[derive(Clone, Copy)]
enum IntegerModel {
    Exact,
    StdinToken(ScanIntegerType),
}

struct ParsedInteger {
    value: Term,
    overflow: String,
    consumed: usize,
    leading_whitespace: usize,
    sign: Option<u8>,
    digits: usize,
    synthesized: bool,
    canonical: bool,
    matched: bool,
}

impl State {
    pub(super) fn argument(
        &self,
        binary: &Binary,
        convention: Convention,
        index: usize,
    ) -> Evaluation<Term> {
        let index = index
            + usize::from(matches!(
                convention,
                Convention::SyscallX86 | Convention::SyscallI386 | Convention::SyscallArm
            ));
        if let Some(&register) = convention.arguments().get(index) {
            return match self.read_register(register) {
                Ok(term) => Ok(term),
                Err(error) => Err(error.into()),
            };
        }
        let Some(base) = convention.stack_arguments() else {
            return Err(invalid("unsupported hook argument convention").into());
        };
        let Some(offset) = self
            .model_call_kind
            .stack_offset(self.isa, convention, base)
        else {
            return Err(invalid("invalid hook stack argument offset").into());
        };
        let stack = match self.read_register(crate::arch::stack_pointer(self.isa)) {
            Ok(term) => match self.resolve(term) {
                Ok(stack) => stack,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error.into()),
        };
        let width = crate::arch::pointer_bytes(self.isa);
        let address = super::super::emulation::stack_argument_address(
            stack.checked_add_signed(offset),
            (index - convention.arguments().len()) as u64,
            width,
        );
        let Some(address) = address else {
            return Err(invalid("hook argument address overflows").into());
        };
        self.eval(
            binary,
            &Expr::Load {
                addr: Box::new(Expr::Const(address)),
                width,
                signed: false,
            },
        )
    }

    pub(super) fn number(
        &self,
        binary: &Binary,
        convention: Convention,
        index: usize,
    ) -> Evaluation<u64> {
        let argument = match self.argument(binary, convention, index) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.resolve(argument)
    }

    pub(super) fn tick(&mut self) -> Evaluation<()> {
        if self.steps >= self.options.step_limit {
            return Err(invalid("step budget in libc model").into());
        }
        self.steps += 1;
        Ok(())
    }

    pub(super) fn byte(&mut self, binary: &Binary, base: u64, offset: usize) -> Evaluation<Term> {
        if let Err(error) = self.tick() {
            return Err(error);
        }
        let Some(address) = base.checked_add(offset as u64) else {
            return Err(invalid("libc memory address overflows").into());
        };
        let mut bytes = match self.read_memory(binary, address, 1) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        Ok(bytes.remove(0))
    }

    pub(super) fn test(&self, condition: String) -> Evaluation<bool> {
        self.test_with_preference(condition, PredicatePreference::FalseFirst)
    }

    fn test_with_preference(
        &self,
        condition: String,
        preference: PredicatePreference,
    ) -> Evaluation<bool> {
        let term = match self.bind(boolean_value(&condition)) {
            Ok(term) => term,
            Err(error) => return Err(error.into()),
        };
        let mut possible = Vec::new();
        let candidates = match preference {
            PredicatePreference::FalseFirst => [0, 1],
            PredicatePreference::TrueFirst => [1, 0],
        };
        for candidate in candidates {
            let mut constraints = self.constraints.clone();
            constraints.push(format!("(= {} {})", term.text, smt::constant(candidate)));
            let result = {
                let mut solver = self.solver.borrow_mut();
                solver.query(&constraints, None)
            };
            match result {
                Ok(Some(_)) => possible.push(candidate),
                Ok(None) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if possible.len() == 1 {
            return Ok(possible[0] != 0);
        }
        Err(Failure::Address(term, possible, false))
    }

    fn zero(&self, byte: &Term) -> Evaluation<bool> {
        if let Some(value) = byte.concrete {
            return Ok(value == 0);
        }
        self.test(format!("(= {} {})", byte.text, smt::constant(0)))
    }

    pub(super) fn whitespace(&self, byte: &Term) -> Evaluation<bool> {
        self.whitespace_with_preference(byte, PredicatePreference::FalseFirst)
    }

    fn whitespace_with_preference(
        &self,
        byte: &Term,
        preference: PredicatePreference,
    ) -> Evaluation<bool> {
        if let Some(value) = byte.concrete {
            return Ok((value as u8).is_ascii_whitespace());
        }
        self.test_with_preference(
            format!(
                "(or (= {0} {1}) (and (bvuge {0} {2}) (bvule {0} {3})))",
                byte.text,
                smt::constant(32),
                smt::constant(9),
                smt::constant(13)
            ),
            preference,
        )
    }

    pub(super) fn string(
        &mut self,
        binary: &Binary,
        address: u64,
        maximum: usize,
    ) -> Evaluation<Vec<Term>> {
        let mut bytes = Vec::new();
        for offset in 0..maximum {
            let byte = match self.byte(binary, address, offset) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let is_zero = match self.zero(&byte) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if is_zero {
                return Ok(bytes);
            }
            bytes.push(byte);
        }
        Err(invalid("string exceeds symbolic model bound").into())
    }

    pub(super) fn model_bound(&self) -> usize {
        // Every loop also charges the per-path statement budget.
        self.options
            .stdin
            .saturating_add(
                self.input_files
                    .values()
                    .fold(0usize, |count, bytes| count.saturating_add(bytes.len())),
            )
            .saturating_add(self.input_memory.len())
            .saturating_add(self.options.argv.iter().sum::<usize>())
            .clamp(4096, 65536)
    }

    pub(super) fn concrete_format(&mut self, binary: &Binary, address: u64) -> Evaluation<Vec<u8>> {
        let terms = match self.string(binary, address, self.model_bound()) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        for term in terms {
            let concrete = match self.resolve(term) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            bytes.push(concrete as u8);
        }
        Ok(bytes)
    }

    pub(super) fn libc(
        &mut self,
        binary: &Binary,
        name: &str,
        convention: Convention,
    ) -> Evaluation<Term> {
        let Some(hook) = hooks::find(name) else {
            return Err(invalid(format!("unsupported symbolic import: {name}")).into());
        };
        if matches!(hook, Hook::StackCheckFail) {
            return Err(invalid("stack check failed").into());
        }
        if matches!(hook, Hook::ErrnoLocation) {
            let memory = match self.mapped_memory(binary.image()) {
                Ok(memory) => memory,
                Err(error) => return Err(error.into()),
            };
            let Some(address) = memory.tls_base.checked_add(0x100) else {
                return Err(invalid("errno address overflows").into());
            };
            return Ok(Term::constant(address));
        }
        if let Hook::Io(operation) = hook {
            let handled = match self.file_hook(binary, convention, operation) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if let Some(result) = handled {
                return Ok(result);
            }
            return self.input_output(binary, convention, operation);
        }
        if matches!(hook, Hook::Upper | Hook::Lower) {
            let term = match self.argument(binary, convention, 0) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let value = match self.low(&term, 32) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            if let Err(error) = self.require_defined(&value, 32) {
                return Err(error.into());
            }
            let converted = match self.bind(case_conversion(&value.text, hook)) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            return Ok(converted);
        }
        if matches!(hook, Hook::Getline) {
            return self.getline(binary, convention);
        }
        if matches!(hook, Hook::Exit) {
            if hooks::has_exit_handlers(binary.image()) {
                return Err(invalid("exit handlers are unsupported").into());
            }
            if let Err(error) = self.files.flush(0) {
                return Err(invalid(error).into());
            }
            self.stop = Some("exit".to_owned());
            return Ok(Term::constant(0));
        }
        if matches!(hook, Hook::Signal) {
            if binary.image().format != crate::loader::Format::Elf {
                return Err(invalid("signal model requires Linux ELF").into());
            }
            let signal = match self.number(binary, convention, 0) {
                Ok(signal) => signal as u32,
                Err(error) => return Err(error),
            };
            if !(1..=64).contains(&signal) || matches!(signal, 9 | 19 | 32 | 33) {
                return Err(invalid(format!("unsupported signal number {signal}")).into());
            }
            let handler = match self.argument(binary, convention, 1) {
                Ok(handler) => handler,
                Err(error) => return Err(error),
            };
            let bits = u32::from(crate::arch::pointer_bytes(self.isa)) * 8;
            if let Err(error) = self.require_defined(&handler, bits) {
                return Err(error.into());
            }
            let mask = crate::ir::semantics::mask(bits);
            let invalid_handler = format!(
                "(= (bvand {} {}) {})",
                handler.text,
                smt::constant(mask),
                smt::constant(mask)
            );
            let mut invalid_constraints = self.constraints.clone();
            invalid_constraints.push(invalid_handler);
            match self.solver.borrow_mut().query(&invalid_constraints, None) {
                Ok(None) => {}
                Ok(Some(_)) => return Err(invalid("unsupported SIG_ERR handler").into()),
                Err(error) => return Err(error.into()),
            }
            return Ok(self
                .signal_handlers
                .insert(signal, handler)
                .unwrap_or_else(|| Term::constant(0)));
        }
        if matches!(hook, Hook::Alarm) {
            let seconds = match self.argument(binary, convention, 0) {
                Ok(seconds) => seconds,
                Err(error) => return Err(error),
            };
            let seconds = match self.low(&seconds, 32) {
                Ok(seconds) => seconds,
                Err(error) => return Err(error.into()),
            };
            return Ok(std::mem::replace(&mut self.alarm, seconds));
        }
        if matches!(hook, Hook::Random | Hook::Seed | Hook::Time) {
            return self.runtime_hook(binary, convention, hook);
        }
        match hook {
            Hook::ParentProcess => {
                return Ok(Term::constant(u64::from(
                    self.options.anti_analysis.parent_process_id,
                )));
            }
            Hook::Debugger => {
                return Ok(Term::constant(u64::from(
                    self.options.anti_analysis.debugger_present,
                )));
            }
            Hook::Ptrace => {
                let request = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if request != 0 {
                    return Err(invalid(format!("unsupported ptrace request {request}")).into());
                }
                let succeeds = self.ptrace_traceme_count == 0
                    && self.options.anti_analysis.ptrace_traceme_succeeds;
                if succeeds {
                    self.ptrace_traceme_count = 1;
                    return Ok(Term::constant(0));
                }
                return Ok(Term::constant(u64::MAX));
            }
            Hook::Dumpable => {
                let operation_number = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let operation = operation_number as u32;
                if operation != 4 {
                    return Err(invalid(format!("unsupported prctl operation {operation}")).into());
                }
                return Ok(Term::constant(if self.options.anti_analysis.dumpable {
                    0
                } else {
                    u64::MAX
                }));
            }
            Hook::SystemCall => {
                let number = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let (ptrace_number, parent_number, prctl_number) = match self.isa {
                    crate::loader::Isa::X86_64 => (101, 110, 157),
                    crate::loader::Isa::I386 => (26, 64, 172),
                    crate::loader::Isa::AArch64 => (117, 173, 167),
                    _ => return Err(invalid("unsupported syscall architecture").into()),
                };
                if number == ptrace_number {
                    let request = match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if request != 0 {
                        return Err(invalid(format!("unsupported ptrace request {request}")).into());
                    }
                    if self.ptrace_traceme_count == 0
                        && self.options.anti_analysis.ptrace_traceme_succeeds
                    {
                        self.ptrace_traceme_count = 1;
                        return Ok(Term::constant(0));
                    }
                    return Ok(Term::constant(u64::MAX));
                }
                if number == parent_number {
                    return Ok(Term::constant(u64::from(
                        self.options.anti_analysis.parent_process_id,
                    )));
                }
                if number == prctl_number {
                    let convention_number = match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let operation = convention_number as u32;
                    if operation != 4 {
                        return Err(
                            invalid(format!("unsupported prctl operation {operation}")).into()
                        );
                    }
                    return Ok(Term::constant(if self.options.anti_analysis.dumpable {
                        0
                    } else {
                        u64::MAX
                    }));
                }
                return Err(invalid(format!("unsupported Linux syscall {number}")).into());
            }
            _ => {}
        }
        let first = match self.number(binary, convention, 0) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if matches!(hook, Hook::MemorySearch | Hook::FindByteReverse) {
            return self.find_byte(binary, convention, first, hook);
        }
        if matches!(hook, Hook::Character | Hook::ReverseCharacter) {
            return self.find_character(binary, convention, first, hook);
        }
        if matches!(hook, Hook::FindSubstring) {
            return self.find_substring(binary, convention, first);
        }
        match hook {
            Hook::ComplementSpan => {
                let reject = match self.number(binary, convention, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let mut rejected = Vec::new();
                let mut terminated = false;
                for offset in 0..self.model_bound() {
                    let byte = match self.byte(binary, reject, offset) {
                        Ok(byte) => byte,
                        Err(error) => return Err(error),
                    };
                    match self.zero(&byte) {
                        Ok(true) => {
                            terminated = true;
                            break;
                        }
                        Ok(false) => rejected.push(byte),
                        Err(error) => return Err(error),
                    }
                }
                if !terminated {
                    return Err(invalid("string exceeds symbolic model bound").into());
                }
                for offset in 0..self.model_bound() {
                    let byte = match self.byte(binary, first, offset) {
                        Ok(byte) => byte,
                        Err(error) => return Err(error),
                    };
                    match self.zero(&byte) {
                        Ok(true) => return Ok(Term::constant(offset as u64)),
                        Ok(false) => {}
                        Err(error) => return Err(error),
                    }
                    for candidate in &rejected {
                        match self.test(format!("(= {} {})", byte.text, candidate.text)) {
                            Ok(true) => return Ok(Term::constant(offset as u64)),
                            Ok(false) => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
                Err(invalid("string exceeds symbolic model bound").into())
            }
            Hook::MemorySearch => {
                let target = match self.argument(binary, convention, 1) {
                    Ok(target) => target,
                    Err(error) => return Err(error),
                };
                if let Err(error) = self.require_defined(&target, 8) {
                    return Err(error.into());
                }
                let target = match self.low(&target, 8) {
                    Ok(target) => target,
                    Err(error) => return Err(error.into()),
                };
                let count = match self.number(binary, convention, 2) {
                    Ok(count) => count,
                    Err(error) => return Err(error),
                };
                if count > 65536 {
                    return Err(invalid("memory search exceeds model bound").into());
                }
                for offset in 0..count as usize {
                    let Some(location) = first.checked_add(offset as u64) else {
                        return Err(invalid("memory search address overflows").into());
                    };
                    let byte = match self.byte(binary, first, offset) {
                        Ok(byte) => byte,
                        Err(error) => return Err(error),
                    };
                    let found = match self.test(format!("(= {} {})", byte.text, target.text)) {
                        Ok(found) => found,
                        Err(error) => return Err(error),
                    };
                    if found {
                        return Ok(Term::constant(location));
                    }
                }
                Ok(Term::constant(0))
            }
            Hook::Length | Hook::LengthN | Hook::StringCopy | Hook::StringCopyN => {
                let copying = matches!(hook, Hook::StringCopy | Hook::StringCopyN);
                let source = if copying {
                    match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                } else {
                    first
                };
                let limited = matches!(hook, Hook::LengthN | Hook::StringCopyN);
                let maximum = if limited {
                    match self.number(binary, convention, if copying { 2 } else { 1 }) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                } else {
                    self.model_bound() as u64
                };
                if maximum > 65536 {
                    return Err(invalid("string operation exceeds model bound").into());
                }
                let mut bytes = Vec::new();
                let mut ended = false;
                for offset in 0..maximum as usize {
                    let byte = if ended {
                        Term::constant(0)
                    } else {
                        match self.byte(binary, source, offset) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        }
                    };
                    let zero = if ended {
                        true
                    } else {
                        match self.zero(&byte) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        }
                    };
                    if copying {
                        bytes.push(byte);
                    }
                    if zero {
                        ended = true;
                        if matches!(hook, Hook::Length | Hook::LengthN) {
                            return Ok(Term::constant(offset as u64));
                        }
                        if !limited {
                            break;
                        }
                    }
                }
                if !limited && !ended {
                    return Err(invalid("string exceeds symbolic model bound").into());
                }
                if copying && let Err(error) = self.write_memory(binary, first, &bytes) {
                    return Err(error.into());
                }
                Ok(Term::constant(if copying { first } else { maximum }))
            }
            Hook::Compare
            | Hook::CompareN
            | Hook::MemoryCompare
            | Hook::CompareCase
            | Hook::CompareCaseN => {
                let second = match self.number(binary, convention, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let maximum = if matches!(hook, Hook::Compare | Hook::CompareCase) {
                    self.model_bound() as u64
                } else {
                    match self.number(binary, convention, 2) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                };
                if maximum > 65536 {
                    return Err(invalid("comparison exceeds model bound").into());
                }
                for offset in 0..maximum as usize {
                    let mut a = match self.byte(binary, first, offset) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let mut b = match self.byte(binary, second, offset) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if matches!(hook, Hook::CompareCase | Hook::CompareCaseN) {
                        a = match self.ascii_lower_byte(&a) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        b = match self.ascii_lower_byte(&b) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                    }
                    let differs = match self.test(format!("(not (= {} {}))", a.text, b.text)) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if differs {
                        // C only specifies the sign of a nonzero comparison result.
                        let sign_result = match self
                            .bind(smt::low(&format!("(bvsub {} {})", a.text, b.text), 32))
                        {
                            Ok(value) => value,
                            Err(error) => return Err(error.into()),
                        };
                        return Ok(sign_result);
                    }
                    if !matches!(hook, Hook::MemoryCompare) {
                        let zero = match self.zero(&a) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if zero {
                            return Ok(Term::constant(0));
                        }
                    }
                }
                if matches!(hook, Hook::Compare | Hook::CompareCase) {
                    return Err(invalid("comparison exceeds string bound").into());
                }
                Ok(Term::constant(0))
            }
            Hook::Copy | Hook::Move | Hook::Set => {
                let second = match self.argument(binary, convention, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let count = match self.number(binary, convention, 2) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if count > 65536 {
                    return Err(invalid("memory operation exceeds model bound").into());
                }
                let mut bytes = Vec::new();
                if matches!(hook, Hook::Set) {
                    for _ in 0..count {
                        if let Err(error) = self.tick() {
                            return Err(error);
                        }
                        let low_byte = match self.low(&second, 8) {
                            Ok(value) => value,
                            Err(error) => return Err(error.into()),
                        };
                        bytes.push(low_byte);
                    }
                } else {
                    let source = match self.resolve(second) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if matches!(hook, Hook::Copy)
                        && count != 0
                        && first < source.saturating_add(count)
                        && source < first.saturating_add(count)
                    {
                        return Err(invalid("overlapping memcpy").into());
                    }
                    for offset in 0..count as usize {
                        let byte = match self.byte(binary, source, offset) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        bytes.push(byte);
                    }
                }
                if let Err(error) = self.write_memory(binary, first, &bytes) {
                    return Err(error.into());
                }
                Ok(Term::constant(first))
            }
            Hook::Duplicate | Hook::DuplicateN => {
                let mut bytes = Vec::new();
                let mut ended = false;
                let maximum = if matches!(hook, Hook::DuplicateN) {
                    match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                } else {
                    self.model_bound() as u64
                };
                if maximum > 65536 {
                    return Err(invalid("string duplication exceeds model bound").into());
                }
                for offset in 0..maximum as usize {
                    let byte = match self.byte(binary, first, offset) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let zero = match self.zero(&byte) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if zero {
                        ended = true;
                        break;
                    }
                    bytes.push(byte);
                }
                if matches!(hook, Hook::Duplicate) && !ended {
                    return Err(invalid("string exceeds symbolic model bound").into());
                }
                bytes.push(Term::constant(0));
                let allocation =
                    match self.allocate_bytes(binary, bytes.len() as u64, Some(&bytes), false) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                match allocation {
                    Some(address) => Ok(Term::constant(address)),
                    None => Ok(Term::constant(0)),
                }
            }
            Hook::Allocate | Hook::AllocateZero => {
                let size = if matches!(hook, Hook::AllocateZero) {
                    let count = match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    match first.checked_mul(count) {
                        Some(size) => size,
                        None => return Ok(Term::constant(0)),
                    }
                } else {
                    first
                };
                if size > 65536 {
                    return Ok(Term::constant(0));
                }
                let zeroed = matches!(hook, Hook::AllocateZero);
                let allocation = match self.allocate_bytes(binary, size, None, zeroed) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                match allocation {
                    Some(address) => Ok(Term::constant(address)),
                    None => Ok(Term::constant(0)),
                }
            }
            Hook::Reallocate => {
                let size = match self.number(binary, convention, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if first == 0 {
                    if size > 65536 {
                        return Ok(Term::constant(0));
                    }
                    let allocation = match self.allocate_bytes(binary, size, None, false) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    return match allocation {
                        Some(address) => Ok(Term::constant(address)),
                        None => Ok(Term::constant(0)),
                    };
                }
                let Some(old_size) = self.allocations.get(&first).copied() else {
                    return Err(invalid("realloc of unallocated pointer").into());
                };
                if size == 0 {
                    self.allocations.remove(&first);
                    return Ok(Term::constant(0));
                }
                if size > 65536 {
                    return Ok(Term::constant(0));
                }
                let copy_size = old_size.min(size) as usize;
                let old_bytes = match self.read_memory(binary, first, copy_size) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
                let allocation = match self.allocate_bytes(binary, size, None, false) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let Some(address) = allocation else {
                    return Ok(Term::constant(0));
                };
                if let Err(error) = self.write_memory(binary, address, &old_bytes) {
                    return Err(error.into());
                }
                self.allocations.remove(&first);
                Ok(Term::constant(address))
            }
            Hook::Free => {
                if first != 0 && self.allocations.remove(&first).is_none() {
                    return Err(invalid("free of unallocated pointer").into());
                }
                Ok(Term::constant(0))
            }
            Hook::Integer
            | Hook::LongInteger
            | Hook::IntegerEnd
            | Hook::LongLongIntegerEnd
            | Hook::UnsignedIntegerEnd
            | Hook::UnsignedLongLongIntegerEnd => {
                let text = match self.string(binary, first, self.model_bound()) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let end_pointer = matches!(
                    hook,
                    Hook::IntegerEnd
                        | Hook::LongLongIntegerEnd
                        | Hook::UnsignedIntegerEnd
                        | Hook::UnsignedLongLongIntegerEnd
                );
                let base = if end_pointer {
                    match self.number(binary, convention, 2) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                } else {
                    10
                };
                if base != 0 && !(2..=36).contains(&base) {
                    return Err(invalid("symbolic integer base is outside 0..=36 or 2..=36").into());
                }
                let long_bits = if matches!(
                    binary.image().format,
                    crate::loader::Format::Pe | crate::loader::Format::Coff
                ) {
                    32
                } else {
                    u32::from(crate::arch::pointer_bytes(self.isa)) * 8
                };
                let integer_kind = match hook {
                    Hook::Integer => IntegerKind::Strtol,
                    Hook::LongInteger | Hook::IntegerEnd => IntegerKind::Strtol,
                    Hook::LongLongIntegerEnd => IntegerKind::Strtoll,
                    Hook::UnsignedIntegerEnd => IntegerKind::Strtoul,
                    Hook::UnsignedLongLongIntegerEnd => IntegerKind::Strtoull,
                    _ => unreachable!("integer hook was checked above"),
                };
                let parsed = match self.parse_integer(
                    &text,
                    base,
                    integer_kind,
                    IntegerModel::Exact,
                    long_bits,
                ) {
                    Ok(parsed) => parsed,
                    Err(error) => return Err(error),
                };
                if end_pointer {
                    if let Err(error) = self.set_symbolic_errno(binary, &parsed.overflow) {
                        return Err(error);
                    }
                    let end = match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if end != 0 {
                        let Some(address) = first.checked_add(if parsed.matched {
                            parsed.consumed as u64
                        } else {
                            0
                        }) else {
                            return Err(invalid("strtol end pointer overflows").into());
                        };
                        if let Err(error) = self.store(
                            binary.image(),
                            end,
                            &Term::constant(address),
                            crate::arch::pointer_bytes(self.isa),
                        ) {
                            return Err(error.into());
                        }
                    }
                }
                let return_bits = match hook {
                    Hook::Integer => 32,
                    Hook::LongInteger | Hook::IntegerEnd | Hook::UnsignedIntegerEnd => long_bits,
                    Hook::LongLongIntegerEnd | Hook::UnsignedLongLongIntegerEnd => 64,
                    _ => unreachable!("integer hook was checked above"),
                };
                match self.low(&parsed.value, return_bits) {
                    Ok(value) => Ok(value),
                    Err(error) => Err(error.into()),
                }
            }
            _ => Err(invalid(format!("unsupported symbolic import: {name}")).into()),
        }
    }

    fn hex_digit(&self, byte: &Term) -> Evaluation<bool> {
        let lower = format!("(bvor {} {})", byte.text, smt::constant(32));
        self.test(format!("(or (and (bvuge {0} {1}) (bvule {0} {2})) (and (bvuge {lower} {3}) (bvule {lower} {4})))", byte.text, smt::constant(48), smt::constant(57), smt::constant(97), smt::constant(102)))
    }

    fn allocate_bytes(
        &mut self,
        binary: &Binary,
        size: u64,
        initial: Option<&[Term]>,
        zeroed: bool,
    ) -> Evaluation<Option<u64>> {
        if size > 65536 {
            return Ok(None);
        }
        let memory = match self.mapped_memory(binary.image()) {
            Ok(memory) => memory,
            Err(error) => return Err(error.into()),
        };
        let Some(address) = self.heap_next.checked_add(15).map(|value| value & !15) else {
            return Ok(None);
        };
        let Some(end) = address.checked_add(size.max(1)) else {
            return Ok(None);
        };
        let Some(heap_end) = memory.heap_base.checked_add(crate::emulation::HEAP_SIZE) else {
            return Err(invalid("heap address overflows").into());
        };
        if end > heap_end {
            return Ok(None);
        }
        self.heap_next = end;
        self.allocations.insert(address, size.max(1));
        for offset in 0..size as usize {
            let Some(at) = address.checked_add(offset as u64) else {
                return Err(invalid("allocation address overflows").into());
            };
            let value = if let Some(value) = initial.and_then(|bytes| bytes.get(offset)) {
                value.clone()
            } else if zeroed {
                Term::constant(0)
            } else {
                match self.symbolic_byte().map_err(Failure::Error) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                }
            };
            self.memory.insert(at, value);
        }
        Ok(Some(address))
    }

    fn ascii_lower_byte(&mut self, byte: &Term) -> Evaluation<Term> {
        let byte = match self.low(byte, 8) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        let converted = match self.bind(format!(
            "(ite (and (bvuge {} {}) (bvule {} {})) (bvadd {} {}) {})",
            byte.text,
            smt::constant(65),
            byte.text,
            smt::constant(90),
            byte.text,
            smt::constant(32),
            byte.text
        )) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        Ok(converted)
    }

    fn find_byte(
        &mut self,
        binary: &Binary,
        convention: Convention,
        base: u64,
        hook: Hook,
    ) -> Evaluation<Term> {
        let argument = match self.argument(binary, convention, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let character = match self.low(&argument, 8) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        let count = match self.number(binary, convention, 2) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if count > 65536 {
            return Err(invalid("memory search exceeds model bound").into());
        }
        let reverse = matches!(hook, Hook::FindByteReverse);
        let mut offsets: Vec<usize> = (0..count as usize).collect();
        if !reverse {
            offsets.reverse();
        }
        let mut result = Term::constant(0);
        for offset in offsets {
            let Some(address) = base.checked_add(offset as u64) else {
                return Err(invalid("memory search address overflows").into());
            };
            let byte = match self.byte(binary, base, offset) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let byte = match self.low(&byte, 8) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            result = match self.bind(format!(
                "(ite (= {} {}) {} {})",
                byte.text,
                character.text,
                smt::constant(address),
                result.text
            )) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
        }
        Ok(result)
    }

    fn find_character(
        &mut self,
        binary: &Binary,
        convention: Convention,
        base: u64,
        hook: Hook,
    ) -> Evaluation<Term> {
        let argument = match self.argument(binary, convention, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let character = match self.low(&argument, 8) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        let mut active = Term::constant(1);
        let mut candidates = Vec::new();
        let mut terminated = false;
        for offset in 0..self.model_bound() {
            let byte = match self.byte(binary, base, offset) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let byte = match self.low(&byte, 8) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            let Some(address) = base.checked_add(offset as u64) else {
                return Err(invalid("string search address overflows").into());
            };
            candidates.push((
                format!(
                    "(and (not (= {} {})) (= {} {}))",
                    active.text,
                    smt::constant(0),
                    byte.text,
                    character.text
                ),
                address,
            ));
            let zero_condition = format!("(= {} {})", byte.text, smt::constant(0));
            let zero = match self.zero(&byte) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            active = match self.bind(format!(
                "(ite {zero_condition} {} {})",
                smt::constant(0),
                active.text
            )) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            if zero {
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(invalid("string exceeds symbolic model bound").into());
        }
        let mut result = Term::constant(0);
        if matches!(hook, Hook::ReverseCharacter) {
            for (condition, address) in candidates {
                result = match self.bind(format!(
                    "(ite {condition} {} {})",
                    smt::constant(address),
                    result.text
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
            }
        } else {
            for (condition, address) in candidates.into_iter().rev() {
                result = match self.bind(format!(
                    "(ite {condition} {} {})",
                    smt::constant(address),
                    result.text
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
            }
        }
        Ok(result)
    }

    fn find_substring(
        &mut self,
        binary: &Binary,
        convention: Convention,
        base: u64,
    ) -> Evaluation<Term> {
        let needle_address = match self.number(binary, convention, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let bound = self.model_bound();
        let needle = match self.string(binary, needle_address, bound) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if needle.is_empty() {
            return Ok(Term::constant(base));
        }
        let haystack = match self.string(binary, base, bound) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let Some(work) = haystack.len().checked_mul(needle.len()) else {
            return Err(invalid("substring search size overflows").into());
        };
        if work > 65536 {
            return Err(invalid("substring search exceeds model bound").into());
        }
        let mut result = Term::constant(0);
        if needle.len() <= haystack.len() {
            for start in (0..=haystack.len() - needle.len()).rev() {
                let mut equal = "true".to_owned();
                for (offset, needle_byte) in needle.iter().enumerate() {
                    let haystack_byte = match self.low(&haystack[start + offset], 8) {
                        Ok(value) => value,
                        Err(error) => return Err(error.into()),
                    };
                    let needle_byte = match self.low(needle_byte, 8) {
                        Ok(value) => value,
                        Err(error) => return Err(error.into()),
                    };
                    equal = format!(
                        "(and {equal} (= {} {}))",
                        haystack_byte.text, needle_byte.text
                    );
                }
                let Some(address) = base.checked_add(start as u64) else {
                    return Err(invalid("substring result address overflows").into());
                };
                result = match self.bind(format!(
                    "(ite {equal} {} {})",
                    smt::constant(address),
                    result.text
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
            }
        }
        Ok(result)
    }

    fn errno_address(&self, binary: &Binary) -> Evaluation<u64> {
        let memory = match self.mapped_memory(binary.image()) {
            Ok(memory) => memory,
            Err(error) => return Err(error.into()),
        };
        memory
            .tls_base
            .checked_add(0x100)
            .ok_or_else(|| invalid("errno address overflows").into())
    }

    fn set_symbolic_errno(&mut self, binary: &Binary, condition: &str) -> Evaluation<()> {
        let address = match self.errno_address(binary) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let previous = match self.read_memory(binary, address, 4) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        for (index, old) in previous.iter().enumerate() {
            let old = match self.low(old, 8) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            let value = if index == 0 { 34 } else { 0 };
            let merged = match self.bind(format!(
                "(ite {condition} {} {})",
                smt::constant(value),
                old.text
            )) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            bytes.push(merged);
        }
        match self.write_memory(binary, address, &bytes) {
            Ok(()) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn hex_prefix(
        &self,
        input: &[Term],
        position: usize,
        allow_missing_digit: bool,
    ) -> Evaluation<bool> {
        let Some(x_position) = position.checked_add(1) else {
            return Ok(false);
        };
        let Some(zero) = input.get(position) else {
            return Ok(false);
        };
        let Some(letter) = input.get(x_position) else {
            return Ok(false);
        };
        let prefix = match self.test(format!(
            "(and (= {} {}) (or (= {} {}) (= {} {})))",
            zero.text,
            smt::constant(48),
            letter.text,
            smt::constant(120),
            letter.text,
            smt::constant(88)
        )) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if !prefix {
            return Ok(false);
        }
        if allow_missing_digit {
            return Ok(true);
        }
        let Some(digit) = position.checked_add(2).and_then(|at| input.get(at)) else {
            return Ok(false);
        };
        self.hex_digit(digit)
    }

    fn parse_integer(
        &mut self,
        input: &[Term],
        base: u64,
        kind: IntegerKind,
        model: IntegerModel,
        long_bits: u32,
    ) -> Evaluation<ParsedInteger> {
        if matches!(kind, IntegerKind::Scan)
            && base == 10
            && input.len() >= 11
            && matches!(model, IntegerModel::StdinToken(_))
        {
            let Some(first) = input.first() else {
                return Err(invalid("scanf integer input is unavailable").into());
            };
            let canonical = match self.test_with_preference(
                format!(
                    "(or (= {} {}) (= {} {}))",
                    first.text,
                    smt::constant(u64::from(b'+')),
                    first.text,
                    smt::constant(u64::from(b'-'))
                ),
                PredicatePreference::TrueFirst,
            ) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let token_ends = if canonical {
                if let Some(next) = input.get(11) {
                    let digit = match self.test_with_preference(
                        format!(
                            "(and (bvuge {} {}) (bvule {} {}))",
                            next.text,
                            smt::constant(48),
                            next.text,
                            smt::constant(57)
                        ),
                        PredicatePreference::FalseFirst,
                    ) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    !digit
                } else {
                    true
                }
            } else {
                false
            };
            if token_ends {
                let source = match self.symbolic() {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
                let raw = format!("((_ extract 31 0) {})", source.text);
                let IntegerModel::StdinToken(integer_type) = model else {
                    return Err(invalid("invalid scanf integer model").into());
                };
                let value = match self.bind(if matches!(integer_type, ScanIntegerType::Signed) {
                    smt::signed(&raw, 32)
                } else {
                    format!("((_ zero_extend 32) {raw})")
                }) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
                return Ok(ParsedInteger {
                    value,
                    overflow: "false".to_owned(),
                    consumed: 11,
                    leading_whitespace: 0,
                    sign: None,
                    digits: 10,
                    synthesized: true,
                    canonical: true,
                    matched: true,
                });
            }
        }
        let (bits, unsigned) = match kind {
            IntegerKind::Scan => (u32::from(crate::arch::pointer_bytes(self.isa)) * 8, false),
            IntegerKind::Strtol => (long_bits, false),
            IntegerKind::Strtoll => (64, false),
            IntegerKind::Strtoul => (long_bits, true),
            IntegerKind::Strtoull => (64, true),
        };
        let negative_limit = 1u64 << (bits - 1);
        let positive_limit = if unsigned {
            crate::ir::semantics::mask(bits)
        } else {
            negative_limit - 1
        };
        let mut position = 0;
        while position < input.len() {
            let whitespace = match self.whitespace(&input[position]) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if !whitespace {
                break;
            }
            if let Err(error) = self.tick() {
                return Err(error);
            }
            position += 1;
        }
        let leading_whitespace = position;
        let mut sign = None;
        if let Some(byte) = input.get(position) {
            let negative = match self.test(format!("(= {} {})", byte.text, smt::constant(45))) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if negative {
                sign = Some(b'-');
                position += 1;
            } else {
                let positive = match self.test(format!("(= {} {})", byte.text, smt::constant(43))) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if positive {
                    sign = Some(b'+');
                    position += 1;
                }
            }
        }
        let negative = sign == Some(b'-');
        let mut base = base;
        if base == 0 {
            let leading_zero = if let Some(byte) = input.get(position) {
                match self.test(format!("(= {} {})", byte.text, smt::constant(48))) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                }
            } else {
                false
            };
            base = if leading_zero { 8 } else { 10 };
            if leading_zero {
                let hex_prefix = match self.hex_prefix(input, position, false) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if hex_prefix {
                    base = 16;
                    position += 2;
                }
            }
        } else if base == 16 {
            let hex_prefix =
                match self.hex_prefix(input, position, matches!(kind, IntegerKind::Scan)) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
            if hex_prefix {
                position += 2;
            }
        }
        let start = position;
        let mut digit_bytes = Vec::new();
        while let Some(byte) = input.get(position) {
            if let Err(error) = self.tick() {
                return Err(error);
            }
            let decimal = format!(
                "(and (bvuge {0} {1}) (bvule {0} {2}))",
                byte.text,
                smt::constant(48),
                smt::constant(57)
            );
            let lower = format!("(bvor {} {})", byte.text, smt::constant(32));
            let digit = if base <= 10 {
                format!(
                    "(and {decimal} (bvult (bvsub {} {}) {}))",
                    byte.text,
                    smt::constant(48),
                    smt::constant(base)
                )
            } else {
                format!(
                    "(or {decimal} (and (bvuge {lower} {}) (bvule {lower} {})))",
                    smt::constant(97),
                    smt::constant(base + 86)
                )
            };
            let preference = if position == start {
                PredicatePreference::TrueFirst
            } else {
                PredicatePreference::FalseFirst
            };
            let is_digit = match self.test_with_preference(digit, preference) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if !is_digit {
                break;
            }
            digit_bytes.push(byte.clone());
            position += 1;
        }
        let digits = position.saturating_sub(start);
        let synthesized = matches!(model, IntegerModel::StdinToken(_))
            && matches!(kind, IntegerKind::Scan)
            && base == 10
            && digits > 0;
        if synthesized {
            let source = match self.symbolic() {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            let raw = format!("((_ extract 31 0) {})", source.text);
            let IntegerModel::StdinToken(integer_type) = model else {
                return Err(invalid("invalid scanf integer model").into());
            };
            let integer_sign = if negative {
                IntegerSign::Negative
            } else {
                IntegerSign::Nonnegative
            };
            self.constrain_scanned_integer(&raw, integer_sign, digits, integer_type);
            let value = match self.bind(if matches!(integer_type, ScanIntegerType::Signed) {
                smt::signed(&raw, 32)
            } else {
                format!("((_ zero_extend 32) {raw})")
            }) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            return Ok(ParsedInteger {
                value,
                overflow: "false".to_owned(),
                consumed: position,
                leading_whitespace,
                sign,
                digits,
                synthesized: true,
                canonical: false,
                matched: true,
            });
        }
        let mut value = Term::constant(0);
        let mut overflow = "false".to_owned();
        let mut maximum = Some(0u64);
        for byte in digit_bytes {
            let decimal = format!(
                "(and (bvuge {0} {1}) (bvule {0} {2}))",
                byte.text,
                smt::constant(48),
                smt::constant(57)
            );
            let lower = format!("(bvor {} {})", byte.text, smt::constant(32));
            let digit_expression = digit_value(&byte.text, &decimal, &lower, base);
            let digit = match self.bind(digit_expression) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            let limit = if matches!(kind, IntegerKind::Scan) {
                u64::MAX
            } else if unsigned {
                positive_limit
            } else if negative {
                negative_limit
            } else {
                positive_limit
            };
            maximum = maximum.and_then(|value| integer_bound(value, base));
            if maximum.is_none_or(|maximum| maximum > limit) {
                overflow = format!(
                    "(or {overflow} {})",
                    integer_overflow(&value.text, &digit.text, base, limit)
                );
            }
            value = match self.bind(format!(
                "(bvadd (bvmul {} {}) {})",
                value.text,
                smt::constant(base),
                digit.text
            )) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            if let Some(maximum) = maximum {
                value.bits = 64 - maximum.leading_zeros();
            }
        }
        let limit = if unsigned {
            positive_limit
        } else if negative {
            negative_limit
        } else {
            positive_limit
        };
        let signed = if negative {
            format!("(bvneg {})", value.text)
        } else {
            value.text
        };
        if matches!(kind, IntegerKind::Scan) {
            match self.test(overflow.clone()) {
                Ok(true) => return Err(invalid("scanf integer exceeds 64 bits").into()),
                Ok(false) => {}
                Err(error) => return Err(error),
            }
        }
        let result = match self.bind(if matches!(kind, IntegerKind::Scan) {
            signed
        } else {
            format!("(ite {overflow} {} {signed})", smt::constant(limit))
        }) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        if matches!(kind, IntegerKind::Scan) && base == 10 {
            self.constrain_decimal_value(&result, negative, digits);
        }
        Ok(ParsedInteger {
            value: result,
            overflow,
            consumed: position,
            leading_whitespace,
            sign,
            digits,
            synthesized: false,
            canonical: false,
            matched: digits > 0,
        })
    }

    fn constrain_decimal_value(&mut self, value: &Term, negative: bool, digits: usize) {
        if !(1..=18).contains(&digits) {
            return;
        }
        let mut maximum = 0u64;
        for _ in 0..digits {
            maximum = maximum * 10 + 9;
        }
        if negative {
            self.constraints.push(format!(
                "(and (bvsge {} {}) (bvsle {} {}))",
                value.text,
                smt::constant(0u64.wrapping_sub(maximum)),
                value.text,
                smt::constant(0)
            ));
        } else {
            self.constraints
                .push(format!("(bvule {} {})", value.text, smt::constant(maximum)));
        }
    }

    fn constrain_scanned_integer(
        &mut self,
        value: &str,
        sign: IntegerSign,
        digits: usize,
        integer_type: ScanIntegerType,
    ) {
        let mut decimal_limit = 0u64;
        for _ in 0..digits {
            decimal_limit = decimal_limit.saturating_mul(10).saturating_add(9);
        }
        if matches!(integer_type, ScanIntegerType::Signed) {
            let limit = decimal_limit.min(if matches!(sign, IntegerSign::Negative) {
                1u64 << 31
            } else {
                (1u64 << 31) - 1
            }) as u32;
            if matches!(sign, IntegerSign::Negative) {
                self.constraints.push(format!(
                    "(and (bvsge {value} (_ bv{} 32)) (bvsle {value} (_ bv0 32)))",
                    0u32.wrapping_sub(limit)
                ));
            } else {
                self.constraints
                    .push(format!("(bvule {value} (_ bv{limit} 32))"));
            }
        } else {
            let limit = decimal_limit.min(u64::from(u32::MAX)) as u32;
            if matches!(sign, IntegerSign::Negative) {
                self.constraints.push(format!(
                    "(bvuge {value} (_ bv{} 32))",
                    0u32.wrapping_sub(limit)
                ));
            } else {
                self.constraints
                    .push(format!("(bvule {value} (_ bv{limit} 32))"));
            }
        }
    }
}

impl State {
    pub(super) fn initialize_streams(&mut self, binary: &Binary) -> crate::error::Result<()> {
        let width = crate::arch::pointer_bytes(self.isa);
        let memory = match self.mapped_memory(binary.image()) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let mut next = memory.heap_base;
        for &address in self.memory.keys() {
            if (memory.heap_base..memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE))
                .contains(&address)
            {
                next = next.max(address.saturating_add(1));
            }
        }
        for (index, name) in ["stdin", "stdout", "stderr"].into_iter().enumerate() {
            let imports: Vec<u64> = binary
                .image()
                .imports
                .iter()
                .filter(|(_, symbol)| {
                    symbol.trim_start_matches('_').split('@').next() == Some(name)
                })
                .map(|(&slot, _)| slot)
                .collect();
            let objects: Vec<u64> = binary
                .image()
                .data_symbols
                .iter()
                .filter(|(_, symbol)| {
                    symbol.trim_start_matches('_').split('@').next() == Some(name)
                })
                .map(|(&slot, _)| slot)
                .collect();
            if imports.is_empty() && objects.is_empty() {
                continue;
            }
            let token = next;
            let Some(end) = next
                .checked_add(32)
                .filter(|end| *end <= memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE))
            else {
                return Err(invalid("stream setup exceeds heap"));
            };
            next = end;
            self.standard_streams[index] = token;
            if index == 0 {
                self.stdin_stream = token;
            }
            let object = token + 8;
            if let Err(error) = self.store(binary.image(), object, &Term::constant(token), width) {
                return Err(error);
            }
            for slot in imports {
                if !memory.check(slot, u64::from(width), false) {
                    return Err(invalid("invalid stream import slot"));
                }
                for (offset, byte) in object
                    .to_le_bytes()
                    .into_iter()
                    .take(width as usize)
                    .enumerate()
                {
                    self.memory
                        .insert(slot + offset as u64, Term::constant(u64::from(byte)));
                }
            }
            for slot in objects {
                if let Err(error) = self.store(binary.image(), slot, &Term::constant(token), width)
                {
                    return Err(error);
                }
            }
        }
        self.heap_next = next;
        Ok(())
    }
}

impl State {
    fn getline(&mut self, binary: &Binary, convention: Convention) -> Evaluation<Term> {
        let pointer = match self.number(binary, convention, 0) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let capacity_pointer = match self.number(binary, convention, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let unsupported_stream = if self.stdin_stream == 0 {
            true
        } else {
            let stream = match self.number(binary, convention, 2) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            stream != self.stdin_stream
        };
        if unsupported_stream {
            return Err(invalid("unsupported getline stream").into());
        }
        let mut bytes = Vec::new();
        while let Some(byte) = io::next_input(&self.stdin, &mut self.input_position) {
            if let Err(error) = self.tick() {
                return Err(error);
            }
            let newline = match self.test(format!("(= {} {})", byte.text, smt::constant(10))) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            bytes.push(byte);
            if newline {
                break;
            }
        }
        if bytes.is_empty() {
            return Ok(Term::constant(u64::MAX));
        }
        let length = bytes.len();
        bytes.push(Term::constant(0));
        let width = crate::arch::pointer_bytes(self.isa);
        let load = |address| Expr::Load {
            addr: Box::new(Expr::Const(address)),
            width,
            signed: false,
        };
        let pointer_term = match self.eval(binary, &load(pointer)) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let mut destination = match self.resolve(pointer_term) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let evaluated = match self.eval(binary, &load(capacity_pointer)) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let capacity = match self.resolve(evaluated) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if destination == 0 || capacity < bytes.len() as u64 {
            destination = self.heap_next;
            let Some(end) = destination.checked_add(bytes.len() as u64) else {
                return Err(invalid("getline allocation overflows").into());
            };
            let memory = match self.mapped_memory(binary.image()) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            if end > memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE) {
                return Err(invalid("getline exceeds heap").into());
            }
            self.heap_next = end;
            if let Err(error) =
                self.store(binary.image(), pointer, &Term::constant(destination), width)
            {
                return Err(error.into());
            }
            if let Err(error) = self.store(
                binary.image(),
                capacity_pointer,
                &Term::constant(bytes.len() as u64),
                width,
            ) {
                return Err(error.into());
            }
        }
        if let Err(error) = self.write_memory(binary, destination, &bytes) {
            return Err(error.into());
        }
        Ok(Term::constant(length as u64))
    }
}

fn integer_bound(maximum: u64, base: u64) -> Option<u64> {
    maximum
        .checked_mul(base)
        .and_then(|value| value.checked_add(base - 1))
}

fn digit_value(byte: &str, decimal: &str, lower: &str, base: u64) -> String {
    if base == 10 {
        format!("(bvsub {byte} {})", smt::constant(48))
    } else {
        format!(
            "(ite {decimal} (bvsub {byte} {}) (bvsub {lower} {}))",
            smt::constant(48),
            smt::constant(87)
        )
    }
}

fn boolean_value(condition: &str) -> String {
    format!(
        "(ite {condition} {} {})",
        smt::constant(1),
        smt::constant(0)
    )
}

pub(super) fn integer_overflow(value: &str, digit: &str, base: u64, limit: u64) -> String {
    format!(
        "(or (bvugt {value} {0}) (and (= {value} {0}) (bvugt {digit} {1})))",
        smt::constant(limit / base),
        smt::constant(limit % base)
    )
}

fn case_conversion(value: &str, hook: Hook) -> String {
    let (start, end, operation) = if matches!(hook, Hook::Upper) {
        (97, 122, "bvsub")
    } else {
        (65, 90, "bvadd")
    };
    format!(
        "(ite (and (bvuge {value} {0}) (bvule {value} {1})) ({operation} {value} {2}) {value})",
        smt::constant(start),
        smt::constant(end),
        smt::constant(32)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smt_decimal_digit_after_range_check() {
        if !smt::Proofs::available() {
            return;
        }
        let mut proofs = smt::Proofs::default();
        let decimal = format!(
            "(and (bvuge r0 {}) (bvule r0 {}))",
            smt::constant(48),
            smt::constant(57)
        );
        let lower = format!("(bvor r0 {})", smt::constant(32));
        let original = digit_value("r0", &decimal, &lower, 16);
        let simplified = digit_value("r0", &decimal, &lower, 10);
        proofs.predicate(
            "decimal digit after range check",
            &format!("(ite {decimal} {simplified} {original})"),
            &original,
        );
        proofs.counterexample(
            "hexadecimal letters need a different conversion",
            &simplified,
            &original,
        );
        proofs.check();
    }

    #[test]
    fn smt_boolean_values_have_exactly_two_possible_values() {
        if !smt::Proofs::available() {
            return;
        }
        let mut proofs = smt::Proofs::default();
        for condition in ["true", "false", "(= r0 r1)", "(bvult r0 r1)"] {
            let value = boolean_value(condition);
            proofs.predicate(
                format!("Boolean domain {condition}"),
                &format!(
                    "(or (= {value} {}) (= {value} {}))",
                    smt::constant(0),
                    smt::constant(1)
                ),
                "true",
            );
            proofs.predicate(
                format!("Boolean truth {condition}"),
                &format!("(= {value} {})", smt::constant(1)),
                condition,
            );
        }
        proofs.counterexample(
            "Boolean false remains feasible",
            &boolean_value("false"),
            &smt::constant(1),
        );
        proofs.check();
    }

    #[test]
    fn i386_models_read_only_the_requested_stack_slots() {
        use crate::ir::CallKind;
        use crate::symbolic::Options;

        if !crate::ir::smt::Proofs::available() {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/metrics/l0_arith.i386.O0.debug.elf");
        let binary = Binary::open(&path).expect("i386 fixture");
        let address = *binary
            .image()
            .functions
            .keys()
            .next()
            .expect("fixture function");
        let mut state = State::new(&binary, &format!("0x{address:x}"), &Options::default())
            .expect("i386 state");
        let top = crate::ir::eval::stack_top(crate::loader::Isa::I386);
        let stack = crate::arch::stack_pointer(crate::loader::Isa::I386);
        state.registers.insert(stack, Term::constant(top - 8));
        state.model_call_kind = CallKind::Tail;
        state
            .store(binary.image(), top - 4, &Term::constant(0x10000000), 4)
            .expect("one pointer argument");
        let Ok(length) = state.libc(&binary, "strlen", Convention::Cdecl) else {
            panic!("one argument model must fit the last stack slot");
        };
        assert_eq!(length.concrete, Some(0));
        state.model_call_kind = CallKind::Invoke;
        state
            .store(binary.image(), top - 8, &Term::constant(0x10000000), 4)
            .expect("first argument");
        state
            .store(binary.image(), top - 4, &Term::constant(0), 4)
            .expect("second argument");
        let Ok(length) = state.libc(&binary, "strnlen", Convention::Cdecl) else {
            panic!("two argument model must fit the last two stack slots");
        };
        assert_eq!(length.concrete, Some(0));
        let unknown = state.libc(&binary, "unmodeled_input", Convention::Cdecl);
        assert!(
            matches!(unknown, Err(super::super::Failure::Error(error)) if error.to_string().contains("unsupported symbolic import: unmodeled_input"))
        );
    }

    #[test]
    fn smt_integer_digit_bounds() {
        use crate::ir::smt::Proofs;
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for base in [10, 16] {
            let mut maximum = 0u64;
            while let Some(next) = integer_bound(maximum, base) {
                let assumption = format!(
                    "(and (bvule r0 {}) (bvult r1 {}))",
                    smt::constant(maximum),
                    smt::constant(base)
                );
                let sum = format!(
                    "(bvadd (bvmul ((_ zero_extend 64) r0) (_ bv{base} 128)) ((_ zero_extend 64) r1))"
                );
                proofs.predicate(
                    format!("integer digit bound {base} {maximum}"),
                    &format!("(=> {assumption} (bvule {sum} (_ bv{next} 128)))"),
                    "true",
                );
                maximum = next;
            }
        }
        let decimal = format!(
            "(and (bvuge r0 {}) (bvule r0 {}))",
            smt::constant(48),
            smt::constant(57)
        );
        let digit = format!("(bvsub r0 {})", smt::constant(48));
        let original = format!(
            "(ite {decimal} {digit} (bvsub (bvor r0 {}) {}))",
            smt::constant(32),
            smt::constant(87)
        );
        proofs.predicate(
            "decimal digit conversion",
            &format!("(=> {decimal} (= {digit} {original}))"),
            "true",
        );
        proofs.counterexample(
            "decimal digit bound requires all nine values",
            &format!("(=> {decimal} (bvule {digit} {}))", smt::constant(8)),
            "true",
        );
        proofs.check();
    }

    #[test]
    fn smt_integer_overflow_matches_wide_arithmetic() {
        use crate::ir::smt::Proofs;
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for base in [10, 16] {
            for limit in [
                i16::MAX as u64,
                1u64 << 15,
                u16::MAX as u64,
                u32::MAX as u64,
                i32::MAX as u64,
                1u64 << 31,
                i64::MAX as u64,
                1u64 << 63,
                u64::MAX,
            ] {
                for digit in 0..base {
                    let reference = format!(
                        "(bvugt (bvadd (bvmul ((_ zero_extend 64) r0) (_ bv{base} 128)) (_ bv{digit} 128)) (_ bv{limit} 128))"
                    );
                    proofs.predicate(
                        format!("overflow {base} {limit} {digit}"),
                        &integer_overflow("r0", &smt::constant(digit), base, limit),
                        &reference,
                    );
                }
            }
        }
        proofs.counterexample(
            "overflow occurs before wrapped sum",
            &integer_overflow("r0", &smt::constant(9), 10, i64::MAX as u64),
            "false",
        );
        proofs.check();
    }

    #[test]
    fn smt_ascii_case_conversion() {
        use crate::ir::smt::Proofs;
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        let value = smt::low("r0", 32);
        for hook in [Hook::Upper, Hook::Lower] {
            let mut reference = value.clone();
            for byte in 0u8..=127 {
                let converted = if matches!(hook, Hook::Upper) {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                };
                reference = format!(
                    "(ite (= {value} {}) {} {reference})",
                    smt::constant(u64::from(byte)),
                    smt::constant(u64::from(converted))
                );
            }
            proofs.predicate(
                "ASCII case mapping",
                &case_conversion(&value, hook),
                &reference,
            );
        }
        proofs.counterexample(
            "case conversion changes lowercase",
            &case_conversion(&smt::constant(97), Hook::Upper),
            &smt::constant(97),
        );
        proofs.check();
    }
}
