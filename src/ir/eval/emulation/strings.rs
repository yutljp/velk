//! Conservative observation of buffer transformations during strict execution.

mod returns;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use crate::emulation::Options;
use crate::ir::{BinOp, CallKind, Convention, Expr};
use crate::loader::Image;
use crate::ssa::ranges::Fact;
use crate::string_decoding::DecodedString;

use super::{Runner, Stop};

const READ: u8 = 1;
const TRANSFORMED: u8 = 2;
const LITERAL: u8 = 4;
const MAX_BUFFER: u64 = 4096;
const MAX_MEMORY: usize = 65536;

pub(super) struct Recovery {
    pub(super) function: u64,
    pub(super) registers: HashMap<u16, u8>,
    memory: BTreeMap<u64, MemoryByte>,
    writes: Vec<u64>,
    results: Vec<DecodedString>,
    pub(super) depth: usize,
    inline_writes: HashSet<u64>,
    returns: HashMap<usize, returns::ReturnAddress>,
}

struct MemoryByte {
    value: Fact,
    origin: u8,
}

pub(super) struct Candidate {
    pointers: Vec<Buffer>,
    first_write: usize,
    stack_arguments: Vec<u64>,
}

struct Buffer {
    address: u64,
    size: u64,
    initial_text: Option<String>,
}

pub(crate) fn recover_strings(
    image: &Image,
    function: u64,
    deadline: Option<Instant>,
) -> Option<Vec<DecodedString>> {
    if image.go {
        return Some(Vec::new());
    }
    let options = Options {
        step_limit: 200_000,
        time_limit_ms: 100,
        ..Options::default()
    };
    let recovery = Recovery {
        function,
        registers: HashMap::new(),
        memory: BTreeMap::new(),
        writes: Vec::new(),
        results: Vec::new(),
        depth: 0,
        inline_writes: HashSet::new(),
        returns: HashMap::new(),
    };
    match super::run_with_recovery(image, function, &options, deadline, Some(recovery)) {
        Ok((report, _)) if report.reason == "time limit" => None,
        Ok((_, Some(recovery))) => Some(recovery.results),
        _ => Some(Vec::new()),
    }
}

impl Runner<'_> {
    pub(super) fn recovery_load(
        &self,
        address: u64,
        width: u8,
        signed: bool,
    ) -> Result<Fact, Stop> {
        if width == 0 || width > 8 {
            return Err(Stop::Error("invalid load width".to_owned()));
        }
        let recovery = self.recovery.as_ref().expect("automatic execution state");
        let memory = self.machine.strict.as_ref().expect("strict memory");
        if !memory.check(address, u64::from(width), /* write */ false) {
            return match self.memory_error() {
                Err(stop) => Err(stop),
                Ok(()) => Err(Stop::Error("invalid memory read".to_owned())),
            };
        }
        let mut zeros = 0;
        let mut ones = 0;
        for offset in 0..u64::from(width) {
            let at = address + offset;
            let fact = if let Some(byte) = recovery.memory.get(&at) {
                byte.value
            } else if let Some(byte) = self.machine.memory.get(&at) {
                Fact::constant(u64::from(*byte))
            } else if self.image.section_at(at).is_some() {
                Fact::constant(u64::from(memory.byte(at)))
            } else {
                Fact::TOP
            };
            zeros |= (fact.zeros & 255) << (offset * 8);
            ones |= (fact.ones & 255) << (offset * 8);
        }
        let fact = Fact::bits(zeros, ones)
            .unwrap_or(Fact::TOP)
            .truncate(u32::from(width) * 8);
        if signed {
            Ok(fact.sign_extend(u32::from(width) * 8))
        } else {
            Ok(fact)
        }
    }

    pub(super) fn recovery_store(
        &mut self,
        address: u64,
        width: u8,
        fact: Fact,
        origin: u8,
    ) -> Result<(), Stop> {
        if width == 0 || width > 8 {
            return Err(Stop::Error("invalid store width".to_owned()));
        }
        if !self.machine.strict.as_ref().expect("strict memory").check(
            address,
            u64::from(width),
            /* write */ true,
        ) {
            return self.memory_error();
        }
        let recovery = self.recovery.as_mut().expect("automatic execution state");
        if recovery.memory.len().saturating_add(usize::from(width)) > MAX_MEMORY
            || recovery.writes.len().saturating_add(usize::from(width)) > 200_000
        {
            return Err(Stop::Error("automatic decoding memory limit".to_owned()));
        }
        for offset in 0..u64::from(width) {
            let byte = stored_byte(fact, offset);
            recovery.memory.insert(
                address + offset,
                MemoryByte {
                    value: byte,
                    origin,
                },
            );
            if recovery.depth == 0 {
                recovery.inline_writes.insert(address + offset);
            } else {
                recovery.inline_writes.remove(&(address + offset));
            }
            recovery.writes.push(address + offset);
            if let Some(value) = byte.singleton() {
                self.machine.memory.insert(address + offset, value as u8);
            } else {
                self.machine.memory.remove(&(address + offset));
            }
        }
        Ok(())
    }

    pub(super) fn origin(&self, expression: &Expr) -> u8 {
        let Some(recovery) = &self.recovery else {
            return 0;
        };
        match expression {
            Expr::Const(_) => LITERAL,
            Expr::Reg { index, .. } => recovery.registers.get(index).copied().unwrap_or(0),
            Expr::Load { addr, width, .. } => {
                let Ok(address) = self.eval(addr) else {
                    return 0;
                };
                let mut origin = READ;
                for offset in 0..u64::from(*width) {
                    if let Some(at) = address.checked_add(offset)
                        && let Some(stored) = recovery.memory.get(&at)
                    {
                        origin |= stored.origin & TRANSFORMED;
                    }
                }
                origin
            }
            Expr::SignExtend { value, .. } => self.origin(value),
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } => {
                if let Expr::Const(mask) = rhs.as_ref() {
                    return if mask & 255 == 0 {
                        LITERAL
                    } else {
                        self.origin(lhs)
                    };
                }
                if let Expr::Const(mask) = lhs.as_ref() {
                    return if mask & 255 == 0 {
                        LITERAL
                    } else {
                        self.origin(rhs)
                    };
                }
                self.origin(lhs) | self.origin(rhs)
            }
            Expr::Bin {
                op: BinOp::Or,
                lhs,
                rhs,
            } => self.origin(lhs) | self.origin(rhs),
            Expr::Bin {
                op: BinOp::Shl,
                lhs,
                rhs,
            } => {
                if let Expr::Const(shift) = rhs.as_ref()
                    && *shift >= 8
                {
                    return LITERAL;
                }
                self.origin(lhs)
            }
            Expr::Bin {
                op: BinOp::Shr | BinOp::Sar,
                lhs,
                ..
            } => self.origin(lhs),
            _ => {
                let mut origin = 0;
                for child in crate::ir::visit::children(expression) {
                    origin |= self.origin(child);
                }
                if origin & READ != 0 {
                    origin |= TRANSFORMED;
                }
                origin
            }
        }
    }

    fn buffer_pointer(&self, value: u64) -> bool {
        let top = super::super::stack_top(self.image.isa);
        (top.saturating_sub(65536)..top).contains(&value)
            || (self.heap_base..self.heap_base.saturating_add(crate::emulation::HEAP_SIZE))
                .contains(&value)
            || self
                .image
                .section_at(value)
                .is_some_and(|s| s.loaded && !s.executable)
    }

    pub(super) fn recovery_candidate(
        &self,
        convention: Convention,
        kind: CallKind,
        stack: u64,
    ) -> Option<Candidate> {
        let Some(recovery) = self.recovery.as_ref() else {
            return None;
        };
        let mut arguments = Vec::new();
        let mut stack_arguments = Vec::new();
        let width = u64::from(crate::arch::pointer_bytes(self.image.isa));
        for index in 0..8 {
            let value = self.argument(index, convention, kind).ok();
            if value.is_some()
                && index >= convention.arguments().len()
                && let Some(base) = convention.stack_arguments()
                && let Some(offset) = kind.stack_offset(self.image.isa, convention, base)
                && let Some(address) = stack.checked_add_signed(offset).and_then(|base| {
                    base.checked_add((index - convention.arguments().len()) as u64 * width)
                })
            {
                stack_arguments.push(address);
            }
            arguments.push(value);
        }
        let mut pointers = Vec::new();
        for (index, argument) in arguments.iter().enumerate() {
            let Some(address) = argument.filter(|value| self.buffer_pointer(*value)) else {
                continue;
            };
            for value in &arguments[index + 1..] {
                if let Some(size) = value.filter(|value| (1..=MAX_BUFFER).contains(value)) {
                    let mut bytes = Vec::new();
                    for offset in 0..size.saturating_add(2).min(MAX_BUFFER) {
                        let Some(at) = address.checked_add(offset) else {
                            break;
                        };
                        let Ok(fact) = self.recovery_load(at, 1, false) else {
                            break;
                        };
                        let Some(byte) = fact.singleton() else {
                            break;
                        };
                        if offset >= size && byte != 0 {
                            break;
                        }
                        bytes.push(byte as u8);
                    }
                    let initial_text = crate::string_decoding::text(&bytes).map(|(_, text)| text);
                    pointers.push(Buffer {
                        address,
                        size,
                        initial_text,
                    });
                    break;
                }
            }
        }
        Some(Candidate {
            pointers,
            first_write: recovery.writes.len(),
            stack_arguments,
        })
    }

    fn observe(
        &mut self,
        buffer: &Buffer,
        decoder: u64,
        site: u64,
        target: Option<u64>,
        literal: bool,
        since: usize,
    ) {
        let pointer = buffer.address;
        let top = super::super::stack_top(self.image.isa);
        let on_stack = (top.saturating_sub(65536)..top).contains(&pointer);
        let Some(recovery) = &self.recovery else {
            return;
        };
        if recovery.results.len() >= 64 {
            return;
        }
        let mut bytes = Vec::new();
        let mut transformed = 0;
        let mut constructed = 0;
        for offset in 0..buffer.size.saturating_add(2).min(MAX_BUFFER) {
            let Some(at) = pointer.checked_add(offset) else {
                return;
            };
            let Ok(fact) = self.recovery_load(at, 1, false) else {
                return;
            };
            let Some(byte) = fact.singleton() else {
                break;
            };
            if offset >= buffer.size && byte != 0 {
                break;
            }
            bytes.push(byte as u8);
            if let Some(byte) = recovery.memory.get(&at) {
                transformed += usize::from(byte.origin & TRANSFORMED != 0);
                constructed += usize::from(byte.origin & (LITERAL | READ) == LITERAL);
            }
            // UTF-16 needs two zero bytes on a code-unit boundary.
            if byte == 0 && offset >= 1 && bytes[bytes.len() - 2] == 0 && offset % 2 == 1 {
                break;
            }
            if byte == 0 && bytes.get(1).is_some_and(|byte| *byte != 0) {
                break;
            }
        }
        let Some((encoding, text)) = crate::string_decoding::text(&bytes) else {
            return;
        };
        if buffer.initial_text.as_ref() == Some(&text) {
            return;
        }
        let size = if encoding == "utf16le" {
            text.encode_utf16().count() * 2
        } else {
            text.len()
        };
        if transformed < size / 2 && !(literal && on_stack && constructed >= size) {
            return;
        }
        let end = pointer.saturating_add(size as u64);
        let terminator = if encoding == "utf16le" { 2 } else { 1 };
        if decoder != recovery.function
            && recovery.writes[since..].iter().any(|at| {
                *at >= end.saturating_add(terminator) && *at < pointer.saturating_add(buffer.size)
            })
        {
            return;
        }
        if decoder == recovery.function
            && !recovery
                .inline_writes
                .iter()
                .any(|at| *at >= pointer && *at < end)
        {
            return;
        }
        if decoder == recovery.function {
            let top = super::super::stack_top(self.image.isa);
            if recovery.inline_writes.iter().any(|at| {
                !(top.saturating_sub(65536)..top).contains(at)
                    && !(*at >= pointer && *at < end.saturating_add(terminator))
            }) {
                return;
            }
        }
        if !recovery.writes[since..]
            .iter()
            .any(|at| *at >= pointer && *at < end)
        {
            return;
        }
        let string = DecodedString {
            addr: pointer,
            function: recovery.function,
            site,
            decoder,
            decoder_name: self
                .image
                .functions
                .get(&decoder)
                .and_then(|f| f.name.clone()),
            stack: on_stack,
            encoding,
            text,
            target,
        };
        let recovery = self.recovery.as_mut().expect("automatic execution state");
        if !recovery.results.contains(&string) {
            recovery.results.push(string);
        }
    }

    pub(super) fn finish_candidate(
        &mut self,
        candidate: Option<Candidate>,
        decoder: u64,
        site: u64,
        stack: u64,
    ) {
        let Some(candidate) = candidate else {
            return;
        };
        let Some(recovery) = &self.recovery else {
            return;
        };
        let top = super::super::stack_top(self.image.isa);
        for at in &recovery.writes[candidate.first_write..] {
            if (top.saturating_sub(65536)..stack).contains(at) {
                continue;
            }
            if candidate.stack_arguments.iter().any(|address| {
                *at >= *address
                    && at.saturating_sub(*address)
                        < u64::from(crate::arch::pointer_bytes(self.image.isa))
            }) {
                continue;
            }
            if !candidate
                .pointers
                .iter()
                .any(|p| *at >= p.address && at.saturating_sub(p.address) < p.size)
            {
                return;
            }
        }
        for buffer in candidate.pointers {
            self.observe(
                &buffer,
                decoder,
                site,
                Some(decoder),
                false,
                candidate.first_write,
            );
        }
    }

    pub(super) fn recover_inline(&mut self, target: u64, convention: Convention, kind: CallKind) {
        let Some(recovery) = &self.recovery else {
            return;
        };
        let function = recovery.function;
        let name = self
            .image
            .imports
            .get(&target)
            .or_else(|| {
                self.image
                    .functions
                    .get(&target)
                    .and_then(|f| f.name.as_ref())
            })
            .map(|s| s.trim_start_matches('_').split('@').next().unwrap_or(s));
        let literal = matches!(
            name,
            Some("puts" | "strlen" | "strcmp" | "strncmp" | "strcpy")
        );
        for index in 0..4 {
            if let Ok(pointer) = self.argument(index, convention, kind)
                && self.buffer_pointer(pointer)
            {
                self.observe(
                    &Buffer {
                        address: pointer,
                        size: MAX_BUFFER,
                        initial_text: None,
                    },
                    function,
                    self.address,
                    Some(target),
                    literal,
                    0,
                );
            }
        }
    }
}

fn stored_byte(fact: Fact, offset: u64) -> Fact {
    Fact::bits(fact.zeros >> (offset * 8), fact.ones >> (offset * 8))
        .unwrap_or(Fact::TOP)
        .truncate(8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::Proofs;

    #[test]
    fn smt_stored_byte_facts_contain_every_permitted_input() {
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for fact in [
            Fact::TOP,
            Fact::width(32),
            Fact::constant(0x1234_5678_90ab_cdef),
            Fact::bits(0x8040_2010_0804_0201, 0x0102_0408_1020_4080).unwrap(),
        ] {
            for offset in 0..8 {
                let byte = stored_byte(fact, offset);
                let input = format!(
                    "(and (= (bvand r0 {}) {}) (= (bvand r0 {}) {}))",
                    crate::ir::smt::constant(fact.ones),
                    crate::ir::smt::constant(fact.ones),
                    crate::ir::smt::constant(fact.zeros),
                    crate::ir::smt::constant(0)
                );
                let value = format!(
                    "(bvand (bvlshr r0 {}) {})",
                    crate::ir::smt::constant(offset * 8),
                    crate::ir::smt::constant(255)
                );
                let output = format!(
                    "(and (= (bvand {value} {}) {}) (= (bvand {value} {}) {}))",
                    crate::ir::smt::constant(byte.ones),
                    crate::ir::smt::constant(byte.ones),
                    crate::ir::smt::constant(byte.zeros),
                    crate::ir::smt::constant(0)
                );
                proofs.predicate(
                    format!("stored byte {offset} {fact:?}"),
                    &format!("(=> {input} {output})"),
                    "true",
                );
            }
        }
        proofs.check();
    }
}
