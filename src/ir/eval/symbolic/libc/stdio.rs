//! Symbolic standard input and output operations.

use super::super::{Evaluation, State, Term};
use super::{IntegerKind, IntegerModel, PredicatePreference, ScanIntegerType};
use crate::ir::Convention;
use crate::ir::eval::emulation::io::{self, Operation};
use crate::ir::smt;
use crate::service::Binary;
use crate::symbolic::invalid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanSource {
    Stdin,
    String,
}

impl State {
    pub(in crate::ir::eval::symbolic) fn input_output(
        &mut self,
        binary: &Binary,
        convention: Convention,
        operation: Operation,
    ) -> Evaluation<Term> {
        if self.isa == crate::loader::Isa::AArch64
            && binary.image().format != crate::loader::Format::Elf
            && matches!(
                operation,
                Operation::Scanf | Operation::Fscanf | Operation::Sscanf | Operation::Printf
            )
        {
            return Err(invalid("variadic I/O models require the ELF AArch64 convention").into());
        }
        match operation {
            Operation::Getchar => Ok(io::next_input(&self.stdin, &mut self.input_position)
                .unwrap_or_else(|| Term::constant(u64::from(u32::MAX)))),
            Operation::Read => {
                let descriptor_number = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let descriptor = descriptor_number as u32;
                if descriptor != 0 && !self.options.stdin_descriptors.contains(&descriptor) {
                    return Err(invalid("unsupported read descriptor").into());
                }
                let address = match self.number(binary, convention, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let count = match self.number(binary, convention, 2) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let count =
                    count.min(self.stdin.len().saturating_sub(self.input_position) as u64) as usize;
                let bytes = self.stdin[self.input_position..self.input_position + count].to_vec();
                for _ in 0..count {
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                }
                if let Err(error) = self.write_memory(binary, address, &bytes) {
                    return Err(error.into());
                }
                self.input_position += count;
                Ok(Term::constant(count as u64))
            }
            Operation::Fgets | Operation::Gets => {
                let destination = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let maximum = if matches!(operation, Operation::Fgets) {
                    let convention_number = match self.number(binary, convention, 1) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let size = convention_number as u32 as i32;
                    if size <= 0 {
                        return Ok(Term::constant(0));
                    }
                    // Only the standard input stream is modeled.
                    let stream = match self.number(binary, convention, 2) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if stream == 0 || stream != self.stdin_stream {
                        return Err(invalid("unsupported fgets stream").into());
                    }
                    size as usize - 1
                } else {
                    self.stdin.len().saturating_sub(self.input_position)
                };
                let input_start = self.input_position;
                let mut bytes = Vec::new();
                while bytes.len() < maximum {
                    let Some(byte) = io::next_input(&self.stdin, &mut self.input_position) else {
                        break;
                    };
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    let newline =
                        match self.test(format!("(= {} {})", byte.text, smt::constant(10))) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                    if !newline || matches!(operation, Operation::Fgets) {
                        bytes.push(byte);
                    }
                    if newline {
                        break;
                    }
                }
                if bytes.is_empty()
                    && (maximum != 0 || matches!(operation, Operation::Gets))
                    && self.input_position == input_start
                {
                    return Ok(Term::constant(0));
                }
                bytes.push(Term::constant(0));
                if let Err(error) = self.write_memory(binary, destination, &bytes) {
                    return Err(error.into());
                }
                Ok(Term::constant(destination))
            }
            Operation::Scanf | Operation::Fscanf | Operation::Sscanf => {
                let (input, format_index, source) = match operation {
                    Operation::Sscanf => {
                        let address = match self.number(binary, convention, 0) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let input_bytes = match self.string(binary, address, self.model_bound()) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        (input_bytes, 1, ScanSource::String)
                    }
                    Operation::Fscanf => {
                        let unsupported_stream = if self.stdin_stream == 0 {
                            true
                        } else {
                            let stream = match self.number(binary, convention, 0) {
                                Ok(value) => value,
                                Err(error) => return Err(error),
                            };
                            stream != self.stdin_stream
                        };
                        if unsupported_stream {
                            return Err(invalid("unsupported fscanf stream").into());
                        }
                        (
                            self.stdin[self.input_position..].to_vec(),
                            1,
                            ScanSource::Stdin,
                        )
                    }
                    _ => (
                        self.stdin[self.input_position..].to_vec(),
                        0,
                        ScanSource::Stdin,
                    ),
                };
                let address = match self.number(binary, convention, format_index) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let format = match self.concrete_format(binary, address) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let (result, consumed) = match self.scan(
                    binary,
                    convention,
                    &format,
                    &input,
                    format_index + 1,
                    source,
                ) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if !matches!(operation, Operation::Sscanf) {
                    self.input_position += consumed;
                }
                Ok(Term::constant(result))
            }
            Operation::Puts | Operation::Printf => {
                let address = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if matches!(operation, Operation::Puts) {
                    let bytes = match self.string(binary, address, self.model_bound()) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    self.write_output(1, bytes);
                    self.stdout.push(Term::constant(10));
                    return Ok(Term::constant(0));
                }
                let format = match self.concrete_format(binary, address) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let start = self.stdout.len();
                let mut argument = 1;
                let mut position = 0;
                while position < format.len() {
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    let byte = format[position];
                    position += 1;
                    if byte != b'%' {
                        self.stdout.push(Term::constant(u64::from(byte)));
                        continue;
                    }
                    let Some(&conversion) = format.get(position) else {
                        return Err(invalid("unsupported printf trailing %").into());
                    };
                    position += 1;
                    if conversion == b'%' {
                        self.stdout.push(Term::constant(37));
                        continue;
                    }
                    let term = match self.argument(binary, convention, argument) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    argument += 1;
                    if let Err(error) = self.require_defined(
                        &term,
                        if conversion == b'c' {
                            8
                        } else if conversion == b's' {
                            64
                        } else {
                            32
                        },
                    ) {
                        return Err(error.into());
                    }
                    match conversion {
                        b'c' => {
                            let byte = match self.low(&term, 8) {
                                Ok(value) => value,
                                Err(error) => return Err(error.into()),
                            };
                            self.stdout.push(byte);
                        }
                        b's' => {
                            let address = match self.resolve(term) {
                                Ok(value) => value,
                                Err(error) => return Err(error),
                            };
                            let bytes = match self.string(binary, address, self.model_bound()) {
                                Ok(value) => value,
                                Err(error) => return Err(error),
                            };
                            self.stdout.extend(bytes);
                        }
                        b'd' | b'u' | b'x' => {
                            let mut value = match self.low(&term, 32) {
                                Ok(value) => value,
                                Err(error) => return Err(error.into()),
                            };
                            let negative = if conversion == b'd' {
                                match self.test(format!(
                                    "(bvuge {} {})",
                                    value.text,
                                    smt::constant(1 << 31)
                                )) {
                                    Ok(value) => value,
                                    Err(error) => return Err(error),
                                }
                            } else {
                                false
                            };
                            if negative {
                                self.stdout.push(Term::constant(45));
                                value = match self
                                    .bind(smt::low(&format!("(bvneg {})", value.text), 32))
                                {
                                    Ok(value) => value,
                                    Err(error) => return Err(error.into()),
                                };
                            }
                            let base = if conversion == b'x' { 16 } else { 10 };
                            let mut digits = Vec::new();
                            loop {
                                let remainder =
                                    format!("(bvurem {} {})", value.text, smt::constant(base));
                                let digit_expression = format!(
                                    "(ite (bvult {remainder} {}) (bvadd {remainder} {}) (bvadd {remainder} {}))",
                                    smt::constant(10),
                                    smt::constant(48),
                                    smt::constant(87)
                                );
                                let digit = match self.bind(digit_expression) {
                                    Ok(value) => value,
                                    Err(error) => return Err(error.into()),
                                };
                                digits.push(digit);
                                value = match self.bind(format!(
                                    "(bvudiv {} {})",
                                    value.text,
                                    smt::constant(base)
                                )) {
                                    Ok(value) => value,
                                    Err(error) => return Err(error.into()),
                                };
                                let is_zero = match self.zero(&value) {
                                    Ok(value) => value,
                                    Err(error) => return Err(error),
                                };
                                if is_zero {
                                    break;
                                }
                                if let Err(error) = self.tick() {
                                    return Err(error);
                                }
                            }
                            self.stdout.extend(digits.into_iter().rev());
                        }
                        _ => return Err(invalid("unsupported symbolic printf conversion").into()),
                    }
                }
                Ok(Term::constant((self.stdout.len() - start) as u64))
            }
            _ => Err(invalid("unsupported symbolic I/O import").into()),
        }
    }

    fn scan(
        &mut self,
        binary: &Binary,
        convention: Convention,
        format: &[u8],
        input: &[Term],
        mut argument: usize,
        source: ScanSource,
    ) -> Evaluation<(u64, usize)> {
        let mut position = 0;
        let mut consumed = 0;
        let mut assignments = 0;
        let mut conversions = 0;
        let mut failure = false;
        while position < format.len() {
            if let Err(error) = self.tick() {
                return Err(error);
            }
            let byte = format[position];
            position += 1;
            if byte.is_ascii_whitespace() {
                while consumed < input.len() {
                    let whitespace = match self.whitespace(&input[consumed]) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if !whitespace {
                        break;
                    }
                    consumed += 1;
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                }
                continue;
            }
            if byte != b'%' || format.get(position) == Some(&b'%') {
                if byte == b'%' {
                    position += 1;
                }
                if consumed == input.len() {
                    failure = true;
                    break;
                }
                let is_literal = match self.test(format!(
                    "(= {} {})",
                    input[consumed].text,
                    smt::constant(u64::from(byte))
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if !is_literal {
                    break;
                }
                consumed += 1;
                continue;
            }
            let suppress = format.get(position) == Some(&b'*');
            if suppress {
                position += 1;
            }
            let mut width = 0usize;
            while let Some(digit @ b'0'..=b'9') = format.get(position) {
                let Some(next) = width
                    .checked_mul(10)
                    .and_then(|n| n.checked_add((digit - b'0') as usize))
                    .filter(|n| *n <= 65536)
                else {
                    return Err(invalid("scanf width exceeds bound").into());
                };
                width = next;
                position += 1;
            }
            let Some(&conversion) = format.get(position) else {
                return Err(invalid("unsupported scanf trailing %").into());
            };
            position += 1;
            if !matches!(conversion, b'd' | b'u' | b'x' | b's' | b'c') {
                return Err(invalid("unsupported symbolic scanf conversion").into());
            }
            if conversion != b'c' {
                while consumed < input.len() {
                    let is_whitespace = match self.whitespace_with_preference(
                        &input[consumed],
                        PredicatePreference::FalseFirst,
                    ) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if !is_whitespace {
                        break;
                    }
                    consumed += 1;
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                }
            }
            if consumed == input.len() {
                failure = true;
                break;
            }
            let maximum = if width == 0 {
                if conversion == b'c' {
                    1
                } else {
                    input.len() - consumed
                }
            } else {
                width
            };
            let end = consumed.saturating_add(maximum).min(input.len());
            let mut bytes = Vec::new();
            if matches!(conversion, b's' | b'c') {
                while consumed < end {
                    if conversion != b'c' {
                        let whitespace = match self.whitespace(&input[consumed]) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if whitespace {
                            break;
                        }
                    }
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    bytes.push(input[consumed].clone());
                    consumed += 1;
                }
                if conversion == b's' {
                    bytes.push(Term::constant(0));
                }
            } else {
                let parsed = match self.parse_integer(
                    &input[consumed..end],
                    if conversion == b'x' { 16 } else { 10 },
                    IntegerKind::Scan,
                    if source == ScanSource::Stdin
                        && !suppress
                        && width == 0
                        && matches!(conversion, b'd' | b'u')
                    {
                        IntegerModel::StdinToken(if conversion == b'd' {
                            ScanIntegerType::Signed
                        } else {
                            ScanIntegerType::Unsigned
                        })
                    } else {
                        IntegerModel::Exact
                    },
                    u32::from(crate::arch::pointer_bytes(self.isa)) * 8,
                ) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if parsed.synthesized {
                    self.scanned_integers.push(super::super::ScannedInteger {
                        start: self.input_position + consumed,
                        length: parsed.consumed,
                        whitespace: parsed.leading_whitespace,
                        sign: parsed.sign,
                        digits: parsed.digits,
                        unsigned: conversion == b'u',
                        canonical: parsed.canonical,
                        value: parsed.value.clone(),
                    });
                }
                consumed += parsed.consumed;
                if !parsed.matched {
                    break;
                }
                let value = parsed.value;
                for index in 0..4 {
                    let shifted_byte = match self.bind(smt::low(
                        &format!("(bvlshr {} {})", value.text, smt::constant(index * 8)),
                        8,
                    )) {
                        Ok(value) => value,
                        Err(error) => return Err(error.into()),
                    };
                    bytes.push(shifted_byte);
                }
            }
            if !suppress {
                let destination = match self.number(binary, convention, argument) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                argument += 1;
                if let Err(error) = self.write_memory(binary, destination, &bytes) {
                    return Err(error.into());
                }
                assignments += 1;
            }
            conversions += 1;
        }
        Ok((
            if failure && conversions == 0 {
                u64::from(u32::MAX)
            } else {
                assignments
            },
            consumed,
        ))
    }
}
