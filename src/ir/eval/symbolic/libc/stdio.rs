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
                let descriptor = self.number(binary, convention, 0)? as u32;
                if descriptor != 0 && !self.options.stdin_descriptors.contains(&descriptor) {
                    return Err(invalid("unsupported read descriptor").into());
                }
                let address = self.number(binary, convention, 1)?;
                let count = self.number(binary, convention, 2)?;
                let count =
                    count.min(self.stdin.len().saturating_sub(self.input_position) as u64) as usize;
                let bytes = self.stdin[self.input_position..self.input_position + count].to_vec();
                for _ in 0..count {
                    self.tick()?;
                }
                self.write_memory(binary, address, &bytes)?;
                self.input_position += count;
                Ok(Term::constant(count as u64))
            }
            Operation::Fgets | Operation::Gets => {
                let destination = self.number(binary, convention, 0)?;
                let maximum = if matches!(operation, Operation::Fgets) {
                    let size = self.number(binary, convention, 1)? as u32 as i32;
                    if size <= 0 {
                        return Ok(Term::constant(0));
                    }
                    // Only the standard input stream is modeled.
                    let stream = self.number(binary, convention, 2)?;
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
                    self.tick()?;
                    let newline = self.test(format!("(= {} {})", byte.text, smt::constant(10)))?;
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
                self.write_memory(binary, destination, &bytes)?;
                Ok(Term::constant(destination))
            }
            Operation::Scanf | Operation::Fscanf | Operation::Sscanf => {
                let (input, format_index, source) = match operation {
                    Operation::Sscanf => {
                        let address = self.number(binary, convention, 0)?;
                        (
                            self.string(binary, address, self.model_bound())?,
                            1,
                            ScanSource::String,
                        )
                    }
                    Operation::Fscanf => {
                        if self.stdin_stream == 0
                            || self.number(binary, convention, 0)? != self.stdin_stream
                        {
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
                let address = self.number(binary, convention, format_index)?;
                let format = self.concrete_format(binary, address)?;
                let (result, consumed) = self.scan(
                    binary,
                    convention,
                    &format,
                    &input,
                    format_index + 1,
                    source,
                )?;
                if !matches!(operation, Operation::Sscanf) {
                    self.input_position += consumed;
                }
                Ok(Term::constant(result))
            }
            Operation::Puts | Operation::Printf => {
                let address = self.number(binary, convention, 0)?;
                if matches!(operation, Operation::Puts) {
                    let bytes = self.string(binary, address, self.model_bound())?;
                    self.write_output(1, bytes);
                    self.stdout.push(Term::constant(10));
                    return Ok(Term::constant(0));
                }
                let format = self.concrete_format(binary, address)?;
                let start = self.stdout.len();
                let mut argument = 1;
                let mut position = 0;
                while position < format.len() {
                    self.tick()?;
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
                    let term = self.argument(binary, convention, argument)?;
                    argument += 1;
                    self.require_defined(
                        &term,
                        if conversion == b'c' {
                            8
                        } else if conversion == b's' {
                            64
                        } else {
                            32
                        },
                    )?;
                    match conversion {
                        b'c' => {
                            let byte = self.low(&term, 8)?;
                            self.stdout.push(byte);
                        }
                        b's' => {
                            let address = self.resolve(term)?;
                            let bytes = self.string(binary, address, self.model_bound())?;
                            self.stdout.extend(bytes);
                        }
                        b'd' | b'u' | b'x' => {
                            let mut value = self.low(&term, 32)?;
                            if conversion == b'd'
                                && self.test(format!(
                                    "(bvuge {} {})",
                                    value.text,
                                    smt::constant(1 << 31)
                                ))?
                            {
                                self.stdout.push(Term::constant(45));
                                value =
                                    self.bind(smt::low(&format!("(bvneg {})", value.text), 32))?;
                            }
                            let base = if conversion == b'x' { 16 } else { 10 };
                            let mut digits = Vec::new();
                            loop {
                                let remainder =
                                    format!("(bvurem {} {})", value.text, smt::constant(base));
                                digits.push(self.bind(format!("(ite (bvult {remainder} {}) (bvadd {remainder} {}) (bvadd {remainder} {}))", smt::constant(10), smt::constant(48), smt::constant(87)))?);
                                value = self.bind(format!(
                                    "(bvudiv {} {})",
                                    value.text,
                                    smt::constant(base)
                                ))?;
                                if self.zero(&value)? {
                                    break;
                                }
                                self.tick()?;
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
            self.tick()?;
            let byte = format[position];
            position += 1;
            if byte.is_ascii_whitespace() {
                while consumed < input.len() && self.whitespace(&input[consumed])? {
                    consumed += 1;
                    self.tick()?;
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
                if !self.test(format!(
                    "(= {} {})",
                    input[consumed].text,
                    smt::constant(u64::from(byte))
                ))? {
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
                    if !self.whitespace_with_preference(
                        &input[consumed],
                        PredicatePreference::FalseFirst,
                    )? {
                        break;
                    }
                    consumed += 1;
                    self.tick()?;
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
                while consumed < end
                    && (conversion == b'c' || !self.whitespace(&input[consumed])?)
                {
                    self.tick()?;
                    bytes.push(input[consumed].clone());
                    consumed += 1;
                }
                if conversion == b's' {
                    bytes.push(Term::constant(0));
                }
            } else {
                let parsed = self.parse_integer(
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
                )?;
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
                    bytes.push(self.bind(smt::low(
                        &format!("(bvlshr {} {})", value.text, smt::constant(index * 8)),
                        8,
                    ))?);
                }
            }
            if !suppress {
                let destination = self.number(binary, convention, argument)?;
                argument += 1;
                self.write_memory(binary, destination, &bytes)?;
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
