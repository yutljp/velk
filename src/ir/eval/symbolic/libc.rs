//! Bounded C library effects on symbolic byte and integer terms.

use super::{Evaluation, Failure, State, Term};
use crate::ir::eval::emulation::hooks::{self, Hook};
use crate::ir::eval::emulation::io::{self, Operation};
use crate::ir::smt;
use crate::ir::{Convention, Expr};
use crate::service::Binary;
use crate::symbolic::invalid;

#[derive(Clone, Copy)]
enum IntegerKind {
    Scan,
    Strtol,
}

#[derive(Clone, Copy)]
enum PredicatePreference {
    FalseFirst,
    TrueFirst,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanSource {
    Stdin,
    String,
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
        self.resolve(self.argument(binary, convention, index)?)
    }

    pub(super) fn tick(&mut self) -> Evaluation<()> {
        if self.steps >= self.options.step_limit {
            return Err(invalid("step budget in libc model").into());
        }
        self.steps += 1;
        Ok(())
    }

    pub(super) fn byte(&mut self, binary: &Binary, base: u64, offset: usize) -> Evaluation<Term> {
        self.tick()?;
        let Some(address) = base.checked_add(offset as u64) else {
            return Err(invalid("libc memory address overflows").into());
        };
        Ok(self.read_memory(binary, address, 1)?.remove(0))
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
            let byte = self.byte(binary, address, offset)?;
            if self.zero(&byte)? {
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
        let terms = self.string(binary, address, self.model_bound())?;
        let mut bytes = Vec::new();
        for term in terms {
            bytes.push(self.resolve(term)? as u8);
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
        if matches!(hook, Hook::IntegerEnd)
            && matches!(
                binary.image().format,
                crate::loader::Format::Pe | crate::loader::Format::Coff
            )
        {
            return Err(invalid("unsupported symbolic strtol data model").into());
        }
        if let Hook::Io(operation) = hook {
            if let Some(result) = self.file_hook(binary, convention, operation)? {
                return Ok(result);
            }
            return self.input_output(binary, convention, operation);
        }
        if matches!(hook, Hook::Upper | Hook::Lower) {
            let term = self.argument(binary, convention, 0)?;
            let value = self.low(&term, 32)?;
            self.require_defined(&value, 32)?;
            return Ok(self.bind(case_conversion(&value.text, hook))?);
        }
        if matches!(hook, Hook::Getline) {
            return self.getline(binary, convention);
        }
        let first = self.number(binary, convention, 0)?;
        match hook {
            Hook::Length
            | Hook::LengthN
            | Hook::StringCopy
            | Hook::StringCopyN
            | Hook::Character => {
                let copying = matches!(hook, Hook::StringCopy | Hook::StringCopyN);
                let source = if copying {
                    self.number(binary, convention, 1)?
                } else {
                    first
                };
                let limited = matches!(hook, Hook::LengthN | Hook::StringCopyN);
                let maximum = if limited {
                    self.number(binary, convention, if copying { 2 } else { 1 })?
                } else {
                    self.model_bound() as u64
                };
                if maximum > 65536 {
                    return Err(invalid("string operation exceeds model bound").into());
                }
                let character = if matches!(hook, Hook::Character) {
                    Some(self.argument(binary, convention, 1)?)
                } else {
                    None
                };
                let mut bytes = Vec::new();
                let mut ended = false;
                for offset in 0..maximum as usize {
                    let byte = if ended {
                        Term::constant(0)
                    } else {
                        self.byte(binary, source, offset)?
                    };
                    if let Some(character) = &character {
                        let low = self.low(character, 8)?;
                        if self.test(format!("(= {} {})", byte.text, low.text))? {
                            let Some(address) = source.checked_add(offset as u64) else {
                                return Err(invalid("strchr address overflows").into());
                            };
                            return Ok(Term::constant(address));
                        }
                    }
                    let zero = ended || self.zero(&byte)?;
                    if copying {
                        bytes.push(byte);
                    }
                    if zero {
                        ended = true;
                        if matches!(hook, Hook::Character) {
                            return Ok(Term::constant(0));
                        }
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
                if copying {
                    self.write_memory(binary, first, &bytes)?;
                }
                Ok(Term::constant(if copying { first } else { maximum }))
            }
            Hook::Compare | Hook::CompareN | Hook::MemoryCompare => {
                let second = self.number(binary, convention, 1)?;
                let maximum = if matches!(hook, Hook::Compare) {
                    self.model_bound() as u64
                } else {
                    self.number(binary, convention, 2)?
                };
                if maximum > 65536 {
                    return Err(invalid("comparison exceeds model bound").into());
                }
                for offset in 0..maximum as usize {
                    let a = self.byte(binary, first, offset)?;
                    let b = self.byte(binary, second, offset)?;
                    if self.test(format!("(not (= {} {}))", a.text, b.text))? {
                        // C only specifies the sign of a nonzero comparison result.
                        return Ok(
                            self.bind(smt::low(&format!("(bvsub {} {})", a.text, b.text), 32))?
                        );
                    }
                    if !matches!(hook, Hook::MemoryCompare) && self.zero(&a)? {
                        return Ok(Term::constant(0));
                    }
                }
                if matches!(hook, Hook::Compare) {
                    return Err(invalid("comparison exceeds string bound").into());
                }
                Ok(Term::constant(0))
            }
            Hook::Copy | Hook::Move | Hook::Set => {
                let second = self.argument(binary, convention, 1)?;
                let count = self.number(binary, convention, 2)?;
                if count > 65536 {
                    return Err(invalid("memory operation exceeds model bound").into());
                }
                let mut bytes = Vec::new();
                if matches!(hook, Hook::Set) {
                    for _ in 0..count {
                        self.tick()?;
                        bytes.push(self.low(&second, 8)?);
                    }
                } else {
                    let source = self.resolve(second)?;
                    if matches!(hook, Hook::Copy)
                        && count != 0
                        && first < source.saturating_add(count)
                        && source < first.saturating_add(count)
                    {
                        return Err(invalid("overlapping memcpy").into());
                    }
                    for offset in 0..count as usize {
                        bytes.push(self.byte(binary, source, offset)?);
                    }
                }
                self.write_memory(binary, first, &bytes)?;
                Ok(Term::constant(first))
            }
            Hook::Integer | Hook::IntegerEnd => {
                let text = self.string(binary, first, self.model_bound())?;
                let base = if matches!(hook, Hook::IntegerEnd) {
                    self.number(binary, convention, 2)?
                } else {
                    10
                };
                if !matches!(base, 10 | 16) {
                    return Err(invalid("unsupported symbolic strtol base").into());
                }
                let parsed =
                    match self.parse_integer(&text, base, IntegerKind::Strtol, IntegerModel::Exact)
                    {
                        Ok(parsed) => parsed,
                        Err(error) => return Err(error),
                    };
                if matches!(hook, Hook::IntegerEnd) {
                    let end = self.number(binary, convention, 1)?;
                    if end != 0 {
                        let Some(address) = first.checked_add(if parsed.matched {
                            parsed.consumed as u64
                        } else {
                            0
                        }) else {
                            return Err(invalid("strtol end pointer overflows").into());
                        };
                        self.store(
                            binary.image(),
                            end,
                            &Term::constant(address),
                            crate::arch::pointer_bytes(self.isa),
                        )?;
                    }
                }
                Ok(if matches!(hook, Hook::Integer) {
                    self.low(&parsed.value, 32)?
                } else {
                    parsed.value
                })
            }
            _ => Err(invalid(format!("unsupported symbolic import: {name}")).into()),
        }
    }

    fn hex_digit(&self, byte: &Term) -> Evaluation<bool> {
        let lower = format!("(bvor {} {})", byte.text, smt::constant(32));
        self.test(format!("(or (and (bvuge {0} {1}) (bvule {0} {2})) (and (bvuge {lower} {3}) (bvule {lower} {4})))", byte.text, smt::constant(48), smt::constant(57), smt::constant(97), smt::constant(102)))
    }

    fn parse_integer(
        &mut self,
        input: &[Term],
        base: u64,
        kind: IntegerKind,
        model: IntegerModel,
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
        let bits = u32::from(crate::arch::pointer_bytes(self.isa)) * 8;
        let negative_limit = 1u64 << (bits - 1);
        let positive_limit = negative_limit - 1;
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
        if base == 16
            && position
                .checked_add(1)
                .is_some_and(|next| next < input.len())
        {
            let next = position + 1;
            let prefix_digit = if matches!(kind, IntegerKind::Scan) {
                true
            } else if let Some(byte) = position.checked_add(2).and_then(|at| input.get(at)) {
                match self.hex_digit(byte) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                }
            } else {
                false
            };
            if prefix_digit {
                let prefix = match self.test(format!(
                    "(and (= {} {}) (or (= {} {}) (= {} {})))",
                    input[position].text,
                    smt::constant(48),
                    input[next].text,
                    smt::constant(120),
                    input[next].text,
                    smt::constant(88)
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if prefix {
                    position += 2;
                }
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
            let hex = format!(
                "(and (bvuge {lower} {}) (bvule {lower} {}))",
                smt::constant(97),
                smt::constant(102)
            );
            let digit = if base == 16 {
                format!("(or {decimal} {hex})")
            } else {
                decimal.clone()
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
            } else if negative {
                negative_limit
            } else {
                positive_limit
            };
            overflow = format!(
                "(or {overflow} {})",
                integer_overflow(&value.text, &digit.text, base, limit)
            );
            value = match self.bind(format!(
                "(bvadd (bvmul {} {}) {})",
                value.text,
                smt::constant(base),
                digit.text
            )) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
        }
        let limit = if negative {
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

    pub(super) fn input_output(
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
                    self.scanned_integers.push(super::ScannedInteger {
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

impl State {
    pub(super) fn initialize_streams(&mut self, binary: &Binary) -> crate::error::Result<()> {
        let width = crate::arch::pointer_bytes(self.isa);
        let memory = self.mapped_memory(binary.image())?;
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
                .filter(|(_, symbol)| symbol.trim_start_matches('_') == name)
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
            self.store(binary.image(), object, &Term::constant(token), width)?;
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
                self.store(binary.image(), slot, &Term::constant(token), width)?;
            }
        }
        self.heap_next = next;
        Ok(())
    }
}

impl State {
    fn getline(&mut self, binary: &Binary, convention: Convention) -> Evaluation<Term> {
        let pointer = self.number(binary, convention, 0)?;
        let capacity_pointer = self.number(binary, convention, 1)?;
        if self.stdin_stream == 0 || self.number(binary, convention, 2)? != self.stdin_stream {
            return Err(invalid("unsupported getline stream").into());
        }
        let mut bytes = Vec::new();
        while let Some(byte) = io::next_input(&self.stdin, &mut self.input_position) {
            self.tick()?;
            let newline = self.test(format!("(= {} {})", byte.text, smt::constant(10)))?;
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
        let mut destination = self.resolve(self.eval(binary, &load(pointer))?)?;
        let capacity = self.resolve(self.eval(binary, &load(capacity_pointer))?)?;
        if destination == 0 || capacity < bytes.len() as u64 {
            destination = self.heap_next;
            let Some(end) = destination.checked_add(bytes.len() as u64) else {
                return Err(invalid("getline allocation overflows").into());
            };
            let memory = self.mapped_memory(binary.image())?;
            if end > memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE) {
                return Err(invalid("getline exceeds heap").into());
            }
            self.heap_next = end;
            self.store(binary.image(), pointer, &Term::constant(destination), width)?;
            self.store(
                binary.image(),
                capacity_pointer,
                &Term::constant(bytes.len() as u64),
                width,
            )?;
        }
        self.write_memory(binary, destination, &bytes)?;
        Ok(Term::constant(length as u64))
    }
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
