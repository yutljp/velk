//! Symbolic Linux syscall dispatch.

use super::{Evaluation, State, Term};
use crate::ir::Convention;
use crate::ir::eval::emulation::io::Operation;
use crate::service::Binary;
use crate::symbolic::invalid;

impl State {
    pub(super) fn syscall(
        &mut self,
        binary: &Binary,
        convention: Convention,
        outputs: &[crate::ir::CallOutput],
    ) -> Evaluation<bool> {
        if binary.image().format != crate::loader::Format::Elf {
            return Err(invalid("Linux syscalls require ELF").into());
        }
        let term = match self.read_register(convention.arguments()[0]) {
            Ok(term) => term,
            Err(error) => return Err(error.into()),
        };
        let number = match self.resolve(term) {
            Ok(number) => number,
            Err(error) => return Err(error),
        };
        let result = match super::super::syscalls::operation(convention, number) {
            Some(super::super::syscalls::Operation::Exit) => return Ok(true),
            Some(super::super::syscalls::Operation::Read) => {
                match self.input_output(binary, convention, Operation::Read) {
                    Ok(result) => result,
                    Err(error) => return Err(error),
                }
            }
            Some(super::super::syscalls::Operation::Write) => {
                let descriptor = match self.number(binary, convention, 0) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let descriptor = descriptor as u32;
                if !Self::output_descriptor(descriptor) {
                    return Err(invalid("unsupported write descriptor").into());
                }
                let address = match self.number(binary, convention, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let count = match self.number(binary, convention, 2) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if count > self.model_bound() as u64 {
                    return Err(invalid("syscall write exceeds model limit").into());
                }
                let mut bytes = Vec::new();
                for offset in 0..count as usize {
                    match self.byte(binary, address, offset) {
                        Ok(byte) => bytes.push(byte),
                        Err(error) => return Err(error),
                    }
                }
                self.write_output(descriptor, bytes);
                Term::constant(count)
            }
            None => return Err(invalid(format!("unsupported Linux syscall {number}")).into()),
        };
        for &register in convention.clobbered() {
            self.registers.remove(&register);
        }
        self.registers.insert(0, result.clone());
        for output in outputs {
            if output.register == 0 {
                let value = match self.low(&result, u32::from(output.dest.width)) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
                self.registers.insert(output.dest.index, value);
            }
        }
        Ok(false)
    }
}
