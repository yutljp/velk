//! Deterministic C library random state and clock effects.

use super::{Evaluation, State, Term};
use crate::ir::Convention;
use crate::ir::eval::emulation::hooks::Hook;
use crate::ir::smt;
use crate::service::Binary;

#[derive(Clone)]
pub(super) enum Random {
    Concrete(super::super::random::Random),
    Symbolic { words: Vec<Term>, position: usize },
}

impl Default for Random {
    fn default() -> Self {
        Self::Concrete(super::super::random::Random::default())
    }
}

impl State {
    pub(super) fn runtime_hook(
        &mut self,
        binary: &Binary,
        convention: Convention,
        hook: Hook,
    ) -> Evaluation<Term> {
        match hook {
            Hook::Random => self.random_next(),
            Hook::Seed => {
                let seed = match self.argument(binary, convention, 0) {
                    Ok(seed) => seed,
                    Err(error) => return Err(error),
                };
                if let Err(error) = self.require_defined(&seed, 32) {
                    return Err(error.into());
                }
                if let Some(seed) = seed.concrete {
                    self.random =
                        Random::Concrete(super::super::random::Random::seeded(seed as u32));
                    return Ok(Term::constant(0));
                }
                let seed = smt::low(&seed.text, 32);
                let concrete = match self
                    .solver
                    .borrow_mut()
                    .query(&self.constraints, Some(&seed))
                {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
                if let Some(value) = concrete {
                    let mut alternative = self.constraints.clone();
                    alternative.push(format!("(not (= {seed} {}))", smt::constant(value)));
                    let unique = match self.solver.borrow_mut().query(&alternative, None) {
                        Ok(result) => result.is_none(),
                        Err(error) => return Err(error.into()),
                    };
                    if unique {
                        self.random =
                            Random::Concrete(super::super::random::Random::seeded(value as u32));
                        return Ok(Term::constant(0));
                    }
                }
                let seed = match self.bind(format!(
                    "(ite (= {seed} {}) {} {seed})",
                    smt::constant(0),
                    smt::constant(1)
                )) {
                    Ok(seed) => seed,
                    Err(error) => return Err(error.into()),
                };
                let mut value = smt::signed(&seed.text, 32);
                let mut words = vec![seed];
                for _ in 1..31 {
                    let next = format!(
                        "(bvsub (bvmul {} (bvsrem {value} {})) (bvmul {} (bvsdiv {value} {})))",
                        smt::constant(16807),
                        smt::constant(127773),
                        smt::constant(2836),
                        smt::constant(127773)
                    );
                    let next = format!(
                        "(ite (bvslt {next} {}) (bvadd {next} {}) {next})",
                        smt::constant(0),
                        smt::constant(2147483647)
                    );
                    let word = match self.bind(next) {
                        Ok(word) => word,
                        Err(error) => return Err(error.into()),
                    };
                    value.clone_from(&word.text);
                    words.push(word);
                }
                self.random = Random::Symbolic { words, position: 0 };
                for _ in 0..310 {
                    if let Err(error) = self.random_next() {
                        return Err(error);
                    }
                }
                Ok(Term::constant(0))
            }
            Hook::Time => {
                let pointer = match self.number(binary, convention, 0) {
                    Ok(pointer) => pointer,
                    Err(error) => return Err(error),
                };
                let value = match &self.options.time {
                    Some(word) => match word.value() {
                        Ok(value) => value,
                        Err(error) => return Err(error.into()),
                    },
                    None => 0,
                };
                let width = crate::arch::pointer_bytes(self.isa);
                let value =
                    Term::constant(value & crate::ir::semantics::mask(u32::from(width) * 8));
                if pointer != 0
                    && let Err(error) = self.store(binary.image(), pointer, &value, width)
                {
                    return Err(error.into());
                }
                Ok(value)
            }
            _ => unreachable!("only random and time hooks are dispatched here"),
        }
    }

    fn random_next(&mut self) -> Evaluation<Term> {
        if let Err(error) = self.tick() {
            return Err(error);
        }
        let Random::Symbolic { words, position } = &self.random else {
            let Random::Concrete(random) = &mut self.random else {
                unreachable!("random state has two variants");
            };
            return Ok(Term::constant(u64::from(random.next())));
        };
        let front = (position + 3) % 31;
        let next_position = (position + 1) % 31;
        let sum = next_word(&words[front].text, &words[*position].text);
        let sum = match self.bind(sum) {
            Ok(sum) => sum,
            Err(error) => return Err(error.into()),
        };
        let result = match self.bind(format!("(bvlshr {} {})", sum.text, smt::constant(1))) {
            Ok(result) => result,
            Err(error) => return Err(error.into()),
        };
        let Random::Symbolic { words, position } = &mut self.random else {
            unreachable!("binding a term does not change random state");
        };
        words[front] = sum;
        *position = next_position;
        Ok(result)
    }
}

fn next_word(front: &str, rear: &str) -> String {
    smt::low(&format!("(bvadd {front} {rear})"), 32)
}

#[cfg(test)]
mod tests {
    #[test]
    fn symbolic_seeds_match_concrete_sequences() {
        use super::*;
        use crate::ir::Cond;
        use crate::symbolic::Options;

        if !smt::Proofs::available() {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/metrics/l0_arith.x86_64.O0.debug.elf");
        let binary = Binary::open(&path).expect("random fixture");
        let address = *binary
            .image()
            .functions
            .keys()
            .next()
            .expect("fixture function");
        let mut state = State::new(&binary, &crate::addr::format(address), &Options::default())
            .expect("random state");
        let seed = state.symbolic().expect("symbolic seed");
        state
            .registers
            .insert(Convention::SysV.arguments()[0], seed.clone());
        assert!(
            state
                .runtime_hook(&binary, Convention::SysV, Hook::Seed)
                .is_ok()
        );
        assert!(matches!(state.random, Random::Symbolic { .. }));
        for value in [0, 1, 42, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut fork = state.clone();
            fork.constrain(Cond::Eq, &seed, &Term::constant(u64::from(value)), 32)
                .expect("seed constraint");
            let mut concrete = super::super::super::random::Random::seeded(value);
            for _ in 0..4 {
                let Ok(actual) = fork.random_next() else {
                    panic!("symbolic random word");
                };
                let expected = u64::from(concrete.next());
                let mut wrong = fork.constraints.clone();
                wrong.push(format!(
                    "(not (= {} {}))",
                    actual.text,
                    smt::constant(expected)
                ));
                assert_eq!(
                    fork.solver
                        .borrow_mut()
                        .query(&wrong, None)
                        .expect("random equivalence"),
                    None,
                    "seed {value}"
                );
            }
        }
    }

    #[test]
    fn smt_additive_random_word() {
        use crate::ir::smt::Proofs;
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        let result = super::next_word("r0", "r1");
        let reference = "((_ zero_extend 32) (bvadd ((_ extract 31 0) r0) ((_ extract 31 0) r1)))";
        proofs.predicate("additive random word wraps at 32 bits", &result, reference);
        proofs.counterexample(
            "random state preserves bit 31",
            &result,
            &crate::ir::smt::low(reference, 31),
        );
        proofs.check();
    }
}
