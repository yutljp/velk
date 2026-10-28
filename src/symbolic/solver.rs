//! Persistent SMT-LIB transport; each query has an isolated assertion scope.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::error::{Error, Result};

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Symbolic(message.into())
}

pub(crate) struct Solver {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u64,
    failed: bool,
}

impl Solver {
    pub(crate) fn new() -> Result<Self> {
        if let Some(command) = std::env::var_os("VELK_SOLVER") {
            let Some(command) = command.to_str() else {
                return Err(invalid("VELK_SOLVER is not valid UTF-8"));
            };
            return Self::command(command);
        }
        for command in ["z3 -in", "bitwuzla --lang smt2 --incremental"] {
            if let Ok(solver) = Self::command(command) {
                return Ok(solver);
            }
        }
        Err(invalid(
            "no SMT solver available; install z3 or bitwuzla, or set VELK_SOLVER",
        ))
    }

    fn command(command: &str) -> Result<Self> {
        // A command line accepts quoted arguments, without invoking a shell.
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quote = None;
        let mut escaped = false;
        for c in command.chars() {
            if escaped {
                word.push(c);
                escaped = false;
            } else if c == '\\' && quote != Some('\'') {
                escaped = true;
            } else if quote == Some(c) {
                quote = None;
            } else if quote.is_none() && matches!(c, '\'' | '"') {
                quote = Some(c);
            } else if quote.is_none() && c.is_whitespace() {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            } else {
                word.push(c);
            }
        }
        if quote.is_some() || escaped {
            return Err(invalid("unclosed quote or escape in VELK_SOLVER"));
        }
        if !word.is_empty() {
            words.push(word);
        }
        let Some(program) = words.first() else {
            return Err(invalid("VELK_SOLVER is empty"));
        };
        let mut child = match Command::new(program)
            .args(&words[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => return Err(invalid(format!("cannot start solver {program}: {error}"))),
        };
        let input = child.stdin.take().expect("solver stdin is piped");
        let output = BufReader::new(child.stdout.take().expect("solver stdout is piped"));
        let mut solver = Self {
            child,
            input,
            output,
            next: 0,
            failed: false,
        };
        solver.send("(set-option :print-success false)\n(set-option :produce-models true)\n(set-logic QF_BV)")?;
        solver.query(&[], None)?;
        Ok(solver)
    }

    fn send(&mut self, command: &str) -> Result<()> {
        if let Err(error) = writeln!(self.input, "{command}").and_then(|()| self.input.flush()) {
            return Err(invalid(format!("writing to solver: {error}")));
        }
        Ok(())
    }

    fn response(&mut self) -> Result<String> {
        let mut response = String::new();
        let mut depth = 0i64;
        let mut quoted = false;
        loop {
            let mut line = String::new();
            match self.output.read_line(&mut line) {
                Ok(0) => return Err(invalid("solver closed stdout unexpectedly")),
                Ok(_) => {}
                Err(error) => return Err(invalid(format!("reading solver response: {error}"))),
            }
            if line.trim().is_empty() {
                continue;
            }
            for c in line.chars() {
                if c == '"' {
                    quoted = !quoted;
                    continue;
                }
                if quoted {
                    continue;
                }
                depth += match c {
                    '(' => 1,
                    ')' => -1,
                    _ => 0,
                };
            }
            response.push_str(&line);
            if depth <= 0 {
                break;
            }
        }
        let response = response.trim().to_owned();
        if response.starts_with("(error") {
            return Err(invalid(format!("solver error: {response}")));
        }
        Ok(response)
    }

    pub(crate) fn define(&mut self, expression: Option<&str>) -> Result<String> {
        let name = format!("s{}", self.next);
        let Some(next) = self.next.checked_add(1) else {
            return Err(invalid("solver term count overflow"));
        };
        self.next = next;
        match expression {
            Some(expression) => self.send(&format!(
                "(define-fun {name} () (_ BitVec 64) {expression})"
            )),
            None => self.send(&format!("(declare-const {name} (_ BitVec 64))")),
        }?;
        Ok(name)
    }

    pub(crate) fn query(
        &mut self,
        constraints: &[String],
        term: Option<&str>,
    ) -> Result<Option<u64>> {
        if self.failed {
            return Err(invalid(
                "solver session failed after an earlier protocol error",
            ));
        }
        self.send("(push 1)")?;
        let result = self.query_inner(constraints, term);
        let cleanup = self.send("(pop 1)");
        if result.is_err() || cleanup.is_err() {
            self.failed = true;
        }
        match (result, cleanup) {
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    fn query_inner(&mut self, constraints: &[String], term: Option<&str>) -> Result<Option<u64>> {
        for constraint in constraints {
            self.send(&format!("(assert {constraint})"))?;
        }
        self.send("(check-sat)")?;
        match self.response()?.as_str() {
            "unsat" => return Ok(None),
            "sat" => {}
            "unknown" => {
                self.send("(get-info :reason-unknown)")?;
                let reason = self.response()?;
                return Err(invalid(format!("solver returned unknown: {reason}")));
            }
            answer => {
                return Err(invalid(format!(
                    "solver did not decide satisfiability: {answer}"
                )));
            }
        }
        let Some(term) = term else {
            return Ok(Some(0));
        };
        self.send(&format!("(get-value ({term}))"))?;
        let response = self.response()?;
        let tokens: Vec<&str> = response
            .split(['(', ')', ' ', '\n', '\r', '\t'])
            .filter(|s| !s.is_empty())
            .collect();
        for (index, token) in tokens.iter().enumerate().rev() {
            let value = if let Some(hex) = token.strip_prefix("#x") {
                u64::from_str_radix(hex, 16).ok()
            } else if let Some(binary) = token.strip_prefix("#b") {
                u64::from_str_radix(binary, 2).ok()
            } else if index > 0 && tokens[index - 1] == "_" {
                token
                    .strip_prefix("bv")
                    .and_then(|value| value.parse::<u64>().ok())
            } else {
                None
            };
            if let Some(value) = value {
                return Ok(Some(value));
            }
        }
        Err(invalid(format!("invalid 64-bit solver value: {response}")))
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        let _ = writeln!(self.input, "(exit)");
        let _ = self.input.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_and_values() {
        if !Command::new("z3")
            .arg("-version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            eprintln!("SKIP solver protocol test: z3 is unavailable");
            return;
        }
        let mut solver = Solver::command("z3 -in").unwrap();
        let x = solver.define(None).unwrap();
        assert_eq!(
            solver
                .query(&[format!("(= {x} #xffffffffffffffff)")], Some(&x))
                .unwrap(),
            Some(u64::MAX)
        );
        assert_eq!(solver.query(&["false".to_owned()], None).unwrap(), None);
        assert_eq!(solver.query(&[], None).unwrap(), Some(0));
    }

    #[test]
    fn unknown_includes_the_solver_reason() {
        if !Command::new("z3")
            .arg("-version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }
        let mut solver = Solver::command("z3 -in").unwrap();
        let term = solver.define(None).unwrap();
        solver.send("(set-option :rlimit 1)").unwrap();
        let error = solver
            .query(
                &[format!("(= (bvmul {term} {term}) #x0000000000000007)")],
                None,
            )
            .unwrap_err();
        assert!(error.to_string().contains("reason-unknown"), "{error}");
    }

    #[test]
    fn command_errors() {
        assert!(Solver::command("velk-missing-smt-solver").is_err());
        assert!(Solver::command("'unclosed").is_err());
        assert!(Solver::command("").is_err());
        if !Command::new("z3")
            .arg("-version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            eprintln!("SKIP solver protocol test: z3 is unavailable");
            return;
        }
        let mut solver = Solver::command("z3 -in").unwrap();
        assert!(
            solver
                .query(&["(unknown-function)".to_owned()], None)
                .is_err()
        );
    }
}
