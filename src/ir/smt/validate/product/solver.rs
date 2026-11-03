//! The z3 process the product's queries go to, and their replies.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use super::horn::solve_horn;
use crate::ir::smt::validate::Strategy;

#[derive(Clone)]
pub(super) enum Reply {
    Unsat,
    /// Satisfiable, with the requested Booleans' values in the model.
    Sat(Vec<bool>),
    Unknown(String),
}

/// A z3 process answering one query at a time.
pub(crate) struct Solver {
    pub(super) child: std::process::Child,
    pub(super) stdin: std::process::ChildStdin,
    pub(super) stdout: BufReader<std::process::ChildStdout>,
    pub(super) stats: Stats,
    /// The replies to queries asked already, by query, strategy and limit.
    pub(super) replies: HashMap<(String, Strategy, u64), Reply>,
    /// The replies to Horn clauses solved already, by clauses and limit.
    pub(super) horns: HashMap<(String, u64), Reply>,
}

/// Where checking an application spent its solver work.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub blocks: usize,
    pub candidates: usize,
    /// Passes of the invariant inference over every edge.
    pub rounds: usize,
    /// Queries, undecided answers and seconds, by strategy: word-level,
    /// bounded, bit-level, Horn, integer.
    pub queries: [usize; 5],
    pub undecided: [usize; 5],
    pub seconds: [f64; 5],
}

impl Solver {
    pub(crate) fn start() -> Option<Self> {
        let mut child = Command::new("z3")
            .args(["-in", "-smt2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .ok()?;
        let stdin = child.stdin.take()?;
        let stdout = BufReader::new(child.stdout.take()?);
        Some(Self {
            child,
            stdin,
            stdout,
            stats: Stats::default(),
            replies: HashMap::new(),
            horns: HashMap::new(),
        })
    }

    pub(super) fn line(&mut self) -> String {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read z3 answer");
        line.trim().to_owned()
    }

    /// The parenthesized answer to a request, possibly over several lines.
    pub(super) fn list(&mut self, request: &str) -> String {
        writeln!(self.stdin, "{request}").expect("write SMT request");
        self.stdin.flush().expect("flush SMT request");
        let mut text = String::new();
        let mut depth = 0i32;
        loop {
            let line = self.line();
            depth += line.matches('(').count() as i32 - line.matches(')').count() as i32;
            text.push_str(&line);
            text.push(' ');
            if depth <= 0 {
                break;
            }
        }
        text.trim().to_owned()
    }

    /// The reply to `query`, with the Booleans `names` in a model. A query
    /// asked again, its names being part of it, gets the reply it got.
    pub(super) fn values(
        &mut self,
        query: &str,
        rlimit: u64,
        strategy: Strategy,
        names: &[&str],
    ) -> Reply {
        let key = (format!("{query}{}", names.join(" ")), strategy, rlimit);
        if let Some(reply) = self.replies.get(&key) {
            return reply.clone();
        }
        let started = std::time::Instant::now();
        let reply = self.answer(query, rlimit, strategy, names);
        let kind = match strategy {
            Strategy::WordLevel => 0,
            Strategy::Bounded => 1,
            Strategy::BitLevel => 2,
            Strategy::Integer => 4,
        };
        self.stats.queries[kind] += 1;
        self.stats.seconds[kind] += started.elapsed().as_secs_f64();
        if matches!(reply, Reply::Unknown(_)) {
            self.stats.undecided[kind] += 1;
        }
        self.replies.insert(key, reply.clone());
        reply
    }

    /// Whether the Horn clauses `text` are satisfiable. Clauses solved
    /// already, such as when equations checked again keep the same ones,
    /// get the reply they got.
    pub(super) fn horn(&mut self, text: &str, rlimit: u64) -> Reply {
        let key = (text.to_owned(), rlimit);
        if let Some(reply) = self.horns.get(&key) {
            return reply.clone();
        }
        let started = std::time::Instant::now();
        let reply = solve_horn(text, rlimit);
        self.stats.queries[3] += 1;
        self.stats.seconds[3] += started.elapsed().as_secs_f64();
        if matches!(reply, Reply::Unknown(_)) {
            self.stats.undecided[3] += 1;
        }
        self.horns.insert(key, reply.clone());
        reply
    }

    pub(super) fn answer(
        &mut self,
        query: &str,
        rlimit: u64,
        strategy: Strategy,
        names: &[&str],
    ) -> Reply {
        let Some(query) = strategy.query(query) else {
            return Reply::Unknown(format!("no {strategy:?} form"));
        };
        writeln!(
            self.stdin,
            "(reset)\n(set-option :rlimit {rlimit})\n{query}{}",
            strategy.check()
        )
        .expect("write SMT query");
        self.stdin.flush().expect("flush SMT query");
        let answer = self.line();
        match answer.as_str() {
            "unsat" => Reply::Unsat,
            "sat" if strategy == Strategy::Integer => {
                Reply::Unknown("a model over integers is not taken".to_owned())
            }
            "sat" if names.is_empty() => Reply::Sat(Vec::new()),
            "sat" => {
                let text = self.list(&format!("(get-value ({}))", names.join(" ")));
                let values: Vec<bool> = text
                    .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
                    .filter_map(|token| match token {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    })
                    .collect();
                assert_eq!(values.len(), names.len(), "z3 values: {text}");
                Reply::Sat(values)
            }
            answer => {
                let answer = answer.to_owned();
                let reason = self.list("(get-info :reason-unknown)");
                Reply::Unknown(format!("{answer} {reason}"))
            }
        }
    }

    pub(super) fn model(&mut self, symbols: &[String]) -> String {
        if symbols.is_empty() {
            return String::new();
        }
        self.list(&format!("(get-value ({}))", symbols.join(" ")))
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "(exit)");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}
