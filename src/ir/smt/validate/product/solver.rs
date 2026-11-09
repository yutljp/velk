//! The z3 process the product's queries go to, and their replies.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use super::horn::solve_horn;
use crate::ir::smt::validate::Strategy;

#[derive(Clone)]
pub(crate) enum Reply {
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
    /// The query z3 last found satisfiable and still holds a model of.
    satisfied: Option<String>,
}

/// Where checking an application spent its solver work.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub blocks: usize,
    pub candidates: usize,
    /// Passes of the invariant inference over every edge.
    pub rounds: usize,
    /// Queries, undecided answers and seconds, by strategy: word-level,
    /// bounded, Horn, integer.
    pub queries: [usize; 4],
    pub undecided: [usize; 4],
    pub seconds: [f64; 4],
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
            satisfied: None,
        })
    }

    /// The lines z3 prints for `request`, read up to a marker echoed after
    /// it, so that whatever z3 prints, such as an error, is never read as
    /// the reply to a later request; none when z3 has stopped, which then
    /// starts again.
    fn request(&mut self, request: &str) -> Option<Vec<String>> {
        let lines = self.exchange(request);
        if lines.is_none()
            && let Some(again) = Self::start()
        {
            let mut old = std::mem::replace(self, again);
            self.stats = std::mem::take(&mut old.stats);
            self.replies = std::mem::take(&mut old.replies);
            self.horns = std::mem::take(&mut old.horns);
        }
        lines
    }

    fn exchange(&mut self, request: &str) -> Option<Vec<String>> {
        writeln!(self.stdin, "{request}\n(echo \"{END}\")").ok()?;
        self.stdin.flush().ok()?;
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if self.stdout.read_line(&mut line).ok()? == 0 {
                return None;
            }
            match line.trim() {
                END => return Some(lines),
                line => lines.push(line.to_owned()),
            }
        }
    }

    /// The one answer to a request, or what z3 printed instead.
    fn reply(&mut self, request: &str) -> Result<String, String> {
        let lines = self.request(request).ok_or("z3 stopped")?;
        if lines.iter().any(|line| line.starts_with("(error")) {
            return Err(lines.join(" "));
        }
        Ok(lines.join(" "))
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
            Strategy::Integer => 3,
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
        self.stats.queries[2] += 1;
        self.stats.seconds[2] += started.elapsed().as_secs_f64();
        if matches!(reply, Reply::Unknown(_)) {
            self.stats.undecided[2] += 1;
        }
        self.horns.insert(key, reply.clone());
        reply
    }

    pub(crate) fn answer(
        &mut self,
        query: &str,
        rlimit: u64,
        strategy: Strategy,
        names: &[&str],
    ) -> Reply {
        let original = query;
        let Some(query) = strategy.query(query) else {
            return Reply::Unknown(format!("no {strategy:?} form"));
        };
        self.satisfied = None;
        // z3's handler of Diophantine equations can run for hours on the
        // large constants of an integer query without counting the work
        // against the limit; it is left out of the integer strategy.
        let answer = match self.reply(&format!(
            "(reset)\n(set-option :rlimit {rlimit})\n(set-option :lp.dio {})\n{query}{}",
            strategy != Strategy::Integer,
            strategy.check()
        )) {
            Ok(answer) => answer,
            Err(printed) => return Reply::Unknown(printed),
        };
        match answer.as_str() {
            "unsat" => Reply::Unsat,
            "sat" if strategy == Strategy::Integer => {
                Reply::Unknown("a model over integers is not taken".to_owned())
            }
            "sat" => {
                self.satisfied = Some(original.to_owned());
                if names.is_empty() {
                    return Reply::Sat(Vec::new());
                }
                let text = match self.reply(&format!("(get-value ({}))", names.join(" "))) {
                    Ok(text) => text,
                    Err(printed) => return Reply::Unknown(printed),
                };
                let values: Vec<bool> = text
                    .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
                    .filter_map(|token| match token {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    })
                    .collect();
                if values.len() == names.len() {
                    Reply::Sat(values)
                } else {
                    Reply::Unknown(format!("no values: {text}"))
                }
            }
            answer => {
                let answer = answer.to_owned();
                let reason = self
                    .reply("(get-info :reason-unknown)")
                    .unwrap_or_else(|printed| printed);
                Reply::Unknown(format!("{answer} {reason}"))
            }
        }
    }

    /// The values of `symbols` in a model of `query`, which the solver
    /// found satisfiable. A reply recalled from an earlier ask leaves z3
    /// holding another query, which is then asked again.
    pub(crate) fn model(&mut self, query: &str, symbols: &[String]) -> String {
        if symbols.is_empty() {
            return String::new();
        }
        if self.satisfied.as_deref() != Some(query) {
            let asked = self
                .replies
                .iter()
                .find(|((asked, _, _), reply)| asked == query && matches!(reply, Reply::Sat(_)))
                .map(|((_, strategy, rlimit), _)| (*strategy, *rlimit));
            let Some((strategy, rlimit)) = asked else {
                return "no model".to_owned();
            };
            if !matches!(self.answer(query, rlimit, strategy, &[]), Reply::Sat(_)) {
                return "no model".to_owned();
            }
        }
        self.reply(&format!("(get-value ({}))", symbols.join(" ")))
            .unwrap_or_else(|printed| printed)
    }
}

/// What z3 is asked to print after each request, marking the end of its reply.
const END: &str = "velk-end";

impl Drop for Solver {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "(exit)");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}
