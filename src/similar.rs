//! Deterministic, evidence-based function similarity over cached analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Serialize;

use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::ir::{Expr, FunctionIr, Stmt};
use crate::loader::Function;
use crate::service::Binary;
use crate::xrefs::Kind;

const FEATURES: [(&str, f64); 6] = [
    ("cfg", 0.15),
    ("calls", 0.20),
    ("constants", 0.25),
    ("strings", 0.20),
    ("operations", 0.15),
    ("prototype", 0.05),
];
type Bag = BTreeMap<String, u64>;

/// A feature vector that can be searched in another binary's index.
#[derive(Clone)]
pub struct Features {
    bags: [Bag; 6],
}

/// The contribution of one feature to a candidate's score.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// Feature name, in scoring order.
    pub feature: &'static str,
    /// Fixed weight in the total score.
    pub weight: f64,
    /// Multiset intersection divided by union; zero for two empty sets.
    pub similarity: f64,
    /// Shared tokens, in lexical order, limited to sixteen entries.
    pub shared: Vec<String>,
}

/// One ranked candidate. A score is evidence overlap, not a probability.
#[derive(Debug, Serialize)]
pub struct Match {
    /// Candidate function in the searched binary.
    pub function: Function,
    /// Weighted feature overlap, between zero and one.
    pub score: f64,
    /// Contributions that reproduce the score.
    pub evidence: Vec<Evidence>,
}

/// Search results and functions omitted because their analysis failed.
#[derive(Serialize)]
pub struct Report {
    /// Descending score, then ascending candidate address.
    pub matches: Vec<Match>,
    /// Analysis failures in the searched binary.
    pub failures: Vec<crate::xrefs::Failure>,
}

/// An immutable index of the successfully analyzed functions of one binary.
pub struct Index {
    entries: BTreeMap<u64, (Function, Features)>,
    failures: Vec<crate::xrefs::Failure>,
}

impl Index {
    pub(crate) fn build(binary: &mut Binary, deadline: Option<Instant>) -> Result<Self> {
        let mut calls = BTreeMap::<u64, Bag>::new();
        let mut strings = BTreeMap::<u64, Bag>::new();
        let navigation = match binary.navigation(deadline) {
            Ok(index) => index,
            Err(error) => return Err(error),
        };
        let mut failures = navigation.failures.clone();
        for reference in &navigation.xrefs {
            if matches!(
                reference.kind,
                Kind::Call | Kind::TailCall | Kind::ResolvedCall
            ) && let Some(name) = &reference.name
            {
                // A set avoids counting multiple recovered references to one call.
                calls
                    .entry(reference.function)
                    .or_default()
                    .insert(crate::loader::demangle_name(name), 1);
            }
        }
        for literal in navigation.strings() {
            for reference in &literal.xrefs {
                strings
                    .entry(reference.function)
                    .or_default()
                    .insert(literal.text.clone(), 1);
            }
        }
        let mut entries = BTreeMap::new();
        for function in binary.functions() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            let analysis = match binary.analysis(function.addr, deadline) {
                Ok(analysis) => analysis,
                Err(Error::TimedOut) => return Err(Error::TimedOut),
                Err(error) => {
                    failures.push(crate::xrefs::Failure {
                        function: function.addr,
                        error: error.to_string(),
                    });
                    continue;
                }
            };
            let mut features = Features::from_ir(&analysis.ir);
            features.bags[1] = calls.remove(&function.addr).unwrap_or_default();
            features.bags[3] = strings.remove(&function.addr).unwrap_or_default();
            features.bags[2].retain(|value, _| {
                let Ok(address) = value.parse::<u64>() else {
                    return false;
                };
                binary.image().section_at(address).is_none()
            });
            entries.insert(function.addr, (function, features));
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        failures.sort_by(|a, b| (a.function, &a.error).cmp(&(b.function, &b.error)));
        failures.dedup_by(|a, b| a.function == b.function && a.error == b.error);
        Ok(Self { entries, failures })
    }

    /// Copies a query vector; an omitted or failed function returns no vector.
    #[must_use]
    pub fn features(&self, addr: u64) -> Option<Features> {
        self.entries
            .get(&addr)
            .map(|(_, features)| features.clone())
    }

    /// Ranks candidates, optionally excluding a function in this index.
    /// A zero limit returns no matches. No analysis runs during a search.
    pub fn search(
        &self,
        query: &Features,
        exclude: Option<u64>,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Report> {
        let mut ranked = Vec::new();
        if limit != 0 {
            for (address, (_, candidate)) in &self.entries {
                if let Err(error) = passed(deadline) {
                    return Err(error);
                }
                if exclude == Some(*address) {
                    continue;
                }
                let mut score = 0.0;
                for (at, (_, weight)) in FEATURES.iter().enumerate() {
                    score += weight * overlap(&query.bags[at], &candidate.bags[at]);
                }
                ranked.push((*address, score.clamp(0.0, 1.0)));
            }
        }
        ranked.sort_by(|(a, left), (b, right)| right.total_cmp(left).then(a.cmp(b)));
        ranked.truncate(limit);
        let mut matches = Vec::with_capacity(ranked.len());
        for (address, score) in ranked {
            let (function, candidate) = &self.entries[&address];
            let mut evidence = Vec::new();
            for (at, (feature, weight)) in FEATURES.iter().enumerate() {
                let mut shared = Vec::new();
                for token in query.bags[at].keys() {
                    if candidate.bags[at].contains_key(token) && shared.len() < 16 {
                        shared.push(token.clone());
                    }
                }
                evidence.push(Evidence {
                    feature,
                    weight: *weight,
                    similarity: overlap(&query.bags[at], &candidate.bags[at]),
                    shared,
                });
            }
            matches.push(Match {
                function: function.clone(),
                score,
                evidence,
            });
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        Ok(Report {
            matches,
            failures: self.failures.clone(),
        })
    }
}

fn increment(bag: &mut Bag, token: String) {
    let count = bag.entry(token).or_default();
    *count = count.saturating_add(1);
}

fn overlap(left: &Bag, right: &Bag) -> f64 {
    let mut common = 0.0;
    let mut union = 0.0;
    for (token, count) in left {
        let other = right.get(token).copied().unwrap_or(0);
        common += (*count).min(other) as f64;
        union += (*count).max(other) as f64;
    }
    for (token, count) in right {
        if !left.contains_key(token) {
            union += *count as f64;
        }
    }
    if union == 0.0 { 0.0 } else { common / union }
}

impl Features {
    fn from_ir(ir: &FunctionIr) -> Self {
        let mut bags: [Bag; 6] = Default::default();
        let successors: Vec<_> = (0..ir.blocks.len())
            .map(|at| crate::ir::cfg::successors(ir, at))
            .collect();
        let dominators = crate::ssa::dom::dominators(&successors);
        let mut incoming = vec![0usize; successors.len()];
        let mut headers = BTreeSet::new();
        for (at, next) in successors.iter().enumerate() {
            for target in next {
                incoming[*target] = incoming[*target].saturating_add(1);
                let mut current = Some(at);
                while let Some(block) = current {
                    if block == *target {
                        headers.insert(*target);
                        break;
                    }
                    current = dominators.idom[block];
                }
                increment(&mut bags[0], "edge".to_owned());
            }
        }
        if !headers.is_empty() {
            bags[0].insert("loop".to_owned(), headers.len() as u64);
        }
        for (at, block) in ir.blocks.iter().enumerate() {
            increment(&mut bags[0], "block".to_owned());
            increment(
                &mut bags[0],
                format!("degree:{},{}", incoming[at], successors[at].len()),
            );
            for statement in &block.stmts {
                let operation = match statement {
                    Stmt::Assign { .. } => "assign",
                    Stmt::Store { .. } => "store",
                    Stmt::Brif { .. } | Stmt::BrifFlags { .. } => "condition",
                    Stmt::Br { .. } | Stmt::BrIndirect { .. } => "branch",
                    Stmt::Switch { .. } => "switch",
                    Stmt::Call { .. } => "call",
                    Stmt::Ret { .. } => "return",
                    Stmt::Trap { .. } => "trap",
                    Stmt::Machine { .. } => "machine",
                    Stmt::Unsupported { .. } => "unsupported",
                };
                increment(&mut bags[4], operation.to_owned());
                for operand in statement.operands() {
                    expression(operand, &mut bags);
                }
            }
        }
        let signature = crate::service::function_signature(ir);
        let mut types = Vec::new();
        if let Some(parameters) = signature["params"].as_array() {
            for parameter in parameters {
                types.push(parameter["type"].as_str().unwrap_or("unknown"));
            }
        }
        bags[5].insert(
            format!(
                "{}({}){}",
                ir.ret_type,
                types.join(", "),
                if ir.variadic { " variadic" } else { "" }
            ),
            1,
        );
        Self { bags }
    }
}

fn expression(root: &Expr, bags: &mut [Bag; 6]) {
    let mut pending = vec![root];
    while let Some(expression) = pending.pop() {
        match expression {
            Expr::Const(value) => {
                bags[2].insert(value.to_string(), 1);
            }
            Expr::Bin { op, .. } => increment(&mut bags[4], format!("binary:{op:?}")),
            Expr::Apply { op, .. } => increment(&mut bags[4], format!("apply:{op:?}")),
            Expr::Load { .. } => increment(&mut bags[4], "load".to_owned()),
            Expr::SignExtend { .. } => increment(&mut bags[4], "signExtend".to_owned()),
            Expr::Select { .. } => increment(&mut bags[4], "select".to_owned()),
            Expr::Reg { .. } => {}
        }
        pending.extend(crate::ir::visit::children(expression));
    }
}

/// Searches another binary using the source function's indexed features.
/// Unlike a same-binary query, no candidate address is excluded.
pub fn search(
    source: &mut Binary,
    addr: u64,
    destination: &mut Binary,
    limit: usize,
    deadline: Option<Instant>,
) -> Result<Report> {
    let addr = source.image().code_address(addr);
    if let Err(error) = source.analysis(addr, deadline) {
        return Err(error);
    }
    let index = match source.similarity_index(deadline) {
        Ok(index) => index,
        Err(error) => return Err(error),
    };
    let Some(features) = index.features(addr) else {
        return Err(Error::NoFunctionAt(addr));
    };
    let index = match destination.similarity_index(deadline) {
        Ok(index) => index,
        Err(error) => return Err(error),
    };
    index.search(&features, None, limit, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Block;
    use crate::loader::Isa;

    #[test]
    fn overlap_is_bounded_symmetric_and_counts_multiplicity() {
        let left = Bag::from([("add".to_owned(), 3), ("load".to_owned(), 1)]);
        let right = Bag::from([("add".to_owned(), 1), ("store".to_owned(), 1)]);
        assert_eq!(overlap(&left, &right), 0.2);
        assert_eq!(overlap(&left, &right), overlap(&right, &left));
        assert_eq!(overlap(&left, &left), 1.0);
        assert_eq!(overlap(&Bag::new(), &Bag::new()), 0.0);
        assert_eq!(overlap(&left, &Bag::new()), 0.0);
        let large = Bag::from([("add".to_owned(), u64::MAX)]);
        assert_eq!(overlap(&large, &large), 1.0);
    }

    #[test]
    fn cfg_ignores_addresses_and_counts_loop_headers() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
        ir.blocks = vec![
            Block {
                start: 100,
                stmts: vec![Stmt::Br {
                    target: Some(200),
                    at: None,
                }],
            },
            Block {
                start: 200,
                stmts: vec![Stmt::Br {
                    target: Some(100),
                    at: None,
                }],
            },
        ];
        let original = Features::from_ir(&ir);
        assert_eq!(original.bags[0]["loop"], 1);
        ir.blocks = vec![
            Block {
                start: 300,
                stmts: vec![Stmt::Br {
                    target: Some(400),
                    at: None,
                }],
            },
            Block {
                start: 400,
                stmts: vec![Stmt::Br {
                    target: Some(300),
                    at: None,
                }],
            },
        ];
        assert_eq!(original.bags, Features::from_ir(&ir).bags);
    }

    #[test]
    fn thousands_of_candidates_are_ranked_without_analysis() {
        let mut binary = Binary::open_input(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/arm64.o"),
            None,
            &crate::loader::OpenOptions {
                cache: Some(crate::service::CacheLocation::Enabled(false)),
                ..Default::default()
            },
        )
        .unwrap();
        let mut index = Index::build(&mut binary, None).unwrap();
        let (function, features) = index.entries.values().next().unwrap().clone();
        index.entries.clear();
        for address in 0..5000 {
            let mut function = function.clone();
            function.addr = address;
            index.entries.insert(address, (function, features.clone()));
        }
        let start = Instant::now();
        let report = index.search(&features, None, 5, None).unwrap();
        let elapsed = start.elapsed();
        eprintln!("5000 candidates: {elapsed:?}");
        assert!(elapsed.as_secs_f64() < 0.5);
        for (at, candidate) in report.matches.iter().enumerate() {
            assert_eq!(candidate.function.addr, at as u64);
            assert!((0.0..=1.0).contains(&candidate.score));
            let sum: f64 = candidate
                .evidence
                .iter()
                .map(|item| item.similarity * item.weight)
                .sum();
            assert_eq!(candidate.score, sum);
        }
    }

    #[test]
    fn different_operations_and_constants_give_low_scores() {
        let mut add = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::Bin {
                    op: crate::ir::BinOp::Add,
                    lhs: Box::new(Expr::reg(1, 64)),
                    rhs: Box::new(Expr::Const(37)),
                },
                at: None,
            }],
        );
        let query = Features::from_ir(&add);
        add.blocks[0].stmts = vec![
            Stmt::Store {
                addr: Expr::reg(1, 64),
                value: Expr::Const(93),
                width: 8,
                at: None,
            },
            Stmt::Trap { at: None },
        ];
        let unrelated = Features::from_ir(&add);
        let mut score = 0.0;
        for (at, (_, weight)) in FEATURES.iter().enumerate() {
            score += weight * overlap(&query.bags[at], &unrelated.bags[at]);
        }
        assert!(
            score < 0.25,
            "unrelated straight-line operations scored {score}"
        );
    }
}
