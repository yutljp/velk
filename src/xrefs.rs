//! A session's immutable navigation index. Locations refer to lifted blocks and
//! statement ordinals, not instruction addresses.

pub mod constants;
pub mod query;
mod strings;

#[cfg(test)]
use strings::extract;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

use serde::Serialize;

use crate::deadline::passed;
use crate::error::Result;
use crate::ir::{CallKind, Expr, Stmt};
use crate::loader::Image;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Xref {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub function: u64,
    #[serde(serialize_with = "crate::addr::serialize")]
    pub block: u64,
    pub statement: usize,
    #[serde(serialize_with = "crate::addr::serialize")]
    pub target: u64,
    pub kind: Kind,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Call,
    TailCall,
    ResolvedCall,
    CandidateCall,
    JumpTable,
    Read,
    Write,
    Address,
}

impl Kind {
    fn call(self) -> bool {
        matches!(self, Self::Call | Self::TailCall | Self::ResolvedCall)
    }
}

#[derive(Debug, Serialize)]
pub struct Failure {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub function: u64,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringLiteral {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub addr: u64,
    pub section: String,
    pub encoding: &'static str,
    pub text: String,
    pub bytes: usize,
    pub xrefs: Vec<Xref>,
}

#[derive(Debug, Default, Serialize)]
pub struct Index {
    pub xrefs: Vec<Xref>,
    pub failures: Vec<Failure>,
    #[serde(skip)]
    incoming: BTreeMap<u64, Vec<usize>>,
    #[serde(skip)]
    outgoing: BTreeMap<u64, Vec<usize>>,
    #[serde(skip)]
    strings: Vec<StringLiteral>,
}

impl Index {
    pub(crate) fn rename(&mut self, address: u64, name: &str) {
        let string_refs = self
            .strings
            .iter_mut()
            .flat_map(|literal| &mut literal.xrefs);
        for reference in self.xrefs.iter_mut().chain(string_refs) {
            if reference.target == address {
                reference.name = Some(name.to_owned());
            }
        }
    }

    fn function(
        image: &Image,
        function: &crate::loader::Function,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let mut index = Self::default();
        let blocks = match crate::analysis::navigation::blocks(image, function) {
            Ok(blocks) => blocks,
            Err(error) => {
                index.failures.push(Failure {
                    function: function.addr,
                    error: error.to_string(),
                });
                return Ok(index);
            }
        };
        let entries = crate::analysis::navigation::constants(&blocks, image);
        for (block, mut values) in std::iter::zip(&blocks, entries) {
            for (statement, stmt) in block.stmts.iter().enumerate() {
                let mut add = |target, kind| {
                    index.xrefs.push(Xref {
                        function: function.addr,
                        block: block.start,
                        statement,
                        target,
                        kind,
                        name: name(image, target),
                    })
                };
                if let Stmt::Call {
                    target,
                    kind,
                    through,
                    via,
                    ..
                } = stmt
                {
                    if let Some(target) = target {
                        add(
                            *target,
                            if *kind == CallKind::Tail {
                                Kind::TailCall
                            } else if via.is_some() {
                                Kind::ResolvedCall
                            } else {
                                Kind::Call
                            },
                        );
                        // Linkage stubs name the same import as their slot.
                        // Keep the stub edge as well as the import use.
                        if let Some(function) = image.functions.get(target)
                            && function.sources.contains(&crate::loader::NameSource::Plt)
                            && let Some(name) = &function.name
                        {
                            for (slot, imported) in &image.imports {
                                if imported == name {
                                    add(*slot, Kind::ResolvedCall);
                                }
                            }
                        }
                    } else if let Some(through) = through {
                        let resolved = crate::analysis::navigation::resolve(through, &values);
                        match &resolved {
                            Expr::Const(target) => add(
                                *target,
                                if *kind == CallKind::Tail {
                                    Kind::TailCall
                                } else {
                                    Kind::ResolvedCall
                                },
                            ),
                            Expr::Load { addr, .. } => {
                                if let Expr::Const(slot) = addr.as_ref()
                                    && image.imports.contains_key(slot)
                                {
                                    add(
                                        *slot,
                                        if *kind == CallKind::Tail {
                                            Kind::TailCall
                                        } else {
                                            Kind::ResolvedCall
                                        },
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    if let Some(via) = via {
                        if via.table == crate::ir::Table::Pointer {
                            add(via.slot, Kind::Read);
                        }
                        for target in &via.candidates {
                            add(*target, Kind::CandidateCall);
                        }
                    }
                }
                if let Stmt::Switch { cases, default, .. } = stmt {
                    for target in cases.iter().map(|(_, target)| target).chain(default) {
                        add(*target, Kind::JumpTable);
                    }
                }
                if let Stmt::Store { addr, value, .. } = stmt {
                    let addr = crate::analysis::navigation::resolve(addr, &values);
                    expression(&addr, Kind::Write, image, &mut add);
                    expression(
                        &crate::analysis::navigation::resolve(value, &values),
                        Kind::Address,
                        image,
                        &mut add,
                    );
                } else {
                    for operand in stmt.operands() {
                        expression(
                            &crate::analysis::navigation::resolve(operand, &values),
                            Kind::Address,
                            image,
                            &mut add,
                        );
                    }
                }
                crate::analysis::navigation::advance(stmt, &mut values);
            }
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        Ok(index)
    }

    pub(crate) fn build(image: &Image, deadline: Option<Instant>) -> Result<Self> {
        if crate::parallel::threads() > 1
            && let Err(error) = crate::analysis::summary::prepare(image, deadline)
        {
            return Err(error);
        }
        let mut index = Self::default();
        let functions: Vec<_> = image.functions.values().collect();
        let results = crate::parallel::map(&functions, |function| {
            Self::function(image, function, deadline)
        });
        for result in results {
            match result {
                Ok(mut function) => {
                    index.xrefs.append(&mut function.xrefs);
                    index.failures.append(&mut function.failures);
                }
                Err(error) => return Err(error),
            }
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        index.xrefs.sort();
        index.xrefs.dedup();
        for (at, xref) in index.xrefs.iter().enumerate() {
            index.incoming.entry(xref.target).or_default().push(at);
            index.outgoing.entry(xref.function).or_default().push(at);
        }
        index.strings = strings::strings(image);
        for literal in &mut index.strings {
            let end = literal.addr.saturating_add(literal.bytes as u64);
            literal.xrefs = index
                .incoming
                .range(literal.addr..end)
                .flat_map(|(_, refs)| refs)
                .map(|at| index.xrefs[*at].clone())
                .collect();
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        Ok(index)
    }

    #[must_use]
    pub fn to(&self, target: u64) -> Vec<&Xref> {
        self.incoming
            .get(&target)
            .into_iter()
            .flatten()
            .map(|at| &self.xrefs[*at])
            .collect()
    }

    #[must_use]
    pub fn from(&self, function: u64) -> Vec<&Xref> {
        self.outgoing
            .get(&function)
            .into_iter()
            .flatten()
            .map(|at| &self.xrefs[*at])
            .collect()
    }

    #[must_use]
    pub fn strings(&self) -> &[StringLiteral] {
        &self.strings
    }

    fn neighbors(&self, function: u64, callers: bool) -> BTreeSet<u64> {
        let refs = if callers {
            self.to(function)
        } else {
            self.from(function)
        };
        refs.into_iter()
            .filter(|xref| xref.kind.call())
            .map(|xref| if callers { xref.function } else { xref.target })
            .collect()
    }

    /// Breadth-first traversal; depth zero returns no neighbors.
    #[must_use]
    pub fn graph(&self, function: u64, callers: bool, depth: usize) -> Vec<u64> {
        let mut seen = BTreeSet::from([function]);
        let mut emitted = BTreeSet::new();
        let mut pending = VecDeque::from([(function, 0usize)]);
        let mut result = Vec::new();
        while let Some((node, distance)) = pending.pop_front() {
            if distance >= depth {
                continue;
            }
            for next in self.neighbors(node, callers) {
                if emitted.insert(next) {
                    result.push(next);
                }
                if seen.insert(next) {
                    pending.push_back((next, distance + 1));
                }
            }
        }
        result
    }

    /// A shortest call path, including both endpoints; empty when unreachable.
    #[must_use]
    pub fn path(&self, from: u64, to: u64, depth: usize) -> Vec<u64> {
        let mut previous = BTreeMap::from([(from, from)]);
        let mut pending = VecDeque::from([(from, 0usize)]);
        while let Some((node, distance)) = pending.pop_front() {
            if node == to {
                let mut result = vec![node];
                let mut at = node;
                while at != from {
                    at = previous[&at];
                    result.push(at);
                }
                result.reverse();
                return result;
            }
            if distance >= depth {
                continue;
            }
            for next in self.neighbors(node, false) {
                if let std::collections::btree_map::Entry::Vacant(entry) = previous.entry(next) {
                    entry.insert(node);
                    pending.push_back((next, distance + 1));
                }
            }
        }
        Vec::new()
    }
}

fn name(image: &Image, target: u64) -> Option<String> {
    image
        .imports
        .get(&target)
        .cloned()
        .or_else(|| image.functions.get(&target).and_then(|f| f.name.clone()))
        .or_else(|| image.data_symbols.get(&target).cloned())
}

fn expression(expr: &Expr, kind: Kind, image: &Image, add: &mut impl FnMut(u64, Kind)) {
    match expr {
        Expr::Const(addr)
            if image.section_at(*addr).is_some() || image.imports.contains_key(addr) =>
        {
            add(*addr, kind)
        }
        Expr::Load { addr, .. } => expression(addr, Kind::Read, image, add),
        _ => {
            for child in crate::ir::visit::children(expr) {
                expression(child, Kind::Address, image, add);
            }
        }
    }
}
