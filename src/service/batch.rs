//! Independent function analysis and rendering in request order.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::Binary;
use crate::analysis::{self, Analysis};
use crate::deadline::passed;
use crate::error::{Error, LiftError, Result};
use crate::loader::Image;
use crate::sigs::Database;

type Analyses = HashMap<u64, Arc<Result<Analysis, LiftError>>>;

pub(super) fn neighbors(image: &Image, analysis: &Analysis) -> Vec<u64> {
    let addr = analysis.ir.addr;
    let ir = &analysis.ir;
    let pointer = |register| {
        ir.pointer_values.contains(&register)
            || ir
                .value_types
                .get(&register)
                .is_some_and(crate::ir::CType::is_pointer)
            || ir
                .params
                .iter()
                .any(|param| param.index == register && param.ty.is_pointer())
    };
    let mut neighbors = std::collections::BTreeSet::new();
    let statements = ir.blocks.iter().flat_map(|block| &block.stmts);
    for stmt in statements {
        if let crate::ir::Stmt::Call {
            target: Some(target),
            through: None,
            args: Some(args),
            outputs,
            ..
        } = stmt
            && (args.iter().any(|arg| {
                let mut reads = std::collections::HashSet::new();
                crate::ir::visit::collect_reads(arg, &mut reads);
                reads.into_iter().any(pointer)
            }) || outputs.iter().any(|output| pointer(output.dest.index)))
            && image.functions.contains_key(target)
        {
            neighbors.insert(*target);
        }
    }
    if ir.params.iter().any(|param| param.ty.is_pointer()) {
        neighbors.extend(analysis::results::callers(image, addr));
    }
    neighbors.remove(&addr);
    neighbors.into_iter().take(8).collect()
}

fn original(
    image: &Image,
    analyses: &Mutex<Analyses>,
    addr: u64,
    deadline: Option<Instant>,
) -> Result<Arc<Result<Analysis, LiftError>>> {
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    if let Some(analysis) = analyses.lock().expect("analysis cache lock").get(&addr) {
        return Ok(Arc::clone(analysis));
    }
    let Some(function) = image.functions.get(&addr) else {
        return Err(Error::NoFunctionAt(addr));
    };
    let analyzed = match analysis::analyze(image, function, deadline) {
        Ok(analysis) => Ok(analysis),
        Err(Error::Lift { source, .. }) => Err(source),
        Err(error) => return Err(error),
    };
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    let mut analyses = analyses.lock().expect("analysis cache lock");
    Ok(Arc::clone(
        analyses.entry(addr).or_insert_with(|| Arc::new(analyzed)),
    ))
}

impl Binary {
    /// Renders functions concurrently, returning one result per requested address in order.
    /// `deadline` limits the entire batch.
    /// Signature identification with annotations retains sequential inference.
    ///
    /// # Panics
    ///
    /// Panics if an analysis cache lock is poisoned by another worker.
    pub fn decompile_many(
        &mut self,
        addresses: &[u64],
        signatures: Option<&Database>,
        deadline: Option<Instant>,
    ) -> Result<Vec<Result<String>>> {
        if let Err(error) = self.refresh_project() {
            return Err(error);
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        // Identification can change types used by the next request's annotations.
        if addresses.len() == 1 || (signatures.is_some() && self.project.is_some()) {
            let mut output = Vec::with_capacity(addresses.len());
            for &addr in addresses {
                output.push(self.decompile(addr, signatures, deadline));
            }
            return Ok(output);
        }
        let overrides = match self.project_signatures(deadline) {
            Ok(overrides) => overrides,
            Err(error) => return Err(error),
        };
        let identified: HashMap<_, _> = match signatures {
            Some(database) => match self.identify(database, deadline) {
                Ok(result) => result
                    .matches
                    .into_iter()
                    .map(|matched| (matched.addr, matched.matched))
                    .collect(),
                Err(error) => return Err(error),
            },
            None => HashMap::new(),
        };
        if crate::parallel::threads() > 1
            && let Err(error) = analysis::summary::prepare(&self.image, deadline)
        {
            return Err(error);
        }
        let originals: Analyses = std::mem::take(&mut self.analyses)
            .into_iter()
            .map(|(addr, analysis)| (addr, Arc::new(analysis)))
            .collect();
        let originals = Mutex::new(originals);
        let results = crate::parallel::map(addresses, |&addr| {
            let addr = self.image.code_address(addr);
            let decoded_strings = if self.string_decoding {
                match self.decoded_strings.get(&addr) {
                    Some(strings) => strings.clone(),
                    None => crate::string_decoding::recover(&self.image, addr, deadline)
                        .unwrap_or_default(),
                }
            } else {
                Vec::new()
            };
            if let Some(analysis) = self.shared_analyses.get(&addr) {
                return match analysis {
                    Ok(analysis) => self
                        .render_analysis(
                            analysis,
                            &overrides,
                            identified.get(&addr).map(String::as_str),
                            &decoded_strings,
                            deadline,
                        )
                        .map(|rendered| (rendered.code, None)),
                    Err(source) => Err(Error::Lift {
                        addr,
                        source: source.clone(),
                    }),
                };
            }
            let root = match original(&self.image, &originals, addr, deadline) {
                Ok(root) => root,
                Err(error) => return Err(error),
            };
            let root = match root.as_ref() {
                Ok(root) => root,
                Err(source) => {
                    return Err(Error::Lift {
                        addr,
                        source: source.clone(),
                    });
                }
            };
            let mut functions = vec![root.clone()];
            for neighbor in neighbors(&self.image, root) {
                match original(&self.image, &originals, neighbor, deadline) {
                    Ok(analysis) => {
                        if let Ok(analysis) = analysis.as_ref() {
                            functions.push(analysis.clone());
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            // Each root shares layouts with the same bounded neighborhood as a single request.
            // Merged layouts never become inputs to another function's neighborhood.
            functions.sort_by_key(|analysis| analysis.ir.addr);
            let mut irs: Vec<_> = functions
                .iter_mut()
                .map(|analysis| &mut analysis.ir)
                .collect();
            analysis::shared_structures::share(&mut irs, &self.data_ranges);
            let analysis = functions
                .into_iter()
                .find(|analysis| analysis.ir.addr == addr)
                .expect("root belongs to its neighborhood");
            match self.render_analysis(
                &analysis,
                &overrides,
                identified.get(&addr).map(String::as_str),
                &decoded_strings,
                deadline,
            ) {
                Ok(rendered) => Ok((rendered.code, Some(analysis))),
                Err(error) => Err(error),
            }
        });
        let originals = originals.into_inner().expect("analysis cache lock");
        for (addr, analysis) in originals {
            let analysis = match Arc::try_unwrap(analysis) {
                Ok(analysis) => analysis,
                Err(analysis) => analysis.as_ref().clone(),
            };
            self.analyses.entry(addr).or_insert(analysis);
        }
        let mut output = Vec::with_capacity(results.len());
        for (&addr, result) in std::iter::zip(addresses, results) {
            match result {
                Ok((code, analysis)) => {
                    if let Some(analysis) = analysis {
                        self.shared_analyses
                            .insert(self.image.code_address(addr), Ok(analysis));
                    }
                    output.push(Ok(code));
                }
                Err(error) => output.push(Err(error)),
            }
        }
        Ok(output)
    }
}
