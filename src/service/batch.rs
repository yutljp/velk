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

/// The analyses a request holds while it renders, and for a large request
/// how many of its functions still want each of them.
struct Held {
    analyses: Analyses,
    /// For each requested function, how many requested functions not yet
    /// rendered may ask for its analysis. None when every analysis is kept
    /// until the request ends.
    wanted: Option<Wanted>,
}

struct Wanted {
    counts: HashMap<u64, usize>,
    /// The requested functions each requested function may ask for: its
    /// callees and the callers `neighbors` can reach.
    asked: HashMap<u64, Vec<u64>>,
}

impl Wanted {
    /// What the `requested` functions ask of each other, `callers` giving
    /// the functions that call one.
    fn new(requested: impl Iterator<Item = u64>, callers: impl Fn(u64) -> Vec<u64>) -> Self {
        let mut asked: HashMap<u64, Vec<u64>> = requested.map(|addr| (addr, Vec::new())).collect();
        let requested: Vec<u64> = asked.keys().copied().collect();
        for &callee in &requested {
            let callers = callers(callee);
            // `neighbors` takes the lowest addresses among callers and
            // callees, so no caller after that many.
            let near = callers.iter().take(NEIGHBORS).copied();
            asked.get_mut(&callee).expect("requested").extend(near);
            for caller in callers {
                if let Some(asked) = asked.get_mut(&caller) {
                    asked.push(callee);
                }
            }
        }
        let mut counts: HashMap<u64, usize> = requested.iter().map(|&addr| (addr, 1)).collect();
        for (addr, others) in &mut asked {
            others.sort_unstable();
            others.dedup();
            others.retain(|other| other != addr && counts.contains_key(other));
            for other in others.iter() {
                *counts.get_mut(other).expect("requested") += 1;
            }
        }
        Self { counts, asked }
    }
}

impl Held {
    /// Drops the analyses no function left to render is expected to ask
    /// for, now that `addr` is rendered. One asked for all the same is made
    /// again.
    fn rendered(&mut self, addr: u64) {
        let Some(wanted) = &mut self.wanted else {
            return;
        };
        let Some(asked) = wanted.asked.remove(&addr) else {
            return;
        };
        for other in std::iter::once(addr).chain(asked) {
            if let Some(count) = wanted.counts.get_mut(&other) {
                *count -= 1;
                if *count == 0 {
                    self.analyses.remove(&other);
                }
            }
        }
    }

    fn keeps(&self, addr: u64) -> bool {
        self.wanted
            .as_ref()
            .and_then(|wanted| wanted.counts.get(&addr))
            .is_none_or(|count| *count != 0)
    }
}

/// The most functions of one request whose analyses are kept for later
/// requests. Those of a larger request, such as every function of a
/// binary, would stay in memory for as long as the binary is open.
const KEPT_ANALYSES: usize = 256;

/// How many functions are rendered between drops of the lifts made for
/// them, which nothing reads again once a function is analysed.
const LIFTS_DROPPED_EVERY: usize = 512;

/// The most functions around one that share with it.
const NEIGHBORS: usize = 8;

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
    let mut required = std::collections::BTreeSet::new();
    let statements = ir.blocks.iter().flat_map(|block| &block.stmts);
    for stmt in statements {
        let crate::ir::Stmt::Call {
            target: Some(target),
            through: None,
            args: Some(args),
            outputs,
            ..
        } = stmt
        else {
            continue;
        };
        let Some(function) = image.functions.get(target) else {
            continue;
        };
        let mut pointer_arguments = false;
        let mut stack_arguments = false;
        for arg in args {
            let mut reads = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(arg, &mut reads);
            stack_arguments |= !image.go && reads.contains(&crate::arch::stack_pointer(ir.isa));
            pointer_arguments |= reads.into_iter().any(pointer);
        }
        let pointer_dependency = pointer_arguments
            || outputs.iter().any(|output| pointer(output.dest.index))
            || (!image.go && analysis::summary::summary(image, *target).pointers != 0);
        if pointer_dependency
            || stack_arguments
            || (!image.go && !function.sources.contains(&crate::loader::NameSource::Plt))
        {
            neighbors.insert(*target);
            if pointer_dependency
                || (!image.go && !ir.structures.is_empty())
                || (!image.go && analysis::summary::needs_parameter_analysis(image, *target))
            {
                required.insert(*target);
            }
        }
    }
    if ir.params.iter().any(|param| param.ty.is_pointer()) {
        let callers = analysis::results::callers(image, addr);
        neighbors.extend(&callers);
        required.extend(callers);
    }
    neighbors.remove(&addr);
    // Prune after the limit so skipped callees do not change the sharing neighborhood.
    neighbors
        .into_iter()
        .take(NEIGHBORS)
        .filter(|addr| required.contains(addr))
        .collect()
}

pub(super) fn share_parameters(functions: &mut [Analysis], go: bool) {
    if go {
        return;
    }
    let mut parameters = HashMap::new();
    for analysis in functions.iter() {
        let ir = &analysis.ir;
        if ir.variadic
            || matches!(
                ir.convention,
                crate::ir::Convention::GoAmd64
                    | crate::ir::Convention::GoArm64
                    | crate::ir::Convention::GoAbi0
                    | crate::ir::Convention::GoAbi0Arm64
            )
            || ir.params.iter().any(|param| {
                !param.ty.is_pointer() && param.ty.integer().is_none() && !param.ty.is_sse_float()
            })
        {
            continue;
        }
        if ir.declared_signature.as_ref().is_some_and(|signature| {
            signature.params.len() != ir.params.len()
                || signature
                    .params
                    .iter()
                    .zip(&ir.params)
                    .any(|((_, ty), param)| *ty != param.ty)
        }) {
            continue;
        }
        let mut types = Vec::new();
        let mut registers = ir.params.iter();
        for position in 0..ir.params.len().saturating_add(ir.stack_params.len()) {
            if let Some(param) = ir
                .stack_params
                .iter()
                .find(|param| param.position == position)
            {
                types.push(param.ty.clone());
            } else if let Some(param) = registers.next() {
                types.push(param.ty.clone());
            }
        }
        if !types.iter().any(crate::render::promoted_parameter) {
            continue;
        }
        parameters.insert(ir.addr, (ir.convention, types));
    }
    for analysis in functions {
        for stmt in analysis.ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let crate::ir::Stmt::Call {
                target: Some(target),
                through: None,
                args: Some(args),
                convention,
                ..
            } = stmt
                && let Some((callee_convention, types)) = parameters.get(target)
                && convention == callee_convention
                && args.len() == types.len()
            {
                analysis.callee_parameters.insert(*target, types.clone());
            }
        }
    }
}

/// The analysis of `root` after it shared structure layouts, parameter
/// types and declarations with the functions around it. `other` gives the
/// analysis of one of those, or None for one to leave out.
pub(super) fn shared(
    image: &Image,
    data_ranges: &[(u64, u64)],
    root: Analysis,
    mut other: impl FnMut(u64) -> Result<Option<Analysis>>,
) -> Result<Analysis> {
    let addr = root.ir.addr;
    let neighbors = neighbors(image, &root);
    let dependencies = super::declarations::dependencies(image, &root);
    let mut functions = vec![root];
    for neighbor in neighbors {
        match other(neighbor) {
            Ok(Some(analysis)) => functions.push(analysis),
            Ok(None) => {}
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
    analysis::shared_structures::share(&mut irs, data_ranges);
    for address in dependencies {
        if functions.iter().any(|analysis| analysis.ir.addr == address) {
            continue;
        }
        match other(address) {
            Ok(Some(analysis)) => functions.push(analysis),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    share_parameters(&mut functions, image.go);
    crate::analysis::declarations::recover(image, &mut functions);
    Ok(functions
        .into_iter()
        .find(|analysis| analysis.ir.addr == addr)
        .expect("root belongs to its neighborhood"))
}

fn original(
    image: &Image,
    held: &Mutex<Held>,
    addr: u64,
    deadline: Option<Instant>,
) -> Result<Arc<Result<Analysis, LiftError>>> {
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    if let Some(analysis) = held
        .lock()
        .expect("analysis cache lock")
        .analyses
        .get(&addr)
    {
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
    let mut held = held.lock().expect("analysis cache lock");
    if !held.keeps(addr) {
        return Ok(Arc::new(analyzed));
    }
    Ok(Arc::clone(
        held.analyses
            .entry(addr)
            .or_insert_with(|| Arc::new(analyzed)),
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
            && let Err(error) = analysis::summary::prepare(
                &self.image,
                deadline,
                analysis::summary::Bodies::Dropped,
            )
        {
            return Err(error);
        }
        let originals: Analyses = std::mem::take(&mut self.analyses)
            .into_iter()
            .map(|(addr, analysis)| (addr, Arc::new(analysis)))
            .collect();
        let originals = Mutex::new(Held {
            analyses: originals,
            wanted: (addresses.len() > KEPT_ANALYSES).then(|| {
                Wanted::new(
                    addresses.iter().map(|&addr| self.image.code_address(addr)),
                    |addr| analysis::results::callers(&self.image, addr),
                )
            }),
        });
        let finished = std::sync::atomic::AtomicUsize::new(0);
        let results = crate::parallel::map(addresses, |&addr| {
            if finished.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % LIFTS_DROPPED_EVERY
                == LIFTS_DROPPED_EVERY - 1
            {
                self.image.lifts.clear();
            }
            let result = self.render_one(
                addr,
                addresses.len() <= KEPT_ANALYSES,
                &originals,
                &overrides,
                &identified,
                deadline,
            );
            originals
                .lock()
                .expect("analysis cache lock")
                .rendered(self.image.code_address(addr));
            result
        });
        let mut originals = originals
            .into_inner()
            .expect("analysis cache lock")
            .analyses;
        if addresses.len() > KEPT_ANALYSES {
            originals.clear();
        }
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

    /// One function of a batch rendered, with its analysis when `kept`.
    fn render_one(
        &self,
        addr: u64,
        kept: bool,
        originals: &Mutex<Held>,
        overrides: &std::collections::BTreeMap<u64, crate::ir::DeclaredSignature>,
        identified: &HashMap<u64, String>,
        deadline: Option<Instant>,
    ) -> Result<(String, Option<Analysis>)> {
        let addr = self.image.code_address(addr);
        let decoded_strings = if self.string_decoding {
            match self.decoded_strings.get(&addr) {
                Some(strings) => strings.clone(),
                None => {
                    crate::string_decoding::recover(&self.image, addr, deadline).unwrap_or_default()
                }
            }
        } else {
            Vec::new()
        };
        if let Some(analysis) = self.shared_analyses.get(&addr) {
            return match analysis {
                Ok(analysis) => self
                    .render_analysis(
                        analysis,
                        overrides,
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
        let root = match original(&self.image, originals, addr, deadline) {
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
        let analysis = match shared(&self.image, &self.data_ranges, root.clone(), |address| {
            original(&self.image, originals, address, deadline)
                .map(|analysis| analysis.as_ref().as_ref().ok().cloned())
        }) {
            Ok(analysis) => analysis,
            Err(error) => return Err(error),
        };
        match self.render_analysis(
            &analysis,
            overrides,
            identified.get(&addr).map(String::as_str),
            &decoded_strings,
            deadline,
        ) {
            Ok(rendered) => Ok((rendered.code, kept.then_some(analysis))),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(requested: &[u64], calls: &[(u64, u64)]) -> Held {
        let wanted = Wanted::new(requested.iter().copied(), |callee| {
            calls
                .iter()
                .filter(|(_, to)| *to == callee)
                .map(|(from, _)| *from)
                .collect()
        });
        Held {
            analyses: requested
                .iter()
                .map(|&addr| (addr, Arc::new(Err(LiftError::NoInstructions))))
                .collect(),
            wanted: Some(wanted),
        }
    }

    fn left(held: &Held) -> Vec<u64> {
        let mut left: Vec<u64> = held.analyses.keys().copied().collect();
        left.sort_unstable();
        left
    }

    #[test]
    fn an_analysis_is_dropped_once_it_and_its_callers_are_rendered() {
        // 1 and 2 call 3; 3 calls 4; 5 is alone and 9 was not requested.
        let mut held = held(&[1, 2, 3, 4, 5], &[(1, 3), (2, 3), (3, 4), (9, 4)]);
        held.rendered(5);
        assert_eq!(left(&held), [1, 2, 3, 4]);
        // 3 may still ask for its caller 1.
        held.rendered(1);
        assert_eq!(left(&held), [1, 2, 3, 4]);
        held.rendered(3);
        assert_eq!(left(&held), [2, 3, 4]);
        assert!(!held.keeps(1) && held.keeps(3));
        // 4 may still ask for its caller 3.
        held.rendered(2);
        assert_eq!(left(&held), [3, 4]);
        // One not requested is kept until the request ends.
        assert!(held.keeps(9));
        held.rendered(4);
        assert!(left(&held).is_empty());
    }

    #[test]
    fn a_function_rendered_twice_or_calling_itself_counts_once() {
        let mut held = held(&[1, 2, 1], &[(1, 1), (1, 2)]);
        held.rendered(1);
        assert_eq!(left(&held), [1, 2]);
        held.rendered(1);
        assert_eq!(left(&held), [1, 2]);
        held.rendered(2);
        assert!(left(&held).is_empty());
    }

    #[test]
    fn a_callee_asks_for_no_more_callers_than_share_with_it() {
        // 100 is called by 1..=20: only its lowest callers wait for it.
        let callers: Vec<u64> = (1..=20).collect();
        let calls: Vec<(u64, u64)> = callers.iter().map(|&from| (from, 100)).collect();
        let requested: Vec<u64> = callers.iter().copied().chain([100]).collect();
        let mut held = held(&requested, &calls);
        for &caller in &callers[NEIGHBORS..] {
            held.rendered(caller);
        }
        let mut expected: Vec<u64> = callers[..NEIGHBORS].to_vec();
        expected.push(100);
        assert_eq!(left(&held), expected);
        // Those callers may ask for it in turn.
        held.rendered(100);
        assert_eq!(left(&held), expected);
        for &caller in &callers[..NEIGHBORS] {
            held.rendered(caller);
        }
        assert!(left(&held).is_empty());
    }

    #[test]
    fn a_request_that_keeps_everything_drops_nothing() {
        let mut held = Held {
            analyses: [(1, Arc::new(Err(LiftError::NoInstructions)))].into(),
            wanted: None,
        };
        held.rendered(1);
        assert!(held.keeps(1) && left(&held) == [1]);
    }
}
