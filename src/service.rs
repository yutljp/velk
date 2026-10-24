use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use crate::analysis::{self, Analysis};
use crate::card::{self, Card};
use crate::deadline::passed;
use crate::error::{Error, LiftError, Result};
use crate::loader::{self, Function, Image};
use crate::sigs::{self, Database};
use crate::{disasm, render};

const SHOWN_CANDIDATES: usize = 10;

/// Loaded binaries, kept across calls so repeated queries reuse the analysis.
#[derive(Default)]
pub struct Session {
    binaries: HashMap<PathBuf, Binary>,
}

impl Session {
    /// Loads the file, or returns the cached binary when the file is unchanged.
    pub fn open(&mut self, path: &Path) -> Result<&mut Binary> {
        let path = std::fs::canonicalize(path).map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })?;
        let modified = modified(&path)?;
        match self.binaries.entry(path) {
            Entry::Occupied(entry) if entry.get().modified == modified => Ok(entry.into_mut()),
            Entry::Occupied(mut entry) => {
                entry.insert(Binary::load(entry.key(), modified)?);
                Ok(entry.into_mut())
            }
            Entry::Vacant(entry) => {
                let binary = Binary::load(entry.key(), modified)?;
                Ok(entry.insert(binary))
            }
        }
    }
}

pub struct Binary {
    path: PathBuf,
    modified: SystemTime,
    image: Image,
    symbols: render::Symbols,
    data_ranges: Vec<(u64, u64)>,
    analyses: HashMap<u64, Result<Analysis, LiftError>>,
    shared_analyses: HashMap<u64, Result<Analysis, LiftError>>,
}

pub struct Failure {
    pub addr: u64,
    pub error: LiftError,
}

pub struct SignatureBuild {
    pub database: Database,
    pub failures: Vec<Failure>,
}

pub struct Identification {
    pub matches: Vec<Match>,
    pub failures: Vec<Failure>,
}

pub struct Match {
    pub addr: u64,
    pub size: Option<u64>,
    pub current: Option<String>,
    pub matched: String,
}

impl Binary {
    pub fn open(path: &Path) -> Result<Self> {
        Self::load(path, modified(path)?)
    }

    fn load(path: &Path, modified: SystemTime) -> Result<Self> {
        let mut image = loader::load(path)?;
        crate::analysis::absorb_jump_table_cases(&mut image);
        Ok(Self {
            path: path.to_owned(),
            modified,
            symbols: render::callee_names(&image),
            data_ranges: render::data_ranges(&image),
            image,
            analyses: HashMap::new(),
            shared_analyses: HashMap::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    /// Resolves an address (`0x1e0` or decimal), an exact name, or a
    /// case-insensitive substring that matches exactly one name.
    pub fn find(&self, target: &str) -> Result<&Function> {
        if let Some(addr) = crate::addr::parse(target) {
            return self.function(addr);
        }
        let functions = self.image.functions.values();
        if let Some(found) = functions.clone().find(|f| names(f).any(|n| n == target)) {
            return Ok(found);
        }
        if self.image.format == loader::Format::MachO
            && let Some(found) = functions
                .clone()
                .find(|f| names(f).any(|n| n.strip_prefix('_') == Some(target)))
        {
            return Ok(found);
        }
        let needle = target.to_lowercase();
        let partial: Vec<&Function> = functions
            .filter(|f| names(f).any(|n| n.to_lowercase().contains(&needle)))
            .collect();
        match partial.as_slice() {
            [] => Err(Error::NoFunctionNamed(target.to_owned())),
            [only] => Ok(only),
            many => Err(Error::AmbiguousName {
                name: target.to_owned(),
                shown: many
                    .iter()
                    .take(SHOWN_CANDIDATES)
                    .map(|f| {
                        format!(
                            "{} ({})",
                            names(f).collect::<Vec<_>>().join(" / "),
                            crate::addr::format(f.addr)
                        )
                    })
                    .collect(),
                total: many.len(),
            }),
        }
    }

    pub fn function(&self, addr: u64) -> Result<&Function> {
        self.image
            .functions
            .get(&addr)
            .ok_or(Error::NoFunctionAt(addr))
    }

    pub fn analysis(&mut self, addr: u64, deadline: Option<Instant>) -> Result<&Analysis> {
        if !self.image.functions.contains_key(&addr) {
            return Err(Error::NoFunctionAt(addr));
        }
        if let Err(error) = self.prepare_structures(addr, deadline) {
            return Err(error);
        }
        let Some(function) = self.image.functions.get(&addr) else {
            return Err(Error::NoFunctionAt(addr));
        };
        let analyzed = match cached(&mut self.shared_analyses, &self.image, function, deadline) {
            Ok(analyzed) => analyzed,
            Err(error) => return Err(error),
        };
        analyzed.as_ref().map_err(|source| Error::Lift {
            addr,
            source: source.clone(),
        })
    }

    pub fn card(
        &mut self,
        addr: u64,
        budget: usize,
        signatures: Option<&Database>,
        deadline: Option<Instant>,
    ) -> Result<Card> {
        if !self.image.functions.contains_key(&addr) {
            return Err(Error::NoFunctionAt(addr));
        }
        if let Err(error) = self.prepare_structures(addr, deadline) {
            return Err(error);
        }
        let Some(function) = self.image.functions.get(&addr) else {
            return Err(Error::NoFunctionAt(addr));
        };
        let analysis = match cached(&mut self.shared_analyses, &self.image, function, deadline) {
            Ok(analyzed) => analyzed.as_ref(),
            Err(error) => return Err(error),
        };
        let identified = identify(signatures, analysis);
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        Ok(card::build(
            &self.image,
            function,
            analysis,
            identified,
            budget,
        ))
    }

    pub fn decompile(
        &mut self,
        addr: u64,
        signatures: Option<&Database>,
        deadline: Option<Instant>,
    ) -> Result<String> {
        self.decompile_with_dependencies(addr, signatures, deadline)
            .map(|rendered| rendered.code)
    }

    /// Renders pseudo-C and the external segment-base reads its caller must bind.
    pub fn decompile_with_dependencies(
        &mut self,
        addr: u64,
        signatures: Option<&Database>,
        deadline: Option<Instant>,
    ) -> Result<render::Rendered> {
        if !self.image.functions.contains_key(&addr) {
            return Err(Error::NoFunctionAt(addr));
        }
        if let Err(error) = self.prepare_structures(addr, deadline) {
            return Err(error);
        }
        let Some(function) = self.image.functions.get(&addr) else {
            return Err(Error::NoFunctionAt(addr));
        };
        let analysis = match cached(&mut self.shared_analyses, &self.image, function, deadline) {
            Ok(Ok(analysis)) => analysis,
            Ok(Err(source)) => {
                return Err(Error::Lift {
                    addr,
                    source: source.clone(),
                });
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let mut rendered = render::render_with_dependencies(
            &analysis.ir,
            &analysis.references,
            &self.symbols,
            &self.data_ranges,
        );
        if let Some(name) = identify(signatures, Ok(analysis)) {
            rendered
                .code
                .insert_str(0, &format!("/* identified: {name} */\n"));
        }
        Ok(rendered)
    }

    fn prepare_structures(&mut self, addr: u64, deadline: Option<Instant>) -> Result<()> {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if self.shared_analyses.contains_key(&addr) {
            return Ok(());
        }
        let Some(function) = self.image.functions.get(&addr) else {
            return Err(Error::NoFunctionAt(addr));
        };
        let root = match cached(&mut self.analyses, &self.image, function, deadline) {
            Ok(result) => result.clone(),
            Err(error) => return Err(error),
        };
        let Ok(root_analysis) = &root else {
            self.shared_analyses.insert(addr, root);
            return Ok(());
        };
        let ir = &root_analysis.ir;
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
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
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
                && self.image.functions.contains_key(target)
            {
                neighbors.insert(*target);
            }
        }
        if ir.params.iter().any(|param| param.ty.is_pointer()) {
            neighbors.extend(analysis::results::callers(&self.image, addr));
        }
        neighbors.remove(&addr);
        // One call edge and at most eight neighbors bound interactive work.
        // Always start from original analyses: another request's merged layouts
        // must never become input to this function's neighborhood.
        let mut functions = vec![root_analysis.clone()];
        for neighbor in neighbors.into_iter().take(8) {
            let Some(function) = self.image.functions.get(&neighbor) else {
                continue;
            };
            match cached(&mut self.analyses, &self.image, function, deadline) {
                Ok(Ok(analysis)) => functions.push(analysis.clone()),
                Ok(Err(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        functions.sort_by_key(|analysis| analysis.ir.addr);
        let mut irs: Vec<_> = functions
            .iter_mut()
            .map(|analysis| &mut analysis.ir)
            .collect();
        analysis::shared_structures::share(&mut irs, &self.data_ranges);
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        for analysis in functions {
            if analysis.ir.addr == addr {
                self.shared_analyses.insert(addr, Ok(analysis));
                break;
            }
        }
        Ok(())
    }

    pub fn disasm(&self, addr: u64, max_lines: usize) -> Result<Vec<String>> {
        let function = self.function(addr)?;
        let len = function.size.unwrap_or(analysis::UNKNOWN_SIZE);
        disasm::listing(&self.image, addr, len, max_lines)
            .map_err(|source| Error::Lift { addr, source })
    }

    pub fn shape_hash(&mut self, addr: u64, deadline: Option<Instant>) -> Result<String> {
        Ok(sigs::shape_hash(&self.analysis(addr, deadline)?.ir))
    }

    /// Signatures of the named functions; Err once `deadline` passes.
    pub fn build_signatures(&mut self, deadline: Option<Instant>) -> Result<SignatureBuild> {
        let mut entries = Vec::new();
        let mut failures = Vec::new();
        for function in self.image.functions.values() {
            let Some(name) = &function.name else {
                continue;
            };
            passed(deadline)?;
            match cached(&mut self.analyses, &self.image, function, deadline)? {
                Ok(analysis) => entries.extend(sigs::entry(name, function.size, &analysis.ir)),
                Err(error) => failures.push(Failure {
                    addr: function.addr,
                    error: error.clone(),
                }),
            }
        }
        Ok(SignatureBuild {
            database: Database::new(entries),
            failures,
        })
    }

    /// The functions `database` names; Err once `deadline` passes.
    pub fn identify(
        &mut self,
        database: &Database,
        deadline: Option<Instant>,
    ) -> Result<Identification> {
        let mut matches = Vec::new();
        let mut failures = Vec::new();
        for function in self.image.functions.values() {
            passed(deadline)?;
            match cached(&mut self.analyses, &self.image, function, deadline)? {
                Ok(analysis) => {
                    if let Some(entry) = database.lookup(&analysis.ir) {
                        matches.push(Match {
                            addr: function.addr,
                            size: function.size,
                            current: function.name.clone(),
                            matched: entry.name.clone(),
                        });
                    }
                }
                Err(error) => failures.push(Failure {
                    addr: function.addr,
                    error: error.clone(),
                }),
            }
        }
        Ok(Identification { matches, failures })
    }
}

fn cached<'a>(
    analyses: &'a mut HashMap<u64, Result<Analysis, LiftError>>,
    image: &Image,
    function: &Function,
    deadline: Option<Instant>,
) -> Result<&'a Result<Analysis, LiftError>> {
    passed(deadline)?;
    if let Entry::Vacant(entry) = analyses.entry(function.addr) {
        let analyzed = match analysis::analyze(image, function, deadline) {
            Ok(analysis) => Ok(analysis),
            Err(Error::Lift { source, .. }) => Err(source),
            Err(error) => return Err(error),
        };
        passed(deadline)?;
        entry.insert(analyzed);
    }
    Ok(analyses.get(&function.addr).expect("analysis was inserted"))
}

fn names(function: &Function) -> impl Iterator<Item = &str> {
    function
        .name
        .iter()
        .chain(&function.aliases)
        .map(String::as_str)
}

fn identify(
    signatures: Option<&Database>,
    analysis: Result<&Analysis, &LiftError>,
) -> Option<String> {
    Some(signatures?.lookup(&analysis.ok()?.ir)?.name.clone())
}

fn modified(path: &Path) -> Result<SystemTime> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CType, Expr, FunctionIr, Stmt};
    use crate::loader::Isa;

    fn fixture(name: &str) -> Binary {
        Binary::open(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .expect("fixture loads")
    }

    #[test]
    fn shared_layouts_do_not_depend_on_request_order() {
        let mut forward = fixture("cpp_virtual_x64.elf");
        let addresses: Vec<_> = forward.image.functions.keys().copied().collect();
        let mut expected = HashMap::new();
        for addr in &addresses {
            expected.insert(*addr, forward.decompile(*addr, None, None).unwrap());
        }
        let mut reverse = fixture("cpp_virtual_x64.elf");
        for addr in addresses.iter().rev() {
            assert_eq!(
                reverse.decompile(*addr, None, None).unwrap(),
                expected[addr]
            );
        }
        for addr in addresses {
            assert_eq!(
                forward.decompile(addr, None, None).unwrap(),
                expected[&addr]
            );
        }
    }

    #[test]
    fn single_function_analysis_is_bounded_and_reused() {
        let mut binary = fixture("go_probe");
        let addr = binary.find("main.main").unwrap().addr;
        let code = binary.decompile(addr, None, None).unwrap();
        assert!(binary.analyses.len() <= 9);
        let count = binary.analyses.len();
        assert_eq!(binary.decompile(addr, None, None).unwrap(), code);
        assert_eq!(binary.analyses.len(), count);
        assert_eq!(binary.shared_analyses.len(), 1);
    }

    #[test]
    fn timed_out_analysis_is_not_cached() {
        let mut binary = fixture("arm64.o");
        let addr = binary.find("pair_sum").expect("fixture function").addr;
        assert!(matches!(
            binary.analysis(addr, Some(Instant::now())),
            Err(Error::TimedOut)
        ));
        assert!(!binary.analyses.contains_key(&addr));
        let code = binary
            .decompile(addr, None, None)
            .expect("unlimited analysis");
        assert!(code.contains("pair_sum"));
        assert!(matches!(binary.analyses.get(&addr), Some(Ok(_))));
        assert_eq!(binary.decompile(addr, None, None).unwrap(), code);
    }

    #[test]
    fn decompile_string_wrapper_preserves_dependency_free_output() {
        let mut binary = fixture("arm64.o");
        let addr = binary.find("pair_sum").expect("fixture function").addr;
        let rendered = binary
            .decompile_with_dependencies(addr, None, None)
            .expect("typed decompilation");
        assert!(rendered.segment_bases.is_empty());
        assert_eq!(binary.decompile(addr, None, None).unwrap(), rendered.code);
        assert!(matches!(
            binary.decompile_with_dependencies(u64::MAX, None, None),
            Err(Error::NoFunctionAt(u64::MAX))
        ));
    }

    #[test]
    fn decompile_keeps_dependencies_and_identification_from_cached_analysis() {
        let mut binary = fixture("x64_div.o");
        let addr = binary.find("smod3x").expect("fixture function").addr;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::Reg {
                    index: crate::arch::x86::FS_BASE,
                    width: 64,
                },
            }],
        );
        ir.addr = addr;
        ir.ret_type = CType::U64;
        let signatures = Database::new(vec![sigs::entry("segment_reader", None, &ir).unwrap()]);
        binary.analyses.insert(
            addr,
            Ok(Analysis {
                ir,
                references: Vec::new(),
            }),
        );
        let rendered = binary
            .decompile_with_dependencies(addr, Some(&signatures), None)
            .expect("typed decompilation");
        assert_eq!(rendered.segment_bases.len(), 1);
        let dependency = &rendered.segment_bases[0];
        assert_eq!(dependency.segment, render::SegmentBase::Fs);
        assert!(
            rendered
                .code
                .contains(&format!("uint64_t {}(void);", dependency.provider))
        );
        assert!(
            rendered
                .code
                .starts_with("/* identified: segment_reader */\n")
        );
        assert_eq!(
            binary.decompile(addr, Some(&signatures), None).unwrap(),
            rendered.code
        );
    }
}
