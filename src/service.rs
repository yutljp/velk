use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use crate::analysis::{self, Analysis};
use crate::card::{self, Card};
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

    pub fn analysis(&mut self, addr: u64) -> Result<&Analysis> {
        let function = self
            .image
            .functions
            .get(&addr)
            .ok_or(Error::NoFunctionAt(addr))?;
        cached(&mut self.analyses, &self.image, function)
            .as_ref()
            .map_err(|source| Error::Lift {
                addr,
                source: source.clone(),
            })
    }

    pub fn card(
        &mut self,
        addr: u64,
        budget: usize,
        signatures: Option<&Database>,
    ) -> Result<Card> {
        let function = self
            .image
            .functions
            .get(&addr)
            .ok_or(Error::NoFunctionAt(addr))?;
        let analysis = cached(&mut self.analyses, &self.image, function).as_ref();
        let identified = identify(signatures, analysis);
        Ok(card::build(
            &self.image,
            function,
            analysis,
            identified,
            budget,
        ))
    }

    pub fn decompile(&mut self, addr: u64, signatures: Option<&Database>) -> Result<String> {
        self.decompile_with_dependencies(addr, signatures)
            .map(|rendered| rendered.code)
    }

    /// Renders pseudo-C and the external segment-base reads its caller must bind.
    pub fn decompile_with_dependencies(
        &mut self,
        addr: u64,
        signatures: Option<&Database>,
    ) -> Result<render::Rendered> {
        let function = self
            .image
            .functions
            .get(&addr)
            .ok_or(Error::NoFunctionAt(addr))?;
        let analysis = cached(&mut self.analyses, &self.image, function)
            .as_ref()
            .map_err(|source| Error::Lift {
                addr,
                source: source.clone(),
            })?;
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

    pub fn disasm(&self, addr: u64, max_lines: usize) -> Result<Vec<String>> {
        let function = self.function(addr)?;
        let len = function.size.unwrap_or(analysis::UNKNOWN_SIZE);
        disasm::listing(&self.image, addr, len, max_lines)
            .map_err(|source| Error::Lift { addr, source })
    }

    pub fn shape_hash(&mut self, addr: u64) -> Result<String> {
        Ok(sigs::shape_hash(&self.analysis(addr)?.ir))
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
            match cached(&mut self.analyses, &self.image, function) {
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
            match cached(&mut self.analyses, &self.image, function) {
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

/// Err once `deadline` has passed.
fn passed(deadline: Option<Instant>) -> Result<()> {
    match deadline {
        Some(deadline) if Instant::now() > deadline => Err(Error::TimedOut),
        _ => Ok(()),
    }
}

fn cached<'a>(
    analyses: &'a mut HashMap<u64, Result<Analysis, LiftError>>,
    image: &Image,
    function: &Function,
) -> &'a Result<Analysis, LiftError> {
    analyses
        .entry(function.addr)
        .or_insert_with(|| analysis::analyze(image, function))
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
    fn decompile_string_wrapper_preserves_dependency_free_output() {
        let mut binary = fixture("arm64.o");
        let addr = binary.find("pair_sum").expect("fixture function").addr;
        let rendered = binary
            .decompile_with_dependencies(addr, None)
            .expect("typed decompilation");
        assert!(rendered.segment_bases.is_empty());
        assert_eq!(binary.decompile(addr, None).unwrap(), rendered.code);
        assert!(matches!(
            binary.decompile_with_dependencies(u64::MAX, None),
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
            .decompile_with_dependencies(addr, Some(&signatures))
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
            binary.decompile(addr, Some(&signatures)).unwrap(),
            rendered.code
        );
    }
}
