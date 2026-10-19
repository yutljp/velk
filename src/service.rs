use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
    callees: HashMap<u64, String>,
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
        let image = loader::load(path)?;
        Ok(Self {
            path: path.to_owned(),
            modified,
            callees: render::callee_names(&image),
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
        let mut text = String::new();
        if let Some(name) = identify(signatures, Ok(analysis)) {
            text.push_str(&format!("/* identified: {name} */\n"));
        }
        text.push_str(&render::render(
            &analysis.ir,
            &analysis.references,
            &self.callees,
            &self.data_ranges,
        ));
        Ok(text)
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

    pub fn build_signatures(&mut self) -> SignatureBuild {
        let mut entries = Vec::new();
        let mut failures = Vec::new();
        for function in self.image.functions.values() {
            let Some(name) = &function.name else {
                continue;
            };
            match cached(&mut self.analyses, &self.image, function) {
                Ok(analysis) => entries.extend(sigs::entry(name, function.size, &analysis.ir)),
                Err(error) => failures.push(Failure {
                    addr: function.addr,
                    error: error.clone(),
                }),
            }
        }
        SignatureBuild {
            database: Database::new(entries),
            failures,
        }
    }

    pub fn identify(&mut self, database: &Database) -> Identification {
        let mut matches = Vec::new();
        let mut failures = Vec::new();
        for function in self.image.functions.values() {
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
        Identification { matches, failures }
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
