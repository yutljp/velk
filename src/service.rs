mod batch;
pub(crate) mod cache;
mod declarations;

pub use cache::Location as CacheLocation;

use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime};

use crate::analysis::{self, Analysis};
use crate::card::{self, Card};
use crate::deadline::passed;
use crate::error::{Error, LiftError, Result};
use crate::loader::{self, Architecture, Function, Image};
use crate::sigs::{self, Certainty, Database, MatchScope};
use crate::{disasm, render};

pub(crate) fn function_signature(ir: &crate::ir::FunctionIr) -> serde_json::Value {
    let params: Vec<_> = if let Ok(scalar) = crate::project::scalar_parameters(ir) {
        scalar
            .iter()
            .map(|(name, ty)| serde_json::json!({"name": name, "type": ty.to_string()}))
            .collect()
    } else {
        let mut params: Vec<_> = ir
            .params
            .iter()
            .map(|param| serde_json::json!({"name": param.name, "type": param.ty.to_string()}))
            .collect();
        let mut stack: Vec<_> = ir.stack_params.iter().collect();
        stack.sort_by_key(|param| param.position);
        for param in stack {
            params.insert(
                param.position.min(params.len()),
                serde_json::json!({
                    "name": param.name, "type": param.ty.to_string(),
                }),
            );
        }
        params
    };
    serde_json::json!({
        "return": ir.ret_type.to_string(),
        "parameterCount": params.len(),
        "params": params,
        "callingConvention": format!("{:?}", ir.convention),
        "variadic": ir.variadic,
    })
}

fn canonicalize(path: &Path) -> Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(source) => Err(Error::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

const SHOWN_CANDIDATES: usize = 10;

/// Signature databases to apply when a binary is opened.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SignatureOptions {
    /// Apply the embedded library sets.
    pub defaults: bool,
    /// Additional JSON databases, matched together with the enabled sets.
    pub files: Vec<PathBuf>,
}

impl Default for SignatureOptions {
    fn default() -> Self {
        Self {
            defaults: true,
            files: Vec::new(),
        }
    }
}

/// Loaded binaries, kept across calls so repeated queries reuse the analysis.
#[derive(Default)]
pub struct Session {
    binaries: HashMap<(PathBuf, loader::OpenOptions, SignatureOptions), Binary>,
}

impl Session {
    pub(crate) fn open_with_options(
        &mut self,
        path: &Path,
        project: Option<&Path>,
        arch: Option<Architecture>,
        signatures: &SignatureOptions,
    ) -> Result<&mut Binary> {
        self.open_input_with_signatures(
            path,
            project,
            &loader::OpenOptions {
                arch,
                raw: None,
                cache: None,
            },
            signatures,
        )
    }

    /// Loads the file, or returns cached analysis when the file is unchanged.
    pub fn open(&mut self, path: &Path) -> Result<&mut Binary> {
        self.open_arch(path, None)
    }

    /// Opens and caches a particular architecture independently.
    pub fn open_arch(&mut self, path: &Path, arch: Option<Architecture>) -> Result<&mut Binary> {
        self.open_with_options(path, None, arch, &SignatureOptions::default())
    }

    /// Opens a normal or raw image, caching each mapping independently.
    pub fn open_input(
        &mut self,
        path: &Path,
        project: Option<&Path>,
        options: &loader::OpenOptions,
    ) -> Result<&mut Binary> {
        self.open_input_with_signatures(path, project, options, &SignatureOptions::default())
    }

    pub(crate) fn open_input_with_signatures(
        &mut self,
        path: &Path,
        project: Option<&Path>,
        options: &loader::OpenOptions,
        signatures: &SignatureOptions,
    ) -> Result<&mut Binary> {
        let path = match canonicalize(path) {
            Ok(path) => path,
            Err(error) => return Err(error),
        };
        let modified = match modified(&path) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        match self
            .binaries
            .entry((path, options.clone(), signatures.clone()))
        {
            Entry::Occupied(entry)
                if entry.get().source_digest.is_some()
                    && entry.get().source_digest
                        == cache::source_digest(&entry.key().0, signatures)
                    && entry.get().modified == modified
                    && project.is_none_or(|project| entry.get().project_path == project) =>
            {
                let binary = entry.into_mut();
                match binary.refresh_project() {
                    Ok(()) => Ok(binary),
                    Err(error) => Err(error),
                }
            }
            Entry::Occupied(mut entry) => {
                let project = project.unwrap_or(&entry.get().project_path);
                let binary = match Binary::load_project(
                    &entry.key().0,
                    modified,
                    Some(project),
                    None,
                    options,
                    signatures,
                ) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                entry.get_mut().cache = None;
                entry.insert(binary);
                Ok(entry.into_mut())
            }
            Entry::Vacant(entry) => {
                let binary = match Binary::load_project(
                    &entry.key().0,
                    modified,
                    project,
                    None,
                    options,
                    signatures,
                ) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                Ok(entry.insert(binary))
            }
        }
    }
}

pub struct Binary {
    cache: Option<cache::Cache>,
    source_digest: Option<String>,
    string_decoding: bool,
    decoded_strings: HashMap<u64, Vec<crate::string_decoding::DecodedString>>,
    navigation: Option<crate::xrefs::Index>,
    similarity: Option<crate::similar::Index>,
    path: PathBuf,
    modified: SystemTime,
    project: Option<crate::project::Project>,
    project_path: PathBuf,
    pub(crate) project_digest: Option<String>,
    image: Image,
    options: loader::OpenOptions,
    signature_options: SignatureOptions,
    signature_database: Cow<'static, Database>,
    symbolic_identifications: OnceLock<BTreeMap<u64, sigs::Evidence>>,
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
    pub candidates: Vec<(u64, sigs::Evidence)>,
}

pub struct Match {
    pub addr: u64,
    pub size: Option<u64>,
    pub current: Option<String>,
    pub matched: String,
    pub evidence: sigs::Evidence,
}

impl Binary {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_project(path, None)
    }

    /// Opens a binary with an optional annotation file location.
    pub fn open_with_project(path: &Path, project: Option<&Path>) -> Result<Self> {
        Self::open_with_options(path, project, None)
    }

    /// Opens a binary with optional annotations and architecture selection.
    pub fn open_with_options(
        path: &Path,
        project: Option<&Path>,
        arch: Option<Architecture>,
    ) -> Result<Self> {
        Self::open_input(
            path,
            project,
            &loader::OpenOptions {
                arch,
                raw: None,
                cache: None,
            },
        )
    }

    /// Opens a normal or raw image with explicit mapping options.
    pub fn open_input(
        path: &Path,
        project: Option<&Path>,
        options: &loader::OpenOptions,
    ) -> Result<Self> {
        let modified = match modified(path) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Self::load_project(
            path,
            modified,
            project,
            None,
            options,
            &SignatureOptions::default(),
        )
    }

    /// Opens a binary with selected signature databases.
    pub fn open_with_signatures(
        path: &Path,
        project: Option<&Path>,
        arch: Option<Architecture>,
        signatures: &SignatureOptions,
    ) -> Result<Self> {
        Self::open_input_with_signatures(
            path,
            project,
            &loader::OpenOptions {
                arch,
                raw: None,
                cache: None,
            },
            signatures,
        )
    }

    /// Opens an image with mapping and signature options.
    pub fn open_input_with_signatures(
        path: &Path,
        project: Option<&Path>,
        options: &loader::OpenOptions,
        signatures: &SignatureOptions,
    ) -> Result<Self> {
        let modified = match modified(path) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Self::load_project(path, modified, project, None, options, signatures)
    }

    fn load_project(
        path: &Path,
        modified: SystemTime,
        project_path: Option<&Path>,
        mut project_digest: Option<String>,
        options: &loader::OpenOptions,
        signatures: &SignatureOptions,
    ) -> Result<Self> {
        let path = match canonicalize(path) {
            Ok(path) => path,
            Err(error) => return Err(error),
        };
        let project_path = project_path
            .map(Path::to_owned)
            .unwrap_or_else(|| crate::project::path(&path));
        let project = match crate::project::load_at(&path, &project_path, &mut project_digest) {
            Ok(project) => project,
            Err(error) => return Err(error),
        };
        let mut options = options.clone();
        if let Some(raw) = project.as_ref().and_then(|project| project.raw.as_ref()) {
            if options
                .raw
                .as_ref()
                .is_some_and(|requested| requested != raw)
            {
                return Err(Error::Raw(
                    "mapping differs from the project file; select a different project".to_owned(),
                ));
            }
            options.raw = Some(raw.clone());
        }
        let mut source_digest = None;
        let mut cache = None;
        let mut reused = false;
        let mut image = match loader::load_input_with_saved(&path, &options, |image| {
            source_digest = cache::image_source_digest(image, signatures);
            cache = cache::Cache::new(
                &path,
                &project_path,
                image.debug_path.as_deref(),
                source_digest.as_deref(),
                &options,
                signatures,
                project.as_ref(),
            );
            let saved = cache.as_mut().and_then(cache::Cache::read);
            reused = saved.is_some();
            saved
        }) {
            Ok(image) => image,
            Err(error) => return Err(error),
        };
        if !reused {
            crate::analysis::absorb_jump_table_cases(&mut image);
        }
        if !reused
            && let Some(project) = &project
            && let Err(error) = project.classify(&mut image)
        {
            return Err(error);
        }
        let needs_defaults = signatures.defaults
            && (!signatures.files.is_empty()
                || if reused {
                    cache.as_ref().is_some_and(|cache| cache.needs_defaults)
                } else {
                    sigs::has_unnamed_candidates(&image)
                });
        if let Some(cache) = &mut cache {
            cache.needs_defaults = needs_defaults;
        }
        let mut database = if needs_defaults {
            Cow::Borrowed(sigs::bundled_for_isa(image.isa))
        } else {
            Cow::Owned(Database::new(Vec::new()))
        };
        for path in &signatures.files {
            let mut extra = match Database::load(path) {
                Ok(database) => database,
                Err(error) => return Err(error),
            };
            let source = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            for entry in &mut extra.entries {
                if entry.set.is_none() {
                    entry.set = Some(source.clone());
                }
            }
            database.to_mut().entries.extend(extra.entries);
            database.to_mut().sources.extend(extra.sources);
        }
        let mut binary = Self {
            cache: None,
            source_digest,
            navigation: None,
            similarity: None,
            path: path.to_owned(),
            modified,
            project,
            project_path,
            project_digest,
            string_decoding: true,
            decoded_strings: HashMap::new(),
            symbols: render::callee_names(&image),
            data_ranges: render::data_ranges(&image),
            image,
            options,
            signature_options: signatures.clone(),
            signature_database: Cow::Owned(Database::new(Vec::new())),
            symbolic_identifications: OnceLock::new(),
            analyses: HashMap::new(),
            shared_analyses: HashMap::new(),
        };
        if !reused
            && (!signatures.files.is_empty() || needs_defaults)
            && let Err(error) = binary.apply_signatures(
                &database,
                None,
                if signatures.files.is_empty() {
                    MatchScope::Unnamed
                } else {
                    MatchScope::All
                },
            )
        {
            return Err(error);
        }
        binary.signature_database = database;
        if let Some(cache) = &mut cache
            && !reused
        {
            cache.write(&binary.image, binary.navigation.as_ref());
        }
        binary.cache = cache;
        Ok(binary)
    }

    pub(crate) fn refresh_project(&mut self) -> Result<()> {
        if self.project.is_none()
            && matches!(std::fs::symlink_metadata(&self.project_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(());
        }
        let current =
            match crate::project::load_at(&self.path, &self.project_path, &mut self.project_digest)
            {
                Ok(project) => project,
                Err(error) => return Err(error),
            };
        if current != self.project {
            match Self::load_project(
                &self.path,
                self.modified,
                Some(&self.project_path),
                self.project_digest.clone(),
                &self.options,
                &self.signature_options,
            ) {
                Ok(mut binary) => {
                    binary.string_decoding = self.string_decoding;
                    self.cache = None;
                    *self = binary;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn input_options(&self) -> &loader::OpenOptions {
        &self.options
    }

    pub(crate) fn project_path(&self) -> &Path {
        &self.project_path
    }

    /// Lists discovered functions with project names applied.
    pub fn functions(&self) -> Vec<Function> {
        self.image
            .functions
            .values()
            .map(|function| {
                let mut function = function.clone();
                function.name = self.function_name(function.addr).map(str::to_owned);
                function
            })
            .collect()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    /// Enables or disables automatic string comments during decompilation.
    pub fn set_string_decoding(&mut self, enabled: bool) {
        self.string_decoding = enabled;
    }

    /// Recovers strings in one function using only known execution inputs.
    pub fn decoded_strings_at(
        &mut self,
        function_address: u64,
        deadline: Option<Instant>,
    ) -> &[crate::string_decoding::DecodedString] {
        let function_address = self.image.code_address(function_address);
        if let Entry::Vacant(entry) = self.decoded_strings.entry(function_address) {
            let Some(strings) =
                crate::string_decoding::recover(&self.image, function_address, deadline)
            else {
                return &[];
            };
            entry.insert(strings);
        }
        match self.decoded_strings.get(&function_address) {
            Some(strings) => strings,
            None => &[],
        }
    }

    /// Lists recovered strings from every function.
    pub fn decoded_strings(
        &mut self,
        deadline: Option<Instant>,
    ) -> Vec<crate::string_decoding::DecodedString> {
        let mut functions: Vec<_> = self.image.functions.keys().copied().collect();
        functions.sort_unstable();
        let pending: Vec<_> = functions
            .iter()
            .copied()
            .filter(|function| !self.decoded_strings.contains_key(function))
            .collect();
        let recovered = crate::parallel::map(&pending, |&function| {
            crate::string_decoding::recover(&self.image, function, deadline)
        });
        for (function, strings) in pending.into_iter().zip(recovered) {
            if let Some(strings) = strings {
                self.decoded_strings.insert(function, strings);
            }
        }
        let mut result = Vec::new();
        for function in functions {
            if let Some(strings) = self.decoded_strings.get(&function) {
                result.extend_from_slice(strings);
            }
        }
        result.sort_by(|a, b| {
            (a.function, a.site, a.addr, &a.text).cmp(&(b.function, b.site, b.addr, &b.text))
        });
        result.dedup();
        result
    }

    fn function_name(&self, address: u64) -> Option<&str> {
        if let Some(project) = &self.project
            && let Some(annotation) = project.get(&crate::project::Target::Function { address })
        {
            return annotation.name.as_deref();
        }
        self.image
            .functions
            .get(&address)
            .and_then(|function| function.name.as_deref())
    }

    /// Builds the navigation index once; interrupted builds are never cached.
    ///
    /// # Panics
    ///
    /// Panics if a successful index build leaves the navigation cache empty.
    pub fn navigation(&mut self, deadline: Option<Instant>) -> Result<&crate::xrefs::Index> {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if self.navigation.is_none() {
            self.navigation = self.cache.as_mut().and_then(cache::Cache::read_navigation);
        }
        if self.navigation.is_none() {
            match crate::xrefs::Index::build(&self.image, deadline) {
                Ok(mut index) => {
                    if let Some(project) = &self.project {
                        for annotation in &project.annotations {
                            let (crate::project::Target::Function { address }
                            | crate::project::Target::Global { address }) = annotation.target
                            else {
                                continue;
                            };
                            if let Some(name) = &annotation.name {
                                index.rename(address, name);
                            }
                        }
                    }
                    self.navigation = Some(index);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(self.navigation.as_ref().expect("index was inserted"))
    }

    /// Resolves a function, import slot, data symbol, or arbitrary address.
    pub fn find_address(&self, target: &str) -> Result<u64> {
        if let Some(addr) = crate::addr::parse(target) {
            return Ok(addr);
        }
        let matches: std::collections::BTreeSet<_> = self
            .image
            .imports
            .iter()
            .chain(self.image.data_symbols.iter())
            .filter(|(_, name)| name.as_str() == target)
            .map(|(addr, _)| *addr)
            .collect();
        if matches.len() == 1
            && let Some(&addr) = matches.first()
        {
            return Ok(addr);
        }
        if matches.len() > 1 {
            return Err(Error::AmbiguousName {
                name: target.to_owned(),
                shown: matches
                    .iter()
                    .take(SHOWN_CANDIDATES)
                    .map(|addr| crate::addr::format(*addr))
                    .collect(),
                total: matches.len(),
            });
        }
        self.find(target).map(|function| function.addr)
    }

    /// Returns recovered parameter types, count, calling convention and variadic status.
    pub fn signature(&mut self, addr: u64, deadline: Option<Instant>) -> Result<serde_json::Value> {
        let ir = match self.annotated_ir(addr, deadline) {
            Ok(ir) => ir,
            Err(error) => return Err(error),
        };
        let mut signature = function_signature(&ir);
        if self.symbols.variadic_functions.get(&ir.addr).copied()
            == Some(ir.params.len().saturating_add(ir.stack_params.len()))
        {
            signature["variadic"] = serde_json::Value::Bool(true);
        }
        Ok(signature)
    }

    pub fn summary(&mut self, addr: u64, deadline: Option<Instant>) -> Result<serde_json::Value> {
        let mut function = match self.function(addr) {
            Ok(function) => function.clone(),
            Err(error) => return Err(error),
        };
        function.name = self.function_name(function.addr).map(str::to_owned);
        let signature = match self.signature(addr, deadline) {
            Ok(signature) => signature,
            Err(error) => return Err(error),
        };
        let (ir, simplification) = match self.analysis(addr, deadline) {
            Ok(analysis) => (&analysis.ir, analysis.simplification),
            Err(error) => return Err(error),
        };
        let mut calls = Vec::new();
        let mut targets = Vec::new();
        for block in &ir.blocks {
            for (position, stmt) in block.stmts.iter().enumerate() {
                let crate::ir::Stmt::Call {
                    target,
                    through,
                    convention,
                    args,
                    via,
                    ..
                } = stmt
                else {
                    continue;
                };
                calls.push(serde_json::json!({
                    "block": crate::addr::format(block.start),
                    "statement": position,
                    "target": target.map(crate::addr::format),
                    "indirect": through.is_some(),
                    "callingConvention": format!("{convention:?}"),
                    "argumentCount": args.as_ref().map(Vec::len),
                    "candidates": via.iter().flat_map(|via| &via.candidates)
                        .copied().map(crate::addr::format).collect::<Vec<_>>(),
                    "signature": target.and_then(|target| ir.callee_signatures.get(&target))
                        .map(|signature| serde_json::json!({
                            "return": signature.ret.to_string(),
                            "params": signature.params.iter().map(|(name, ty)|
                                serde_json::json!({"name": name, "type": ty.to_string()})
                            ).collect::<Vec<_>>(),
                            "parameterCount": signature.params.len(),
                            "callingConvention": format!("{convention:?}"),
                            "variadic": signature.variadic,
                        })),
                }));
                if let Some(target) = target {
                    targets.push((calls.len() - 1, *target));
                }
            }
        }
        for (position, target) in targets {
            if !calls[position]["signature"].is_null()
                || !self.image.functions.contains_key(&target)
            {
                continue;
            }
            let recovered = if target == addr {
                signature.clone()
            } else {
                match self.signature(target, deadline) {
                    Ok(signature) => signature,
                    Err(Error::TimedOut) => return Err(Error::TimedOut),
                    Err(_) => continue,
                }
            };
            calls[position]["signature"] = recovered;
        }
        let api_hashes = match self.shared_analyses.get(&addr) {
            Some(Ok(analysis)) => crate::api_hashes::recover(&self.image, &analysis.ir, deadline),
            _ => Vec::new(),
        };
        let imports: std::collections::BTreeMap<_, _> = self
            .image
            .imports
            .iter()
            .map(|(addr, name)| (*addr, name.clone()))
            .chain(
                self.image
                    .functions
                    .values()
                    .filter(|function| function.sources.contains(&loader::NameSource::Plt))
                    .filter_map(|function| function.name.clone().map(|name| (function.addr, name))),
            )
            .collect();
        let inline_functions = match self.decompile_with_dependencies(addr, None, deadline) {
            Ok(rendered) => rendered.inline_functions,
            Err(error) => return Err(error),
        };
        let index = match self.navigation(deadline) {
            Ok(index) => index,
            Err(error) => return Err(error),
        };
        let outgoing = index.from(addr);
        Ok(serde_json::json!({
            "addr": crate::addr::format(addr), "name": function.name, "size": function.size,
            "signature": signature, "calls": calls, "simplification": simplification,
            "inlineFunctions": inline_functions,
            "apiHashes": api_hashes,
            "callees": index.graph(addr, false, 1).into_iter().map(crate::addr::format).collect::<Vec<_>>(),
            "imports": outgoing.iter().filter_map(|xref| imports.get(&xref.target))
                .collect::<std::collections::BTreeSet<_>>(),
            "strings": index.strings().iter().filter(|string| string.xrefs.iter().any(|xref| xref.function == addr)).collect::<Vec<_>>(),
            "incomingXrefs": index.to(addr).len(), "outgoingXrefs": outgoing.len(),
            "failures": index.failures,
        }))
    }

    /// Resolves an address (`0x1e0` or decimal), an exact name, or a
    /// case-insensitive substring that matches exactly one name.
    pub fn find(&self, target: &str) -> Result<&Function> {
        if let Some(addr) = crate::addr::parse(target) {
            return self.function(addr);
        }
        if let Some(project) = &self.project {
            for annotation in &project.annotations {
                if let crate::project::Target::Function { address } = annotation.target
                    && annotation.name.as_deref() == Some(target)
                {
                    return self.function(address);
                }
            }
        }
        let functions = self.image.functions.values();
        if let Some(found) = functions
            .clone()
            .filter(|f| names(f).any(|name| name == target))
            .min_by_key(|f| f.sources.contains(&loader::NameSource::Plt))
        {
            return Ok(found);
        }
        if self.image.format == loader::Format::MachO
            && let Some(found) = functions
                .clone()
                .find(|f| names(f).any(|name| name.strip_prefix('_') == Some(target)))
        {
            return Ok(found);
        }
        let needle = target.to_lowercase();
        let partial: Vec<&Function> = functions
            .filter(|f| {
                names(f).any(|name| name.to_lowercase().contains(&needle))
                    || self
                        .project
                        .as_ref()
                        .and_then(|project| {
                            project.get(&crate::project::Target::Function { address: f.addr })
                        })
                        .and_then(|entry| entry.name.as_ref())
                        .is_some_and(|name| name.to_lowercase().contains(&needle))
            })
            .collect();
        match partial.as_slice() {
            [] if self.image.stripped => Err(Error::StrippedFunctionName {
                name: target.to_owned(),
                entry: self.image.entry,
            }),
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
        let addr = self.image.code_address(addr);
        self.image
            .functions
            .get(&addr)
            .ok_or(Error::NoFunctionAt(addr))
    }

    pub fn analysis(&mut self, addr: u64, deadline: Option<Instant>) -> Result<&Analysis> {
        let addr = self.image.code_address(addr);
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

    pub(crate) fn annotated_ir(
        &mut self,
        addr: u64,
        deadline: Option<Instant>,
    ) -> Result<crate::ir::FunctionIr> {
        let mut ir = match self.analysis(addr, deadline) {
            Ok(analysis) => analysis.ir.clone(),
            Err(error) => return Err(error),
        };
        if let Some(project) = &self.project
            && let Err(error) = project.apply(&mut ir, &mut self.symbols.clone())
        {
            return Err(error);
        }
        Ok(ir)
    }

    fn identify_selected(
        &mut self,
        addr: u64,
        signatures: Option<&Database>,
        deadline: Option<Instant>,
    ) -> Result<Option<String>> {
        match signatures {
            Some(database) => match self.identify(database, deadline) {
                Ok(result) => Ok(result
                    .matches
                    .into_iter()
                    .find(|matched| matched.addr == addr)
                    .map(|matched| matched.matched)),
                Err(error) => Err(error),
            },
            None => Ok(self.image.functions.get(&addr).and_then(|function| {
                let Some(evidence) = function.library.as_ref() else {
                    return None;
                };
                (evidence.certainty == Certainty::Exact)
                    .then(|| evidence.candidates[0].name.clone())
            })),
        }
    }

    pub fn card(
        &mut self,
        addr: u64,
        budget: usize,
        signatures: Option<&Database>,
        deadline: Option<Instant>,
    ) -> Result<Card> {
        let addr = self.image.code_address(addr);
        if !self.image.functions.contains_key(&addr) {
            return Err(Error::NoFunctionAt(addr));
        }
        let identified = match self.identify_selected(addr, signatures, deadline) {
            Ok(identified) => identified,
            Err(error) => return Err(error),
        };
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
        if let Err(error) = self.refresh_project() {
            return Err(error);
        }
        let decoded_strings = if self.string_decoding {
            self.decoded_strings_at(addr, deadline).to_vec()
        } else {
            Vec::new()
        };
        let overrides = match self.project_signatures(deadline) {
            Ok(overrides) => overrides,
            Err(error) => return Err(error),
        };
        let addr = self.image.code_address(addr);
        if !self.image.functions.contains_key(&addr) {
            return Err(Error::NoFunctionAt(addr));
        }
        let identified = match self.identify_selected(addr, signatures, deadline) {
            Ok(identified) => identified,
            Err(error) => return Err(error),
        };
        if let Err(error) = self.prepare_structures(addr, deadline) {
            return Err(error);
        }
        let Some(function) = self.image.functions.get(&addr) else {
            return Err(Error::NoFunctionAt(addr));
        };
        match cached(&mut self.shared_analyses, &self.image, function, deadline) {
            Ok(Ok(_)) => {}
            Ok(Err(source)) => {
                return Err(Error::Lift {
                    addr,
                    source: source.clone(),
                });
            }
            Err(error) => return Err(error),
        };
        let Some(Ok(analysis)) = self.shared_analyses.get(&addr) else {
            unreachable!("successful analysis is cached");
        };
        self.render_analysis(
            analysis,
            &overrides,
            identified.as_deref(),
            &decoded_strings,
            deadline,
        )
    }

    fn render_analysis(
        &self,
        analysis: &Analysis,
        overrides: &std::collections::BTreeMap<u64, crate::ir::DeclaredSignature>,
        identified: Option<&str>,
        decoded_strings: &[crate::string_decoding::DecodedString],
        deadline: Option<Instant>,
    ) -> Result<render::Rendered> {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let addr = analysis.ir.addr;
        let mut ir = std::borrow::Cow::Borrowed(&analysis.ir);
        let mut symbols = std::borrow::Cow::Borrowed(&self.symbols);
        if !analysis.import_parameters.is_empty() {
            symbols
                .to_mut()
                .import_parameters
                .extend(analysis.import_parameters.clone());
        }
        if !analysis.unused_parameters.is_empty() {
            symbols
                .to_mut()
                .unused_parameters
                .extend(analysis.unused_parameters.clone());
        }
        if !analysis.callee_parameters.is_empty() {
            symbols
                .to_mut()
                .function_parameters
                .extend(analysis.callee_parameters.clone());
        }
        if !analysis.callee_structures.is_empty() {
            symbols
                .to_mut()
                .function_structures
                .extend(analysis.callee_structures.clone());
        }
        if let Some(project) = &self.project {
            if let Err(error) = project.apply(ir.to_mut(), symbols.to_mut()) {
                return Err(error);
            }
            for (&target, signature) in overrides {
                let statements = ir.blocks.iter().flat_map(|block| &block.stmts);
                for stmt in statements {
                    if let crate::ir::Stmt::Call {
                        target: Some(callee),
                        through: None,
                        args,
                        ..
                    } = stmt
                        && *callee == target
                        && args
                            .as_ref()
                            .is_none_or(|args| args.len() != signature.params.len())
                    {
                        return Err(crate::project::error(
                            "unsupported_signature",
                            format!("call to 0x{target:x} has an incompatible argument count"),
                        ));
                    }
                }
                ir.to_mut()
                    .callee_signatures
                    .insert(target, signature.clone());
            }
        }
        let api_hashes = crate::api_hashes::recover(&self.image, &ir, deadline);
        if api_hashes.iter().any(|hash| !hash.candidates.is_empty()) {
            crate::api_hashes::add_comments(&api_hashes, &ir, symbols.to_mut());
        }
        let mut rendered = render::render_with_dependencies(
            &ir,
            &analysis.references,
            &symbols,
            &self.data_ranges,
        );
        crate::string_decoding::annotate(&mut rendered.code, decoded_strings, &ir, &symbols);
        crate::api_hashes::annotate(&mut rendered.code, &api_hashes);
        if let Some(project) = &self.project
            && let Err(error) = project.validate_rendered_names(&ir, &rendered.code)
        {
            return Err(error);
        }
        rendered.code.insert_str(
            0,
            &render::seh::comments(&self.image.exception_handlers, addr),
        );
        rendered.code.insert_str(
            0,
            &render::seh::cpp_comments(&self.image.exception_regions, addr),
        );
        rendered
            .code
            .insert_str(0, &render::classes::comments(&ir, &self.image));
        if let Some(name) = identified {
            rendered.code.insert_str(
                0,
                &format!(
                    "/* identified: {}{} */\n",
                    name.replace("*/", "* /"),
                    self.image
                        .functions
                        .get(&addr)
                        .and_then(|function| function.library.as_ref())
                        .map(|evidence| format!(
                            "; {}; exact",
                            evidence
                                .candidates
                                .iter()
                                .map(|candidate| candidate.set.replace("*/", "* /"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                        .unwrap_or_default()
                ),
            );
        }
        if let Some(project) = &self.project {
            let declarations = match project.declarations() {
                Ok(text) => text,
                Err(error) => return Err(error),
            };
            rendered.code.insert_str(0, &project.comments(&ir));
            rendered.code.insert_str(0, &declarations);
        }
        Ok(rendered)
    }

    fn project_signatures(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<std::collections::BTreeMap<u64, crate::ir::DeclaredSignature>> {
        let Some(project) = self.project.clone() else {
            return Ok(Default::default());
        };
        let targets: std::collections::BTreeSet<_> = project
            .annotations
            .iter()
            .filter_map(|annotation| match annotation.target {
                crate::project::Target::Parameter { function, .. }
                    if annotation.c_type.is_some() =>
                {
                    Some(function)
                }
                crate::project::Target::Signature { function } => Some(function),
                _ => None,
            })
            .collect();
        let mut signatures = std::collections::BTreeMap::new();
        for target in targets {
            let mut ir = match self.analysis(target, deadline) {
                Ok(analysis) => analysis.ir.clone(),
                Err(error) => return Err(error),
            };
            if let Err(error) = project.apply(&mut ir, &mut self.symbols.clone()) {
                return Err(error);
            }
            let parameters = match crate::project::scalar_parameters(&ir) {
                Ok(parameters) => parameters,
                Err(error) => return Err(error),
            };
            signatures.insert(
                target,
                crate::ir::DeclaredSignature {
                    params: parameters,
                    ret: ir.ret_type.clone(),
                    variadic: false,
                    abi: Err(crate::ir::AbiIssue::UnsupportedType),
                },
            );
        }
        Ok(signatures)
    }

    fn prepare_structures(&mut self, addr: u64, deadline: Option<Instant>) -> Result<()> {
        crate::timing::scope!("service::prepare_structures");
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
            Ok(result) => result,
            Err(error) => return Err(error),
        };
        let Ok(root_analysis) = root else {
            self.shared_analyses.insert(addr, root.clone());
            return Ok(());
        };
        let neighbors = batch::neighbors(&self.image, root_analysis);
        let declaration_callers = declarations::callers(&self.image, root_analysis);
        let mut functions = vec![root_analysis.clone()];
        for neighbor in neighbors {
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
        for address in declaration_callers {
            if functions.iter().any(|analysis| analysis.ir.addr == address) {
                continue;
            }
            let Some(function) = self.image.functions.get(&address) else {
                continue;
            };
            match cached(&mut self.analyses, &self.image, function, deadline) {
                Ok(Ok(analysis)) => functions.push(analysis.clone()),
                Ok(Err(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        batch::share_parameters(&mut functions, self.image.go);
        declarations::recover(&self.image, &mut functions);
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
        let addr = self.image.code_address(addr);
        let function = match self.function(addr) {
            Ok(function) => function,
            Err(error) => return Err(error),
        };
        let len = function.size.unwrap_or(analysis::UNKNOWN_SIZE);
        disasm::listing(&self.image, addr, len, max_lines)
            .map_err(|source| Error::Lift { addr, source })
    }

    /// Builds a similarity index once, reusing cached function analyses.
    /// Interrupted builds are discarded. Project and signature changes invalidate it.
    ///
    /// # Panics
    ///
    /// Panics if a successful index build leaves the similarity cache empty.
    pub fn similarity_index(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<&crate::similar::Index> {
        if let Err(error) = self.refresh_project() {
            return Err(error);
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if self.similarity.is_none() {
            let index = match crate::similar::Index::build(self, deadline) {
                Ok(index) => index,
                Err(error) => return Err(error),
            };
            self.similarity = Some(index);
        }
        Ok(self
            .similarity
            .as_ref()
            .expect("successful build inserted the index"))
    }

    /// Returns similar functions in this binary, excluding the query itself.
    pub fn similar(
        &mut self,
        addr: u64,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<crate::similar::Report> {
        let addr = self.image.code_address(addr);
        if let Err(error) = self.analysis(addr, deadline) {
            return Err(error);
        }
        let index = match self.similarity_index(deadline) {
            Ok(index) => index,
            Err(error) => return Err(error),
        };
        let Some(features) = index.features(addr) else {
            return Err(Error::NoFunctionAt(addr));
        };
        index.search(&features, Some(addr), limit, deadline)
    }

    pub fn shape_hash(&mut self, addr: u64, deadline: Option<Instant>) -> Result<String> {
        Ok(sigs::shape_hash(&self.analysis(addr, deadline)?.ir))
    }

    /// Signatures of the named functions; Err once `deadline` passes.
    pub fn build_signatures(&mut self, deadline: Option<Instant>) -> Result<SignatureBuild> {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let database = if self.options.arch.is_some() || self.options.raw.is_some() {
            let entries = match sigs::image_entries(&self.image, deadline) {
                Ok(entries) => entries,
                Err(error) => return Err(error),
            };
            let mut database = Database::new(entries);
            database.sources.push(
                self.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            );
            database
        } else {
            match sigs::build(&self.path, deadline) {
                Ok(database) => database,
                Err(error) => return Err(error),
            }
        };
        Ok(SignatureBuild {
            database,
            failures: Vec::new(),
        })
    }

    pub(crate) fn symbolic_identifications(&self) -> Result<&BTreeMap<u64, sigs::Evidence>> {
        if let Some(matches) = self.symbolic_identifications.get() {
            return Ok(matches);
        }
        let database =
            if self.signature_options.defaults && self.signature_database.entries.is_empty() {
                sigs::bundled_for_isa(self.image.isa)
            } else {
                self.signature_database.as_ref()
            };
        let matches: BTreeMap<u64, sigs::Evidence> =
            match sigs::identify(&self.image, database, None, MatchScope::All) {
                Ok(matches) => matches.into_iter().collect(),
                Err(error) => return Err(error),
            };
        let _ = self.symbolic_identifications.set(matches);
        Ok(self
            .symbolic_identifications
            .get()
            .expect("identifications were initialized"))
    }

    /// Matches instruction signatures and names unnamed functions; Err once `deadline` passes.
    pub fn identify(
        &mut self,
        database: &Database,
        deadline: Option<Instant>,
    ) -> Result<Identification> {
        self.cache = None;
        self.similarity = None;
        let mut combined =
            if self.signature_options.defaults && self.signature_database.entries.is_empty() {
                sigs::bundled_for_isa(self.image.isa).clone()
            } else {
                self.signature_database.as_ref().clone()
            };
        let source = if database.sources.is_empty() {
            "user database".to_owned()
        } else {
            database.sources.join(", ")
        };
        for entry in &database.entries {
            let mut entry = entry.clone();
            if entry.set.is_none() {
                entry.set = Some(source.clone());
            }
            combined.entries.push(entry);
        }
        combined.sources.extend(database.sources.clone());
        let result = match self.apply_signatures(&combined, deadline, MatchScope::All) {
            Ok(result) => result,
            Err(error) => return Err(error),
        };
        self.signature_database = Cow::Owned(combined);
        Ok(result)
    }

    fn apply_signatures(
        &mut self,
        database: &Database,
        deadline: Option<Instant>,
        scope: MatchScope,
    ) -> Result<Identification> {
        let _ = self.symbolic_identifications.take();
        crate::timing::scope!("service::apply_signatures");
        let arm_modes = self.image.arm_modes.clone();
        let discovered = match sigs::discover_arm32(&mut self.image, database, deadline) {
            Ok(discovered) => discovered,
            Err(error) => return Err(error),
        };
        let identified = match sigs::identify(&self.image, database, deadline, scope) {
            Ok(identified) => identified,
            Err(error) => {
                for address in discovered {
                    self.image.functions.remove(&address);
                }
                self.image.arm_modes = arm_modes;
                return Err(error);
            }
        };
        let mut matches = Vec::new();
        let mut changed = !discovered.is_empty();
        let mut candidates = Vec::new();
        for function in self.image.functions.values_mut() {
            if function.sources.contains(&loader::NameSource::Signature)
                && function
                    .library
                    .as_ref()
                    .is_some_and(|evidence| evidence.certainty == Certainty::Exact)
            {
                function.name = None;
                changed = true;
            }
            function.library = None;
        }
        for (addr, evidence) in identified {
            let Some(function) = self.image.functions.get_mut(&addr) else {
                continue;
            };
            function.library = Some(Box::new(evidence.clone()));
            if evidence.certainty != Certainty::Exact {
                candidates.push((addr, evidence));
                continue;
            }
            let matched = evidence.candidates[0].name.clone();
            let current = function.name.clone();
            matches.push(Match {
                addr,
                size: function.size,
                current: current.clone(),
                matched: matched.clone(),
                evidence,
            });
            if current.is_none() {
                function.name = Some(matched);
                if !function.sources.contains(&loader::NameSource::Signature) {
                    function.sources.push(loader::NameSource::Signature);
                }
                changed = true;
            }
        }
        if changed {
            self.image.summaries = Default::default();
            self.navigation = None;
            self.similarity = None;
            self.symbols = render::callee_names(&self.image);
            self.analyses.clear();
            self.shared_analyses.clear();
        }
        Ok(Identification {
            matches,
            candidates,
            failures: Vec::new(),
        })
    }
}

fn cached<'a>(
    analyses: &'a mut HashMap<u64, Result<Analysis, LiftError>>,
    image: &Image,
    function: &Function,
    deadline: Option<Instant>,
) -> Result<&'a Result<Analysis, LiftError>> {
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    if let Entry::Vacant(entry) = analyses.entry(function.addr) {
        let analyzed = match analysis::analyze(image, function, deadline) {
            Ok(analysis) => Ok(analysis),
            Err(Error::Lift { source, .. }) => Err(source),
            Err(error) => return Err(error),
        };
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
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

fn modified(path: &Path) -> Result<SystemTime> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })
}

impl Drop for Binary {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        if let Some(cache) = &mut self.cache {
            cache.write(&self.image, self.navigation.as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CType, Expr, FunctionIr, Stmt};
    use crate::loader::Isa;

    fn fixture(name: &str) -> Binary {
        Binary::open_input(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
            None,
            &loader::OpenOptions {
                cache: Some(CacheLocation::Enabled(false)),
                ..loader::OpenOptions::default()
            },
        )
        .expect("fixture loads")
    }

    #[test]
    fn similarity_index_reuses_analyses_and_discards_interrupted_builds() {
        let mut binary = fixture("arm64.o");
        assert!(matches!(
            binary.similarity_index(Some(Instant::now())),
            Err(Error::TimedOut)
        ));
        assert!(binary.similarity.is_none());
        let addr = binary.find("pair_sum").unwrap().addr;
        let first = serde_json::to_value(binary.similar(addr, 3, None).unwrap()).unwrap();
        let count = binary.analyses.len();
        let shared_count = binary.shared_analyses.len();
        let original = binary.similarity.as_ref().unwrap() as *const _;
        let second = serde_json::to_value(binary.similar(addr, 3, None).unwrap()).unwrap();
        assert_eq!(original, binary.similarity.as_ref().unwrap() as *const _);
        assert_eq!(first, second);
        assert_eq!(count, binary.analyses.len());
        assert_eq!(shared_count, binary.shared_analyses.len());
        binary.identify(&Database::new(Vec::new()), None).unwrap();
        assert!(binary.similarity.is_none());
    }

    #[test]
    fn similarity_index_keeps_candidates_after_one_analysis_fails() {
        let mut binary = fixture("arm64.o");
        let failed = binary.find("pair_sum").unwrap().addr;
        binary
            .shared_analyses
            .insert(failed, Err(LiftError::Unreadable));
        let index = binary.similarity_index(None).unwrap();
        assert!(index.features(failed).is_none());
        let addr = binary.find("sum3").unwrap().addr;
        let report = binary.similar(addr, usize::MAX, None).unwrap();
        assert!(!report.matches.is_empty());
        assert!(
            report
                .matches
                .iter()
                .all(|candidate| candidate.function.addr != failed)
        );
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.function == failed)
        );
        assert!(matches!(
            binary.similar(failed, 1, None),
            Err(Error::Lift { .. })
        ));
    }

    #[test]
    fn exact_names_prefer_definitions_over_linkage_stubs() {
        let mut binary = fixture("arm64.o");
        let definition = binary.find("pair_sum").unwrap().clone();
        let mut stub = definition.clone();
        stub.addr = definition.addr.saturating_sub(1);
        stub.sources = vec![loader::NameSource::Plt];
        binary.image.functions.insert(stub.addr, stub.clone());
        assert_eq!(binary.find("pair_sum").unwrap().addr, definition.addr);
        binary.image.functions.remove(&definition.addr);
        assert_eq!(binary.find("pair_sum").unwrap().addr, stub.addr);
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
    fn default_signature_databases_are_shared_between_binaries() {
        let first = fixture("cpp_virtual_x64_stripped.elf");
        let second = fixture("cpp_virtual_x64_stripped.elf");
        assert!(matches!(first.signature_database, Cow::Borrowed(_)));
        assert!(std::ptr::eq(
            first.signature_database.as_ref(),
            second.signature_database.as_ref(),
        ));
    }

    #[test]
    fn symbolic_identification_checks_named_functions_with_default_signatures() {
        use std::io::Read as _;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/library_signatures/xxhash.x86_64.O2.elf.gz");
        let compressed = std::fs::read(path).expect("read library fixture");
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut bytes = Vec::new();
        decoder
            .read_to_end(&mut bytes)
            .expect("decode library fixture");
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("symbolic-signatures-{}.elf", std::process::id()));
        std::fs::write(&path, bytes).expect("write library fixture");
        let mut binary = Binary::open_with_signatures(
            &path,
            None,
            None,
            &SignatureOptions {
                defaults: false,
                files: Vec::new(),
            },
        )
        .expect("open named library fixture");
        binary.signature_options.defaults = true;
        assert!(binary.signature_database.entries.is_empty());
        let address = binary.find_address("XXH32").expect("named function");
        let matches = binary
            .symbolic_identifications()
            .expect("identify functions");
        let evidence = matches
            .get(&address)
            .expect("named function identification");
        assert_eq!(evidence.certainty, Certainty::Exact);
        assert!(
            evidence
                .candidates
                .iter()
                .any(|candidate| candidate.name == "XXH32")
        );
        std::fs::remove_file(path).expect("remove library fixture");
    }

    #[test]
    fn short_unnamed_functions_do_not_load_default_signatures() {
        let mut binary = fixture("pe64.exe");
        assert!(binary.signature_database.entries.is_empty());
        let mut eager = fixture("pe64.exe");
        let result = eager
            .apply_signatures(
                sigs::bundled_for_isa(eager.image.isa),
                None,
                MatchScope::Unnamed,
            )
            .unwrap();
        assert!(result.matches.is_empty());
        assert!(result.candidates.is_empty());
        for function in binary.functions() {
            assert_eq!(
                binary.decompile(function.addr, None, None).unwrap(),
                eager.decompile(function.addr, None, None).unwrap(),
            );
        }
    }

    #[test]
    fn single_function_analysis_is_bounded_and_reused() {
        let mut binary = fixture("go_probe");
        assert!(
            binary
                .image
                .functions
                .values()
                .all(|function| function.name.is_some()
                    || function.sources == [loader::NameSource::Call])
        );
        assert!(
            binary
                .image
                .functions
                .values()
                .all(|function| function.library.is_none())
        );
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
    fn decompile_keeps_dependencies_from_cached_analysis() {
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
        binary.analyses.insert(
            addr,
            Ok(Analysis {
                unused_parameters: Default::default(),
                import_parameters: Default::default(),
                callee_parameters: Default::default(),
                callee_structures: Default::default(),
                ir,
                references: Vec::new(),
                simplification: Default::default(),
            }),
        );
        let rendered = binary
            .decompile_with_dependencies(addr, None, None)
            .expect("typed decompilation");
        assert_eq!(rendered.segment_bases.len(), 1);
        let dependency = &rendered.segment_bases[0];
        assert_eq!(dependency.segment, render::SegmentBase::Fs);
        assert!(
            rendered
                .code
                .contains(&format!("uint64_t {}(void);", dependency.provider))
        );
        assert_eq!(binary.decompile(addr, None, None).unwrap(), rendered.code);
    }
}
