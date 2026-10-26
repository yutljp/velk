use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use crate::analysis::{self, Analysis};
use crate::card::{self, Card};
use crate::deadline::passed;
use crate::error::{Error, LiftError, Result};
use crate::loader::{self, Architecture, Function, Image};
use crate::sigs::{self, Database};
use crate::{disasm, render};

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

/// Loaded binaries, kept across calls so repeated queries reuse the analysis.
#[derive(Default)]
pub struct Session {
    binaries: HashMap<(PathBuf, Option<Architecture>), Binary>,
}

impl Session {
    pub(crate) fn open_with_options(
        &mut self,
        path: &Path,
        project: Option<&Path>,
        arch: Option<Architecture>,
    ) -> Result<&mut Binary> {
        let path = match canonicalize(path) {
            Ok(path) => path,
            Err(error) => return Err(error),
        };
        if let Some(project) = project {
            let reuse = self
                .binaries
                .get(&(path.clone(), arch))
                .is_some_and(|binary| binary.project_path == project);
            if !reuse {
                let binary = match Binary::open_with_options(&path, Some(project), arch) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                self.binaries.insert((path.clone(), arch), binary);
            }
        }
        self.open_arch(&path, arch)
    }

    /// Loads the file, or returns the cached binary when the file is unchanged.
    pub fn open(&mut self, path: &Path) -> Result<&mut Binary> {
        self.open_arch(path, None)
    }

    /// Opens and caches a particular architecture independently.
    pub fn open_arch(&mut self, path: &Path, arch: Option<Architecture>) -> Result<&mut Binary> {
        let path = match canonicalize(path) {
            Ok(path) => path,
            Err(error) => return Err(error),
        };
        let modified = match modified(&path) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        match self.binaries.entry((path, arch)) {
            Entry::Occupied(entry) if entry.get().modified == modified => {
                let binary = entry.into_mut();
                match binary.refresh_project() {
                    Ok(()) => Ok(binary),
                    Err(error) => Err(error),
                }
            }
            Entry::Occupied(mut entry) => {
                let binary = match Binary::load_project(
                    &entry.key().0,
                    modified,
                    Some(&entry.get().project_path),
                    None,
                    arch,
                ) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                entry.insert(binary);
                Ok(entry.into_mut())
            }
            Entry::Vacant(entry) => {
                let binary = match Binary::load_project(&entry.key().0, modified, None, None, arch)
                {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                Ok(entry.insert(binary))
            }
        }
    }
}

pub struct Binary {
    navigation: Option<crate::xrefs::Index>,
    path: PathBuf,
    modified: SystemTime,
    project: Option<crate::project::Project>,
    project_path: PathBuf,
    pub(crate) project_digest: Option<String>,
    image: Image,
    arch: Option<Architecture>,
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
        let modified = match modified(path) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Self::load_project(path, modified, project, None, arch)
    }

    fn load_project(
        path: &Path,
        modified: SystemTime,
        project_path: Option<&Path>,
        mut project_digest: Option<String>,
        arch: Option<Architecture>,
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
        let mut image = match loader::load_with_arch(&path, arch) {
            Ok(image) => image,
            Err(error) => return Err(error),
        };
        crate::analysis::absorb_jump_table_cases(&mut image);
        if let Some(project) = &project
            && let Err(error) = project.classify(&mut image)
        {
            return Err(error);
        }
        Ok(Self {
            navigation: None,
            path: path.to_owned(),
            modified,
            project,
            project_path,
            project_digest,
            symbols: render::callee_names(&image),
            data_ranges: render::data_ranges(&image),
            image,
            arch,
            analyses: HashMap::new(),
            shared_analyses: HashMap::new(),
        })
    }

    fn refresh_project(&mut self) -> Result<()> {
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
                self.arch,
            ) {
                Ok(binary) => *self = binary,
                Err(error) => return Err(error),
            }
        }
        Ok(())
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
        if let [addr] = matches.iter().copied().collect::<Vec<_>>().as_slice() {
            return Ok(*addr);
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

    pub fn summary(&mut self, addr: u64, deadline: Option<Instant>) -> Result<serde_json::Value> {
        let mut function = match self.function(addr) {
            Ok(function) => function.clone(),
            Err(error) => return Err(error),
        };
        function.name = self.function_name(function.addr).map(str::to_owned);
        let ir = match self.analysis(addr, deadline) {
            Ok(analysis) => &analysis.ir,
            Err(error) => return Err(error),
        };
        let signature = serde_json::json!({
            "return": ir.ret_type.to_string(),
            "params": ir.params.iter().map(|p| serde_json::json!({"name": p.name, "type": p.ty.to_string()})).collect::<Vec<_>>(),
        });
        let imports: std::collections::BTreeMap<_, _> = self
            .image
            .imports
            .iter()
            .map(|(addr, name)| (*addr, name.clone()))
            .chain(
                self.image
                    .functions
                    .values()
                    .filter(|f| f.sources.contains(&loader::NameSource::Plt))
                    .filter_map(|f| f.name.clone().map(|name| (f.addr, name))),
            )
            .collect();
        let index = match self.navigation(deadline) {
            Ok(index) => index,
            Err(error) => return Err(error),
        };
        let outgoing = index.from(addr);
        Ok(serde_json::json!({
            "addr": crate::addr::format(addr), "name": function.name, "size": function.size,
            "signature": signature,
            "callees": index.graph(addr, false, 1).into_iter().map(crate::addr::format).collect::<Vec<_>>(),
            "imports": outgoing.iter().filter_map(|xref| imports.get(&xref.target))
                .collect::<std::collections::BTreeSet<_>>(),
            "strings": index.strings().iter().filter(|s| s.xrefs.iter().any(|xref| xref.function == addr)).collect::<Vec<_>>(),
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
            .filter(|f| {
                names(f).any(|n| n.to_lowercase().contains(&needle))
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
            None => Ok(None),
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
        let mut ir = std::borrow::Cow::Borrowed(&analysis.ir);
        let mut symbols = std::borrow::Cow::Borrowed(&self.symbols);
        if let Some(project) = &self.project {
            if let Err(error) = project.apply(ir.to_mut(), symbols.to_mut()) {
                return Err(error);
            }
            for (target, signature) in overrides {
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
                ir.to_mut().callee_signatures.insert(target, signature);
            }
        }
        let mut rendered = render::render_with_dependencies(
            &ir,
            &analysis.references,
            &symbols,
            &self.data_ranges,
        );
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
                &format!("/* identified: {} */\n", name.replace("*/", "* /")),
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
        let addr = self.image.code_address(addr);
        let function = match self.function(addr) {
            Ok(function) => function,
            Err(error) => return Err(error),
        };
        let len = function.size.unwrap_or(analysis::UNKNOWN_SIZE);
        disasm::listing(&self.image, addr, len, max_lines)
            .map_err(|source| Error::Lift { addr, source })
    }

    pub fn shape_hash(&mut self, addr: u64, deadline: Option<Instant>) -> Result<String> {
        Ok(sigs::shape_hash(&self.analysis(addr, deadline)?.ir))
    }

    /// Signatures of the named functions; Err once `deadline` passes.
    pub fn build_signatures(&mut self, deadline: Option<Instant>) -> Result<SignatureBuild> {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let database = if self.arch.is_some() {
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

    /// Matches instruction signatures and names unnamed functions; Err once `deadline` passes.
    pub fn identify(
        &mut self,
        database: &Database,
        deadline: Option<Instant>,
    ) -> Result<Identification> {
        let identified = match sigs::identify(&self.image, database, deadline) {
            Ok(identified) => identified,
            Err(error) => return Err(error),
        };
        let mut matches = Vec::new();
        let mut changed = false;
        for (addr, matched) in identified {
            let Some(function) = self.image.functions.get_mut(&addr) else {
                continue;
            };
            let current = function.name.clone();
            matches.push(Match {
                addr,
                size: function.size,
                current: current.clone(),
                matched: matched.clone(),
            });
            if current.is_none() {
                function.name = Some(matched);
                function.sources.push(loader::NameSource::Signature);
                changed = true;
            }
        }
        if changed {
            self.image.summaries = Default::default();
            self.navigation = None;
            self.symbols = render::callee_names(&self.image);
            self.analyses.clear();
            self.shared_analyses.clear();
        }
        Ok(Identification {
            matches,
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
                ir,
                references: Vec::new(),
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
