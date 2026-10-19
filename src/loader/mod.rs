mod discover;
pub mod dwarf;
pub mod go;
mod symbols;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use std::fmt;
use std::path::Path;

use crate::loader::discover::aarch64_prologues;
use crate::loader::discover::estimate_sizes;
use crate::loader::discover::is_aarch64_padding;
use crate::loader::discover::read_word;
use crate::loader::discover::x86_prologues;
use crate::loader::symbols::demangle;
use object::read::{File as ObjFile, Object, ObjectSection, ObjectSymbol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Elf,
    Pe,
    Coff,
    MachO,
    Other,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Elf => "elf",
            Format::Pe => "pe",
            Format::Coff => "coff",
            Format::MachO => "macho",
            Format::Other => "other",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Isa {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    AArch64,
    #[serde(rename = "unsupported")]
    Unsupported,
}

impl fmt::Display for Isa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Isa::X86_64 => "x86_64",
            Isa::AArch64 => "aarch64",
            Isa::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    #[serde(rename = "addr", serialize_with = "crate::addr::serialize")]
    pub vaddr: u64,
    pub size: u64,
    #[serde(skip)]
    pub file_offset: Option<u64>,
    pub executable: bool,
}

/// Where a function's start, name or size was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NameSource {
    Symtab,
    Dynamic,
    Entry,
    Pclntab,
    Dwarf,
    Prologue,
}

impl fmt::Display for NameSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameSource::Symtab => "symtab",
            NameSource::Dynamic => "dynamic",
            NameSource::Entry => "entry",
            NameSource::Pclntab => "pclntab",
            NameSource::Dwarf => "dwarf",
            NameSource::Prologue => "prologue",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub addr: u64,
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub size_estimated: bool,
    pub name: Option<String>,
    /// Further names other symbols give the same address.
    pub aliases: Vec<String>,
    #[serde(rename = "nameSources")]
    pub sources: Vec<NameSource>,
}

impl Function {
    fn merge(&mut self, name: Option<String>, size: Option<u64>, source: NameSource) {
        if let Some(name) = name {
            let name = demangle(&name).unwrap_or(name);
            match &self.name {
                None => self.name = Some(name),
                Some(current) if *current != name && !self.aliases.contains(&name) => {
                    self.aliases.push(name)
                }
                Some(_) => {}
            }
        }
        if self.size.is_none() {
            self.size = size;
        }
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }
}

#[derive(Debug)]
pub struct Image {
    pub format: Format,
    pub isa: Isa,
    pub entry: Option<u64>,
    bytes: Vec<u8>,
    pub sections: Vec<Section>,
    pub functions: BTreeMap<u64, Function>,
    /// Branch relocations the object left unapplied: instruction address to
    /// the symbol address it calls.
    pub relocations: BTreeMap<u64, u64>,
    /// The image carries a Go pclntab, so its functions follow the Go ABI.
    pub go: bool,
}

impl Image {
    /// An image holding only `code`, mapped executable at `addr`.
    #[cfg(test)]
    pub(crate) fn from_code(isa: Isa, addr: u64, code: Vec<u8>) -> Self {
        Self {
            format: Format::Elf,
            isa,
            entry: None,
            sections: vec![Section {
                name: ".text".to_owned(),
                vaddr: addr,
                size: code.len() as u64,
                file_offset: Some(0),
                executable: true,
            }],
            bytes: code,
            functions: BTreeMap::new(),
            relocations: BTreeMap::new(),
            go: false,
        }
    }

    pub fn section_at(&self, vaddr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| vaddr >= s.vaddr && vaddr < s.vaddr.saturating_add(s.size))
            .min_by_key(|s| (!s.executable, s.size))
    }

    pub fn virtual_offset(&self, vaddr: u64) -> Option<u64> {
        let section = self.section_at(vaddr)?;
        let offset = section.file_offset?.checked_add(vaddr - section.vaddr)?;
        (offset < self.bytes.len() as u64).then_some(offset)
    }

    /// The addresses of branch instructions the linker has not bound yet.
    fn relocated_branches(&self) -> std::collections::HashSet<u64> {
        self.relocations.keys().copied().collect()
    }

    /// Adds function starts recognized by their prologues, which follow the
    /// padding that ends the previous function.
    fn scan_prologues(&mut self) {
        let mut found: Vec<u64> = Vec::new();
        for section in &self.sections {
            if !section.executable {
                continue;
            }
            let Some(bytes) = self.read_vaddr(section.vaddr, section.size) else {
                continue;
            };
            let mut starts = match self.isa {
                crate::loader::Isa::AArch64 => {
                    aarch64_prologues(bytes, section.vaddr, &self.relocated_branches())
                }
                crate::loader::Isa::X86_64 => x86_prologues(bytes, section.vaddr),
                crate::loader::Isa::Unsupported => continue,
            };
            // Code begins with a function unless padding opens the section.
            let opens = match self.isa {
                crate::loader::Isa::AArch64 => {
                    read_word(bytes, 0).is_some_and(|word| !is_aarch64_padding(word))
                }
                _ => bytes
                    .first()
                    .is_some_and(|byte| !matches!(byte, 0x90 | 0xcc | 0x00)),
            };
            if opens {
                starts.insert(0, section.vaddr);
            }
            found.extend(starts);
        }
        for address in found {
            // An address inside a function of known size is not a new start;
            // an estimated size may be too long to trust.
            if self
                .functions
                .range(..=address)
                .next_back()
                .is_some_and(|(start, function)| {
                    let size = function.size.unwrap_or(0);
                    *start != address
                        && !function.size_estimated
                        && size != 0
                        && address < start.saturating_add(size)
                })
            {
                continue;
            }
            upsert(
                &mut self.functions,
                address,
                None,
                None,
                NameSource::Prologue,
            );
        }
    }

    /// Drops functions outside executable sections, such as data symbols.
    fn retain_code_functions(&mut self) {
        self.functions.retain(|address, _| {
            self.sections.iter().any(|section| {
                section.executable
                    && *address >= section.vaddr
                    && *address < section.vaddr.saturating_add(section.size)
            })
        });
    }

    pub fn section_data(&self, name: &str) -> Option<&[u8]> {
        let section = self.sections.iter().find(|section| section.name == name)?;
        let start = section.file_offset?;
        let end = start.checked_add(section.size)?;
        self.bytes.get(start as usize..end as usize)
    }

    pub fn read(&self, offset: u64, len: u64) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        (end <= self.bytes.len() as u64).then(|| &self.bytes[offset as usize..end as usize])
    }

    pub fn read_vaddr(&self, vaddr: u64, len: u64) -> Option<&[u8]> {
        self.virtual_offset(vaddr)
            .and_then(|offset| self.read(offset, len))
            .or_else(|| self.read(vaddr, len))
    }

    fn add_go_functions(&mut self) {
        let mut discovered = crate::loader::go::functions(self);
        self.go = !discovered.is_empty();
        discovered.sort_by_key(|function| function.addr);
        discovered.dedup_by_key(|function| function.addr);
        let addresses: Vec<u64> = discovered.iter().map(|function| function.addr).collect();
        for (index, function) in discovered.into_iter().enumerate() {
            let size = addresses
                .get(index + 1)
                .map(|next| next.saturating_sub(function.addr))
                .filter(|size| *size > 0 && *size <= 0x4000);
            upsert(
                &mut self.functions,
                function.addr,
                Some(function.name),
                size,
                NameSource::Pclntab,
            );
        }
    }

    fn add_dwarf_functions(&mut self) {
        let discovered = crate::loader::dwarf::functions(self);
        for function in discovered {
            if let Some(existing) = self.functions.get_mut(&function.addr)
                && existing.size_estimated
            {
                existing.size = None;
                existing.size_estimated = false;
            }
            upsert(
                &mut self.functions,
                function.addr,
                Some(function.name),
                Some(function.size),
                NameSource::Dwarf,
            );
        }
    }
}

fn isa_of(arch: object::Architecture) -> Isa {
    match arch {
        object::Architecture::X86_64 => Isa::X86_64,
        object::Architecture::Aarch64 => Isa::AArch64,
        _ => Isa::Unsupported,
    }
}

fn format_of(kind: object::FileKind) -> Format {
    use object::FileKind as K;
    match kind {
        K::Elf32 | K::Elf64 => Format::Elf,
        K::Pe32 | K::Pe64 => Format::Pe,
        K::Coff | K::CoffBig => Format::Coff,
        K::MachO32 | K::MachO64 | K::MachOFat32 | K::MachOFat64 => Format::MachO,
        _ => Format::Other,
    }
}

fn is_executable(kind: object::SectionKind) -> bool {
    matches!(kind, object::SectionKind::Text)
}

fn upsert(
    functions: &mut BTreeMap<u64, Function>,
    addr: u64,
    name: Option<String>,
    size: Option<u64>,
    source: NameSource,
) {
    functions
        .entry(addr)
        .or_insert_with(|| Function {
            addr,
            size: None,
            size_estimated: false,
            name: None,
            aliases: Vec::new(),
            sources: Vec::new(),
        })
        .merge(name, size, source);
}

fn symbol_name<'data, S: ObjectSymbol<'data>>(sym: &S) -> Option<String> {
    sym.name().ok().filter(|n| !n.is_empty()).map(str::to_owned)
}

pub fn load(path: &Path) -> Result<Image> {
    let bytes = std::fs::read(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    let object_error = |source| Error::Object {
        path: path.to_owned(),
        source,
    };
    let kind = object::FileKind::parse(&bytes[..]).map_err(object_error)?;
    let file = ObjFile::parse(&bytes[..]).map_err(object_error)?;

    let mut sections = Vec::new();
    for section in file.sections() {
        sections.push(Section {
            name: section.name().unwrap_or("<unnamed>").to_owned(),
            vaddr: section.address(),
            size: section.size(),
            file_offset: section.file_range().map(|(offset, _)| offset),
            executable: is_executable(section.kind()),
        });
    }

    // Relocatable objects leave branch displacements unresolved; the targets
    // are only in the relocations.
    let mut relocations = BTreeMap::new();
    for section in file.sections() {
        // Data sections such as `.eh_frame` also hold PC-relative relocations;
        // since every section of an object starts at zero, their offsets would
        // collide with instruction addresses.
        if !is_executable(section.kind()) {
            continue;
        }
        let base = section.address();
        for (offset, relocation) in section.relocations() {
            if !matches!(
                relocation.kind(),
                object::RelocationKind::Relative | object::RelocationKind::PltRelative
            ) {
                continue;
            }
            let object::RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Ok(symbol) = file.symbol_by_index(index) else {
                continue;
            };
            if symbol.is_undefined() {
                continue;
            }
            let address = if isa_of(file.architecture()) == Isa::X86_64 {
                // x86-64 relocations point at the rel32 field, one byte after
                // the E8/E9 opcode; key them by instruction address instead.
                let Some((section_file_offset, _)) = section.file_range() else {
                    continue;
                };
                let Some(field_offset) =
                    usize::try_from(section_file_offset).ok().and_then(|base| {
                        usize::try_from(offset)
                            .ok()
                            .and_then(|offset| base.checked_add(offset))
                    })
                else {
                    continue;
                };
                let Some(opcode_offset) = field_offset.checked_sub(1) else {
                    continue;
                };
                if !matches!(bytes.get(opcode_offset), Some(0xe8 | 0xe9)) {
                    continue;
                }
                base.wrapping_add(offset.saturating_sub(1))
            } else {
                base.wrapping_add(offset)
            };
            relocations.insert(address, symbol.address());
        }
    }

    let mut functions = BTreeMap::new();
    for sym in file.symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        upsert(
            &mut functions,
            sym.address(),
            symbol_name(&sym),
            (sym.size() > 0).then_some(sym.size()),
            NameSource::Symtab,
        );
    }
    for sym in file.dynamic_symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        upsert(
            &mut functions,
            sym.address(),
            symbol_name(&sym),
            (sym.size() > 0).then_some(sym.size()),
            NameSource::Dynamic,
        );
    }

    if let Ok(exports) = file.exports() {
        for export in exports.flatten() {
            let object::read::ExportTarget::Address { address } = export.target() else {
                continue;
            };
            let name = match export.name() {
                object::read::NameOrOrdinal::Name(bytes) => {
                    Some(String::from_utf8_lossy(bytes).into_owned())
                }
                object::read::NameOrOrdinal::Ordinal(_) => None,
            };
            upsert(&mut functions, address, name, None, NameSource::Dynamic);
        }
    }

    let entry = (file.entry() != 0).then(|| file.entry());
    if let Some(entry) = entry {
        upsert(&mut functions, entry, None, None, NameSource::Entry);
    }

    functions.retain(|address, _| {
        sections.iter().any(|section| {
            section.executable
                && *address >= section.vaddr
                && *address < section.vaddr.saturating_add(section.size)
        })
    });
    estimate_sizes(&sections, &mut functions);

    let mut image = Image {
        format: format_of(kind),
        isa: isa_of(file.architecture()),
        entry,
        bytes,
        sections,
        functions,
        relocations,
        go: false,
    };
    image.add_go_functions();
    image.add_dwarf_functions();
    // Only an image with nothing but an entry point needs the prologue scan;
    // symbols, debug info or a Go pclntab already list the functions.
    if image.functions.values().all(|function| {
        function
            .sources
            .iter()
            .all(|source| *source == NameSource::Entry)
    }) {
        image.scan_prologues();
    }
    image.retain_code_functions();
    // An estimated size may cover starts found later; cut it at the next start.
    let starts: Vec<u64> = image.functions.keys().copied().collect();
    for function in image.functions.values_mut() {
        if !function.size_estimated {
            continue;
        }
        let end = function.addr.saturating_add(function.size.unwrap_or(0));
        if let Some(next) = starts
            .iter()
            .copied()
            .find(|start| *start > function.addr && *start < end)
        {
            function.size = Some(next - function.addr);
        }
    }
    estimate_sizes(&image.sections, &mut image.functions);
    Ok(image)
}
