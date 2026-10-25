mod codeview;
mod discover;
pub mod dwarf;
pub mod go;
mod macho;
mod objc;
mod plt;
mod relocate;
pub(crate) mod seh;
mod symbols;
mod unwind;

use std::collections::{BTreeMap, HashMap};

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
    #[serde(rename = "arm32")]
    Arm32,
    #[serde(rename = "unsupported")]
    Unsupported,
}

impl fmt::Display for Isa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Isa::X86_64 => "x86_64",
            Isa::AArch64 => "aarch64",
            Isa::Arm32 => "arm32",
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
    /// The section occupies memory when the image is loaded.
    #[serde(skip)]
    pub loaded: bool,
    /// Data the program does not write once loaded, relocated data included.
    #[serde(skip)]
    pub read_only: bool,
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
    CodeView,
    Unwind,
    #[serde(rename = "function-starts")]
    FunctionStarts,
    Objc,
    Plt,
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
            NameSource::CodeView => "codeview",
            NameSource::Unwind => "unwind",
            NameSource::FunctionStarts => "function-starts",
            NameSource::Objc => "objc",
            NameSource::Plt => "plt",
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

/// What a call needs to know of its callee.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// How many integer argument registers it reads, when known.
    pub arity: Option<usize>,
    /// How many floating-point argument registers it reads, when known.
    pub floats: Option<usize>,
    /// The incoming registers the body uses, excluding unused argument positions.
    pub inputs: Option<crate::ir::Registers>,
    /// The integer arguments it takes as pointers, one bit for each.
    pub pointers: u32,
    /// How many 8-byte arguments it reads past the registers.
    pub stack: usize,
    /// How many bytes it reads of each of its first stack arguments, where
    /// fewer than eight; zero where it reads all eight.
    pub stack_widths: [u8; 16],
    /// The results it writes past its stack arguments under Go's assembly
    /// ABI, in order: offset from the first argument, and width in bytes.
    /// A zero width ends them.
    pub stack_results: [(u16, u8); 9],
    /// It reads `AArch64`'s indirect result register: it returns through
    /// memory the caller points it at.
    pub indirect_result: bool,
    /// Every value it returns is 32 bits wide: a call to it writes only
    /// the low half of the return register.
    pub narrow_return: bool,
    /// The registers it may return with changed, when every way out of it
    /// is known; the ones it saves and restores are not among them.
    pub clobbers: Option<crate::ir::Registers>,

    /// No path through it returns.
    pub noreturn: bool,
}

#[derive(Debug)]
pub struct Image {
    codeview: codeview::Data,
    pub format: Format,
    pub isa: Isa,
    /// ARM mapping symbols and function entry modes, keyed by physical address.
    pub arm_modes: BTreeMap<u64, ArmMode>,
    /// The byte order of the file's data, which its debug information
    /// is read in; None when unknown.
    byte_order: Option<object::Endianness>,
    pub entry: Option<u64>,
    bytes: Vec<u8>,
    pub sections: Vec<Section>,
    pub functions: BTreeMap<u64, Function>,
    /// The names of the data objects the symbol tables define.
    pub data_symbols: BTreeMap<u64, String>,
    pub objc_selectors: BTreeMap<u64, String>,
    /// Code split off a function, such as its cold part, by start and size:
    /// it belongs to the functions that branch into it.
    pub fragments: BTreeMap<u64, u64>,
    /// What is known of each function as a callee, filled on demand.
    pub summaries: std::sync::RwLock<HashMap<u64, Summary>>,
    /// The debug-information declarations of callees, read on demand.
    pub(crate) call_declarations: crate::analysis::calls::Declarations,
    /// The direct calls and jumps the code makes, by target: the address of
    /// each instruction. Built on first use.
    pub branches_to: std::sync::OnceLock<HashMap<u64, Vec<u64>>>,
    /// The addresses the code computes relative to the program counter, as
    /// where a table begins. Built on first use.
    pub addressed: std::sync::OnceLock<std::collections::HashSet<u64>>,
    /// Go functions called through the assembly ABI: their callers zero
    /// xmm15 again right after each call. Built on first use.
    pub go_abi0: std::sync::OnceLock<std::collections::HashSet<u64>>,
    /// The unwind table's rows, by address. Built on first use.
    stack_rows: std::sync::OnceLock<Vec<unwind::StackRow>>,
    /// Whether some caller reads what the function returns, filled on
    /// demand.
    pub result_reads: std::sync::Mutex<HashMap<u64, bool>>,
    /// The lifts made so far, shared by everything that lifts the same.
    pub lifts: crate::lift::Lifts,
    /// Branch relocations the object left unapplied: instruction address to
    /// the symbol address it calls.
    pub relocations: BTreeMap<u64, u64>,
    /// The file is a relocatable object, whose branches to other modules
    /// stay unresolved.
    pub relocatable: bool,
    /// The slots the dynamic linker fills with another module's function or
    /// object, by its name: calls through them call it.
    pub imports: BTreeMap<u64, String>,
    /// DLL-qualified names of PE imports, keyed by their slots.
    pub(crate) qualified_imports: HashMap<u64, String>,
    /// The landing pads of the exception tables, each with the code ranges
    /// whose calls unwind into it.
    pub landing_pads: BTreeMap<u64, Vec<(u64, u64)>>,
    pub(crate) exception_handlers: Vec<seh::Handler>,
    /// The image carries a Go pclntab, so its functions follow the Go ABI.
    pub go: bool,
    pub(crate) go_types: std::sync::OnceLock<go::types::Types>,
    /// The C++ virtual tables, by address point. Built on first use.
    pub vtables: std::sync::OnceLock<std::collections::BTreeSet<u64>>,
    /// The table each function leaves at the start of the object its first
    /// argument points to, as a constructor does, filled on demand.
    pub installs: std::sync::Mutex<HashMap<u64, Option<u64>>>,
}

/// The instruction mode or data selected by ARM mapping symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmMode {
    Arm,
    Thumb,
    Data,
}

impl Image {
    pub(crate) fn code_address(&self, address: u64) -> u64 {
        crate::arch::code_address(self.isa, address)
    }

    /// The ARM instruction mode at an address, including its Thumb bit.
    pub fn arm_mode(&self, address: u64) -> ArmMode {
        if address & 1 != 0 {
            return ArmMode::Thumb;
        }
        self.arm_modes
            .range(..=address)
            .next_back()
            .map_or(ArmMode::Arm, |(_, mode)| *mode)
    }

    pub(crate) fn byte_order(&self) -> Option<object::Endianness> {
        self.byte_order
    }

    /// The calling convention the function at `addr` follows.
    pub fn convention_of(&self, addr: u64) -> crate::ir::Convention {
        if self.go
            && self.isa == Isa::X86_64
            && self
                .go_abi0
                .get_or_init(|| self.assembly_callees())
                .contains(&addr)
        {
            return crate::ir::Convention::GoAbi0;
        }
        crate::ir::Convention::of(self.isa, self.format, self.go)
    }

    /// The targets of the direct calls `xorps xmm15, xmm15` follows: Go
    /// zeroes xmm15 again after calling into the assembly ABI, which uses it.
    fn assembly_callees(&self) -> std::collections::HashSet<u64> {
        let mut out = std::collections::HashSet::new();
        // ABI0-to-register wrappers initialize the fixed registers before
        // their call, rather than restoring them after an assembly call.
        for function in self.functions.values() {
            let Some(size) = function.size else {
                continue;
            };
            let Some(bytes) = self.read_vaddr(function.addr, size.min(128)) else {
                continue;
            };
            let mut decoder = iced_x86::Decoder::with_ip(
                64,
                bytes,
                function.addr,
                iced_x86::DecoderOptions::NONE,
            );
            while decoder.can_decode() {
                let at = decoder.position();
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    break;
                }
                if bytes.get(at..at.saturating_add(18)).is_some_and(|window| {
                    window[..14]
                        == [
                            0x45, 0x0f, 0x57, 0xff, // xorps xmm15, xmm15
                            0x64, 0x4c, 0x8b, 0x34, 0x25, 0xf8, 0xff, 0xff,
                            0xff, // mov r14, fs:[-8]
                            0xe8,
                        ]
                }) {
                    out.insert(function.addr);
                    break;
                }
                if matches!(
                    instruction.flow_control(),
                    iced_x86::FlowControl::Return
                        | iced_x86::FlowControl::UnconditionalBranch
                        | iced_x86::FlowControl::IndirectBranch
                ) {
                    break;
                }
            }
        }
        for section in self.sections.iter().filter(|section| section.executable) {
            let Some(bytes) = self.read_vaddr(section.vaddr, section.size) else {
                continue;
            };
            for at in 0..bytes.len().saturating_sub(8) {
                if bytes[at] != 0xe8 || bytes[at + 5..at + 9] != [0x45, 0x0f, 0x57, 0xff] {
                    continue;
                }
                let displacement =
                    i32::from_le_bytes(bytes[at + 1..at + 5].try_into().expect("four bytes"));
                out.insert(
                    (section.vaddr + at as u64 + 5).wrapping_add(displacement as i64 as u64),
                );
            }
        }
        out
    }

    /// An image holding only little-endian `code`, mapped executable at
    /// `addr`.
    #[cfg(test)]
    pub(crate) fn from_code(isa: Isa, addr: u64, code: Vec<u8>) -> Self {
        Self {
            codeview: Default::default(),
            format: Format::Elf,
            isa,
            arm_modes: BTreeMap::new(),
            byte_order: match isa {
                Isa::X86_64 | Isa::AArch64 | Isa::Arm32 => Some(object::Endianness::Little),
                Isa::Unsupported => None,
            },
            entry: None,
            sections: vec![Section {
                name: ".text".to_owned(),
                vaddr: addr,
                size: code.len() as u64,
                file_offset: Some(0),
                executable: true,
                loaded: true,
                read_only: false,
            }],
            bytes: code,
            functions: BTreeMap::new(),
            data_symbols: BTreeMap::new(),
            objc_selectors: BTreeMap::new(),
            fragments: BTreeMap::new(),
            summaries: Default::default(),
            call_declarations: Default::default(),
            branches_to: Default::default(),
            addressed: Default::default(),
            go_types: Default::default(),
            go_abi0: Default::default(),
            stack_rows: Default::default(),
            imports: BTreeMap::new(),
            qualified_imports: HashMap::new(),
            landing_pads: BTreeMap::new(),
            exception_handlers: Vec::new(),
            result_reads: Default::default(),
            lifts: Default::default(),
            relocations: BTreeMap::new(),
            relocatable: false,
            go: false,
            vtables: Default::default(),
            installs: Default::default(),
        }
    }

    pub fn section_at(&self, vaddr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| s.loaded && vaddr >= s.vaddr && vaddr < s.vaddr.saturating_add(s.size))
            .min_by_key(|s| (!s.executable, s.size))
    }

    pub fn virtual_offset(&self, vaddr: u64) -> Option<u64> {
        let Some(section) = self.section_at(vaddr) else {
            return None;
        };
        let Some(start) = section.file_offset else {
            return None;
        };
        let Some(offset) = start.checked_add(vaddr - section.vaddr) else {
            return None;
        };
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
            if !section.executable || plt::is_stub_section(&section.name) {
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
                crate::loader::Isa::Arm32 | crate::loader::Isa::Unsupported => continue,
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
                || self.fragment_at(address).is_some()
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

    /// Removes the given starts where only the prologue scan found them, and
    /// estimates again the sizes they cut short. Returns whether any went.
    pub fn drop_scanned_starts(&mut self, starts: &std::collections::HashSet<u64>) -> bool {
        let before = self.functions.len();
        self.functions.retain(|address, function| {
            !(starts.contains(address)
                && function
                    .sources
                    .iter()
                    .all(|source| *source == NameSource::Prologue))
        });
        if self.functions.len() == before {
            return false;
        }
        for function in self.functions.values_mut() {
            if function.size_estimated {
                function.size = None;
                function.size_estimated = false;
            }
        }
        estimate_sizes(&self.sections, &mut self.functions);
        true
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
        let Some(section) = self.sections.iter().find(|section| section.name == name) else {
            return None;
        };
        let Some(start) = section.file_offset else {
            return None;
        };
        let Some(end) = start.checked_add(section.size) else {
            return None;
        };
        self.bytes.get(start as usize..end as usize)
    }

    pub fn read(&self, offset: u64, len: u64) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        (end <= self.bytes.len() as u64).then(|| &self.bytes[offset as usize..end as usize])
    }

    /// The file's bytes at a virtual address; None where no section holds
    /// file data, as in zero-initialized data.
    pub fn read_vaddr(&self, vaddr: u64, len: u64) -> Option<&[u8]> {
        self.virtual_offset(vaddr)
            .and_then(|offset| self.read(offset, len))
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

    fn add_unwind_functions(&mut self) {
        for frame in unwind::frames(self) {
            // Linkage stubs are found from their slots, one by one.
            if self
                .section_at(frame.start)
                .is_some_and(|section| plt::is_stub_section(&section.name))
            {
                continue;
            }
            if frame.kind == unwind::FrameKind::Entry {
                if let Some(existing) = self.functions.get_mut(&frame.start)
                    && existing.size_estimated
                {
                    existing.size = None;
                    existing.size_estimated = false;
                }
                upsert(
                    &mut self.functions,
                    frame.start,
                    None,
                    Some(frame.size),
                    NameSource::Unwind,
                );
            } else if frame.kind == unwind::FrameKind::Fragment {
                // Code that starts inside a frame is no function, even when
                // a symbol names it.
                self.functions.remove(&frame.start);
                self.fragments.insert(frame.start, frame.size);
            }
        }
    }

    /// Whether the unwind table has the stack pointer where it was on the
    /// function's entry at `pc`; `None` where no table covers `pc`.
    pub(crate) fn stack_at_entry(&self, pc: u64) -> Option<bool> {
        let rows = self.stack_rows.get_or_init(|| unwind::stack_rows(self));
        let Some(index) = rows.partition_point(|row| row.start <= pc).checked_sub(1) else {
            return None;
        };
        let row = rows[index];
        (pc < row.end).then_some(row.at_entry)
    }

    /// The fragment holding `address`, as its start and size.
    pub fn fragment_at(&self, address: u64) -> Option<(u64, u64)> {
        self.fragments
            .range(..=address)
            .next_back()
            .filter(|(start, size)| address < start.saturating_add(**size))
            .map(|(start, size)| (*start, *size))
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
        object::Architecture::Arm => Isa::Arm32,
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

/// Whether a section holds constants. A relocated one the loader makes
/// read-only after applying its relocations, as `.data.rel.ro` and the
/// global offset table, counts too.
fn is_read_only(kind: object::SectionKind, name: &str) -> bool {
    use object::SectionKind;
    matches!(
        kind,
        SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel | SectionKind::ReadOnlyString
    ) || name.starts_with(".data.rel.ro")
        || name == ".got"
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
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) => {
            return Err(Error::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    let object_error = |source| Error::Object {
        path: path.to_owned(),
        source,
    };
    let kind = match object::FileKind::parse(&bytes[..]) {
        Ok(kind) => kind,
        Err(source) => return Err(object_error(source)),
    };
    let file = match ObjFile::parse(&bytes[..]) {
        Ok(file) => file,
        Err(source) => return Err(object_error(source)),
    };
    let bases = relocate::layout(&file);
    let mut relocated = bytes.clone();
    relocate::apply(&file, &bases, &mut relocated);
    relocate::apply_dynamic(&file, &mut relocated);

    let mut sections = Vec::new();
    for section in file.sections() {
        let vaddr = bases
            .get(&section.index())
            .copied()
            .unwrap_or(section.address());
        // A damaged header can place a section past the end of the address
        // space; nothing in it is reachable.
        if vaddr.checked_add(section.size()).is_none() {
            continue;
        }
        sections.push(Section {
            name: section.name().unwrap_or("<unnamed>").to_owned(),
            vaddr,
            size: section.size(),
            file_offset: section.file_range().map(|(offset, _)| offset),
            executable: is_executable(section.kind()),
            loaded: relocate::allocated(&section),
            read_only: is_read_only(section.kind(), section.name().unwrap_or("")),
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
        let base = bases
            .get(&section.index())
            .copied()
            .unwrap_or(section.address());
        for (offset, relocation) in section.relocations() {
            let arm_branch = isa_of(file.architecture()) == Isa::Arm32
                && matches!(
                    relocation.flags(),
                    object::RelocationFlags::Elf {
                        r_type: object::elf::R_ARM_CALL
                            | object::elf::R_ARM_JUMP24
                            | object::elf::R_ARM_THM_PC22
                            | object::elf::R_ARM_THM_JUMP24
                            | object::elf::R_ARM_PC24
                    }
                );
            if !arm_branch
                && !matches!(
                    relocation.kind(),
                    object::RelocationKind::Relative | object::RelocationKind::PltRelative
                )
            {
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
            relocations.insert(address, relocate::symbol_address(&symbol, &bases));
        }
    }

    let mut data_symbols = BTreeMap::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if sym.kind() == object::SymbolKind::Data
            && !sym.is_undefined()
            && let Some(name) = symbol_name(&sym)
        {
            data_symbols
                .entry(relocate::symbol_address(&sym, &bases))
                .or_insert(name);
        }
    }

    let arm = isa_of(file.architecture()) == Isa::Arm32;
    let mut arm_modes = BTreeMap::new();
    if arm {
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            let address = relocate::symbol_address(&sym, &bases);
            if sym.kind() == object::SymbolKind::Text && !sym.is_undefined() {
                arm_modes.insert(
                    address & !1,
                    if address & 1 == 0 {
                        ArmMode::Arm
                    } else {
                        ArmMode::Thumb
                    },
                );
            }
        }
        for sym in file.symbols() {
            let address = relocate::symbol_address(&sym, &bases);
            let mode = match sym.name().unwrap_or("").split('.').next().unwrap_or("") {
                "$a" => Some(ArmMode::Arm),
                "$t" => Some(ArmMode::Thumb),
                "$d" => Some(ArmMode::Data),
                _ => None,
            };
            if let Some(mode) = mode {
                arm_modes.insert(address & !1, mode);
            }
        }
    }
    let physical = |address: u64| if arm { address & !1 } else { address };
    let mut functions = BTreeMap::new();
    for sym in file.symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        upsert(
            &mut functions,
            physical(relocate::symbol_address(&sym, &bases)),
            symbol_name(&sym),
            (sym.size() > 0).then_some(sym.size()),
            NameSource::Symtab,
        );
    }
    for (address, name) in plt::stubs(&file) {
        upsert(&mut functions, address, Some(name), None, NameSource::Plt);
    }
    for sym in file.dynamic_symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        upsert(
            &mut functions,
            physical(sym.address()),
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

    if arm && file.entry() != 0 {
        arm_modes
            .entry(file.entry() & !1)
            .or_insert(if file.entry() & 1 == 0 {
                ArmMode::Arm
            } else {
                ArmMode::Thumb
            });
    }
    let address = physical(file.entry());
    let entry = (file.entry() != 0
        && !(format_of(kind) == Format::Pe && address == file.relative_address_base()))
    .then_some(address);
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

    let codeview = codeview::read(path, &file, &bases);
    let mut image = Image {
        codeview,
        format: format_of(kind),
        isa: isa_of(file.architecture()),
        arm_modes,
        byte_order: Some(if file.is_little_endian() {
            object::Endianness::Little
        } else {
            object::Endianness::Big
        }),
        entry,
        bytes: relocated,
        sections,
        functions,
        data_symbols,
        objc_selectors: BTreeMap::new(),
        fragments: BTreeMap::new(),
        summaries: Default::default(),
        call_declarations: Default::default(),
        branches_to: Default::default(),
        addressed: Default::default(),
        go_types: Default::default(),
        go_abi0: Default::default(),
        stack_rows: Default::default(),
        result_reads: Default::default(),
        lifts: Default::default(),
        relocations,
        relocatable: file.kind() == object::ObjectKind::Relocatable,
        imports: plt::imports(&file).into_iter().collect(),
        qualified_imports: plt::qualified_imports(&file),
        landing_pads: BTreeMap::new(),
        exception_handlers: Vec::new(),
        go: false,
        vtables: Default::default(),
        installs: Default::default(),
    };
    image.add_go_functions();
    image.add_dwarf_functions();
    for function in image.codeview.functions() {
        if let Some(existing) = image.functions.get_mut(&function.addr)
            && existing.size_estimated
        {
            existing.size = None;
            existing.size_estimated = false;
        }
        upsert(
            &mut image.functions,
            function.addr,
            Some(function.name),
            Some(function.size),
            NameSource::CodeView,
        );
    }
    image.add_unwind_functions();
    macho::add_functions(&file, &mut image);
    objc::read(&mut image);
    image.exception_handlers = seh::read(&image);
    seh::discover(&mut image);
    image.landing_pads = unwind::landing_pads(&image);
    // Only an image without symbols, debug info or a Go pclntab needs the
    // prologue scan, and only for the code no unwind entry covers.
    if image.functions.values().all(|function| {
        function.sources.iter().all(|source| {
            matches!(
                source,
                NameSource::Entry | NameSource::Unwind | NameSource::Plt | NameSource::Objc
            )
        })
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
            .chain(image.fragments.keys().copied())
            .filter(|start| *start > function.addr && *start < end)
            .min()
        {
            function.size = Some(next - function.addr);
        }
    }
    estimate_sizes(&image.sections, &mut image.functions);
    Ok(image)
}

#[cfg(test)]
mod byte_order_tests {
    use super::*;
    use object::Endianness;

    fn parsed_elf(byte_order: Endianness) -> Image {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let object = object::write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::Aarch64,
            byte_order,
        );
        let bytes = object.write().expect("ELF object");
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "velk-byte-order-{}-{sequence}.o",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("scratch object");
        let image = load(&path);
        std::fs::remove_file(&path).expect("remove scratch object");
        image.expect("parsed ELF object")
    }

    #[test]
    fn byte_order_raw_code_has_the_explicit_ir_contract() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            assert_eq!(
                Image::from_code(isa, 0, Vec::new()).byte_order(),
                Some(Endianness::Little)
            );
        }
        assert_eq!(
            Image::from_code(Isa::Unsupported, 0, Vec::new()).byte_order(),
            None
        );
    }

    #[test]
    fn byte_order_elf_comes_from_the_object_reader() {
        for order in [Endianness::Little, Endianness::Big] {
            let image = parsed_elf(order);
            assert_eq!(image.format, Format::Elf);
            assert_eq!(image.isa, Isa::AArch64);
            assert_eq!(image.byte_order(), Some(order));
        }
    }

    #[test]
    fn byte_order_existing_pe_coff_and_macho_are_preserved() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for (name, format) in [
            ("pe64.exe", Format::Pe),
            ("pe64.obj", Format::Coff),
            ("arm64_macho.o", Format::MachO),
        ] {
            let image =
                load(&fixtures.join(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(image.format, format, "{name}");
            assert_eq!(image.byte_order(), Some(Endianness::Little), "{name}");
        }
    }

    #[test]
    fn byte_order_nonlittle_dwarf_is_not_read_as_little() {
        let big = parsed_elf(Endianness::Big);
        let unknown = Image::from_code(Isa::Unsupported, 0, Vec::new());
        for image in [&big, &unknown] {
            assert!(dwarf::function_types(image, 0).is_none());
            assert!(dwarf::functions(image).is_empty());
            assert!(matches!(
                dwarf::calls::call_index(image),
                Err(crate::ir::AbiIssue::UnsupportedProfile)
            ));
        }
        assert!(dwarf::calls::call_index(&parsed_elf(Endianness::Little)).is_ok());
    }
}
