//! PE headers, loader lists, import addresses and static TLS initialization.

use std::collections::{BTreeMap, BTreeSet};

use crate::loader::{Format, Isa};

use super::{Export, Module, Process, Runner, apis, crt, module_name};

struct Headers {
    base: u64,
    size: u64,
    headers_size: u64,
    exports: (u64, u64),
    tls: (u64, u64),
}

fn word(bytes: &[u8], offset: usize, width: usize) -> Result<u64, String> {
    let Some(end) = offset.checked_add(width) else {
        return Err("PE header offset overflows".to_owned());
    };
    let Some(bytes) = bytes
        .get(offset..end)
        .filter(|_| matches!(width, 1 | 2 | 4 | 8))
    else {
        return Err(format!("missing PE header field at offset 0x{offset:x}"));
    };
    let mut value = [0; 8];
    value[..width].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}

fn headers(image: &crate::loader::Image) -> Result<Headers, String> {
    // Any missing or invalid header field invalidates the entire process setup.
    let Some(dos) = image.read(0, 64).filter(|bytes| bytes.starts_with(b"MZ")) else {
        return Err("missing DOS header".to_owned());
    };
    let offset = match word(dos, 0x3c, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let Some(nt) = image
        .read(offset, 24)
        .filter(|bytes| bytes.starts_with(b"PE\0\0"))
    else {
        return Err(format!("missing PE header at file offset 0x{offset:x}"));
    };
    let optional_size = match word(nt, 20, 2) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let Some(optional) = offset
        .checked_add(24)
        .and_then(|offset| image.read(offset, optional_size))
    else {
        return Err("missing PE optional header".to_owned());
    };
    let width = crate::arch::pointer_bytes(image.isa) as usize;
    let magic = if width == 8 { 0x20b } else { 0x10b };
    let optional_magic = match word(optional, 0, 2) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if optional_magic != magic {
        return Err("PE optional header does not match the architecture".to_owned());
    }
    let base = match word(optional, if width == 8 { 24 } else { 28 }, width) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let size = match word(optional, 56, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let headers_size = match word(optional, 60, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let limit = if width == 8 { u64::MAX } else { 1u64 << 32 };
    if size == 0
        || headers_size == 0
        || headers_size > super::super::HEAP_SIZE
        || headers_size > size
        || base.checked_add(size).is_none_or(|end| end > limit)
        || image.read(0, headers_size).is_none()
    {
        return Err("invalid PE image or header size".to_owned());
    }
    let directory_start = if width == 8 { 112 } else { 96 };
    let directories = match word(optional, directory_start - 4, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let directory = |index: usize| -> Result<(u64, u64), String> {
        if index as u64 >= directories {
            return Ok((0, 0));
        }
        let rva = match word(optional, directory_start + index * 8, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let data_size = match word(optional, directory_start + index * 8 + 4, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if rva == 0 {
            return Ok((0, 0));
        }
        if rva.checked_add(data_size).is_none_or(|end| end > size) {
            return Err(format!("PE data directory {index} exceeds the image"));
        }
        Ok((base + rva, data_size))
    };
    let exports_directory = match directory(0) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let tls_directory = match directory(9) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    Ok(Headers {
        base,
        size,
        headers_size,
        exports: exports_directory,
        tls: tls_directory,
    })
}

fn put(bytes: &mut [u8], offset: usize, value: u64, width: usize) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

/// Where a modeled image has its parts, each from its base.
struct Layout {
    size: usize,
    /// The entry points, 16 bytes each.
    entries: usize,
    addresses: usize,
    names: usize,
    ordinals: usize,
    library: usize,
    strings: usize,
}

/// The layout for `names`: a small one, or a larger one for a library
/// listed with every function known of it.
fn layout(names: &BTreeSet<String>) -> Layout {
    let text: usize = names.iter().map(|name| name.len() + 1).sum();
    if names.len() <= 512 && text <= 0x8000 - 0x2500 {
        return Layout {
            size: 0x10000,
            entries: 0x8000,
            addresses: 0x1100,
            names: 0x1900,
            ordinals: 0x2100,
            library: 0x2400,
            strings: 0x2500,
        };
    }
    Layout {
        size: 0x40000,
        entries: 0x20000,
        addresses: 0x1100,
        names: 0x5100,
        ordinals: 0x9100,
        library: 0xb100,
        strings: 0xb200,
    }
}

fn synthetic_image(
    dll: &str,
    names: &BTreeSet<String>,
    width: usize,
) -> Result<(Vec<u8>, Layout), String> {
    if names.len() > 4096 {
        return Err("modeled DLL has more than 4096 exports".to_owned());
    }
    if dll.len() > 255 {
        return Err("modeled DLL name exceeds 255 bytes".to_owned());
    }
    let layout = layout(names);
    let mut bytes = vec![0; layout.size];
    bytes[..2].copy_from_slice(b"MZ");
    put(&mut bytes, 0x3c, 0x80, 4);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put(&mut bytes, 0x84, if width == 8 { 0x8664 } else { 0x14c }, 2);
    put(&mut bytes, 0x86, 1, 2);
    let optional_size = if width == 8 { 240 } else { 224 };
    put(&mut bytes, 0x94, optional_size, 2);
    put(&mut bytes, 0x96, 0x2002, 2);
    let optional = 0x98;
    put(
        &mut bytes,
        optional,
        if width == 8 { 0x20b } else { 0x10b },
        2,
    );
    put(&mut bytes, optional + 32, 0x1000, 4);
    put(&mut bytes, optional + 36, 0x200, 4);
    put(&mut bytes, optional + 56, layout.size as u64, 4);
    put(&mut bytes, optional + 60, 0x400, 4);
    put(&mut bytes, optional + 68, 3, 2);
    let directories = optional + if width == 8 { 112 } else { 96 };
    put(&mut bytes, directories - 4, 16, 4);
    put(&mut bytes, directories, 0x1000, 4);
    put(
        &mut bytes,
        directories + 4,
        (layout.entries - 0x1000) as u64,
        4,
    );
    let section = optional + optional_size as usize;
    bytes[section..section + 5].copy_from_slice(b".text");
    put(&mut bytes, section + 8, (layout.size - 0x1000) as u64, 4);
    put(&mut bytes, section + 12, 0x1000, 4);
    put(&mut bytes, section + 36, 0x6000_0020, 4);
    put(&mut bytes, 0x1010, 1, 4);
    put(&mut bytes, 0x100c, layout.library as u64, 4);
    bytes[layout.library..layout.library + dll.len()].copy_from_slice(dll.as_bytes());
    put(&mut bytes, 0x1014, names.len() as u64, 4);
    put(&mut bytes, 0x1018, names.len() as u64, 4);
    put(&mut bytes, 0x101c, layout.addresses as u64, 4);
    put(&mut bytes, 0x1020, layout.names as u64, 4);
    put(&mut bytes, 0x1024, layout.ordinals as u64, 4);
    let mut string = layout.strings;
    for (index, name) in names.iter().enumerate() {
        let Some(end) = string
            .checked_add(name.len() + 1)
            .filter(|end| *end <= layout.entries)
        else {
            return Err("modeled DLL export names exceed the room for them".to_owned());
        };
        put(
            &mut bytes,
            layout.addresses + index * 4,
            (layout.entries + index * 16) as u64,
            4,
        );
        put(&mut bytes, layout.names + index * 4, string as u64, 4);
        put(&mut bytes, layout.ordinals + index * 2, index as u64, 2);
        bytes[string..end - 1].copy_from_slice(name.as_bytes());
        bytes[layout.entries + index * 16] = 0xc3;
        string = end;
    }
    Ok((bytes, layout))
}

impl Runner<'_> {
    fn setup_store(&mut self, address: u64, value: u64, width: u8) {
        for offset in 0..width {
            self.machine
                .memory
                .insert(address + u64::from(offset), (value >> (offset * 8)) as u8);
        }
    }

    fn setup_bytes(&mut self, bytes: &[u8]) -> Result<u64, String> {
        let pointer = self.allocate(bytes.len() as u64);
        if pointer == 0 {
            return Err("Windows process state exceeds the heap capacity".to_owned());
        }
        for (offset, &byte) in bytes.iter().enumerate() {
            self.machine.memory.insert(pointer + offset as u64, byte);
        }
        Ok(pointer)
    }

    fn setup_wide(&mut self, text: &str) -> Result<(u64, u16), String> {
        if text.contains('\0') {
            return Err("Windows process parameter contains NUL".to_owned());
        }
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
            if bytes.len() > u16::MAX as usize - 2 {
                return Err("Windows process parameter exceeds UNICODE_STRING capacity".to_owned());
            }
        }
        let length = bytes.len() as u16;
        bytes.extend_from_slice(&[0, 0]);
        match self.setup_bytes(&bytes) {
            Ok(pointer) => Ok((pointer, length)),
            Err(error) => Err(error),
        }
    }

    fn setup_unicode(&mut self, address: u64, text: &str) -> Result<u64, String> {
        let (pointer, length) = match self.setup_wide(text) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        self.setup_store(address, u64::from(length), 2);
        self.setup_store(address + 2, u64::from(length) + 2, 2);
        self.setup_store(address + u64::from(width), pointer, width);
        Ok(pointer)
    }

    /// Adds every function known of `dll` when calls without a model are
    /// passed over: a program that finds its imports by walking the export
    /// names of a library then finds each of them.
    fn list_known_functions(&self, dll: &str, functions: &mut BTreeSet<String>) {
        if !self.options.skip_calls {
            return;
        }
        for name in crate::analysis::prototypes::library_functions(self.image, dll) {
            functions.insert(name.to_owned());
        }
    }

    /// Maps a modeled image of `dll` exporting `functions`.
    fn map_module(
        &mut self,
        dll: &str,
        functions: BTreeSet<String>,
        width: u8,
    ) -> Result<Module, String> {
        let (mut bytes, layout) = match synthetic_image(dll, &functions, width as usize) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let base = match self
            .machine
            .strict_memory
            .as_mut()
            .expect("strict memory")
            .map_zeroed(bytes.len() as u64, true)
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        put(
            &mut bytes,
            0x98 + if width == 8 { 24 } else { 28 },
            base,
            width as usize,
        );
        for (offset, byte) in bytes.into_iter().enumerate() {
            if byte != 0 {
                self.machine.memory.insert(base + offset as u64, byte);
            }
        }
        let mut module = Module {
            name: dll.to_owned(),
            path: format!("C:\\Windows\\System32\\{dll}"),
            base,
            size: layout.size as u64,
            entries: layout.entries as u64,
            exports: BTreeMap::new(),
        };
        for (index, name) in functions.into_iter().enumerate() {
            let address = base + module.entries + index as u64 * 16;
            module.exports.insert(name, (address, index as u32 + 1));
        }
        Ok(module)
    }

    /// The base of a modeled image of `dll`, mapped now: a packed program
    /// loads the libraries of the program it holds by name.
    pub(in super::super) fn load_library(&mut self, dll: &str) -> Result<u64, String> {
        if self.windows_state().modules.len() >= 64 {
            return Err("more than 64 DLLs are loaded".to_owned());
        }
        let mut functions = apis(dll)
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        self.list_known_functions(dll, &mut functions);
        let width = crate::arch::pointer_bytes(self.machine.isa);
        let module = match self.map_module(dll, functions, width) {
            Ok(module) => module,
            Err(error) => return Err(error),
        };
        let base = module.base;
        let process = self
            .windows
            .as_mut()
            .expect("Windows setup precedes API calls");
        for (name, (address, _)) in &module.exports {
            process.exports.insert(
                *address,
                Export {
                    dll: dll.to_owned(),
                    name: name.clone(),
                },
            );
        }
        process.modules.push(module);
        Ok(base)
    }

    /// An address for the export `name` of the module at `index`, which
    /// its modeled image does not list: the image has room for more
    /// entry points than its export directory names.
    pub(in super::super) fn add_export(&mut self, index: usize, name: &str) -> Option<u64> {
        let process = self
            .windows
            .as_mut()
            .expect("Windows setup precedes API calls");
        let module = &mut process.modules[index];
        let position = module.exports.len() as u64;
        if position >= (module.size - module.entries) / 16 || name.is_empty() || name.len() > 255 {
            return None;
        }
        let address = module.base + module.entries + position * 16;
        module
            .exports
            .insert(name.to_owned(), (address, position as u32 + 1));
        process.exports.insert(
            address,
            Export {
                dll: module.name.clone(),
                name: name.to_owned(),
            },
        );
        self.machine.memory.insert(address, 0xc3);
        Some(address)
    }

    pub(in super::super) fn initialize_windows(&mut self) -> Result<(), String> {
        if self.image.format != Format::Pe
            || !matches!(self.image.isa, Isa::X86_64 | Isa::I386)
            || self.recovery.is_some()
        {
            return Ok(());
        }
        // Setup errors invalidate the complete process; partial loader state is never executed.
        let header = match headers(self.image) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        if let Err(error) = self
            .machine
            .strict_memory
            .as_mut()
            .expect("strict memory")
            .map(header.base, header.headers_size, true)
        {
            return Err(error);
        }
        let bytes = self
            .image
            .read(0, header.headers_size)
            .expect("validated PE headers");
        for (offset, &byte) in bytes.iter().enumerate() {
            self.machine
                .memory
                .insert(header.base + offset as u64, byte);
        }
        let mut modules = vec![Module {
            name: module_name(&self.options.windows.image_path),
            path: self.options.windows.image_path.clone(),
            base: header.base,
            size: header.size,
            // The program is no modeled image with entry points to add.
            entries: header.size,
            exports: BTreeMap::new(),
        }];
        let mut names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for dll in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
            names.insert(dll.to_owned(), BTreeSet::new());
        }
        let mut imports = BTreeMap::new();
        for (&slot, qualified) in &self.image.qualified_imports {
            let Some((dll, name)) = qualified.split_once('!') else {
                return Err(format!("invalid qualified import at 0x{slot:x}"));
            };
            let dll = module_name(dll);
            names
                .entry(dll.clone())
                .or_default()
                .insert(name.to_owned());
            imports.insert(slot, (dll, name.to_owned()));
        }
        if names.len() > 64 {
            return Err("PE imports more than 64 DLLs".to_owned());
        }
        let mut dlls = vec![
            "ntdll.dll".to_owned(),
            "kernel32.dll".to_owned(),
            "kernelbase.dll".to_owned(),
        ];
        for name in names.keys() {
            if !dlls.contains(name) {
                dlls.push(name.clone());
            }
        }
        let mut exports = BTreeMap::new();
        for dll in dlls {
            let mut functions = names.remove(&dll).expect("DLL import names");
            let table = apis(&dll);
            if crt(&dll) && dll != "msvcrt.dll" {
                for name in &functions {
                    // rand is exported but has no deterministic model.
                    if name != "rand" && !table.iter().any(|(export, _)| export == name) {
                        return Err(format!("unavailable Windows export {dll}!{name}"));
                    }
                }
            }
            for &(name, _) in table {
                functions.insert(name.to_owned());
            }
            self.list_known_functions(&dll, &mut functions);
            let module = match self.map_module(&dll, functions, width) {
                Ok(module) => module,
                Err(error) => return Err(error),
            };
            for (name, (address, _)) in &module.exports {
                exports.insert(
                    *address,
                    Export {
                        dll: dll.clone(),
                        name: name.clone(),
                    },
                );
            }
            modules.push(module);
        }
        for (slot, (dll, name)) in imports {
            let module = modules
                .iter()
                .find(|module| module.name == dll)
                .expect("created imported DLL");
            let address = module.exports[&name].0;
            if !self
                .machine
                .strict_memory
                .as_ref()
                .expect("strict memory")
                .check(slot, u64::from(width), false)
            {
                return Err(format!("invalid IAT slot at 0x{slot:x}"));
            }
            self.setup_store(slot, address, width);
        }
        let main_exports = match self.main_exports(&header) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        modules[0].exports = main_exports;
        let peb = self.allocate(0x400);
        let ldr = self.allocate(0x80);
        let parameters = self.allocate(0x100);
        if peb == 0 || ldr == 0 || parameters == 0 {
            return Err("Windows process state allocation failed".to_owned());
        }
        self.setup_store(parameters, 0x100, 4);
        self.setup_store(parameters + 4, 0x100, 4);
        self.setup_store(parameters + 8, 1, 4);
        for (index, handle) in super::io::STANDARD.into_iter().enumerate() {
            let offset = if width == 8 { 0x20 } else { 0x18 };
            self.setup_store(
                parameters + offset + index as u64 * u64::from(width),
                handle,
                width,
            );
        }
        let teb = self
            .machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .tls_base;
        let stack_end = crate::ir::eval::stack_top(self.image.isa) + 0x1000;
        for (address, value) in [
            (teb, if width == 4 { u64::from(u32::MAX) } else { 0 }),
            (teb + u64::from(width), stack_end),
            (teb + u64::from(width) * 2, stack_end - (1 << 20)),
            (teb + u64::from(width) * 6, teb),
            (teb + u64::from(width) * 12, peb),
            (teb + u64::from(width) * 8, 1000),
            (teb + u64::from(width) * 9, 1001),
            (peb + u64::from(width) * 2, header.base),
            (peb + u64::from(width) * 3, ldr),
            (peb + u64::from(width) * 4, parameters),
            (peb + u64::from(width) * 6, self.heap_base),
        ] {
            self.setup_store(address, value, width);
        }
        self.setup_store(
            peb + 2,
            u64::from(self.options.anti_analysis.debugger_present),
            1,
        );
        let flags = peb + if width == 8 { 0xbc } else { 0x68 };
        self.setup_store(flags, 0, 4);
        let memory = self.machine.strict_memory.as_mut().expect("strict memory");
        memory.watch_read(peb + 2, 1, "PEB.BeingDebugged");
        memory.watch_read(flags, 4, "PEB.NtGlobalFlag");
        self.setup_store(ldr, if width == 8 { 0x58 } else { 0x30 }, 4);
        self.setup_store(ldr + 4, 1, 1);
        let mut entries = Vec::new();
        for module in &modules {
            let entry = self.allocate(0x100);
            if entry == 0 {
                return Err("Windows loader entry allocation failed".to_owned());
            }
            self.setup_store(entry + u64::from(width) * 6, module.base, width);
            self.setup_store(entry + u64::from(width) * 8, module.size, 4);
            let full = entry + if width == 8 { 0x48 } else { 0x24 };
            if let Err(error) = self.setup_unicode(full, &module.path) {
                return Err(error);
            }
            let basename = module
                .path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(&module.path);
            if let Err(error) = self.setup_unicode(full + u64::from(width) * 2, basename) {
                return Err(error);
            }
            entries.push(entry);
        }
        for list in 0..3u64 {
            let head = ldr + if width == 8 { 0x10 } else { 0xc } + list * u64::from(width) * 2;
            let links: Vec<u64> = entries
                .iter()
                .map(|entry| entry + list * u64::from(width) * 2)
                .collect();
            self.setup_store(head, links[0], width);
            self.setup_store(
                head + u64::from(width),
                *links.last().expect("main module"),
                width,
            );
            for (index, &link) in links.iter().enumerate() {
                self.setup_store(link, links.get(index + 1).copied().unwrap_or(head), width);
                self.setup_store(
                    link + u64::from(width),
                    if index == 0 { head } else { links[index - 1] },
                    width,
                );
            }
        }
        let image_name = parameters + if width == 8 { 0x60 } else { 0x38 };
        if let Err(error) = self.setup_unicode(image_name, &self.options.windows.image_path) {
            return Err(error);
        }
        let command_wide = match self.setup_unicode(
            image_name + u64::from(width) * 2,
            &self.options.windows.command_line,
        ) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let command_ansi = if self.options.windows.command_line.is_ascii() {
            let mut bytes = self.options.windows.command_line.as_bytes().to_vec();
            bytes.push(0);
            match self.setup_bytes(&bytes) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        } else {
            0
        };
        let mut environment = Vec::new();
        let mut variables = BTreeMap::new();
        for (name, value) in &self.options.windows.environment {
            if name.is_empty() || name.contains(['\0', '=']) || value.contains('\0') {
                return Err("invalid Windows environment variable".to_owned());
            }
            if variables
                .insert(name.to_uppercase(), (name, value))
                .is_some()
            {
                return Err("duplicate case-insensitive Windows environment variable".to_owned());
            }
        }
        for (_, (name, value)) in variables {
            for unit in format!("{name}={value}").encode_utf16().chain([0]) {
                environment.extend_from_slice(&unit.to_le_bytes());
                if environment.len() as u64 > super::super::HEAP_SIZE {
                    return Err("Windows environment exceeds 16 MiB".to_owned());
                }
            }
        }
        if environment.is_empty() {
            environment.extend_from_slice(&[0, 0]);
        }
        environment.extend_from_slice(&[0, 0]);
        let environment_pointer = match self.setup_bytes(&environment) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.setup_store(
            parameters + if width == 8 { 0x80 } else { 0x48 },
            environment_pointer,
            width,
        );
        let callbacks = match self.setup_static_tls(header.tls, teb) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let heap = match self.setup_bytes(&[0; 64]) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.setup_store(peb + if width == 8 { 0x30 } else { 0x18 }, heap, width);
        let registry = match super::registry::contents(&self.options.windows.registry) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.windows = Some(Process {
            modules,
            exports,
            callbacks,
            detaching: false,
            crt_closed: false,
            crt_exiting: false,
            exit_handlers: Vec::new(),
            exception_active: false,
            instruction_state: None,
            tls_directory: header.tls,
            threads: BTreeMap::new(),
            active_thread: None,
            teb,
            next_thread_id: 1002,
            command_line: [command_ansi, command_wide],
            environment_bytes: environment,
            environment_blocks: BTreeSet::new(),
            elapsed: 0,
            tls_used: [false; 64],
            heap,
            heap_blocks: BTreeMap::new(),
            virtual_allocations: BTreeMap::new(),
            file_handles: BTreeMap::new(),
            standard_handles: [true; 3],
            crt_output: [Vec::new(), Vec::new()],
            crt_buffering: [None, None],
            registry,
            registry_handles: BTreeMap::new(),
        });
        Ok(())
    }

    fn image_word(&self, address: u64, width: u8) -> Result<u64, String> {
        let Some(bytes) = self.image.read_vaddr(address, u64::from(width)) else {
            return Err(format!("missing PE data at 0x{address:x}"));
        };
        word(bytes, 0, width as usize)
    }

    fn main_exports(&self, header: &Headers) -> Result<BTreeMap<String, (u64, u32)>, String> {
        let mut exports = BTreeMap::new();
        let (directory, size) = header.exports;
        if directory == 0 {
            return Ok(exports);
        }
        // Every malformed field invalidates the main module's export table.
        if size < 40 {
            return Err("truncated PE export directory".to_owned());
        }
        let ordinal_base = match self.image_word(directory + 16, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let count = match self.image_word(directory + 24, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if count > 4096 {
            return Err("main module has more than 4096 named exports".to_owned());
        }
        let functions = match self.image_word(directory + 28, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let names = match self.image_word(directory + 32, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let ordinals = match self.image_word(directory + 36, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let function_count = match self.image_word(directory + 20, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        for (rva, count, width) in [
            (functions, function_count, 4),
            (names, count, 4),
            (ordinals, count, 2),
        ] {
            if count
                .checked_mul(width)
                .and_then(|size| rva.checked_add(size))
                .is_none_or(|end| end > header.size)
            {
                return Err("PE export table exceeds the image".to_owned());
            }
        }
        for index in 0..count {
            let rva = match self.image_word(header.base + names + index * 4, 4) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if rva >= header.size {
                return Err("PE export name is outside the image".to_owned());
            }
            let mut name = Vec::new();
            let mut terminated = false;
            for offset in 0..4096.min(header.size - rva) {
                let loaded = match self.image_word(header.base + rva + offset, 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let byte = loaded as u8;
                if byte == 0 {
                    terminated = true;
                    break;
                }
                name.push(byte);
            }
            if !terminated {
                return Err("unterminated PE export name".to_owned());
            }
            let ordinal = match self.image_word(header.base + ordinals + index * 2, 2) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if ordinal >= function_count {
                return Err("PE export ordinal exceeds the function table".to_owned());
            }
            let rva = match self.image_word(header.base + functions + ordinal * 4, 4) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if rva == 0 || rva >= header.size {
                continue;
            }
            let address = header.base + rva;
            if (directory..directory + size).contains(&address) {
                continue;
            }
            let Ok(name) = String::from_utf8(name) else {
                return Err("PE export name is not UTF-8".to_owned());
            };
            let Some(ordinal) = ordinal_base
                .checked_add(ordinal)
                .and_then(|value| u32::try_from(value).ok())
            else {
                return Err("PE export ordinal overflows".to_owned());
            };
            exports.insert(name, (address, ordinal));
        }
        Ok(exports)
    }

    pub(super) fn setup_static_tls(
        &mut self,
        tls: (u64, u64),
        teb: u64,
    ) -> Result<Vec<u64>, String> {
        let (directory, size) = tls;
        if directory == 0 {
            return Ok(Vec::new());
        }
        let width = crate::arch::pointer_bytes(self.image.isa);
        // Invalid TLS metadata invalidates process setup before any callback executes.
        if size < u64::from(width) * 4 + 8 {
            return Err("truncated PE TLS directory".to_owned());
        }
        let start = match self.image_word(directory, width) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let end = match self.image_word(directory + u64::from(width), width) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let index = match self.image_word(directory + u64::from(width) * 2, width) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let callbacks = match self.image_word(directory + u64::from(width) * 3, width) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let zero = match self.image_word(directory + u64::from(width) * 4, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let Some(length) = end.checked_sub(start) else {
            return Err("PE TLS template ends before its start".to_owned());
        };
        let Some(size) = length
            .checked_add(zero)
            .filter(|size| *size <= super::super::HEAP_SIZE)
        else {
            return Err("PE TLS data exceeds 16 MiB".to_owned());
        };
        let flags = match self.image_word(directory + u64::from(width) * 4 + 4, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let alignment = (flags >> 20) & 15;
        if alignment == 15 {
            return Err("invalid PE TLS alignment".to_owned());
        }
        let alignment = if alignment == 0 {
            16
        } else {
            1u64 << (alignment - 1)
        };
        let Some(aligned) = self.heap_next.checked_add(alignment - 1) else {
            return Err("PE TLS alignment overflows".to_owned());
        };
        self.heap_next = aligned & !(alignment - 1);
        let data = self.allocate(size);
        let vector = self.allocate(64 * u64::from(width));
        if data == 0 || vector == 0 {
            return Err("PE TLS allocation failed".to_owned());
        }
        if length != 0 {
            let Some(bytes) = self.image.read_vaddr(start, length) else {
                return Err("PE TLS template is not mapped".to_owned());
            };
            for (offset, &byte) in bytes.iter().enumerate() {
                self.machine.memory.insert(data + offset as u64, byte);
            }
        }
        if !self
            .machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .check(index, 4, true)
        {
            return Err(format!("invalid PE TLS index at 0x{index:x}"));
        }
        if self.windows.is_none() {
            self.setup_store(index, 0, 4);
        }
        self.setup_store(vector, data, width);
        self.setup_store(teb + u64::from(width) * 11, vector, width);
        let mut addresses = Vec::new();
        if callbacks == 0 {
            return Ok(addresses);
        }
        for offset in 0..128u64 {
            let Some(at) = callbacks.checked_add(offset * u64::from(width)) else {
                return Err("PE TLS callback table overflows".to_owned());
            };
            let address = match self.image_word(at, width) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if address == 0 {
                return Ok(addresses);
            }
            if !self
                .image
                .section_at(address)
                .is_some_and(|section| section.executable)
            {
                return Err(format!(
                    "PE TLS callback at 0x{address:x} is not executable"
                ));
            }
            addresses.push(address);
        }
        Err("PE TLS callback table exceeds 128 entries".to_owned())
    }
}
