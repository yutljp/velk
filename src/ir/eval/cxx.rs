//! Bounded standard C++ stream calls and 64-bit string layouts.

use crate::loader::Image;

#[derive(Clone, Copy)]
pub(super) enum Layout {
    Gnu,
    Llvm,
    LlvmAlternate,
}

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Input,
    Output,
}

#[derive(Clone, Copy)]
pub(super) enum Input {
    Word,
    Line,
    Delimited,
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    Ignore,
    Construct(Layout),
    Destroy,
    Allocate,
    StringAllocate,
    ConstructText(Layout),
    ConstructRange(Layout),
    Text,
    String(Layout),
    Character,
    Integer { signed: bool, bits: u8 },
    InputInteger { signed: bool, bits: u8 },
    Input(Layout, Input),
    Endl,
    Flush,
    Manipulator,
    Write,
    Compare(Layout),
    Unsupported,
}

pub(super) fn name(symbol: &str) -> &str {
    let symbol = symbol.strip_prefix("__Z").map_or(symbol, |_| &symbol[1..]);
    symbol.split('@').next().unwrap_or(symbol)
}

const CALLS: &[(&str, Call)] = &[
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm",
        Call::ConstructRange(Layout::Llvm),
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEPFRS3_S4_E",
        Call::Manipulator,
    ),
    (
        "_ZNSt3__1lsINS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc",
        Call::Text,
    ),
    (
        "_ZNSt3__1lsIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_",
        Call::Text,
    ),
    (
        "_ZNSt3__1lsINS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_c",
        Call::Character,
    ),
    (
        "_ZNSt3__1lsIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_S4_",
        Call::Character,
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE3putEc",
        Call::Character,
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5flushEv",
        Call::Flush,
    ),
    (
        "_ZNSt3__15flushIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_",
        Call::Flush,
    ),
    (
        "_ZNSt3__14endlIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_",
        Call::Endl,
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5writeEPKcl",
        Call::Write,
    ),
    (
        "_ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m",
        Call::Write,
    ),
    (
        "_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE",
        Call::String(Layout::Llvm),
    ),
    (
        "_ZNSt3__1rsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EE",
        Call::Input(Layout::Llvm, Input::Word),
    ),
    (
        "_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EE",
        Call::Input(Layout::Llvm, Input::Line),
    ),
    (
        "_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_",
        Call::Input(Layout::Llvm, Input::Delimited),
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev",
        Call::Construct(Layout::Llvm),
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2Ev",
        Call::Construct(Layout::Llvm),
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev",
        Call::Destroy,
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev",
        Call::Destroy,
    ),
    (
        "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEPKc",
        Call::Compare(Layout::Llvm),
    ),
    ("_Znwm", Call::Allocate),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm",
        Call::StringAllocate,
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_",
        Call::ConstructText(Layout::Gnu),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2EPKcRKS3_",
        Call::ConstructText(Layout::Gnu),
    ),
    ("__cxa_atexit", Call::Ignore),
    ("___cxa_atexit", Call::Ignore),
    ("_ZNSt8ios_base4InitC1Ev", Call::Ignore),
    ("_ZNSt8ios_base4InitD1Ev", Call::Ignore),
    ("_ZSt21ios_base_library_initv", Call::Ignore),
    ("_ZNSt3__18ios_base4InitC1Ev", Call::Ignore),
    ("_ZNSt3__18ios_base4InitD1Ev", Call::Ignore),
    ("_ZdlPv", Call::Ignore),
    ("_ZdlPvm", Call::Ignore),
    ("_ZNSolsEPFRSoS_E", Call::Manipulator),
    ("_ZNSo3putEc", Call::Character),
    ("_ZNSo5flushEv", Call::Flush),
    ("_ZNSo5writeEPKcl", Call::Write),
    (
        "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc",
        Call::Text,
    ),
    (
        "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_",
        Call::Text,
    ),
    (
        "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c",
        Call::Character,
    ),
    (
        "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_S3_",
        Call::Character,
    ),
    (
        "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l",
        Call::Write,
    ),
    (
        "_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_",
        Call::Endl,
    ),
    (
        "_ZSt5flushIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_",
        Call::Flush,
    ),
    (
        "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        Call::String(Layout::Gnu),
    ),
    (
        "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        Call::Input(Layout::Gnu, Input::Word),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        Call::Input(Layout::Gnu, Input::Line),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EES4_",
        Call::Input(Layout::Gnu, Input::Delimited),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EEc",
        Call::Input(Layout::Gnu, Input::Delimited),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev",
        Call::Construct(Layout::Gnu),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2Ev",
        Call::Construct(Layout::Gnu),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
        Call::Destroy,
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED2Ev",
        Call::Destroy,
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc",
        Call::Compare(Layout::Gnu),
    ),
];

pub(super) fn find(symbol: &str) -> Option<Call> {
    let normalized = without_tags(name(symbol));
    let symbol = normalized.as_str();
    if let Some((_, call)) = CALLS.iter().find(|(candidate, _)| *candidate == symbol) {
        return Some(*call);
    }

    if let Some(code) = symbol
        .strip_prefix("_ZNSo9_M_insertI")
        .and_then(|s| s.strip_suffix("EERSoT_"))
        .filter(|s| s.len() == 1)
    {
        return integer(code, false);
    }
    if let Some(code) = symbol
        .strip_prefix("_ZNSi10_M_extractI")
        .and_then(|s| s.strip_suffix("EERSiRT_"))
        .filter(|s| s.len() == 1)
    {
        return integer(code, true);
    }
    if let Some(code) = symbol
        .strip_prefix("_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsE")
        .filter(|s| s.len() == 1)
    {
        return integer(code, false);
    }
    if let Some(code) = symbol
        .strip_prefix("_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEErsER")
        .filter(|s| s.len() == 1)
    {
        return integer(code, true);
    }
    if let Some(code) = symbol.strip_prefix("_ZNSolsE").filter(|s| s.len() == 1) {
        return integer(code, false);
    }
    if let Some(code) = symbol.strip_prefix("_ZNSirsER").filter(|s| s.len() == 1) {
        return integer(code, true);
    }
    symbol.starts_with("_Z").then_some(Call::Unsupported)
}

fn integer(code: &str, input: bool) -> Option<Call> {
    let (signed, bits) = match code {
        "b" if !input => (false, 8),
        "s" => (true, 16),
        "t" => (false, 16),
        "i" => (true, 32),
        "j" => (false, 32),
        "l" | "x" => (true, 64),
        "m" | "y" => (false, 64),
        _ => return Some(Call::Unsupported),
    };
    Some(if input {
        Call::InputInteger { signed, bits }
    } else {
        Call::Integer { signed, bits }
    })
}

pub(super) fn stream_symbol(symbol: &str) -> Option<bool> {
    match name(symbol) {
        "_ZSt3cin" | "_ZNSt3__13cinE" => Some(true),
        "_ZSt4cout" | "_ZNSt3__14coutE" => Some(false),
        _ => None,
    }
}

// Each failure aborts the imported call: continuing with a guessed value would
// change the executed program. The implementations retain symbolic byte terms.
pub(super) trait Machine {
    type Byte: Clone;
    type Value;
    fn result(&self, value: u64) -> Self::Value;
    type Error;
    fn bound(&self) -> usize;
    fn error(&self, message: &str) -> Self::Error;
    fn constant(&self, value: u8) -> Self::Byte;
    fn argument(&mut self, index: usize) -> Result<u64, Self::Error>;
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<Self::Byte>, Self::Error>;
    fn write(&mut self, address: u64, bytes: &[Self::Byte]) -> Result<(), Self::Error>;
    fn end_input(&mut self, address: u64) -> Result<(), Self::Error>;
    fn alternate_string_layout(&self) -> bool;
    fn character(&mut self) -> Result<Self::Byte, Self::Error>;
    fn byte_value(&mut self, byte: Self::Byte) -> Result<u8, Self::Error>;
    fn word(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn relocate(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn store_word(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn allocate(&mut self, length: usize) -> Result<u64, Self::Error>;
    fn equal(&mut self, byte: &Self::Byte, value: u8) -> Result<bool, Self::Error>;
    fn whitespace(&mut self, byte: &Self::Byte) -> Result<bool, Self::Error>;
    fn input(&mut self, consume: bool) -> Result<Option<Self::Byte>, Self::Error>;
    fn output(&mut self, bytes: Vec<Self::Byte>) -> Result<(), Self::Error>;
    fn integer(&mut self, signed: bool, bits: u8, direction: Direction) -> Result<(), Self::Error>;
    fn compare(
        &mut self,
        left: &[Self::Byte],
        right: &[Self::Byte],
        layout: Layout,
    ) -> Result<Self::Value, Self::Error>;
    fn stream(&mut self, address: u64, input: bool) -> Result<(), Self::Error>;
    fn manipulator(&mut self, address: u64) -> Result<Call, Self::Error>;
}

fn address<M: Machine>(machine: &M, base: u64, offset: u64) -> Result<u64, M::Error> {
    base.checked_add(offset)
        .ok_or_else(|| machine.error("C++ object address overflows"))
}

fn text<M: Machine>(machine: &mut M, pointer: u64) -> Result<Vec<M::Byte>, M::Error> {
    let mut bytes = Vec::new();
    for offset in 0..machine.bound() {
        let location = address(machine, pointer, offset as u64)?;
        let byte = machine.read(location, 1)?.remove(0);
        if machine.equal(&byte, 0)? {
            return Ok(bytes);
        }
        bytes.push(byte);
    }
    Err(machine.error("C++ string exceeds model bound"))
}

fn string<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
) -> Result<Vec<M::Byte>, M::Error> {
    let layout = if matches!(layout, Layout::Llvm) && machine.alternate_string_layout() {
        Layout::LlvmAlternate
    } else {
        layout
    };
    let (pointer, length) = match layout {
        Layout::Gnu => (
            machine.word(object)?,
            machine.word(address(machine, object, 8)?)?,
        ),
        Layout::LlvmAlternate => {
            let header_address = address(machine, object, 23)?;
            let byte = machine.read(header_address, 1)?.remove(0);
            let header = machine.byte_value(byte)?;
            if header & 128 == 0 {
                if header > 22 {
                    return Err(machine.error("invalid libc++ short string size"));
                }
                (object, u64::from(header))
            } else {
                (
                    machine.word(object)?,
                    machine.word(address(machine, object, 8)?)?,
                )
            }
        }
        Layout::Llvm => {
            let byte = machine.read(object, 1)?.remove(0);
            let header = machine.byte_value(byte)?;
            if header & 1 == 0 {
                if header >> 1 > 22 {
                    return Err(machine.error("invalid libc++ short string size"));
                }
                (address(machine, object, 1)?, u64::from(header >> 1))
            } else {
                (
                    machine.word(address(machine, object, 16)?)?,
                    machine.word(address(machine, object, 8)?)?,
                )
            }
        }
    };
    if length > machine.bound() as u64 {
        return Err(machine.error("C++ string exceeds model bound"));
    }
    machine.read(pointer, length as usize)
}

fn assign<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
    mut bytes: Vec<M::Byte>,
) -> Result<(), M::Error> {
    let layout = if matches!(layout, Layout::Llvm) && machine.alternate_string_layout() {
        Layout::LlvmAlternate
    } else {
        layout
    };
    let length = bytes.len();
    if length > machine.bound() {
        return Err(machine.error("C++ input exceeds model bound"));
    }
    bytes.push(machine.constant(0));
    let pointer = match layout {
        Layout::Gnu => {
            let pointer = if length <= 15 {
                address(machine, object, 16)?
            } else {
                machine.allocate(bytes.len())?
            };
            machine.store_word(object, pointer)?;
            machine.store_word(address(machine, object, 8)?, length as u64)?;
            if length > 15 {
                machine.store_word(address(machine, object, 16)?, length as u64)?;
            }
            pointer
        }
        Layout::LlvmAlternate if length <= 22 => {
            machine.write(
                address(machine, object, 23)?,
                &[machine.constant(length as u8)],
            )?;
            object
        }
        Layout::LlvmAlternate => {
            let pointer = machine.allocate(bytes.len())?;
            machine.store_word(object, pointer)?;
            machine.store_word(address(machine, object, 8)?, length as u64)?;
            machine.store_word(
                address(machine, object, 16)?,
                bytes.len() as u64 | (1 << 63),
            )?;
            pointer
        }
        Layout::Llvm if length <= 22 => {
            machine.write(object, &[machine.constant((length * 2) as u8)])?;
            address(machine, object, 1)?
        }
        Layout::Llvm => {
            let capacity = bytes.len().saturating_add(1) & !1;
            let pointer = machine.allocate(capacity)?;
            machine.store_word(object, (capacity as u64) | 1)?;
            machine.store_word(address(machine, object, 8)?, length as u64)?;
            machine.store_word(address(machine, object, 16)?, pointer)?;
            pointer
        }
    };
    machine.write(pointer, &bytes)
}

pub(super) fn execute<M: Machine>(machine: &mut M, call: Call) -> Result<M::Value, M::Error> {
    if matches!(call, Call::Ignore | Call::Destroy) {
        return Ok(machine.result(0));
    }
    if matches!(call, Call::Unsupported) {
        return Err(machine.error("unsupported C++ import"));
    }
    let first = machine.argument(0)?;
    if matches!(call, Call::StringAllocate) {
        let capacity_pointer = machine.argument(1)?;
        let capacity = machine.word(capacity_pointer)?;
        let old_capacity = machine.argument(2)?;
        let Some(double) = old_capacity.checked_mul(2) else {
            return Err(machine.error("C++ string capacity overflows"));
        };
        let capacity = if capacity > old_capacity && capacity < double {
            double
        } else {
            capacity
        };
        if capacity > machine.bound() as u64 {
            return Err(machine.error("C++ string capacity exceeds model bound"));
        }
        machine.store_word(capacity_pointer, capacity)?;
        let pointer = machine.allocate(capacity as usize + 1)?;
        return Ok(machine.result(pointer));
    }
    if matches!(call, Call::Allocate) {
        if first > machine.bound() as u64 {
            return Err(machine.error("C++ allocation exceeds model bound"));
        }
        let pointer = machine.allocate(first as usize)?;
        return Ok(machine.result(pointer));
    }
    if let Call::ConstructText(layout) | Call::ConstructRange(layout) = call {
        let pointer = machine.argument(1)?;
        let bytes = if matches!(call, Call::ConstructRange(_)) {
            let length = machine.argument(2)?;
            if length > machine.bound() as u64 {
                return Err(machine.error("C++ string initialization exceeds model bound"));
            }
            machine.read(pointer, length as usize)?
        } else {
            text(machine, pointer)?
        };
        assign(machine, first, layout, bytes)?;
        return Ok(machine.result(first));
    }
    match call {
        Call::Construct(layout) => {
            assign(machine, first, layout, Vec::new())?;
            return Ok(machine.result(first));
        }
        Call::Compare(layout) => {
            let left = string(machine, first, layout)?;
            let pointer = machine.argument(1)?;
            let right = text(machine, pointer)?;
            return machine.compare(&left, &right, layout);
        }
        _ => {}
    }
    let input = matches!(call, Call::Input(..) | Call::InputInteger { .. });
    machine.stream(first, input)?;
    let call = if matches!(call, Call::Manipulator) {
        let pointer = machine.argument(1)?;
        machine.manipulator(pointer)?
    } else {
        call
    };
    let mut eof = false;
    let bytes = match call {
        Call::Text => {
            let pointer = machine.argument(1)?;
            text(machine, pointer)?
        }
        Call::String(layout) => {
            let object = machine.argument(1)?;
            string(machine, object, layout)?
        }
        Call::Write => {
            let pointer = machine.argument(1)?;
            let length = machine.argument(2)?;
            if length > machine.bound() as u64 {
                return Err(machine.error("C++ output exceeds model bound"));
            }
            machine.read(pointer, length as usize)?
        }
        Call::Character => {
            vec![machine.character()?]
        }
        Call::Endl => vec![machine.constant(10)],
        Call::Flush => Vec::new(),
        Call::Integer { signed, bits } | Call::InputInteger { signed, bits } => {
            let direction = if input {
                Direction::Input
            } else {
                Direction::Output
            };
            machine.integer(signed, bits, direction)?;
            eof = input && machine.input(false)?.is_none();
            Vec::new()
        }
        Call::Input(layout, kind) => {
            let line = !matches!(kind, Input::Word);
            let delimiter = if matches!(kind, Input::Delimited) {
                machine.argument(2)? as u8
            } else {
                10
            };
            let destination = machine.argument(1)?;
            let mut bytes = Vec::new();
            if machine.input(false)?.is_none() {
                return Err(machine.error("unsupported C++ input failure at EOF"));
            }
            if !line {
                while let Some(byte) = machine.input(false)? {
                    if !machine.whitespace(&byte)? {
                        break;
                    }
                    machine.input(true)?;
                }
            }
            let mut delimited = false;
            while let Some(byte) = machine.input(false)? {
                if line && machine.equal(&byte, delimiter)? {
                    machine.input(true)?;
                    delimited = true;
                    break;
                }
                if !line && machine.whitespace(&byte)? {
                    break;
                }
                machine.input(true)?;
                bytes.push(byte);
                if bytes.len() > machine.bound() {
                    return Err(machine.error("C++ input exceeds model bound"));
                }
            }
            if !line && bytes.is_empty() {
                return Err(machine.error("unsupported C++ input failure"));
            }
            eof = !delimited && machine.input(false)?.is_none();
            assign(machine, destination, layout, bytes)?;
            Vec::new()
        }
        _ => return Err(machine.error("unsupported C++ stream operation")),
    };
    if eof {
        machine.end_input(first)?;
    }
    machine.output(bytes)?;
    Ok(machine.result(first))
}

// PLT display names are demangled; dispatch still uses the original import.
pub(super) fn imported_name<'image>(
    image: &'image Image,
    display: &'image str,
) -> Option<&'image str> {
    if image.imports.values().any(|symbol| symbol == display) {
        return Some(display);
    }
    if !display.contains('(') {
        return None;
    }
    let mut matched = None;
    for symbol in image.imports.values() {
        if symbol == display || crate::loader::demangle_name(symbol) == display {
            if matched.is_some_and(|previous| previous != symbol) {
                return None;
            }
            matched = Some(symbol.as_str());
        }
    }
    matched
}

// libstdc++'s 64-bit basic_ios virtual base and classic ctype cache are read
// inline by getline and endl, even when the actual I/O call is imported.
pub(super) fn initialize<M: Machine>(machine: &mut M, image: &Image) -> Result<(), M::Error> {
    if crate::arch::pointer_bytes(image.isa) != 8
        && (image
            .imports
            .values()
            .any(|symbol| stream_symbol(symbol).is_some())
            || image
                .data_symbols
                .values()
                .any(|symbol| stream_symbol(symbol).is_some()))
    {
        return Err(machine.error("unsupported C++ ABI: requires 64-bit pointers"));
    }
    for (&slot, symbol) in &image.imports {
        if matches!(find(symbol), Some(Call::Endl | Call::Flush)) {
            machine.relocate(slot, slot)?;
        }
    }
    for input in [true, false] {
        let mut objects: Vec<(u64, bool)> = image
            .data_symbols
            .iter()
            .filter(|(_, symbol)| stream_symbol(symbol) == Some(input))
            .map(|(&address, symbol)| (address, name(symbol).starts_with("_ZSt")))
            .collect();
        for (&slot, symbol) in &image.imports {
            if stream_symbol(symbol) != Some(input) {
                continue;
            }
            if image
                .data_symbols
                .get(&slot)
                .is_some_and(|symbol| stream_symbol(symbol) == Some(input))
            {
                continue;
            }
            let object = machine.allocate(512)?;
            machine.relocate(slot, object)?;
            objects.push((object, name(symbol).starts_with("_ZSt")));
        }
        for (object, gnu) in objects {
            let vtable = machine.allocate(64)?;
            let base = if input { 16 } else { 8 };
            machine.store_word(vtable, base)?;
            machine.store_word(object, address(machine, vtable, 24)?)?;
            if !gnu {
                machine.store_word(address(machine, object, base + 8)?, 0x1002)?;
                machine.store_word(address(machine, object, base + 16)?, 6)?;
                machine.store_word(address(machine, object, base + 24)?, 0)?;
                machine.store_word(address(machine, object, base + 32)?, 0)?;
                continue;
            }
            let facet = machine.allocate(320)?;
            machine.store_word(address(machine, object, base + 8)?, 6)?;
            machine.store_word(address(machine, object, base + 16)?, 0)?;
            machine.store_word(address(machine, object, base + 24)?, 0x1002)?;
            machine.store_word(address(machine, object, base + 32)?, 0)?;
            machine.store_word(address(machine, object, base + 240)?, facet)?;
            let mut cache = vec![machine.constant(1)];
            for byte in 0..=255 {
                cache.push(machine.constant(byte));
            }
            machine.write(address(machine, facet, 56)?, &cache)?;
        }
    }
    Ok(())
}

fn without_tags(symbol: &str) -> String {
    let mut output = String::new();
    let mut position = 0;
    let bytes = symbol.as_bytes();
    while position < bytes.len() {
        if bytes[position] == b'B' {
            let mut end = position + 1;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            if end > position + 1
                && let Ok(length) = symbol[position + 1..end].parse::<usize>()
                && let Some(next) = end
                    .checked_add(length)
                    .filter(|next| *next <= bytes.len() && symbol.is_char_boundary(*next))
            {
                position = next;
                continue;
            }
        }
        let Some(character) = symbol[position..].chars().next() else {
            break;
        };
        output.push(character);
        position += character.len_utf8();
    }
    output
}

pub(super) fn stream_object(image: &Image, address: u64, input: bool) -> Option<Layout> {
    let Some(symbol) = image.data_symbols.get(&address) else {
        return None;
    };
    if stream_symbol(symbol) != Some(input) {
        return None;
    }
    Some(if name(symbol).starts_with("_ZSt") {
        Layout::Gnu
    } else {
        Layout::Llvm
    })
}

pub(super) fn validate_stream<M: Machine>(
    machine: &mut M,
    object: u64,
    input: bool,
    layout: Layout,
) -> Result<(), M::Error> {
    let base = if input { 16 } else { 8 };
    let (flags_offset, width_offset) = if matches!(layout, Layout::Gnu) {
        (24, 16)
    } else {
        (8, 24)
    };
    let flags = machine.word(address(machine, object, base + flags_offset)?)?;
    let width = machine.word(address(machine, object, base + width_offset)?)?;
    let state = machine.word(address(machine, object, base + 32)?)?;
    if flags != 0x1002 || width != 0 || state != 0 {
        return Err(machine.error("unsupported C++ stream formatting or error state"));
    }
    Ok(())
}

pub(super) fn eof<M: Machine>(machine: &mut M, object: u64) -> Result<(), M::Error> {
    machine.store_word(address(machine, object, 48)?, 2)
}

pub(super) fn local_name(image: &Image, target: u64) -> Option<&'static str> {
    let Some(function) = image.functions.get(&target) else {
        return None;
    };
    let Some(display) = function.name.as_deref() else {
        return None;
    };
    if !display.contains("std::") {
        return None;
    }
    let display = without_display_tags(display);
    CALLS
        .iter()
        .find(|(symbol, call)| {
            (symbol.contains("St3__1") || matches!(call, Call::Endl | Call::Flush))
                && crate::loader::demangle_name(symbol) == display
        })
        .map(|(symbol, _)| *symbol)
}

fn without_display_tags(display: &str) -> String {
    let mut output = String::new();
    let mut rest = display;
    while let Some(start) = rest.find("[abi:") {
        output.push_str(&rest[..start]);
        let Some(end) = rest[start..].find(']') else {
            return display.to_owned();
        };
        rest = &rest[start + end + 1..];
    }
    output.push_str(rest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mangled_dispatch_rejects_other_types() {
        assert!(matches!(
            find("_ZNSolsEi@GLIBCXX_3.4"),
            Some(Call::Integer {
                signed: true,
                bits: 32
            })
        ));
        assert!(matches!(find("_ZNSolsEd"), Some(Call::Unsupported)));
        assert!(matches!(
            find("_ZSt4endlIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6_"),
            Some(Call::Unsupported)
        ));
        assert!(matches!(
            find("__ZNSt3__1lsB8ne190107INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc"),
            Some(Call::Text)
        ));
        assert!(find("printf").is_none());
        assert_eq!(
            without_tags("_ZB18446744073709551616x"),
            "_ZB18446744073709551616x"
        );
        assert_eq!(without_tags("_ZB2é"), "_Z");
    }
}
