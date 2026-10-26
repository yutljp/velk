use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::{CType, Precision};

mod combined;

pub(super) use combined::resolve;

#[derive(Clone, Copy)]
pub(super) enum View {
    Unsigned(u8),
    Float(Precision),
}

impl View {
    pub(super) fn width(self) -> u64 {
        match self {
            Self::Unsigned(width) => u64::from(width),
            Self::Float(precision) => u64::from(precision.bits() / 8),
        }
    }

    fn key(self) -> u8 {
        match self {
            Self::Unsigned(width) => width,
            Self::Float(precision) => 16 + precision.bits() / 8,
        }
    }

    pub(super) fn ty(self) -> &'static str {
        match self {
            Self::Unsigned(width) => super::expr::type_of(width, false),
            Self::Float(Precision::Single) => "float",
            Self::Float(Precision::Double) => "double",
        }
    }

    fn suffix(self) -> String {
        match self {
            Self::Unsigned(width) => format!("u{}", u32::from(width) * 8),
            Self::Float(precision) => format!("f{}", precision.bits()),
        }
    }
}

struct Global {
    name: String,
    view: View,
    array: bool,
}

#[derive(Default)]
struct Used {
    objects: BTreeMap<u64, String>,
    view_names: BTreeMap<u64, String>,
    views: BTreeMap<(u64, u8), Global>,
    names: HashSet<String>,
}

#[derive(Default)]
pub(super) struct Globals {
    linkable: HashSet<u64>,
    types: HashMap<u64, CType>,
    sizes: HashMap<u64, u64>,
    headers: HashMap<u64, String>,
    names: HashMap<u64, String>,
    repeated: HashSet<String>,
    used: RefCell<Used>,
}

impl Globals {
    pub(super) fn new(
        symbols: &super::Symbols,
        reserved: impl IntoIterator<Item = String>,
    ) -> Self {
        let names: HashMap<_, _> = symbols
            .import_slots
            .iter()
            .chain(&symbols.data)
            .map(|(address, name)| {
                let name = symbols
                    .library_variables
                    .get(address)
                    .map_or_else(|| identifier(name), |variable| variable.name.clone());
                (*address, name)
            })
            .collect();
        let mut counts = HashMap::<&str, usize>::new();
        for name in names.values() {
            *counts.entry(name).or_default() += 1;
        }
        let repeated: HashSet<String> = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(name, _)| name.to_owned())
            .collect();
        let variables: Vec<_> = symbols
            .library_variables
            .iter()
            .filter(|(address, variable)| {
                names
                    .get(address)
                    .is_some_and(|name| !repeated.contains(name))
                    && variable.size != 0
                    && address.checked_add(variable.size).is_some()
            })
            .collect();
        Self {
            linkable: symbols
                .data
                .iter()
                .filter(|(_, name)| identifier(name) == **name)
                .map(|(address, _)| *address)
                .collect(),
            types: variables
                .iter()
                .map(|(address, variable)| (**address, variable.ty.clone()))
                .collect(),
            sizes: variables
                .iter()
                .map(|(address, variable)| (**address, variable.size))
                .collect(),
            headers: variables
                .iter()
                .map(|(address, variable)| (**address, variable.header.clone()))
                .collect(),
            names,
            repeated,
            used: RefCell::new(Used {
                names: reserved.into_iter().collect(),
                ..Used::default()
            }),
        }
    }

    pub(super) fn pointer(&self, address: u64, view: View) -> String {
        if let Some(ty) = self.target(address)
            && match view {
                View::Unsigned(width) if self.headers.contains_key(&address) => {
                    self.sizes.get(&address) == Some(&u64::from(width))
                }
                View::Unsigned(width) => ty
                    .integer()
                    .is_some_and(|(bits, _)| bits == u32::from(width) * 8),
                View::Float(_) => ty.to_string() == view.ty(),
            }
            && let Some(pointer) = self.object_pointer(address)
        {
            return pointer;
        }
        if let Some((base, offset)) = self.containing(address)
            && offset
                .checked_add(view.width())
                .is_some_and(|end| end <= self.sizes[&base])
            && let Some(pointer) = self.object_pointer(base)
        {
            return if offset == 0 {
                format!("(({} *){pointer})", view.ty())
            } else {
                format!("(({} *)((uint8_t *){pointer} + {offset}))", view.ty())
            };
        }
        let key = (address, view.key());
        let mut used = self.used.borrow_mut();
        if let Some(global) = used.views.get(&key) {
            return format!("(&{})", global.name);
        }
        let base = self
            .names
            .get(&address)
            .cloned()
            .unwrap_or_else(|| format!("g_{address:x}"));
        let mut name = base.clone();
        if let Some(name_at_address) = used.view_names.get(&address) {
            name = format!("{name_at_address}_{}", view.suffix());
        } else if self.repeated.contains(&base) || used.names.contains(&name) {
            name = format!("{base}_{address:x}");
        }
        let candidate = name.clone();
        let mut suffix = 2;
        while used.names.contains(&name) {
            name = format!("{candidate}_{suffix}");
            suffix += 1;
        }
        used.names.insert(name.clone());
        used.view_names
            .entry(address)
            .or_insert_with(|| name.clone());
        used.views.insert(
            key,
            Global {
                name: name.clone(),
                view,
                array: false,
            },
        );
        format!("(&{name})")
    }

    pub(super) fn array_pointer(&self, address: u64, view: View) -> String {
        let pointer = self.pointer(address, view);
        if let Some(global) = self.used.borrow_mut().views.get_mut(&(address, view.key())) {
            global.array = true;
            return global.name.clone();
        }
        pointer
    }

    pub(super) fn add_types(
        &mut self,
        ir: &crate::ir::FunctionIr,
        layouts: &HashMap<String, super::naming::Layout>,
    ) {
        for (address, ty, size) in &ir.debug_globals {
            if self.headers.contains_key(address) {
                continue;
            }
            let Some(name) = self.names.get(address) else {
                continue;
            };
            if !self.linkable.contains(address)
                || self.repeated.contains(name)
                || self.used.borrow().names.contains(name)
                || !ir
                    .definitions
                    .iter()
                    .all(|definition| !definition.fields.contains(name))
                || ir
                    .debug_globals
                    .iter()
                    .any(|(other, other_ty, other_size)| {
                        other == address && (other_ty != ty || other_size != size)
                    })
            {
                continue;
            }
            let element = match ty {
                CType::Array(element) => element.as_ref(),
                ty => ty,
            };
            if matches!(element, CType::Named(name) if name.split_whitespace().any(|word| matches!(word, "bool" | "_Bool")))
            {
                continue;
            }
            let width = match element {
                CType::Named(name) if name.starts_with("struct ") => {
                    layouts.get(&name[7..]).map(|layout| layout.size)
                }
                ty if ty.integer().is_some() || ty.is_sse_float() => {
                    CType::pointer_to(ty.clone()).pointee_size().map(u64::from)
                }
                _ => None,
            };
            if let Some(width) = width.filter(|width| *width != 0)
                && (if matches!(ty, CType::Array(_)) {
                    size.is_multiple_of(width)
                } else {
                    *size == width
                })
                && *size != 0
                && address.checked_add(*size).is_some()
            {
                self.types.insert(*address, ty.clone());
                self.sizes.insert(*address, *size);
            }
        }
        self.used.borrow_mut().names.extend(
            self.types
                .keys()
                .filter_map(|address| self.names.get(address))
                .cloned(),
        );
    }

    pub(super) fn target(&self, address: u64) -> Option<CType> {
        self.types.get(&address).map(|ty| match ty {
            CType::Array(element) => element.as_ref().clone(),
            ty => ty.clone(),
        })
    }

    pub(super) fn header_object(&self, address: u64, width: u8) -> Option<(String, CType)> {
        if !self.headers.contains_key(&address)
            || self.sizes.get(&address) != Some(&u64::from(width))
        {
            return None;
        }
        let Some(pointer) = self.object_pointer(address) else {
            return None;
        };
        Some((format!("*{pointer}"), self.types[&address].clone()))
    }

    pub(super) fn containing(&self, address: u64) -> Option<(u64, u64)> {
        let mut found = self
            .sizes
            .iter()
            .filter(|(start, size)| address >= **start && address - **start < **size);
        let Some((start, _)) = found.next() else {
            return None;
        };
        if found.next().is_some() {
            return None;
        }
        Some((*start, address - *start))
    }

    pub(super) fn object_pointer(&self, address: u64) -> Option<String> {
        let Some(ty) = self.types.get(&address) else {
            return None;
        };
        let Some(name) = self.names.get(&address) else {
            return None;
        };
        self.used.borrow_mut().objects.insert(address, name.clone());
        Some(if matches!(ty, CType::Array(_)) {
            name.clone()
        } else {
            format!("(&{name})")
        })
    }

    pub(super) fn object_declarations(&self, body: &str) -> String {
        self.used
            .borrow()
            .objects
            .iter()
            .filter(|(_, name)| super::function::code_mentions(body, name))
            .map(|(address, name)| {
                if let Some(header) = self.headers.get(address) {
                    return format!("#include <{header}>\n\n");
                }
                format!(
                    "extern {}; /* address: 0x{address:x} */\n\n",
                    match &self.types[address] {
                        CType::Array(element) => format!("{element} {name}[]"),
                        ty => super::declaration(ty, name),
                    }
                )
            })
            .collect()
    }

    pub(super) fn finish(&self, body: &str, code: &mut String) -> String {
        let used = self.used.borrow();
        let mut groups: Vec<Vec<(u64, &Global)>> = Vec::new();
        let mut end = 0;
        for ((address, _), global) in &used.views {
            if !super::function::code_mentions(body, &global.name) {
                continue;
            }
            if groups.is_empty()
                || (*address >= end
                    && groups
                        .last()
                        .and_then(|group| group.last())
                        .is_none_or(|(previous, _)| previous != address))
            {
                groups.push(Vec::new());
            }
            end = end.max(address.saturating_add(global.view.width()));
            groups
                .last_mut()
                .expect("a group was just inserted")
                .push((*address, global));
        }
        let mut declarations = self.object_declarations(body);
        let mut replacements = HashMap::new();
        for name in used.objects.values() {
            replacements.insert(format!("*(&{name})"), name.clone());
        }
        for group in groups {
            let (base, first) = group[0];
            let mut primary = first;
            let mut extent = 0;
            let mut array = false;
            for (address, global) in &group {
                if *address == base && global.view.width() > primary.view.width() {
                    primary = global;
                }
                extent = extent.max((address - base).saturating_add(global.view.width()));
                array |= global.array;
            }
            let ty = if extent > primary.view.width() {
                "uint8_t"
            } else {
                primary.view.ty()
            };
            array |= extent > primary.view.width();
            let name = &used.view_names[&base];
            let pointer = if array {
                name.clone()
            } else {
                format!("(&{name})")
            };
            for (address, global) in &group {
                let offset = address - base;
                let view_pointer = view_pointer(&pointer, ty, global.view.ty(), offset);
                if !array && offset == 0 && global.view.ty() == ty {
                    replacements.insert(format!("*(&{})", global.name), name.clone());
                } else if array && offset == 0 && global.view.ty() == ty {
                    replacements.insert(format!("*(&{})", global.name), format!("{name}[0]"));
                } else {
                    replacements.insert(format!("*(&{})", global.name), format!("*{view_pointer}"));
                }
                replacements.insert(format!("(&{})", global.name), view_pointer.clone());
                if global.array {
                    replacements.insert(global.name.clone(), view_pointer.clone());
                }
                // Indexed accesses use the pointer without an address operator.
                replacements.insert(format!("{}[", global.name), format!("{view_pointer}["));
            }
            let suffix = if array { "[]" } else { "" };
            declarations.push_str(&format!(
                "extern {ty} {name}{suffix}; /* address: 0x{base:x} */\n\n"
            ));
        }
        *code = replace_expressions(code, &replacements);
        declarations
    }
}

fn replace_expressions(code: &str, replacements: &HashMap<String, String>) -> String {
    let mut output = String::new();
    let bytes = code.as_bytes();
    let mut at = 0;
    let mut copied = 0;
    let mut member = false;
    let mut record_type = false;
    let mut record_tag = false;
    let mut record_braces = 0usize;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if bytes[at..].starts_with(b"/*") {
            at += 2;
            while at < bytes.len() && !bytes[at..].starts_with(b"*/") {
                at += 1;
            }
            at = at.saturating_add(2).min(bytes.len());
        } else if matches!(bytes[at], b'\'' | b'"') {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                let next = bytes[at];
                at += 1;
                if next == b'\\' {
                    at = at.saturating_add(1).min(bytes.len());
                } else if next == quote {
                    break;
                }
            }
        } else if (record_type || record_tag) && bytes[at..].starts_with(b"__attribute__(") {
            at += b"__attribute__(".len();
            let mut depth = 1usize;
            while at < bytes.len() && depth != 0 {
                if bytes[at] == b'(' {
                    depth += 1;
                }
                if bytes[at] == b')' {
                    depth -= 1;
                }
                at += 1;
            }
        } else {
            let start = at;
            let was_member = member;
            member = false;
            if bytes[at..].starts_with(b"*(&") || bytes[at..].starts_with(b"(&") {
                let prefix = if bytes[at] == b'*' { 3 } else { 2 };
                at += prefix;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                if bytes.get(at) == Some(&b')') {
                    at += 1;
                }
            } else if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                if bytes.get(at) == Some(&b'[') {
                    at += 1;
                }
            } else {
                if bytes[at] == b'{' && (record_type || record_tag || record_braces != 0) {
                    record_braces += 1;
                    record_type = false;
                } else if bytes[at] == b'}' && record_braces != 0 {
                    record_braces -= 1;
                }
                if bytes[at..].starts_with(b"->") {
                    member = true;
                    at += 2;
                    continue;
                }
                member = if bytes[at].is_ascii_whitespace() {
                    was_member
                } else {
                    record_tag = false;
                    bytes[at] == b'.'
                };
                at += 1;
                continue;
            }
            if !was_member
                && !record_type
                && record_braces == 0
                && let Some(to) = replacements.get(&code[start..at])
            {
                output.push_str(&code[copied..start]);
                output.push_str(to);
                copied = at;
            }
            if bytes[start].is_ascii_alphabetic() || bytes[start] == b'_' {
                record_tag = record_type;
                record_type = matches!(&code[start..at], "struct" | "union");
            }
        }
    }
    output.push_str(&code[copied..]);
    output
}

fn identifier(name: &str) -> String {
    let name = super::sanitize(name);
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || reserved_identifier(&name)
    {
        format!("data_{name}")
    } else {
        name
    }
}

pub(crate) fn reserved_identifier(name: &str) -> bool {
    matches!(
        name,
        "alignas"
            | "alignof"
            | "auto"
            | "bool"
            | "break"
            | "case"
            | "char"
            | "const"
            | "constexpr"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "nullptr"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "static_assert"
            | "struct"
            | "switch"
            | "thread_local"
            | "true"
            | "typedef"
            | "typeof"
            | "typeof_unqual"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_BitInt"
            | "_Bool"
            | "_Complex"
            | "_Decimal32"
            | "_Decimal64"
            | "_Decimal128"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "intptr_t"
            | "uintptr_t"
            | "size_t"
            | "ptrdiff_t"
            | "__builtin_memcpy"
    )
}

fn view_pointer(pointer: &str, storage_type: &str, view_type: &str, offset: u64) -> String {
    if offset == 0 && view_type == storage_type {
        pointer.to_owned()
    } else if offset == 0 {
        format!("(({view_type} *){pointer})")
    } else {
        format!("(({view_type} *)((uint8_t *){pointer} + {offset}))")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_keywords_are_not_global_identifiers() {
        for name in [
            "true",
            "false",
            "nullptr",
            "typeof",
            "typeof_unqual",
            "static_assert",
            "thread_local",
            "alignas",
            "alignof",
            "constexpr",
            "_BitInt",
        ] {
            assert_eq!(identifier(name), format!("data_{name}"));
        }
        assert_eq!(identifier("value"), "value");
    }

    #[test]
    fn views_share_addresses_but_keep_their_storage_types() {
        let symbols = super::super::Symbols {
            data: HashMap::from([(0x1000, "value".to_owned())]),
            ..Default::default()
        };
        let globals = Globals::new(&symbols, []);
        let wide = globals.pointer(0x1000, View::Unsigned(8));
        let byte = globals.pointer(0x1000, View::Unsigned(1));
        let float = globals.pointer(0x1000, View::Float(Precision::Single));
        let adjacent = globals.pointer(0x1001, View::Unsigned(1));
        assert_eq!(wide, globals.pointer(0x1000, View::Unsigned(8)));
        let body = format!("*{wide}; *{byte}; *{float}; *{adjacent};");
        let mut code = body.clone();
        let declarations = globals.finish(&body, &mut code);
        assert_eq!(declarations.matches("extern ").count(), 1);
        assert!(declarations.contains("extern uint64_t value; /* address: 0x1000 */"));
        assert!(code.contains("value;"), "{code}");
        assert!(code.contains("uint8_t *"), "{code}");
        assert!(code.contains("float *"), "{code}");
        assert!(code.contains("+ 1"), "{code}");
    }

    #[test]
    fn views_do_not_shadow_visible_names_or_each_other() {
        let symbols = super::super::Symbols {
            data: HashMap::from([
                (0x10, "value".to_owned()),
                (0x20, "same.name".to_owned()),
                (0x30, "same_name".to_owned()),
                (0x40, "return".to_owned()),
                (0x50, "32bit".to_owned()),
                (0x60, "uint32_t".to_owned()),
            ]),
            ..Default::default()
        };
        let globals = Globals::new(&symbols, ["value".to_owned(), "value_10".to_owned()]);
        let view = globals.pointer(0x10, View::Unsigned(4));
        assert_eq!(view, "(&value_10_2)");
        assert_eq!(globals.pointer(0x20, View::Unsigned(4)), "(&same_name_20)");
        assert_eq!(globals.pointer(0x30, View::Unsigned(4)), "(&same_name_30)");
        assert_eq!(globals.pointer(0x40, View::Unsigned(4)), "(&data_return)");
        assert_eq!(globals.pointer(0x50, View::Unsigned(4)), "(&data_32bit)");
        assert_eq!(globals.pointer(0x60, View::Unsigned(4)), "(&data_uint32_t)");
        assert!(
            globals
                .finish("value_10_u32_20", &mut String::new())
                .is_empty()
        );
        assert_eq!(
            globals
                .finish(&view, &mut String::new())
                .matches("extern ")
                .count(),
            1
        );
    }

    #[test]
    fn view_replacement_is_simultaneous_and_leaves_literals_unchanged() {
        let symbols = super::super::Symbols {
            data: HashMap::from([(0x1000, "value".to_owned())]),
            ..Default::default()
        };
        let globals = Globals::new(&symbols, []);
        let float = globals.pointer(0x1000, View::Float(Precision::Single));
        let wide = globals.pointer(0x1000, View::Unsigned(8));
        let body = format!("*{float}; *{wide}; puts(\"*{wide} λ\"); /* *{float} */");
        let mut code = body.clone();
        let declarations = globals.finish(&body, &mut code);
        assert!(
            declarations.contains("extern uint64_t value;"),
            "{declarations}"
        );
        assert!(code.starts_with("*((float *)(&value)); value;"), "{code}");
        assert!(
            code.contains(&format!("puts(\"*{wide} λ\"); /* *{float} */")),
            "{code}"
        );
    }
}
