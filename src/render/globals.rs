use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::{CType, Precision};

#[derive(Clone, Copy)]
pub(super) enum View {
    Unsigned(u8),
    Float(Precision),
}

impl View {
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
}

#[derive(Default)]
struct Used {
    objects: BTreeMap<u64, String>,
    views: BTreeMap<(u64, u8), Global>,
    names: HashSet<String>,
}

#[derive(Default)]
pub(super) struct Globals {
    linkable: HashSet<u64>,
    types: HashMap<u64, CType>,
    sizes: HashMap<u64, u64>,
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
            .map(|(address, name)| (*address, identifier(name)))
            .collect();
        let mut counts = HashMap::<&str, usize>::new();
        for name in names.values() {
            *counts.entry(name).or_default() += 1;
        }
        let repeated = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(name, _)| name.to_owned())
            .collect();
        Self {
            linkable: symbols
                .data
                .iter()
                .filter(|(_, name)| identifier(name) == **name)
                .map(|(address, _)| *address)
                .collect(),
            types: HashMap::new(),
            sizes: HashMap::new(),
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
                View::Unsigned(width) => ty
                    .integer()
                    .is_some_and(|(bits, _)| bits == u32::from(width) * 8),
                View::Float(_) => ty.to_string() == view.ty(),
            }
            && let Some(pointer) = self.object_pointer(address)
        {
            return pointer;
        }
        let key = (address, view.key());
        let mut used = self.used.borrow_mut();
        if let Some(global) = used.views.get(&key) {
            return global.name.clone();
        }
        let base = self.names.get(&address).cloned().unwrap_or_else(|| {
            let kind = match view {
                View::Unsigned(1) => "byte",
                View::Unsigned(2) => "word",
                View::Unsigned(4) => "dword",
                View::Unsigned(_) => "qword",
                View::Float(Precision::Single) => "float",
                View::Float(Precision::Double) => "double",
            };
            format!("{kind}_{address:x}")
        });
        let mut name = base.clone();
        if used.views.keys().any(|(other, _)| *other == address) {
            name = format!("{base}_{}", view.suffix());
        } else if self.repeated.contains(&base) || used.names.contains(&name) {
            name = format!("{base}_{address:x}_{}", view.suffix());
        }
        let candidate = name.clone();
        let mut suffix = 2;
        while used.names.contains(&name) {
            name = format!("{candidate}_{suffix}");
            suffix += 1;
        }
        used.names.insert(name.clone());
        used.views.insert(
            key,
            Global {
                name: name.clone(),
                view,
            },
        );
        name
    }

    pub(super) fn add_types(
        &mut self,
        ir: &crate::ir::FunctionIr,
        layouts: &HashMap<String, super::naming::Layout>,
    ) {
        for (address, ty, size) in &ir.debug_globals {
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
            .filter(|(_, name)| super::variables::mentions(body, name))
            .map(|(address, name)| {
                format!(
                    "extern {};\n",
                    match &self.types[address] {
                        CType::Array(element) => format!("{element} {name}[]"),
                        ty => super::declaration(ty, name),
                    }
                )
            })
            .collect()
    }

    pub(super) fn declarations(&self, body: &str) -> Vec<String> {
        self.used
            .borrow()
            .views
            .iter()
            .filter(|(_, global)| super::variables::mentions(body, &global.name))
            .map(|((address, _), global)| {
                let ty = global.view.ty();
                format!("{ty} *const {} = ({ty} *)0x{address:x}ULL;", global.name)
            })
            .collect()
    }
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
        let declarations = globals.declarations(&format!("{wide} {byte} {float} {adjacent}"));
        assert_eq!(declarations.len(), 4);
        assert!(declarations.contains(&format!("uint64_t *const {wide} = (uint64_t *)0x1000ULL;")));
        assert!(declarations.contains(&format!("uint8_t *const {byte} = (uint8_t *)0x1000ULL;")));
        assert!(declarations.contains(&format!("float *const {float} = (float *)0x1000ULL;")));
        assert!(declarations.contains(&format!(
            "uint8_t *const {adjacent} = (uint8_t *)0x1001ULL;"
        )));
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
        let globals = Globals::new(&symbols, ["value".to_owned(), "value_10_u32".to_owned()]);
        let view = globals.pointer(0x10, View::Unsigned(4));
        assert_eq!(view, "value_10_u32_2");
        assert_eq!(globals.pointer(0x20, View::Unsigned(4)), "same_name_20_u32");
        assert_eq!(globals.pointer(0x30, View::Unsigned(4)), "same_name_30_u32");
        assert_eq!(globals.pointer(0x40, View::Unsigned(4)), "data_return");
        assert_eq!(globals.pointer(0x50, View::Unsigned(4)), "data_32bit");
        assert_eq!(globals.pointer(0x60, View::Unsigned(4)), "data_uint32_t");
        assert!(globals.declarations("value_10_u32_20").is_empty());
        assert_eq!(globals.declarations(&view).len(), 1);
    }
}
