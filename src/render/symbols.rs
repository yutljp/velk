use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

pub(crate) struct FunctionSymbols<'symbols> {
    symbols: &'symbols Symbols,
    pub(super) function_parameters: Cow<'symbols, HashMap<u64, Vec<crate::ir::CType>>>,
    pub(super) import_parameters: Cow<'symbols, HashMap<u64, Vec<crate::ir::CType>>>,
    pub(super) unused_parameters:
        Cow<'symbols, HashMap<u64, crate::analysis::prototypes::Prototype>>,
}

impl<'symbols> FunctionSymbols<'symbols> {
    pub(crate) fn new(symbols: &'symbols Symbols) -> Self {
        Self {
            symbols,
            function_parameters: Cow::Borrowed(&symbols.function_parameters),
            import_parameters: Cow::Borrowed(&symbols.import_parameters),
            unused_parameters: Cow::Borrowed(&symbols.unused_parameters),
        }
    }

    pub(crate) fn new_with_analysis(
        symbols: &'symbols Symbols,
        analysis: &crate::analysis::Analysis,
    ) -> Self {
        let mut view = Self::new(symbols);
        if !analysis.import_parameters.is_empty() {
            view.import_parameters
                .to_mut()
                .extend(analysis.import_parameters.clone());
        }
        if !analysis.unused_parameters.is_empty() {
            view.unused_parameters
                .to_mut()
                .extend(analysis.unused_parameters.clone());
        }
        if !analysis.callee_parameters.is_empty() {
            view.function_parameters
                .to_mut()
                .extend(analysis.callee_parameters.clone());
        }
        view
    }
}

impl std::ops::Deref for FunctionSymbols<'_> {
    type Target = Symbols;

    fn deref(&self) -> &Self::Target {
        self.symbols
    }
}

#[derive(Default, Clone)]
pub struct Symbols {
    /// Value-preserving parameter types recovered for direct calls to imports.
    pub import_parameters: HashMap<u64, Vec<crate::ir::CType>>,
    /// Linkage stubs call imports rather than defining another C function.
    pub import_thunks: HashSet<u64>,
    /// Parameters unused by the body, including positions omitted by some callers.
    pub unused_parameters: HashMap<u64, crate::analysis::prototypes::Prototype>,
    /// Recovered parameters that require a prototype under default promotions.
    pub function_parameters: HashMap<u64, Vec<crate::ir::CType>>,
    /// Go runtime parameter types used to infer pointer values stored on the stack.
    pub runtime_parameters: HashMap<u64, Vec<crate::ir::CType>>,
    /// Candidate export names attached to an indirect call expression.
    pub api_hash_comments: HashMap<(u64, crate::ir::Expr), String>,
    pub user_definitions: HashSet<String>,
    pub unnamed_functions: HashSet<u64>,
    pub original_functions: HashMap<u64, String>,
    pub variable_names: HashMap<(u64, u16), String>,
    pub variable_types: HashMap<(u64, u16), crate::ir::CType>,
    pub stack_types: HashMap<(u64, i64), crate::ir::CType>,
    pub stack_names: HashMap<(u64, i64), String>,
    /// Named parameter counts for functions declared variadic in debug information.
    pub variadic_functions: HashMap<u64, usize>,
    /// The object format of a known little-endian target.
    pub target_format: Option<crate::loader::Format>,
    /// Target-specific declarations of imported functions, keyed by printed name.
    pub library_prototypes: HashMap<String, crate::analysis::prototypes::Prototype>,
    pub functions: HashMap<u64, String>,
    /// C++ method signatures without their owning class.
    pub cpp_methods: HashMap<u64, String>,
    /// ABI-checked scalar prototypes for recovered virtual methods.
    pub cpp_signatures: HashMap<u64, crate::ir::DeclaredSignature>,
    /// Class names and table ownership supplied by runtime descriptors.
    pub cpp_classes: Vec<crate::loader::classes::Class>,
    /// Original runtime helper names that establish Go value shapes.
    pub go_value_shapes: HashMap<u64, String>,
    /// Original names of known allocators, before conversion to C identifiers.
    pub allocator_names: HashMap<u64, String>,
    pub import_slots: HashMap<u64, String>,
    /// Byte addends retained from imported pointer relocations.
    pub import_addends: HashMap<u64, i64>,
    pub function_returns: HashMap<u64, crate::ir::CType>,
    pub import_returns: HashMap<u64, crate::ir::CType>,
    pub data: HashMap<u64, String>,
    /// Exact constant-table names used only for already identified global accesses.
    pub constant_names: HashMap<u64, String>,
    /// Header declarations for data objects stored at their symbol addresses.
    pub library_variables: HashMap<u64, crate::analysis::prototypes::LibraryVariable>,
    pub objc_selectors: HashMap<u64, String>,
    /// Additional source names to keep generated identifiers distinct from.
    /// Only names supplied by the caller or retained by the loader are known.
    pub reserved_names: HashSet<String>,
}

impl Symbols {
    pub(super) fn import_name(&self, slot: &u64) -> Option<&String> {
        if self
            .import_addends
            .get(slot)
            .is_some_and(|addend| *addend != 0)
        {
            return None;
        }
        self.import_slots.get(slot)
    }

    pub(crate) fn original_or_printed_function_name(&self, address: u64) -> Option<&String> {
        self.original_functions
            .get(&address)
            .or_else(|| self.functions.get(&address))
    }

    pub(super) fn use_macho_c_names(&mut self) {
        let occupied: HashSet<_> = self
            .functions
            .values()
            .chain(self.import_slots.values())
            .chain(self.data.values())
            .map(|name| super::sanitize(name))
            .collect();
        let mut renamed = Vec::new();
        for name in self
            .functions
            .values_mut()
            .chain(self.import_slots.values_mut())
            .chain(self.data.values_mut())
        {
            let Some(candidate) = name.strip_prefix('_') else {
                continue;
            };
            // Keep the link spelling when removing its prefix would be unsafe
            // or would take another symbol's C identifier.
            if candidate.is_empty()
                || candidate.starts_with(|c: char| c.is_ascii_digit())
                || super::sanitize(candidate) != candidate
                || super::globals::reserved_identifier(candidate)
                || occupied.contains(candidate)
            {
                continue;
            }
            renamed.push((super::sanitize(name), candidate.to_owned()));
            *name = candidate.to_owned();
        }
        for (original, name) in renamed {
            if let Some(prototype) = self.library_prototypes.remove(&original) {
                self.library_prototypes.insert(name, prototype);
            }
        }
    }

    pub(crate) fn reserve_name(&mut self, name: &str) {
        let short = super::short_name(name);
        self.reserved_names.extend([
            name.to_owned(),
            super::sanitize(name),
            super::sanitize(&short),
            short,
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macho_names_strip_one_prefix_only_when_safe() {
        let mut symbols = Symbols {
            functions: HashMap::from([
                (1, "_plain".into()),
                (2, "__double".into()),
                (3, "_int".into()),
                (4, "_1digit".into()),
                (5, "_taken".into()),
            ]),
            import_slots: HashMap::from([(6, "_memcpy".into())]),
            library_prototypes: HashMap::from([(
                "_memcpy".into(),
                crate::analysis::prototypes::of("memcpy", false)
                    .unwrap()
                    .clone(),
            )]),
            data: HashMap::from([(7, "taken".into()), (8, "_object".into())]),
            ..Default::default()
        };
        symbols.use_macho_c_names();
        for (address, expected) in [
            (1, "plain"),
            (2, "_double"),
            (3, "_int"),
            (4, "_1digit"),
            (5, "_taken"),
        ] {
            assert_eq!(symbols.functions[&address], expected);
            let mut ir = crate::ir::FunctionIr::single_block(
                crate::loader::Isa::AArch64,
                vec![crate::ir::Stmt::Ret {
                    value: crate::ir::Expr::Const(1),
                }],
            );
            ir.addr = address;
            ir.ret_type = crate::ir::CType::I32;
            let code = super::super::render(&ir, &[], &symbols, &[]);
            assert!(
                code.contains(&format!("int32_t {expected}(void)")),
                "{code}"
            );
        }
        assert_eq!(symbols.import_slots[&6], "memcpy");
        assert!(symbols.library_prototypes.contains_key("memcpy"));
        assert!(!symbols.library_prototypes.contains_key("_memcpy"));
        assert_eq!(symbols.data[&8], "object");
        let mut ir = crate::ir::FunctionIr::single_block(
            crate::loader::Isa::AArch64,
            vec![crate::ir::Stmt::Ret {
                value: crate::ir::Expr::Load {
                    addr: Box::new(crate::ir::Expr::Const(8)),
                    width: 32,
                    signed: true,
                },
            }],
        );
        ir.ret_type = crate::ir::CType::I32;
        let code = super::super::render(&ir, &[], &symbols, &[(8, 4)]);
        assert!(code.contains("extern int64_t object;"), "{code}");
        assert!(code.contains("return object;"), "{code}");
    }

    #[test]
    fn source_names_reserve_their_emitted_forms() {
        let mut symbols = Symbols::default();
        symbols.reserve_name("root::module::Type::method(int)");
        assert_eq!(
            symbols.reserved_names,
            HashSet::from([
                "root::module::Type::method(int)".to_owned(),
                "root__module__Type__method_int_".to_owned(),
                "Type::method".to_owned(),
                "Type__method".to_owned(),
            ])
        );
    }

    #[test]
    fn reserving_aliases_preserves_symbol_bindings() {
        let mut symbols = Symbols {
            functions: HashMap::from([(0x40, "original".to_owned())]),
            import_slots: HashMap::from([(0x40, "imported".to_owned())]),
            data: HashMap::from([(0x40, "object".to_owned())]),
            ..Default::default()
        };
        symbols.reserve_name("velk_x86_fs_base");
        symbols.reserve_name("velk_x86_fs_base");
        assert_eq!(
            symbols.reserved_names,
            HashSet::from(["velk_x86_fs_base".to_owned()])
        );
        assert_eq!(symbols.functions[&0x40], "original");
        assert_eq!(symbols.import_slots[&0x40], "imported");
        assert_eq!(symbols.data[&0x40], "object");
    }
}
