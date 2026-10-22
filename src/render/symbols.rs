use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct Symbols {
    pub functions: HashMap<u64, String>,
    pub import_slots: HashMap<u64, String>,
    pub function_returns: HashMap<u64, crate::ir::CType>,
    pub import_returns: HashMap<u64, crate::ir::CType>,
    pub data: HashMap<u64, String>,
    /// Additional source names to keep generated identifiers distinct from.
    /// Only names supplied by the caller or retained by the loader are known.
    pub reserved_names: HashSet<String>,
}

impl Symbols {
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
