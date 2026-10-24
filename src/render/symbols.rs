use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct Symbols {
    pub functions: HashMap<u64, String>,
    /// Original runtime helper names that establish Go value shapes.
    pub go_value_shapes: HashMap<u64, String>,
    /// Original names of known allocators, before conversion to C identifiers.
    pub allocator_names: HashMap<u64, String>,
    pub import_slots: HashMap<u64, String>,
    pub function_returns: HashMap<u64, crate::ir::CType>,
    pub import_returns: HashMap<u64, crate::ir::CType>,
    pub data: HashMap<u64, String>,
    /// Additional source names to keep generated identifiers distinct from.
    /// Only names supplied by the caller or retained by the loader are known.
    pub reserved_names: HashSet<String>,
}

impl Symbols {
    pub(super) fn use_macho_c_names(&mut self) {
        let names: HashSet<_> = self
            .functions
            .values()
            .chain(self.import_slots.values())
            .chain(self.data.values())
            .cloned()
            .collect();
        let occupied: HashSet<_> = names.iter().map(|name| super::sanitize(name)).collect();
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
            *name = candidate.to_owned();
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
        assert!(code.contains("*const object ="), "{code}");
        assert!(code.contains("*object;"), "{code}");
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
