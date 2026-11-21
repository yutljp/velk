//! Declarations of the functions a body calls or takes the address of.

use std::collections::{BTreeSet, HashMap};

use super::{CType, FunctionIr, declaration, sanitize, unused_signature, variables};
use crate::render::symbols::FunctionSymbols;

pub(super) struct Input<'a> {
    pub(super) ir: &'a FunctionIr,
    pub(super) symbols: &'a FunctionSymbols<'a>,
    /// The printed name of the function itself, which needs no declaration.
    pub(super) own: &'a str,
    pub(super) body: &'a str,
    pub(super) mentions: &'a variables::Mentions<'a>,
    pub(super) code_names: &'a rustc_hash::FxHashSet<&'a str>,
    /// The functions the body names outside a call.
    pub(super) taken: &'a BTreeSet<String>,
    pub(super) call_returns_used: &'a HashMap<String, bool>,
}

pub(super) fn callees(input: &Input<'_>) -> String {
    let Input {
        ir,
        symbols,
        body,
        mentions,
        code_names,
        taken,
        call_returns_used,
        ..
    } = *input;
    let mut call_returns: rustc_hash::FxHashMap<String, &CType> = rustc_hash::FxHashMap::default();
    for (address, ty) in &symbols.import_returns {
        if let Some(name) = symbols.import_name(address) {
            call_returns.insert(sanitize(name), ty);
        }
    }
    for (address, ty) in &symbols.function_returns {
        let name = symbols
            .functions
            .get(address)
            .map_or_else(|| format!("sub_{address:x}"), |name| sanitize(name));
        call_returns.insert(name, ty);
    }
    // The callees whose calls are printed with their declarations are
    // declared as their debug information declares them.
    let mut declared_callees: HashMap<String, String> = ir
        .callee_signatures
        .iter()
        .filter_map(|(target, signature)| {
            let callee = symbols
                .functions
                .get(target)
                .map_or_else(|| format!("sub_{target:x}"), |name| sanitize(name));
            if callee == input.own || !mentions.contains(&callee) {
                return None;
            }
            if let Some(header) =
                super::super::support::declaration_header(&callee, symbols.target_format)
            {
                return Some((callee, format!("#include <{header}>\n")));
            }
            let params = if signature.params.is_empty() {
                "void".to_owned()
            } else {
                signature
                    .params
                    .iter()
                    .map(|(_, ty)| ty.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let prototype = declaration(&signature.ret, &format!("{callee}({params})"));
            Some((callee, format!("{prototype};\n")))
        })
        .collect();
    for (callee, prototype) in &symbols.library_prototypes {
        if callee == input.own
            || declared_callees.contains_key(callee)
            || !mentions.contains(callee)
        {
            continue;
        }
        declared_callees.insert(
            callee.clone(),
            super::super::support::prototype(callee, prototype, symbols.target_format),
        );
    }
    for callee in taken.iter() {
        if callee == input.own
            || declared_callees.contains_key(callee)
            || !code_names.contains(callee.as_str())
        {
            continue;
        }
        if let Some(header) =
            super::super::support::declaration_header(callee, symbols.target_format)
        {
            declared_callees.insert(callee.clone(), format!("#include <{header}>\n"));
            continue;
        }
        let Some(prototype) = crate::analysis::prototypes::of(
            callee,
            symbols.target_format == Some(crate::loader::Format::MachO),
        ) else {
            continue;
        };
        declared_callees.insert(
            callee.clone(),
            super::super::support::prototype(callee, prototype, symbols.target_format),
        );
    }
    if !body.contains("main(")
        && let Some(prototype) = declared_callees.get_mut("main")
    {
        *prototype = "int main(int, char **, char **);\n".to_owned();
    }
    let mut prototypes: String = taken
        .iter()
        .filter(|taken| {
            *taken != input.own
                && !declared_callees.contains_key(*taken)
                && code_names.contains(taken.as_str())
        })
        .map(|taken| {
            if taken == "main" && !body.contains("main(") {
                return "int main(int, char **, char **);\n".to_owned();
            }
            if let Some(types) = symbols
                .import_parameters
                .iter()
                .find_map(|(address, types)| {
                    let Some(name) = symbols.functions.get(address) else {
                        return None;
                    };
                    (sanitize(name) == *taken).then_some(types)
                })
            {
                let ty = call_returns.get(taken).copied().unwrap_or(&CType::U64);
                let params = if types.is_empty() {
                    "void".to_owned()
                } else {
                    types
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let specified = declaration(ty, &format!("{taken}({params})"));
                let unspecified = declaration(ty, &format!("{taken}()"));
                return format!("#if defined(__x86_64__) && !defined(_WIN32)\n{unspecified};\n#else\n{specified};\n#endif\n");
            }
            if let Some(types) = symbols
                .unused_parameters
                .iter()
                .find_map(|(address, types)| {
                    let name = symbols
                        .functions
                        .get(address)
                        .map_or_else(|| format!("sub_{address:x}"), |name| sanitize(name));
                    (name == *taken).then_some(types)
                })
            {
                let ret = if types.params.is_empty()
                    && types.ret == CType::Void
                    && call_returns_used.get(taken) == Some(&true)
                {
                    call_returns.get(taken).copied().unwrap_or(&CType::U64)
                } else {
                    &types.ret
                };
                let parameters = if types.params.iter().any(super::super::prelude::promoted_parameter) {
                    unused_signature(&types.params, &mut std::collections::HashSet::<String>::new())
                } else {
                    String::new()
                };
                let prototype = declaration(ret, &format!("{taken}({parameters})"));
                return format!("{prototype};\n");
            }
            if let Some(types) = symbols.function_parameters.iter().find_map(|(address, types)| {
                let name = symbols.functions.get(address).map_or_else(
                    || format!("sub_{address:x}"), |name| sanitize(name));
                (name == *taken).then_some(types)
            }) {
                let ret = call_returns.get(taken).copied().unwrap_or(&CType::U64);
                let params = unused_signature(types, &mut std::collections::HashSet::<String>::new());
                return format!("{};\n", declaration(ret, &format!("{taken}({params})")));
            }
            if body.contains(&format!("{taken}(")) {
                let ty = call_returns.get(taken).copied().unwrap_or(&CType::U64);
                format!("{ty} {taken}();\n")
            } else {
                let ty = call_returns.get(taken).copied().unwrap_or(&CType::Void);
                format!("{ty} {taken}();\n")
            }
        })
        .collect();
    let mut declared_callees: Vec<(String, String)> = declared_callees.into_iter().collect();
    declared_callees.sort();
    for (_, prototype) in declared_callees {
        prototypes.push_str(&prototype);
    }
    prototypes
}
