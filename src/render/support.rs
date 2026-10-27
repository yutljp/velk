//! Headers and type declarations required by standalone output.

use super::function::code_names;

pub(super) fn definitions(code: &str) -> String {
    let names_in_code: rustc_hash::FxHashSet<&str> = code_names(code).collect();
    let mut definitions = String::from("#include <stdint.h>\n\n");
    for (names, header) in [
        (&["bool", "true", "false"][..], "stdbool.h"),
        (&["size_t", "ptrdiff_t", "NULL", "wchar_t"][..], "stddef.h"),
    ] {
        if names.iter().any(|name| names_in_code.contains(name)) {
            definitions.push_str(&format!("#include <{header}>\n\n"));
        }
    }
    for name in [
        "isunordered",
        "NAN",
        "INFINITY",
        "fma",
        "fmaf",
        "sqrt",
        "sqrtf",
        "fabs",
        "fabsf",
    ] {
        if names_in_code.contains(name) {
            definitions.push_str("#include <math.h>\n\n");
            break;
        }
    }
    if names_in_code.contains("FILE") && !code.contains("#include <wchar.h>") {
        definitions.push_str("#include <stdio.h>\n\n");
    }
    for (name, definition) in [
        ("DIR", "typedef struct velk_directory DIR;"),
        (
            "pthread_mutex_t",
            "typedef struct velk_mutex pthread_mutex_t;",
        ),
        (
            "pthread_mutexattr_t",
            "typedef struct velk_mutex_attributes pthread_mutexattr_t;",
        ),
        (
            "pthread_attr_t",
            "typedef struct velk_thread_attributes pthread_attr_t;",
        ),
        ("pthread_t", "typedef uintptr_t pthread_t;"),
        ("pthread_key_t", "typedef uint32_t pthread_key_t;"),
        ("pid_t", "typedef int32_t pid_t;"),
        ("ssize_t", "typedef intptr_t ssize_t;"),
        ("off_t", "typedef int64_t off_t;"),
    ] {
        if names_in_code.contains(name) {
            definitions.push_str(&format!("{definition}\n\n"));
        }
    }
    super::prelude::section(&definitions)
}

pub(super) fn prototype(name: &str, prototype: &crate::analysis::prototypes::Prototype) -> String {
    let mut records = Vec::new();
    for ty in prototype.params.iter().chain([&prototype.ret]) {
        if let Some(record) = crate::analysis::prototypes::record_name(ty) {
            records.push(format!("{record}; "));
        }
    }
    records.sort();
    records.dedup();
    let mut params = prototype
        .params
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if !params.is_empty() && prototype.variadic {
        params.push_str(", ...");
    } else if params.is_empty() && !prototype.variadic {
        params.push_str("void");
    }
    // Parentheses keep function-like macros in host headers from expanding declarations.
    let text = super::declaration(&prototype.ret, &format!("({name})({params})"));
    format!("{}{text};\n", records.concat())
}
