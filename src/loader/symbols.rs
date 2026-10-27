pub(crate) fn demangle(name: &str) -> Option<String> {
    let name = name
        .strip_prefix('_')
        .filter(|_| name.starts_with("__Z") || name.starts_with("__R"))
        .unwrap_or(name);
    if let Ok(symbol) = rustc_demangle::try_demangle(name)
        && (name.starts_with("_R")
            || (name.starts_with("_ZN") && name.rsplit_once("17h").is_some()))
    {
        return Some(format!("{symbol:#}"));
    }
    if name.starts_with("_Z")
        && let Ok(symbol) = cpp_demangle::Symbol::new(name)
        && let Ok(text) = symbol.demangle()
    {
        return Some(text);
    }
    None
}
