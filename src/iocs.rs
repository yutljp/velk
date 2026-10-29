//! Indicators extracted from strings found in a binary.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub function: u64,
    #[serde(serialize_with = "crate::addr::serialize")]
    pub address: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    pub kind: String,
    pub value: String,
    pub sources: Vec<String>,
    pub references: Vec<Reference>,
}

/// Classifies supported indicators in a string. IPv4-looking version text beginning with `v`
/// is excluded; a dotted numeric string without that prefix is treated as an address.
#[must_use]
pub fn classify(text: &str) -> Vec<(String, String)> {
    let mut results = BTreeMap::<(String, String), ()>::new();
    for (kind, value) in classify_one(text) {
        results.insert((kind, value), ());
    }
    for token in
        text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '(' || c == ')')
    {
        for (kind, value) in classify_one(token) {
            results.insert((kind, value), ());
        }
    }
    results.into_keys().collect()
}

fn classify_one(text: &str) -> Vec<(String, String)> {
    let mut found = BTreeMap::<(String, String), ()>::new();
    let trimmed = text.trim_matches(|c: char| !c.is_alphanumeric() && !"./:@%[]_-\\".contains(c));
    let lower = trimmed.to_ascii_lowercase();
    let mut add = |kind: &str, value: &str| {
        if !value.is_empty() {
            found.insert((kind.to_owned(), value.to_owned()), ());
        }
    };

    for scheme in ["http://", "https://", "ftp://", "ws://", "wss://"] {
        if let Some(at) = lower.find(scheme) {
            let value = &trimmed[at..];
            let end = value
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(value.len());
            let url = value[..end].trim_end_matches([')', ',', ';', '.']);
            add("url", url);
            if let Some(authority) = url.split_once("//").map(|(_, host)| host) {
                let host = authority
                    .split(['/', ':', '?', '#'])
                    .next()
                    .unwrap_or(authority);
                add_domain(host, &mut add);
            }
        }
    }
    if let Ok(address) = trimmed.parse::<std::net::IpAddr>() {
        add("ip", &address.to_string());
    }
    if let Some(at) = trimmed.find('@') {
        let (local, domain) = trimmed.split_at(at);
        let domain = &domain[1..];
        if !local.is_empty()
            && local
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
            && valid_domain(domain)
        {
            add("email", trimmed);
        }
    }
    if let Some(at) = lower.find("hklm\\").or_else(|| lower.find("hkey_")) {
        let value = &trimmed[at..];
        let end = value.find(char::is_whitespace).unwrap_or(value.len());
        add(
            "registryKey",
            value[..end].trim_end_matches([';', '"', '\'']),
        );
    }
    if trimmed.starts_with("\\\\")
        || (trimmed.len() > 2
            && trimmed.as_bytes().get(1) == Some(&b':')
            && trimmed
                .as_bytes()
                .get(2)
                .is_some_and(|b| *b == b'\\' || *b == b'/'))
    {
        add("windowsPath", trimmed);
    } else if trimmed.starts_with('/') && trimmed.len() > 1 {
        add("posixPath", trimmed);
    }
    if trimmed.starts_with("Mozilla/") {
        add("userAgent", trimmed);
    }
    add_domain(trimmed.strip_prefix("www.").unwrap_or(trimmed), &mut add);
    found.into_keys().collect()
}

fn add_domain(host: &str, add: &mut impl FnMut(&str, &str)) {
    let host = host.trim_end_matches('.');
    if valid_domain(host) {
        add("domain", host);
    }
}

fn valid_domain(host: &str) -> bool {
    let parts: Vec<_> = host.split('.').collect();
    let tld = parts.last().unwrap_or(&"").to_ascii_lowercase();
    const TLDS: &[&str] = &[
        "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "uk", "jp", "de", "fr", "ru",
        "cn", "info", "biz", "xyz", "me", "app", "dev", "site", "online", "tech",
    ];
    parts.len() >= 2
        && TLDS.contains(&tld.as_str())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn identifies_common_indicators_and_rejects_numeric_version() {
        let values = classify(
            "http://bad.example.com/a https://bad.example.com/a ftp://bad.example.com/a ws://bad.example.com/a wss://bad.example.com/a 8.8.8.8 name@example.org v1.2.3.4 /etc/passwd C:\\temp\\x HKLM\\Software\\Bad Mozilla/5.0",
        );
        for kind in [
            "url",
            "domain",
            "ip",
            "email",
            "posixPath",
            "windowsPath",
            "registryKey",
            "userAgent",
        ] {
            assert!(
                values.iter().any(|value| value.0 == kind),
                "missing {kind}: {values:?}"
            );
        }
        for scheme in ["http://", "https://", "ftp://", "ws://", "wss://"] {
            assert!(
                values
                    .iter()
                    .any(|value| value.0 == "url" && value.1.starts_with(scheme)),
                "missing {scheme} URL: {values:?}"
            );
        }
        assert!(
            !values.iter().any(|value| value.1 == "1.2.3.4"),
            "version text was classified as an address"
        );
        assert!(
            classify("ordinary sentence").is_empty(),
            "ordinary prose produced indicators"
        );
        assert!(
            !classify("text @example.com")
                .iter()
                .any(|value| value.0 == "email"),
            "an email address with spaces was accepted"
        );
    }
}
