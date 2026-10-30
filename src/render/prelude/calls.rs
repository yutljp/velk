//! Conversions required when separately printed functions share typed definitions.

use std::collections::HashMap;
use std::ops::Range;

#[derive(Clone, Copy, PartialEq)]
enum Type {
    Pointer(u64),
    Scalar,
    Bool,
}

struct Token<'code> {
    text: &'code str,
    range: Range<usize>,
}

fn tokens(code: &str) -> Vec<Token<'_>> {
    let bytes = code.as_bytes();
    let mut result = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if bytes[at] == b'#' {
            while at < bytes.len() {
                if bytes[at] == b'\n' && (at == 0 || bytes[at - 1] != b'\\') {
                    break;
                }
                at += 1;
            }
            continue;
        }
        let start = at;
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if bytes[at..].starts_with(b"/*") {
            at += 2;
            while at < bytes.len() && !bytes[at..].starts_with(b"*/") {
                at += 1;
            }
            at = at.saturating_add(2).min(bytes.len());
            continue;
        }
        if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                let byte = bytes[at];
                at += 1;
                if byte == b'\\' {
                    at = at.saturating_add(1).min(bytes.len());
                } else if byte == quote {
                    break;
                }
            }
        } else if bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_' {
            at += 1;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
        } else {
            at += 1;
            while !code.is_char_boundary(at) {
                at += 1;
            }
        }
        result.push(Token {
            text: &code[start..at],
            range: start..at,
        });
    }
    result
}

fn closing(tokens: &[Token<'_>], open: usize) -> Option<usize> {
    let end = match tokens[open].text {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        _ => return None,
    };
    let mut depth = 0usize;
    let later_tokens = tokens.iter().enumerate().skip(open);
    for (index, token) in later_tokens {
        if token.text == tokens[open].text {
            depth += 1;
        } else if token.text == end {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn parts<'a, 'code>(tokens: &'a [Token<'code>]) -> Vec<&'a [Token<'code>]> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < tokens.len() {
        if matches!(tokens[at].text, "(" | "[" | "{") {
            let Some(end) = closing(tokens, at) else {
                return result;
            };
            at = end;
        } else if tokens[at].text == "," {
            result.push(&tokens[start..at]);
            start = at + 1;
        }
        at += 1;
    }
    if start < tokens.len() {
        result.push(&tokens[start..]);
    }
    result
}

fn type_name(tokens: &[Token<'_>]) -> Option<Type> {
    let mut known = false;
    let mut pointer = false;
    let mut boolean = false;
    let mut tag = false;
    for token in tokens {
        if tag {
            tag = false;
            continue;
        }
        match token.text {
            "*" => pointer = true,
            "const" | "volatile" | "restrict" | "static" | "extern" | "inline" => (),
            "struct" | "union" | "enum" => {
                known = true;
                tag = true;
            }
            "_Bool" | "bool" => {
                known = true;
                boolean = true;
            }
            "void" | "char" | "short" | "int" | "long" | "signed" | "unsigned" | "float"
            | "double" | "size_t" | "ssize_t" | "uintptr_t" | "intptr_t" => known = true,
            name if name.ends_with("_t")
                && (name.starts_with("int") || name.starts_with("uint")) =>
            {
                known = true
            }
            _ => return None,
        }
    }
    known.then_some(if pointer {
        Type::Pointer(pointer_type(tokens))
    } else if boolean {
        Type::Bool
    } else {
        Type::Scalar
    })
}

fn pointer_type(tokens: &[Token<'_>]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hash = std::hash::DefaultHasher::new();
    let mut depth = 0;
    let mut void = false;
    let mut words = Vec::new();
    for token in tokens {
        match token.text {
            "const" | "volatile" | "restrict" | "static" | "extern" | "inline" => (),
            "void" => void = true,
            "*" => depth += 1,
            word => words.push(word),
        }
    }
    let base = words.join(" ");
    let base = match base.as_str() {
        "int8_t" => "signed char",
        "uint8_t" => "unsigned char",
        "int16_t" | "signed short" | "signed short int" | "short int" => "short",
        "uint16_t" | "unsigned short int" => "unsigned short",
        "int32_t" | "signed" | "signed int" => "int",
        "uint32_t" | "unsigned" => "unsigned int",
        _ => &base,
    };
    base.hash(&mut hash);
    if void && depth == 1 {
        return 0;
    }
    void.hash(&mut hash);
    depth.hash(&mut hash);
    hash.finish()
}

fn declaration<'a>(tokens: &'a [Token<'_>]) -> Option<(&'a str, Type)> {
    let Some(last) = tokens.last() else {
        return None;
    };
    let Some(ty) = type_name(&tokens[..tokens.len() - 1]) else {
        return None;
    };
    Some((last.text, ty))
}

fn members(tokens: &[Token<'_>], name: &str) -> HashMap<String, Type> {
    let mut result = HashMap::new();
    let mut start = 0;
    for (at, token) in tokens.iter().enumerate() {
        if token.text == ";" {
            let field = &tokens[start..at];
            let array = field.iter().position(|token| token.text == "[");
            let field = &field[..array.unwrap_or(field.len())];
            if let Some((member, ty)) = declaration(field) {
                result.insert(
                    format!("{name}.{member}"),
                    if array.is_some() {
                        Type::Pointer(0)
                    } else {
                        ty
                    },
                );
            }
            start = at + 1;
        }
    }
    result
}

fn expression(
    mut tokens: &[Token<'_>],
    variables: &HashMap<String, Type>,
    returns: &HashMap<&str, Type>,
) -> Option<Type> {
    let mut cast = None;
    while tokens.first().is_some_and(|token| token.text == "(") {
        let Some(end) = closing(tokens, 0) else {
            return None;
        };
        if end == tokens.len() - 1 {
            tokens = &tokens[1..end];
        } else if let Some(ty) = type_name(&tokens[1..end]) {
            cast = Some(ty);
            break;
        } else {
            break;
        }
    }
    let mut at = 0;
    while at < tokens.len() {
        if matches!(tokens[at].text, "(" | "[") {
            let Some(end) = closing(tokens, at) else {
                return None;
            };
            at = end;
        } else if at > 0 && matches!(tokens[at].text, "+" | "-") {
            let left = expression(&tokens[..at], variables, returns);
            let right = expression(&tokens[at + 1..], variables, returns);
            return match (left, right, tokens[at].text) {
                (Some(Type::Pointer(target)), Some(Type::Scalar | Type::Bool), _)
                | (Some(Type::Scalar | Type::Bool), Some(Type::Pointer(target)), "+") => {
                    Some(Type::Pointer(target))
                }
                (Some(Type::Pointer(_)), Some(Type::Pointer(_)), "-") => Some(Type::Scalar),
                (Some(Type::Scalar | Type::Bool), Some(Type::Scalar | Type::Bool), _) => {
                    Some(Type::Scalar)
                }
                _ => None,
            };
        } else if at > 0 && matches!(tokens[at].text, "=" | "!" | "<" | ">" | "?" | ":") {
            return None;
        }
        at += 1;
    }
    if cast.is_some() {
        return cast;
    }
    let Some(first) = tokens.first() else {
        return None;
    };
    if first.text == "&" || first.text.starts_with('"') {
        return Some(Type::Pointer(0));
    }
    if tokens.len() == 3 && tokens[1].text == "." {
        return variables
            .get(&format!("{}.{}", first.text, tokens[2].text))
            .copied();
    }
    if tokens.len() == 1 {
        if first
            .text
            .starts_with(|c: char| c.is_ascii_digit() || c == '\'')
        {
            return Some(Type::Scalar);
        }
        return variables.get(first.text).copied();
    }
    if tokens.get(1).is_some_and(|token| token.text == "(")
        && closing(tokens, 1) == Some(tokens.len() - 1)
    {
        return returns.get(first.text).copied();
    }
    None
}

pub(super) fn conform(code: &str) -> String {
    let tokens = tokens(code);
    let mut signatures = HashMap::new();
    let mut returns = HashMap::new();
    let mut functions = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < tokens.len() {
        if tokens[at].text == "(" && at > start {
            let Some(end) = closing(&tokens, at) else {
                break;
            };
            if tokens.get(end + 1).is_some_and(|token| token.text == "{") {
                let Some(body_end) = closing(&tokens, end + 1) else {
                    break;
                };
                let name = tokens[at - 1].text;
                let params = parts(&tokens[at + 1..end]);
                let types: Vec<_> = params.iter().map(|param| declaration(param)).collect();
                signatures.insert(name, types.clone());
                if let Some(ty) = type_name(&tokens[start..at - 1]) {
                    returns.insert(name, ty);
                }
                functions.push((end + 2..body_end, types));
                at = body_end;
                start = at + 1;
            } else {
                at = end;
            }
        } else if tokens[at].text == ";" {
            start = at + 1;
        } else if tokens[at].text == "{" {
            let Some(end) = closing(&tokens, at) else {
                break;
            };
            at = end;
            start = at + 1;
        }
        at += 1;
    }
    let mut edits = Vec::new();
    for (body, params) in functions {
        let mut variables: HashMap<_, _> = params
            .into_iter()
            .flatten()
            .map(|(name, ty)| (name.to_owned(), ty))
            .collect();
        let mut records = HashMap::new();
        let mut scopes = Vec::new();
        let mut statement = body.start;
        for at in body.clone() {
            if matches!(tokens[at].text, "=" | ";" | "[")
                && let Some((name, mut ty)) = declaration(&tokens[statement..at])
            {
                if tokens[at].text == "[" {
                    let mut target: Vec<_> = tokens[statement..at - 1]
                        .iter()
                        .map(|token| Token {
                            text: token.text,
                            range: token.range.clone(),
                        })
                        .collect();
                    target.push(Token {
                        text: "*",
                        range: 0..0,
                    });
                    ty = Type::Pointer(pointer_type(&target));
                }
                variables.insert(name.to_owned(), ty);
            }
            if tokens[at].text == "{" {
                if tokens[statement..at]
                    .iter()
                    .any(|token| matches!(token.text, "struct" | "union"))
                    && let Some(end) = closing(&tokens, at)
                    && let Some(name) = tokens.get(end + 1)
                {
                    records.insert(end, members(&tokens[at + 1..end], name.text));
                }
                scopes.push(variables.clone());
            } else if tokens[at].text == "}"
                && let Some(outer) = scopes.pop()
            {
                variables = outer;
                if let Some(members) = records.remove(&at) {
                    variables.extend(members);
                }
            }
            if matches!(tokens[at].text, ";" | "{" | "}") {
                statement = at + 1;
            }
            let Some(parameters) = signatures.get(tokens[at].text) else {
                continue;
            };
            if !tokens.get(at + 1).is_some_and(|token| token.text == "(") {
                continue;
            }
            let Some(end) = closing(&tokens, at + 1) else {
                continue;
            };
            let arguments = parts(&tokens[at + 2..end]);
            for (argument, parameter) in arguments.iter().zip(parameters) {
                let Some((_, expected)) = parameter else {
                    continue;
                };
                let Some(actual) = expression(argument, &variables, &returns) else {
                    continue;
                };
                if matches!(expected, Type::Pointer(_))
                    && argument.len() == 1
                    && matches!(argument[0].text, "0" | "0x0" | "NULL")
                {
                    continue;
                }
                let conversion = match (expected, actual) {
                    (Type::Pointer(_), Type::Scalar | Type::Bool) => "void *",
                    (Type::Scalar, Type::Pointer(_)) => "uintptr_t",
                    (Type::Pointer(expected), Type::Pointer(actual))
                        if *expected != 0 && actual != 0 && *expected != actual =>
                    {
                        "void *"
                    }
                    _ => continue,
                };
                let (Some(first), Some(last)) = (argument.first(), argument.last()) else {
                    continue;
                };
                edits.push((first.range.start, format!("({conversion})(")));
                edits.push((last.range.end, ")".to_owned()));
            }
        }
    }
    edits.sort_by_key(|(at, _)| *at);
    let mut output = code.to_owned();
    for (at, insertion) in edits.into_iter().rev() {
        output.insert_str(at, &insertion);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pointer_integer_arguments_need_conversions() {
        let code = "uint64_t bits(uint64_t x) { return x; }\nvoid memory(void *p) {}\nvoid boolean(_Bool b) {}\nvoid caller(void *p, uint64_t x) {\n bits(p); memory(x); bits(x); memory(p); boolean(p);\n}\n";
        let output = conform(code);
        assert!(
            output.contains(
                "bits((uintptr_t)(p)); memory((void *)(x)); bits(x); memory(p); boolean(p);"
            ),
            "{output}"
        );
        assert_eq!(conform(&output), output);
    }

    #[test]
    fn inline_record_array_arguments_keep_their_addresses() {
        let code = "void bits(uint64_t x) {}\nvoid caller(void) {\n _Alignas(16) struct __attribute__((packed)) { uint8_t gap[8]; void *pointer; } local;\n bits(local.gap); bits(local.pointer);\n}\n";
        let output = conform(code);
        assert!(
            output.contains("bits((uintptr_t)(local.gap)); bits((uintptr_t)(local.pointer));"),
            "{output}"
        );
        assert_eq!(conform(&output), output);
    }

    #[test]
    fn compatible_integer_pointer_aliases_need_no_conversion() {
        let code = "void byte(unsigned char *p) {}\nvoid word(unsigned int *p) {}\nvoid caller(uint8_t *b, uint32_t *w) { byte(b); word(w); }\n";
        assert_eq!(conform(code), code);
    }

    #[test]
    fn strings_comments_nested_calls_and_local_declarations_keep_their_types() {
        let code = "#include <stdint.h>\nuint64_t bits(uint64_t x) { return x; }\nvoid *address(void) { return 0; }\nvoid caller(void) {\n void *p = address();\n uint64_t x = 1;\n bits(p); bits(address()); bits((uint64_t)x);\n /* bits(p) */ const char *s = \"bits(p)\";\n bits(s);\n}\n";
        let output = conform(code);
        assert!(
            output
                .contains("bits((uintptr_t)(p)); bits((uintptr_t)(address())); bits((uint64_t)x);"),
            "{output}"
        );
        assert!(output.contains("/* bits(p) */ const char *s = \"bits(p)\";"));
        assert!(output.contains("bits((uintptr_t)(s));"));
        assert_eq!(conform(&output), output);
    }
}
