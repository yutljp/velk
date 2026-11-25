//! Conversions required when separately printed functions share typed definitions.

use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq)]
enum Type {
    Pointer(u64),
    Scalar,
    Bool,
}

struct Token<'code> {
    text: &'code str,
}

/// Where `token`, a token of `code`, starts in it.
fn offset(code: &str, token: &Token<'_>) -> usize {
    token.text.as_ptr() as usize - code.as_ptr() as usize
}

fn tokens(code: &str) -> Vec<Token<'_>> {
    scan(code).0
}

/// The tokens of `code`, and whether its end closes the directive, comment
/// or literal it is in, so that text after it would be read the same alone.
fn scan(code: &str) -> (Vec<Token<'_>>, bool) {
    let mut closed = true;
    let bytes = code.as_bytes();
    // A token and the space after it take about six bytes of code.
    let mut result = Vec::with_capacity(code.len() / 4);
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
            closed &= at < bytes.len();
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
            closed &= at < bytes.len();
            at = at.saturating_add(2).min(bytes.len());
            continue;
        }
        if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            at += 1;
            let mut ended = false;
            while at < bytes.len() {
                let byte = bytes[at];
                at += 1;
                if byte == b'\\' {
                    at = at.saturating_add(1).min(bytes.len());
                } else if byte == quote {
                    ended = true;
                    break;
                }
            }
            closed &= ended;
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
        });
    }
    (result, closed)
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

fn declaration<'code>(tokens: &[Token<'code>]) -> Option<(&'code str, Type)> {
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

/// The parameters of a function: the name and type of each one that reads
/// as a declaration.
type Parameters<'code> = Vec<Option<(&'code str, Type)>>;

/// The functions defined at the top level of `tokens`: the tokens of each
/// body with the parameters, the token after the last definition or
/// declaration, and whether every bracket closed: the functions after one
/// left open are not found. Their signatures and return types go into the
/// two maps.
fn definitions<'code>(
    tokens: &[Token<'code>],
    signatures: &mut HashMap<&'code str, Parameters<'code>>,
    returns: &mut HashMap<&'code str, Type>,
) -> (
    Vec<(std::ops::Range<usize>, Parameters<'code>)>,
    usize,
    bool,
) {
    let mut functions = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < tokens.len() {
        if tokens[at].text == "(" && at > start {
            let Some(end) = closing(tokens, at) else {
                return (functions, start, false);
            };
            if tokens.get(end + 1).is_some_and(|token| token.text == "{") {
                let Some(body_end) = closing(tokens, end + 1) else {
                    return (functions, start, false);
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
            let Some(end) = closing(tokens, at) else {
                return (functions, start, false);
            };
            at = end;
            start = at + 1;
        }
        at += 1;
    }
    (functions, start, true)
}

/// The conversions the calls in the bodies of `functions` need, as text to
/// insert at offsets of `code`, which `tokens` is a part of.
fn conversions<'code>(
    code: &str,
    tokens: &[Token<'code>],
    functions: Vec<(std::ops::Range<usize>, Parameters<'code>)>,
    signatures: &HashMap<&'code str, Parameters<'code>>,
    returns: &HashMap<&'code str, Type>,
    edits: &mut Vec<(usize, String)>,
) {
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
                        .map(|token| Token { text: token.text })
                        .collect();
                    target.push(Token { text: "*" });
                    ty = Type::Pointer(pointer_type(&target));
                }
                variables.insert(name.to_owned(), ty);
            }
            if tokens[at].text == "{" {
                if tokens[statement..at]
                    .iter()
                    .any(|token| matches!(token.text, "struct" | "union"))
                    && let Some(end) = closing(tokens, at)
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
            let Some(end) = closing(tokens, at + 1) else {
                continue;
            };
            let arguments = parts(&tokens[at + 2..end]);
            for (argument, parameter) in arguments.iter().zip(parameters) {
                let Some((_, expected)) = parameter else {
                    continue;
                };
                let Some(actual) = expression(argument, &variables, returns) else {
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
                edits.push((offset(code, first), format!("({conversion})(")));
                edits.push((offset(code, last) + last.text.len(), ")".to_owned()));
            }
        }
    }
}

/// `code` with each text inserted at its offset, after `before`.
fn edited(before: &str, code: &str, mut edits: Vec<(usize, String)>) -> String {
    edits.sort_by_key(|(at, _)| *at);
    let inserted: usize = edits.iter().map(|(_, insertion)| insertion.len()).sum();
    let mut output = String::with_capacity(before.len() + code.len() + inserted);
    output.push_str(before);
    let mut copied = 0;
    for (at, insertion) in edits {
        output.push_str(&code[copied..at]);
        output.push_str(&insertion);
        copied = at;
    }
    output.push_str(&code[copied..]);
    output
}

/// True when every bracket of `tokens` closes among them, each kind
/// counted alone as [`closing`] counts it.
fn balanced(tokens: &[Token<'_>]) -> bool {
    let mut depths = [0usize; 3];
    for token in tokens {
        let (kind, opens) = match token.text {
            "(" => (0, true),
            ")" => (0, false),
            "[" => (1, true),
            "]" => (1, false),
            "{" => (2, true),
            "}" => (2, false),
            _ => continue,
        };
        if opens {
            depths[kind] += 1;
        } else if depths[kind] == 0 {
            return false;
        } else {
            depths[kind] -= 1;
        }
    }
    depths == [0; 3]
}

const FUNCTION: &str = "/* velk pseudo-C:";

/// The same as [`conform_whole`] for the outputs of many functions, read
/// one function at a time so that only its tokens are held. `None` when
/// some part does not stand alone: a bracket, comment or literal runs past
/// its end. Text a part leaves after its last definition, such as a line
/// printed between two functions, is read with the next part, whose first
/// declaration it belongs to in the whole text.
fn conform_parts(before: &str, code: &str) -> Option<String> {
    let mut starts = vec![0];
    starts.extend(
        code.match_indices(FUNCTION)
            .map(|(at, _)| at)
            .filter(|at| *at != 0 && code.as_bytes()[at - 1] == b'\n'),
    );
    if starts.len() == 1 {
        return None;
    }
    starts.push(code.len());
    let mut signatures = HashMap::new();
    let mut returns = HashMap::new();
    let mut parts = Vec::with_capacity(starts.len());
    let mut begin = 0;
    for stop in starts[1..].iter().copied() {
        let (tokens, closed) = scan(&code[begin..stop]);
        if !closed || !balanced(&tokens) {
            return None;
        }
        let (defined, end, complete) = definitions(&tokens, &mut signatures, &mut returns);
        if !complete {
            return None;
        }
        parts.push((begin..stop, defined));
        begin = tokens.get(end).map_or(stop, |token| offset(code, token));
    }
    let mut edits = Vec::new();
    for (part, defined) in parts {
        if defined.is_empty() {
            continue;
        }
        let tokens = tokens(&code[part]);
        conversions(code, &tokens, defined, &signatures, &returns, &mut edits);
    }
    Some(edited(before, code, edits))
}

fn conform_whole(before: &str, code: &str) -> String {
    let tokens = tokens(code);
    let mut signatures = HashMap::new();
    let mut returns = HashMap::new();
    let mut edits = Vec::new();
    let (functions, _, _) = definitions(&tokens, &mut signatures, &mut returns);
    conversions(code, &tokens, functions, &signatures, &returns, &mut edits);
    edited(before, code, edits)
}

/// `code` with the conversions its calls need, after `before`.
pub(super) fn conform_after(before: &str, code: &str) -> String {
    conform_parts(before, code).unwrap_or_else(|| conform_whole(before, code))
}

#[cfg(test)]
fn conform(code: &str) -> String {
    conform_after("", code)
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

    #[test]
    fn functions_read_one_at_a_time_get_the_conversions_of_the_whole_text() {
        let code = "#include <stdint.h>\n/* velk pseudo-C: bits */\nuint64_t bits(uint64_t x) { return x; }\n/* velk pseudo-C: memory */\nvoid memory(void *p) {}\n/* velk pseudo-C: caller */\nvoid caller(void *p, uint64_t x) {\n bits(p); memory(x); bits(x);\n}\n";
        let output = conform_parts("", code).expect("every function stands alone");
        assert_eq!(output, conform_whole("", code));
        assert!(
            output.contains("bits((uintptr_t)(p)); memory((void *)(x)); bits(x);"),
            "{output}"
        );
        assert_eq!(conform_after("before\n", code), format!("before\n{output}"));
    }

    #[test]
    fn text_between_functions_is_read_with_the_function_after_it() {
        for between in ["0x1000\n", "int pending\n", "0x1000\n/* note */\nstatic "] {
            let code = format!(
                "/* velk pseudo-C: bits */\nuint64_t bits(uint64_t x) {{ return x; }}\n{between}/* velk pseudo-C: memory */\nvoid *memory(void *p) {{ return p; }}\n0x2000\n/* velk pseudo-C: caller */\nvoid caller(void *p, uint64_t x) {{\n bits(p); memory(x); bits(memory(p));\n}}\n0x3000\n"
            );
            let output = conform_parts("", &code).expect("every function is closed");
            assert_eq!(output, conform_whole("", &code), "{code}");
            assert!(
                output.contains("bits((uintptr_t)(p)); memory((void *)(x));"),
                "{output}"
            );
        }
    }

    #[test]
    fn text_whose_functions_do_not_stand_alone_is_read_whole() {
        let alone = "void memory(void *p) {}\nvoid caller(uint64_t x) { memory(x); }\n";
        assert!(conform_parts("", alone).is_none());
        for first in [
            "void open(void) { if (1) {\n",
            "void closed(void) { } }\n",
            "void comment(void) {} /* runs on\n",
            "void literal(void) { char *s = \"runs on; }\n",
            "#define CONTINUED \\\n",
        ] {
            let code = format!(
                "{first}/* velk pseudo-C: memory */\nvoid memory(void *p) {{}}\n/* velk pseudo-C: caller */\nvoid caller(uint64_t x) {{ memory(x); }}\n"
            );
            assert!(conform_parts("", &code).is_none(), "{code}");
            assert_eq!(conform_after("", &code), conform_whole("", &code));
        }
    }
}
