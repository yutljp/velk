use std::ffi::OsStr;
use std::io::{self, IsTerminal};

#[derive(Clone, Copy)]
pub enum Language {
    C,
    Ir,
    Disassembly,
}

#[derive(Clone, Copy)]
pub struct Terminal {
    interactive: bool,
    color: bool,
}

impl Terminal {
    pub fn stdout() -> Self {
        Self::detect(io::stdout().is_terminal())
    }

    pub fn stderr() -> Self {
        Self::detect(io::stderr().is_terminal())
    }

    fn detect(interactive: bool) -> Self {
        Self::new(
            interactive,
            std::env::var_os("NO_COLOR").as_deref(),
            std::env::var_os("TERM").as_deref(),
        )
    }

    fn new(interactive: bool, no_color: Option<&OsStr>, term: Option<&OsStr>) -> Self {
        Self {
            interactive,
            color: interactive
                && no_color.is_none_or(OsStr::is_empty)
                && term != Some(OsStr::new("dumb")),
        }
    }

    pub fn interactive(self) -> bool {
        self.interactive
    }

    fn paint(self, text: &str, style: &str) -> String {
        if self.color && !text.is_empty() {
            format!("\x1b[{style}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    pub fn heading(self, text: &str) -> String {
        self.paint(text, "1")
    }

    pub fn muted(self, text: &str) -> String {
        self.paint(text, "2")
    }

    pub fn address(self, text: &str) -> String {
        self.paint(text, "36")
    }

    pub fn success(self, text: &str) -> String {
        self.paint(text, "32")
    }

    pub fn warning(self, text: &str) -> String {
        self.paint(text, "33")
    }

    pub fn error(self, text: &str) -> String {
        self.paint(text, "1;31")
    }

    pub fn block(self, title: &str, metadata: &str, text: &str, language: Language) -> String {
        if !self.interactive {
            return text.to_owned();
        }
        format!(
            "{}\n{}\n\n{}{}",
            self.heading(title),
            self.muted(metadata),
            self.code(text, language),
            if text.ends_with('\n') { "\n" } else { "\n\n" },
        )
    }

    fn code(self, text: &str, language: Language) -> String {
        if !self.color {
            return text.to_owned();
        }
        if matches!(language, Language::Disassembly) {
            return self.disassembly(text);
        }
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            let rest = &text[index..];
            let first = rest.chars().next().expect("remaining text");
            let (length, style) = if rest.starts_with("/*") {
                (rest.find("*/").map_or(rest.len(), |end| end + 2), Some("2"))
            } else if rest.starts_with("//") {
                (rest.find('\n').unwrap_or(rest.len()), Some("2"))
            } else if matches!(first, '\'' | '"') {
                (quoted(rest, first), Some("32"))
            } else if first.is_ascii_digit() {
                (
                    rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
                        .unwrap_or(rest.len()),
                    Some("35"),
                )
            } else if first.is_ascii_alphabetic() || first == '_' {
                let length = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                (length, keyword(&rest[..length], language))
            } else {
                (first.len_utf8(), None)
            };
            let token = &rest[..length];
            match style {
                Some(style) => out.push_str(&self.paint(token, style)),
                None => out.push_str(token),
            }
            index += length;
        }
        out
    }

    fn disassembly(self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let mut index = 0;
            let address_end = line.find(char::is_whitespace).unwrap_or(line.len());
            if line.starts_with("0x")
                && address_end > 2
                && line[2..address_end]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                out.push_str(&self.address(&line[..address_end]));
                index = address_end;
            }
            if line[index..].trim_start().starts_with("(undecodable:") {
                out.push_str(&line[index..]);
                continue;
            }
            let mut mnemonic = true;
            while index < line.len() {
                let rest = &line[index..];
                let first = rest.chars().next().expect("remaining line");
                let (length, style) = if rest.starts_with(';') || rest.starts_with("//") {
                    (rest.find('\n').unwrap_or(rest.len()), Some("2"))
                } else if matches!(first, '\'' | '"') {
                    mnemonic = false;
                    (quoted(rest, first), Some("32"))
                } else if let Some((length, number)) = assembly_number(rest) {
                    mnemonic = false;
                    (length, number.then_some("35"))
                } else if assembly_word(first) {
                    let length = rest
                        .char_indices()
                        .skip(1)
                        .find(|&(_, ch)| !assembly_word(ch))
                        .map_or(rest.len(), |(index, _)| index);
                    let word = &rest[..length];
                    let style = if mnemonic
                        && word
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
                    {
                        if matches!(
                            word,
                            "lock"
                                | "rep"
                                | "repe"
                                | "repz"
                                | "repne"
                                | "repnz"
                                | "xacquire"
                                | "xrelease"
                                | "bnd"
                                | "notrack"
                        ) {
                            Some("2")
                        } else {
                            mnemonic = false;
                            Some(assembly_mnemonic(word, &rest[length..]))
                        }
                    } else {
                        mnemonic = false;
                        (!line[..index].ends_with(':') && assembly_register(word)).then_some("36")
                    };
                    (length, style)
                } else {
                    (first.len_utf8(), None)
                };
                let token = &rest[..length];
                match style {
                    Some(style) => out.push_str(&self.paint(token, style)),
                    None => out.push_str(token),
                }
                index += length;
            }
        }
        out
    }
}

fn assembly_word(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(character, '_' | '.' | '@' | '$' | '#' | '%')
        || (!character.is_ascii() && !character.is_whitespace())
}

fn assembly_mnemonic(word: &str, operands: &str) -> &'static str {
    match word {
        "call" | "callq" | "bl" | "blr" => "1;35",
        "ret" | "retq" | "retf" | "iret" | "iretd" | "iretq" | "retaa" | "retab" => "1;34",
        "b" | "br" | "cbz" | "cbnz" | "tbz" | "tbnz" | "loop" | "loope" | "loopne" | "loopz"
        | "loopnz" => "34",
        _ if word.starts_with('j') || word.starts_with("b.") => "34",
        "push" | "pop" | "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "ldur"
        | "ldurb" | "ldurh" | "ldursb" | "ldursh" | "ldursw" | "ldp" | "ldpsw" | "ldnp"
        | "ldar" | "ldarb" | "ldarh" | "ldxr" | "ldxrb" | "ldxrh" | "ldaxr" | "ldaxrb"
        | "ldaxrh" | "str" | "strb" | "strh" | "stur" | "sturb" | "sturh" | "stp" | "stnp"
        | "stlr" | "stlrb" | "stlrh" | "stxr" | "stxrb" | "stxrh" | "stlxr" | "stlxrb"
        | "stlxrh" => "33",
        _ if (word.starts_with("mov") || word.starts_with("vmov")) && assembly_memory(operands) => {
            "33"
        }
        _ => "1",
    }
}

fn assembly_memory(mut text: &str) -> bool {
    while let Some(first) = text.chars().next() {
        if first == '[' {
            return true;
        }
        if first == ';' || text.starts_with("//") {
            return false;
        }
        let length = if matches!(first, '\'' | '"') {
            quoted(text, first)
        } else {
            first.len_utf8()
        };
        text = &text[length..];
    }
    false
}

fn assembly_register(word: &str) -> bool {
    fn numbered(word: &str, prefix: &str, limit: u8) -> bool {
        word.strip_prefix(prefix).is_some_and(|digits| {
            !digits.is_empty()
                && (digits.len() == 1 || !digits.starts_with('0'))
                && digits.parse::<u8>().is_ok_and(|index| index <= limit)
        })
    }
    let word = word.strip_prefix('%').unwrap_or(word);
    if matches!(
        word,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "eip"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "bp"
            | "sp"
            | "ip"
            | "al"
            | "ah"
            | "bl"
            | "bh"
            | "cl"
            | "ch"
            | "dl"
            | "dh"
            | "sil"
            | "dil"
            | "bpl"
            | "spl"
            | "cs"
            | "ds"
            | "es"
            | "fs"
            | "gs"
            | "ss"
            | "wsp"
            | "xzr"
            | "wzr"
            | "fp"
            | "lr"
    ) {
        return true;
    }
    const NUMBERED: [(&str, u8); 14] = [
        ("xmm", 31),
        ("ymm", 31),
        ("zmm", 31),
        ("mm", 7),
        ("k", 7),
        ("x", 30),
        ("w", 30),
        ("q", 31),
        ("d", 31),
        ("s", 31),
        ("h", 31),
        ("b", 31),
        ("z", 31),
        ("p", 15),
    ];
    if NUMBERED
        .iter()
        .any(|(prefix, limit)| numbered(word, prefix, *limit))
    {
        return true;
    }
    let extended = word.strip_suffix(['b', 'w', 'd']).unwrap_or(word);
    if extended.strip_prefix('r').is_some_and(|digits| {
        digits
            .parse::<u8>()
            .is_ok_and(|index| (8..=15).contains(&index))
            && !digits.starts_with('0')
    }) {
        return true;
    }
    let (base, arrangement) = word
        .split_once('.')
        .map_or((word, None), |(base, suffix)| (base, Some(suffix)));
    numbered(base, "v", 31)
        && arrangement.is_none_or(|suffix| {
            matches!(
                suffix,
                "b" | "h" | "s" | "d" | "8b" | "16b" | "4h" | "8h" | "2s" | "4s" | "1d" | "2d"
            )
        })
}

fn assembly_number(text: &str) -> Option<(usize, bool)> {
    let marker = usize::from(text.starts_with(['#', '$']));
    let sign = usize::from(text[marker..].starts_with(['+', '-']));
    let start = marker + sign;
    if !text.as_bytes().get(start)?.is_ascii_digit() {
        return None;
    }
    let length = text[start..]
        .find(|ch: char| !assembly_word(ch))
        .map_or(text.len(), |end| start + end);
    let value = &text[start..length];
    let hexadecimal = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .or_else(|| value.strip_suffix(['h', 'H']));
    let number = match hexadecimal {
        Some(digits) => !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => value.parse::<f64>().is_ok(),
    };
    Some((length, number))
}

fn quoted(text: &str, quote: char) -> usize {
    let mut escaped = false;
    for (index, ch) in text.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return index + ch.len_utf8();
        }
    }
    text.len()
}

fn keyword(word: &str, language: Language) -> Option<&'static str> {
    match language {
        Language::C => match word {
            "if" | "else" | "for" | "while" | "do" | "switch" | "case" | "default" | "break"
            | "continue" | "goto" | "return" | "sizeof" => Some("34"),
            "bool" | "char" | "short" | "int" | "long" | "float" | "double" | "void" | "signed"
            | "unsigned" | "const" | "struct" | "union" | "enum" | "typedef" => Some("36"),
            _ if word.ends_with("_t") => Some("36"),
            _ => None,
        },
        Language::Ir => match word {
            "fn" | "br" | "brif" | "ret" | "call" | "select" | "switch" => Some("34"),
            "unsupported" => Some("33"),
            _ => None,
        },
        Language::Disassembly => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uncolored(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.next() == Some('[') {
                for ch in chars.by_ref() {
                    if ch == 'm' {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn color_requires_a_terminal_and_respects_standard_suppression() {
        assert!(Terminal::new(true, None, None).color);
        assert!(Terminal::new(true, Some(OsStr::new("")), None).color);
        for terminal in [
            Terminal::new(false, None, None),
            Terminal::new(true, Some(OsStr::new("1")), None),
            Terminal::new(true, Some(OsStr::new("0")), None),
            Terminal::new(true, None, Some(OsStr::new("dumb"))),
        ] {
            assert!(!terminal.color);
            assert_eq!(terminal.error("error:"), "error:");
        }
    }

    #[test]
    fn code_coloring_preserves_text_and_quoted_or_commented_tokens() {
        let terminal = Terminal::new(true, None, None);
        let code = "/* return 0x1\nπ */\nint32_t f(void) {\n    const char *s = \"return \\\"/* 0x2\";\n    return '\\'' + 0x3; // if 7\n}\n";
        let colored = terminal.code(code, Language::C);
        assert_eq!(uncolored(&colored), code);
        assert!(colored.contains("\x1b[2m/* return 0x1\nπ */\x1b[0m"));
        assert!(colored.contains("\x1b[32m\"return \\\"/* 0x2\"\x1b[0m"));
        assert!(colored.contains("\x1b[34mreturn\x1b[0m"));
        assert!(colored.contains("\x1b[35m0x3\x1b[0m"));
        for language in [Language::C, Language::Ir, Language::Disassembly] {
            for code in ["", "ret #0xff\n", "0x10          ret\n", "\tπ + 0.5"] {
                assert_eq!(uncolored(&terminal.code(code, language)), code);
                assert_eq!(Terminal::new(false, None, None).code(code, language), code);
            }
        }
    }

    #[test]
    fn disassembly_distinguishes_control_flow_memory_and_registers() {
        let terminal = Terminal::new(true, None, None);
        let code = concat!(
            "0x10          call 0x20\n",
            "0x14          je 0x30\n",
            "0x18          ret\n",
            "0x1c          mov rax,[rbx+8]\n",
            "0x20          lea rax,[rbx+8]\n",
            "0x24          std\n",
            "0x28          lock add qword ptr [rax],1\n",
            "0x2c          b.eq 0x40\n",
            "0x30          ldp x29,x30,[sp],#0x10\n",
            "0x34          fadd v0.4s,v1.4s,v2.4s\n",
        );
        let colored = terminal.code(code, Language::Disassembly);
        assert_eq!(uncolored(&colored), code);
        for (token, style) in [
            ("0x10", "36"),
            ("call", "1;35"),
            ("je", "34"),
            ("ret", "1;34"),
            ("mov", "33"),
            ("ldp", "33"),
            ("b.eq", "34"),
            ("lea", "1"),
            ("std", "1"),
            ("lock", "2"),
            ("add", "1"),
            ("rax", "36"),
            ("x29", "36"),
            ("v0.4s", "36"),
            ("#0x10", "35"),
        ] {
            assert!(
                colored.contains(&format!("\x1b[{style}m{token}\x1b[0m")),
                "{token}"
            );
        }
        assert!(!colored.contains("\x1b[33mlea\x1b[0m"));
        assert!(!colored.contains("\x1b[33mstd\x1b[0m"));
        for code in ["0x10 mov rax,rbx ; [x0]", "0x10 mov rax,\"[x0]\""] {
            let colored = terminal.code(code, Language::Disassembly);
            assert_eq!(uncolored(&colored), code);
            assert!(colored.contains("\x1b[1mmov\x1b[0m"));
        }
    }

    #[test]
    fn assembly_operands_keep_quotes_comments_and_symbol_boundaries() {
        let terminal = Terminal::new(true, None, None);
        let code = concat!(
            "0x10 mov %rax,$-0x1 ; x0 #2 π\n",
            "0x14 ldr x0,[x1,#0x8] // rax 0xff\n",
            "0x18 data \"x0; // #0xff\\\" π\" // w0\n",
            "0x1c mov r8d,x0_handler,π_x0,foo::rax,x31,w31,r16,x00,v32.4s,.x0,$rax,x0\u{301}\n",
            "0x20 mov fs:[rax],0FFh\n",
        );
        let colored = terminal.code(code, Language::Disassembly);
        assert_eq!(uncolored(&colored), code);
        assert!(colored.contains("\x1b[36m%rax\x1b[0m"));
        assert!(colored.contains("\x1b[35m$-0x1\x1b[0m"));
        assert!(colored.contains("\x1b[35m#0x8\x1b[0m"));
        assert!(colored.contains("\x1b[35m0FFh\x1b[0m"));
        assert!(colored.contains("\x1b[36mfs\x1b[0m:"));
        assert!(colored.contains("\x1b[2m; x0 #2 π\x1b[0m"));
        assert!(colored.contains("\x1b[2m// rax 0xff\x1b[0m"));
        assert!(colored.contains("\x1b[32m\"x0; // #0xff\\\" π\"\x1b[0m"));
        assert!(
            colored.contains("x0_handler,π_x0,foo::rax,x31,w31,r16,x00,v32.4s,.x0,$rax,x0\u{301}")
        );
    }

    #[test]
    fn assembly_colors_preserve_malformed_lines_and_suppressed_output() {
        let terminal = Terminal::new(true, None, None);
        for code in [
            "",
            "0x10",
            "0x10 ret",
            "0x10 ret\r\n",
            "0x10 data \"π",
            "0x10 data '\\'",
            "0x10 mov rax,0x1g,123label,#,$\n",
            "0x10          (undecodable: x0 / π #0xff)\n",
            "\tπ_x0 + 0.5\n",
        ] {
            assert_eq!(uncolored(&terminal.code(code, Language::Disassembly)), code);
            for terminal in [
                Terminal::new(false, None, None),
                Terminal::new(true, Some(OsStr::new("1")), None),
                Terminal::new(true, None, Some(OsStr::new("dumb"))),
            ] {
                assert_eq!(terminal.code(code, Language::Disassembly), code);
            }
        }
        let undecodable = "0x10          (undecodable: x0 / π #0xff)\n";
        let colored = terminal.code(undecodable, Language::Disassembly);
        assert!(colored.ends_with("          (undecodable: x0 / π #0xff)\n"));
        let malformed = terminal.code("0x10 mov rax,0x1g,123label", Language::Disassembly);
        assert!(malformed.ends_with("0x1g,123label"));
    }

    #[test]
    fn only_terminal_blocks_add_framing_and_keep_code_indentation() {
        let code = "int f(void) {\n    return 1;\n}\n";
        assert_eq!(
            Terminal::new(false, None, None).block("Pseudo-C", "file", code, Language::C),
            code,
        );
        let plain = Terminal::new(true, Some(OsStr::new("1")), None);
        let expected = format!("Pseudo-C\nfile\n\n{code}\n");
        assert_eq!(plain.block("Pseudo-C", "file", code, Language::C), expected);
        assert_eq!(
            uncolored(&Terminal::new(true, None, None).block(
                "Pseudo-C",
                "file",
                code,
                Language::C
            )),
            expected,
        );
        let padded = format!("{:<14}", "0x10");
        assert_eq!(
            uncolored(&Terminal::new(true, None, None).address(&padded)),
            padded
        );
    }
}
