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
            let mut out = String::new();
            for line in text.split_inclusive('\n') {
                match line.find(char::is_whitespace) {
                    Some(end) if line.starts_with("0x") => {
                        out.push_str(&self.address(&line[..end]));
                        out.push_str(&line[end..]);
                    }
                    _ => out.push_str(line),
                }
            }
            return out;
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
