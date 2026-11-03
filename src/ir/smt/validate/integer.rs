//! The same query over integers: each bit-vector of width w is an integer
//! from 0 to 2^w - 1 and each operation its exact value modulo 2^w. Linear
//! integer arithmetic decides products and quotients of constants, such as
//! a division recovered from a multiplication by its reciprocal, that the
//! bit-vector strategies give up on. A query with an operation outside that
//! fragment, a product of two variables, a shift or division by a variable,
//! or a symbol that is not a Boolean or a bit-vector, has no translation.

use std::collections::HashMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sexp {
    Atom(String),
    List(Vec<Sexp>),
}

fn parse(text: &str) -> Option<Vec<Sexp>> {
    let mut stack: Vec<Vec<Sexp>> = vec![Vec::new()];
    let mut chars = text.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        match c {
            '(' => stack.push(Vec::new()),
            ')' => {
                let list = stack.pop()?;
                stack.last_mut()?.push(Sexp::List(list));
            }
            ';' => while chars.next_if(|&(_, c)| c != '\n').is_some() {},
            c if c.is_whitespace() => {}
            '|' => return None,
            _ => {
                let mut end = start + c.len_utf8();
                while let Some(&(at, c)) = chars.peek() {
                    if c.is_whitespace() || c == '(' || c == ')' {
                        break;
                    }
                    end = at + c.len_utf8();
                    chars.next();
                }
                stack
                    .last_mut()?
                    .push(Sexp::Atom(text[start..end].to_owned()));
            }
        }
    }
    let top = stack.pop()?;
    stack.is_empty().then_some(top)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sort {
    Bool,
    Bits(u32),
}

/// What a symbol stands for.
#[derive(Debug, Clone)]
enum Symbol {
    /// A value of the sort, known when it is a constant.
    Value(Sort, Option<u128>),
    /// A function of the sorts to the sort.
    Function(Vec<Sort>, Sort),
    /// Something with no translation, such as memory.
    Untranslated,
}

/// A translated term.
struct Term {
    text: String,
    sort: Sort,
    constant: Option<u128>,
}

/// The widest bit-vector whose constants are followed.
const WIDEST: u32 = 128;

/// 2^k in decimal.
fn power(k: u32) -> String {
    // Base 10^9 digits, least significant first.
    let mut digits: Vec<u64> = vec![1];
    for _ in 0..k {
        let mut carry = 0;
        for digit in &mut digits {
            let doubled = *digit * 2 + carry;
            *digit = doubled % 1_000_000_000;
            carry = doubled / 1_000_000_000;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    let mut text = digits.last().expect("a digit").to_string();
    for digit in digits.iter().rev().skip(1) {
        write!(text, "{digit:09}").expect("writing to a String");
    }
    text
}

fn modulo(text: &str, width: u32) -> String {
    format!("(mod {text} {})", power(width))
}

/// The signed value of `text`, of `width` bits.
fn signed(text: &str, width: u32) -> String {
    format!(
        "(ite (>= {text} {}) (- {text} {}) {text})",
        power(width - 1),
        power(width)
    )
}

fn mask(width: u32) -> u128 {
    if width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    }
}

/// The bits of `text` that `constant` keeps, as a sum of its runs of ones.
fn and_constant(text: &str, constant: u128, width: u32) -> String {
    if constant == 0 {
        return "0".to_owned();
    }
    if constant == mask(width) {
        return text.to_owned();
    }
    let mut runs = Vec::new();
    let mut bit = 0;
    while bit < width {
        if constant >> bit & 1 == 0 {
            bit += 1;
            continue;
        }
        let low = bit;
        while bit < width && constant >> bit & 1 == 1 {
            bit += 1;
        }
        let kept = modulo(&format!("(div {text} {})", power(low)), bit - low);
        runs.push(format!("(* {kept} {})", power(low)));
    }
    match runs.as_slice() {
        [one] => one.clone(),
        _ => format!("(+ {})", runs.join(" ")),
    }
}

struct Translation {
    symbols: HashMap<String, Symbol>,
}

impl Translation {
    fn sort(sexp: &Sexp) -> Option<Sort> {
        match sexp {
            Sexp::Atom(name) if name == "Bool" => Some(Sort::Bool),
            Sexp::List(items) => match items.as_slice() {
                [Sexp::Atom(underscore), Sexp::Atom(kind), Sexp::Atom(width)]
                    if underscore == "_" && kind == "BitVec" =>
                {
                    let width: u32 = width.parse().ok()?;
                    (width > 0).then_some(Sort::Bits(width))
                }
                _ => None,
            },
            Sexp::Atom(_) => None,
        }
    }

    fn literal(atom: &str) -> Option<(u128, u32)> {
        if let Some(hex) = atom.strip_prefix("#x") {
            let width = u32::try_from(hex.len()).ok()? * 4;
            (width <= WIDEST)
                .then(|| {
                    u128::from_str_radix(hex, 16)
                        .ok()
                        .map(|value| (value, width))
                })
                .flatten()
        } else if let Some(binary) = atom.strip_prefix("#b") {
            let width = u32::try_from(binary.len()).ok()?;
            (width <= WIDEST)
                .then(|| {
                    u128::from_str_radix(binary, 2)
                        .ok()
                        .map(|value| (value, width))
                })
                .flatten()
        } else {
            None
        }
    }

    fn constant(value: u128, width: u32) -> Term {
        Term {
            text: value.to_string(),
            sort: Sort::Bits(width),
            constant: Some(value),
        }
    }

    fn bits(text: String, width: u32) -> Term {
        Term {
            text,
            sort: Sort::Bits(width),
            constant: None,
        }
    }

    fn boolean(text: String) -> Term {
        Term {
            text,
            sort: Sort::Bool,
            constant: None,
        }
    }

    /// The operands' common width, when all are bit-vectors of one width.
    fn width(terms: &[Term]) -> Option<u32> {
        let Sort::Bits(width) = terms.first()?.sort else {
            return None;
        };
        terms
            .iter()
            .all(|term| term.sort == Sort::Bits(width))
            .then_some(width)
    }

    fn term(&self, sexp: &Sexp, scope: &HashMap<String, Sort>) -> Option<Term> {
        let items = match sexp {
            Sexp::Atom(atom) => return self.atom(atom, scope),
            Sexp::List(items) => items,
        };
        let (head, arguments) = items.split_first()?;
        match head {
            Sexp::Atom(underscore) if underscore == "_" => {
                // (_ bvN w)
                let [Sexp::Atom(value), Sexp::Atom(width)] = arguments else {
                    return None;
                };
                let value: u128 = value.strip_prefix("bv")?.parse().ok()?;
                let width: u32 = width.parse().ok()?;
                (width > 0 && width <= WIDEST && value <= mask(width))
                    .then(|| Self::constant(value, width))
            }
            Sexp::List(indexed) => {
                let [Sexp::Atom(underscore), Sexp::Atom(op), indices @ ..] = indexed.as_slice()
                else {
                    return None;
                };
                if underscore != "_" {
                    return None;
                }
                let indices: Vec<u32> = indices
                    .iter()
                    .map(|index| match index {
                        Sexp::Atom(number) => number.parse().ok(),
                        Sexp::List(_) => None,
                    })
                    .collect::<Option<_>>()?;
                let [operand] = arguments else {
                    return None;
                };
                let operand = self.term(operand, scope)?;
                let Sort::Bits(width) = operand.sort else {
                    return None;
                };
                let mut term = Self::indexed(op, &indices, &operand, width)?;
                if let (Some(value), Sort::Bits(wider)) = (operand.constant, term.sort) {
                    term.constant = Self::folded(op, &indices, value, width, wider);
                }
                Some(term)
            }
            Sexp::Atom(op) => {
                let terms: Vec<Term> = arguments
                    .iter()
                    .map(|argument| self.term(argument, scope))
                    .collect::<Option<_>>()?;
                self.apply(op, &terms)
            }
        }
    }

    fn atom(&self, atom: &str, scope: &HashMap<String, Sort>) -> Option<Term> {
        if let Some((value, width)) = Self::literal(atom) {
            return Some(Self::constant(value, width));
        }
        if atom == "true" || atom == "false" {
            return Some(Self::boolean(atom.to_owned()));
        }
        if let Some(sort) = scope.get(atom) {
            return Some(Term {
                text: atom.to_owned(),
                sort: *sort,
                constant: None,
            });
        }
        match self.symbols.get(atom)? {
            Symbol::Value(sort, constant) => Some(Term {
                text: atom.to_owned(),
                sort: *sort,
                constant: *constant,
            }),
            Symbol::Function(..) | Symbol::Untranslated => None,
        }
    }

    /// The constant an extraction or extension of the constant `value` is,
    /// so a product with it stays linear.
    fn folded(op: &str, indices: &[u32], value: u128, width: u32, result: u32) -> Option<u128> {
        if result > WIDEST {
            return None;
        }
        match (op, indices) {
            ("extract", &[_, low]) => Some(value >> low & mask(result)),
            ("zero_extend", _) => Some(value),
            ("sign_extend", _) if value >> (width - 1) & 1 == 1 => {
                Some(value | (mask(result) ^ mask(width)))
            }
            ("sign_extend", _) => Some(value),
            _ => None,
        }
    }

    fn indexed(op: &str, indices: &[u32], operand: &Term, width: u32) -> Option<Term> {
        let text = &operand.text;
        match (op, indices) {
            ("extract", &[high, low]) if low <= high && high < width => {
                let kept = high - low + 1;
                if low == 0 && kept == width {
                    return Some(Self::bits(text.clone(), width));
                }
                let shifted = if low == 0 {
                    text.clone()
                } else {
                    format!("(div {text} {})", power(low))
                };
                Some(Self::bits(modulo(&shifted, kept), kept))
            }
            ("zero_extend", &[added]) => Some(Self::bits(text.clone(), width + added)),
            ("sign_extend", &[added]) => {
                let wider = width + added;
                if added == 0 {
                    return Some(Self::bits(text.clone(), width));
                }
                Some(Self::bits(
                    format!(
                        "(ite (>= {text} {}) (+ {text} (- {} {})) {text})",
                        power(width - 1),
                        power(wider),
                        power(width)
                    ),
                    wider,
                ))
            }
            ("rotate_left" | "rotate_right", &[amount]) => {
                let amount = amount % width;
                let left = if op == "rotate_left" {
                    amount
                } else {
                    (width - amount) % width
                };
                if left == 0 {
                    return Some(Self::bits(text.clone(), width));
                }
                Some(Self::bits(
                    format!(
                        "(+ {} (div {text} {}))",
                        modulo(&format!("(* {text} {})", power(left)), width),
                        power(width - left)
                    ),
                    width,
                ))
            }
            _ => None,
        }
    }

    fn apply(&self, op: &str, terms: &[Term]) -> Option<Term> {
        let texts: Vec<&str> = terms.iter().map(|term| term.text.as_str()).collect();
        match op {
            "not" | "and" | "or" | "xor" | "=>" if terms.iter().all(|t| t.sort == Sort::Bool) => {
                if op == "not" && terms.len() != 1 {
                    return None;
                }
                Some(Self::boolean(format!("({op} {})", texts.join(" "))))
            }
            "=" | "distinct" => {
                let sort = terms.first()?.sort;
                (terms.len() >= 2 && terms.iter().all(|t| t.sort == sort))
                    .then(|| Self::boolean(format!("({op} {})", texts.join(" "))))
            }
            "ite" => {
                let [condition, then, otherwise] = terms else {
                    return None;
                };
                (condition.sort == Sort::Bool && then.sort == otherwise.sort).then(|| Term {
                    text: format!("(ite {} {} {})", condition.text, then.text, otherwise.text),
                    sort: then.sort,
                    constant: None,
                })
            }
            _ => {
                if let Some(Symbol::Function(parameters, result)) = self.symbols.get(op) {
                    let sorts: Vec<Sort> = terms.iter().map(|t| t.sort).collect();
                    return (sorts == *parameters).then(|| Term {
                        text: format!("({op} {})", texts.join(" ")),
                        sort: *result,
                        constant: None,
                    });
                }
                let width = Self::width(terms)?;
                Self::bit_vector(op, terms, &texts, width)
            }
        }
    }

    fn bit_vector(op: &str, terms: &[Term], texts: &[&str], width: u32) -> Option<Term> {
        let comparison = |relation: &str, signed_operands: bool| {
            let [lhs, rhs] = texts else {
                return None;
            };
            let (lhs, rhs) = if signed_operands {
                (signed(lhs, width), signed(rhs, width))
            } else {
                ((*lhs).to_owned(), (*rhs).to_owned())
            };
            Some(Self::boolean(format!("({relation} {lhs} {rhs})")))
        };
        // The constant operand of a binary operation, and the other one.
        let by_constant = || -> Option<(&str, u128)> {
            let [lhs, rhs] = terms else {
                return None;
            };
            Some((lhs.text.as_str(), rhs.constant?))
        };
        match op {
            "bvult" => comparison("<", false),
            "bvule" => comparison("<=", false),
            "bvugt" => comparison(">", false),
            "bvuge" => comparison(">=", false),
            "bvslt" => comparison("<", true),
            "bvsle" => comparison("<=", true),
            "bvsgt" => comparison(">", true),
            "bvsge" => comparison(">=", true),
            "bvadd" if terms.len() >= 2 => Some(Self::bits(
                modulo(&format!("(+ {})", texts.join(" ")), width),
                width,
            )),
            "bvsub" if terms.len() == 2 => Some(Self::bits(
                modulo(&format!("(- {})", texts.join(" ")), width),
                width,
            )),
            "bvneg" if terms.len() == 1 => Some(Self::bits(
                modulo(&format!("(- {})", texts[0]), width),
                width,
            )),
            "bvnot" if terms.len() == 1 => Some(Self::bits(
                format!("(- {} {})", mask(width), texts[0]),
                width,
            )),
            "bvmul" if terms.len() >= 2 => {
                let variables = terms.iter().filter(|t| t.constant.is_none()).count();
                (variables <= 1)
                    .then(|| Self::bits(modulo(&format!("(* {})", texts.join(" ")), width), width))
            }
            "bvand" | "bvor" | "bvxor" if terms.len() >= 2 => {
                let mut constant = match op {
                    "bvand" => mask(width),
                    _ => 0,
                };
                let mut variable = None;
                for term in terms {
                    match term.constant {
                        Some(value) => {
                            constant = match op {
                                "bvand" => constant & value,
                                "bvor" => constant | value,
                                _ => constant ^ value,
                            }
                        }
                        None if variable.is_none() => variable = Some(term.text.as_str()),
                        None => return None,
                    }
                }
                let Some(variable) = variable else {
                    return Some(Self::constant(constant, width));
                };
                let kept = and_constant(variable, constant, width);
                Some(Self::bits(
                    match op {
                        "bvand" => kept,
                        "bvor" => format!("(- (+ {variable} {constant}) {kept})"),
                        _ => format!("(- (+ {variable} {constant}) (* 2 {kept}))"),
                    },
                    width,
                ))
            }
            "bvshl" | "bvlshr" | "bvashr" => {
                let (value, amount) = by_constant()?;
                if amount >= u128::from(width) {
                    return Some(match op {
                        "bvashr" => Self::bits(
                            format!("(ite (>= {value} {}) {} 0)", power(width - 1), mask(width)),
                            width,
                        ),
                        _ => Self::constant(0, width),
                    });
                }
                let amount = amount as u32;
                let scale = power(amount);
                Some(Self::bits(
                    match op {
                        "bvshl" => modulo(&format!("(* {value} {scale})"), width),
                        "bvlshr" => format!("(div {value} {scale})"),
                        _ => modulo(&format!("(div {} {scale})", signed(value, width)), width),
                    },
                    width,
                ))
            }
            "bvudiv" | "bvurem" => {
                let (value, divisor) = by_constant()?;
                Some(match (op, divisor) {
                    ("bvudiv", 0) => Self::constant(mask(width), width),
                    ("bvurem", 0) => Self::bits(value.to_owned(), width),
                    ("bvudiv", _) => Self::bits(format!("(div {value} {divisor})"), width),
                    _ => Self::bits(format!("(mod {value} {divisor})"), width),
                })
            }
            "bvsdiv" | "bvsrem" => {
                let (value, divisor) = by_constant()?;
                let negative = divisor >> (width - 1) & 1 == 1;
                if divisor == 0 || (width == WIDEST && negative) {
                    return None;
                }
                // The divisor's absolute value, from its two's complement.
                let magnitude = if negative {
                    mask(width) - divisor + 1
                } else {
                    divisor
                };
                let dividend = signed(value, width);
                // Truncated toward zero, as the signed division is.
                let quotient = format!(
                    "(ite (>= {dividend} 0) (div {dividend} {magnitude}) (- (div (- {dividend}) {magnitude})))"
                );
                let quotient = if negative {
                    format!("(- {quotient})")
                } else {
                    quotient
                };
                let result = if op == "bvsdiv" {
                    quotient
                } else {
                    let signed_divisor = if negative {
                        format!("(- {magnitude})")
                    } else {
                        magnitude.to_string()
                    };
                    format!("(- {dividend} (* {signed_divisor} {quotient}))")
                };
                Some(Self::bits(modulo(&result, width), width))
            }
            "concat" if terms.len() == 2 => {
                let Sort::Bits(low) = terms[1].sort else {
                    return None;
                };
                let Sort::Bits(high) = terms[0].sort else {
                    return None;
                };
                Some(Self::bits(
                    format!("(+ (* {} {}) {})", texts[0], power(low), texts[1]),
                    high + low,
                ))
            }
            _ => None,
        }
    }
}

/// `query` over integers, or None when it has no translation.
pub(super) fn translate(query: &str) -> Option<String> {
    let commands = parse(query)?;
    let mut translation = Translation {
        symbols: HashMap::new(),
    };
    let mut script = String::new();
    for command in &commands {
        let Sexp::List(items) = command else {
            return None;
        };
        let [Sexp::Atom(keyword), rest @ ..] = items.as_slice() else {
            return None;
        };
        match (keyword.as_str(), rest) {
            ("set-option", _) => {
                writeln!(script, "{}", print(command)).expect("writing to a String");
            }
            ("declare-const", [Sexp::Atom(name), sort])
            | ("declare-fun", [Sexp::Atom(name), Sexp::List(_), sort])
                if !matches!(rest, [_, Sexp::List(parameters), _] if !parameters.is_empty()) =>
            {
                match Translation::sort(sort) {
                    Some(Sort::Bool) => {
                        writeln!(script, "(declare-const {name} Bool)")
                            .expect("writing to a String");
                        translation
                            .symbols
                            .insert(name.clone(), Symbol::Value(Sort::Bool, None));
                    }
                    Some(Sort::Bits(width)) => {
                        writeln!(
                            script,
                            "(declare-const {name} Int)\n(assert (and (<= 0 {name}) (< {name} {})))",
                            power(width)
                        )
                        .expect("writing to a String");
                        translation
                            .symbols
                            .insert(name.clone(), Symbol::Value(Sort::Bits(width), None));
                    }
                    None => {
                        translation
                            .symbols
                            .insert(name.clone(), Symbol::Untranslated);
                    }
                }
            }
            ("declare-fun", [Sexp::Atom(name), ..]) => {
                translation
                    .symbols
                    .insert(name.clone(), Symbol::Untranslated);
            }
            ("define-fun", [Sexp::Atom(name), Sexp::List(parameters), sort, body]) => {
                let defined = (|| {
                    let result = Translation::sort(sort)?;
                    let mut scope = HashMap::new();
                    let mut declared = Vec::new();
                    let mut sorts = Vec::new();
                    for parameter in parameters {
                        let Sexp::List(pair) = parameter else {
                            return None;
                        };
                        let [Sexp::Atom(parameter), sort] = pair.as_slice() else {
                            return None;
                        };
                        let sort = Translation::sort(sort)?;
                        scope.insert(parameter.clone(), sort);
                        sorts.push(sort);
                        declared.push(format!(
                            "({parameter} {})",
                            if sort == Sort::Bool { "Bool" } else { "Int" }
                        ));
                    }
                    let term = translation.term(body, &scope)?;
                    (term.sort == result).then_some((term, result, declared, sorts))
                })();
                match defined {
                    Some((term, result, declared, sorts)) => {
                        writeln!(
                            script,
                            "(define-fun {name} ({}) {} {})",
                            declared.join(" "),
                            if result == Sort::Bool { "Bool" } else { "Int" },
                            term.text
                        )
                        .expect("writing to a String");
                        let symbol = if parameters.is_empty() {
                            Symbol::Value(result, term.constant)
                        } else {
                            Symbol::Function(sorts, result)
                        };
                        translation.symbols.insert(name.clone(), symbol);
                    }
                    None => {
                        translation
                            .symbols
                            .insert(name.clone(), Symbol::Untranslated);
                    }
                }
            }
            ("assert", [assertion]) => {
                let term = translation.term(assertion, &HashMap::new())?;
                if term.sort != Sort::Bool {
                    return None;
                }
                writeln!(script, "(assert {})", term.text).expect("writing to a String");
            }
            _ => return None,
        }
    }
    Some(script)
}

fn print(sexp: &Sexp) -> String {
    match sexp {
        Sexp::Atom(atom) => atom.clone(),
        Sexp::List(items) => format!(
            "({})",
            items.iter().map(print).collect::<Vec<_>>().join(" ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    fn z3(script: &str) -> String {
        let mut child = Command::new("z3")
            .args(["-in", "-smt2", "-T:60"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start z3");
        child
            .stdin
            .take()
            .expect("z3 input")
            .write_all(script.as_bytes())
            .expect("write the script");
        let output = child.wait_with_output().expect("z3 answer");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn available() -> bool {
        let found = Command::new("z3").arg("-version").output().is_ok();
        if !found {
            eprintln!("SKIP integer translation: z3 unavailable");
        }
        found
    }

    /// Proves that `term`, over the 8-bit `X` and `Y`, has the value its
    /// translation has, for every `X` and `Y`.
    fn exact(term: &str) {
        let translation = Translation {
            symbols: [
                ("ix".to_owned(), Symbol::Value(Sort::Bits(8), None)),
                ("iy".to_owned(), Symbol::Value(Sort::Bits(8), None)),
            ]
            .into(),
        };
        let integer_term = term.replace('X', "ix").replace('Y', "iy");
        let term = term.replace('X', "x").replace('Y', "y");
        let parsed = parse(&integer_term).expect("a term");
        let translated = translation
            .term(&parsed[0], &HashMap::new())
            .unwrap_or_else(|| panic!("{term} translates"));
        let value = match translated.sort {
            Sort::Bool => term.clone(),
            Sort::Bits(_) => format!("(bv2nat {term})"),
        };
        let script = format!(
            "(declare-const x (_ BitVec 8))\n(declare-const y (_ BitVec 8))\n\
             (define-fun ix () Int (bv2nat x))\n(define-fun iy () Int (bv2nat y))\n\
             (assert (not (= {value} {})))\n(check-sat)\n",
            translated.text
        );
        assert_eq!(z3(&script), "unsat", "{term}\n{script}");
    }

    #[test]
    fn each_operation_has_its_exact_value_over_integers() {
        if !available() {
            return;
        }
        for term in [
            "(bvadd X Y #xf3)",
            "(bvsub X Y)",
            "(bvneg X)",
            "(bvnot X)",
            "(bvmul X #x0d)",
            "(bvmul #x03 X #x05)",
            "(bvand X #x00)",
            "(bvand X #xff)",
            "(bvand X #x0f)",
            "(bvand X #xa6)",
            "(bvor X #x31)",
            "(bvxor X #x5a)",
            "(bvxor #x0f #xf0)",
            "(bvshl X #x03)",
            "(bvshl X #x09)",
            "(bvlshr X #x02)",
            "(bvlshr X #x08)",
            "(bvashr X #x03)",
            "(bvashr X #x08)",
            "(bvudiv X #x07)",
            "(bvudiv X #x00)",
            "(bvurem X #x0a)",
            "(bvurem X #x00)",
            "(bvsdiv X #x03)",
            "(bvsdiv X #xfd)",
            "(bvsdiv X #x80)",
            "(bvsdiv X #xff)",
            "(bvsrem X #x03)",
            "(bvsrem X #xfd)",
            "(bvsrem X #x80)",
            "(bvult X Y)",
            "(bvule X Y)",
            "(bvugt X Y)",
            "(bvuge X Y)",
            "(bvslt X Y)",
            "(bvsle X Y)",
            "(bvsgt X Y)",
            "(bvsge X Y)",
            "(= X Y)",
            "(distinct X Y #x00)",
            "(ite (bvult X Y) X Y)",
            "((_ extract 6 2) X)",
            "((_ extract 7 0) X)",
            "((_ zero_extend 8) X)",
            "((_ sign_extend 8) X)",
            "((_ rotate_left 3) X)",
            "((_ rotate_right 3) X)",
            "(concat X Y)",
            "(bvmul ((_ zero_extend 8) X) ((_ zero_extend 8) #xab))",
            "(bvmul ((_ sign_extend 8) X) ((_ sign_extend 8) #xab))",
            "((_ extract 15 8) (bvmul ((_ zero_extend 8) X) (_ bv171 16)))",
            "(and (bvult X Y) (not (= X #x00)))",
        ] {
            exact(term);
        }
    }

    #[test]
    fn what_is_not_linear_or_reads_memory_has_no_translation() {
        let declared = "(declare-const x (_ BitVec 64))\n(declare-const y (_ BitVec 64))\n\
                        (declare-const m (Array (_ BitVec 64) (_ BitVec 8)))\n";
        for assertion in [
            "(= (bvmul x y) #x0000000000000000)",
            "(= (bvshl x y) x)",
            "(= (bvudiv x y) x)",
            "(= (bvsdiv x #x0000000000000000) x)",
            "(= (select m x) #x00)",
            "(= (bvsmod x #x0000000000000003) x)",
        ] {
            assert_eq!(
                translate(&format!("{declared}(assert {assertion})\n")),
                None,
                "{assertion}"
            );
        }
        // Memory nothing reads does not keep the rest from translating.
        assert!(translate(&format!("{declared}(assert (= x y))\n")).is_some());
    }

    #[test]
    fn a_quotient_by_a_reciprocal_is_proved_over_integers() {
        if !available() {
            return;
        }
        // udiv3 on AArch64: umull by 0xaaaaaaab, then a shift by 33.
        let query = "(set-option :produce-models true)\n\
             (declare-const x (_ BitVec 64))\n\
             (define-fun w () (_ BitVec 64) ((_ zero_extend 32) ((_ extract 31 0) x)))\n\
             (define-fun d () (_ BitVec 64) #x0000000000000003)\n\
             (define-fun scaled () (_ BitVec 64) (bvlshr (bvmul w #x00000000aaaaaaab) #x0000000000000021))\n\
             (assert (not (= scaled (bvudiv w d))))\n";
        let translated = translate(query).expect("a linear query");
        assert_eq!(z3(&format!("{translated}(check-sat)\n")), "unsat");
        // One more than the reciprocal is not one.
        let wrong = query.replace("aaaaaaab", "aaaaaaac");
        let translated = translate(&wrong).expect("a linear query");
        assert_eq!(z3(&format!("{translated}(check-sat)\n")), "sat");
        // Parameters of a defined function are integers too.
        let count = "(define-fun twice ((v (_ BitVec 8))) (_ BitVec 8) (bvadd v v))\n\
             (declare-const b (_ BitVec 8))\n\
             (assert (not (= (twice b) (bvshl b #x01))))\n";
        let translated = translate(count).expect("a defined function");
        assert_eq!(z3(&format!("{translated}(check-sat)\n")), "unsat");
    }
}
