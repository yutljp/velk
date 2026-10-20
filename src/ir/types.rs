use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CType {
    Void,
    Int {
        bytes: u8,
        signed: bool,
    },
    Pointer(Box<CType>),
    Array(Box<CType>),
    /// A type named by the debug info, kept as written (`struct pair`, `unsigned int`).
    Named(String),
}

impl CType {
    pub const U64: CType = CType::Int {
        bytes: 8,
        signed: false,
    };
    pub const I64: CType = CType::Int {
        bytes: 8,
        signed: true,
    };
    pub const U32: CType = CType::Int {
        bytes: 4,
        signed: false,
    };
    pub const I32: CType = CType::Int {
        bytes: 4,
        signed: true,
    };

    /// The integer type of an access `bytes` wide; unusual widths read as 64 bits.
    pub fn int(bytes: u8, signed: bool) -> Self {
        let bytes = if matches!(bytes, 1 | 2 | 4) { bytes } else { 8 };
        CType::Int { bytes, signed }
    }

    pub fn pointer_to(target: CType) -> Self {
        CType::Pointer(Box::new(target))
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self, CType::Pointer(_))
    }

    /// True for `float` and `double`, which SSE registers carry.
    pub fn is_sse_float(&self) -> bool {
        let CType::Named(name) = self else {
            return false;
        };
        let words: Vec<&str> = name.split_whitespace().collect();
        (words.contains(&"float") || words.contains(&"double")) && !words.contains(&"long")
    }

    pub fn is_32_bit_int(&self) -> bool {
        matches!(self, CType::Int { bytes: 4, .. })
    }

    /// True for a type whose values fit in 32 bits.
    pub fn is_narrow(&self) -> bool {
        match self {
            CType::Int { bytes, .. } => *bytes <= 4,
            CType::Named(name) => narrow_c_name(name),
            CType::Void | CType::Pointer(_) | CType::Array(_) => false,
        }
    }

    /// The size of the scalar a pointer points at: 4 for `int *`.
    pub fn pointee_size(&self) -> Option<u8> {
        let CType::Pointer(target) = self else {
            return None;
        };
        match target.as_ref() {
            CType::Int { bytes, .. } => Some(*bytes),
            CType::Named(name) => scalar_size(name),
            _ => None,
        }
    }

    /// `pair` for `struct pair *`.
    pub fn pointee_struct(&self) -> Option<&str> {
        match self {
            CType::Pointer(target) => match target.as_ref() {
                CType::Named(name) => name.strip_prefix("struct ").map(str::trim),
                _ => None,
            },
            _ => None,
        }
    }
}

/// The size of a scalar C type named by the debug info, ignoring
/// qualifiers; None for anything else.
fn scalar_size(name: &str) -> Option<u8> {
    let words: Vec<&str> = name
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "signed" | "unsigned"))
        .collect();
    Some(match words.as_slice() {
        ["char"] | ["_Bool"] | ["bool"] => 1,
        ["short"] | ["short", "int"] => 2,
        ["int"] | ["float"] => 4,
        ["long"] | ["long", "int"] | ["long", "long"] | ["long", "long", "int"] | ["double"] => 8,
        [] => 4,
        [other] => {
            let bits: u8 = other
                .strip_prefix("uint")
                .or_else(|| other.strip_prefix("int"))?
                .strip_suffix("_t")?
                .parse()
                .ok()?;
            bits / 8
        }
        _ => return None,
    })
}

fn narrow_c_name(name: &str) -> bool {
    let mut narrow = false;
    for word in name.split_whitespace() {
        match word {
            "char" | "short" | "int" | "_Bool" | "bool" | "float" => narrow = true,
            "long" | "double" => return false,
            other => {
                if let Some(rest) = other
                    .strip_prefix("uint")
                    .or_else(|| other.strip_prefix("int"))
                {
                    narrow = rest
                        .strip_suffix("_t")
                        .and_then(|bits| bits.parse::<u32>().ok())
                        .is_some_and(|bits| bits <= 32);
                }
            }
        }
    }
    narrow
}

impl fmt::Display for CType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CType::Void => f.write_str("void"),
            CType::Int { bytes, signed } => {
                write!(
                    f,
                    "{}int{}_t",
                    if *signed { "" } else { "u" },
                    u32::from(*bytes) * 8
                )
            }
            CType::Pointer(target) => write!(f, "{target} *"),
            CType::Array(element) => write!(f, "{element} []"),
            CType::Named(name) => f.write_str(name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Param {
    pub index: u16,
    pub name: String,
    pub ty: CType,
}

/// A parameter passed in the caller's stack frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackParam {
    /// Where it lies, from the stack pointer on entry.
    pub offset: i64,
    pub size: u64,
    pub name: String,
    pub ty: CType,
    /// Its place among all the parameters, the register ones included.
    pub position: usize,
}

/// The fields a function reads or writes through one pointer parameter.
#[derive(Debug, Clone)]
pub struct Access {
    pub register: u16,
    /// `(byte offset, type)` in offset order.
    pub fields: Vec<(u64, CType)>,
}

/// A structure recovered from the accesses through a pointer, its fields
/// in offset order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structure {
    pub name: String,
    pub fields: Vec<(u64, CType)>,
    /// The element size of an array of them, which the definition pads to.
    pub size: Option<u64>,
    /// The variables that point at the start of an element of that array.
    pub elements: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub structure: String,
    pub offset: i64,
    pub name: String,
}
