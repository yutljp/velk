use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiProfile {
    SysV,
    Aapcs64,
    Win64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiIssue {
    UnknownLayout,
    UnsupportedProfile,
    UnsupportedType,
    NonTrivial,
    IncompatibleDefinition,
}

impl fmt::Display for AbiIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownLayout => "unknown object layout",
            Self::UnsupportedProfile => "unsupported target ABI",
            Self::UnsupportedType => "unsupported ABI type",
            Self::NonTrivial => "unresolved or nontrivial call semantics",
            Self::IncompatibleDefinition => "incompatible C object definition",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterClass {
    Integer,
    Simd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiLocation {
    Register(u16),
    Stack(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiPiece {
    pub location: AbiLocation,
    pub object_offset: u64,
    pub bytes: u64,
    pub class: Option<RegisterClass>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Passing {
    Direct(Vec<AbiPiece>),
    Indirect {
        pointer: AbiLocation,
        returned_pointer: Option<u16>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueAbi {
    pub aggregate: bool,
    pub size: u64,
    /// Alignment of the generated representative C object.
    pub alignment: u64,
    /// Object bit offset and bit count, excluding padding and unused bit-fields.
    pub defined_bits: Vec<(u64, u64)>,
    pub passing: Passing,
}

impl ValueAbi {
    pub fn validate(&self) -> Result<(), AbiIssue> {
        if self.size == 0
            || !self.alignment.is_power_of_two()
            || !self.size.is_multiple_of(self.alignment)
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let Some(bits) = self.size.checked_mul(8) else {
            return Err(AbiIssue::UnknownLayout);
        };
        let mut end = 0;
        for &(offset, count) in &self.defined_bits {
            if count == 0 || offset < end {
                return Err(AbiIssue::UnknownLayout);
            }
            end = match offset.checked_add(count) {
                Some(value) => value,
                None => return Err(AbiIssue::UnknownLayout),
            };
            if end > bits {
                return Err(AbiIssue::UnknownLayout);
            }
        }
        if let Passing::Direct(pieces) = &self.passing {
            let mut end = 0;
            for piece in pieces {
                if piece.bytes == 0 || piece.object_offset < end {
                    return Err(AbiIssue::UnknownLayout);
                }
                end = match piece.object_offset.checked_add(piece.bytes) {
                    Some(value) => value,
                    None => return Err(AbiIssue::UnknownLayout),
                };
                if end > self.size
                    || match piece.location {
                        AbiLocation::Register(_) => piece.bytes > 8 || piece.class.is_none(),
                        AbiLocation::Stack(_) => piece.class.is_some(),
                    }
                {
                    return Err(AbiIssue::UnknownLayout);
                }
            }
            if pieces.is_empty() {
                return Err(AbiIssue::UnknownLayout);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAbi {
    pub profile: AbiProfile,
    pub arguments: Vec<ValueAbi>,
    pub result: Option<ValueAbi>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSignature {
    /// Source parameters in logical order; hidden result addresses are separate.
    pub params: Vec<(String, CType)>,
    pub ret: CType,
    pub variadic: bool,
    pub abi: Result<SignatureAbi, AbiIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CType {
    Void,
    Int {
        bytes: u8,
        signed: bool,
    },
    Pointer(Box<CType>),
    Array(Box<CType>),
    Function {
        params: Vec<CType>,
        ret: Box<CType>,
        variadic: bool,
        convention: super::Convention,
    },
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
    #[must_use]
    pub fn int(bytes: u8, signed: bool) -> Self {
        let bytes = if matches!(bytes, 1 | 2 | 4) { bytes } else { 8 };
        CType::Int { bytes, signed }
    }

    #[must_use]
    pub fn pointer_to(target: CType) -> Self {
        CType::Pointer(Box::new(target))
    }

    #[must_use]
    pub fn is_pointer(&self) -> bool {
        matches!(self, CType::Pointer(_))
    }

    /// True for `float` and `double`, which SSE registers carry.
    #[must_use]
    pub fn is_sse_float(&self) -> bool {
        let CType::Named(name) = self else {
            return false;
        };
        let words: Vec<&str> = name.split_whitespace().collect();
        (words.contains(&"float") || words.contains(&"double")) && !words.contains(&"long")
    }

    #[must_use]
    pub fn is_32_bit_int(&self) -> bool {
        matches!(self, CType::Int { bytes: 4, .. })
    }

    /// True for a type whose values fit in 32 bits.
    #[must_use]
    pub fn is_narrow(&self) -> bool {
        match self {
            CType::Int { bytes, .. } => *bytes <= 4,
            CType::Named(name) => match self.integer() {
                Some((bits, _)) => bits <= 32,
                None => narrow_c_name(name),
            },
            CType::Void | CType::Pointer(_) | CType::Array(_) | CType::Function { .. } => false,
        }
    }

    /// The width in bits and the sign of an integer type, None for any
    /// other type or one whose width is not known.
    #[must_use]
    pub fn integer(&self) -> Option<(u32, bool)> {
        match self {
            CType::Int { bytes, signed } => Some((u32::from(*bytes) * 8, *signed)),
            CType::Named(name) => {
                let words: Vec<&str> = name.split_whitespace().collect();
                if words.iter().any(|word| matches!(*word, "float" | "double")) {
                    return None;
                }
                // Rust's integers name their width and sign.
                if let [word] = words.as_slice()
                    && let Some((sign, digits)) = word.split_at_checked(1)
                    && matches!(sign, "u" | "i")
                    && let Some(bits) = match digits {
                        "size" => Some(64),
                        digits => digits
                            .parse()
                            .ok()
                            .filter(|bits| matches!(bits, 8 | 16 | 32 | 64)),
                    }
                {
                    return Some((bits, sign == "i"));
                }
                let unsigned = words.iter().any(|word| {
                    matches!(
                        *word,
                        "unsigned" | "_Bool" | "bool" | "size_t" | "uintptr_t"
                    ) || word.starts_with("uint")
                });
                if let [word] = words.as_slice()
                    && let Some(known) = typedef_integer(word)
                {
                    return Some(known);
                }
                let bits = match words.as_slice() {
                    ["size_t" | "ssize_t" | "uintptr_t" | "intptr_t" | "ptrdiff_t"] => 64,
                    _ => {
                        let Some(size) = scalar_size(name) else {
                            return None;
                        };
                        u32::from(size) * 8
                    }
                };
                Some((bits, !unsigned))
            }
            CType::Void | CType::Pointer(_) | CType::Array(_) | CType::Function { .. } => None,
        }
    }

    /// The size of the scalar a pointer points at: 4 for `int *`.
    #[must_use]
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

    /// Declare a value, including names nested inside function pointer declarators.
    #[must_use]
    pub fn declaration(&self, name: &str) -> String {
        match self {
            Self::Pointer(target) => {
                let name = if matches!(target.as_ref(), Self::Function { .. } | Self::Array(_)) {
                    format!("(*{name})")
                } else {
                    format!("*{name}")
                };
                target.declaration(&name)
            }
            Self::Function {
                params,
                ret,
                variadic,
                convention,
            } => {
                let mut params: Vec<String> = params.iter().map(ToString::to_string).collect();
                if *variadic {
                    params.push("...".to_owned());
                } else if params.is_empty() {
                    params.push("void".to_owned());
                }
                let attribute = match convention {
                    super::Convention::Stdcall => "__attribute__((stdcall)) ",
                    super::Convention::Fastcall => "__attribute__((fastcall)) ",
                    super::Convention::Thiscall => "__attribute__((thiscall)) ",
                    super::Convention::Win64 => "__attribute__((ms_abi)) ",
                    _ => "",
                };
                ret.declaration(&format!("{attribute}{name}({})", params.join(", ")))
            }
            Self::Array(element) => element.declaration(&format!("{name}[]")),
            _ if name.is_empty() => self.to_string(),
            _ => format!("{self} {name}"),
        }
    }
}

/// The width and sign of the system's integer typedefs, as Linux and macOS
/// on 64-bit machines define them. `mode_t` is 16 bits on macOS, but a
/// register passes it extended to 32.
fn typedef_integer(name: &str) -> Option<(u32, bool)> {
    Some(match name {
        "off_t" | "time_t" | "clock_t" => (64, true),
        "pthread_t" | "nfds_t" => (64, false),
        "pid_t" | "clockid_t" => (32, true),
        "uid_t" | "gid_t" | "mode_t" | "useconds_t" | "socklen_t" | "in_addr_t" => (32, false),
        _ => return None,
    })
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
            let Some(width_text) = other
                .strip_prefix("uint")
                .or_else(|| other.strip_prefix("int"))
            else {
                return None;
            };
            let Some(digits) = width_text.strip_suffix("_t") else {
                return None;
            };
            let Some(bits): Option<u8> = digits.parse().ok() else {
                return None;
            };
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
            CType::Pointer(target) => {
                let mut base = target.as_ref();
                while let CType::Pointer(inner) = base {
                    base = inner;
                }
                if matches!(base, CType::Function { .. } | CType::Array(_)) {
                    f.write_str(&self.declaration(""))
                } else if target.is_pointer() {
                    write!(f, "{target}*")
                } else {
                    write!(f, "{target} *")
                }
            }
            CType::Array(element) => write!(f, "{element} []"),
            CType::Function { .. } => f.write_str(&self.declaration("")),
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

/// A structure or union the debug info defines, as C declares it.
#[derive(Debug, Clone)]
pub struct Definition {
    /// `struct pair` or `union value`.
    pub name: String,
    /// Each member's declaration, `int a;`, with gaps where the layout
    /// leaves bytes no member names, such as bit-fields.
    pub members: Vec<String>,
    /// The names its members are accessed by.
    pub fields: Vec<String>,
    /// The structures and unions it holds by value, which C defines first.
    pub contains: Vec<String>,
    pub size: u64,
    pub alignment: Option<u64>,
    /// Profiles where the generated declaration preserves the source ABI layout.
    pub compatible_profiles: Vec<AbiProfile>,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub structure: String,
    pub offset: i64,
    pub name: String,
    pub ty: CType,
    pub width: u64,
}
