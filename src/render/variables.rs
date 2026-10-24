use std::collections::{BTreeMap, HashMap, HashSet};

use crate::analysis::typing::SignEvidence;
use crate::ir::{BinOp, CType, Expr, FunctionIr, Operation, Precision, Stmt};
use crate::render::widths::Narrow;

/// The C type of each variable, from how the body uses it: a float when
/// float operations compute or read it, a pointer when it addresses memory
/// and takes no part in arithmetic beyond adding offsets, and otherwise an
/// integer as wide as its reads and as signed as the operations on it.
pub(crate) fn variable_types(
    ir: &FunctionIr,
    narrow: &HashSet<u16>,
    float_return: Option<Precision>,
) -> BTreeMap<u16, CType> {
    let mut uses = Uses::default();
    let mut pointer_copies = Vec::new();
    let mut integer_copies = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign {
                dest,
                value: Expr::Reg { width: 64, .. },
            } if dest.width == 64 => {}
            Stmt::Store { value, .. } => integer_reads(value, &mut integer_copies),
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Atomic { .. },
                inputs,
                ..
            } => {
                for value in inputs.iter().skip(1) {
                    integer_reads(value, &mut integer_copies);
                }
            }
            Stmt::Ret { .. } if ir.ret_type.is_pointer() => {}
            other => {
                for value in other.operands() {
                    integer_reads(value, &mut integer_copies);
                }
            }
        }
        match stmt {
            Stmt::Assign { dest, value } => {
                uses.seen.insert(dest.index);
                if dest.width == 64
                    && let Expr::Reg { index, width: 64 } = value
                {
                    pointer_copies.push((dest.index, *index));
                }
                if let Expr::Load { addr, .. } = value
                    && let Some(base) = base(addr)
                {
                    uses.loaded.push((dest.index, base));
                }
                if let Some(base) = base(value) {
                    uses.derived.entry(dest.index).or_default().push(base);
                } else {
                    uses.derived.entry(dest.index).or_default().push(u16::MAX);
                }
                if let Expr::Apply { op, .. } = value
                    && let Some(precision) = op.result_precision()
                {
                    uses.float(dest.index, precision);
                }
                if let Some(source) = copied(value) {
                    uses.copies.push((dest.index, source));
                }
                if let Expr::Select { then, els, .. } = value {
                    for branch in [then, els] {
                        if let Some(source) = copied(branch) {
                            uses.copies.push((dest.index, source));
                        }
                    }
                }
                if let Expr::Apply { op, .. } = value
                    && op.result_precision().is_none()
                    && op.argument_precision().is_none()
                {
                    uses.bits.insert(dest.index);
                }
            }
            Stmt::Store { addr, width, .. } => uses.address(addr, *width),
            Stmt::Ret { value } => {
                if let (Some(precision), Some(source)) = (float_return, copied(value)) {
                    uses.float(source, precision);
                }
            }
            Stmt::Machine {
                instruction,
                inputs,
                outputs,
            } => {
                if let crate::ir::MachineInstruction::Atomic { width, .. } = instruction
                    && let Some(addr) = inputs.first()
                {
                    uses.address(addr, *width);
                }
                for output in outputs {
                    uses.seen.insert(output.index);
                    uses.bits.insert(output.index);
                    uses.arithmetic.insert(output.index);
                    uses.floats.insert(output.index, None);
                }
            }
            Stmt::Call { .. } => {
                uses.seen
                    .extend(stmt.call_outputs().iter().map(|output| output.dest.index));
            }
            _ => {}
        }
        for value in stmt.operands() {
            uses.walk(value);
        }
    }
    uses.spread_floats();
    loop {
        let mut changed = false;
        for &(dest, source) in &pointer_copies {
            for (from, to) in [(source, dest), (dest, source)] {
                if integer_copies.contains(&to) {
                    continue;
                }
                let Some(widths) = uses.addresses.get(&from).cloned() else {
                    continue;
                };
                let known = uses.addresses.entry(to).or_default();
                for width in widths {
                    if !known.contains(&width) {
                        known.push(width);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    // What a float variable is loaded from holds floats.
    for (dest, base) in uses.loaded.clone() {
        if let Some(Some(precision)) = uses.floats.get(&dest).copied() {
            uses.float_elements.insert(base, precision);
        }
    }
    let signs = SignEvidence::of_variables(ir);
    let mut types = BTreeMap::new();
    let mut ints = HashSet::new();
    for index in uses.seen.clone() {
        if !crate::ir::is_temp(index) {
            continue;
        }
        let ty = if let Some(Some(precision)) = uses.floats.get(&index) {
            CType::Named(
                match precision {
                    Precision::Single => "float",
                    Precision::Double => "double",
                }
                .to_owned(),
            )
        } else if let Some(widths) = uses.addresses.get(&index)
            && !uses.arithmetic.contains(&index)
            && !narrow.contains(&index)
        {
            match ir
                .structures
                .iter()
                .find(|structure| structure.elements.contains(&index))
            {
                Some(structure) => {
                    CType::pointer_to(CType::Named(format!("struct {}", structure.name)))
                }
                // The structure its accesses at fixed offsets make.
                None => match ir.value_types.get(&index) {
                    Some(given) if given.pointee_struct().is_some() => given.clone(),
                    _ => CType::Pointer(Box::new(element(ir, &uses, index, widths))),
                },
            }
        } else if ir.pointer_values.contains(&index)
            && !uses.arithmetic.contains(&index)
            && !narrow.contains(&index)
        {
            // A callee takes it as a pointer.
            match ir.value_types.get(&index) {
                Some(given) if given.pointee_struct().is_some() => given.clone(),
                _ => CType::pointer_to(CType::Void),
            }
        } else {
            ints.insert(index);
            continue;
        };
        types.insert(index, ty);
    }
    let pointers: HashSet<u16> = types
        .iter()
        .filter(|(_, ty)| ty.is_pointer())
        .map(|(index, _)| *index)
        .chain(
            ir.params
                .iter()
                .filter(|param| param.ty.is_pointer())
                .map(|param| param.index),
        )
        .chain([crate::arch::stack_pointer(ir.isa)])
        .collect();
    let narrowed = crate::render::widths::narrow_variables(ir, &ints, narrow, &pointers);
    for index in ints {
        let signed = !uses.bits.contains(&index) && signs.mostly_signed(index);
        let ty = match narrowed.get(&index) {
            // A byte or a half word no signed operation reads is taken for
            // one without a sign, as is one a reader extends with zeros.
            Some(Narrow::Read { bits, extended }) => CType::Int {
                bytes: (bits / 8) as u8,
                signed: signed && ((!extended && *bits == 32) || signs.signed.contains(&index)),
            },
            Some(Narrow::Held { bits }) => CType::Int {
                bytes: (bits / 8) as u8,
                signed: false,
            },
            None => CType::Int { bytes: 8, signed },
        };
        let ty = match ir.value_types.get(&index) {
            Some(given) => agreeing(
                ty,
                given,
                narrow.contains(&index),
                uses.arithmetic.contains(&index),
            ),
            None => ty,
        };
        types.insert(index, ty);
    }
    if !ir.members.is_empty() {
        for index in super::naming::scaled_offsets(ir).keys() {
            types.insert(*index, CType::I64);
        }
    }
    types
}

/// Gives each field of a recovered structure that only ever holds pointers
/// a pointer type: every eight-byte value stored there and every variable
/// loaded from there is a pointer under `types`, so neither needs a
/// conversion. Fields holding pointers of more than one type are `void *`.
pub(crate) fn pointer_fields(ir: &mut FunctionIr, types: &BTreeMap<u16, CType>) {
    let type_of = |index: u16| {
        types.get(&index).cloned().or_else(|| {
            ir.params
                .iter()
                .find(|param| param.index == index)
                .map(|param| param.ty.clone())
        })
    };
    // The structure and offset an address names a field at.
    let field = |addr: &Expr| -> Option<(String, u64)> {
        let (index, offset) = match addr {
            Expr::Reg { index, width: 64 } => (*index, 0),
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, width: 64 }, Expr::Const(offset)) => (*index, *offset),
                _ => return None,
            },
            _ => return None,
        };
        let Some(ty) = type_of(index) else {
            return None;
        };
        ty.pointee_struct().map(|name| (name.to_owned(), offset))
    };
    // What each field holds: the pointer types seen, or None once anything
    // else is.
    let mut held: HashMap<(String, u64), Option<Vec<CType>>> = HashMap::new();
    let mut note = |key: (String, u64), ty: Option<CType>| {
        let entry = held.entry(key).or_insert_with(|| Some(Vec::new()));
        match (entry.as_mut(), ty) {
            (Some(seen), Some(ty)) if ty.is_pointer() => seen.push(ty),
            _ => *entry = None,
        }
    };
    // Loads of each field, and those a variable takes whole.
    let mut loads: HashMap<(String, u64), usize> = HashMap::new();
    let mut whole: HashMap<(String, u64), usize> = HashMap::new();
    fn count_loads(
        expr: &Expr,
        field: &dyn Fn(&Expr) -> Option<(String, u64)>,
        loads: &mut HashMap<(String, u64), usize>,
    ) {
        if let Expr::Load { addr, .. } = expr
            && let Some(key) = field(addr)
        {
            *loads.entry(key).or_default() += 1;
        }
        for child in crate::ir::visit::children(expr) {
            count_loads(child, field, loads);
        }
    }
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for value in stmt.operands() {
            count_loads(value, &field, &mut loads);
        }
        match stmt {
            Stmt::Store { addr, value, width } => {
                if let Some(key) = field(addr) {
                    match (width, value) {
                        (8, Expr::Reg { index, width: 64 }) => note(key, type_of(*index)),
                        // A null pointer is any pointer.
                        (8, Expr::Const(0)) => {}
                        _ => note(key, None),
                    }
                }
            }
            Stmt::Assign { dest, value } => {
                if let Expr::Load { addr, width: 8, .. } = value
                    && dest.width == 64
                    && let Some(key) = field(addr)
                {
                    note(key.clone(), type_of(dest.index));
                    *whole.entry(key).or_default() += 1;
                }
            }
            Stmt::Machine { inputs, .. } => {
                if let Some(key) = inputs.first().and_then(field) {
                    note(key, None);
                }
            }
            _ => {}
        }
    }
    // A field read any other way holds a value used otherwise.
    for (key, count) in loads {
        if whole.get(&key).copied().unwrap_or(0) < count {
            note(key, None);
        }
    }
    for structure in &mut ir.structures {
        // A field sharing its cell with others is a member of a union.
        let shared: HashSet<u64> = crate::render::unions::cells(&structure.fields)
            .into_iter()
            .filter(|(_, _, fields)| fields.len() > 1)
            .flat_map(|(_, _, fields)| fields.into_iter().map(|(offset, _)| offset))
            .collect();
        for (offset, ty) in &mut structure.fields {
            if ty.integer().map(|(bits, _)| bits) != Some(64) || shared.contains(offset) {
                continue;
            }
            let Some(Some(seen)) = held.get(&(structure.name.clone(), *offset)) else {
                continue;
            };
            let Some(first) = seen.first() else {
                continue;
            };
            *ty = if seen.iter().all(|other| other == first) {
                first.clone()
            } else {
                CType::pointer_to(CType::Void)
            };
        }
    }
}

/// Reads of a value rather than of the memory it addresses.
fn integer_reads(expr: &Expr, reads: &mut HashSet<u16>) {
    match expr {
        Expr::Load { .. } => {}
        Expr::Reg { index, .. } => {
            reads.insert(*index);
        }
        other => {
            for child in crate::ir::visit::children(other) {
                integer_reads(child, reads);
            }
        }
    }
}

/// The type a prototype gives a variable where it agrees with how the body
/// uses it: a pointer the body does no arithmetic on, and that the
/// accesses through it say no more of; an integer as wide as its reads.
fn agreeing(used: CType, given: &CType, narrow: bool, arithmetic: bool) -> CType {
    if used.is_sse_float() || used.pointee_struct().is_some() {
        return used;
    }
    if given.pointee_struct().is_some() && !narrow {
        return given.clone();
    }
    if given.is_pointer() {
        let vague = crate::analysis::prototypes::void_pointer(given) && used.is_pointer();
        return if narrow || arithmetic || vague {
            used
        } else {
            given.clone()
        };
    }
    match given.integer() {
        Some((bits, _)) if !used.is_pointer() && (bits <= 32) == narrow => given.clone(),
        _ => used,
    }
}

/// What a pointer variable points at: the type of the parameter it moves
/// along, or else scalars as wide as every access through it.
fn element(ir: &FunctionIr, uses: &Uses, index: u16, widths: &[u8]) -> CType {
    let width = widths[0];
    if widths.iter().any(|other| *other != width) {
        return CType::Void;
    }
    let sources = uses.derived.get(&index).map(Vec::as_slice).unwrap_or(&[]);
    let mut from_params = sources
        .iter()
        .filter(|source| **source != index)
        .map(|source| {
            ir.params
                .iter()
                .find(|param| param.index == *source && param.ty.pointee_size() == Some(width))
        });
    if let Some(Some(param)) = from_params.next()
        && from_params.all(|other| other.is_some_and(|other| other.ty == param.ty))
        && let CType::Pointer(target) = &param.ty
    {
        return target.as_ref().clone();
    }
    match uses.float_elements.get(&index) {
        Some(Precision::Double) if width == 8 => CType::Named("double".to_owned()),
        Some(Precision::Single) if width == 4 => CType::Named("float".to_owned()),
        // Elements every load extends with the sign are signed.
        _ => CType::Int {
            bytes: width,
            signed: width < 8
                && uses
                    .extended
                    .get(&index)
                    .is_some_and(|signs| signs.iter().all(|signed| *signed)),
        },
    }
}

#[derive(Default)]
struct Uses {
    seen: HashSet<u16>,
    /// The precision of each float register; `None` once two disagree.
    floats: HashMap<u16, Option<Precision>>,
    /// The widths of the accesses each register addresses.
    addresses: HashMap<u16, Vec<u8>>,
    /// Registers some operation other than adding an offset reads.
    arithmetic: HashSet<u16>,
    /// Registers holding lanes or bit counts, which have no sign.
    bits: HashSet<u16>,
    /// `(destination, source)` of each copy.
    copies: Vec<(u16, u16)>,
    /// `(destination, pointer)` of each load through a pointer.
    loaded: Vec<(u16, u16)>,
    /// Pointers floats are loaded through, with their precision.
    float_elements: HashMap<u16, Precision>,
    /// The pointer each assignment offsets, `u16::MAX` for any other value.
    derived: HashMap<u16, Vec<u16>>,
    /// Whether each load through a pointer extends with the sign.
    extended: HashMap<u16, Vec<bool>>,
}

impl Uses {
    fn float(&mut self, index: u16, precision: Precision) {
        let entry = self.floats.entry(index).or_insert(Some(precision));
        if *entry != Some(precision) {
            *entry = None;
        }
    }

    /// A copy holds the same value as its source, so the float type of
    /// either is the other's.
    fn spread_floats(&mut self) {
        loop {
            let mut changed = false;
            for (dest, source) in self.copies.clone() {
                for (from, to) in [(source, dest), (dest, source)] {
                    if let Some(Some(precision)) = self.floats.get(&from).copied()
                        && !self.floats.contains_key(&to)
                    {
                        self.floats.insert(to, Some(precision));
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn address(&mut self, addr: &Expr, width: u8) {
        if let Some(base) = base(addr) {
            self.addresses.entry(base).or_default().push(width);
        }
    }

    fn walk(&mut self, expr: &Expr) {
        match expr {
            Expr::Reg { index, .. } => {
                self.seen.insert(*index);
            }
            Expr::Load {
                addr,
                width,
                signed,
            } => {
                self.address(addr, *width);
                if let Some(base) = base(addr) {
                    self.extended.entry(base).or_default().push(*signed);
                }
            }
            Expr::Bin { op, lhs, rhs } => {
                if !matches!(op, BinOp::Add | BinOp::Sub) {
                    for side in [lhs, rhs] {
                        if let Some(index) = copied(side) {
                            self.arithmetic.insert(index);
                        }
                    }
                }
            }
            Expr::SignExtend { value, .. } => {
                if let Some(index) = copied(value) {
                    self.arithmetic.insert(index);
                }
            }
            Expr::Apply { op, args } => {
                for arg in args {
                    if let (Some(precision), Expr::Load { addr, .. }) =
                        (op.argument_precision(), arg)
                        && let Some(base) = base(addr)
                    {
                        self.float_elements.insert(base, precision);
                    }
                    let Some(index) = copied(arg) else {
                        continue;
                    };
                    self.arithmetic.insert(index);
                    match op.argument_precision() {
                        Some(precision) => self.float(index, precision),
                        None if !matches!(op, Operation::IntToFloat { .. }) => {
                            self.bits.insert(index);
                        }
                        None => {}
                    }
                }
            }
            _ => {}
        }
        for child in crate::ir::visit::children(expr) {
            self.walk(child);
        }
    }
}

/// The register a value is, or the low half of.
fn copied(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            Expr::Reg { index, .. } => Some(*index),
            _ => None,
        },
        _ => None,
    }
}

/// The one register an address adds offsets to: constants, and indexes
/// scaled by a multiply or a shift.
fn base(addr: &Expr) -> Option<u16> {
    fn terms<'e>(expr: &'e Expr, out: &mut Vec<&'e Expr>) {
        match expr {
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                terms(lhs, out);
                terms(rhs, out);
            }
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(_)) => terms(lhs, out),
            other => out.push(other),
        }
    }
    let mut found = Vec::new();
    terms(addr, &mut found);
    let mut registers = found.iter().filter_map(|term| match term {
        Expr::Reg { index, width: 64 } => Some(*index),
        _ => None,
    });
    let Some(register) = registers.next() else {
        return None;
    };
    let rest_are_offsets = found.iter().all(|term| match term {
        Expr::Reg { index, .. } => *index == register,
        Expr::Const(_) => true,
        Expr::Bin {
            op: BinOp::Mul | BinOp::Shl,
            ..
        } => true,
        _ => false,
    });
    (registers.next().is_none() && rest_are_offsets).then_some(register)
}

/// Whether `name` stands in `text` as a whole word.
pub(crate) fn mentions(text: &str, name: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(name).any(|(at, _)| {
        !text[..at].chars().next_back().is_some_and(word)
            && !text[at + name.len()..].chars().next().is_some_and(word)
    })
}
