//! Pseudo-C rendering of the register-expression IR.

use std::collections::HashMap;

use crate::ir::{reg_name, BinOp, Cond, Expr, FunctionIr, Stmt};
use crate::loader::Isa;
use crate::structure::{structure, Out};

struct Ctx<'a> {
    isa: Isa,
    names: HashMap<u16, &'a str>,
    /// Rendered stack addresses that name a local slot, mapped to the
    /// local's name. Frame-relative accesses are reviewed once per
    /// function so a load and its store agree even after the frame moves.
    slots: HashMap<String, String>,
    /// The declared width of each named local, so a read that only repeats
    /// the local's own width is not spelled out as a mask.
    local_widths: HashMap<String, u8>,
    /// Parameters declared wider than 32 bits: masking one of those down is
    /// a real truncation, so it keeps its spelling.
    wide_params: std::collections::HashSet<u16>,
    /// Parameters declared as pointers, with the fields their accesses name.
    pointer_params: std::collections::HashSet<u16>,
    fields: HashMap<(u16, i64), (u8, bool)>,
    /// Symbol names by address, so a call reads with the callee's name.
    callees: &'a HashMap<u64, String>,
    /// Non-executable section ranges: an access at a constant address there
    /// is a global, named from its width and address.
    data_ranges: Vec<(u64, u64)>,
    /// Structure fields the debug info names, by struct and byte offset.
    members: HashMap<(String, i64), String>,
    /// The struct type each pointer parameter points at, when known.
    pointees: HashMap<u16, String>,
    /// Registers whose readers only ever look at the low 32 bits.
    narrow_regs: std::collections::HashSet<u16>,
    /// The function returns a 32-bit value, so reg 0 needs no truncation.
    narrow_return: bool,
}

impl Ctx<'_> {
    fn register(&self, index: u16, width: u8) -> String {
        match self.names.get(&index) {
            Some(name) => (*name).to_owned(),
            None => reg_name(self.isa, index, width),
        }
    }
}

fn type_of(width: u8, signed: bool) -> &'static str {
    match (width, signed) {
        (1, false) => "uint8_t",
        (2, false) => "uint16_t",
        (4, false) => "uint32_t",
        (8, false) => "uint64_t",
        (1, true) => "int8_t",
        (2, true) => "int16_t",
        (4, true) => "int32_t",
        _ => "int64_t",
    }
}

fn operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::MulHigh => "__umulh",
        BinOp::MulHighS => "__smulh",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
        BinOp::Sar => ">>>",
        BinOp::DivS => "/",
        BinOp::ModS => "%",
        BinOp::DivU => "/",
        BinOp::ModU => "%",
    }
}

/// Binding strength, so a nested expression only keeps the parentheses it
/// needs: `x8 = w8 * w9` rather than `x8 = ((w8 * w9))`.
fn precedence(expr: &Expr) -> u8 {
    match expr {
        Expr::Select { .. } => 1,
        Expr::Bin { op, .. } => match op {
            BinOp::Or => 4,
            BinOp::Xor => 5,
            BinOp::And => 6,
            BinOp::Shl | BinOp::Shr | BinOp::Sar => 9,
            BinOp::Add | BinOp::Sub => 10,
            BinOp::Mul
            | BinOp::DivS
            | BinOp::DivU
            | BinOp::ModS
            | BinOp::ModU
            | BinOp::MulHigh
            | BinOp::MulHighS => 11,
        },
        Expr::SignExtend { .. } => 12,
        _ => 13,
    }
}

/// The binding strength the printed text will have, which is weaker than
/// the node's own when a mask around it disappears.
fn printed_precedence(expr: &Expr, ctx: &Ctx<'_>) -> u8 {
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        let mask = matches!(rhs.as_ref(), Expr::Const(0xffff_ffff));
        let elided = fits(lhs, 32, ctx)
            || mask_matches_local(lhs, rhs, ctx)
            || matches!(lhs.as_ref(), Expr::Reg { index, .. } if !ctx.wide_params.contains(index));
        if mask {
            // An elided mask leaves the value's own binding; a printed one
            // carries its own parentheses.
            return if elided {
                printed_precedence(lhs, ctx)
            } else {
                13
            };
        }
    }
    precedence(expr)
}

/// Renders a child, parenthesising it when the surrounding operator would
/// otherwise regroup it.
fn operand(expr: &Expr, ctx: &Ctx<'_>, parent: u8, right: bool) -> String {
    let text = render_expr(expr, ctx);
    let own = printed_precedence(expr, ctx);
    let binds = own > parent || (own == parent && !right);
    if binds || own >= 12 {
        text
    } else {
        format!("({text})")
    }
}

fn render_expr(value: &Expr, ctx: &Ctx<'_>) -> String {
    match value {
        Expr::Reg { index, width } => ctx.register(*index, *width),
        Expr::Const(value) => match ctx.callees.get(value) {
            // An address that names a function reads as that function; zero
            // stays a constant, since an image may place code there.
            Some(name) if *value != 0 => sanitize(name),
            _ => format!("0x{value:x}"),
        },
        // Negation reads `-x`, not `0 - x`, the way mature decompilers
        // print the two's-complement negate idiom.
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Const(0)) => {
            format!("-{}", operand(rhs, ctx, 12, false))
        }
        // Complementing a value with an all-ones constant reads as `~x`.
        Expr::Bin {
            op: BinOp::Xor,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(u64::MAX)) => {
            format!("~{}", operand(lhs, ctx, 12, false))
        }
        // A mask over a value that cannot exceed it is noise: the boolean
        // materialisations and 32-bit loads land here.
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) && fits(lhs, 32, ctx) => {
            render_expr(lhs, ctx)
        }
        // A mask that only repeats a local's own declared width is noise.
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if mask_matches_local(lhs, rhs, ctx) => render_expr(lhs, ctx),
        // `reg & 0xffffffff` reads the register's 32-bit name instead.
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            // A truncating mask on a wide parameter keeps its spelling; on
            // a register that already holds a 32-bit value it reads as the
            // 32-bit register name.
            Expr::Reg { index, .. } if !ctx.wide_params.contains(index) => {
                ctx.register(*index, 32)
            }
            // Parenthesise the masked value so the mask reads as one
            // operation, not as a suffix on the last term.
            _ => {
                let strength = precedence(lhs);
                let left = if strength > 6 && strength < 12 {
                    format!("({})", render_expr(lhs, ctx))
                } else {
                    operand(lhs, ctx, 6, false)
                };
                format!("({left} & {})", render_expr(rhs, ctx))
            }
        },
        // A negated displacement reads as subtraction: `sp - 0x20` rather
        // than `sp + 0xffffffffffffffe0`.
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(value) if *value >= 1 << 63 => format!(
                "{} - 0x{:x}",
                operand(lhs, ctx, 10, false),
                value.wrapping_neg()
            ),
            _ => format!(
                "{} + {}",
                operand(lhs, ctx, 10, false),
                operand(rhs, ctx, 10, true)
            ),
        },
        // The wide multiply reads as the intrinsic that names it.
        Expr::Bin {
            op: BinOp::MulHigh,
            lhs,
            rhs,
        } => format!(
            "__umulh({}, {})",
            render_expr(lhs, ctx),
            render_expr(rhs, ctx)
        ),
        Expr::Bin {
            op: BinOp::MulHighS,
            lhs,
            rhs,
        } => format!(
            "__smulh({}, {})",
            render_expr(lhs, ctx),
            render_expr(rhs, ctx)
        ),
        Expr::Bin { op, lhs, rhs } => {
            let strength = precedence(value);
            format!(
                "{} {} {}",
                operand(lhs, ctx, strength, false),
                operator(*op),
                operand(rhs, ctx, strength, true)
            )
        }
        Expr::Load { addr, width, signed } => {
            if let Some(member) = member_access(addr, *width, ctx) {
                return member;
            }
            // A table lookup reads as indexing the table: `dword_200120[i]`.
            if let Some(indexed) = array_access(addr, *width, ctx) {
                return indexed;
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => name.clone(),
                None => match global_name(addr, *width, ctx) {
                    Some(name) => name,
                    None => format!("*({} *)({})", type_of(*width, *signed), address),
                },
            }
        }
        Expr::SignExtend { value, width } => {
            format!("({})({})", type_of(*width, true), render_expr(value, ctx))
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => format!(
            "({} ? {} : {})",
            condition(*cond, lhs, rhs, ctx),
            operand(then, ctx, 1, false),
            operand(els, ctx, 1, true)
        ),
    }
}

/// True when the value provably fits in `bits` bits, so a mask of that
/// width cannot change it.
fn fits(expr: &Expr, bits: u32, ctx: &Ctx<'_>) -> bool {
    match expr {
        Expr::Const(value) => bits >= 64 || (*value >> bits) == 0,
        // A parameter declared 32 bits wide already holds a 32-bit value,
        // however wide the register read is.
        Expr::Reg { index, width } => {
            u32::from(*width) <= bits
                || (ctx.names.contains_key(index) && !ctx.wide_params.contains(index))
        }
        Expr::Load { width, .. } => u32::from(*width) * 8 <= bits,
        // A sign-extended value carries its source's width, sign included.
        Expr::SignExtend { width, .. } => u32::from(*width) * 8 <= bits,
        Expr::Bin { op, lhs, rhs } => match op {
            // A constant mask bounds the result, whatever the input was.
            BinOp::And => match rhs.as_ref() {
                Expr::Const(mask) => bits >= 64 || (*mask >> bits) == 0,
                _ => fits(lhs, bits, ctx) && fits(rhs, bits, ctx),
            },
            // A bitwise result cannot carry more bits than its inputs.
            BinOp::Or | BinOp::Xor => fits(lhs, bits, ctx) && fits(rhs, bits, ctx),
            // Arithmetic on 32-bit typed operands wraps at 32 bits in C the
            // same way the mask does.
            BinOp::Add | BinOp::Sub | BinOp::Mul => {
                fits(lhs, bits, ctx) && fits(rhs, bits, ctx)
            }
            // A left shift of a 32-bit value wraps at 32 bits in C.
            BinOp::Shl => matches!(rhs.as_ref(), Expr::Const(amount) if *amount < 32) && fits(lhs, bits, ctx),
            // A quotient and a remainder are bounded by their operands, and
            // a right shift only ever loses bits.
            BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU | BinOp::Shr | BinOp::Sar => {
                fits(lhs, bits, ctx) && fits(rhs, bits, ctx)
            }
            _ => false,
        },
        Expr::Select { then, els, .. } => fits(then, bits, ctx) && fits(els, bits, ctx),
    }
}

/// True when the mask is exactly the width a named local already has.
fn mask_matches_local(lhs: &Expr, rhs: &Expr, ctx: &Ctx<'_>) -> bool {
    let Expr::Const(mask) = rhs else {
        return false;
    };
    let Expr::Load { addr, .. } = lhs else {
        return false;
    };
    let Some(name) = ctx.slots.get(&render_expr(addr, ctx)) else {
        return false;
    };
    let Some(width) = ctx.local_widths.get(name) else {
        return false;
    };
    *width < 8 && *mask == (1u64 << (u32::from(*width) * 8)).wrapping_sub(1)
}

fn condition(cond: Cond, lhs: &Expr, rhs: &Expr, ctx: &Ctx<'_>) -> String {
    let a = render_expr(lhs, ctx);
    let b = render_expr(rhs, ctx);
    match cond {
        Cond::Eq => format!("{a} == {b}"),
        Cond::Ne => format!("{a} != {b}"),
        Cond::Lt => format!("{a} < {b}"),
        Cond::Ge => format!("{a} >= {b}"),
        Cond::Gt => format!("{a} > {b}"),
        Cond::Le => format!("{a} <= {b}"),
        Cond::Cs => format!("{a} >= {b} /* unsigned */"),
        Cond::Cc => format!("{a} < {b} /* unsigned */"),
        Cond::Hi => format!("{a} > {b} /* unsigned */"),
        Cond::Ls => format!("{a} <= {b} /* unsigned */"),
        Cond::Mi => "flags_mi /* mi */".to_owned(),
        Cond::Pl => "flags_pl /* pl */".to_owned(),
        Cond::Vs => "flags_vs /* vs */".to_owned(),
        Cond::Vc => "flags_vc /* vc */".to_owned(),
    }
}

/// The non-executable section ranges, where a constant address names a
/// global rather than a jump target.
pub fn data_ranges(image: &crate::loader::Image) -> Vec<(u64, u64)> {
    image
        .sections
        .iter()
        .filter(|section| !section.executable)
        .map(|section| (section.vaddr, section.size))
        .collect()
}

/// Symbol names by address, for call sites.
pub fn callee_names(image: &crate::loader::Image) -> HashMap<u64, String> {
    image
        .functions
        .iter()
        .filter_map(|(address, function)| {
            function
                .name
                .as_ref()
                .map(|name| (*address, name.clone()))
        })
        .collect()
}

pub fn render(
    ir: &mut FunctionIr,
    references: &[crate::refs::Reference],
    callees: &HashMap<u64, String>,
    data_ranges: Vec<(u64, u64)>,
) -> String {
    // Settle the frame once: every access then names its slot, and the
    // pointer adjustments drop out of the pseudocode.
    let frames = block_frames(ir, stack_pointer(ir.isa));
    if canonical_frame(ir, &frames) {
        rewrite_frame(ir, &frames);
        // Every access names its slot now, so a slot nothing reads can go,
        // and the copy that leaves its reader can fold.
        crate::pass::drop_dead_frame_stores(ir);
        crate::pass::inline_local_copies(ir);
        let frames = block_frames(ir, stack_pointer(ir.isa));
        let locals = stack_locals(ir, &frames);
        return render_with(ir, references, locals, callees, data_ranges);
    }
    let ir: &FunctionIr = ir;
    let locals = stack_locals(ir, &frames);
    render_with(ir, references, locals, callees, data_ranges)
}

fn render_with(
    ir: &FunctionIr,
    references: &[crate::refs::Reference],
    locals: Locals,
    callees: &HashMap<u64, String>,
    data_ranges: Vec<(u64, u64)>,
) -> String {
    let names: HashMap<u16, &str> = ir
        .params
        .iter()
        .map(|param| (param.index, param.name.as_str()))
        .collect();
    let wide_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| !narrow_type(&param.ty))
        .map(|param| param.index)
        .collect();
    let (pointer_params, fields) = struct_fields(ir);
    let narrow_regs = narrow_registers(ir);
    let members: HashMap<(String, i64), String> = ir
        .members
        .iter()
        .map(|(structure, offset, name)| ((structure.clone(), *offset), name.clone()))
        .collect();
    // `struct pair *p` points at a `pair`, so `p->0x4` can take a name.
    let pointees: HashMap<u16, String> = ir
        .params
        .iter()
        .filter_map(|param| {
            let ty = param.ty.trim();
            let base = ty
                .strip_suffix('*')
                .map(str::trim)
                .and_then(|inner| inner.strip_prefix("struct "))
                .map(|name| name.trim().to_owned())?;
            Some((param.index, base))
        })
        .collect();
    let ctx = Ctx {
        isa: ir.isa,
        names,
        slots: locals.slots,
        local_widths: locals.widths,
        wide_params,
        pointer_params,
        fields,
        callees,
        data_ranges,
        members,
        pointees,
        narrow_regs,
        narrow_return: matches!(ir.ret_type.as_str(), "uint32_t" | "int32_t"),
    };

    let mut out = String::new();
    let name = ir.name.as_deref().unwrap_or("fn");
    out.push_str(&format!(
        "/* velk pseudo-C: {} @ 0x{:x} */\n",
        name, ir.addr
    ));
    for reference in references {
        out.push_str(&format!("/* ref: {} */\n", reference.describe()));
    }
    for access in &ir.accesses {
        out.push_str(&format!("/* struct: {access} */\n"));
    }
    out.push_str(&format!(
        "{} {}({}) {{\n",
        ret_type(ir),
        sanitize(name),
        signature(ir)
    ));
    // The frame slots the body names, declared with the widest access they
    // receive so the pseudocode reads like C.
    let mut decls = locals.decls;
    // Declared in the order the body first names them.
    decls.sort_by_key(|local| {
        local
            .name
            .rsplit_once('_')
            .and_then(|(_, index)| index.parse::<usize>().ok())
            .unwrap_or(0)
    });
    // Render the body first, so the declarations only cover the slots the
    // pseudocode actually names.
    let mut body = String::new();
    render_nodes(&structure(ir), 1, &mut body, &ctx);
    for local in &decls {
        if local.width == 0 || !body.contains(&local.name) {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!(
            "{} {}; /* [sp{}{:x}] */\n",
            type_of(local.width, local.signed),
            local.name,
            if local.slot < 0 { "-" } else { "+" },
            local.slot.unsigned_abs()
        ));
    }
    let declared = decls
        .iter()
        .filter(|local| local.width != 0 && body.contains(&local.name))
        .count();
    if declared > 0 {
        out.push('\n');
    }
    out.push_str(&body);
    out.push_str("}\n");
    out
}

/// True when the stack pointer is only ever a frame-relative address base,
/// so the code can be rewritten against the frame it settled into and the
/// adjustments themselves dropped. Anything else (a stack argument, a saved
/// stack pointer) keeps the original spelling.
fn canonical_frame(ir: &FunctionIr, frames: &[Option<i64>]) -> bool {
    let sp = stack_pointer(ir.isa);
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            return false;
        };
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    if frame_slot(addr, frame, sp).is_none() || !frame_only(value, frame, sp) {
                        return false;
                    }
                }
                Stmt::Assign { dest, value } => {
                    if dest.index == sp {
                        // Only the adjustment itself may write the pointer.
                        if !is_adjustment(value, sp) {
                            if std::env::var("VELK_FRAME_TRACE").is_ok() {
                                eprintln!("blk{position} sp write rejected: {stmt:?}");
                            }
                            return false;
                        }
                        continue;
                    }
                    if !frame_only(value, frame, sp) {
                        return false;
                    }
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    if !frame_only(lhs, frame, sp) || !frame_only(rhs, frame, sp) {
                        return false;
                    }
                }
                Stmt::Switch { index, .. } => {
                    if !frame_only(index, frame, sp) {
                        return false;
                    }
                }
                Stmt::BrIndirect { target } => {
                    if !frame_only(target, frame, sp) {
                        return false;
                    }
                }
                Stmt::Ret { value } => {
                    if !frame_only(value, frame, sp) {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    true
}

/// True when every stack pointer mention in the value is the base of a
/// frame slot the analysis can name.
fn frame_only(expr: &Expr, frame: i64, sp: u16) -> bool {
    match expr {
        Expr::Reg { index, .. } => *index != sp,
        Expr::Const(_) => true,
        Expr::Bin { lhs, rhs, .. } => {
            frame_only(lhs, frame, sp) && frame_only(rhs, frame, sp)
        }
        // A load through a pointer is fine as long as the pointer itself
        // carries no bare stack pointer: the slot load under it names the
        // variable the pointer came from.
        Expr::Load { addr, .. } => match frame_slot(addr, frame, sp) {
            Some(_) => true,
            None => frame_only(addr, frame, sp),
        },
        Expr::SignExtend { value, .. } => frame_only(value, frame, sp),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            frame_only(lhs, frame, sp)
                && frame_only(rhs, frame, sp)
                && frame_only(then, frame, sp)
                && frame_only(els, frame, sp)
        }
    }
}

fn is_adjustment(value: &Expr, sp: u16) -> bool {
    matches!(
        value,
        Expr::Bin { lhs, .. } if matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp)
    )
}

/// Rewrites every frame-relative address against the entry frame and drops
/// the adjustments, so one slot keeps one spelling wherever it is touched.
fn rewrite_frame(ir: &mut FunctionIr, frames: &[Option<i64>]) {
    let sp = stack_pointer(ir.isa);
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let Some(mut frame) = frames[position] else {
            continue;
        };
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    if let Some(slot) = frame_slot(addr, frame, sp) {
                        *addr = frame_address(sp, slot);
                    }
                    rewrite_expr_frame(value, frame, sp);
                }
                Stmt::Assign { dest, value } => {
                    if dest.index == sp {
                        if let Expr::Bin { op, rhs, .. } = value {
                            if let Expr::Const(delta) = rhs.as_ref() {
                                frame = match op {
                                    BinOp::Add => frame.wrapping_add(*delta as i64),
                                    BinOp::Sub => frame.wrapping_sub(*delta as i64),
                                    _ => frame,
                                };
                            }
                        }
                        continue;
                    }
                    rewrite_expr_frame(value, frame, sp);
                }
                Stmt::Ret { value } => rewrite_local_loads(value, frame, sp),
                _ => {}
            }
        }
        // Drop the adjustments now that every access names its slot.
        block
            .stmts
            .retain(|stmt| !matches!(stmt, Stmt::Assign { dest, value } if dest.index == sp && is_adjustment(value, sp)));
    }
}

/// Rewrites a value's local-slot loads into the canonical frame address.
fn rewrite_local_loads(expr: &mut Expr, frame: i64, sp: u16) {
    match expr {
        Expr::Load { addr, .. } => match frame_slot(addr, frame, sp) {
            Some(slot) if slot < 0 => *addr = Box::new(frame_address(sp, slot)),
            Some(_) => {}
            None => rewrite_local_loads(addr, frame, sp),
        },
        Expr::Bin { lhs, rhs, .. } => {
            rewrite_local_loads(lhs, frame, sp);
            rewrite_local_loads(rhs, frame, sp);
        }
        Expr::SignExtend { value, .. } => rewrite_local_loads(value, frame, sp),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            rewrite_local_loads(lhs, frame, sp);
            rewrite_local_loads(rhs, frame, sp);
            rewrite_local_loads(then, frame, sp);
            rewrite_local_loads(els, frame, sp);
        }
        _ => {}
    }
}

fn rewrite_expr_frame(expr: &mut Expr, frame: i64, sp: u16) {
    match expr {
        Expr::Load { addr, .. } => {
            if let Some(slot) = frame_slot(addr, frame, sp) {
                **addr = frame_address(sp, slot);
            } else {
                rewrite_expr_frame(addr, frame, sp);
            }
        }
        Expr::Bin { lhs, rhs, .. } => {
            rewrite_expr_frame(lhs, frame, sp);
            rewrite_expr_frame(rhs, frame, sp);
        }
        Expr::SignExtend { value, .. } => rewrite_expr_frame(value, frame, sp),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            rewrite_expr_frame(lhs, frame, sp);
            rewrite_expr_frame(rhs, frame, sp);
            rewrite_expr_frame(then, frame, sp);
            rewrite_expr_frame(els, frame, sp);
        }
        _ => {}
    }
}

fn frame_address(sp: u16, slot: i64) -> Expr {
    Expr::bin(
        BinOp::Add,
        Expr::Reg { index: sp, width: 64 },
        Expr::Const(slot as u64),
    )
}


/// A store of `op(load(same address), rhs)` is a compound assignment.
fn update_of_same_location<'e>(addr: &Expr, value: &'e Expr) -> Option<(&'static str, &'e Expr)> {
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    let symbol = match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
        BinOp::Sar => ">>",
        BinOp::Mul => "*",
        _ => return None,
    };
    let Expr::Load { addr: read, .. } = lhs.as_ref() else {
        return None;
    };
    if format!("{read:?}") != format!("{addr:?}") {
        return None;
    }
    Some((symbol, rhs))
}

/// True for the C types that hold a 32-bit value, so a register read of one
/// needs no explicit truncation.
fn narrow_type(ty: &str) -> bool {
    let cleaned = ty.trim();
    if cleaned.ends_with('*') || cleaned.ends_with(']') {
        return false;
    }
    let mut words = cleaned.split_whitespace();
    let mut narrow = false;
    let mut wide_word = false;
    for word in words.by_ref() {
        let word = word.trim_start_matches("const ").trim();
        match word {
            "signed" | "unsigned" | "const" | "volatile" => {}
            "char" | "short" | "int" | "_Bool" | "float" | "bool" => narrow = true,
            "long" | "double" | "long long" => wide_word = true,
            other => {
                if let Some(rest) = other.strip_prefix("uint") {
                    narrow = rest
                        .strip_suffix("_t")
                        .and_then(|bits| bits.parse::<u32>().ok())
                        .is_some_and(|bits| bits <= 32);
                } else if let Some(rest) = other.strip_prefix("int") {
                    narrow = rest
                        .strip_suffix("_t")
                        .and_then(|bits| bits.parse::<u32>().ok())
                        .is_some_and(|bits| bits <= 32);
                }
            }
        }
    }
    narrow && !wide_word
}

/// Registers every reader truncates to 32 bits, so a 32-bit value needs no
/// explicit zero extension on the way in.
fn narrow_registers(ir: &FunctionIr) -> std::collections::HashSet<u16> {
    let mut wide: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut seen: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { value, .. } => scan_reads(value, &mut seen, &mut wide),
                Stmt::Store { addr, value, .. } => {
                    scan_reads(addr, &mut seen, &mut wide);
                    scan_reads(value, &mut seen, &mut wide);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    scan_reads(lhs, &mut seen, &mut wide);
                    scan_reads(rhs, &mut seen, &mut wide);
                }
                Stmt::Ret { value } => scan_reads(value, &mut seen, &mut wide),
                Stmt::BrIndirect { target } => scan_reads(target, &mut seen, &mut wide),
                Stmt::Switch { index, .. } => scan_reads(index, &mut seen, &mut wide),
                _ => {}
            }
        }
    }
    seen.into_iter().filter(|index| !wide.contains(index)).collect()
}

fn scan_reads(
    expr: &Expr,
    seen: &mut std::collections::HashSet<u16>,
    wide: &mut std::collections::HashSet<u16>,
) {
    match expr {
        Expr::Reg { index, width } => {
            seen.insert(*index);
            if u32::from(*width) > 32 {
                wide.insert(*index);
            }
        }
        Expr::Const(_) => {}
        Expr::Bin { op, lhs, rhs } => {
            // A masked read only observes the low 32 bits.
            if matches!(op, BinOp::And) && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) {
                if let Expr::Reg { index, .. } = lhs.as_ref() {
                    seen.insert(*index);
                    scan_reads(rhs, seen, wide);
                    return;
                }
            }
            scan_reads(lhs, seen, wide);
            scan_reads(rhs, seen, wide);
        }
        Expr::Load { addr, .. } => scan_reads(addr, seen, wide),
        Expr::SignExtend { value, .. } => scan_reads(value, seen, wide),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            scan_reads(lhs, seen, wide);
            scan_reads(rhs, seen, wide);
            scan_reads(then, seen, wide);
            scan_reads(els, seen, wide);
        }
    }
}

/// `*(T *)(base + i * sizeof T)` indexes the table at `base`.
fn array_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let span = u64::from(width);
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = addr
    else {
        return None;
    };
    let (base, index) = match (lhs.as_ref(), rhs.as_ref()) {
        (Expr::Const(base), scaled) => (*base, scaled),
        (scaled, Expr::Const(base)) => (*base, scaled),
        _ => return None,
    };
    let index = match index {
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(shift) if (1u64 << (shift & 63)) == span => lhs.as_ref(),
            _ => return None,
        },
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Const(step), index) | (index, Expr::Const(step)) if *step == span => index,
            _ => return None,
        },
        _ => return None,
    };
    let name = global_name(&Expr::Const(base), width, ctx)?;
    Some(format!("{}[{}]", name, render_expr(index, ctx)))
}

/// Names a global the way disassemblers do: the access width plus the
/// address, so `*(uint64_t *)(0x140003000)` reads as `qword_140003000`.
fn global_name(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let Expr::Const(address) = addr else {
        return None;
    };
    if !ctx
        .data_ranges
        .iter()
        .any(|(start, size)| *address >= *start && *address < start.saturating_add(*size))
    {
        return None;
    }
    let kind = match width {
        1 => "byte",
        2 => "word",
        4 => "dword",
        _ => "qword",
    };
    Some(format!("{kind}_{address:x}"))
}

/// The pointer parameters and the `(offset, width, signed)` fields their
/// accesses name, so a member reads as `p->field_0x4` instead of a cast.
/// Every `base + offset` a pointer-parameter load reads through.
fn field_loads(expr: &Expr, out: &mut Vec<(u16, i64)>) {
    match expr {
        Expr::Load { addr, .. } => {
            if let Some((base, offset)) = member_address(addr) {
                out.push((base, offset));
            }
            field_loads(addr, out);
        }
        Expr::Bin { lhs, rhs, .. } => {
            field_loads(lhs, out);
            field_loads(rhs, out);
        }
        Expr::SignExtend { value, .. } => field_loads(value, out),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            field_loads(lhs, out);
            field_loads(rhs, out);
            field_loads(then, out);
            field_loads(els, out);
        }
        Expr::Reg { .. } | Expr::Const(_) => {}
    }
}

fn struct_fields(
    ir: &FunctionIr,
) -> (
    std::collections::HashSet<u16>,
    HashMap<(u16, i64), (u8, bool)>,
) {
    let pointer_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| param.ty.trim_end().ends_with('*'))
        .map(|param| param.index)
        .collect();
    let mut fields: HashMap<(u16, i64), (u8, bool)> = HashMap::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            let (addr, width, signed) = match stmt {
                Stmt::Store {
                    addr, width, value, ..
                } => {
                    let signed = matches!(value, Expr::Const(_));
                    (addr, *width, signed)
                }
                Stmt::Assign { value, .. } => match value {
                    Expr::Load {
                        addr, width, signed, ..
                    } => (addr.as_ref(), *width, *signed),
                    // An inlined load keeps its field visible wherever the
                    // finished statement puts it.
                    other => {
                        let mut loads = Vec::new();
                        field_loads(other, &mut loads);
                        for (base, offset) in loads {
                            if pointer_params.contains(&base) {
                                fields.entry((base, offset)).or_insert((4, false));
                            }
                        }
                        continue;
                    }
                },
                Stmt::Ret { value } => {
                    let mut loads = Vec::new();
                    field_loads(value, &mut loads);
                    for (base, offset) in loads {
                        if pointer_params.contains(&base) {
                            fields.entry((base, offset)).or_insert((4, false));
                        }
                    }
                    continue;
                }
                _ => continue,
            };
            let Some((base, offset)) = member_address(addr) else {
                continue;
            };
            if !pointer_params.contains(&base) {
                continue;
            }
            fields.entry((base, offset)).or_insert((width, signed));
        }
    }
    (pointer_params, fields)
}

/// `p` or `p + k` as a parameter index and byte offset.
fn member_address(addr: &Expr) -> Option<(u16, i64)> {
    match addr {
        Expr::Reg { index, .. } => Some((*index, 0)),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) => Some((*index, *delta as i64)),
            (Expr::Const(delta), Expr::Reg { index, .. }) => Some((*index, *delta as i64)),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) => Some((*index, -(*delta as i64))),
            _ => None,
        },
        _ => None,
    }
}

/// Renders a member access when the pointer's field table has it at the
/// access's own width.
fn member_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let (base, offset) = member_address(addr)?;
    if !ctx.pointer_params.contains(&base) {
        return None;
    }
    let (field_width, _) = *ctx.fields.get(&(base, offset))?;
    if field_width != width {
        return None;
    }
    // The debug info names the field when the pointer's pointee is known.
    if let Some(pointee) = ctx.pointees.get(&base) {
        if let Some(name) = ctx.members.get(&(pointee.clone(), offset)) {
            return Some(format!("{}->{}", ctx.register(base, 64), name));
        }
    }
    Some(format!(
        "{}->field_0x{:x}",
        ctx.register(base, 64),
        offset
    ))
}

/// The stack pointer's register index for the function's ISA.
fn stack_pointer(isa: Isa) -> u16 {
    match isa {
        Isa::AArch64 => 31,
        _ => 4,
    }
}

/// The canonical frame slot of an address that is exactly `sp + k`, given
/// the frame displacement in effect at that point.
fn frame_slot(expr: &Expr, frame: i64, sp: u16) -> Option<i64> {
    match expr {
        Expr::Reg { index, .. } if *index == sp => Some(frame),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => {
                Some(frame.wrapping_add(*delta as i64))
            }
            (Expr::Const(delta), Expr::Reg { index, .. }) if *index == sp => {
                Some(frame.wrapping_add(*delta as i64))
            }
            _ => None,
        },
        _ => None,
    }
}

/// A named frame slot, with the widest access it receives.
struct Local {
    name: String,
    slot: i64,
    width: u8,
    signed: bool,
}

/// The function's frame-relative locals: the rendered address that names
/// each slot, and the declarations to print for them.
struct Locals {
    slots: HashMap<String, String>,
    widths: HashMap<String, u8>,
    decls: Vec<Local>,
}

/// Names the function's frame-relative locals in order of first use, so a
/// stack slot reads as `local_0` instead of `*(uint64_t *)(sp - 0x18)`.
/// Both accesses of a slot share the name even though the frame moved
/// between them; a rendered address that names two different slots stays
/// unnamed rather than guessing.
fn stack_locals(ir: &FunctionIr, frames: &[Option<i64>]) -> Locals {
    let sp = stack_pointer(ir.isa);
    let base = Ctx {
        isa: ir.isa,
        names: HashMap::new(),
        slots: HashMap::new(),
        local_widths: HashMap::new(),
        wide_params: std::collections::HashSet::new(),
        pointer_params: std::collections::HashSet::new(),
        fields: HashMap::new(),
        callees: &HashMap::new(),
        data_ranges: Vec::new(),
        members: HashMap::new(),
        pointees: HashMap::new(),
        narrow_regs: std::collections::HashSet::new(),
        narrow_return: false,
    };
    let accesses = frame_accesses(ir, sp, frames);
    let mut slot_names: HashMap<i64, Local> = HashMap::new();
    let mut rendered: HashMap<String, Option<i64>> = HashMap::new();
    for (slot, address, width, signed) in &accesses {
        let Some(slot) = slot else {
            continue;
        };
        if !slot_names.contains_key(slot) {
            let name = format!("local_{}", slot_names.len());
            slot_names.insert(
                *slot,
                Local {
                    name,
                    slot: *slot,
                    width: 0,
                    signed: true,
                },
            );
        }
        if let Some(local) = slot_names.get_mut(slot) {
            local.width = local.width.max(*width);
            if !*signed {
                local.signed = false;
            }
        }
        let key = render_expr(address, &base);
        match rendered.get(&key) {
            Some(Some(existing)) if existing != slot => {
                // The same text names a different slot elsewhere: leave it
                // spelled out rather than mislabel it.
                rendered.insert(key, None);
            }
            Some(_) => {}
            None => {
                rendered.insert(key, Some(*slot));
            }
        }
    }
    let slots = rendered
        .into_iter()
        .filter_map(|(key, slot)| {
            let slot = slot?;
            slot_names
                .get(&slot)
                .map(|local| (key, local.name.clone()))
        })
        .collect();
    let widths = slot_names
        .values()
        .map(|local| (local.name.clone(), local.width))
        .collect();
    Locals {
        slots,
        widths,
        decls: slot_names.into_values().collect(),
    }
}

/// The frame displacement on entry to each block, solved over the control
/// flow so a slot keeps one name even when reachable along several paths.
fn block_frames(ir: &FunctionIr, sp: u16) -> Vec<Option<i64>> {
    let index: HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut frames: Vec<Option<i64>> = vec![None; ir.blocks.len()];
    if frames.is_empty() {
        return frames;
    }
    frames[0] = Some(0);
    for _ in 0..ir.blocks.len().max(1) * 4 {
        let mut changed = false;
        for position in 0..ir.blocks.len() {
            let Some(entry) = frames[position] else {
                continue;
            };
            let block = &ir.blocks[position];
            // Apply the block's own stack adjustments.
            let mut exit = entry;
            for stmt in &block.stmts {
                if let Stmt::Assign { dest, value } = stmt {
                    if dest.index == sp {
                        if let Expr::Bin { op, rhs, .. } = value {
                            if let Expr::Const(delta) = rhs.as_ref() {
                                exit = match op {
                                    BinOp::Add => exit.wrapping_add(*delta as i64),
                                    BinOp::Sub => exit.wrapping_sub(*delta as i64),
                                    _ => exit,
                                };
                            }
                        }
                    }
                }
            }
            let mut successors: Vec<usize> = Vec::new();
            match block.stmts.last() {
                Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
                    if let Some(target) = index.get(target) {
                        successors.push(*target);
                    }
                    if position + 1 < ir.blocks.len() {
                        successors.push(position + 1);
                    }
                }
                Some(Stmt::Switch { cases, default, .. }) => {
                    for (_, target) in cases {
                        if let Some(target) = index.get(target) {
                            successors.push(*target);
                        }
                    }
                    if let Some(target) = default {
                        if let Some(target) = index.get(target) {
                            successors.push(*target);
                        }
                    }
                }
                Some(Stmt::Br {
                    target: Some(target),
                }) => {
                    if let Some(target) = index.get(target) {
                        successors.push(*target);
                    }
                }
                Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) => {}
                _ => {
                    if position + 1 < ir.blocks.len() {
                        successors.push(position + 1);
                    }
                }
            }
            for successor in successors {
                match frames[successor] {
                    None => {
                        frames[successor] = Some(exit);
                        changed = true;
                    }
                    Some(existing) if existing != exit => {
                        // Two paths disagree: the slot numbers from here on
                        // cannot be trusted, so leave them unnamed.
                        frames[successor] = Some(i64::MIN);
                    }
                    Some(_) => {}
                }
            }
        }
        if !changed {
            break;
        }
    }
    frames.into_iter().map(|frame| (frame != Some(i64::MIN)).then_some(frame).flatten()).collect()
}

/// Every frame-relative memory access, with its canonical slot and the
/// address expression as written.
/// Every local slot a value reads, in the order the value names them.
/// Only the slots below the entry frame are locals; a positive one is an
/// argument the caller passed on the stack and keeps its address.
fn frame_loads(expr: &Expr, frame: i64, sp: u16, out: &mut Vec<(Expr, i64, u8, bool)>) {
    match expr {
        Expr::Load { addr, width, signed } => match frame_slot(addr, frame, sp) {
            Some(slot) if slot < 0 => out.push((addr.as_ref().clone(), slot, *width, *signed)),
            Some(_) => {}
            None => frame_loads(addr, frame, sp, out),
        },
        Expr::Bin { lhs, rhs, .. } => {
            frame_loads(lhs, frame, sp, out);
            frame_loads(rhs, frame, sp, out);
        }
        Expr::SignExtend { value, .. } => frame_loads(value, frame, sp, out),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            frame_loads(lhs, frame, sp, out);
            frame_loads(rhs, frame, sp, out);
            frame_loads(then, frame, sp, out);
            frame_loads(els, frame, sp, out);
        }
        _ => {}
    }
}

fn frame_accesses(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
) -> Vec<(Option<i64>, Expr, u8, bool)> {
    let mut accesses = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            continue;
        };
        let mut frame = frame;
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store {
                    addr, value, width, ..
                } => {
                    let written = match value {
                        Expr::Const(_) => *width,
                        _ => *width,
                    };
                    accesses.push((frame_slot(addr, frame, sp), addr.clone(), written, false));
                }
                Stmt::Assign { dest, value } => {
                    if let Expr::Load { addr, width, signed } = value {
                        accesses.push((
                            frame_slot(addr, frame, sp),
                            addr.as_ref().clone(),
                            *width,
                            *signed,
                        ));
                    }
                    if dest.index == sp {
                        if let Expr::Bin { op, rhs, .. } = value {
                            if let Expr::Const(delta) = rhs.as_ref() {
                                frame = match op {
                                    BinOp::Add => frame.wrapping_add(*delta as i64),
                                    BinOp::Sub => frame.wrapping_sub(*delta as i64),
                                    _ => frame,
                                };
                            }
                        }
                    }
                }
                // A return value may read a slot: `return local_0;`.
                Stmt::Ret { value } => {
                    let mut found = Vec::new();
                    frame_loads(value, frame, sp, &mut found);
                    for (addr, slot, width, signed) in found {
                        accesses.push((Some(slot), addr, width, signed));
                    }
                }
                _ => {}
            }
        }
    }
    accesses
}

fn ret_type(ir: &FunctionIr) -> String {
    ir.ret_type.clone()
}

fn signature(ir: &FunctionIr) -> String {
    if ir.params.is_empty() {
        return "void".to_owned();
    }
    ir.params
        .iter()
        .map(|param| {
            if param.ty.ends_with('*') {
                format!("{}{}", param.ty, param.name)
            } else {
                format!("{} {}", param.ty, param.name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

fn render_nodes(nodes: &[Out], depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    let mut index = 0;
    while index < nodes.len() {
        // Consecutive instructions the lifter could not model read as one
        // note instead of one comment per instruction.
        if let Out::Stmt(Stmt::Unsupported { text }) = &nodes[index] {
            let mut merged = text.clone();
            let mut count = 1;
            while let Some(Out::Stmt(Stmt::Unsupported { text })) = nodes.get(index + count) {
                merged.push_str(", ");
                merged.push_str(text);
                count += 1;
            }
            indent(depth, out);
            if count > 1 {
                out.push_str(&format!("/* unsupported ({} steps): {} */\n", count, merged));
            } else {
                out.push_str(&format!("/* unsupported: {} */\n", merged));
            }
            index += count;
            continue;
        }
        render_node(&nodes[index], depth, out, ctx);
        index += 1;
    }
}

fn render_node(node: &Out, depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    match node {
        Out::Stmt(stmt) => {
                let text = render_stmt(stmt, ctx);
                if !text.is_empty() {
                    for line in text.lines() {
                        indent(depth, out);
                        out.push_str(line);
                        out.push('\n');
                    }
                }
            }
            Out::Label(address) => {
                indent(depth.saturating_sub(1), out);
                out.push_str(&format!("L_{address:x}:\n"));
            }
            Out::If {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => {
                indent(depth, out);
                out.push_str(&format!(
                    "if ({}) {{\n",
                    condition(*cond, lhs, rhs, ctx)
                ));
                render_nodes(then, depth + 1, out, ctx);
                if els.is_empty() {
                    indent(depth, out);
                    out.push_str("}\n");
                } else {
                    indent(depth, out);
                    out.push_str("} else {\n");
                    render_nodes(els, depth + 1, out, ctx);
                    indent(depth, out);
                    out.push_str("}\n");
                }
            }
            Out::Switch {
                index,
                arms,
                default,
            } => {
                indent(depth, out);
                out.push_str(&format!("switch ({}) {{\n", render_expr(index, ctx)));
                for (values, body) in arms {
                    for value in values {
                        indent(depth, out);
                        out.push_str(&format!("case {value}:\n"));
                    }
                    render_nodes(body, depth + 1, out, ctx);
                }
                if let Some(body) = default {
                    indent(depth, out);
                    out.push_str("default:\n");
                    render_nodes(body, depth + 1, out, ctx);
                }
                indent(depth, out);
                out.push_str("}\n");
            }
            Out::Break => {
                indent(depth, out);
                out.push_str("break;\n");
            }
            Out::Continue => {
                indent(depth, out);
                out.push_str("continue;\n");
            }
            Out::Forever { body } => {
                indent(depth, out);
                out.push_str("for (;;) {\n");
                render_nodes(body, depth + 1, out, ctx);
                indent(depth, out);
                out.push_str("}\n");
            }
            Out::While {
                prefix,
                cond,
                lhs,
                rhs,
                body,
            } => {
                indent(depth, out);
                if prefix.is_empty() {
                    out.push_str(&format!(
                        "while ({}) {{\n",
                        condition(*cond, lhs, rhs, ctx)
                    ));
                    render_nodes(body, depth + 1, out, ctx);
                } else {
                    out.push_str("while (true) {\n");
                    render_nodes(prefix, depth + 1, out, ctx);
                    indent(depth + 1, out);
                    out.push_str(&format!(
                        "if ({}) break;\n",
                        condition(cond.invert(), lhs, rhs, ctx)
                    ));
                    render_nodes(body, depth + 1, out, ctx);
                }
                indent(depth, out);
                out.push_str("}\n");
            }
            Out::DoWhile {
                cond,
                lhs,
                rhs,
                body,
            } => {
                indent(depth, out);
                out.push_str("do {\n");
                render_nodes(body, depth + 1, out, ctx);
                indent(depth, out);
                out.push_str(&format!(
                    "}} while ({});\n",
                    condition(*cond, lhs, rhs, ctx)
                ));
            }
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

fn render_stmt(stmt: &Stmt, ctx: &Ctx<'_>) -> String {
    match stmt {
        Stmt::Assign { dest, value } => {
            // A destination whose readers only use the low 32 bits reads
            // under its 32-bit register name, the way the loads do.
            let target = if ctx.narrow_regs.contains(&dest.index)
                && dest.index != 0
                && !ctx.wide_params.contains(&dest.index)
            {
                ctx.register(dest.index, 32)
            } else {
                ctx.register(dest.index, dest.width)
            };
            // A register whose readers only use the low 32 bits never needs
            // the zero extension, and the return register is already typed.
            if let Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } = value
            {
                let truncates_param = match lhs.as_ref() {
                    Expr::Reg { index, .. } => ctx.wide_params.contains(index),
                    _ => false,
                };
                if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                    && !truncates_param
                    && (ctx.narrow_regs.contains(&dest.index)
                        || (ctx.narrow_return && dest.index == 0))
                {
                    // The mask fixed the value at 32 bits, so a register
                    // reads under its 32-bit name.
                    let value = match lhs.as_ref() {
                        Expr::Reg { index, .. } => ctx.register(*index, 32),
                        other => render_expr(other, ctx),
                    };
                    return format!("{target} = {value};");
                }
            }
            format!("{target} = {};", render_expr(value, ctx))
        }
        Stmt::Store { addr, value, width } => {
            if let Some(member) = member_access(addr, *width, ctx) {
                return match update_of_same_location(addr, value) {
                    Some((op, rhs)) => format!("{} {}= {};", member, op, render_expr(rhs, ctx)),
                    None => format!("{} = {};", member, render_expr(value, ctx)),
                };
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => match update_of_same_location(addr, value) {
                    Some((op, rhs)) => {
                        format!("{} {}= {};", name, op, render_expr(rhs, ctx))
                    }
                    None => format!("{} = {};", name, render_expr(value, ctx)),
                },
                None => match global_name(addr, *width, ctx) {
                    Some(name) => match update_of_same_location(addr, value) {
                    Some((op, rhs)) => {
                        format!("{} {}= {};", name, op, render_expr(rhs, ctx))
                    }
                    None => format!("{} = {};", name, render_expr(value, ctx)),
                },
                    None => format!(
                        "*({} *)({}) = {};",
                        type_of(*width, false),
                        address,
                        render_expr(value, ctx)
                    ),
                },
            }
        }
        Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        } => format!(
            "if ({}) {{ goto L_{:x}; }}",
            condition(*cond, lhs, rhs, ctx),
            target
        ),
        Stmt::BrifFlags { cond, target } => format!(
            "if (/* {} */ true) {{ goto L_{:x}; }}",
            cond.text(),
            target
        ),
        Stmt::Br { target } => match target {
            Some(target) => format!("goto L_{target:x};"),
            None => "goto <dynamic>;".to_owned(),
        },
        Stmt::BrIndirect { target } => {
            format!("goto *({});", render_expr(target, ctx))
        }
        Stmt::Switch {
            index,
            cases,
            default,
        } => {
            let mut text = format!("switch ({}) {{\n", render_expr(index, ctx));
            for (value, target) in cases {
                text.push_str(&format!("    case {value}: goto L_{target:x};\n"));
            }
            if let Some(target) = default {
                text.push_str(&format!("    default: goto L_{target:x};\n"));
            }
            text.push('}');
            text
        }
        Stmt::Call { target } => match target {
            Some(target) => match ctx.callees.get(target) {
                Some(name) => format!("{}();", sanitize(name)),
                None => format!("sub_{target:x}();"),
            },
            None => "sub_<dynamic>();".to_owned(),
        },
        Stmt::Ret { value } => format!("return {};", render_expr(value, ctx)),
        Stmt::Unsupported { text } => format!("/* unsupported: {text} */"),
        Stmt::Trap => "__builtin_trap();".to_owned(),
    }
}
