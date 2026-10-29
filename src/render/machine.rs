use super::expr::{Ctx, render_expr};
use crate::ir::{Expr, MachineInstruction, RegRef};

fn expected_in_output(inputs: &[Expr], outputs: &[RegRef], width: u8, ctx: &Ctx<'_>) -> bool {
    let [result] = outputs else {
        return false;
    };
    let Some(declared) = ctx.declared.get(&result.index) else {
        return false;
    };
    if !crate::ir::is_temp(result.index)
        || result.width != width.saturating_mul(8)
        || !declared.integer
        || declared.signed
        || declared.bits != u32::from(width) * 8
    {
        return false;
    }
    let mut reads = std::collections::HashSet::new();
    for input in inputs {
        crate::ir::visit::collect_reads(input, &mut reads);
    }
    !reads.contains(&result.index)
}

pub(super) fn render(
    instruction: MachineInstruction,
    inputs: &[Expr],
    outputs: &[RegRef],
    ctx: &Ctx<'_>,
) -> String {
    render_inner(instruction, inputs, outputs, ctx, false)
}

fn render_inner(
    instruction: MachineInstruction,
    inputs: &[Expr],
    outputs: &[RegRef],
    ctx: &Ctx<'_>,
    tested: bool,
) -> String {
    let input = |index| render_expr(&inputs[index], ctx);
    let address = || match &inputs[0] {
        // Keep fixed memory addresses even when they name strings or functions.
        Expr::Const(_) | Expr::Select { .. } => input(0),
        _ => super::expr::render_value_at(&inputs[0], ctx, 64, false),
    };
    let output = |index: usize| ctx.register(outputs[index].index, outputs[index].width);
    let mut reserved = std::collections::HashSet::new();
    for text in (0..inputs.len())
        .map(input)
        .chain((0..outputs.len()).map(output))
    {
        reserved.extend(
            text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .map(str::to_owned),
        );
    }
    match instruction {
        MachineInstruction::ArmExclusive {
            load,
            width,
            pair,
            ordered,
        } => {
            let suffix = if pair {
                "p"
            } else {
                match width {
                    1 => "rb",
                    2 => "rh",
                    _ => "r",
                }
            };
            let mnemonic = format!(
                "{}{}x{suffix}",
                if load { "ld" } else { "st" },
                if ordered {
                    if load { "a" } else { "l" }
                } else {
                    ""
                }
            );
            let reg = if width == 8 { "%x" } else { "%w" };
            if load && pair {
                format!(
                    "__asm__ volatile (\"{mnemonic} {reg}0, {reg}1, [%2]\" : \"=&r\"({}), \"=&r\"({}) : \"r\"((uint64_t)({})) : \"memory\");",
                    output(0),
                    output(1),
                    address()
                )
            } else if load {
                format!(
                    "__asm__ volatile (\"{mnemonic} {reg}0, [%1]\" : \"=&r\"({}) : \"r\"((uint64_t)({})) : \"memory\");",
                    output(0),
                    address()
                )
            } else if pair {
                format!(
                    "__asm__ volatile (\"{mnemonic} %w0, {reg}2, {reg}3, [%1]\" : \"=&r\"({}) : \"r\"((uint64_t)({})), \"r\"((uint64_t)({})), \"r\"((uint64_t)({})) : \"memory\");",
                    output(0),
                    address(),
                    input(1),
                    input(2)
                )
            } else {
                format!(
                    "__asm__ volatile (\"{mnemonic} %w0, {reg}2, [%1]\" : \"=&r\"({}) : \"r\"((uint64_t)({})), \"r\"((uint64_t)({})) : \"memory\");",
                    output(0),
                    address(),
                    input(1)
                )
            }
        }
        MachineInstruction::ArmSystem { register, write } => {
            let name = format!(
                "s{}_{}_c{}_c{}_{}",
                2 + ((register >> 14) & 1),
                (register >> 11) & 7,
                (register >> 7) & 15,
                (register >> 3) & 15,
                register & 7
            );
            if write {
                format!(
                    "__asm__ volatile (\"msr {name}, %0\" : : \"r\"((uint64_t)({})) : \"memory\");",
                    input(0)
                )
            } else {
                format!(
                    "__asm__ volatile (\"mrs %x0, {name}\" : \"=r\"({}) : : \"memory\");",
                    output(0)
                )
            }
        }
        MachineInstruction::ArmBarrier { kind, option } => {
            let name = match kind {
                0 => "dmb",
                1 => "dsb",
                _ => "isb",
            };
            format!("__asm__ volatile (\"{name} #{option}\" : : : \"memory\");")
        }
        MachineInstruction::ArmCacheZero => format!(
            "__asm__ volatile (\"dc zva, %0\" : : \"r\"((uint64_t)({})) : \"memory\");",
            address()
        ),
        MachineInstruction::ArmLoadAcquire { width } => {
            let suffix = match width {
                1 => "b",
                2 => "h",
                _ => "",
            };
            let register = if width == 8 { "%x0" } else { "%w0" };
            format!(
                "__asm__ volatile (\"ldapr{suffix} {register}, [%1]\" : \"=r\"({}) : \"r\"((uint64_t)({})) : \"memory\");",
                output(0),
                address()
            )
        }
        MachineInstruction::Atomic { .. } => {
            render_atomic(instruction, inputs, outputs, ctx, tested, &mut reserved)
        }
        MachineInstruction::Cpuid => {
            let a = super::vacant_name("a", &mut reserved);
            let b = super::vacant_name("b", &mut reserved);
            let c = super::vacant_name("c", &mut reserved);
            let d = super::vacant_name("d", &mut reserved);
            format!(
                "{{ unsigned int {a}, {b}, {c}, {d}; __cpuid_count({}, {}, {a}, {b}, {c}, {d}); {} = {a}; {} = {b}; {} = {c}; {} = {d}; }}",
                input(0),
                input(1),
                output(0),
                output(1),
                output(2),
                output(3)
            )
        }
        MachineInstruction::Xgetbv => format!("{} = _xgetbv({});", output(0), input(0)),
        MachineInstruction::Rdtsc => format!("{} = __rdtsc();", output(0)),
        MachineInstruction::Rdtscp => {
            let aux = super::vacant_name("aux", &mut reserved);
            format!(
                "{{ unsigned int {aux}; {} = __rdtscp(&{aux}); {} = {aux}; }}",
                output(0),
                output(1)
            )
        }
        MachineInstruction::ReadFlags => format!(
            "{} = (__builtin_ia32_readeflags_u64() & ~((uint64_t)({}) | 0x30000ULL)) | ({});",
            output(0),
            input(0),
            input(1)
        ),
        MachineInstruction::WriteFlags => format!(
            "__builtin_ia32_writeeflags_u64({}); {} = __builtin_ia32_readeflags_u64();",
            input(0),
            output(0)
        ),
    }
}

pub(super) fn in_condition(
    stmt: &crate::ir::Stmt,
    next: &super::Node,
    depth: usize,
    ctx: &Ctx<'_>,
) -> Option<String> {
    use crate::ir::{AtomicOp, Cond, MachineInstruction, Stmt};
    let Stmt::Machine {
        instruction: instruction @ MachineInstruction::Atomic { op, width, .. },
        inputs,
        outputs,
        ..
    } = stmt
    else {
        return None;
    };
    let [result] = outputs.as_slice() else {
        return None;
    };
    if !crate::ir::is_temp(result.index) {
        return None;
    }
    let super::Node::If {
        cond: cond @ (Cond::Eq | Cond::Ne),
        lhs,
        rhs,
        ..
    } = next
    else {
        return None;
    };
    let whole = |value: &Expr| matches!(value, Expr::Reg { index, width } if *index == result.index && *width >= result.width);
    let other = if whole(lhs) {
        rhs
    } else if whole(rhs) {
        lhs
    } else {
        return None;
    };
    // Moving the operation into the test must not reorder another load.
    if !matches!(other, Expr::Const(_) | Expr::Reg { .. }) {
        return None;
    }
    let Some(declared) = ctx.declared.get(&result.index) else {
        return None;
    };
    if !declared.integer || declared.signed || declared.bits < u32::from(*width) * 8 {
        return None;
    }
    if *op == AtomicOp::CompareExchange {
        // Success compares the width-truncated expected value. Only a
        // fitting constant makes that identical to the original test.
        let Some(Expr::Const(expected)) = inputs.get(2) else {
            return None;
        };
        if other != &Expr::Const(*expected)
            || (*width < 8 && *expected >> (u32::from(*width) * 8) != 0)
            || (!expected_in_output(inputs, outputs, *width, ctx)
                && !ctx.read_once.contains(&result.index))
            || result.width != width.saturating_mul(8)
        {
            return None;
        }
        let expression = render_inner(*instruction, inputs, outputs, ctx, true);
        let negate = if *cond == Cond::Ne { "!" } else { "" };
        let mut rendered = String::new();
        super::render_node(next, depth, &mut rendered, ctx);
        let Some((_, rest)) = rendered.split_once('\n') else {
            return None;
        };
        let mut output = format!("{}if ({negate}{expression}) {{\n", "    ".repeat(depth));
        super::addresses::append(&mut output, next.origin(), ctx.symbols.addresses);
        output.push_str(rest);
        return Some(output);
    }
    if *op == AtomicOp::Store || result.width != width.saturating_mul(8) {
        return None;
    }
    let statement = render(*instruction, inputs, outputs, ctx);
    let name = ctx.register(result.index, result.width);
    let prefix = format!("{name} = ");
    let Some(expression) = statement
        .strip_prefix(&prefix)
        .and_then(|text| text.strip_suffix(';'))
    else {
        return None;
    };
    let first = format!(
        "{}if ({}) {{",
        "    ".repeat(depth),
        super::condition(*cond, lhs, rhs, ctx)
    );
    let Some(at) = super::calls::only_word(&first, &name) else {
        return None;
    };
    let expression = if ctx.read_once.contains(&result.index) {
        expression.to_owned()
    } else {
        format!("({name} = {expression})")
    };
    let mut rendered = String::new();
    super::render_node(next, depth, &mut rendered, ctx);
    let Some((_, rest)) = rendered.split_once('\n') else {
        return None;
    };
    let mut output = format!(
        "{}{expression}{}\n",
        &first[..at],
        &first[at + name.len()..]
    );
    super::addresses::append(&mut output, next.origin(), ctx.symbols.addresses);
    output.push_str(rest);
    Some(output)
}

fn render_atomic(
    instruction: MachineInstruction,
    inputs: &[Expr],
    outputs: &[RegRef],
    ctx: &Ctx<'_>,
    tested: bool,
    reserved: &mut std::collections::HashSet<String>,
) -> String {
    let MachineInstruction::Atomic {
        op,
        width,
        ordering,
    } = instruction
    else {
        unreachable!("atomic rendering requires an atomic instruction");
    };
    let input = |index| render_expr(&inputs[index], ctx);
    let output = |index: usize| ctx.register(outputs[index].index, outputs[index].width);
    use crate::ir::{AtomicOp, Ordering};
    let ty = match width {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "unsigned __int128",
    };
    let ptr = if super::expr::print(&inputs[0], ctx, 64).is_pointer()
        && crate::render::naming::pointer_target(&inputs[0], ctx)
            == Some(crate::ir::CType::int(width, false))
    {
        input(0)
    } else if let Some(member) = crate::render::naming::member_access(&inputs[0], width, ctx)
        && member
            .ty
            .integer()
            .is_some_and(|(bits, _)| bits == u32::from(width) * 8)
    {
        if member.ty == crate::ir::CType::int(width, false) {
            format!("&{}", member.text)
        } else {
            format!("({ty} *)&{}", member.text)
        }
    } else {
        format!("({ty} *)({})", input(0))
    };
    let operand = |index| {
        let value = super::expr::print(&inputs[index], ctx, 64);
        if value.is_pointer() {
            value.address_integer().text
        } else {
            input(index)
        }
    };
    let order = ordering.builtin();
    if op == AtomicOp::CompareExchange && outputs.len() == 2 {
        let expected = super::vacant_name("expected", reserved);
        let half = u32::from(width) * 4;
        let lo_ty = if width == 16 { "uint64_t" } else { "uint32_t" };
        return format!(
            "{{ {ty} {expected} = ({ty})({lo_ty})({}) | (({ty})({lo_ty})({}) << {half}); __atomic_compare_exchange_n({ptr}, &{expected}, ({ty})({lo_ty})({}) | (({ty})({lo_ty})({}) << {half}), 0, {order}, {order}); {} = ({lo_ty}){expected}; {} = ({lo_ty})({expected} >> {half}); }}",
            input(2),
            input(4),
            input(1),
            input(3),
            output(0),
            output(1)
        );
    }
    match op {
        AtomicOp::Load => format!("{} = __atomic_load_n({ptr}, {order});", output(0)),
        AtomicOp::Store => {
            format!("__atomic_store_n({ptr}, {}, {order});", operand(1))
        }
        AtomicOp::CompareExchange => {
            let expected = super::vacant_name("expected", reserved);
            let failure = match ordering {
                Ordering::Release => Ordering::Relaxed,
                Ordering::AcqRel => Ordering::Acquire,
                other => other,
            }
            .builtin();
            if tested {
                if ctx.read_once.contains(&outputs[0].index) {
                    return format!(
                        "__atomic_compare_exchange_n({ptr}, ({ty}[1]){{{}}}, {}, 0, {order}, {failure})",
                        operand(2),
                        operand(1)
                    );
                }
                return format!(
                    "({} = {}, __atomic_compare_exchange_n({ptr}, &{}, {}, 0, {order}, {failure}))",
                    output(0),
                    operand(2),
                    output(0),
                    operand(1)
                );
            }
            if expected_in_output(inputs, outputs, width, ctx) {
                return format!(
                    "{{ {} = {}; __atomic_compare_exchange_n({ptr}, &{}, {}, 0, {order}, {failure}); }}",
                    output(0),
                    operand(2),
                    output(0),
                    operand(1)
                );
            }
            format!(
                "{{ {ty} {expected} = {}; __atomic_compare_exchange_n({ptr}, &{expected}, {}, 0, {order}, {failure}); {} = {expected}; }}",
                operand(2),
                operand(1),
                output(0)
            )
        }
        _ => {
            let name = match op {
                AtomicOp::Add => "fetch_add",
                AtomicOp::Sub => "fetch_sub",
                AtomicOp::And => "fetch_and",
                AtomicOp::Or => "fetch_or",
                AtomicOp::Xor => "fetch_xor",
                _ => "exchange_n",
            };
            format!(
                "{} = __atomic_{name}({ptr}, {}, {order});",
                output(0),
                operand(1)
            )
        }
    }
}
