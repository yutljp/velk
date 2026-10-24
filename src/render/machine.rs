use super::expr::{Ctx, render_expr};
use crate::ir::{Expr, MachineInstruction, RegRef};

pub(super) fn render(
    instruction: MachineInstruction,
    inputs: &[Expr],
    outputs: &[RegRef],
    ctx: &Ctx<'_>,
) -> String {
    let input = |index| render_expr(&inputs[index], ctx);
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
        MachineInstruction::Atomic {
            op,
            width,
            ordering,
        } => {
            use crate::ir::{AtomicOp, Ordering};
            let ty = match width {
                1 => "uint8_t",
                2 => "uint16_t",
                4 => "uint32_t",
                8 => "uint64_t",
                _ => "unsigned __int128",
            };
            let ptr = if crate::render::naming::pointer_target(&inputs[0], ctx)
                == Some(crate::ir::CType::int(width, false))
            {
                input(0)
            } else {
                format!("({ty} *)({})", input(0))
            };
            let operand = || {
                let value = super::expr::print(&inputs[1], ctx, 64);
                if value.is_pointer() {
                    value.address_integer().text
                } else {
                    input(1)
                }
            };
            let order = ordering.builtin();
            if op == AtomicOp::CompareExchange && outputs.len() == 2 {
                let expected = super::vacant_name("expected", &mut reserved);
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
                    format!("__atomic_store_n({ptr}, {}, {order});", operand())
                }
                AtomicOp::CompareExchange => {
                    let expected = super::vacant_name("expected", &mut reserved);
                    let failure = match ordering {
                        Ordering::Release => Ordering::Relaxed,
                        Ordering::AcqRel => Ordering::Acquire,
                        other => other,
                    }
                    .builtin();
                    format!(
                        "{{ {ty} {expected} = ({ty})({}); __atomic_compare_exchange_n({ptr}, &{expected}, ({ty})({}), 0, {order}, {failure}); {} = {expected}; }}",
                        input(2),
                        input(1),
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
                        operand()
                    )
                }
            }
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
