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
