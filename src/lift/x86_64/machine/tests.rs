use std::collections::HashSet;
use std::process::Command;

use crate::ir::eval::{self, Outcome};
use crate::ir::{BinOp, CType, Expr, FunctionIr, MachineInstruction, Param, Stmt};
use crate::loader::{Image, Isa};

fn lift(code: &[u8], result: Expr) -> FunctionIr {
    let image = Image::from_code(Isa::X86_64, 0, code.to_vec());
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
    ir.blocks = crate::lift::lift(&image, 0, code.len() as u64, &HashSet::new()).unwrap();
    for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        assert!(!matches!(stmt, Stmt::Unsupported { .. }), "{stmt:?}");
        if let Stmt::Ret { value } = stmt {
            *value = result.clone();
        }
    }
    ir
}

fn setup(registers: &[(u16, u64)]) -> eval::Setup<'_> {
    eval::Setup {
        seed: 1,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers,
        memory: &[],
        step_limit: 1000,
    }
}

#[test]
fn direction_is_clear_at_entry_and_after_a_returning_call() {
    for code in [
        vec![0x48, 0xa5, 0xc3],
        vec![0xfd, 0xe8, 0, 0, 0, 0, 0x48, 0xa5, 0xc3],
    ] {
        let mut ir = lift(&code, Expr::reg(7, 64));
        crate::passes::optimize(&mut ir, false);
        let code = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains(" ? "), "{code}");
        assert!(!code.contains("-0x8"), "{code}");
        assert!(code.contains("+ 8") || code.contains("+ 0x8"), "{code}");
    }
}

fn source(instruction: MachineInstruction, inputs: &[u64]) -> Result<Vec<u64>, &'static str> {
    Ok(match instruction {
        MachineInstruction::Cpuid => {
            assert_eq!(inputs, [7, 3]);
            vec![
                0xffff_ffff_8123_4567,
                0xabcd_1234_9876_5432,
                0x1234_5678_fedc_ba98,
                0x1111_2222_ffff_0000,
            ]
        }
        MachineInstruction::Xgetbv => {
            assert_eq!(inputs, [3]);
            vec![0x9876_5432_fedc_ba98]
        }
        MachineInstruction::Rdtsc => vec![0x9876_5432_fedc_ba98],
        MachineInstruction::Rdtscp => vec![0x9876_5432_fedc_ba98, 0xffff_ffff_8123_4567],
        MachineInstruction::ReadFlags => vec![0x30002],
        MachineInstruction::WriteFlags => vec![inputs[0] & 0xcd5 | 0x202],
        MachineInstruction::Atomic { .. } => panic!("atomic access does not use external state"),
    })
}

fn returned(ir: &FunctionIr, registers: &[(u16, u64)]) -> u64 {
    match eval::run_with_machine(ir, &setup(registers), &source) {
        Outcome::Return { value, .. } => value,
        other => panic!("{other:?}\n{}", ir.render()),
    }
}

#[test]
fn outputs_zero_extend_and_preserve_other_registers_through_optimization() {
    let inputs = [
        (0, 0xffff_ffff_0000_0007),
        (1, 0xffff_ffff_0000_0003),
        (2, u64::MAX),
        (3, u64::MAX),
        (6, 0x1122_3344_5566_7788),
    ];
    for (code, expected) in [
        (
            vec![0x0f, 0xa2, 0xc3],
            vec![
                (0, 0x8123_4567),
                (3, 0x9876_5432),
                (1, 0xfedc_ba98),
                (2, 0xffff_0000),
            ],
        ),
        (
            vec![0x0f, 0x01, 0xd0, 0xc3],
            vec![(0, 0xfedc_ba98), (2, 0x9876_5432), (1, inputs[1].1)],
        ),
        (
            vec![0x0f, 0x31, 0xc3],
            vec![(0, 0xfedc_ba98), (2, 0x9876_5432), (1, inputs[1].1)],
        ),
        (
            vec![0x0f, 0x01, 0xf9, 0xc3],
            vec![(0, 0xfedc_ba98), (2, 0x9876_5432), (1, 0x8123_4567)],
        ),
    ] {
        for (register, expected) in expected.into_iter().chain([(6, inputs[4].1)]) {
            let mut ir = lift(&code, Expr::reg(register, 64));
            assert_eq!(returned(&ir, &inputs), expected);
            let ssa = crate::ssa::build(&ir).unwrap();
            crate::ssa::verify(&ssa).unwrap();
            crate::passes::optimize(&mut ir, false);
            assert_eq!(returned(&ir, &inputs), expected, "{}", ir.render());
        }
    }
}

#[test]
fn arithmetic_and_direction_flags_are_explicit_values() {
    // cmp rdi, rsi; jmp next; pushfq; pop rax; ret
    let code = [0x48, 0x39, 0xf7, 0xeb, 0, 0x9c, 0x58, 0xc3];
    for (left, right, flags) in [
        (0, 0, 0x44),
        (0, 1, 0x95),
        (0x8000_0000_0000_0000, 1, 0x814),
    ] {
        let result = Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::constant(0x8d5));
        let mut ir = lift(&code, result);
        assert_eq!(returned(&ir, &[(7, left), (6, right)]), flags);
        crate::passes::optimize(&mut ir, false);
        assert_eq!(returned(&ir, &[(7, left), (6, right)]), flags);
    }
    // std; pushfq; pop rax; cld; ret
    let mut ir = lift(&[0xfd, 0x9c, 0x58, 0xfc, 0xc3], Expr::reg(0, 64));
    assert_eq!(returned(&ir, &[]), 0x402);
    crate::passes::optimize(&mut ir, false);
    assert_eq!(returned(&ir, &[]), 0x402);
    // push rdi; popfq; seto al; ret
    let mut ir = lift(
        &[0x57, 0x9d, 0x0f, 0x90, 0xc0, 0xc3],
        Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::constant(0xff)),
    );
    assert_eq!(returned(&ir, &[(7, 0xa02)]), 1);
    crate::passes::optimize(&mut ir, false);
    assert_eq!(returned(&ir, &[(7, 0xa02)]), 1);
}

#[test]
fn reads_are_ordered_and_other_machine_instructions_preserve_flags() {
    let mut ir = lift(
        &[
            0x0f, 0x31, 0x49, 0x89, 0xc0, 0x0f, 0x31, 0x4c, 0x29, 0xc0, 0xc3,
        ],
        Expr::reg(0, 64),
    );
    for optimize in [false, true] {
        if optimize {
            crate::passes::optimize(&mut ir, false);
        }
        let count = std::cell::Cell::new(0);
        let source = |instruction, _: &[u64]| {
            assert_eq!(instruction, MachineInstruction::Rdtsc);
            count.set(count.get() + 1);
            Ok(vec![count.get() * 100])
        };
        assert!(matches!(
            eval::run_with_machine(&ir, &setup(&[]), &source),
            Outcome::Return { value: 100, .. }
        ));
        assert_eq!(count.get(), 2);
    }
    for instruction in [
        vec![0x0f, 0xa2],
        vec![0x0f, 0x01, 0xd0],
        vec![0x0f, 0x31],
        vec![0x0f, 0x01, 0xf9],
    ] {
        // cmp rdi, rsi; machine instruction; setb al; ret
        let code = [
            vec![0x48, 0x39, 0xf7],
            instruction,
            vec![0x0f, 0x92, 0xc0, 0xc3],
        ]
        .concat();
        let mut ir = lift(
            &code,
            Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::constant(0xff)),
        );
        let inputs = [(0, 7), (1, 3), (7, 0), (6, 1)];
        assert_eq!(returned(&ir, &inputs), 1);
        crate::passes::optimize(&mut ir, false);
        assert_eq!(returned(&ir, &inputs), 1);
    }
}

#[test]
fn flag_stack_operations_use_eight_bytes_and_effective_flags() {
    let top = eval::STACK_TOP;
    let ir = lift(&[0x9c, 0xc3], Expr::reg(0, 64));
    let initial = [(4, top)];
    let (registers, memory) =
        eval::state_after_with_machine(&ir, &setup(&initial), &source).unwrap();
    assert_eq!(registers[&4], top - 8);
    let saved = u64::from_le_bytes(std::array::from_fn(|byte| memory[&(top - 8 + byte as u64)]));
    assert_eq!(saved, 2);
    let ir = lift(&[0x9d, 0xc3], Expr::reg(0, 64));
    let mut initial_state = setup(&initial);
    let memory = [(top, 0x400)];
    initial_state.memory = &memory;
    let (registers, _) = eval::state_after_with_machine(&ir, &initial_state, &source).unwrap();
    assert_eq!(registers[&4], top + 8);
    assert_eq!(registers[&super::DIRECTION], 1);
}

#[test]
fn missing_source_and_invalid_outputs_are_refused() {
    let ir = lift(&[0x0f, 0x31, 0xc3], Expr::reg(0, 64));
    assert_eq!(
        eval::run(&ir, &setup(&[])),
        Outcome::Unknown("machine state unavailable")
    );
    assert_eq!(
        eval::run_with_machine(&ir, &setup(&[]), &|_, _| Ok(vec![])),
        Outcome::Unknown("invalid machine-state output count")
    );
}

#[test]
fn printed_intrinsics_compile_and_cpuid_matches_hardware() {
    let mut code = String::from("#include <stdint.h>\n");
    for (name, bytes, result) in [
        ("vendor_b", vec![0x0f, 0xa2, 0xc3], 3),
        ("vendor_c", vec![0x0f, 0xa2, 0xc3], 1),
        ("vendor_d", vec![0x0f, 0xa2, 0xc3], 2),
        ("clock_low", vec![0x0f, 0x31, 0xc3], 0),
        ("clock_whole", vec![0x0f, 0x31, 0xc3], 0),
        ("state_whole", vec![0x0f, 0x01, 0xd0, 0xc3], 0),
        ("clock_aux", vec![0x0f, 0x01, 0xf9, 0xc3], 1),
        ("extended_state", vec![0x0f, 0x01, 0xd0, 0xc3], 0),
        ("saved_flags", vec![0x48, 0x39, 0xf7, 0x9c, 0x58, 0xc3], 0),
        (
            "restored_flags",
            vec![0x57, 0x9d, 0x0f, 0x92, 0xc0, 0xc3],
            0,
        ),
    ] {
        let result = if name.ends_with("_whole") {
            Expr::bin(
                BinOp::Or,
                Expr::reg(0, 64),
                Expr::bin(BinOp::Shl, Expr::reg(2, 64), Expr::constant(32)),
            )
        } else {
            Expr::reg(result, 64)
        };
        let mut ir = lift(&bytes, result);
        ir.name = Some(name.to_owned());
        ir.params = [0, 1, 7, 6]
            .into_iter()
            .map(|index| Param {
                index,
                name: match index {
                    0 => "a",
                    1 => "b",
                    7 => "aux",
                    _ => "d",
                }
                .to_owned(),
                ty: CType::U64,
            })
            .collect();
        crate::passes::optimize(&mut ir, false);
        crate::passes::frame_slots::settle(&mut ir);
        code.push_str(&crate::render::render(&ir, &[], &Default::default(), &[]));
        code.push('\n');
    }
    for intrinsic in [
        "__cpuid_count(",
        "_xgetbv(",
        "__rdtsc()",
        "__rdtscp(&aux)",
        "__builtin_ia32_readeflags_u64()",
        "__builtin_ia32_writeeflags_u64(",
    ] {
        assert!(code.contains(intrinsic), "{intrinsic}\n{code}");
    }
    code.push_str(r#"
int main(void) {
    unsigned int a, b, c, d;
    __cpuid_count(0, 0, a, b, c, d);
    if (vendor_b(0, 0, 0, 0) != b || vendor_c(0, 0, 0, 0) != c || vendor_d(0, 0, 0, 0) != d) return 1;
    __cpuid_count(1, 0, a, b, c, d);
    if (vendor_b(1, 0, 0, 0) != b || vendor_c(1, 0, 0, 0) != c || vendor_d(1, 0, 0, 0) != d) return 4;
#ifdef VELK_MACHINE_TEST_VALUES
    if (clock_whole(0, 0, 0, 0) != 0x98765432fedcba98ULL) return 5;
    if (state_whole(0, 0, 0, 0) != 0x98765432fedcba98ULL) return 6;
    if (clock_aux(0, 0, 0, 0) != 0x81234567ULL) return 7;
#endif
    if ((saved_flags(0, 0, 0, 1) & 0x8d5) != 0x95) return 2;
    if ((restored_flags(0, 0, 0x203, 0) & 0xff) != 1) return 3;
    return 0;
}
"#);
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/machine-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("intrinsics.c");
    std::fs::write(&source, &code).unwrap();
    for mocked in [false, true] {
        let printed = if mocked {
            String::from(
                "#include <stdint.h>\n#define VELK_MACHINE_TEST_VALUES\nstatic uint64_t test_rdtsc(void) { return 0x98765432fedcba98ULL; }\nstatic uint64_t test_xgetbv(unsigned int n) { (void)n; return 0x98765432fedcba98ULL; }\nstatic uint64_t test_rdtscp(unsigned int *aux) { *aux = 0x81234567U; return 0x98765432fedcba98ULL; }\n",
            ) + &code
                .replace("__rdtsc()", "test_rdtsc()")
                .replace("_xgetbv(", "test_xgetbv(")
                .replace("__rdtscp(&aux)", "test_rdtscp(&aux)")
        } else {
            code.clone()
        };
        std::fs::write(&source, &printed).unwrap();
        for level in ["-O0", "-O2"] {
            let binary = dir.join(format!("intrinsics{level}-{mocked}"));
            let mut command = Command::new("clang");
            if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
                command.args(["-arch", "x86_64"]);
            }
            let compiled = command
                .args([level, "-Werror", "-Wno-unused-variable"])
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                compiled.status.success(),
                "{}\n{code}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            let executed = Command::new(&binary).output().unwrap();
            assert!(
                executed.status.success(),
                "{level}: {executed:?}\n{printed}"
            );
        }
    }
}
