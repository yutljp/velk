use super::*;
use velk::ir::{LaneOp, Operation};

#[test]
fn printed_vector_operations_define_their_helpers() {
    let mut candidates = Vec::new();
    let lanes = [
        LaneOp::Add,
        LaneOp::Sub,
        LaneOp::Mul,
        LaneOp::Equal,
        LaneOp::GreaterSigned,
        LaneOp::GreaterUnsigned,
        LaneOp::GreaterEqualSigned,
        LaneOp::GreaterEqualUnsigned,
        LaneOp::MinSigned,
        LaneOp::MinUnsigned,
        LaneOp::MaxSigned,
        LaneOp::MaxUnsigned,
        LaneOp::ShiftLeft,
        LaneOp::ShiftRight,
        LaneOp::ShiftRightSigned,
        LaneOp::AddSaturatingSigned,
        LaneOp::AddSaturatingUnsigned,
        LaneOp::SubSaturatingSigned,
        LaneOp::SubSaturatingUnsigned,
        LaneOp::Average,
        LaneOp::MulHighSigned,
        LaneOp::MulHighUnsigned,
        LaneOp::PopCount,
        LaneOp::CountLeadingZeros,
    ];
    for bits in [8, 16, 32] {
        let mut ops: Vec<_> = lanes
            .iter()
            .map(|lane| Operation::Lanes(*lane, bits))
            .collect();
        ops.extend([
            Operation::Narrow(bits * 2),
            Operation::SumLanes(bits),
            Operation::InterleaveLow(bits),
            Operation::InterleaveHigh(bits),
            Operation::SignBits(bits),
            Operation::Pack {
                from: bits * 2,
                unsigned: false,
            },
            Operation::Pack {
                from: bits * 2,
                unsigned: true,
            },
        ]);
        if bits == 8 {
            ops.extend([
                Operation::MultiplyAddPairs,
                Operation::SumAbsoluteDifferences,
            ]);
        }
        for signed in [false, true] {
            ops.push(Operation::SumLanesLong { bits, signed });
            for high in [false, true] {
                ops.push(Operation::Widen { bits, signed, high });
            }
        }
        for (i, op) in ops.into_iter().enumerate() {
            let params = [7, 6][..op.arity()]
                .iter()
                .enumerate()
                .map(|(i, index)| Param {
                    index: *index,
                    name: format!("a{i}"),
                    ty: CType::U64,
                })
                .collect();
            let ir = synthetic_ir(
                &format!("vector_{bits}_{i}"),
                params,
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::Apply {
                        op,
                        args: [7, 6][..op.arity()]
                            .iter()
                            .map(|index| Expr::reg(*index, 64))
                            .collect(),
                    },
                }],
            );
            let inputs = [
                0,
                1,
                u64::MAX,
                0x8000_7fff_ffff_0001,
                0x7fff_ffff_8000_0000,
                0x80ff_017f_0000_ffff,
            ];
            let values = inputs
                .iter()
                .flat_map(|a| {
                    inputs
                        .iter()
                        .map(move |b| vec![*a, *b][..op.arity()].to_vec())
                })
                .collect();
            candidates.push(printed_candidate(ir, values));
        }
    }
    check_candidates(
        "vector-helper-definitions",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_stack_address_with_low_bits_set_reaches_the_local() {
    let sp = velk::arch::stack_pointer(Isa::AArch64);
    let address =
        |offset: i64| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset as u64));
    let mut ir = synthetic_ir(
        "frame_bits",
        vec![Param {
            index: 0,
            name: "value".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Store {
                addr: address(-24),
                value: Expr::reg(0, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::bin(BinOp::Or, address(-32), Expr::Const(8))),
                    width: 8,
                    signed: false,
                },
            },
        ],
    );
    ir.isa = Isa::AArch64;
    ir.convention = Convention::Aapcs64;
    let original = ir.clone();
    velk::passes::frame_slots::settle(&mut ir);
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(!code.contains("sp"), "{code}");
    let mut candidate = printed_candidate(
        ir,
        vec![
            vec![0],
            vec![1],
            vec![u64::MAX],
            vec![0x1234_5678_90ab_cdef],
        ],
    );
    candidate.ir = original;
    check_candidates("frame-low-bits", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_tail_call_reads_only_the_callees_parameters() {
    let scratch = scratch_dir("tail-call-parameters");
    let source = scratch.join("original.c");
    let binary_path = scratch.join("original");
    std::fs::write(&source, "__attribute__((noinline)) unsigned next(unsigned x) { return x + 1; }\n__attribute__((noinline)) unsigned forward(unsigned x) { return next(x); }\nint main(void) { return forward(1); }\n").unwrap();
    let output = Command::new(COMPILER)
        .args(["-O2", "-fno-stack-protector"])
        .arg(&source)
        .arg("-o")
        .arg(&binary_path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let mut binary = Binary::open(&binary_path).unwrap();
    let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
    let address = binary.find(&format!("{prefix}forward")).unwrap().addr;
    let callee = binary.find(&format!("{prefix}next")).unwrap().addr;
    let mut ir = binary.analysis(address, None).unwrap().ir.clone();
    ir.name = Some("forward".into());
    assert_eq!(ir.params.len(), 1, "{ir:?}");
    let symbols = velk::render::Symbols {
        functions: [(callee, "next".into())].into(),
        function_returns: [(callee, CType::U32)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    let mut text = String::from(HEADER);
    text.push_str("uint32_t next(uint32_t x) { return x + 1; }\n");
    text.push_str(&code);
    text.push_str("int main(void) { return forward(0) != 1 || forward(0xffffffff) != 0; }\n");
    for level in LEVELS {
        let executable = build(
            &Program {
                text: text.clone(),
                ranges: vec![],
            },
            &scratch,
            level,
            &[],
        );
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}
