use super::*;

pub(super) const SC_COUNTER: u64 = REGION + 0x80;
const SC_LEFT: u64 = REGION + 0x100;
pub(super) const SC_RIGHT: u64 = REGION + 0x108;

fn argument_register(position: usize) -> Expr {
    Expr::reg([7, 6, 2][position], 64)
}

pub(super) fn sc_load(address: u64) -> Expr {
    Expr::Load {
        addr: Box::new(Expr::Const(address)),
        width: 8,
        signed: false,
    }
}

pub(super) fn sc_store(address: u64, value: Expr) -> Stmt {
    Stmt::Store {
        addr: Expr::Const(address),
        value,
        width: 8,
        at: None,
    }
}

fn increment_counter() -> Stmt {
    sc_store(
        SC_COUNTER,
        Expr::bin(BinOp::Add, sc_load(SC_COUNTER), Expr::Const(1)),
    )
}

fn conditional_branch(test: &(Cond, Expr, Expr), invert: bool, target: u64) -> Stmt {
    Stmt::Brif {
        cond: if invert { test.0.invert() } else { test.0 },
        lhs: test.1.clone(),
        rhs: test.2.clone(),
        target,
        at: None,
    }
}

pub(super) fn sc_ir(name: &str, types: Vec<CType>, blocks: Vec<Block>) -> FunctionIr {
    let params = types
        .into_iter()
        .zip([7, 6, 2])
        .enumerate()
        .map(|(position, (ty, index))| Param {
            index,
            name: format!("argument_{position}"),
            ty,
        })
        .collect();
    let mut ir = synthetic_ir(name, params, CType::U64, Vec::new());
    ir.blocks = blocks;
    ir
}

fn short_circuit_pair_candidate(
    name: &str,
    types: Vec<CType>,
    mut prefix: Vec<Stmt>,
    first: (Cond, Expr, Expr),
    second: (Cond, Expr, Expr),
    or: bool,
    inputs: Vec<Vec<u64>>,
) -> Candidate {
    prefix.push(sc_store(SC_COUNTER, Expr::Const(0)));
    prefix.push(conditional_branch(&first, !or, 0x30));
    let blocks = vec![
        Block {
            start: 0,
            stmts: prefix,
        },
        Block {
            start: 0x10,
            stmts: vec![conditional_branch(&second, !or, 0x30)],
        },
        Block {
            start: 0x20,
            stmts: if or {
                vec![Stmt::Ret {
                    value: Expr::Const(0),
                    at: None,
                }]
            } else {
                vec![increment_counter()]
            },
        },
        Block {
            start: 0x30,
            stmts: vec![Stmt::Ret {
                value: if or {
                    Expr::Const(7)
                } else {
                    sc_load(SC_COUNTER)
                },
                at: None,
            }],
        },
    ];
    printed_candidate(sc_ir(name, types, blocks), inputs)
}

fn assert_expected_outcomes(candidate: &Candidate, expected: &[(u64, u64)]) {
    assert_eq!(candidate.inputs.len(), expected.len());
    let fixture = Fixture {
        name: "short-circuit oracle".into(),
        convention: eval::Convention {
            arguments: Convention::SysV.arguments(),
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: Vec::new(),
        functions: 1,
        excluded: BTreeMap::new(),
        candidates: Vec::new(),
    };
    for (trial, (input, &(expected_return, expected_counter))) in
        candidate.inputs.iter().zip(expected).enumerate()
    {
        let outcome = interpret(&fixture, candidate, trial as u64, input, Mode::Memory)
            .unwrap_or_else(|reason| panic!("{} trial {trial}: {reason}", candidate.label));
        let Outcome::Return {
            value,
            calls,
            memory,
        } = outcome
        else {
            panic!("{}: {outcome:?}", candidate.label)
        };
        assert_eq!(value, expected_return, "{} trial {trial}", candidate.label);
        assert!(calls.is_empty());
        let counter = (0..8).fold(0, |value, offset| {
            value | u64::from(memory[&(SC_COUNTER + offset)]) << (8 * offset)
        });
        assert_eq!(
            counter, expected_counter,
            "{} trial {trial}",
            candidate.label
        );
    }
}

pub(super) fn printed_short_circuit_conditions_keep_order_and_effects() {
    let nonzero = |position| (Cond::Ne, argument_register(position), Expr::Const(0));
    let division = || Expr::bin(BinOp::DivU, Expr::Const(100), argument_register(0));
    let mut candidates = Vec::new();
    let truth_inputs: Vec<Vec<u64>> = [0, 1, 2, u64::MAX]
        .into_iter()
        .flat_map(|a| [0, 1, 2, u64::MAX].into_iter().map(move |b| vec![a, b]))
        .collect();
    for or in [false, true] {
        let candidate = short_circuit_pair_candidate(
            if or { "short_or" } else { "short_and" },
            vec![CType::U64; 2],
            Vec::new(),
            nonzero(0),
            nonzero(1),
            or,
            truth_inputs.clone(),
        );
        let wanted: Vec<_> = truth_inputs
            .iter()
            .map(|row| {
                let yes = if or {
                    row[0] != 0 || row[1] != 0
                } else {
                    row[0] != 0 && row[1] != 0
                };
                if or {
                    (if yes { 7 } else { 0 }, 0)
                } else {
                    (u64::from(yes), u64::from(yes))
                }
            })
            .collect();
        assert_expected_outcomes(&candidate, &wanted);
        candidates.push(candidate);
    }
    let mut mixed_inputs = Vec::new();
    for a in [0, 1, 2, u64::MAX] {
        for b in [0, 1, 2, u64::MAX] {
            for c in [0, 1, 2, u64::MAX] {
                mixed_inputs.push(vec![a, b, c]);
            }
        }
    }
    for grouped in [false, true] {
        let name = if grouped {
            "short_grouped_or_and"
        } else {
            "short_or_nested_and"
        };
        let candidate = printed_candidate(
            sc_ir(
                name,
                vec![CType::U64; 3],
                vec![
                    Block {
                        start: 0,
                        stmts: vec![
                            sc_store(SC_COUNTER, Expr::Const(0)),
                            conditional_branch(
                                &nonzero(0),
                                false,
                                if grouped { 0x20 } else { 0x30 },
                            ),
                        ],
                    },
                    Block {
                        start: 0x10,
                        stmts: vec![conditional_branch(&nonzero(1), true, 0x40)],
                    },
                    Block {
                        start: 0x20,
                        stmts: vec![conditional_branch(&nonzero(2), true, 0x40)],
                    },
                    Block {
                        start: 0x30,
                        stmts: vec![increment_counter()],
                    },
                    Block {
                        start: 0x40,
                        stmts: vec![Stmt::Ret {
                            value: sc_load(SC_COUNTER),
                            at: None,
                        }],
                    },
                ],
            ),
            mixed_inputs.clone(),
        );
        let wanted: Vec<_> = mixed_inputs
            .iter()
            .map(|row| {
                let (a, b, c) = (row[0] != 0, row[1] != 0, row[2] != 0);
                let yes = if grouped {
                    (a || b) && c
                } else {
                    a || (b && c)
                };
                (u64::from(yes), u64::from(yes))
            })
            .collect();
        assert_expected_outcomes(&candidate, &wanted);
        assert!(
            candidate
                .code
                .lines()
                .any(|line| line.contains(" && ") && line.contains(" || ")),
            "{}: mixed logical operators missing\n{}",
            candidate.label,
            candidate.code
        );
        candidates.push(candidate);
    }
    let divisors = [0, 1, 2, 10, 11, u64::MAX];
    for or in [false, true] {
        let candidate = short_circuit_pair_candidate(
            if or { "short_div_or" } else { "short_div_and" },
            vec![CType::U64],
            Vec::new(),
            (
                if or { Cond::Eq } else { Cond::Ne },
                argument_register(0),
                Expr::Const(0),
            ),
            (Cond::Hi, division(), Expr::Const(10)),
            or,
            divisors.into_iter().map(|value| vec![value]).collect(),
        );
        let wanted: Vec<_> = divisors
            .into_iter()
            .map(|value| {
                let yes = if or {
                    value == 0 || 100 / value > 10
                } else {
                    value != 0 && 100 / value > 10
                };
                if or {
                    (if yes { 7 } else { 0 }, 0)
                } else {
                    (u64::from(yes), u64::from(yes))
                }
            })
            .collect();
        assert_expected_outcomes(&candidate, &wanted);
        candidates.push(candidate);
    }
    let guarded_load = short_circuit_pair_candidate(
        "short_guarded_load",
        vec![CType::pointer_to(CType::U64), CType::U64],
        vec![
            sc_store(SC_LEFT, Expr::Const(0x1234)),
            sc_store(SC_RIGHT, Expr::Const(0)),
        ],
        nonzero(1),
        (
            Cond::Eq,
            Expr::Load {
                addr: Box::new(argument_register(0)),
                width: 8,
                signed: false,
            },
            Expr::Const(0x1234),
        ),
        false,
        vec![
            vec![1, 0],
            vec![SC_LEFT, 0],
            vec![SC_LEFT, 2],
            vec![SC_RIGHT, 2],
        ],
    );
    assert_expected_outcomes(&guarded_load, &[(0, 0), (0, 0), (1, 1), (0, 0)]);
    candidates.push(guarded_load);

    let store_barrier = printed_candidate(
        sc_ir(
            "short_store_barrier",
            vec![CType::U64],
            vec![
                Block {
                    start: 0,
                    stmts: vec![
                        sc_store(SC_COUNTER, Expr::Const(0)),
                        sc_store(SC_LEFT, Expr::Const(0)),
                        conditional_branch(&nonzero(0), true, 0x30),
                    ],
                },
                Block {
                    start: 0x10,
                    stmts: vec![
                        sc_store(SC_LEFT, Expr::Const(1)),
                        conditional_branch(
                            &(Cond::Ne, sc_load(SC_LEFT), Expr::Const(0)),
                            true,
                            0x30,
                        ),
                    ],
                },
                Block {
                    start: 0x20,
                    stmts: vec![increment_counter()],
                },
                Block {
                    start: 0x30,
                    stmts: vec![Stmt::Ret {
                        value: sc_load(SC_COUNTER),
                        at: None,
                    }],
                },
            ],
        ),
        vec![vec![0], vec![1], vec![2], vec![u64::MAX]],
    );
    assert_expected_outcomes(&store_barrier, &[(0, 0), (1, 1), (1, 1), (1, 1)]);
    candidates.push(store_barrier);

    let sequential = printed_candidate(
        sc_ir(
            "short_separate_effects",
            vec![CType::U64; 2],
            vec![
                Block {
                    start: 0,
                    stmts: vec![
                        sc_store(SC_COUNTER, Expr::Const(0)),
                        conditional_branch(&nonzero(0), true, 0x20),
                    ],
                },
                Block {
                    start: 0x10,
                    stmts: vec![increment_counter()],
                },
                Block {
                    start: 0x20,
                    stmts: vec![conditional_branch(&nonzero(1), true, 0x40)],
                },
                Block {
                    start: 0x30,
                    stmts: vec![increment_counter()],
                },
                Block {
                    start: 0x40,
                    stmts: vec![Stmt::Ret {
                        value: sc_load(SC_COUNTER),
                        at: None,
                    }],
                },
            ],
        ),
        truth_inputs.clone(),
    );
    let wanted: Vec<_> = truth_inputs
        .iter()
        .map(|row| {
            let count = u64::from(row[0] != 0) + u64::from(row[1] != 0);
            (count, count)
        })
        .collect();
    assert_expected_outcomes(&sequential, &wanted);
    candidates.push(sequential);

    let bits = [
        f64::NEG_INFINITY.to_bits(),
        (-1.0_f64).to_bits(),
        (-0.0_f64).to_bits(),
        0.0_f64.to_bits(),
        1.0_f64.to_bits(),
        f64::INFINITY.to_bits(),
        0x7ff8_0000_0000_0042,
    ];
    let mut inputs = Vec::new();
    let mut wanted = Vec::new();
    for left in bits {
        for right in bits {
            for gate in [0, 2] {
                let yes = f64::from_bits(left).partial_cmp(&f64::from_bits(right))
                    != Some(std::cmp::Ordering::Less)
                    && gate != 0;
                inputs.push(vec![left, right, gate]);
                wanted.push((u64::from(yes), u64::from(yes)));
            }
        }
    }
    let less = || Expr::Apply {
        op: Operation::FloatLess(Precision::Double),
        args: vec![sc_load(SC_LEFT), sc_load(SC_RIGHT)],
    };
    let candidate = short_circuit_pair_candidate(
        "short_unordered_and",
        vec![CType::U64; 3],
        vec![
            sc_store(SC_LEFT, argument_register(0)),
            sc_store(SC_RIGHT, argument_register(1)),
        ],
        (Cond::Eq, less(), Expr::Const(0)),
        nonzero(2),
        false,
        inputs,
    );
    assert_expected_outcomes(&candidate, &wanted);
    candidates.push(candidate);
    let inputs = vec![
        vec![0x7ff8_0000_0000_0042, 1.0_f64.to_bits(), 0],
        vec![f64::INFINITY.to_bits(), 1.0_f64.to_bits(), 0],
        vec![1.0_f64.to_bits(), 2.0_f64.to_bits(), 1],
        vec![1.0_f64.to_bits(), 2.0_f64.to_bits(), 20],
    ];
    let candidate = short_circuit_pair_candidate(
        "short_unordered_or",
        vec![CType::U64; 3],
        vec![
            sc_store(SC_LEFT, argument_register(0)),
            sc_store(SC_RIGHT, argument_register(1)),
        ],
        (Cond::Eq, less(), Expr::Const(0)),
        (
            Cond::Hi,
            Expr::bin(BinOp::DivU, Expr::Const(100), argument_register(2)),
            Expr::Const(10),
        ),
        true,
        inputs,
    );
    assert_expected_outcomes(&candidate, &[(7, 0), (7, 0), (7, 0), (0, 0)]);
    candidates.push(candidate);
    assert_eq!(candidates.len(), 11);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.inputs.len())
            .sum::<usize>(),
        298
    );
    check_candidates("short-circuit", candidates, Mode::Memory, &[]);
}

pub(super) fn printed_real_short_circuit_guards_preserve_memory_and_results() {
    let mut fixtures = Vec::new();
    for architecture in ["x86_64", "aarch64"] {
        for (case, name) in [("memory", "copy_bytes"), ("control", "short_circuit")] {
            let path = common::fixtures_dir()
                .join("metrics")
                .join(format!("{case}.{architecture}.O2.debug.elf"));
            let mut binary = Binary::open(&path).unwrap();
            let address = binary.find(name).unwrap().addr;
            let ir = binary.analysis(address, None).unwrap().ir.clone();
            let mut initial_memory = Vec::new();
            let inputs = if name == "copy_bytes" {
                let source = REGION + 0x400;
                [
                    0, 1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 39, 40, 63, 64, 65, 95, 96,
                    97,
                ]
                .into_iter()
                .flat_map(|length| {
                    [
                        REGION + 0x800,
                        source,
                        source - 1,
                        source - 8,
                        source - 31,
                        source - 32,
                        source + 1,
                        source + 7,
                        source + 8,
                        source + 15,
                        source + 16,
                        source + 31,
                        source + 32,
                        source + 33,
                        source + 64,
                    ]
                    .into_iter()
                    .map(move |destination| vec![destination, source, length])
                })
                .collect()
            } else {
                initial_memory = vec![
                    (REGION + 0x200, 1),
                    (REGION + 0x220, 1 << 32),
                    (REGION + 0x240, 0),
                ];
                vec![
                    vec![0, 0],
                    vec![0, 1],
                    vec![0, u64::MAX],
                    vec![0, i32::MAX as u64],
                    vec![REGION + 0x200, 0],
                    vec![REGION + 0x200, u64::MAX],
                    vec![REGION + 0x200, 1],
                    vec![REGION + 0x200, 2],
                    vec![REGION + 0x220, 1],
                    vec![REGION + 0x220, 2],
                    vec![REGION + 0x240, 1],
                    vec![REGION + 0x240, 2],
                ]
            };
            let mut candidate = printed_candidate(ir, inputs);
            candidate.code = binary.decompile(address, None, None).unwrap();
            if architecture == "aarch64" && name == "copy_bytes" {
                let code = &candidate.code;
                let mut pointers = Vec::new();
                for line in code.lines() {
                    if let Some(declaration) = line.trim_start().strip_prefix("uint64_t *v") {
                        let suffix = declaration.split([' ', ';']).next().expect("pointer name");
                        pointers.push(format!("v{suffix}"));
                    }
                }
                assert_eq!(pointers.len(), 4, "{code}");
                assert_eq!(
                    code.lines()
                        .filter(|line| line.trim_start().starts_with("uint8_t *v"))
                        .count(),
                    2,
                    "{code}"
                );
                for pointer in &pointers[..2] {
                    assert!(code.contains(&format!("{pointer} += 0x4;")), "{code}");
                }
                for pointer in &pointers[2..] {
                    assert!(code.contains(&format!("++{pointer};")), "{code}");
                }
            }
            candidate.label = format!("{architecture} {name}");
            let fixture = Fixture {
                name: format!("{architecture} {name}").into(),
                convention: eval::Convention {
                    arguments: candidate.ir.convention.arguments(),
                    clobbered: &[],
                },
                entry_registers: Vec::new(),
                initial_memory,
                functions: 1,
                excluded: BTreeMap::new(),
                candidates: vec![candidate],
            };
            let candidate = &fixture.candidates[0];
            for (trial, input) in candidate.inputs.iter().enumerate() {
                let outcome = interpret(&fixture, candidate, trial as u64, input, Mode::Memory)
                    .unwrap_or_else(|reason| panic!("{} trial {trial}: {reason}", candidate.label));
                let Outcome::Return {
                    value,
                    calls,
                    memory,
                } = outcome
                else {
                    panic!("{} trial {trial}: {outcome:?}", candidate.label)
                };
                assert!(calls.is_empty());
                let mut expected: BTreeMap<u64, u8> = (REGION..REGION + REGION_SIZE)
                    .map(|address| (address, eval::hash(trial as u64, address) as u8))
                    .collect();
                for &(address, word) in &fixture.initial_memory {
                    for offset in 0..8 {
                        expected.insert(address + offset, (word >> (8 * offset)) as u8);
                    }
                }
                if name == "copy_bytes" {
                    for offset in 0..input[2] {
                        let byte = expected[&(input[1] + offset)];
                        expected.insert(input[0] + offset, byte);
                    }
                } else {
                    let n = input[1] as u32 as i32;
                    let word = |address| {
                        (0..4).fold(0_u32, |value, offset| {
                            value | u32::from(expected[&(address + offset)]) << (8 * offset)
                        })
                    };
                    let wanted = input[0] != 0
                        && n > 0
                        && (word(input[0]) == 1 || word(input[0] + (n as u64 - 1) * 4) == 1);
                    assert_eq!(
                        value,
                        u64::from(wanted),
                        "{} trial {trial}",
                        candidate.label
                    );
                }
                assert_eq!(memory, expected, "{} trial {trial}", candidate.label);
            }
            fixtures.push(fixture);
        }
    }
    let scratch = scratch_dir("short-circuit-real");
    let findings = check(&fixtures, &scratch, Mode::Memory, &[]);
    assert_eq!(findings.len(), 4);
    for (fixture, result) in fixtures.iter().zip(&findings) {
        assert_comparison_runs(result, 1, fixture.candidates[0].inputs.len());
    }
    assert_eq!(
        findings.iter().map(|result| result.runs).sum::<usize>(),
        684
    );
    std::fs::remove_dir_all(&scratch).ok();
}
