use super::*;
use velk::ir::{AtomicOp, MachineInstruction, Ordering, RegRef, VARIABLE_BASE};

fn atomic_add(ordering: Ordering) -> Stmt {
    Stmt::Machine {
        at: None,
        instruction: MachineInstruction::Atomic {
            op: AtomicOp::Add,
            width: 8,
            ordering,
        },
        inputs: vec![Expr::reg(7, 64), Expr::Const(1)],
        outputs: vec![RegRef {
            index: VARIABLE_BASE + 1,
            width: 64,
        }],
    }
}

fn atomic_parameters() -> Vec<Param> {
    vec![
        Param {
            index: 7,
            name: "p".into(),
            ty: CType::pointer_to(CType::U64),
        },
        Param {
            index: 6,
            name: "a".into(),
            ty: CType::U64,
        },
    ]
}

#[test]
fn printed_private_values_cross_atomics_without_moving_shared_loads() {
    let mut text = String::from(HEADER);
    text.push_str("#include <sys/mman.h>\n");
    let mut checks = String::from(
        "int main(void) { uint64_t x; uint64_t *g = mmap((void *)0x300000000000ULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0); if (g == MAP_FAILED) return 3;\n",
    );
    for (i, ordering) in [
        Ordering::Relaxed,
        Ordering::Acquire,
        Ordering::Release,
        Ordering::AcqRel,
        Ordering::SeqCst,
    ]
    .into_iter()
    .enumerate()
    {
        let sp = velk::arch::stack_pointer(Isa::X86_64);
        let slot = Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const((-8i64) as u64));
        let load = |addr: Expr| Expr::Load {
            addr: Box::new(addr),
            width: 8,
            signed: false,
        };
        for promotion in [false, true] {
            let name = format!("private_atomic_{i}_{promotion}");
            let mut ir = synthetic_ir(
                &name,
                atomic_parameters(),
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: slot.clone(),
                        value: Expr::reg(6, 64),
                        width: 8,
                        at: None,
                    },
                    atomic_add(ordering),
                    Stmt::Ret {
                        value: load(slot.clone()),
                        at: None,
                    },
                ],
            );
            if promotion {
                velk::passes::memory::promote_frame_slots(&mut ir);
            } else {
                velk::passes::memory::forward_stored_values(&mut ir);
            }
            velk::passes::copies::copy_propagate_guarded(&mut ir);
            velk::passes::dce::dce(&mut ir);
            let code = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(!code.contains("/* [sp"), "{code}");
            assert!(code.contains("__atomic_fetch_add(p,"), "{code}");
            assert!(code.contains("return a;"), "{code}");
            text.push_str(&code);
            checks.push_str(&format!(
                "x = 41; if ({name}(&x, 73) != 73 || x != 42) return 1;\n"
            ));
        }
        let name = format!("shared_atomic_{i}");
        let mut ir = synthetic_ir(
            &name,
            atomic_parameters(),
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: load(Expr::reg(7, 64)),
                    at: None,
                },
                atomic_add(ordering),
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                    at: None,
                },
            ],
        );
        velk::passes::copies::inline_local_copies(&mut ir);
        velk::passes::copies::copy_propagate_guarded(&mut ir);
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        let read = code.find("*p").expect("shared read");
        let barrier = code.find("__atomic_fetch_add").expect("atomic");
        assert!(read < barrier, "{code}");
        text.push_str(&code);
        checks.push_str(&format!(
            "x = 41; if ({name}(&x, 0) != 41 || x != 42) return 2;\n"
        ));
        let name = format!("global_atomic_{i}");
        let mut ir = synthetic_ir(
            &name,
            atomic_parameters(),
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: load(Expr::Const(0x3000_0000_0000)),
                    at: None,
                },
                atomic_add(ordering),
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                    at: None,
                },
            ],
        );
        velk::passes::copies::inline_local_copies(&mut ir);
        velk::passes::copies::copy_propagate_guarded(&mut ir);
        let symbols = velk::render::Symbols {
            data: [(0x3000_0000_0000, "shared".into())].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        let read = code
            .find("= *(uint64_t *)(0x300000000000)")
            .unwrap_or_else(|| panic!("global read: {code}"));
        let barrier = code.find("__atomic_fetch_add").expect("atomic");
        assert!(read < barrier, "{code}");
        text.push_str(&code);
        checks.push_str(&format!(
            "*g = 41; if ({name}(g, 0) != 41 || *g != 42) return 4;\n"
        ));
    }
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
    let mut barrier = atomic_add(Ordering::SeqCst);
    let Stmt::Machine { outputs, .. } = &mut barrier else {
        unreachable!()
    };
    outputs[0].index = 6;
    let mut saved = synthetic_ir(
        "atomic_redefines_saved_value",
        atomic_parameters(),
        CType::U64,
        vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(6, 64),
                width: 8,
                at: None,
            },
            barrier,
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(slot),
                    width: 8,
                    signed: false,
                },
                at: None,
            },
        ],
    );
    velk::passes::memory::forward_stored_values(&mut saved);
    velk::passes::memory::forward_spilled_variables(&mut saved);
    let code = velk::render::render(&saved, &[], &Default::default(), &[]);
    assert!(!code.contains("return a;"), "{code}");
    text.push_str(&code);
    checks
        .push_str("x = 41; if (atomic_redefines_saved_value(&x, 73) != 73 || x != 42) return 6;\n");
    let mut pointer_params = atomic_parameters();
    pointer_params[1].ty = CType::pointer_to(CType::U64);
    let pointer_value = synthetic_ir(
        "atomic_pointer_value",
        pointer_params,
        CType::U64,
        vec![
            Stmt::Machine {
                at: None,
                instruction: MachineInstruction::Atomic {
                    op: AtomicOp::Exchange,
                    width: 8,
                    ordering: Ordering::SeqCst,
                },
                inputs: vec![Expr::reg(7, 64), Expr::reg(6, 64)],
                outputs: vec![RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                }],
            },
            Stmt::Ret {
                value: Expr::reg(VARIABLE_BASE, 64),
                at: None,
            },
        ],
    );
    let code = velk::render::render(&pointer_value, &[], &Default::default(), &[]);
    assert!(
        code.contains("__atomic_exchange_n(p, (uintptr_t)a,"),
        "{code}"
    );
    text.push_str(&code);
    checks.push_str(
        "x = 41; if (atomic_pointer_value(&x, &x) != 41 || x != (uint64_t)&x) return 5;\n",
    );
    checks.push_str("return 0; }\n");
    text.push_str(&checks);
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("atomic-values");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &[]);
        assert_eq!(run(&program, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn incoming_and_atomic_frame_slots_are_not_forwarded() {
    for offset in [-8i64, 8] {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64));
        let mut barrier = atomic_add(Ordering::SeqCst);
        if offset < 0 {
            let Stmt::Machine { inputs, .. } = &mut barrier else {
                unreachable!()
            };
            inputs[0] = slot.clone();
        }
        let mut ir = synthetic_ir(
            "shared_frame_atomic",
            atomic_parameters(),
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(6, 64),
                    width: 8,
                    at: None,
                },
                barrier,
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(slot),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                },
            ],
        );
        velk::passes::memory::forward_stored_values(&mut ir);
        velk::passes::memory::forward_spilled_variables(&mut ir);
        velk::passes::memory::promote_frame_slots(&mut ir);
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains("return a;"), "{}\n{code}", ir.render());
        assert!(code.contains("__atomic_fetch_add"), "{code}");
    }
}

#[test]
fn printed_compare_exchange_uses_implicit_integer_conversions() {
    let scratch = scratch_dir("atomic-conversions");
    let mut text = String::from(HEADER);
    let mut checks = String::from(
        "int main(void) { uint64_t values[] = {0, 1, 127, 255, 256, UINT32_MAX, UINT64_C(0x8000000000000000), UINT64_MAX};\n",
    );
    for width in [1u8, 2, 4, 8] {
        for pointers in [false, true] {
            if pointers && width != 8 {
                continue;
            }
            let name = format!("compare_{width}_{pointers}");
            let operand_type = if pointers {
                CType::pointer_to(CType::U64)
            } else {
                CType::U64
            };
            let ir = synthetic_ir(
                &name,
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(width, false)),
                    },
                    Param {
                        index: 6,
                        name: "desired".into(),
                        ty: operand_type.clone(),
                    },
                    Param {
                        index: 2,
                        name: "expected".into(),
                        ty: operand_type,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Machine {
                        at: None,
                        instruction: MachineInstruction::Atomic {
                            op: AtomicOp::CompareExchange,
                            width,
                            ordering: Ordering::SeqCst,
                        },
                        inputs: vec![Expr::reg(7, 64), Expr::reg(6, 64), Expr::reg(2, 64)],
                        outputs: vec![RegRef {
                            index: VARIABLE_BASE,
                            width: width * 8,
                        }],
                    },
                    Stmt::Ret {
                        value: Expr::reg(VARIABLE_BASE, 64),
                        at: None,
                    },
                ],
            );
            let code = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(!code.contains(&format!("(uint{}_t)(", width * 8)), "{code}");
            if pointers {
                assert!(code.contains("(uintptr_t)expected"), "{code}");
                assert!(code.contains("(uintptr_t)desired"), "{code}");
            }
            text.push_str(&code);
            let mask = if width == 8 {
                u64::MAX
            } else {
                (1u64 << (width * 8)) - 1
            };
            let argument = |value: &str| {
                if pointers {
                    format!("(void *)(uintptr_t){value}")
                } else {
                    value.to_owned()
                }
            };
            writeln!(checks, "for (unsigned a = 0; a < 8; ++a) for (unsigned b = 0; b < 8; ++b) for (unsigned c = 0; c < 8; ++c) {{ uint{}_t x = values[a]; uint64_t old = x; uint64_t desired = values[b], expected = values[c]; uint64_t result = {name}(&x, {}, {}); if (result != old || x != (old == (expected & UINT64_C({mask})) ? (desired & UINT64_C({mask})) : old)) return 1; }}", width * 8, argument("desired"), argument("expected")).unwrap();
        }
    }
    checks.push_str("return 0; }\n");
    text.push_str(&checks);
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}
