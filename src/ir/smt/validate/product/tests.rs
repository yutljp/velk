use super::*;
use crate::ir::smt::raw_bin;
use crate::ir::{BinOp, Cond, Convention, RegRef, Stmt};

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        at: None,
        dest: RegRef { index, width: 64 },
        value,
    }
}

fn r(index: u16) -> Expr {
    Expr::reg(index, 64)
}

fn plus(index: u16, k: i64) -> Expr {
    raw_bin(BinOp::Add, r(index), Expr::Const(k as u64))
}

fn block(start: u64, stmts: Vec<Stmt>) -> Block {
    Block { start, stmts }
}

fn br(target: u64) -> Stmt {
    Stmt::Br {
        at: None,
        target: Some(target),
    }
}

fn ret(value: Expr) -> Stmt {
    Stmt::Ret { at: None, value }
}

fn store(addr: Expr, value: Expr) -> Stmt {
    Stmt::Store {
        at: None,
        addr,
        value,
        width: 8,
    }
}

fn call() -> Stmt {
    Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x2000),
        through: None,
        convention: Convention::SysV,
        args: Some(Vec::new()),
        floats_named: false,
        abi: None,
        outputs: Vec::new(),
        clobbers: None,
        via: None,
        at: None,
    }
}

fn application(before: Vec<Block>, after: Vec<Block>) -> Application {
    Application {
        site: "test",
        tag: String::new(),
        index: 0,
        before,
        after,
        landing_pads: false,
        narrow_stack: None,
        stack_entries: Default::default(),
        private_frame: None,
        frames: None,
        convention: crate::ir::Convention::SysV,
        entry_alignment: None,
        returned: Some(64),
        narrow_results: BTreeSet::new(),
        without_result_address: BTreeSet::new(),
        scratch_reads: BTreeMap::new(),
        narrow_registers: BTreeSet::new(),
        entry_pairs: BTreeMap::new(),
    }
}

fn verdict(before: Vec<Block>, after: Vec<Block>) -> Verdict {
    check(&application(before, after), 50_000_000, 1_000_000_000)
}

fn returning(before: Vec<Block>, after: Vec<Block>, returned: Option<u32>) -> Verdict {
    assuming(before, after, returned, BTreeSet::new())
}

fn assuming(
    before: Vec<Block>,
    after: Vec<Block>,
    returned: Option<u32>,
    narrow_results: BTreeSet<u64>,
) -> Verdict {
    check(
        &Application {
            site: "test",
            tag: String::new(),
            index: 0,
            before,
            after,
            landing_pads: false,
            narrow_stack: None,
            stack_entries: Default::default(),
            private_frame: None,
            frames: None,
            convention: crate::ir::Convention::SysV,
            entry_alignment: None,
            returned,
            narrow_results,
            without_result_address: BTreeSet::new(),
            scratch_reads: BTreeMap::new(),
            narrow_registers: BTreeSet::new(),
            entry_pairs: BTreeMap::new(),
        },
        50_000_000,
        1_000_000_000,
    )
}

fn aligned(
    before: Vec<Block>,
    after: Vec<Block>,
    alignment: Option<crate::ir::EntryAlignment>,
) -> Verdict {
    check(
        &Application {
            site: "test",
            tag: String::new(),
            index: 0,
            before,
            after,
            landing_pads: false,
            narrow_stack: None,
            stack_entries: Default::default(),
            private_frame: None,
            frames: None,
            convention: crate::ir::Convention::SysV,
            entry_alignment: alignment.map(|alignment| (4, alignment)),
            returned: Some(64),
            narrow_results: BTreeSet::new(),
            without_result_address: BTreeSet::new(),
            scratch_reads: BTreeMap::new(),
            narrow_registers: BTreeSet::new(),
            entry_pairs: BTreeMap::new(),
        },
        50_000_000,
        1_000_000_000,
    )
}

fn not_proved(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::NotProved { .. })
}

#[test]
fn functions_are_compared_across_blocks_and_loops() {
    if !crate::ir::smt::z3_available("product validation") {
        return;
    }
    // A register renamed throughout the function.
    let renamed = |k| {
        verdict(
            vec![
                block(0, vec![assign(10, plus(0, 1)), br(1)]),
                block(1, vec![ret(r(10))]),
            ],
            vec![
                block(0, vec![assign(11, plus(0, k)), br(1)]),
                block(1, vec![ret(r(11))]),
            ],
        )
    };
    assert_eq!(renamed(1), Verdict::Proved);
    assert!(not_proved(&renamed(2)));

    // A frame address taken from another register, through a loop that
    // keeps both registers or moves one of them.
    let framed = |step: Expr| {
        let body = |addr: Expr| {
            block(
                1,
                vec![
                    store(addr, r(0)),
                    assign(5, step.clone()),
                    Stmt::Brif {
                        at: None,
                        cond: Cond::Ne,
                        lhs: r(1),
                        rhs: Expr::Const(0),
                        target: 1,
                    },
                ],
            )
        };
        verdict(
            vec![
                block(0, vec![assign(5, plus(4, 8))]),
                body(plus(5, -12)),
                block(2, vec![ret(Expr::Const(0))]),
            ],
            vec![
                block(0, vec![assign(5, plus(4, 8))]),
                body(plus(4, -4)),
                block(2, vec![ret(Expr::Const(0))]),
            ],
        )
    };
    assert_eq!(framed(r(5)), Verdict::Proved);
    assert!(not_proved(&framed(plus(5, 1))));

    // A constant another block assigned, or a value it did not fix.
    let constant = |value: Expr| {
        verdict(
            vec![
                block(0, vec![assign(0, value.clone()), br(1)]),
                block(1, vec![ret(r(0))]),
            ],
            vec![
                block(0, vec![assign(0, value), br(1)]),
                block(1, vec![ret(Expr::Const(7))]),
            ],
        )
    };
    assert_eq!(constant(Expr::Const(7)), Verdict::Proved);
    assert!(not_proved(&constant(r(1))));

    // A call keeps rbx (3) and may change r9 (9).
    let across = |register| {
        verdict(
            vec![
                block(0, vec![assign(register, Expr::Const(5)), call()]),
                block(1, vec![ret(r(register))]),
            ],
            vec![
                block(0, vec![assign(register, Expr::Const(5)), call()]),
                block(1, vec![ret(Expr::Const(5))]),
            ],
        )
    };
    assert_eq!(across(3), Verdict::Proved);
    assert!(not_proved(&across(9)));

    // A register a call changes keeps its value when an output takes
    // the change, and does not when none does.
    let routed = |outputs: Vec<crate::ir::CallOutput>| {
        let mut changing = call();
        if let Stmt::Call {
            outputs: taken,
            clobbers,
            ..
        } = &mut changing
        {
            *taken = outputs;
            let mut changed = crate::ir::Registers::default();
            changed.insert(0);
            *clobbers = Some(changed);
        }
        verdict(
            vec![
                block(0, vec![assign(10, r(0)), changing.clone()]),
                block(1, vec![ret(r(10))]),
            ],
            vec![block(0, vec![changing]), block(1, vec![ret(r(0))])],
        )
    };
    assert_eq!(
        routed(vec![crate::ir::CallOutput {
            register: 0,
            dest: RegRef {
                index: 11,
                width: 64
            },
        }]),
        Verdict::Proved
    );
    assert!(not_proved(&routed(Vec::new())));

    // A dropped assignment no one reads, and one the return reads.
    let dropped = |read| {
        verdict(
            vec![block(0, vec![assign(2, plus(0, 1)), ret(r(read))])],
            vec![block(0, vec![ret(r(read))])],
        )
    };
    assert_eq!(dropped(0), Verdict::Proved);
    assert!(not_proved(&dropped(2)));

    // An undefined value for bits nothing reads after, and for bits the
    // return reads.
    let undefined = |kept: u64| {
        let merged = |high: Expr| {
            raw_bin(
                BinOp::Or,
                raw_bin(BinOp::And, high, Expr::Const(!0xff)),
                raw_bin(BinOp::And, r(1), Expr::Const(0xff)),
            )
        };
        let returned = ret(raw_bin(BinOp::And, r(2), Expr::Const(kept)));
        verdict(
            vec![block(0, vec![assign(2, merged(r(2))), returned.clone()])],
            vec![block(
                0,
                vec![
                    assign(
                        2,
                        merged(Expr::apply(crate::ir::Operation::Undefined, Vec::new())),
                    ),
                    returned,
                ],
            )],
        )
    };
    assert_eq!(undefined(0xff), Verdict::Proved);
    assert!(not_proved(&undefined(0x1ff)));

    // An undefined value both sides assign alike, stored in the next block
    // after an assignment no one reads is dropped: one value on both sides.
    // So too when both assign it twice there, or the rewritten side assigns
    // it at another place, the rewritten side's values being chosen as the
    // original's in order; not when the original assigns a value there.
    let alike = |times: usize, place: u64| {
        let unknown = |at: u64| Stmt::Assign {
            at: Some(at),
            dest: RegRef {
                index: 3,
                width: 64,
            },
            value: Expr::apply(crate::ir::Operation::Undefined, Vec::new()),
        };
        let tail = block(
            1,
            vec![store(Expr::Const(0x1000), r(3)), ret(Expr::Const(0))],
        );
        let mut old = vec![assign(8, Expr::Const(5))];
        let mut new = Vec::new();
        for _ in 0..times {
            old.push(unknown(0x10));
            new.push(unknown(place));
        }
        old.push(br(1));
        new.push(br(1));
        verdict(vec![block(0, old), tail.clone()], vec![block(0, new), tail])
    };
    assert_eq!(alike(1, 0x10), Verdict::Proved);
    assert_eq!(alike(2, 0x10), Verdict::Proved);
    assert_eq!(alike(1, 0x14), Verdict::Proved);
    let dropped_value = verdict(
        vec![
            block(
                0,
                vec![
                    Stmt::Assign {
                        at: Some(0x10),
                        dest: RegRef {
                            index: 3,
                            width: 64,
                        },
                        value: r(9),
                    },
                    br(1),
                ],
            ),
            block(
                1,
                vec![store(Expr::Const(0x1000), r(3)), ret(Expr::Const(0))],
            ),
        ],
        vec![
            block(
                0,
                vec![
                    Stmt::Assign {
                        at: Some(0x14),
                        dest: RegRef {
                            index: 3,
                            width: 64,
                        },
                        value: Expr::apply(crate::ir::Operation::Undefined, Vec::new()),
                    },
                    br(1),
                ],
            ),
            block(
                1,
                vec![store(Expr::Const(0x1000), r(3)), ret(Expr::Const(0))],
            ),
        ],
    );
    assert!(not_proved(&dropped_value));

    // High bits dropped that only a narrow store in another block would
    // read, and a store wide enough to read them.
    let stored = |width: u8| {
        let low = raw_bin(BinOp::And, r(1), Expr::Const(1));
        let merged = raw_bin(
            BinOp::Or,
            raw_bin(BinOp::And, r(10), Expr::Const(!0xff)),
            low.clone(),
        );
        let tail = block(
            1,
            vec![
                Stmt::Store {
                    at: None,
                    addr: Expr::Const(0x1000),
                    value: r(10),
                    width,
                },
                ret(Expr::Const(0)),
            ],
        );
        verdict(
            vec![block(0, vec![assign(10, merged), br(1)]), tail.clone()],
            vec![block(0, vec![assign(10, low), br(1)]), tail],
        )
    };
    assert_eq!(stored(1), Verdict::Proved);
    assert!(not_proved(&stored(2)));

    // An operation the solver does not model, applied to the same
    // arguments on both sides of a renaming, and to others.
    let crc = |second: u16| {
        Expr::apply(
            crate::ir::Operation::Crc32 {
                castagnoli: true,
                bits: 32,
            },
            vec![r(1), r(second)],
        )
    };
    let unmodeled = |second: u16| {
        verdict(
            vec![
                block(0, vec![assign(5, crc(3)), br(1)]),
                block(1, vec![ret(r(5))]),
            ],
            vec![
                block(0, vec![assign(6, crc(second)), br(1)]),
                block(1, vec![ret(r(6))]),
            ],
        )
    };
    assert_eq!(unmodeled(3), Verdict::Proved);
    assert!(not_proved(&unmodeled(4)));

    // A frame slot read back past a call, which leaves the frame above
    // its stack arguments alone when no address of the frame is handed
    // out; and a slot among those arguments.
    let kept = |private: bool, offset: u64, args: usize| {
        let slot = raw_bin(BinOp::Add, r(4), Expr::Const(offset));
        let mut calling = call();
        if let Stmt::Call { args: taken, .. } = &mut calling {
            *taken = Some(vec![Expr::Const(0); args]);
        }
        let store = Stmt::Store {
            at: None,
            addr: slot.clone(),
            value: Expr::Const(7),
            width: 8,
        };
        let mut application = application(
            vec![block(
                0,
                vec![
                    store.clone(),
                    calling.clone(),
                    assign(
                        2,
                        Expr::Load {
                            addr: Box::new(slot),
                            width: 8,
                            signed: false,
                        },
                    ),
                    ret(r(2)),
                ],
            )],
            vec![block(
                0,
                vec![store, calling, assign(2, Expr::Const(7)), ret(r(2))],
            )],
        );
        application.private_frame = private.then_some(4);
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(kept(true, 16, 0), Verdict::Proved);
    assert_eq!(kept(true, 16, 2), Verdict::Proved);
    assert!(not_proved(&kept(false, 16, 0)));
    assert!(not_proved(&kept(true, 0, 1)));
    assert!(not_proved(&kept(true, 16, 3)));

    // The same slot past a call, with the stack pointer of the rewritten
    // side left where the function entered, as a settled frame has it:
    // its slot lies among the call's arguments by that side's count.
    let settled = {
        let slot = |offset| raw_bin(BinOp::Add, r(4), Expr::Const(offset));
        let load = |offset| Expr::Load {
            addr: Box::new(slot(offset)),
            width: 8,
            signed: false,
        };
        let store = |offset| Stmt::Store {
            at: None,
            addr: slot(offset),
            value: Expr::Const(7),
            width: 8,
        };
        let mut calling = call();
        if let Stmt::Call { args, .. } = &mut calling {
            *args = Some(vec![Expr::Const(0); 3]);
        }
        let mut application = application(
            vec![block(
                0,
                vec![
                    assign(4, plus(4, -32)),
                    store(40),
                    calling.clone(),
                    assign(2, load(40)),
                    assign(4, plus(4, 32)),
                    ret(r(2)),
                ],
            )],
            vec![block(
                0,
                vec![store(8), calling, assign(2, load(8)), ret(r(2))],
            )],
        );
        application.private_frame = Some(4);
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(settled, Verdict::Proved);

    // A slot among a Go register-convention callee's arguments, which only
    // a caller of that convention keeps clear of what it reads afterwards;
    // and a slot reached through a register that holds a frame address,
    // which a kept byte is not read through.
    let go = |caller: Convention, callee: Convention, count: usize, through: bool| {
        let sp = if callee == Convention::Aapcs64 { 31 } else { 4 };
        let slot = raw_bin(BinOp::Add, r(sp), Expr::Const(16));
        let address = if through { r(5) } else { slot.clone() };
        let mut calling = call();
        if let Stmt::Call {
            args, convention, ..
        } = &mut calling
        {
            *args = Some(vec![Expr::Const(0); count]);
            *convention = callee;
        }
        let store = Stmt::Store {
            at: None,
            addr: address.clone(),
            value: Expr::Const(7),
            width: 8,
        };
        let load = Expr::Load {
            addr: Box::new(address),
            width: 8,
            signed: false,
        };
        let mut application = application(
            vec![block(
                0,
                vec![
                    assign(5, slot.clone()),
                    store.clone(),
                    calling.clone(),
                    assign(2, load),
                    ret(r(2)),
                ],
            )],
            vec![block(
                0,
                vec![
                    assign(5, slot),
                    store,
                    calling,
                    assign(2, Expr::Const(7)),
                    ret(r(2)),
                ],
            )],
        );
        application.private_frame = Some(sp);
        application.convention = caller;
        check(&application, 50_000_000, 1_000_000_000)
    };
    use Convention::{Aapcs64, GoAmd64, SysV};
    assert_eq!(go(GoAmd64, GoAmd64, 3, false), Verdict::Proved);
    assert!(not_proved(&go(SysV, GoAmd64, 3, false)));
    assert!(not_proved(&go(GoAmd64, GoAmd64, 3, true)));
    // On AArch64 the stack carries the ninth argument on, from the stack
    // pointer: ten leave the slot at 16 alone, eleven reach it.
    assert_eq!(go(Aapcs64, Aapcs64, 3, false), Verdict::Proved);
    assert_eq!(go(Aapcs64, Aapcs64, 10, false), Verdict::Proved);
    assert!(not_proved(&go(Aapcs64, Aapcs64, 11, false)));
    assert!(not_proved(&go(SysV, Aapcs64, 3, false)));

    // A frame slot read back past an atomic, in the next block, which
    // writes nothing below the stack pointer on entry of a function that
    // moves it only by constants: whether it moves it first, and the slot.
    let atomic = |moved: Option<Expr>, slot: i64, frames: bool| {
        let slot = plus(4, slot);
        let store = Stmt::Store {
            at: None,
            addr: slot.clone(),
            value: Expr::Const(7),
            width: 8,
        };
        let exchange = Stmt::Machine {
            at: None,
            instruction: crate::ir::MachineInstruction::Atomic {
                op: crate::ir::AtomicOp::Exchange,
                width: 8,
                ordering: crate::ir::Ordering::SeqCst,
            },
            inputs: vec![r(1), r(3)],
            outputs: vec![RegRef {
                index: 6,
                width: 64,
            }],
        };
        let first: Vec<Stmt> = moved
            .into_iter()
            .map(|value| assign(4, value))
            .chain([store, exchange, br(1)])
            .collect();
        let load = Expr::Load {
            addr: Box::new(slot),
            width: 8,
            signed: false,
        };
        let mut application = application(
            vec![
                block(0, first.clone()),
                block(1, vec![assign(2, load), ret(r(2))]),
            ],
            vec![
                block(0, first),
                block(1, vec![assign(2, Expr::Const(7)), ret(r(2))]),
            ],
        );
        application.private_frame = Some(4);
        application.frames = frames.then(|| Frames {
            before: stack_offsets(&application.before, 4).expect("offsets"),
            after: stack_offsets(&application.after, 4).expect("offsets"),
        });
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(atomic(None, -16, true), Verdict::Proved);
    assert!(not_proved(&atomic(None, -16, false)));
    assert_eq!(atomic(Some(plus(4, -32)), 16, true), Verdict::Proved);
    assert!(not_proved(&atomic(Some(plus(4, -32)), 32, true)));

    // A call of unknown arguments between two functions of the AArch64
    // standard, after the function moved its stack pointer down by 48:
    // whether a slot at `slot` past it, at or past where the stack pointer
    // was on entry, survives the call.
    let unknown = |slot: u64, caller: Convention, frames: bool| {
        let sp = 31;
        let address = raw_bin(BinOp::Add, r(sp), Expr::Const(slot));
        let mut calling = call();
        if let Stmt::Call {
            args, convention, ..
        } = &mut calling
        {
            *args = None;
            *convention = Convention::Aapcs64;
        }
        let body = |returned: Expr| {
            vec![block(
                0,
                vec![
                    assign(sp, plus(sp, -48)),
                    store(address.clone(), r(19)),
                    calling.clone(),
                    assign(19, returned),
                    assign(sp, plus(sp, 48)),
                    ret(r(19)),
                ],
            )]
        };
        let load = Expr::Load {
            addr: Box::new(address.clone()),
            width: 8,
            signed: false,
        };
        let mut application = application(body(load), body(r(19)));
        application.private_frame = Some(sp);
        application.convention = caller;
        application.frames = frames.then(|| Frames {
            before: stack_offsets(&application.before, sp).expect("offsets"),
            after: stack_offsets(&application.after, sp).expect("offsets"),
        });
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(unknown(56, Convention::Aapcs64, true), Verdict::Proved);
    assert_eq!(unknown(48, Convention::Aapcs64, true), Verdict::Proved);
    assert!(not_proved(&unknown(40, Convention::Aapcs64, true)));
    assert!(not_proved(&unknown(56, Convention::Aapcs64, false)));
    assert!(not_proved(&unknown(56, Convention::SysV, true)));
    let at = |blocks: &[Block]| stack_offsets(blocks, 4);
    assert_eq!(
        at(&[
            block(0, vec![assign(4, plus(4, -32)), br(2)]),
            block(1, vec![ret(r(0))]),
            block(2, vec![assign(4, plus(4, 32)), ret(r(0))]),
        ]),
        Some(vec![
            vec![Some(0), Some(-32)],
            vec![None],
            vec![Some(-32), Some(0)]
        ])
    );
    assert_eq!(at(&[block(0, vec![assign(4, r(5)), ret(r(0))])]), None);
    assert_eq!(
        at(&[
            block(
                0,
                vec![
                    Stmt::Brif {
                        at: None,
                        cond: Cond::Eq,
                        lhs: r(0),
                        rhs: Expr::Const(0),
                        target: 2,
                    },
                    assign(4, plus(4, -8)),
                ],
            ),
            block(2, vec![ret(r(0))]),
        ]),
        None
    );

    // A mask a branch in another block makes redundant: a range the
    // equations cannot state, found from the Horn clauses; and the same
    // mask after a branch that says nothing of the sign.
    let masked = |cond| {
        let low = Expr::reg(1, 32);
        let quarter = raw_bin(BinOp::Shr, low.clone(), Expr::Const(2));
        let entry = block(
            0,
            vec![Stmt::Brif {
                at: None,
                cond,
                lhs: low,
                rhs: Expr::Const(0),
                target: 2,
            }],
        );
        verdict(
            vec![
                entry.clone(),
                block(
                    1,
                    vec![ret(raw_bin(
                        BinOp::And,
                        quarter.clone(),
                        Expr::Const(0x1fff_ffff),
                    ))],
                ),
                block(2, vec![ret(Expr::Const(0))]),
            ],
            vec![
                entry,
                block(1, vec![ret(quarter)]),
                block(2, vec![ret(Expr::Const(0))]),
            ],
        )
    };
    assert_eq!(masked(Cond::Lt), Verdict::Proved);
    assert!(not_proved(&masked(Cond::Eq)));

    // Rounding the stack pointer down is a known move when the entry
    // alignment fixes it, and not otherwise.
    let rounded = |alignment| {
        aligned(
            vec![
                block(
                    0,
                    vec![
                        assign(4, plus(4, -8)),
                        assign(
                            4,
                            raw_bin(BinOp::And, r(4), Expr::Const(16u64.wrapping_neg())),
                        ),
                        store(r(4), r(0)),
                        br(1),
                    ],
                ),
                block(1, vec![ret(Expr::Const(0))]),
            ],
            vec![
                block(0, vec![store(plus(4, -8), r(0)), br(1)]),
                block(1, vec![ret(Expr::Const(0))]),
            ],
            alignment,
        )
    };
    let called = crate::ir::EntryAlignment {
        residue: 8,
        modulus: 16,
    };
    assert_eq!(rounded(Some(called)), Verdict::Proved);
    assert!(not_proved(&rounded(None)));
    assert!(not_proved(&rounded(Some(crate::ir::EntryAlignment {
        residue: 0,
        modulus: 16
    }))));

    // Registers renamed through a loop, every assignment with them; and
    // a renaming one use misses.
    let loop_with = |count: u16, index: u16, missed: bool| {
        vec![
            block(0, vec![assign(count, r(6)), assign(index, Expr::Const(0))]),
            block(
                1,
                vec![
                    store(plus(index, 0), r(7)),
                    assign(index, plus(index, 1)),
                    Stmt::Brif {
                        at: None,
                        cond: Cond::Ne,
                        lhs: r(count),
                        rhs: r(if missed { 2 } else { index }),
                        target: 1,
                    },
                ],
            ),
            block(2, vec![ret(r(index))]),
        ]
    };
    assert_eq!(
        verdict(loop_with(1, 2, false), loop_with(4352, 4353, false)),
        Verdict::Proved
    );
    assert!(not_proved(&verdict(
        loop_with(1, 2, false),
        loop_with(4352, 4353, true)
    )));

    // A result cut to the return type's width, which keeps its low byte
    // only, or nothing at all.
    let cut = |returned| {
        returning(
            vec![block(0, vec![ret(r(0))])],
            vec![block(
                0,
                vec![ret(raw_bin(BinOp::And, r(0), Expr::Const(0xff)))],
            )],
            returned,
        )
    };
    assert_eq!(cut(Some(8)), Verdict::Proved);
    assert_eq!(cut(None), Verdict::Proved);
    assert!(not_proved(&cut(Some(16))));

    // A call's result taken as 32 bits, as the callee's summary finds it.
    let result = |narrow: BTreeSet<u64>| {
        let mut calling = call();
        if let Stmt::Call { outputs, .. } = &mut calling {
            *outputs = vec![crate::ir::CallOutput {
                register: 0,
                dest: RegRef {
                    index: 10,
                    width: 64,
                },
            }];
        }
        assuming(
            vec![block(0, vec![calling.clone()]), block(1, vec![ret(r(10))])],
            vec![
                block(0, vec![calling]),
                block(
                    1,
                    vec![ret(raw_bin(BinOp::And, r(10), Expr::Const(0xffff_ffff)))],
                ),
            ],
            Some(64),
            narrow,
        )
    };
    assert_eq!(result([0x2000].into()), Verdict::Proved);
    assert!(not_proved(&result(BTreeSet::new())));

    // A parameter in two 32-bit registers bound to one variable, which
    // holds what they do only when the registers enter 32 bits wide.
    let paired = |narrow: BTreeSet<u16>| {
        let joined = || raw_bin(BinOp::Or, raw_bin(BinOp::Shl, r(1), Expr::Const(32)), r(0));
        check(
            &Application {
                site: "test",
                tag: String::new(),
                index: 0,
                before: vec![block(0, vec![ret(joined())])],
                after: vec![block(
                    0,
                    vec![
                        assign(0, raw_bin(BinOp::And, r(5000), Expr::Const(0xffff_ffff))),
                        assign(1, raw_bin(BinOp::Shr, r(5000), Expr::Const(32))),
                        ret(joined()),
                    ],
                )],
                landing_pads: false,
                narrow_stack: None,
                stack_entries: Default::default(),
                private_frame: None,
                frames: None,
                convention: crate::ir::Convention::SysV,
                entry_alignment: None,
                returned: Some(64),
                narrow_results: BTreeSet::new(),
                without_result_address: BTreeSet::new(),
                scratch_reads: BTreeMap::new(),
                narrow_registers: narrow,
                entry_pairs: [(5000, (0, 1))].into(),
            },
            50_000_000,
            1_000_000_000,
        )
    };
    assert_eq!(paired([0, 1].into()), Verdict::Proved);
    assert!(not_proved(&paired(BTreeSet::new())));

    // A 32-bit frame address computed in 32 bits, which a 64-bit one
    // equals only on an architecture whose stack is 32 bits wide.
    let framed32 = |narrow: bool| {
        let low = |expr: Expr| raw_bin(BinOp::And, expr, Expr::Const(0xffff_ffff));
        check(
            &Application {
                site: "test",
                tag: String::new(),
                index: 0,
                before: vec![block(
                    0,
                    vec![
                        store(low(raw_bin(BinOp::Add, low(r(13)), Expr::Const(16))), r(1)),
                        ret(Expr::Const(0)),
                    ],
                )],
                after: vec![block(
                    0,
                    vec![store(plus(13, 16), r(1)), ret(Expr::Const(0))],
                )],
                landing_pads: false,
                narrow_stack: narrow.then_some(13),
                stack_entries: Default::default(),
                private_frame: None,
                frames: None,
                convention: crate::ir::Convention::SysV,
                entry_alignment: None,
                returned: Some(64),
                narrow_results: BTreeSet::new(),
                without_result_address: BTreeSet::new(),
                scratch_reads: BTreeMap::new(),
                narrow_registers: if narrow { [13].into() } else { BTreeSet::new() },
                entry_pairs: BTreeMap::new(),
            },
            50_000_000,
            1_000_000_000,
        )
    };
    assert_eq!(framed32(true), Verdict::Proved);
    assert!(not_proved(&framed32(false)));

    // The same address through a frame pointer set in an earlier block: the
    // second block needs the stack pointer still clear of the address
    // space's ends, which holds where only constants have moved it.
    let later32 = |entries: [Vec<Option<i64>>; 2]| {
        let low = |expr: Expr| raw_bin(BinOp::And, expr, Expr::Const(0xffff_ffff));
        let frame = assign(5, low(plus(13, -4)));
        let mut application = application(
            vec![
                block(0, vec![frame.clone(), br(1)]),
                block(
                    1,
                    vec![
                        store(
                            low(raw_bin(BinOp::Add, low(r(5)), Expr::Const(-4i64 as u64))),
                            r(1),
                        ),
                        ret(Expr::Const(0)),
                    ],
                ),
            ],
            vec![
                block(0, vec![frame, br(1)]),
                block(1, vec![store(plus(13, -8), r(1)), ret(Expr::Const(0))]),
            ],
        );
        application.narrow_stack = Some(13);
        application.narrow_registers = [13].into();
        application.stack_entries = (13, entries);
        // Inference over paths from the start finds the bound by itself in
        // a function this small, so the blocks are checked alone as well.
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        let alone = product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none();
        (check(&application, 50_000_000, 1_000_000_000), alone)
    };
    let unmoved = vec![Some(0), Some(0)];
    assert_eq!(later32([unmoved.clone(), unmoved]), (Verdict::Proved, true));
    assert_eq!(later32([Vec::new(), Vec::new()]), (Verdict::Proved, false));

    // A slot one side reaches below pushes in this block and an earlier one
    // and the other from where the function entered: the blocks agree on it
    // alone only knowing how far apart the two stack pointers start, which
    // the stack entries say, or the address put over the entry values.
    let pushed = |entries: [Vec<Option<i64>>; 2]| {
        let push = || assign(4, plus(4, -8));
        let mut application = application(
            vec![
                block(0, vec![push(), push(), br(1)]),
                block(1, vec![push(), store(r(4), r(1)), ret(Expr::Const(0))]),
            ],
            vec![
                block(0, vec![br(1)]),
                block(1, vec![store(plus(4, -24), r(1)), ret(Expr::Const(0))]),
            ],
        );
        application.stack_entries = (4, entries);
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(pushed([vec![Some(0), Some(-16)], vec![Some(0), Some(0)]]));
    assert!(pushed([Vec::new(), vec![Some(0), Some(0)]]));
    // A slot at another distance is another slot.
    let push = || assign(4, plus(4, -8));
    assert!(not_proved(&verdict(
        vec![
            block(0, vec![push(), push(), br(1)]),
            block(1, vec![push(), store(r(4), r(1)), ret(Expr::Const(0))]),
        ],
        vec![
            block(0, vec![br(1)]),
            block(1, vec![store(plus(4, -16), r(1)), ret(Expr::Const(0))]),
        ],
    )));

    // A value moved out of a register a call of unknown floating-point
    // arguments reads unnamed: the same call only when the register holds
    // scratch the call passes by.
    let passed_by = |scratch: BTreeMap<(u64, usize), BTreeSet<u16>>| {
        let lanes = || assign(18, raw_bin(BinOp::Add, r(7), Expr::Const(1)));
        let mut moved = lanes();
        if let Stmt::Assign { dest, .. } = &mut moved {
            dest.index = crate::ir::VARIABLE_BASE;
        }
        let mut application = application(
            vec![block(0, vec![lanes(), call(), ret(Expr::Const(0))])],
            vec![block(0, vec![moved, call(), ret(Expr::Const(0))])],
        );
        application.scratch_reads = scratch;
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(passed_by([((0, 1), [18].into())].into()), Verdict::Proved);
    assert!(not_proved(&passed_by(BTreeMap::new())));

    // A mask a later block drops from a sum of a register a byte load
    // assigned: the blocks agree alone only knowing the register keeps
    // within a byte, which no differing expression says, the sum being
    // computed in the block.
    let byte = Expr::Load {
        addr: Box::new(Expr::Const(0x4000)),
        width: 1,
        signed: false,
    };
    let within = |load: Expr| {
        let sum = || assign(2, plus(1, 1));
        let application = application(
            vec![
                block(0, vec![assign(1, load.clone()), br(1)]),
                block(
                    1,
                    vec![sum(), ret(raw_bin(BinOp::And, r(2), Expr::Const(0x1ff)))],
                ),
            ],
            vec![
                block(0, vec![assign(1, load), br(1)]),
                block(1, vec![sum(), ret(r(2))]),
            ],
        );
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(within(byte.clone()));
    // A load of two bytes does not keep within one.
    let Expr::Load { addr, .. } = byte else {
        unreachable!()
    };
    assert!(!within(Expr::Load {
        addr,
        width: 2,
        signed: false,
    }));

    // A register a call clobbers, read to keep its upper bits beside a new
    // low byte and then stored: the rewrite reads an undefined value in its
    // place, which may be what the call left.
    let kept = |undefined: bool| {
        let low = |upper: Expr| {
            raw_bin(
                BinOp::Or,
                raw_bin(BinOp::And, upper, Expr::Const(!0xff)),
                Expr::Const(1),
            )
        };
        let upper = if undefined {
            Expr::Apply {
                op: crate::ir::Operation::Undefined,
                args: Vec::new(),
            }
        } else {
            r(2)
        };
        let stored = |value: Expr| {
            vec![
                call(),
                assign(1, value),
                store(Expr::Const(0x4000), r(1)),
                ret(Expr::Const(0)),
            ]
        };
        verdict(
            vec![block(0, stored(low(r(1))))],
            vec![block(0, stored(low(upper)))],
        )
    };
    assert_eq!(kept(true), Verdict::Proved);
    // An expression in its place is no choice.
    assert!(not_proved(&kept(false)));

    // The same undefined upper bits folded away, as `simplify` takes an
    // undefined value as zero; a different low byte is no such choice.
    let folded = |byte: u64| {
        let undefined = Expr::Apply {
            op: crate::ir::Operation::Undefined,
            args: Vec::new(),
        };
        let stored = |value: Expr| {
            vec![
                assign(1, value),
                store(Expr::Const(0x4000), r(1)),
                ret(Expr::Const(0)),
            ]
        };
        verdict(
            vec![block(
                0,
                stored(raw_bin(
                    BinOp::Or,
                    raw_bin(BinOp::And, undefined, Expr::Const(!0xff)),
                    Expr::Const(1),
                )),
            )],
            vec![block(0, stored(Expr::Const(byte)))],
        )
    };
    assert_eq!(folded(1), Verdict::Proved);
    assert!(not_proved(&folded(2)));

    // The register read in a later block than the call that left it, on
    // every path; with a path that sets it first, it is no choice.
    let later = |set: bool| {
        let read = |upper: Expr| {
            vec![
                assign(
                    1,
                    raw_bin(
                        BinOp::Or,
                        raw_bin(BinOp::And, upper, Expr::Const(!0xff)),
                        Expr::Const(1),
                    ),
                ),
                store(Expr::Const(0x4000), r(1)),
                ret(Expr::Const(0)),
            ]
        };
        let first = |set: bool| {
            let mut stmts = vec![call()];
            if set {
                stmts.push(Stmt::Brif {
                    at: None,
                    cond: Cond::Eq,
                    lhs: r(2),
                    rhs: Expr::Const(0),
                    target: 2,
                });
            }
            stmts.push(br(1));
            stmts
        };
        let setting = block(2, vec![assign(1, r(3)), br(1)]);
        let undefined = Expr::Apply {
            op: crate::ir::Operation::Undefined,
            args: Vec::new(),
        };
        verdict(
            vec![block(0, first(set)), block(1, read(r(1))), setting.clone()],
            vec![block(0, first(set)), block(1, read(undefined)), setting],
        )
    };
    assert_eq!(later(false), Verdict::Proved);
    assert!(not_proved(&later(true)));

    // A loop counter counting from zero while below 16, which leaves the
    // loop at 16: the blocks agree alone that it is 16 there only knowing
    // it stays at or below the bound the branch compares it with.
    let counted = |returned: u64| {
        let blocks = |last: Expr| {
            vec![
                block(0, vec![assign(1, Expr::Const(0)), br(10)]),
                block(
                    10,
                    vec![Stmt::Brif {
                        at: None,
                        cond: Cond::Cc,
                        lhs: r(1),
                        rhs: Expr::Const(16),
                        target: 20,
                    }],
                ),
                block(30, vec![ret(last)]),
                block(20, vec![assign(1, plus(1, 1)), br(10)]),
            ]
        };
        let application = application(blocks(r(1)), blocks(Expr::Const(returned)));
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(counted(16));
    assert!(!counted(15));

    // The counter copied when the loop ends and then overwritten: a later
    // block drops a mask from a sum it computes from the copy only knowing
    // the copy keeps the counter's bound.
    let copied = |mask: u64| {
        let blocks = |last: Expr| {
            vec![
                block(0, vec![assign(1, Expr::Const(0)), br(10)]),
                block(
                    10,
                    vec![Stmt::Brif {
                        at: None,
                        cond: Cond::Cc,
                        lhs: r(1),
                        rhs: Expr::Const(16),
                        target: 20,
                    }],
                ),
                block(
                    30,
                    vec![assign(2, r(1)), assign(1, Expr::Const(99)), br(40)],
                ),
                block(40, vec![assign(3, plus(2, 1)), ret(last)]),
                block(20, vec![assign(1, plus(1, 1)), br(10)]),
            ]
        };
        let application = application(
            blocks(raw_bin(BinOp::And, r(3), Expr::Const(mask))),
            blocks(r(3)),
        );
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(copied(0x1f));
    assert!(!copied(0xf));

    // A 32-bit load masked to its low 32 bits twice, in two blocks, where
    // the rewrite keeps the load alone in another register: the blocks
    // agree only joining the masked registers to the loaded one.
    let extended = |mask: u64| {
        let load = Expr::Load {
            addr: Box::new(Expr::Const(0x4000)),
            width: 4,
            signed: false,
        };
        let before = vec![
            block(
                0,
                vec![
                    assign(1, load.clone()),
                    assign(2, raw_bin(BinOp::And, r(1), Expr::Const(mask))),
                    br(10),
                ],
            ),
            block(
                10,
                vec![
                    assign(3, raw_bin(BinOp::And, r(2), Expr::Const(0xffff_ffff))),
                    br(20),
                ],
            ),
            block(20, vec![ret(r(3))]),
        ];
        let after = vec![
            block(0, vec![assign(5, load), br(10)]),
            block(10, vec![br(20)]),
            block(20, vec![ret(r(5))]),
        ];
        let application = application(before, after);
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(extended(0xffff_ffff));
    assert!(!extended(0xffff));

    // A byte stored after two paths that each leave the register's low
    // byte zero, one testing it and one setting it: the store's block
    // agrees alone that the byte is zero only from the low bits.
    let zero_byte = |stored: u64| {
        let blocks = |value: Expr| {
            vec![
                block(
                    0,
                    vec![Stmt::Brif {
                        at: None,
                        cond: Cond::Eq,
                        lhs: raw_bin(BinOp::And, r(0), Expr::Const(0xff)),
                        rhs: Expr::Const(0),
                        target: 20,
                    }],
                ),
                block(10, vec![assign(0, Expr::Const(0)), br(20)]),
                block(
                    20,
                    vec![
                        Stmt::Store {
                            at: None,
                            addr: Expr::Const(0x4000),
                            value,
                            width: 1,
                        },
                        ret(Expr::Const(0)),
                    ],
                ),
            ]
        };
        let application = application(blocks(r(0)), blocks(Expr::Const(stored)));
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(zero_byte(0));
    assert!(!zero_byte(1));

    // A value past a signed check that it is at least 4 and then at most 4
    // unsigned: the last block agrees alone that it is 4 only knowing the
    // signed bound the first branch leaves.
    let pinned = |returned: u64| {
        let branch = |cond, target| Stmt::Brif {
            at: None,
            cond,
            lhs: r(1),
            rhs: Expr::Const(4),
            target,
        };
        let blocks = |last: Expr| {
            vec![
                block(0, vec![branch(Cond::Lt, 40)]),
                block(10, vec![branch(Cond::Ls, 20)]),
                block(15, vec![ret(Expr::Const(0))]),
                block(20, vec![ret(last)]),
                block(40, vec![ret(Expr::Const(0))]),
            ]
        };
        let application = application(blocks(r(1)), blocks(Expr::Const(returned)));
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(pinned(4));
    assert!(!pinned(3));

    // A 32-bit load a branch checks is not negative as a 32-bit value: a
    // later block sets the low bit of its low 32 bits and drops the sign
    // extension only knowing the check's bound; setting the sign bit
    // instead is no such rewrite.
    let nonnegative = |bit: u64| {
        let blocks = |last: Expr| {
            vec![
                block(
                    0,
                    vec![
                        assign(
                            1,
                            Expr::Load {
                                addr: Box::new(Expr::Const(0x4000)),
                                width: 4,
                                signed: false,
                            },
                        ),
                        Stmt::Brif {
                            at: None,
                            cond: Cond::Lt,
                            lhs: raw_bin(BinOp::And, r(1), Expr::Const(0xffff_ffff)),
                            rhs: Expr::Const(0),
                            target: 40,
                        },
                    ],
                ),
                block(10, vec![br(20)]),
                block(
                    20,
                    vec![
                        assign(2, raw_bin(BinOp::Or, Expr::reg(1, 32), Expr::Const(bit))),
                        ret(last),
                    ],
                ),
                block(40, vec![ret(Expr::Const(0))]),
            ]
        };
        let application = application(
            blocks(Expr::SignExtend {
                value: Box::new(r(2)),
                width: 4,
            }),
            blocks(r(2)),
        );
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(nonnegative(1));
    assert!(!nonnegative(0x8000_0000));

    // The same with the low bit set on the whole register: dropping the
    // sign extension also needs the load's upper 32 bits zero, which on an
    // architecture with 64-bit addresses a 32-bit mask candidate says.
    let loaded32 = |bit: u64| {
        let blocks = |last: Expr| {
            vec![
                block(
                    0,
                    vec![
                        assign(
                            1,
                            Expr::Load {
                                addr: Box::new(Expr::Const(0x4000)),
                                width: 4,
                                signed: false,
                            },
                        ),
                        Stmt::Brif {
                            at: None,
                            cond: Cond::Lt,
                            lhs: raw_bin(BinOp::And, r(1), Expr::Const(0xffff_ffff)),
                            rhs: Expr::Const(0),
                            target: 40,
                        },
                    ],
                ),
                block(10, vec![br(20)]),
                block(
                    20,
                    vec![
                        assign(1, raw_bin(BinOp::Or, r(1), Expr::Const(bit))),
                        ret(last),
                    ],
                ),
                block(40, vec![ret(Expr::Const(0))]),
            ]
        };
        let application = application(
            blocks(Expr::SignExtend {
                value: Box::new(r(1)),
                width: 4,
            }),
            blocks(r(1)),
        );
        let product = Product::new(&application).expect("a product");
        let mut solver = Solver::start().expect("z3");
        product
            .equations(
                &application,
                &mut solver,
                &[(Strategy::WordLevel, 50_000_000)],
                false,
            )
            .failed
            .is_none()
    };
    assert!(loaded32(1));
    assert!(!loaded32(0x8000_0000));

    // A value left in x8 before a call that reads it as a result address
    // unless the callee's summary says it takes none.
    let scratch = |without: BTreeSet<u64>| {
        let mut calling = call();
        if let Stmt::Call { convention, .. } = &mut calling {
            *convention = Convention::Aapcs64;
        }
        let mut application = Application {
            site: "test",
            tag: String::new(),
            index: 0,
            before: vec![
                block(0, vec![assign(8, Expr::Const(5)), calling.clone()]),
                block(1, vec![ret(Expr::Const(0))]),
            ],
            after: vec![block(0, vec![calling]), block(1, vec![ret(Expr::Const(0))])],
            landing_pads: false,
            narrow_stack: None,
            stack_entries: Default::default(),
            private_frame: None,
            frames: None,
            convention: crate::ir::Convention::SysV,
            entry_alignment: None,
            returned: Some(64),
            narrow_results: BTreeSet::new(),
            without_result_address: BTreeSet::new(),
            scratch_reads: BTreeMap::new(),
            narrow_registers: BTreeSet::new(),
            entry_pairs: BTreeMap::new(),
        };
        application.without_result_address = without;
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(scratch([0x2000].into()), Verdict::Proved);
    assert!(not_proved(&scratch(BTreeSet::new())));

    // A division by zero the rewrite makes, though nothing reads it.
    assert!(not_proved(&verdict(
        vec![block(0, vec![ret(r(0))])],
        vec![block(
            0,
            vec![
                assign(2, raw_bin(BinOp::DivU, r(0), Expr::Const(0))),
                ret(r(0))
            ]
        )],
    )));
}

#[test]
fn narrow_stores_and_masks_suggest_equations_of_their_bits() {
    let stored = Stmt::Store {
        at: None,
        addr: Expr::Const(0x1000),
        value: r(10),
        width: 1,
    };
    let masked = ret(raw_bin(BinOp::And, r(1), Expr::Const(0xffff)));
    let blocks = vec![block(0, vec![stored, masked])];
    let found = candidates(&application(blocks.clone(), blocks));
    for (index, width) in [(10, 8), (1, 16)] {
        assert!(
            found.contains(&(Expr::reg(index, width), Expr::reg(index, width))),
            "r{index} at {width} bits: {found:?}"
        );
    }
    assert!(!found.contains(&(Expr::reg(10, 16), Expr::reg(10, 16))));

    // Through the operations whose low bits their operands' low bits
    // decide, and through assignments; not through a shift right.
    let blocks = vec![block(
        0,
        vec![
            assign(2, raw_bin(BinOp::And, r(0), Expr::Const(0xffff_ffff))),
            assign(5, raw_bin(BinOp::Shr, r(6), Expr::Const(8))),
            Stmt::Store {
                at: None,
                addr: Expr::Const(0x1000),
                value: raw_bin(BinOp::Add, r(2), raw_bin(BinOp::Xor, r(3), r(5))),
                width: 1,
            },
            ret(Expr::Const(0)),
        ],
    )];
    let found = candidates(&application(blocks.clone(), blocks));
    for index in [0, 2, 3, 5] {
        assert!(
            found.contains(&(Expr::reg(index, 8), Expr::reg(index, 8))),
            "r{index} at 8 bits: {found:?}"
        );
    }
    assert!(!found.contains(&(Expr::reg(6, 8), Expr::reg(6, 8))));
}

#[test]
fn a_load_after_stores_to_other_bytes_suggests_an_equation_at_the_entry() {
    let load = |addr: Expr| Expr::Load {
        addr: Box::new(addr),
        width: 8,
        signed: false,
    };
    // The block stores, then returns what one side loads and the other
    // side holds in a register.
    let proposed = |first: Stmt| {
        let blocks = |returned: Expr| {
            vec![block(
                0,
                vec![first.clone(), store(plus(4, 16), r(1)), ret(returned)],
            )]
        };
        let found = candidates(&application(blocks(load(plus(4, 8))), blocks(r(0))));
        found.contains(&(load(plus(4, 8)), r(0)))
    };
    assert!(proposed(store(plus(4, 0), r(2))));
    assert!(!proposed(store(plus(4, 12), r(2))));
    assert!(!proposed(store(r(5), r(2))));
    assert!(!proposed(call()));
    assert!(!proposed(assign(4, plus(4, -16))));
}

#[test]
fn a_difference_after_an_assignment_suggests_an_equation_over_the_entry_values() {
    // The shift count is at most 52 past the branch, so the test of it
    // against 64 is dropped; the count is assigned in the block itself.
    let count = raw_bin(BinOp::Sub, Expr::Const(1075), r(1));
    let shifted = |count: Expr| raw_bin(BinOp::Shl, Expr::Const(1), count);
    let tested = |count: Expr| Expr::Select {
        cond: Cond::Cc,
        lhs: Box::new(count.clone()),
        rhs: Box::new(Expr::Const(64)),
        then: Box::new(shifted(raw_bin(BinOp::And, count, Expr::Const(63)))),
        els: Box::new(Expr::Const(0)),
    };
    let blocks = |bound: u64, value: Expr| {
        vec![
            block(
                0,
                vec![Stmt::Brif {
                    at: None,
                    cond: Cond::Cs,
                    lhs: raw_bin(BinOp::Sub, r(1), Expr::Const(1023)),
                    rhs: Expr::Const(bound),
                    target: 2,
                }],
            ),
            block(1, vec![assign(1, count.clone()), assign(0, value)]),
            block(2, vec![ret(r(0))]),
        ]
    };
    let found = candidates(&application(
        blocks(52, tested(r(1))),
        blocks(52, shifted(r(1))),
    ));
    assert!(
        found.contains(&(tested(count.clone()), shifted(count.clone()))),
        "{found:?}"
    );
    assert!(matches!(
        verdict(blocks(52, tested(r(1))), blocks(52, shifted(r(1)))),
        Verdict::Proved
    ));
    // A count that may reach 64 leaves the two apart.
    assert!(not_proved(&verdict(
        blocks(5000, tested(r(1))),
        blocks(5000, shifted(r(1)))
    )));

    // A register written by a call, or read in part, is not followed.
    let after_call = |value: Expr| vec![block(0, vec![assign(1, r(2)), call(), ret(value)])];
    let found = candidates(&application(
        after_call(plus(1, 1)),
        after_call(raw_bin(BinOp::Sub, r(1), Expr::Const(u64::MAX))),
    ));
    assert!(
        !found.iter().any(|(old, _)| *old == plus(2, 1)),
        "{found:?}"
    );
    // Nor is one assigned an operation the solver has no meaning for.
    let divided = Expr::Apply {
        op: crate::ir::Operation::WideDivide {
            signed: false,
            remainder: false,
            bits: 16,
        },
        args: vec![r(2), r(3), r(5)],
    };
    let after_division = |value: Expr| vec![block(0, vec![assign(1, divided.clone()), ret(value)])];
    let found = candidates(&application(
        after_division(plus(1, 1)),
        after_division(raw_bin(BinOp::Sub, r(1), Expr::Const(u64::MAX))),
    ));
    assert!(
        found.iter().all(|(old, new)| {
            crate::ir::smt::validate::unmodeled(old).is_none()
                && crate::ir::smt::validate::unmodeled(new).is_none()
        }),
        "{found:?}"
    );
    let narrow = |value: Expr| vec![block(0, vec![assign(1, r(2)), ret(value)])];
    let low = raw_bin(BinOp::Add, Expr::reg(1, 32), Expr::Const(1));
    let found = candidates(&application(
        narrow(low.clone()),
        narrow(raw_bin(BinOp::Sub, Expr::reg(1, 32), Expr::Const(u64::MAX))),
    ));
    assert!(
        !found.iter().any(|(old, _)| *old == plus(2, 1)),
        "{found:?}"
    );
    assert!(!found.iter().any(|(old, _)| *old == low), "{found:?}");
}

#[test]
fn a_register_replaced_by_a_constant_suggests_that_it_holds_the_constant() {
    // A loop multiplies by a register set before it; the rewrite puts the
    // constant in its place and drops a mask the product then needs not.
    let low = |value: Expr| raw_bin(BinOp::And, value, Expr::Const(0xffff_ffff));
    let digits = raw_bin(BinOp::And, r(2), Expr::Const(0x3fff));
    let original = low(raw_bin(BinOp::Mul, digits.clone(), low(r(15))));
    let rewritten = raw_bin(BinOp::Mul, digits, Expr::Const(0x147b));
    let blocks = |set: u64, product: Expr| {
        vec![
            block(0, vec![assign(15, Expr::Const(set))]),
            block(
                1,
                vec![
                    assign(2, raw_bin(BinOp::Shr, product, Expr::Const(17))),
                    Stmt::Brif {
                        at: None,
                        cond: Cond::Ne,
                        lhs: r(2),
                        rhs: Expr::Const(0),
                        target: 1,
                    },
                ],
            ),
            block(2, vec![ret(r(2))]),
        ]
    };
    let found = candidates(&application(
        blocks(0x147b, original.clone()),
        blocks(0x147b, rewritten.clone()),
    ));
    assert!(found.contains(&(r(15), Expr::Const(0x147b))), "{found:?}");
    assert!(matches!(
        verdict(
            blocks(0x147b, original.clone()),
            blocks(0x147b, rewritten.clone())
        ),
        Verdict::Proved
    ));
    assert!(not_proved(&verdict(
        blocks(0x147c, original.clone()),
        blocks(0x147c, rewritten)
    )));
    // A register still read where it was is not proposed.
    let found = candidates(&application(
        blocks(0x147b, original.clone()),
        blocks(0x147b, low(original)),
    ));
    assert!(!found.contains(&(r(15), Expr::Const(0x147b))), "{found:?}");
}

#[test]
fn a_register_one_side_lacks_is_put_over_the_entry_values() {
    // A loop counts in a register that holds a byte; the rewrite drops the
    // copy that masks it and reads the counter itself.
    let byte = |value: Expr| raw_bin(BinOp::And, value, Expr::Const(0xff));
    let load = Expr::Load {
        addr: Box::new(plus(4, 0x17)),
        width: 1,
        signed: false,
    };
    let scaled = |index: u16| raw_bin(BinOp::Shl, r(index), Expr::Const(4));
    let blocks = |next: Expr, copied: bool| {
        let mut body = vec![Stmt::Store {
            at: None,
            addr: plus(4, 0x17),
            value: raw_bin(BinOp::Add, r(10), Expr::Const(1)),
            width: 1,
        }];
        if copied {
            body.push(assign(11, byte(r(10))));
        }
        body.push(store(plus(4, 0x20), scaled(if copied { 11 } else { 10 })));
        body.push(assign(10, next));
        body.push(Stmt::Brif {
            at: None,
            cond: Cond::Ne,
            lhs: byte(r(10)),
            rhs: Expr::Const(4),
            target: 1,
        });
        vec![
            block(0, vec![assign(10, Expr::Const(0))]),
            block(1, body),
            block(2, vec![ret(Expr::Const(0))]),
        ]
    };
    let found = candidates(&application(
        blocks(load.clone(), true),
        blocks(load.clone(), false),
    ));
    assert!(found.contains(&(byte(r(10)), r(10))), "{found:?}");
    assert!(matches!(
        verdict(blocks(load.clone(), true), blocks(load, false)),
        Verdict::Proved
    ));
    // A counter that may pass a byte is not the masked copy.
    let wide = Expr::Load {
        addr: Box::new(plus(4, 0x17)),
        width: 4,
        signed: false,
    };
    assert!(not_proved(&verdict(
        blocks(wide.clone(), true),
        blocks(wide, false)
    )));
}

#[test]
fn a_reply_with_an_error_decides_nothing_and_leaves_the_next_reply_its_own() {
    if !crate::ir::smt::z3_available("solver replies") {
        return;
    }
    let mut solver = Solver::start().expect("z3");
    let undeclared = "(declare-const x (_ BitVec 8))\n(assert (= y #x00))\n";
    assert!(matches!(
        solver.answer(undeclared, 1_000_000, Strategy::WordLevel, &["x"]),
        Reply::Unknown(_)
    ));
    let refuted = "(declare-const x (_ BitVec 8))\n(assert (= x (bvadd x #x01)))\n";
    assert!(matches!(
        solver.answer(refuted, 1_000_000, Strategy::WordLevel, &[]),
        Reply::Unsat
    ));
    let held = "(declare-const p Bool)\n(assert p)\n";
    assert!(matches!(
        solver.answer(held, 1_000_000, Strategy::WordLevel, &["p"]),
        Reply::Sat(values) if values == [true]
    ));
}

#[test]
fn a_time_limit_leaves_what_it_cuts_short_undecided_and_never_refuted() {
    if !crate::ir::smt::z3_available("time limit") {
        return;
    }
    let renamed = |k| {
        application(
            vec![
                block(0, vec![assign(10, plus(0, 1)), br(1)]),
                block(1, vec![ret(r(10))]),
            ],
            vec![
                block(0, vec![assign(11, plus(0, k)), br(1)]),
                block(1, vec![ret(r(11))]),
            ],
        )
    };
    let limited = |application: &Application, seconds| {
        check_measured(application, 50_000_000, 1_000_000_000, seconds).0
    };
    // Time enough changes neither verdict.
    for seconds in [None, Some(600)] {
        assert_eq!(limited(&renamed(1), seconds), Verdict::Proved);
        assert!(not_proved(&limited(&renamed(2), seconds)));
    }
    // With none, the rewrite that holds and the one that does not are both
    // undecided, and say why.
    for k in [1, 2] {
        let Verdict::Unknown { reason, .. } = limited(&renamed(k), Some(0)) else {
            panic!("a verdict without time for a query");
        };
        assert_eq!(reason, "time limit of 0 s");
    }
    // What needs no query is decided all the same.
    let mut unwinding = renamed(1);
    unwinding.landing_pads = true;
    assert!(matches!(
        limited(&unwinding, Some(0)),
        Verdict::Unchecked(_)
    ));
}

#[test]
fn a_solver_past_its_deadline_stops_a_running_query_and_asks_no_more() {
    if !crate::ir::smt::z3_available("solver deadline") {
        return;
    }
    let easy = "(declare-const x (_ BitVec 8))\n(assert (= x (bvadd x #x01)))\n";
    // That a product of remainders has the remainder of the product,
    // without a limit on solver work: far longer than the test waits.
    let hard = "(declare-const a (_ BitVec 64))\n(declare-const b (_ BitVec 64))\n\
        (declare-const c (_ BitVec 64))\n\
        (assert (bvult a #x0000000100000000))\n(assert (bvult b #x0000000100000000))\n\
        (assert (bvult #x0000000000000001 c))\n\
        (assert (distinct (bvurem (bvmul (bvurem a c) (bvurem b c)) c) (bvurem (bvmul a b) c)))\n";
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(2);
    let mut solver = Solver::start_until(Some(deadline)).expect("z3");
    assert!(!solver.expired());
    assert!(matches!(
        solver.answer(easy, 1_000_000, Strategy::WordLevel, &[]),
        Reply::Unsat
    ));
    assert!(matches!(
        solver.answer(hard, u64::from(u32::MAX), Strategy::WordLevel, &[]),
        Reply::Unknown(_)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    assert!(solver.expired());
    assert!(matches!(
        solver.answer(easy, 1_000_000, Strategy::WordLevel, &[]),
        Reply::Unknown(reason) if reason == "time limit"
    ));
    assert!(matches!(
        solver.horn("(check-sat)", 1_000_000),
        Reply::Unknown(reason) if reason == "time limit"
    ));
    // Without a deadline none passes.
    assert!(!Solver::start().expect("z3").expired());
}

#[test]
fn a_solver_past_its_memory_leaves_the_query_undecided_and_answers_the_next() {
    if !crate::ir::smt::z3_available("solver memory") {
        return;
    }
    let easy = "(declare-const x (_ BitVec 8))\n(assert (= x (bvadd x #x01)))\n";
    // z3 takes more than this for the remainders of 64-bit products.
    let hard = "(declare-const a (_ BitVec 64))\n(declare-const b (_ BitVec 64))\n\
        (declare-const c (_ BitVec 64))\n\
        (assert (distinct (bvurem (bvmul (bvurem a c) (bvurem b c)) c) (bvurem (bvmul a b) c)))\n";
    let started = std::time::Instant::now();
    let mut solver = Solver::start_within(None, Some(20)).expect("z3");
    assert!(matches!(
        solver.answer(hard, u64::from(u32::MAX), Strategy::WordLevel, &[]),
        Reply::Unknown(_)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    assert!(matches!(
        solver.answer(easy, 1_000_000, Strategy::WordLevel, &[]),
        Reply::Unsat
    ));
}
