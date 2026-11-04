use std::process::Command;

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
        private_frame: None,
        fixed_frame: false,
        convention: crate::ir::Convention::SysV,
        entry_alignment: None,
        returned: Some(64),
        narrow_results: BTreeSet::new(),
        without_result_address: BTreeSet::new(),
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
            private_frame: None,
            fixed_frame: false,
            convention: crate::ir::Convention::SysV,
            entry_alignment: None,
            returned,
            narrow_results,
            without_result_address: BTreeSet::new(),
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
            private_frame: None,
            fixed_frame: false,
            convention: crate::ir::Convention::SysV,
            entry_alignment: alignment.map(|alignment| (4, alignment)),
            returned: Some(64),
            narrow_results: BTreeSet::new(),
            without_result_address: BTreeSet::new(),
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
    if Command::new("z3").arg("-version").output().is_err() {
        eprintln!("SKIP product validation: z3 unavailable");
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
    let go = |caller: Convention, through: bool| {
        let slot = raw_bin(BinOp::Add, r(4), Expr::Const(16));
        let address = if through { r(5) } else { slot.clone() };
        let mut calling = call();
        if let Stmt::Call {
            args, convention, ..
        } = &mut calling
        {
            *args = Some(vec![Expr::Const(0); 3]);
            *convention = Convention::GoAmd64;
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
        application.private_frame = Some(4);
        application.convention = caller;
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(go(Convention::GoAmd64, false), Verdict::Proved);
    assert!(not_proved(&go(Convention::SysV, false)));
    assert!(not_proved(&go(Convention::GoAmd64, true)));

    // A frame slot read back past an atomic, which writes nothing below the
    // stack pointer of a function that never moves it.
    let atomic = |fixed: bool| {
        let slot = raw_bin(BinOp::Add, r(4), Expr::Const(-16i64 as u64));
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
        let mut application = application(
            vec![block(
                0,
                vec![
                    store.clone(),
                    exchange.clone(),
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
                vec![store, exchange, assign(2, Expr::Const(7)), ret(r(2))],
            )],
        );
        application.private_frame = Some(4);
        application.fixed_frame = fixed;
        check(&application, 50_000_000, 1_000_000_000)
    };
    assert_eq!(atomic(true), Verdict::Proved);
    assert!(not_proved(&atomic(false)));

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
                private_frame: None,
                fixed_frame: false,
                convention: crate::ir::Convention::SysV,
                entry_alignment: None,
                returned: Some(64),
                narrow_results: BTreeSet::new(),
                without_result_address: BTreeSet::new(),
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
                private_frame: None,
                fixed_frame: false,
                convention: crate::ir::Convention::SysV,
                entry_alignment: None,
                returned: Some(64),
                narrow_results: BTreeSet::new(),
                without_result_address: BTreeSet::new(),
                narrow_registers: if narrow { [13].into() } else { BTreeSet::new() },
                entry_pairs: BTreeMap::new(),
            },
            50_000_000,
            1_000_000_000,
        )
    };
    assert_eq!(framed32(true), Verdict::Proved);
    assert!(not_proved(&framed32(false)));

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
            private_frame: None,
            fixed_frame: false,
            convention: crate::ir::Convention::SysV,
            entry_alignment: None,
            returned: Some(64),
            narrow_results: BTreeSet::new(),
            without_result_address: BTreeSet::new(),
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
fn a_reply_with_an_error_decides_nothing_and_leaves_the_next_reply_its_own() {
    if Command::new("z3").arg("-version").output().is_err() {
        eprintln!("SKIP solver replies: z3 unavailable");
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
