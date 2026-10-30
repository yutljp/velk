//! Independently rebuild SSA after renaming and check for unrelated local definitions.
#[path = "../../../../tests/common/mod.rs"]
mod common;

use crate as velk;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use velk::ir::{BinOp, Expr, FunctionIr, RegRef, Stmt, VALUE_BASE, VARIABLE_BASE};
use velk::service::Binary;

#[test]
fn instruction_origins_do_not_change_exception_site_matching() {
    let call = Stmt::Call {
        at: Some(0x10),
        kind: velk::ir::CallKind::Invoke,
        target: Some(0x30),
        through: None,
        convention: velk::ir::Convention::SysV,
        args: Some(Vec::new()),
        floats_named: true,
        abi: None,
        outputs: Vec::new(),
        clobbers: None,
        via: None,
    };
    let original = vec![super::exception_statement(&call)];
    let mut moved = call;
    moved.set_origin(Some(0x20));
    assert!(super::matches_exception_site(
        std::slice::from_ref(&moved),
        &original
    ));
    let Stmt::Call { target, .. } = &mut moved else {
        panic!("call remains a call");
    };
    *target = Some(0x40);
    assert!(!super::matches_exception_site(
        std::slice::from_ref(&moved),
        &original
    ));
}

#[test]
fn coalesced_copy_is_removed_from_the_rendered_statements() {
    let source = VARIABLE_BASE;
    let copy = source + 1;
    let copy_next = source + 2;
    let copy_last = source + 3;
    let result = source + 4;
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
        at: None,
    };
    let ir = FunctionIr::single_block(
        velk::loader::Isa::X86_64,
        vec![
            assign(source, Expr::Const(19)),
            assign(copy, Expr::reg(source, 64)),
            assign(copy_next, Expr::reg(copy, 64)),
            assign(copy_last, Expr::reg(copy_next, 64)),
            assign(
                result,
                Expr::bin(BinOp::Add, Expr::reg(copy_last, 64), Expr::Const(5)),
            ),
            Stmt::Ret {
                value: Expr::reg(result, 64),
                at: None,
            },
        ],
    );
    let mut nodes = crate::render::structure::structure_best(&ir);
    let lowered = super::split_variables(&ir, &mut nodes);

    for stmt in lowered.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = velk::ir::visit::statement_registers(stmt);
        assert!(
            ![copy, copy_next, copy_last]
                .iter()
                .any(|value| writes.contains(value) || reads.contains(value))
        );
    }
    for node in &nodes {
        let crate::render::structure::Node::Stmt(stmt) = node else {
            continue;
        };
        let (writes, reads) = velk::ir::visit::statement_registers(stmt);
        assert!(
            ![copy, copy_next, copy_last]
                .iter()
                .any(|value| writes.contains(value) || reads.contains(value))
        );
    }
}

fn root(parent: &mut [usize], mut value: usize) -> usize {
    while parent[value] != value {
        parent[value] = parent[parent[value]];
        value = parent[value];
    }
    value
}

fn join(parent: &mut [usize], a: u16, b: u16) {
    let a = root(parent, usize::from(a - VALUE_BASE));
    let b = root(parent, usize::from(b - VALUE_BASE));
    parent[a] = b;
}

struct Webs {
    unrelated: BTreeMap<u16, usize>,
    phis: usize,
    bindings: usize,
    unknown_successor_variables: usize,
}

fn webs(ir: &FunctionIr) -> Webs {
    let printed_types = crate::render::variable_types(ir);
    let ssa = velk::ssa::build(ir).expect("fixture fits SSA value indices");
    let mut parent: Vec<usize> = (0..ssa.origin.len()).collect();
    let mut needed = HashSet::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        for operand in stmt.operands() {
            velk::ir::visit::collect_reads(operand, &mut needed);
        }
    }
    for reads in ssa.implicit_reads.values() {
        needed.extend(reads.iter().map(|(_, value)| *value));
    }
    // Only live phis impose a relationship. Copies also carry the same value
    // between names; arithmetic and storage reuse do not.
    loop {
        let before = needed.len();
        for phi in ssa.phis.iter().flatten() {
            if needed.contains(&phi.value) {
                needed.extend(&phi.args);
            }
        }
        if needed.len() == before {
            break;
        }
    }
    let mut phi_joins = 0;
    for phi in ssa.phis.iter().flatten() {
        if needed.contains(&phi.value) {
            for arg in &phi.args {
                join(&mut parent, phi.value, *arg);
            }
            phi_joins += 1;
        }
    }
    let mut reads_by_definition = HashMap::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, .. } = stmt {
            let mut reads = HashSet::new();
            for operand in stmt.operands() {
                velk::ir::visit::collect_reads(operand, &mut reads);
            }
            reads_by_definition.insert(dest.index, reads.into_iter().collect::<Vec<_>>());
        }
    }
    for phi in ssa.phis.iter().flatten() {
        reads_by_definition.insert(phi.value, phi.args.clone());
    }
    for phi in ssa.phis.iter().flatten() {
        let origin = ssa.register_of(phi.value);
        if (origin < VARIABLE_BASE && !ir.params.iter().any(|param| param.index == origin))
            || !needed.contains(&phi.value)
        {
            continue;
        }
        let mut pending = vec![phi.value];
        let mut visited = HashSet::new();
        while let Some(value) = pending.pop() {
            if !visited.insert(value) || ssa.register_of(value) != origin {
                continue;
            }
            join(&mut parent, phi.value, value);
            if let Some(reads) = reads_by_definition.get(&value) {
                pending.extend(reads);
            }
        }
    }
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign {
            dest,
            value: Expr::Bin { .. },
            ..
        } = stmt
            && dest.width >= crate::arch::pointer_bytes(ir.isa) * 8
        {
            let origin = ssa.register_of(dest.index);
            if origin < VARIABLE_BASE
                && ir
                    .params
                    .iter()
                    .any(|param| param.index == origin && !param.ty.is_pointer())
            {
                for operand in stmt.operands() {
                    let mut reads = HashSet::new();
                    velk::ir::visit::collect_reads(operand, &mut reads);
                    for value in reads {
                        if ssa.register_of(value) == origin {
                            join(&mut parent, dest.index, value);
                        }
                    }
                }
            }
        }
        if let Stmt::Assign {
            dest,
            value: Expr::Reg { index, width },
            ..
        } = stmt
            && *width >= crate::arch::pointer_bytes(ir.isa) * 8
            && dest.width >= crate::arch::pointer_bytes(ir.isa) * 8
        {
            join(&mut parent, dest.index, *index);
        }
        if let Stmt::Assign {
            dest,
            value:
                Expr::Bin {
                    op: velk::ir::BinOp::And | velk::ir::BinOp::Or | velk::ir::BinOp::Xor,
                    ..
                },
            ..
        } = stmt
            && dest.width >= crate::arch::pointer_bytes(ir.isa) * 8
        {
            let origin = ssa.register_of(dest.index);
            if origin < VARIABLE_BASE
                || ir
                    .value_types
                    .get(&origin)
                    .is_some_and(velk::ir::CType::is_pointer)
                || ir.pointer_values.contains(&origin)
                || ir
                    .structures
                    .iter()
                    .any(|structure| structure.elements.contains(&origin))
            {
                continue;
            }
            for operand in stmt.operands() {
                let mut reads = HashSet::new();
                velk::ir::visit::collect_reads(operand, &mut reads);
                for value in reads {
                    if ssa.register_of(value) == origin {
                        join(&mut parent, dest.index, value);
                    }
                }
            }
        }
        if let Stmt::Assign {
            dest,
            value:
                Expr::Bin {
                    op: velk::ir::BinOp::Add | velk::ir::BinOp::Sub,
                    lhs,
                    rhs,
                },
            ..
        } = stmt
            && dest.width >= crate::arch::pointer_bytes(ir.isa) * 8
            && let (
                Expr::Reg {
                    index,
                    width: 32 | 64,
                },
                Expr::Const(_),
            ) = (lhs.as_ref(), rhs.as_ref())
        {
            let origin = ssa.register_of(dest.index);
            if ssa.register_of(*index) == origin
                && (printed_types
                    .get(&origin)
                    .is_some_and(velk::ir::CType::is_pointer)
                    || ir
                        .params
                        .iter()
                        .any(|param| param.index == origin && param.ty.is_pointer()))
            {
                join(&mut parent, dest.index, *index);
            }
        }
    }
    let mut definitions: BTreeMap<u16, BTreeSet<usize>> = BTreeMap::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        let mut stmt = stmt.clone();
        for dest in velk::ir::visit::statement_destinations_mut(&mut stmt) {
            let origin = ssa.register_of(dest.index);
            let local = origin >= VARIABLE_BASE
                || (velk::arch::machine_registers().contains(&origin)
                    && origin != velk::arch::stack_pointer(ir.isa)
                    && origin != velk::arch::frame_pointer(ir.isa));
            if local && needed.contains(&dest.index) {
                definitions
                    .entry(origin)
                    .or_default()
                    .insert(root(&mut parent, usize::from(dest.index - VALUE_BASE)));
            }
        }
    }
    let bound_values = ssa
        .entry
        .values()
        .copied()
        .chain(
            ssa.implicit_reads
                .values()
                .flatten()
                .map(|(_, value)| *value),
        )
        .chain(
            ssa.implicit_writes
                .values()
                .flatten()
                .map(|(_, value)| *value),
        )
        .chain(
            ssa.ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .flat_map(Stmt::call_outputs)
                .map(|output| output.dest.index),
        );
    let mut bound: BTreeMap<u16, HashSet<usize>> = BTreeMap::new();
    for value in bound_values {
        bound
            .entry(ssa.register_of(value))
            .or_default()
            .insert(root(&mut parent, usize::from(value - VALUE_BASE)));
    }
    let unknown_successors = ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::BrIndirect { .. } | Stmt::Br { target: None, .. }
        )
    });
    let mut unrelated = BTreeMap::new();
    let fixed: HashSet<u16> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(Stmt::call_outputs)
        .map(|output| output.register)
        .collect();
    let mut bindings = 0;
    let mut unknown_successor_variables = 0;
    for (variable, roots) in definitions {
        if roots.len() < 2 {
            continue;
        }
        // Implicit ABI operands must retain their physical register binding.
        if unknown_successors {
            unknown_successor_variables += 1;
        } else if variable < VARIABLE_BASE
            && (fixed.contains(&variable)
                || (ir.declared_signature.is_some()
                    && ir.params.iter().any(|param| param.index == variable))
                || bound
                    .get(&variable)
                    .is_some_and(|bound| roots.iter().all(|root| bound.contains(root))))
        {
            bindings += 1;
        } else {
            unrelated.insert(variable, roots.len());
        }
    }
    Webs {
        unrelated,
        phis: phi_joins,
        bindings,
        unknown_successor_variables,
    }
}

#[test]
fn fixture_variables_keep_unrelated_webs_separate() {
    let fixtures = common::fixtures();
    let results = common::in_parallel(&fixtures, |fixture| {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let functions: Vec<_> = binary.image().functions.values().cloned().collect();
        let group = common::fixture_group(fixture, binary.image());
        let mut count = 0;
        let mut before = 0;
        let mut phis = 0;
        let mut bindings = 0;
        let mut unknown_successor_variables = 0;
        let mut details = String::new();
        for function in functions {
            let Ok(analysis) = binary.analysis(function.addr, None) else {
                continue;
            };
            before += webs(&analysis.ir).unrelated.len();
            let mut nodes = crate::render::structure::structure_best(&analysis.ir);
            let ir = super::split_variables(&analysis.ir, &mut nodes);
            let found = webs(&ir);
            count += found.unrelated.len();
            phis += found.phis;
            bindings += found.bindings;
            unknown_successor_variables += found.unknown_successor_variables;
            for (variable, roots) in found.unrelated {
                writeln!(
                    details,
                    "{} {:#x} {}: {roots} webs",
                    fixture.display(),
                    function.addr,
                    velk::ir::reg_name(analysis.ir.isa, variable, 64)
                )
                .unwrap();
                for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
                    if velk::ir::visit::statement_registers(stmt)
                        .0
                        .contains(&variable)
                    {
                        writeln!(details, "  {stmt:?}").unwrap();
                    }
                }
            }
        }
        (
            fixture.clone(),
            group,
            count,
            before,
            phis,
            bindings,
            unknown_successor_variables,
            details,
        )
    });
    let mut totals: BTreeMap<&str, (usize, usize, usize, usize, usize)> = BTreeMap::new();
    let mut details = String::new();
    for (fixture, group, count, before, phis, bindings, unknown_successor_variables, found) in
        results
    {
        writeln!(
            details,
            "# {} | {group}: {before} -> {count}; {phis}; {bindings}; {unknown_successor_variables}",
            fixture.display()
        )
        .unwrap();
        let total = totals.entry(group).or_default();
        total.0 += count;
        total.1 += phis;
        total.2 += bindings;
        total.3 += unknown_successor_variables;
        total.4 += before;
        details.push_str(&found);
    }
    let count: usize = totals.values().map(|(count, _, _, _, _)| count).sum();
    let mut report = String::from(
        "# group: variables with unrelated webs before -> after splitting; live phi joins; fixed register bindings; variables with unknown successors\n",
    );
    for (group, (count, phis, bindings, unknown_successor_variables, before)) in totals {
        writeln!(
            report,
            "{group}: {before} -> {count}; {phis}; {bindings}; {unknown_successor_variables}"
        )
        .unwrap();
    }
    report.push_str(&details);
    print!("{report}");
    assert_eq!(
        count, 0,
        "unrelated SSA webs share a printed local\n{report}"
    );
    if let Some(difference) = common::check_expected(
        &common::root().join("tests/golden/variable_webs.txt"),
        &report,
    ) {
        panic!("{difference}");
    }
}

#[test]
fn a_formal_register_does_not_hide_storage_reuse() {
    let mut binary = Binary::open(&common::fixtures_dir().join("alt.o")).unwrap();
    let mut ir = binary.analysis(0, None).unwrap().ir.clone();
    ir.params = vec![velk::ir::Param {
        index: 6,
        name: "input".into(),
        ty: velk::ir::CType::U64,
    }];
    let assign = |value| Stmt::Assign {
        dest: velk::ir::RegRef {
            index: 6,
            width: 64,
        },
        value: Expr::Const(value),
        at: None,
    };
    ir.blocks = vec![velk::ir::Block {
        start: 0,
        stmts: vec![
            assign(7),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(6, 64),
                width: 8,
                at: None,
            },
            assign(9),
            Stmt::Ret {
                value: Expr::reg(6, 64),
                at: None,
            },
        ],
    }];
    assert_eq!(webs(&ir).unrelated.get(&6), Some(&2));
    let mut nodes = crate::render::structure::structure_best(&ir);
    let separated = super::split_variables(&ir, &mut nodes);
    assert!(webs(&separated).unrelated.is_empty());
}

#[test]
fn distinguishes_storage_reuse_from_phi_and_loop_values() {
    use velk::ir::{BinOp, Block, Cond, RegRef};

    let variable = VARIABLE_BASE;
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: variable,
            width: 64,
        },
        value,
        at: None,
    };
    let mut binary = Binary::open(&common::fixtures_dir().join("alt.o")).unwrap();
    let mut ir = binary.analysis(0, None).unwrap().ir.clone();
    ir.blocks = vec![Block {
        start: 0,
        stmts: vec![
            assign(Expr::Const(7)),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(variable, 64),
                width: 8,
                at: None,
            },
            assign(Expr::Const(9)),
            Stmt::Ret {
                value: Expr::reg(variable, 64),
                at: None,
            },
        ],
    }];
    assert_eq!(webs(&ir).unrelated.get(&variable), Some(&2));
    ir.blocks[0].stmts = vec![
        Stmt::Assign {
            dest: RegRef {
                index: variable,
                width: 32,
            },
            value: Expr::reg(0, 32),
            at: None,
        },
        Stmt::Store {
            addr: Expr::reg(7, 64),
            value: Expr::reg(variable, 64),
            width: 8,
            at: None,
        },
        assign(Expr::reg(0, 64)),
        Stmt::Ret {
            value: Expr::reg(variable, 64),
            at: None,
        },
    ];
    assert_eq!(webs(&ir).unrelated.get(&variable), Some(&2));
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(6, 64),
                rhs: Expr::Const(0),
                target: 0x20,
                at: None,
            }],
        },
        Block {
            start: 0x10,
            stmts: vec![
                assign(Expr::Const(7)),
                Stmt::Br {
                    target: Some(0x30),
                    at: None,
                },
            ],
        },
        Block {
            start: 0x20,
            stmts: vec![assign(Expr::Const(9))],
        },
        Block {
            start: 0x30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(variable, 64),
                at: None,
            }],
        },
    ];
    assert!(webs(&ir).unrelated.is_empty());
    assert!(webs(&ir).phis > 0);
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![assign(Expr::Const(0))],
        },
        Block {
            start: 0x10,
            stmts: vec![
                assign(Expr::bin(
                    BinOp::Add,
                    Expr::reg(variable, 64),
                    Expr::Const(1),
                )),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(variable, 64),
                    rhs: Expr::reg(6, 64),
                    target: 0x10,
                    at: None,
                },
            ],
        },
        Block {
            start: 0x20,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(variable, 64),
                at: None,
            }],
        },
    ];
    assert!(webs(&ir).unrelated.is_empty());
    assert!(webs(&ir).phis > 0);
}

#[test]
fn implicit_call_operands_keep_their_register_binding() {
    use velk::ir::{CallKind, Convention, RegRef};

    let mut binary = Binary::open(&common::fixtures_dir().join("alt.o")).unwrap();
    let mut ir = binary.analysis(0, None).unwrap().ir.clone();
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: 8,
            width: 64,
        },
        value: Expr::Const(value),
        at: None,
    };
    let call = Stmt::Call {
        kind: CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: Convention::Aapcs64,
        args: None,
        floats_named: false,
        abi: None,
        clobbers: None,
        outputs: velk::ir::fallback_call_outputs(Convention::Aapcs64, None),
        via: None,
        at: None,
    };
    ir.blocks[0].stmts = vec![
        assign(0x2000),
        call.clone(),
        assign(0x3000),
        call,
        Stmt::Ret {
            value: Expr::Const(0),
            at: None,
        },
    ];
    let found = webs(&ir);
    assert!(found.unrelated.is_empty());
    assert_eq!(found.bindings, 1);
    ir.blocks[0].stmts = vec![
        Stmt::Assign {
            dest: RegRef {
                index: 8,
                width: 64,
            },
            value: Expr::reg(0, 64),
            at: None,
        },
        Stmt::Store {
            addr: Expr::reg(1, 64),
            value: Expr::reg(8, 64),
            width: 8,
            at: None,
        },
        Stmt::Assign {
            dest: RegRef {
                index: 8,
                width: 64,
            },
            value: Expr::reg(2, 64),
            at: None,
        },
        Stmt::Ret {
            value: Expr::reg(8, 64),
            at: None,
        },
    ];
    let found = webs(&ir);
    assert_eq!(found.unrelated.get(&8), Some(&2));
    assert_eq!(found.bindings, 0);
    ir.blocks[0].stmts[3] = Stmt::BrIndirect {
        target: Expr::reg(8, 64),
        at: None,
    };
    let found = webs(&ir);
    assert!(found.unrelated.is_empty());
    assert_eq!(found.unknown_successor_variables, 1);
}

#[test]
fn disconnected_exception_returns_read_the_assigned_local() {
    let mut binary = Binary::open(&common::fixtures_dir().join("seh.O2.dll")).unwrap();
    let address = binary.find("seh_nested").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    let returns: HashSet<_> = code
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("return "))
        .collect();
    assert_eq!(returns.len(), 1, "{code}");
    let returned = returns.iter().next().unwrap().trim_start_matches("return ");
    let variable = returned.trim_end_matches(';');
    assert!(code.contains(&format!("{variable} = v1;")), "{code}");
}
