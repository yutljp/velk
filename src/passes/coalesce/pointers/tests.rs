use super::*;
use crate::ir::{Access, BinOp, Convention, Param, RegRef, Structure};
use crate::loader::Isa;

const FIRST: u16 = VARIABLE_BASE;
const SECOND: u16 = VARIABLE_BASE + 1;

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    }
}

fn store(index: u16, width: u8) -> Stmt {
    Stmt::Store {
        addr: Expr::reg(index, 64),
        value: Expr::Const(7),
        width,
    }
}

fn pointers() -> FunctionIr {
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(
                FIRST,
                Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(8)),
            ),
            store(FIRST, 8),
            assign(
                SECOND,
                Expr::bin(BinOp::Add, Expr::reg(1, 64), Expr::Const(16)),
            ),
            assign(
                SECOND,
                Expr::bin(BinOp::Add, Expr::reg(SECOND, 64), Expr::Const(8)),
            ),
            store(SECOND, 8),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    ir.params = ["src", "dst"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| Param {
            index: index as u16,
            name: name.to_owned(),
            ty: CType::pointer_to(CType::int(1, false)),
        })
        .collect();
    ir.variable_registers = [(FIRST, 9), (SECOND, 9)].into_iter().collect();
    ir
}

fn call(args: Option<Vec<Expr>>) -> Stmt {
    Stmt::Call {
        target: Some(0x1000),
        through: None,
        convention: Convention::Aapcs64,
        args,
        floats_named: true,
        clobbers: None,
        outputs: Vec::new(),
        via: None,
    }
}

fn assert_separate(mut ir: FunctionIr) {
    let before = crate::render::render(&ir, &[], &Default::default(), &[]);
    let origins = ir.variable_registers.clone();
    reuse_pointers(&mut ir);
    assert_eq!(
        crate::render::render(&ir, &[], &Default::default(), &[]),
        before
    );
    assert!(before.contains("v2"), "{before}");
    assert_eq!(ir.variable_registers, origins);
}

#[test]
fn disjoint_pointers_share_a_declaration_and_keep_element_steps() {
    let mut ir = pointers();
    ir.pointer_values = vec![FIRST, SECOND];
    ir.value_types.insert(SECOND, CType::pointer_to(CType::U64));
    ir.accesses.push(Access {
        register: SECOND,
        fields: vec![(0, CType::U64)],
    });
    ir.structures.push(Structure {
        name: "unused".to_owned(),
        fields: vec![(0, CType::U64)],
        size: Some(8),
        elements: vec![SECOND],
    });
    // A recovered array type applies equally to both lifetimes.
    ir.structures[0].elements.push(FIRST);
    reuse_pointers(&mut ir);
    let text = crate::render::render(&ir, &[], &Default::default(), &[]);
    assert!(!text.contains("v2"), "{text}");
    assert_eq!(ir.variable_registers.len(), 1);
    assert!(!ir.value_types.contains_key(&SECOND));
    assert_eq!(ir.pointer_values, [FIRST]);
    assert_eq!(ir.accesses[0].register, FIRST);
    assert_eq!(ir.structures[0].elements, [FIRST]);

    let mut scalar = pointers();
    reuse_pointers(&mut scalar);
    let text = crate::render::render(&scalar, &[], &Default::default(), &[]);
    assert!(text.contains("uint64_t *v1;"), "{text}");
    assert!(!text.contains("v2"), "{text}");
    assert!(text.contains("v1 = v1 + 0x1;"), "{text}");
}

#[test]
fn simultaneous_pointer_values_stay_separate() {
    let mut ir = pointers();
    ir.blocks[0].stmts.insert(5, store(FIRST, 8));
    assert_separate(ir);
}

#[test]
fn different_element_widths_and_integer_values_stay_separate() {
    let mut ir = pointers();
    ir.blocks[0].stmts[4] = store(SECOND, 1);
    assert_separate(ir);
    let mut ir = pointers();
    ir.blocks[0].stmts[5] = Stmt::Ret {
        value: Expr::bin(BinOp::Mul, Expr::reg(SECOND, 64), Expr::Const(2)),
    };
    assert_separate(ir);
}

#[test]
fn different_structure_layouts_stay_separate() {
    let mut ir = pointers();
    for (variable, name, size) in [(FIRST, "small", 8), (SECOND, "large", 16)] {
        ir.structures.push(Structure {
            name: name.to_owned(),
            fields: vec![(0, CType::U64)],
            size: Some(size),
            elements: vec![variable],
        });
    }
    assert_separate(ir);
}

#[test]
fn different_origins_and_unknown_layouts_stay_separate() {
    let mut ir = pointers();
    ir.variable_registers.insert(FIRST, 10);
    assert_separate(ir);
    let mut ir = pointers();
    ir.blocks[0].stmts[1] = assign(FIRST, Expr::reg(0, 64));
    ir.blocks[0].stmts[4] = assign(SECOND, Expr::reg(1, 64));
    ir.pointer_values = vec![FIRST, SECOND];
    assert_separate(ir);
}

#[test]
fn partial_writes_and_reads_stay_separate() {
    for width in [8, 16, 32] {
        let mut ir = pointers();
        if let Stmt::Assign { dest, .. } = &mut ir.blocks[0].stmts[2] {
            dest.width = width;
        }
        assert_separate(ir);
        let mut ir = pointers();
        ir.blocks[0].stmts[5] = Stmt::Ret {
            value: Expr::reg(SECOND, width),
        };
        assert_separate(ir);
    }
}

#[test]
fn full_width_masks_and_merges_cannot_reuse_declared_structure_pointers() {
    for mask in [0xff, 0xff00, 0xffff, 0xffff_ffff] {
        let mut ir = pointers();
        ir.isa = Isa::X86_64;
        let ty = CType::pointer_to(CType::Named("struct item".to_owned()));
        ir.structures.push(Structure {
            name: "item".to_owned(),
            fields: vec![(0, CType::U64)],
            size: Some(8),
            elements: Vec::new(),
        });
        ir.value_types = [(FIRST, ty.clone()), (SECOND, ty)].into_iter().collect();
        let value = if mask == 0xffff_ffff {
            Expr::bin(BinOp::And, Expr::reg(SECOND, 64), Expr::Const(mask))
        } else {
            Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::And, Expr::reg(SECOND, 64), Expr::Const(!mask)),
                Expr::Const(mask),
            )
        };
        ir.blocks[0].stmts[3] = assign(SECOND, value);
        let types = crate::render::variable_types(&ir);
        assert_eq!(types[&FIRST], types[&SECOND]);
        assert!(types[&SECOND].is_pointer());
        assert_separate(ir);
    }
}

#[test]
fn call_arguments_results_and_implicit_reads_stay_separate() {
    let mut ir = pointers();
    ir.blocks[0]
        .stmts
        .insert(2, call(Some(vec![Expr::reg(FIRST, 64)])));
    assert_separate(ir);
    let mut ir = pointers();
    ir.variable_registers = [(FIRST, 0), (SECOND, 0)].into_iter().collect();
    ir.blocks[0].stmts.insert(2, call(None));
    assert_separate(ir);
    let mut ir = pointers();
    let mut result = call(Some(Vec::new()));
    if let Stmt::Call { outputs, .. } = &mut result {
        outputs.push(crate::ir::CallOutput {
            register: 9,
            dest: RegRef {
                index: SECOND,
                width: 64,
            },
        });
    }
    ir.blocks[0].stmts[2] = result;
    assert_separate(ir);
}

#[test]
fn exception_edges_and_unknown_control_flow_prevent_reuse() {
    for pad in [0x20, 0x100] {
        let mut ir = pointers();
        ir.blocks[0].stmts.insert(2, call(Some(Vec::new())));
        ir.blocks.push(crate::ir::Block {
            start: 0x20,
            stmts: vec![
                store(FIRST, 8),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        });
        ir.landing_pads.push((pad, vec![(0, 0x10)]));
        assert_separate(ir);
    }
    let mut ir = pointers();
    ir.blocks[0].stmts.push(Stmt::Br { target: None });
    assert_separate(ir);
}

#[test]
fn entry_values_cannot_be_joined_even_through_a_non_entry_leader() {
    let mut ir = pointers();
    ir.blocks[0]
        .stmts
        .splice(0..0, [store(FIRST, 8), store(SECOND, 8)]);
    assert_separate(ir);
    let mut groups = Groups::default();
    let entry = [SECOND, SECOND + 1].into_iter().collect();
    let interferes = HashMap::new();
    assert!(groups.join(FIRST, SECOND, &interferes, &entry));
    assert!(!groups.join(FIRST, SECOND + 1, &interferes, &entry));
}
