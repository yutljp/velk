use super::*;
use crate::ir::{CallKind, Convention, Expr, FunctionIr, RegRef, Stmt};
use crate::loader::Isa;

fn declaration_for(profile: AbiProfile, count: usize) -> Arc<CallDeclaration> {
    let layout = crate::ir::abi::TypeLayout {
        size: 8,
        alignment: Some(8),
        kind: crate::ir::abi::LayoutKind::Integer,
        trivial: true,
    };
    Arc::new(CallDeclaration {
        signature: DeclaredSignature {
            params: (0..count).map(|i| (format!("a{i}"), CType::U64)).collect(),
            ret: CType::U64,
            variadic: false,
            abi: crate::analysis::abi::allocate(
                profile,
                &vec![layout.clone(); count],
                Some(&layout),
            ),
        },
        sources: Vec::new(),
    })
}

fn call(dependencies: Vec<u16>, memory: bool) -> Stmt {
    Stmt::Call {
        kind: CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: Convention::Aapcs64,
        args: Some(Vec::new()),
        floats_named: true,
        outputs: Vec::new(),
        clobbers: Some(Default::default()),
        via: None,
        abi: Some(crate::ir::calls::test_call_abi(dependencies, memory)),
    }
}

#[test]
fn scalar_bindings_preserve_abi_stack_coordinates() {
    for (profile, isa, convention, registers, first_stack) in [
        (AbiProfile::SysV, Isa::X86_64, Convention::SysV, 6, 8),
        (AbiProfile::Win64, Isa::X86_64, Convention::Win64, 4, 40),
        (AbiProfile::Aapcs64, Isa::AArch64, Convention::Aapcs64, 8, 0),
    ] {
        let sp = crate::arch::stack_pointer(isa);
        for kind in [CallKind::Invoke, CallKind::Tail] {
            let fallback = CallFallback::Implicit {
                floats_named: false,
            };
            let bound = input_binding(
                declaration_for(profile, registers + 2),
                42,
                kind,
                isa,
                convention,
                sp,
                fallback,
            )
            .unwrap();
            assert_eq!(bound.kind, kind);
            assert_eq!(bound.target, 42);
            assert_eq!(bound.convention, convention);
            assert_eq!(bound.fallback, fallback);
            assert!(bound.hidden_result.is_none());
            assert!(bound.deferred_memory);
            assert!(bound.dependencies.contains(&sp));
            let expected = kind.stack_offset(isa, convention, first_stack).unwrap();
            for (i, argument) in bound.arguments.iter().enumerate() {
                let CallInput::Direct(pieces) = argument else {
                    panic!("direct scalar")
                };
                assert_eq!(pieces.len(), 1);
                assert_eq!(pieces[0].object_offset, 0);
                if i < registers {
                    assert_eq!(
                        pieces[0].source,
                        CallTransport::Register {
                            register: convention.arguments()[i],
                            bytes: 8
                        }
                    );
                } else {
                    assert_eq!(
                        pieces[0].source,
                        CallTransport::Stack {
                            offset: expected + ((i - registers) * 8) as i64,
                            bytes: 8
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn bindings_refuse_syscalls_wrong_isa_and_wrong_stack_pointer() {
    let record = declaration_for(AbiProfile::SysV, 1);
    let fallback = CallFallback::Named {
        count: 1,
        floats_named: true,
    };
    for (kind, isa, convention, sp) in [
        (
            CallKind::Syscall,
            Isa::X86_64,
            Convention::SysV,
            crate::arch::stack_pointer(Isa::X86_64),
        ),
        (
            CallKind::Invoke,
            Isa::AArch64,
            Convention::SysV,
            crate::arch::stack_pointer(Isa::AArch64),
        ),
        (
            CallKind::Invoke,
            Isa::X86_64,
            Convention::Win64,
            crate::arch::stack_pointer(Isa::X86_64),
        ),
        (CallKind::Invoke, Isa::X86_64, Convention::SysV, 0),
    ] {
        assert!(input_binding(record.clone(), 42, kind, isa, convention, sp, fallback).is_err());
    }
}

#[test]
fn declared_reads_survive_copy_folding_and_ssa_demand() {
    let register = Convention::Aapcs64.arguments()[0];
    let stmt = call(vec![register], false);
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: register,
                    width: 64,
                },
                value: Expr::Const(7),
            },
            stmt,
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    crate::passes::copies::inline_local_copies(&mut ir);
    assert!(matches!(ir.blocks[0].stmts[0], Stmt::Assign { .. }));
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            call(vec![register], false),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    let demands = crate::ssa::entry_demands(&ir, &[0]).unwrap();
    assert_eq!(demands.get(&register), Some(&u64::MAX));
}

#[test]
fn deferred_call_memory_keeps_frame_store() {
    let sp = crate::arch::stack_pointer(Isa::AArch64);
    let store = Stmt::Store {
        addr: Expr::bin(crate::ir::BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8)),
        value: Expr::Const(123),
        width: 8,
    };
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            store,
            call(vec![sp], true),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    crate::passes::frame::drop_dead_frame_stores(&mut ir);
    assert!(matches!(ir.blocks[0].stmts[0], Stmt::Store { .. }));
}

#[test]
fn fixture_declarations_are_cached() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/metrics/integers.aarch64.O0.debug.elf");
    let binary = crate::service::Binary::open(&path).unwrap();
    let image = binary.image();
    let mut count = 0;
    for function in image.functions.values() {
        let Ok(Some(record)) = declaration(image, function.addr) else {
            continue;
        };
        assert!(Arc::ptr_eq(
            &record,
            &declaration(image, function.addr).unwrap().unwrap()
        ));
        assert!(!record.sources.is_empty());
        let source = &record.sources[0];
        assert_eq!(
            source.source.parameters.len(),
            record.signature.params.len()
        );
        for id in &source.required_types {
            assert!(source.graph.types.contains_key(id));
        }
        for id in &source.required_definitions {
            assert!(source.graph.definitions.contains_key(id));
        }
        count += 1;
    }
    assert!(count > 0);
    assert!(declaration(image, u64::MAX).unwrap().is_none());
}

#[test]
fn attachment_skips_unknown_callee_without_changing_call() {
    let image = Image::from_code(Isa::AArch64, 0, Vec::new());
    let mut stmt = call(Vec::new(), false);
    if let Stmt::Call { abi, .. } = &mut stmt {
        *abi = None;
    }
    let mut ir = FunctionIr::single_block(Isa::AArch64, vec![stmt]);
    let before = format!("{:?}", ir.blocks);
    attach_outputs(&image, &mut ir.blocks);
    attach_inputs(&image, &mut ir.blocks);
    assert_eq!(format!("{:?}", ir.blocks), before);
}

mod declarations {
    use super::*;
    use crate::ir::CType;
    use crate::ir::abi::{LayoutField, LayoutKind, TypeLayout};
    use crate::ir::calls::{CallType, TypeGraph};
    use crate::loader::Isa;
    use crate::loader::dwarf::FunctionTypes;

    fn source(unit: u64, die: usize) -> TypeSource {
        TypeSource { unit, die }
    }

    fn typed_unit(unit: u64, aggregate: bool, field: &str) -> (TypeSource, Arc<CallUnit>) {
        let integer = TypeLayout {
            size: 8,
            alignment: Some(8),
            kind: LayoutKind::Integer,
            trivial: true,
        };
        let layout = if aggregate {
            TypeLayout {
                kind: LayoutKind::Struct(vec![LayoutField {
                    bit_offset: 0,
                    bit_size: None,
                    defined: true,
                    layout: integer.clone(),
                }]),
                ..integer.clone()
            }
        } else {
            integer
        };
        let ty = if aggregate {
            CType::Named("struct shared".to_owned())
        } else {
            CType::U64
        };
        let root = source(unit, 1);
        let function = source(unit, 2);
        let types = FunctionTypes {
            globals: Vec::new(),
            locals: Vec::new(),
            registers: Vec::new(),
            params: vec![(Some("value".to_owned()), Some(ty.clone()))],
            ret: Some(ty.clone()),
            ret_aggregate_size: aggregate.then_some(8),
            param_aggregate_sizes: vec![aggregate.then_some(8)],
            variadic: false,
            members: Vec::new(),
            definitions: Vec::new(),
            param_layouts: vec![Ok(layout.clone())],
            ret_layout: Ok(Some(layout.clone())),
            abi_profile: Ok(AbiProfile::Aapcs64),
            source: FunctionSource {
                function,
                parameters: vec![Some(root)],
                result: Some(root),
            },
        };
        let mut found = CallUnit::default();
        found.functions.insert(function, Ok(types));
        let mut graph = TypeGraph::default();
        graph.types.insert(
            root,
            CallType {
                tag: if aggregate {
                    gimli::DW_TAG_structure_type.0
                } else {
                    gimli::DW_TAG_base_type.0
                },
                name: aggregate.then(|| "shared".to_owned()),
                layout: Ok(layout),
                dimensions: Vec::new(),
                enumerators: Vec::new(),
                spelling: Some(ty),
                size: Some(8),
                encoding: (!aggregate).then_some(u16::from(gimli::DW_ATE_unsigned.0)),
                references: Vec::new(),
                members: Vec::new(),
                complete: true,
                pointer: false,
                aggregate,
            },
        );
        if aggregate {
            graph.definitions.insert(
                root,
                Definition {
                    name: "struct shared".to_owned(),
                    members: vec![format!("uint64_t {field};")],
                    fields: vec![field.to_owned()],
                    contains: Vec::new(),
                    size: 8,
                    alignment: Some(8),
                    compatible_profiles: vec![AbiProfile::Aapcs64],
                },
            );
        }
        found.graph = Arc::new(graph);
        (function, Arc::new(found))
    }

    #[test]
    fn generated_member_comparison_follows_source_types_and_gap_extents() {
        let (_, mut left) = typed_unit(0, true, "value");
        let (_, mut right) = typed_unit(32, true, "value");
        for (unit, id) in [(&mut left, 0), (&mut right, 32)] {
            let graph = Arc::get_mut(&mut Arc::get_mut(unit).unwrap().graph).unwrap();
            graph.generated_members.insert(
                source(id, 1),
                vec![CallMember::Bytes {
                    offset: 0,
                    bytes: 8,
                }],
            );
        }
        let call_source = |unit: &Arc<CallUnit>, id| CallSource {
            source: FunctionSource {
                function: source(id, 2),
                parameters: vec![Some(source(id, 1))],
                result: Some(source(id, 1)),
            },
            graph: unit.graph.clone(),
            required_types: vec![source(id, 1)],
            required_definitions: vec![source(id, 1)],
        };
        assert!(same_types(&call_source(&left, 0), &call_source(&right, 32)));
        Arc::get_mut(&mut Arc::get_mut(&mut right).unwrap().graph)
            .unwrap()
            .generated_members
            .insert(
                source(32, 1),
                vec![CallMember::Bytes {
                    offset: 0,
                    bytes: 7,
                }],
            );
        assert!(!same_types(
            &call_source(&left, 0),
            &call_source(&right, 32)
        ));
        for (unit, id) in [(&mut left, 0), (&mut right, 32)] {
            let (_, mut scalar) = typed_unit(id, false, "");
            let scalar = Arc::get_mut(&mut Arc::get_mut(&mut scalar).unwrap().graph)
                .unwrap()
                .types
                .remove(&source(id, 1))
                .unwrap();
            let graph = Arc::get_mut(&mut Arc::get_mut(unit).unwrap().graph).unwrap();
            graph.types.insert(source(id, 3), scalar);
            graph.generated_members.insert(
                source(id, 1),
                vec![CallMember::Field {
                    name: "value".to_owned(),
                    ty: source(id, 3),
                    offset: 0,
                    bytes: graph.types[&source(id, 3)].layout.as_ref().unwrap().size,
                }],
            );
        }
        assert!(same_types(&call_source(&left, 0), &call_source(&right, 32)));
        Arc::get_mut(&mut Arc::get_mut(&mut right).unwrap().graph)
            .unwrap()
            .types
            .get_mut(&source(32, 3))
            .unwrap()
            .encoding = Some(5);
        assert!(!same_types(
            &call_source(&left, 0),
            &call_source(&right, 32)
        ));
    }

    fn seeded_image(candidates: &[(u64, TypeSource, Arc<CallUnit>)]) -> Image {
        let image = Image::from_code(Isa::AArch64, 0, Vec::new());
        let mut index = CallIndex::default();
        for (address, source, unit) in candidates {
            index.addresses.entry(*address).or_default().push(*source);
            let cell = Arc::new(OnceLock::new());
            cell.set(Ok(unit.clone())).expect("new unit cell");
            image
                .call_declarations
                .units
                .lock()
                .unwrap()
                .insert(source.unit, cell);
        }
        image
            .call_declarations
            .index
            .set(Ok(index))
            .expect("new index");
        image
    }

    #[test]
    fn declarations_at_distinct_addresses_share_the_same_unit_graph() {
        let (first_id, mut unit) = typed_unit(0, true, "word");
        let second_id = source(0, 3);
        let mut second = unit.functions[&first_id].as_ref().unwrap().clone();
        second.source.function = second_id;
        Arc::get_mut(&mut unit)
            .unwrap()
            .functions
            .insert(second_id, Ok(second));
        let image = seeded_image(&[(0x1000, first_id, unit.clone()), (0x2000, second_id, unit)]);
        let first = declaration(&image, 0x1000).unwrap().unwrap();
        let second = declaration(&image, 0x2000).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(
            &first.sources[0].graph,
            &second.sources[0].graph
        ));
        assert_eq!(first.sources[0].source.function, first_id);
        assert_eq!(second.sources[0].source.function, second_id);
        assert_eq!(
            first.sources[0].required_definitions,
            second.sources[0].required_definitions
        );
    }

    #[test]
    fn a_declaration_outlives_the_image_without_retaining_the_parser_table() {
        let (id, unit) = typed_unit(0, true, "word");
        let parser = Arc::downgrade(&unit);
        let graph = Arc::downgrade(&unit.graph);
        let image = seeded_image(&[(0x1000, id, unit)]);
        let declaration = declaration(&image, 0x1000).unwrap().unwrap();
        drop(image);
        assert!(parser.upgrade().is_none());
        let retained = &declaration.sources[0];
        assert!(Arc::ptr_eq(&graph.upgrade().unwrap(), &retained.graph));
        let ty = retained.required_types[0];
        assert_eq!(retained.graph.types[&ty].name.as_deref(), Some("shared"));
        let definition = retained.required_definitions[0];
        assert_eq!(retained.graph.definitions[&definition].fields, vec!["word"]);
        assert!(declaration.signature.abi.is_ok());
        drop(declaration);
        assert!(graph.upgrade().is_none());
    }

    #[test]
    fn identical_source_offsets_in_different_images_keep_distinct_graphs() {
        let (first_id, first_unit) = typed_unit(0, true, "left");
        let (second_id, second_unit) = typed_unit(0, true, "right");
        let first_image = seeded_image(&[(0x1000, first_id, first_unit)]);
        let second_image = seeded_image(&[(0x1000, second_id, second_unit)]);
        let first = declaration(&first_image, 0x1000).unwrap().unwrap();
        let second = declaration(&second_image, 0x1000).unwrap().unwrap();
        assert_eq!(
            first.sources[0].required_types,
            second.sources[0].required_types
        );
        assert!(!Arc::ptr_eq(
            &first.sources[0].graph,
            &second.sources[0].graph
        ));
        assert!(!same_types(&first.sources[0], &second.sources[0]));
    }

    #[test]
    fn go_rejection_does_not_build_the_dwarf_index() {
        let mut image = Image::from_code(Isa::X86_64, 0, Vec::new());
        image.go = true;
        for _ in 0..2 {
            assert!(matches!(
                declaration(&image, 0x1000),
                Err(AbiIssue::UnsupportedProfile)
            ));
        }
        assert!(image.call_declarations.index.get().is_none());
        assert!(image.call_declarations.units.lock().unwrap().is_empty());
        assert_eq!(image.call_declarations.addresses.lock().unwrap().len(), 1);
    }

    #[test]
    fn missing_declarations_are_cached_without_type_units() {
        let image = Image::from_code(Isa::AArch64, 0, Vec::new());
        for _ in 0..2 {
            assert!(declaration(&image, 0x1000).unwrap().is_none());
        }
        assert!(
            image
                .call_declarations
                .index
                .get()
                .unwrap()
                .as_ref()
                .unwrap()
                .addresses
                .is_empty()
        );
        assert!(image.call_declarations.units.lock().unwrap().is_empty());
        assert_eq!(image.call_declarations.addresses.lock().unwrap().len(), 1);
    }

    #[test]
    fn scalar_calls_reuse_allocation_without_changing_entry_admission() {
        let (id, unit) = typed_unit(0, false, "word");
        assert!(crate::analysis::abi::declaration(unit.functions[&id].as_ref().unwrap()).is_none());
        let image = seeded_image(&[(0x1000, id, unit)]);
        let first = declaration(&image, 0x1000).unwrap().unwrap();
        let second = declaration(&image, 0x1000).unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.signature.params.len(), 1);
        assert!(first.signature.abi.is_ok());
    }

    #[test]
    fn equivalent_candidates_keep_distinct_source_identities() {
        let (a, first) = typed_unit(0, true, "word");
        let (b, second) = typed_unit(100, true, "word");
        let image = seeded_image(&[(0x1000, a, first), (0x1000, b, second)]);
        let declaration = declaration(&image, 0x1000).unwrap().unwrap();
        assert_eq!(declaration.sources.len(), 2);
        assert_ne!(
            declaration.sources[0].required_types,
            declaration.sources[1].required_types
        );
        assert!(!Arc::ptr_eq(
            &declaration.sources[0].graph,
            &declaration.sources[1].graph
        ));
    }

    #[test]
    fn same_address_conflicting_definitions_are_rejected_and_cached() {
        let (a, first) = typed_unit(0, true, "left");
        let (b, second) = typed_unit(100, true, "right");
        let image = seeded_image(&[(0x1000, a, first), (0x1000, b, second)]);
        for _ in 0..2 {
            assert!(matches!(
                declaration(&image, 0x1000),
                Err(AbiIssue::IncompatibleDefinition)
            ));
        }
        assert_eq!(image.call_declarations.addresses.lock().unwrap().len(), 1);
    }

    #[test]
    fn identical_tag_spelling_at_different_addresses_does_not_merge_types() {
        let (a, first) = typed_unit(0, true, "left");
        let (b, second) = typed_unit(100, true, "right");
        let image = seeded_image(&[(0x1000, a, first), (0x2000, b, second)]);
        let first = declaration(&image, 0x1000).unwrap().unwrap();
        let second = declaration(&image, 0x2000).unwrap().unwrap();
        assert_ne!(
            first.sources[0].required_types,
            second.sources[0].required_types
        );
        assert_eq!(first.signature.params[0].1, second.signature.params[0].1);
    }
    #[test]
    fn range_only_candidates_do_not_become_a_missing_declaration() {
        let image = Image::from_code(Isa::AArch64, 0, Vec::new());
        image
            .call_declarations
            .index
            .set(Ok(CallIndex {
                addresses: Default::default(),
                unresolved_ranges: std::iter::once(0x1000..0x1010).collect(),
            }))
            .expect("new index");
        assert!(matches!(
            declaration(&image, 0x1000),
            Err(AbiIssue::UnknownLayout)
        ));
        assert!(declaration(&image, 0x1010).unwrap().is_none());
        assert!(image.call_declarations.units.lock().unwrap().is_empty());
    }

    #[test]
    fn unsupported_profiles_skip_the_dwarf_index() {
        let image = Image::from_code(Isa::Unsupported, 0, Vec::new());
        assert!(matches!(
            declaration(&image, 0x1000),
            Err(AbiIssue::UnsupportedProfile)
        ));
        assert!(image.call_declarations.index.get().is_none());
        assert!(image.call_declarations.units.lock().unwrap().is_empty());
    }

    #[test]
    fn variadic_declarations_cache_the_unsupported_result() {
        let (id, mut unit) = typed_unit(0, false, "word");
        Arc::get_mut(&mut unit)
            .unwrap()
            .functions
            .get_mut(&id)
            .unwrap()
            .as_mut()
            .unwrap()
            .variadic = true;
        let image = seeded_image(&[(0x1000, id, unit)]);
        for _ in 0..2 {
            assert!(matches!(
                declaration(&image, 0x1000),
                Err(AbiIssue::UnsupportedProfile)
            ));
        }
        let cells = image.call_declarations.addresses.lock().unwrap();
        assert!(matches!(
            cells[&0x1000].get(),
            Some(Err(AbiIssue::UnsupportedProfile))
        ));
    }

    #[test]
    fn one_incomplete_candidate_prevents_first_match_admission() {
        let (first, a) = typed_unit(0, false, "word");
        let (second, mut b) = typed_unit(100, false, "word");
        Arc::get_mut(&mut b)
            .unwrap()
            .functions
            .get_mut(&second)
            .unwrap()
            .as_mut()
            .unwrap()
            .params[0]
            .1 = None;
        let image = seeded_image(&[(0x1000, first, a), (0x1000, second, b)]);
        assert!(matches!(
            declaration(&image, 0x1000),
            Err(AbiIssue::UnknownLayout)
        ));
    }

    #[test]
    fn an_exact_entry_is_not_rejected_for_another_functions_overlapping_range() {
        let (id, unit) = typed_unit(0, false, "word");
        let mut image = seeded_image(&[(0x1000, id, unit)]);
        image
            .call_declarations
            .index
            .get_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .unresolved_ranges
            .push(0x0ff0..0x1010);
        assert!(declaration(&image, 0x1000).unwrap().is_some());
        assert!(matches!(
            declaration(&image, 0x1008),
            Err(AbiIssue::UnknownLayout)
        ));
    }
    const AGGREGATE_FIXTURE_FUNCTIONS: [&str; 11] = [
        "abi_pair_adjust",
        "abi_mixed_adjust",
        "abi_hfa1_adjust",
        "abi_hfa2_adjust",
        "abi_hfa3_adjust",
        "abi_hfa4_adjust",
        "abi_exhaust_five",
        "abi_exhaust_seven",
        "abi_indirect_make",
        "abi_exhaust_five_aligned",
        "abi_exhaust_seven_aligned",
    ];

    fn aggregate_fixture(isa: &str, optimization: &str) -> Image {
        crate::loader::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "tests/fixtures/metrics/aggregate_abi.{isa}.{optimization}.debug.elf"
            )),
        )
        .expect("the compiled aggregate debug fixture")
    }

    fn aggregate_fixture_address(image: &Image, name: &str) -> u64 {
        let functions: Vec<_> = image
            .functions
            .values()
            .filter(|function| function.name.as_deref() == Some(name))
            .collect();
        assert_eq!(functions.len(), 1, "fixture symbol {name}");
        functions[0].addr
    }

    fn fixture_source_types(name: &str) -> (Vec<CType>, CType) {
        let integer = || CType::Named("unsigned long long".into());
        let named = |name: &str| CType::Named(format!("struct {name}"));
        match name {
            "abi_pair_adjust" => (vec![named("abi_pair"), integer()], named("abi_pair")),
            "abi_mixed_adjust" => (
                vec![named("abi_mixed"), integer(), CType::Named("double".into())],
                named("abi_mixed"),
            ),
            "abi_indirect_make" => (vec![named("abi_pair"), integer()], named("abi_triple")),
            name if name.starts_with("abi_hfa") => {
                let value = named(&name[..8]);
                (vec![value.clone(), CType::Named("double".into())], value)
            }
            name => {
                let count = if name.starts_with("abi_exhaust_five") {
                    5
                } else {
                    7
                };
                let mut params = vec![integer(); count];
                params.push(named(if name.ends_with("_aligned") {
                    "abi_pair_aligned"
                } else {
                    "abi_pair"
                }));
                params.push(integer());
                (params, integer())
            }
        }
    }

    fn assert_fixture_root(
        graph: &TypeGraph,
        id: TypeSource,
        expected: &CType,
        profile: AbiProfile,
    ) {
        use crate::ir::Precision;
        let node = &graph.types[&id];
        assert!(node.complete && !node.pointer);
        assert_eq!(node.spelling.as_ref(), Some(expected));
        let CType::Named(name) = expected else {
            panic!("unexpected fixture type")
        };
        let scalar = |floating| TypeLayout {
            size: 8,
            alignment: Some(8),
            kind: if floating {
                LayoutKind::Float(Precision::Double)
            } else {
                LayoutKind::Integer
            },
            trivial: true,
        };
        if !name.starts_with("struct ") {
            assert!(!node.aggregate);
            assert_eq!(node.tag, gimli::DW_TAG_base_type.0);
            assert_eq!(node.size, Some(8));
            assert_eq!(node.layout, Ok(scalar(name == "double")));
            assert_eq!(
                node.encoding,
                Some(u16::from(if name == "double" {
                    gimli::DW_ATE_float.0
                } else {
                    gimli::DW_ATE_unsigned.0
                }))
            );
            assert!(node.references.is_empty() && node.members.is_empty());
            return;
        }
        let (fields, floats): (&[&str], &[bool]) = match name.as_str() {
            "struct abi_pair" | "struct abi_pair_aligned" => (&["low", "high"], &[false, false]),
            "struct abi_mixed" => (&["floating", "integer"], &[true, false]),
            "struct abi_hfa1" => (&["a"], &[true]),
            "struct abi_hfa2" => (&["a", "b"], &[true, true]),
            "struct abi_hfa3" => (&["a", "b", "c"], &[true, true, true]),
            "struct abi_hfa4" => (&["a", "b", "c", "d"], &[true, true, true, true]),
            "struct abi_triple" => (&["first", "second", "third"], &[false, false, false]),
            _ => panic!("unexpected fixture aggregate {name}"),
        };
        assert!(node.aggregate);
        assert_eq!(node.tag, gimli::DW_TAG_structure_type.0);
        assert_eq!(node.name.as_deref(), name.strip_prefix("struct "));
        assert_eq!(node.size, Some(fields.len() as u64 * 8));
        assert_eq!(
            node.layout,
            Ok(TypeLayout {
                size: fields.len() as u64 * 8,
                alignment: name.ends_with("_aligned").then_some(8),
                trivial: true,
                kind: LayoutKind::Struct(
                    floats
                        .iter()
                        .enumerate()
                        .map(|(index, floating)| LayoutField {
                            bit_offset: index as u64 * 64,
                            bit_size: None,
                            defined: true,
                            layout: scalar(*floating),
                        })
                        .collect()
                ),
            })
        );
        assert_eq!(
            node.members
                .iter()
                .map(|(name, _)| name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            fields
        );
        assert_eq!(
            node.references,
            node.members.iter().map(|(_, id)| *id).collect::<Vec<_>>()
        );
        for ((_, member), floating) in node.members.iter().zip(floats) {
            assert_eq!(member.unit, id.unit);
            assert_fixture_root(
                graph,
                *member,
                &CType::Named(
                    if *floating {
                        "double"
                    } else {
                        "unsigned long long"
                    }
                    .into(),
                ),
                profile,
            );
        }
        let definition = &graph.definitions[&id];
        assert_eq!(definition.name, *name);
        assert_eq!(definition.size, fields.len() as u64 * 8);
        assert_eq!(definition.alignment, Some(8));
        assert_eq!(definition.fields, fields);
        assert_eq!(definition.compatible_profiles, [profile]);
    }

    fn assert_fixture_call_binding(
        name: &str,
        signature: &DeclaredSignature,
        profile: AbiProfile,
    ) -> Vec<u16> {
        use crate::ir::{AbiLocation, AbiPiece, Passing, RegisterClass};
        let x86 = profile == AbiProfile::SysV;
        let integers: &[u16] = if x86 {
            &[7, 6, 2, 1, 8, 9]
        } else {
            &[0, 1, 2, 3, 4, 5, 6, 7]
        };
        let simd = if x86 { 18 } else { 32 };
        let piece = |register, object_offset, class| AbiPiece {
            location: AbiLocation::Register(register),
            object_offset,
            bytes: 8,
            class: Some(class),
        };
        let integer = |register| Passing::Direct(vec![piece(register, 0, RegisterClass::Integer)]);
        let float = |register| Passing::Direct(vec![piece(register, 0, RegisterClass::Simd)]);
        let pair = |a, b| {
            Passing::Direct(vec![
                piece(a, 0, RegisterClass::Integer),
                piece(b, 8, RegisterClass::Integer),
            ])
        };
        let stack = |offset, bytes| {
            Passing::Direct(vec![AbiPiece {
                location: AbiLocation::Stack(offset),
                object_offset: 0,
                bytes,
                class: None,
            }])
        };
        let hidden = || Passing::Indirect {
            pointer: AbiLocation::Register(if x86 { 7 } else { 8 }),
            returned_pointer: x86.then_some(0),
        };
        let ordinary = name.strip_suffix("_aligned").unwrap_or(name);
        let (arguments, result) = match ordinary {
            "abi_pair_adjust" => (
                vec![pair(integers[0], integers[1]), integer(integers[2])],
                pair(0, if x86 { 2 } else { 1 }),
            ),
            "abi_mixed_adjust" if x86 => (
                vec![
                    Passing::Direct(vec![
                        piece(18, 0, RegisterClass::Simd),
                        piece(7, 8, RegisterClass::Integer),
                    ]),
                    integer(6),
                    float(20),
                ],
                Passing::Direct(vec![
                    piece(18, 0, RegisterClass::Simd),
                    piece(0, 8, RegisterClass::Integer),
                ]),
            ),
            "abi_mixed_adjust" => (vec![pair(0, 1), integer(2), float(32)], pair(0, 1)),
            "abi_indirect_make" => {
                let shift = usize::from(x86);
                (
                    vec![
                        pair(integers[shift], integers[shift + 1]),
                        integer(integers[shift + 2]),
                    ],
                    hidden(),
                )
            }
            "abi_exhaust_five" => {
                let mut arguments: Vec<_> = integers[..5].iter().copied().map(integer).collect();
                arguments.push(if x86 { stack(8, 16) } else { pair(5, 6) });
                arguments.push(integer(if x86 { 9 } else { 7 }));
                (arguments, integer(0))
            }
            "abi_exhaust_seven" => {
                let mut arguments: Vec<_> = integers.iter().take(7).copied().map(integer).collect();
                if x86 {
                    arguments.push(stack(8, 8));
                }
                arguments.push(stack(if x86 { 16 } else { 0 }, 16));
                arguments.push(stack(if x86 { 32 } else { 16 }, 8));
                (arguments, integer(0))
            }
            name if name.starts_with("abi_hfa") => {
                let lanes = u16::from(name.as_bytes()[7] - b'0');
                let hfa = Passing::Direct(
                    (0..lanes)
                        .map(|lane| {
                            piece(simd + lane * 2, u64::from(lane) * 8, RegisterClass::Simd)
                        })
                        .collect(),
                );
                if x86 && lanes > 2 {
                    (vec![stack(8, u64::from(lanes) * 8), float(simd)], hidden())
                } else {
                    (vec![hfa.clone(), float(simd + lanes * 2)], hfa)
                }
            }
            _ => panic!("unexpected fixture function {name}"),
        };
        let abi = signature.abi.as_ref().expect("the real source ABI");
        assert_eq!(abi.profile, profile);
        assert_eq!(abi.arguments.len(), arguments.len());
        for (actual, expected) in abi.arguments.iter().zip(arguments) {
            assert_eq!(actual.passing, expected, "{name}");
        }
        let actual = abi.result.as_ref().expect("fixture result");
        assert_eq!(actual.passing, result, "{name}");
        let (params, returned) = fixture_source_types(name);
        for (value, ty) in abi
            .arguments
            .iter()
            .chain(&abi.result)
            .zip(params.iter().chain([&returned]))
        {
            let CType::Named(ty) = ty else {
                panic!("unexpected fixture type")
            };
            assert_eq!(value.aggregate, ty.starts_with("struct "));
            let size = match ty.as_str() {
                "struct abi_pair" | "struct abi_pair_aligned" | "struct abi_mixed" => 16,
                "struct abi_triple" => 24,
                name if name.starts_with("struct abi_hfa") => {
                    u64::from(name.as_bytes()[14] - b'0') * 8
                }
                _ => 8,
            };
            assert_eq!(value.size, size);
            assert_eq!(value.alignment, 8);
            assert_eq!(value.defined_bits, [(0, value.size * 8)]);
            value.validate().unwrap();
        }
        let expected_registers = match (ordinary, x86) {
            ("abi_pair_adjust" | "abi_mixed_adjust", false) => vec![0, 1],
            ("abi_pair_adjust", true) => vec![0, 2],
            ("abi_mixed_adjust", true) => vec![18, 0],
            ("abi_indirect_make", false) => vec![],
            (name, _) if name.starts_with("abi_hfa") => {
                let lanes = u16::from(name.as_bytes()[7] - b'0');
                if x86 && lanes > 2 {
                    vec![0]
                } else {
                    (0..lanes).map(|lane| simd + lane * 2).collect()
                }
            }
            _ => vec![0],
        };
        assert_eq!(
            super::result_registers(actual),
            Some(expected_registers.clone())
        );
        expected_registers
    }

    #[test]
    fn compiled_aggregate_declarations_preserve_source_roots_and_exact_abi_locations() {
        let (mut accepted, mut rejected) = (0, 0);
        for (isa, profile) in [
            ("x86_64", AbiProfile::SysV),
            ("aarch64", AbiProfile::Aapcs64),
        ] {
            for optimization in ["O0", "O2"] {
                let image = aggregate_fixture(isa, optimization);
                assert!(image.call_declarations.index.get().is_none());
                assert!(image.call_declarations.units.lock().unwrap().is_empty());
                assert!(image.call_declarations.addresses.lock().unwrap().is_empty());
                let mut function_ids = BTreeSet::new();
                let mut declarations = Vec::new();
                for name in AGGREGATE_FIXTURE_FUNCTIONS {
                    let address = aggregate_fixture_address(&image, name);
                    if matches!((isa, name), ("x86_64", "abi_exhaust_seven")) {
                        for _ in 0..2 {
                            assert!(
                                matches!(
                                    declaration(&image, address),
                                    Err(AbiIssue::UnknownLayout)
                                ),
                                "{isa} {optimization} {name}"
                            );
                        }
                        let convention = crate::analysis::abi::convention(profile);
                        let mut blocks = vec![crate::ir::Block {
                            start: 0,
                            stmts: vec![crate::ir::Stmt::Call {
                                kind: crate::ir::CallKind::Invoke,
                                target: Some(address),
                                through: None,
                                convention,
                                args: Some(Vec::new()),
                                floats_named: true,
                                outputs: crate::ir::fallback_call_outputs(convention, None),
                                clobbers: None,
                                via: None,
                                abi: None,
                            }],
                        }];
                        let before = format!("{blocks:?}");
                        attach_outputs(&image, &mut blocks);
                        assert_eq!(format!("{blocks:?}"), before);
                        rejected += 1;
                        continue;
                    }
                    let found = declaration(&image, address)
                        .unwrap_or_else(|issue| panic!("{isa} {optimization} {name}: {issue:?}"))
                        .expect("a real source declaration");
                    let again = declaration(&image, address).unwrap().unwrap();
                    assert!(Arc::ptr_eq(&found, &again));
                    let (params, result) = fixture_source_types(name);
                    assert_eq!(
                        found
                            .signature
                            .params
                            .iter()
                            .map(|(_, ty)| ty.clone())
                            .collect::<Vec<_>>(),
                        params
                    );
                    assert_eq!(found.signature.ret, result);
                    assert!(!found.signature.variadic);
                    let expected_registers =
                        assert_fixture_call_binding(name, &found.signature, profile);
                    let mut blocks = vec![crate::ir::Block {
                        start: 0,
                        stmts: vec![crate::ir::Stmt::Call {
                            kind: crate::ir::CallKind::Invoke,
                            target: Some(address),
                            through: None,
                            convention: crate::analysis::abi::convention(profile),
                            args: Some(Vec::new()),
                            floats_named: true,
                            outputs: Vec::new(),
                            clobbers: Some(crate::ir::Registers(0)),
                            via: None,
                            abi: None,
                        }],
                    }];
                    attach_outputs(&image, &mut blocks);
                    let outputs = blocks[0].stmts[0].call_outputs();
                    assert_eq!(
                        outputs
                            .iter()
                            .map(|output| output.register)
                            .collect::<Vec<_>>(),
                        expected_registers
                    );
                    for output in outputs {
                        assert_eq!(
                            (output.dest.index, output.dest.width),
                            (output.register, 64)
                        );
                    }
                    assert_eq!(found.sources.len(), 1);
                    let source = &found.sources[0];
                    assert!(function_ids.insert(source.source.function));
                    assert_eq!(
                        image
                            .call_declarations
                            .index
                            .get()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .addresses[&address],
                        [source.source.function]
                    );
                    assert_eq!(source.source.parameters.len(), params.len());
                    if name.ends_with("_adjust") {
                        assert_eq!(source.source.parameters[0], source.source.result);
                    }
                    let roots: Vec<_> = source
                        .source
                        .parameters
                        .iter()
                        .map(|id| id.expect("parameter source"))
                        .chain([source.source.result.expect("result source")])
                        .collect();
                    for (root, expected) in roots.iter().zip(params.iter().chain([&result])) {
                        assert_eq!(root.unit, source.source.function.unit);
                        assert_ne!(root.die, source.source.function.die);
                        assert_fixture_root(&source.graph, *root, expected, profile);
                    }
                    let required: BTreeSet<_> = roots.iter().copied().collect();
                    assert_eq!(
                        source.required_types,
                        required.into_iter().collect::<Vec<_>>()
                    );
                    let definitions: BTreeSet<_> = roots
                        .iter()
                        .zip(params.iter().chain([&result]))
                        .filter_map(|(root, ty)| {
                            matches!(ty, CType::Named(name) if name.starts_with("struct "))
                                .then_some(*root)
                        })
                        .collect();
                    assert_eq!(
                        source.required_definitions,
                        definitions.into_iter().collect::<Vec<_>>()
                    );
                    if let Some(before) = declarations.first() {
                        let before: &Arc<CallDeclaration> = before;
                        assert!(Arc::ptr_eq(&before.sources[0].graph, &source.graph));
                    }
                    declarations.push(found);
                    accepted += 1;
                }
                assert_eq!(declarations.len(), if isa == "aarch64" { 11 } else { 10 });
                assert_eq!(image.call_declarations.units.lock().unwrap().len(), 1);
                let addresses = image.call_declarations.addresses.lock().unwrap();
                assert_eq!(addresses.len(), 11);
                assert!(addresses.values().all(|cell| cell.get().is_some()));
            }
        }
        assert_eq!((accepted, rejected), (42, 2));
    }

    #[test]
    fn compiled_aggregate_address_cache_shares_graphs_without_retaining_parsers() {
        let mut checked = 0;
        for isa in ["x86_64", "aarch64"] {
            for optimization in ["O0", "O2"] {
                let image = aggregate_fixture(isa, optimization);
                let first =
                    declaration(&image, aggregate_fixture_address(&image, "abi_pair_adjust"))
                        .unwrap()
                        .unwrap();
                let second = declaration(
                    &image,
                    aggregate_fixture_address(&image, "abi_indirect_make"),
                )
                .unwrap()
                .unwrap();
                assert!(!Arc::ptr_eq(&first, &second));
                assert!(Arc::ptr_eq(
                    &first.sources[0].graph,
                    &second.sources[0].graph
                ));
                assert_eq!(
                    first.sources[0].source.parameters,
                    second.sources[0].source.parameters
                );
                assert_ne!(
                    first.sources[0].source.result,
                    second.sources[0].source.result
                );
                assert_eq!(image.call_declarations.addresses.lock().unwrap().len(), 2);
                let parser = {
                    let units = image.call_declarations.units.lock().unwrap();
                    assert_eq!(units.len(), 1);
                    Arc::downgrade(
                        units
                            .values()
                            .next()
                            .unwrap()
                            .get()
                            .unwrap()
                            .as_ref()
                            .unwrap(),
                    )
                };
                let graph = Arc::downgrade(&first.sources[0].graph);
                drop(image);
                assert!(parser.upgrade().is_none());
                assert!(graph.upgrade().is_some());
                let _ = assert_fixture_call_binding(
                    "abi_pair_adjust",
                    &first.signature,
                    if isa == "x86_64" {
                        AbiProfile::SysV
                    } else {
                        AbiProfile::Aapcs64
                    },
                );
                let _ = assert_fixture_call_binding(
                    "abi_indirect_make",
                    &second.signature,
                    if isa == "x86_64" {
                        AbiProfile::SysV
                    } else {
                        AbiProfile::Aapcs64
                    },
                );
                drop(first);
                assert!(graph.upgrade().is_some());
                drop(second);
                assert!(graph.upgrade().is_none());
                checked += 1;
            }
        }
        assert_eq!(checked, 4);
    }
}

mod input_tests {
    use super::*;
    use crate::ir::abi::{LayoutField, LayoutKind, TypeLayout};
    use crate::ir::{
        AbiLocation, AbiPiece, Block, Convention, Expr, FunctionIr, Passing, Precision,
        SignatureAbi, Stmt, ValueAbi,
    };
    use crate::loader::{Format, Isa};

    fn integer() -> TypeLayout {
        TypeLayout {
            size: 8,
            alignment: Some(8),
            kind: LayoutKind::Integer,
            trivial: true,
        }
    }

    fn double() -> TypeLayout {
        TypeLayout {
            kind: LayoutKind::Float(Precision::Double),
            ..integer()
        }
    }

    fn structure(fields: Vec<TypeLayout>) -> TypeLayout {
        TypeLayout {
            size: fields.len() as u64 * 8,
            alignment: Some(8),
            trivial: true,
            kind: LayoutKind::Struct(
                fields
                    .into_iter()
                    .enumerate()
                    .map(|(at, layout)| LayoutField {
                        bit_offset: at as u64 * 64,
                        bit_size: None,
                        defined: true,
                        layout,
                    })
                    .collect(),
            ),
        }
    }

    fn record(binding: SignatureAbi) -> Arc<CallDeclaration> {
        Arc::new(CallDeclaration {
            signature: DeclaredSignature {
                params: binding
                    .arguments
                    .iter()
                    .enumerate()
                    .map(|(at, value)| {
                        (
                            format!("arg{at}"),
                            if value.aggregate {
                                CType::Named("struct argument".to_owned())
                            } else {
                                CType::U64
                            },
                        )
                    })
                    .collect(),
                ret: if binding.result.is_some() {
                    CType::U64
                } else {
                    CType::Void
                },
                variadic: false,
                abi: Ok(binding),
            },
            sources: Vec::new(),
        })
    }

    fn seeded_image(binding: SignatureAbi) -> Image {
        let isa = if binding.profile == AbiProfile::Aapcs64 {
            Isa::AArch64
        } else {
            Isa::X86_64
        };
        let mut image = Image::from_code(isa, 0, Vec::new());
        if binding.profile == AbiProfile::Win64 {
            image.format = Format::Pe;
        }
        let cell = Arc::new(OnceLock::new());
        cell.set(Ok(Some(record(binding)))).unwrap();
        image
            .call_declarations
            .addresses
            .lock()
            .unwrap()
            .insert(0x1000, cell);
        image
    }

    fn call(profile: AbiProfile, args: Option<Vec<Expr>>) -> Stmt {
        let convention = crate::analysis::abi::convention(profile);
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention,
            args,
            floats_named: true,
            outputs: crate::ir::fallback_call_outputs(convention, None),
            clobbers: None,
            via: None,
            abi: None,
        }
    }

    fn attach(image: &Image, call: Stmt) -> Stmt {
        let mut blocks = vec![Block {
            start: 0,
            stmts: vec![call],
        }];
        attach_outputs(image, &mut blocks);
        attach_inputs(image, &mut blocks);
        blocks.pop().unwrap().stmts.pop().unwrap()
    }

    fn candidate(stmt: &Stmt) -> &CallAbi {
        let Stmt::Call { abi: Some(abi), .. } = stmt else {
            panic!("missing candidate");
        };
        abi
    }

    fn bind(profile: AbiProfile, args: &[TypeLayout], result: Option<&TypeLayout>) -> CallAbi {
        let signature = crate::analysis::abi::allocate(profile, args, result).unwrap();
        let convention = crate::analysis::abi::convention(profile);
        let sp = if profile == AbiProfile::Aapcs64 {
            31
        } else {
            4
        };
        input_binding(
            record(signature),
            0x1000,
            crate::ir::CallKind::Invoke,
            if profile == AbiProfile::Aapcs64 {
                crate::loader::Isa::AArch64
            } else {
                crate::loader::Isa::X86_64
            },
            convention,
            sp,
            CallFallback::Named {
                count: 0,
                floats_named: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn hfa_and_mixed_inputs_retain_the_allocated_physical_banks() {
        let hfa = structure(vec![double(); 4]);
        let a64 = bind(AbiProfile::Aapcs64, &[hfa, integer()], None);
        assert_eq!(a64.dependencies, vec![0, 31, 32, 34, 36, 38]);
        let CallInput::Direct(pieces) = &a64.arguments[0] else {
            panic!("HFA must be direct");
        };
        assert_eq!(
            pieces.iter().map(|piece| piece.source).collect::<Vec<_>>(),
            [32, 34, 36, 38]
                .into_iter()
                .map(|register| CallTransport::Register { register, bytes: 8 })
                .collect::<Vec<_>>()
        );
        assert!(!a64.deferred_memory);
        let mixed = structure(vec![double(), integer()]);
        let sysv = bind(AbiProfile::SysV, &[mixed, integer()], None);
        assert_eq!(sysv.dependencies, vec![4, 6, 7, 18]);
        assert_eq!(
            sysv.arguments[0],
            CallInput::Direct(vec![
                CallInputPiece {
                    object_offset: 0,
                    source: CallTransport::Register {
                        register: 18,
                        bytes: 8
                    }
                },
                CallInputPiece {
                    object_offset: 8,
                    source: CallTransport::Register {
                        register: 7,
                        bytes: 8
                    }
                },
            ])
        );
    }

    #[test]
    fn exhausted_banks_use_call_current_stack_coordinates() {
        for (profile, before, tail) in [
            (AbiProfile::SysV, 5, None),
            (
                AbiProfile::Aapcs64,
                7,
                Some(CallTransport::Stack {
                    offset: 16,
                    bytes: 8,
                }),
            ),
        ] {
            let mut args = vec![integer(); before];
            args.push(structure(vec![integer(); 2]));
            args.push(integer());
            let value = bind(profile, &args, None);
            assert_eq!(
                value.arguments[before],
                CallInput::Direct(vec![
                    CallInputPiece {
                        object_offset: 0,
                        source: CallTransport::Stack {
                            offset: 0,
                            bytes: 8
                        }
                    },
                    CallInputPiece {
                        object_offset: 8,
                        source: CallTransport::Stack {
                            offset: 8,
                            bytes: 8
                        }
                    },
                ])
            );
            let expected = tail.unwrap_or(CallTransport::Register {
                register: 9,
                bytes: 8,
            });
            assert_eq!(
                value.arguments[before + 1],
                CallInput::Direct(vec![CallInputPiece {
                    object_offset: 0,
                    source: expected
                },])
            );
            assert!(value.deferred_memory);
        }
    }

    #[test]
    fn windows_fifth_indirect_parameter_describes_only_its_pointer_slot() {
        let mut args = vec![integer(); 4];
        args.push(structure(vec![integer(); 3]));
        let value = bind(AbiProfile::Win64, &args, None);
        assert_eq!(
            value.arguments[4],
            CallInput::Indirect {
                pointer: CallTransport::Stack {
                    offset: 32,
                    bytes: 8
                },
            }
        );
        assert_eq!(value.dependencies, vec![1, 2, 4, 8, 9]);
        assert!(value.deferred_memory);
    }

    #[test]
    fn large_parameters_preserve_stack_objects_or_register_pointer_transport() {
        let large = structure(vec![integer(); 3]);
        for (profile, pointer, tail) in [(AbiProfile::Aapcs64, 0, 1), (AbiProfile::Win64, 1, 2)] {
            let value = bind(profile, &[large.clone(), integer()], None);
            assert_eq!(
                value.arguments[0],
                CallInput::Indirect {
                    pointer: CallTransport::Register {
                        register: pointer,
                        bytes: 8
                    },
                }
            );
            assert_eq!(
                value.arguments[1],
                CallInput::Direct(vec![CallInputPiece {
                    object_offset: 0,
                    source: CallTransport::Register {
                        register: tail,
                        bytes: 8
                    },
                }])
            );
            assert!(value.deferred_memory);
        }
        let value = bind(AbiProfile::SysV, &[large, integer()], None);
        assert_eq!(
            value.arguments[0],
            CallInput::Direct(
                [0, 8, 16]
                    .into_iter()
                    .map(|offset| CallInputPiece {
                        object_offset: offset,
                        source: CallTransport::Stack {
                            offset: offset as i64,
                            bytes: 8
                        },
                    })
                    .collect()
            )
        );
        assert_eq!(value.dependencies, vec![4, 7]);
    }

    #[test]
    fn floating_bank_exhaustion_keeps_stack_inputs_and_the_integer_bank() {
        let mut args = vec![double(); 7];
        args.push(structure(vec![double(); 2]));
        args.push(double());
        args.push(integer());
        for profile in [AbiProfile::SysV, AbiProfile::Aapcs64] {
            let value = bind(profile, &args, None);
            assert_eq!(
                value.arguments[7],
                CallInput::Direct(vec![
                    CallInputPiece {
                        object_offset: 0,
                        source: CallTransport::Stack {
                            offset: 0,
                            bytes: 8
                        }
                    },
                    CallInputPiece {
                        object_offset: 8,
                        source: CallTransport::Stack {
                            offset: 8,
                            bytes: 8
                        }
                    },
                ])
            );
            let floating = if profile == AbiProfile::SysV {
                CallTransport::Register {
                    register: 32,
                    bytes: 8,
                }
            } else {
                CallTransport::Stack {
                    offset: 16,
                    bytes: 8,
                }
            };
            assert_eq!(
                value.arguments[8],
                CallInput::Direct(vec![CallInputPiece {
                    object_offset: 0,
                    source: floating
                }])
            );
            let integer = if profile == AbiProfile::SysV { 7 } else { 0 };
            assert_eq!(
                value.arguments[9],
                CallInput::Direct(vec![CallInputPiece {
                    object_offset: 0,
                    source: CallTransport::Register {
                        register: integer,
                        bytes: 8
                    },
                }])
            );
            assert!(value.deferred_memory);
        }
    }

    #[test]
    fn hidden_results_remain_separate_from_source_arguments_and_echoes() {
        let result = structure(vec![integer(); 3]);
        for (profile, hidden, first, echo) in [
            (AbiProfile::SysV, 7, 6, Some(0)),
            (AbiProfile::Aapcs64, 8, 0, None),
            (AbiProfile::Win64, 1, 2, Some(0)),
        ] {
            let value = bind(profile, &[integer()], Some(&result));
            assert_eq!(value.arguments.len(), 1);
            assert_eq!(
                value.hidden_result,
                Some(CallTransport::Register {
                    register: hidden,
                    bytes: 8
                })
            );
            assert_eq!(
                value.arguments[0],
                CallInput::Direct(vec![CallInputPiece {
                    object_offset: 0,
                    source: CallTransport::Register {
                        register: first,
                        bytes: 8
                    },
                }])
            );
            let returned = value
                .declaration
                .signature
                .abi
                .as_ref()
                .unwrap()
                .result
                .as_ref()
                .unwrap();
            assert!(
                matches!(returned.passing, Passing::Indirect { returned_pointer, .. } if returned_pointer == echo)
            );
            assert!(value.deferred_memory);
        }
    }

    #[test]
    fn odd_stack_extents_use_exact_supported_widths_without_overread() {
        let signature = SignatureAbi {
            profile: AbiProfile::SysV,
            arguments: vec![ValueAbi {
                aggregate: true,
                size: 15,
                alignment: 1,
                defined_bits: vec![(0, 120)],
                passing: Passing::Direct(vec![AbiPiece {
                    location: AbiLocation::Stack(8),
                    object_offset: 0,
                    bytes: 15,
                    class: None,
                }]),
            }],
            result: None,
        };
        let value = input_binding(
            record(signature),
            0x1000,
            crate::ir::CallKind::Invoke,
            crate::loader::Isa::X86_64,
            Convention::SysV,
            4,
            CallFallback::Implicit {
                floats_named: false,
            },
        )
        .unwrap();
        assert_eq!(
            value.arguments[0],
            CallInput::Direct(vec![
                CallInputPiece {
                    object_offset: 0,
                    source: CallTransport::Stack {
                        offset: 0,
                        bytes: 8
                    }
                },
                CallInputPiece {
                    object_offset: 8,
                    source: CallTransport::Stack {
                        offset: 8,
                        bytes: 4
                    }
                },
                CallInputPiece {
                    object_offset: 12,
                    source: CallTransport::Stack {
                        offset: 12,
                        bytes: 2
                    }
                },
                CallInputPiece {
                    object_offset: 14,
                    source: CallTransport::Stack {
                        offset: 14,
                        bytes: 1
                    }
                },
            ])
        );
        assert_eq!(value.dependencies, vec![4]);
    }

    #[test]
    fn attaching_missing_stack_inputs_keeps_original_fallback_operands_and_events() {
        let signature =
            crate::analysis::abi::allocate(AbiProfile::Aapcs64, &vec![integer(); 10], None)
                .unwrap();
        let image = seeded_image(signature);
        for args in [
            None,
            Some(vec![Expr::Load {
                addr: Box::new(Expr::Const(0x4000)),
                width: 8,
                signed: false,
            }]),
        ] {
            let before = call(AbiProfile::Aapcs64, args);
            let after = attach(&image, before.clone());
            assert_eq!(
                format!("{:?}", before.operands()),
                format!("{:?}", after.operands())
            );
            assert_eq!(before.call_outputs(), after.call_outputs());
            assert_eq!(before.unnamed_call_reads(), after.unnamed_call_reads());
            let Stmt::Call {
                args, floats_named, ..
            } = &before
            else {
                unreachable!()
            };
            assert_eq!(
                candidate(&after).fallback,
                match args {
                    Some(args) => CallFallback::Named {
                        count: args.len(),
                        floats_named: *floats_named
                    },
                    None => CallFallback::Implicit {
                        floats_named: *floats_named
                    },
                }
            );
            let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
            ir.blocks = vec![Block {
                start: 0,
                stmts: vec![
                    before,
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            }];
            let mut attached = ir.clone();
            attached.blocks[0].stmts[0] = after;
            let setup = crate::ir::eval::Setup {
                seed: 1,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[(0x4000, 11)],
                step_limit: 100,
            };
            assert_eq!(
                crate::ir::eval::run(&ir, &setup),
                crate::ir::eval::run(&attached, &setup)
            );
            let mut blocks = attached.blocks.clone();
            let first = match &blocks[0].stmts[0] {
                Stmt::Call { abi: Some(abi), .. } => abi.clone(),
                _ => unreachable!(),
            };
            attach_inputs(&image, &mut blocks);
            assert!(
                matches!(&blocks[0].stmts[0], Stmt::Call { abi: Some(abi), .. } if Arc::ptr_eq(abi, &first))
            );
        }
    }

    #[test]
    fn direct_register_call_stack_origin_survives_optimization() {
        for profile in [AbiProfile::Aapcs64, AbiProfile::SysV, AbiProfile::Win64] {
            let abi = Arc::new(bind(profile, &[integer()], None));
            assert!(!abi.deferred_memory);
            let convention = crate::analysis::abi::convention(profile);
            let isa = if profile == AbiProfile::Aapcs64 {
                Isa::AArch64
            } else {
                Isa::X86_64
            };
            let sp = crate::arch::stack_pointer(isa);
            let argument = convention.arguments()[0];
            let adjustment = |delta: i64| Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: sp,
                    width: 64,
                },
                value: Expr::bin(
                    crate::ir::BinOp::Add,
                    Expr::reg(sp, 64),
                    Expr::Const(delta as u64),
                ),
            };
            let mut ir = FunctionIr::single_block(
                isa,
                vec![
                    adjustment(-32),
                    Stmt::Store {
                        addr: Expr::bin(crate::ir::BinOp::Add, Expr::reg(sp, 64), Expr::Const(8)),
                        value: Expr::reg(argument, 64),
                        width: 8,
                    },
                    Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention,
                        args: Some(vec![Expr::reg(argument, 64)]),
                        floats_named: true,
                        outputs: Vec::new(),
                        clobbers: Some(Default::default()),
                        abi: Some(abi.clone()),
                        via: None,
                    },
                    adjustment(32),
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            );
            ir.convention = convention;
            crate::passes::optimize(&mut ir, false);
            crate::passes::frame_slots::settle(&mut ir);
            let site = ir.blocks[0]
                .stmts
                .iter()
                .position(|stmt| matches!(stmt, Stmt::Call { .. }))
                .unwrap();
            assert!(
                matches!(&ir.blocks[0].stmts[site], Stmt::Call { abi: Some(current), .. } if Arc::ptr_eq(current, &abi))
            );
            let ssa = crate::ssa::build(&ir).unwrap();
            assert!(
                ssa.implicit_reads[&(0, site)]
                    .iter()
                    .any(|(register, _)| *register == sp)
            );
        }
    }

    #[test]
    fn direct_register_call_keeps_the_x86_frame_across_prologue_elimination() {
        for profile in [AbiProfile::SysV, AbiProfile::Win64] {
            let abi = Arc::new(bind(profile, &[integer()], None));
            assert!(!abi.deferred_memory);
            let convention = crate::analysis::abi::convention(profile);
            let sp = crate::arch::stack_pointer(Isa::X86_64);
            let fp = crate::arch::frame_pointer(Isa::X86_64);
            let assignment = |index, value| Stmt::Assign {
                dest: crate::ir::RegRef { index, width: 64 },
                value,
            };
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    assignment(
                        sp,
                        Expr::bin(crate::ir::BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8)),
                    ),
                    Stmt::Store {
                        addr: Expr::reg(sp, 64),
                        value: Expr::reg(fp, 64),
                        width: 8,
                    },
                    assignment(fp, Expr::reg(sp, 64)),
                    Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention,
                        args: Some(vec![Expr::reg(convention.arguments()[0], 64)]),
                        floats_named: true,
                        outputs: Vec::new(),
                        clobbers: Some(Default::default()),
                        abi: Some(abi.clone()),
                        via: None,
                    },
                    assignment(
                        fp,
                        Expr::Load {
                            addr: Box::new(Expr::reg(sp, 64)),
                            width: 8,
                            signed: false,
                        },
                    ),
                    assignment(
                        sp,
                        Expr::bin(crate::ir::BinOp::Add, Expr::reg(sp, 64), Expr::Const(8)),
                    ),
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            );
            ir.convention = convention;
            let before = format!("{ir:?}");
            crate::passes::frame::elide_frame_pointer(&mut ir);
            assert_eq!(format!("{ir:?}"), before, "{profile:?}");
        }
    }

    #[test]
    fn dynamic_stack_origin_is_retained_without_claiming_an_object_address() {
        let signature =
            crate::analysis::abi::allocate(AbiProfile::Aapcs64, &vec![integer(); 9], None).unwrap();
        let image = seeded_image(signature);
        let after = attach(&image, call(AbiProfile::Aapcs64, Some(Vec::new())));
        assert!(after.declared_call_reads().contains(&31));
        assert!(after.has_deferred_call_memory());
        assert_eq!(after.operands().len(), 0);
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks = vec![Block {
            start: 0,
            stmts: vec![
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 31,
                        width: 64,
                    },
                    value: Expr::reg(12, 64),
                },
                after,
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        }];
        let ssa = crate::ssa::build(&ir).unwrap();
        assert!(
            ssa.implicit_reads[&(0, 1)]
                .iter()
                .any(|(register, value)| *register == 31 && *value != ssa.entry[&12])
        );
    }

    #[test]
    fn overflowing_stack_extent_and_duplicate_result_registers_fail_atomically() {
        let mut signature =
            crate::analysis::abi::allocate(AbiProfile::Aapcs64, &vec![integer(); 9], None).unwrap();
        if let Passing::Direct(pieces) = &mut signature.arguments[8].passing {
            pieces[0].location = AbiLocation::Stack(i64::MAX - 4);
        }
        let image = seeded_image(signature);
        let before = call(AbiProfile::Aapcs64, None);
        let after = attach(&image, before.clone());
        assert!(!after.has_declared_call());
        assert_eq!(format!("{before:?}"), format!("{after:?}"));
        let mut signature =
            crate::analysis::abi::allocate(AbiProfile::Aapcs64, &[integer(), integer()], None)
                .unwrap();
        signature.arguments[1].passing = signature.arguments[0].passing.clone();
        let image = seeded_image(signature);
        assert!(!attach(&image, call(AbiProfile::Aapcs64, None)).has_declared_call());
    }

    #[test]
    fn incompatible_or_unavailable_declarations_keep_physical_fallback_unchanged() {
        let signature =
            crate::analysis::abi::allocate(AbiProfile::Aapcs64, &[integer()], None).unwrap();
        let image = seeded_image(signature);
        let mismatch = call(AbiProfile::SysV, None);
        assert_eq!(
            format!("{:?}", attach(&image, mismatch.clone())),
            format!("{mismatch:?}")
        );
        let mut indirect = call(AbiProfile::Aapcs64, None);
        let Stmt::Call { through, .. } = &mut indirect else {
            unreachable!()
        };
        *through = Some(Expr::reg(9, 64));
        assert_eq!(
            format!("{:?}", attach(&image, indirect.clone())),
            format!("{indirect:?}")
        );
        for failure in [
            Ok(None),
            Err(AbiIssue::UnknownLayout),
            Err(AbiIssue::UnsupportedProfile),
            Err(AbiIssue::IncompatibleDefinition),
        ] {
            let cell = Arc::new(OnceLock::new());
            cell.set(failure).unwrap();
            image
                .call_declarations
                .addresses
                .lock()
                .unwrap()
                .insert(0x1000, cell);
            let before = call(AbiProfile::Aapcs64, Some(vec![Expr::reg(0, 64)]));
            assert_eq!(
                format!("{:?}", attach(&image, before.clone())),
                format!("{before:?}")
            );
        }
        let hfa = structure(vec![double(); 4]);
        let signature =
            crate::analysis::abi::allocate(AbiProfile::Aapcs64, &[integer()], Some(&hfa)).unwrap();
        let image = seeded_image(signature);
        let mut blocks = vec![Block {
            start: 0,
            stmts: vec![call(AbiProfile::Aapcs64, None)],
        }];
        attach_inputs(&image, &mut blocks);
        assert!(!blocks[0].stmts[0].has_declared_call());
        attach_outputs(&image, &mut blocks);
        attach_inputs(&image, &mut blocks);
        assert!(blocks[0].stmts[0].has_declared_call());
        assert!(
            blocks[0].stmts[0]
                .call_outputs()
                .iter()
                .any(|output| output.register == 38)
        );
    }

    #[test]
    fn passive_tail_bindings_keep_kind_and_incoming_stack_coordinates() {
        for (profile, count, expected) in [(AbiProfile::SysV, 7, 8), (AbiProfile::Win64, 5, 40)] {
            let layouts = vec![integer(); count];
            let signature = crate::analysis::abi::allocate(profile, &layouts, None).unwrap();
            let image = seeded_image(signature);
            for kind in [crate::ir::CallKind::Invoke, crate::ir::CallKind::Tail] {
                let mut stmt = call(profile, None);
                let Stmt::Call { kind: actual, .. } = &mut stmt else {
                    unreachable!()
                };
                *actual = kind;
                let stmt = attach(&image, stmt);
                let binding = candidate(&stmt);
                assert_eq!(binding.kind, kind);
                assert!(
                    matches!(binding.arguments.last(), Some(CallInput::Direct(pieces))
                    if matches!(&pieces[..], [CallInputPiece { source: CallTransport::Stack { offset, bytes: 8 }, .. }]
                        if *offset == if kind == crate::ir::CallKind::Tail { expected } else { expected - 8 }))
                );
                assert!(matches!(stmt, Stmt::Call { args: None, .. }));
            }
        }
    }

    #[test]
    fn passive_bindings_refuse_syscall_kind_and_architecture_mismatch() {
        let signature = crate::analysis::abi::allocate(AbiProfile::SysV, &[], None).unwrap();
        for (kind, isa, sp) in [
            (crate::ir::CallKind::Syscall, Isa::X86_64, 4),
            (crate::ir::CallKind::Invoke, Isa::AArch64, 31),
            (crate::ir::CallKind::Invoke, Isa::X86_64, 31),
        ] {
            assert!(matches!(
                input_binding(
                    record(signature.clone()),
                    0x1000,
                    kind,
                    isa,
                    Convention::SysV,
                    sp,
                    CallFallback::Implicit {
                        floats_named: false
                    }
                ),
                Err(AbiIssue::UnknownLayout)
            ));
        }
    }
}

mod output_tests {
    use super::*;
    use crate::ir::abi::{LayoutField, LayoutKind, TypeLayout};
    use crate::ir::{
        AbiLocation, AbiPiece, BinOp, Block, CallOutput, Convention, Expr, FunctionIr, Passing,
        Precision, RegRef, RegisterClass, Registers, SignatureAbi, Stmt, ValueAbi,
    };
    use crate::loader::{Format, Isa};

    fn integer() -> TypeLayout {
        TypeLayout {
            size: 8,
            alignment: Some(8),
            kind: LayoutKind::Integer,
            trivial: true,
        }
    }

    fn double() -> TypeLayout {
        TypeLayout {
            kind: LayoutKind::Float(Precision::Double),
            ..integer()
        }
    }

    fn structure(fields: Vec<TypeLayout>) -> TypeLayout {
        TypeLayout {
            size: fields.len() as u64 * 8,
            alignment: Some(8),
            trivial: true,
            kind: LayoutKind::Struct(
                fields
                    .into_iter()
                    .enumerate()
                    .map(|(at, layout)| LayoutField {
                        bit_offset: at as u64 * 64,
                        bit_size: None,
                        defined: true,
                        layout,
                    })
                    .collect(),
            ),
        }
    }

    fn binding(profile: AbiProfile, result: Option<&TypeLayout>) -> SignatureAbi {
        crate::analysis::abi::allocate(profile, &[], result).unwrap()
    }

    fn image(profile: AbiProfile, answer: Result<Option<SignatureAbi>, AbiIssue>) -> Image {
        let isa = if profile == AbiProfile::Aapcs64 {
            Isa::AArch64
        } else {
            Isa::X86_64
        };
        let mut image = Image::from_code(isa, 0, Vec::new());
        if profile == AbiProfile::Win64 {
            image.format = Format::Pe;
        }
        let answer = answer.map(|binding| {
            binding.map(|abi| {
                Arc::new(CallDeclaration {
                    signature: DeclaredSignature {
                        params: Vec::new(),
                        ret: match &abi.result {
                            None => CType::Void,
                            Some(value) if value.aggregate => {
                                CType::Named("struct returned".to_owned())
                            }
                            Some(ValueAbi {
                                passing: Passing::Direct(pieces),
                                ..
                            }) if pieces
                                .first()
                                .is_some_and(|piece| piece.class == Some(RegisterClass::Simd)) =>
                            {
                                CType::Named("double".to_owned())
                            }
                            Some(_) => CType::U64,
                        },
                        variadic: false,
                        abi: Ok(abi),
                    },
                    sources: Vec::new(),
                })
            })
        });
        let cell = Arc::new(OnceLock::new());
        cell.set(answer).unwrap();
        image
            .call_declarations
            .addresses
            .lock()
            .unwrap()
            .insert(0x1000, cell);
        image
    }

    fn output(register: u16) -> CallOutput {
        CallOutput {
            register,
            dest: RegRef {
                index: register,
                width: 64,
            },
        }
    }

    fn call(convention: Convention, clobbers: Option<Registers>) -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention,
            args: Some(Vec::new()),
            floats_named: true,
            outputs: crate::ir::fallback_call_outputs(convention, clobbers),
            clobbers,
            via: None,

            abi: None,
        }
    }

    fn attach(image: &Image, stmt: Stmt) -> Stmt {
        let mut blocks = vec![Block {
            start: 0,
            stmts: vec![stmt],
        }];
        attach_outputs(image, &mut blocks);
        blocks.pop().unwrap().stmts.pop().unwrap()
    }

    fn result_registers(stmt: &Stmt) -> Vec<u16> {
        stmt.call_outputs()
            .iter()
            .map(|output| output.register)
            .collect()
    }

    fn hfa() -> TypeLayout {
        structure(vec![double(); 4])
    }

    #[test]
    fn declared_hfa_keeps_factory_outputs_and_all_original_call_operands() {
        let image = image(
            AbiProfile::Aapcs64,
            Ok(Some(binding(AbiProfile::Aapcs64, Some(&hfa())))),
        );
        for implicit in [false, true] {
            let mut before = call(Convention::Aapcs64, None);
            if let Stmt::Call {
                args,
                floats_named,
                via,
                ..
            } = &mut before
            {
                *args = if implicit {
                    None
                } else {
                    Some(vec![Expr::Load {
                        addr: Box::new(Expr::Const(0x4000)),
                        width: 8,
                        signed: false,
                    }])
                };
                *floats_named = false;
                *via = Some(Box::new(crate::ir::Via {
                    table: crate::ir::Table::Pointer,
                    slot: 0x5000,
                    candidates: vec![0x1000],
                }));
            }
            let mut expected = before.clone();
            if let Stmt::Call { outputs, .. } = &mut expected {
                *outputs = [0, 1, 32, 34, 36, 38].into_iter().map(output).collect();
            }
            let after = attach(&image, before);
            assert_eq!(format!("{after:?}"), format!("{expected:?}"));
            assert_eq!(
                format!("{:?}", attach(&image, after.clone())),
                format!("{after:?}")
            );
        }
    }

    #[test]
    fn declared_preserved_outputs_keep_their_pre_call_sources() {
        let image = image(
            AbiProfile::Aapcs64,
            Ok(Some(binding(AbiProfile::Aapcs64, Some(&hfa())))),
        );
        let after = attach(
            &image,
            call(Convention::Aapcs64, Some(Registers::default())),
        );
        assert_eq!(result_registers(&after), vec![32, 34, 36, 38]);
        assert!(after.call_clobbers().is_empty());
        assert_eq!(
            after.preserved_output_sources(),
            vec![(0, 32), (1, 34), (2, 36), (3, 38)]
        );
        let (writes, reads) = crate::ir::visit::statement_registers(&after);
        for register in [32, 34, 36, 38] {
            assert!(writes.contains(&register));
            assert!(reads.contains(&register));
        }
    }

    #[test]
    fn declared_direct_result_registers_cover_mixed_banks_scalar_floats_and_integer_pairs() {
        let cases = vec![
            (
                AbiProfile::SysV,
                structure(vec![double(), integer()]),
                vec![18, 0],
            ),
            (AbiProfile::SysV, double(), vec![18]),
            (AbiProfile::Aapcs64, double(), vec![32]),
            (AbiProfile::Win64, double(), vec![18]),
            (AbiProfile::SysV, structure(vec![integer(); 2]), vec![0, 2]),
            (
                AbiProfile::Aapcs64,
                structure(vec![integer(); 2]),
                vec![0, 1],
            ),
        ];
        for (profile, layout, expected) in cases {
            let image = image(profile, Ok(Some(binding(profile, Some(&layout)))));
            let after = attach(
                &image,
                call(
                    crate::analysis::abi::convention(profile),
                    Some(Registers::default()),
                ),
            );
            assert_eq!(result_registers(&after), expected);
        }
    }

    #[test]
    fn indirect_result_echo_does_not_expose_the_hidden_pointer_as_an_output() {
        let result = structure(vec![integer(); 3]);
        for (profile, hidden, expected) in [
            (AbiProfile::SysV, 7, vec![0]),
            (AbiProfile::Win64, 1, vec![0]),
            (AbiProfile::Aapcs64, 8, vec![]),
        ] {
            let abi = binding(profile, Some(&result));
            assert!(matches!(abi.result.as_ref().map(|value| &value.passing),
                Some(Passing::Indirect { pointer: AbiLocation::Register(register), .. }) if *register == hidden));
            let image = image(profile, Ok(Some(abi)));
            let before = call(
                crate::analysis::abi::convention(profile),
                Some(Registers::default()),
            );
            let after = attach(&image, before);
            assert_eq!(result_registers(&after), expected);
            assert!(!result_registers(&after).contains(&hidden));
        }
    }

    #[test]
    fn absent_rejected_void_and_mismatched_declarations_leave_fallbacks_unchanged() {
        let abi = binding(AbiProfile::Aapcs64, Some(&hfa()));
        for answer in [
            Ok(None),
            Err(AbiIssue::UnsupportedProfile),
            Err(AbiIssue::UnknownLayout),
            Err(AbiIssue::IncompatibleDefinition),
            Ok(Some(binding(AbiProfile::Aapcs64, None))),
            Ok(Some(binding(AbiProfile::SysV, Some(&integer())))),
        ] {
            let image = image(AbiProfile::Aapcs64, answer);
            let before = call(Convention::Aapcs64, None);
            let expected = format!("{before:?}");
            assert_eq!(format!("{:?}", attach(&image, before)), expected);
        }
        for mode in 0..4 {
            let mut image = image(AbiProfile::Aapcs64, Ok(Some(abi.clone())));
            let mut before = call(Convention::Aapcs64, None);
            if let Stmt::Call {
                target,
                through,
                convention,
                ..
            } = &mut before
            {
                match mode {
                    0 => *convention = Convention::SysV,
                    1 => {
                        *target = None;
                        *through = Some(Expr::Const(0x1000));
                    }
                    2 => *through = Some(Expr::reg(9, 64)),
                    _ => image.go = true,
                }
            }
            let expected = format!("{before:?}");
            assert_eq!(format!("{:?}", attach(&image, before)), expected);
        }
    }

    #[test]
    fn renamed_duplicate_or_narrow_output_destinations_are_not_extended() {
        let image = image(
            AbiProfile::Aapcs64,
            Ok(Some(binding(AbiProfile::Aapcs64, Some(&hfa())))),
        );
        for mode in 0..5 {
            let mut before = call(Convention::Aapcs64, None);
            if let Stmt::Call { outputs, .. } = &mut before {
                match mode {
                    0 => outputs[0].dest.index = crate::ir::VARIABLE_BASE,
                    1 => {
                        let duplicate = outputs[0];
                        outputs.push(duplicate);
                    }
                    2 => {
                        let first = outputs[0].dest.index;
                        outputs[1].dest.index = first;
                    }
                    3 => outputs[0].dest.width = 32,
                    _ => {
                        outputs[0].register = crate::ir::TEMP_BASE;
                        outputs[0].dest.index = crate::ir::TEMP_BASE;
                    }
                }
            }
            let expected = format!("{before:?}");
            assert_eq!(format!("{:?}", attach(&image, before)), expected);
        }
    }

    #[test]
    fn an_invalid_result_tail_cannot_partially_append_a_valid_first_register() {
        for mode in 0..4 {
            let mut value = ValueAbi {
                aggregate: true,
                size: 16,
                alignment: 8,
                defined_bits: vec![(0, 128)],
                passing: Passing::Direct(vec![
                    AbiPiece {
                        location: AbiLocation::Register(36),
                        object_offset: 0,
                        bytes: 8,
                        class: Some(RegisterClass::Simd),
                    },
                    AbiPiece {
                        location: AbiLocation::Register(38),
                        object_offset: 8,
                        bytes: 8,
                        class: Some(RegisterClass::Simd),
                    },
                ]),
            };
            if let Passing::Direct(pieces) = &mut value.passing {
                match mode {
                    0 => {
                        pieces[1].location = AbiLocation::Stack(0);
                        pieces[1].class = None;
                    }
                    1 => pieces[1].location = AbiLocation::Register(36),
                    2 => pieces[1].location = AbiLocation::Register(crate::ir::TEMP_BASE),
                    _ => value.defined_bits = vec![(0, 129)],
                }
            }
            let image = image(
                AbiProfile::Aapcs64,
                Ok(Some(SignatureAbi {
                    profile: AbiProfile::Aapcs64,
                    arguments: Vec::new(),
                    result: Some(value),
                })),
            );
            let before = call(Convention::Aapcs64, None);
            let expected = format!("{before:?}");
            assert_eq!(format!("{:?}", attach(&image, before)), expected);
        }
    }

    fn sum(registers: &[u16]) -> Expr {
        registers
            .iter()
            .enumerate()
            .fold(Expr::Const(0), |sum, (at, register)| {
                Expr::bin(
                    BinOp::Add,
                    sum,
                    Expr::bin(
                        BinOp::Mul,
                        Expr::reg(*register, 64),
                        Expr::Const(at as u64 + 1),
                    ),
                )
            })
    }

    fn stages(ir: &FunctionIr) -> Vec<FunctionIr> {
        let mut defined = ir.clone();
        crate::ssa::undefine_clobbered_reads(&mut defined);
        let ssa = crate::ssa::build(&defined).unwrap();
        crate::ssa::verify(&ssa).unwrap();
        let lowered = crate::ssa::lower(&ssa);
        let mut split = defined.clone();
        crate::ssa::split_variables(
            &mut split,
            &crate::arch::machine_registers().collect::<Vec<_>>(),
        );
        let mut forwarded = split.clone();
        crate::ssa::take_results_directly(&mut forwarded);
        crate::passes::dce::dce_flow(&mut forwarded);
        vec![defined, lowered, split, forwarded]
    }

    #[test]
    fn supplemented_hfa_result_registers_survive_destructive_analysis_against_a_complete_reference()
    {
        use crate::ir::eval::{self, Setup};
        let registers = [32, 34, 36, 38];
        let image = image(
            AbiProfile::Aapcs64,
            Ok(Some(binding(AbiProfile::Aapcs64, Some(&hfa())))),
        );
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                call(Convention::Aapcs64, Some(registers.into_iter().collect())),
                Stmt::Ret {
                    value: sum(&registers),
                },
            ],
        );
        attach_outputs(&image, &mut ir.blocks);
        assert_eq!(result_registers(&ir.blocks[0].stmts[0]), registers);
        let mut reference = ir.clone();
        if let Stmt::Call { outputs, .. } = &mut reference.blocks[0].stmts[0] {
            *outputs = [32, 34, 36, 38].into_iter().map(output).collect();
        }
        for seed in [0, 1, u64::MAX] {
            let setup = Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            let expected = eval::run(&reference, &setup);
            let value = registers
                .iter()
                .enumerate()
                .fold(0u64, |sum, (at, register)| {
                    sum.wrapping_add(
                        eval::hash(seed ^ 1, 0x2_0000 + u64::from(*register))
                            .wrapping_mul(at as u64 + 1),
                    )
                });
            assert!(
                matches!(&expected, eval::Outcome::Return { value: actual, .. } if *actual == value)
            );
            assert_eq!(eval::run(&ir, &setup), expected);
            for transformed in stages(&ir) {
                assert_eq!(eval::run(&transformed, &setup), expected);
                let returned: Vec<_> = transformed
                    .blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .flat_map(Stmt::call_outputs)
                    .map(|output| output.register)
                    .collect();
                assert_eq!(returned, registers);
            }
        }
    }

    #[test]
    fn supplemented_preserved_result_keeps_the_pre_call_value_through_ssa() {
        use crate::ir::eval::{self, Setup};
        let image = image(
            AbiProfile::Aapcs64,
            Ok(Some(binding(AbiProfile::Aapcs64, Some(&hfa())))),
        );
        let before = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 38,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Add, Expr::reg(38, 64), Expr::Const(3)),
                },
                call(Convention::Aapcs64, Some(Registers::default())),
                Stmt::Ret {
                    value: Expr::reg(38, 64),
                },
            ],
        );
        let mut ir = before.clone();
        attach_outputs(&image, &mut ir.blocks);
        assert_eq!(
            result_registers(&ir.blocks[0].stmts[1]),
            vec![32, 34, 36, 38]
        );
        assert_eq!(
            crate::ssa::entry_demands(&ir, &[u64::MAX]).unwrap()[&38],
            u64::MAX
        );
        let setup = Setup {
            seed: 17,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[(38, 0x1234)],
            memory: &[],
            step_limit: 100,
        };
        let expected = eval::run(&before, &setup);
        assert!(matches!(
            &expected,
            eval::Outcome::Return { value: 0x1237, .. }
        ));
        assert_eq!(eval::run(&ir, &setup), expected);
        for transformed in stages(&ir) {
            assert_eq!(eval::run(&transformed, &setup), expected);
        }
    }
}
