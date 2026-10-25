//! What a callee's debug-information declaration says of a call: the
//! types it names and where the call passes each parameter and result.
// Calls are not yet given these records outside tests.
#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Debug call records are currently consumed only by tests."
    )
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use super::abi::TypeLayout;
use super::{AbiIssue, CType, Convention, DeclaredSignature, Definition};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TypeSource {
    pub unit: u64,
    pub die: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionSource {
    pub function: TypeSource,
    pub parameters: Vec<Option<TypeSource>>,
    pub result: Option<TypeSource>,
}

#[derive(Debug)]
pub(crate) struct CallType {
    pub tag: u16,
    pub name: Option<String>,
    pub spelling: Option<CType>,
    pub size: Option<u64>,
    pub encoding: Option<u16>,
    pub layout: Result<TypeLayout, AbiIssue>,
    pub dimensions: Vec<u64>,
    pub enumerators: Vec<(String, i128)>,
    pub references: Vec<TypeSource>,
    pub members: Vec<(Option<String>, TypeSource)>,
    pub complete: bool,
    pub pointer: bool,
    pub aggregate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallMember {
    Field {
        name: String,
        ty: TypeSource,
        offset: u64,
        bytes: u64,
    },
    Bytes {
        offset: u64,
        bytes: u64,
    },
}

#[derive(Debug, Default)]
pub(crate) struct TypeGraph {
    pub types: BTreeMap<TypeSource, CallType>,
    pub definitions: BTreeMap<TypeSource, Definition>,
    pub generated_members: BTreeMap<TypeSource, Vec<CallMember>>,
}

#[derive(Debug)]
pub(crate) struct CallDeclaration {
    pub signature: DeclaredSignature,
    pub sources: Vec<CallSource>,
}

#[derive(Debug)]
pub(crate) struct CallSource {
    pub source: FunctionSource,
    pub graph: Arc<TypeGraph>,
    pub required_types: Vec<TypeSource>,
    pub required_definitions: Vec<TypeSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallTransport {
    Register { register: u16, bytes: u8 },
    Stack { offset: i64, bytes: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallInputPiece {
    pub object_offset: u64,
    pub source: CallTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallInput {
    Direct(Vec<CallInputPiece>),
    Indirect { pointer: CallTransport },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallFallback {
    Named { count: usize, floats_named: bool },
    Implicit { floats_named: bool },
}

#[derive(Debug)]
pub struct CallAbi {
    pub(crate) kind: super::CallKind,
    pub(crate) declaration: Arc<CallDeclaration>,
    pub(crate) target: u64,
    pub(crate) convention: Convention,
    pub(crate) arguments: Vec<CallInput>,
    pub(crate) hidden_result: Option<CallTransport>,
    pub(crate) dependencies: Vec<u16>,
    pub(crate) deferred_memory: bool,
    pub(crate) fallback: CallFallback,
}

#[cfg(test)]
pub(crate) fn test_call_abi(dependencies: Vec<u16>, deferred_memory: bool) -> Arc<CallAbi> {
    Arc::new(CallAbi {
        kind: crate::ir::CallKind::Invoke,
        declaration: Arc::new(CallDeclaration {
            signature: DeclaredSignature {
                params: Vec::new(),
                ret: CType::Void,
                variadic: false,
                abi: Err(AbiIssue::UnknownLayout),
            },
            sources: Vec::new(),
        }),
        target: 0,
        convention: Convention::Aapcs64,
        arguments: Vec::new(),
        hidden_result: None,
        dependencies,
        deferred_memory,
        fallback: CallFallback::Named {
            count: 0,
            floats_named: true,
        },
    })
}
