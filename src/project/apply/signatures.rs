//! Scalar signature overrides for annotated functions and calls.
use super::scalar_parameters;
use crate::error::Result;
use crate::ir::{FunctionIr, Stmt};
use crate::project::error;
use crate::project::types::Types;
use crate::render::Symbols;

pub(super) fn apply(
    types: &Types,
    text: &str,
    function: &u64,
    ir: &mut FunctionIr,
    symbols: &mut Symbols,
) -> Result<()> {
    let signature = match types.signature(text) {
        Ok(signature) => signature,
        Err(cause) => return Err(cause),
    };
    if *function == ir.addr {
        if ir.ret_type.is_sse_float()
            || ir.params.iter().any(|p| p.ty.is_sse_float())
            || !matches!(
                ir.convention,
                crate::ir::Convention::SysV
                    | crate::ir::Convention::Win64
                    | crate::ir::Convention::Aapcs64
            )
        {
            return Err(error(
                "unsupported_signature",
                "override requires an integer/pointer scalar ABI",
            ));
        }
        let parameters = match scalar_parameters(ir) {
            Ok(parameters) => parameters,
            Err(cause) => return Err(cause),
        };
        if signature.params.len() != parameters.len()
            || ir.variadic
            || ir
                .declared_signature
                .as_ref()
                .is_some_and(|sig| match &sig.abi {
                    Ok(abi) => abi
                        .arguments
                        .iter()
                        .chain(&abi.result)
                        .any(|arg| arg.aggregate),
                    Err(_) => true,
                })
        {
            return Err(error(
                "unsupported_signature",
                "override requires the existing nonvariadic parameter count and scalar ABI",
            ));
        }
        let mut registers = ir.params.iter_mut();
        for (position, (name, ty)) in signature.params.iter().enumerate() {
            if let Some(param) = ir
                .stack_params
                .iter_mut()
                .find(|param| param.position == position)
            {
                param.name = name.clone();
                param.ty = ty.clone();
            } else if let Some(param) = registers.next() {
                param.name = name.clone();
                param.ty = ty.clone();
                symbols
                    .variable_names
                    .insert((ir.addr, param.index), name.clone());
            }
        }
        ir.ret_type = signature.ret.clone();
        ir.declared_signature = None;
    }
    let statements = ir.blocks.iter().flat_map(|block| &block.stmts);
    for stmt in statements {
        if let Stmt::Call {
            target: Some(target),
            through: None,
            args,
            convention,
            ..
        } = stmt
            && target == function
            && (args
                .as_ref()
                .is_none_or(|args| args.len() != signature.params.len())
                || *convention != ir.convention)
        {
            return Err(error(
                "unsupported_signature",
                format!("call to 0x{function:x} does not match the override's scalar ABI"),
            ));
        }
    }
    ir.callee_signatures.insert(*function, signature);
    Ok(())
}
