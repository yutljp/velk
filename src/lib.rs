#![cfg_attr(not(test), deny(clippy::missing_assert_message))]
#[cfg(test)]
extern crate self as velk;

pub mod addr;
pub mod analysis;
pub mod api_hashes;
pub mod arch;
pub mod card;
pub mod compare;
mod deadline;
pub mod disasm;
pub mod emulation;
pub mod error;
pub mod ir;
pub mod lift;
pub mod loader;
pub mod memory;

pub mod mcp;
mod parallel;
pub mod passes;
pub mod project;
pub mod render;
pub mod script;
pub mod serve;
pub mod service;
pub mod sigs;
pub mod similar;
pub mod ssa;
pub mod string_decoding;
pub mod symbolic;
mod tables;
mod timing;
pub mod xrefs;
