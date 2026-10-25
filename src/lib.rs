#![cfg_attr(not(test), deny(clippy::missing_assert_message))]

pub mod addr;
pub mod analysis;
pub mod arch;
pub mod card;
mod deadline;
pub mod disasm;
pub mod error;
pub mod ir;
pub mod lift;
pub mod loader;
pub mod mcp;
pub mod passes;
pub mod render;
pub mod script;
pub mod service;
pub mod sigs;
pub mod ssa;
mod timing;
pub mod xrefs;
