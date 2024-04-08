//! Modules for the rescue hash function.

mod primitive;
mod rescue_counter_mode;
mod rescue_crhf_gate;
mod rescue_perm_gate;

#[doc = include_str!("../../docs/docs-rescue.md")]
pub mod documentation {}

#[cfg(test)]
mod test_vectors;

pub use primitive::*;
pub use rescue_counter_mode::*;
pub use rescue_crhf_gate::*;
pub use rescue_perm_gate::*;
