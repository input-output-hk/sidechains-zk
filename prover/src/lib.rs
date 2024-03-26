#![deny(missing_debug_implementations)]
// #![deny(missing_docs)] // todo: looking forward bringing this back
#![doc = include_str!("../README.md")]
// todo: eventually remove this
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use halo2_proofs::circuit::AssignedCell;

pub mod ecc;
pub mod instructions;
pub mod main_gate;
pub mod rescue;
pub mod signatures;

mod c_api;
pub mod proof;
pub mod util;

/// AssignedValue
pub type AssignedValue<F> = AssignedCell<F, F>;
/// AssignedCondition
pub type AssignedCondition<F> = AssignedCell<F, F>;
