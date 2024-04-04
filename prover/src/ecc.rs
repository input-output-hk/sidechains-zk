//! Elliptic curve operations.
use std::fmt::Debug;

use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{Chip, Layouter, Value},
    plonk::Error,
};

pub mod chip;
#[doc = include_str!("../docs/docs-ecc.md")]
pub mod Documentation {}
