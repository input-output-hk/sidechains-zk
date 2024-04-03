//! Elliptic curve operations.

use std::fmt::Debug;

use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{Chip, Layouter, Value},
    plonk::Error,
};

#[doc = include_str!("../docs/ecc_twisted_edwards.md")]
pub mod chip;
