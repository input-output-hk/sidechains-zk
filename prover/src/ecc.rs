//! Elliptic curve operations.
//!
//! See the [Elliptic curve cryptography documentation][crate::docs::ecc].
use std::fmt::Debug;

use midnight_curves::CurveAffine;
use midnight_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::Error,
};

pub mod chip;
