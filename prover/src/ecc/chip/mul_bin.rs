// Variable-base scalar multiplication. To comput s * P we use double-and-add
// method.
//
// Temporary until we have dynamic lookups in Halo2 https://github.com/zcash/halo2/pull/715
// See file [./mul] for ideas on how to use dynamic lookups.
//
// Compute the binary representation of s:
//
//    s = s_0 + s_1 * 2^1 + ... + s_255 * 2^255,
//
// with `s_i \in {0, 1}` for `0 ≤ i ≤ 255`.
//
// This decomposition requires s < 2^256.

use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector};
use crate::ecc::chip::add::AddConfig;
use crate::ecc::chip::AssignedEccPoint;
use crate::main_gate::{MainGate, MainGateConfig};
use crate::util::RegionCtx;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinMulConfig {
    maingate_config: MainGateConfig,
    add_config: AddConfig,
    q_bin_mul: Selector,

    // scalar a in a * P = R
    pub a: Column<Advice>,
}

impl BinMulConfig {
    pub(crate) fn configure (
        meta: &mut ConstraintSystem<jubjub::Base>,
        a: Column<Advice>,
        maingate_config: MainGateConfig,
        add_config: AddConfig,
    ) -> Self {
        meta.enable_equality(a);

        Self {
            maingate_config,
            add_config,
            q_bin_mul: meta.selector(),
            a,
        }
    }
}
