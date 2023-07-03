//! This module contains the Halo2 prover.

use halo2_proofs::halo2curves::bls12_381::Bls12;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use rand_core::OsRng;

#[test]
fn kzg_backend() {
    const K: u32 = 4;

    let params = ParamsKZG::<Bls12>::setup(K, OsRng);

    // assert!(true);
}
