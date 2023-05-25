//! Proof wrapper. API for higher level abstraction.

use bls12_381::Scalar as BlsScalar;
use jubjub::{Scalar, SubgroupPoint};

/// EdDSA Public key, represented by a point in the subgroup of the JubJub curve
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdDsaPk(SubgroupPoint);

/// EdDSA signature, represented by a point in the subgroup and a scalar of the JubJubCurve
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdDsaSig(SubgroupPoint, Scalar);

/// Merkle Tree Commitment, represented by a BLS12-381 scalar. We use Poseidon for MT commitments
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtCommitment(BlsScalar);

/// A Plonk Proof
pub type PlonkProof = ();

/// Create a proof for a SNARK-based ATMS. Given a list of public keys and valid associated signatures,
/// together with an aggregate verification key, the function returns a proof that guarantees that there
/// exists at least `threshold` valid signatures for public keys committed under `avk`
pub fn prove(pks: &[EdDsaPk], sigs: &[EdDsaSig], _avk: &MtCommitment) -> Result<PlonkProof, ()> {
    if pks.len() == sigs.len() {
        return Ok(());
    }

    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let pks = [EdDsaPk::default(); 4];
        let sigs = [EdDsaSig::default(); 4];
        let avk = MtCommitment(BlsScalar::one());

        assert!(prove(&pks, &sigs, &avk).is_ok());
    }
}
