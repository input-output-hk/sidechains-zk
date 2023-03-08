use jubjub::{AffinePoint, Scalar};
use bls12_381::{Scalar as BlsScalar};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdDsaPk(AffinePoint);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdDsaSig(AffinePoint, Scalar);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtCommitment(BlsScalar);

pub type PlonkProof = ();

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
        let pks = [EdDsaPk(AffinePoint::identity()); 4];
        let sigs = [EdDsaSig::default(); 4];
        let avk = MtCommitment(BlsScalar::one());

        assert!(prove(&pks, &sigs, &avk).is_ok());
    }
}
