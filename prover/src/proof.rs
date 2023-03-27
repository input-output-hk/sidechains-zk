use jubjub::{SubgroupPoint, Scalar};
use bls12_381::{Scalar as BlsScalar};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdDsaPk(SubgroupPoint);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdDsaSig(SubgroupPoint, Scalar);

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
        let pks = [EdDsaPk::default(); 4];
        let sigs = [EdDsaSig::default(); 4];
        let avk = MtCommitment(BlsScalar::one());

        assert!(prove(&pks, &sigs, &avk).is_ok());
    }
}
