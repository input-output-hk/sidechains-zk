//! # SNARK-based ATMS
//! Circuit implementation for ATMS verification. The goal of this library
//! is to provide a proof-of-concept implementation of a circuit to provide a
//! proof that there exists `t` valid signatures of some subset of a given
//! set of public keys. This is the first effort of implementing a SNARK-based
//! Ad-hoc Threshold Multi Signature scheme.
//!
//! The Zero Knowledge Proving system we'll use is Plonk with KZG commitments. We
//! will use curve BLS12-381. Therefore, to implement in-circuit Elliptic Curve
//! operations, we will use JubJub, which is an elliptic curve defined over the
//! Scalar field of BLS12-381, aka its 'embedded' curve. This enables what is sometimes
//! referred to as SNARK-friendly signature schemes. In particular, EdDSA over the
//! JubJub curve. As a SNARK-friendly hash algorithm we use Poseidon252, both for
//! the signature generation/verification as for the Merkle Tree commitments.
//!
//! ## Committee participation
//! The committee and signature generation precedes the proof creation. Each
//! committee member needs to participate in a registration procedure, during
//! which they share their EdDSA public keys (a JubJub compressed point) with
//! the Registration Authority. The role of the registration authority is simply
//! to commit to all public keys of the committee in a Merkle Tree (MT). This means
//! that the role of the Registration Authority can be a Plutus script, a trusted
//! party, or be distributed amongst the committee members. The reason why it
//! needs to be 'trusted' is because it can exclude certain participants, or
//! include several keys it owns.
//!
//! Once all registration requests have been submitted with their corresponding
//! public keys, `pks = [pk_1, ..., pk_n]`, the aggregated public key is created
//! `avk = MT::commit(&pks)`. This value will be used as a public input for the
//! SNARK verification. This finalises the registration phase.
//!
//! The signature phase simply consists in at least `t > n/2` (or whatever
//! threshold is defined) signers produce valid signatures `sig_1, ..., sig_t`.
//! These signatures are then sent to the aggregator to create the ZKP. The
//! role of the aggregator is simply to serve as a facilitator, and is not
//! required to be trusted. Anyone can aggregate the signatures into a ZKP.
//!
//! ## Circuit
//! In this section we describe what is the statement that will be proven in
//! the Zero Knowledge Proof (ZKP).
//!
//! Once the aggregator receives at least `t` valid signatures `sig_1, ..., sig_t`
//! it proceeds to generate the SNARK. In particular, it proves that:
//! * There exists `t'` valid and distinct signatures, `sig_1, ..., sig_t'` for
//!   public keys `pk_1, ..., pk_t'` and message `m` (public input maybe?).
//! * There exists a valid merkle proof for each distinct public key `pk_1, ..., pk_t'`
//!   wrt to merkle root `pks` (which is given as public input)
//! * `t'> t`, for `t` global parameter defining the threshold (probably a constant
//!   in the circuit)
extern crate core;

use core::slice;
use jubjub::{AffinePoint, Scalar};
use bls12_381::{Scalar as BlsScalar};

pub const NULLPOINTERERR: i64 = -99;

type EdDsaPk = AffinePoint;
type EdDsaJubJub = (AffinePoint, Scalar);
type MtCommitment = BlsScalar;
type PlonkProof = ();

pub type EdDsaPkPtr = *mut EdDsaPk;
pub type EdDsaJubJubPtr = *mut EdDsaJubJub;
pub type MtCommitmentPtr = *mut MtCommitment;
pub type PlonkProofPtr = *mut PlonkProof;

pub fn prove(pks: &[EdDsaPk], sigs: &[EdDsaJubJub], _avk: &MtCommitment) -> Result<PlonkProof, ()> {
    if pks.len() == sigs.len() {
        return Ok(());
    }

    Err(())
}

macro_rules! free_pointer {
    ($type_name:ident, $pointer_type:ty) => {
        paste::item! {
            #[no_mangle]
            /// Free pointer
            pub extern "C" fn [< free_ $type_name>](p: $pointer_type) -> i64 {
                unsafe {
                    if let Some(p) = p.as_mut() {
                        Box::from_raw(p);
                        return 0;
                    }
                    NULLPOINTERERR
                }
            }
        }
    };
}

free_pointer!(PlonkProofPtr);
free_pointer!(EdDsaPkPtr);
free_pointer!(EdDsaJubJubPtr);
free_pointer!(MtCommitmentPtr);

#[no_mangle]
pub extern "C" fn atms_prove(
    proof_ptr: *mut PlonkProofPtr,
    pks_ptr: *const EdDsaPkPtr,
    sigs_ptr: *const EdDsaJubJubPtr,
    nr_sigs: usize,
    avk: MtCommitmentPtr,
) -> i64 {
    unsafe {
        if let (Some(proof_ref), Some(&pks_ref), Some(&sigs_ref), Some(avk_ref)) = (proof_ptr.as_mut(), pks_ptr.as_ref(), sigs_ptr.as_ref(), avk.as_ref()) {
            let pks = slice::from_raw_parts_mut(pks_ref, nr_sigs).iter().map(|p| *p).collect::<Vec<_>>();
            let sigs  = slice::from_raw_parts_mut(sigs_ref, nr_sigs).iter().map(|p| *p).collect::<Vec<_>>();

            *proof_ref = Box::into_raw(Box::new(prove(&pks, &sigs, avk_ref).unwrap()));
            return 1;
        }

        return 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let pks = [AffinePoint::identity(); 4];
        let sigs = [EdDsaJubJub::default(); 4];
        let avk = BlsScalar::one();

        assert!(prove(&pks, &sigs, &avk).is_ok());
    }
}
