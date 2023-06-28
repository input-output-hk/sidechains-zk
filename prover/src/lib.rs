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

#![deny(missing_debug_implementations)]
// #![deny(missing_docs)] // todo: looking forward bringing this back

// todo: eventually remove this
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use halo2_proofs::circuit::AssignedCell;

pub mod ecc;
pub mod instructions;
pub mod main_gate;
pub mod prover;
pub mod rescue;
pub mod signatures;

mod c_api;
pub mod proof;
pub mod util;

/// AssignedValue
pub type AssignedValue<F> = AssignedCell<F, F>;
/// AssignedCondition
pub type AssignedCondition<F> = AssignedCell<F, F>;
