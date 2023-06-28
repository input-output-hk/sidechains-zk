//! We implement a gate that verifies the validity of an ATMS signature given the threshold
//! and public key commitment as Public Inputs.

use ff::Field;
use halo2_proofs::circuit::{Chip, Value};
use halo2_proofs::plonk::{ConstraintSystem, Error};
use halo2curves::jubjub::Base;
use crate::AssignedValue;
use crate::ecc::chip::{AssignedEccPoint, EccChip, EccConfig, EccInstructions};
use crate::instructions::MainGateInstructions;
use crate::rescue::{RescueCrhfGate, RescueCrhfGateConfig, RescueCrhfInstructions, RescueParametersBls};
use crate::signatures::schnorr::{AssignedSchnorrSignature, SchnorrVerifierConfig, SchnorrVerifierGate};
use crate::util::RegionCtx;

#[derive(Clone, Debug)]
pub struct AtmsVerifierConfig {
    rescue_hash_config: RescueCrhfGateConfig,
    schnorr_config: SchnorrVerifierConfig,
}

#[derive(Clone, Debug)]
/// ATMS verifier gate. It consists of a rescue hash chip and a schnorr chip
pub struct AtmsVerifierGate {
    rescue_hash_gate: RescueCrhfGate<Base, RescueParametersBls>,
    schnorr_gate: SchnorrVerifierGate,
    config: AtmsVerifierConfig,
}

impl AtmsVerifierGate {
    /// Initialise the gate
    pub fn new(config: AtmsVerifierConfig) -> Self {
        Self {
            rescue_hash_gate: RescueCrhfGate::new(config.clone().rescue_hash_config),
            schnorr_gate: SchnorrVerifierGate::new(config.clone().schnorr_config),
            config
        }
    }

    /// Configure the ATMS gate
    pub fn configure(meta: &mut ConstraintSystem<Base>) -> AtmsVerifierConfig {
        AtmsVerifierConfig {
            rescue_hash_config: RescueCrhfGate::<Base, RescueParametersBls>::configure(meta),
            schnorr_config: SchnorrVerifierGate::configure(meta),
        }
    }

    /// ATMS verifier instruction. Takes as input:
    /// * A list of `Option<AssignedSchnorrSignature>`s. We take options as we may not have a signature
    ///   for every index, but we want them to be 'indexed' in agreement with the public keys
    /// * A list of all public keys of eligible members (including those that do not participate)
    /// * A commitment of all public keys
    /// * A message `msg`,
    /// * The threshold of the number of valid signatures needed
    ///
    /// The circuit will verify that exactly a threshold amount of valid signatures exist for
    /// the given message and public keys that pertain to the committed set. This means that if
    /// the prover has more signatures, it should still only provide a proof for the given
    /// threshold.
    pub fn verify(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        signatures: &[Option<AssignedSchnorrSignature>],
        pks: &[AssignedEccPoint],
        commited_pks: AssignedValue<Base>,
        msg: &AssignedValue<Base>,
        threshold: &AssignedValue<Base>,
    ) -> Result<(), Error> {
        let mut flattened_pks = Vec::new();
        for pk in pks {
            flattened_pks.push(pk.x.clone());
            flattened_pks.push(pk.y.clone());
        }

        let hashed_pks = self.rescue_hash_gate.hash(ctx, &flattened_pks)?;

        self.schnorr_gate.ecc_gate.main_gate.assert_equal(ctx, &hashed_pks, &commited_pks)?;

        let mut counter = self.schnorr_gate.ecc_gate.main_gate.assign_constant(ctx, Base::ZERO)?;

        for (sig, pk) in signatures.into_iter().zip(pks.into_iter()) {
            if let Some(signature) = sig {
                self.schnorr_gate.verify(ctx, signature, pk, msg)?;
                counter = self.schnorr_gate.ecc_gate.main_gate.add_constant(ctx, &counter, Base::one())?;
            }
        }

        self.schnorr_gate.ecc_gate.main_gate.assert_equal(ctx, &counter, threshold)?;

        Ok(())
    }
}

impl Chip<Base> for AtmsVerifierGate {
    type Config = AtmsVerifierConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}


