//! We implement a gate that verifies the validity of an ATMS signature given the threshold
//! and public key commitment as Public Inputs.

use crate::ecc::chip::{AssignedEccPoint, EccChip, EccConfig, EccInstructions};
use crate::instructions::MainGateInstructions;
use crate::rescue::{
    RescueCrhfGate, RescueCrhfGateConfig, RescueCrhfInstructions, RescueParametersBls,
};
use crate::signatures::schnorr::{
    AssignedSchnorrSignature, SchnorrVerifierConfig, SchnorrVerifierGate,
};
use crate::util::RegionCtx;
use crate::AssignedValue;
use ff::Field;
use halo2_proofs::circuit::{Chip, Value};
use halo2_proofs::plonk::{ConstraintSystem, Error};
use halo2curves::jubjub::Base;

#[derive(Clone, Debug)]
pub struct AtmsVerifierConfig {
    schnorr_config: SchnorrVerifierConfig,
}

#[derive(Clone, Debug)]
/// ATMS verifier gate. It consists of a rescue hash chip and a schnorr chip
pub struct AtmsVerifierGate {
    pub schnorr_gate: SchnorrVerifierGate,
    config: AtmsVerifierConfig,
}

impl AtmsVerifierGate {
    /// Initialise the gate
    pub fn new(config: AtmsVerifierConfig) -> Self {
        Self {
            schnorr_gate: SchnorrVerifierGate::new(config.clone().schnorr_config),
            config,
        }
    }

    /// Configure the ATMS gate
    pub fn configure(meta: &mut ConstraintSystem<Base>) -> AtmsVerifierConfig {
        AtmsVerifierConfig {
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
        commited_pks: &AssignedValue<Base>,
        msg: &AssignedValue<Base>,
        threshold: &AssignedValue<Base>,
    ) -> Result<(), Error> {
        let mut flattened_pks = Vec::new();
        for pk in pks {
            flattened_pks.push(pk.x.clone());
        }

        let hashed_pks = self
            .schnorr_gate
            .rescue_hash_gate
            .hash(ctx, &flattened_pks)?;

        self.schnorr_gate
            .ecc_gate
            .main_gate
            .assert_equal(ctx, &hashed_pks, commited_pks)?;

        let mut counter = self
            .schnorr_gate
            .ecc_gate
            .main_gate
            .assign_constant(ctx, Base::ZERO)?;

        for (sig, pk) in signatures.iter().zip(pks.iter()) {
            if let Some(signature) = sig {
                self.schnorr_gate.verify(ctx, signature, pk, msg)?;
                counter = self.schnorr_gate.ecc_gate.main_gate.add_constant(
                    ctx,
                    &counter,
                    Base::one(),
                )?;
            }
        }

        self.schnorr_gate
            .ecc_gate
            .main_gate
            .assert_equal(ctx, &counter, threshold)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::RescueSponge;
    use crate::signatures::primitive::schnorr::Schnorr;
    use crate::signatures::schnorr::SchnorrSig;
    use group::{Curve, Group};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit};
    use halo2_proofs::poly::commitment::Prover;
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
    use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
    use halo2_proofs::poly::VerificationStrategy;
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
    use halo2curves::bls12_381::Bls12;
    use halo2curves::jubjub::{AffinePoint, ExtendedPoint, Scalar, SubgroupPoint};
    use rand::prelude::IteratorRandom;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::ops::Mul;
    use std::time::Instant;

    #[derive(Clone)]
    struct TestCircuitConfig {
        atms_config: AtmsVerifierConfig,
    }

    #[derive(Default)]
    struct TestCircuitAtmsSignature {
        signatures: Vec<Option<SchnorrSig>>,
        pks: Vec<AffinePoint>,
        pks_comm: Base,
        msg: Base,
        threshold: Base,
    }

    impl Circuit<Base> for TestCircuitAtmsSignature {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
            let atms_config = AtmsVerifierGate::configure(meta);
            TestCircuitConfig { atms_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Base>,
        ) -> Result<(), Error> {
            let atms_gate = AtmsVerifierGate::new(config.atms_config);

            let pi_values = layouter.assign_region(
                || "ATMS verifier test",
                |region| {
                    let offset = 0;
                    let mut ctx = RegionCtx::new(region, offset);
                    let assigned_sigs = self
                        .signatures
                        .iter()
                        .map(|&signature| {
                            if let Some(sig) = signature {
                                Some(
                                    atms_gate
                                        .schnorr_gate
                                        .assign_sig(&mut ctx, &Value::known(sig))
                                        .ok()?,
                                )
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    let assigned_pks = self
                        .pks
                        .iter()
                        .map(|&pk| {
                            atms_gate
                                .schnorr_gate
                                .ecc_gate
                                .witness_point(&mut ctx, &Value::known(pk))
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                    // We assign cells to be compared against the PI
                    let pi_cells = atms_gate
                        .schnorr_gate
                        .ecc_gate
                        .main_gate
                        .assign_values_slice(
                            &mut ctx,
                            &[
                                Value::known(self.pks_comm),
                                Value::known(self.msg),
                                Value::known(self.threshold),
                            ],
                        )?;

                    atms_gate.verify(
                        &mut ctx,
                        &assigned_sigs,
                        &assigned_pks,
                        &pi_cells[0],
                        &pi_cells[1],
                        &pi_cells[2],
                    )?;

                    Ok(pi_cells)
                },
            )?;

            let ecc_gate = atms_gate.schnorr_gate.ecc_gate;

            layouter.constrain_instance(pi_values[0].cell(), ecc_gate.instance_col(), 0)?;

            layouter.constrain_instance(pi_values[1].cell(), ecc_gate.instance_col(), 1)?;

            layouter.constrain_instance(pi_values[2].cell(), ecc_gate.instance_col(), 2)?;

            Ok(())
        }
    }

    #[test]
    fn atms_signature() {
        // const K: u32 = 22;
        // const NUM_PARTIES: usize = 2001; // todo: multiple of three so Rescue does not complain. We should do some padding
        // const THRESHOLD: usize = 1602;

        const K: u32 = 19;
        const NUM_PARTIES: usize = 102;
        const THRESHOLD: usize = 72;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let generator = ExtendedPoint::from(SubgroupPoint::generator());
        let msg = Base::random(&mut rng);

        let keypairs = (0..NUM_PARTIES)
            .map(|_| Schnorr::keygen(&mut rng))
            .collect::<Vec<_>>();

        let pks = keypairs.iter().map(|(_, pk)| *pk).collect::<Vec<_>>();

        let mut flattened_pks = Vec::with_capacity(keypairs.len() * 2);
        for (_, pk) in &keypairs {
            flattened_pks.push(pk.get_u());
        }

        let pks_comm = RescueSponge::<Base, RescueParametersBls>::hash(&flattened_pks, None);

        let signing_parties = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures = (0..NUM_PARTIES)
            .map(|index| {
                if signing_parties.contains(&index) {
                    Some(Schnorr::sign(keypairs[index], msg, &mut rng))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let circuit = TestCircuitAtmsSignature {
            signatures,
            pks,
            pks_comm,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi = vec![vec![pks_comm, msg, Base::from(THRESHOLD as u64)]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run ATMS verifier mock prover");

        assert!(prover.verify().is_ok());
    }
}
