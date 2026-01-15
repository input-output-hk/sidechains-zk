//! ATMS verifier.
//!
//! We implement a gate that verifies the validity of an ATMS signature given the threshold and public key commitment as Public Inputs.
//!
//! Background for SNARK-based ATMS with Schnorr setup can be found [here][crate::docs::atms].

#![doc = include_str!("../../docs/signatures/atms/example.md")]

use crate::ecc::chip::{AssignedEccPoint, EccChip, EccConfig, EccInstructions};
use crate::instructions::MainGateInstructions;
use crate::rescue::{
    RescueCrhfGate, RescueCrhfGateConfig, RescueCrhfInstructions, RescueParametersBls, RescueSponge,
};
use crate::signatures::schnorr::{
    AssignedSchnorrSignature, SchnorrSig, SchnorrVerifierConfig, SchnorrVerifierGate,
};
use crate::util::RegionCtx;
use crate::AssignedValue;
use blstrs::{Base, Fr as JubjubScalar, JubjubAffine};
use ff::Field;
use halo2_proofs::circuit::{Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

/// Configuration for `AtmsVerifierGate`.
///
/// Includes [SchnorrVerifierConfig].
#[derive(Clone, Debug)]
pub struct AtmsVerifierConfig {
    schnorr_config: SchnorrVerifierConfig,
}

/// ATMS verifier gate.
///
/// It consists of [SchnorrVerifierGate] and [AtmsVerifierConfig].
#[derive(Clone, Debug)]
pub struct AtmsVerifierGate {
    pub schnorr_gate: SchnorrVerifierGate,
    config: AtmsVerifierConfig,
}

impl AtmsVerifierGate {
    /// Initialise the [AtmsVerifierGate] by initializing the [SchnorrVerifierGate].
    /// Return the initialized gate which also includes the [AtmsVerifierConfig].
    pub fn new(config: AtmsVerifierConfig) -> Self {
        Self {
            schnorr_gate: SchnorrVerifierGate::new(config.clone().schnorr_config),
            config,
        }
    }

    /// Configure the ATMS gate by configuring [SchnorrVerifierGate].
    /// Return the [AtmsVerifierConfig].
    pub fn configure(meta: &mut ConstraintSystem<Base>) -> AtmsVerifierConfig {
        AtmsVerifierConfig {
            schnorr_config: SchnorrVerifierGate::configure(meta),
        }
    }

    /// ATMS verifier instruction.
    ///
    #[doc = include_str!("../../docs/signatures/atms/gate-verifier.md")]
    pub fn verify(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        signatures: &[AssignedSchnorrSignature],
        pks: &[AssignedEccPoint],
        commited_pks: &AssignedValue<Base>,
        msg: &AssignedValue<Base>,
        threshold: &AssignedValue<Base>,
    ) -> Result<(), Error> {
        assert_eq!(signatures.len(), pks.len());

        let assigned_zero = self
            .schnorr_gate
            .ecc_gate
            .main_gate
            .assign_constant(ctx, Base::ZERO)?;

        let mut flattened_pks = Vec::new();
        for pk in pks {
            flattened_pks.push(pk.x.clone());
        }

        // Pad the input to be multiple of RATE (3 for Rescue over BLS12-381 scalar field)
        let rate = RescueSponge::<Base, RescueParametersBls>::RATE;
        let remainder = pks.len() % rate;
        if remainder != 0 {
            let padding_needed = rate - remainder;
            flattened_pks.extend(vec![assigned_zero.clone(); padding_needed])
        }

        let hashed_pks = self
            .schnorr_gate
            .rescue_hash_gate
            .hash(ctx, &flattened_pks)?;

        self.schnorr_gate
            .ecc_gate
            .main_gate
            .assert_equal(ctx, &hashed_pks, commited_pks)?;

        let mut counter = assigned_zero.clone();
        let mut is_enough_sigs = assigned_zero;

        // TODO: currently checks all N signatures, where N is a number of public keys.
        //       Actually we can do better by checking only threshold number of signatures,
        //       but this would require using lookup tables to check the public key for a given signature.
        //       Postponed for now, because it makes the verifier a bit more complex and more expensive
        //       to be executed on-chain.
        for (sig, pk) in signatures.iter().zip(pks.iter()) {
            let is_verified = self.schnorr_gate.verify(ctx, &sig, pk, msg)?;
            counter = self
                .schnorr_gate
                .ecc_gate
                .main_gate
                .add(ctx, &counter, &is_verified)?;

            // TODO: instead of checking at each step if the threshold is reached,
            //       we can do a single check at the end that counter >= threshold.
            //       This would require implementing `assert_greater`
            let is_threshold_reached = self
                .schnorr_gate
                .ecc_gate
                .main_gate
                .is_equal(ctx, &counter, threshold)?;

            is_enough_sigs = self.schnorr_gate.ecc_gate.main_gate.or(
                ctx,
                &is_threshold_reached,
                &is_enough_sigs,
            )?;
        }

        self.schnorr_gate
            .ecc_gate
            .main_gate
            .assert_equal_to_constant(ctx, &is_enough_sigs, Base::ONE)?;

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

#[derive(Default, Clone, Debug)]
pub struct AtmsSignatureCircuit {
    pub signatures: Vec<Option<SchnorrSig>>,
    pub pks: Vec<JubjubAffine>,
    pub pks_comm: Base,
    pub msg: Base,
    pub threshold: Base,
}

impl Circuit<Base> for AtmsSignatureCircuit {
    type Config = AtmsVerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
        AtmsVerifierGate::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Base>,
    ) -> Result<(), Error> {
        let atms_gate = AtmsVerifierGate::new(config);

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
                            atms_gate
                                .schnorr_gate
                                .assign_sig(&mut ctx, &Value::known(sig))
                        } else {
                            atms_gate.schnorr_gate.assign_dummy_sig(&mut ctx)
                        }
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::{zero_padding, RescueSponge};
    use crate::signatures::primitive::schnorr::Schnorr;
    use crate::signatures::schnorr::SchnorrSig;
    use blake2b_simd::State as Blake2bState;
    use blstrs::{Bls12, JubjubAffine, JubjubExtended, JubjubSubgroup};
    use group::{Curve, Group};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::k_from_circuit;
    use halo2_proofs::poly::kzg::KZGCommitmentScheme;
    use halo2_proofs::utils::SerdeFormat;
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, prepare, Circuit, ProvingKey, VerifyingKey},
        poly::{commitment::Guard, kzg::params::ParamsKZG},
        transcript::{CircuitTranscript, Transcript},
    };
    use rand::prelude::IteratorRandom;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::fs::{create_dir_all, File};
    use std::io::BufReader;
    use std::ops::Mul;
    use std::path::Path;
    use std::time::Instant;

    /// Generate keypairs and corresponding public keys
    fn generate_keypairs<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        num_parties: usize,
    ) -> (Vec<(blstrs::Fr, JubjubAffine)>, Vec<JubjubAffine>) {
        let keypairs: Vec<_> = (0..num_parties).map(|_| Schnorr::keygen(rng)).collect();
        let pks = keypairs.iter().map(|(_, pk)| *pk).collect();
        (keypairs, pks)
    }

    /// Compute commitment to public keys
    fn compute_pks_commitment(pks: &[JubjubAffine]) -> Base {
        let flattened_pks: Vec<Base> = pks.iter().map(|pk| pk.get_u()).collect();
        RescueSponge::<Base, RescueParametersBls>::hash(
            &flattened_pks,
            Some(zero_padding::<Base, RescueParametersBls>),
        )
    }

    /// Generate signatures for selected parties
    fn generate_signatures<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        keypairs: &[(blstrs::Fr, JubjubAffine)],
        signing_parties: &[usize],
        msg: Base,
    ) -> Vec<Option<SchnorrSig>> {
        (0..keypairs.len())
            .map(|index| {
                if signing_parties.contains(&index) {
                    Some(Schnorr::sign(keypairs[index], msg, rng))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Create a proof for the given circuit and public inputs
    fn create_and_verify_proof<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        params: &ParamsKZG<Bls12>,
        pk: &ProvingKey<Base, KZGCommitmentScheme<Bls12>>,
        vk: &VerifyingKey<Base, KZGCommitmentScheme<Bls12>>,
        circuit: AtmsSignatureCircuit,
        public_inputs: &[&[&[Base]]],
    ) -> Result<(), String> {
        let mut transcript = CircuitTranscript::<Blake2bState>::init();

        create_proof::<Base, KZGCommitmentScheme<_>, _, _>(
            params,
            pk,
            &[circuit],
            public_inputs,
            rng,
            &mut transcript,
        )
        .map_err(|e| format!("proof generation failed: {:?}", e))?;

        let proof = transcript.finalize();

        let mut transcript_verifier = CircuitTranscript::<Blake2bState>::init_from_bytes(&proof);

        let verifier = prepare::<_, KZGCommitmentScheme<Bls12>, CircuitTranscript<Blake2bState>>(
            vk,
            public_inputs,
            &mut transcript_verifier,
        )
        .map_err(|e| format!("prepare verification failed: {:?}", e))?;

        verifier
            .verify(&params.verifier_params())
            .map_err(|e| format!("verification failed: {:?}", e))
    }

    #[test]
    fn atms_signature() {
        // const K: u32 = 22; // we are 600_000 constraints above 2^21
        // const NUM_PARTIES: usize = 2001; // todo: multiple of three so Rescue does not complain. We should do some padding
        // const THRESHOLD: usize = 1602;

        const K: u32 = 19;
        const NUM_PARTIES: usize = 102;
        const THRESHOLD: usize = 72;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        let (keypairs, pks) = generate_keypairs(&mut rng, NUM_PARTIES);
        let pks_comm = compute_pks_commitment(&pks);

        let signing_parties = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures = generate_signatures(&mut rng, &keypairs, &signing_parties, msg);

        let circuit = AtmsSignatureCircuit {
            signatures,
            pks,
            pks_comm,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi = vec![vec![pks_comm, msg, Base::from(THRESHOLD as u64)]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run ATMS verifier mock prover");

        prover.assert_satisfied();
    }

    #[test]
    fn atms_signature_non_divisible_by_3() {
        const NUM_PARTIES: usize = 4;
        const THRESHOLD: usize = 3;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        let (keypairs, pks) = generate_keypairs(&mut rng, NUM_PARTIES);
        let pks_comm = compute_pks_commitment(&pks);

        let signing_parties = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures = generate_signatures(&mut rng, &keypairs, &signing_parties, msg);

        let circuit = AtmsSignatureCircuit {
            signatures,
            pks,
            pks_comm,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi = vec![vec![pks_comm, msg, Base::from(THRESHOLD as u64)]];

        let prover = MockProver::run(k_from_circuit(&circuit), &circuit, pi)
            .expect("Failed to run ATMS verifier mock prover");

        prover.assert_satisfied();
    }

    #[test]
    fn same_circuit_for_different_signatures() {
        const NUM_PARTIES: usize = 6;
        const THRESHOLD: usize = 3;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        let (keypairs, pks) = generate_keypairs(&mut rng, NUM_PARTIES);
        let pks_comm = compute_pks_commitment(&pks);

        // Generate two different sets of signatures from the same keypairs
        let signing_parties_1 = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures_1 = generate_signatures(&mut rng, &keypairs, &signing_parties_1, msg);

        let signing_parties_2 = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures_2 = generate_signatures(&mut rng, &keypairs, &signing_parties_2, msg);
        assert_ne!(signing_parties_1, signing_parties_2);

        let mut circuit = AtmsSignatureCircuit {
            signatures: signatures_1,
            pks: pks.clone(),
            pks_comm,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi: &[&[&[Base]]] = &[&[&[pks_comm, msg, Base::from(THRESHOLD as u64)]]];

        // Setup real circuit
        let k: u32 = k_from_circuit(&circuit);
        let kzg_params = ParamsKZG::<Bls12>::unsafe_setup(k, &mut rng);

        let vk = keygen_vk(&kzg_params, &circuit).unwrap();
        let pk = keygen_pk(vk.clone(), &circuit).unwrap();

        // Prove with first set of signatures
        create_and_verify_proof(&mut rng, &kzg_params, &pk, &vk, circuit.clone(), pi)
            .expect("first proof should succeed");

        // Prove with second set of signatures (same circuit structure)
        circuit.signatures = signatures_2;
        create_and_verify_proof(&mut rng, &kzg_params, &pk, &vk, circuit, pi)
            .expect("second proof should succeed");
    }

    #[test]
    fn same_circuit_for_different_parties() {
        const NUM_PARTIES: usize = 6;
        const THRESHOLD: usize = 3;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        // Generate two different sets of keypairs
        let (keypairs1, pks1) = generate_keypairs(&mut rng, NUM_PARTIES);
        let (keypairs2, pks2) = generate_keypairs(&mut rng, NUM_PARTIES);

        let pks_comm1 = compute_pks_commitment(&pks1);
        let pks_comm2 = compute_pks_commitment(&pks2);

        // Generate signatures with different thresholds
        let signing_parties_1 = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures_1 = generate_signatures(&mut rng, &keypairs1, &signing_parties_1, msg);

        let signing_parties_2 = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let signatures_2 = generate_signatures(&mut rng, &keypairs2, &signing_parties_2, msg);

        let mut circuit = AtmsSignatureCircuit {
            signatures: signatures_1,
            pks: pks1,
            pks_comm: pks_comm1,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi1: &[&[&[Base]]] = &[&[&[pks_comm1, msg, Base::from(THRESHOLD as u64)]]];
        let pi2: &[&[&[Base]]] = &[&[&[pks_comm2, msg, Base::from(THRESHOLD as u64)]]];

        // Setup real circuit
        let k: u32 = k_from_circuit(&circuit);
        let kzg_params = ParamsKZG::<Bls12>::unsafe_setup(k, &mut rng);

        let vk = keygen_vk(&kzg_params, &circuit).unwrap();
        let pk = keygen_pk(vk.clone(), &circuit).unwrap();

        // Prove with first set of parties
        create_and_verify_proof(&mut rng, &kzg_params, &pk, &vk, circuit.clone(), pi1)
            .expect("first proof should succeed");

        // Prove with second set of parties and different threshold (same circuit structure)
        circuit.signatures = signatures_2;
        circuit.pks_comm = pks_comm2;
        circuit.pks = pks2;

        create_and_verify_proof(&mut rng, &kzg_params, &pk, &vk, circuit, pi2)
            .expect("second proof should succeed");
    }

    #[test]
    fn variable_threshold() {
        const NUM_PARTIES: usize = 6;
        const THRESHOLD: usize = 3;
        const THRESHOLD2: usize = 2;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        let (keypairs1, pks1) = generate_keypairs(&mut rng, NUM_PARTIES);
        let pks_comm1 = compute_pks_commitment(&pks1);

        // Generate more signatures than needed for the first threshold
        let signing_parties_1 = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD + 1);
        let signatures_1 = generate_signatures(&mut rng, &keypairs1, &signing_parties_1, msg);

        let signing_parties_2 = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD2);
        let signatures_2 = generate_signatures(&mut rng, &keypairs1, &signing_parties_2, msg);

        let mut circuit = AtmsSignatureCircuit {
            signatures: signatures_1,
            pks: pks1,
            pks_comm: pks_comm1,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi1: &[&[&[Base]]] = &[&[&[pks_comm1, msg, Base::from(THRESHOLD as u64)]]];
        let pi2: &[&[&[Base]]] = &[&[&[pks_comm1, msg, Base::from(THRESHOLD2 as u64)]]];

        // Setup real circuit
        let k: u32 = k_from_circuit(&circuit);
        let kzg_params = ParamsKZG::<Bls12>::unsafe_setup(k, &mut rng);

        let vk = keygen_vk(&kzg_params, &circuit).unwrap();
        let pk = keygen_pk(vk.clone(), &circuit).unwrap();

        // Prove with first threshold
        create_and_verify_proof(&mut rng, &kzg_params, &pk, &vk, circuit.clone(), pi1)
            .expect("first proof should succeed");

        // Prove with second threshold
        circuit.signatures = signatures_2;
        circuit.threshold = Base::from(THRESHOLD2 as u64);

        create_and_verify_proof(&mut rng, &kzg_params, &pk, &vk, circuit, pi2)
            .expect("second proof should succeed");
    }

    #[test]
    fn duplicate_signature_should_fail() {
        const NUM_PARTIES: usize = 6;
        const THRESHOLD: usize = 3;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        let (keypairs, pks) = generate_keypairs(&mut rng, NUM_PARTIES);
        let pks_comm = compute_pks_commitment(&pks);

        // Generate valid signatures from exactly THRESHOLD parties
        let signing_parties = (0..NUM_PARTIES).choose_multiple(&mut rng, THRESHOLD);
        let mut signatures = generate_signatures(&mut rng, &keypairs, &signing_parties, msg);

        // Find the first valid signature
        let first_valid_index = signatures.iter().position(|s| s.is_some()).unwrap();
        let first_valid_sig = signatures[first_valid_index].clone();

        // Find the second valid signature and replace it with a duplicate of the first
        let second_valid_index = signatures
            .iter()
            .skip(first_valid_index + 1)
            .position(|s| s.is_some())
            .map(|i| i + first_valid_index + 1)
            .unwrap();

        // Replace the second valid signature with the duplicate
        signatures[second_valid_index] = first_valid_sig;

        // Now we have THRESHOLD signatures total, but one is duplicated
        // so only THRESHOLD-1 unique valid signatures

        let circuit = AtmsSignatureCircuit {
            signatures,
            pks,
            pks_comm,
            msg,
            threshold: Base::from(THRESHOLD as u64),
        };

        let pi = vec![vec![pks_comm, msg, Base::from(THRESHOLD as u64)]];
        let prover = MockProver::run(k_from_circuit(&circuit), &circuit, pi)
            .expect("Failed to run ATMS verifier mock prover");

        assert!(
            prover.verify().is_err(),
            "Proof should fail with duplicate signature, but succeeded"
        );
    }
}
