 ## Example
 Here we provide an example to demonstrate how ATMS circuit is used.
 ```rust
 use ff::Field;
 use halo2_proofs::poly::commitment::Params;
 use halo2_proofs::{
     circuit::{Layouter, SimpleFloorPlanner, Value},
     plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
     poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
     poly::kzg::multiopen::ProverGWC,
     transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
 };
 use halo2curves::bls12_381::Bls12;
 use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint, SubgroupPoint};
 use rand::prelude::IteratorRandom;
 use rand_core::SeedableRng;
 use std::fs::{create_dir_all, File};
 use std::io::{BufReader, Write};
 use std::path::Path;
 use group::Group;
 use halo2_proofs::dev::MockProver;
 use crate::atms_halo2::ecc::chip::EccInstructions;
 use crate::atms_halo2::instructions::MainGateInstructions;
 use crate::atms_halo2::rescue::{RescueParametersBls, RescueSponge};
 use crate::atms_halo2::signatures::atms::{AtmsVerifierConfig, AtmsVerifierGate};
 use crate::atms_halo2::signatures::primitive::schnorr::Schnorr;
 use crate::atms_halo2::signatures::schnorr::SchnorrSig;
 use crate::atms_halo2::util::RegionCtx;

 #[derive(Clone)]
 struct TestCircuitConfig {
     atms_config: AtmsVerifierConfig,
 }

 #[derive(Clone, Default)]
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

fn main() {
     use rand_chacha::ChaCha8Rng;
     // const K: u32 = 22; // we are 600_000 constraints above 2^21
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

     prover.assert_satisfied();
}
 ```
