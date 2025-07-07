use atms_halo2::{
    ecc::chip::EccInstructions,
    instructions::MainGateInstructions,
    rescue::{RescueParametersBls, RescueSponge},
    signatures::atms::{AtmsVerifierConfig, AtmsVerifierGate},
    signatures::primitive::schnorr::Schnorr,
    signatures::schnorr::SchnorrSig,
    util::RegionCtx,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ff::Field;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
    poly::{commitment::Guard, kzg::params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};
// use halo2curves::bls12_381::Bls12;
// use halo2curves::jubjub::{AffinePoint, Base};
use blstrs::{Bls12, BlsScalar};
use blstrs::{JubjubAffine as AffinePoint, Base};
use rand::prelude::IteratorRandom;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use std::fs::{create_dir_all, File};
use std::io::{BufReader, Write, Read};
use std::path::Path;
use std::io;
use halo2_proofs::utils::helpers::ProcessedSerdeObject;
use blake2b_simd::{State as Blake2bState, State};
use halo2_proofs::plonk::k_from_circuit;
use halo2_proofs::poly::kzg::KZGCommitmentScheme;
use halo2_proofs::utils::SerdeFormat;

#[derive(Clone)]
struct BenchCircuitConfig {
    atms_config: AtmsVerifierConfig,
}

#[derive(Clone, Default)]
struct BenchCircuitAtmsSignature {
    signatures: Vec<Option<SchnorrSig>>,
    pks: Vec<AffinePoint>,
    pks_comm: Base,
    msg: Base,
    threshold: Base,
}

impl Circuit<Base> for BenchCircuitAtmsSignature {
    type Config = BenchCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
        let atms_config = AtmsVerifierGate::configure(meta);
        BenchCircuitConfig { atms_config }
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

fn atms_bench_helper(c: &mut Criterion, k: u32, num_parties: usize, threshold: usize) {
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    let msg = Base::random(&mut rng);

    let keypairs = (0..num_parties)
        .map(|_| Schnorr::keygen(&mut rng))
        .collect::<Vec<_>>();

    let pks = keypairs.iter().map(|(_, pk)| *pk).collect::<Vec<_>>();

    let mut flattened_pks = Vec::with_capacity(keypairs.len() * 2);
    for (_, pk) in &keypairs {
        flattened_pks.push(pk.get_u());
    }

    let pks_comm = RescueSponge::<Base, RescueParametersBls>::hash(&flattened_pks, None);

    let signing_parties = (0..num_parties).choose_multiple(&mut rng, threshold);
    let signatures = (0..num_parties)
        .map(|index| {
            if signing_parties.contains(&index) {
                Some(Schnorr::sign(keypairs[index], msg, &mut rng))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let circuit = BenchCircuitAtmsSignature {
        signatures,
        pks,
        pks_comm,
        msg,
        threshold: Base::from(threshold as u64),
    };

    let k: u32 = k_from_circuit(&circuit);

    // Create parent directory for assets
    create_dir_all("./benches/atms_assets").expect("Failed to create sha256_assets directory");

    // Initialize the polynomial commitment parameters
    let params_path = format!("./benches/atms_assets/atms_params_{}", k);

    if File::open(Path::new(&params_path)).is_err() {
        let kzg_params = ParamsKZG::<Bls12>::unsafe_setup(k, &mut rng);
        let mut buf = Vec::new();

        kzg_params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).expect("Failed to write params");

        let mut file =
            File::create(Path::new(&params_path)).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }

    let params_fs = File::open(Path::new(&params_path)).expect("couldn't load sha256_params");

    let kzg_params = ParamsKZG::<Bls12>::read_custom(&mut BufReader::new(params_fs), SerdeFormat::RawBytesUnchecked).expect("Failed to read params");

    // let kzg_params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk = keygen_vk(&kzg_params, &circuit).unwrap();
    let pk = keygen_pk(vk, &circuit).unwrap();

    let mut group = c.benchmark_group("ATMS");
    group.bench_function(BenchmarkId::new("Proof generation", threshold), |b| {
        b.iter(|| {
            let mut transcript: CircuitTranscript<Blake2bState> =
                CircuitTranscript::<Blake2bState>::init();
            create_proof::<Base, KZGCommitmentScheme<_>, _, _>(
                &kzg_params,
                &pk,
                &[circuit.clone()],
                &[&[&[pks_comm, msg, Base::from(threshold as u64)]]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation should not fail");

            transcript.finalize();
        })
    });
}

fn atms_3_of_6(c: &mut Criterion) {
    atms_bench_helper(c, 14, 6, 3)
}
fn atms_6_of_9(c: &mut Criterion) {
    atms_bench_helper(c, 15, 9, 6)
}
fn atms_8_of_9(c: &mut Criterion) {
    atms_bench_helper(c, 15, 9, 8)
}
fn atms_14_of_14(c: &mut Criterion) {
    atms_bench_helper(c, 16, 15, 15)
}
fn atms_14_of_21(c: &mut Criterion) {
    atms_bench_helper(c, 16, 21, 14)
}
fn atms_17_of_21(c: &mut Criterion) {
    atms_bench_helper(c, 17, 21, 17)
}
fn atms_28_of_42(c: &mut Criterion) {
    atms_bench_helper(c, 17, 42, 28)
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = atms_3_of_6, atms_6_of_9, atms_8_of_9, atms_14_of_14, atms_14_of_21, atms_17_of_21, atms_28_of_42
}

criterion_main!(benches);
