//! Schnorr signature verification

use crate::ecc::chip::{AssignedEccPoint, EccChip, EccConfig, EccInstructions, ScalarVar};
use crate::rescue::{
    RescueCrhfGate, RescueCrhfGateConfig, RescueCrhfInstructions, RescueParametersBls,
};
use crate::util::RegionCtx;
use crate::AssignedValue;
use group::prime::PrimeCurveAffine;
use group::Group;
use halo2_proofs::circuit::{Chip, Value};
use halo2_proofs::plonk::{ConstraintSystem, Error};
use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint, SubgroupPoint};

/// Type of a Schnorr Signature
pub type AssignedSchnorrSignature = (AssignedEccPoint, ScalarVar);

/// Configuration for SchnorrVerifierGate
#[derive(Clone, Debug)]
pub struct SchnorrVerifierConfig {
    rescue_hash_config: RescueCrhfGateConfig,
    ecc_config: EccConfig,
}

/// Schnorr verifier Gate. It consists of a rescue hash chip and ecc chip.
#[derive(Clone, Debug)]
pub struct SchnorrVerifierGate {
    rescue_hash_gate: RescueCrhfGate<Base, RescueParametersBls>,
    pub(crate) ecc_gate: EccChip,
    config: SchnorrVerifierConfig,
}

impl SchnorrVerifierGate {
    /// Initialise the gate
    pub fn new(config: SchnorrVerifierConfig) -> Self {
        Self {
            rescue_hash_gate: RescueCrhfGate::new(config.clone().rescue_hash_config),
            ecc_gate: EccChip::new(config.clone().ecc_config),
            config,
        }
    }

    /// Configure the schnorr gate
    pub fn configure(meta: &mut ConstraintSystem<Base>) -> SchnorrVerifierConfig {
        SchnorrVerifierConfig {
            rescue_hash_config: RescueCrhfGate::<Base, RescueParametersBls>::configure(meta),
            ecc_config: EccChip::configure(meta),
        }
    }

    /// Schnorr verifier instruction
    pub fn verify(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        signature: &AssignedSchnorrSignature,
        pk: &AssignedEccPoint,
        msg: &AssignedValue<Base>,
    ) -> Result<(), Error> {
        let input_hash = [signature.0.x.clone(), pk.x.clone(), msg.clone()];
        let generator = self.ecc_gate.witness_point(
            ctx,
            &Value::known(ExtendedPoint::from(SubgroupPoint::generator()).into()),
        )?;
        let challenge = self.rescue_hash_gate.hash(ctx, &input_hash)?;
        let lhs = self.ecc_gate.mul(ctx, &signature.1, &generator)?;
        let rhs_1 = self.ecc_gate.mul(ctx, &ScalarVar(challenge), pk)?;
        let rhs = self.ecc_gate.add(ctx, &signature.0, &rhs_1)?;

        self.ecc_gate.constrain_equal(ctx, &lhs, &rhs)?;

        Ok(())
    }
}

impl Chip<Base> for SchnorrVerifierGate {
    type Config = SchnorrVerifierConfig;
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
    use crate::instructions::MainGateInstructions;
    use crate::rescue::RescueSponge;
    use ff::Field;
    use group::{Curve, Group};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit;
    use halo2curves::jubjub::{ExtendedPoint, Scalar};
    use halo2curves::CurveAffine;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::ops::Mul;

    #[derive(Clone)]
    struct TestCircuitConfig {
        schnorr_config: SchnorrVerifierConfig,
    }

    // The prover claims knowledge of a valid signature for a given public key and message
    #[derive(Default)]
    struct TestCircuitSignature {
        signature: (AffinePoint, Scalar),
        pk: AffinePoint,
        msg: Base,
    }

    impl Circuit<Base> for TestCircuitSignature {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
            let schnorr_config = SchnorrVerifierGate::configure(meta);
            TestCircuitConfig { schnorr_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Base>,
        ) -> Result<(), Error> {
            let schnorr_gate = SchnorrVerifierGate::new(config.schnorr_config.clone());
            let rescue_hash_gate = RescueCrhfGate::<Base, RescueParametersBls>::new(
                config.schnorr_config.rescue_hash_config.clone(),
            );
            let ecc_gate = EccChip::new(config.schnorr_config.ecc_config.clone());

            let hashed_msg_pk = layouter.assign_region(
                || "Schnorr verifier test",
                |region| {
                    let offset = 0;
                    let mut ctx = RegionCtx::new(region, offset);
                    let assigned_sig_scalar =
                        ecc_gate.witness_scalar_var(&mut ctx, &Value::known(self.signature.1))?;
                    let assigned_msg = schnorr_gate
                        .ecc_gate
                        .main_gate
                        .assign_value(&mut ctx, Value::known(self.msg))?;
                    let assigned_sig_point =
                        ecc_gate.witness_point(&mut ctx, &Value::known(self.signature.0))?;
                    let assigned_pk = ecc_gate.witness_point(&mut ctx, &Value::known(self.pk))?;

                    schnorr_gate.verify(
                        &mut ctx,
                        &(assigned_sig_point, assigned_sig_scalar),
                        &assigned_pk,
                        &assigned_msg,
                    )?;

                    // We could test with hashing the PIs, but that limits us more wrt to testing (different pk, different msg)
                    // rescue_hash_gate.hash(&mut ctx, &[assigned_pk.x, assigned_pk.y, assigned_msg])

                    Ok((assigned_pk.x, assigned_pk.y, assigned_msg))
                },
            )?;

            layouter.constrain_instance(
                hashed_msg_pk.0.cell(),
                config
                    .schnorr_config
                    .ecc_config
                    .maingate_config
                    .instance
                    .clone(),
                0,
            )?;

            layouter.constrain_instance(
                hashed_msg_pk.1.cell(),
                config
                    .schnorr_config
                    .ecc_config
                    .maingate_config
                    .instance
                    .clone(),
                1,
            )?;

            layouter.constrain_instance(
                hashed_msg_pk.2.cell(),
                config
                    .schnorr_config
                    .ecc_config
                    .maingate_config
                    .instance
                    .clone(),
                2,
            )?;

            Ok(())
        }
    }

    #[test]
    fn schnorr_signature() {
        const K: u32 = 16;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let sk = Scalar::random(&mut rng);
        let generator = ExtendedPoint::from(SubgroupPoint::generator());
        let pk = generator.mul(sk).to_affine();
        let msg = Base::random(&mut rng);

        let k = Scalar::random(&mut rng);
        let announcement = generator.mul(k).to_affine();

        let input_hash = [
            *announcement.coordinates().unwrap().x(),
            *pk.coordinates().unwrap().x(),
            msg.clone(),
        ];

        let challenge = RescueSponge::<Base, RescueParametersBls>::hash(&input_hash, None);

        // we need to have some wide bytes to reduce the challenge.
        let mut wide_bytes = [0u8; 64];
        wide_bytes[..32].copy_from_slice(&challenge.to_bytes());
        let reduced_challenge = Scalar::from_bytes_wide(&wide_bytes);

        let response = k + reduced_challenge * sk;

        let circuit = TestCircuitSignature {
            signature: (announcement, response),
            pk,
            msg,
        };

        let pi = vec![vec![], vec![pk.get_u(), pk.get_v(), msg]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_ok());

        // We try to verify for a different message (the hash of the PI
        let msg_fake = Base::random(&mut rng);

        let pi = vec![vec![], vec![pk.get_u(), pk.get_v(), msg_fake]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_err());

        // We try to verify with a different pk
        let pk_fake = ExtendedPoint::random(&mut rng).to_affine();

        let pi = vec![vec![], vec![pk_fake.get_u(), pk_fake.get_v(), msg]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_err());
    }
}
