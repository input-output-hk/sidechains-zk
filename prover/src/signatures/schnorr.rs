//! Schnorr signature verification

use crate::ecc::chip::{AssignedEccPoint, EccChip, EccConfig, EccInstructions, ScalarVar};
use crate::instructions::MainGateInstructions;
use crate::rescue::{
    RescueCrhfGate, RescueCrhfGateConfig, RescueCrhfInstructions, RescueParametersBls,
};
use crate::util::RegionCtx;
use crate::AssignedValue;
use group::prime::PrimeCurveAffine;
use group::{Curve, Group};
use halo2_proofs::circuit::{Chip, Value};
use halo2_proofs::plonk::{ConstraintSystem, Error};
use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint, Scalar, SubgroupPoint};

/// Type of an Assigned Schnorr Signature
pub type AssignedSchnorrSignature = (AssignedEccPoint, ScalarVar);

/// Type of a Schnorr Signature
pub type SchnorrSig = (AffinePoint, Scalar);

/// Configuration for SchnorrVerifierGate
#[derive(Clone, Debug)]
pub struct SchnorrVerifierConfig {
    rescue_hash_config: RescueCrhfGateConfig,
    pub(crate) ecc_config: EccConfig,
}

/// Schnorr verifier Gate. It consists of a rescue hash chip and ecc chip.
#[derive(Clone, Debug)]
pub struct SchnorrVerifierGate {
    pub(crate) rescue_hash_gate: RescueCrhfGate<Base, RescueParametersBls>,
    pub ecc_gate: EccChip,
    config: SchnorrVerifierConfig,
}

impl SchnorrVerifierGate {
    /// Initialise the gate
    pub fn new(config: SchnorrVerifierConfig) -> Self {
        let rescue_hash_gate = RescueCrhfGate::new(config.clone().rescue_hash_config);

        Self {
            rescue_hash_gate: rescue_hash_gate.clone(),
            ecc_gate: EccChip::new(
                rescue_hash_gate.rescue_perm_gate.maingate,
                config.clone().ecc_config,
            ),
            config,
        }
    }

    /// Configure the schnorr gate
    pub fn configure(meta: &mut ConstraintSystem<Base>) -> SchnorrVerifierConfig {
        let rescue_hash_config = RescueCrhfGate::<Base, RescueParametersBls>::configure(meta);
        SchnorrVerifierConfig {
            rescue_hash_config: rescue_hash_config.clone(),
            ecc_config: EccChip::configure(
                meta,
                rescue_hash_config.rescue_perm_gate_config.maingate_config,
            ),
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
        let challenge = self.rescue_hash_gate.hash(ctx, &input_hash)?;

        let lhs = self.ecc_gate.fixed_mul(
            ctx,
            &signature.1,
            ExtendedPoint::from(SubgroupPoint::generator()).to_affine(),
        )?;
        let rhs_1 = self.ecc_gate.mul(ctx, &ScalarVar(challenge), pk)?;
        let rhs = self.ecc_gate.add(ctx, &signature.0, &rhs_1)?;

        self.ecc_gate.constrain_equal(ctx, &lhs, &rhs)?;

        Ok(())
    }

    /// Assign a schnorr signature
    pub fn assign_sig(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        signature: &Value<SchnorrSig>,
    ) -> Result<AssignedSchnorrSignature, Error> {
        let a = signature.map(|value| value.0);
        let e = signature.map(|value| value.1);

        let assigned_sig_scalar = self.ecc_gate.witness_scalar_var(ctx, &e)?;
        let assigned_sig_point = self.ecc_gate.witness_point(ctx, &a)?;

        Ok((assigned_sig_point, assigned_sig_scalar))
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
    use crate::signatures::primitive::schnorr::Schnorr;
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
                config.schnorr_config.rescue_hash_config,
            );

            let hashed_msg_pk = layouter.assign_region(
                || "Schnorr verifier test",
                |region| {
                    let offset = 0;
                    let mut ctx = RegionCtx::new(region, offset);
                    let assigned_sig =
                        schnorr_gate.assign_sig(&mut ctx, &Value::known(self.signature))?;
                    let assigned_msg = schnorr_gate
                        .ecc_gate
                        .main_gate
                        .assign_value(&mut ctx, Value::known(self.msg))?;
                    let assigned_pk = schnorr_gate
                        .ecc_gate
                        .witness_point(&mut ctx, &Value::known(self.pk))?;

                    schnorr_gate.verify(&mut ctx, &assigned_sig, &assigned_pk, &assigned_msg)?;

                    // We could test with hashing the PIs, but that limits us more wrt to testing (different pk, different msg)
                    // rescue_hash_gate.hash(&mut ctx, &[assigned_pk.x, assigned_pk.y, assigned_msg])

                    Ok((assigned_pk.x, assigned_pk.y, assigned_msg))
                },
            )?;

            let ecc_gate = schnorr_gate.ecc_gate;
            layouter.constrain_instance(hashed_msg_pk.0.cell(), ecc_gate.instance_col(), 0)?;

            layouter.constrain_instance(hashed_msg_pk.1.cell(), ecc_gate.instance_col(), 1)?;

            layouter.constrain_instance(hashed_msg_pk.2.cell(), ecc_gate.instance_col(), 2)?;

            Ok(())
        }
    }

    #[test]
    fn schnorr_signature() {
        const K: u32 = 12;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let (sk, pk) = Schnorr::keygen(&mut rng);
        let msg = Base::random(&mut rng);

        let signature = Schnorr::sign((sk, pk), msg, &mut rng);

        let circuit = TestCircuitSignature { signature, pk, msg };

        let pi = vec![vec![pk.get_u(), pk.get_v(), msg]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run Schnorr verifier mock prover");

        assert!(prover.verify().is_ok());

        // We try to verify for a different message (the hash of the PI
        let msg_fake = Base::random(&mut rng);

        let pi = vec![vec![pk.get_u(), pk.get_v(), msg_fake]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_err());

        // We try to verify with a different pk
        let pk_fake = ExtendedPoint::random(&mut rng).to_affine();

        let pi = vec![vec![pk_fake.get_u(), pk_fake.get_v(), msg]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_err());
    }
}
