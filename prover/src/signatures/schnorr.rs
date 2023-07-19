//! Schnorr signature verification

use crate::ecc::chip::{AssignedEccPoint, EccChip, EccConfig, EccInstructions, ScalarVar};
use crate::instructions::{MainGateInstructions, Term};
use num_integer::Integer;

use crate::rescue::{
    RescueCrhfGate, RescueCrhfGateConfig, RescueCrhfInstructions, RescueParametersBls,
};
use crate::util::{big_to_fe, fe_to_big, RegionCtx};
use crate::AssignedValue;
use ff::{Field, PrimeField};
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
        let two_pk = self.ecc_gate.add(ctx, pk, pk)?;
        let four_pk = self.ecc_gate.add(ctx, &two_pk, &two_pk)?;
        let eight_pk = self.ecc_gate.add(ctx, &four_pk, &four_pk)?;

        let assigned_generator = self.ecc_gate.witness_point(
            ctx,
            &Value::known(ExtendedPoint::from(SubgroupPoint::generator()).to_affine()),
        )?;

        let one = self
            .ecc_gate
            .main_gate
            .assign_bit(ctx, Value::known(Base::ONE))?;
        // check low order PK
        self.ecc_gate.main_gate.assert_not_zero(ctx, &eight_pk.x)?;
        self.ecc_gate
            .main_gate
            .assert_not_equal(ctx, &eight_pk.y, &one)?;

        let input_hash = [signature.0.x.clone(), pk.x.clone(), msg.clone()];
        let challenge = self.rescue_hash_gate.hash(ctx, &input_hash)?; //  larger than mod with high prob

        let lhs = self.combined_mul(
            ctx,
            &signature.1 .0,
            &challenge,
            &assigned_generator,
            pk,
        )?;

        self.ecc_gate.constrain_equal(ctx, &lhs, &signature.0)?;

        Ok(())
    }

    // We need to negate the second scalar prior to the addition
    fn combined_mul(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        scalar_1: &AssignedValue<Base>,
        scalar_2: &AssignedValue<Base>,
        base_1: &AssignedEccPoint,
        base_2: &AssignedEccPoint,
    ) -> Result<AssignedEccPoint, Error> {
        // We compute a combined mul for `signature.1 * generator - challenge * pk`. For that
        // we first negate the challenge, and the compute use combined_mul. We negate with
        // respect to the Scalar modulus bytes. However, we allow the challenge to be above the
        // modulus, because the loss in security is not a concern. However, this slightly complicates
        // this negation.
        // We need to find (a,b) = challenge.div_remainder(modulus), then compute
        // neg_challenge = modulus - b, and prove that challenge + neg_challenge = (a + 1) * modulus
        // With this we should save ~250 constraints, so probably worth it.

        let jub_jub_scalar_bytes = [
            183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0, 59, 52,
            1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
        ];

        let jubjub_mod =
            Base::from_bytes(&jub_jub_scalar_bytes).expect("Failed to deserialise modulus"); // This will not fail as jubjub mod is smaller than BLS

        let mult_remainder = scalar_2.value().map(|&val| {
            let (mult, remainder) = fe_to_big(val).div_rem(&fe_to_big(jubjub_mod));
            [big_to_fe(mult), big_to_fe(remainder)]
        }).transpose_vec(2);

        self.ecc_gate.main_gate.assert_zero_sum(
            ctx,
            &[Term::Assigned(scalar_2, - Base::ONE), Term::Unassigned(mult_remainder[0], jubjub_mod), Term::Unassigned(mult_remainder[1], Base::ONE)],
            Base::ZERO
        )?;

        let neg_scalar_2 = self
            .ecc_gate
            .main_gate
            .assign_value(ctx, mult_remainder[1].map(|val| jubjub_mod - val))?;

        self.ecc_gate.main_gate.assert_zero_sum(
            ctx,
            &[Term::Assigned(scalar_2, Base::ONE), Term::Assigned(&neg_scalar_2, Base::ONE), Term::Unassigned(mult_remainder[0] + Value::known(Base::ONE), - jubjub_mod)],
            Base::ZERO
        )?;

        // Decompose scalar into bits
        let mut decomposition_1 =
            self.ecc_gate
                .main_gate
                .to_bits(ctx, &scalar_1, Base::NUM_BITS as usize)?;
        decomposition_1.reverse(); // to get MSB first

        let mut decomposition_2 =
            self.ecc_gate
                .main_gate
                .to_bits(ctx, &neg_scalar_2, Base::NUM_BITS as usize)?;
        decomposition_2.reverse(); // to get MSB first

        // Initialise the aggregator at zero
        let assigned_0x = ctx.assign_advice(
            || "x of zero",
            self.ecc_gate.config.add.x_pr,
            Value::known(Base::ZERO),
        )?;
        ctx.next();

        let assigned_0y = ctx.assign_advice(
            || "y of zero",
            self.ecc_gate.config.add.y_pr,
            Value::known(Base::ONE),
        )?;
        ctx.assign_fixed(|| "base", self.ecc_gate.main_gate.config.sb, Base::ONE)?;
        ctx.assign_fixed(
            || "s_constant",
            self.ecc_gate.main_gate.config.s_constant,
            -Base::ONE,
        )?;
        ctx.next();

        // We copy the aggregator to its right position
        let assigned_aggr_x = ctx.copy_advice(
            || "x aggregator",
            self.ecc_gate.config.add.x_pr,
            assigned_0x,
        )?;
        let assigned_aggr_y = ctx.copy_advice(
            || "y aggregator",
            self.ecc_gate.config.add.y_pr,
            assigned_0y.clone(),
        )?;

        let mut assigned_aggr = AssignedEccPoint {
            x: assigned_aggr_x,
            y: assigned_aggr_y,
        };

        for (bit_1, bit_2) in decomposition_1.into_iter().zip(decomposition_2.into_iter()) {
            // We copy the aggregator into the `q` cell for doubling
            let assigned_aggr_x = ctx.copy_advice(
                || "x aggregator double",
                self.ecc_gate.config.add.x_q,
                assigned_aggr.x.clone(),
            )?;
            let assigned_aggr_y = ctx.copy_advice(
                || "y aggregator double",
                self.ecc_gate.config.add.y_q,
                assigned_aggr.y.clone(),
            )?;

            let assigned_aggr_q = AssignedEccPoint {
                x: assigned_aggr_x,
                y: assigned_aggr_y,
            };

            // We copy one for always performing doubling
            let b = ctx.copy_advice(|| "one", self.ecc_gate.config.add.b, assigned_0y.clone())?;

            // We perform doubling
            assigned_aggr = self
                .ecc_gate
                .cond_add(ctx, &assigned_aggr, &assigned_aggr_q, &b)?;

            // Now we conditionally perform addition of the first point. We begin by copying the base point to the `q` cell
            let base_x = ctx.copy_advice(
                || "x point cond add",
                self.ecc_gate.config.add.x_q,
                base_1.x.clone(),
            )?;
            let base_y = ctx.copy_advice(
                || "y point cond add",
                self.ecc_gate.config.add.y_q,
                base_1.y.clone(),
            )?;

            let base_q = AssignedEccPoint {
                x: base_x,
                y: base_y,
            };

            // We now copy the bit to its right position
            let b = ctx.copy_advice(|| "b1", self.ecc_gate.config.add.b, bit_1)?;

            // Aggr = Aggr + cond_add
            assigned_aggr = self.ecc_gate.cond_add(ctx, &assigned_aggr, &base_q, &b)?;

            // Now we conditionally perform addition of the second point. We begin by copying the base point to the `q` cell
            let base_x = ctx.copy_advice(
                || "x point cond add",
                self.ecc_gate.config.add.x_q,
                base_2.x.clone(),
            )?;
            let base_y = ctx.copy_advice(
                || "y point cond add",
                self.ecc_gate.config.add.y_q,
                base_2.y.clone(),
            )?;

            let base_q = AssignedEccPoint {
                x: base_x,
                y: base_y,
            };

            // We now copy the bit to its right position
            let b = ctx.copy_advice(|| "b2", self.ecc_gate.config.add.b, bit_2)?;

            // Aggr = Aggr + cond_add
            assigned_aggr = self.ecc_gate.cond_add(ctx, &assigned_aggr, &base_q, &b)?;
        }
        ctx.next();

        Ok(assigned_aggr)
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

        prover.assert_satisfied();
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
