//! Chip implementations for the ECC gadgets.

use arrayvec::ArrayVec;

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Fixed},
};
use halo2curves::CurveAffine;

use group::{Curve, Group};
use halo2_proofs::plonk::Instance;
use halo2curves::jubjub::{AffinePoint, Base, Scalar};
use std::convert::TryInto;
use std::fmt::Debug;

pub(super) mod add;
pub mod constants;
pub(super) mod witness_point;

use crate::ecc::chip::add::AddConfig;
use crate::instructions::MainGateInstructions;
use crate::main_gate::{MainGate, MainGateConfig};
use crate::util::RegionCtx;
use crate::AssignedValue;
pub use constants::*;

/// A curve point represented in affine (x, y) coordinates, or the
/// identity represented as (0, 0).
/// Each coordinate is assigned to a cell.
#[derive(Clone, Debug)]
pub struct AssignedEccPoint {
    /// x-coordinate
    ///
    /// Stored as an `Assigned<F>` to enable batching inversions.
    pub x: AssignedValue<Base>,
    /// y-coordinate
    ///
    /// Stored as an `Assigned<F>` to enable batching inversions.
    pub y: AssignedValue<Base>,
}

impl AssignedEccPoint {
    /// Constructs a point from its coordinates, without checking they are on the curve.
    ///
    /// This is an internal API that we only use where we know we have a valid curve point.
    pub(crate) fn from_coordinates_unchecked(
        x: AssignedValue<Base>,
        y: AssignedValue<Base>,
    ) -> Self {
        AssignedEccPoint { x, y }
    }

    /// Returns the value of this curve point, if known.
    pub fn point(&self) -> Value<AffinePoint> {
        self.x.value().zip(self.y.value()).map(|(x, y)| {
            if x.is_zero_vartime() && y.is_zero_vartime() {
                AffinePoint::identity()
            } else {
                AffinePoint::from_raw_unchecked(*x, *y)
            }
        })
    }

    /// The cell containing the affine x-coordinate,
    /// or 0 for the zero point.
    pub fn x(&self) -> AssignedValue<Base> {
        self.x.clone()
    }

    /// The cell containing the affine y-coordinate,
    /// or 0 for the zero point.
    pub fn y(&self) -> AssignedValue<Base> {
        self.y.clone()
    }

    #[cfg(test)]
    fn is_identity(&self) -> Value<bool> {
        self.x.value().map(|x| x.is_zero_vartime())
    }
}

/// Configuration for [`EccChip`].
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct EccConfig {
    /// Advice columns needed
    x_p: Column<Advice>,
    y_p: Column<Advice>,
    x_qr: Column<Advice>,
    y_qr: Column<Advice>,
    alpha: Column<Advice>,
    beta: Column<Advice>,
    scalar_mul: Column<Advice>,

    /// Addition
    add: AddConfig,

    /// Witness point
    witness_point: witness_point::Config,
}

/// An [`EccInstructions`] chip that uses 10 advice columns.
#[derive(Clone, Debug)]
pub struct EccChip {
    pub main_gate: MainGate<Base>,
    config: EccConfig,
}

impl EccChip {
    /// Given config creates new chip that implements ranging
    pub fn new(main_gate: MainGate<Base>, config: EccConfig) -> Self {
        Self { main_gate, config }
    }

    /// Configures lookup and returns the resulting config
    pub fn configure(
        meta: &mut ConstraintSystem<Base>,
        maingate_config: MainGateConfig,
    ) -> EccConfig {
        let q_add = meta.complex_selector();

        // we reuse maingate's columns We just need two extra columns
        let x_p = maingate_config.a;
        let y_p = maingate_config.b;

        let x_qr = maingate_config.c;
        let y_qr = maingate_config.d;

        let alpha = maingate_config.e;
        let beta = meta.advice_column();

        let scalar_mul = meta.advice_column();
        meta.enable_equality(scalar_mul);

        let add_config = add::AddConfig::configure(meta, x_p, y_p, x_qr, y_qr, alpha, beta);

        let witness_config = witness_point::Config::configure(meta, x_p, y_p);

        EccConfig {
            x_p,
            y_p,
            x_qr,
            y_qr,
            alpha,
            beta,
            scalar_mul,
            add: add_config,
            witness_point: witness_config,
        }
    }
}

impl Chip<Base> for EccChip {
    type Config = EccConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// The set of circuit instructions required to use the ECC gadgets.
pub trait EccInstructions<C: CurveAffine>: Chip<C::Base> + Clone + Debug {
    /// Variable representing a scalar used in variable-base scalar mul.
    ///
    /// This type is treated as a full-width scalar. However, if `Self` implements
    /// [`BaseFitsInScalarInstructions`] then this may also be constructed from an element
    /// of the base field.
    type ScalarVar: Clone + Debug;
    /// Variable representing an elliptic curve point.
    type Point: Clone + Debug;
    /// Variable representing the x-coordinate of an
    /// elliptic curve point.
    type X: Clone + Debug;

    /// Constrains point `a` to be equal in value to point `b`.
    fn constrain_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<(), Error>;

    /// Witnesses the given point as a private input to the circuit.
    /// This allows the point to be the identity, mapped to (0, 0) in
    /// affine coordinates.
    fn witness_point(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        value: &Value<C>,
    ) -> Result<Self::Point, Error>;

    /// Witnesses a full-width scalar to be used in variable-base multiplication.
    fn witness_scalar_var(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        value: &Value<C::Scalar>,
    ) -> Result<Self::ScalarVar, Error>;

    /// Performs complete point addition, returning `a + b`.
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error>;

    /// Performs variable-base scalar multiplication, returning `[scalar] base`.
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        scalar: &Self::ScalarVar,
        base: &Self::Point,
    ) -> Result<Self::Point, Error>;
}

/// Structure representing a `Scalar` used in variable-base multiplication.
#[derive(Clone, Debug)]
pub struct ScalarVar(pub(crate) AssignedValue<Base>);

impl EccInstructions<AffinePoint> for EccChip {
    type ScalarVar = ScalarVar;
    type Point = AssignedEccPoint;
    type X = AssignedValue<Base>;

    fn constrain_equal(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<(), Error> {
        ctx.constrain_equal(a.x().cell(), b.x().cell())?;
        ctx.constrain_equal(a.y().cell(), b.y().cell())?;

        Ok(())
    }

    fn witness_point(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        value: &Value<AffinePoint>, // todo: We allow for points not in the subgroup. Double check
    ) -> Result<Self::Point, Error> {
        let config = self.config().witness_point;
        config.point(ctx, value)
    }

    fn witness_scalar_var(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        value: &Value<Scalar>,
    ) -> Result<Self::ScalarVar, Error> {
        let value_with_base = value.map(|v| Base::from_bytes(&v.to_bytes()).unwrap());
        let scalar =
            ctx.assign_advice(|| "assign scalar", self.config.scalar_mul, value_with_base)?;
        ctx.next();
        Ok(ScalarVar(scalar))
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config().add;

        config.assign_region(ctx, a, b)
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        scalar: &Self::ScalarVar, // todo: we might want to have a type for scalar
        base: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let mut assigned_p = base.clone();

        // Decompose scalar into bits
        let decomposition = self
            .main_gate
            .to_bits(ctx, &scalar.0, Base::NUM_BITS as usize)?;

        // Proceed with double and add algorithm for each bit of the scalar
        // Initialise the aggregator at zero
        let assigned_0x =
            ctx.assign_advice(|| "x of zero", self.config.x_qr, Value::known(Base::ZERO))?;

        let assigned_0y =
            ctx.assign_advice(|| "y of zero", self.config.y_qr, Value::known(Base::ONE))?;

        ctx.next();

        let assigned_0 = AssignedEccPoint {
            x: assigned_0x.clone(),
            y: assigned_0y.clone(),
        };

        // We clone the cell of zero, to make it mutable for ease of looping over the bits
        let mut assigned_aggr = assigned_0.clone();

        // Constrain the zero point
        self.main_gate.assert_zero(ctx, &assigned_0x)?;
        self.main_gate.assert_one(ctx, &assigned_0y)?;

        for bit in decomposition {
            let cond_add_x = self
                .main_gate
                .select(ctx, &assigned_p.x, &assigned_0.x, &bit)?;
            let cond_add_y = self
                .main_gate
                .select(ctx, &assigned_p.y, &assigned_0.y, &bit)?;

            let assigned_cond_add = AssignedEccPoint {
                x: cond_add_x,
                y: cond_add_y,
            };

            // Aggr = Aggr + cond_add
            assigned_aggr =
                self.config
                    .add
                    .assign_region(ctx, &assigned_aggr, &assigned_cond_add)?;

            // Point = [2] Point
            assigned_p = self
                .config
                .add
                .assign_region(ctx, &assigned_p, &assigned_p)?;
        }

        Ok(assigned_aggr)
    }
}

impl EccChip {
    /// Get the instance column
    pub fn instance_col(&self) -> Column<Instance> {
        self.main_gate.config.instance
    }
}

#[cfg(test)]
mod tests {
    use crate::ecc::chip::{EccChip, EccConfig, EccInstructions};
    use crate::main_gate::{MainGate, MainGateConfig};
    use crate::util::RegionCtx;
    use ff::Field;
    use group::{Curve, Group};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint, Scalar};
    use halo2curves::CurveAffine;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::ops::Mul;

    #[derive(Clone)]
    struct TestCircuitConfig {
        maingate_config: MainGateConfig,
        ecc_config: EccConfig,
    }

    #[derive(Clone, Debug, Default)]
    struct TestCircuit {
        point: AffinePoint,
        scalar: Scalar,
    }

    impl Circuit<Base> for TestCircuit {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
            let maingate = MainGate::configure(meta);
            let ecc_config = EccChip::configure(meta, maingate.config.clone());
            // todo: do we need to enable equality?

            Self::Config {
                maingate_config: maingate.config,
                ecc_config,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Base>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::new(config.maingate_config);
            let ecc_chip = EccChip::new(main_gate, config.ecc_config);

            let assigned_val = layouter.assign_region(
                || "Ecc mult test",
                |region| {
                    let offset = 0;
                    let mut ctx = RegionCtx::new(region, offset);
                    let assigned_scalar =
                        ecc_chip.witness_scalar_var(&mut ctx, &Value::known(self.scalar))?;
                    let assigned_point =
                        ecc_chip.witness_point(&mut ctx, &Value::known(self.point))?;

                    ecc_chip.mul(&mut ctx, &assigned_scalar, &assigned_point)
                },
            )?;

            layouter.constrain_instance(
                assigned_val.x.cell(),
                ecc_chip.main_gate.config.instance,
                0,
            )?;
            layouter.constrain_instance(
                assigned_val.y.cell(),
                ecc_chip.main_gate.config.instance,
                1,
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_ec_mul() {
        const K: u32 = 11;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let point = ExtendedPoint::random(&mut rng);
        let scalar = Scalar::random(&mut rng);
        let res = point.mul(&scalar);

        let circuit = TestCircuit {
            point: point.to_affine(),
            scalar,
        };

        let res_coords = res.to_affine().coordinates().unwrap();
        let pi = vec![vec![*res_coords.x(), *res_coords.y()]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_ok());

        let random_result = ExtendedPoint::random(&mut rng);
        let random_res_coords = random_result.to_affine().coordinates().unwrap();

        let pi = vec![vec![*random_res_coords.x(), *random_res_coords.y()]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_err());

        // mult by one
        let scalar = Scalar::one();
        let circuit = TestCircuit {
            point: point.to_affine(),
            scalar,
        };

        let res_coords = point.to_affine().coordinates().unwrap();
        let pi = vec![vec![*res_coords.x(), *res_coords.y()]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_ok());

        // mult by zero
        let scalar = Scalar::zero();
        let circuit = TestCircuit {
            point: point.to_affine(),
            scalar,
        };

        let pi = vec![vec![Base::ZERO, Base::ONE]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_ok());
    }
}
