//! Chip implementations for the ECC gadgets.

use arrayvec::ArrayVec;

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Fixed},
};
use halo2curves::{jubjub, CurveAffine};

use std::convert::TryInto;
use std::fmt::Debug;
use group::{Curve, Group};
use halo2curves::jubjub::AffinePoint;


pub(super) mod add;
pub mod constants;
// pub(super) mod mul;
pub(super) mod witness_point;

pub use constants::*;
use crate::AssignedValue;
use crate::ecc::chip::add::Config;
use crate::main_gate::{MainGate, MainGateConfig};
use crate::util::RegionCtx;

/// A curve point represented in affine (x, y) coordinates, or the
/// identity represented as (0, 0).
/// Each coordinate is assigned to a cell.
#[derive(Clone, Debug)]
pub struct AssignedEccPoint {
    /// x-coordinate
    ///
    /// Stored as an `Assigned<F>` to enable batching inversions.
    x: AssignedValue<jubjub::Base>,
    /// y-coordinate
    ///
    /// Stored as an `Assigned<F>` to enable batching inversions.
    y: AssignedValue<jubjub::Base>,
}

impl AssignedEccPoint {
    /// Constructs a point from its coordinates, without checking they are on the curve.
    ///
    /// This is an internal API that we only use where we know we have a valid curve point.
    pub(crate) fn from_coordinates_unchecked(
        x: AssignedValue<jubjub::Base>,
        y: AssignedValue<jubjub::Base>,
    ) -> Self {
        AssignedEccPoint { x, y }
    }

    /// Returns the value of this curve point, if known.
    pub fn point(&self) -> Value<jubjub::AffinePoint> {
        self.x.value().zip(self.y.value()).map(|(x, y)| {
            if x.is_zero_vartime() && y.is_zero_vartime() {
                jubjub::AffinePoint::identity()
            } else {
                jubjub::AffinePoint::from_raw_unchecked(*x, *y)
            }
        })
    }

    /// The cell containing the affine x-coordinate,
    /// or 0 for the zero point.
    pub fn x(&self) -> AssignedValue<jubjub::Base> {
        self.x.clone().into()
    }

    /// The cell containing the affine y-coordinate,
    /// or 0 for the zero point.
    pub fn y(&self) -> AssignedValue<jubjub::Base> {
        self.y.clone().into()
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
    maingate_config: MainGateConfig,
    /// Advice columns needed
    x_p:Column<Advice>,
    y_p:Column<Advice>,
    x_qr:Column<Advice>,
    y_qr:Column<Advice>,
    alpha:Column<Advice>,
    beta:Column<Advice>,

    /// Addition
    add: add::Config,

    // /// Variable-base scalar multiplication
    // mul: mul::Config,

    /// Witness point
    witness_point: witness_point::Config,
}

/// An [`EccInstructions`] chip that uses 10 advice columns.
#[derive(Clone, Debug)]
pub struct EccChip {
    config: EccConfig,
}

impl EccChip {
    /// Given config creates new chip that implements ranging
    pub fn new(config: EccConfig) -> Self {
        Self {
            config,
        }
    }

    /// Configures lookup and returns the resulting config
    pub fn configure(meta: &mut ConstraintSystem<jubjub::Base>) -> EccConfig {
        let q_add = meta.complex_selector();

        let x_p = meta.advice_column();
        let y_p = meta.advice_column();

        let x_qr = meta.advice_column();
        let y_qr = meta.advice_column();

        let alpha = meta.advice_column();
        let beta = meta.advice_column();

        let add_config = add::Config::configure(
            meta, x_p, y_p, x_qr, y_qr, alpha, beta
        );

        let witness_config = witness_point::Config::configure(
            meta, x_p, y_p
        );

        EccConfig {
            maingate_config: MainGate::configure(meta).config().clone(),
            x_p,
            y_p,
            x_qr,
            y_qr,
            alpha,
            beta,
            add: add_config,
            witness_point: witness_config
        }
    }
}

impl Chip<jubjub::Base> for EccChip {
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
pub trait EccInstructions<C: CurveAffine>:
Chip<C::Base> + Clone + Debug
{
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
        value: Value<C>,
    ) -> Result<Self::Point, Error>;

    /// Witnesses a full-width scalar to be used in variable-base multiplication.
    fn witness_scalar_var(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        value: Value<C::Scalar>,
    ) -> Result<Self::ScalarVar, Error>;

    /// Extracts the x-coordinate of a point.
    fn extract_p<Point: Into<Self::Point> + Clone>(point: &Point) -> Self::X;

    /// Performs complete point addition, returning `a + b`.
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        a: &Value<AffinePoint>,
        b: &Value<AffinePoint>,
    ) -> Result<Self::Point, Error>;

    // /// Performs variable-base scalar multiplication, returning `[scalar] base`.
    // fn mul(
    //     &self,
    //     ctx: &mut RegionCtx<'_, F>,
    //     scalar: &Self::ScalarVar,
    //     base: &Self::Point,
    // ) -> Result<(Self::Point, Self::ScalarVar), Error>;
}

/// Structure representing a `Scalar` used in variable-base multiplication.
#[derive(Clone, Debug)]
pub struct ScalarVar (AssignedValue<jubjub::Base>);

impl EccInstructions<jubjub::AffinePoint> for EccChip
{
    type ScalarVar = ScalarVar;
    type Point = AssignedEccPoint;
    type X = AssignedValue<jubjub::Base>;

    fn constrain_equal(
        &self,
        ctx: &mut RegionCtx<'_, jubjub::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<(), Error> {
        ctx.constrain_equal(a.x().cell(), b.x().cell())?;
        ctx.constrain_equal(a.y().cell(), b.y().cell())?;

        Ok(())
    }

    fn witness_point(
        &self,
        ctx: &mut RegionCtx<'_, jubjub::Base>,
        value: Value<jubjub::AffinePoint>, // todo: We allow for points not in the subgroup. Double check
    ) -> Result<Self::Point, Error> {
        let config = self.config().witness_point;
        config.point(ctx, value)
    }

    fn witness_scalar_var(
        &self,
        _ctx: &mut RegionCtx<'_, jubjub::Base>,
        _value: Value<jubjub::Scalar>,
    ) -> Result<Self::ScalarVar, Error> {
        todo!()
    }

    fn extract_p<Point: Into<Self::Point> + Clone>(point: &Point) -> Self::X {
        let point: AssignedEccPoint = (point.clone()).into();
        point.x()
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, jubjub::Base>,
        a: &Value<AffinePoint>,
        b: &Value<AffinePoint>,
    ) -> Result<Self::Point, Error> {
        let config = self.config().add;
        config.assign_region(
            ctx,
            &(
                a.map(|p| *(p.coordinates().unwrap().x())),
                a.map(|p| *(p.coordinates().unwrap().y())),
            ),
            &(
                b.map(|p| *(p.coordinates().unwrap().x())),
                b.map(|p| *(p.coordinates().unwrap().y()))
            )
        )
    }

    // fn mul(
    //     &self,
    //     layouter: &mut impl Layouter<jubjub::Base>,
    //     scalar: &Self::ScalarVar,
    //     base: &Self::NonIdentityPoint,
    // ) -> Result<(Self::Point, Self::ScalarVar), Error> {
    //     let config = self.config().mul;
    //     config.assign(
    //             ctx.namespace(|| "variable-base scalar mul"),
    //             scalar.clone(),
    //             base,
    //     )
    // }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit;
    use halo2curves::jubjub::{AffinePoint, ExtendedPoint};
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use super::*;

    #[derive(Clone)]
    struct TestCircuitConfig {
        ecc_config: EccConfig,
    }

    #[derive(Clone, Debug, Default)]
    struct TestCircuit {
        point_a: AffinePoint,
        point_b: AffinePoint,
    }

    impl Circuit<jubjub::Base> for TestCircuit {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<jubjub::Base>) -> Self::Config {
            let ecc_config = EccChip::configure(meta);
            // todo: do we need to enable equality?

            Self::Config {
                ecc_config,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<jubjub::Base>,
        ) -> Result<(), Error> {
            let ecc_chip = EccChip::new(config.ecc_config.clone());

            let assigned_val = layouter.assign_region(
                || "Ecc addition test",
                |region| {
                    let offset = 0;
                    let mut ctx = RegionCtx::new(region, offset);

                    ecc_chip.add(&mut ctx, &Value::known(self.point_a), &Value::known(self.point_b))
                },
            )?;

            layouter.constrain_instance(assigned_val.x.cell(), config.ecc_config.maingate_config.instance.clone(), 0)?;
            layouter.constrain_instance(assigned_val.y.cell(), config.ecc_config.maingate_config.instance.clone(), 1)?;

            Ok(())
        }
    }

    #[test]
    fn test_ec_addition() {
        const K: u32 = 11;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let lhs = ExtendedPoint::random(&mut rng);
        let rhs = ExtendedPoint::random(&mut rng);
        let res = lhs + rhs;

        let circuit = TestCircuit {
            point_a: lhs.to_affine(),
            point_b: rhs.to_affine(),
        };

        let res_coords = res.to_affine().coordinates().unwrap();
        let pi = vec![vec![*res_coords.x(), *res_coords.y()]];

        let prover = MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        prover.verify().unwrap();
        assert!(prover.verify().is_ok());
    }
}

