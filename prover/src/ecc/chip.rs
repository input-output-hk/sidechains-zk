//! Chip implementations for the ECC gadgets.

use arrayvec::ArrayVec;

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};
use halo2curves::{Coordinates, CurveAffine};
use blstrs::{};

use group::{Curve, Group};
use halo2_proofs::plonk::Instance;
//use halo2curves::jubjub::{AffinePoint, Base, Scalar};
use blstrs::{JubjubAffine as AffinePoint, Base, Fr as Scalar};
use std::convert::TryInto;
use std::fmt::Debug;
use std::ops::Mul;

pub(super) mod add;
pub mod constants;
pub(super) mod witness_point;

use crate::ecc::chip::add::CondAddConfig;
use crate::instructions::{MainGateInstructions, Term};
use crate::main_gate::{MainGate, MainGateConfig};
use crate::util::{decompose, RegionCtx};
use crate::{AssignedCondition, AssignedValue};
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
    scalar_mul: Column<Advice>,

    /// Addition
    pub(crate) add: CondAddConfig,

    /// Witness point
    witness_point: witness_point::Config,
}

/// An [`EccInstructions`] chip that uses 10 advice columns.
#[derive(Clone, Debug)]
pub struct EccChip {
    pub main_gate: MainGate<Base>,
    pub(crate) config: EccConfig,
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
        let x_pr = maingate_config.a;
        let y_pr = maingate_config.b;

        let x_q = maingate_config.c;
        let y_q = maingate_config.d;

        let b = meta.advice_column(); // todo: fails if I assign e

        let scalar_mul = meta.advice_column();
        meta.enable_equality(scalar_mul);

        let add_config = CondAddConfig::configure(meta, b, x_pr, y_pr, x_q, y_q);

        let witness_config = witness_point::Config::configure(meta, x_pr, y_pr);

        EccConfig {
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
    /// \[`BaseFitsInScalarInstructions`\] then this may also be constructed from an element
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

    /// Performs a conditional addition, return `a + cond * b`. Takes as input an
    /// `Option` of a point as a first argument such that one can provide `None`,
    /// in which case the function assumes that that value is already assigned by a
    /// previous call to this function.
    ///
    /// This function does not call `ctx.next()`, after the addition, meaning that the
    /// offset is set in the row were the result is stored.
    fn cond_add(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &Self::Point,
        b: &Self::Point,
        cond: &AssignedCondition<Base>,
    ) -> Result<Self::Point, Error>;

    /// Performs variable-base scalar multiplication, returning `[scalar] base`.
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        scalar: &Self::ScalarVar,
        base: &Self::Point,
    ) -> Result<Self::Point, Error>;

    // Given three EC points A1, A2, A3 and two bits b0, b1, this function returns
    // A{b0 + 2*b1}, with A0 being the identity point.
    //
    // let (x, y) be the output coordinates. It is easy to see that
    //
    // x = b0 * (1 - b1) * x_1 + (1 - b0) * b1 * x_2 + b0 * b1 * x3
    //   = x1 * b0 + x2 * b1 + (x3 - x2 - x1) * b0 * b1
    // and,
    //
    // y = (1 - b0) * (1 - b1) + b0 * (1 - b1) * y1 + (1 - b0) * b1 * y2 + b0 * b1 * y3
    //   = (y1 - 1) * b0 + (y2 - 1) * b1 + (y3 - y2 - y1 + 1) * b0 * b1 + 1
    //
    // We note that this function is used for fixed-based multiplication. This means that
    // everytime this function is used, A1, A2 and A3 are public values (and, by consequence,
    // their corresponding coordinates). This means that we can achieve this with the following
    // two constraints:
    //
    //                  q_1 * b0 + q2 * b1 + q_m * b0 * b1 = q_O * x
    //
    // with q_1 = x1, q_2 = x2, q_m = x3 - x2 - x1, and q_O = 1, and:
    //
    //               q_1 * b0 + q_2 * b1 + q_m * b0 * b1 + q_C = q_O * y
    //
    // with q_1 = y1 - 1, q_2 = y_2 - 1, q_M = y3 - y2 - y1 + 1, and q_O = q_C = 1.
    fn point_selection(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        a_1: Coordinates<AffinePoint>,
        a_2: Coordinates<AffinePoint>,
        a_3: Coordinates<AffinePoint>,
        bit_1: &AssignedCondition<C::Base>,
        bit_2: &AssignedCondition<C::Base>,
    ) -> Result<Self::Point, Error>;

    /// Performs fixed-base scalar multiplication, returning `[scalar] basePoint`.
    fn fixed_mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Base>,
        scalar: &Self::ScalarVar,
        base: AffinePoint,
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
        lhs: &Self::Point,
        rhs: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config().add;

        let cond = ctx.assign_advice(|| "bit", self.config.add.b, Value::known(Base::ONE))?;
        self.main_gate.assert_one(ctx, &cond)?;

        let b = ctx.copy_advice(|| "b", self.config.add.b, cond)?; // todo: extra row :: necessary?

        // Copy point `lhs` into `x_pr`, `y_pr` columns
        let lhs_x = ctx.assign_advice(|| "x_p", self.config.add.x_pr, lhs.x.value().map(|v| *v))?;
        // ctx.constrain_equal(lhs_x.cell(), lhs.x.cell())?;
        let lhs_y = ctx.assign_advice(|| "y_p", self.config.add.y_pr, lhs.y.value().map(|v| *v))?;
        // ctx.constrain_equal(lhs_y.cell(), lhs.y.cell())?;
        // Copy point `q` into `x_q`, `y_q` columns
        let rhs_x = ctx.assign_advice(|| "x_q", self.config.add.x_q, rhs.x.value().map(|v| *v))?;
        // ctx.constrain_equal(rhs_x.cell(), rhs.x.cell())?;
        let rhs_y = ctx.assign_advice(|| "y_q", self.config.add.y_q, rhs.y.value().map(|v| *v))?;
        // ctx.constrain_equal(rhs_y.cell(), rhs.x.cell())?;

        let lhs = AssignedEccPoint { x: lhs_x, y: lhs_y };

        let rhs = AssignedEccPoint { x: rhs_x, y: rhs_y };

        let res = config.assign_region(ctx, &lhs, &rhs, &b);
        ctx.next();
        res
    }

    fn cond_add(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &Self::Point,
        b: &Self::Point,
        cond: &AssignedCondition<Base>,
    ) -> Result<Self::Point, Error> {
        let config = self.config().add;
        config.assign_region(ctx, a, b, cond)
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        scalar: &Self::ScalarVar, // todo: we might want to have a type for scalar
        base: &Self::Point,
    ) -> Result<Self::Point, Error> {
        // Decompose scalar into bits
        let mut decomposition = self
            .main_gate
            .to_bits(ctx, &scalar.0, Base::NUM_BITS as usize)?;
        decomposition.reverse(); // to get MSB first

        // Initialise the aggregator at zero
        let assigned_0x = ctx.assign_advice(
            || "x of zero",
            self.config.add.x_pr,
            Value::known(Base::ZERO),
        )?;
        ctx.next();

        let assigned_0y = ctx.assign_advice(
            || "y of zero",
            self.config.add.y_pr,
            Value::known(Base::ONE),
        )?;
        ctx.assign_fixed(|| "base", self.main_gate.config.sb, Base::ONE)?;
        ctx.assign_fixed(
            || "s_constant",
            self.main_gate.config.s_constant,
            -Base::ONE,
        )?;
        ctx.next();

        // We copy the aggregator to its right position
        let assigned_aggr_x =
            ctx.copy_advice(|| "x aggregator", self.config.add.x_pr, assigned_0x)?;
        let assigned_aggr_y =
            ctx.copy_advice(|| "y aggregator", self.config.add.y_pr, assigned_0y.clone())?;

        let mut assigned_aggr = AssignedEccPoint {
            x: assigned_aggr_x,
            y: assigned_aggr_y,
        };

        for (index, bit) in decomposition.into_iter().enumerate() {
            // We copy the aggregator into the `q` cell for doubling
            let assigned_aggr_x = ctx.copy_advice(
                || "x aggregator double",
                self.config.add.x_q,
                assigned_aggr.x.clone(),
            )?;
            let assigned_aggr_y = ctx.copy_advice(
                || "y aggregator double",
                self.config.add.y_q,
                assigned_aggr.y.clone(),
            )?;

            let assigned_aggr_q = AssignedEccPoint {
                x: assigned_aggr_x,
                y: assigned_aggr_y,
            };

            // We copy one for always performing doubling
            let b = ctx.copy_advice(|| "one", self.config.add.b, assigned_0y.clone())?;

            // We perform doubling
            assigned_aggr = self.cond_add(ctx, &assigned_aggr, &assigned_aggr_q, &b)?;

            // Now we conditionally perform addition. We begin by copying the base point to the `q` cell
            let base_x =
                ctx.copy_advice(|| "x point cond add", self.config.add.x_q, base.x.clone())?;
            let base_y =
                ctx.copy_advice(|| "y point cond add", self.config.add.y_q, base.y.clone())?;

            let base_q = AssignedEccPoint {
                x: base_x,
                y: base_y,
            };

            // We now copy the bit to its right position
            let b = ctx.copy_advice(|| format!("b{}", index), self.config.add.b, bit)?;

            // Aggr = Aggr + cond_add
            assigned_aggr = self.cond_add(ctx, &assigned_aggr, &base_q, &b)?;
        }
        ctx.next();

        Ok(assigned_aggr)
    }

    fn point_selection(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a_1: Coordinates<AffinePoint>,
        a_2: Coordinates<AffinePoint>,
        a_3: Coordinates<AffinePoint>,
        bit_1: &AssignedCondition<Base>,
        bit_2: &AssignedCondition<Base>,
    ) -> Result<Self::Point, Error> {
        let result_x = bit_1.value().zip(bit_2.value()).map(|(b1, b2)| {
            if b1 == &Base::ZERO && b2 == &Base::ZERO {
                Base::ZERO
            } else if b1 == &Base::ONE && b2 == &Base::ZERO {
                *a_1.x()
            } else if b1 == &Base::ZERO && b2 == &Base::ONE {
                *a_2.x()
            } else if b1 == &Base::ONE && b2 == &Base::ONE {
                *a_3.x()
            } else {
                panic!("Unexpected bit values");
            }
        });

        let x = ctx.assign_advice(|| "x result", self.main_gate.config.e, result_x)?;

        let b1 = ctx.assign_advice(
            || "A column",
            self.main_gate.config.a,
            bit_1.value().copied(),
        )?;
        let b2 = ctx.assign_advice(
            || "B column",
            self.main_gate.config.b,
            bit_2.value().copied(),
        )?;

        ctx.constrain_equal(b1.cell(), bit_1.cell())?;
        ctx.constrain_equal(b2.cell(), bit_2.cell())?;

        // Selector of the result
        ctx.assign_fixed(|| "Res x selector", self.main_gate.config.se, -Base::ONE)?;

        ctx.assign_fixed(|| "A coeff", self.main_gate.config.sa, *a_1.x())?;
        ctx.assign_fixed(|| "B coeff", self.main_gate.config.sb, *a_2.x())?;

        ctx.assign_fixed(
            || "multiplication factor",
            self.main_gate.config.s_mul_ab,
            a_3.x() - a_2.x() - a_1.x(),
        )?;

        ctx.next();

        // We move to the next line, to handle the y coordinate
        let result_y = bit_1.value().zip(bit_2.value()).map(|(b1, b2)| {
            if b1 == &Base::ZERO && b2 == &Base::ZERO {
                Base::ONE
            } else if b1 == &Base::ONE && b2 == &Base::ZERO {
                *a_1.y()
            } else if b1 == &Base::ZERO && b2 == &Base::ONE {
                *a_2.y()
            } else if b1 == &Base::ONE && b2 == &Base::ONE {
                *a_3.y()
            } else {
                panic!("Unexpected bit values");
            }
        });

        let y = ctx.assign_advice(|| "y result", self.main_gate.config.e, result_y)?;

        let b1 = ctx.assign_advice(
            || "A column",
            self.main_gate.config.a,
            bit_1.value().copied(),
        )?;
        let b2 = ctx.assign_advice(
            || "B column",
            self.main_gate.config.b,
            bit_2.value().copied(),
        )?;

        ctx.constrain_equal(b1.cell(), bit_1.cell())?;
        ctx.constrain_equal(b2.cell(), bit_2.cell())?;

        // Selector of the result
        ctx.assign_fixed(|| "Res y selector", self.main_gate.config.se, -Base::ONE)?;

        ctx.assign_fixed(|| "A coeff", self.main_gate.config.sa, a_1.y() - Base::ONE)?;
        ctx.assign_fixed(|| "B coeff", self.main_gate.config.sb, a_2.y() - Base::ONE)?;

        ctx.assign_fixed(
            || "multiplication factor",
            self.main_gate.config.s_mul_ab,
            a_3.y() - a_2.y() - a_1.y() + Base::ONE,
        )?;

        ctx.assign_fixed(|| "s_constant", self.main_gate.config.s_constant, Base::ONE)?;

        ctx.next();

        Ok(Self::Point { x, y })
    }

    fn fixed_mul(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        scalar: &Self::ScalarVar,
        base: AffinePoint,
    ) -> Result<Self::Point, Error> {
        let l_prime = (Scalar::NUM_BITS / 2) as usize;
        let base_points = (0..l_prime)
            .map(|power| {
                base.mul(Scalar::from(4).pow_vartime(&[power as u64, 0, 0, 0]))
                    .to_affine()
            })
            .collect::<Vec<AffinePoint>>();
        let base_points_2 = (0..l_prime)
            .map(|power| {
                base.mul(Scalar::from(2) * Scalar::from(4).pow_vartime(&[power as u64, 0, 0, 0]))
                    .to_affine()
            })
            .collect::<Vec<AffinePoint>>();
        let base_points_3 = (0..l_prime)
            .map(|power| {
                base.mul(Scalar::from(3) * Scalar::from(4).pow_vartime(&[power as u64, 0, 0, 0]))
                    .to_affine()
            })
            .collect::<Vec<AffinePoint>>();

        let scalar_binary = self
            .main_gate
            .to_bits(ctx, &scalar.0, Scalar::NUM_BITS as usize)?;

        let mut acc = self.point_selection(
            ctx,
            base_points[0].coordinates().unwrap(),
            base_points_2[0].coordinates().unwrap(),
            base_points_3[0].coordinates().unwrap(),
            &scalar_binary[0],
            &scalar_binary[1],
        )?;

        let mut z: AssignedEccPoint;

        for i in 1..l_prime - 1 {
            z = self.point_selection(
                ctx,
                base_points[i].coordinates().unwrap(),
                base_points_2[i].coordinates().unwrap(),
                base_points_3[i].coordinates().unwrap(),
                &scalar_binary[2 * i],
                &scalar_binary[2 * i + 1],
            )?;

            acc = self.add(ctx, &acc, &z)?;
        }

        z = self.point_selection(
            ctx,
            base_points[l_prime - 1].coordinates().unwrap(),
            base_points_2[l_prime - 1].coordinates().unwrap(),
            base_points_3[l_prime - 1].coordinates().unwrap(),
            &scalar_binary[2 * l_prime - 2],
            &scalar_binary[2 * l_prime - 1],
        )?;

        self.add(ctx, &acc, &z)
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
    use group::prime::PrimeCurveAffine;
    use group::{Curve, Group};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    // use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint, Scalar, SubgroupPoint};
    use blstrs::{JubjubAffine as AffinePoint, Base, JubjubExtended as ExtendedPoint, Fr as Scalar, JubjubSubgroup as SubgroupPoint};
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

        prover.verify().unwrap();
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

    #[derive(Clone, Debug, Default)]
    struct TestCircuitFixed {
        scalar: Scalar,
    }

    impl Circuit<Base> for TestCircuitFixed {
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

                    ecc_chip.fixed_mul(
                        &mut ctx,
                        &assigned_scalar,
                        ExtendedPoint::from(SubgroupPoint::generator()).to_affine(),
                    )
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
    fn test_ec_fixed_mul() {
        const K: u32 = 11;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let point = ExtendedPoint::from(SubgroupPoint::generator());
        let scalar = Scalar::random(&mut rng);
        let res = point.mul(&scalar);

        let circuit = TestCircuitFixed { scalar };

        let res_coords = res.to_affine().coordinates().unwrap();
        let pi = vec![vec![*res_coords.x(), *res_coords.y()]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        prover.verify().unwrap();
        assert!(prover.verify().is_ok());

        let random_result = ExtendedPoint::random(&mut rng);
        let random_res_coords = random_result.to_affine().coordinates().unwrap();

        let pi = vec![vec![*random_res_coords.x(), *random_res_coords.y()]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_err());

        // mult by one
        let scalar = Scalar::one();
        let circuit = TestCircuitFixed { scalar };

        let res_coords = point.to_affine().coordinates().unwrap();
        let pi = vec![vec![*res_coords.x(), *res_coords.y()]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_ok());

        // mult by zero
        let scalar = Scalar::zero();
        let circuit = TestCircuitFixed { scalar };

        let pi = vec![vec![Base::ZERO, Base::ONE]];

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        assert!(prover.verify().is_ok());
    }
}
