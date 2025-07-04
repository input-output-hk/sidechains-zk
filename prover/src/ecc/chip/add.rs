use super::AssignedEccPoint;
use crate::util::RegionCtx;
use crate::AssignedCondition;
use ff::PrimeField;
use halo2_proofs::circuit::Value;
use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
//use halo2curves::bls12_381::Scalar;
//use halo2curves::jubjub;
use blstrs::{Base, Scalar};
use blstrs::Base as Fq;
use blstrs::Fr;

use std::collections::HashSet;
use halo2_proofs::utils::rational::Rational;
// The twisted Edwards addition law is defined as follows:
//
//
// P + Q = (x_p, y_p) + (x_q, y_q) =
//
// (     x_p * y_q + x_q * y_p             y_p * y_q + x_p * x_q    )
// ( ------------------------------, ------------------------------ )
// ( 1 + d * x_p * x_q * y_p * y_q   1 - d * x_p * x_q * y_p * y_q  )
//
// If we define the resulting point as (x_r, y_r), we have that
//           x_p * y_q + x_q * y_p
// x_r = ------------------------------
//       1 + d * x_p * x_q * y_p * y_q
// <=>
// x_r * (1 + d * x_p * x_q * y_p * y_q) = x_p * y_q + x_q * y_p
// <=>
// x_r * (1 + d * x_p * x_q * y_p * y_q) - x_p * y_q + x_q * y_p = 0
//
// And similarly
//            y_p * y_q + x_p * x_q
// y_r = ------------------------------
//       1 - d * x_p * x_q * y_p * y_q
// <=>
// y_r * (1 - d * x_p * x_q * y_p * y_q) = y_p * y_q + x_p * x_q
// <=>
// y_r * (1 - d * x_p * x_q * y_p * y_q) - y_p * y_q + x_p * x_q = 0
//
// We define a conditional add that does the following:
//
// | b | Px | Py | Qx | Qy |
// |   | Rx | Ry |    |    |     R = P + b Q
//
// We achieve that as follows:
// x_r * (1 + b * d * x_p * x_q * y_p * y_q) - (x_p + b * (x_p * y_q + x_q * y_p - x_p))  = 0
// and
// y_r * (1 - b * d * x_p * x_q * y_p * y_q) - (y_p + b * (y_p * y_q + x_p * x_q - y_p)) = 0

// `d = -(10240/10241)`
pub(crate) const EDWARDS_D: Fq = Fq::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CondAddConfig {
    q_add: Selector,
    // Conditional
    pub b: Column<Advice>,
    // x-coordinate of P in P + Q = R
    pub x_pr: Column<Advice>,
    // y-coordinate of P in P + Q = R
    pub y_pr: Column<Advice>,
    // x-coordinate of Q or R in P + Q = R
    pub x_q: Column<Advice>,
    // y-coordinate of Q or R in P + Q = R
    pub y_q: Column<Advice>,
}

impl CondAddConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Base>,
        b: Column<Advice>,
        x_pr: Column<Advice>,
        y_pr: Column<Advice>,
        x_q: Column<Advice>,
        y_q: Column<Advice>,
    ) -> Self {
        meta.enable_equality(b);
        meta.enable_equality(x_pr);
        meta.enable_equality(y_pr);
        meta.enable_equality(x_q);
        meta.enable_equality(y_q);

        let config = Self {
            q_add: meta.selector(),
            b,
            x_pr,
            y_pr,
            x_q,
            y_q,
        };

        config.create_gate(meta);

        config
    }

    pub(crate) fn advice_columns(&self) -> HashSet<Column<Advice>> {
        [self.b, self.x_pr, self.y_pr, self.x_q, self.y_q]
            .into_iter()
            .collect()
    }

    pub(crate) fn output_columns(&self) -> HashSet<Column<Advice>> {
        [self.x_pr, self.y_pr].into_iter().collect()
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<Base>) {
        meta.create_gate("complete addition", |meta| {
            let q_add = meta.query_selector(self.q_add);
            let b = meta.query_advice(self.b, Rotation::cur());
            let x_p = meta.query_advice(self.x_pr, Rotation::cur());
            let y_p = meta.query_advice(self.y_pr, Rotation::cur());
            let x_q = meta.query_advice(self.x_q, Rotation::cur());
            let y_q = meta.query_advice(self.y_q, Rotation::cur());
            let x_r = meta.query_advice(self.x_pr, Rotation::next());
            let y_r = meta.query_advice(self.y_pr, Rotation::next());

            // Useful constants
            let one = Expression::Constant(Base::one());
            let two = Expression::Constant(Base::from(2));
            let three = Expression::Constant(Base::from(3));
            let edwards_d = Expression::Constant(EDWARDS_D);

            // Useful composite expressions
            // x_p * x_q
            let x_p_times_x_q = x_p.clone() * x_q.clone();
            // y_p * y_q
            let y_p_times_y_q = y_p.clone() * y_q.clone();
            // x_p * y_q
            let x_p_times_y_q = x_p.clone() * y_q;
            // x_q * y_p
            let x_q_times_y_p = x_q * y_p.clone();
            // b * (d x_p x_qr y_p y_qr)
            let b_d_x_p_x_q_y_p_y_q =
                b.clone() * edwards_d * x_p_times_x_q.clone() * y_p_times_y_q.clone();

            // x_r * (1 + b * d * x_p * x_q * y_p * y_q) - (x_p + b * (x_p * y_q + x_q * y_p - x_p)) = 0
            let poly1 = {
                let one_plus = one.clone() + b_d_x_p_x_q_y_p_y_q.clone(); // (1 + b * d * x_p * x_q * y_p * y_q)
                let nominator = x_p.clone() + b.clone() * (x_p_times_y_q + x_q_times_y_p - x_p); // x_p + b * (x_p * y_q + x_q * y_p - x_p)

                // q_add * (x_r * (1 + b * d * x_p * x_q * y_p * y_q) - (x_p + b * (x_p * y_q + x_q * y_p - x_p))
                x_r * one_plus - nominator
            };

            // y_r * (1 - b * d * x_p * x_q * y_p * y_q) - (y_p + b * (y_p * y_q + x_p * x_q - y_p)) = 0
            let poly2 = {
                let one_minus = one - b_d_x_p_x_q_y_p_y_q; // (1 - b * d * x_p * x_q * y_p * y_q)
                let nominator = y_p.clone() + b * (y_p_times_y_q + x_p_times_x_q - y_p); // y_p + b * (y_p * y_q + x_p * x_q - y_p)

                // q_add * (y_r * (1 - b * d * x_p * x_q * y_p * y_q) - (y_p + b * (y_p * y_q + x_q * x_p - y_p))
                y_r * one_minus - nominator
            };

            Constraints::with_selector(
                q_add,
                [("x_r constraint", poly1), ("y_r constraint", poly2)],
            )
        });
    }

    /// Assign region takes as input two assigned points, and one assigned condition. They
    /// already need to be aligned as follows:
    ///
    /// | b | Px | Py | Qx | Qy |
    pub(super) fn assign_region(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        p: &AssignedEccPoint,
        q: &AssignedEccPoint,
        b: &AssignedCondition<Base>,
    ) -> Result<AssignedEccPoint, Error> {
        // Enable `q_add` selector
        ctx.enable(self.q_add)?;

        let (x_p, y_p) = (p.x(), p.y());
        let (x_q, y_q) = (q.x(), q.y());

        // x_r * (1 + b * d * x_p * x_q * y_p * y_q) - (x_p + b * (x_p * y_q + x_q * y_p - x_p)) = 0
        // y_r * (1 - b * d * x_p * x_q * y_p * y_q) - (y_p + b * (y_p * y_q + x_p * x_q - y_p)) = 0
        let r = b
            .value()
            .zip(x_p.value())
            .zip(y_p.value())
            .zip(x_q.value())
            .zip(y_q.value())
            .map(|((((b, x_p), y_p), x_q), y_q)| {
                {
                    // λ = (b * d * x_p * x_q * y_p * y_q)
                    let lambda = Rational::from(EDWARDS_D) * *b * *x_p * *x_q * *y_p * *y_q;
                    // α = inv0(1 + d x_p x_qr y_p y_qr)
                    let alpha = (Rational::from(Scalar::one()) + lambda).invert();
                    // β = inv0(1 - d x_p x_qr y_p y_qr)
                    let beta = (Rational::from(Scalar::one()) - lambda).invert();
                    // x_r = (x_p + b * (x_p * y_q + x_q * y_p - x_p) * (1 + lambda)^{-1}
                    let x_r = alpha * (*x_p + *b * (*x_p * *y_q + *x_q * *y_p - *x_p));
                    // y_r = (y_p + b * (x_p * x_q + y_p * y_q - y_p)) * (1 - lambda)^{-1}
                    let y_r = beta * (*y_p + *b * (*x_p * *x_q + *y_p * *y_q - *y_p));
                    (x_r, y_r)
                }
            });

        // Assign the sum to `x_qr`, `y_qr` columns in the next row
        let x_r = r.map(|r| r.0.evaluate());
        let y_r = r.map(|r| r.1.evaluate());

        // Assign the result in the next cell.
        ctx.next();
        let x_r_cell = ctx.assign_advice(|| "x_r", self.x_pr, x_r)?;
        let y_r_cell = ctx.assign_advice(|| "y_r", self.y_pr, y_r)?;

        let result = AssignedEccPoint {
            x: x_r_cell,
            y: y_r_cell,
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::ecc::chip::{EccChip, EccConfig, EccInstructions};
    use crate::main_gate::{MainGate, MainGateConfig};
    use crate::util::RegionCtx;
    use group::{Curve, Group};
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    //use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint};
    use blstrs::{JubjubAffine as AffinePoint, Base, JubjubExtended as ExtendedPoint};
    use halo2curves::CurveAffine;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[derive(Clone)]
    struct TestCircuitConfig {
        maingate_config: MainGateConfig,
        ecc_config: EccConfig,
    }

    #[derive(Clone, Debug, Default)]
    struct TestCircuit {
        point_a: AffinePoint,
        point_b: AffinePoint,
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

        // todo: working on trying to avoid instantiating two main-gates

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Base>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::new(config.maingate_config);
            let ecc_chip = EccChip::new(main_gate, config.ecc_config);

            let assigned_val = layouter.assign_region(
                || "Ecc addition test",
                |region| {
                    let offset = 0;
                    let mut ctx = RegionCtx::new(region, offset);
                    let assigned_a =
                        ecc_chip.witness_point(&mut ctx, &Value::known(self.point_a))?;
                    let assigned_b =
                        ecc_chip.witness_point(&mut ctx, &Value::known(self.point_b))?;

                    ecc_chip.add(&mut ctx, &assigned_a, &assigned_b)
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
    fn test_ec_addition() {
        const K: u32 = 4;

        // useful for debugging
        let _print_coords = |a: ExtendedPoint, name: &str| {
            println!(
                "Coordinates {name}: {:?}",
                a.to_affine().coordinates().unwrap()
            );
        };

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

        let prover =
            MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");

        prover.verify().unwrap();
        assert!(prover.verify().is_ok());

        // let random_result = ExtendedPoint::random(&mut rng);
        // let random_res_coords = random_result.to_affine().coordinates().unwrap();
        //
        // let pi = vec![vec![*random_res_coords.x(), *random_res_coords.y()]];
        //
        // let prover =
        //     MockProver::run(K, &circuit, pi).expect("Failed to run EC addition mock prover");
        //
        // assert!(prover.verify().is_err());
        //
        // // Addition with equal points
        // let circuit = TestCircuit {
        //     point_a: lhs.to_affine(),
        //     point_b: lhs.to_affine(),
        // };
        //
        // let res = lhs + lhs;
        // let res_coords = res.to_affine().coordinates().unwrap();
        // let pi = vec![vec![*res_coords.x(), *res_coords.y()]];
        //
        // let prover =
        //     MockProver::run(K, &circuit, pi).expect("Failed to run EC add with equal points");
        //
        // assert!(prover.verify().is_ok());
        //
        // // Addition with zero
        // let zero = ExtendedPoint::identity();
        // let circuit = TestCircuit {
        //     point_a: zero.to_affine(),
        //     point_b: lhs.to_affine(),
        // };
        //
        // let res_coords = lhs.to_affine().coordinates().unwrap();
        // let pi = vec![vec![*res_coords.x(), *res_coords.y()]];
        //
        // let prover =
        //     MockProver::run(K, &circuit, pi).expect("Failed to run EC add with equal points");
        //
        // assert!(prover.verify().is_ok());
    }
}
