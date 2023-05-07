use super::EccPoint;
use ff::PrimeField;
use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::jubjub;
use std::collections::HashSet;
use halo2curves::bls12_381::Scalar;

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

// `d = -(10240/10241)`
pub(crate) const EDWARDS_D: jubjub::Fq = jubjub::Fq::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    q_add: Selector,
    // x-coordinate of P in P + Q = R
    pub x_p: Column<Advice>,
    // y-coordinate of P in P + Q = R
    pub y_p: Column<Advice>,
    // x-coordinate of Q or R in P + Q = R
    pub x_qr: Column<Advice>,
    // y-coordinate of Q or R in P + Q = R
    pub y_qr: Column<Advice>,
    // α = inv0(1 + d x_p x_qr y_p y_qr)
    alpha: Column<Advice>,
    // β = inv0(1 - d x_p x_qr y_p y_qr)
    beta: Column<Advice>
}

impl Config {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<jubjub::Base>,
        x_p: Column<Advice>,
        y_p: Column<Advice>,
        x_qr: Column<Advice>,
        y_qr: Column<Advice>,
        alpha: Column<Advice>,
        beta: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x_p);
        meta.enable_equality(y_p);
        meta.enable_equality(x_qr);
        meta.enable_equality(y_qr);

        let config = Self {
            q_add: meta.selector(),
            x_p,
            y_p,
            x_qr,
            y_qr,
            alpha,
            beta,
        };

        config.create_gate(meta);

        config
    }

    pub(crate) fn advice_columns(&self) -> HashSet<Column<Advice>> {
        [
            self.x_p,
            self.y_p,
            self.x_qr,
            self.y_qr,
            self.alpha,
            self.beta,
        ]
        .into_iter()
        .collect()
    }

    pub(crate) fn output_columns(&self) -> HashSet<Column<Advice>> {
        [self.x_qr, self.y_qr].into_iter().collect()
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<jubjub::Base>) {
        meta.create_gate("complete addition", |meta| {
            let q_add = meta.query_selector(self.q_add);
            let x_p = meta.query_advice(self.x_p, Rotation::cur());
            let y_p = meta.query_advice(self.y_p, Rotation::cur());
            let x_q = meta.query_advice(self.x_qr, Rotation::cur());
            let y_q = meta.query_advice(self.y_qr, Rotation::cur());
            let x_r = meta.query_advice(self.x_qr, Rotation::next());
            let y_r = meta.query_advice(self.y_qr, Rotation::next());

            // α = inv0(1 + d x_p x_qr y_p y_qr)
            let alpha = meta.query_advice(self.alpha, Rotation::cur());
            // β = inv0(1 - d x_p x_qr y_p y_qr)
            let beta = meta.query_advice(self.beta, Rotation::cur());

            // Useful constants
            let one = Expression::Constant(jubjub::Base::one());
            let two = Expression::Constant(jubjub::Base::from(2));
            let three = Expression::Constant(jubjub::Base::from(3));
            let edwards_d = Expression::Constant(EDWARDS_D);

            // Useful composite expressions
            // x_p * x_q
            let x_p_times_x_q = x_p.clone() * x_q.clone();
            // y_p * y_q
            let y_p_times_y_q = y_p.clone() * y_q.clone();
            // x_p * y_q
            let x_p_times_y_q = x_p.clone() * y_q.clone();
            // x_q * y_p
            let x_q_times_y_p = x_q.clone() * y_p.clone();
            // (d x_p x_qr y_p y_qr)
            let d_x_p_x_q_y_p_y_q = edwards_d.clone() * x_p_times_x_q.clone() * y_p_times_y_q.clone();

            // x_r * (1 + d * x_p * x_q * y_p * y_q) - x_p * y_q + x_q * y_p = 0
            let poly1 = {
                let one_plus = one.clone() + d_x_p_x_q_y_p_y_q.clone(); // (1 + d * x_p * x_q * y_p * y_q)
                let nominator = x_p_times_y_q.clone() * x_q_times_y_p.clone(); // (x_p * y_q + x_q * y_p)

                // q_add * (x_r * (1 + d * x_p * x_q * y_p * y_q) - x_p * y_q + x_q * y_p)
                x_r.clone() * one_plus - nominator
            };

            // y_r * (1 - d * x_p * x_q * y_p * y_q) - y_p * y_q + x_p * x_q = 0
            let poly2 = {
                let one_minus = one.clone() - d_x_p_x_q_y_p_y_q.clone(); // (1 + d * x_p * x_q * y_p * y_q)
                let nominator = y_p_times_y_q.clone() * x_p_times_x_q.clone(); // (y_p * y_q + x_p * x_q)

                // q_add * (x_r * (1 + d * x_p * x_q * y_p * y_q) - x_p * y_q + x_q * y_p)
                y_r.clone() * one_minus - nominator
            };

            Constraints::with_selector(
                q_add,
                [
                    ("x_r", poly1),
                    ("y_r", poly2),
                ],
            )
        });
    }

    pub(super) fn assign_region(
        &self,
        p: &EccPoint,
        q: &EccPoint,
        offset: usize,
        region: &mut Region<'_, jubjub::Base>,
    ) -> Result<EccPoint, Error> {
        // Enable `q_add` selector
        self.q_add.enable(region, offset)?;

        // Handle exceptional cases
        let (x_p, y_p) = (p.x.value(), p.y.value());
        let (x_q, y_q) = (q.x.value(), q.y.value());

        // Copy point `p` into `x_p`, `y_p` columns
        p.x.copy_advice(|| "x_p", region, self.x_p, offset)?;
        p.y.copy_advice(|| "y_p", region, self.y_p, offset)?;

        // Copy point `q` into `x_qr`, `y_qr` columns
        q.x.copy_advice(|| "x_q", region, self.x_qr, offset)?;
        q.y.copy_advice(|| "y_q", region, self.y_qr, offset)?;

        // Compute the sum `P + Q = R`
        // x_r * (1 + d * x_p * x_q * y_p * y_q) = x_p * y_q + x_q * y_p
        // y_r * (1 - d * x_p * x_q * y_p * y_q) = y_p * y_q + x_p * x_q
        let r = x_p
            .zip(y_p)
            .zip(x_q)
            .zip(y_q)
            .map(|(((x_p, y_p), x_q), y_q)| {
                {
                    // λ = (d * x_p * x_q * y_p * y_q)
                    let lambda = Assigned::from(EDWARDS_D) * x_p.clone() * x_q.clone() * y_p.clone() * y_q.clone();
                    // x_r = (x_p * y_q + x_q * y_p) * (1 + lambda)^{-1}
                    let x_r = (x_p.clone() * y_q.clone() + x_q.clone() * y_p.clone()) * (Assigned::from(Scalar::one()) + lambda).invert();
                    // y_r = (x_p * x_q + y_p * y_q) * (1 - lambda)^{-1}
                    let y_r = (x_p.clone() * x_q.clone() + y_p.clone() * y_q.clone()) * (Assigned::from(Scalar::one()) - lambda).invert();
                    (x_r, y_r)
                }
            });

        // Assign the sum to `x_qr`, `y_qr` columns in the next row
        let x_r = r.map(|r| r.0);
        let x_r_var = region.assign_advice(|| "x_r", self.x_qr, offset + 1, || x_r)?;

        let y_r = r.map(|r| r.1);
        let y_r_var = region.assign_advice(|| "y_r", self.y_qr, offset + 1, || y_r)?;

        let result = EccPoint {
            x: x_r_var,
            y: y_r_var,
        };

        Ok(result)
    }
}

#[cfg(test)]
pub mod tests {
    use group::{Curve};
    use halo2_proofs::{
        circuit::{Layouter, Value},
        plonk::Error,
    };
    use halo2curves::{jubjub, CurveExt};

    use crate::ecc::{chip::EccPoint, EccInstructions, NonIdentityPoint};

    #[allow(clippy::too_many_arguments)]
    pub fn test_add<
        EccChip: EccInstructions<jubjub::AffinePoint, Point = EccPoint> + Clone + Eq + std::fmt::Debug,
    >(
        chip: EccChip,
        mut layouter: impl Layouter<jubjub::Base>,
        p_val: jubjub::AffinePoint,
        p: &NonIdentityPoint<jubjub::AffinePoint, EccChip>,
        q_val: jubjub::AffinePoint,
        q: &NonIdentityPoint<jubjub::AffinePoint, EccChip>,
        p_neg: &NonIdentityPoint<jubjub::AffinePoint, EccChip>,
    ) -> Result<(), Error> {
        // Make sure P and Q are not the same point.
        assert_ne!(p_val, q_val);

        // Check complete addition P + (-P)
        let zero = {
            let result = p.add(layouter.namespace(|| "P + (-P)"), p_neg)?;
            result
                .inner()
                .is_identity()
                .assert_if_known(|is_identity| *is_identity);
            result
        };

        // Check complete addition 𝒪 + 𝒪
        {
            let result = zero.add(layouter.namespace(|| "𝒪 + 𝒪"), &zero)?;
            result.constrain_equal(layouter.namespace(|| "𝒪 + 𝒪 = 𝒪"), &zero)?;
        }

        // Check P + Q
        {
            let result = p.add(layouter.namespace(|| "P + Q"), q)?;
            let witnessed_result = NonIdentityPoint::new(
                chip.clone(),
                layouter.namespace(|| "witnessed P + Q"),
                Value::known((p_val + q_val).to_affine()),
            )?;
            result.constrain_equal(layouter.namespace(|| "constrain P + Q"), &witnessed_result)?;
        }

        // P + P
        {
            let result = p.add(layouter.namespace(|| "P + P"), p)?;
            let witnessed_result = NonIdentityPoint::new(
                chip.clone(),
                layouter.namespace(|| "witnessed P + P"),
                Value::known((p_val + p_val).to_affine()),
            )?;
            result.constrain_equal(layouter.namespace(|| "constrain P + P"), &witnessed_result)?;
        }

        // P + 𝒪
        {
            let result = p.add(layouter.namespace(|| "P + 𝒪"), &zero)?;
            result.constrain_equal(layouter.namespace(|| "P + 𝒪 = P"), p)?;
        }

        // 𝒪 + P
        {
            let result = zero.add(layouter.namespace(|| "𝒪 + P"), p)?;
            result.constrain_equal(layouter.namespace(|| "𝒪 + P = P"), p)?;
        }

        Ok(())
    }
}
