use super::AssignedEccPoint;
use ff::PrimeField;
use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::jubjub;
use std::collections::HashSet;
use halo2_proofs::circuit::Value;
use halo2curves::bls12_381::Scalar;
use crate::util::RegionCtx;

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

            // // α = inv0(1 + d x_p x_qr y_p y_qr)
            // let alpha = meta.query_advice(self.alpha, Rotation::cur());
            // // β = inv0(1 - d x_p x_qr y_p y_qr)
            // let beta = meta.query_advice(self.beta, Rotation::cur());

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
                let nominator = x_p_times_y_q.clone() + x_q_times_y_p.clone(); // (x_p * y_q + x_q * y_p)

                // q_add * (x_r * (1 + d * x_p * x_q * y_p * y_q) - x_p * y_q + x_q * y_p)
                x_r.clone() * one_plus - nominator
            };

            // y_r * (1 - d * x_p * x_q * y_p * y_q) - y_p * y_q + x_p * x_q = 0
            let poly2 = {
                let one_minus = one.clone() - d_x_p_x_q_y_p_y_q.clone(); // (1 + d * x_p * x_q * y_p * y_q)
                let nominator = y_p_times_y_q.clone() + x_p_times_x_q.clone(); // (y_p * y_q + x_p * x_q)

                // q_add * (x_r * (1 + d * x_p * x_q * y_p * y_q) - x_p * y_q + x_q * y_p)
                y_r.clone() * one_minus - nominator
            };

            Constraints::with_selector(
                q_add,
                [
                    ("x_r constraint", poly1),
                    ("y_r constraint", poly2),
                ],
            )
        });
    }

    pub(super) fn assign_region(
        &self,
        ctx: &mut RegionCtx<'_, jubjub::Base>,
        p: &(Value<jubjub::Base>, Value<jubjub::Base>),
        q: &(Value<jubjub::Base>, Value<jubjub::Base>),
    ) -> Result<AssignedEccPoint, Error> {
        // Enable `q_add` selector
        ctx.enable(self.q_add)?;

        let (x_p, y_p) = (p.0, p.1);
        let (x_q, y_q) = (q.0, q.1);

        // Copy point `p` into `x_p`, `y_p` columns
        ctx.assign_advice(|| "x_p", self.x_p, x_p)?;
        ctx.assign_advice(|| "y_p", self.y_p, y_p)?;

        // Copy point `q` into `x_qr`, `y_qr` columns
        ctx.assign_advice(|| "x_q", self.x_qr, x_q)?;
        ctx.assign_advice(|| "y_q", self.y_qr, y_q)?;

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
                    // α = inv0(1 + d x_p x_qr y_p y_qr)
                    let alpha = (Assigned::from(Scalar::one()) + lambda).invert();
                    // β = inv0(1 - d x_p x_qr y_p y_qr)
                    let beta = (Assigned::from(Scalar::one()) - lambda).invert();
                    // x_r = (x_p * y_q + x_q * y_p) * (1 + lambda)^{-1}
                    let x_r = alpha * (x_p.clone() * y_q.clone() + x_q.clone() * y_p.clone());
                    // y_r = (x_p * x_q + y_p * y_q) * (1 - lambda)^{-1}
                    let y_r = beta * (x_p.clone() * x_q.clone() + y_p.clone() * y_q.clone());
                    (alpha, beta, x_r, y_r)
                }
            });

        // Assign the cells for alpha and beta
        let alpha = r.map(|r| r.0.evaluate());
        let beta = r.map(|r| r.1.evaluate());

        ctx.assign_advice(|| "alpha", self.alpha, alpha)?;
        ctx.assign_advice(|| "beta", self.beta, beta)?;

        // Assign the sum to `x_qr`, `y_qr` columns in the next row
        let x_r = r.map(|r| r.2.evaluate());
        let y_r = r.map(|r| r.3.evaluate());

        // Assign the result in the next cell.
        ctx.next();
        let x_r_cell = ctx.assign_advice(|| "x_r", self.x_qr, x_r)?;
        let y_r_cell = ctx.assign_advice(|| "y_r", self.y_qr, y_r)?;

        let result = AssignedEccPoint {
            x: x_r_cell,
            y: y_r_cell,
        };

        Ok(result)
    }
}
