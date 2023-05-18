use group::Group;
use super::{AssignedEccPoint};

use group::prime::PrimeCurveAffine;

use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{
        Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector,
        VirtualCells,
    },
    poly::Rotation,
};
use halo2curves::{jubjub, CurveAffine};
use crate::ecc::chip::add::EDWARDS_D;
use crate::util::RegionCtx;

type Coordinates = (
    AssignedCell<jubjub::Base, jubjub::Base>,
    AssignedCell<jubjub::Base, jubjub::Base>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    q_point: Selector,
    // x-coordinate
    pub x: Column<Advice>,
    // y-coordinate
    pub y: Column<Advice>,
}

impl Config {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<jubjub::Base>,
        x: Column<Advice>,
        y: Column<Advice>,
    ) -> Self {
        let config = Self {
            q_point: meta.selector(),
            x,
            y,
        };

        let curve_eqn = |meta: &mut VirtualCells<jubjub::Base>| {
            let x_square = meta.query_advice(config.x, Rotation::cur()).square();
            let y_square = meta.query_advice(config.y, Rotation::cur()).square();

            // -x^2 + y^2 = 1 + d * x^2 * y^2
            y_square.clone() - x_square.clone() - (Expression::Constant(jubjub::Fq::one()) + Expression::Constant(EDWARDS_D) * x_square * y_square)
        };

        meta.create_gate("witness point", |meta| {
            // Check that the point being witnessed is either:
            // - the identity, which is mapped to (0, 0) in affine coordinates; or
            // - a valid curve point -x^2 + y^2 = 1 + d * x^2 * y^2

            let q_point = meta.query_selector(config.q_point);
            let x = meta.query_advice(config.x, Rotation::cur());
            let y = meta.query_advice(config.y, Rotation::cur());

            // We can't use `Constraints::with_selector` because that creates constraints
            // of the form `q_point * (x * curve_eqn)`, but this was implemented without
            // parentheses, and thus evaluates as `(q_point * x) * curve_eqn`, which is
            // structurally different in the pinned verifying key.
            [
                ("x == 0 v on_curve", q_point.clone() * x * curve_eqn(meta)),
                ("y == 0 v on_curve", q_point * y * curve_eqn(meta)),
            ]
        });

        config
    }

    fn assign_xy(
        &self,
        ctx: &mut RegionCtx<'_, jubjub::Base>,
        value: &Value<(jubjub::Base, jubjub::Base)>,
    ) -> Result<Coordinates, Error> {
        // Assign `x` value
        let x_val = value.map(|value| value.0);
        let x_var = ctx.assign_advice(|| "x", self.x, x_val)?;

        // Assign `y` value
        let y_val = value.map(|value| value.1);
        let y_var = ctx.assign_advice(|| "y", self.y, y_val)?;

        ctx.next();

        Ok((x_var, y_var))
    }

    /// Assigns a point that can be the identity.
    pub(super) fn point(
        &self,
        ctx: &mut RegionCtx<'_, jubjub::Base>,
        value: &Value<jubjub::AffinePoint>,
    ) -> Result<AssignedEccPoint, Error> {
        // Enable `q_point` selector
        ctx.enable(self.q_point)?;

        let value = value.map(|value| {
            // Map the identity to (0, 0).
            if value == jubjub::AffinePoint::identity() {
                (jubjub::Base::zero(), jubjub::Base::zero())
            } else {
                let value = value.coordinates().unwrap();
                (value.x().clone(), value.y().clone())
            }
        });

        self.assign_xy(ctx, &value)
            .map(|(x, y)| AssignedEccPoint { x, y })
    }
}
