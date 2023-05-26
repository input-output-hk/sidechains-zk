//! The `main_gate` is a five width standard like PLONK gate
//! that constrains the equation below:
//!
//! q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
//! q_mul_ab * a * b +
//! q_mul_cd * c * d +
//! q_e_next * e +
//! public_input +
//! q_constant +
//! q_h1 * a^5 + q_h2 * b^5 + q_h3 * c^5 + q_h4 * d^5 +
//! = 0
//!
//! TODO: once we progress with the circuit, check if we actually need this number of columns.

use crate::instructions::{CombinationOptionCommon, MainGateInstructions, Term};
use crate::util::{pow_5, RegionCtx};
use crate::{AssignedCondition, AssignedValue};
use halo2_proofs::circuit::{Chip, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance};
use halo2_proofs::poly::Rotation;
use halo2curves::ff::PrimeField;
use std::iter;
use std::marker::PhantomData;

const WIDTH: usize = 5;

/// `ColumnTags` is an helper to find special columns that are frequently used
/// across gates
pub trait ColumnTags<Column> {
    /// Next row accumulator
    fn next() -> Column;
    /// First column
    fn first() -> Column;
    /// Index that last term should in linear combination
    fn last_term_index() -> usize;
    /// Get the `i % 5`th column
    fn from_index(index: u8) -> Column;
}

/// Enumerates columns of the main gate
#[derive(Debug)]
pub enum MainGateColumn {
    /// A
    A = 0,
    /// B
    B = 1,
    /// C
    C = 2,
    /// D
    D = 3,
    /// E
    E = 4,
}

impl From<u8> for MainGateColumn {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::A,
            1 => Self::B,
            2 => Self::C,
            3 => Self::D,
            4 => Self::E,
            _ => panic!("Invalid conversion. There is not enough columns"),
        }
    }
}

impl ColumnTags<MainGateColumn> for MainGateColumn {
    fn first() -> Self {
        MainGateColumn::A
    }

    fn next() -> Self {
        MainGateColumn::E
    }

    fn last_term_index() -> usize {
        Self::first() as usize
    }

    fn from_index(index: u8) -> MainGateColumn {
        MainGateColumn::from(index % 5)
    }
}

/// Config defines fixed and witness columns of the main gate
#[derive(Clone, Debug)]
pub struct MainGateConfig {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) c: Column<Advice>,
    pub(crate) d: Column<Advice>,
    pub(crate) e: Column<Advice>,

    pub(crate) sa: Column<Fixed>,
    pub(crate) sb: Column<Fixed>,
    pub(crate) sc: Column<Fixed>,
    pub(crate) sd: Column<Fixed>,
    pub(crate) se: Column<Fixed>,

    pub(crate) se_next: Column<Fixed>,

    pub(crate) s_mul_ab: Column<Fixed>,
    pub(crate) s_mul_cd: Column<Fixed>,

    pub(crate) s_constant: Column<Fixed>,
    pub instance: Column<Instance>,

    pub(crate) q_h1: Column<Fixed>,
    pub(crate) q_h2: Column<Fixed>,
    pub(crate) q_h3: Column<Fixed>,
    pub(crate) q_h4: Column<Fixed>,
}

impl MainGateConfig {
    /// Returns advice columns of `MainGateConfig`
    pub fn advices(&self) -> [Column<Advice>; WIDTH] {
        [self.a, self.b, self.c, self.d, self.e]
    }
}

/// MainGate implements instructions with [`MainGateConfig`]
#[derive(Clone, Debug)]
pub struct MainGate<F: PrimeField> {
    config: MainGateConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Chip<F> for MainGate<F> {
    type Config = MainGateConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// Additional combination customisations for this gate with two multiplication
#[derive(Clone, Debug)]
pub enum CombinationOption<F: PrimeField> {
    /// Wrapper for common combination options
    Common(CombinationOptionCommon<F>),
    /// Activates both of the multiplication gate
    OneLinerDoubleMul(F),
    /// Activates both multiplication gate and combines the result to the next
    /// row
    CombineToNextDoubleMul(F),
}

impl<F: PrimeField> From<CombinationOptionCommon<F>> for CombinationOption<F> {
    fn from(option: CombinationOptionCommon<F>) -> Self {
        CombinationOption::Common(option)
    }
}

impl<F: PrimeField> MainGateInstructions<F, WIDTH> for MainGate<F> {
    type CombinationOption = CombinationOption<F>;
    type MainGateColumn = MainGateColumn;

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedValue<F>,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();
        layouter.constrain_instance(value.cell(), config.instance, row)
    }

    fn assign_to_column(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
        column: MainGateColumn,
    ) -> Result<AssignedValue<F>, Error> {
        let column = match column {
            MainGateColumn::A => self.config.a,
            MainGateColumn::B => self.config.b,
            MainGateColumn::C => self.config.c,
            MainGateColumn::D => self.config.d,
            MainGateColumn::E => self.config.e,
        };
        let cell = ctx.assign_advice(|| "assign value", column, unassigned)?;
        // proceed to the next row
        self.no_operation(ctx)?;
        Ok(cell)
    }

    fn sub_sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b_0: &AssignedValue<F>,
        b_1: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a
            .value()
            .zip(b_0.value())
            .zip(b_1.value())
            .map(|((a, b_0), b_1)| *a - *b_0 - *b_1 + constant);

        Ok(self
            .apply(
                ctx,
                [
                    Term::assigned_to_add(a),
                    Term::assigned_to_sub(b_0),
                    Term::assigned_to_sub(b_1),
                    Term::unassigned_to_sub(c),
                ],
                constant,
                CombinationOptionCommon::OneLinerAdd.into(),
            )?
            .swap_remove(3))
    }

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error> {
        // We should satisfy the equation below with bit asserted condition flag
        // c (a-b) + b - res = 0
        // cond * a - cond * b + b - res = 0

        // Witness layout:
        // | A   | B   | C | D   | E  |
        // | --- | --- | - | --- | ---|
        // | c   | a   | c | b   | res|

        let res = a
            .value()
            .zip(b.value())
            .zip(cond.value())
            .map(|((a, b), cond)| {
                if *cond == F::ONE {
                    *a
                } else {
                    assert_eq!(*cond, F::ZERO);
                    *b
                }
            });

        let mut assigned = self.apply(
            ctx,
            [
                Term::assigned_to_mul(cond),
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(cond),
                Term::assigned_to_add(b),
                Term::unassigned_to_sub(res),
            ],
            F::ZERO,
            CombinationOption::OneLinerDoubleMul(-F::ONE),
        )?;
        ctx.constrain_equal(assigned[0].cell(), assigned[2].cell())?;
        Ok(assigned.swap_remove(4))
    }

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: F,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error> {
        // We should satisfy the equation below with bit asserted condition flag
        // c (a-b_constant) + b_constant - res = 0

        // Witness layout:
        // | A   | B   | C | D   |
        // | --- | --- | - | --- |
        // | dif | a   | - | -   |
        // | c   | dif | - | res |

        let (dif, res) = a
            .value()
            .zip(cond.value())
            .map(|(a, cond)| {
                (
                    *a - b,
                    if *cond == F::ONE {
                        *a
                    } else {
                        assert_eq!(*cond, F::ZERO);
                        b
                    },
                )
            })
            .unzip();

        // a - b - dif = 0
        let dif = &self.apply(
            ctx,
            [Term::assigned_to_add(a), Term::unassigned_to_sub(dif)],
            -b,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1];

        // cond * dif + b + a_or_b  = 0
        let res = self
            .apply(
                ctx,
                [
                    Term::assigned_to_mul(dif),
                    Term::assigned_to_mul(cond),
                    Term::unassigned_to_sub(res),
                ],
                b,
                CombinationOptionCommon::OneLinerMul.into(),
            )?
            .swap_remove(2);

        Ok(res)
    }
    fn apply<'t>(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: impl IntoIterator<Item = Term<'t, F>> + 't,
        constant: F,
        option: CombinationOption<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let terms = terms.into_iter().collect::<Vec<_>>();
        debug_assert!(terms.len() <= WIDTH);

        let assigned = [
            self.config.a,
            self.config.b,
            self.config.c,
            self.config.d,
            self.config.e,
        ]
        .into_iter()
        .zip([
            self.config.sa,
            self.config.sb,
            self.config.sc,
            self.config.sd,
            self.config.se,
        ])
        .zip(terms.iter().chain(iter::repeat(&Term::Zero)))
        .enumerate()
        .map(|(idx, ((coeff, base), term))| {
            let assigned = ctx.assign_advice(|| format!("coeff_{idx}"), coeff, term.coeff())?;
            ctx.assign_fixed(|| format!("base_{idx}"), base, term.base())?;
            Ok(assigned)
        })
        .collect::<Result<Vec<_>, Error>>()?;

        ctx.assign_fixed(|| "s_constant", self.config.s_constant, constant)?;

        // Given specific option configure multiplication and rotation gates
        match option {
            CombinationOption::Common(option) => match option {
                // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
                // a * b +
                // q_e_next * e +
                // q_constant = 0
                CombinationOptionCommon::CombineToNextMul(next) => {
                    ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ONE)?;
                    ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ZERO)?;
                    ctx.assign_fixed(|| "se_next", self.config.se_next, next)?;
                }

                // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
                // q_mul_ab * a * b +
                // q_e_next * e +
                // q_constant = 0
                CombinationOptionCommon::CombineToNextScaleMul(next, n) => {
                    ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, n)?;
                    ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ZERO)?;
                    ctx.assign_fixed(|| "se_next", self.config.se_next, next)?;
                }

                // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
                // q_e_next * e_next +
                // q_constant = 0
                // todo: Include the result, so that the `assign_advice` is done automatically
                CombinationOptionCommon::CombineToNextAdd(next) => {
                    ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ZERO)?;
                    ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ZERO)?;
                    ctx.assign_fixed(|| "se_next", self.config.se_next, next)?;
                }

                // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
                // q_mul_ab * a * b +
                // q_constant = 0
                CombinationOptionCommon::OneLinerMul => {
                    ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ONE)?;
                    ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ZERO)?;
                    ctx.assign_fixed(|| "se_next", self.config.se_next, F::ZERO)?;
                }

                // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
                // q_constant = 0
                CombinationOptionCommon::OneLinerAdd => {
                    ctx.assign_fixed(|| "se_next", self.config.se_next, F::ZERO)?;
                    ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ZERO)?;
                    ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ZERO)?;
                }
            },

            // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
            // q_mul_ab * a * b +
            // q_mul_cd * c * d +
            // q_e_next * e +
            // q_constant = 0
            CombinationOption::CombineToNextDoubleMul(next) => {
                ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ONE)?;
                ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ONE)?;
                ctx.assign_fixed(|| "se_next", self.config.se_next, next)?;
            }

            // q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
            // q_mul_ab * a * b +
            // q_mul_cd * c * d +
            // q_constant = 0
            CombinationOption::OneLinerDoubleMul(e) => {
                ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ONE)?;
                ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, e)?;
                ctx.assign_fixed(|| "se_next", self.config.se_next, F::ZERO)?;
            }
        };

        // If given witness is already assigned apply copy constains
        for (term, rhs) in terms.iter().zip(assigned.iter()) {
            if let Term::Assigned(lhs, _) = term {
                ctx.constrain_equal(lhs.cell(), rhs.cell())?;
            }
        }

        ctx.next();

        Ok(assigned)
    }

    /// Skip this row without any operation
    fn no_operation(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.assign_fixed(|| "s_mul_ab", self.config.s_mul_ab, F::ZERO)?;
        ctx.assign_fixed(|| "s_mul_cd", self.config.s_mul_cd, F::ZERO)?;
        ctx.assign_fixed(|| "sc", self.config.sc, F::ZERO)?;
        ctx.assign_fixed(|| "sa", self.config.sa, F::ZERO)?;
        ctx.assign_fixed(|| "sb", self.config.sb, F::ZERO)?;
        ctx.assign_fixed(|| "sd", self.config.sd, F::ZERO)?;
        ctx.assign_fixed(|| "se", self.config.se, F::ZERO)?;
        ctx.assign_fixed(|| "se_next", self.config.se_next, F::ZERO)?;
        ctx.assign_fixed(|| "s_constant", self.config.s_constant, F::ZERO)?;
        ctx.next();
        Ok(())
    }

    fn assert_pow_5(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        val5: &AssignedValue<F>,
        val: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        // assign witness val (val should be val5^{1/5})
        let assigned = ctx.assign_advice(|| "advice_0", self.config.a, val)?;
        ctx.assign_advice(|| "advice_4", self.config.e, val5.value().copied())?;

        // Assign constants
        ctx.assign_fixed(|| "q_h1", self.config.q_h1, F::ONE)?;
        ctx.assign_fixed(|| "se", self.config().se, -F::ONE)?;

        // Set to 0 the rest of selectors, except e
        ctx.assign_fixed(|| "s_mul_ab", self.config().s_mul_ab, F::ZERO)?;
        ctx.assign_fixed(|| "s_mul_cd", self.config().s_mul_cd, F::ZERO)?;
        ctx.assign_fixed(|| "sa", self.config().sa, F::ZERO)?;
        ctx.assign_fixed(|| "sb", self.config().sb, F::ZERO)?;
        ctx.assign_fixed(|| "sc", self.config().sc, F::ZERO)?;
        ctx.assign_fixed(|| "sd", self.config().sd, F::ZERO)?;
        ctx.assign_fixed(|| "se_next", self.config().se_next, F::ZERO)?;
        ctx.assign_fixed(|| "s_constant", self.config().s_constant, F::ZERO)?;
        ctx.assign_fixed(|| "q_h2", self.config.q_h2, F::ZERO)?;
        ctx.assign_fixed(|| "q_h3", self.config.q_h3, F::ZERO)?;
        ctx.assign_fixed(|| "q_h4", self.config.q_h4, F::ZERO)?;
        ctx.next();

        Ok(assigned)
    }

    fn sum_pow_5_const(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        vals: [&AssignedValue<F>; 4],
        constants: [F; 4],
        aff_constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        // Assign input witness
        [self.config.a, self.config.b, self.config.c, self.config.d]
            .into_iter()
            .zip(vals.iter())
            .enumerate()
            .map(|(i, (column, value))| {
                ctx.assign_advice(|| format!("advice_{i}"), column, value.value().copied())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        //Compute and assign result
        let result = vals
            .iter()
            .zip(constants.iter())
            .fold(Value::known(aff_constant), |acc, (val, c)| {
                acc.and_then(|a| val.value().map(|v| a + pow_5(*v) * c))
            });

        let assigned = ctx.assign_advice(|| "advice_4", self.config.e, result)?;

        // Assign constants
        ctx.assign_fixed(|| "q_h1", self.config.q_h1, constants[0])?;
        ctx.assign_fixed(|| "q_h2", self.config.q_h2, constants[1])?;
        ctx.assign_fixed(|| "q_h3", self.config.q_h3, constants[2])?;
        ctx.assign_fixed(|| "q_h4", self.config.q_h4, constants[3])?;
        ctx.assign_fixed(|| "s_constant", self.config.s_constant, aff_constant)?;

        // Set to 0 the rest of selectors, except e
        ctx.assign_fixed(|| "s_mul_ab", self.config().s_mul_ab, F::ZERO)?;
        ctx.assign_fixed(|| "s_mul_cd", self.config().s_mul_cd, F::ZERO)?;
        ctx.assign_fixed(|| "sc", self.config().sc, F::ZERO)?;
        ctx.assign_fixed(|| "sa", self.config().sa, F::ZERO)?;
        ctx.assign_fixed(|| "sb", self.config().sb, F::ZERO)?;
        ctx.assign_fixed(|| "sd", self.config().sd, F::ZERO)?;
        ctx.assign_fixed(|| "se", self.config().se, -F::ONE)?;
        ctx.assign_fixed(|| "se_next", self.config().se_next, F::ZERO)?;
        ctx.next();

        Ok(assigned)
    }

    fn const_affine_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        vals: [&AssignedValue<F>; 4],
        constants: [F; 4],
        aff_constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let result = vals
            .iter()
            .zip(constants.iter())
            .fold(Value::known(aff_constant), |acc, (val, c)| {
                acc.and_then(|a| val.value().map(|v| a + *v * c))
            });

        let assigned = self
            .apply(
                ctx,
                [
                    Term::Assigned(vals[0], constants[0]),
                    Term::Assigned(vals[1], constants[1]),
                    Term::Assigned(vals[2], constants[2]),
                    Term::Assigned(vals[3], constants[3]),
                    Term::unassigned_to_sub(result),
                ],
                aff_constant,
                CombinationOptionCommon::OneLinerAdd.into(),
            )?
            .swap_remove(4);
        Ok(assigned)
    }
}

impl<F: PrimeField> MainGate<F> {
    /// Main Gate
    pub fn new(config: MainGateConfig) -> Self {
        MainGate {
            config: config.clone(),
            _marker: PhantomData::default(),
        }
    }

    /// Configure polynomial relationship and returns the resulting Config
    pub fn configure(meta: &mut ConstraintSystem<F>) -> MainGate<F> {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();
        let e = meta.advice_column();

        let sa = meta.fixed_column();
        let sb = meta.fixed_column();
        let sc = meta.fixed_column();
        let sd = meta.fixed_column();
        let se = meta.fixed_column();

        let s_mul_ab = meta.fixed_column();
        let s_mul_cd = meta.fixed_column();

        let se_next = meta.fixed_column();
        let s_constant = meta.fixed_column();

        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(d);
        meta.enable_equality(e);
        meta.enable_equality(instance);

        let q_h1 = meta.fixed_column();
        let q_h2 = meta.fixed_column();
        let q_h3 = meta.fixed_column();
        let q_h4 = meta.fixed_column();

        meta.create_gate("cap_gate", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());
            let e_next = meta.query_advice(e, Rotation::next());
            let e = meta.query_advice(e, Rotation::cur());

            let sa = meta.query_fixed(sa, Rotation::cur());
            let sb = meta.query_fixed(sb, Rotation::cur());
            let sc = meta.query_fixed(sc, Rotation::cur());
            let sd = meta.query_fixed(sd, Rotation::cur());
            let se = meta.query_fixed(se, Rotation::cur());

            let se_next = meta.query_fixed(se_next, Rotation::cur());

            let s_mul_ab = meta.query_fixed(s_mul_ab, Rotation::cur());
            let s_mul_cd = meta.query_fixed(s_mul_cd, Rotation::cur());

            let s_constant = meta.query_fixed(s_constant, Rotation::cur());

            let q_h1 = meta.query_fixed(q_h1, Rotation::cur());
            let q_h2 = meta.query_fixed(q_h2, Rotation::cur());
            let q_h3 = meta.query_fixed(q_h3, Rotation::cur());
            let q_h4 = meta.query_fixed(q_h4, Rotation::cur());

            let pow_5 = |val: Expression<F>| -> Expression<F> {
                val.clone() * val.clone() * val.clone() * val.clone() * val.clone()
            };

            vec![
                a.clone() * sa
                    + b.clone() * sb
                    + c.clone() * sc
                    + d.clone() * sd
                    + e * se
                    + a.clone() * b.clone() * s_mul_ab
                    + c.clone() * d.clone() * s_mul_cd
                    + se_next * e_next
                    + s_constant
                    + pow_5(a) * q_h1
                    + pow_5(b) * q_h2
                    + pow_5(c) * q_h3
                    + pow_5(d) * q_h4,
            ]
        });

        let config = MainGateConfig {
            a,
            b,
            c,
            d,
            e,
            sa,
            sb,
            sc,
            sd,
            se,
            se_next,
            s_constant,
            s_mul_ab,
            s_mul_cd,
            instance,
            q_h1,
            q_h2,
            q_h3,
            q_h4,
        };

        MainGate {
            config,
            _marker: Default::default(),
        }
    }
}
