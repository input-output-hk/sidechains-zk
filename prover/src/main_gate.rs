//! The `main_gate` is a five width stardart like PLONK gate
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

use std::marker::PhantomData;
use halo2_proofs::circuit::Chip;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, Instance};
use halo2_proofs::poly::Rotation;
use halo2curves::ff::PrimeField;

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
    pub(crate) instance: Column<Instance>,

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
            _marker: Default::default()
        }
    }
}
