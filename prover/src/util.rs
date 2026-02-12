//! Utilities for numeric operations.

use ff::PrimeField;
use midnight_proofs::plonk::Instance;
use midnight_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Column, Error, Fixed, Selector},
};
use num_bigint::BigUint;
use num_traits::{Num, One};
use std::ops::Mul;
use std::process::Output;
use std::{iter, ops::Shl};

#[cfg(test)]
use rand_core::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct RegionCtx<'a, F: PrimeField> {
    region: Region<'a, F>,
    offset: usize,
}

impl<'a, F: PrimeField> RegionCtx<'a, F> {
    pub fn new(region: Region<'a, F>, offset: usize) -> RegionCtx<'a, F> {
        RegionCtx { region, offset }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn into_region(self) -> Region<'a, F> {
        self.region
    }

    pub fn assign_fixed<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_fixed(annotation, column, self.offset, || Value::known(value))
    }

    pub fn copy_advice<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        cell: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let offset = self.offset;
        cell.copy_advice(annotation, &mut self.region, column, offset)
    }

    pub fn assign_advice_from_instance<A, AR>(
        &mut self,
        annotation: A,
        instance: Column<Instance>,
        row: usize,
        advice: Column<Advice>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region.assign_advice_from_instance(
            || annotation().into(),
            instance,
            row,
            advice,
            offset,
        )
    }

    pub fn assign_advice<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_advice(annotation, column, self.offset, || value)
    }

    pub fn constrain_equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }

    pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(&mut self.region, self.offset)
    }

    pub fn next(&mut self) {
        self.offset += 1
    }
}

pub fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub fn power_of_two<F: PrimeField>(n: usize) -> F {
    big_to_fe(BigUint::one() << n)
}

pub fn big_to_fe<F: PrimeField>(e: BigUint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn decompose<F: PrimeField>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}

pub fn decompose_big<F: PrimeField>(e: BigUint, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    let mut e = e;
    let mask = BigUint::from(1usize).shl(bit_len) - 1usize;
    let limbs: Vec<F> = (0..number_of_limbs)
        .map(|_| {
            let limb = mask.clone() & e.clone();
            e = e.clone() >> bit_len;
            big_to_fe(limb)
        })
        .collect();

    limbs
}

/// Decomposes an element into a determined number of limbs. The decomposition is done in such a
/// way that each limb is an accumulation of the next ones: The first limb is equal to the provided
/// value, then each limb is equal to the previous limb right shifted by `bit_len`. Note:
/// `number_of_limbs` may be larger than the what is necessary to represent the given element, in
/// these case the last limbs are 0.
pub fn decompose_acc<F: PrimeField>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    let mut val = fe_to_big(e);
    iter::once(e)
        .chain((1..number_of_limbs).map(|_| {
            val >>= bit_len;
            big_to_fe(val.clone())
        }))
        .collect()
}

/// Create an array with random values
#[cfg(test)]
pub(crate) fn random_scalar_array<const SIZE: usize, F: PrimeField, R: RngCore + CryptoRng>(
    mut rng: R,
) -> [F; SIZE] {
    let mut vec = Vec::with_capacity(SIZE);
    for _ in 0..SIZE {
        vec.push(F::random(&mut rng));
    }

    vec.try_into().unwrap()
}

/// Raises val to the 5th power using 3 multiplications
pub(crate) fn pow_5<M>(val: M) -> M
where
    M: Mul<M, Output = M> + Clone,
{
    let val2 = val.clone() * val.clone();
    val2.clone() * val2 * val
}
