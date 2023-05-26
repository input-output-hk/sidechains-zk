//! rescue_perm_gate implements the rescue permutation as described [here](https://eprint.iacr.org/2019/426.pdf).
//! We assume a fixed state size of 4 fixed elements.

use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::Chip,
    plonk::{ConstraintSystem, Error},
};

use crate::instructions::MainGateInstructions;
use crate::main_gate::{MainGate, MainGateConfig};
use crate::util::RegionCtx;
use crate::AssignedValue;

use super::primitive::*;

/// Raises val to the {1/5}-th power
fn pow_5_inv<F, RP>(val: F) -> F
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    val.pow_vartime(RP::A_INV)
}

// Type aliases for assigned rescue states
pub(crate) type AssignedRescueState<F> = [AssignedValue<F>; STATE_WIDTH];
pub(crate) type AssignedRescueStateRef<'a, F> = [&'a AssignedValue<F>; STATE_WIDTH];

// Type alias for key type used in Rescue Cipher
type AssignedKeyInjection<F> = [AssignedRescueState<F>; 2 * N_ROUNDS + 1];

/// Configuration for RescuePermGate. This simply contains the CapGateConfig.
#[derive(Clone, Debug)]
pub struct RescuePermGateConfig {
    pub maingate_config: MainGateConfig,
}

/// Rescue Permutation Gate. It consists of CapGate and depends on rescue parameters which in turn
/// depend on the field choice
#[derive(Clone, Debug)]
pub struct RescuePermGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    pub(crate) maingate: MainGate<F>,
    config: RescuePermGateConfig,
    rescue_parameters: PhantomData<RP>,
}

impl<F, RP> RescuePermGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Rescue Gate
    pub fn new(config: RescuePermGateConfig) -> Self {
        RescuePermGate {
            maingate: MainGate::new(config.clone().maingate_config),
            config,
            rescue_parameters: PhantomData::default(),
        }
    }

    /// Configure the rescue gate by configuring the cap gate
    pub fn configure(meta: &mut ConstraintSystem<F>) -> RescuePermGateConfig {
        RescuePermGateConfig {
            maingate_config: MainGate::configure(meta).config().clone(),
        }
    }
}

impl<F, RP> Chip<F> for RescuePermGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    type Config = RescuePermGateConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// Instructions for the Rescue Permutation
pub trait RescuePermInstructions<F, RP>: Chip<F>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Given a state st, computes a new state by mapping st[i] to st_a[i] + st_b[i]
    fn state_addition(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given a state st, computes a new state by mapping st[i] to st_a[i] + st_b[i]
    fn state_negation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given a constant state st, computes a new state by mapping st[i] to st[i] + constant[i]
    fn constant_state_addition(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        constant: &RescueState<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given a state st, computes a new state by mapping st[i] to st[i]^{1/5}
    fn state_inversion(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given two states st_a and st_b, computes a new state by mapping st_a to M st_a + st_b
    fn affine_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given a state st, computes a new state by mapping st to M st + constant  
    fn constant_affine_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        constant: &RescueState<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given two states st_a and st_b, computes a new state by mapping st_a to M st_a^5 + st_b
    /// where st^5 denotes exponentiation by 5 in each element of st_a
    fn nonlinear_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Given a state st, computes a new state by mapping st to M st^5 + constant  
    /// where st^5 denotes exponentiation by 5 in each element of st
    fn constant_nonlinear_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        constant: &RescueState<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error>;

    /// Performs the rescue permutation as described in `RescueWithRoundKeys` procedure of Algorithm 2
    /// of the [CAP specification](https://github.com/EspressoSystems/cap/blob/main/cap-specification.pdf).
    /// This considers fixed keys which are known and treated as constant values.
    fn rescue_permutation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        // add initial round constants to state
        let round_constant_initial = RP::round_constants_state(0);
        let mut st = self.constant_state_addition(ctx, st, &round_constant_initial)?;

        let mds = RP::mds();

        // We apply the round transformation N_ROUNDS times. In each iteration, we constraint the
        // full round, that is, we apply st -> inverse S box -> affine transformation -> pow_5 S box -> affine
        // transformation. This corresponds to two loop iterations as described in the CAP specs.
        for i in 0..N_ROUNDS {
            let round_constant_start = RP::round_constants_state(2 * i + 1);
            let round_constant_end = RP::round_constants_state(2 * i + 2);

            // apply state inversion
            st = self.state_inversion(ctx, get_refs(&st))?;

            // apply the affine transformation in the inverted values
            st = self.constant_affine_transformation(
                ctx,
                get_refs(&st),
                &round_constant_start,
                &mds,
            )?;

            // apply the affine transformation in the exponentiated values
            st = self.constant_nonlinear_transformation(
                ctx,
                get_refs(&st),
                &round_constant_end,
                &mds,
            )?;
        }

        Ok(st)
    }

    /// Performs the `RescueWithRoundKeys` procedure of Algorithm 2 with non-fixed keys. To use this procedure
    /// with fixed keys, use `rescue_permutation`.
    fn rescue_with_round_keys(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        key_injection: &AssignedKeyInjection<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let mut st = self.state_addition(ctx, st, get_refs(&key_injection[0]))?;

        let mds = RP::mds();

        // We apply the round transformation N_ROUNDS times. In each iteration, we constraint the
        // full round, that is, we apply st -> inverse S box -> affine transformation -> pow_5 S box -> affine
        // transformation. This corresponds to two loop iterations as described in the CAP specs.
        for i in 0..N_ROUNDS {
            // apply state inversion
            st = self.state_inversion(ctx, get_refs(&st))?;

            // apply the affine transformation in the inverted values
            st = self.affine_transformation(
                ctx,
                get_refs(&st),
                get_refs(&key_injection[2 * i + 1]),
                &mds,
            )?;

            // apply the affine transformation in the exponentiated values
            st = self.nonlinear_transformation(
                ctx,
                get_refs(&st),
                get_refs(&key_injection[2 * i + 2]),
                &mds,
            )?;
        }

        Ok(st)
    }
    /// Performs the full rescue permutation as described in `RescuePseudoRandomPermutation` procedure of Algorithm 2
    /// of the [CAP specification](https://github.com/EspressoSystems/cap/blob/main/cap-specification.pdf).
    fn rescue_cipher(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        key: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let key_injection = self.key_scheduling(ctx, key)?;
        self.rescue_with_round_keys(ctx, st, &key_injection)
    }

    /// Implements the `KeyScheduling` procedure of Algorithm 2 from the CAP spec
    fn key_scheduling(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: AssignedRescueStateRef<F>,
    ) -> Result<AssignedKeyInjection<F>, Error> {
        let mut key_schedule = Vec::with_capacity(N_ROUNDS * 2 + 1);
        let mut prev_key = self.constant_state_addition(ctx, key, &RP::key_injection_state(0))?;
        key_schedule.push(prev_key.clone());

        for i in 0..N_ROUNDS {
            // apply state inversion
            prev_key = self.state_inversion(ctx, get_refs(&prev_key))?;

            // apply affine transformation
            prev_key = self.constant_affine_transformation(
                ctx,
                get_refs(&prev_key),
                &RP::key_injection_state(2 * i + 1),
                &RP::MDS,
            )?;

            key_schedule.push(prev_key.clone());

            // apply the affine transformation in the exponentiated values
            prev_key = self.constant_nonlinear_transformation(
                ctx,
                get_refs(&prev_key),
                &RP::key_injection_state(2 * i + 2),
                &RP::MDS,
            )?;

            key_schedule.push(prev_key.clone());
        }

        // Will not panic as key_schedule, if we reach this point, will have size 2 * N_ROUNDS + 1
        Ok(key_schedule.try_into().unwrap())
    }
}

// helper function to transform AssignedRescueState to AssignedRescueStateRef
// TODO: consider using array_methods when it is more stable
pub(crate) fn get_refs<F: PrimeField>(state: &AssignedRescueState<F>) -> AssignedRescueStateRef<F> {
    // this should never panic since we map [F; N] to [&F: N]
    state.iter().collect::<Vec<_>>().try_into().unwrap()
}

impl<F, RP> RescuePermInstructions<F, RP> for RescuePermGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    fn state_addition(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let new_st = st_a
            .iter()
            .zip(st_b.iter())
            .map(|(a, b)| self.maingate.add(ctx, a, b))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        Ok(new_st)
    }

    fn state_negation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let new_st = st_a
            .iter()
            .zip(st_b.iter())
            .map(|(a, b)| self.maingate.sub(ctx, a, b))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        Ok(new_st)
    }

    fn constant_state_addition(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        constant: &RescueState<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let new_st = st
            .iter()
            .zip(constant.iter())
            .map(|(s, c)| self.maingate.add_constant(ctx, s, *c))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            // never panics: new_st contains 4 elements
            .unwrap();
        Ok(new_st)
    }

    fn state_inversion(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let new_st = st
            .iter()
            .map(|s| {
                let s_inv5 = s.value().copied().map(|v| pow_5_inv::<F, RP>(v));
                self.maingate.assert_pow_5(ctx, s, s_inv5)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            // never panics: new_st contains 4 elements
            .unwrap();

        Ok(new_st)
    }

    fn affine_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        // we add STATE_WIDTH constraint, one for each state variable
        let new_st = matrix
            .iter()
            .zip(st_b.iter())
            .map(|(&row, &c)| {
                let affine_result =
                    self.maingate
                        .const_affine_transformation(ctx, st_a, row, F::ZERO)?;
                self.maingate.add(ctx, &affine_result, c)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            // never panics: new_st contains 4 elements
            .unwrap();
        Ok(new_st)
    }

    fn constant_affine_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        constant: &RescueState<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        // we add STATE_WIDTH constraint, one for each state variable
        let new_st = matrix
            .iter()
            .zip(constant.iter())
            .map(|(&row, &c)| self.maingate.const_affine_transformation(ctx, st, row, c))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            // never panics: new_st contains 4 elements
            .unwrap();
        Ok(new_st)
    }

    fn nonlinear_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st_a: AssignedRescueStateRef<F>,
        st_b: AssignedRescueStateRef<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let new_st = matrix
            .iter()
            .zip(st_b.iter())
            .map(|(&row, &c)| {
                let nonlinear_result = self.maingate.sum_pow_5_const(ctx, st_a, row, F::ZERO)?;
                self.maingate.add(ctx, &nonlinear_result, c)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            // never panics: new_st contains 4 elements
            .unwrap();
        Ok(new_st)
    }

    fn constant_nonlinear_transformation(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        st: AssignedRescueStateRef<F>,
        constant: &RescueState<F>,
        matrix: &RescueMatrix<F>,
    ) -> Result<AssignedRescueState<F>, Error> {
        let new_st = matrix
            .iter()
            .zip(constant.iter())
            .map(|(&row, &c)| self.maingate.sum_pow_5_const(ctx, st, row, c))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            // never panics: new_st contains 4 elements
            .unwrap();
        Ok(new_st)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::rescue::test_vectors::*;
//     use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
//     use halo2_proofs::dev::MockProver;
//     use halo2_proofs::plonk::Circuit;
//     use pasta_curves::{Fp, Fq};
//
//     #[derive(Clone)]
//     struct TestCircuitConfig {
//         rescue_perm_config: RescuePermGateConfig,
//     }
//
//     // Test1: The prover claims knowlegde of preimage of a hash output
//     #[derive(Default)]
//     struct TestCircuitPreimage<F, RP>
//     where
//         F: PrimeField,
//         RP: RescueParameters<F>,
//     {
//         // rescue parameters
//         rescue_params: PhantomData<RP>,
//         // The rescue hash (secret) input
//         witness: RescueState<F>,
//     }
//
//     impl<F, RP> Circuit<F> for TestCircuitPreimage<F, RP>
//     where
//         F: PrimeField,
//         RP: RescueParameters<F>,
//     {
//         type Config = TestCircuitConfig;
//         type FloorPlanner = SimpleFloorPlanner;
//
//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }
//
//         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//             let rescue_perm_config = RescuePermGate::<F, RP>::configure(meta);
//             TestCircuitConfig { rescue_perm_config }
//         }
//
//         fn synthesize(
//             &self,
//             config: Self::Config,
//             mut layouter: impl Layouter<F>,
//         ) -> Result<(), Error> {
//             // the rescue gate
//             let rescue_gate = RescuePermGate::<F, RP>::new(config.rescue_perm_config.clone());
//
//             // compute rescue_perm(witness) inside the circuit
//             let assigned_result = layouter.assign_region(
//                 || "Testing rescue prp region",
//                 |region| {
//                     let offset = 0;
//                     let ctx = &mut RegionCtx::new(region, offset);
//
//                     // wrap field elements around Value
//                     let values = self
//                         .witness
//                         .into_iter()
//                         .map(|v| Value::known(v))
//                         .collect::<Vec<_>>();
//
//                     // assign the witness (hash preimage)
//                     let assigned_hash_input =
//                         rescue_gate.maingate.assign_values_slice(ctx, &values)?;
//
//                     // compute hash_output (the public input) in circuit using the rescue gate
//                     rescue_gate
//                         .rescue_permutation(ctx, get_refs(&assigned_hash_input.try_into().unwrap()))
//                 },
//             )?;
//
//             // constraint the output to equal the public input:
//             assigned_result
//                 .iter()
//                 .enumerate()
//                 .try_for_each(|(i, val)| {
//                     layouter.constrain_instance(
//                         val.cell(),
//                         config
//                             .rescue_perm_config
//                             .capgate_config
//                             .main_gate_config
//                             .instance,
//                         i,
//                     )
//                 })?;
//             Ok(())
//         }
//     }
//
//     #[test]
//     fn test_rescue_perm_preimage_pallas() {
//         const K: u32 = 8;
//         PALLAS_TEST_VECTORS.iter().for_each(|test_vec| {
//             let circuit = TestCircuitPreimage::<Fp, RescueParametersPallas> {
//                 // hash input is the witness
//                 witness: test_vec.0,
//                 rescue_params: PhantomData::default(),
//             };
//
//             let rescue_prp = RescuePRP::<Fp, RescueParametersPallas>::new(None);
//
//             // compute output outside of circuit
//             let permuted = rescue_prp.permute(&circuit.witness);
//
//             // hash output is the public input
//             let pi = vec![permuted.into()];
//
//             let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");
//
//             assert!(prover.verify().is_ok());
//         })
//     }
//     #[test]
//     fn test_rescue_perm_preimage_vesta() {
//         const K: u32 = 8;
//         VESTA_TEST_VECTORS.iter().for_each(|test_vec| {
//             let circuit = TestCircuitPreimage::<Fq, RescueParametersVesta> {
//                 // hash input is the witness
//                 witness: test_vec.0,
//                 rescue_params: PhantomData::default(),
//             };
//
//             let rescue_prp = RescuePRP::<Fq, RescueParametersVesta>::new(None);
//
//             // compute output outside of circuit
//             let permuted = rescue_prp.permute(&circuit.witness);
//
//             // hash output is the public input
//             let pi = vec![permuted.into()];
//
//             let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");
//
//             assert!(prover.verify().is_ok());
//         })
//     }
//
//     // Test2: The prover claims that it knows input such that H(H...(H(input))) = output (applied 32 times)
//     // The outputs can be cross-checked with the scipts `rescue_pallas.sage` and `rescue_vesta.sage`
//     // from [this repo](https://github.com/alexandroszacharakis8/Marvellous)
//     // commit 81f3bbb1c8536186679a4c6acca31b88d656ec7e
//     #[derive(Default)]
//     struct TestCircuitChain<F, RP>
//     where
//         F: PrimeField,
//         RP: RescueParameters<F>,
//     {
//         // rescue parameters
//         rescue_params: PhantomData<RP>,
//         // The rescue hash chain input
//         witness: RescueState<F>,
//     }
//
//     impl<F, RP> Circuit<F> for TestCircuitChain<F, RP>
//     where
//         F: PrimeField,
//         RP: RescueParameters<F>,
//     {
//         type Config = TestCircuitConfig;
//         type FloorPlanner = SimpleFloorPlanner;
//
//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }
//
//         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//             let rescue_perm_config = RescuePermGate::<F, RP>::configure(meta);
//             TestCircuitConfig { rescue_perm_config }
//         }
//
//         fn synthesize(
//             &self,
//             config: Self::Config,
//             mut layouter: impl Layouter<F>,
//         ) -> Result<(), Error> {
//             // the rescue gate
//             let rescue_gate = RescuePermGate::<F, RP>::new(config.rescue_perm_config.clone());
//
//             // compute rescue_perm^{32}(witness) inside the circuit
//             let assigned_result = layouter.assign_region(
//                 || "Testing rescue prp region",
//                 |region| {
//                     let offset = 0;
//                     let ctx = &mut RegionCtx::new(region, offset);
//
//                     // wrap field elements around Value
//                     let values = self
//                         .witness
//                         .into_iter()
//                         .map(|v| Value::known(v))
//                         .collect::<Vec<_>>();
//
//                     // assign the witness (hash preimage)
//                     let assigned_hash_input =
//                         rescue_gate.maingate.assign_values_slice(ctx, &values)?;
//
//                     // 32 applications of the rescue permutation
//                     let mut assigned_hash_output = assigned_hash_input.try_into().unwrap();
//                     for _ in 0..32 {
//                         assigned_hash_output =
//                             rescue_gate.rescue_permutation(ctx, get_refs(&assigned_hash_output))?;
//                     }
//                     Ok(assigned_hash_output)
//                 },
//             )?;
//
//             // constraint the output to equal the public input:
//             assigned_result
//                 .iter()
//                 .enumerate()
//                 .try_for_each(|(i, val)| {
//                     layouter.constrain_instance(
//                         val.cell(),
//                         config
//                             .rescue_perm_config
//                             .capgate_config
//                             .main_gate_config
//                             .instance,
//                         i,
//                     )
//                 })?;
//             Ok(())
//         }
//     }
//
//     #[test]
//     fn test_rescue_perm_chain_pallas() {
//         const K: u32 = 13;
//         // We test h(h..(h(0))..) = output
//         let circuit = TestCircuitChain::<Fp, RescueParametersPallas> {
//             // hash input is the witness
//             witness: [Fp::zero(), Fp::zero(), Fp::zero(), Fp::zero()],
//             rescue_params: PhantomData::default(),
//         };
//
//         let rescue_prp = RescuePRP::<Fp, RescueParametersPallas>::new(None);
//
//         // compute output outside of circuit
//         let mut chained = circuit.witness;
//         for _ in 0..32 {
//             chained = rescue_prp.permute(&chained);
//         }
//
//         // fixed output for crosschecking
//         // let output = [
//         //     Fp::from_raw([
//         //         0x364a25222ccced65,
//         //         0x806e8b9291e8eded,
//         //         0xdd35fd2cb238d8e3,
//         //         0x250deed477d12b79,
//         //     ]),
//         //     Fp::from_raw([
//         //         0x73e6e6b36d8dc9cc,
//         //         0x84a3185e268c9e01,
//         //         0x27327c9d8027f60f,
//         //         0x30fb9a1d4cfb2eae,
//         //     ]),
//         //     Fp::from_raw([
//         //         0xd18398c4641ef40b,
//         //         0xa4040e8ce552fcf8,
//         //         0xc5f96ae8af76d73e,
//         //         0x162379e0627f80e1,
//         //     ]),
//         //     Fp::from_raw([
//         //         0xd3cec126fe000464,
//         //         0x3793a281cd331fd1,
//         //         0x9917b2ef5f3fa3da,
//         //         0x2e90fdbf441682b1,
//         //     ]),
//         // ];
//
//         let pi = vec![chained.into()];
//
//         let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");
//
//         assert!(prover.verify().is_ok());
//     }
//
//     #[test]
//     fn test_rescue_perm_chain_vesta() {
//         const K: u32 = 13;
//         // We test h(h..(h(0))..) = output
//         let circuit = TestCircuitChain::<Fq, RescueParametersVesta> {
//             // hash input is the witness
//             witness: [Fq::zero(), Fq::zero(), Fq::zero(), Fq::zero()],
//             rescue_params: PhantomData::default(),
//         };
//
//         let rescue_prp = RescuePRP::<Fq, RescueParametersVesta>::new(None);
//
//         // compute output outside of circuit
//         let mut chained = circuit.witness;
//         for _ in 0..32 {
//             chained = rescue_prp.permute(&chained);
//         }
//
//         // fixed output for crosschecking
//         // let output = [
//         //     Fq::from_raw([
//         //         0x1f8e6684f330fcb9,
//         //         0xc97dcd449d22fd2f,
//         //         0xbf47920de669b490,
//         //         0x1e4debc2f76471cb,
//         //     ]),
//         //     Fq::from_raw([
//         //         0x3aa6197384cba66a,
//         //         0xe2752cdde16fdaf3,
//         //         0x4f770a6d8a75c9e7,
//         //         0x39957fbda746359,
//         //     ]),
//         //     Fq::from_raw([
//         //         0x3bd73588dd3b10ae,
//         //         0xebc797569daa7b51,
//         //         0xe2698b49f643873c,
//         //         0x30e4acb7ca34812a,
//         //     ]),
//         //     Fq::from_raw([
//         //         0x25228cb3e2c739b2,
//         //         0xbb2b917568a2b5c7,
//         //         0x6917c6a30bf50714,
//         //         0xf9a1c9ca52809b1,
//         //     ]),
//         // ];
//
//         let pi = vec![chained.into()];
//
//         let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");
//
//         assert!(prover.verify().is_ok());
//     }
//
//     // Test3: The prover claims knowlegde of key and preimage of an output permutation
//     #[derive(Default)]
//     struct TestCircuitCipherPreimage<F, RP>
//     where
//         F: PrimeField,
//         RP: RescueParameters<F>,
//     {
//         // rescue parameters
//         rescue_params: PhantomData<RP>,
//         // The rescue key (secret) input
//         key: RescueState<F>,
//         // The rescue input (secret) input
//         input: RescueState<F>,
//     }
//
//     impl<F, RP> Circuit<F> for TestCircuitCipherPreimage<F, RP>
//     where
//         F: PrimeField,
//         RP: RescueParameters<F>,
//     {
//         type Config = TestCircuitConfig;
//         type FloorPlanner = SimpleFloorPlanner;
//
//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }
//
//         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//             let rescue_perm_config = RescuePermGate::<F, RP>::configure(meta);
//             TestCircuitConfig { rescue_perm_config }
//         }
//
//         fn synthesize(
//             &self,
//             config: Self::Config,
//             mut layouter: impl Layouter<F>,
//         ) -> Result<(), Error> {
//             // the rescue gate
//             let rescue_gate = RescuePermGate::<F, RP>::new(config.rescue_perm_config.clone());
//
//             // compute rescue_perm(witness) inside the circuit
//             let assigned_result = layouter.assign_region(
//                 || "Testing keyed rescue prp region",
//                 |region| {
//                     let offset = 0;
//                     let ctx = &mut RegionCtx::new(region, offset);
//
//                     // wrap field elements around Value
//                     let key_values = self
//                         .key
//                         .into_iter()
//                         .map(|v| Value::known(v))
//                         .collect::<Vec<_>>();
//                     let input_values = self
//                         .input
//                         .into_iter()
//                         .map(|v| Value::known(v))
//                         .collect::<Vec<_>>();
//
//                     // assign the key and input values
//                     let assigned_key = rescue_gate.maingate.assign_values_slice(ctx, &key_values)?;
//
//                     let assigned_input = rescue_gate
//                         .capgate
//                         .assign_values_slice(ctx, &input_values)?;
//
//                     // compute hash_output (the public input) in circuit using the rescue gate
//                     rescue_gate.rescue_cipher(
//                         ctx,
//                         get_refs(&assigned_input.try_into().unwrap()),
//                         get_refs(&assigned_key.try_into().unwrap()),
//                     )
//                 },
//             )?;
//
//             // constraint the output to equal the public input:
//             assigned_result
//                 .iter()
//                 .enumerate()
//                 .try_for_each(|(i, val)| {
//                     layouter.constrain_instance(
//                         val.cell(),
//                         config
//                             .rescue_perm_config
//                             .capgate_config
//                             .main_gate_config
//                             .instance,
//                         i,
//                     )
//                 })?;
//             Ok(())
//         }
//     }
//
//     #[test]
//     fn test_rescue_cipher_preimage_pallas() {
//         const K: u32 = 9;
//         PALLAS_TEST_VECTORS_KEYED.iter().for_each(|test_vec| {
//             let circuit = TestCircuitCipherPreimage::<Fp, RescueParametersPallas> {
//                 // hash input is the witness
//                 key: test_vec.0,
//                 input: test_vec.1,
//                 rescue_params: PhantomData::default(),
//             };
//
//             let rescue_prp = RescuePRP::<Fp, RescueParametersPallas>::new(Some(test_vec.0));
//
//             // compute output outside of circuit
//             let permuted = rescue_prp.permute(&circuit.input);
//
//             // hash output is the public input
//             let pi = vec![permuted.into()];
//
//             let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");
//
//             assert!(prover.verify().is_ok());
//         })
//     }
//     #[test]
//     fn test_rescue_cipher_preimage_vesta() {
//         const K: u32 = 9;
//         VESTA_TEST_VECTORS_KEYED.iter().for_each(|test_vec| {
//             let circuit = TestCircuitCipherPreimage::<Fq, RescueParametersVesta> {
//                 // hash input is the witness
//                 key: test_vec.0,
//                 input: test_vec.1,
//                 rescue_params: PhantomData::default(),
//             };
//
//             let rescue_prp = RescuePRP::<Fq, RescueParametersVesta>::new(Some(test_vec.0));
//
//             // compute output outside of circuit
//             let permuted = rescue_prp.permute(&circuit.input);
//
//             // hash output is the public input
//             let pi = vec![permuted.into()];
//
//             let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");
//
//             assert!(prover.verify().is_ok());
//         })
//     }
// }
