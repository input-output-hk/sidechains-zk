//! rescue_crhf_gate implements the rescue sponge-based crhf.

use crate::rescue::{RescuePermGate, RescuePermGateConfig, RescuePermInstructions};
use crate::util::RegionCtx;
use crate::AssignedValue;
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Chip, Value},
    plonk::{ConstraintSystem, Error},
};

use crate::instructions::MainGateInstructions;

const RATE: usize = 3;

use super::primitive::*;

// helper function to transform AssignedRescueState to AssignedRescueStateRef
// TODO: consider using array_methods when it is more stable
fn get_refs<F: PrimeField>(state: &[AssignedValue<F>; 4]) -> [&AssignedValue<F>; 4] {
    // this should never panic since we map [F; N] to [&F: N]
    state.iter().collect::<Vec<_>>().try_into().unwrap()
}

/// Configuration for RescuePermGate. This simply contains the CapGateConfig.
#[derive(Clone, Debug)]
pub struct RescueCrhfGateConfig {
    rescue_perm_gate_config: RescuePermGateConfig,
}

/// Rescue CRHF Gate. It consists of a RescueCrhfGate and depends on rescue parameters which in turn
/// depend on the field choice
#[derive(Clone, Debug)]
pub struct RescueCrhfGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    pub(crate) rescue_perm_gate: RescuePermGate<F, RP>,
    pub(crate) config: RescueCrhfGateConfig,
}

impl<F, RP> RescueCrhfGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Rescue Gate
    pub fn new(config: RescueCrhfGateConfig) -> Self {
        RescueCrhfGate {
            rescue_perm_gate: RescuePermGate::new(config.clone().rescue_perm_gate_config),
            config,
        }
    }

    /// Configure the rescue gate by configuring the rescue_perm_gate
    pub fn configure(meta: &mut ConstraintSystem<F>) -> RescueCrhfGateConfig {
        RescueCrhfGateConfig {
            rescue_perm_gate_config: RescuePermGate::<F, RP>::configure(meta),
        }
    }
}

impl<F, RP> Chip<F> for RescueCrhfGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    type Config = RescueCrhfGateConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// Instructions for the Rescue Permutation
pub trait RescueCrhfInstructions<F>: Chip<F>
where
    F: PrimeField,
{
    /// Given a constant state st, computes a new state by mapping st[i] to st[i] + constant[i]
    fn hash(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        input: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error>;
}

impl<F, RP> RescueCrhfInstructions<F> for RescueCrhfGate<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    fn hash(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        input: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        debug_assert!(input.len() % RATE == 0);

        // TODO: Consider a better way for this
        let zero = self
            .rescue_perm_gate
            .maingate
            .assign_value(ctx, Value::known(F::ZERO))?;
        self.rescue_perm_gate
            .maingate
            .assert_equal_to_constant(ctx, &zero, F::ZERO)?;

        let mut state: [AssignedValue<F>; STATE_WIDTH] = [&input[0..RATE], &[zero.clone()]]
            .concat()
            .try_into()
            .unwrap();

        state = self
            .rescue_perm_gate
            .rescue_permutation(ctx, get_refs(&state))?;

        for i in 1..(input.len() / RATE) {
            let next_input: [AssignedValue<F>; STATE_WIDTH] =
                [&input[RATE * i..RATE * i + RATE], &[zero.clone()]]
                    .concat()
                    .try_into()
                    .unwrap();
            state = self.rescue_perm_gate.state_addition(
                ctx,
                get_refs(&state),
                get_refs(&next_input),
            )?;
            state = self
                .rescue_perm_gate
                .rescue_permutation(ctx, get_refs(&state))?;
        }
        Ok(state[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use crate::rescue::test_vectors::*;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit;
    use halo2curves::bls12_381::Scalar;

    #[derive(Clone)]
    struct TestCircuitConfig {
        rescue_crhf_config: RescueCrhfGateConfig,
    }

    // The prover claims knowlegde of preimage of a hash output
    #[derive(Default)]
    struct TestCircuitPreimage<F, RP>
    where
        F: PrimeField,
        RP: RescueParameters<F>,
    {
        rescue_params: PhantomData<RP>,
        // The rescue hash (secret) input
        witness: Vec<F>,
    }

    impl<F, RP> Circuit<F> for TestCircuitPreimage<F, RP>
    where
        F: PrimeField,
        RP: RescueParameters<F>,
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let rescue_crhf_config = RescueCrhfGate::<F, RP>::configure(meta);
            TestCircuitConfig { rescue_crhf_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // the crhf gate
            let rescue_crhf_gate = RescueCrhfGate::<F, RP>::new(config.rescue_crhf_config.clone());

            // compute witness inside the circuit
            let assigned_result = layouter.assign_region(
                || "Testing rescue crhf region",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // wrap field elements around Value
                    let values = self
                        .witness
                        .clone()
                        .into_iter()
                        .map(|v| Value::known(v))
                        .collect::<Vec<_>>();

                    // assign the witness (hash preimage)
                    let assigned_hash_input = rescue_crhf_gate
                        .rescue_perm_gate
                        .maingate
                        .assign_values_slice(ctx, &values)?;

                    // compute hash_output (the public input) in circuit using the rescue crhf gate
                    rescue_crhf_gate.hash(ctx, &assigned_hash_input)
                },
            )?;

            layouter.constrain_instance(
                assigned_result.cell(),
                config
                    .rescue_crhf_config
                    .rescue_perm_gate_config
                    .maingate_config
                    .instance,
                0,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_rescue_crhf_preimage_pasta() {
        const K: u32 = 10;
        BLS_SPONGE_TEST_VECTORS.iter().for_each(|test_vec| {
            let circuit = TestCircuitPreimage::<Scalar, RescueParametersBls> {
                // hash input is the witness
                witness: Vec::from(test_vec.0),
                rescue_params: PhantomData::default(),
            };

            let correct_result: Scalar =
                RescueSponge::<Scalar, RescueParametersBls>::hash(&circuit.witness, None);

            // hash output is the public input
            let pi = vec![vec![correct_result]];

            let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");

            assert!(prover.verify().is_ok());
        });
    }
}
