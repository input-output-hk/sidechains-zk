//! Rescue Counter modes, as described in the cap spec (2022-03-04), page 38. This is used
//! to instantiate counter mode encryptions from rescue block ciphers.

use super::{
    get_refs, AssignedRescueState, AssignedRescueStateRef, RescueParameters, RescuePermGate,
    RescuePermGateConfig, RescuePermInstructions, STATE_WIDTH,
};
use crate::instructions::MainGateInstructions;
use crate::util::RegionCtx;
use ff::PrimeField;
use halo2_proofs::circuit::{Chip, Value};
use halo2_proofs::plonk::{ConstraintSystem, Error};

/// Configuration for RescueCounterModeGate.
#[derive(Clone, Debug)]
pub struct RescueCounterModeConfig {
    rescue_perm_config: RescuePermGateConfig,
}

/// Rescue Counter Mode gate. It consists of a `RescuePermGate`
#[derive(Clone, Debug)]
pub struct RescueCounterMode<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    rescue_gate: RescuePermGate<F, RP>,
    config: RescueCounterModeConfig,
}

impl<F, RP> RescueCounterMode<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Initiate the Rescue Counter Mode gate
    pub fn new(config: RescueCounterModeConfig) -> Self {
        RescueCounterMode {
            rescue_gate: RescuePermGate::new(config.clone().rescue_perm_config),
            config,
        }
    }

    /// Configure the Rescue Counter Mode gate by configuring the `RescuePermGateConfig`
    pub fn configure(meta: &mut ConstraintSystem<F>) -> RescueCounterModeConfig {
        RescueCounterModeConfig {
            rescue_perm_config: RescuePermGate::<F, RP>::configure(meta),
        }
    }
}

impl<F, RP> Chip<F> for RescueCounterMode<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    type Config = RescueCounterModeConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F, RP> RescueCounterMode<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Given input data `data`, formed by `l` `AssignedRescueStateRef` elements, a rescue cipher `key`,
    /// and a bool `encrypt` (that is `true` for encryption and `false` otherwise), it returns an
    /// encryption/decryption of `data` under `key`.
    fn apply_key_stream(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: AssignedRescueStateRef<'_, F>,
        data: Vec<AssignedRescueStateRef<'_, F>>,
        encrypt: bool,
    ) -> Result<Vec<AssignedRescueState<F>>, Error> {
        let mut output: Vec<AssignedRescueState<F>> = data
            .into_iter()
            .map(|val| {
                val.into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect();

        let round_keys = self.rescue_gate.key_scheduling(ctx, key)?;

        let mut input = self
            .rescue_gate
            .maingate
            .assign_values_slice(ctx, &[Value::known(F::ZERO); STATE_WIDTH])?;
        self.rescue_gate.maingate.is_zero(ctx, &input[0])?;
        for i in 1..STATE_WIDTH {
            self.rescue_gate
                .maingate
                .is_equal(ctx, &input[0], &input[i])?;
        }

        for val in output.iter_mut() {
            let key_stream = self.rescue_gate.rescue_with_round_keys(
                ctx,
                get_refs(&input.clone().try_into().unwrap()),
                &round_keys,
            )?;
            *val = if encrypt {
                self.rescue_gate
                    .state_addition(ctx, get_refs(val), get_refs(&key_stream))?
            } else {
                self.rescue_gate
                    .state_negation(ctx, get_refs(val), get_refs(&key_stream))?
            };

            input[0] = self
                .rescue_gate
                .maingate
                .add_constant(ctx, &input[0], F::ONE)?;
        }

        Ok(output)
    }

    /// Given a rescue cipher `key`, and a `msg` formed by `AssignedRescueStateRef` `F` element, the
    /// encrypt function proceeds to call the `apply_key_stream`.
    pub fn encrypt(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: AssignedRescueStateRef<'_, F>,
        msg: Vec<AssignedRescueStateRef<'_, F>>,
    ) -> Result<Vec<AssignedRescueState<F>>, Error> {
        self.apply_key_stream(ctx, key, msg, true)
    }

    /// Given a rescue cipher `key`, and a ciphertext `ctxt` formed by `AssignedRescueStateRef` `F` elements, the
    /// decrypt function proceeds to call the `apply_key_stream` in decryption mode.
    pub fn decrypt(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: AssignedRescueStateRef<'_, F>,
        ctxt: Vec<AssignedRescueStateRef<'_, F>>,
    ) -> Result<Vec<AssignedRescueState<F>>, Error> {
        self.apply_key_stream(ctx, key, ctxt, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::{RescueBlockCipher, RescueParametersBls, RescueState};
    use crate::util::random_scalar_array;
    use ff::Field;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit;
    // use halo2curves::bls12_381::Scalar;
    use blstrs::Scalar;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::marker::PhantomData;

    #[derive(Clone)]
    struct TestCircuitConfig {
        rescue_counter_config: RescueCounterModeConfig,
    }

    // Test: The prover claims knowledge of a key such that a given ciphertext is the encryption of a secret
    // plaintext.
    #[derive(Default)]
    struct TestCircuitCorrectEncryption<F, RP>
    where
        F: PrimeField,
        RP: RescueParameters<F>,
    {
        // rescue parameters
        rescue_params: PhantomData<RP>,
        // The rescue secret key
        key: RescueState<F>,
        // The secret, encrypted, message
        msg: Vec<RescueState<F>>,
    }

    impl<F, RP> Circuit<F> for TestCircuitCorrectEncryption<F, RP>
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
            let rescue_counter_config = RescueCounterMode::<F, RP>::configure(meta);
            TestCircuitConfig {
                rescue_counter_config,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // the rescue counter mode
            let rescue_counter_mode =
                RescueCounterMode::<F, RP>::new(config.rescue_counter_config.clone());

            // compute rescue_counter_mode(witness, msg) inside the circuit
            let assigned_result = layouter.assign_region(
                || "Proof of knowledge of encryption secret key",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // wrap field elements around Value
                    let key_values = self
                        .key
                        .into_iter()
                        .map(|v| Value::known(v))
                        .collect::<Vec<_>>();

                    let msg_values = self
                        .msg
                        .clone()
                        .into_iter()
                        .map(|msg_slice| {
                            msg_slice
                                .into_iter()
                                .map(|v| Value::known(v))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();

                    // assign the witness (seccret key)
                    let assigned_key = rescue_counter_mode
                        .rescue_gate
                        .maingate
                        .assign_values_slice(ctx, &key_values)?
                        .try_into()
                        .unwrap();

                    // assign the witness (msg)
                    let mut assigned_msg: Vec<AssignedRescueState<F>> = Vec::new();
                    for msg in msg_values {
                        let rescue_state = rescue_counter_mode
                            .rescue_gate
                            .maingate
                            .assign_values_slice(ctx, &msg)?;
                        assigned_msg.push(rescue_state.try_into().unwrap());
                    }

                    let ref_msgs = assigned_msg
                        .iter()
                        .map(|msg| get_refs(msg))
                        .collect::<Vec<_>>();
                    // compute hash_output (the public input) in circuit using the rescue gate
                    rescue_counter_mode.apply_key_stream(
                        ctx,
                        get_refs(&assigned_key),
                        ref_msgs,
                        true,
                    )
                },
            )?;

            // constraint the output to equal the public input:
            for (i, output_slice) in assigned_result.iter().enumerate() {
                for (j, val) in output_slice.iter().enumerate() {
                    layouter.constrain_instance(
                        val.cell(),
                        config
                            .rescue_counter_config
                            .rescue_perm_config
                            .maingate_config
                            .instance,
                        i * STATE_WIDTH + j, // The first `STATE_WIDTH` inputs were for the msg
                    )?;
                }
            }

            Ok(())
        }
    }

    #[test]
    fn test_encrypt() {
        const K: u32 = 10;
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let key = RescueBlockCipher::<Scalar, RescueParametersBls>::keygen(&mut rng);

        let msg = vec![
            [Scalar::random(&mut rng); 4],
            [Scalar::random(&mut rng); 4],
            [Scalar::random(&mut rng); 4],
        ];
        let ctxt = RescueBlockCipher::<Scalar, RescueParametersBls>::encrypt(msg.clone(), key);

        let circuit = TestCircuitCorrectEncryption::<Scalar, RescueParametersBls> {
            rescue_params: PhantomData::default(),
            key,
            msg,
        };

        let pi = vec![ctxt.concat()];

        let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");

        assert!(prover.verify().is_ok());

        let pi = vec![vec![Scalar::random(&mut rng); 4]];
        let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");

        assert!(prover.verify().is_err());
    }

    const MSG_LEN: usize = 4; // We create a circuit for a message with a fixed number of rows

    #[derive(Clone)]
    struct TestCircuitConfigMsgPi {
        rescue_counter_config: RescueCounterModeConfig,
    }

    // Test: The prover claims knowledge of a key such that a given ciphertext is the encryption of a given
    // plaintext.
    #[derive(Default)]
    struct TestCircuitCorrectEncryptionMsgPi<F, RP>
    where
        F: PrimeField,
        RP: RescueParameters<F>,
    {
        // rescue parameters
        rescue_params: PhantomData<RP>,
        // The rescue secret key
        key: RescueState<F>,
        // The message to be encrypted
        msg: [RescueState<F>; MSG_LEN],
    }

    impl<F, RP> Circuit<F> for TestCircuitCorrectEncryptionMsgPi<F, RP>
    where
        F: PrimeField,
        RP: RescueParameters<F>,
    {
        type Config = TestCircuitConfigMsgPi;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let rescue_counter_config = RescueCounterMode::<F, RP>::configure(meta);
            TestCircuitConfigMsgPi {
                rescue_counter_config,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // the rescue counter mode
            let rescue_counter_mode =
                RescueCounterMode::<F, RP>::new(config.rescue_counter_config.clone());

            // compute rescue_counter_mode(witness, msg) inside the circuit
            let (assigned_msg, assigned_result) = layouter.assign_region(
                || "Proof of knowledge of encryption secret key",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // wrap field elements around Value
                    let key_values = self
                        .key
                        .into_iter()
                        .map(|v| Value::known(v))
                        .collect::<Vec<_>>();

                    // wrap msg elements around Value
                    let msg_values = self
                        .msg
                        .into_iter()
                        .map(|state| {
                            state
                                .into_iter()
                                .map(|v| Value::known(v))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();

                    // assign the witness (seccret key)
                    let assigned_key = rescue_counter_mode
                        .rescue_gate
                        .maingate
                        .assign_values_slice(ctx, &key_values)?
                        .try_into()
                        .unwrap();

                    // assign the witness (msg)
                    let mut assigned_msg: Vec<AssignedRescueState<F>> = Vec::new();
                    for msg_vec in msg_values {
                        assigned_msg.push(
                            rescue_counter_mode
                                .rescue_gate
                                .maingate
                                .assign_values_slice(ctx, &msg_vec)?
                                .try_into()
                                .unwrap(),
                        );
                    }

                    let msg_refs = assigned_msg
                        .iter()
                        .map(|msg| get_refs(msg))
                        .collect::<Vec<_>>();
                    // compute hash_output (the public input) in circuit using the rescue gate
                    let assigned_result = rescue_counter_mode.apply_key_stream(
                        ctx,
                        get_refs(&assigned_key),
                        msg_refs,
                        true,
                    )?;

                    Ok((assigned_msg, assigned_result))
                },
            )?;

            let mut constrain_instance =
                |input: Vec<AssignedRescueState<F>>, pi_offset: usize| -> Result<(), Error> {
                    for (i, slice) in input.iter().enumerate() {
                        for (j, val) in slice.iter().enumerate() {
                            layouter.constrain_instance(
                                val.cell(),
                                config
                                    .rescue_counter_config
                                    .rescue_perm_config
                                    .maingate_config
                                    .instance,
                                pi_offset + i * STATE_WIDTH + j,
                            )?;
                        }
                    }

                    Ok(())
                };

            // constraint the input messages to be equal to the public input:
            constrain_instance(assigned_msg, 0)?;

            // constraint the output to equal the public input:
            constrain_instance(assigned_result, STATE_WIDTH * MSG_LEN)?;

            Ok(())
        }
    }

    #[test]
    fn test_encrypt_msg_pi() {
        const K: u32 = 11;
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let key = RescueBlockCipher::<Scalar, RescueParametersBls>::keygen(&mut rng);

        let msg: [[Scalar; STATE_WIDTH]; MSG_LEN] = [
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng),
        ];
        let ctxt = RescueBlockCipher::<Scalar, RescueParametersBls>::encrypt(msg.to_vec(), key);

        let circuit = TestCircuitCorrectEncryptionMsgPi::<Scalar, RescueParametersBls> {
            rescue_params: PhantomData::default(),
            key,
            msg,
        };

        let pi = vec![[msg.concat(), ctxt.to_vec().concat()].concat()];

        let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");

        assert!(prover.verify().is_ok());

        let pi = vec![[
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
            random_scalar_array::<4, Scalar, &mut ChaCha8Rng>(&mut rng).to_vec(),
        ]
        .concat()];
        let prover = MockProver::run(K, &circuit, pi).expect("Failed to run mock prover");

        assert!(prover.verify().is_err());
    }
}
