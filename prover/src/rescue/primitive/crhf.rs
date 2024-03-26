use super::rescue_parameters::*;
use super::PseudoRandomPermutation;
use crate::rescue::RescuePRP;
use ff::PrimeField;

// type synonym for a padding function that maps D^* -> D^*
type PaddingFunction<D> = fn(&[D]) -> Vec<D>;

// input for the sponge which in the rescue case is [F; RATE]
type IO<D> = [D; 3];

/// Struct for implementing a rescue based sponge
#[derive(Debug, Default)]
pub struct RescueSponge<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// holds the current state of the sponge
    state: RescueState<F>,
    /// the prp that is used to update the state after absorbing or squeezing
    prp: RescuePRP<F, RP>,
}

// constants defining the sponge construction
impl<F, RP> RescueSponge<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// The rate of the sponge, i.e. the number of field elements that are absorbed/squeezed in each
    /// opertion.
    pub const RATE: usize = 3;

    /// The capacity of the sponge. It should always be the case that RATE + CAPACITY = STATE_WIDTH
    pub const CAPACITY: usize = 1;
}

/// Sponge implementation based on the rescue permutation
impl<F, RP> RescueSponge<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    // Initializes a sponge by setting the internal state to zero
    fn new() -> Self {
        Self {
            state: [F::ZERO; STATE_WIDTH],
            prp: RescuePRP::new(None),
        }
    }

    // absorbing an element in F^3
    fn absorb(&mut self, input: IO<F>) {
        // First we add the elements to the first RATE positions of state
        self.state.iter_mut().zip(input).for_each(|(s, i)| *s += i);
        // apply the rescue prp to derive the new state
        self.state = self.prp.permute(&self.state);
    }

    // outputs an element in F^3 from the sponge
    fn squeeze(&mut self) -> IO<F> {
        let mut output = [F::ZERO; 3];
        // We output the first RATE elements of the state
        output[..].clone_from_slice(&self.state[0..3]);
        // We apply the rescue prp to prepare for outputing more elements
        self.state = self.prp.permute(&self.state);
        output
    }
}

// Implementation of simple padding for rescue inputs
impl<F, RP> RescueSponge<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Simple padding function that first extends the input with 1 and then adds 0s until the
    /// length of the vector is divisible by rate.
    pub fn simple_pad(input: &[F]) -> Vec<F> {
        let mut padded_input = Vec::from(input);
        padded_input.push(F::ONE);
        while padded_input.len() % (RescueSponge::<F, RP>::RATE) != 0 {
            padded_input.push(F::ZERO);
        }
        padded_input
    }
}

// Implementation of rescue sponge based CRHF
impl<F, RP> RescueSponge<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    /// Hash function based on a rescue sponge. It maps F^* -> F. Takes as input a slice &\[F\] encoding
    /// the input and an optional padding function and outputs a single field element as the
    /// digest.
    pub fn hash(input: &[F], pad: Option<PaddingFunction<F>>) -> F {
        let rate = RescueSponge::<F, RP>::RATE;

        // initialize the sponge
        let mut sponge = RescueSponge::<F, RP>::new();

        // iteratively absorb F^3 elements in the sponge using the (possibly padded) input
        if let Some(f) = pad {
            f(input)
                .chunks(rate)
                .for_each(|curr| sponge.absorb(curr.try_into().unwrap()));
        } else {
            input
                .chunks(rate)
                .for_each(|curr| sponge.absorb(curr.try_into().unwrap()));
        }
        // squeeze the sponge to get an F^3 output and keep the first element as the hash
        *sponge.squeeze().first().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::{primitive::RescueParametersBls, test_vectors};
    use halo2curves::bls12_381::Scalar;

    #[test]
    fn test_rescue_crhf_pallas() {
        for (input, correct_output) in test_vectors::BLS_SPONGE_TEST_VECTORS {
            let output: Scalar = RescueSponge::<Scalar, RescueParametersBls>::hash(&input, None);
            assert_eq!(output, correct_output[0]);
        }
    }
}
