**Input:**
- A list of signatures: `&[Option<AssignedSchnorrSignature>]`
    - Collect [Schnorr signatures][AssignedSchnorrSignature].
    - Use `Option`, because there might not be a signature for every index, but we want them to be 'indexed' in agreement with the public keys.
- A list of public keys: `&[AssignedEccPoint]`
    - Public keys of all the eligible parties even if they do not participate.
    - Public keys are [Assigned ECC points][AssignedEccPoint].
- A commitment of all public keys: `&AssignedValue<Base>`
    - This is the aggregated public key.
    - The committed public key is an element of the base field $\mathbb{F}_q$ of the Jubjub elliptic curve construction, see [Base].
- Message to be signed of the form [Base].
- Threshold value of the form [Base].

**Goal of the Circuit:**
- Verify that for the given message and public keys
    - There are exactly a threshold amount of valid signatures
    - Given list of public keys pertain the committed public key.
- Note that the proof must include only threshold-many valid signatures even if the prover has more valid signatures.

**Algorithm:**
1. Check whether given list of public keys actually produce the committed public key:
    * Collect the public keys in a vector,
    * Hash the content of the vector,
    * Check whether the hash result and the committed pks are equal.
    ```ignore
    for pk in pks {
            flattened_pks.push(pk.x.clone());
        }

    let hashed_pks = self
        .schnorr_gate
        .rescue_hash_gate
        .hash(ctx, &flattened_pks)?;

    self.schnorr_gate
        .ecc_gate
        .main_gate
        .assert_equal(ctx, &hashed_pks, commited_pks)?;
    ```
2. Count the valid signatures.
    * Initialize a counter and set it to `0`,
    * Iterate through the signatures and public keys,
    * Verify each signature with respect to the related public key and the given message,
    * Increase the counter by `1` for each valid signature.
    ```ignore
    let mut counter = self
        .schnorr_gate
        .ecc_gate
        .main_gate
        .assign_constant(ctx, Base::ZERO)?;

    for (sig, pk) in signatures.iter().zip(pks.iter()) {
        if let Some(signature) = sig {
            self.schnorr_gate.verify(ctx, signature, pk, msg)?;
            counter = self.schnorr_gate.ecc_gate.main_gate.add_constant(
                ctx,
                &counter,
                Base::one(),
            )?;
        }
    }
    ```
3. Check if the resulting count and the given threshold are equal.
```ignore
self.schnorr_gate
    .ecc_gate
    .main_gate
    .assert_equal(ctx, &counter, threshold)?;
```
