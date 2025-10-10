**Input:**
- A list of signatures: `&[AssignedSchnorrSignature]`
    - Collect [Schnorr signatures][AssignedSchnorrSignature].
    - All positions must contain a signature (either valid or dummy).
    - Dummy signatures should be assigned for parties that did not sign to maintain circuit structure consistency.
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
    - There are at least a threshold amount of valid signatures
    - Given list of public keys pertain the committed public key.
- Note that the circuit verifies all signatures (including dummy ones) and counts only the valid ones.
- The circuit ensures that at some point during iteration, the count of valid signatures reaches the threshold.

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
2. Count valid signatures and check if threshold is reached.
    * Initialize a counter and set it to `0`,
    * Initialize a flag `is_enough_sigs` and set it to `0` (false),
    * Iterate through ALL signatures and public keys (including dummy signatures),
    * For each signature:
        - Verify the signature with respect to the related public key and the given message,
        - If verification succeeds, the signature contributes `1` to the counter; if it fails (dummy signature), it contributes `0`,
        - Add the verification result to the counter,
        - Check if `counter == threshold`,
        - Update `is_enough_sigs` to be `is_enough_sigs OR (counter == threshold)`,
    * After the loop, assert that `is_enough_sigs == 1`.
    ```ignore
    let mut counter = self
        .schnorr_gate
        .ecc_gate
        .main_gate
        .assign_constant(ctx, Base::ZERO)?;

    let mut is_enough_sigs = self
        .schnorr_gate
        .ecc_gate
        .main_gate
        .assign_constant(ctx, Base::ZERO)?;

    for (sig, pk) in signatures.iter().zip(pks.iter()) {
        // Verify signature - returns 1 if valid, 0 if invalid (dummy)
        let is_verified = self.schnorr_gate.verify(ctx, &sig, pk, msg)?;

        // Add verification result to counter
        counter = self.schnorr_gate.ecc_gate.main_gate.add(ctx, &counter, &is_verified)?;

        // Check if we've reached the threshold
        let is_threshold_reached = self.schnorr_gate.ecc_gate.main_gate.is_equal(ctx, &counter, threshold)?;

        // Update flag: once true, stays true (OR preserves the state)
        is_enough_sigs = self.schnorr_gate.ecc_gate.main_gate.or(ctx, &is_threshold_reached, &is_enough_sigs)?;
    }

    // Assert that we reached the threshold at some point
    self.schnorr_gate
        .ecc_gate
        .main_gate
        .assert_equal_to_constant(ctx, &is_enough_sigs, Base::ONE)?;
    ```

    **Possible Optimizations:**

    1. **Verify only threshold-many signatures (instead of all N)**
       - Use lookup tables to match signatures to public keys, reducing verifications from N to threshold.
       - Postponed because it increases verification cost (critical for on-chain verification).

    2. **Single comparison of the counter at the end: `assert_greater(counter, threshold)`**
       - Replace N equality checks and N OR operations with one comparison.
       - `assert_greater` is not implemented yet, requires range proofs and bit decomposition.
