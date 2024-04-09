Ad-hoc Threshold MultiSignatures

# ATMS: _Ad-hoc Threshold Multi-signatures_
* Properties from multi-signatures and threshold signatures.
* Ad-hoc in the sense that signers need to be selected on the fly from an existing key set.
* Parametrized by a threshold $t$.
* Properties:
  * Aggregate the public keys of a subset of the parties into a single aggregate public key $avk$,
  * Checking the given $avk$ is created using the right sequence of public keys,
  * Aggregate $t' \geq t$ individual signatures into a single aggregate signature,
  * The aggregate signature is generated with at least $t$ individual signatures and can be verified with $avk$.

## SNARK-based ATMS with Schnorr setup
Here we present a simple design that allows us to instantiate ATMS with Schnorr using SNARKs.
* Assume that there exists $n$ committee members, and the required threshold is $t$.
* Each individual signer proceeds the [$keygen$][crate::signatures::primitive::schnorr#keygen] operation.
  * The function generates $(sk_i, pk_i)$ as the keypair for the $signer_i$.
* Signers share their public keys with the registration authority.
  * The role of the registration authority is simply to commit to all public keys of the committee in a Merkle Tree (MT).
  * The Registration Authority can be a Plutus script, a trusted party, or be distributed amongst the committee members.
  * The reason why it needs to be 'trusted' is because it can exclude certain participants, or include several keys it owns.
* Once all registration requests have been submitted with their corresponding public keys, $pks = [pk_1, ..., pk_n]$, the aggregated public key is created $avk = H(pk_1, \ldots, pk_n)$.
* Individual parties generate their single signature with [$sign$][crate::signatures::primitive::schnorr#sign] and send the signature to aggregator (does not need to be trusted).
* Individual signatures should be verifiable with [$verify$][crate::signatures::primitive::schnorr#verify].
* Aggregator receives the single signatures. It collects at least threshold-many valid signatures as the aggregate signature.
* Once the aggregator receives at least $t$ valid signatures $sig_1, ..., sig_t$ it proceeds to generate the SNARK. In particular, it proves that:
  * There exists $t'$ valid and distinct signatures, $sig_1, ..., sig_t$ for public keys $pk_1, ..., pk_t$ and message $msg$.
  * The hash of all $t$ public keys, together with some other set of keys, results in the corresponding $avk$.
