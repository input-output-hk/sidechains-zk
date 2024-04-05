# ATMS - _Ad-hoc Threshold Multi-signatures_

* Properties from multi-signatures and threshold signatures.
* Ad-hoc in the sense that signers need to be selected on the fly from an existing key set.
* Parametrized by a threshold $t$.
* Properties:
  * Aggregate the public keys of a subset of the parties into a single aggregate public key $avk$,
  * Checking the given $avk$ is created using the right sequence of public keys,
  * Aggregate $t' \geq t$ individual signatures into a single aggregate signature,
  * The aggregate signature is generated with at least $t$ individual signatures and can be verified with $avk$.

## ATMS with Schnorr setup
* Each individual signer proceeds the [$keygen$](../primitive/schnorr/function.Schnorr.keygen.html) operation.
* Aggregator collects the public keys of the signers and generates the aggregate public key $avk$.
* Individual parties generate their single signature with [$sign$](crate::signatures::primitive::schnorr) and send the signature to aggregator.
