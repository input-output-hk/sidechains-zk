# SNARK-based ATMS
Ad-hoc Threshold MultiSignatures (ATMS) allow key-pair owners to create a threshold signature without having to overgo a complex distributed key generation procedure (ad-hoc), or interactive signature procedure (multisignature).
The original paper proposes three ways to construct such signatures:
- **Trivial ATMS:** simply consists in aggregating at least a threshold number of individual signatures, and verifying them individually. This construction is really easy to instantiate, but does not provide efficient signature sizes or verification.
- **Pairing based ATMS:** this scheme presents an interesting tradeoff between feasibility and ease of implementation. It also presents the most efficient signature and verification, but only in the optimistic case (when all committee members participate in the signature). This is hard to achieve when the committee size grows. We already have an existing implementation of such an instantiation in Rust and Haskell. However, preliminary benchmarks showed that this still limits us wrt the committee size (in a situation where t/3 committee members don't participate). We explored the possibility of separating ATMS verification, but this considerably complicates the protocol.
- **SNARK-based ATMS:** this scheme presents the most efficient signature sizes and verifier independent of participation. The downside of such an option is the implementation complexity.

We are now set to explore the last setting, i.e. a SNARK-based ATMS, and we specify exactly how we plan on instantiating such a construction.

## SNARK-friendly primitives
Modern zero knowledge proofs allow a prover to convince a verifier about the correctness of any NP-statement.
However, the prover cost is proportional to the complexity of the statement, and therefore carefully choosing the statement to be proven, or the primitives used thereof can provide considerable improvements to the prover complexity.
The flexibility of the sidechains design allows us to choose the cryptographic primitives which provide a more efficient prover.
In this section we introduce which are such primitives, and further in this document we describe how we use them to instantiate SNARK-based ATMS.

One design decision over which we have no flexibility is that of the 'parent' curve, or the curve over which proving and verification of the SNARK happens. The reason for this inflexibility is that the ultimate goal is to verify such proofs in Cardano main-net. The curve that we have available in Plutus (or rather, will have available) is BLS12-381. Therefore, our decisions in this document are conditioned by the 'parent' curve. The rest of the primitives used are the following:

- **JubJub curve:** We use the JubJub curve, which is an elliptic curve that has as the base field, the scalar field of BLS12-381, i.e. it's an embedded curve. This allows for efficient EC operations within the proof.
- **Schnorr over JubJub:** Given that JubJub is an edwards curve with a cofactor of 8, the selected digital signature algorithm we choose is Schnorr.
- **Rescue:** As a hashing algorithm (used both for signing and Merkle trees), we use a SNARK friendly hash function, namely Rescue, which is instantiated over the base field of BLS12-381.
- **Plonk with KZG:** The proof system that we use is Plonk with KZG commitments schemes. This provides a universal SNARK (meaning that we can use some existing trusted setup) which is sufficiently succinct to be verified on main-net. In particular, we use Halo2 implementation.

## SNARK based ATMS
We present a simple design that allows us to instantiate ATMS using SNARKs.
It is out of the scope of this document to describe how the committee members are selected or registered.
Therefore, we assume that there exists $n$ committee members, and the required threshold is $t$.
For sake of simplicity, we abstract the details of the underlying cryptographic primitives.

Each committee member has a keypair, $(sk_i, pk_i)$.
The global public key is defined as the hash of all committee members' public key, $avk = H(pk_1, \ldots, pk_n)$.
When a threshold signature is required from $avk$, exactly $t$ committee members produce a Schnorr signature, $sig_i$.
This signature is sent to the aggregator.
We note that the aggregator has a facilitator role, and does not need to be trusted.
Once the aggregator has collected at $t$ signatures, it proceeds to create a SNARK about the following statement:

Given public input $msg$, $avk$, $t$:
- There exists $t$ valid Schnorr signatures for $msg$ wrt public keys, $pk_1, \ldots, pk_t$.
- The hash of all $t$ public keys, together with some other set of keys, results in the corresponding $avk$.
