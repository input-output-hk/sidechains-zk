Library documentation.

# Ad-hoc Threshold MultiSignatures - ATMS
ATMS is a multisignature scheme that allows key-pair owners to create a threshold signature without having a complex distributed key generation (ad-hoc), or interactive signature procedure (multisignature).
The original paper [Proof-of-Stake Sidechains](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8835275) by Gazi, Kiayias, and Zindros proposes the following ways to construct ATMS:
1. **Trivial ATMS:**
   * Aggregates at least a threshold number of individual signatures.
   * Individual signatures are verified individually.
   * Easy construction.
   * Not efficient in terms of signature sizes and verification.

2. **Pairing based ATMS:**
   * Tradeoff between feasibility and ease of implementation.
   * Provides the most efficient signature and verification but only in the optimistic case where all committee members participate in the signature.
   * When committee size grows, it is hard to achieve the case where all members participate.

3. **SNARK-based ATMS:**
   * Most efficient signature sizes and verifier independent of participation.
   * The downside of such an option is the implementation complexity.

We will focus on a **SNARK-based ATMS**, and we specify exactly how we plan on instantiating such a construction.

## SNARK-friendly primitives
* Modern zero knowledge proofs allow a prover to convince a verifier about the correctness of any _NP-statement_.
  * Prover cost is proportional to the complexity of the statement,
  * To improve the prover complexity choose carefully:
    * The statement to be proven, and/or
    * The primitives to be used.
* The flexibility of the sidechains design allows us to choose the cryptographic primitives which provide a more efficient prover.
* The ultimate goal is to verify such proofs in Cardano main-net. Therefore, the design decision is made considering this.

1. **Parent curve:**
   * The curve that we have available in Plutus (or rather, will have available) is **BLS12-381**.
   * Therefore, BLS12-381 is used as the parent curve and the rest of the primitives are conditioned by the parent curve.
2. **Embedded curve:**
   * We use the **JubJub** curve, which is an elliptic curve that has as the base field, the scalar field of BLS12-381, i.e. it's an embedded curve.
   * This allows for efficient EC operations within the proof.
3. **Digital signature scheme:**
   * JubJub is an edwards curve with a cofactor of 8,
   * So, the selected digital signature algorithm we choose is **Schnorr**.
4. **Hash algorithm:**
   * For both signing and Merkle tree commitments we need a SNARK friendly hash function.
   * We used **Rescue** hash function which is instantiated over the base field of BLS12-381.
5. **Proof system:**
   * **Plonk with KZG commitments** scheme provides a universal SNARK (meaning that we can use some existing trusted setup) which is sufficiently succinct to be verified on main-net.
   * In particular, we use **Halo2** implementation.

## Roadmap
The structure of the documentation is designed as following:
* **ECC preliminaries:**
This section includes the basic primitives of elliptic curve cryptography required by the ATMS implementation.
  - We provide an introductory level [ECC toolbox][crate::docs::ecc#basic-ecc-toolbox].
  - Followed by the [EdDSA][crate::docs::ecc#edwards-curve-digital-signature-algorithm-eddsa].
  - [BLS12-381][crate::docs::ecc#curve-setting] and [pairings][crate::docs::ecc#pairing] are explained briefly.
  - Lastly, we give the specs of [JubJub][crate::docs::ecc#jubjub] curve.
* **Schnorr signature:** 
  * Key generation, signing, and verification algorithms of Schnorr signature is given in [here][crate::docs::schnorr].
* **ATMS:** 
  * We give a brief introduction to [ATMS][crate::docs::atms#atms-ad-hoc-threshold-multi-signatures] and explained the [SNARK-based ATMS with Schnorr setup][crate::docs::atms#snark-based-atms-with-schnorr-setup].
* **Rescue sponge:**
* **Encoding and I/O:**
* **Flow:** 