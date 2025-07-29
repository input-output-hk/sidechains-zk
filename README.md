# Sidechains ZK

Zero knowledge cryptography code and JNI bindings for sidechains, implementing
SNARK-based [Ad-hoc Threshold MultiSignatures (ATMS)](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8835275).

## Overview

This repository contains a proof-of-concept implementation of a Halo2 circuit that provides a proof that there
exists `t` valid signatures of some subset of a given set of public keys. This is the first effort of implementing a
SNARK-based Ad-hoc Threshold Multi Signature scheme.

The implementation leverages SNARK-friendly cryptographic primitives:

- **Zero Knowledge Proving System**: Halo2 with KZG commitments
- **Parent Curve**: BLS12-381 (compatible with Cardano Plutus)
- **Embedded Curve**: JubJub curve (defined over BLS12-381 scalar field)
- **Digital Signature**: Schnorr signatures over JubJub curve
- **Hash Function**: Rescue hash for SNARK-friendly operations

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This is a proof-of-concept implementation that has not undergone security auditing.** This code is provided "as is"
> for research and educational purposes only. It has not been subjected to a formal security review or audit and may
> contain vulnerabilities.  **Do not use this code in production systems or any environment where security is critical
> without conducting your own thorough security assessment.**  By using this code, you acknowledge and accept all
> associated risks, and our company disclaims any liability for damages or losses.

## Repository Structure

### 📁 `prover/` - Core SNARK Implementation

The ATMS circuit implementation using Halo2 with KZG commitments.

**Key Features:**

- Circuit implementation for Ad-hoc Threshold Multi-Signatures
- Elliptic curve operations over JubJub curve
- Schnorr signature verification within SNARK circuits
- Rescue hash function integration
- C API bindings for interoperability

**Structure:**

- `src/signatures/` - Schnorr and ATMS signature implementations
- `src/ecc/` - Elliptic curve operations and Halo2 chips
- `src/rescue/` - Rescue hash function modules
- `src/c_api.rs` - C API bindings
- `docs/` - Comprehensive cryptographic documentation

### 📁 `eddsa/` - EdDSA Signature Implementation

Standalone EdDSA signature implementation over the JubJub curve.

**Key Features:**

- EdDSA signature generation and verification
- JubJub curve operations
- Poseidon hash integration
- Cryptographic primitives for signature schemes

**API:**

- `sign(msg: &Vec<u8>, prv_key: Scalar) -> EdDsaSignature`
- `verify(sig: EdDsaSignature, pub_key: SubgroupPoint, msg: &Vec<u8>) -> Result<(), ()>`

### 📁 `jubjub/` - JNI Bindings (Scala/Java)

Scala/Java bindings for native cryptographic operations, enabling integration with JVM-based applications.

**Structure:**

- `jubjub-native/` - Rust native library with JNI bindings
- `jubjub-bindings/` - Scala wrapper around native functions

**API:**

- `derivePublicKey(privateKey: Bytes): Bytes`
- `sign(data: Bytes, key: Bytes): Bytes`
- `verify(data: Bytes, signature: Bytes, publicKey: Bytes): Boolean`
- `createATMSProof(data: Bytes, signatures: Array[Bytes], keys: Array[Bytes]): Bytes`

## Building

### Prerequisites

- Rust (with nightly toolchain for cbindgen)
- Scala 2.13.10
- SBT 1.8.2+
- Java 17+

### Building Rust Components

```bash
# Build the main prover library
cd prover
cargo build --release

# Build EdDSA component
cd eddsa
cargo build --release

# Build native JNI library
cd jubjub/jubjub-native/src/native
cargo build --release
```

### Generate C Headers

```bash
# Install cbindgen
cargo install cbindgen

# Generate header file from prover directory
cd prover
rustup run nightly cbindgen ./ --config cbindgen.toml --crate atms-halo2 --output target/include/atms_halo2.h
```

### Building Scala/Java Components

```bash
cd jubjub
sbt compile
```

## Testing

### Rust Tests

```bash
# Run tests for prover
cd prover && cargo test

# Run tests for eddsa
cd eddsa && cargo test

# Run benchmarks
cd prover && cargo bench
```

### Scala Tests

```bash
cd jubjub
sbt test
sbt IntegrationTest/test
```

## Cryptographic Background

### Ad-hoc Threshold Multi-Signatures (ATMS)

ATMS is a multisignature scheme that allows key-pair owners to create a threshold signature without complex distributed
key generation (ad-hoc) or interactive signature procedures. The original
paper "[Proof-of-Stake Sidechains](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8835275)" by Gazi, Kiayias,
and Zindros proposes three construction methods:

1. **Trivial ATMS**: Simple aggregation with individual verification
2. **Pairing-based ATMS**: Efficient but requires full participation
3. **SNARK-based ATMS**: Most efficient signatures, verifier independent of participation

This implementation focuses on **SNARK-based ATMS** for optimal efficiency and scalability.

## Documentation

Comprehensive documentation is available in the `prover/docs/` directory:

- [Introduction](prover/docs/intro.md) - Overview and roadmap
- [ECC Preliminaries](prover/docs/docs-ecc.md) - Elliptic curve cryptography
- [Schnorr Signatures](prover/docs/signatures/schnorr/) - Signature scheme details
- [ATMS Implementation](prover/docs/signatures/atms/) - Threshold signature construction
- [Rescue Hash](prover/docs/docs-rescue.md) - Hash function specification
- [Flow](prover/docs/flow.md) - Operational workflow
- [Primitives](prover/docs/atms-primitives.md) - Cryptographic primitive relationships

## License

Copyright 2025 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License