 # SNARK-based ATMS
This is the circuit implementation for [Ad-hoc Threshold MultiSignatures (ATMS)](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8835275).
The goal of this library is to provide a proof-of-concept implementation of a circuit to provide a proof that there exists `t` valid signatures of some subset of a given set of public keys. 
This is the first effort of implementing a SNARK-based Ad-hoc Threshold Multi Signature scheme.

* The Zero Knowledge Proving system is implemented with PLONK with KZG commitments.
* BLS12-381 curve is used. Therefore, in-circuit elliptic curve operations are implemented with JubJub, which is an elliptic curve defined over the Scalar field of BLS12-381, aka its 'embedded' curve. This enables what is sometimes referred to as SNARK-friendly signature schemes. In particular, Schnorr over the JubJub curve. 
* As a SNARK-friendly hash algorithm we use Rescue, both for the signature generation/verification as for the Merkle Tree commitments.

## Compiling the library and header file
First, one needs to compile the library running:
```shell
cargo build --release
```

Then, we need to build the header files using `cbindgen`. For this, first install
cbindgen:
```shell
cargo install cbindgen
```

and then build the header file by running the following command from the parent directory (nightly is required):
```shell
rustup run nightly cbindgen ./ --config cbindgen.toml --crate atms-halo2 --output target/include/atms_halo2.h
```

## Documentation
The library provides a documentation for ATMS functionality. $\rightarrow$ [Documentation][crate::docs].

You can also jump to following sections from following links: 
- Elliptic curve cryptography preliminaries: [ECC][crate::docs::ecc]
- Schnorr signature: [Schnorr][crate::docs::schnorr]
- Ad-hoc threshold multi-signature: [ATMS][crate::docs::atms]
- Rescue sponge hash function: [Rescue][crate::docs::rescue]
- I/O specs and encoding: [I/O][crate::docs::encoding_io]
- Flow of the functionality: [flow][crate::docs::flow]
- Relation between the cryptographic primitives: [primitives][crate::docs::primitives]