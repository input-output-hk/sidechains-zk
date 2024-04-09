Encoding and I/O requirements.

This module includes the following:
- [Commonly used types and structs][crate::docs::encoding_io#commonly-used-types-and-structs]
- [Functions: I/O][crate::docs::encoding_io#functions-io]
- [Encoding][crate::docs::encoding_io#encoding]

# Commonly used types and structs
## Type Base
Represents an element of the base field $\mathbb{F}_q$ of the Jubjub elliptic curve construction.
```ignore
pub type Base = Fq;
```
## Type Scalar
Represents an element of the scalar field $\mathbb{F}_r$ of the Jubjub elliptic curve construction.
```ignore
pub type Scalar = Fr;
```
## Type AffinePoint
This represents a Jubjub point in the affine `(u, v)` coordinates.
Coordinates are elements of the [base field][crate::docs::encoding_io#type-base] $\mathbb{F}_q$.
```ignore
pub struct AffinePoint {
  u: Fq,
  v: Fq,
}
```
## Struct ExtendedPoint
This represents an extended point `(U, V, Z, T1, T2)` with `Z` nonzero, corresponding to the affine point `(U/Z, V/Z)`. We always have `T1 * T2 = UV/Z`.
Coordinates are elements of the [base field][crate::docs::encoding_io#type-base] $\mathbb{F}_q$.
```ignore
pub struct ExtendedPoint {
  u: Fq,
  v: Fq,
  z: Fq,
  t1: Fq,
  t2: Fq,
 }
 ```
## Type SchnorrSig
Schnorr signature including an [AffinePoint][crate::docs::encoding_io#type-affinepoint] and a [Scalar][crate::docs::encoding_io#type-scalar].

## Struct AssignedEccPoint
A curve point represented in affine `(x:` [Base][crate::docs::encoding_io#type-base], `y:` [Base][crate::docs::encoding_io#type-base]) coordinates, or the identity represented as `(0, 0)`.
Each coordinate is assigned to a cell.
```ignore
x: AssignedValue<Base>,
y: AssignedValue<Base>
```

## Struct ScalarVar 
Structure representing a (`Scalar`: [Base][crate::docs::encoding_io#type-base]) used in variable-base multiplication.
```ignore 
pub struct ScalarVar(pub(crate) AssignedValue<Base>);
```

## Type AssignedSchnorrSignature
Type representing an assigned Schnorr signature. Including:
* [AssignedEccPoint][crate::docs::encoding_io#struct-assignedeccpoint], 
* [ScalarVar][crate::docs::encoding_io#struct-scalarvar].

## Struct Value
A value that might exist within a circuit. This behaves like `Option<V>` but differs in two key ways:
- It does not expose the enum cases, or provide an `Option::unwrap` equivalent. This helps to ensure that unwitnessed values correctly propagate.
- It provides pass-through implementations of common traits such as `Add` and `Mul`, for improved usability.
```ignore
pub struct Value<V> {
  inner: Option<V>,
}
```

# Functions: I/O

## Primitive Schnorr
The input/output specs of the functions of [Primitive/Schnorr][crate::signatures::primitive::schnorr::Schnorr].
### Generator
The private function `generator` returns the generator of the form [ExtendedPoint][crate::docs::encoding_io#struct-extendedpoint]
```ignore 
fn generator() -> ExtendedPoint {
    ExtendedPoint::from(SubgroupPoint::generator())
}
```
### Key generation
The function [keygen][crate::signatures::primitive::schnorr::Schnorr::keygen()]
* Takes `(rng: &mut R)` as the input.
* Outputs ([Scalar][crate::docs::encoding_io#type-Scalar], [AffinePoint][crate::docs::encoding_io#type-affinepoint]).
* Note that, the scalar multiplication is handled by multiplying the scalar with an extended point. The result is converted to affine point.

### Signing 
The function [sign][crate::signatures::primitive::schnorr::Schnorr::sign()] takes the following as inputs: 
  * `key_pair`: ([Scalar][crate::docs::encoding_io#type-Scalar], [AffinePoint][crate::docs::encoding_io#type-affinepoint]), 
  * `msg`: [Base][crate::docs::encoding_io#type-base], 
  * `rng`: &mut R.

Outputs a [SchnorrSig][crate::docs::encoding_io#type-schnorrsig]

### Verification
The function [verify][crate::signatures::primitive::schnorr::Schnorr::verify()] takes the following as inputs:
  * `msg`: [Base][crate::docs::encoding_io#type-base],
  * `pk`: [AffinePoint][crate::docs::encoding_io#type-affinepoint]
  * `sig`: [SchnorrSig][crate::docs::encoding_io#type-schnorrsig],

Returns an error if the verification fails, else returns `Ok(())`

## Schnorr Verifier Gate
The input/output specs of the functions of [Schnorr Verifier Gate][crate::signatures::schnorr::SchnorrVerifierGate].

### Schnorr Verification
The function [verify][crate::signatures::schnorr::SchnorrVerifierGate::verify()] takes the following as inputs:
  * `&self`,
  * `ctx: &mut RegionCtx<'_, Base>`,
  * `signature`: &[AssignedSchnorrSignature][crate::docs::encoding_io#type-assignedschnorrsignature],
  * `pk`: &[AssignedEccPoint][crate::docs::encoding_io#type-assignedeccpoint],
  * `msg`: &AssignedValue<[Base][crate::docs::encoding_io#type-base]>,

Returns `Ok(())`, if the verification succeeds.

### Assign Signature
The function [assign_sig][crate::signatures::schnorr::SchnorrVerifierGate::assign_sig()] takes the following as inputs:
  * `&self`,
  * `ctx: &mut RegionCtx<'_, Base>`,
  * `signature`: &[Value][crate::docs::encoding_io#struct-value]<[SchnorrSig][crate::docs::encoding_io#type-schnorrsig]>

Returns `Result<`[AssignedSchnorrSignature][crate::docs::encoding_io#type-assignedschnorrsignature]`, Error>`


## ATMS Verifier
### Verify ATMS
The function [assign_sig][crate::signatures::atms::AtmsVerifierGate::verify()] takes the following as inputs:
  * `&self`,
  * `ctx: &mut RegionCtx<'_, Base>`,
  * `signatures`: &[Option<[AssignedSchnorrSignature][crate::docs::encoding_io#type-assignedschnorrsignature]>],
  * `pks`: &[AssignedEccPoint][crate::docs::encoding_io#type-assignedeccpoint],
  * `commited_pks`: &AssignedValue<[Base][crate::docs::encoding_io#type-base]>,
  * `msg`: &AssignedValue<[Base][crate::docs::encoding_io#type-base]>,
  * `threshold`: &AssignedValue<[Base][crate::docs::encoding_io#type-base]>,

Returns `Ok(())`, if the verification succeeds.

## Rescue Sponge 
Commonly used hash function `RescueSponge::<Base, RescueParametersBls>::hash()` takes the following as inputs:
  * `input`: `&[F]`, 
  * `pad`: `Option<PaddingFunction<F>> `

`F` represents a finite field. It maps $F^* -> F$. The padding function is an optional parameter. 
It outputs a single field element as the digest.

# Encoding
## Base field of Jubjub
The base field of Jubjub curve is $\mathbb{F}_q$. 
It is a finite field defined over $255$-bit prime, $q$.
The hexadecimal representation of $q$ is given below:
```ignore 
0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```
* An element of $\mathbb{F}_q$ is represented by four $64$-bit (`[u64; 4]`) unsigned integers in little-endian order. 
* Values are always in the form $\mathbb{F}_q(a) = aR \mod q$, with $R = 2^{256}$.
```ignore 
0xffff_ffff_0000_0001,
0x53bd_a402_fffe_5bfe,
0x3339_d808_09a1_d805,
0x73ed_a753_299d_7d48, 
```

## Scalar field of Jubjub
The scalar field of Jubjub curve is $\mathbb{F}_r$.
It is a finite field defined over 252-bit prime, $r$.
The hexadecimal representation of $r$ is given below:
```ignore 
0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
```
* An element of $\mathbb{F}_r$ is represented by four $64$-bit (`[u64; 4]`) unsigned integers in little-endian order.
* Values are always in the form $\mathbb{F}_r(a) = aR \mod r$, with $R = 2^{256}$.
```ignore 
0xd097_0e5e_d6f7_2cb7,
0xa668_2093_ccc8_1082,
0x0667_3b01_0134_3b00,
0x0e7d_b4ea_6533_afa9, 
```




