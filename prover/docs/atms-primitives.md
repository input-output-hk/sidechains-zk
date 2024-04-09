Relation between the elliptic curves and signature schemes.

In order to comply with the Cardano main-net, Curve BLS12-381 is used as the parent curve in this library. 
Therefore, the rest of the primitives are selected considering this case.
In-circuit elliptic curve operations are implemented with Jubjub curve.
Jubjub is the embedded curve of BLS12-381.
We used a SNARK-friendly signature scheme, Schnorr over Jubjub.

In this section, we explain the relation between BLS12-381, Jubjub, Schnorr, and EdDSA.

See the documentation of the related topics:
- [BLS12-381][crate::docs::ecc#curve-setting]
- [JubJub][crate::docs::ecc#jubjub]
- [EdDSA][crate::docs::ecc#edwards-curve-digital-signature-algorithm-eddsa]
- [Schnorr][crate::docs::schnorr]

## Relation between BLS12-381 and Jubjub
BLS12-381 is preferred for pairing operations.
We define two curves:
- Curve 1: Defined over the field $\mathbb{F}_p$. The curve equation is given below:
$$E(\mathbb{F}_p): y^2 = x^3 + 4$$

- Curve 2: Defined over the field $\mathbb{F}_{p^2}$. The curve equation is given below:

$$E'(\mathbb{F}_{p^2}): y^2 = x^3 + 4 (1 + i)$$

The prime $p$ is represented in hexadecimal as following:
```ignore
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab	
```

Pairings are usually denoted as $e(P, Q)$ where
* $e: G_1 \times G_2 \rightarrow G_T$
* $P \in G_1 \sub E(\mathbb{F}_p)$
* $Q \in G_2 \sub E'(\mathbb{F}_{p^2})$
* $G_T \sub \mathbb{F}_{p^{12}}$

As described in [here][crate::docs::ecc#pairing], the following identity holds:
$$e(\[a\]P, \[b\]Q) = e(P, \[b\]Q)^a = e(P, Q)^{ab} = e(P, \[a\]Q)b = e(\[b\]P, \[a\]Q).$$

Note that, in the above identity, we showed some scalar multiplications, i.e., $\[a\]P$.
The value $a$ is an element of $\mathbb{F}_s$, 
where $s$ is the size of the subgroup of the curve.
$\mathbb{F}_s$ is a finite field defined over the prime $s$, which is represented in hexadecimal as follows:
```ignore
0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```
(_For sake of simplicity, we won't explain the details of the mentioned subgroup._)

> As a conclusion, we say that the base field of BLS12-381 is $\mathbb{F}_p$ and the scalar field of the curve is $\mathbb{F}_s$.

Our second primitive is the Jubjub curve. 
Jubjub is an elliptic curve of the [twisted Edward's form][crate::docs::ecc#twisted-edwards-curve].

Let $d = -(10240/10241)$, the Jubjub curve is defined as follows:
$$E_{d}: -u^2 + v^2 = 1 + du^2v^2.$$
We use Jubjub for in-circuit elliptic curve operations since it provides efficient EC operations within the proof.
We define the Jubjub curve over the field $\mathbb{F}_q$ where $q$ is represented in hexadecimal as follows:
```ignore 
q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```
In addition, it has a subgroup of order $r$ and cofactor $8$.
```ignore 
r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
```
As mentioned before, we set the Jubjub curve as the embedded curve of BLS12-381.
Meaning that, Jubjub curve is defined over a prime which is also the prime that defines the scalar field of BLS12-381.

> As a conclusion, we say that the base field of Jubjub is $\mathbb{F}_q$ and the scalar field of the curve is $\mathbb{F}_r$.

---

**Note that, the scalar field of BLS12-381 $\mathbb{F}_s$ equals to the base field of Jubjub $\mathbb{F}_q$.**
**It means that  if I have a result on the base field of the JubJub curve, it is also an element of the scalar field of the BLS curve.**

---

## Relation between Schnorr signature and EdDSA
EdDSA is a variant of the Schnorr signature scheme designed specifically for Edward's curve. 
See the [$sign$][crate::docs::schnorr#sign] algorithm of Schnorr and the [sign][crate::docs::ecc#sign] algorithm of EdDSA.
Note that, the only difference between two algorithms is the first step.
* In Schnorr signature, we have:
  * Choose a random scalar: $r \leftarrow Z_p$,
  * Compute the nonce: $R = r \cdot G$.
* In EdDSA, we have:
  * Get the hash of private key and the message: $r = H(H_{b, \ldots, 2b-1}(x) || m)$.
  * Compute the point $R = r \cdot B$.

This means that the randomness used in the first step of the Schnorr signer is generated using a hash function by the EdDSA signer, rather than sampling the value at random. 

* We use the probabilistic Schnorr signature scheme in our setting. We can make this deterministic using EdDSA instead.

## Relation between BLS12-381, Jubjub, and Schnorr
To implement the Schnorr signature, we use elliptic curve scalar multiplications.
_(See [$Schnorr signature$][crate::docs::schnorr]) and [scalar multiplication][crate::docs::ecc#basic-ecc-toolbox].)_
* In this library, the scalar multiplication is implemented as follows:
  * Let $a$ be scalar and an element of the scalar field of Jubjub curve.
    * $a \in \mathbb{F}_r$
  * Let $P$ be an extended point on Jubjub curve. Meaning that, the coordinates of the point are elements of the base field of the Jubjub curve, $\mathbb{F}_q$.
  * $Q = a \cdot P$ is the result of the scalar multiplication and is an extended point on Jubjub curve.
  * Convert $Q$ to an affine point. The coordinates of an affine point are elements of the base field of the Jubjub curve, $\mathbb{F}_q$.

> As a conclusion, we can say that the coordinates of both affine and extended points in the above scheme are also elements of the scalar field of BLS12-381 curve.