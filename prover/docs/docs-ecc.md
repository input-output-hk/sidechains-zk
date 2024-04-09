# ECC Preliminaries
## Basic ECC Toolbox
- $p$: a large prime number.
- $\mathbb{F}_p$: Finite field over prime $p$.
- $E(\mathbb{F}_p): y^2=x^3+ax+b$: is an elliptic curve of the short Weierstrass form defined over $\mathbb{F}_p$.
- $P = (x, y)$ is a point on $E(\mathbb{F}_p)$.
- $-P = (x, -y)$ is the negative of the point $P$.
- $P + (-P) = \mathcal{O}$ is the identity of the curve.
- $P + \mathcal{O} = P$.
- Elliptic curve scalar multiplication:
    - Let $n \leftarrow \mathbb{Z}_p$,
    - Let $P$ be a point on $E(\mathbb{F}_p)$,
    - $Q = n \cdot P$ is a point on $E(\mathbb{F}_p)$.
- Elliptic curve discrete logarithm problem:
    - Let $P$ and $Q$ be points on $E(\mathbb{F}_p)$ and $Q = n \cdot P$.
    - Knowing $P$ and $Q$, finding $n = \log_P^Q$ is a hard problem.
- Base point: Let $G$ be a base point, then $G$ generates all points at $E(\mathbb{F}_p)$.
- Order of a point: If $l\cdot P = \mathcal{O}$, then $l$ is the order of $P$.

## Twisted Edward's Curve
Let $\mathbb{F}_p$ be a field where $p$ is a large prime. The twisted Edward's curve is defined as follows:

$$ E_{E, a, d}: ax^2 + y^2 = 1 + dx^2y^2$$

where $a, d \in \mathbb{F}_p$ and non-zero.

* A point on $E_{E, a, d}$ is represented as $P = (x, y)$.
* Negative of a point: $-P = (-x, y)$.
* Neutral element(point at infinity): $\mathcal{O} = (0,1)$.
* Let $P = (x_1, y_1)$ and $Q = (x_2, y_2)$ be points on $E_{E, a, d}$. $P+Q = (x_3, y_3)$ is written as:

$$(x_3, y_3) = \Bigg(\frac{x_1y_2 + y_1x_2}{1 + dx_1x_2y_1y_2}, \frac{y_1y_2 - ax_1x_2}{1 - dx_1x_2y_1y_2}\Bigg).$$


### Edward's Curve Digital Signature Algorithm (EdDSA)
Let $B$ be the base point of $E_{E, a, d}$ with order $l$ and $H$ be a hash function with $2b-$bit output size where $2^{b-1} > p$.
* $keygen$
    * **Input**: Security parameter $\lambda$.
    * **Output**: Keypair $(x, P)$.
    * **Algorithm**:
        * Choose a random scalar as the private key: $x \leftarrow \mathbb{Z}_p$,
        * Compute the public key: $P \leftarrow x \cdot B$,
        * Return $(x, P)$.
* $sign$
    * **Input**: Keypair $(x, P)$, message $m$.
    * **Output**: Signature $\sigma = (R, s)$.
    * **Algorithm**:
        * Get the hash of private key and the message: $r = H(H_{b, \ldots, 2b-1}(x) || m)$.
        * Compute the point $R = r \cdot B$.
        * Calculate $s \equiv r + H(R || P|| m) x \mod{l}$.
        * Return $(R, s)$.
* $verify$
    * **Input**: Message $m$, public key $P$, signature $\sigma = (R, s)$.
    * **Output**: $true/false$
    * **Algorithm**:
        * If $s \cdot B = R + H(R || P|| m) \cdot P$, return $true$.
        * Else, return $false$.


---


## BLS12-381

### Curve setting
* `z = -0xd201000000010000` (hexadecimal): low hamming weight, few bits set to $1$.
    * Field modulus: $q = \frac{1}{3}(z-1)^2(z^4 - z^2 + 1) + z$, $381$-bit
  ```ignore
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab	
  ```
    * Subgroup size: $r = (z^4 - z^2 + 1)$, $255$-bit.
  ```ignore
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  ```
* **Curve 1:** $E(\mathbb{F}_q): y^2 = x^3 + 4$.
* **Curve 2:** $E'(\mathbb{F}_{q^2}): y^2 = x^3 + 4 (1 + i)$.

### Pairing
A pairing is a bilinear map, taking as input two points, each from two distinct groups of the same prime order, $r$. This map outputs a point from a group $G_T$. The pairing is defined as follows:

$$e: G_1 \times G_2 \rightarrow G_T$$

* $P \in G_1 \sub E(\mathbb{F}_q)$
* $Q \in G_2 \sub E'(\mathbb{F}_{q^2})$
* $G_T \sub \mathbb{F}_{q^{12}}$

Pairing is denoted as $e(P, R)$. Pairing-based cryptography uses the following properties:
* $e(P, Q+R) = e(P, Q) \cdot e(P, R)$,
* $e(P+S, R) = e(P, R) \cdot e(S, R)$.

Thus, the following identity holds:

$$e(\[a\]P, \[b\]Q) = e(P, \[b\]Q)^a = e(P, Q)^{ab} = e(P, \[a\]Q)b = e(\[b\]P, \[a\]Q).$$


## jubjub

Jubjub is an elliptic curve of the twisted Edward's form. It is defined over finite field $\mathbb{F}_q$ where
```ignore 
q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```
with a subgroup of order $r$ and cofactor $8$.
```ignore 
r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
```
Let $d = -(10240/10241)$, the Jubjub curve is defined as follows:

$$E_{d}: -u^2 + v^2 = 1 + du^2v^2.$$

* $\mathbb{F}_q$ is chosen to be the scalar field of BLS12-381 curve construction.
