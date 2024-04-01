# Schnorr Signature
## Preliminaries
- $p$: a large prime number.
- $\mathbb{F}_p$: Finite field over prime $p$.
- $E(\mathbb{F}_p)$: elliptic curve defined over $\mathbb{F}_p$.
- $P = (x, y)$ is a point on $E(\mathbb{F}_p)$.
- Elliptic curve scalar multiplication:
  - Let $n \leftarrow \mathbb{Z}_p$,
  - Let $P$ be a point on $E(\mathbb{F}_p)$,
  - $Q = n \cdot P$ is a point on $E(\mathbb{F}_p)$.
- Elliptic curve discrete logarithm problem:
  - Let $P$ and $Q$ be points on $E(\mathbb{F}_p)$ and $Q = n \cdot P$.
  - Knowing $P$ and $Q$, finding $n = \log_P^Q$ is a hard problem.
- Base point: Let $G$ be a base point, then $G$ generates all points at $E(\mathbb{F}_p)$.

## Schnorr signature scheme
A Schnorr signature consists of the following functions:
* $keygen$ 
  * **Input**: Security parameter $\lambda$.
  * **Output**: Keypair $(sk, pk)$.
  * **Algorithm**:
    * Choose a random scalar as the private key: $sk \leftarrow \mathbb{Z}_p$,
    * Compute the public key: $pk \leftarrow sk \cdot G$,
    * Return (sk, pk).
* $sign$
  * **Input**: Keypair $(sk, pk)$, message $m$.
  * **Output**: Signature $\sigma = (R, s)$.
  * **Algorithm**: 
    * Choose a random scalar: $r \leftarrow Z_p$,
    * Compute the nonce: $R = r \cdot G$,
    * Compute the hash: $c \leftarrow H(R, pk, m)$,
    * Compute $s$: $s = r + c \cdot sk$,
    * Return the signature: $\sigma = (R, s)$.
* $verify$
  * **Input**: Message $m$, public key $pk$, signature $\sigma = (R, s)$.
  * **Output**: $true/false$
  * **Algorithm**:
    * If $s \cdot G = R + c\cdot pk$, return $true$.
    * Else, return $false$.

