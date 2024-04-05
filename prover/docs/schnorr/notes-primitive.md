# Schnorr Signature
See [ECC toolbox][crate::ecc::documentation#asic-ecc-toolbox].

A Schnorr signature consists of the following functions:
## $keygen$ 
  * **Input**: Security parameter $\lambda$.
  * **Output**: Keypair $(sk, pk)$.
  * **Algorithm**:
    * Choose a random scalar as the private key: $sk \leftarrow \mathbb{Z}_p$,
    * Compute the public key: $pk \leftarrow sk \cdot G$,
    * Return (sk, pk). 
## $sign$
  * **Input**: Keypair $(sk, pk)$, message $m$.
  * **Output**: Signature $\sigma = (R, s)$.
  * **Algorithm**: 
    * Choose a random scalar: $r \leftarrow Z_p$,
    * Compute the nonce: $R = r \cdot G$,
    * Compute the hash: $c \leftarrow H(R, pk, m)$,
    * Compute $s$: $s = r + c \cdot sk$,
    * Return the signature: $\sigma = (R, s)$.
## $verify$
  * **Input**: Message $m$, public key $pk$, signature $\sigma = (R, s)$.
  * **Output**: $true/false$
  * **Algorithm**:
    * If $s \cdot G = R + c\cdot pk$, return $true$.
    * Else, return $false$.

