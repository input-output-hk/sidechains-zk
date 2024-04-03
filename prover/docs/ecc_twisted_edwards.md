# Elliptic Curves
## Twisted Edward's Curve

Let $\mathbb{F}_p$ be a field where $p$ is a large prime. The twisted Edward's curve is defined as follows:

$$ E_{E, a, d}: ax^2 + y^2 = 1 + dx^2y^2$$

where $a, d \in \mathbb{F}_p$ and non-zero.

* A point on $E_{E, a, d}$ is represented as $P = (x, y)$.
* Negative of a point: $-P = (-x, y)$.
* Neutral element(point at infinity): $\mathcal{O} = (0,1)$.
* Let $P = (x_1, y_1)$ and $Q = (x_2, y_2)$ be points on $E_{E, a, d}$. $P+Q = (x_3, y_3)$ is written as:

$$(x_3, y_3) = \Bigg(\frac{x_1y_2 + y_1x_2}{1 + dx_1x_2y_1y_2}, \frac{y_1y_2 - ax_1x_2}{1 - dx_1x_2y_1y_2}\Bigg).$$
* Elliptic curve scalar multiplication:
* Order of a point: If $l\cdot P = \mathcal{O}$, then $l$ is the order of $P$.


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
