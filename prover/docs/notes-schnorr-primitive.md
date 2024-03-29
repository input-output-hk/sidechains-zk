# Schnorr Signature
A Schnorr signature consists of the following functions:
* \\keygen(1^\lambda)\\ takes as input the security parameter $\lambda$ and returns a key-pair $(x, X)$. First, it chooses $x \leftarrow Z_p $. Finally, compute $X \leftarrow x \cdot G$, and return $(x, X)$.
* $sign(x, X, m) $ takes as input a keypair $(x, X)$ and a message $m$, and returns a signature $\sigma$. Let $r \leftarrow Z_p$. Compute $R = r \cdot G$, then compute $c \leftarrow H(R, X, m)$, and finally compute $s = r + c \cdot x$. The signature is $\sigma = (R, s)$.
* $verify(m, X, \sigma)$ takes as input a message $m$, a verification key $X$ and a signature $\sigma$, and returns $\result \in\{accept, reject\}$ depending on whether the signature is valid or not. The algorithm returns $accept$ if $s \cdot G = R + c\cdot X$
