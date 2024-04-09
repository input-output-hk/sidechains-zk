Rescue prime hash function

# Rescue Prime
* $p$ is a prime with a binary expansion of at least $32$ bits and $\mathbb{F}_p$ is a prime field.
* $m$ is the state width of the hash function.
* $c_p$ is the capacity of the arithmetic sponge.
* $80 \leq s \leq 512$ is the target security level, measured in bits. 

## Rescue-Prime hash function
The Rescue-Prime hash function sends arbitrary-length sequences of field elements to $r_p$ field elements:
$$f_{R'}: \mathbb{F}_p^* \rightarrow \mathbb{F}_p^{r_p}.$$

It is obtained by employing the Rescue-XLIX permutation in a sponge construction. 
The resulting sponge function sends arbitrary-length sequences to infinite length sequences of field elements:
$$f_{R'-sponge}: \mathbb{F}_p^* \rightarrow \mathbb{F}_p^{*}.$$


## Sponge function

A sponge function is built from three components:
* a state memory, $S$, containing $b$
* a function $f \: \\{0, 1 \\}^b \rightarrow \\{0, 1\\}^b$
* a padding function $P$
$S$ is divided into two sections: one of size $r$ (the bitrate) and the remaining part of size $c$ (the capacity). These sections are denoted $R$ and $C$ respectively.

$f$ produces a pseudorandom permutation of the $2^b$ states from $S$.

$P$ appends enough bits to the input string so that the length of the padded input is a whole multiple of the bitrate, $r$. 
This means the input is segmented into blocks of $r$ bits.
