* Compute the challenge: Create `input_hash` including `x` coordinate of `announcement`, `x` coordinate of `pk`, and `msg`. Calculate the `RescueSponge` hash of the `input_hash`.
```rust
let input_hash = [
    *sig.0.coordinates().unwrap().x(),
    *pk.coordinates().unwrap().x(),
    msg,
];
let challenge = RescueSponge::<Base, RescueParametersBls>::hash(&input_hash, None);
```
* Reduce the challenge: `RescueSponge::<Base, RescueParametersBls>::hash` returns an element from $\mathbb{F}_q$. However, we need an element from $\mathbb{F}_r$ to compute the response. So, we reduce the challenge as follows:
```rust
let mut wide_bytes = [0u8; 64];
wide_bytes[..32].copy_from_slice(&challenge.to_bytes());
let reduced_challenge = Scalar::from_bytes_wide(&wide_bytes);
```
* Check whether $G \cdot response = announcement + challenge \cdot pk$. Return true if the equality holds.
```rust
if generator().mul(sig.1) == sig.0.add(pk.mul(reduced_challenge).to_affine()) {
    Ok(())
} else {
    Err(Error)
}
```