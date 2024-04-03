* Select a random scalar `k` and compute the announcement:
 ```rust
let k = Scalar::random(rng);
let announcement = generator().mul(k).to_affine();
```
* Compute the challenge: Create `input_hash` including `x` coordinate of `announcement`, `x` coordinate of `pk`, and `msg`. Calculate the `RescueSponge` hash of the `input_hash`.
```rust
let input_hash = [
    *announcement.coordinates().unwrap().x(),
    *key_pair.1.coordinates().unwrap().x(),
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
* Compute the response and return the signature:
```rust
let response = k + reduced_challenge * key_pair.0;
(announcement, response)
```