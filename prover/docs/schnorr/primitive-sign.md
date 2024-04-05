[//]: # (* Select a random scalar `k` and compute the announcement:)

[//]: # ( ```)

[//]: # (let k = Scalar::random&#40;rng&#41;;)

[//]: # (let announcement = generator&#40;&#41;.mul&#40;k&#41;.to_affine&#40;&#41;;)

[//]: # (```)

[//]: # (* Compute the challenge: Create `input_hash` including `x` coordinate of `announcement`, `x` coordinate of `pk`, and `msg`. Calculate the `RescueSponge` hash of the `input_hash`.)

[//]: # (```)

[//]: # (let input_hash = [)

[//]: # (    *announcement.coordinates&#40;&#41;.unwrap&#40;&#41;.x&#40;&#41;,)

[//]: # (    *key_pair.1.coordinates&#40;&#41;.unwrap&#40;&#41;.x&#40;&#41;,)

[//]: # (    msg,)

[//]: # (];)

[//]: # (let challenge = RescueSponge::<Base, RescueParametersBls>::hash&#40;&input_hash, None&#41;;)

[//]: # (```)

[//]: # (* Reduce the challenge: `RescueSponge::<Base, RescueParametersBls>::hash` returns an element from $\mathbb{F}_q$. However, we need an element from $\mathbb{F}_r$ to compute the response. So, we reduce the challenge as follows:)

[//]: # (```)

[//]: # (let mut wide_bytes = [0u8; 64];)

[//]: # (wide_bytes[..32].copy_from_slice&#40;&challenge.to_bytes&#40;&#41;&#41;;)

[//]: # (let reduced_challenge = Scalar::from_bytes_wide&#40;&wide_bytes&#41;;)

[//]: # (```)

[//]: # (* Compute the response and return the signature:)

[//]: # (```)

[//]: # (let response = k + reduced_challenge * key_pair.0;)

[//]: # (&#40;announcement, response&#41;)

[//]: # (```)