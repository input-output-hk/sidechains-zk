* First, check if the [public key][AssignedEccPoint] has a low order. To do that
  1. Compute $8 \cdot pk$:
        ```ignore
        let two_pk = self.ecc_gate.add(ctx, pk, pk)?;
        let four_pk = self.ecc_gate.add(ctx, &two_pk, &two_pk)?;
        let eight_pk = self.ecc_gate.add(ctx, &four_pk, &four_pk)?;
        ```

  2. Assign the [curve generator][AssignedEccPoint] and [1][AssignedValue].
      ```ignore
      let assigned_generator = self.ecc_gate.witness_point(
           ctx,
           &Value::known(ExtendedPoint::from(SubgroupPoint::generator()).to_affine()),
        )?;
      let one = self
         .ecc_gate
         .main_gate
         .assign_bit(ctx, Value::known(Base::ONE))?;
      ```
     
  3. Check whether $8 \cdot pk = 8 \cdot (x, y) = (0, 1)$.
     ```ignore
     self.ecc_gate.main_gate.assert_not_zero(ctx, &eight_pk.x)?;
             self.ecc_gate
             .main_gate
             .assert_not_equal(ctx, &eight_pk.y, &one)?;
     ```
* Compute the challenge. Set the input hash including the `x` coordinate of the point in signature and the public key, and the message. Then call the hash function for input hash:
```ignore
let input_hash = [signature.0.x.clone(), pk.x.clone(), msg.clone()];
let challenge = self.rescue_hash_gate.hash(ctx, &input_hash)?;
```
* Set the `lhs = signature.1 * generator - challenge * pk` with `combined_mul`.
Check the equality of `lhs` and `signature.0` with [constrain_equal][crate::ecc::chip::EccChip::constrain_equal()].
```ignore
let lhs = self.combined_mul(ctx, &signature.1 .0, &challenge, &assigned_generator, pk)?;
self.ecc_gate.constrain_equal(ctx, &lhs, &signature.0)?;
```