In this document we keep track of constraint count. 

## EC operations
* Witness point: 2 constraints
* Point addition: 3 constraints
* Point multiplication: 1854 (7,3 per scalar bit - without counting the range check we are at 6,08 per bit, close the CAP spec)
* Point mult with trick: 834 (3,3 per scalar bit - without counting range check we are at 2 per bit)
* Fixed Point multiplication: 820 (3,2 per scalar bit - without counting range check we are at 2 per bit)

## Hash functions


## Signatures
* Schnorr signature verification:
  * 3860 
  * 2824 with fixed base - 28% improvement
  * 2834 with low order check - still good
* ATMS signature (102/72): 
  * 283090 (3930 per threshold signature) 
  * 208500 with fixed base in schnorr - 2890 per threshold - 27% improvement
  
