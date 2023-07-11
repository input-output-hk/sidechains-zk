In this document we keep track of constraint count. 

## EC operations
* Witness point: 2 constraints
* Point addition: 3 constraints
* Point multiplication: 1854 (7,3 per scalar bit - without counting the range check we are at 6,08 per bit, close the CAP spec)

## Signatures
* Schnorr signature verification: 3860
* ATMS signature (102/72): 283090 (3930 per threshold signature)
