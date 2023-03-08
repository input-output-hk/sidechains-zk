#include "stdio.h"
#include "../target/include/atms_halo2.h"

int main() {
    EdDsaPkPtr pks[5];
    EdDsaSigPtr sigs[5];
    MtCommitmentPtr avk;
    PlonkProofPtr proof;

    if (atms_prove(&proof, pks, sigs, 5, avk) == 1) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }

}
