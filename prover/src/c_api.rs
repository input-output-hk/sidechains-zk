extern crate core;

use crate::proof::{prove, EdDsaPk, EdDsaSig, MtCommitment, PlonkProof};
use core::slice;

pub const NULLPOINTERERR: i64 = -99;

type EdDsaPkPtr = *mut EdDsaPk;
type EdDsaSigPtr = *mut EdDsaSig;
type MtCommitmentPtr = *mut MtCommitment;
type PlonkProofPtr = *mut PlonkProof;

macro_rules! free_pointer {
    ($type_name:ident, $pointer_type:ty) => {
        paste::item! {
            #[no_mangle]
            /// Free pointer
            pub extern "C" fn [< free_ $type_name>](p: $pointer_type) -> i64 {
                unsafe {
                    if let Some(p) = p.as_mut() {
                        drop(Box::from_raw(p));
                        return 0;
                    }
                    NULLPOINTERERR
                }
            }
        }
    };
}

free_pointer!(proof, PlonkProofPtr);
free_pointer!(pk, EdDsaPkPtr);
free_pointer!(sig, EdDsaSigPtr);
free_pointer!(mt_comm, MtCommitmentPtr);

#[no_mangle]
pub extern "C" fn atms_prove(
    proof_ptr: *mut PlonkProofPtr,
    pks_ptr: *const EdDsaPkPtr,
    sigs_ptr: *const EdDsaSigPtr,
    nr_sigs: usize,
    avk: MtCommitmentPtr,
) -> i64 {
    unsafe {
        if let (Some(proof_ref), Some(&pks_ref), Some(&sigs_ref), Some(avk_ref)) = (
            proof_ptr.as_mut(),
            pks_ptr.as_ref(),
            sigs_ptr.as_ref(),
            avk.as_ref(),
        ) {
            let pks = slice::from_raw_parts_mut(pks_ref, nr_sigs)
                .iter()
                .map(|p| *p)
                .collect::<Vec<_>>();
            let sigs = slice::from_raw_parts_mut(sigs_ref, nr_sigs)
                .iter()
                .map(|p| *p)
                .collect::<Vec<_>>();

            if let Ok(proof) = prove(&pks, &sigs, avk_ref) {
                *proof_ref = Box::into_raw(Box::new(proof));
                return 1;
            } else {
                return 0;
            }
        }

        return 1;
    }
}
