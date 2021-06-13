use blake2b_pow::verify_nonce;
use codec::{Encode};

use crate::traits::PowVerifier;

impl<T: Encode> PowVerifier<T, u64> for () {
    fn verify(author: T, pow: u64) -> bool {
        author.using_encoded(|a_bytes|{
            verify_nonce(a_bytes, 
                u16::MAX as u64, 
                pow)
        })
    }
}
