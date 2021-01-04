use codec::{Encode, Decode};

pub trait PowVerifier<AuthorType>{
    fn verify(author: AuthorType, pow: Vec<u8>) -> bool;
}

impl<T: Decode + Encode> PowVerifier<T> for () {
    fn verify(_author: T, _pow: Vec<u8>) -> bool {
      true
    }
}