use codec::{Encode};
use sp_io::ed25519::Signature;

use pallet_onboard::traits::PowVerifier;

impl<T: Config> PowVerifier<T::AccountId, (Call, Signature)> for Module<T> {
    fn verify(author: T::AccountId, pow: (Call, Signature)) -> bool {
        // TODO, ensure that author pubkey represents a feed that is being actively hosted.
        pow.1.verify(author, pow.0)
    }
}