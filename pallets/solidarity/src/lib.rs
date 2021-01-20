#![cfg_attr(not(feature = "std"), no_std)]


use sp_std::prelude::*;
use sp_std::fmt::Debug;
use frame_support::{
	decl_module,
	decl_storage,
	decl_event,
	decl_error,
	debug::native,
	fail,
    ensure,
    storage::{
		StorageMap,
		StorageValue,
		IterableStorageMap,
		IterableStorageDoubleMap,
	},
	traits::{
        EnsureOrigin,
		Get,
        Randomness,
    },
    weights::{
		Pays,
		DispatchClass::{
			Operational,
		}
	}
};
use frame_system::{
	self as system,
	ensure_signed,
	ensure_root,
	RawOrigin
};
use codec::{
	Encode,
	Decode,
	Codec,
	EncodeLike
};

pub trait Trait: system::Trait{
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}
        
decl_event!(
    pub enum Event {

    }
);

decl_error! {
	pub enum OnboardError for Module<T: Trait> {

    }
}


decl_storage! {
	trait Store for Module<T: Trait> as Onboard{
    }
}

decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    }
}



impl<T: Trait> Module<T> {

}
