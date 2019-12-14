use sp_std::prelude::*;
use support::{
	decl_module,
	decl_storage, 
	decl_event, 
    ensure,
    dispatch,
	StorageValue, 
	StorageMap
};
use system::{ensure_signed, ensure_root};

/// The module's configuration trait.
pub trait Trait: system::Trait + Sized {
	type Call: Parameter + Dispatchable<Origin=Self::Origin>;
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}