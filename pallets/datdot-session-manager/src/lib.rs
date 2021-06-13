#![cfg_attr(not(feature = "std"), no_std)]


use sp_std::prelude::*;
use sp_std::fmt::Debug;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::collections::btree_map::BTreeMap;
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

pub struct DatdotSession<T: Trait>{
	current_session: BTreeSet<T::AccountId>,
	pending_sessions: BTreeMap<SessionIndex, BTreeSet<T::AccountId>>,
	session_number: SessionIndex
}

pub trait Trait: system::Trait + pallet_datdot_jobs::Trait {
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
	// the Job representing block production work; currently we pass no params to it
	type Job: Get<pallet_datdot_jobs::RewardableJob<Self::AccountId>>;
}
        
decl_event!(
    pub enum Event {

    }
);

decl_error! {
	pub enum SessionError for Module<T: Trait> {
		
    }
}


decl_storage! {
	trait Store for Module<T: Trait> as SessionManager {
		pub Session: DatdotSession<T>;
    }
}

decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    }
}



impl<T: Trait> Module<T> {
	//infallibly adds a validator to the set - if when < session_number,
	//adds to the current session instead of a future one
	fn add_validator(who: T::AccountId, when: SessionIndex){
		let mut session_data: DatdotSession<T> = Session::<T>::get();
		if session_data.session_number >= when {
			session_data.current_session.insert(who);
		} else {
			session_data.pending_sessions.insert(when, who);
		}
		Session::<T>::put(session_data);
	}

	//attempts to remove a validator from the current set
	//if a future session index is provided, remove from that future pending session instead
	fn remove_validator(who: T::AccountId, maybe_future: Option<SessionIndex>){
		let mut session_data: DatdotSession<T> = Session::<T>::get();
		if let Some(future_index) = maybe_future {
			let mut future_session = session_data.pending_sessions.remove(future_index);
		} else {

		}
		Session::<T>::put(session_data);
	}
}

impl<T: Trait> pallet_session::SessionManager<<T as Trait>::AccountId> for DatdotSession<T> {
	fn new_session(index: SessionIndex) -> Option<Vec<T::AccountId>> { 
		// RETURN NEW VALIDATORS
		let session_data: DatdotSession<T> = Session::<T>::get();
		let return_vec = session_data.pending_session.get(index).and_then(|set_to_vec: BTreeSet<T::AccountId>|{
			set_to_vec.iter().collect()
		});
		return_vec
	}

	fn start_session(index: SessionIndex) {
		let mut session_data: DatdotSession<T> = Session::<T>::get();
		// only generate a new pending session if one doesn't already exist
		if let Some(mut pending) = session_data.pending_session.get(index+1){
			pending.append(session_data.current_session.clone());
			session_data.pending_session.insert(index+1, pending);
		} else {
			session_data.pending_session.insert(index+1, session_data.current_session);
		}
		Session::<T>::put(session_data);
	}

	fn end_session(index: SessionIndex) {
		let mut session_data = Session::<T>::get();
		//reward current session members
		for participant in session_data.current_session {
			// TODO - consider passing in cumulative block weight and length as JobParameters
			T::Job::get().reward_job(participant, pallet_datdot_jobs::JobParameters::new());
		}
		session_data.session_number = index + 1;
		session_data.current_session = session_data.pending_session.get(session_data.session_number);
		session_data.pending_session.remove(index);
		Session::<T>::put(session_data);
	}
}
