#![cfg_attr(not(feature = "std"), no_std)]
/// A runtime module template with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references


/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/srml/example/src/lib.rs
use sp_std::prelude::*;
use sp_std::fmt::Debug;
use sp_std::collections::btree_map::BTreeMap;
use frame_support::{
	decl_module,
	decl_storage, 
	decl_event,
	decl_error,
	debug::native,
	fail,
	ensure,
	Parameter,
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
		schedule::Named as ScheduleNamed,
	},
	weights::{
		Pays,
		DispatchClass::{
			Operational,
		}
	},
};
use sp_std::convert::{
	TryInto,
};
use frame_system::{
	self as system,
	ensure_signed,
	ensure_root,
	RawOrigin
};
use codec::{Encode, Decode, Codec};
use sp_core::{
	ed25519,
	H256,
	H512,
};
use sp_runtime::{
	RuntimeDebug,
	traits::{
		Verify,
		CheckEqual,
		Dispatchable,
		SimpleBitOps,
		MaybeDisplay,
		TrailingZeroInput,
		AtLeast32Bit,
		MaybeSerializeDeserialize,
		Member
	},
};
use sp_io::hashing::blake2_256;
use rand_chacha::{rand_core::{RngCore, SeedableRng}, ChaChaRng};
use ed25519::{Public, Signature};

/// The module's configuration trait.
pub trait Trait: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	type Hash: 
	Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + SimpleBitOps
	+ Default + Copy + CheckEqual + sp_std::hash::Hash + AsRef<[u8]> + AsMut<[u8]>;
	type Randomness: Randomness<<Self as system::Trait>::Hash>;
	//ID TYPES---
	type FeedId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type UserId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type ContractId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type ChallengeId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type PlanId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type AttestorId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type AttestationId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type HosterId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type EncoderId: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type ChunkIndex: Parameter + Member + AtLeast32Bit + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	// ---
}



// Events in order of expected incidence
decl_event!(
	pub enum Event<T> where
	<T as Trait>::EncoderId, 
	<T as Trait>::HosterId, 
	<T as Trait>::FeedId, 
	<T as Trait>::ContractId,
	<T as Trait>::PlanId,
	<T as Trait>::ChallengeId
	{
		/// New feed registered
		NewFeed(FeedId),
		/// New hosting plan
		NewPlan(PlanId),
		//const data = [encoderID, hosterID, selectedPlan.feed, contractID, contract.ranges]
		/// A new contract is created between publisher, encoder, and hoster
		NewContract(EncoderId, HosterId, FeedId, ContractId, ContractRanges),
		/// Hosting (contract) started
		HostingStarted(ContractId),
		/// New proof-of-storage challenge
		ProofOfStorageChallenge(ChallengeId),
		/// Proof of storage confirmed
		ProofOfStorageConfirmed(AttestorId, ChallengeId),
		/// Proof of storage not confirmed
		ProofOfStorageFailed(ChallengeId),
		/// Attestation of retrievability requested
		ProofOfRetrievabilityAttestation(ChallengeId),
		/// Proof of retrievability confirmed
		ProofOfRetrievabilityConfirmed(ChallengeId),
		/// Data serving not verified
		ProofOfRetrievabilityFailed(ChallengeId),
	}
);

decl_error! {
    pub enum Error for Module<T: Trait> {
		
    }
}

type RoleValue = Option<u32>;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
enum Role {
	Encoder,
	Hoster,
	Attestor
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct User<T: Trait> {
	id: T::UserId,
	address: T::AccountId
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Copy, RuntimeDebug)]
pub struct ParentHashInRoot {
	hash: H256,
	hash_number: u64,
	total_length: u64
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct TreeRoot {
	signature: H512,
	hash_type: u8, //2
	children: Vec<ParentHashInRoot>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct TreeHashPayload {
	hash_type: u8, //2
	children: Vec<ParentHashInRoot>
}

type FeedKey = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct Feed<T: Trait> {
	id: T::FeedId,
	publickey: FeedKey,
	meta: TreeRoot
}

type Ranges<T: Trait> = Vec<(T::ChunkIndex, T::ChunkIndex)>;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct Plan<T: Trait> {
	id: T::PlanId,
	feed: T::FeedId,
	publisher: T::UserId,
	ranges: Ranges<T>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct Contract<T: Trait> {
	id: T::ContractId,
	plan: T::PlanId,
	ranges: Ranges<T>,
	encoder: T::EncoderId,
	hoster: T::HosterId
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct Challenge<T: Trait> {
	id: T::ChallengeId,
	contract: T::ContractId,
	chunks: Vec<T::ChunkIndex>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct Attestation<T: Trait> {
	id: T::AttestationId,
	attestor: T::AttestorId,
	contract: T::ContractId,
	chunks: Vec<T::ChunkIndex>
}

// storage items/db
decl_storage! {
	trait Store for Module<T: Trait> as DatVerify {
		// public/api
		pub GetFeedByID: map hasher(twox_64_concat) T::FeedId => Option<Feed<T>>;
        pub GetUserByID: map hasher(twox_64_concat) T::UserId => Option<User<T>>;
        pub GetContractByID: map hasher(twox_64_concat) T::ContractId => Option<Contract<T>>;
        pub GetChallengeByID: map hasher(twox_64_concat) T::ChallengeId => Option<Challenge<T>>;
		pub GetPlanByID: map hasher(twox_64_concat) T::PlanId => Option<Plan<T>>;
		pub GetAttestationByID: map hasher(twox_64_concat) T::AttestationId => Option<Attestation<T>>;
		// internally required storage
		pub GetNextFeedID: T::FeedId;
		pub GetNextUserID: T::UserId;
		pub GetNextContractID: T::ContractId;
		pub GetNextChallengeID: T::ChallengeId;
		pub GetNextPlanID: T::PlanId;
		pub GetNextAttestationID: T::AttestationId;
		pub Nonce: u64;
		// lookups (created as neccesary)
		pub GetIDByUser: map hasher(twox_64_concat) User<T> => T::UserId;
		// role array
		pub Roles: double_map hasher(twox_64_concat) Role, hasher(twox_64_concat) T::UserId => RoleValue;
	}
}

//externally dispatchable functions/calls
//(including on_finalize, on_initialize)
decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;
		
		fn deposit_event() = default;

		fn new_user(origin){
			let user_address = ensure_signed(origin)?;
			<GetIDByUser>::exists(&user_address);
			<GetNextUserID>::mutate(|x|{
				let new_user = User {
					id: x,
					address: user_address
				};
				<GetUserByID>::insert(x, new_user);
				x = x+1;
			});
		}

		fn register_encoder(origin){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			<roles>::insert(Role::Encoder, user_id, Some(0));
		}

		fn register_hoster(origin){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			<roles>::insert(Role::Hoster, user_id, Some(0));
		}

		fn register_attestor(origin){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			<roles>::insert(Role::Attestor, user_id, Some(0));
		}

		fn unregister_encoder(origin){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			<roles>::insert(Role::Encoder, user_id, None);
		}

		fn unregister_hoster(origin){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			<roles>::insert(Role::Hoster, user_id, None);
		}

		fn unregister_attestor(origin){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			<roles>::insert(Role::Attestor, user_id, None);
		}

		fn publish_feed_and_plan(origin, merkle_root: (Public, TreeHashPayload, H512), plan: Plan){
			let user_address = ensure_signed(origin)?;
			let user_id = <GetUserByID>::Get(&user_address);
			let mut feed_id;
			let mut plan_id;
			//TODO -- currently re-registering existing feeds creates a new FeedID, should lookup first.
			<GetNextFeedID>::mutate(|x|{
				let new_feed = Feed {
					id: x,
					publickey: merkle_root.0,
					meta: TreeRoot {
						signature: merkle_root.2,
						...merkle_root.1
					}
				};
				<GetFeedByID>::insert(x, new_feed);
				feed_id = x;
				x = x+1;
			});
			<GetNextPlanID>::mutate(|x|{
				let new_plan = Plan {
					id: x,
					publisher: user_id,
					feed: feed_id,
					ranges: plan.ranges
				};
				<GetPlanByID>::insert(x, new_plan);
				plan_id = x;
				x = x+1;
			});
			Self::try_new_contract(None, None, Some(plan_id));
			Self::deposit_event(RawEvent::NewFeed(feed_id));
			Self::deposit_event(RawEvent::NewPlan(plan_id));
		}

		fn 
	}
}

//pallet internal functions
impl<T: Trait> Module<T> {

	fn try_new_contract(
		encoder_option: Option<T::EncoderId>,
		hoster_option: Option<T::HosterId>,
		plan_option: Option<T::PlanId>
	){
		let mut random_hoster_option;
		let mut random_encoder_option;
		let mut random_plan_option;
		match (encoder_option, hoster_option, plan_option) {
			(Some(encoder_id), Some(hoster_id), Some(plan_id)) => {
				<GetNextContractID<T>>::mutate(|x|{
					let plan = <GetPlanByID<T>>::get(plan_id);
					let new_contract = Contract<T> {
						id: x,
						plan: plan_id,
						ranges: plan.ranges,
						encoder: encoder_id,
						hoster: hoster_id
					};
					<GetContractByID<T>>::insert(x, new_contract);
					x = x+1;
				});
			},
			(None, None, Some(plan_id)) => {
				// todo get random
				Self::try_new_contract(random_encoder_option, random_hoster_option, plan_option);
			},
			(None, Some(hoster_id), None) => {
				// todo get random
				Self::try_new_contract(random_encoder_option, hoster_option, random_plan_option);
			},
			(Some(encoder_id), None, None) => {
				// todo get random
				Self::try_new_contract(encoder_option, random_hoster_option, random_plan_option);
			},
			(_, _, _) => ()
		}
	}
	//borrowing from society pallet ---
	fn pick_usize<'a, R: RngCore>(rng: &mut R, max: usize) -> usize {

		(rng.next_u32() % (max as u32 + 1)) as usize
	}

	
	/// Pick an item at pseudo-random from the slice, given the `rng`. `None` iff the slice is empty.
	fn pick_item<'a, R: RngCore, E>(rng: &mut R, items: &'a [E]) -> Option<&'a E> {
		if items.is_empty() {
			None
		} else {
			Some(&items[Self::pick_usize(rng, items.len() - 1)])
		}
	}
	// ---

	fn unique_nonce() -> u64 {
		let nonce = <Nonce>::Get();
		<Nonce>::put(nonce+1);
		nonce
	}

	fn Get_random_of_role(influence: &[u8], role: &Role, count: u32) -> Vec<u64> {
		let members : Vec<u64> = <roles<T>>::iter_prefix(role).filter_map(|x|{
			
		}).collect();
		match members.len() {
			0 => members,
			_ => {
				let nonce : u64 = Self::unique_nonce();
				let mut random_select: Vec<u64> = Vec::new();
				// added indeces to seed in order to ensure challenges Get unique randomness.
				let seed = (nonce, influence, T::Randomness::random(b"dat_random_attestors"))
					.using_encoded(|b| <[u8; 32]>::decode(&mut TrailingZeroInput::new(b)))
					.expect("input is padded with zeroes; qed");
				let mut rng = ChaChaRng::from_seed(seed);
				let pick_attestor = |_| Self::pick_item(&mut rng, &members[..]).expect("exited if members empty; qed");
				for attestor in (0..count).map(pick_attestor){
					random_select.push(*attestor);
				}
				random_select
			},
		}
	}

}