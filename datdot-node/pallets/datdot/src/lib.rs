#![cfg_attr(not(feature = "std"), no_std)]

/******************************************************************************
  A runtime module template with necessary imports
******************************************************************************/

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
use codec::{
	Encode,
	Decode, 
	Codec, 
	EncodeLike
};
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
use sp_arithmetic::traits::{BaseArithmetic, One};
use sp_io::hashing::blake2_256;
use rand_chacha::{rand_core::{RngCore, SeedableRng}, ChaChaRng};
use ed25519::{Public, Signature};

/******************************************************************************
  The module's configuration trait
******************************************************************************/
pub trait Trait: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	type Hash:
	Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + SimpleBitOps
	+ Default + Copy + CheckEqual + sp_std::hash::Hash + AsRef<[u8]> + AsMut<[u8]>;
	type Randomness: Randomness<<Self as system::Trait>::Hash>;
	//ID TYPES---
	type FeedId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type UserId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type ContractId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type ChallengeId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type PlanId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type AttestorId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type AttestationId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type HosterId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type EncoderId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type ChunkIndex: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	// ---
}


/******************************************************************************
  Events
******************************************************************************/
decl_event!(
	pub enum Event<T> where
	<T as Trait>::AttestorId,
	<T as Trait>::EncoderId, 
	<T as Trait>::HosterId, 
	<T as Trait>::FeedId, 
	<T as Trait>::ContractId,
	<T as Trait>::PlanId,
	<T as Trait>::ChallengeId,
	<T as Trait>::ChunkIndex
	{
		/// New data feed registered
		NewFeed(FeedId),
		/// New hosting plan by publisher for selected feed (many possible plans per feed)
		NewPlan(PlanId),
		/// A new contract between publisher, encoder, and hoster (many contracts per plan)
		NewContract(EncoderId, HosterId, FeedId, ContractId, Ranges<ChunkIndex>),
		/// Hosting contract started
		HostingStarted(ContractId),
		/// New proof-of-storage challenge
		NewProofOfStorageChallenge(ChallengeId),
		/// Proof-of-storage confirmed
		ProofOfStorageConfirmed(AttestorId, ChallengeId),
		/// Proof-of-storage not confirmed
		ProofOfStorageFailed(ChallengeId),
		/// Attestation of retrievability requested
		NewAttestation(ChallengeId),
		/// Proof of retrievability confirmed
		AttestationReportConfirmed(ChallengeId),
		/// Data serving not verified
		AttestationReportFailed(ChallengeId),
	}
);

type RoleValue = Option<u32>;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
enum Role {
	Encoder,
	Hoster,
	Attestor
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct User<T: Trait> {
	id: T::UserId,
	address: T::AccountId
}

type FeedKey = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Feed<T: Trait> {
	id: T::FeedId,
	publickey: FeedKey,
	meta: TreeRoot
}

type Ranges<C> = Vec<(C, C)>;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct ParentHashInRoot {
	hash: H256,
	hash_number: u64,
	total_length: u64
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
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

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Plan<T: Trait> {
	id: T::PlanId,
	feed: T::FeedId,
	publisher: T::UserId,
	ranges: Ranges<T::ChunkIndex>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Contract<T: Trait> {
	id: T::ContractId,
	plan: T::PlanId,
	ranges: Ranges<T::ChunkIndex>,
	encoder: T::EncoderId,
	hoster: T::HosterId
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Challenge<T: Trait> {
	id: T::ChallengeId,
	contract: T::ContractId,
	chunks: Vec<T::ChunkIndex>
}



#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Node {
	index: u64,
	hash: H256,
	size: u64
}

impl Node {
	fn height(&self) -> u64 {
		Self::get_height(self.index)
	}

	fn get_height(index : u64) -> u64 {
		let mut bit_pointer : u64 = 1;
		let mut cur_height : u64 = 0;
		while (index | bit_pointer) == index {
			cur_height += 1;
			bit_pointer *= 2;
		}
		cur_height
	}

	//get the index as if it were a leaf
	fn relative_index(&self) -> u64 {
		Self::index_at_height(self.index, self.height())
	}

	fn index_at_height(index : u64, height : u64) -> u64 {
		index / 2u64.pow(height.try_into().unwrap())
	}

	//get the last index at a given height, given a max leaf index
	fn top_index_at_height(height : u64, max_index : u64) -> Option<u64> {
		let offset = 2u64.pow(height.try_into().unwrap())-1;
		let interval = 2u64.pow((height+1).try_into().unwrap());
		let mut furthest_leaf = 0;
		let mut result = None;
		if height == 0 {
			result = Some(max_index);
		} else {
			for i in 0..height { //not inclusive of height intended
				furthest_leaf += 2u64.pow(i.try_into().unwrap());
			}
		}
		if max_index > offset {
			let mut next_result = true;
			while next_result {	
				match result {
					Some(index) => {
						if index + interval + furthest_leaf > max_index {
							next_result = false;
						} else {
							result = Some(index+interval);
						}
					},
					None => {
						result = Some(offset); 
					},
				}
			}
		}
		result
	}

	//get the highest height, given a max leaf index
	fn highest_at_index(max_index : u64) -> u64 {
		//max_index == 2^n - 2
		//return n
		//TODO: needs tests/audit, this was written using trail and error.
		let mut current_index = Some(max_index);
		let mut current_height : u64 = 0;
		while current_index.unwrap_or(0) > 2u64.pow(current_height.try_into().unwrap()) {
			current_index = current_index
				.unwrap_or(0)
				.checked_sub(2u64.pow((current_height+1).try_into().unwrap()));
			match current_index {
				Some(_) => current_height += 1,
				None => (),
			}
		}
		current_height
	}


	//get indexes of nodes in a merkle tree that are used to
	//calculate the root hash
	fn get_orphan_indeces(highest_index : u64) -> Vec<u64> {
		let mut indeces : Vec<u64> = Vec::new();
		for i in 0..Self::highest_at_index(highest_index)+1{
			match Self::top_index_at_height(i, highest_index) {
				Some(expr) => if expr % 2 == 0 {
					indeces.push(expr);
				},
				None => (),
			}
		}
		indeces
	}

	fn is_orphan(&self, highest_index : u64) -> bool {
		Self::get_orphan_indeces(highest_index)
			.contains(&self.index)
	}
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Proof {
	index: u64,
	nodes: Vec<Node>,
	signature: Option<Signature>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Attestation<T: Trait> {
	id: T::AttestationId,
	attestor: T::AttestorId,
	contract: T::ContractId,
	chunks: Vec<T::ChunkIndex>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Report {
	location: u8,
	latency: Option<u8>
}

/******************************************************************************
  Storage items/db
******************************************************************************/
decl_storage! {
	trait Store for Module<T: Trait> as DatVerify {
		// PUBLIC/API
		pub GetFeedByID: map hasher(twox_64_concat) T::FeedId => Option<Feed<T>>;
        pub GetUserByID: map hasher(twox_64_concat) T::UserId => Option<User<T>>;
        pub GetContractByID: map hasher(twox_64_concat) T::ContractId => Option<Contract<T>>;
        pub GetChallengeByID: map hasher(twox_64_concat) T::ChallengeId => Option<Challenge<T>>;
		pub GetPlanByID: map hasher(twox_64_concat) T::PlanId => Option<Plan<T>>;
		pub GetAttestationByID: map hasher(twox_64_concat) T::AttestationId => Option<Attestation<T>>;
		// INTERNALLY REQUIRED STORAGE
		pub GetNextFeedID: T::FeedId;
		pub GetNextUserID: T::UserId;
		pub GetNextContractID: T::ContractId;
		pub GetNextChallengeID: T::ChallengeId;
		pub GetNextPlanID: T::PlanId;
		pub GetNextAttestationID: T::AttestationId;
		pub Nonce: u64;
		// LOOKUPS (created as neccesary)
		pub GetIDByUser: map hasher(twox_64_concat) T::AccountId => Option<T::UserId>;
		// ROLES ARRAY
		pub Roles: double_map hasher(twox_64_concat) Role, hasher(twox_64_concat) T::UserId => RoleValue;
	}
}

/******************************************************************************
  External functions (including on_finalize, on_initialize)
******************************************************************************/
decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn new_user(origin){
			let user_address = ensure_signed(origin)?;
			if <GetIDByUser<T>>::contains_key(&user_address){
				// some err
			} else {
				let mut x = <GetNextUserID<T>>::get();
					let new_user = User {
						id: x.clone(),
						address: user_address.clone()
					};
					<GetUserByID<T>>::insert(x, new_user);
					<GetIDByUser<T>>::insert(&user_address, x.clone());
				<GetNextUserID<T>>::put(x+One::one());
			}
		}


		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_encoder(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Encoder, user_id, RoleValue::Some(0));
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_hoster(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Hoster, user_id, RoleValue::Some(0));
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_attestor(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Attestor, user_id, RoleValue::Some(0));
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_encoder(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Encoder, user_id, RoleValue::None);
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_hoster(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Hoster, user_id, RoleValue::None);
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_attestor(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Attestor, user_id, RoleValue::None);
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn publish_feed_and_plan(origin, merkle_root: (Public, TreeHashPayload, H512), ranges: Ranges<T::ChunkIndex>){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				let mut feed_id : T::FeedId;
				let mut plan_id : T::PlanId;
			//TODO -- currently re-registering existing feeds creates a new FeedID, should lookup first.
			let next_feed_id = <GetNextFeedID<T>>::get();
				let new_feed = Feed {
					id: next_feed_id.clone(),
					publickey: merkle_root.0,
					meta: TreeRoot {
						signature: merkle_root.2,
						hash_type: merkle_root.1.hash_type,
						children: merkle_root.1.children
					}
				};
				<GetFeedByID<T>>::insert(next_feed_id, new_feed.clone());
				feed_id = next_feed_id.clone();
				<GetNextFeedID<T>>::put(next_feed_id+One::one());
			let next_plan_id = <GetNextPlanID<T>>::get();
				let new_plan = Plan::<T> {
					id: next_plan_id.clone(),
					publisher: user_id,
					feed: feed_id,
					ranges: ranges
				};
				<GetPlanByID<T>>::insert(next_plan_id, new_plan.clone());
				plan_id = next_plan_id.clone();
				<GetNextPlanID<T>>::put(next_plan_id+One::one());
			Self::make_new_contract(None, None, Some(plan_id.clone()));
			Self::deposit_event(RawEvent::NewFeed(feed_id));
			Self::deposit_event(RawEvent::NewPlan(plan_id.clone()));
			} else {
				//some err
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn encoding_done(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			// DB.contractsEncoded.push(contractID)
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn hosting_starts(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			// DB.contractsHosted.push(contractID)
			// const HostingStarted = { event: { data: [contractID], method: 'HostingStarted' } }
			// handlers.forEach(handler => handler([HostingStarted]))
			Self::deposit_event(RawEvent::HostingStarted(contract_id));
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_proof_of_storage_challenge(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			if let Some(contract) = <GetContractByID<T>>::get(&contract_id){
				let ranges = contract.ranges;
				let random_chunks = Self::random_from_ranges(ranges);
				let challenge_id = <GetNextChallengeID<T>>::get();
				let challenge = Challenge::<T> {
					id: challenge_id.clone(),
					contract: contract_id,
					chunks: random_chunks
				};
				<GetChallengeByID<T>>::insert(challenge_id, challenge);
				<GetNextChallengeID<T>>::put(challenge_id.clone()+One::one());
				Self::deposit_event(RawEvent::NewProofOfStorageChallenge(challenge_id));
				/*
				const ranges = DB.contracts[contractID - 1].ranges // [ [0, 3], [5, 7] ]
				const chunks = ranges.map(range => getRandomInt(range[0], range[1] + 1))
				const challenge = { contract: contractID, chunks }
				const challengeID = DB.challenges.push(challenge)
				challenge.id = challengeID
				// emit events
				const newChallenge = { event: { data: [challengeID], method: 'NewProofOfStorageChallenge' } }
				handlers.forEach(handler => handler([newChallenge]))
				*/
			} else {
				//some err
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_proof_of_storage(origin, challenge_id: T::ChallengeId, proof: Proof ){
			let user_address = ensure_signed(origin)?;
			if let Some(challenge) = <GetChallengeByID<T>>::get(&challenge_id){
			/*
			const challenge = DB.challenges[challengeID - 1]
		    const isValid = validateProof(proof, challenge)
		    let proofValidation
		    const data = [challengeID]
		    console.log('Submitting Proof Of Storage Challenge with ID:', challengeID)
		    if (isValid) proofValidation = { event: { data, method: 'ProofOfStorageConfirmed' } }
		    else proofValidation = { event: { data: [challengeID], method: 'ProofOfStorageFailed' } }
		    // emit events
		    handlers.forEach(handler => handler([proofValidation]))
			*/
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_attestation(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			/*
			const [ attestorID ] = getRandom(DB.attestors)
		    const attestation = { contract: contractID , attestor: attestorID }
		    const attestationID = DB.attestations.push(attestation)
		    attestation.id = attestationID
		    const PoRChallenge = { event: { data: [attestationID], method: 'newAttestation' } }
		    handlers.forEach(handler => handler([PoRChallenge]))
			*/
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_attestation_report(origin, attestation_id: T::AttestationId, report: Report ){
			let user_address = ensure_signed(origin)?;
			/*
			console.log('Submitting Proof Of Retrievability Attestation with ID:', attestationID)
			// emit events
			if (report) PoR = { event: { data: [attestationID], method: 'AttestationReportConfirmed' } }
			else PoR = { event: { data: [attestationID], method: 'AttestationReportFailed' } }
			handlers.forEach(handler => handler([PoR]))
			*/
		}
	}
}

/******************************************************************************
  Internal functions
******************************************************************************/
impl<T: Trait> Module<T> {

	fn make_new_contract(
		encoder_option: Option<T::EncoderId>,
		hoster_option: Option<T::HosterId>,
		plan_option: Option<T::PlanId>
	){
		let mut random_hoster_option = None;
		let mut random_encoder_option = None;
		let mut random_plan_option = None;
		match (encoder_option, hoster_option, plan_option) {
			(Some(encoder_id), Some(hoster_id), Some(plan_id)) => {
				let x = <GetNextContractID<T>>::get();
					if let Some(plan) = <GetPlanByID<T>>::get(plan_id){
						let new_contract = Contract::<T> {
							id: x.clone(),
							plan: plan_id,
							ranges: plan.ranges,
							encoder: encoder_id,
							hoster: hoster_id
						};
						<GetContractByID<T>>::insert(x, new_contract);
						<GetNextContractID<T>>::put(x+One::one());
					};
			},
			(None, None, Some(plan_id)) => {  // Condition: if planID && encoders available & hosters available
				// todo get random
				if random_encoder_option.is_some() && random_hoster_option.is_some(){
					Self::make_new_contract(random_encoder_option, random_hoster_option, plan_option);
				}
			},
			(None, Some(hoster_id), None) => { //Condition: if hosterID && encoders available & plans available
				// todo get random
				if random_encoder_option.is_some() && random_plan_option.is_some(){
					Self::make_new_contract(random_encoder_option, hoster_option, random_plan_option);
				}
			},
			(Some(encoder_id), None, None) => { //Condition: if encoderID && hosters available & plans available
				// todo get random
				if random_hoster_option.is_some() && random_plan_option.is_some(){
					Self::make_new_contract(encoder_option, random_hoster_option, random_plan_option);
				}
			},
			(_, _, _) => ()
		}
	}

	fn random_from_ranges(ranges: Ranges<T::ChunkIndex>) -> Vec<T::ChunkIndex>{
		//TODO, currently only returns first chunk of every available range,
		//should return some random selection.
		ranges.iter().map(|x|x.0).collect()
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
		let nonce : u64 = <Nonce>::get();
		<Nonce>::put(nonce+1);
		nonce
	}

	/*
	fn get_random_of_role(influence: &[u8], role: &Role, count: u32) -> Vec<u64> {
		let members : Vec<u64> = <Roles<T>>::iter_prefix(role).filter_map(|x|{

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
	*/

}
