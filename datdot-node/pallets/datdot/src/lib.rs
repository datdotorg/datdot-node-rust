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
		LockableCurrency
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
		Member,
		Scale
	},
};
use sp_arithmetic::{
	Percent,
	traits::{BaseArithmetic, One}
};
use sp_io::hashing::blake2_256;
use rand_chacha::{rand_core::{RngCore, SeedableRng}, ChaChaRng};
use ed25519::{Public, Signature};

/******************************************************************************
  The module's configuration trait
******************************************************************************/
pub trait Trait: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

	/// Type used for expressing timestamp.
	type Moment: Parameter + Default + AtLeast32Bit
		+ Scale<Self::BlockNumber, Output = Self::Moment> + Copy;

	
	/// The currency trait.
	type Currency: LockableCurrency<Self::AccountId>;

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
	type AttestationId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	// ---
}


/******************************************************************************
  Events
******************************************************************************/
decl_event!(
	pub enum Event<T> where
	<T as Trait>::FeedId,
	<T as Trait>::ContractId,
	<T as Trait>::PlanId,
	<T as Trait>::ChallengeId,
	<T as Trait>::AttestationId
	{
		/// New data feed registered
		NewFeed(FeedId),
		/// New hosting plan by publisher for selected feed (many possible plans per feed)
		NewPlan(PlanId),
		/// A new contract between publisher, encoder, and hoster (many contracts per plan)
		/// (Encoder, Hoster,...)
		NewContract(ContractId),
		/// Hosting contract started
		HostingStarted(ContractId),
		/// New proof-of-storage challenge
		NewProofOfStorageChallenge(ChallengeId),
		/// Proof-of-storage confirmed
		ProofOfStorageConfirmed(ChallengeId),
		/// Proof-of-storage not confirmed
		ProofOfStorageFailed(ChallengeId),
		/// Attestation of retrievability requested
		NewAttestation(AttestationId),
		/// Proof of retrievability confirmed
		AttestationReportConfirmed(AttestationId),
		/// Data serving not verified
		AttestationReportFailed(AttestationId),
	}
);

type RoleValue = Option<u32>;
type ChunkIndex = u64;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
enum Role {
	Encoder,
	Hoster,
	Attestor
}

type NoiseKey = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct User<T: Trait> {
	id: T::UserId,
	address: T::AccountId,
	attestor_key: Option<NoiseKey>,
	encoder_key: Option<NoiseKey>,
	hoster_key: Option<NoiseKey>,
	attestor_form: Form<T::Moment>,
	encoder_form: Form<T::Moment>,
	hoster_form: Form<T::Moment>
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
pub struct PlanUntil<Time> {
	time: Option<Time>,
	budget: Option<u64>,
	traffic: Option<u64>,
	price: Option<u64>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Plan<T: Trait> {
	id: T::PlanId,
	feeds: Vec<T::FeedId>,
	from: T::Moment,
	until: PlanUntil<T::Moment>,
	importance: u8,
	config: Config,
	schedules: Schedule<T::Moment>,
	sponsor: T::UserId,
	unhosted_feeds: Vec<T::FeedId>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Contract<T: Trait> {
	id: T::ContractId,
	plan: T::PlanId,
	ranges: Ranges<ChunkIndex>,
	encoder: T::UserId,
	hoster: T::UserId
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Challenge<T: Trait> {
	id: T::ChallengeId,
	contract: T::ContractId,
	chunks: Vec<ChunkIndex>
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

// #[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
// pub struct Proof {
// 	index: u64,
// 	nodes: Vec<Node>,
// 	signature: Option<Signature>
// }

pub type Proof = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Attestation<T: Trait> {
	id: T::AttestationId,
	attestor: T::UserId,
	contract: T::ContractId
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Report {
	location: u8,
	latency: Option<u8>
}
#[derive(Decode, Default, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Performance {
	availability: Percent,
	bandwidth: (u64, Percent),
	latency: (u16, Percent)
}

pub type Region = Vec<u8>;

#[derive(Decode, Default, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Config {
	performance: Performance,
	regions: Vec<(Region, Performance)>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Schedule<Time> {
	duration: Time,
	delay: Time,
	interval: Time,
	repeat: u32,
	config: Config
}

#[derive(Decode, Default, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Form<Time> {
	storage: u64,
	idle_storage: u64,
	from: Time,
	until: Time,
	schedules: Vec<Schedule<Time>>,
	config: Config,
}

/******************************************************************************
  Storage items/db
******************************************************************************/
/* expected js storage queries
const queries = {
	getFeedByID,
	getFeedByKey,
	getUserByID,
	getPlanByID,
	getContractByID,
	getStorageChallengeByID,
	getPerformanceChallengeByID,
}
*/
decl_storage! {
	trait Store for Module<T: Trait> as DatVerify {
		// PUBLIC/API
		pub GetFeedByID: map hasher(twox_64_concat) T::FeedId => Option<Feed<T>>;
		pub GetFeedByKey: map hasher(twox_64_concat) FeedKey => Option<Feed<T>>;
        pub GetUserByID: map hasher(twox_64_concat) T::UserId => Option<User<T>>;
        pub GetContractByID: map hasher(twox_64_concat) T::ContractId => Option<Contract<T>>;
        pub GetChallengeByID: map hasher(twox_64_concat) T::ChallengeId => Option<Challenge<T>>;
		pub GetPlanByID: map hasher(twox_64_concat) T::PlanId => Option<Plan<T>>;
		pub GetPerformanceChallengeByID: map hasher(twox_64_concat) T::AttestationId => Option<Attestation<T>>;
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

		/*
		if (type === 'publishFeed') _publishFeed(user, { name, nonce }, status, args)
		else if (type === 'publishPlan') _publishPlan(user, { name, nonce }, status, args)
		else if (type === 'registerEncoder') _registerEncoder(user, { name, nonce }, status, args)
		else if (type === 'registerAttestor') _registerAttestor(user, { name, nonce }, status, args)
		else if (type === 'registerHoster') _registerHoster(user, { name, nonce }, status, args)
		else if (type === 'encodingDone') _encodingDone(user, { name, nonce }, status, args)
		else if (type === 'hostingStarts') _hostingStarts(user, { name, nonce }, status, args)
		else if (type === 'requestStorageChallenge') _requestStorageChallenge(user, { name, nonce }, status, args)
		else if (type === 'requestPerformanceChallenge') _requestPerformanceChallenge(user, { name, nonce }, status, args)
		else if (type === 'submitStorageChallenge') _submitStorageChallenge(user, { name, nonce }, status, args)
		else if (type === 'submitPerformanceChallenge') _submitPerformanceChallenge(user, { name, nonce }, status, args)
		// else if ... 
		*/
		
		/*
		const log = connections[name].log

  		const [merkleRoot]  = args
  		const [key, {hashType, children}, signature] = merkleRoot
  		const keyBuf = Buffer.from(key, 'hex')
  		// check if feed already exists
  		if (DB.feedByKey[keyBuf.toString('hex')]) return
  		const feed = { publickey: keyBuf.toString('hex'), meta: { signature, hashType, children } }
  		const feedID = DB.feeds.push(feed)
  		feed.id = feedID
  		// push to feedByKey lookup array
  		DB.feedByKey[keyBuf.toString('hex')] = feedID
  		const userID = user.id
  		feed.publisher = userID
  		// Emit event
  		const NewFeed = { event: { data: [feedID], method: 'FeedPublished' } }
  		const event = [NewFeed]
  		handlers.forEach(([name, handler]) => handler(event))
  		// log({ type: 'chain', body: [`emit chain event ${JSON.stringify(event)}`] })
		*/
		fn publish_feed(origin, merkle_root: (Public, TreeHashPayload, H512)){

		}

		/*
		const log = connections[name].log
  		log({ type: 'chain', body: [`Publishing a plan`] })
  		const [plan] = args
  		const { feeds, from, until, importance, config, schedules } =  plan
  		const userID = user.id
		plan.sponsor = userID // or patron?
		const planID = DB.plans.push(plan)
		plan.id = planID
		// Add planID to unhostedPlans
		DB.unhostedPlans.push(planID)
		// Add feeds to unhosted
		plan.unhostedFeeds = feeds
		// Find hosters,encoders and attestors
		tryContract({ plan, log })
		// Emit event
		const NewPlan = { event: { data: [planID], method: 'NewPlan' } }
		const event = [NewPlan]
		handlers.forEach(([name, handler]) => handler(event))
		// log({ type: 'chain', body: [`emit chain event ${JSON.stringify(event)}`] })
		*/
		fn publish_plan(origin, plan: Plan){

		}

		/*
		const log = connections[name].log
		const userID = user.id
		const [encoderKey, form] = args
		if (DB.users[userID-1].encoderKey) return log({ type: 'chain', body: [`User is already registered as encoder`] })
		const keyBuf = Buffer.from(encoderKey, 'hex')
		DB.users[userID - 1].encoderKey = keyBuf.toString('hex')
		DB.users[userID - 1].encoderForm = form
		DB.idleEncoders.push(userID)
		tryContract({ log })

		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_encoder(origin, encoder_key: NoiseKey, form: Form){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				Self::reg_user(user_address, Some(noise_key));
				<Roles<T>>::insert(Role::Encoder, user_id, RoleValue::Some(0));
				Self::make_new_contract(Some(user_id.clone()), None, None);
			}
		}

		/*
		const log = connections[name].log
		const userID = user.id
		const [hosterKey, form] = args
		// @TODO emit event or make a callback to notify the user
		if (DB.users[userID-1].hosterKey) return log({ type: 'chain', body: [`User is already registered as a hoster`] })
		const keyBuf = Buffer.from(hosterKey, 'hex')
		DB.users[userID - 1].hosterKey = keyBuf.toString('hex')
		DB.users[userID - 1].hosterForm = form
		DB.idleHosters.push(userID)
		tryContract({ log })
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_hoster(origin, hoster_key: NoiseKey, form: Form){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				Self::reg_user(user_address, Some(noise_key));
				<Roles<T>>::insert(Role::Hoster, user_id, RoleValue::Some(0));
				Self::make_new_contract(None, Some(user_id.clone()), None);
			}
		}

		/*
		const userID = user.id
		const [attestorKey, form] = args
		if (DB.users[userID-1].attestorKey) return log({ type: 'chain', body: [`User is already registered as a attestor`] })
		const keyBuf = Buffer.from(attestorKey, 'hex')
		DB.users[userID - 1].attestorKey = keyBuf.toString('hex')
		DB.users[userID - 1].attestorForm = form
		DB.idleAttestors.push(userID)
		checkAttestorJobs(log)
		tryContract({ log })
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_attestor(origin, attestor_key: NoiseKey, form: Form){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Attestor, user_id, RoleValue::Some(0));
			}
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_encoder(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Encoder, user_id, RoleValue::None);
			}
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_hoster(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Hoster, user_id, RoleValue::None);
			}
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_attestor(origin){
			let user_address = ensure_signed(origin)?;
			if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
				<Roles<T>>::insert(Role::Attestor, user_id, RoleValue::None);
			}
		}

		/*
		const [ contractID ] = args
		DB.contractsEncoded.push(contractID)
		const contract = DB.contracts[contractID - 1]
		const encoderIDs = contract.encoders
		encoderIDs.forEach(encoderID => {
			 if (!DB.idleEncoders.includes(encoderID))
			  DB.idleEncoders.push(encoderID) 
			})	
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn encoding_done(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			// DB.contractsEncoded.push(contractID)
		}

		/*
		// @TODO check if encodingDone and only then trigger hostingStarts
		const [ contractID ] = args
		DB.contractsHosted.push(contractID)
		const contract = DB.contracts[contractID - 1]
		// if hosting starts, also the attestor finished job, add them to idleAttestors again
		const attestorID = contract.attestor
		if (!DB.idleAttestors.includes(attestorID)) {
			DB.idleAttestors.push(attestorID)
			checkAttestorJobs(log)
		}
		const userID = user.id
		const confirmation = { event: { data: [contractID, userID], method: 'HostingStarted' } }
		const event = [confirmation]
		handlers.forEach(([name, handler]) => handler(event))
		// log({ type: 'chain', body: [`emit chain event ${JSON.stringify(event)}`] })
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn hosting_starts(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			// DB.contractsHosted.push(contractID)
			// const HostingStarted = { event: { data: [contractID], method: 'HostingStarted' } }
			// handlers.forEach(handler => handler([HostingStarted]))
			Self::deposit_event(RawEvent::HostingStarted(contract_id));
		}

		/*

		const [ contractID, hosterID ] = args
		const ranges = DB.contracts[contractID - 1].ranges // [ [0, 3], [5, 7] ]
		// @TODO currently we check one random chunk in each range => find better logic
		const chunks = ranges.map(range => getRandomInt(range[0], range[1] + 1))
		const storageChallenge = { contract: contractID, hoster: hosterID, chunks }
		const storageChallengeID = DB.storageChallenges.push(storageChallenge)
		storageChallenge.id = storageChallengeID
		const attestorID = getAttestor(storageChallenge, log)
		if (!attestorID) return
		storageChallenge.attestor = attestorID
		// emit events
		const challenge = { event: { data: [storageChallengeID], method: 'NewStorageChallenge' } }
		const event = [challenge]
		handlers.forEach(([name, handler]) => handler(event))
		// log({ type: 'chain', body: [`emit chain event ${JSON.stringify(event)}`] })

		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_storage_challenge(origin, contract_id: T::ContractId, hoster_id: T::UserId ){
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
				<GetChallengeByID<T>>::insert(challenge_id, challenge.clone());
				<GetNextChallengeID<T>>::put(challenge_id.clone()+One::one());
				Self::deposit_event(RawEvent::NewProofOfStorageChallenge(challenge_id.clone()));
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

		/*
		const [ storageChallengeID, proofs ] = args
		const storageChallenge = DB.storageChallenges[storageChallengeID - 1]
		// attestor finished job, add them to idleAttestors again
		const attestorID = storageChallenge.attestor
		if (!DB.idleAttestors.includes(attestorID)) {
		DB.idleAttestors.push(attestorID)
		checkAttestorJobs(log)
		}
		// @TODO validate proof
		const isValid = validateProof(proofs, storageChallenge)
		let proofValidation
		const data = [storageChallengeID]
		log({ type: 'chain', body: [`StorageChallenge Proof for challenge: ${storageChallengeID}`] })
		if (isValid) response = { event: { data, method: 'StorageChallengeConfirmed' } }
		else response = { event: { data: [storageChallengeID], method: 'StorageChallengeFailed' } }
		// emit events
		const event = [response]
		handlers.forEach(([name, handler]) => handler(event))
		// log({ type: 'chain', body: [`emit chain event ${JSON.stringify(event)}`] })
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_storage_challenge(origin, challenge_id: T::ChallengeId, proofs: Vec<Proof> ){
			let user_address = ensure_signed(origin)?;
			let mut success: bool = true;
			if let Some(challenge) = <GetChallengeByID<T>>::get(&challenge_id){
				for proof in proofs {
					if Self::validate_proof(proof.clone(), challenge.clone()){
						success = success && true;
					} else {
						success = success && false;
					}
				}
				if success {
					Self::deposit_event(RawEvent::ProofOfStorageConfirmed(challenge_id.clone()));
				} else {
					Self::deposit_event(RawEvent::ProofOfStorageFailed(challenge_id.clone()));
				}
			} else {
				// TODO invalid challenge
			}
		}

		/*
		const log = connections[name].log
		const [ contractID ] = args
		const performanceChallenge = { contract: contractID }
		const performanceChallengeID = DB.performanceChallenges.push(performanceChallenge)
		performanceChallenge.id = performanceChallengeID
		if (DB.idleAttestors.length >= 5) emitPerformanceChallenge(performanceChallenge, log)
		else DB.attestorJobs.push({ fnName: 'emitPerformanceChallenge', opts: performanceChallenge })
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_performance_challenge(origin, contract_id: T::ContractId ){
			let user_address = ensure_signed(origin)?;
			if let Some(rand_attestor) = Self::get_random_of_role(&[0], &Role::Attestor, 1).pop(){
				let attestation_id = <GetNextAttestationID<T>>::get();
				let attestation = Attestation::<T> {
					id: attestation_id.clone(),
					attestor: rand_attestor,
					contract: contract_id
				};
				<GetAttestationByID<T>>::insert(attestation_id, attestation.clone());
				Self::deposit_event(RawEvent::NewAttestation(attestation_id.clone()));
			}
		}

		/*
		const [ performanceChallengeID, report ] = args
		log({ type: 'chain', body: [`Performance Challenge proof by attestor: ${user.id} for challenge: ${performanceChallengeID}`] })
		const performanceChallenge = DB.performanceChallenges[performanceChallengeID - 1]
		// attestor finished job, add them to idleAttestors again
		const attestorID = user.id
		if (!DB.idleAttestors.includes(attestorID)) {
			DB.idleAttestors.push(attestorID)
			checkAttestorJobs(log)
		}
		// emit events
		if (report) response = { event: { data: [performanceChallengeID], method: 'PerformanceChallengeConfirmed' } }
		else response = { event: { data: [performanceChallengeID], method: 'PerformanceChallengeFailed' } }
		const event = [response]
		handlers.forEach(([name, handler]) => handler(event))
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_performance_challenge(origin, attestation_id: T::AttestationId, reports: Vec<Report>){
			let user_address = ensure_signed(origin)?;
			let mut success: bool = true;
			if let Some(attestation) = <GetAttestationByID<T>>::get(&attestation_id){
				for report in reports {
					match report.latency {
						Some(_) => {
							// report passed
							success = success && true;
						},
						_ => {
							// report failed
							success = success && false;
						}
					}
				}
				if success {
					Self::deposit_event(RawEvent::AttestationReportConfirmed(attestation_id.clone()));
				} else {
					Self::deposit_event(RawEvent::AttestationReportFailed(attestation_id.clone()));
				}
			}
		}
	}
}

/******************************************************************************
  Internal functions
******************************************************************************/
impl<T: Trait> Module<T> {

	fn reg_user(user_address: T::AccountId, noise_key: Option<NoiseKey>){
		if let Some(user_id) = <GetIDByUser<T>>::get(&user_address){
			if let Some(user) = <GetUserByID<T>>::get(&user_id){
				<GetUserByID<T>>::insert(user_id, User::<T> {
					noise_key: noise_key,
					..user
				});
			} else {
				// some err
			}
		} else {
			let mut x = <GetNextUserID<T>>::get();
				let new_user = User {
					id: x.clone(),
					address: user_address.clone(),
					noise_key: noise_key
				};
				<GetUserByID<T>>::insert(x, new_user.clone());
				<GetIDByUser<T>>::insert(&user_address, x.clone());
			<GetNextUserID<T>>::put(x+One::one());
		}
	}

	fn make_new_contract(
		encoder_option: Option<T::UserId>,
		hoster_option: Option<T::UserId>,
		plan_option: Option<T::PlanId>
	){
		let mut contract_id : T::ContractId;
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
						contract_id = x.clone();
						<GetContractByID<T>>::insert(x, new_contract.clone());
						<GetNextContractID<T>>::put(x+One::one());
						Self::deposit_event(RawEvent::NewContract(contract_id.clone()));
					};
			},
			(None, None, Some(plan_id)) => {  // Condition: if planID && encoders available & hosters available
				random_hoster_option = Self::get_random_of_role(&[], &Role::Hoster, 1).pop();
				random_encoder_option = Self::get_random_of_role(&[], &Role::Encoder, 1).pop();
				if random_encoder_option.is_some() && random_hoster_option.is_some(){
					Self::make_new_contract(random_encoder_option, random_hoster_option, plan_option);
				}
			},
			(None, Some(hoster_id), None) => { //Condition: if hosterID && encoders available & plans available
				random_encoder_option = Self::get_random_of_role(&[], &Role::Encoder, 1).pop();
				let plans : Vec<T::PlanId> = <GetPlanByID<T>>::iter().map(|x|x.0).collect();
				random_plan_option = Self::get_random_of_vec(&[], plans, 1).pop();
				if random_encoder_option.is_some() && random_plan_option.is_some(){
					Self::make_new_contract(random_encoder_option, hoster_option, random_plan_option);
				}
			},
			(Some(encoder_id), None, None) => { //Condition: if encoderID && hosters available & plans available
				random_hoster_option = Self::get_random_of_role(&[], &Role::Hoster, 1).pop();
				let plans : Vec<T::PlanId> = <GetPlanByID<T>>::iter().map(|x|x.0).collect();
				random_plan_option = Self::get_random_of_vec(&[], plans, 1).pop();
				if random_hoster_option.is_some() && random_plan_option.is_some(){
					Self::make_new_contract(encoder_option, random_hoster_option, random_plan_option);
				}
			},
			(_, _, _) => ()
		}
	}

	fn random_from_ranges(ranges: Ranges<ChunkIndex>) -> Vec<ChunkIndex>{
		//TODO, currently only returns first chunk of every available range,
		//should return some random selection.
		ranges.iter().map(|x|x.0).collect()
	}

	fn validate_proof(proof: Proof, challenge: Challenge<T>) -> bool {
		//TODO validate proof!
		true
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

	fn get_random_of_vec<Item: Copy>(influence: &[u8], members: Vec<Item>, count: u32) -> Vec<Item>{
		let match_count : usize = count.try_into().unwrap();
		if members.len() <= match_count { members } else {
			let nonce : u64 = Self::unique_nonce();
			let mut random_select: Vec<Item> = Vec::new();
				// added indeces to seed in order to ensure challenges Get unique randomness.
			let seed = (nonce, T::Randomness::random(influence))
				.using_encoded(|b| <[u8; 32]>::decode(&mut TrailingZeroInput::new(b)))
				.expect("input is padded with zeroes; qed");
			let mut rng = ChaChaRng::from_seed(seed);
			let pick_item = |_| Self::pick_item(&mut rng, &members[..]).expect("exited if members empty; qed");
			for item in (0..count).map(pick_item){
				random_select.push(*item);
			}
			random_select
		}
	}

	fn get_random_of_role(influence: &[u8], role: &Role, count: u32) -> Vec<T::UserId> {
		let members : Vec<T::UserId> = <Roles<T>>::iter_prefix(role).filter_map(|x|{
			if x.1.is_some(){
				Some(x.0)
			} else {
				None
			}
		}).collect();
		Self::get_random_of_vec(influence, members, count)
	}


	fn get_random_of_role_filtered<F>(influence: &[u8], role: &Role, count: u32, filter: F) -> Vec<T::UserId>
	where F: Fn(RoleValue) -> bool {
		let members : Vec<T::UserId> = <Roles<T>>::iter_prefix(role).filter_map(|x|{
			if filter(x.1){
				Some(x.0)
			} else {
				None
			}
		}).collect();
		Self::get_random_of_vec(influence, members, count)
	}


}
