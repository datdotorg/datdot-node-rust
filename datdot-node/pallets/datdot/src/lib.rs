#![cfg_attr(not(feature = "std"), no_std)]

/******************************************************************************
  A runtime module template with necessary imports
******************************************************************************/

use sp_std::prelude::*;
use sp_std::fmt::Debug;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::iter::ExactSizeIterator;
use sp_std::iter::Take;
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
		schedule::{
			Named as ScheduleNamed,
			DispatchTime
		},
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
	traits::{BaseArithmetic, One, Zero}
};
use rand_chacha::{rand_core::{RngCore, SeedableRng}, ChaChaRng};
use ed25519::{Public, Signature};

/******************************************************************************
  The module's configuration trait
******************************************************************************/
pub trait Trait: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	
	/// The Scheduler.

	type Proposal: Parameter + Dispatchable<Origin=Self::Origin> + From<Call<Self>>;
	type Scheduler: ScheduleNamed<Self::BlockNumber, Self::Proposal, Self::PalletsOrigin>;
	type PalletsOrigin: From<RawOrigin<Self::AccountId>>;

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
	type PerformanceChallengeId: Parameter + Member + AtLeast32Bit + BaseArithmetic + EncodeLike<u32> + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	// ---

	//CONSTS
	type PerformanceAttestorCount: Get<u8>;
	type ChallengeDelay: Get<<Self as system::Trait>::BlockNumber>;
	type ContractSetSize: Get<u64>;
	type ContractActivationCap: Get<u8>;
	type EncodersPerContract: Get<u8>;
	type HostersPerContract: Get<u8>;
	type AttestorsPerContract: Get<u8>;
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
	<T as Trait>::PerformanceChallengeId
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
		NewStorageChallenge(ChallengeId),
		/// Proof-of-storage confirmed
		ProofOfStorageConfirmed(ChallengeId),
		/// Proof-of-storage not confirmed
		ProofOfStorageFailed(ChallengeId),
		/// PerformanceChallenge of retrievability requested
		NewPerformanceChallenge(PerformanceChallengeId),
		/// Proof of retrievability confirmed
		AttestationReportConfirmed(PerformanceChallengeId),
		/// Data serving not verified
		AttestationReportFailed(PerformanceChallengeId),
	}
);

decl_error! {
	pub enum DatDotError for Module<T: Trait> {
		/// Incorrect permissions
		PermissionError,
		/// Missing Plan
		MissingPlan,
		/// Missing Contract
		MissingContract,
		/// Missing Challenge
		MissingChallenge
	}
}

type ChunkIndex = u64;

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
enum Role {
	Encoder,
	IdleEncoder,
	Hoster,
	IdleHoster,
	Attestor,
	IdleAttestor
}

type NoiseKey = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct User<UserId, AccountId, Time> {
	id: UserId,
	address: AccountId,
	attestor_key: Option<NoiseKey>,
	encoder_key: Option<NoiseKey>,
	hoster_key: Option<NoiseKey>,
	attestor_form: Option<Form<Time>>,
	encoder_form: Option<Form<Time>>,
	hoster_form: Option<Form<Time>>
}

type FeedKey = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Feed<T: Trait> {
	id: T::FeedId,
	publickey: FeedKey,
	meta: TreeRoot,
	publisher: T::UserId
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
pub struct FeedInPlan<A, B>{
	id: A,
	ranges: B
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
pub struct Plan<PlanId, FeedId, Time, UserId, ContractId> {
	id: PlanId,
	feeds: Vec<FeedInPlan<FeedId, Ranges<u64>>>,
	from: Time,
	until: PlanUntil<Time>,
	importance: u8,
	config: Config,
	schedules: Vec<Schedule<Time>>,
	sponsor: UserId,
	contracts: Vec<ContractId>
}

struct Expirable<Item, Time> {
	inner: Item,
	expires: Time
}
#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Contract<T: Trait> {
	id: T::ContractId,
	plan: T::PlanId,
	ranges: Ranges<ChunkIndex>,
	providers: Option<Providers<T>>,
	failed_hosters: Vec<T::UserId>
}
#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Providers<T: Trait> {
	encoders: Vec<T::UserId>,
	hosters: Vec<T::UserId>,
	attestors: Vec<T::UserId>,
	active_hosters: Vec<T::UserId>,
	failed_hosters: Vec<T::UserId>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct StorageChallenge<T: Trait> {
	id: T::ChallengeId,
	contract: T::ContractId,
	hoster: T::UserId,
	chunks: Vec<ChunkIndex>,
	attestor: Option<T::UserId>
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
struct PerformanceChallenge<T: Trait> {
	id: T::PerformanceChallengeId,
	attestors: Option<Vec<T::UserId>>,
	contract: T::ContractId,
	hoster: T::UserId
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
	capacity: u64,
	idle_storage: u64,
	from: Time,
	until: Time,
	schedules: Vec<Schedule<Time>>,
	config: Config,
}

// (number of attestors required, job id)
#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub enum AttestorJob<ChallengeId, PerformanceChallengeId> {
	StorageChallenge(ChallengeId),
	PerformanceChallenge(PerformanceChallengeId)
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub enum ChallengeType {
	StorageChallenge,
	PerformanceChallenge
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
        pub GetUserByID: map hasher(twox_64_concat) T::UserId => Option<User<T::UserId, T::AccountId, T::Moment>>;
        pub GetContractByID: map hasher(twox_64_concat) T::ContractId => Option<Contract<T>>;
        pub GetChallengeByID: map hasher(twox_64_concat) T::ChallengeId => Option<StorageChallenge<T>>;
		pub GetPlanByID: map hasher(twox_64_concat) T::PlanId => Option<Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>>;
		pub GetPerformanceChallengeByID: map hasher(twox_64_concat) T::PerformanceChallengeId => Option<PerformanceChallenge<T>>;
		// INTERNALLY REQUIRED STORAGE
		pub GetNextFeedID: T::FeedId;
		pub GetNextUserID: T::UserId;
		pub GetNextContractID: T::ContractId;
		pub GetNextChallengeID: T::ChallengeId;
		pub GetNextPlanID: T::PlanId;
		pub GetNextAttestationID: T::PerformanceChallengeId;
		pub Nonce: u64;
		pub GetAttestorJobQueue: Vec<AttestorJob<T::ChallengeId, T::PerformanceChallengeId>>;
		pub DraftContractsQueue: Vec<T::ContractId>;
		// LOOKUPS (created as neccesary)
		pub GetUserByKey: map hasher(twox_64_concat) T::AccountId => Option<User<T::UserId, T::AccountId, T::Moment>>;
		// ROLES ARRAY
		pub Roles: double_map hasher(twox_64_concat) Role, hasher(twox_64_concat) T::UserId => ();
	}
}

/******************************************************************************
  External functions (including on_finalize, on_initialize)
******************************************************************************/
decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
		type Error = DatDotError<T>;


		const ChallengeDelay : <T as system::Trait>::BlockNumber = T::ChallengeDelay::get();
		const PerformanceAttestorCount : u8 = T::PerformanceAttestorCount::get();
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
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn publish_feed(origin, merkle_root: (Public, TreeHashPayload, H512)){
			let publisher_address = ensure_signed(origin)?;
			let user = Self::load_user(publisher_address);
			if let Some(feed) = <GetFeedByKey<T>>::get(merkle_root.0){
				// if a feed is already published, emit error here.
			} else {
				let feed_id : T::FeedId;
				let next_feed_id = <GetNextFeedID<T>>::get();
				//TODO feed.ranges from?
				let new_feed = Feed::<T> {
					id: next_feed_id.clone(),
					publickey: merkle_root.0,
					meta: TreeRoot {
						signature: merkle_root.2,
						hash_type: merkle_root.1.hash_type,
						children: merkle_root.1.children
					},
					publisher: user.id
				};
				<GetFeedByID<T>>::insert(next_feed_id, new_feed.clone());
				<GetFeedByKey<T>>::insert(merkle_root.0, new_feed.clone());
				feed_id = next_feed_id.clone();
				<GetNextFeedID<T>>::put(next_feed_id+One::one());
				Self::deposit_event(RawEvent::NewFeed(feed_id));
			}
		}

		/*
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
		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn publish_plan(origin, plan: Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>){
			let sponsor_address = ensure_signed(origin)?;
			let user = Self::load_user(sponsor_address);
			let next_plan_id = <GetNextPlanID<T>>::get();
			let new_plan = Plan::<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId> {
				id: next_plan_id.clone(),
				sponsor: user.id,
				..plan
			};
			<GetPlanByID<T>>::insert(next_plan_id.clone(), new_plan.clone());
			let plan_id = next_plan_id.clone();
			<GetNextPlanID<T>>::put(next_plan_id+One::one());
			//unzip plan 
			Self::make_draft_contracts(new_plan);
			//verify plan.from is now or in past,
			//else schedule scheduled_make_contracts in the future
			//{
				//get the queue
				//try to find providers
				//emit events
			//}
			Self::deposit_event(RawEvent::NewPlan(plan_id.clone()));
		}

		// If within Self::make_draft_contracts the queue of unhosted sets is not zero, this extrinsic is scheduled
		// calls make_draft_contracts again 
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn scheduled_activate_contracts(origin){
			//todo origins
			Self::try_activate_draft_contracts();
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
		fn register_encoder(origin, encoder_key: NoiseKey, form: Form<T::Moment>){

			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.encoder_form = Some(form);
			user.encoder_key = Some(encoder_key);
			Self::save_user(&mut user);
			<Roles<T>>::insert(Role::Encoder, user.id, ());
			<Roles<T>>::insert(Role::IdleEncoder, user.id, ());
			Self::try_activate_draft_contracts();
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
		fn register_hoster(origin, hoster_key: NoiseKey, form: Form<T::Moment>){
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.hoster_form = Some(form);
			user.hoster_key = Some(hoster_key);
			Self::save_user(&mut user);
			<Roles<T>>::insert(Role::Hoster, user.id, ());
			<Roles<T>>::insert(Role::IdleHoster, user.id, ());
			Self::try_activate_draft_contracts();
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
		fn register_attestor(origin, attestor_key: NoiseKey, form: Form<T::Moment>){
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.attestor_form = Some(form);
			user.attestor_key = Some(attestor_key);
			Self::save_user(&mut user);
			<Roles<T>>::insert(Role::Attestor, user.id, ());
			Self::give_attestors_jobs(&mut [user.id], &mut []);
			Self::try_activate_draft_contracts();
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_encoder(origin){
			
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.encoder_form = None;
			user.encoder_key = None;
			Self::save_user(&mut user);
			<Roles<T>>::remove(Role::Encoder, user.id);
			<Roles<T>>::remove(Role::IdleEncoder, user.id);
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_hoster(origin){
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.hoster_form = None;
			user.hoster_key = None;
			Self::save_user(&mut user);
			<Roles<T>>::remove(Role::Hoster, user.id);
			<Roles<T>>::remove(Role::IdleHoster, user.id);

		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_attestor(origin){	
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.attestor_form = None;
			user.attestor_key = None;
			Self::save_user(&mut user);
			<Roles<T>>::remove(Role::Attestor, user.id);
			<Roles<T>>::remove(Role::IdleAttestor, user.id);
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
			let user = Self::load_user(user_address);
			if let Some(mut contract) = <GetContractByID<T>>::get(contract_id){
				if let Some(mut providers) = contract.providers {
					ensure!(providers.hosters.contains(&user.id), DatDotError::<T>::PermissionError);
					if !providers.active_hosters.contains(&user.id) {
						providers.active_hosters.push(user.id);
					} else if providers.active_hosters.len() == providers.hosters.len() {
						for current_encoder in providers.clone().encoders {
							<Roles<T>>::insert(Role::IdleEncoder, current_encoder.clone(), ());
						}
					}
					contract.providers = Some(providers.clone());
					<GetContractByID<T>>::insert(contract_id, contract.clone());
					Self::give_attestors_jobs(providers.attestors.as_slice(), &mut []);
					Self::start_challenges(contract_id, user.id);
					Self::deposit_event(RawEvent::HostingStarted(contract_id));
				} else {
					//TODO contract is still in draft
				}
			};
			//todo should be economic logic, still under consideration.
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

		*/
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_storage_challenge(origin, contract_id: T::ContractId, hoster_id: T::UserId ){
			let user_address = ensure_signed(origin)?;
			let user = Self::load_user(user_address);
			if let Some(contract) = <GetContractByID<T>>::get(&contract_id){
				let sponsor = <GetPlanByID<T>>::get(contract.plan).ok_or(DatDotError::<T>::MissingPlan)?.sponsor;
				ensure!(sponsor == user.id, DatDotError::<T>::MissingChallenge);
				let ranges = contract.ranges;
				let random_chunks = Self::random_from_ranges(ranges);
				let challenge_id = <GetNextChallengeID<T>>::get();
				let challenge = StorageChallenge::<T> {
					id: challenge_id.clone(),
					contract: contract_id,
					hoster: hoster_id,
					chunks: random_chunks,
					attestor: None
				};
				<GetChallengeByID<T>>::insert(challenge_id, challenge.clone());
				<GetNextChallengeID<T>>::put(challenge_id.clone()+One::one());
				Self::give_attestors_jobs(&[], &mut [AttestorJob::StorageChallenge(challenge_id.clone())]);
				if let Some(plan) = <GetPlanByID<T>>::get(contract.plan){
					Self::schedule_challenges(contract_id, hoster_id, plan, &[ChallengeType::StorageChallenge]);
				}
			} else {
				fail!(DatDotError::<T>::MissingContract);
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
			let user = Self::load_user(user_address);
			let mut success: bool = true;
			if let Some(challenge) = <GetChallengeByID<T>>::get(&challenge_id){
				ensure!(user.id == challenge.hoster, DatDotError::<T>::PermissionError);
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
				fail!(DatDotError::<T>::MissingChallenge);
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
		fn request_performance_challenge(origin, contract_id: T::ContractId, hoster_id: T::UserId){
			let user_address = ensure_signed(origin)?;
			let user = Self::load_user(user_address);
			//TODO ensure user is sponsor 
			let attestation_id = <GetNextAttestationID<T>>::get();
			let attestation = PerformanceChallenge::<T> {
				id: attestation_id.clone(),
				attestors: None,
				contract: contract_id,
				hoster: hoster_id
			};
			<GetPerformanceChallengeByID<T>>::insert(attestation_id, attestation.clone());
			<GetNextAttestationID<T>>::put(attestation_id.clone()+One::one());
			Self::give_attestors_jobs(&mut [], &mut [AttestorJob::PerformanceChallenge(attestation_id)]);
			if let Some(contract) = <GetContractByID<T>>::get(contract_id){
				if let Some(plan) = <GetPlanByID<T>>::get(contract.plan){
					Self::schedule_challenges(contract_id, hoster_id, plan, &[ChallengeType::PerformanceChallenge]);
				}
			}
		}

		/*
		const [ performanceChallengeID, report ] = args
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
		fn submit_performance_challenge(origin, attestation_id: T::PerformanceChallengeId, reports: Vec<Report>){
			let user_address = ensure_signed(origin)?;
			let mut success: bool = true;
			if let Some(attestation) = <GetPerformanceChallengeByID<T>>::get(&attestation_id){
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

	fn make_draft_contracts(plan: Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>){
		let mut draft_contracts: Vec<T::ContractId> = plan.feeds.iter().flat_map(|feed_struct|{
			let feed_opt: Option<Feed<T>> = <GetFeedByID<T>>::get(feed_struct.id);
			match feed_opt {
				Some(feed) => {
					let sets = Self::split_main(feed_struct.clone().ranges);
					sets.iter().map(|set|{
						let contract_id = <GetNextContractID<T>>::get();
						let draft_contract = Contract::<T> {
							id: contract_id.clone(),
							plan: plan.id,
							ranges: set.to_vec(),
							providers: None,
							failed_hosters: Vec::new()
						};
						<GetContractByID<T>>::insert(contract_id, draft_contract);
						<GetNextContractID<T>>::put(contract_id.clone()+One::one());
						contract_id
					}).collect()
				},
				None => {
					Vec::new()
				}
			}
		}).collect();
		let mut current_draft_contracts = <DraftContractsQueue<T>>::get();
		current_draft_contracts.append(&mut draft_contracts);
		<DraftContractsQueue<T>>::put(current_draft_contracts);
	}

	fn try_activate_draft_contracts(){
		let mut failed_contracts: Vec<T::ContractId> = Vec::new();
		let mut failed_contract_count = 0;
		let mut current_draft_contracts: Vec<T::ContractId> = <DraftContractsQueue<T>>::get();
		for contract_id in current_draft_contracts.iter_mut().take(T::ContractActivationCap::get() as usize) {
			if let Err(Some(failed_contract)) = Self::activate_single_draft_contract(*contract_id){
				failed_contract_count += 1;
				failed_contracts.push(failed_contract);
			}
		}
		//and try that many MORE contracts, but ONLY ONCE.
		for contract_id in current_draft_contracts.iter_mut().take(failed_contract_count){
			if let Err(Some(failed_contract)) = Self::activate_single_draft_contract(*contract_id){
				failed_contracts.push(failed_contract);
			}
		}
		//currently we put failed contracts back into the front, but we need some fallback 
		failed_contracts.append(&mut current_draft_contracts);
		<DraftContractsQueue<T>>::put(failed_contracts);
		
	}

	fn activate_single_draft_contract(contract_id: T::ContractId) -> Result<(),Option<T::ContractId>> {
		//contract should exist, if removed, should remove from queue too, so unwrap
		let contract_option = <GetContractByID<T>>::get(contract_id);
		if let Some(mut contract) = contract_option {
			if let Some(mut plan) = <GetPlanByID<T>>::get(contract.plan){
				if let Some(providers) = Self::get_providers(plan.clone()){
					contract.providers = Some(providers);
					plan.contracts.push(contract_id);
					<GetContractByID<T>>::insert(contract_id, contract);
					<GetPlanByID<T>>::insert(plan.clone().id, plan.clone());
					Self::deposit_event(RawEvent::NewContract(contract_id.clone()));
					//Self::schedule_contract_followup(contract, plan);
					Ok(())
				} else {
					//not enough providers, throw error and ask to requeue contract
					Err(Some(contract_id))
				}
			} else {
				//plan is missing, this should also not be possible/an error
				// TODO remove plan for missing plan
				Err(None)
			}
		} else {
			//if the contract doesn't exist, this is an error, but we should return no ID
			//so the ID is not readded to queue
			Err(None)
		}
	}

	fn get_providers(plan: Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>) -> Option<Providers<T>> {
		let mut avoid = Self::make_avoid(&plan);
		let attestors = Self::select(Role::IdleAttestor, T::AttestorsPerContract::get().into(), |(x,_)|{
			(!avoid.contains(x)) && Self::qualifyAttestor(&plan, x)
		});
		avoid.append(&mut attestors.clone());
		if attestors.len() < T::AttestorsPerContract::get() as usize { return None } else {
			let hosters = Self::select(Role::IdleHoster, T::HostersPerContract::get().into(), |(x,_)|{
				(!avoid.contains(x)) && Self::qualifyHoster(&plan, x)
			});
			avoid.append(&mut hosters.clone());
			if hosters.len() < T::HostersPerContract::get() as usize { return None } else {
				let encoders = Self::select(Role::IdleEncoder, T::EncodersPerContract::get().into(), |(x,_)|{
					(!avoid.contains(x)) && Self::qualifyEncoder(&plan, x)
				});
				avoid.append(&mut encoders.clone());
				if encoders.len() < T::EncodersPerContract::get() as usize { return None } else {
					Some(Providers::<T> {
						encoders: encoders,
						hosters: hosters,
						active_hosters: Vec::new(),
						failed_hosters: Vec::new(),
						attestors: attestors
					})
				}
			}
		}
	}

	fn qualifyAttestor(plan: &Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>, user_id: &T::UserId)->bool{
		if let Some(user) = <GetUserByID<T>>::get(user_id){
			if let Some(form) = user.attestor_form {
				Self::is_idle_now(form)
			} else {
				false
			}
		} else {
			false
		}
		
		// from - until matches curremt time
		// future: geolocation
	}

	fn qualifyEncoder(plan: &Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>, user_id: &T::UserId)->bool{
		if let Some(user) = <GetUserByID<T>>::get(user_id){
			if let Some(form) = user.encoder_form {
				if Self::is_idle_now(form) {
					//Self::contract_storage_check(form);
					//currently encoders do not register storage
					true
				} else {
					false
				}
			} else {
				false
			}
		} else {
			false
		}
		// from - until matches current time
		// future: geolocation
	}

	fn qualifyHoster(plan: &Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>, user_id: &T::UserId)->bool{
		if let Some(user) = <GetUserByID<T>>::get(user_id){
			if let Some(form) = user.hoster_form {
				if let Some(plan_until_time) = plan.until.time {
					if form.from <= plan.from && form.until >= plan_until_time {
						Self::contract_storage_check(form)
					} else {
						false
					}
				} else {
					// check other plan.until fields
					true
				}
			} else {
				false
			}
		} else {
			false
		}
		// future: geolocation
		// future: schedule match
	}

	fn contract_storage_check(form: Form<T::Moment>) -> bool {
		let storage_used = T::ContractSetSize::get()*65536;
		storage_used <= form.storage
	}

	fn is_idle_now(form: Form<T::Moment>) -> bool {
		// comparision without comparison operator because I have Scale trait - maybe I should just add comparison trait?
		form.from.div(<system::Module<T>>::block_number().into()) == Zero::zero() && form.until.div(<system::Module<T>>::block_number().into()) >= One::one()
	}

	fn make_avoid(plan: &Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>) -> Vec<T::UserId>{
		let mut avoid = Vec::new();
		avoid.push(plan.sponsor);
		for feed_struct in &plan.feeds {
			if let Some(feed) = <GetFeedByID<T>>::get(feed_struct.id){
				avoid.push(feed.publisher.clone());
			}
		}
		avoid
	}

	fn select(select_role: Role, select_amount: usize, select_function: impl Fn((&T::UserId, &())) -> bool) -> Vec<T::UserId>{
		<Roles<T>>::iter_prefix(select_role)
			.filter(|(x, y)|{select_function((x, y))})
			.take(select_amount)
			.map(|(x, _)|x)
			.collect()
	}

	fn start_challenges(contract_id: T::ContractId, hoster_id: T::UserId){
		if let Some(contract) = <GetContractByID<T>>::get(contract_id){
			if let Some(plan) = <GetPlanByID<T>>::get(contract.plan){
					Self::schedule_challenges(
						contract_id,
						hoster_id,
						plan,
						&[ChallengeType::StorageChallenge,ChallengeType::PerformanceChallenge]
					);
			}
		}
	}

	fn schedule_challenges(
		contract_id: T::ContractId,
		hoster_id: T::UserId,
		plan: Plan<T::PlanId, T::FeedId, T::Moment, T::UserId, T::ContractId>,
		challenge_types: &[ChallengeType]
	){
		// if plan.until.time > time now, do logic below
		if let Some(sponsor) = <GetUserByID<T>>::get(&plan.sponsor){
			let sponsor_origin = RawOrigin::Signed(sponsor.address);
			for challenge_type in challenge_types {
				let challenge_call: Call<T> = match challenge_type {
					ChallengeType::StorageChallenge => {
						Call::request_storage_challenge(contract_id, hoster_id)
					},
					ChallengeType::PerformanceChallenge => {
						Call::request_performance_challenge(contract_id, hoster_id)
					}
				};
				//schedule based on defaults
				// challenge request types: 0 = storage, 1 = performance
				let challenge_delay: <T as system::Trait>::BlockNumber = T::ChallengeDelay::get();
				if plan.schedules.len() == 0 {
					(contract_id, hoster_id, challenge_type).using_encoded(
						|id_bytes|{
							T::Scheduler::schedule_named(
								id_bytes.to_vec(),
								DispatchTime::After(challenge_delay),
								None,
								254,
								sponsor_origin.clone().into(),
								challenge_call.into()
							);
						}
					)
				} else {
					//schedule based on plan_schedules
				}
			}
		}
	}

	fn load_user(account_id: T::AccountId) -> User<T::UserId, T::AccountId, T::Moment> {
			if let Some(user) = <GetUserByKey<T>>::get(&account_id){
				user
			} else {
				let mut user_id = <GetNextUserID<T>>::get();
				let mut new_user = User::<T::UserId, T::AccountId, T::Moment> {
					id: user_id.clone(),
					address: account_id.clone(),
					..User::<T::UserId, T::AccountId, T::Moment>::default()
				};
				Self::save_user(&mut new_user);
				<GetNextUserID<T>>::put(user_id+One::one());
				new_user
			}
	}

	fn save_user(user: &mut User<T::UserId, T::AccountId, T::Moment>){
		<GetUserByID<T>>::insert(user.id, user.clone());
		<GetUserByKey<T>>::insert(user.clone().address, user.clone());
	}

	fn give_attestors_jobs(
		attestors: &[T::UserId],
		jobs: &mut [AttestorJob<T::ChallengeId, T::PerformanceChallengeId>]
	){
		for attestor in attestors {
			<Roles<T>>::insert(Role::IdleAttestor, attestor, ());
		}
		let mut old_job_queue = <GetAttestorJobQueue<T>>::get();
		let mut job_queue_slice = [old_job_queue.as_mut_slice(), jobs].concat();
		let job_queue = job_queue_slice.iter();
		for job in job_queue.clone() {
			match job {
				AttestorJob::PerformanceChallenge(challenge_id) => {
					// Verify we have a sufficient number of attestors for this challenge type
					let mut attestor_count = 0;
					let mut performance_attestors : Vec<T::UserId> = Vec::new();
						// emit an attestation request for each performance attestor
					for attestor in <Roles<T>>::iter_prefix(Role::IdleAttestor) {
						attestor_count += 1;
						performance_attestors.push(attestor.0);
						if attestor_count > T::PerformanceAttestorCount::get().into(){
							<Roles<T>>::remove(Role::IdleAttestor, attestor.0);
							if let Some(mut challenge) = <GetPerformanceChallengeByID<T>>::get(&challenge_id){
								challenge.attestors = Some(performance_attestors);
								<GetPerformanceChallengeByID<T>>::insert(&challenge_id, challenge);
							}
							Self::deposit_event(RawEvent::NewPerformanceChallenge(challenge_id.clone()));
							break;
						}
					}
				},
				AttestorJob::StorageChallenge(challenge_id) => {
					if let Some(attestor) = <Roles<T>>::iter_prefix(Role::IdleAttestor).next(){
						<Roles<T>>::remove(Role::IdleAttestor, attestor.0);
						if let Some(mut challenge) = <GetChallengeByID<T>>::get(&challenge_id){
							challenge.attestor = Some(attestor.0);
							<GetChallengeByID<T>>::insert(&challenge_id, challenge);
						}
						Self::deposit_event(RawEvent::NewStorageChallenge(challenge_id.clone()));
						break;
					}
				}
			}
		}
		<GetAttestorJobQueue<T>>::put(
			job_queue.collect::<Vec<&AttestorJob<T::ChallengeId, T::PerformanceChallengeId>>>()
		);
	}

	fn random_from_ranges(ranges: Ranges<ChunkIndex>) -> Vec<ChunkIndex>{
		//TODO, currently only returns first chunk of every available range,
		//should return some random selection.
		ranges.iter().map(|x|x.0).collect()
		//todo, get rng from 0->set_size-1, get a single random index based on that.
	}

	fn validate_proof(proof: Proof, challenge: StorageChallenge<T>) -> bool {
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
			if x.1 == (){
				Some(x.0)
			} else {
				None
			}
		}).collect();
		Self::get_random_of_vec(influence, members, count)
	}

	fn set_len(set_in: Vec<(u64, u64)>) -> u64 {
		set_in.iter().fold(0, |mut count, input_range|{
			if input_range.1 > input_range.0 {
				count += input_range.1 - input_range.0;
			} else {
				//bad range, but...
				count += input_range.0 - input_range.1;
			}
			count+=1;
			count
		})
	}

	fn process_previous_set(temp_out: &mut Vec<Vec<(u64,u64)>>) -> u64 {
		let current_pointer = temp_out.last();
		let set_max_index : u64 = T::ContractSetSize::get();
		let set_size : u64 = T::ContractSetSize::get();
		match current_pointer {
			Some(last_set) => {
				//last set is either less than or equal to set size,
				let set_length =  Self::set_len(last_set.to_vec());
				if set_length >= 0 && set_length <= set_max_index {
					//get the remaining required
					let remains: u64 = set_size - Self::set_len(last_set.to_vec());
					//println!("last set {:?} was smaller, remainder {:?}", last_set, remains);
					remains	
				} else if set_length == set_size {
					//if equal, add new set to temp_out, and set remaining to 10
					
					//println!("last set {:?} was equal", last_set);
					temp_out.push(Vec::new());
					set_size
				} else {
						
					//println!("last set {:?} was larger, should split", last_set);
					let mut split_set = Self::split_main(last_set.to_vec());
					//println!("split to {:?} ", split_set);
					temp_out.pop();
					temp_out.append(&mut split_set);
					Self::process_previous_set(temp_out);
					set_size
				}
				
			},
			None => {
				temp_out.push(Vec::new());
				set_size
			}
		}
		
	}

	fn merge_last_consecutive(temp_out: &mut Vec<Vec<(u64,u64)>>){
		if let Some(last) = temp_out.pop(){
			let mut new: Vec<(u64, u64)> = Vec::new();
			let mut maybe_previous_end: Option<u64> = None;
			for (start, end) in last {
				if let Some(previous_end) = maybe_previous_end {
					if start == previous_end+1 {
						if let Some(previous_range) = new.pop(){
							new.push((previous_range.0, end));
						}
					} else {
						new.push((start, end));
					}
				} else {
					new.push((start, end));
				}
				maybe_previous_end = Some(end);
			}
			temp_out.push(new);
		}
	}

	fn split_main(ranges: Vec<(u64,u64)>) -> Vec<Vec<(u64, u64)>> {
		ranges.iter().fold(Vec::new(),|mut temp_out, input_range|{
			let remaining = Self::process_previous_set(&mut temp_out);
			let mut range_vec = Vec::new();
			range_vec.push(*input_range);
			if Self::set_len(range_vec) < remaining {
				let mut last_set = temp_out.pop().unwrap();
				last_set.push(*input_range);
				temp_out.push(last_set);
			} else {
				let split_index = input_range.0 as u64 + (remaining-1 as u64);
				let new_range = (input_range.0, split_index);
				let mut last_set = temp_out.pop().unwrap();
				
				//println!("insert range into previous set: {:?}", new_range);
				last_set.push(new_range);
				temp_out.push(last_set);
				
				
				let next_range = (split_index+1, input_range.1);
				if next_range.0 <= next_range.1 { 
					let mut next_set = Vec::new();
					next_set.push(next_range);
					//println!("insert new set: {:?}", next_set);
					temp_out.push(next_set);
				}
			}
			//println!("pre-merge: {:?}", temp_out);
			Self::merge_last_consecutive(&mut temp_out);
			//println!("post-merge: {:?}", temp_out);
			temp_out
		})
	}
}
