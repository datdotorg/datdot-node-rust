#![cfg_attr(not(feature = "std"), no_std)]
/******************************************************************************
  A runtime module template with necessary imports
******************************************************************************/

use sp_std::prelude::*;
use sp_std::fmt::Debug;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::iter::ExactSizeIterator;
use sp_std::iter::Take;
use sp_std::cmp::Ordering;
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

type IdType = u32;
/******************************************************************************
  The module's configuration trait
******************************************************************************/
pub trait Trait: system::Trait{
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
	
	/// The Scheduler.

	type Proposal: Parameter + Dispatchable<Origin=Self::Origin> + From<Call<Self>>;
	type Scheduler: ScheduleNamed<Self::BlockNumber, Self::Proposal, Self::PalletsOrigin>;
	type PalletsOrigin: From<RawOrigin<Self::AccountId>>;

	/// The currency trait.
	type Currency: LockableCurrency<Self::AccountId>;

	type Hash:
	Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + SimpleBitOps
	+ Default + Copy + CheckEqual + sp_std::hash::Hash + AsRef<[u8]> + AsMut<[u8]>;
	type Randomness: Randomness<<Self as system::Trait>::Hash>;
	// ---

	//CONSTS
	type PerformanceAttestorCount: Get<u8>;
	type ChallengeDelay: Get<<Self as system::Trait>::BlockNumber>;
	type EncodingDuration: Get<<Self as system::Trait>::BlockNumber>;
	type AttestingDuration: Get<<Self as system::Trait>::BlockNumber>;
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
	pub enum Event {
		/// New data feed registered
		NewFeed(IdType),
		/// New hosting plan by publisher for selected feed (many possible plans per feed)
		NewPlan(IdType),
		/// A new contract between publisher, encoder, and hoster (many contracts per plan)
		/// (Encoder, Hoster,...)
		NewContract(IdType),
		/// Hosting contract started
		HostingStarted(IdType),
		/// New proof-of-storage challenge
		NewStorageChallenge(IdType),
		/// Proof-of-storage confirmed
		ProofOfStorageConfirmed(IdType),
		/// Proof-of-storage not confirmed
		ProofOfStorageFailed(IdType),
		/// PerformanceChallenge of retrievability requested
		NewPerformanceChallenge(IdType),
		/// Proof of retrievability confirmed
		AttestationReportConfirmed(IdType),
		/// Data serving not verified
		AttestationReportFailed(IdType),
		/// New Amendment created
		NewAmendment(IdType),
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

#[derive(Decode, Default, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Form<Time> {
	storage: u64,
	idle_storage: u64,
	capacity: u64,
	from: Time,
	until: Option<Time>,
	schedules: Vec<Schedule<Time>>,
	config: Config,
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct ProviderRoleData<Time> {
	key: NoiseKey,
	form: Form<Time>,
	capacity: u64,
	idle_storage: u64,
	jobs: BTreeSet<JobId>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct User<AccountId, Time> {
	id: IdType,
	address: AccountId,
	hoster: Option<ProviderRoleData<Time>>,
	encoder: Option<ProviderRoleData<Time>>,
	attestor: Option<ProviderRoleData<Time>>
}

type FeedKey = Public;

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Feed {
	id: IdType,
	publickey: FeedKey,
	meta: TreeRoot,
	publisher: IdType
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
pub struct FeedInPlan<B>{
	id: IdType,
	ranges: B
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
pub struct Plan<Time> {
	id: IdType,
	feeds: Vec<FeedInPlan<Ranges<u64>>>,
	from: Time,
	until: PlanUntil<Time>,
	importance: u8,
	config: Config,
	schedules: Vec<Schedule<Time>>,
	sponsor: IdType,
	contracts: Vec<IdType>
}

struct Expirable<Item, Time> {
	inner: Item,
	expires: Time
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Amendment {
	id: IdType,
	contract: IdType,
	providers: Providers
}

/*
impl Ord for Amendment {
	fn cmp(&self, other: &Self) -> Ordering {
		let other_sum = 
			other.providers.hosters.len() +
			other.providers.encoders.len() +
			other.providers.attestors.len();

		let self_sum = 
			self.providers.hosters.len() +
			self.providers.encoders.len() +
			self.providers.attestors.len();

		other_sum.cmp(self_sum)
	}
}
*/


#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Contract {
	id: IdType,
	plan: IdType,
	feed: IdType,
	ranges: Ranges<ChunkIndex>,
	amendments: Vec<IdType>,
	active_hosters: Vec<IdType>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct Providers {
	encoders: Vec<IdType>,
	hosters: Vec<IdType>,
	attestors: Vec<IdType>
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, Default, RuntimeDebug)]
struct StorageChallenge {
	id: IdType,
	contract: IdType,
	hoster: IdType,
	chunks: Vec<ChunkIndex>,
	attestor: Option<IdType>
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
struct PerformanceChallenge {
	id: IdType,
	attestors: Option<Vec<IdType>>,
	contract: IdType,
	hoster: IdType
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

// (number of attestors required, job id)
#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug, PartialOrd, Ord)]
pub enum JobId {
	StorageChallenge(IdType),
	PerformanceChallenge(IdType),
	ContractAmendment(IdType),
	HosterJob(IdType),
	EncoderJob(IdType)
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub enum ChallengeType {
	StorageChallenge,
	PerformanceChallenge
}

/******************************************************************************
  Storage items/db
******************************************************************************/

decl_storage! {
	trait Store for Module<T: Trait> as DatVerify{
		// PUBLIC/API
		pub GetFeedByID: map hasher(twox_64_concat) IdType => Option<Feed>;
		pub GetFeedByKey: map hasher(twox_64_concat) FeedKey => Option<Feed>;
        pub GetUserByID: map hasher(twox_64_concat) IdType => Option<User<T::AccountId, T::BlockNumber>>;
		pub GetContractByID: map hasher(twox_64_concat) IdType => Option<Contract>;
		pub GetAmendmentByID: map hasher(twox_64_concat) IdType => Option<Amendment>;
        pub GetChallengeByID: map hasher(twox_64_concat) IdType => Option<StorageChallenge>;
		pub GetPlanByID: map hasher(twox_64_concat) IdType => Option<Plan<T::BlockNumber>>;
		pub GetPerformanceChallengeByID: map hasher(twox_64_concat) IdType => Option<PerformanceChallenge>;
		// INTERNALLY REQUIRED STORAGE
		pub GetNextFeedID: IdType;
		pub GetNextUserID: IdType;
		pub GetNextContractID: IdType;
		pub GetNextAmendmentID: IdType;
		pub GetNextChallengeID: IdType;
		pub GetNextPlanID: IdType;
		pub GetNextAttestationID: IdType;
		pub Nonce: u64;
		pub GetJobIdQueue: Vec<JobId>;
		pub PendingAmendments: Vec<IdType>;
		// LOOKUPS (created as neccesary)
		pub GetUserByKey: map hasher(twox_64_concat) T::AccountId => Option<User<T::AccountId, T::BlockNumber>>;
		// ROLES ARRAY
		pub Roles: double_map hasher(twox_64_concat) Role, hasher(twox_64_concat) IdType => ();
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

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn publish_feed(origin, merkle_root: (Public, TreeHashPayload, H512)){
			let publisher_address = ensure_signed(origin)?;
			let user = Self::load_user(publisher_address);
			if let Some(feed) = <GetFeedByKey>::get(merkle_root.0){
				// if a feed is already published, emit error here.
			} else {
				let feed_id : IdType;
				let next_feed_id = <GetNextFeedID>::get();
				//TODO feed.ranges from?
				let new_feed = Feed {
					id: next_feed_id.clone(),
					publickey: merkle_root.0,
					meta: TreeRoot {
						signature: merkle_root.2,
						hash_type: merkle_root.1.hash_type,
						children: merkle_root.1.children
					},
					publisher: user.id
				};
				<GetFeedByID>::insert(next_feed_id, new_feed.clone());
				<GetFeedByKey>::insert(merkle_root.0, new_feed.clone());
				feed_id = next_feed_id.clone();
				let feed_id_counter : IdType = next_feed_id+1;
				<GetNextFeedID>::put(feed_id_counter);
				Self::deposit_event(Event::NewFeed(feed_id));
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn publish_plan(origin, plan: Plan<T::BlockNumber>){
			let sponsor_address = ensure_signed(origin)?;
			let user = Self::load_user(sponsor_address);
			let next_plan_id = <GetNextPlanID>::get();
			let new_plan = Plan::<T::BlockNumber> {
				id: next_plan_id.clone(),
				sponsor: user.id,
				..plan
			};
			<GetPlanByID<T>>::insert(next_plan_id.clone(), new_plan.clone());
			let plan_id = next_plan_id.clone();
			let plan_id_counter : IdType = next_plan_id+1;
			<GetNextPlanID>::put(plan_id_counter);
			//unzip plan 
			let contract_ids = Self::make_contracts_schedule_amendments(new_plan);
			// for each contract ID schedule amendment (extrinsic) to execute on contract from.
			// TODO make amendments and add to pending amendments
			Self::deposit_event(Event::NewPlan(plan_id.clone()));
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn scheduled_activate_contracts(origin){
			//todo origins
			Self::try_next_amendments();
		}

		#[weight = (100000, Operational, Pays::No)]
		fn scheduled_amendment(origin, contract_id: IdType){
			//todo origins
			if let Some(amendment_id) =
			Self::make_draft_amendment(contract_id, Providers::default()) {
				Self::add_to_pending_amendments([amendment_id].to_vec(), None);
				Self::try_next_amendments();
			}

		}


		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_encoder(origin, key: NoiseKey, form: Form<T::BlockNumber>){

			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			let new_role_data = ProviderRoleData::<T::BlockNumber> {
				key: key,
				form: form.clone(),
				capacity: form.capacity.clone(),
				idle_storage: form.storage.clone(),
				jobs: BTreeSet::new()
			};
			user.encoder = Some(new_role_data);
			Self::save_user(&mut user);
			<Roles>::insert(Role::Encoder, user.id, ());
			<Roles>::insert(Role::IdleEncoder, user.id, ());
			Self::try_next_amendments();
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_hoster(origin, hoster_key: NoiseKey, form: Form<T::BlockNumber>){
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			let new_role_data = ProviderRoleData::<T::BlockNumber> {
				key: hoster_key,
				form: form.clone(),
				capacity: form.capacity.clone(),
				idle_storage: form.storage.clone(),
				jobs: BTreeSet::new()
			};
			user.hoster = Some(new_role_data);
			Self::save_user(&mut user);
			<Roles>::insert(Role::Hoster, user.id, ());
			<Roles>::insert(Role::IdleHoster, user.id, ());
			Self::try_next_amendments();
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn register_attestor(origin, attestor_key: NoiseKey, form: Form<T::BlockNumber>){
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			let new_role_data = ProviderRoleData::<T::BlockNumber> {
				key: attestor_key,
				form: form.clone(),
				capacity: form.capacity.clone(),
				idle_storage: form.storage.clone(),
				jobs: BTreeSet::new()
			};
			user.attestor = Some(new_role_data);
			Self::save_user(&mut user);
			<Roles>::insert(Role::Attestor, user.id, ());
			Self::give_attestors_jobs(&mut [user.id], &mut []);
			Self::try_next_amendments();
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_encoder(origin){
			
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.encoder = None;
			Self::save_user(&mut user);
			<Roles>::remove(Role::Encoder, user.id);
			<Roles>::remove(Role::IdleEncoder, user.id);
		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_hoster(origin){
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.hoster = None;
			Self::save_user(&mut user);
			<Roles>::remove(Role::Hoster, user.id);
			<Roles>::remove(Role::IdleHoster, user.id);

		}

		// Ensure that these match new logic TODO
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn unregister_attestor(origin){	
			let user_address = ensure_signed(origin)?;
			let mut user = Self::load_user(user_address);
			user.attestor = None;
			Self::save_user(&mut user);
			<Roles>::remove(Role::Attestor, user.id);
			<Roles>::remove(Role::IdleAttestor, user.id);
		}

		//args - report - (amendment_id, vec<failed ids>)
		// TODO - fail case, submit amendment
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn amendment_report(origin, report: (IdType, Vec<IdType>)){
			let user_address = ensure_signed(origin)?;
			let user = Self::load_user(user_address);
			if let Some(amendment) = <GetAmendmentByID>::get(report.0) {
				let contract_id = amendment.contract;
				if let Some(mut contract) = <GetContractByID>::get(contract_id){
					if let Some(last_amendment) = <GetAmendmentByID>::get(contract.amendments.pop().unwrap()) {
						let mut providers = last_amendment.providers.clone();
						// TODO logic here needs to be refactored for amendments
						ensure!(providers.hosters.contains(&user.id), DatDotError::<T>::PermissionError);
						if !contract.active_hosters.contains(&user.id) {
							contract.active_hosters.push(user.id);
						} else {
							if contract.active_hosters.len() == providers.hosters.len() {
								for current_encoder in providers.clone().encoders {
									<Roles>::insert(Role::IdleEncoder, current_encoder.clone(), ());
								}
							}
						}
						<GetContractByID>::insert(contract_id, contract.clone());
						Self::give_attestors_jobs(providers.attestors.as_slice(), &mut []);
						Self::start_challenges(contract_id, user.id);
						Self::deposit_event(Event::HostingStarted(contract_id));
					}
				};
			}
			//todo should be economic logic, still under consideration.
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_storage_challenge(origin, contract_id: IdType, hoster_id: IdType ){
			let user_address = ensure_signed(origin)?;
			let user = Self::load_user(user_address);
			if let Some(contract) = <GetContractByID>::get(&contract_id){
				let sponsor = <GetPlanByID<T>>::get(contract.plan).ok_or(DatDotError::<T>::MissingPlan)?.sponsor;
				ensure!(sponsor == user.id, DatDotError::<T>::MissingChallenge);
				let ranges = contract.ranges;
				let random_chunks = Self::random_from_ranges(ranges);
				let challenge_id = <GetNextChallengeID>::get();
				let challenge = StorageChallenge {
					id: challenge_id.clone(),
					contract: contract_id,
					hoster: hoster_id,
					chunks: random_chunks,
					attestor: None
				};
				<GetChallengeByID>::insert(challenge_id, challenge.clone());
				<GetNextChallengeID>::put(challenge_id.clone()+1);
				Self::give_attestors_jobs(&[], &mut [JobId::StorageChallenge(challenge_id.clone())]);
				if let Some(plan) = <GetPlanByID<T>>::get(contract.plan){
					Self::schedule_challenges(contract_id, hoster_id, plan, &[ChallengeType::StorageChallenge]);
				}
			} else {
				fail!(DatDotError::<T>::MissingContract);
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_storage_challenge(origin, challenge_id: IdType, proofs: Vec<Proof> ){
			let user_address = ensure_signed(origin)?;
			let user = Self::load_user(user_address);
			let mut success: bool = true;
			if let Some(challenge) = <GetChallengeByID>::get(&challenge_id){
				ensure!(user.id == challenge.hoster, DatDotError::<T>::PermissionError);
				for proof in proofs {
					if Self::validate_proof(proof.clone(), challenge.clone()){
						success = success && true;
					} else {
						success = success && false;
					}
				}
				if success {
					Self::deposit_event(Event::ProofOfStorageConfirmed(challenge_id.clone()));
				} else {
					Self::deposit_event(Event::ProofOfStorageFailed(challenge_id.clone()));
				}
			} else {
				fail!(DatDotError::<T>::MissingChallenge);
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn request_performance_challenge(origin, contract_id: IdType, hoster_id: IdType){
			let user_address = ensure_signed(origin)?;
			let user = Self::load_user(user_address);
			//TODO ensure user is sponsor 
			let attestation_id = <GetNextAttestationID>::get();
			let attestation = PerformanceChallenge {
				id: attestation_id.clone(),
				attestors: None,
				contract: contract_id,
				hoster: hoster_id
			};
			<GetPerformanceChallengeByID>::insert(attestation_id, attestation.clone());
			let next_attestation_id : IdType = attestation_id.clone()+1;
			<GetNextAttestationID>::put(next_attestation_id);
			Self::give_attestors_jobs(&mut [], &mut [JobId::PerformanceChallenge(attestation_id)]);
			if let Some(contract) = <GetContractByID>::get(contract_id){
				if let Some(plan) = <GetPlanByID<T>>::get(contract.plan){
					Self::schedule_challenges(contract_id, hoster_id, plan, &[ChallengeType::PerformanceChallenge]);
				}
			}
		}

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_performance_challenge(origin, attestation_id: IdType, reports: Vec<Report>){
			let user_address = ensure_signed(origin)?;
			let mut success: bool = true;
			if let Some(attestation) = <GetPerformanceChallengeByID>::get(&attestation_id){
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
					Self::deposit_event(Event::AttestationReportConfirmed(attestation_id.clone()));
				} else {
					Self::deposit_event(Event::AttestationReportFailed(attestation_id.clone()));
				}
			}
		}
	}
}

/******************************************************************************
  Internal functions
******************************************************************************/


impl<T: Trait> Module<T> {

	fn make_contracts_schedule_amendments(plan: Plan<T::BlockNumber>){
		let contract_ids = Self::make_contracts(plan.clone());
		for contract_id in contract_ids {
			Self::schedule_amendment(plan.clone(), contract_id, None);
		}
	}

	fn schedule_amendment(
		plan: Plan<T::BlockNumber>, 
		contract_id: IdType, 
		amendment_id: Option<IdType>
	){
		if let Some(sponsor) = <GetUserByID<T>>::get(&plan.sponsor){
			let sponsor_origin = RawOrigin::Signed(sponsor.address);
			let call = Call::scheduled_amendment(contract_id);
			//id is (plan_id, contract_id, Some(amendment_id) OR None if no amendments)
			(plan.id, contract_id, amendment_id).using_encoded(
				|id_bytes|{
					T::Scheduler::schedule_named(
						id_bytes.to_vec(),
						DispatchTime::At(plan.from.into()),
						None,
						254,
						sponsor_origin.clone().into(),
						call.into()
					);
				}
			)
		}
	}

	fn make_contracts(plan: Plan<T::BlockNumber>) -> Vec<IdType> {
		let mut contract_ids: Vec<IdType> = plan.feeds.iter().flat_map(|feed_struct|{
			let feed_opt: Option<Feed> = <GetFeedByID>::get(feed_struct.id);
			match feed_opt {
				Some(feed) => {
					let sets = Self::split_main(feed_struct.clone().ranges);
					sets.iter().map(|set|{
						let contract_id : IdType = <GetNextContractID>::get();
						let draft_contract = Contract {
							id: contract_id.clone(),
							plan: plan.id,
							ranges: set.to_vec(),
							active_hosters: Vec::new(),
							amendments: Vec::new(),
							feed: feed_struct.id
						};
						<GetContractByID>::insert(contract_id, draft_contract);
						let next_contract_id : IdType = contract_id.clone()+1;
						<GetNextContractID>::put(next_contract_id);
						contract_id
					}).collect()
				},
				None => {
					Vec::new()
				}
			}
		}).collect();
		// TODO replace draft contracts with complete contracts, add hosters via amendments.
		contract_ids
	}

	fn make_draft_amendment(contract_id: IdType, reuse: Providers) -> Option<IdType> {
		if let Some(mut contract) = <GetContractByID>::get(contract_id) {
			let amendment_id : IdType = <GetNextAmendmentID>::get();
			let amendment = Amendment {
				id: amendment_id,
				providers: reuse,
				contract: contract_id
			};
			contract.amendments.push(amendment_id);
			<GetContractByID>::insert(contract_id, contract);
			<GetAmendmentByID>::insert(amendment_id, amendment);
			let next_amendment_id : IdType = amendment_id+1;
			<GetNextAmendmentID>::put(next_amendment_id);
			Some(amendment_id)
		} else {
			None
		}
	}

	fn add_to_pending_amendments(
		amendment_ids: Vec<IdType>, 
		pending_option: Option<Vec<IdType>>
	){
		//get amendment queue, insert amendments, sort by priority
		let mut current_pending_set: Vec<IdType> = match pending_option {
			Some(item) => {
				item.clone()
			},
			None => {
				PendingAmendments::get()
			}
		};

		let mut new_amendments: Vec<IdType> = amendment_ids.clone();
		current_pending_set.append(&mut new_amendments);
		current_pending_set.sort_unstable_by(Self::amendment_sort_function);
		PendingAmendments::put(current_pending_set);
	}

	fn amendment_sort_function(amendment_a: &IdType, amendment_b: &IdType) -> Ordering {
		let a_cmp : usize = if let Some(a) = <GetAmendmentByID>::get(amendment_a) {
			a.providers.hosters.len() +
			a.providers.encoders.len() +
			a.providers.attestors.len()
		} else {
			0
		};
		let b_cmp : usize = if let Some(b) = <GetAmendmentByID>::get(amendment_b) {
			b.providers.hosters.len() +
			b.providers.encoders.len() +
			b.providers.attestors.len()
		} else {
			0
		};
		b_cmp.cmp(&a_cmp)
	}

	fn try_next_amendments(){
		let mut failed_amendments: Vec<IdType> = Vec::new();
		let mut failed_amendment_count = 0;
		let mut current_draft_amendments: Vec<IdType> = <PendingAmendments>::get();
		for amendment_id in current_draft_amendments.iter_mut().take(T::ContractActivationCap::get() as usize) {
			if let Err(Some(failed_amendment)) = Self::execute_amendment(*amendment_id){
				failed_amendment_count += 1;
				failed_amendments.push(failed_amendment);
			}
		}
		//and try that many MORE contracts, but ONLY ONCE.
		for amendment_id in current_draft_amendments.iter_mut().take(failed_amendment_count){
			if let Err(Some(failed_amendment)) = Self::execute_amendment(*amendment_id){
				failed_amendments.push(failed_amendment);
			}
		}
		Self::add_to_pending_amendments(failed_amendments, Some(current_draft_amendments))
	}

	
	fn execute_amendment(amendment_id: IdType) -> Result<(),Option<IdType>> {
			let amendment_option = <GetAmendmentByID>::get(amendment_id);
			if let Some(mut amendment) = amendment_option {
				if let Some(contract) = <GetContractByID>::get(amendment.contract){
					if let Some(plan) = <GetPlanByID<T>>::get(contract.plan){
						if let Some(providers) = Self::get_providers(plan.clone(), amendment.providers){
							amendment.providers = providers;
							<GetAmendmentByID>::insert(amendment_id, amendment);
							Self::deposit_event(Event::NewAmendment(amendment_id.clone()));
							Ok(())
						} else {
							//insufficient, return to queue
							Err(Some(amendment_id))
						}
					} else {
						Err(None)
					}
			} else {
				//amendment unavailable, do not return to queue
				Err(None)
			}
		} else {
			Err(None)
		}
	}

	fn get_providers(plan: Plan<T::BlockNumber>, reused: Providers) -> Option<Providers> {
		let mut avoid = Self::make_avoid(&plan);
		avoid.append(&mut reused.encoders.clone());
		avoid.append(&mut reused.hosters.clone());
		avoid.append(&mut reused.attestors.clone());
		let mut attestors = Self::select(Role::IdleAttestor, T::AttestorsPerContract::get().into(), |(x,_)|{
			(!avoid.contains(x)) && Self::doesQualify(&plan, x, Role::IdleAttestor)
		});
		avoid.append(&mut attestors.clone());
		if attestors.len() < T::AttestorsPerContract::get() as usize - reused.attestors.len() {
			return None 
		} else {
			let mut hosters = Self::select(Role::IdleHoster, T::HostersPerContract::get().into(), |(x,_)|{
				(!avoid.contains(x)) && Self::doesQualify(&plan, x, Role::IdleHoster)
			});
			avoid.append(&mut hosters.clone());
			if hosters.len() < T::HostersPerContract::get() as usize - reused.hosters.len() { 
				return None 
			} else {
				let mut encoders = Self::select(Role::IdleEncoder, T::EncodersPerContract::get().into(), |(x,_)|{
					(!avoid.contains(x)) && Self::doesQualify(&plan, x, Role::IdleEncoder)
				});
				avoid.append(&mut encoders.clone());
				if encoders.len() < T::EncodersPerContract::get() as usize - reused.encoders.len() { 
					return None 
				} else {
					encoders.append(&mut reused.encoders.clone());
					hosters.append(&mut reused.hosters.clone());
					attestors.append(&mut reused.attestors.clone());
					Some(Providers {
						encoders: encoders,
						hosters: hosters,
						attestors: attestors
					})
				}
			}
		}
	}

	fn doesQualify(plan: &Plan<T::BlockNumber>, user_id: &IdType, role: Role)->bool{
		if let Some(user) = <GetUserByID<T>>::get(user_id){
			let user_role = match role {
				Role::IdleAttestor | Role::Attestor => user.attestor,
				Role::IdleHoster | Role::Hoster => user.hoster,
				Role::IdleEncoder | Role::Encoder => user.encoder,
			};
			if let Some(role_data) = user_role {
				Self::is_schedule_compatible(role_data.form.clone(), plan.clone(), role) &&
				Self::capacity_check(role_data.clone()) 
			} else {
				// if the user is not participating in the role, 
				// does not qualify
				false
			}
		} else {
			false
		}
		// future: geolocation
	}

	fn capacity_check(role_data: ProviderRoleData<T::BlockNumber>) -> bool {
		let storage_used = T::ContractSetSize::get()*65536;
		storage_used <= role_data.idle_storage && role_data.capacity as usize > role_data.jobs.len()
	}

	fn is_idle_now(form: &Form<T::BlockNumber>) -> bool {
		if form.from <= <system::Module<T>>::block_number().into() {
			if let Some(form_until) = form.until {
				form_until >= <system::Module<T>>::block_number().into()
			} else {
				true
			}
		} else {
			false
		}
		
	}

	fn is_schedule_compatible(form: Form<T::BlockNumber>, plan: Plan<T::BlockNumber>, role: Role) -> bool {
		let end_block = match role {
			Role::IdleAttestor | Role::Attestor => {
				<system::Module<T>>::block_number()+T::AttestingDuration::get().into()
			},
			Role::IdleEncoder | Role::Encoder => {
				<system::Module<T>>::block_number()+T::EncodingDuration::get().into()
			},
			Role::IdleHoster | Role::Hoster => {
				if let Some(plan_until_time) = plan.until.time {
					plan_until_time
				} else {
					0.into() //open ended/no end block defined.
				}
			},
		};
		let matches_end = match form.until {
			Some(until) => until >= end_block,
			None => true,
		};
		Self::is_idle_now(&form) && form.from <= plan.from && matches_end
	}

	fn make_avoid(plan: &Plan<T::BlockNumber>) -> Vec<IdType>{
		let mut avoid = Vec::new();
		avoid.push(plan.sponsor);
		for feed_struct in &plan.feeds {
			if let Some(feed) = <GetFeedByID>::get(feed_struct.id){
				avoid.push(feed.publisher.clone());
			}
		}
		avoid
	}

	fn select(select_role: Role, select_amount: usize, select_function: impl Fn((&IdType, &())) -> bool) -> Vec<IdType>{
		<Roles>::iter_prefix(select_role)
			.filter(|(x, y)|{select_function((x, y))})
			.take(select_amount)
			.map(|(x, _)|x)
			.collect()
	}

	fn start_challenges(contract_id: IdType, hoster_id: IdType){
		if let Some(contract) = <GetContractByID>::get(contract_id){
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
		contract_id: IdType,
		hoster_id: IdType,
		plan: Plan<T::BlockNumber>,
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

	fn load_user(account_id: T::AccountId) -> User<T::AccountId, T::BlockNumber> {
			if let Some(user) = <GetUserByKey<T>>::get(&account_id){
				user
			} else {
				let mut user_id = <GetNextUserID>::get();
				let mut new_user = User::<T::AccountId, T::BlockNumber> {
					id: user_id.clone(),
					address: account_id.clone(),
					..User::<T::AccountId, T::BlockNumber>::default()
				};
				Self::save_user(&mut new_user);
				let user_id_counter : IdType = user_id+1;
				<GetNextUserID>::put(user_id_counter);
				new_user
			}
	}

	fn save_user(user: &mut User<T::AccountId, T::BlockNumber>){
		<GetUserByID<T>>::insert(user.id, user.clone());
		<GetUserByKey<T>>::insert(user.clone().address, user.clone());
	}

	fn give_attestors_jobs(
		attestors: &[IdType],
		jobs: &mut [JobId]
	){
		for attestor in attestors {
			<Roles>::insert(Role::IdleAttestor, attestor, ());
		}
		let mut old_job_queue = <GetJobIdQueue>::get();
		let mut job_queue_slice = [old_job_queue.as_mut_slice(), jobs].concat();
		let job_queue = job_queue_slice.iter();
		for job in job_queue.clone() {
			match job {
				JobId::PerformanceChallenge(challenge_id) => {
					// Verify we have a sufficient number of attestors for this challenge type
					let mut attestor_count = 0;
					let mut performance_attestors : Vec<IdType> = Vec::new();
						// emit an attestation request for each performance attestor
					for attestor in <Roles>::iter_prefix(Role::IdleAttestor) {
						attestor_count += 1;
						performance_attestors.push(attestor.0);
						if attestor_count > T::PerformanceAttestorCount::get().into(){
							<Roles>::remove(Role::IdleAttestor, attestor.0);
							if let Some(mut challenge) = <GetPerformanceChallengeByID>::get(&challenge_id){
								challenge.attestors = Some(performance_attestors);
								<GetPerformanceChallengeByID>::insert(&challenge_id, challenge);
							}
							Self::deposit_event(Event::NewPerformanceChallenge(challenge_id.clone()));
							break;
						}
					}
				},
				JobId::StorageChallenge(challenge_id) => {
					if let Some(attestor) = <Roles>::iter_prefix(Role::IdleAttestor).next(){
						<Roles>::remove(Role::IdleAttestor, attestor.0);
						if let Some(mut challenge) = <GetChallengeByID>::get(&challenge_id){
							challenge.attestor = Some(attestor.0);
							<GetChallengeByID>::insert(&challenge_id, challenge);
						}
						Self::deposit_event(Event::NewStorageChallenge(challenge_id.clone()));
						break;
					}
				},
				_ => {
					//TODO, check.
				}
			}
		}
		<GetJobIdQueue>::put(
			job_queue.collect::<Vec<&JobId>>()
		);
	}

	fn random_from_ranges(ranges: Ranges<ChunkIndex>) -> Vec<ChunkIndex>{
		//TODO, currently only returns first chunk of every available range,
		//should return some random selection.
		ranges.iter().map(|x|x.0).collect()
		//todo, get rng from 0->set_size-1, get a single random index based on that.
	}

	fn validate_proof(proof: Proof, challenge: StorageChallenge) -> bool {
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

	fn get_random_of_role(influence: &[u8], role: &Role, count: u32) -> Vec<IdType> {
		let members : Vec<IdType> = <Roles>::iter_prefix(role).filter_map(|x|{
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
