#![cfg_attr(not(feature = "std"), no_std)]
/// A runtime module template with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references


/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/srml/example/src/lib.rs
use sp_std::prelude::*;
use sp_std::fmt::Debug;
use frame_support::{
	decl_module,
	decl_storage, 
	decl_event,
	decl_error,
	debug::native,
	dispatch,
	ensure,
	fail,
	Parameter,
	storage::{
		StorageMap,
		StorageValue,
		IterableStorageMap
	},
	traits::{
		EnsureOrigin,
		Get,
		Randomness,
		ChangeMembers,
	},
	weights::{
		SimpleDispatchInfo,
		Weight,
	},
};
use sp_std::convert::{
	TryInto, TryFrom
};
use frame_system::{
	self as system,
	ensure_signed,
	ensure_root,
	offchain
};
use codec::{Encode, Decode, Output};
use sp_core::{
	ed25519,
	Hasher,
	H256,
	H512,
	convert_hash,
};
use core::mem;
use sp_runtime::{
	RuntimeDebug,
	DispatchError,
	traits::{
		Verify,
		CheckEqual,
		Dispatchable,
		StaticLookup,
		SimpleBitOps,
		MaybeDisplay,
		TrailingZeroInput,
		MaybeSerializeDeserialize,
		Member
	},
	transaction_validity::{
		TransactionValidity,
		TransactionLongevity,
		ValidTransaction,
		InvalidTransaction
	}
};
use sp_io::hashing::blake2_256;
use rand_chacha::{rand_core::{RngCore, SeedableRng}, ChaChaRng};

pub type Public = ed25519::Public;
pub type Signature = ed25519::Signature;

/// The module's configuration trait.
pub trait Trait: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	type Hash: 
	Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + SimpleBitOps
	+ Default + Copy + CheckEqual + sp_std::hash::Hash + AsRef<[u8]> + AsMut<[u8]>;
	type Randomness: Randomness<<Self as system::Trait>::Hash>;
	type ForceOrigin: EnsureOrigin<<Self as system::Trait>::Origin>;
	type Proposal: Parameter + Dispatchable<Origin=Self::Origin>;
	type AttestorsPerChallenge: Get<u32>;
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
		for i in 0..Self::highest_at_index(highest_index)+1 {
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


//https://datprotocol.github.io/how-dat-works/#hashes-and-signatures
#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct ChunkHashPayload {
	hash_type: u8, //0
	chunk_length: u64,
	chunk_content: Vec<u8>
}


#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct ParentHashPayload {
	hash_type: u8, //1
	total_length: u64,
	child_hashes: [H256; 2]
}


#[derive(Decode, PartialEq, Eq, Encode, Clone, Copy, RuntimeDebug)]
pub struct ParentHashInRoot {
	hash: H256,
	hash_number: u64,
	total_length: u64
}


#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct RootHashPayload {
	hash_type: u8, //2
	children: Vec<ParentHashInRoot>
}

trait HashPayload where Self: Sized + Encode {
	fn hash(&self) -> H256 {
		self.using_encoded(|b|{
			native::info!("Hash Payload: {:x?}", b);
			blake2_256(b).into()
		})
	}
}

impl HashPayload for RootHashPayload {
	//hackish manual manipulation of the bits being hashed.
	//made using trial-and-error. lots of memcpy. loop. kill it with fire.
	fn hash(&self) -> H256 {
		self.using_encoded(|dirtybits|{
			native::info!("Root Hash Dirty Payload [{:#?}]: {:x?}", dirtybits.len(), dirtybits);
			let mut dirtycopy = dirtybits.to_vec();
			let mut x = 2;
			let mut bits : Vec<u8> = Vec::new();
			bits.push(*dirtycopy.get(0).expect(""));
			loop{
				let pt1 = dirtycopy.get(x+0..x+32).expect("");
				let mut pt2: &mut [u8; 8] = &mut [0,0,0,0,0,0,0,0];
				pt2.copy_from_slice(dirtycopy.get(x+32..x+40).expect(""));
				pt2.reverse();
				let mut pt3: &mut [u8;8] = &mut [0,0,0,0,0,0,0,0];
				pt3.copy_from_slice(dirtycopy.get(x+40..x+48).expect(""));
				pt3.reverse();
				let mut newbits = [
					pt1,
					pt2,
					pt3
				].concat();
				x += 48;
				bits.extend_from_slice(&mut newbits);
				match dirtybits.get(x) {
					Some(_) => (),
					None => break,
				}
			};
			native::info!("Root Hash Clean Payload [{:#?}]: {:x?}", bits.len(), bits);
			blake2_256(bits.as_slice()).into()
		})
	}
}
impl HashPayload for ParentHashPayload {
	fn hash(&self) -> H256 {
		self.using_encoded(|b|{
			native::info!("Parent Hash Payload Dirty [{:x?}]: {:x?}", b.len(), b);
			let mut dirtycopy = b.to_vec();
			let mut cleanbits: Vec<u8> = Vec::new();
			let mut hash_type = dirtycopy.get(0..1).expect("");
			let mut total_length = &mut [0,0,0,0,0,0,0,0];
			total_length.copy_from_slice(dirtycopy.get(1..9).expect(""));
			total_length.reverse();

			native::info!("Child nodes raw: {:x?}", dirtycopy.get(9..).expect(""));
			cleanbits.extend_from_slice(hash_type);
			cleanbits.extend_from_slice(total_length);
			native::info!("Parent Hash Payload [{:x?}]: {:x?}", b.len(), b);
			blake2_256(cleanbits.as_slice()).into()
		})
	}
}
impl HashPayload for ChunkHashPayload {
	fn hash(&self) -> H256 {
		self.using_encoded(|b|{
			native::info!("Chunk Hash Payload: {:x?}", b);
			let mut dirtycopy = b.to_vec();
			let mut cleanbits: Vec<u8> = Vec::new();
			let mut hash_type = dirtycopy.get(0..1).expect("");
			let mut total_length = &mut [0,0,0,0,0,0,0,0];
			total_length.copy_from_slice(dirtycopy.get(1..9).expect(""));
			total_length.reverse();

			native::info!("Child nodes raw: {:x?}", dirtycopy.get(9..).expect(""));
			cleanbits.extend_from_slice(hash_type);
			cleanbits.extend_from_slice(total_length);
			blake2_256(cleanbits.as_slice()).into()
		})
	}
}

#[derive(Default, Decode, PartialEq, Eq, Encode, Clone, Copy, RuntimeDebug)]
pub struct Attestation {
	//todo, actually decide format
	location: u8,
	latency: Option<u8> //may be failure.
}

#[derive(Default, Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct ChallengeAttestations {
	expected_attestors: Vec<u64>,
	expected_friends: Vec<u64>,
	seen: Vec<(u64, Attestation)>
}

type DatIdIndex = u64;
type DatIdVec = Vec<DatIdIndex>;
type UserIdIndex = u64; 
type DatSize = u64;


decl_event!(
	pub enum Event<T> 
	where
	AccountId = <T as system::Trait>::AccountId,
	BlockNumber = <T as system::Trait>::BlockNumber 
	{
		SomethingStored(DatIdIndex, Public),
		SomethingUnstored(DatIdIndex, Public),
		Challenge(AccountId,BlockNumber),
		ChallengeFailed(AccountId, Public),
		NewPin(AccountId, Public),
		Attest(AccountId, Attestation),
		AttestPhase(bool, u64),
	}
);

decl_error! {
    pub enum Error for Module<T: Trait> {
		/// The call was made with an incorrect account
		PermissionError,
		/// Potentially valid merkle proof, no signature present
		UnsignedProof,
		/// Signature verification failed
		VerificationFailed,
		/// Potentially valid merkle proof, proves wrong index
		ProvesWrongChunk,
		/// Potentially valid merkle proof, no chunk provided
		MissingLeaf,
		/// Chunk hash does not match expected value
		ChunkHashVerificationFailed,
		/// Root hash does not match expected value
		RootHashVerificationFailed,
		/// Chain state is invalid - requires manual intervention
		InvalidState,
		/// declared tree size is invalid
		InvalidTreeSize,
    }
}


// Dat related storage items.
decl_storage! {
	trait Store for Module<T: Trait> as DatVerify {
		// A vec of free indeces, with the last item usable for `len`
		pub DatId get(next_id): DatIdVec;
		// Each dat archive has a public key
		pub DatKey get(public_key): map hasher(twox_64_concat) DatIdIndex => Public;
		// Each dat archive has a tree size
		// TODO: remove calls to this when expecting indeces
		pub TreeSize get(tree_size): map hasher(twox_64_concat) Public => DatSize;
		// each dat archive has a merkle root
		pub MerkleRoot get(merkle_root): map hasher(twox_64_concat) Public => (H256, Signature);
		// vec of occupied user indeces for when users are removed.
		pub UsersCount: Vec<u64>;
		// users are put into an "array"
		pub Users get(user): map hasher(twox_64_concat) UserIdIndex => T::AccountId;
		// each user has a vec of dats they seed
		pub UsersStorage: map hasher(twox_64_concat) T::AccountId => Vec<DatIdIndex>;
		// each dat has a vec of users pinning it
		pub DatHosters: map hasher(twox_64_concat) Public => Vec<T::AccountId>;
		// each user has a mapping and vec of dats they want seeded
		pub UserRequestsMap: map hasher(twox_64_concat) Public => T::AccountId;

		// current check condition
		pub ChallengeIndex: u64;
		pub UserIndex: u64;
		// Challenge => User
		pub ChallengeMap: map hasher(twox_64_concat) u64 => u64;
		// Dat and which index to verify, and deadline
		pub SelectedChallenges: map hasher(twox_64_concat) u64 => (Public, u64, T::BlockNumber);
		pub RemovedDats: Vec<Public>;
		pub SelectedUsers: map hasher(twox_64_concat) u64 => T::AccountId;
		// (index, challenge count)
		pub SelectedUserIndex: map hasher(twox_64_concat) T::AccountId => (u64, u64);
		pub Nonce: u64;

		// all attestors
		pub Attestors get(atts): map hasher(twox_64_concat) UserIdIndex => T::AccountId;
		// vec of occupied attestor indeces for when attestors are removed.
		pub AttestorsCount: Vec<u64>;
		// non-friend, randomly-selectable attestors.
		pub ActiveAttestors: Vec<u64>;
		// challenge => ([expected attestors], [rewarded friends], [seen attestations])
		pub ChallengeAttestors: map hasher(twox_64_concat) u64 => ChallengeAttestations;
	}
}

decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;
		
		fn deposit_event() = default;
		const AttestorsPerChallenge: u32 = T::AttestorsPerChallenge::get();

		#[weight = SimpleDispatchInfo::default()]
		fn force_clear_challenge(origin, account: T::AccountId, challenge_index: u64){
			T::ForceOrigin::try_origin(origin)
				.map(|_| ())
				.or_else(ensure_root)?; 
			Self::clear_challenge(account, challenge_index);
			
		}
		

		//test things progressively, doing quicker computations first.
		//gutted temporarily to demonstrate datdot flow.
		//we should manually verify proof from raw bits.
		#[weight = SimpleDispatchInfo::default()]
		fn submit_proof(origin, challenge_index: u64, proof: Vec<u8>) {
			let account = ensure_signed(origin)?;
			// TODO - verify proof!
			Self::clear_challenge(account, challenge_index);
		}


		/// Submit or update a piece of data that you want to have users copy, optionally provide chunk for execution.
		#[weight = SimpleDispatchInfo::default()]
		fn register_data(origin, merkle_root: (Public, RootHashPayload, H512)) {
			let account = ensure_signed(origin)?;
			let pubkey = merkle_root.0;
			let root_hash_children = merkle_root.clone().1.children;
			let root_hash_sanitized_payload = RootHashPayload {
				hash_type: 2,
				children: root_hash_children,
			};
			let root_hash = root_hash_sanitized_payload.hash();
			let sig = Signature::from_h512(merkle_root.2);
			native::info!("Register Data Merkle Root: {:x?}", merkle_root);
			native::info!("Register Data Merkle Root Hash: {:x?}", root_hash);
			//FIXME: we don't currently verify if we are updating to a newer root from an older one.
			//verify the signature
			ensure!(
				sig.verify(
					root_hash.as_bytes(),
					&pubkey
				),
				Error::<T>::VerificationFailed
			);
			Self::forced_register_data(account, merkle_root)
		}

		//debug method when you don't have valid data for register_data, no validity checks, only root.
		#[weight = SimpleDispatchInfo::default()]
		fn force_register_data(
			origin,
			account: T::AccountId,
			merkle_root: (Public, RootHashPayload, H512)
		)
		{
			T::ForceOrigin::try_origin(origin)
				.map(|_| ())
				.or_else(ensure_root)?;
			Self::forced_register_data(account, merkle_root)
		}

		//user stops requesting others pin their data
		#[weight = SimpleDispatchInfo::default()]
		fn unregister_data(origin, index: DatIdIndex){
			let account = ensure_signed(origin)?;
			let pubkey = <DatKey>::get(index);
			//only allow owner to unregister
			ensure!(
				<UserRequestsMap<T>>::get(&pubkey) == account,
				Error::<T>::PermissionError
			);
			let mut dat_vec = <DatId>::get();
			match dat_vec.last() {
				Some(last_index) => {
					if index == last_index - 1 {
						dat_vec.pop();
					}
					dat_vec.push(index);
					dat_vec.sort_unstable();
					dat_vec.dedup();
					<DatId>::put(dat_vec);
				},
				None => (),
			}
			<DatHosters<T>>::get(&pubkey)
				.iter()
				.for_each(|account| {
					let mut storage : Vec<DatIdIndex> =
						<UsersStorage<T>>::get(account.clone());
					match storage.binary_search(&index).ok() {
						Some(index) => {storage.remove(index);},
						None => (),
					}
					<UsersStorage<T>>::insert(account.clone(), &storage);
				});
			<DatHosters<T>>::remove(&pubkey);
			<DatKey>::remove(&index);
			<UserRequestsMap<T>>::remove(&pubkey);
			<TreeSize>::remove(&pubkey);
			<MerkleRoot>::remove(&pubkey);
			//if the dat being unregistered is currently part of the challenge
			let mut tmp = match <RemovedDats>::try_get() {
				Ok(expr) => expr,
				Err(_) => Vec::new(),
			};
			tmp.push(pubkey);
			<RemovedDats>::put(tmp);
			Self::deposit_event(RawEvent::SomethingUnstored(index, pubkey));
		}


		#[weight = SimpleDispatchInfo::default()]
		fn register_attestor(origin){
			let account = ensure_signed(origin)?;
			let mut att_count = <AttestorsCount>::get();
			let last = att_count.last();
			match last {
				Some(last_index) => {
					let user_index_option = att_count.pop();
					let current_user_index = match user_index_option {
						Some(x) => x,
						None => 0,
					};
					match current_user_index.checked_add(1){
						Some(i) => {
							<Attestors<T>>::insert(&i, &account);
							let mut atts = <AttestorsCount>::get();
							atts.push(i);
							<AttestorsCount>::put(atts);
							<ActiveAttestors>::mutate(|mut att_vec|{
								att_vec.push(i);
								att_vec.sort_unstable();
								att_vec.dedup();
							});
						},
						None => (),
					}
				},
				None => (),
			}
		}

		#[weight = SimpleDispatchInfo::default()]
		fn submit_attestation(origin, challenge_index: u64, attestation: Attestation) {
			let attestor = ensure_signed(origin)?;
			let mut challenge : ChallengeAttestations = <ChallengeAttestors>::get(challenge_index);
			let mut attestor_index;
			for (user_index, user_account) in <Attestors<T>>::iter(){
				if user_account == attestor {
					attestor_index = user_index;
				match challenge.expected_attestors.binary_search(&attestor_index) {
					Ok(index) => {
						challenge.expected_attestors.remove(index);
						challenge.seen.push((attestor_index, attestation));
					},
					Err(_) => (),
				}
				match challenge.expected_friends.binary_search(&attestor_index) {
					Ok(index) => {
						challenge.expected_friends.remove(index);
						challenge.seen.push((attestor_index, attestation));
					},
					Err(_) => (),
				}
				Self::deposit_event(RawEvent::Attest(attestor, attestation));
				break;
				}
			}
		}

		#[weight = SimpleDispatchInfo::default()]
		fn unregister_attestor(origin){
			let account = ensure_signed(origin)?;
			for (user_index, user_account) in <Attestors<T>>::iter(){
				if user_account == account {
					<Attestors<T>>::remove(user_index);
					let mut user_indexes = <AttestorsCount>::get();
					match user_indexes.binary_search(&user_index){
						Ok(i) => {
							user_indexes.remove(i);
							<ActiveAttestors>::mutate(|mut att_vec|{
								match att_vec.binary_search(&user_index){
									Ok(e) => {
										att_vec.remove(e);
									},
									_ => (),
								}
								att_vec.sort_unstable();
								att_vec.dedup();
							});
						},
						_ => (),
					}
					if user_indexes.len() > 0 {
						<AttestorsCount>::put(user_indexes);
					} else {
						<AttestorsCount>::kill();
					}
				}
			}
		}

		
		// User requests a dat for them to pin. FIXME: May return a dat they are already pinning.
		#[weight = SimpleDispatchInfo::default()]
		fn register_seeder(origin) {
			//TODO: bias towards unseeded dats and high incentive
			let account = ensure_signed(origin)?;
			let dat_vec = <DatId>::get();
			let last = dat_vec.last();
			native::info!("Last Dat Index: {:#?}", last);
			match last {
				Some(last_index) => {
				let nonce = <Nonce>::get();
				let new_random = (T::Randomness::random(b"dat_verify_register"), &nonce, &account)
					.using_encoded(|mut b| u64::decode(&mut b))
					.expect("hash must be of correct size; Qed");
				let random_index = new_random % last_index;
				let dat_pubkey = DatKey::get(&random_index);
				let mut current_user_dats = <UsersStorage<T>>::get(&account);
				let mut dat_hosters = <DatHosters<T>>::get(&dat_pubkey);
				current_user_dats.push(random_index);
				current_user_dats.sort_unstable();
				current_user_dats.dedup();
				dat_hosters.push(account.clone());
				dat_hosters.sort_unstable();
				dat_hosters.dedup();
				<DatHosters<T>>::insert(&dat_pubkey, &dat_hosters);
				<UsersStorage<T>>::insert(&account, &current_user_dats);
				<Nonce>::mutate(|m| *m += 1);
				if(current_user_dats.len() == 1){
					let user_index_option = <UsersCount>::get().pop();
					let current_user_index = match user_index_option {
						Some(x) => x,
						None => 0,
					};
					match current_user_index.checked_add(1){
						Some(i) => {
							<Users<T>>::insert(&i, &account);
							let mut users = <UsersCount>::get();
							users.push(i);
							<UsersCount>::put(users);
						},
						None => (),
					}
				}
				native::info!("NewPin; Account: {:#?}", account);
				native::info!("NewPin; Pubkey: {:#?}", dat_pubkey);
				Self::deposit_event(RawEvent::NewPin(account, dat_pubkey));
				},
				None => {
					
				},
			}
		} 


		#[weight = SimpleDispatchInfo::default()]
		fn unregister_seeder(origin) {
			let account = ensure_signed(origin)?;
			for dat_id in <UsersStorage<T>>::get(&account) {
				let dat_key = <DatKey>::get(dat_id);
				let mut hosters = <DatHosters<T>>::get(&dat_key);
				hosters.sort_unstable();
				match hosters.binary_search(&account) {
					Ok(index) => {
						hosters.remove(index);
					},
					_ => (),
				}
				<DatHosters<T>>::insert(dat_key, hosters);
			}
			for (user_index, user_account) in <Users<T>>::iter(){
				if user_account == account {
					<Users<T>>::remove(user_index);
					let mut user_indexes = <UsersCount>::get();
					match user_indexes.binary_search(&user_index){
						Ok(i) => {
							user_indexes.remove(i);
						},
						_ => (),
					}
					if user_indexes.len() > 0 {
						<UsersCount>::put(user_indexes);
					} else {
						<UsersCount>::kill();
					}
				}
			}
			<UsersStorage<T>>::remove(account);
		}

		/*
		fn on_initialize(n: T::BlockNumber) => Weight {
			let dat_vec : Vec<DatIdIndex> = <DatId>::get();
			let challenge_index = <ChallengeIndex>::get();
			let valid_users = <UsersCount>::get();
			let valid_users_len = valid_users.len();
			
			match dat_vec.last() {
				Some(last_index) => {
			// if no one is currently selected to give proof, select someone if someone exists to select
			if !<ChallengeMap>::contains_key(&challenge_index) && valid_users_len > 0 {
				let nonce = <Nonce>::get();
				let new_random = (T::Randomness::random(b"dat_verify_init"), nonce)
				.using_encoded(|mut b| u64::decode(&mut b))
				.expect("hash must be of correct size; Qed");
				let new_time_limit = new_random % last_index;
				let challenge_length = new_time_limit.try_into().unwrap_or(2) + 1;
				let future_block = 
					n + T::BlockNumber::from(challenge_length);
				let selected_user = (new_random as usize % valid_users_len);
				let random_user_index = valid_users.get(selected_user)
					.expect("the remainder is always in bounds when % len");
				let random_user = <Users<T>>::get(random_user_index);
				let users_dats = <UsersStorage<T>>::get(&random_user);
				let users_dats_len = users_dats.len();
				let random_dat_id = users_dats.get(new_random as usize % users_dats_len)
					.expect("the remainder is always in bounds when % len");
				let random_dat = <DatKey>::get(random_dat_id);
				let dat_tree_len = <TreeSize>::get(&random_dat);
				let mut random_leave = 0;
				if dat_tree_len != 0 { // avoid 0 divisor 
					random_leave = new_random % dat_tree_len;
				} 
				let y : u64;
				if <SelectedUserIndex<T>>::contains_key(&random_user) {
					let (user_index, count) = <SelectedUserIndex<T>>::get(&random_user);
					<SelectedUserIndex<T>>::insert(&random_user, (user_index, count+1));
					y = user_index;
				} else {	
					let user_index = <UserIndex>::get();
					<SelectedUserIndex<T>>::insert(&random_user, (user_index, 1));
					<UserIndex>::put(<UserIndex>::get() + 1);
					y = user_index;
				}
				<SelectedChallenges<T>>::insert(&challenge_index, (random_dat, random_leave, future_block));
				<SelectedUsers<T>>::insert(&y, &random_user);
				<ChallengeMap>::insert(challenge_index, y);
				<Nonce>::put(<Nonce>::get() + 1);
				<ChallengeIndex>::put(<ChallengeIndex>::get() + 1);
				Self::deposit_event(RawEvent::Challenge(random_user, future_block));
			}},
				None => (),
			}
			SimpleDispatchInfo::default().weigh_data(())
		}
		*/

		//TODO: this is probably bad and should probably go into an offchain worker
		fn on_finalize(n: T::BlockNumber) {
			for (challenge_index, user_index) in <ChallengeMap>::iter() {
				let user = <SelectedUsers<T>>::get(user_index);
				let dat = <SelectedChallenges<T>>::get(challenge_index).0;
				let time = <SelectedChallenges<T>>::get(challenge_index).2;
				let attesting = <ChallengeAttestors>::contains_key(challenge_index);
				if (n == time) {
					if attesting {
						<SelectedChallenges<T>>::remove(challenge_index);
						<ChallengeMap>::remove(challenge_index);
						Self::punish_seeder(user.clone());
						Self::deposit_event(RawEvent::ChallengeFailed(user, dat));
					} else {
						<ChallengeAttestors>::insert(challenge_index, Self::get_attestors_for(challenge_index));
						Self::deposit_event(RawEvent::AttestPhase(false, challenge_index));
					}
				} else {
					if <RemovedDats>::get().contains(&dat) {
						Self::clear_challenge(user, challenge_index);
					}
					//todo charge fee*
				}
				//todo - iterate through attestations
			}
			<RemovedDats>::kill();
		}
	}
}

impl<T: Trait> Module<T> {

	fn get_attestors_for(challenge_index: u64) -> ChallengeAttestations{
		let attestors = <ChallengeAttestors>::get(challenge_index);
		if attestors.expected_attestors.len() > 0{
			return attestors
		} else {
			return ChallengeAttestations {
				expected_attestors: Self::get_random_attestors(),
				expected_friends: attestors.expected_friends,
				seen: attestors.seen,
			}
		}
	}

	fn clear_challenge(account: T::AccountId, challenge_index: u64){
		let account_index = <ChallengeMap>::get(&challenge_index);
			let (_, count) = <SelectedUserIndex<T>>::get(&account);
			match count {
				1 => {	
					<SelectedUsers<T>>::remove(account_index);
					<SelectedUserIndex<T>>::remove(account);
				},
				_ => <SelectedUserIndex<T>>::insert(account, (account_index, count-1))
			}
			<SelectedChallenges<T>>::remove(challenge_index);
			<ChallengeMap>::remove(challenge_index);
	}

	fn punish_seeder(punished: T::AccountId) {
		let user_tuple = <SelectedUserIndex<T>>::take(&punished);
		match user_tuple.1 {
			1 => <SelectedUsers<T>>::remove(user_tuple.0),
			_ => {
					<SelectedUserIndex<T>>::mutate(
						&punished,
						|tuple|{
							let el1 = tuple.0.clone();
							let el2 = tuple.1-1;
							*tuple = (el1, el2);
						});
					()
				},
		};
		/* disabled while punishment is determined
		let inner_origin =
		system::RawOrigin::Signed(punished.clone());
		Self::unregister_seeder(inner_origin.into());
		// todo: punish seeder.
		*/
	}


	fn reward_seeder(rewarded: T::AccountId) {
		//todo
	}

	fn forced_register_data(
		account: T::AccountId,
		merkle_root: (Public, RootHashPayload, H512)
	)
	{
		let pubkey = merkle_root.0;
		let sig = Signature::from_h512(merkle_root.2);
		let mut lowest_free_index : DatIdIndex = 0;
		let mut tree_size : u64 = u64::min_value();
		let root_hash = merkle_root.1.hash(); //todo: do not calculate twice!
		for child in merkle_root.1.children {
			tree_size += child.total_length;
		}
		native::info!("{:#?}", tree_size);
		let mut dat_vec : Vec<DatIdIndex> = <DatId>::get();
		match <MerkleRoot>::contains_key(&pubkey){
			true => (),
			false => {
				match dat_vec.first() {
					Some(_) => {
						dat_vec.sort_unstable();
						lowest_free_index = dat_vec.remove(0);
						dat_vec.push(lowest_free_index + 1);
						dat_vec.sort_unstable();
						dat_vec.dedup();
					},
					None => {
						//add an element if the vec is empty
						dat_vec.push(1);
						lowest_free_index = 1;
					},
				}
				//register new unknown dats
				<DatKey>::insert(&lowest_free_index, &pubkey)
			},
		}
		<MerkleRoot>::insert(&pubkey, (root_hash, sig));
		<DatId>::put(dat_vec);
		<TreeSize>::insert(&pubkey, tree_size);
		<UserRequestsMap<T>>::insert(&pubkey, &account);
		Self::deposit_event(RawEvent::SomethingStored(lowest_free_index, pubkey));
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

	fn get_random_attestors() -> Vec<u64> {
		let nonce = <Nonce>::get();
		let mut random_select: Vec<u64> = Vec::new();
		let seed = (T::Randomness::random(b"dat_random_attestors"), nonce)
			.using_encoded(|b| <[u8; 32]>::decode(&mut TrailingZeroInput::new(b)))
			.expect("input is padded with zeroes; qed");
		let members = <ActiveAttestors>::get();
		let mut rng = ChaChaRng::from_seed(seed);
		let pick_attestor = |_| Self::pick_item(&mut rng, &members[..]).expect("exited if members empty; qed");
		for attestor in (0..T::AttestorsPerChallenge::get()).map(pick_attestor){
			random_select.push(*attestor);
		}
		random_select
	}

}