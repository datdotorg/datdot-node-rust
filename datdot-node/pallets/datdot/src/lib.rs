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
use codec::{Encode, Decode};
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
	type ForceOrigin: EnsureOrigin<<Self as system::Trait>::Origin>;
	type AttestorsPerChallenge: Get<u32>;
	type ChallengeDelay: Get<u32>;
	type Proposal: Parameter + Dispatchable<Origin=Self::Origin> + From<Call<Self>>;
	type Scheduler: ScheduleNamed<Self::BlockNumber, Self::Proposal>;
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
pub struct TreeHashPayload {
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

impl HashPayload for TreeHashPayload {
	//hackish manual manipulation of the bits being hashed.
	//made using trial-and-error. lots of memcpy. loop. kill it with fire.
	fn hash(&self) -> H256 {
		self.using_encoded(|dirtybits|{
			native::info!("Root Hash Dirty Payload [{:#?}]: {:x?}", dirtybits.len(), dirtybits);
			let dirtycopy = dirtybits.to_vec();
			let mut x = 2;
			let mut bits : Vec<u8> = Vec::new();
			bits.push(*dirtycopy.get(0).expect(""));
			loop{
				let pt1 = dirtycopy.get(x+0..x+32).expect("");
				let pt2: &mut [u8; 8] = &mut [0,0,0,0,0,0,0,0];
				pt2.copy_from_slice(dirtycopy.get(x+32..x+40).expect(""));
				pt2.reverse();
				let pt3: &mut [u8;8] = &mut [0,0,0,0,0,0,0,0];
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
			let dirtycopy = b.to_vec();
			let mut cleanbits: Vec<u8> = Vec::new();
			let hash_type = dirtycopy.get(0..1).expect("");
			let total_length = &mut [0,0,0,0,0,0,0,0];
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
			let dirtycopy = b.to_vec();
			let mut cleanbits: Vec<u8> = Vec::new();
			let hash_type = dirtycopy.get(0..1).expect("");
			let total_length = &mut [0,0,0,0,0,0,0,0];
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
	completed: Vec<(u64, Attestation)>
}

type DatIdIndex = u64;
type DatIdVec = Vec<DatIdIndex>;
type UserIdIndex = u64; 
type DatSize = u64;

/// encoded: SortedVec<(ChunkIndex, EncoderId)>,
/// state: State,
#[derive(Default, Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
struct HostedArchive {
	encoded: Vec<(u64, u64)>,
    encoding: Vec<(u64, u64)>,
    state: BTreeMap<u64, Challenge>, //K = chunk index
}

///	Active(blockNumber),
///	Attesting(ChallengeAttestations),
#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
enum Challenge {
	Active(u64),
	Attesting(ChallengeAttestations),
}

decl_event!(
	pub enum Event<T> 
	where
	AccountId = <T as system::Trait>::AccountId
	{
		SomethingStored(DatIdIndex, Public),
		SomethingUnstored(DatIdIndex, Public),
		Challenge(AccountId, Public),
		//user index, dat index
		ChallengeFailed(u64, u64),
		NewPin(u64, u64, u64),
		Attest(AccountId, Attestation),
		AttestPhase(u64, u64, ChallengeAttestations),
		//user index, dat index
		ChallengeSuccess(u64, u64),
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
		/// hoster/hosted pair does not exist
		InvalidChallenge,
    }
}


// Dat related storage items.
decl_storage! {
	trait Store for Module<T: Trait> as DatVerify {
		// A vec of free indeces, with the last item usable for `len`
		pub DatId get(fn next_id): DatIdVec;
		// Each dat archive has a public key
		pub DatKey get(fn public_key): map hasher(twox_64_concat) DatIdIndex => Public;
		// Each dat archive has a tree size
		// TODO: remove calls to this when expecting indeces
		pub TreeSize get(fn tree_size): map hasher(twox_64_concat) Public => DatSize;
		// each dat archive has a merkle root
		pub MerkleRoot get(fn merkle_root): map hasher(twox_64_concat) Public => (H256, Signature);
		// vec of occupied user indeces for when users are removed.
		pub UsersCount: Vec<u64>;
		// users are put into an "array"
		pub Users get(fn user): map hasher(twox_64_concat) UserIdIndex => T::AccountId;
		pub UserIndices get(fn user_id): map hasher(twox_64_concat) T::AccountId => UserIdIndex;
		// each user has a mapping and vec of dats they want seeded
		pub UserRequestsMap: map hasher(twox_64_concat) Public => T::AccountId;
		pub UserIndex: u64;
		// hoster, archive => HostedArchive
		pub HostedMap: double_map hasher(twox_64_concat) u64, hasher(twox_64_concat) u64 => HostedArchive;
		//Attestors
		pub Attestors get(fn atts): map hasher(twox_64_concat) UserIdIndex => T::AccountId;
		pub AttestorsCount: Vec<u64>;
		pub ActiveAttestors: Vec<u64>;
		//Encoders
		pub Encoders get(fn encs): map hasher(twox_64_concat) UserIdIndex => T::AccountId;
		pub EncodersCount: Vec<u64>;
		pub ActiveEncoders: Vec<u64>;
		pub Nonce: u64;
	}
}

decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;
		
		fn deposit_event() = default;
		const AttestorsPerChallenge: u32 = T::AttestorsPerChallenge::get();
		const ChallengeDelay: u32 = T::ChallengeDelay::get();

		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn force_clear_challenge(origin, user_index: u64, dat_index: u64, chunk_index: u64){
			T::ForceOrigin::try_origin(origin)
				.map(|_| ())
				.or_else(ensure_root)?; 
			Self::clear_challenge(user_index, dat_index, chunk_index);
		}
		

		//test things progressively, doing quicker computations first.
		//gutted temporarily to demonstrate datdot flow.
		//we should manually verify proof from raw bits.
		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_proof(origin, dat_index: u64, chunk_index:u64, _proof: Vec<u8>) {
			let account = ensure_signed(origin)?;
			let user_index = <UserIndices<T>>::get(&account);
			
			// TODO - verify proof!
			if let Some(challenge_attestors) = Self::update_attestors_for(user_index, dat_index, chunk_index){
				Self::deposit_event(RawEvent::AttestPhase(user_index, dat_index, challenge_attestors));
				Self::clear_challenge(user_index, dat_index, chunk_index);
			} else {
				fail!(Error::<T>::InvalidChallenge)
			}
		}


		/// Submit or update a piece of data that you want to have users copy, optionally provide chunk for execution.
		#[weight = (100000, Pays::No)]
		fn register_data(origin, merkle_root: (Public, TreeHashPayload, H512)) {
			let account = ensure_signed(origin)?;
			let pubkey = merkle_root.0;
			let root_hash_children = merkle_root.clone().1.children;
			let root_hash_sanitized_payload = TreeHashPayload {
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
		#[weight = (100000, Pays::No)]
		fn force_register_data(
			origin,
			account: T::AccountId,
			merkle_root: (Public, TreeHashPayload, H512)
		)
		{
			T::ForceOrigin::try_origin(origin)
				.map(|_| ())
				.or_else(ensure_root)?;
			Self::forced_register_data(account, merkle_root)
		}

		//user stops requesting others pin their data
		#[weight = (100000, Pays::No)]
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
			<DatKey>::remove(&index);
			<UserRequestsMap<T>>::remove(&pubkey);
			<TreeSize>::remove(&pubkey);
			<MerkleRoot>::remove(&pubkey);
			//inefficient - fixme later.
			for (hoster_index, dat_index, _) in <HostedMap>::iter() {
				if dat_index == index {
					<HostedMap>::remove(hoster_index, dat_index);
				}
			}
			Self::deposit_event(RawEvent::SomethingUnstored(index, pubkey));
		}


		#[weight = (100000, Pays::No)]
		fn register_attestor(origin){
			let account = ensure_signed(origin)?;
			// if already active, stop here. (if any active attestor matches. shortcircuit)
			// super inefficient worstcase, needs refactor at some point.
			let mut all_attestors = <Attestors<T>>::iter().map(|(_,y)| y);
			if !<ActiveAttestors>::get().iter().any(|_|{
				all_attestors.any(|y| y == account)
			}){
				let mut att_count = <AttestorsCount>::get();
				let user_index_option = att_count.pop();
				let current_user_index = match user_index_option {
					Some(x) => x,
					None => 0,
				};
				let i = current_user_index.saturating_add(1);
				<Attestors<T>>::insert(&i, &account);
				let mut atts = <AttestorsCount>::get();
				atts.push(i);
				<AttestorsCount>::put(atts);
				let mut att_vec = <ActiveAttestors>::get();
				att_vec.push(i);
				att_vec.sort_unstable();
				att_vec.dedup();
				native::info!("registerAttestor; att_vec: {:#?}", att_vec);
				<ActiveAttestors>::put(att_vec);
			}
		}

		#[weight = (100000, Pays::No)]
		fn register_encoder(origin){
			let account = ensure_signed(origin)?;

		}

		#[weight = (100000, Pays::No)]
		fn unregister_encoder(origin){
			let account = ensure_signed(origin)?;

		}

		#[weight = (100000, Pays::No)]
		fn register_encoding(origin, hoster_id: u64, dat_id: u64, start: u64, range: u64){
			let account = ensure_signed(origin)?;
			// TODO: register encoding and begin challenge phase
			// TODO: selected_hoster AND selected_encoder must register_encoding
		}


		#[weight = (100000, Pays::No)]
		fn refute_encoding(origin, archive: u64, index: u64, encoded: Vec<u8>, proof: Vec<u8>){
			//TODO
			//remove an invalid encoding if `encoded` is 
			//signed by `encoder` and `proof` does not match encoded chunk. 
		}

		#[weight = (100000, Pays::No)]
		fn confirm_hosting(origin, archive: u64){
			//TODO
			//move a valid encoding to `encoded` if `encoded` is 
			//signed by `encoder` and `proof` does match encoded chunk. 
		}

		#[weight = (100000, Pays::No)]
		fn submit_attestation(
			origin,
			hoster_index: u64,
			dat_index: u64,
			chunk_index: u64,
			attestation: Attestation
		) {
			let attestor = ensure_signed(origin)?;
		}

		#[weight = (100000, Pays::No)]
		fn unregister_attestor(origin){
			let account = ensure_signed(origin)?;
			for (user_index, user_account) in <Attestors<T>>::iter(){
				if user_account == account {
					<Attestors<T>>::remove(user_index);
					let mut user_indexes = <AttestorsCount>::get();
					match user_indexes.binary_search(&user_index){
						Ok(i) => {
							user_indexes.remove(i);
							<ActiveAttestors>::mutate(|att_vec|{
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
		#[weight = (100000, Pays::No)]
		fn register_seeder(origin) {
			//TODO: bias towards unseeded dats and high incentive
			let account = ensure_signed(origin)?;
			let dat_vec = <DatId>::get();
			let last = dat_vec.last();
			native::info!("Last Dat Index: {:#?}", last);
			match last {
				Some(last_index) => {
				let nonce = Self::unique_nonce();
				let new_random = (T::Randomness::random(b"dat_verify_register"), &nonce, &account)
					.using_encoded(|mut b| u64::decode(&mut b))
					.expect("hash must be of correct size; Qed");
				let random_index = new_random % last_index;
				let dat_pubkey = DatKey::get(&random_index);
				// DO SOMETHING HERE

				// SOMETHING DONE
				let user_index;
				let user_exists = <UserIndices<T>>::contains_key(&account);
				if !user_exists {
					let user_index_option = <UsersCount>::get().pop();
					let current_user_index = match user_index_option {
						Some(x) => {
							x
						},
						None => 0,
					};
					//maybe this should panic instead of saturate
					user_index = current_user_index.saturating_add(1);
					let mut users = <UsersCount>::get();
					users.push(user_index);
					<UsersCount>::put(users);
					<UserIndices<T>>::insert(&account, user_index);
				} else {
					user_index = <UserIndices<T>>::get(&account);
				}
				<Users<T>>::insert(&user_index, &account);
				native::info!("NewPin; Account: {:#?}", account);
				native::info!("NewPin; Pubkey: {:#?}", dat_pubkey);
				let publisher_index = <UserIndices<T>>::get(<UserRequestsMap<T>>::get(&dat_pubkey));
				Self::deposit_event(RawEvent::NewPin(publisher_index, user_index, random_index));
				},
				None => {
					
				},
			}
		} 


		#[weight = (100000, Pays::No)]
		fn unregister_seeder(origin) {
			let account = ensure_signed(origin)?;
			let user_id = <UserIndices<T>>::get(account);	
			<HostedMap>::remove_prefix(user_id);
			//maybe there should be a penalty here?
		}


		#[weight = (100000, Operational, Pays::No)] //todo weight
		fn submit_challenge(_origin, selected_user: u64, dat_id: u64){
			let hosted_map = <HostedMap>::get(selected_user, dat_id);
			// TODO: verify has encoded and block if encoding is not complete.
			let nonce = Self::unique_nonce();
			let new_random = (T::Randomness::random(b"dat_verify_init"), nonce)
				.using_encoded(|mut b| u64::decode(&mut b))
				.expect("hash must be of correct size; Qed");
			let dat_pubkey = <DatKey>::get(dat_id);
			let dat_tree_len = <TreeSize>::get(&dat_pubkey);
			let mut random_leaf = 0;
			if dat_tree_len != 0 { // avoid 0 divisor 
				random_leaf = new_random % dat_tree_len;
			}
			let selected_user_key = <Users<T>>::get(&selected_user);
			let challenge_length = T::ChallengeDelay::get();
			Self::deposit_event(RawEvent::Challenge(selected_user_key, dat_pubkey));
		}

		#[weight = (1000000, Operational, Pays::No)] //todo
		fn submit_scheduled_challenge(
			origin,
			selected_user: u64,
			dat_id: u64,
			start_in: T::BlockNumber,
			repeat_in: T::BlockNumber,
			repeat_times: u32
		){
			let account = ensure_signed(origin)?;
			let mut name : Vec<u8> = selected_user.to_be_bytes().to_vec();
			name.extend(dat_id.to_be_bytes().to_vec());
			//this makes me sad.
			let startnum : u64 = start_in.try_into().unwrap_or(0).try_into().unwrap_or(0u64);
			// :(
			name.extend(startnum.to_be_bytes().to_vec());
			if T::Scheduler::schedule_named(
				name,
				start_in,
				Some((repeat_in, repeat_times)),
				255,
				Call::submit_challenge(selected_user, dat_id).into()
			).is_err(){
				frame_support::print("LOGIC ERROR: submit_scheduled_challenge failed");
			}
		}

/*
		fn on_initialize(n: T::BlockNumber) => Weight {
			MINIMUM_WEIGHT
		}
*/ //some bug here, on_initialize breaks
// consider turning this into a schedulable
// "anyone calls" function (verify_challenges),
// like submit_scheduled_challenge
		fn on_finalize(n: T::BlockNumber) {
			for (user_index, dat_index, hosted_archive) in <HostedMap>::iter() {
				for &chunk_index in hosted_archive.state.keys(){
					let deadline_option = hosted_archive.state.get(&chunk_index);
					let attesting = Self::get_attestation_status(user_index, dat_index, chunk_index);
					match deadline_option {
						Some(Challenge::Active(deadline)) => {
							if deadline < &n.try_into().unwrap_or(usize::MAX).try_into().unwrap_or(u64::MAX) {
								Self::clear_challenge(user_index, dat_index, chunk_index);
								Self::punish_seeder(user_index);
								Self::deposit_event(RawEvent::ChallengeFailed(user_index, dat_index));
							}
						},
						Some(Challenge::Attesting(_)) => {
							match attesting {
								Some(true) => {
									Self::clear_challenge(user_index, dat_index, chunk_index);
									Self::reward_seeder(user_index);
									Self::deposit_event(RawEvent::ChallengeSuccess(user_index, dat_index));
								},
								_ => (),
							}
						},
						_ => (),
					}
				}
			}
		}
	}
}

pub struct EnsureSeeder<T>(sp_std::marker::PhantomData<T>);
impl<T: Trait> EnsureOrigin<T::Origin> for EnsureSeeder<T> {
	type Success = T::AccountId;
	fn try_origin(o: T::Origin) -> Result<Self::Success, T::Origin>{
		o.into().and_then(|o| match o {
			RawOrigin::Signed(ref account) => match <UserIndices<T>>::contains_key(&account) {
				true => Ok(account.clone()),
				false => Err(T::Origin::from(o)),
			},
			_ => Err(T::Origin::from(o)),
		})
	}
}

pub struct EnsureEncoder<T>(sp_std::marker::PhantomData<T>);
impl<T: Trait> EnsureOrigin<T::Origin> for EnsureEncoder<T> {
	type Success = T::AccountId;
	fn try_origin(o: T::Origin) -> Result<Self::Success, T::Origin>{
		o.into().and_then(|o| match o {
			RawOrigin::Signed(ref account) => match <UserIndices<T>>::contains_key(&account) {
				true => Ok(account.clone()),
				false => Err(T::Origin::from(o)),
			},
			_ => Err(T::Origin::from(o)),
		})
	}
}


impl<T: Trait> Module<T> {

	fn update_attestors_for(
		hoster_index: u64,
		dat_index: u64,
		chunk_index: u64,
		) -> Option<ChallengeAttestations> {
		let mut hosted : HostedArchive = <HostedMap>::get(hoster_index, dat_index);
		let attestations : ChallengeAttestations;
		let challenge = hosted.state.get(&chunk_index);
		match challenge {
			Some(Challenge::Attesting(attestors)) => {
				if attestors.expected_attestors.len() == 0{
					let mut expected_attestors = 
						Self::get_random_attestors(hoster_index, dat_index);
					expected_attestors.sort_unstable();
					expected_attestors.dedup();
					attestations = ChallengeAttestations {
						expected_attestors: expected_attestors,
						expected_friends: attestors.expected_friends.clone(),
						completed: attestors.completed.clone(),
					};
					hosted.state.insert(chunk_index, Challenge::Attesting(attestations.clone()));
					<HostedMap>::insert(hoster_index, dat_index, hosted);
				} else {
					attestations = ChallengeAttestations {
						expected_attestors: attestors.expected_attestors.clone(),
						expected_friends: attestors.expected_friends.clone(),
						completed: attestors.completed.clone(),
					};
				}
				Some(attestations)
			},
			Some(Challenge::Active(_)) => {
				let mut expected_attestors = 
					Self::get_random_attestors(hoster_index, dat_index);
				expected_attestors.sort_unstable();
				expected_attestors.dedup();
				attestations = ChallengeAttestations {
					expected_attestors: expected_attestors,
					expected_friends: Vec::new(),
					completed: Vec::new(),
				};
				hosted.state.insert(chunk_index, Challenge::Attesting(attestations.clone()));
				<HostedMap>::insert(hoster_index, dat_index, hosted);
				Some(attestations)
			},
			_ => None,
		}
	}

	fn get_attestation_status(hoster_index: u64, dat_index: u64, chunk_index: u64) -> Option<bool> {
		if let Some(state) = Self::update_attestors_for( 
			hoster_index,
			dat_index,
			chunk_index
		){
			let mut fail_count = 0;
			for expected in state.clone().expected_attestors {
				// If any of the expected attestors haven't returned, return None.
				if state.completed
					.iter()
					.map(|x|x.0)
					.position(|x| x == expected)
					.and_then(|y| state.completed.get(y)
					.and_then(|z|{
						if z.1.latency.is_none(){
							fail_count += 1;
							Some(false)
						} else {
							Some(true)
						}
					}
				))
				.is_none(){
					return None;
				} 
		}
		// else return Some(success status)
			Some(fail_count<=(T::AttestorsPerChallenge::get()/2))
		} else {
			None
		}
	}

	fn clear_challenge(user_index: u64, dat_index: u64, chunk_index: u64){
		let mut hoster : HostedArchive = <HostedMap>::get(user_index, dat_index);
		hoster.state.remove(&chunk_index);
		<HostedMap>::insert(user_index, dat_index, hoster);
	}

	fn punish_seeder(punished: u64) {
		for x in <HostedMap>::iter_prefix_values(punished).enumerate(){
			let (index, archive): (usize, HostedArchive) = x;
			let index_small : u64 = index.try_into().unwrap();
			let new_archive = HostedArchive {
				encoded: archive.encoded,
				encoding: archive.encoding,
				state: BTreeMap::new()
			};
			<HostedMap>::insert(punished, index_small, new_archive);
		}
	}


	fn reward_seeder(_rewarded: u64) {
		//todo
		unimplemented!();
	}

	fn forced_register_data(
		account: T::AccountId,
		merkle_root: (Public, TreeHashPayload, H512)
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
				native::info!("Dat Keys Vec: {:#?}", dat_vec);
				match dat_vec.pop() {
					Some(x) => {
						dat_vec.sort_unstable();
						let lowest_free_index = x;
						//currently only getting highest free index
						//but if we actually get lowest, do not push
						//new lowest on top of dat_vec
						dat_vec.push(lowest_free_index + 1);
						dat_vec.sort_unstable();
						dat_vec.dedup();
					},
					None => {
						//add an element if the vec is empty
						dat_vec.push(1);
						lowest_free_index = 0;
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

	fn unique_nonce() -> u64 {
		let nonce = <Nonce>::get();
		<Nonce>::put(nonce+1);
		nonce
	}

	fn get_random_attestors(hoster_index: u64, dat_index: u64) -> Vec<u64> {
		let members : Vec<u64> = <ActiveAttestors>::get();
		match members.len() {
			0 => members,
			_ => {
				let nonce : u64 = Self::unique_nonce();
				let mut random_select: Vec<u64> = Vec::new();
				// added indeces to seed in order to ensure challenges get unique randomness.
				let seed = (nonce, hoster_index, dat_index, T::Randomness::random(b"dat_random_attestors"))
					.using_encoded(|b| <[u8; 32]>::decode(&mut TrailingZeroInput::new(b)))
					.expect("input is padded with zeroes; qed");
				let mut rng = ChaChaRng::from_seed(seed);
				let pick_attestor = |_| Self::pick_item(&mut rng, &members[..]).expect("exited if members empty; qed");
				for attestor in (0..T::AttestorsPerChallenge::get()).map(pick_attestor){
					random_select.push(*attestor);
				}
				random_select
			},
		}
	}

}