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
	ensure,
	StorageValue,
	StorageMap,
	traits::Randomness,
	Parameter
};
use sp_std::convert::{TryInto, TryFrom};
use frame_system::{ensure_signed, ensure_root};
use frame_system as system;
use codec::{Encode, Decode};
use sp_core::{
	ed25519,
	Hasher,
	Blake2Hasher, 
	H256
};
use sp_runtime::{
	RuntimeDebug,
	traits::{
		Verify,
		CheckEqual,
		SimpleBitOps,
		MaybeDisplay,
		MaybeSerializeDeserialize,
		Member
	}
};

pub type Public = ed25519::Public;
pub type Signature = ed25519::Signature;

/// The module's configuration trait.
pub trait Trait: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	type Hash: 
	Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + SimpleBitOps
	+ Default + Copy + CheckEqual + sp_std::hash::Hash + AsRef<[u8]> + AsMut<[u8]>;
	type Randomness: Randomness<<Self as system::Trait>::Hash>;
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Node {
	index: u64,
	hash: H256,
	size: u64
}

//todo: 'from' the different HashPayload types
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
		//needs tests, this was written using trail and error.
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


#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
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


#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Attestation {
	//todo, actually decide format
	location: u8,
	latency: Option<u8> //may be failure.
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
		NewPin(AccountId, Public),
		Attest(AccountId, Attestation),
	}
);

// Dat related storage items.
decl_storage! {
	trait Store for Module<T: Trait> as DatVerify {
		// A vec of free indeces, with the last item usable for `len`
		DatId get(next_id): DatIdVec;
		// Each dat archive has a public key
		DatKey get(public_key): map DatIdIndex => Public;
		// Each dat archive has a tree size
		// TODO: remove calls to this when expecting indeces
		TreeSize get(tree_size): map Public => DatSize;
		// each dat archive has a merkle root
		MerkleRoot get(merkle_root): map Public => (H256, Signature);
		// users are put into an "array"
		UsersCount: u64;
		Users get(user): map UserIdIndex => T::AccountId;
		// each user has a vec of dats they seed
		UsersStorage: map T::AccountId => Vec<Public>;
		// each dat has a vec of users pinning it
		DatHosters: map Public => Vec<T::AccountId>;
		// each user has a mapping and vec of dats they want seeded
		UserRequestsMap: map Public => T::AccountId;

		// current check condition
		SelectedUser: T::AccountId;
		// Dat and which index to verify
		SelectedDat: (Public, u64);
		TimeLimit get(time_limit): T::BlockNumber;
		Nonce: u64;
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		fn on_initialize(n: T::BlockNumber) {
			let dat_vec = <DatId>::get();
			match dat_vec.last() {
				Some(last_index) => {
			// if no one is currently selected to give proof, select someone
			if !<SelectedUser<T>>::exists() && <UsersCount>::get() > 0 {
				let nonce = <Nonce>::get();
				let new_random = (T::Randomness::random(b"dat_verify"), nonce)
					.using_encoded(|b| Blake2Hasher::hash(b))
					.using_encoded(|mut b| u64::decode(&mut b))
					.expect("Hash must be bigger than 8 bytes; Qed");
				let new_time_limit = new_random % last_index;
				let future_block = 
					n + T::BlockNumber::from(new_time_limit.try_into().unwrap_or(2));
				let random_user_index = new_random % <UsersCount>::get();
				let random_user = <Users<T>>::get(random_user_index);
				let users_dats = <UsersStorage<T>>::get(&random_user);
				let users_dats_len = users_dats.len();
				let random_dat = users_dats.get(new_random as usize % users_dats_len)
					.expect("Users must not have empty storage; Qed");
				let dat_tree_len = <TreeSize>::get(random_dat);
				let random_leave = new_random % dat_tree_len;
				<SelectedDat>::put((random_dat.clone(), random_leave));
				<SelectedUser<T>>::put(&random_user);
				<TimeLimit<T>>::put(future_block);
				<Nonce>::mutate(|m| *m += 1);
				Self::deposit_event(RawEvent::Challenge(random_user, future_block));
			}},
				None => (),
			}
		}

		//TODO: submit attestation that a peer is online and behaving correctly on the dat network
		fn submit_attestation(origin, attestation: Attestation) {
			let attestor = ensure_signed(origin)?;
			// TODO: verify you have been requested an attestation
			let challenge = (
				<SelectedUser<T>>::get(),
				<system::Module<T>>::block_number(),
			);
			// TODO: remove challenge iff threshold is met
			Self::deposit_event(RawEvent::Attest(attestor, attestation));
		}

		//test things progressively, doing quicker computations first.
		fn submit_proof(origin, proof: Proof, unsigned_root_hash: H256, chunk_content: Vec<u8>) {
			let account = ensure_signed(origin)?;
			ensure!(
				account == <SelectedUser<T>>::get(),
				"Only the current challengee can respond to their challenge"
			);
			let index_proved = proof.index;
			let challenge = <SelectedDat>::get();
			let signature = proof.signature.expect(
				"Proof should be signed"
			);
			ensure!(
				&signature.verify(
					unsigned_root_hash.as_bytes(),
					&challenge.0
				),
				"Signature verification failed"
			);
			ensure!(
				index_proved == challenge.1,
				"Proof is for the wrong chunk"
			);
			let payload = ChunkHashPayload{
				hash_type : 0,
				chunk_length : chunk_content.len() as u64,
				chunk_content : chunk_content
			};
			let chunk_hash = payload.using_encoded(|b| Blake2Hasher::hash(b));
			let proof_nodes : Vec<Node> = proof.nodes.clone();
			let node_indeces : Vec<u64> = proof_nodes.clone().into_iter().map(|m| {
					m.index
				}).collect();
			let leaf_node_index : usize = node_indeces.binary_search(&index_proved).expect(
				"Leaf node should exist"
			);
			let leaf_node : &Node = proof_nodes.get(leaf_node_index).expect(
				"Leaf node should exist"
			);
			let provided_chunk_hash = leaf_node.hash;
			ensure!(
				chunk_hash == provided_chunk_hash,
				"Could not verify chunk hash"
			);
			let root_indeces = Node::get_orphan_indeces(index_proved);
			let mut root_nodes : Vec<ParentHashInRoot> = Vec::new();
			proof_nodes.iter().for_each(|check : &Node| {
				let node_index = check.index; 
				if root_indeces.contains(&node_index) {
					let orphan_hash = ParentHashInRoot {
						hash: check.hash,
						hash_number: check.index,
						total_length: check.size
					};
					root_nodes.push(orphan_hash);
				}
			});
			root_nodes.sort_unstable_by(|a , b|
				a.hash_number.cmp(&b.hash_number)
			);
			let root_hash_payload = RootHashPayload {
				hash_type: 2,
				children: root_nodes
			};
			let root_hash = root_hash_payload
				.using_encoded(|b| Blake2Hasher::hash(b));
			ensure!(
				root_hash == unsigned_root_hash,
				"Root hash verification failed"
			);
			//TODO:
			// verify roots and direct ancestors of the proved chunk_hash
				//charge archive pinner (FUTURE: scale by some burn_factor)
				//reward and unselect prover
				//reward must be greater than charge!
			<SelectedUser<T>>::kill();
			// else let the user try again until time limit
		}

		// Submit or update a piece of data that you want to have users copy
		fn register_data(origin, merkle_root: (Public, RootHashPayload, Signature)) {
			let account = ensure_signed(origin)?;
			let pubkey = merkle_root.0;
			let mut lowest_free_index : DatIdIndex = 0;
			let root_hash = merkle_root.1
				.using_encoded(|b| Blake2Hasher::hash(b));
			//FIXME: we don't currently verify if we are updating to a newer root from an older one.
			//verify the signature
			ensure!(
				&merkle_root.2.verify(
					root_hash.as_bytes(),
					&pubkey
					),
				"Signature Verification Failed"
			);
			let mut tree_size : u64 = u64::min_value();
			for child in merkle_root.1.children {
				tree_size += child.total_length
			}
			let mut dat_vec : Vec<DatIdIndex> = <DatId>::get();
			if !<MerkleRoot>::exists(&pubkey){
				match dat_vec.first() {
					Some(index) => {
						lowest_free_index = dat_vec.remove(0);
						if dat_vec.is_empty() {
							dat_vec.push(lowest_free_index + 1);
						}
					},
					None => {
						//add an element if the vec is empty
						dat_vec.push(1);
					},
				}
				//register new unknown dats
				<DatKey>::insert(&lowest_free_index, &pubkey)
			}
			<MerkleRoot>::insert(&pubkey, (root_hash, merkle_root.2));
			<DatId>::put(dat_vec);
			<TreeSize>::insert(&pubkey, tree_size);
			<UserRequestsMap<T>>::insert(&pubkey, &account);
			Self::deposit_event(RawEvent::SomethingStored(lowest_free_index, pubkey));
		}

		//user stops requesting others pin their data
		fn unregister_data(origin, index: DatIdIndex){
			let account = ensure_signed(origin)?;
			let pubkey = <DatKey>::get(index);
			//only allow owner to unregister
			ensure!(
				<UserRequestsMap<T>>::get(&pubkey) == account,
				"Cannot unregister archive, not owner."
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
					let mut storage : Vec<Public> =
						<UsersStorage<T>>::get(account.clone());
					match storage.binary_search(&pubkey).ok() {
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
			if (<SelectedDat>::get().0 == pubkey){
				<SelectedUser<T>>::kill();
			}
			Self::deposit_event(RawEvent::SomethingUnstored(index, pubkey));
		}

		// User requests a dat for them to pin. FIXME: May return a dat they are already pinning.
		fn register_backup(origin) {
			//TODO: bias towards unseeded dats and high incentive
			let account = ensure_signed(origin)?;
			let dat_vec = <DatId>::get();
			match dat_vec.last() {
				Some(last_index) => {
				let nonce = <Nonce>::get();
				let new_random = (T::Randomness::random(b"dat_verify"), &nonce, &account)
					.using_encoded(|b| Blake2Hasher::hash(b))
					.using_encoded(|mut b| u64::decode(&mut b))
					.expect("Hash must be bigger than 8 bytes; Qed");
				let random_index = new_random % last_index;
				let dat_pubkey = DatKey::get(random_index);
				let mut current_user_dats = <UsersStorage<T>>::get(&account);
				let mut dat_hosters = <DatHosters<T>>::get(&dat_pubkey);
				current_user_dats.push(dat_pubkey.clone());
				current_user_dats.sort_unstable();
				current_user_dats.dedup();
				dat_hosters.push(account.clone());
				dat_hosters.sort_unstable();
				dat_hosters.dedup();
				<DatHosters<T>>::insert(&dat_pubkey, &dat_hosters);
				<UsersStorage<T>>::insert(&account, &current_user_dats);
				<Nonce>::mutate(|m| *m += 1);
				if(current_user_dats.len() == 1){
					<Users<T>>::insert(<UsersCount>::get(), &account);
					<UsersCount>::mutate(|m| *m += 1);
				}
				Self::deposit_event(RawEvent::NewPin(account, dat_pubkey));
				},
				None => (),
			}
		}

		fn on_finalize(n: T::BlockNumber) {
			let user = <SelectedUser<T>>::get();
			let dat = <SelectedDat>::get().0;
			if (n == Self::time_limit()) {
				<SelectedUser<T>>::kill();
			} else {
				//charge fee*
			}
		}
	}
}


/// TODO: tests for this module
/// TODO: get some reference test vectors for the proof
#[cfg(test)]
mod tests {
	use super::*;

	use runtime_io::with_externalities;
	use primitives::{H256, Blake2Hasher};
	use support::{impl_outer_origin, assert_ok, parameter_types};
	use sr_primitives::{traits::{BlakeTwo256, IdentityLookup}, testing::Header};
	use sr_primitives::weights::Weight;
	use sr_primitives::Perbill;

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	// For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`Test`) which `impl`s each of the
	// configuration traits of modules we want to use.
	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	parameter_types! {
		pub const BlockHashCount: u64 = 250;
		pub const MaximumBlockWeight: Weight = 1024;
		pub const MaximumBlockLength: u32 = 2 * 1024;
		pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
	}
	impl system::Trait for Test {
		type Origin = Origin;
		type Call = ();
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type WeightMultiplierUpdate = ();
		type Event = ();
		type BlockHashCount = BlockHashCount;
		type MaximumBlockWeight = MaximumBlockWeight;
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
	}
	impl Trait for Test {
		type Event = ();
	}
	type TemplateModule = Module<Test>;

	// This function basically just builds a genesis storage key/value store according to
	// our desired mockup.
	fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
		system::GenesisConfig::default().build_storage::<Test>().unwrap().into()
	}

	#[test]
	fn it_works_for_default_value() {
		with_externalities(&mut new_test_ext(), || {
			// Just a dummy test for the dummy funtion `do_something`
			// calling the `do_something` function with a value 42
			assert_ok!(TemplateModule::do_something(Origin::signed(1), 42));
			// asserting that the stored value is equal to what we stored
			assert_eq!(TemplateModule::something(), Some(42));
		});
	}
}
