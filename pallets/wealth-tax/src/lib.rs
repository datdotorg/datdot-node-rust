#![cfg_attr(not(feature = "std"), no_std)]

use std::hash::Hash;

use sp_core::{H512, Hasher};
use sp_runtime::{AnySignature, DispatchError, Perbill, RuntimeDebug, traits::{AtLeast32Bit, AtLeast32BitUnsigned, CheckedSub, MaybeSerializeDeserialize, Member, Saturating, Scale, Verify, Zero}};
use sp_std::prelude::*;
use sp_std::convert::TryInto;
use sp_std::fmt::Debug;
use sp_std::mem;
use sp_std::{collections::btree_map::BTreeMap, ops::{BitAnd, BitOr, Mul}};
use frame_support::{Parameter, decl_error, decl_event, decl_module, decl_storage, ensure, fail, storage::{
		StorageMap,
		StorageValue,
		IterableStorageMap,
		IterableStorageDoubleMap,
	}, traits::{Currency, EnsureOrigin, ExistenceRequirement, Get, Imbalance, LockIdentifier, LockableCurrency, ReservableCurrency, SignedImbalance, TryDrop, WithdrawReason, WithdrawReasons}, weights::{
		Pays,
		DispatchClass::{
			Operational,
		}
	}};
use frame_system::{
	self as system,
	ensure_signed,
	ensure_root,
	RawOrigin
};
use codec::{Codec, Decode, Encode, EncodeLike, Input, Joiner};


#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct AgedUTXO<BA, BN> {
	value: BA,
	start: BN,
	// new value on new block (100% = no change, anything smaller = wealth taxing)
	rate: Perbill,
	permissions: WithdrawReasons
}

impl<BA: Default, BN: Default> Default for AgedUTXO<BA, BN> {
	fn default() -> Self {
		Self {
			value: BA::default(),
			start: BN::default(),
			rate: Perbill::default(),
			permissions: WithdrawReasons::all()
		}
	}
}

impl<BA: PartialOrd, BN: AtLeast32Bit+Copy> PartialOrd for AgedUTXO<BA, BN> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		self.value.partial_cmp(&other.value)
    }
}

impl<BA: Ord, BN: AtLeast32Bit+Copy> Ord for AgedUTXO<BA, BN> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<
	BN: AtLeast32Bit+Copy, 
	BA: AtLeast32BitUnsigned+Copy
	> AgedUTXO<BA, BN> {

	/// update this UTXO to a new start block
	fn update(&mut self, now: BN){
		if let Ok(age) = (now - self.start).try_into(){
			let new_val = self.rate.saturating_pow(age).mul_floor(self.value);
			if !new_val.is_zero() { 
				self.value = new_val;
				self.start = now;
			}
		} 
	}

}

impl<
	BN: AtLeast32BitUnsigned+Copy, 
	BA: AtLeast32BitUnsigned+Copy
	> Imbalance<BA> for AgedUTXO<BA, BN>{
    	type Opposite = AgedUTXO<BA, BN>;

    fn zero() -> Self {
        Self {
			value: Zero::zero(),
			start: Zero::zero(),
			rate: Perbill::one(),
			permissions: WithdrawReasons::all()
		}
    }

    fn drop_zero(self) -> Result<(), Self> {
        if self.value.is_zero() {
			Ok(())
		} else {
			Err(self)
		}
    }

    fn split(self, amount: BA) -> (Self, Self) {
			let first = self.value.min(amount);
			let second = self.value - first;
			let rate = self.rate;
			let start = self.start;
			let perms = self.permissions;
			let first_split = Self {
				value: first,
				rate: rate.clone(),
				start: start.clone(),
				permissions: perms
			};

			let second_split = Self {
				value: second,
				rate: rate.clone(),
				start: start.clone(),
				permissions: perms
			};

			mem::forget(self);
			(first_split, second_split)
    }

	// We rely on the caller to ensure permissions match between imbalances
	// if this is not the case, we use the most restrictive permissions 
    fn merge(self, other: Self) -> Self {
			let rated_value = self.rate.mul(self.value).saturating_add(other.rate.mul(other.value));
			let (higher, lower) = 
				(self.clone().max(other.clone()), self.clone().min(other.clone()));
			let value_ratio = Perbill::from_rational_approximation(
				lower.value,
				higher.value
			);
			
			let new_value = self.value.saturating_add(other.value);
			let new_rate = Perbill::from_rational_approximation(rated_value, new_value);
			let difference = self.start.max(other.start)-self.start.min(other.start);
			let new_difference = value_ratio.mul_floor(difference);
			let new_start = self.start.min(other.start)+new_difference;
			let new_perms = self.permissions.bitand(other.permissions);
			mem::forget(other);
			mem::forget(self);

			let new = Self {
				value: new_value,
				rate: new_rate,
				start: new_start,
				permissions: new_perms
			};

			new
    }

    fn subsume(&mut self, other: Self) {
        let rated_value = self.rate.mul(self.value).saturating_add(other.rate.mul(other.value));
		let (higher, lower) = 
			(self.clone().max(other.clone()), self.clone().min(other.clone()));
		let value_ratio = Perbill::from_rational_approximation(
			lower.value,
			higher.value
		);
		
		let new_value = self.value.saturating_add(other.value);
		let new_rate = Perbill::from_rational_approximation(rated_value, new_value);
		let difference = self.start.max(other.start)-self.start.min(other.start);
		let new_difference = value_ratio.mul_floor(difference);
		let new_start = self.start.min(other.start)+new_difference;
		mem::forget(other);
		self.value = new_value;
		self.rate = new_rate;
		self.start = new_start;
    }

    fn offset(self, other: Self::Opposite) -> Result<Self, Self::Opposite> {
        let (a, b) = (self.value, other.value);
		let mut new = Self::merge(self, other);
		if a >= b {
			new.value = a - b;
			Ok(new)
		} else {
			new.value = b - a;
			Err(new)
		}
    }

	//try not to use this without an update() call prior.
    fn peek(&self) -> BA {
        self.value
    }
}

impl<
	BN: AtLeast32BitUnsigned+Copy, 
	BA: AtLeast32BitUnsigned+Copy
	> TryDrop for AgedUTXO<BA, BN> {
    	fn try_drop(self) -> Result<(), Self> {
        self.drop_zero()
    }
}


#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub enum UTXOIdType<IdType> {
	Lock(IdType),
	UTXO(IdType)
}

impl<IdType> UTXOIdType<IdType> {
	fn peek(&self) -> &IdType {
		match self {
			Self::Lock(id) => id,
			Self::UTXO(id) => id
		}
	}
}

pub trait Trait: system::Trait{
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
	type Balance: Parameter + Member + AtLeast32BitUnsigned + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type Moment: Parameter + Default + AtLeast32Bit
	+ Scale<Self::BlockNumber, Output = Self::Moment> + Copy;
	type MaxLocks: Get<u32>;	
	type MinimumBalance: Get<Self::Balance>;
	type CommitmentAmount: Get<Self::Balance>;
	type CommitmentId: Get<Vec<u8>>;
	type SecretHasher: Hasher<Out = H512>;
}
        
decl_event!(
    pub enum Event {

    }
);

decl_error! {
	pub enum WealthError for Module<T: Trait> {
		InsufficientLiquidity
    }
}


decl_storage! {
	trait Store for Module<T: Trait> as Wealth {
		// Support for various different custom "tokens" for lock purposes
		// custom tokens should ideally not be user-configurable without a
		// numerical or hash prefix.
		pub UTXOStore: double_map 
			hasher(blake2_128_concat) T::AccountId, 
			hasher(identity) UTXOIdType<Vec<u8>>
				=>
			Option<AgedUTXO<T::Balance, T::BlockNumber>>;
		pub TotalIssuance: AgedUTXO<T::Balance, T::BlockNumber>;
		pub DecayRate: map
			hasher(identity) Vec<u8> 
				=>
			Perbill;
		pub CommitmentCount: map hasher(blake2_128_concat) T::AccountId => u32;
		pub CommitmentSecrets: map hasher(blake2_128_concat) H512 => Option<(T::AccountId, T::AccountId)>;
    }
}

decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
		type Error = WealthError<T>;

		#[weight = 0]
		fn transfer(origin, dest: T::AccountId, value: T::Balance){
			let source = ensure_signed(origin)?;
			<Self as Currency<T::AccountId>>::transfer(&source, &dest, value, ExistenceRequirement::AllowDeath)?;
		}

		#[weight = 0]
		fn transfer_keep_alive(origin, dest: T::AccountId, value: T::Balance){
			let source = ensure_signed(origin)?;
			<Self as Currency<T::AccountId>>::transfer(&source, &dest, value, ExistenceRequirement::KeepAlive)?;
		}

		#[weight = 0]
		fn set_rate_for(origin, rate_id: Vec<u8>, rate: Perbill){
			ensure_root(origin)?;
			Self::set_rate(rate_id, rate);
		}

		#[weight = 0]
		fn recalculate_locks(origin, who: T::AccountId){
			ensure_signed(origin)?;
			Self::refill_locks(&who, None);
		}

		//irreversibly commit some amount to be used for utility and not spending,
		//secret is optional for use in PoWVerifier trait - hash of a secret and 
		//the recipient of the commitment.
		#[weight = 0]
		fn usage_commitment(origin, secret: Option<(H512, T::AccountId)>){
			let who = ensure_signed(origin)?;
			Self::inc_commit(who.clone())?;
			if let Some((hash, author)) = secret {
				CommitmentSecrets::<T>::insert(hash, (who, author));
			}
		}

    }
}



impl<T: Trait> Module<T> {

	pub fn set_rate(rate_id: Vec<u8>, rate: Perbill){
		<DecayRate>::insert(rate_id, rate);
	}
	// get UTXOs that satisfy a specific withdrawal reason (optionally, up to a given amount)
	// if an insufficient amount/none are found, returns None.
	// second item in returned tuple represents the surplus amount in the final tuple, None if exact or no amount was requested.
	fn filter_utxos_for(who: &T::AccountId, what: WithdrawReasons, amount: Option<T::Balance>) 
	-> Option<Vec<(Vec<u8>, AgedUTXO<T::Balance, T::BlockNumber>)>>
	{
		let mut amount_mut: Option<T::Balance> = amount.clone();
		let mut output_utxos: Vec<(Vec<u8>, AgedUTXO<T::Balance, T::BlockNumber>)> = Vec::new();
		let mut success: bool = false;
		for (id_type, mut utxo) in UTXOStore::<T>::iter_prefix(who){
			let withdraw_reasons = utxo.permissions;
			if withdraw_reasons.contains(what){
				utxo.update(<system::Module<T>>::block_number());
				match (amount_mut, id_type) {
					(Some(amt), UTXOIdType::UTXO(id)) => {
						if let Some(new_amt) = amt.checked_sub(&utxo.value){
							amount_mut = Some(new_amt);
							output_utxos.push((id, utxo));
						} else {
							output_utxos.push((id, utxo));
							success = true;
							break;
						}
					},
					(None, UTXOIdType::UTXO(id)) => {
						output_utxos.push((id, utxo));
						success = true;
					},
					_ => ()
				}
			}
		}
		if success {
			Some(output_utxos)
		} else {
			None
		}
	}

	fn utxo_id_to_lock_id(utxo_id: UTXOIdType<Vec<u8>>) -> Option<LockIdentifier> {
		let mut id_holder: LockIdentifier = LockIdentifier::default();
				match utxo_id {
					UTXOIdType::Lock(i_d) => {
						//check the len to avoid panic on copy-from-slice
						if !LockIdentifier::default().len() == i_d.len(){
							None
						} else {
							id_holder.copy_from_slice(&i_d);
							Some(id_holder)
						}
					},
					_ => None
				}
	}

	pub fn refill_locks(who: &T::AccountId, maybe_id: Option<LockIdentifier>){
		if let Some(lock_id) = maybe_id {
			let block_number = <system::Module<T>>::block_number();
			match 
			(
				UTXOStore::<T>::get(who, UTXOIdType::Lock(lock_id.into())),
				UTXOStore::<T>::get(who, UTXOIdType::UTXO(lock_id.into()))
			){
				(Some(mut lock), Some(mut utxo)) => {
					lock.update(block_number);
					utxo.update(block_number);
					//lock already exists and locked amount already exists
					//compare sizes and resolve by pulling or pushing from free balance
					match lock.peek().cmp(&utxo.peek()) {
					    std::cmp::Ordering::Less => {
							//lock has less value than utxo, free some
							let (mut new_utxo, mut difference_imbalance) = utxo.split(lock.peek());
							//either both deposit&withdrawal succeed simultaneously, or nothing happens.
							difference_imbalance.permissions = WithdrawReasons::all();
							if let Ok(_) = Self::resolve_into_existing(who, difference_imbalance){
								new_utxo.permissions = lock.permissions;
								UTXOStore::<T>::insert(who, UTXOIdType::UTXO(lock_id.into()), new_utxo);
							}
						},
					    std::cmp::Ordering::Equal => {
							// nothing to do.
						},
					    std::cmp::Ordering::Greater => {
							//lock has more value than utxo, lock some more
							let difference = lock.peek() - utxo.peek();
							if let Ok(difference_imbalance) = Self::withdraw(who, difference, WithdrawReasons::all(), ExistenceRequirement::KeepAlive){
								//account has enough balance to lock - do something
								let mut new_utxo = utxo.merge(difference_imbalance);
								new_utxo.permissions = lock.permissions;
								UTXOStore::<T>::insert(who, UTXOIdType::UTXO(lock_id.into()), new_utxo);
							}
						}
					}
				},
				(Some(lock), None) => {
					//there is a lock, but it has no utxo
					//we make best effort to move free balance into the lock
					if let Ok(mut new_utxo) = Self::withdraw(who, lock.peek(), WithdrawReasons::all(), ExistenceRequirement::KeepAlive){
						//account has enough balance to lock - do something
						new_utxo.permissions = lock.permissions;
						UTXOStore::<T>::insert(who, UTXOIdType::UTXO(lock_id.into()), new_utxo);
					}
				},
				(None, Some(mut utxo)) => {
					//there is a utxo, but no corresponding lock
					//we move the locked amount into freed balance
					utxo.permissions = WithdrawReasons::all();
					if let Ok(_) = Self::resolve_into_existing(who, utxo){
						UTXOStore::<T>::remove(who, UTXOIdType::UTXO(lock_id.into()));
					}
				},
				_ => ()


			}
		} else {
			let all_locks: Vec<LockIdentifier> =
			UTXOStore::<T>::iter_prefix(who).filter_map(|(id, _)|{
				Self::utxo_id_to_lock_id(id)
			}).collect();
			for lock_id_value in all_locks {
				
				Self::refill_locks(who, Some(lock_id_value));
			}
		}
	}

	fn new_utxo(value: T::Balance, id: Vec<u8>, permissions: WithdrawReasons) -> AgedUTXO<T::Balance, T::BlockNumber> {
		AgedUTXO {
			value: value,
			start: <system::Module<T>>::block_number(),
			rate: DecayRate::get(id),
			permissions: permissions
		}
	}

	pub fn custom_issue(who: &T::AccountId, value: T::Balance, id: UTXOIdType<Vec<u8>>, permissions: WithdrawReasons){
		//we get the existing balance if any exists
		let old_balance;
		if let Some(current_balance) = UTXOStore::<T>::get(&who, id.clone()){
			old_balance = current_balance;
		} else {
			old_balance = AgedUTXO::default();
		}
		//first increase issuance.
		drop(Self::issue(value));
		let new_balance = Self::new_utxo(value, id.peek().to_vec(), permissions);
		//and store the merged version.
		UTXOStore::<T>::insert(&who, id.clone(), old_balance.merge(new_balance));
	}

	pub fn custom_resolve(who: &T::AccountId, imbalance: AgedUTXO<T::Balance, T::BlockNumber>, id: UTXOIdType<Vec<u8>>, permissions: WithdrawReasons){
		//we get the existing balance if any exists
		let old_balance;
		if let Some(current_balance) = UTXOStore::<T>::get(&who, id.clone()){
			old_balance = current_balance;
		} else {
			old_balance = AgedUTXO::default();
		}
		//and store the merged version.
		UTXOStore::<T>::insert(&who, id.clone(), old_balance.merge(imbalance));
	}

	pub fn custom_burn(who: &T::AccountId, value: T::Balance, id: UTXOIdType<Vec<u8>>) -> Result<(), ()>{
		//we get the existing balance if any exists
		if let Some(old_balance) = UTXOStore::<T>::get(&who, id.clone()){
			let (to_burn, to_keep) = old_balance.split(value);
			if to_burn.peek() < value {
				//balance was insufficient
				Err(())
			} else {
				//and store the merged version.
				UTXOStore::<T>::insert(&who, id.clone(), to_keep);
				//finally decrease issuance.
				drop(Self::burn(to_burn.peek()));
				Ok(())
			}
		} else {
			//balance didn't exist
			Err(())
		}
	}

	pub fn inc_commit(who: T::AccountId) -> Result<(), DispatchError>{
		let id = T::CommitmentId::get();
		let commitment_count = CommitmentCount::<T>::get(&who);
		let imbalance = Self::withdraw(&who, T::CommitmentAmount::get(), WithdrawReason::Transfer.into(), ExistenceRequirement::KeepAlive)?;
		Self::custom_resolve(&who, imbalance, UTXOIdType::UTXO(id), WithdrawReasons::except(WithdrawReason::Transfer.into()));
		CommitmentCount::<T>::insert(who, commitment_count+1);
		Ok(())
	}

	pub fn consume_commit(who: T::AccountId) -> Result<(), ()>{
		let commitment_count = CommitmentCount::<T>::get(&who);
		if let Some(consumed_count) = commitment_count.checked_sub(1){
			CommitmentCount::<T>::insert(&who, consumed_count);
			Ok(())
		} else {
			Err(())
		}
	}
}

impl<T: Trait> Currency<T::AccountId> for Module<T>{
    type Balance = T::Balance;

    type PositiveImbalance = AgedUTXO<Self::Balance, T::BlockNumber>;

    type NegativeImbalance = AgedUTXO<Self::Balance, T::BlockNumber>;

    fn total_balance(who: &T::AccountId) -> Self::Balance {
        let mut out_balance = Self::Balance::zero();
        if let Some(free_utxos)
			= Self::filter_utxos_for(who, WithdrawReasons::none(), None)
		{
			for (_id , mut utxo) in free_utxos {
				utxo.update(<system::Module<T>>::block_number());
				out_balance = out_balance.saturating_add(utxo.value);
			}
		}
		out_balance
    }

    fn can_slash(who: &T::AccountId, value: Self::Balance) -> bool {
        Self::total_balance(who) >= value
    }

    fn total_issuance() -> Self::Balance {
        let mut total = TotalIssuance::<T>::get();
		total.update(<system::Module<T>>::block_number());
		total.peek()
    }

    fn minimum_balance() -> Self::Balance {
        T::MinimumBalance::get()
    }

    fn burn(amount: Self::Balance) -> Self::PositiveImbalance {
        let mut total = TotalIssuance::<T>::get();
		total.update(<system::Module<T>>::block_number());
		let (burned, remains) = total.split(amount);
		TotalIssuance::<T>::put(remains);
		burned
    }

    fn issue(amount: Self::Balance) -> Self::NegativeImbalance {
		let now = <system::Module<T>>::block_number();
        let mut total = TotalIssuance::<T>::get();
		let new = Self::NegativeImbalance {
			value: amount,
			start: now,
			rate: DecayRate::get(Vec::<u8>::default()),
			permissions: WithdrawReasons::all()
		};
		//update total beforehand to minimize inaccuracies in the merge step
		total.update(now);
		let result = new.clone();
		let new_total = total.merge(new);
		TotalIssuance::<T>::put(new_total);
		result
    }

    fn free_balance(who: &T::AccountId) -> Self::Balance {
		let mut out_balance = Self::Balance::zero();
        if let Some(free_utxos) 
			= Self::filter_utxos_for(who, WithdrawReasons::all(), None)
		{
			for (_id , mut utxo) in free_utxos {
				utxo.update(<system::Module<T>>::block_number());
				out_balance = out_balance.saturating_add(utxo.value);
			}
		}
		out_balance
    }

    fn ensure_can_withdraw(
		who: &T::AccountId,
		amount: Self::Balance,
		reasons: frame_support::traits::WithdrawReasons,
		_new_balance: Self::Balance,
	) -> sp_runtime::DispatchResult {
		if Self::filter_utxos_for(who, reasons, Some(amount)).is_some() {
			Ok(())
		} else {
			Err(WealthError::<T>::InsufficientLiquidity.into())
		}
    }

    fn transfer(
		source: &T::AccountId,
		dest: &T::AccountId,
		value: Self::Balance,
		existence_requirement: frame_support::traits::ExistenceRequirement,
	) -> sp_runtime::DispatchResult {
		let withdraw_result = Self::withdraw(source, value, WithdrawReason::Transfer.into(), existence_requirement);
		match withdraw_result {
			Ok(withdrawn) => {
				Self::resolve_creating(dest, withdrawn);
				Ok(())
			},
			Err(err) => {
				Err(err).into()
			}
		}
    }

    fn slash(
		who: &T::AccountId,
		value: Self::Balance
	) -> (Self::NegativeImbalance, Self::Balance) {
		// get uncapped utxos - as we slash as much as possible
		let maybe_inputs = Self::filter_utxos_for(who, WithdrawReasons::none(), None);
		if let Some(inputs) = maybe_inputs {
			let mut merged: AgedUTXO<T::Balance, T::BlockNumber> = Default::default();
			for input in inputs {
				let inner_id = input.0.clone();
				let utxo_id = UTXOIdType::UTXO(inner_id);
				let utxo = input.1;
				let permissions = utxo.permissions;
				merged = merged.merge(utxo);
				UTXOStore::<T>::remove(who, utxo_id.clone());
				if let Some(surplus) = merged.peek().checked_sub(&value) {
					let utxo_change = 
						Self::new_utxo(surplus, input.0, permissions);
					UTXOStore::<T>::insert(who, utxo_id, utxo_change);
				}
			}
			Self::refill_locks(who, None);
			let merged_amount = merged.peek();
			if merged_amount < value {
				(merged, value - merged_amount)
			} else {
				(merged, Zero::zero())
			}
		} else {
			(AgedUTXO::default(), value)
		}
    }

    fn deposit_into_existing(
		who: &T::AccountId,
		value: Self::Balance
	) -> Result<Self::PositiveImbalance, DispatchError> {
        Ok(Self::deposit_creating(who, value))
    }

    fn deposit_creating(
		who: &T::AccountId,
		value: Self::Balance,
	) -> Self::PositiveImbalance {
		let new =
			Self::new_utxo(value, Vec::<u8>::default(), WithdrawReasons::all());
		if let Some(mut recipient_utxo) = UTXOStore::<T>::take(who, UTXOIdType::UTXO(Vec::default())){
			//TODO - we saturate here instead of returning+handling an error.
			recipient_utxo = recipient_utxo.merge(new.clone());
			UTXOStore::<T>::insert(who, UTXOIdType::UTXO(Vec::default()), recipient_utxo);
		} else {
			UTXOStore::<T>::insert(who, UTXOIdType::UTXO(Vec::default()), new.clone());
		}
		new
    }

    fn withdraw(
		who: &T::AccountId,
		value: Self::Balance,
		reasons: frame_support::traits::WithdrawReasons,
		_liveness: frame_support::traits::ExistenceRequirement,
	) -> Result<Self::NegativeImbalance, DispatchError> {
		let transfer_reason = WithdrawReasons::from(reasons);
        let maybe_inputs = Self::filter_utxos_for(who, transfer_reason, Some(value));
		if let Some(inputs) = maybe_inputs {
			let mut merged: AgedUTXO<T::Balance, T::BlockNumber> = Default::default();
			for input in inputs {
				let utxo_id = UTXOIdType::UTXO(input.0.clone());
				let utxo = input.1;
				let permissions = utxo.permissions;
				merged = merged.merge(utxo);
				UTXOStore::<T>::remove(who, utxo_id.clone());
				if let Some(surplus) = merged.peek().checked_sub(&value) {
					let utxo_change =
						Self::new_utxo(surplus, input.0, permissions);
					UTXOStore::<T>::insert(who, utxo_id.clone(), utxo_change);
				}
				if let Some(lock_id) = Self::utxo_id_to_lock_id(utxo_id) {
					//we only refill a lock if we withdrew from one.
					//refill_locks calls withdraw internally, pulling from free balance
					//so we must ensure that EITHER 
					// we never create locks with WithdrawReason::all()
					//OR
					// if we create a lock with WithdrawReason::all(),
					// we do not refill it automatically on withdrawal
					//..
					//for sake of flexibility and api correctness
					//we add an additional check (the second option).
					if !permissions.is_all(){
						Self::refill_locks(who, Some(lock_id));
					}
				}
			}
			Ok(merged)
		} else {
			Err(WealthError::<T>::InsufficientLiquidity.into())
		}
    }

    fn make_free_balance_be(
		who: &T::AccountId,
		balance: Self::Balance,
	) -> frame_support::traits::SignedImbalance<Self::Balance, Self::PositiveImbalance> {
        let current_balance = Self::free_balance(who);
		if let Some(slashable_surplus) = balance.checked_sub(&current_balance){
			if let Ok(withdrawal) = Self::withdraw(who, slashable_surplus, WithdrawReasons::all(), frame_support::traits::ExistenceRequirement::AllowDeath){
				SignedImbalance::Negative(withdrawal)
			} else {
				SignedImbalance::Positive(Self::PositiveImbalance::zero())
			}
		} else {
			SignedImbalance::Positive(Self::deposit_creating(who, current_balance - balance))
		}
    }

    fn pair(amount: Self::Balance) -> (Self::PositiveImbalance, Self::NegativeImbalance) {
		(Self::burn(amount.clone()), Self::issue(amount))
	}

    fn resolve_into_existing(
		who: &T::AccountId,
		value: Self::NegativeImbalance,
	) -> Result<(), Self::NegativeImbalance> {
		let v = value.peek();
		match Self::deposit_into_existing(who, v) {
			Ok(opposite) => Ok(drop(value.offset(opposite))),
			_ => Err(value),
		}
	}

    fn resolve_creating(
		who: &T::AccountId,
		value: Self::NegativeImbalance,
	) {
		let v = value.peek();
		drop(value.offset(Self::deposit_creating(who, v)));
	}

    fn settle(
		who: &T::AccountId,
		value: Self::PositiveImbalance,
		reasons: frame_support::traits::WithdrawReasons,
		liveness: frame_support::traits::ExistenceRequirement,
	) -> Result<(), Self::PositiveImbalance> {
		let v = value.peek();
		match Self::withdraw(who, v, reasons, liveness) {
			Ok(opposite) => Ok(drop(value.offset(opposite))),
			_ => Err(value),
		}
	}
}

impl<T: Trait> LockableCurrency<T::AccountId> for Module<T> {
    type Moment = T::Moment;

    type MaxLocks = T::MaxLocks;

    fn set_lock(
		id: frame_support::traits::LockIdentifier,
		who: &T::AccountId,
		amount: Self::Balance,
		reasons: frame_support::traits::WithdrawReasons,
	) {

		UTXOStore::<T>::insert(who, UTXOIdType::Lock(id.into()), Self::new_utxo(amount, id.into(), reasons));
		Self::refill_locks(who, Some(id));
    }

    fn extend_lock(
		id: frame_support::traits::LockIdentifier,
		who: &T::AccountId,
		amount: Self::Balance,
		reasons: frame_support::traits::WithdrawReasons,
	) {
		if let Some(current_lock) = UTXOStore::<T>::take(who, UTXOIdType::Lock(id.into())){
			let max_utxo = Self::new_utxo(
				amount.max(current_lock.peek()),
				id.into(),
				reasons.bitand(current_lock.permissions)
			);
			UTXOStore::<T>::insert(who, UTXOIdType::Lock(id.into()), max_utxo);
		} else {
			Self::set_lock(id, who, amount, reasons);
		}
		Self::refill_locks(who, Some(id));
    }

    fn remove_lock(
		id: frame_support::traits::LockIdentifier,
		who: &T::AccountId,
	) {
        if let Some(lock_utxo) = UTXOStore::<T>::take(who, UTXOIdType::UTXO(id.into())){
			UTXOStore::<T>::remove(who, UTXOIdType::Lock(id.into()));
			Self::resolve_creating(who, lock_utxo);
		} else {
			//no lock exists to remove, so noop.
		}
    }
}

impl<T: Trait> pallet_onboard::traits::PowVerifier<T::AccountId, H512> for Module<T> {
	//"PoW" is the preimage of the hash
    fn verify(author: T::AccountId, pow: H512) -> bool {
		let secret_hash = T::SecretHasher::hash(&pow.to_fixed_bytes());
        if let Some((committed, rewarded)) = 
			CommitmentSecrets::<T>::get(secret_hash)
		{
			if rewarded == author { //check this first to gate potential commitment consumption
				if let Ok(_) = Self::consume_commit(committed) {
					// consume secret
					CommitmentSecrets::<T>::remove(secret_hash);
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
    }
}