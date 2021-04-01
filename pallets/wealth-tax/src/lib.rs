#![cfg_attr(not(feature = "std"), no_std)]


use std::ops::{BitAnd, BitOr, Mul};

use sp_runtime::{Perbill, RuntimeDebug, traits::{AtLeast32Bit, AtLeast32BitUnsigned, CheckedSub, MaybeSerializeDeserialize, Member, Saturating, Scale, Zero}};
use sp_std::prelude::*;
use sp_std::convert::TryInto;
use sp_std::fmt::Debug;
use sp_std::mem;
use frame_support::{Parameter, decl_error, decl_event, decl_module, decl_storage, ensure, fail, storage::{
		StorageMap,
		StorageValue,
		IterableStorageMap,
		IterableStorageDoubleMap,
	}, traits::{Currency, EnsureOrigin, Get, Imbalance, LockIdentifier, LockableCurrency, SignedImbalance, TryDrop, WithdrawReason, WithdrawReasons}, weights::{
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

pub trait Trait: system::Trait{
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
	type Balance: Parameter + Member + AtLeast32BitUnsigned + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug;
	type Moment: Parameter + Default + AtLeast32Bit
	+ Scale<Self::BlockNumber, Output = Self::Moment> + Copy;
	type MaxLocks: Get<u32>;	
	type MinimumBalance: Get<Self::Balance>;
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
    }
}

decl_module!{
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		
    }
}



impl<T: Trait> Module<T> {
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

	fn refill_locks(who: &T::AccountId, maybe_id: Option<LockIdentifier>){
		if let Some(lock_id) = maybe_id {
			match 
			(
				UTXOStore::<T>::get(who, UTXOIdType::Lock(lock_id.into())),
				UTXOStore::<T>::get(who, UTXOIdType::UTXO(lock_id.into()))
			){
				_ => ()
			}
		} else {
			let all_locks: Vec<LockIdentifier> =
			UTXOStore::<T>::iter_prefix(who).filter_map(|(id, _)|{
				let mut id_holder: [u8; 8] = [0,0,0,0,0,0,0,0];
				match id {
					UTXOIdType::Lock(i_d) => {
						id_holder.copy_from_slice(&i_d);
						Some(id_holder)
					},
					_ => None
				}
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
	) -> Result<Self::PositiveImbalance, sp_runtime::DispatchError> {
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
	) -> Result<Self::NegativeImbalance, sp_runtime::DispatchError> {
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
					UTXOStore::<T>::insert(who, utxo_id, utxo_change);
				}
			}
			Self::refill_locks(who, None);
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
				reasons.bitor(current_lock.permissions)
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
