pub mod interception;
pub mod weights;

use codec::Codec;
use sp_std::prelude::*;
use sp_std::fmt::Debug;
use frame_support::{Parameter, decl_error, decl_event, decl_module, decl_storage, ensure, error::BadOrigin, fail, traits::{Currency, ExistenceRequirement, Get, Imbalance, LockableCurrency, WithdrawReason, WithdrawReasons}, transactional, unsigned::{
		TransactionSource
	}};
use frame_system::{
	self as system,
	ensure_none,
	ensure_signed,
};

use sp_runtime::{DispatchError, Either, Percent, traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Member, Saturating, Zero}, transaction_validity::{InvalidTransaction, TransactionValidity}};
use interception::{Destination, InterceptableReward, Intercepted};
use system::ensure_root;
use weights::WeightInfo;

type BalanceOf<T> = <<T as Config>::UnderlyingCurrency as Currency<<T as system::Trait>::AccountId>>::Balance;
pub trait Config: system::Trait{
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
	type UnderlyingCurrency: Currency<Self::AccountId>;
    type InterceptedReward: InterceptableReward<Self::AccountId, Self::UnderlyingCurrency>;
	type MinimumContributionPercent: Get<Percent>;
	type MinimumContributionAmount: Get<<Self::UnderlyingCurrency as Currency<Self::AccountId>>::Balance>;
	type MaximumContributionCount: Get<u8>;
	type WeightInfo: WeightInfo;
}

decl_event!(
	pub enum Event{
    }
);

decl_error! {
	pub enum orchardError for Module<T: Config> {
		PermissionError,
		AmountError
    }
}


decl_storage! {
	trait Store for Module<T: Config> as orchard {
        pub Branches: map 
            hasher(twox_64_concat) Intercepted<T::AccountId>
			=> Vec<Destination<T::AccountId, <T::UnderlyingCurrency as Currency<T::AccountId>>::Balance>>;
		pub InterceptOwner: map hasher(twox_64_concat) Vec<u8> => T::AccountId;
    }
}

decl_module!{
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
		type Error = orchardError<T>;

		#[weight = T::WeightInfo::add_manual_intercept()]
		pub fn transfer_id(
			origin,
			intercept: Vec<u8>,
			new_owner: T::AccountId
		){
			let check_owner = ensure_signed(origin)?;
			if Self::is_intercept_owner(&intercept, check_owner) {
				Self::set_intercept_owner(&intercept, new_owner);
			} else {
				fail!(orchardError::<T>::PermissionError);
			}
		}

		#[weight = T::WeightInfo::add_manual_intercept()]
		pub fn set_intercepts(
			origin,
			rewardee: Intercepted<T::AccountId>, 
			intercepts: Vec<Destination<T::AccountId, 
				<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
			>>
		){
			//ensure origin
			
		}

		#[weight = T::WeightInfo::direct_reward()]
		pub fn direct_reward(
			origin, 
			amount: 
				<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
			){
			let account = ensure_signed(origin)?;
			let mut reasons = WithdrawReasons::none();
			reasons.toggle(WithdrawReason::Transfer);
			ensure!(amount > T::MinimumContributionAmount::get(), orchardError::<T>::AmountError);
			let withdraw_result = T::UnderlyingCurrency::withdraw(
				&account,
				amount,
				reasons,
				ExistenceRequirement::KeepAlive
			);
			match withdraw_result {
				Ok(successful_amount) => {
					Self::do_reward(
						successful_amount, 
						&Intercepted::Account(account.clone())
					).or_else(|unsuccessful_amount|{
						// Revert withdrawal and refund rewarder
						T::UnderlyingCurrency::resolve_into_existing(
							&account,
							unsuccessful_amount
						)
					}).map_err(|x|{
						T::UnderlyingCurrency::resolve_creating(
							&account,
							x
						);
					}).ok();
				},
				Err(err) => {
					fail!(err);
				}
			};
        }
	}
}

impl<T: Config> Module<T> {

	fn is_intercept_owner(id: &Vec<u8>, owner: T::AccountId) -> bool {
		owner == <InterceptOwner<T>>::get(id)
	}

	fn set_intercept_owner(id: &Vec<u8>, owner: T::AccountId){
		<InterceptOwner<T>>::insert(id, owner);
	}
}

impl<T: Config> InterceptableReward<T::AccountId, T::UnderlyingCurrency> for Module<T>{
    fn add_intercept(
        intercepted: Intercepted<T::AccountId>,
		destination: Destination<T::AccountId, 
			<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
		>
    ){
		let mut current_intercepts = <Branches<T>>::get(&intercepted);
		current_intercepts.push(destination.clone());
		<Branches<T>>::insert(&intercepted, current_intercepts);
    }

    fn clear_intercepts(
        intercepted: Intercepted<T::AccountId>
    ){
		<Branches<T>>::remove(&intercepted);
	}
	
	fn do_reward(
		amount: <T::UnderlyingCurrency as Currency<T::AccountId>>::NegativeImbalance,
		rewardee: &Intercepted<T::AccountId>
	) -> Result<(), <T::UnderlyingCurrency as Currency<T::AccountId>>::NegativeImbalance>{
		let mut current_intercepts = <Branches<T>>::get(&rewardee);
		let mut percent_count: Percent = Percent::zero();
		let mut intercept_count: u8 = 0;
		let raw_amount = amount.peek().clone();
		if raw_amount < T::MinimumContributionAmount::get(){return Err(amount);}
		//take intercepts from vec until percent == 100 OR intercept count == max
		//if intercept_count is not max, "expand" each intercept to it's own intercepts
		// until intercept_count >= max
		// awardee is added as a final intercept with the remainder of the
		// percentage, or replacing final intercept otherwise. amount is then split into portions up to each their amounts for each 
		// intercept and then `resolve()`d into the accounts sequentially
		// results are collected and NegativeImbalances are coalesced and returned
		// non-existing accounts are removed from intercepts and amounts are reduced by
		// the received amount, and then Branches is updated accordingly.
		let iter_intercepts = current_intercepts.clone();
		let mut raw_intercepts: Vec<Destination::<
		T::AccountId, 
		<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
		>> = iter_intercepts.into_iter().take_while(|intercept|{
			let mut should_continue = true;
			let new_percent_count = percent_count.saturating_add(intercept.proportion);
			if new_percent_count.is_one() {
				should_continue = false;
			} else {
				percent_count = new_percent_count;
				intercept_count += 1;
				should_continue = intercept_count < T::MaximumContributionCount::get()
			}
			should_continue
		}).collect();
		//if percent_count is below minimum, send remainder-to-minimum to Intercept::Id(Vec::new())
		if percent_count < T::MinimumContributionPercent::get() {
			let default_destination = Destination::<
			T::AccountId, 
			<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
			> {
				destination: Intercepted::Id(Vec::new()),
				proportion: T::MinimumContributionPercent::get().saturating_sub(percent_count),
				amount: None
			};
			raw_intercepts.push(default_destination);
			percent_count = Percent::from(T::MinimumContributionPercent::get());
		}
		// pay rewardee immediately
		let remainder = Percent::one().saturating_sub(percent_count);
		let self_account = match rewardee {
			Intercepted::Account(acc) => {
				acc.clone()
			},
			Intercepted::Id(int_id) => {
				<InterceptOwner<T>>::get(int_id)
			}
		};
		let self_amount = remainder.mul_floor(raw_amount);
		let (self_imbalance, mut other_imbalance) = amount.split(self_amount);
		<T::UnderlyingCurrency as Currency<T::AccountId>>::resolve_creating(&self_account, self_imbalance);
		// for each intercept, call do_reward() with the proportion reserved for them
		for intercept in raw_intercepts {
			let sub = &intercept.destination;
			let factor = intercept.proportion;
			let outcome = 
			if let Some(max) = intercept.amount {
				let attempt_amount = max.max(factor.mul_floor(raw_amount));
				let temp =
					other_imbalance.split(attempt_amount);
				let attempt_imbalance = temp.0;
				other_imbalance = temp.1;
				let reward_result = Self::do_reward(attempt_imbalance, sub);
				let reduce_amount;
				// subtract successful amount from amount, save amount back into branch
				let result = if let Err(failed_amount) = reward_result {
					reduce_amount = attempt_amount - failed_amount.peek();
					Err(failed_amount)
				} else {
					reduce_amount = attempt_amount;
					Ok(())
				};
				if let Some(pos) = current_intercepts
				.clone()
				.iter()
				.position(|x|x.destination == intercept.destination) {
					// if intercept cap has not been consumed, update it, otherwise, simply remove it
					if max > reduce_amount {
						let new_destination = Destination::<
							T::AccountId, 
							<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
						> {
							destination: sub.clone(),
							proportion: factor.clone(),
							amount: Some(max - reduce_amount)
						};
						current_intercepts.push(new_destination);
					}
					current_intercepts.swap_remove(pos);
				}
				return result;
			} else {
				let attempt_amount = factor.mul_floor(raw_amount);
				let temp = other_imbalance.split(attempt_amount);
				let attempt_imbalance = temp.0;
				other_imbalance = temp.1;
				Self::do_reward(attempt_imbalance, sub)
			};
			//accumulate failures.
			other_imbalance.maybe_subsume(outcome.err());
		};
		//save mutated branches
		<Branches<T>>::insert(&rewardee, current_intercepts);
		//if reward amount is below minimum, propagate up to parent&sibs, else, recurse down
		if other_imbalance.peek() < T::MinimumContributionAmount::get() {
			Err(other_imbalance)
		} else {
			Self::do_reward(other_imbalance, rewardee)
		}
	}
}
