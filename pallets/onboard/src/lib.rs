#![cfg_attr(not(feature = "std"), no_std)]

/**

Onboarding pallet

"Highly Inefficient" POW-based faucet with mandatory waiting period.
 - where inefficiency is relative to other mechanisms to earn on the chain in question, ie, in DatDot, 
 POW should be scaled relative to processing time as an encoder, if encoding pays y DDT per hour of 
 active computation, POW should pay at most y/x DDT per hour of computation+waiting, where x is a 
 constant scaling factor > 1.

1) Assume account creation is not possible without this pallet.
 -  Users can create accounts "on loan" for other users by submitting their own account as a referrer, 
 and earn back up to (y-z)-y/x [where z is a constant z < y, z >= 0, to make sure referral is still 
 somewhat inefficient in comparison to encoding] from their referred user's activity. This ensures that 
 referrers only have incentive to create accounts for users that either compensate them directly or they 
 believe will be productive members of the network in the future.

Traits/Config:
    UnderlyingCurrency - the currency that is rewarded to accounts from this pallet.
    InterceptableReward - the source of rewards that is intercepted to recompensate referrers.
	PowVerifier - seperate logic that verifies the pow provided to `create_account` given the information
	 provided (pubkey, referrer, etc) and any other runtime information it needs.
    MandatoryDelay - const, the amount of time you force people to wait before unlocking their account.
    ClaimExpiry - const, the amount of time after which a `create_account` it is cleanable.
    CreateAmount - const, the amount created (locked), in an account.

Unsigned Calls: 
 `create_account(origin, new_account_pubkey, referrer_option, pow)` - create a new account with enough
  balance - locked to only be spendable for fees - to begin participating in the network, ensure_unsigned
  is used to ensure that the origin is not an existing account. We ensure, referrer exists if provided,
  and new_account does not exist, and then verify PoW.
 `clean(origin)` - withdraw CreateAmount balance from an account, remove the balance lock, and dec_ref -
  for use after an account is onboarded elsewhere in the chain and no longer wants a part of their 
  balance locked for fees.
 **/

pub mod traits;
pub mod pow;
pub mod weights;
use codec::{Decode, Encode};
use sp_std::prelude::*;
use sp_std::fmt::Debug;
use frame_support::{
	decl_error,
	decl_event, 
	decl_module, 
	error::BadOrigin, 
	fail, 
	traits::{
		Currency, 
		ExistenceRequirement, 
		Get, 
		LockableCurrency, 
		WithdrawReason, 
		WithdrawReasons
	}, 
	transactional, 
	unsigned::{
		TransactionSource
	}
};
use frame_system::{
	self as system,
	ensure_none,
	ensure_signed,
};

use sp_runtime::{DispatchError, Either, Percent, traits::{Zero}, transaction_validity::{InvalidTransaction, TransactionValidity}};


use traits::PowVerifier;
use weights::WeightInfo;
use pallet_eden::traits::{InterceptableReward, Intercepted, Destination};

type BalanceOf<T> = <<T as Config>::UnderlyingCurrency as Currency<<T as system::Trait>::AccountId>>::Balance;
pub trait Config: system::Trait{
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	type UnderlyingCurrency: Currency<Self::AccountId> + LockableCurrency<Self::AccountId>;
	type InterceptedReward: InterceptableReward<Self::AccountId, Self::UnderlyingCurrency>;
	type PowType: Copy + Encode + Decode + Debug 
		+ PartialEq + Eq + From<Self::PowType> + Into<Self::PowType>;
	type PowVerifier: PowVerifier<Self::AccountId, Self::PowType>;
	type MandatoryDelay: Get<<Self as system::Trait>::BlockNumber>;
	type ClaimExpiry: Get<<Self as system::Trait>::BlockNumber>;
	type CreateAmount:  Get<BalanceOf<Self>>;
	type InterceptedPercent: Get<Percent>;
	type LockIdentifier: Get<[u8; 8]>;
	type WeightInfo: WeightInfo;
}

decl_event!(
	pub enum Event<T> 
	where <T as system::Trait>::AccountId {
		OnboardComplete(AccountId, Option<AccountId>),
    }
);

decl_error! {
	pub enum OnboardError for Module<T: Config> {
		AlreadyOnboarded,
		UnlockFailed
    }
}

decl_module!{
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
		type Error = OnboardError<T>;


		#[weight = T::WeightInfo::create_account()]
		pub fn create_account(
			origin,
			new_account_pubkey: T::AccountId,
			referrer_option: Option<T::AccountId>,
			pow: T::PowType
		){
			// if onboarding has already happened or is in progress.
			ensure_none(origin)?;
			if T::UnderlyingCurrency::free_balance(&new_account_pubkey) > Zero::zero()
			{
				fail!(OnboardError::<T>::AlreadyOnboarded);
			} else {
				// if referrer exists, add intercept to repay their PoW
				if let Some(referrer) = referrer_option.clone() {
					let reward_destination = 
					Destination::<
						T::AccountId,
						<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
					>{
						destination: referrer,
						proportion: T::InterceptedPercent::get(),
						amount: T::CreateAmount::get().into()
					};
					T::InterceptedReward::add_intercept(
						Intercepted::Account(new_account_pubkey.clone()),
						reward_destination
					);
				}
				system::Module::<T>::inc_ref(&new_account_pubkey);
				T::UnderlyingCurrency::deposit_creating(&new_account_pubkey, T::CreateAmount::get());
				T::UnderlyingCurrency::set_lock(
					T::LockIdentifier::get(), 
					&new_account_pubkey, 
					T::CreateAmount::get(), 
					WithdrawReasons::except(WithdrawReason::Transfer)
				);
				Self::deposit_event(
					Event::<T>::OnboardComplete(new_account_pubkey, referrer_option)
				);
			}
		}

		#[weight = T::WeightInfo::clean()]
		#[transactional]
		pub fn clean(origin) -> Result<(), DispatchError> {
			let account_result = ensure_signed(origin);
			//TODO consider not withdrawing entire amount
			//we might want to incentivise cleaning state
			//TODO withdraw reasons
			//TODO find some way to ensure dec ref is not called incorrectly
			match account_result {
				Ok(account) => {
					match T::UnderlyingCurrency::withdraw(
						&account, 
						T::CreateAmount::get(), 
						WithdrawReasons::none(), 
						ExistenceRequirement::AllowDeath
					){
						Ok(_) => {
							T::UnderlyingCurrency::remove_lock(T::LockIdentifier::get(), &account);
							system::Module::<T>::dec_ref(&account);
							Ok(())
						},
						_ => {
							Err(OnboardError::<T>::UnlockFailed.into())
						}
					}
				},
				_ => Err(BadOrigin.into())
			}
		// Ok(())
		}
	}
}


impl<T: Config> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;
	fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
		match call {
			Call::create_account(new_account, _, pow) => {
				if T::PowVerifier::verify(new_account.clone(), pow.clone().into()) {
					Ok(Default::default())
				} else {
					InvalidTransaction::BadProof.into()
				}
			},
			_ => Ok(Default::default()),
		}
	}
}
