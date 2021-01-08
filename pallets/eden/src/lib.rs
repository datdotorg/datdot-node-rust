pub mod traits;
pub mod weights;

use codec::Codec;
use sp_std::prelude::*;
use sp_std::fmt::Debug;
use frame_support::{Parameter, decl_error, decl_event, decl_module, decl_storage, error::BadOrigin, fail, traits::{
		Currency, 
		ExistenceRequirement, 
		Get, 
		LockableCurrency, 
		WithdrawReason, 
		WithdrawReasons
	}, transactional, unsigned::{
		TransactionSource
	}};
use frame_system::{
	self as system,
	ensure_none,
	ensure_signed,
};

use sp_runtime::{DispatchError, Either, Percent, traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Member, Zero}, transaction_validity::{InvalidTransaction, TransactionValidity}};
use traits::{Destination, InterceptableReward, Intercepted};
use weights::WeightInfo;

type BalanceOf<T> = <<T as Config>::UnderlyingCurrency as Currency<<T as system::Trait>::AccountId>>::Balance;
pub trait Config: system::Trait{
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
	type UnderlyingCurrency: Currency<Self::AccountId>;
    type InterceptedReward: InterceptableReward<Self::AccountId, Self::UnderlyingCurrency>;
    type MinimumContribution: Get<Percent>;
	type WeightInfo: WeightInfo;
	type Balance: Parameter + Member + AtLeast32BitUnsigned + Codec + Default + Copy +
	MaybeSerializeDeserialize + Debug + 
	Into<<Self::UnderlyingCurrency as Currency<Self::AccountId>>::Balance>;
}

decl_event!(
	pub enum Event{
    }
);

decl_error! {
	pub enum EdenError for Module<T: Config> {
    }
}


decl_storage! {
	trait Store for Module<T: Config> as Eden {
        pub Roles: map 
            hasher(twox_64_concat) Intercepted<T::AccountId>
            => Vec<Destination<T::AccountId, T::Balance>>;
    }
}

decl_module!{
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
		type Error = EdenError<T>;


		#[weight = T::WeightInfo::direct_reward()]
		pub fn direct_reward(origin, amount: T::Balance){
			let account = ensure_signed(origin)?;
			let mut reasons = WithdrawReasons::none();
			reasons.toggle(WithdrawReason::Transfer);
			let withdraw_result = T::UnderlyingCurrency::withdraw(
				&account,
				amount.into(),
				reasons,
				ExistenceRequirement::KeepAlive
			);
			match withdraw_result {
				Ok(successful_amount) => {
					Self::do_reward(
						successful_amount, 
						Intercepted::Account(account.clone())
					).or_else(|unsuccessful_amount|{
						// Revert withdrawal and refund rewarder
						T::UnderlyingCurrency::resolve_into_existing(
							&account,
							unsuccessful_amount
						)
					});
				},
				Err(err) => ()
			};
        }
	}
}

impl<T: Config> Module<T> {

}

impl<T: Config> InterceptableReward<T::AccountId, T::UnderlyingCurrency> for Module<T>{
    fn add_intercept(
        intercepted: Intercepted<T::AccountId>,
		destination: Destination<T::AccountId, 
			<T::UnderlyingCurrency as Currency<T::AccountId>>::Balance
		>
    ){

    }

    fn clear_intercepts(
        intercepted: Intercepted<T::AccountId>
    ){

	}
	
	fn do_reward(
		amount: <T::UnderlyingCurrency as Currency<T::AccountId>>::NegativeImbalance,
		intercepted: Intercepted<T::AccountId>
	) -> Result<(), <T::UnderlyingCurrency as Currency<T::AccountId>>::NegativeImbalance>{
		todo!()
	}
}
