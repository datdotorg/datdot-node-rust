use frame_support::traits::Currency;
use sp_runtime::{DispatchError, Percent, RuntimeDebug};
use codec::{
	Encode,
    Decode,
};

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub enum Intercepted<A> {
    Account(A),
    Id(Vec<u8>)
}

#[derive(Decode, PartialEq, Eq, Encode, Clone, RuntimeDebug)]
pub struct Destination<DestinationAddress, DestinationAmount>{
    pub destination: Intercepted<DestinationAddress>,
    pub proportion: Percent,
    pub amount: Option<DestinationAmount>
}

// Intercepts should be FIFO, if any intercept does not get claimed 100%
// at any given queue item, the remainder of the reward carries forward
// to the next intercept until 100% is accounted for, or all intercepts are
pub trait InterceptableReward<A, C: Currency<A>> {
    fn add_intercept(
        intercepted: Intercepted<A>,
        destination: Destination<A, C::Balance>
    );
    fn clear_intercepts(
        intercepted: Intercepted<A>
    );
    fn do_reward(
		amount: C::NegativeImbalance,
		rewardee: &Intercepted<A>
	) -> Result<(), C::NegativeImbalance>;
}