use frame_support::traits::Currency;
use sp_runtime::{Either, Percent};

pub type Intercepted<A> = Either<A, Vec<u8>>;

// Intercepts should be FIFO, if any intercept does not get claimed 100%
// at any given queue item, the remainder of the reward carries forward
// to the next intercept
pub trait InterceptableReward<A, C: Currency<A>> {
    fn add_intercept(
        intercepted: Intercepted<A>,
        destination: A, 
        proportion: Percent, 
        amount: C::Balance
    );
    fn clear_intercepts(
        intercepted: Intercepted<A>
    );
}