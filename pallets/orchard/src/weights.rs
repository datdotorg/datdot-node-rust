use frame_support::{weights::Weight};

pub trait WeightInfo {
    fn direct_reward() -> Weight;
    fn add_manual_intercept() -> Weight;
}

impl WeightInfo for () {
    fn direct_reward() -> Weight {
        2000000
    }

    fn add_manual_intercept() -> Weight {
        2000000
    }
}