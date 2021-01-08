use frame_support::{weights::Weight};

pub trait WeightInfo {
    fn direct_reward() -> Weight;
}

impl WeightInfo for () {
    fn direct_reward() -> Weight {
        2000000
    }
}