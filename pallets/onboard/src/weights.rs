use frame_support::{weights::Weight};

pub trait WeightInfo {
    fn create_account() -> Weight;
    fn clean() -> Weight;
}

impl WeightInfo for () {
    fn create_account() -> Weight {
        2000000
    }

    fn clean() -> Weight {
        1000000
    }
}