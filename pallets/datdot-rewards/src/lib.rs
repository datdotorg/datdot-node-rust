#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Codec, Decode, Encode, EncodeLike};
use frame_support::{
    debug::native,
    decl_error, decl_event, decl_module, decl_storage, ensure, fail,
    storage::{IterableStorageDoubleMap, IterableStorageMap, StorageMap, StorageValue},
    traits::{Currency, EnsureOrigin, ExistenceRequirement, Get, Randomness, WithdrawReasons},
    weights::{DispatchClass::Operational, Pays},
    Parameter,
};
use frame_system::{self as system, ensure_root, ensure_signed, RawOrigin};
use pallet_wealth_tax::{AgedUTXO, CustomLockableCurrency, UTXOIdType};
use sp_core::H512;
use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Member, Zero};
use sp_std::collections::{btree_map::BTreeMap, btree_set::BTreeSet};
use sp_std::fmt::Debug;
use sp_std::prelude::*;

type ParameterId = Vec<u8>;
type ParameterValue = u32;
type ResourceId = H512;
type JobIdType = H512;
type JobParameters = BTreeMap<ParameterId, ParameterValue>;
type UTXOId = UTXOIdType<Vec<u8>>;
type UTXOType<T: Trait> = AgedUTXO<T::Balance, T::BlockNumber>;

pub trait Trait: system::Trait {
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
    type Balance: Parameter
        + Member
        + AtLeast32BitUnsigned
        + Codec
        + Default
        + Copy
        + MaybeSerializeDeserialize
        + Debug;
    type UnderlyingCurrency: Currency<Self::AccountId> + CustomLockableCurrency<Self::AccountId, Self::Balance, UTXOId, UTXOType<Self>>;
}

enum VerificationType {
    Simple,
    Treshold(u32),
    Unanimous,
}
//jobs should be immutable (they are used as keys)
//jobs have descriptions,
//jobs have optional and default parameters (that determine their rewards)
//jobs have optional issuers and verifiers (accountIds)
//jobs have optional limitations (max completions, etc.)

//both users and the runtime can define custom jobs
//a user consumes a commitment to define a job onchain,
//job resources are consumed from a lock if neccessary
pub struct JobType<T: Trait> {
    description: Vec<u8>,
    default_parameters: JobParameters,
    resources: BTreeMap<ParameterId, ResourceId>,
    issuers: BTreeSet<T::AccountId>,
    verifiers: BTreeSet<T::AccountId>,
    verification: VerificationType,
    resource_source: LiquiditySource<T>,
}

impl<T: Trait> JobType<T> {
    pub fn resolve_parameters(
        &self,
        maybe_additional_parameters: Option<JobParameters>,
    ) -> BTreeMap<ResourceId, ParameterValue> {
        let mut results: BTreeMap<ResourceId, ParameterValue> = BTreeMap::new();
        let mut merged_parameters = self.default_parameters.clone();
        if let Some(mut additional_parameters) = maybe_additional_parameters {
            merged_parameters.append(&mut additional_parameters);
        }
        for (parameter, resource) in self.resources.clone() {
            let maybe_value = merged_parameters.get(&parameter);
            if let Some(&value) = maybe_value {
                results.insert(resource, value);
            }
        }
        results
    }

    //verifications should come PRE-AUTHENTICATED - this function will only count the treshold
    //this is because we allow the runtime to create verifications and it may not neccesarily have
    //accountIDs/verifiers to verify against here.
    pub fn verify_threshold(&self, verifications: BTreeSet<T::AccountId>) -> bool {
        match self.verification {
            VerificationType::Simple => verifications.len() > 0,
            VerificationType::Treshold(n) => verifications.len() > n as usize,
            VerificationType::Unanimous => verifications.len() >= self.verifiers.len(),
        }
    }

    pub fn can_issue(&self, attempted_issuer: T::AccountId) -> bool {
        self.issuers.contains(&attempted_issuer) || self.issuers.len().is_zero()
    }
}

pub enum LiquiditySource<T: Trait> {
    //attempt to pull liquidity from a custom lock on the local chain.
    Local(T::AccountId, Vec<u8>),
    //attempt to pull liquidity via XCM by converting assets held on other chains.
    Foreign(MultiLocation, MultiAsset),
}

trait LiquidityProvider<
    T: Trait,
    C: Currency<T::AccountId>
        + CustomLockableCurrency<
            T::AccountId,
            T::Balance,
            UTXOId,
            UTXOType<T>,
        >,
>
{
    //attempt to withdraw amount from who - on success returns the imbalance (to deposit elsewhere)
    fn attempt_withdraw(who: T::AccountId, amount: T::Balance) -> Result<C::NegativeImbalance, ()>;

    //attempt to lock amount on who, if not completely successful, fail.
    fn attempt_lock(who: T::AccountId, amount: T::Balance) -> Result<(), ()>;

    //deposit amount to who, infallible
    fn deposit(who: T::AccountId, amount: C::NegativeImbalance);
}

impl<
        T: Trait,
        C: Currency<T::AccountId>
            + CustomLockableCurrency<
                T::AccountId,
                T::Balance,
                UTXOId,
                UTXOType<T>,
            >,
    > LiquidityProvider<T, C> for JobType<T>
{
    fn attempt_withdraw(who: T::AccountId, amount: T::Balance) -> Result<C::NegativeImbalance, ()> {
        match C::withdraw(
            &who,
            amount,
            WithdrawReasons::all(),
            ExistenceRequirement::KeepAlive,
        ) {
            Ok(_) => {}
            Err(_) => {}
        }
    }

    fn attempt_lock(who: T::AccountId, amount: T::Balance) -> Result<(), ()> {
        todo!()
    }

    fn deposit(who: T::AccountId, amount: C::NegativeImbalance) {
        todo!()
    }
}

pub enum ResourceIssuer<T: Trait> {
    Job(JobIdType),
    Account(T::AccountId)
}

pub struct Resource<T: Trait> {
    description: Vec<u8>,
    //The jobs and/or accounts, allowed to mint this resource.
    issuers: BTreeSet<ResourceIssuer<T>>
}

decl_event!(
    pub enum Event {}
);

decl_error! {
    pub enum RewardError for Module<T: Trait> {

    }
}

decl_storage! {
    trait Store for Module<T: Trait> as Reward{
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    }
}

impl<T: Trait> Module<T> {
    //reward resources for job with given Job and parameters
    pub fn reward_job(job: JobType<T>, parameters: JobParameters) {
        todo!()
    }

    pub fn define_job() {
        todo!()
    }

    //define new resource, or redefine existing resources (in terms of onchain currency).
    //resources have optional issuers (in terms of jobs and accounts that can issue them "freely")
    pub fn define_resource() {
        todo!()
    }

    //remove a given job from onchain jobs.
    pub fn resolve_job() {
        todo!()
    }

    //resolve all balances of a given resource (into it's counterpart) and delete the resource
    pub fn resolve_resource() {
        todo!()
    }

    //the runtime can always issue any job
    pub fn issue_job() {
        todo!()
    }

    //the runtime can always verify any job
    pub fn verify_job() {}

    //do not immediately verify, instead add a *single* approval
    //it is up to external pallets (or this pallet) to verify
    //they do not duplicate approvals.
    pub fn approve_job() {}
}
