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
type VerificationCount = u32;
type JobIdType = H512;
pub type JobParameters = BTreeMap<ParameterId, ParameterValue>;
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
}

pub trait RewardableJob<AccountType> {
    pub fn reward_job(&self, who: AccountType, parameters: ParameterType);
}

impl<A> RewardableJob<A> for () {
    fn reward_job(&self, _who: A, _parameters: JobParameters) {
        ()
    }
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
    resources: BTreeMap<ParameterId, Resource<T>>,
    issuers: BTreeSet<T::AccountId>,
    verifiers: BTreeSet<T::AccountId>,
    verification: VerificationType,
    resource_source: LiquiditySource<T>,
}

impl<T: Trait> JobType<T> {
    pub fn resolve_parameters(
        &self,
        maybe_additional_parameters: Option<JobParameters>,
    ) -> BTreeMap<ParameterId, ParameterValue> {
        let mut results: BTreeMap<ParameterId, ParameterValue> = BTreeMap::new();
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
    pub fn verify_threshold(&self, verifications: VerificationCount) -> bool {
        match self.verification {
            VerificationType::Simple => verifications > 0,
            VerificationType::Treshold(n) => verifications > n,
            VerificationType::Unanimous => verifications >= self.verifiers.len(),
        }
    }

    pub fn can_issue(&self, attempted_issuer: T::AccountId) -> bool {
        self.issuers.contains(&attempted_issuer) || self.issuers.len().is_zero()
    }
}

impl<T: Trait> RewardableJob<T::AccountId> for JobType<T> {
    //reward resources for job with given Job and parameters
    fn reward_job(&self, who: T::AccountId, parameters: JobParameters) {
        let parameters = self.resolve_parameters(Some(JobParameters));
        for (parameter, resource) in self.resources {
            let amount = parameters.get(parameter);
            resource.reward_resource(who, amount, self.resource_source);
        }
    }
}

impl<T: Trait> Default for JobType<T>{
    fn default() -> Self {
        JobType::<T> {
            description: Vec::new(),
            default_parameters: BTreeMap::new(),
            resources: BTreeMap::new(),
            issuers: BTreeSet::new(),
            verifiers: BTreeSet::new(),
            verification: VerificationType::Simple,
            resource_source: LiquiditySource::None
        }
    }
}
pub enum LiquiditySource<T: Trait> {
    //attempt to pull liquidity from a custom lock on the local chain.
    Local(T::AccountId, Vec<u8>),
    //attempt to pull liquidity via XCM by converting assets held on other chains.
    Foreign(MultiLocation, MultiAsset),
    //fail if liquidity is requested.
    None

}
trait LiquidityProvider
{
    
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

impl<T: Trait> Resource<T> {
    pub fn reward_resource(&self, who: T::AccountId, amount: ParameterValue, from: JobType<T>) -> Result<(),()> {
        //if `from` is not directly a member of `self.issuers`
        if !(self.issuers.contains(ResourceIssuer::Job(from)) || self.issuers.contains(from.resource_source)){
            //attempt withdraw from `from.issuer` to reward for job.

            Err(())
        }
        //and reward `who`
        //if insufficient balance to withdraw
        //return 
    }

    pub fn can_issue(&self, attempted_issuer: ResourceIssuer<T>) -> bool {
        self.issuers.contains(&attempted_issuer)
    }
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
        pub Jobs: double_map hasher(blake2_128_concat) JobType<T>, hasher(twox_64_concat) JobIdType => Option<(VerificatonCount, T::AccountId)>;
		pub ResourceCounts: double_map hasher(blake2_128_concat) Resource<T>, hasher(twox_64_concat) T::AccountId => ParameterValue;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    }
}

impl<T: Trait> Module<T> {
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

    //reward resources for job with given Job and parameters
    fn reward_job(job: JobType<T>, job_id: JobIdType, parameters: JobParameters) {
        if let Some((_, jobber)) = Jobs::<T>::get(job_id){
            job.reward_job(jobber, parameters);
        }
    }
}
