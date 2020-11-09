//! Helper module to build a genesis configuration for the weight-fee-runtime

use super::{
	AccountId, GenesisConfig, Signature, SudoConfig,
	SystemConfig, WASM_BINARY, AuraConfig, GrandpaConfig
};
use sp_core::{sr25519, Pair};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{IdentifyAccount, Verify};

pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(
		get_from_seed::<AuraId>(s),
		get_from_seed::<GrandpaId>(s),
	)
}

/// Helper function to generate a crypto pair from seed
fn get_from_seed<TPair: Pair>(seed: &str) -> TPair::Public {
	TPair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn account_id_from_seed<TPair: Pair>(seed: &str) -> AccountId
where
	AccountPublic: From<TPair::Public>,
{
	AccountPublic::from(get_from_seed::<TPair>(seed)).into_account()
}

pub fn dev_genesis() -> GenesisConfig {
	testnet_genesis(
		// Root Key
		account_id_from_seed::<sr25519::Pair>("Alice"),
		// Endowed Accounts
		vec![
			account_id_from_seed::<sr25519::Pair>("Alice"),
			account_id_from_seed::<sr25519::Pair>("Bob"),
			account_id_from_seed::<sr25519::Pair>("Alice//stash"),
			account_id_from_seed::<sr25519::Pair>("Bob//stash"),
		],
		// Initial Authorities
		vec![
			authority_keys_from_seed("Alice"),
			authority_keys_from_seed("Bob"),
		],
	)
}

/// Helper function to build a genesis configuration
pub fn testnet_genesis(
	root_key: AccountId, 
	endowed_accounts: Vec<AccountId>,
	initial_authorities: Vec<(AuraId, GrandpaId)>
) -> GenesisConfig {
	GenesisConfig {
		system: Some(SystemConfig {
			code: WASM_BINARY.unwrap().to_vec(),
			changes_trie_config: Default::default(),
		}),
		pallet_sudo: Some(SudoConfig { key: root_key }),
		pallet_grandpa: Some(GrandpaConfig {
			authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect()
		}),
		pallet_aura: Some(AuraConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect()
		})
	}
}
