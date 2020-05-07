use sp_core::{Pair, Public, sr25519};
use datdot_runtime::{
	primitives::AccountId, primitives::Signature, primitives::Balance,
	BabeConfig, BalancesConfig, GenesisConfig, GrandpaConfig, ElectionsConfig,
	SudoConfig, SystemConfig, WASM_BINARY, IndicesConfig, ImOnlineConfig,
	AuthorityDiscoveryConfig, CouncilConfig, TechnicalCommitteeConfig,
	DemocracyConfig, SessionConfig, SessionKeys,
	constants::currency::*
};
use sp_consensus_babe::AuthorityId as BabeId;
use sp_finality_grandpa::AuthorityId as GrandpaId;
use pallet_im_online::sr25519::{AuthorityId as ImOnlineId};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_runtime::traits::{Verify, IdentifyAccount};
use sc_service::ChainType;

// Note this is the URL for the telemetry server
//const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate stash, controller and session key from seed
pub fn authority_keys_from_seed(seed: &str) -> (
	AccountId,
	AccountId,
	GrandpaId,
	BabeId,
	ImOnlineId,
	AuthorityDiscoveryId,
) {
	(
		get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
		get_account_id_from_seed::<sr25519::Public>(seed),
		get_from_seed::<GrandpaId>(seed),
		get_from_seed::<BabeId>(seed),
		get_from_seed::<ImOnlineId>(seed),
		get_from_seed::<AuthorityDiscoveryId>(seed),
	)
}

pub fn development_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Development",
		"dev",
		ChainType::Development,
		|| testnet_genesis(
			vec![
				authority_keys_from_seed("Alice"),
			],
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			Some(vec![
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				get_account_id_from_seed::<sr25519::Public>("Bob"),
				get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
				get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
			]),
			true,
		),
		vec![],
		None,
		None,
		None,
		None,
	)
}

pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Local Testnet",
		"local_testnet",
		ChainType::Local,
		|| testnet_genesis(
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			Some(vec![
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				get_account_id_from_seed::<sr25519::Public>("Bob"),
				get_account_id_from_seed::<sr25519::Public>("Charlie"),
				get_account_id_from_seed::<sr25519::Public>("Dave"),
				get_account_id_from_seed::<sr25519::Public>("Eve"),
				get_account_id_from_seed::<sr25519::Public>("Ferdie"),
				get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
				get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
				get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
				get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
				get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
				get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
			]),
			true,
		),
		vec![],
		None,
		None,
		None,
		None,
	)
}

fn session_keys(
	grandpa: GrandpaId,
	babe: BabeId,
	im_online: ImOnlineId,
	authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
	SessionKeys { grandpa, babe, im_online, authority_discovery }
}

fn testnet_genesis(
	initial_authorities: Vec<(
		AccountId,
		AccountId,
		GrandpaId,
		BabeId,
		ImOnlineId,
		AuthorityDiscoveryId,
	)>,
root_key: AccountId,
endowed_accounts: Option<Vec<AccountId>>,
enable_println: bool,
) -> GenesisConfig {
let endowed_accounts: Vec<AccountId> = endowed_accounts.unwrap_or_else(|| {
	vec![
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		get_account_id_from_seed::<sr25519::Public>("Bob"),
		get_account_id_from_seed::<sr25519::Public>("Charlie"),
		get_account_id_from_seed::<sr25519::Public>("Dave"),
		get_account_id_from_seed::<sr25519::Public>("Eve"),
		get_account_id_from_seed::<sr25519::Public>("Ferdie"),
		get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
		get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
		get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
		get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
		get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
		get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
	]
});
let num_endowed_accounts = endowed_accounts.len();

const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
const STASH: Balance = 100 * DOLLARS;

GenesisConfig {
	frame_system: Some(SystemConfig {
		code: WASM_BINARY.to_vec(),
		changes_trie_config: Default::default(),
	}),
	pallet_balances: Some(BalancesConfig {
		balances: endowed_accounts.iter().cloned()
			.map(|k| (k, ENDOWMENT))
			.chain(initial_authorities.iter().map(|x| (x.0.clone(), STASH)))
			.collect(),
	}),
	pallet_indices: Some(IndicesConfig {
		indices: vec![],
	}),
	pallet_session: Some(SessionConfig {
		keys: initial_authorities.iter().map(|x| {
			(x.0.clone(), x.0.clone(), session_keys(
				x.2.clone(),
				x.3.clone(),
				x.4.clone(),
				x.5.clone(),
			))
		}).collect::<Vec<_>>(),
	}),
	pallet_democracy: Some(DemocracyConfig::default()),
	pallet_elections_phragmen: Some(ElectionsConfig {
		members: endowed_accounts.iter()
					.take((num_endowed_accounts + 1) / 2)
					.cloned()
					.map(|member| (member, STASH))
					.collect(),
	}),
	pallet_collective_Instance1: Some(CouncilConfig::default()),
	pallet_collective_Instance2: Some(TechnicalCommitteeConfig {
		members: endowed_accounts.iter()
					.take((num_endowed_accounts + 1) / 2)
					.cloned()
					.collect(),
		phantom: Default::default(),
	}),
	pallet_sudo: Some(SudoConfig {
		key: root_key,
	}),
	pallet_babe: Some(BabeConfig {
		authorities: vec![],
	}),
	pallet_im_online: Some(ImOnlineConfig {
		keys: vec![],
	}),
	pallet_authority_discovery: Some(AuthorityDiscoveryConfig {
		keys: vec![],
	}),
	pallet_grandpa: Some(GrandpaConfig {
		authorities: vec![],
	}),
	pallet_membership_Instance1: Some(Default::default()),
	}
}
