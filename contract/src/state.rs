use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use cosmwasm_std::{StdError, StdResult, Storage};
use cw_storage_plus::Map;
use scrt_sss::{Secp256k1Point, Secp256k1Scalar, Share};

pub static CONFIG_KEY: &[u8] = b"config";

pub fn save_state(storage: &mut dyn Storage, state: State) -> StdResult<()> {
    const GAME_STATE: Map<&[u8], Vec<u8>> = Map::new("game_state");

    // binary encoding because it's more efficient and cw_storage::map uses json encoding lol
    let encoded =
        bincode2::serialize(&state).map_err(|_| StdError::generic_err("Failed to encode"))?;

    GAME_STATE.save(storage, CONFIG_KEY, &encoded)
}

pub fn load_state(storage: &dyn Storage) -> StdResult<State> {
    const GAME_STATE: Map<&[u8], Vec<u8>> = Map::new("game_state");

    let resp = GAME_STATE.load(storage, CONFIG_KEY)?;

    bincode2::deserialize(&resp)
        .map_err(|e| StdError::generic_err(format!("Failed to decode: {:?}", e)))
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct State {
    // Public params
    pub num_of_users: u8,
    pub threshold: u8,

    // Keygen
    pub public_key: Secp256k1Point,
    pub sk_chain: Secp256k1Scalar,
    pub sk_user_shares: Vec<Share<Secp256k1Scalar>>,
    pub sk_chain_shares: Vec<Share<Secp256k1Scalar>>,
    pub sk_chain_shares_final: Vec<Share<Secp256k1Scalar>>,
    
    //// Presig data
    // k, R=k*G (instance key pair)
    pub k_chain_shares: Vec<Share<Secp256k1Scalar>>,
    pub k_user_shares: Vec<Share<Secp256k1Scalar>>,
    pub k_chain_shares_final: Vec<Share<Secp256k1Scalar>>,
    pub public_instance_key: Secp256k1Point,

    // a (random value)
    pub a_chain_shares: Vec<Share<Secp256k1Scalar>>,
    pub a_user_shares: Vec<Share<Secp256k1Scalar>>,
    pub a_chain_shares_final: Vec<Share<Secp256k1Scalar>>,

    // zero values
    pub chain_zero_shares1: Vec<Share<Secp256k1Scalar>>,
    pub chain_zero_shares2: Vec<Share<Secp256k1Scalar>>,
    pub user_zero_shares1: Vec<Share<Secp256k1Scalar>>,
    pub user_zero_shares2: Vec<Share<Secp256k1Scalar>>,

    pub chain_zero_shares_final1: Vec<Share<Secp256k1Scalar>>,
    pub chain_zero_shares_final2: Vec<Share<Secp256k1Scalar>>,

    // sig values
    pub sig_num_shares: Vec<Share<Secp256k1Scalar>>,
    pub sig_denom_shares: Vec<Share<Secp256k1Scalar>>,

    #[cfg(test)]
    pub chain_private_instance_key: Secp256k1Scalar,
    // pub chain_private_key: Secp256k1Scalar,
}
