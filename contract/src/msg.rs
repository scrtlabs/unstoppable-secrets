use cosmwasm_std::{Addr, Coin};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    /// When the contract is initialized, each party should provide a pubkey (used in ECDH to encrypt shares)
    /// We can assume for simplicity that the user that initializes the contract supplies these
    // public_keys = Vec<String>
    /// The number of users that will be a part of the secret sharing and signing process
    pub number_of_users: u32,
    /// You need (t + 1) shares to reconstruct the secret value
    pub signing_threshold: u32
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    CreateShare {
        user_index: u32,
        shares: Vec<String>,
        public_key: String
    }
}

/// also possible to get the input with the x,y values rather than a 64 byte string
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct PublicKey {
//     x: String,
//     y: String
// }

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// User that wants to read their share (todo: authentication)
    ReadShare {
        user_index: u32
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ReadShareResponse {
    pub(crate) user_share: String,
    pub(crate) chain_share: String,
    pub(crate) public_key: String
}
