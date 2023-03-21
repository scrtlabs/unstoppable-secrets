use cosmwasm_std::Binary;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct InstantiateMsg {
    /// paillier encryption key
    pub encryption_key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ExecuteMsg {
    pub encrypted_c1: Binary,
    pub encrypted_c2: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Get encrption key
    GetEncryptionKey {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct GetEncryptionKey {
    pub encryption_key: Binary,
}
