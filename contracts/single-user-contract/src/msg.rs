use cosmwasm_std::Binary;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum InstantiateMsg {
    KeyGen {
        encrypted_user_signing_key: Binary,
        public_signing_key_user: Binary,
        enc_public_key: Binary,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Sign {
        message_hash: Binary,
        public_instance_key_user: Binary,
        proof: Binary,
        commitment: Binary,
    },
}
