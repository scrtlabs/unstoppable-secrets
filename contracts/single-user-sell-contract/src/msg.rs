use cosmwasm_std::Binary;
use scrt_sss::{Secp256k1Point, Secp256k1Scalar};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
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
        message_hash: Secp256k1Scalar,
        public_instance_key_user: Secp256k1Point,
        proof: Binary,
        commitment: Binary,
    },
    Bid {
        buyer_enc_public_key: Binary,
        proof: Binary,
    },
    Sell {
        encrypted_buyer_signing_key: Binary,
        buyer_enc_public_key: Binary,
        proof: Binary,
        payment_address: String,
    },
}
