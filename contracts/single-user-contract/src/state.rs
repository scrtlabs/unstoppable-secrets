use cosmwasm_std::Binary;
use cw_storage_plus::Item;
use paillier::{BigInt, EncodedCiphertext, EncryptionKey};
use scrt_sss::{Secp256k1Point, Secp256k1Scalar};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    pub chain_signing_key: Secp256k1Scalar,
    pub public_signing_key_chain: Secp256k1Point,
    pub encrypted_user_signing_key: EncodedCiphertext<BigInt>,
    pub public_signing_key_user: Secp256k1Point,
    pub enc_public_key: EncryptionKey,
    pub public_signing_key: Secp256k1Point,
}

pub const CONFIG: Item<Config> = Item::new("encryption_key");
