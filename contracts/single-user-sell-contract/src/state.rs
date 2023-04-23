use cosmwasm_std::{Addr, Coin};
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

pub const CONFIG: Item<Config> = Item::new("config");

pub const BID_DEPOSIT: Item<Coin> = Item::new("bid_deposit");
pub const BID_BIDDER: Item<Addr> = Item::new("bid_bidder");
