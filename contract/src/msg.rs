use scrt_sss::{Secp256k1Scalar, Share};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct InstantiateMsg {
    /// When the contract is initialized, each party should provide a pubkey (used in ECDH to encrypt shares)
    /// We can assume for simplicity that the user that initializes the contract supplies these
    // public_keys = Vec<String>
    /// The number of users that will be a part of the secret sharing and signing process
    pub number_of_users: u32,
    /// You need (t + 1) shares to reconstruct the secret value
    pub signing_threshold: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    CreatePresig {
        user_index: u32,
        k_user_shares: Vec<Share<Secp256k1Scalar>>,
        a_user_shares: Vec<Share<Secp256k1Scalar>>,
        user_zero_shares1: Vec<Share<Secp256k1Scalar>>,
        user_zero_shares2: Vec<Share<Secp256k1Scalar>>,
        public_instance_key: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct CreatePresigResponse {
    result: Status,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Success,
    Error,
}

/// also possible to get the input with the x,y values rather than a 64 byte string
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct PublicKey {
//     x: String,
//     y: String
// }

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// User that wants to read their share (todo: authentication)
    ReadPresig { user_index: u32 },
    #[cfg(test)]
    TestReadInstanceSecret {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ReadPresigResponse {
    pub(crate) k_user_share: Share<Secp256k1Scalar>,
    pub(crate) k_chain_share: Share<Secp256k1Scalar>,
    pub(crate) public_instance_key: String,
    pub(crate) a_user_share: Share<Secp256k1Scalar>,
    pub(crate) a_chain_share: Share<Secp256k1Scalar>,
    pub(crate) user_zero_share1: Share<Secp256k1Scalar>,
    pub(crate) user_zero_share2: Share<Secp256k1Scalar>,
    pub(crate) chain_zero_share1: Share<Secp256k1Scalar>,
    pub(crate) chain_zero_share2: Share<Secp256k1Scalar>
}
