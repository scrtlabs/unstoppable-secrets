use ethereum_types::H160;
use scrt_sss::{Secp256k1Scalar, Share};
use serde::{Deserialize, Serialize};
use tx_from_scratch::Transaction;

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
    KeyGen {
        user_public_key: String,
        user_secret_key_shares: Vec<Share<Secp256k1Scalar>>,
    },
    Sign {
        user_index: u32,
        user_sig_num_share: Share<Secp256k1Scalar>,
        user_sig_denom_share: Share<Secp256k1Scalar>,
        tx: EthTx,
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
    /// User that wants to read their shares of data - keygen or presig (todo: authentication)
    ReadKeyGen {
        user_index: u32,
    },
    ReadPresig {
        user_index: u32,
    },
    #[cfg(test)]
    TestReadInstanceSecret {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ReadKeyGenResponse {
    pub(crate) sk_user_share: Share<Secp256k1Scalar>,
    pub(crate) sk_chain_share: Share<Secp256k1Scalar>,
    pub(crate) public_key: String,
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
    pub(crate) chain_zero_share2: Share<Secp256k1Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EthTx {
    /// Nonce of your next transaction
    pub nonce: u128,

    /// Gas price
    pub gas_price: u128,

    /// Gas or Gas_limit. So amount of gas you are willing to spend
    pub gas: u128,

    /// Address you want to transact with. If you want to deploy a contract, `to` should be None.
    ///
    /// To convert your address from string to [u8; 20] you will have to use ethereum_types crate.
    /// ```no_run
    /// use ethereum_types::H160;
    /// use std::str::FromStr;
    ///
    /// let address: [u8; 20] = H160::from_str(&"/* your address */").unwrap().to_fixed_bytes();
    /// ```
    pub to: String,

    /// Amount of ether you want to send
    pub value: u128,

    /// If you want to interact or deploy smart contract add the bytecode here
    pub data: Vec<u8>,

    /// Chain id for the target chain. Mainnet = 1
    pub chain_id: u64,
}

impl From<Transaction> for EthTx {
    fn from(tx: Transaction) -> Self {
        EthTx {
            nonce: tx.nonce,
            gas_price: tx.gas_price,
            gas: tx.gas,
            to: H160::from_slice(&tx.to.expect("converting 'to' into bytes")).to_string(),
            value: tx.value,
            data: tx.data,
            chain_id: tx.chain_id,
        }
    }
}
