use crate::errors::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{Config, CONFIG};
use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use paillier::{Add, BigInt, EncodedCiphertext, EncryptionKey, Paillier};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use scrt_sss::{ECPoint, ECScalar, Secp256k1Point, Secp256k1Scalar};

/// // On-chain
/// ```
/// func execute_keygen_tx(encrypted_user_signing_key, public_signing_key_user, enc_public_key):
///     chain_signing_key, public_signing_key_chain = ECDSA.Keygen();
///
///     public_signing_key = chain_signing_key * public_signing_key_user;
///     save_to_state(chain_signing_key, public_signing_key_chain, encrypted_user_signing_key, public_signing_key_user, enc_public_key, public_signing_key);
/// ```
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    match msg {
        InstantiateMsg::KeyGen {
            encrypted_user_signing_key,
            public_signing_key_user,
            enc_public_key,
        } => {
            let encrypted_user_signing_key: EncodedCiphertext<BigInt> =
                bincode2::deserialize(encrypted_user_signing_key.as_slice()).unwrap();
            let public_signing_key_user: Secp256k1Point =
                bincode2::deserialize(public_signing_key_user.as_slice()).unwrap();
            let enc_public_key: EncryptionKey =
                bincode2::deserialize(enc_public_key.as_slice()).unwrap();

            // chain_signing_key, public_signing_key_chain = ECDSA.Keygen();
            let mut rng = ChaChaRng::from_seed([0u8; 32]); // rng::thread_rng();
            let chain_signing_key = Secp256k1Scalar::random(&mut rng);
            let public_signing_key_chain = Secp256k1Point::generate(&chain_signing_key);

            // public_signing_key = chain_signing_key * public_signing_key_user;
            let public_signing_key = public_signing_key_user.clone() * chain_signing_key.clone();

            CONFIG.save(
                deps.storage,
                &Config {
                    chain_signing_key,
                    public_signing_key_chain,
                    encrypted_user_signing_key,
                    public_signing_key_user,
                    enc_public_key,
                    public_signing_key,
                },
            )?;
            Ok(Response::default())
        }
    }
}

// #[entry_point]
// pub fn execute(
//     deps: DepsMut,
//     _env: Env,
//     _info: MessageInfo,
//     msg: ExecuteMsg,
// ) -> Result<Response, ContractError> {
//     let encryption_key = CONFIG.load(deps.storage)?;

//     let ek: EncryptionKey = bincode2::deserialize(encryption_key.as_slice()).unwrap();

//     let c1: EncodedCiphertext<u64> = bincode2::deserialize(msg.c1.as_slice()).unwrap();
//     let c2: EncodedCiphertext<u64> = bincode2::deserialize(msg.c2.as_slice()).unwrap();

//     // add all of them together
//     let c = Paillier::add(&ek, &c1, &c2);

//     let c = bincode2::serialize(&c).unwrap();

//     Ok(Response::default().set_data(c))
// }

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    /// ```
    /// // User
    /// func keygen_user():
    ///     user_signing_key, public_signing_key_user = ECDSA.Keygen();
    ///     enc_secret_key, enc_public_key = Paillier.Keygen();
    ///
    ///     encrypted_user_signing_key = Paillier.encrypt(enc_secret_key, user_signing_key);
    ///
    ///     send_keygen_tx(encrypted_user_signing_key, public_signing_key_user, enc_public_key);
    ///
    ///     Save ( (user_signing_key, public_signing_key_user), (enc_secret_key, enc_public_key) ); // need to keep these keys for later
    /// ```
    fn keygen_user() -> (
        (Secp256k1Scalar, Secp256k1Point),
        (DecryptionKey, EncryptionKey),
        EncodedCiphertext<BigInt>,
    ) {
        // user_signing_key, public_signing_key_user = ECDSA.Keygen();
        let mut rng = ChaChaRng::from_seed([0u8; 32]); // rng::thread_rng();
        let user_signing_key = Secp256k1Scalar::random(&mut rng);
        let public_signing_key_user = Secp256k1Point::generate(&user_signing_key);

        // enc_secret_key, enc_public_key = Paillier.Keygen();
        let (enc_public_key, enc_secret_key) = Paillier::keypair().keys(); // Also ChaChaRng::from_seed([0u8; 32]) behind the scenes

        // encrypted_user_signing_key = Paillier.encrypt(enc_secret_key, user_signing_key);
        let encrypted_user_signing_key: EncodedCiphertext<BigInt> = Paillier::encrypt(
            &enc_public_key,
            BigInt::from_str_radix(&user_signing_key.to_hex(), 16).unwrap(),
        );

        (
            (user_signing_key, public_signing_key_user),
            (enc_secret_key, enc_public_key),
            encrypted_user_signing_key,
        )
    }

    #[test]
    // #[cfg(feature = "rand-std")]
    fn test() {
        let (
            (user_signing_key, public_signing_key_user),
            (enc_secret_key, enc_public_key),
            encrypted_user_signing_key,
        ) = keygen_user();

        let mut deps = mock_dependencies();

        let encrypted_user_signing_key: Binary = bincode2::serialize(&encrypted_user_signing_key)
            .unwrap()
            .into();
        let public_signing_key_user: Binary = bincode2::serialize(&public_signing_key_user)
            .unwrap()
            .into();
        let enc_public_key: Binary = bincode2::serialize(&enc_public_key).unwrap().into();

        // send encryption_key to the contract
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("yolo", &[]),
            InstantiateMsg::KeyGen {
                encrypted_user_signing_key,
                public_signing_key_user,
                enc_public_key,
            },
        )
        .unwrap();

        // encrypt two values
        let c1 = Paillier::encrypt(&ek, 10);
        let c2 = Paillier::encrypt(&ek, 20);

        let c1: Binary = bincode2::serialize(&c1).unwrap().into();
        let c2: Binary = bincode2::serialize(&c2).unwrap().into();

        // send the two values to the contract and get their sum
        let encrypted_c = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("creator", &[]),
            ExecuteMsg { c1, c2 },
        )
        .unwrap()
        .data
        .unwrap();

        let c: EncodedCiphertext<u64> = bincode2::deserialize(encrypted_c.as_slice()).unwrap();

        // decrypt final result
        let m: u64 = Paillier::decrypt(&dk, &c);

        println!("decrypted total sum is {}", m);
    }
}
