use crate::errors::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{Config, BID_BIDDER, BID_DEPOSIT, CONFIG};
use cosmwasm_std::{
    entry_point, Addr, BankMsg, Binary, Coin, CosmosMsg, DepsMut, Env, MessageInfo, Response,
    StdError, StdResult,
};
use paillier::{Add, BigInt, EncodedCiphertext, EncryptionKey, Mul, Paillier};
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
            let (chain_signing_key, public_signing_key_chain) = ecdsa_keygen([1u8; 32]);

            // public_signing_key = chain_signing_key * public_signing_key_user;
            let public_signing_key = public_signing_key_user.clone() * chain_signing_key.clone();

            CONFIG
                .save(
                    deps.storage,
                    &Config {
                        chain_signing_key,
                        public_signing_key_chain: public_signing_key_chain.clone(),
                        encrypted_user_signing_key,
                        public_signing_key_user,
                        enc_public_key,
                        public_signing_key,
                    },
                )
                .unwrap();

            let public_signing_key_chain: Binary = bincode2::serialize(&public_signing_key_chain)
                .unwrap()
                .into();

            Ok(Response::default().set_data(public_signing_key_chain))
        }
    }
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Sign {
            message_hash,
            public_instance_key_user,
            proof,
            commitment,
            seed,
        } => sign(
            message_hash,
            public_instance_key_user,
            proof,
            commitment,
            deps,
            seed,
        ),
        ExecuteMsg::Bid {
            buyer_enc_public_key,
            proof,
        } => bid(
            buyer_enc_public_key,
            proof,
            info.funds[0].clone(),
            info.sender,
            deps,
        ),
        ExecuteMsg::Sell {
            encrypted_buyer_signing_key,
            buyer_enc_public_key,
            proof,
            payment_address,
        } => sell(
            encrypted_buyer_signing_key,
            buyer_enc_public_key,
            proof,
            payment_address,
            env,
            deps,
        ),
    }
}

// A stub for now
fn verify_dlog_proof_and_commitment(
    _public_instance_key_user: Secp256k1Point,
    _proof: Binary,
    _commitment: Binary,
) -> bool {
    true
}

fn ecdsa_keygen(seed: [u8; 32]) -> (Secp256k1Scalar, Secp256k1Point) {
    let mut rng = ChaChaRng::from_seed(seed); // rng::thread_rng();
    let privkey = Secp256k1Scalar::random(&mut rng);
    let pubkey = Secp256k1Point::generate(&privkey);

    (privkey, pubkey)
}

/// ```
/// // On-chain
/// func execute_sign_tx(message_hash, public_instance_key_user, proof, commitment):
/// 	assert(verify_dlog_proof_and_commitment(public_instance_key_user, proof, commitment); // Just create a stub that returns true for now.
/// 	encrypted_user_signing_key= load_from_state("encrypted_user_signing_key");
/// 	chain_signing_key = load_from_state("chain_signing_key");
///
/// 	k_chain, public_instance_key_chain = ECDSA.Keygen();
/// 	public_instance_key = k_chain * public_instance_key_user;
/// 	r = public_instance_key.x; // Get x-coordinate of the point
///
/// 	k_chain_inverse = modular_inverse(k_chain, secp256k1.q);
/// 	encrypted_chain_sig = k_chain_inverse * r * chain_signing_key * encrypted_user_signing_key + k_chain_inverse * message_hash // This is the homomorphic encryption operation. This is a complicated formula so let me know if it's not clear. Also, TODO: add noise (p*q) later on..
///
/// 	return encrypted_chain_sig, public_instance_key_chain
/// ```
fn sign(
    message_hash: Secp256k1Scalar,
    public_instance_key_user: Secp256k1Point,
    proof: Binary,
    commitment: Binary,
    deps: DepsMut,
    seed: u8,
) -> Result<Response, ContractError> {
    // assert(verify_dlog_proof_and_commitment(public_instance_key_user, proof, commitment); // Just create a stub that returns true for now.
    if !verify_dlog_proof_and_commitment(public_instance_key_user.clone(), proof, commitment) {
        return Err(ContractError::Std(StdError::generic_err(
            "Unable to verify dlog proof and commitment",
        )));
    }

    let config: Config = CONFIG.load(deps.storage)?;
    let enc_public_key = config.enc_public_key;
    let encrypted_user_signing_key = config.encrypted_user_signing_key;
    let chain_signing_key = config.chain_signing_key;

    // k_chain, public_instance_key_chain = ECDSA.Keygen();
    let (k_chain, public_instance_key_chain) =
        ecdsa_keygen([seed /* TODO replace with env.block.random */ ; 32]);

    // public_instance_key = k_chain * public_instance_key_user;
    let public_instance_key = public_instance_key_user * k_chain.clone();

    // r = public_instance_key.x; // Get x-coordinate of the point
    let r = public_instance_key.x();

    // k_chain_inverse = modular_inverse(k_chain, secp256k1.q);
    let k_chain_inverse = k_chain.inv();

    // encrypted_chain_sig = k_chain_inverse * r * chain_signing_key * encrypted_user_signing_key + k_chain_inverse * message_hash // This is the homomorphic encryption operation. This is a complicated formula so let me know if it's not clear. Also, TODO: add noise (p*q) later on..

    let k_chain_inverse_mul_r_mul_chain_signing_key = BigInt::from_str_radix(
        &(k_chain_inverse.clone() * r * chain_signing_key).to_hex(),
        16,
    )
    .unwrap();
    let k_chain_inverse_mul_message_hash =
        BigInt::from_str_radix(&(k_chain_inverse * message_hash).to_hex(), 16).unwrap();

    let encrypted_chain_sig = Paillier::add(
        &enc_public_key,
        Paillier::mul(
            &enc_public_key,
            encrypted_user_signing_key,
            k_chain_inverse_mul_r_mul_chain_signing_key,
        ),
        k_chain_inverse_mul_message_hash,
    );

    let encrypted_chain_sig: Binary = bincode2::serialize(&encrypted_chain_sig).unwrap().into();
    let public_instance_key_chain: Binary = bincode2::serialize(&public_instance_key_chain)
        .unwrap()
        .into();

    let result: Binary = bincode2::serialize(&(encrypted_chain_sig, public_instance_key_chain))
        .unwrap()
        .into();

    Ok(Response::default().set_data(result))
}

// A stub for now
fn verify_bidder_proof(_buyer_enc_public_key: Binary, _proof: Binary) -> bool {
    true
}

// A stub for now
fn verify_seller_proof(_encrypted_buyer_signing_key: Binary, _proof: Binary) -> bool {
    true
}

/// ```
/// // On-chain
/// func send_bid_tx(buyer_enc_public_key, proof, deposit):
///     verify_proof(proof); // TODO: just a stub at this point
///     lock(deposit); // Basically, contract holds the bidder's deposit
/// ```
fn bid(
    buyer_enc_public_key: Binary,
    proof: Binary,
    deposit: Coin,
    sender: Addr,
    deps: DepsMut,
) -> Result<Response, ContractError> {
    if !verify_bidder_proof(buyer_enc_public_key.clone(), proof) {
        return Err(ContractError::Std(StdError::generic_err(
            "Unable to verify bidder proof",
        )));
    }

    BID_BIDDER.save(deps.storage, &sender)?;
    BID_DEPOSIT.save(deps.storage, &deposit)?;

    Ok(Response::default())
}

/// ```
/// // On-chain
/// func send_sell_tx(encrypted_buyer_signing_key, proof, payment_address):
/// 	verify_proof(proof); // TODO: just a stub at this point
/// 	transfer(deposit, payment_address);
/// 	random_value, _ = ECDSA.Keygen(); // This is to refresh the shares, which revokes seller's access
///
/// 	// Refresh the shares
/// 	chain_signing_key = load_from_state("chain_signing_key");
/// 	chain_signing_key = load_from_state("chain_signing_key"); * random_value.inv();
/// 	encrypted_user_signing_key = encrypted_buyer_signing_key * random_value; // TODO: may need to add noise here
///
/// 	save_to_state(chain_signing_key, encrypted_user_signing_key);
/// ```
fn sell(
    encrypted_buyer_signing_key: Binary,
    buyer_enc_public_key: Binary,
    proof: Binary,
    payment_address: String,
    _env: Env,
    deps: DepsMut,
) -> Result<Response, ContractError> {
    if !verify_seller_proof(encrypted_buyer_signing_key.clone(), proof) {
        return Err(ContractError::Std(StdError::generic_err(
            "Unable to verify seller proof",
        )));
    }

    let random_value = Binary::from_base64("wLsKdf/sYqvSMI0G0aWRjob25mrIB0VQVjTjDXnDafk=")
        .unwrap()
        .0; // use env.block.random.unwrap().0 after the v1.9 upgrade

    let random_value = Secp256k1Scalar::from_slice(&random_value).unwrap();

    let mut config: Config = CONFIG.load(deps.storage)?;
    let chain_signing_key = config.chain_signing_key;
    let chain_signing_key = chain_signing_key * random_value.inv();

    let encrypted_buyer_signing_key: EncodedCiphertext<BigInt> =
        bincode2::deserialize(encrypted_buyer_signing_key.as_slice()).unwrap();

    let buyer_enc_public_key: EncryptionKey =
        bincode2::deserialize(buyer_enc_public_key.as_slice()).unwrap();

    let encrypted_user_signing_key = Paillier::mul(
        &buyer_enc_public_key,
        encrypted_buyer_signing_key,
        BigInt::from_str_radix(&random_value.to_hex(), 16).unwrap(),
    ); // TODO: may need to add noise here

    // https://en.bitcoin.it/wiki/Secp256k1
    let secp256k1_g = Secp256k1Point::from_str(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    )
    .unwrap();

    let public_signing_key_chain = secp256k1_g * chain_signing_key.clone();

    config.enc_public_key = buyer_enc_public_key;
    config.encrypted_user_signing_key = encrypted_user_signing_key;
    config.chain_signing_key = chain_signing_key;
    config.public_signing_key_chain = public_signing_key_chain;

    CONFIG.save(deps.storage, &config)?;

    Ok(
        Response::default().add_message(CosmosMsg::Bank(BankMsg::Send {
            to_address: payment_address,
            amount: vec![BID_DEPOSIT.load(deps.storage)?],
        })),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Binary, Coin,
    };
    use paillier::{Decrypt, DecryptionKey, Encrypt, KeyGeneration, Paillier};
    use secp256k1::Secp256k1;

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
        let (user_signing_key, public_signing_key_user) = ecdsa_keygen([0u8; 32]);

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

    ///```
    /// // User
    /// func generate_sign_tx(enc_secret_key, message_hash):
    ///     k_user, public_instance_key_user = ECDSA.Keygen();
    ///     proof, commitment = generate_dlog_proof_and_commit(k_user, public_instance_key_user); // Just create a stub that returns whatever, don't implement
    ///    
    ///     // Send a tx with all the data to the chain. Get encrypted_chain_sig back
    ///     encrypted_chain_sig, public_instance_key_chain = send_sign_tx(message_hash, public_instance_key_user, proof, commitment);
    ///    
    ///     public_instance_key = k_user * public_instance_key_chain;
    ///     r = public_instance_key.x; // Get x-coordinate of the point
    ///    
    ///     chain_sig = Paillier.decrypt(enc_secret_key, encrypted_chain_sig);
    ///     s = (modular_inverse(k_user, secp256k1.q) * chain_sig) % secp256k1.q;
    ///    
    ///     signature = (r, s)
    ///     return signature;
    ///  ```
    fn generate_sign_tx(
        _enc_secret_key: &DecryptionKey,
        _message_hash: Secp256k1Scalar,
        stub: u8,
    ) -> (Secp256k1Scalar, Secp256k1Point, Binary, Binary) {
        // k_user, public_instance_key_user = ECDSA.Keygen();
        let (k_user, public_instance_key_user) = ecdsa_keygen([stub; 32]);

        // proof, commitment = generate_dlog_proof_and_commit(k_user, public_instance_key_user); // Just create a stub that returns whatever, don't implement
        let (proof, commitment) =
            generate_dlog_proof_and_commit(k_user.clone(), public_instance_key_user.clone());

        (k_user, public_instance_key_user, proof, commitment)
    }

    fn generate_dlog_proof_and_commit(
        _k_user: Secp256k1Scalar,
        _public_instance_key_user: Secp256k1Point,
    ) -> (Binary, Binary) {
        (Binary::from(vec![]), Binary::from(vec![]))
    }

    /// ```
    /// // A buyer wishes to bid on a given wallet
    /// // deposit is the sSCRT amount you want to the deposit as the bid. There probably should also be a tx for the bidder to release his bid after X blocks if the seller ignores it.
    /// func buyer(deposit):
    /// buyer_enc_secret_key, buyer_enc_public_key = Paillier.Keygen();
    /// proof = empty_proof(); // TODO: generate proof that the keys were generated correctly, like in the original key-gen
    /// send_bid_tx(buyer_enc_public_key, proof, deposit);
    ///
    /// Save (buyer_enc_secret_key, buyer_enc_public_key);
    /// ```
    fn buyer() -> (EncryptionKey, DecryptionKey, Binary) {
        // buyer_enc_secret_key, buyer_enc_public_key = Paillier.Keygen();
        let (buyer_enc_public_key, buyer_enc_secret_key) = Paillier::keypair().keys(); // Also ChaChaRng::from_seed([0u8; 32]) behind the scenes

        // proof = empty_proof(); // TODO: generate proof that the keys were generated correctly, like in the original key-gen
        let proof = Binary::from(vec![]);

        (buyer_enc_public_key, buyer_enc_secret_key, proof)
    }

    /// ```
    /// // The seller accepts the bid and sells the wallet
    /// // user_signing_key is the user's share of the wallet
    /// // payment_address is the destination wallet to receive the sSCRT payment
    /// func seller(user_signing_key, payment_address):
    /// buyer_enc_public_key = read_from_contract_state('buyer_enc_public_key');
    /// encrypted_buyer_signing_key = Paillier.encrypt(buyer_enc_public_key, user_signing_key);
    /// proof = empty_proof_of_correct_encryption(); // TODO: generate proof that this encryption encrypted user_signing_key under the buyer's key. Guy needs to look into key-gen protocol to better define this.
    /// send_sell_tx(encrypted_buyer_signing_key, proof, payment_address); // deposit is the sSCRT amount you want to the deposit as the bid. There probably should also be a tx for the bidder to release his bid after X blocks if the seller ignores it.
    /// ```
    fn seller(
        user_signing_key: Secp256k1Scalar,
        buyer_enc_public_key: &EncryptionKey,
    ) -> (EncodedCiphertext<BigInt>, Binary) {
        // TODO: generate proof that this encryption encrypted user_signing_key under the buyer's key. Guy needs to look into key-gen protocol to better define this.
        let proof = Binary::from(vec![]);

        let encrypted_buyer_signing_key: EncodedCiphertext<BigInt> = Paillier::encrypt(
            buyer_enc_public_key,
            BigInt::from_str_radix(&user_signing_key.to_hex(), 16).unwrap(),
        );

        (encrypted_buyer_signing_key, proof)
    }

    #[test]
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

        // println!("init: {{");
        // println!(
        //     "\"encrypted_user_signing_key\": {},",
        //     serde_json_wasm::to_string(&encrypted_user_signing_key).unwrap()
        // );
        // println!(
        //     "\"public_signing_key_user\": {},",
        //     serde_json_wasm::to_string(&public_signing_key_user).unwrap()
        // );
        // println!(
        //     "\"enc_public_key\": {},",
        //     serde_json_wasm::to_string(&enc_public_key).unwrap()
        // );
        // println!("}}");

        // send encryption_key to the contract
        let start = Instant::now();
        let result = instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("yolo", &[]),
            InstantiateMsg::KeyGen {
                encrypted_user_signing_key,
                public_signing_key_user,
                enc_public_key,
            },
        )
        .unwrap()
        .data
        .unwrap();
        let duration = start.elapsed();
        println!("keygen: {}", duration.as_nanos());

        let public_signing_key_chain: Secp256k1Point =
            bincode2::deserialize(result.as_slice()).unwrap();

        let message_hash = Secp256k1Scalar::from_slice(&[17u8; 32]).unwrap();

        let (k_user, public_instance_key_user, proof, commitment) =
            generate_sign_tx(&enc_secret_key, message_hash.clone(), 2);

        // println!("exec: {{");
        // println!(
        //     "\"message_hash\": {},",
        //     serde_json_wasm::to_string(&message_hash).unwrap()
        // );
        // println!(
        //     "\"public_instance_key_user\": {},",
        //     serde_json_wasm::to_string(&public_instance_key_user).unwrap()
        // );
        // println!(
        //     "\"proof\": {},",
        //     serde_json_wasm::to_string(&proof).unwrap()
        // );
        // println!(
        //     "\"commitment\": {},",
        //     serde_json_wasm::to_string(&commitment).unwrap()
        // );
        // println!("}}");

        let start = Instant::now();
        let result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("yolo", &[]),
            ExecuteMsg::Sign {
                message_hash: message_hash.clone(),
                public_instance_key_user,
                proof,
                commitment,
                seed: 3,
            },
        )
        .unwrap()
        .data
        .unwrap();
        let duration = start.elapsed();
        println!("sign: {}", duration.as_nanos());

        let (encrypted_chain_sig, public_instance_key_chain): (Binary, Binary) =
            bincode2::deserialize(result.as_slice()).unwrap();
        let encrypted_chain_sig: EncodedCiphertext<BigInt> =
            bincode2::deserialize(encrypted_chain_sig.as_slice()).unwrap();
        let public_instance_key_chain: Secp256k1Point =
            bincode2::deserialize(public_instance_key_chain.as_slice()).unwrap();

        // public_instance_key = k_user * public_instance_key_chain;
        let public_instance_key = public_instance_key_chain * k_user.clone();

        // r = public_instance_key.x; // Get x-coordinate of the point
        let r = public_instance_key.x();

        // chain_sig = Paillier.decrypt(enc_secret_key, encrypted_chain_sig);
        let chain_sig = Paillier::decrypt(&enc_secret_key, encrypted_chain_sig);

        // secp256k1_order aka n aka q
        // source: https://en.bitcoin.it/wiki/Secp256k1
        let secp256k1_order = BigInt::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();
        let chain_sig = chain_sig.pow_mod(&BigInt::one(), &secp256k1_order);
        let chain_sig = chain_sig.to_str_radix(16, false);

        // s = (modular_inverse(k_user, secp256k1.q) * chain_sig) % secp256k1.q;
        let s = k_user.inv() * Secp256k1Scalar::from_str(&chain_sig).unwrap();

        // signature = (r, s)
        let _signature = (r.clone(), s.clone());

        // pubkey is dereived using ECDH:
        // pubkey = user_signing_key * chain_signing_key * G
        // pubkey = user_signing_key * public_signing_key_chain
        // pubkey = chain_signing_key * public_signing_key_user
        let pubkey = public_signing_key_chain.clone() * user_signing_key.clone();
        let mut pubkey_uncompressed = vec![];
        pubkey_uncompressed.extend_from_slice(&[0x04u8]); // uncompressed pubkey prefix
        pubkey_uncompressed.extend_from_slice(&pubkey.to_slice());

        // verify signature:

        let secp = Secp256k1::new();

        let message = secp256k1::Message::from_slice(&message_hash.to_raw()).unwrap();

        let mut signature_compact = vec![];
        signature_compact.extend_from_slice(&r.to_raw());
        signature_compact.extend_from_slice(&s.to_raw());
        let sig = secp256k1::ecdsa::Signature::from_compact(&signature_compact).unwrap();

        let public_key = secp256k1::PublicKey::from_slice(&pubkey_uncompressed).unwrap();

        assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());

        // sell wallet

        let (buyer_enc_public_key, buyer_enc_secret_key, proof) = buyer();

        let buyer_enc_public_key_binary: Binary =
            bincode2::serialize(&buyer_enc_public_key).unwrap().into();

        println!("bid: {{");
        println!(
            "\"buyer_enc_public_key\": {},",
            serde_json_wasm::to_string(&buyer_enc_public_key_binary).unwrap()
        );
        println!(
            "\"proof\": {},",
            serde_json_wasm::to_string(&proof).unwrap()
        );
        println!("}}");

        let start = Instant::now();
        let _result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("buyer", &vec![Coin::new(1, "uscrt")]),
            ExecuteMsg::Bid {
                buyer_enc_public_key: buyer_enc_public_key_binary,
                proof,
            },
        );
        let duration = start.elapsed();
        println!("bid: {}", duration.as_nanos());

        let (encrypted_buyer_signing_key, proof) =
            seller(user_signing_key.clone(), &buyer_enc_public_key);

        let encrypted_buyer_signing_key: Binary = bincode2::serialize(&encrypted_buyer_signing_key)
            .unwrap()
            .into();
        let buyer_enc_public_key: Binary =
            bincode2::serialize(&buyer_enc_public_key).unwrap().into();

        println!("sell: {{");
        println!(
            "\"encrypted_buyer_signing_key\": {},",
            serde_json_wasm::to_string(&encrypted_buyer_signing_key).unwrap()
        );
        println!(
            "\"buyer_enc_public_key\": {},",
            serde_json_wasm::to_string(&buyer_enc_public_key).unwrap()
        );
        println!(
            "\"proof\": {},",
            serde_json_wasm::to_string(&proof).unwrap()
        );
        println!(
            "\"payment_address\": {},",
            serde_json_wasm::to_string(&"seller").unwrap()
        );
        println!("}}");

        let start = Instant::now();
        let duration = start.elapsed();
        let _result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("seller", &vec![]),
            ExecuteMsg::Sell {
                encrypted_buyer_signing_key,
                buyer_enc_public_key,
                proof,
                payment_address: "seller".to_string(),
            },
        );
        println!("sell: {}", duration.as_nanos());

        let message_hash = Secp256k1Scalar::from_slice(&[18u8; 32]).unwrap();

        let (k_user, public_instance_key_user, proof, commitment) =
            generate_sign_tx(&buyer_enc_secret_key, message_hash.clone(), 3);

        let result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("new owner", &[]),
            ExecuteMsg::Sign {
                message_hash: message_hash.clone(),
                public_instance_key_user,
                proof,
                commitment,
                seed: 4,
            },
        )
        .unwrap()
        .data
        .unwrap();

        let (encrypted_chain_sig, public_instance_key_chain): (Binary, Binary) =
            bincode2::deserialize(result.as_slice()).unwrap();
        let encrypted_chain_sig: EncodedCiphertext<BigInt> =
            bincode2::deserialize(encrypted_chain_sig.as_slice()).unwrap();
        let public_instance_key_chain: Secp256k1Point =
            bincode2::deserialize(public_instance_key_chain.as_slice()).unwrap();

        // public_instance_key = k_user * public_instance_key_chain;
        let public_instance_key = public_instance_key_chain * k_user.clone();

        // r = public_instance_key.x; // Get x-coordinate of the point
        let r = public_instance_key.x();

        // chain_sig = Paillier.decrypt(enc_secret_key, encrypted_chain_sig);
        let chain_sig = Paillier::decrypt(&buyer_enc_secret_key, encrypted_chain_sig);

        // secp256k1_order aka n aka q
        // source: https://en.bitcoin.it/wiki/Secp256k1
        let secp256k1_order = BigInt::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();
        let chain_sig = chain_sig.pow_mod(&BigInt::one(), &secp256k1_order); // modolu on chain_sig because it's not necessarily in the 2^256 filed
        let chain_sig = chain_sig.to_str_radix(16, false);

        // s = (modular_inverse(k_user, secp256k1.q) * chain_sig) % secp256k1.q;
        let s = k_user.inv() * Secp256k1Scalar::from_str(&chain_sig).unwrap();

        // signature = (r, s)
        let _signature = (r.clone(), s.clone());

        // pubkey is dereived using ECDH:
        // pubkey = user_signing_key * chain_signing_key * G
        // pubkey = user_signing_key * public_signing_key_chain
        // pubkey = chain_signing_key * public_signing_key_user
        let pubkey2 = public_signing_key_chain * user_signing_key;
        let mut pubkey2_uncompressed = vec![];
        pubkey2_uncompressed.extend_from_slice(&[0x04u8]); // uncompressed pubkey prefix
        pubkey2_uncompressed.extend_from_slice(&pubkey2.to_slice());

        // verify signature:

        let secp = Secp256k1::new();

        let message = secp256k1::Message::from_slice(&message_hash.to_raw()).unwrap();

        let mut signature_compact = vec![];
        signature_compact.extend_from_slice(&r.to_raw());
        signature_compact.extend_from_slice(&s.to_raw());
        let sig = secp256k1::ecdsa::Signature::from_compact(&signature_compact).unwrap();

        let public_key2 = secp256k1::PublicKey::from_slice(&pubkey2_uncompressed).unwrap();

        assert!(secp.verify_ecdsa(&message, &sig, &public_key2).is_ok());
        assert!(pubkey_uncompressed.eq(&pubkey2_uncompressed));
    }
}
