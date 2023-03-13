use crate::errors::CustomContractError;
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use libsecp256k1::{PublicKey, PublicKeyFormat, Signature};
use scrt_sss::{ECPoint, ECScalar, Secp256k1Point, Secp256k1Scalar, Share};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ReadKeyGenResponse, ReadPresigResponse};
use crate::rng::Prng;
use crate::state::{load_state, save_state, State};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let mut state = State::default();

    state.num_of_users = msg.number_of_users as u8;
    state.threshold = msg.signing_threshold as u8;
    let sig_num_shares = vec![];
    let sig_denom_shares = vec![];

    state.sig_num_shares = sig_num_shares;
    state.sig_denom_shares = sig_denom_shares;

    save_state(deps.storage, state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, CustomContractError> {
    match msg {
        ExecuteMsg::CreatePresig {
            public_instance_key,
            k_user_shares,
            a_user_shares,
            user_zero_shares1,
            user_zero_shares2,
            ..
        } => create_presig(
            deps,
            env,
            info,
            public_instance_key,
            k_user_shares,
            a_user_shares,
            user_zero_shares1,
            user_zero_shares2,
        ),
        ExecuteMsg::KeyGen {
            user_public_key,
            user_secret_key_shares,
            ..
        } => keygen(deps, env, info, user_public_key, user_secret_key_shares),
        ExecuteMsg::Sign {
            user_index,
            user_sig_num_share,
            user_sig_denom_share,
            ..
        } => execute_sign(
            deps,
            env,
            info,
            user_index,
            user_sig_num_share,
            user_sig_denom_share,
        ),
    }
}

fn keygen(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    user_public_key: String,
    user_secret_key_shares: Vec<Share<Secp256k1Scalar>>,
) -> Result<Response, CustomContractError> {
    let mut state = load_state(deps.storage)?;
    let total_shares = state.num_of_users + state.threshold;

    if user_secret_key_shares.len() != total_shares as usize {
        return Err(CustomContractError::Std(StdError::generic_err(format!(
            "Wrong number of user shares provided: {} vs expected: {}",
            user_secret_key_shares.len(),
            total_shares
        ))));
    }

    // generate chain secret key
    let silly = env.block.time.nanos().to_be_bytes();
    let mut rng = Prng::new(b"hello", silly.as_slice());
    let sk_chain = Secp256k1Scalar::random(&mut rng);

    // generate chain public key
    let pk_chain = Secp256k1Point::generate(&sk_chain);

    // Calculate sum of public keys
    let pk_user = Secp256k1Point::from_str(&user_public_key)
        .map_err(|_| StdError::generic_err("Failed to decode user public key"))?;
    state.public_key = pk_user + pk_chain;

    let sk_chain_shares = scrt_sss::split(&mut rng, &sk_chain, state.threshold, total_shares);

    // Chain has the last 't' shares. Compute over them
    let mut sk_chain_shares_final = vec![];

    for i in state.num_of_users..total_shares {
        sk_chain_shares_final.push(
            user_secret_key_shares.get((i) as usize).unwrap()
                + sk_chain_shares.get(i as usize).unwrap(),
        );
    }

    // Store all to state so everyone can retreive later..

    state.sk_user_shares = user_secret_key_shares;
    state.sk_chain_shares = sk_chain_shares;
    state.sk_chain_shares_final = sk_chain_shares_final;
    state.sk_chain = sk_chain;

    save_state(deps.storage, state)?;

    Ok(Response::default())
}

fn create_presig(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    user_public_instance_key: String,
    k_user_shares: Vec<Share<Secp256k1Scalar>>,
    a_user_shares: Vec<Share<Secp256k1Scalar>>,
    user_zero_shares1: Vec<Share<Secp256k1Scalar>>,
    user_zero_shares2: Vec<Share<Secp256k1Scalar>>,
) -> Result<Response, CustomContractError> {
    let mut state = load_state(deps.storage)?;
    let total_shares = state.num_of_users + state.threshold;

    if k_user_shares.len() != total_shares as usize {
        return Err(CustomContractError::Std(StdError::generic_err(format!(
            "Wrong number of user shares provided: {} vs expected: {}",
            k_user_shares.len(),
            total_shares
        ))));
    }

    if a_user_shares.len() != total_shares as usize {
        return Err(CustomContractError::Std(StdError::generic_err(format!(
            "Wrong number of user shares provided: {} vs expected: {}",
            a_user_shares.len(),
            total_shares
        ))));
    }

    if user_zero_shares1.len() != total_shares as usize {
        return Err(CustomContractError::Std(StdError::generic_err(format!(
            "Wrong number of user shares provided: {} vs expected: {}",
            user_zero_shares1.len(),
            total_shares
        ))));
    }

    if user_zero_shares2.len() != total_shares as usize {
        return Err(CustomContractError::Std(StdError::generic_err(format!(
            "Wrong number of user shares provided: {} vs expected: {}",
            user_zero_shares2.len(),
            total_shares
        ))));
    }

    // generate chain secret key

    // rand = info.random;
    // let rng = Prng::new(rand.as_slice(), b"");
    let silly = env.block.time.nanos().to_be_bytes();
    let mut rng = Prng::new(b"hello", silly.as_slice());
    let k_chain = Secp256k1Scalar::random(&mut rng);
    let a_chain = Secp256k1Scalar::random(&mut rng);

    // generate chain public key
    let chain_public_instance_key = Secp256k1Point::generate(&k_chain);

    // Calculate sum of public keys
    let user_pk = Secp256k1Point::from_str(&user_public_instance_key)
        .map_err(|_| StdError::generic_err("Failed to decode user public key"))?;
    state.public_instance_key = user_pk + chain_public_instance_key;

    let k_chain_shares = scrt_sss::split(&mut rng, &k_chain, state.threshold, total_shares);
    let a_chain_shares = scrt_sss::split(&mut rng, &a_chain, state.threshold, total_shares);
    let chain_zero_shares1 = scrt_sss::split(
        &mut rng,
        &Secp256k1Scalar::zero(),
        state.threshold * 2,
        total_shares,
    );
    let chain_zero_shares2 = scrt_sss::split(
        &mut rng,
        &Secp256k1Scalar::zero(),
        state.threshold * 2,
        total_shares,
    );

    // Chain has the last 't' shares. Compute over them
    let mut k_chain_shares_final = vec![];
    let mut a_chain_shares_final = vec![];
    let mut chain_zero_shares_final1 = vec![];
    let mut chain_zero_shares_final2 = vec![];
    for i in state.num_of_users..total_shares {
        k_chain_shares_final.push(
            k_user_shares.get((i) as usize).unwrap() + k_chain_shares.get(i as usize).unwrap(),
        );
        a_chain_shares_final.push(
            a_user_shares.get((i) as usize).unwrap() + a_chain_shares.get(i as usize).unwrap(),
        );
        chain_zero_shares_final1.push(
            user_zero_shares1.get((i) as usize).unwrap()
                + chain_zero_shares1.get(i as usize).unwrap(),
        );
        chain_zero_shares_final2.push(
            user_zero_shares2.get((i) as usize).unwrap()
                + chain_zero_shares2.get(i as usize).unwrap(),
        );
    }

    // Store all to state so everyone can retreive later..

    state.k_user_shares = k_user_shares;
    state.k_chain_shares = k_chain_shares;
    state.k_chain_shares_final = k_chain_shares_final;

    state.a_user_shares = a_user_shares;
    state.a_chain_shares = a_chain_shares;
    state.a_chain_shares_final = a_chain_shares_final;

    state.user_zero_shares1 = user_zero_shares1;
    state.chain_zero_shares1 = chain_zero_shares1;
    state.chain_zero_shares_final1 = chain_zero_shares_final1;

    state.user_zero_shares2 = user_zero_shares2;
    state.chain_zero_shares2 = chain_zero_shares2;
    state.chain_zero_shares_final2 = chain_zero_shares_final2;

    #[cfg(test)]
    {
        state.chain_private_instance_key = k_chain;
    }

    save_state(deps.storage, state)?;

    Ok(Response::default())
}

fn execute_sign(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    user_index: u32,
    user_sig_num_share: Share<Secp256k1Scalar>,
    user_sig_denom_share: Share<Secp256k1Scalar>,
) -> Result<Response, CustomContractError> {
    let mut state = load_state(deps.storage)?;
    let total_shares = state.num_of_users + state.threshold;

    // Store user's shares
    state.sig_num_shares.push(user_sig_num_share);
    state.sig_denom_shares.push(user_sig_denom_share);

    if state.sig_num_shares.len() + (state.threshold as usize)
        < ((2 * state.threshold + 1) as usize)
    {
        // Not enough shares yet to produce a signature
        // println!("Not enough shares yet!");
        save_state(deps.storage, state)?;
        return Ok(Response::default());
    }

    if state.sig != Secp256k1Scalar::default() {
        // Already generated signature
        // println!("Already generated signature!");
        return Ok(Response::default());
    }

    // We have 2t+1 shares --> can produce a signature on-chain
    // println!("Running sign..");
    // TODO: not deterministic message..
    let message_arr = [6u8; 32];
    let m = Secp256k1Scalar::from_slice(&message_arr).unwrap();

    let r = state.public_instance_key.x();
    // Produce the t 'chain' shares
    for i in 0..=state.threshold - 1 {
        let sk_share = state.sk_chain_shares_final.get(i as usize).unwrap().clone();

        let k_share = state.k_chain_shares_final.get(i as usize).unwrap().clone();

        let a_share = state.a_chain_shares_final.get(i as usize).unwrap().clone();

        let zero_share1 = state
            .chain_zero_shares_final1
            .get(i as usize)
            .unwrap()
            .clone();

        let zero_share2 = state
            .chain_zero_shares_final2
            .get(i as usize)
            .unwrap()
            .clone();

        let sig_num_share =
            a_share.clone() * (m.clone() + (r.clone() * sk_share.data)) - zero_share1.clone();
        let sig_denom_share = k_share.clone() * a_share.clone().data - zero_share2.clone();
        // println!("Shares ids are: {:?}, {:?}, {:?}", sk_share.id, sig_num_share.id, sig_denom_share.id);
        state.sig_num_shares.push(sig_num_share);
        state.sig_denom_shares.push(sig_denom_share);
    }

    let s1 = scrt_sss::open(state.sig_num_shares.clone()).unwrap();
    let s2 = scrt_sss::open(state.sig_denom_shares.clone()).unwrap();
    let s = s1 * s2.inv();
    // println!("The value of s is {:?}", s.to_hex());

    // for mesasge hash we can just use message_arr here, but I want to test if
    // to_raw() is the opposite of Secp256k1Scalar::from_slice(), e.g.:
    // Secp256k1Scalar::from_slice(&message_arr).unwrap().to_raw()

    let msg_hash_for_precompiled = &m.to_raw();
    let sig_for_precompiled = &Signature {
        r: r.value,
        s: s.value,
    }
    .serialize();
    let pk_for_precompiled =
        &PublicKey::parse_slice(&state.public_key.to_slice(), Some(PublicKeyFormat::Raw))
            .unwrap()
            .serialize_compressed();

    let is_verified = deps
        .api
        .secp256k1_verify(
            msg_hash_for_precompiled,
            sig_for_precompiled,
            pk_for_precompiled,
        )
        .unwrap();

    if is_verified {
        println!("Signature verified correctly!");
    } else {
        println!("Bad Signature!");
    }

    // TODO: we need to be able to store multiple signatures on-chain so other parties can read them. This is temporary
    state.sig = s.clone();
    save_state(deps.storage, state)?;

    Ok(Response::default().add_attribute("is_verified", format!("{}", is_verified)))
}

fn read_keygen(deps: Deps, _env: Env, user_index: u32) -> StdResult<ReadKeyGenResponse> {
    // todo: authentication
    let state = load_state(deps.storage)?;

    // read the share from state

    return Ok(ReadKeyGenResponse {
        sk_user_share: state
            .sk_user_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        sk_chain_share: state
            .sk_chain_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        public_key: state.public_key.to_string(),
    });
}

fn read_presig(deps: Deps, _env: Env, user_index: u32) -> StdResult<ReadPresigResponse> {
    // todo: authentication
    let state = load_state(deps.storage)?;

    // read the shares from state

    return Ok(ReadPresigResponse {
        k_user_share: state
            .k_user_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        k_chain_share: state
            .k_chain_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        public_instance_key: state.public_instance_key.to_string(),
        a_user_share: state
            .a_user_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        a_chain_share: state
            .a_chain_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        user_zero_share1: state
            .user_zero_shares1
            .get(user_index as usize)
            .unwrap()
            .clone(),
        chain_zero_share1: state
            .chain_zero_shares1
            .get(user_index as usize)
            .unwrap()
            .clone(),
        user_zero_share2: state
            .user_zero_shares2
            .get(user_index as usize)
            .unwrap()
            .clone(),
        chain_zero_share2: state
            .chain_zero_shares2
            .get(user_index as usize)
            .unwrap()
            .clone(),
    });
}

#[cfg(test)]
fn test_read_instance_secret(deps: Deps) -> StdResult<Secp256k1Scalar> {
    // todo: authentication
    let state = load_state(deps.storage)?;

    // read the shares from state

    return Ok(state.chain_private_instance_key);
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ReadKeyGen { user_index } => to_binary(&read_keygen(deps, env, user_index)?),
        QueryMsg::ReadPresig { user_index } => to_binary(&read_presig(deps, env, user_index)?),
        #[cfg(test)]
        QueryMsg::TestReadInstanceSecret {} => to_binary(&test_read_instance_secret(deps)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};
    // use rand::{RngCore, CryptoRng};

    fn instantiate_contract(deps: DepsMut, users: u8, threshold: u8) -> MessageInfo {
        let msg = InstantiateMsg {
            number_of_users: users as u32,
            signing_threshold: threshold as u32,
        };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps, mock_env(), info.clone(), msg).unwrap();
        info
    }

    fn client_create_share_helper(
        num_of_shares: u8,
        threshold: u8,
        compute_public: bool,
        compute_secret: bool,
    ) -> (
        Vec<Share<Secp256k1Scalar>>,
        Option<Secp256k1Scalar>,
        Option<Secp256k1Point>,
    ) {
        let mut rng = rand::thread_rng();

        let secret = if compute_secret {
            Some(Secp256k1Scalar::random(&mut rng))
        } else {
            Some(Secp256k1Scalar::zero())
        };

        let public = if compute_public {
            Some(Secp256k1Point::generate(secret.as_ref().unwrap()))
        } else {
            None
        };

        let shares = scrt_sss::split(&mut rng, secret.as_ref().unwrap(), threshold, num_of_shares);

        return (shares, secret, public);
    }

    fn client_create_share(
        num_of_shares: u8,
        threshold: u8,
    ) -> (Vec<Share<Secp256k1Scalar>>, Secp256k1Scalar, Secp256k1Point) {
        let (shares, secret, public) =
            client_create_share_helper(num_of_shares, threshold, true, true);
        return (shares, secret.unwrap(), public.unwrap());
    }

    fn client_create_share_no_public(
        num_of_shares: u8,
        threshold: u8,
    ) -> (Vec<Share<Secp256k1Scalar>>, Secp256k1Scalar) {
        let (shares, secret, _) = client_create_share_helper(num_of_shares, threshold, false, true);
        return (shares, secret.unwrap());
    }

    fn client_create_share_no_secret(
        num_of_shares: u8,
        threshold: u8,
    ) -> Vec<Share<Secp256k1Scalar>> {
        let (shares, _, _) = client_create_share_helper(num_of_shares, threshold, false, false);
        return shares;
    }

    #[test]
    fn keygen_test() {
        let mut deps = mock_dependencies();

        let num_of_shares = 7u8;
        let threshold = 2u8;
        let total_shares = num_of_shares + threshold;

        let info = instantiate_contract(deps.as_mut(), num_of_shares, threshold);

        let (sk_user_shares, sk_user, pk_user) = client_create_share(total_shares, threshold);
        let msg = ExecuteMsg::KeyGen {
            user_public_key: pk_user.to_string(),
            user_secret_key_shares: sk_user_shares,
        };

        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Get all values..
        let mut sk_shares = vec![];
        let mut pk = Secp256k1Point::default();

        for i in 0..=num_of_shares {
            // read shares for each party

            let msg = QueryMsg::ReadKeyGen {
                user_index: i as u32,
            };
            let resp = query(deps.as_ref(), mock_env(), msg).unwrap();

            let decoded_response: ReadKeyGenResponse = from_binary(&resp).unwrap();

            let sk_share = decoded_response.sk_user_share + decoded_response.sk_chain_share;
            pk = Secp256k1Point::from_str(&decoded_response.public_key).unwrap();
            sk_shares.push(sk_share);
        }

        let sk = scrt_sss::open(sk_shares).unwrap();
        let computed_pk = Secp256k1Point::generate(&sk);
        assert_eq!(pk, computed_pk);

        println!("KeyGen successful!");
    }

    #[test]
    // #[cfg(feature = "rand-std")]
    fn execute_test() {
        use std::fs::File;
        use std::io::prelude::*;
        use std::time::Instant;

        let mut deps = mock_dependencies();

        for n in 2..16 {
            for t in 1..n {
                let num_of_shares = n;
                let threshold = t;
                let total_shares = num_of_shares + threshold;

                let now = Instant::now();
                let info = instantiate_contract(deps.as_mut(), num_of_shares, threshold);
                let elapsed = now.elapsed().as_nanos();
                println!("{},{},init,{}", n, t, elapsed);

                //// Keygen

                let (sk_user_shares, sk_user, pk_user) =
                    client_create_share(total_shares, threshold);
                let msg = ExecuteMsg::KeyGen {
                    user_public_key: pk_user.to_string(),
                    user_secret_key_shares: sk_user_shares,
                };

                let x = to_binary(&msg);

                let now = Instant::now();
                let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
                let elapsed = now.elapsed().as_nanos();
                println!("{},{},keygen,{}", n, t, elapsed);
                let mut file = File::create(format!("{}_{}_keygen.json", n, t)).unwrap();
                file.write_all(x.unwrap().as_slice()).unwrap();

                // Get all values..
                let mut sk_shares = vec![];
                let mut pk = Secp256k1Point::default();

                for i in 0..=num_of_shares - 1 {
                    // read shares for each party

                    let msg = QueryMsg::ReadKeyGen {
                        user_index: i as u32,
                    };
                    let resp = query(deps.as_ref(), mock_env(), msg).unwrap();

                    let decoded_response: ReadKeyGenResponse = from_binary(&resp).unwrap();

                    let sk_share = decoded_response.sk_user_share + decoded_response.sk_chain_share;
                    pk = Secp256k1Point::from_str(&decoded_response.public_key).unwrap();
                    sk_shares.push(sk_share);
                }

                //// Presig

                // Generate 4 values and their shares: k_user, a_user, 0, 0
                let (k_user_shares, k_user, k_user_public) =
                    client_create_share(total_shares, threshold);
                let (a_user_shares, a_user) =
                    client_create_share_no_public(total_shares, threshold);
                let user_zero_shares1 = client_create_share_no_secret(total_shares, threshold * 2);
                let user_zero_shares2 = client_create_share_no_secret(total_shares, threshold * 2);

                let msg = ExecuteMsg::CreatePresig {
                    user_index: 0,
                    k_user_shares: k_user_shares,
                    a_user_shares: a_user_shares,
                    user_zero_shares1: user_zero_shares1,
                    user_zero_shares2: user_zero_shares2,
                    public_instance_key: k_user_public.to_string(),
                };

                let x = to_binary(&msg);

                let now = Instant::now();
                let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
                let elapsed = now.elapsed().as_nanos();
                println!("{},{},presig,{}", n, t, elapsed);
                let mut file = File::create(format!("{}_{}_presign.json", n, t)).unwrap();
                file.write_all(x.unwrap().as_slice()).unwrap();
                //// Sign
                // Get all values..
                let mut pk_from_chain = Secp256k1Point::default();
                let message_arr = [6u8; 32]; // TODO: custom message..
                let m = Secp256k1Scalar::from_slice(&message_arr).unwrap();

                for i in 0..=num_of_shares - 1 {
                    // read shares for each party

                    let msg = QueryMsg::ReadPresig {
                        user_index: i as u32,
                    };
                    let resp = query(deps.as_ref(), mock_env(), msg).unwrap();

                    let decoded_response: ReadPresigResponse = from_binary(&resp).unwrap();

                    let k_share = decoded_response.k_user_share + decoded_response.k_chain_share;
                    let a_share = decoded_response.a_user_share + decoded_response.a_chain_share;
                    let zero_share1 =
                        decoded_response.user_zero_share1 + decoded_response.chain_zero_share1;
                    let zero_share2 =
                        decoded_response.user_zero_share2 + decoded_response.chain_zero_share2;

                    pk_from_chain =
                        Secp256k1Point::from_str(&decoded_response.public_instance_key).unwrap();
                    let r = pk_from_chain.x();

                    let sk_share = sk_shares.get(i as usize).unwrap().clone();

                    let sig_num_share =
                        a_share.clone() * (m.clone() + (r * sk_share.data)) - zero_share1.clone();
                    let sig_denom_share =
                        k_share.clone() * a_share.clone().data - zero_share2.clone();
                    // println!("Shares ids are: {:?}, {:?}, {:?}", sk_share.id, sig_num_share.id, sig_denom_share.id);

                    let msg = ExecuteMsg::Sign {
                        user_index: i as u32,
                        user_sig_num_share: sig_num_share,
                        user_sig_denom_share: sig_denom_share,
                    };

                    let x = to_binary(&msg);

                    let now = Instant::now();
                    let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
                    let elapsed = now.elapsed().as_nanos();
                    println!("{},{},sign,{}", n, t, elapsed);
                    let mut file = File::create(format!("{}_{}_sign.json", n, t)).unwrap();
                    file.write_all(x.unwrap().as_slice()).unwrap();
                    break;
                }
            }
        }
    }

    #[test]
    // #[cfg(feature = "rand-std")]
    fn execute_test_old() {
        let mut deps = mock_dependencies();

        let num_of_shares = 7u8;
        let threshold = 2u8;
        let total_shares = num_of_shares + threshold;

        // TODO: KeyGen - for now good enough to just ignore..
        let (sk_shares, sk, pk) = client_create_share(total_shares, threshold);
        let info = instantiate_contract(deps.as_mut(), num_of_shares, threshold);

        // Generate 4 values and their shares: k_user, a_user, 0, 0
        let (k_user_shares, k_user, k_user_public) = client_create_share(total_shares, threshold);
        let (a_user_shares, a_user) = client_create_share_no_public(total_shares, threshold);
        let user_zero_shares1 = client_create_share_no_secret(total_shares, threshold * 2);
        let user_zero_shares2 = client_create_share_no_secret(total_shares, threshold * 2);

        let msg = ExecuteMsg::CreatePresig {
            user_index: 0,
            k_user_shares: k_user_shares,
            a_user_shares: a_user_shares,
            user_zero_shares1: user_zero_shares1,
            user_zero_shares2: user_zero_shares2,
            public_instance_key: k_user_public.to_string(),
        };

        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Get all values..
        let mut k_shares = vec![];
        let mut a_shares = vec![];
        let mut zero_shares1 = vec![];
        let mut zero_shares2 = vec![];
        let mut sig_num = vec![];
        let mut sig_denom = vec![];
        let mut pk_from_chain = Secp256k1Point::default();

        let message_arr = [6u8; 32];
        let m = Secp256k1Scalar::from_slice(&message_arr).unwrap();
        // for i in 0..=2*threshold {
        for i in 0..=num_of_shares {
            // read shares for each party

            let msg = QueryMsg::ReadPresig {
                user_index: i as u32,
            };
            let resp = query(deps.as_ref(), mock_env(), msg).unwrap();

            let decoded_response: ReadPresigResponse = from_binary(&resp).unwrap();

            let k_share = decoded_response.k_user_share + decoded_response.k_chain_share;
            let a_share = decoded_response.a_user_share + decoded_response.a_chain_share;
            let zero_share1 =
                decoded_response.user_zero_share1 + decoded_response.chain_zero_share1;
            let zero_share2 =
                decoded_response.user_zero_share2 + decoded_response.chain_zero_share2;

            pk_from_chain =
                Secp256k1Point::from_str(&decoded_response.public_instance_key).unwrap();
            let r = pk_from_chain.x();

            let k_copy = k_share.clone();
            let a_copy = a_share.clone();
            let a_copy2 = a_share.clone();
            let zero1_copy = zero_share1.clone();
            let zero2_copy = zero_share2.clone();

            k_shares.push(k_share);
            a_shares.push(a_share);
            zero_shares1.push(zero_share1);
            zero_shares2.push(zero_share2);

            let sk_share = sk_shares.get(i as usize).unwrap().clone();

            let sig_num_share = a_copy * (m.clone() + (r * sk_share.data)) - zero1_copy;
            let sig_denom_share = k_copy * a_copy2.data - zero2_copy;
            println!(
                "Shares ids are: {:?}, {:?}, {:?}",
                sk_share.id, sig_num_share.id, sig_denom_share.id
            );
            sig_num.push(sig_num_share);
            sig_denom.push(sig_denom_share);
        }
        let k = scrt_sss::open(k_shares).unwrap();
        let a = scrt_sss::open(a_shares).unwrap();
        let r = pk_from_chain.x();

        // Test all values reconstruct to values that make sense
        let recovered = k.clone();

        let msg = QueryMsg::TestReadInstanceSecret {};
        let chain_secret: Secp256k1Scalar =
            from_binary(&query(deps.as_ref(), mock_env(), msg).unwrap()).unwrap();

        assert_eq!(recovered, (chain_secret + k_user));
        let computed_pk = Secp256k1Point::generate(&recovered);
        assert_eq!(pk_from_chain, computed_pk);

        let recovered = scrt_sss::open(zero_shares1).unwrap();
        assert_eq!(recovered, Secp256k1Scalar::zero());
        let recovered = scrt_sss::open(zero_shares2).unwrap();
        assert_eq!(recovered, Secp256k1Scalar::zero());

        let recovered = scrt_sss::open(sig_num.clone()).unwrap();
        let ref_val = (m.clone() + r.clone() * sk.clone()) * a.clone();
        assert_eq!(recovered, ref_val);

        let recovered = scrt_sss::open(sig_denom.clone()).unwrap();
        let ref_val = a.clone() * k.clone();
        assert_eq!(recovered, ref_val);

        // Test a local (non MPC) sig
        let message = Message::parse(&message_arr);
        let s = (m + r.clone() * sk) * k.inv();
        println!("The value of s is {:?}", s.to_hex());

        let sig = Signature {
            r: r.value,
            s: s.value,
        };
        let pk_lib = PublicKey::parse_slice(&pk.to_slice(), Some(PublicKeyFormat::Raw)).unwrap();
        assert!(verify(&message, &sig, &pk_lib));
        println!("Non MPC sig verify passed successfully!");

        let s1 = scrt_sss::open(sig_num).unwrap();
        let s2 = scrt_sss::open(sig_denom).unwrap();
        let s = s1 * s2.inv();
        println!("The value of s is {:?}", s.to_hex());

        let sig = Signature {
            r: r.value,
            s: s.value,
        };
        assert!(verify(&message, &sig, &pk_lib));
        println!("MPC sig verified successfully!");
    }

    use secp256k1::hashes::sha256;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message as SecpMessage, Secp256k1};

    #[test]
    fn secp256k1_test() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let message = SecpMessage::from_hashed_data::<sha256::Hash>("gm".as_bytes());

        let sig = secp.sign_ecdsa(&message, &secret_key);
        assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
    }

    use libsecp256k1::*;
    #[test]
    fn libsecp256k1_test() {
        let secp256k1 = Secp256k1::new();

        let message_arr = [6u8; 32];
        let (secp_privkey, secp_pubkey) = secp256k1.generate_keypair(&mut OsRng);
        let pubkey_a = secp_pubkey.serialize_uncompressed();
        assert_eq!(pubkey_a.len(), 65);
        let pubkey = PublicKey::parse(&pubkey_a).unwrap();
        let mut seckey_a = [0u8; 32];
        for i in 0..32 {
            seckey_a[i] = secp_privkey[i];
        }

        let message = Message::parse(&message_arr);

        let seckey = SecretKey::parse(&seckey_a).unwrap();
        let (sig, recid) = sign(&message, &seckey);

        // Self verify
        assert!(verify(&message, &sig, &pubkey));
        println!("The value of (r,s)) is {:?}", sig);
    }

    // GOAL: pure math signature works with ecdsa.verify from a common library
    #[test]
    fn sign_and_verify_test() {
        // Generate pure math (sk, pk)
        let sk_math = Secp256k1Scalar::random(&mut OsRng);
        let pk_math = Secp256k1Point::generate(&sk_math);

        let message_arr = [6u8; 32];
        let message_math = Secp256k1Scalar::from_slice(&message_arr).unwrap();

        // Generate sig = (r, s) using pure math
        let k = Secp256k1Scalar::random(&mut OsRng);
        let R = Secp256k1Point::generate(&k);
        let r = R.x();
        let s = (message_math + r.clone() * sk_math) * k.inv();
        let sig = Signature {
            r: r.value,
            s: s.value,
        };

        // Try to verify sig with secp256k1 verify
        // let secp256k1 = Secp256k1::new();
        let message = Message::parse(&message_arr);
        let pk = PublicKey::parse_slice(&pk_math.to_slice(), Some(PublicKeyFormat::Raw)).unwrap();

        assert!(verify(&message, &sig, &pk));
        println!("The value of (r,s)) is {:?}", sig);
    }
}
