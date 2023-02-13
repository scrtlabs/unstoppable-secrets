use crate::errors::CustomContractError;
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use scrt_sss::{ECPoint, ECScalar, Secp256k1Point, Secp256k1Scalar, Share};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ReadShareResponse};
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
        ExecuteMsg::CreateShare {
            public_key, shares, ..
        } => create_share(deps, env, info, public_key, shares),
    }
}

fn create_share(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    user_public_key: String,
    user_shares: Vec<Share<Secp256k1Scalar>>,
) -> Result<Response, CustomContractError> {
    let mut state = load_state(deps.storage)?;
    let total_shares = state.num_of_users + state.threshold;

    if user_shares.len() != total_shares as usize {
        return Err(CustomContractError::Std(StdError::generic_err(format!(
            "Wrong number of user shares provided: {} vs expected: {}",
            user_shares.len(),
            total_shares
        ))));
    }

    // generate chain secret key

    // rand = info.random;
    // let rng = Prng::new(rand.as_slice(), b"");
    let silly = env.block.time.nanos().to_be_bytes();
    let mut rng = Prng::new(b"hello", silly.as_slice());
    let secret_key = Secp256k1Scalar::random(&mut rng);

    // generate chain public key
    let chain_public_key = Secp256k1Point::generate(&secret_key);

    // Calculate sum of public keys
    let user_pk = Secp256k1Point::from_str(&user_public_key)
        .map_err(|_| StdError::generic_err("Failed to decode user public key"))?;
    state.public_key = user_pk + chain_public_key;

    let chain_shares = scrt_sss::split(&mut rng, &secret_key, state.threshold, total_shares);

    // what's this and why are we computing it?
    let mut chain_shares_final = vec![];
    for i in state.num_of_users..total_shares {
        chain_shares_final
            .push(user_shares.get((i) as usize).unwrap() + chain_shares.get(i as usize).unwrap())
    }

    state.user_generated_shares = user_shares;
    state.chain_generated_shares = chain_shares;
    state.chain_generated_final = chain_shares_final;

    #[cfg(test)]
    {
        state.chain_private_key = secret_key;
    }

    save_state(deps.storage, state)?;

    Ok(Response::default())
}

fn read_share(deps: Deps, _env: Env, user_index: u32) -> StdResult<ReadShareResponse> {
    // todo: authentication
    let state = load_state(deps.storage)?;

    // read the shares from state

    return Ok(ReadShareResponse {
        user_share: state
            .user_generated_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        chain_share: state
            .chain_generated_shares
            .get(user_index as usize)
            .unwrap()
            .clone(),
        public_key: state.public_key.to_string(),
    });
}

#[cfg(test)]
fn test_read_secret(deps: Deps) -> StdResult<Secp256k1Scalar> {
    // todo: authentication
    let state = load_state(deps.storage)?;

    // read the shares from state

    return Ok(state.chain_private_key);
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ReadShare { user_index } => to_binary(&read_share(deps, env, user_index)?),
        #[cfg(test)]
        QueryMsg::TestReadSecret {} => to_binary(&test_read_secret(deps)?),
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

    fn client_create_share(
        num_of_shares: u8,
        threshold: u8,
    ) -> (Vec<Share<Secp256k1Scalar>>, Secp256k1Scalar, Secp256k1Point) {
        let mut rng = rand::thread_rng();

        let secret = Secp256k1Scalar::random(&mut rng);
        let public = Secp256k1Point::generate(&secret);

        let shares = scrt_sss::split(&mut rng, &secret, threshold, num_of_shares);

        return (shares, secret, public);
    }

    #[test]
    fn execute_test() {
        let mut deps = mock_dependencies();

        let num_of_shares = 7u8;
        let threshold = 4u8;
        let total_shares = num_of_shares + threshold;
        // 5 users: 8 shares
        let info = instantiate_contract(deps.as_mut(), num_of_shares, threshold);

        let (shares, user_secret, public) = client_create_share(total_shares, threshold);
        let msg = ExecuteMsg::CreateShare {
            user_index: 0,
            shares,
            public_key: public.to_string(),
        };
        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let mut new_shares = vec![];
        let mut pk_from_chain = Secp256k1Point::default();
        for i in 0..=threshold {
            // read shares for each party

            let msg = QueryMsg::ReadShare {
                user_index: i as u32,
            };
            let resp = query(deps.as_ref(), mock_env(), msg).unwrap();

            let decoded_response: ReadShareResponse = from_binary(&resp).unwrap();

            let new_share = decoded_response.user_share + decoded_response.chain_share;

            pk_from_chain = Secp256k1Point::from_str(&decoded_response.public_key).unwrap();

            new_shares.push(new_share);
        }

        let recovered = scrt_sss::open(new_shares).unwrap();

        let msg = QueryMsg::TestReadSecret {};
        let chain_secret: Secp256k1Scalar =
            from_binary(&query(deps.as_ref(), mock_env(), msg).unwrap()).unwrap();
        assert_eq!(recovered, (chain_secret + user_secret));

        let computed_pk = Secp256k1Point::generate(&recovered);

        assert_eq!(pk_from_chain, computed_pk);
    }

    use secp256k1::hashes::sha256;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    #[test]
    fn secp256k1_test() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let message = Message::from_hashed_data::<sha256::Hash>("gm".as_bytes());

        let sig = secp.sign_ecdsa(&message, &secret_key);
        assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
    }
}
