use crate::errors::CustomContractError;
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

use scrt_sss::{ScalarElement, ECScalar};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ReadShareResponse};
use crate::rng::Prng;

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {

    // save init params to state

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
        ExecuteMsg::CreateShare { public_key, shares, user_index } =>
            ssss(deps, env, public_key, shares, user_index)
    }
}

fn ssss(deps: DepsMut, env: Env, public_key: String, shares: Vec<String>, user_index: u32) -> Result<Response, CustomContractError> {

    /// convert public key to EC Point
    /// convert each of the shares to EC Scalar (?)

    /// generate new secp256k1 private/public

    /// compute <public user> + <public contract>

    /// split <contract private key> into a bunch of pieces using shamir secret sharing

    /// for each party:

    /// /// save a share of the split private key and the input shares for each of the users?

    /// save the generated shares and input shares in state

    /// example of secret sharing that doesn't work in wasm:

    let secret = ScalarElement::from_num(14748364);
    let k = 3;
    let n = 5;

    let mut rng = Prng::new(b"hello", b"hello");

    let shares = scrt_sss::split(&mut rng, &secret, k, n);

    deps.api.debug(&format!("Shares: {:?}", shares));

    let recovered = scrt_sss::open(shares).unwrap();

    assert_eq!(secret, recovered);

    deps.api.debug(&format!("Done: Started with: {:?}", secret));
    deps.api.debug(&format!("Done: Got: {:?}", recovered));

    Ok(Response::default())
}


fn read_share(deps: Deps, env: Env, user_index: u32) -> StdResult<ReadShareResponse> {
    // todo: authentication

    // read the shares from state

    return Ok(ReadShareResponse {
        user_share: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        chain_share: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
    })
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ReadShare { user_index } => to_binary(&read_share(deps, env, user_index)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::msg::GameStateResponse;
    use crate::state::{GameResult, GameStatus, RPS};
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{coins, OwnedDeps};

    fn instantiate_contract(deps: DepsMut) -> MessageInfo {
        let msg = InstantiateMsg { number_of_users: 0, signing_threshold: 0 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps, mock_env(), info.clone(), msg).unwrap();
        info
    }

    #[test]
    fn execute_test() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        let info = instantiate_contract(deps.as_mut());

        let msg = ExecuteMsg::CreateShare {
            user_index: 0,
            shares: vec![],
            public_key: "".to_string()
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        assert_eq!(res, Response::default());
    }
}
