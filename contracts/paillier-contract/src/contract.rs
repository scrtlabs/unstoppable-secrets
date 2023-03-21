use crate::errors::ContractError;
use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::ENCRYPTION_KEY;
use paillier::*;

/// Assaf: The paillier crates requires libgmp3
/// sudo apt install libgmp3-dev

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    ENCRYPTION_KEY.save(deps.storage, &msg.encryption_key)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let encryption_key = ENCRYPTION_KEY.load(deps.storage)?;

    let ek: EncryptionKey = bincode2::deserialize(encryption_key.as_slice()).unwrap();

    let c1: EncodedCiphertext<u64> = bincode2::deserialize(msg.encrypted_c1.as_slice()).unwrap();
    let c2: EncodedCiphertext<u64> = bincode2::deserialize(msg.encrypted_c2.as_slice()).unwrap();

    // add all of them together
    let c = Paillier::add(&ek, &c1, &c2);

    let encrypted_c: Binary = bincode2::serialize(&c).unwrap().into();

    Ok(Response::default().set_data(encrypted_c))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetEncryptionKey {} => Ok(ENCRYPTION_KEY.load(deps.storage)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    #[test]
    // #[cfg(feature = "rand-std")]
    fn execute_test() {
        // generate a fresh keypair and extract encryption and decryption keys
        let (ek, dk) = Paillier::keypair().keys();

        let encryption_key: Binary = bincode2::serialize(&ek).expect("bincode2 ek").into();

        let mut deps = mock_dependencies();

        // send encryption_key to the contract
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("creator", &[]),
            InstantiateMsg { encryption_key },
        )
        .expect("instantiate");

        // encrypt two values
        let c1 = Paillier::encrypt(&ek, 10);
        let c2 = Paillier::encrypt(&ek, 20);

        let encrypted_a: Binary = bincode2::serialize(&c1).expect("bincode2 c1").into();
        let encrypted_b: Binary = bincode2::serialize(&c2).expect("bincode2 c2").into();

        // send the two values to the contract and get their sum
        let encrypted_c = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("creator", &[]),
            ExecuteMsg {
                encrypted_c1: encrypted_a,
                encrypted_c2: encrypted_b,
            },
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
