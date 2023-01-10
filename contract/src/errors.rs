use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CustomContractError {
    #[error("{0}")]
    // let thiserror implement From<StdError> for you
    Std(#[from] StdError),
    // this is whatever we want
    #[error("Custom error #1: Cannot add more than 2 millionaires. Try resetting the contract to add new data")]
    AlreadyAddedBothMillionaires,
}
