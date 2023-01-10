use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use cosmwasm_std::{Addr, Coin, StdResult, Storage};
// use cw_storage_plus::Map;

pub static CONFIG_KEY: &[u8] = b"config";

// pub fn save_match_info(storage: &mut dyn Storage, game: &str, state: RPSMatch) -> StdResult<()> {
//     const GAME_STATE: Map<&[u8], RPSMatch> = Map::new("game_state");
//     GAME_STATE.save(storage, game.as_bytes(), &state)
// }
//
// pub fn load_match_info(storage: &dyn Storage, game: &str) -> StdResult<RPSMatch> {
//     const GAME_STATE: Map<&[u8], RPSMatch> = Map::new("game_state");
//     GAME_STATE.load(storage, game.as_bytes())
// }
