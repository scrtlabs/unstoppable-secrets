// use crate::msg::{CheckWinner, GameStateResponse};
// use crate::state::GameStatus::WaitingForWinner;
// use crate::state::{load_match_info, GameResult, GameStatus};
// use cosmwasm_std::{Deps, Env, StdError, StdResult};
//
// pub fn query_game_state(deps: Deps, env: Env, game: String) -> StdResult<GameStateResponse> {
//     let state = load_match_info(deps.storage, &game)
//         .map_err(|_| StdError::generic_err("Game with this ID not found"))?;
//
//     if state.status == GameStatus::Done && (state.meta.end_game_block.unwrap() >= env.block.height)
//     {
//         Ok(GameStateResponse {
//             game,
//             state: WaitingForWinner,
//         })
//     } else {
//         Ok(GameStateResponse {
//             game,
//             state: state.status,
//         })
//     }
// }
//
// pub fn query_who_won(deps: Deps, env: Env, game: String) -> StdResult<CheckWinner> {
//     let state = load_match_info(deps.storage, &game)?;
//
//     if state.status != GameStatus::Done {
//         return Err(StdError::generic_err(
//             "Players didn't finish submitting their choice!",
//         ));
//     }
//
//     if state.meta.end_game_block.unwrap() + 1 > env.block.height{
//         return Err(StdError::generic_err("Still processing results!"));
//     }
//
//     return Ok(match state.meta.winner.unwrap() {
//         GameResult::Player1 => CheckWinner {
//             winner: GameResult::Player1,
//             address: Some(state.players[0].address().clone()),
//         },
//         GameResult::Player2 => CheckWinner {
//             winner: GameResult::Player2,
//             address: Some(state.players[1].address().clone()),
//         },
//         GameResult::Tie => CheckWinner {
//             winner: GameResult::Tie,
//             address: None,
//         },
//     });
// }
