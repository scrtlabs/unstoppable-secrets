use cosmwasm_std::Binary;
use cw_storage_plus::Item;

pub const ENCRYPTION_KEY: Item<Binary> = Item::new("encryption_key");
