// extern crate hex;
// #[cfg(test)]
// extern crate rstest;
// #[cfg(test)]
// extern crate serde_json;
// #[cfg(test)]
// extern crate bincode;
//
// extern crate rand_core;
// extern crate secp256k1;

use super::Error;

/// The order of the secp256k1 curve
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
];

pub mod scalar;
pub mod point;


fn u8_ref_to_32_array(data: &[u8]) -> Result<[u8; 32], Error>{
    let mut u32_arr = [0u8; 32];
    match data.len() {
        0..=31 => {
            let mut arr = vec![0; 32 - data.len()];
            arr.extend_from_slice(&data);
            u32_arr.copy_from_slice(&arr);
            Ok(u32_arr)
        }
        32 => {
            u32_arr.copy_from_slice(&data);
            Ok(u32_arr)
        }
        _ => {
            Err(Error::InvalidInputLength)
        }
    }
}
