#[macro_use]
extern crate impl_ops;

extern crate core;
extern crate num_bigint;
extern crate serde;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidCurvePoint,
    // InvalidMultiplicationResult,
    InvalidInputLength,
    InvalidInputEncoding, // InvalidScalar,
}

pub mod secp256k1;
pub mod traits;
