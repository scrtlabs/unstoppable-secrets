#[macro_use]
extern crate impl_ops;

extern crate num_bigint;
extern crate serde;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidCurvePoint,
    // InvalidMultiplicationResult,
    InvalidInputLength,
    // InvalidScalar,
}

pub mod traits;
pub mod secp256k1;