use core::ops::{Add, Mul, Neg, Sub};

use num_bigint::BigUint;
use num_traits::int;
use rand_core::{CryptoRng, RngCore};
use serde::{Serialize};
use serde::de::DeserializeOwned;
use super::Error;

pub trait ECScalar where
    Self: Add<Output = Self>
    + Mul<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
    + PartialEq
    + Clone
    + Default
    + Serialize
    + DeserializeOwned,
{
    fn to_raw(&self) -> [u8; 32];
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    fn from_num<T: int::PrimInt>(num: T) -> Self;
    fn from_slice(slice: &[u8]) -> Result<Self, Error>;
    fn from_big_int(other: &BigUint) -> Self;
    fn to_big_int(&self) -> BigUint;
    fn to_hex(&self) -> String;
    fn parse(p: &[u8; 32]) -> Self;
    fn q() -> BigUint;
    fn inv(&self) -> Self;
    fn is_zero(&self) -> bool;
    fn is_high(&self) -> bool;
    fn is_even(&self) -> bool;
}

pub trait ECPoint<ECScalar>
    where
        Self:
        Add
        + Mul<ECScalar>
        + Sub
        + Neg
        + Sized
        + Serialize
        + DeserializeOwned,
{
    fn generator() -> Self;
    fn x(&self) -> ECScalar;
    fn y(&self) -> ECScalar;
    fn parse(p: &[u8; 64]) -> Result<Self, Error>;
    fn from_slice(bytes: &[u8]) -> Result<Self, Error>;
    fn to_slice(&self) -> [u8; 64];
    fn to_big_int(&self) -> (BigUint, BigUint);
    fn from_xy(x: &BigUint, y: &BigUint) -> Self;
    fn generate(x: &ECScalar) -> Self;
}