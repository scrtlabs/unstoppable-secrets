use core::fmt;
use core::ops;
use core::ops::Neg;
use impl_ops::impl_op_ex;

use libsecp256k1::curve::Scalar;
use libsecp256k1::util::SECRET_KEY_SIZE;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::int;
use rand_core::{CryptoRng, RngCore};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::super::serde::de::SeqAccess;
use super::super::traits::ECScalar;
use super::super::Error;
use super::u8_ref_to_32_array;
use super::CURVE_ORDER;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Secp256k1Scalar {
    pub value: Scalar,
}

impl Secp256k1Scalar {
    pub fn from_str(input: &str) -> Result<Secp256k1Scalar, Error> {
        let decoded = hex::decode(input).map_err(|_| Error::InvalidInputEncoding)?;
        Self::from_slice(decoded.as_slice())
    }
}

impl ECScalar for Secp256k1Scalar {
    fn to_raw(&self) -> [u8; 32] {
        u8_ref_to_32_array(&self.to_big_int().to_bytes_be()).unwrap()
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Secp256k1Scalar {
        let mut arr = [0u8; 32];
        match rng.try_fill_bytes(&mut arr[..]) {
            Ok(_) => Self::parse(&arr),
            Err(_) => panic!("Failed to generate random data"),
        }
    }

    fn zero() -> Secp256k1Scalar {
        ECScalar::from_big_int(&BigUint::from(0 as u64))
    }

    fn one() -> Secp256k1Scalar {
        Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64))
    }

    fn from_num<T: int::PrimInt>(num: T) -> Self {
        Secp256k1Scalar::from_big_int(&BigUint::from(num.to_u64().unwrap()))
    }

    fn from_slice(slice: &[u8]) -> Result<Secp256k1Scalar, Error> {
        if slice.len() != SECRET_KEY_SIZE {
            return Err(Error::InvalidInputLength);
        }

        let mut a = [0; 32];
        a.copy_from_slice(slice);
        Ok(Self::parse(&a))
    }

    fn from_big_int(other: &BigUint) -> Self {
        let key = BigUint::to_bytes_be(&other.mod_floor(&Self::q()));
        Self::from_slice(&u8_ref_to_32_array(&key).unwrap()).unwrap()
    }

    fn to_big_int(&self) -> BigUint {
        BigUint::from_bytes_be(&self.value.b32())
    }

    fn to_hex(&self) -> String {
        hex::encode(&self.to_raw())
    }

    fn parse(p: &[u8; SECRET_KEY_SIZE]) -> Secp256k1Scalar {
        let mut elem = Scalar::default();
        let _ = elem.set_b32(p);
        Secp256k1Scalar { value: elem }
    }
    /// q cannot be a Scalar Element because it's by definition zero/infinity
    fn q() -> BigUint {
        BigUint::from_bytes_be(&CURVE_ORDER)
    }

    fn inv(&self) -> Self {
        Self {
            value: self.value.inv(),
        }
    }

    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    /// Check whether a scalar is higher than the group order divided
    /// by 2.
    fn is_high(&self) -> bool {
        self.value.is_high()
    }

    fn is_even(&self) -> bool {
        self.value.is_even()
    }
}

impl Neg for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn neg(self) -> Secp256k1Scalar {
        Self {
            value: self.value.neg(),
        }
    }
}

impl_op_ex!(
    -|a: Secp256k1Scalar, b: Secp256k1Scalar| -> Secp256k1Scalar {
        Secp256k1Scalar {
            value: a.value + b.value.neg(),
        }
    }
);
impl_op_ex!(
    *|a: &Secp256k1Scalar, b: &Secp256k1Scalar| -> Secp256k1Scalar {
        Secp256k1Scalar {
            value: &a.value * &b.value,
        }
    }
);
impl_op_ex!(+ |a: &Secp256k1Scalar, b: &Secp256k1Scalar| -> Secp256k1Scalar { Secp256k1Scalar { value: &a.value + &b.value } });

// serialize a ScalarElement to hex string with 0x preamble
impl Serialize for Secp256k1Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // serde_json will return true, while bincode will return false. Didn't try cbor_serde so who knows what that will do
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
            // let mut s = serializer.serialize_struct("ScalarElement", 1)?;
            // s.serialize_field("value", &("0x".to_string() + &self.to_hex()))?;
            // s.end()
        } else {
            serializer.serialize_bytes(&self.to_raw())
            // let mut s = serializer.serialize_seq(Some(32))?;
            // s.serialize_element(&self.to_raw())?;
            // s.end()
        }
    }
}

struct ScalarElementVisitor;

impl<'de> Visitor<'de> for ScalarElementVisitor {
    type Value = Secp256k1Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Secp256k1Scalar::from_str(v).map_err(|error| match error {
            Error::InvalidCurvePoint => de::Error::custom("Invalid curve point"),
            Error::InvalidInputLength => de::Error::custom("Invalid input length"),
            Error::InvalidInputEncoding => de::Error::custom("Invalid input encoding (not hex)"),
        })
    }

    // this is used when parsing from bincode
    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let bytes: Vec<u8> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(32, &self))?;

        println!("bytes: {:?}", bytes);

        if bytes.len() != 32 {
            return Err(de::Error::invalid_length(bytes.len(), &"32"));
        }

        Ok(Secp256k1Scalar::from_slice(bytes.as_slice()).unwrap())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Secp256k1Scalar::from_slice(v).map_err(|e| match e {
            Error::InvalidCurvePoint => E::custom("Invalid curve point"),
            Error::InvalidInputLength => E::custom("Invalid length"),
            Error::InvalidInputEncoding => E::custom("Invalid encoding (expected hex)"),
        })
    }

    // fn visit_map<E: de::MapAccess<'de>>(self, mut map: E) -> Result<Self::Value, E::Error> {
    //     let mut x: String = Default::default();
    //
    //     while let Some(ref key) = map.next_key::<String>()? {
    //         let v = map.next_value::<String>()?;
    //         if key == "value" {
    //             x = v;
    //         } else {
    //             panic!("Serialization failed!")
    //         }
    //     }
    //     // serialized string will start with 0x
    //     match ScalarElement::from_slice(&hex::decode(&x[2..]).unwrap()) {
    //         Ok(elem) => Ok(elem),
    //         Err(_) => panic!("Serialization failed!"),
    //     }
    // }
}

impl<'de> Deserialize<'de> for Secp256k1Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(ScalarElementVisitor)
        } else {
            //deserializer.deserialize_seq(ScalarElementVisitor)
            deserializer.deserialize_bytes(ScalarElementVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bincode2;
    use rstest::rstest;
    use serde_json;

    use super::*;

    #[test]
    fn test_serialize_de_bincode() {
        // generate shares for a vector of secrets
        let target = Secp256k1Scalar::from_num(1234234234i64);
        let encoded: Vec<u8> = bincode2::serialize(&target).unwrap();
        let decoded: Secp256k1Scalar = bincode2::deserialize(&encoded[..]).unwrap();
        assert_eq!(target, decoded);
    }

    #[test]
    fn test_serialize() {
        let val: Secp256k1Scalar = Secp256k1Scalar::from_num(1i64);
        let x = serde_json::to_string(&val).unwrap();
        let val2 = serde_json::from_str::<Secp256k1Scalar>(&x).unwrap();

        assert_eq!(val, val2)
    }

    #[test]
    #[should_panic]
    fn test_from_slice_invalid_length() {
        let val = hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        let _ = Secp256k1Scalar::from_slice(&val).unwrap();
    }

    #[test]
    fn test_from_big_int() {
        let mut scal = Scalar::default();

        let val = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(val.as_slice());
        let _ = scal.set_b32(&mut a);

        let scalar2: Secp256k1Scalar = ECScalar::from_big_int(&BigUint::from(1 as u64));
        let scalar = Secp256k1Scalar { value: scal };
        assert_eq!(scalar, scalar2)
    }

    #[test]
    fn test_neg() {
        let scalar: Secp256k1Scalar = Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64));
        let expected: Secp256k1Scalar = Secp256k1Scalar::from_big_int(
            &BigUint::from_str(
                "115792089237316195423570985008687907852837564279074904382605163141518161494336",
            )
            .unwrap(),
        );
        assert_eq!(-scalar, expected, "Simple negative");
    }

    #[test]
    fn test_sub() {
        let scalar = Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64));
        let scalar2 = Secp256k1Scalar::from_big_int(&BigUint::from(151 as u64));
        let expected = Secp256k1Scalar::from_big_int(&BigUint::from(150 as u64));
        assert_eq!(
            scalar2.clone() - scalar,
            expected,
            "Test simple subtraction"
        );

        let scalar = Secp256k1Scalar::from_big_int(&BigUint::from(150 as u64));
        let expected = Secp256k1Scalar::from_big_int(
            &BigUint::from_str(
                "115792089237316195423570985008687907852837564279074904382605163141518161494336",
            )
            .unwrap(),
        );
        assert_eq!(scalar - scalar2, expected, "Test subtraction modulo");
    }

    #[test]
    fn test_inv() {
        let scalar = Secp256k1Scalar::from_big_int(&BigUint::from_bytes_be(
            &hex::decode("3a4cde3a84c4a18d3251e627e5b21743c3db6507f24358ae4b44a1c4ca5ee209")
                .unwrap(),
        ));
        let scalar2 = (&scalar).inv();

        let expected = Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64));

        assert_eq!(scalar * scalar2, expected)
    }
    #[test]
    fn test_mul() {
        let scalar = Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64));
        let scalar2 = Secp256k1Scalar::from_big_int(&BigUint::from(151 as u64));

        let expected = Secp256k1Scalar::from_big_int(&BigUint::from(151 as u64));
        assert_eq!(
            scalar * scalar2.clone(),
            expected,
            "Test simple multiplication"
        );
        let expected = Secp256k1Scalar::from_big_int(&BigUint::from_bytes_be(
            &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0362b6e")
                .unwrap(),
        ));
        let scalar = Secp256k1Scalar::from_big_int(
            &BigUint::from_str(
                "115792089237316195423570985008687907852837564279074904382605163141518161494300",
            )
            .unwrap(),
        );
        assert_eq!(&scalar * &scalar2, expected, "Test multiplication modulo");
    }

    #[test]
    fn test_add() {
        let scalar = Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64));
        let scalar2 = Secp256k1Scalar::from_big_int(&BigUint::from(151 as u64));

        let expected = Secp256k1Scalar::from_big_int(&BigUint::from(152 as u64));
        assert_eq!(scalar + scalar2, expected.clone(), "Test simple addition");

        let scalar3 = Secp256k1Scalar::from_big_int(
            &BigUint::from_str(
                "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            )
            .unwrap(),
        );
        assert_eq!(expected.clone() + scalar3, expected, "Test addition modulo");
    }

    #[test]
    fn test_from_big_int2() {
        let bigint_from_scalar =
            Secp256k1Scalar::from_big_int(&BigUint::from(1 as u64)).to_big_int();
        let bigint = BigUint::from(1 as u64);
        assert_eq!(bigint, bigint_from_scalar)
    }

    #[test]
    fn test_random() {
        let mut rng = rand::thread_rng();
        // Just testing this actually does something, this isn't a RNG test
        let scalar = Secp256k1Scalar::random(&mut rng);
        let scalar2 = Secp256k1Scalar::random(&mut rng);
        assert_ne!(scalar, scalar2);
    }

    #[test]
    fn test_from_num() {
        let one = Secp256k1Scalar::one();

        macro_rules! test_equal_num {
            ($($t:ty)*) =>($(
                let a: $t = 1;
                assert_eq!(Secp256k1Scalar::from_num(a), one);
            )*);
        }

        test_equal_num! { isize i8 i16 i32 i64 i128 usize u8 u16 u32 u64 u128 }
    }

    #[rstest(
        scalar,
        case("0000000000000000000000000000000000000000000000000000000000000001"),
        case("0000000000000000000000000000000000000000000000000000000000000002"),
        case("1000000000000000000000000000000000000000000000000000000000000000"),
        case("774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB"),
        case("D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A"),
        case("F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8"),
        case("499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4"),
        case("D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E"),
        case("A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29")
    )]
    fn test_one(scalar: &str) {
        let one = Secp256k1Scalar::one();
        let scalar_from_big =
            Secp256k1Scalar::from_big_int(&BigUint::from_bytes_be(&hex::decode(scalar).unwrap()));
        assert_eq!(scalar_from_big, one * &scalar_from_big);
    }

    #[rstest(
        scalar,
        case("0000000000000000000000000000000000000000000000000000000000000001"),
        case("0000000000000000000000000000000000000000000000000000000000000002"),
        case("1000000000000000000000000000000000000000000000000000000000000000"),
        case("774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB"),
        case("D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A"),
        case("F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8"),
        case("499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4"),
        case("D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E"),
        case("A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29")
    )]
    fn test_zero(scalar: &str) {
        let zero = Secp256k1Scalar::zero();
        let scalar_from_big =
            Secp256k1Scalar::from_big_int(&BigUint::from_bytes_be(&hex::decode(scalar).unwrap()));
        assert_eq!(zero, &zero * scalar_from_big);
    }

    #[test]
    fn test_q() {
        let q_from_trait: BigUint = Secp256k1Scalar::q();
        let q_from_str = BigUint::from_str(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        )
        .unwrap();
        assert_eq!(q_from_trait, q_from_str);
    }
}
