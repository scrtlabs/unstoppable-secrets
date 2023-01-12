use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};
use std::fmt::{Display, Formatter};

use arrayref::array_ref;
use libsecp256k1::curve::{Affine, Field};
use libsecp256k1::curve::{ECMultContext, ECMultGenContext, Jacobian, Scalar, AFFINE_G};
use libsecp256k1::util::SIGNATURE_SIZE;
use num_bigint::BigUint;
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::super::traits::{ECPoint, ECScalar};
use super::super::Error;
use super::scalar::Secp256k1Scalar;
use super::u8_ref_to_32_array;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Secp256k1Point {
    point: Affine,
}

impl Secp256k1Point {
    pub fn from_str(input: &str) -> Result<Self, Error> {
        let decoded = hex::decode(input).map_err(|_| Error::InvalidInputEncoding)?;

        Self::from_slice(decoded.as_slice())
    }
}

impl ECPoint<Secp256k1Scalar> for Secp256k1Point {
    fn generator() -> Self {
        let mut pt = Affine::default();
        pt.set_xy(&AFFINE_G.x, &AFFINE_G.y);
        Secp256k1Point { point: pt }
    }

    fn x(&self) -> Secp256k1Scalar {
        Secp256k1Scalar::from_big_int(&BigUint::from_bytes_be(&self.point.x.b32()))
    }

    fn y(&self) -> Secp256k1Scalar {
        Secp256k1Scalar::from_big_int(&BigUint::from_bytes_be(&self.point.y.b32()))
    }

    fn parse(p: &[u8; 64]) -> Result<Secp256k1Point, Error> {
        let mut x = Field::default();
        let mut y = Field::default();
        if !x.set_b32(array_ref!(p, 0, 32)) {
            return Err(Error::InvalidCurvePoint);
        }
        if !y.set_b32(array_ref!(p, 32, 32)) {
            return Err(Error::InvalidCurvePoint);
        }
        let mut elem = Affine::default();
        elem.set_xy(&x, &y);
        return if elem.is_valid_var() {
            Ok(Secp256k1Point { point: elem })
        } else {
            // the default isn't a valid var, but we should be able to parse it anyhow
            if elem == Affine::default() {
                return Ok(Secp256k1Point::default());
            } else {
                Err(Error::InvalidCurvePoint)
            }
        };
    }

    fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != SIGNATURE_SIZE {
            return Err(Error::InvalidInputLength);
        }

        let mut a = [0; SIGNATURE_SIZE];
        a.copy_from_slice(slice);
        Self::parse(&a)
    }

    fn to_slice(&self) -> [u8; 64] {
        let mut xy = [0u8; 64];
        xy[0..32].copy_from_slice(&self.point.x.b32());
        xy[32..64].copy_from_slice(&self.point.y.b32());
        xy
    }

    fn to_big_int(&self) -> (BigUint, BigUint) {
        let x = BigUint::from_bytes_be(&self.point.clone().x.b32());
        let y = BigUint::from_bytes_be(&self.point.y.b32());
        (x, y)
    }

    fn from_xy(x: &BigUint, y: &BigUint) -> Self {
        let mut point = Affine::default();
        let mut x_field = Field::default();
        let mut y_field = Field::default();

        let _ = x_field.set_b32(&u8_ref_to_32_array(&x.to_bytes_be()).unwrap());
        let _ = y_field.set_b32(&u8_ref_to_32_array(&y.to_bytes_be()).unwrap());

        point.set_xy(&x_field, &y_field);
        Secp256k1Point { point }
    }

    fn generate(scalar: &Secp256k1Scalar) -> Self {
        let mut point = Affine::default();
        let mut gej = Jacobian::default();

        let mut s = Scalar::default();
        let _ = s.set_b32(&scalar.to_raw());

        let ctx = ECMultGenContext::new_boxed();
        ctx.ecmult_gen(&mut gej, &s);
        point.set_gej(&gej);
        point.x.normalize();
        point.y.normalize();
        Self { point }
    }
}

impl Display for Secp256k1Point {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.to_slice()))
    }
}

impl Sub<Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn sub(self, rhs: Secp256k1Point) -> Secp256k1Point {
        let mut point = Affine::default();
        let gej = Jacobian::from_ge(&self.point);
        point.set_gej(&gej.add_ge(&rhs.point.neg()));
        point.x.normalize();
        point.y.normalize();
        Self { point }
    }
}

impl<'a, 'b> Sub<&'a Secp256k1Point> for &'b Secp256k1Point {
    type Output = Secp256k1Point;
    fn sub(self, rhs: &'a Secp256k1Point) -> Secp256k1Point {
        let mut point = Affine::default();
        let gej = Jacobian::from_ge(&self.point);
        point.set_gej(&gej.add_ge(&rhs.point.neg()));
        point.x.normalize();
        point.y.normalize();
        Secp256k1Point { point }
    }
}

impl Add<Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, rhs: Secp256k1Point) -> Secp256k1Point {
        let mut point = Affine::default();
        let gej = Jacobian::from_ge(&self.point);
        point.set_gej(&gej.add_ge(&rhs.point));
        point.x.normalize();
        point.y.normalize();
        Self { point }
    }
}

impl<'a, 'b> Add<&'a Secp256k1Point> for &'b Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, rhs: &'a Secp256k1Point) -> Secp256k1Point {
        let mut point = Affine::default();
        let gej = Jacobian::from_ge(&self.point);
        point.set_gej(&gej.add_ge(&rhs.point));
        point.x.normalize();
        point.y.normalize();
        Secp256k1Point { point }
    }
}

impl<T: ECScalar> Mul<T> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, rhs: T) -> Secp256k1Point {
        let mut point = Affine::default();
        let mut gej = Jacobian::default();

        let mut scalar = Scalar::default();
        let _ = scalar.set_b32(&rhs.to_raw());

        let ctx = ECMultContext::new_boxed();
        ctx.ecmult_const(&mut gej, &self.point, &scalar);
        point.set_gej(&gej);
        point.x.normalize();
        point.y.normalize();
        Self { point }
    }
}

impl<'a, 'b, T: ECScalar> Mul<&'a T> for &'b Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, rhs: &'a T) -> Secp256k1Point {
        let mut point = Affine::default();
        let mut gej = Jacobian::default();

        let mut scalar = Scalar::default();
        let _ = scalar.set_b32(&rhs.to_raw());

        let ctx = ECMultContext::new_boxed();
        ctx.ecmult_const(&mut gej, &self.point, &scalar);
        point.set_gej(&gej);
        point.x.normalize();
        point.y.normalize();
        Secp256k1Point { point }
    }
}

impl Neg for Secp256k1Point {
    type Output = Secp256k1Point;
    fn neg(self) -> Secp256k1Point {
        Self {
            point: self.point.neg(),
        }
    }
}

impl<'a> Neg for &'a Secp256k1Point {
    type Output = Secp256k1Point;
    fn neg(self) -> Secp256k1Point {
        Secp256k1Point {
            point: self.point.neg(),
        }
    }
}

impl Serialize for Secp256k1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
            // let mut s = serializer.serialize_struct("Point", 1)?;
            // s.serialize_field("x", &self.x().to_hex())?;
            // s.serialize_field("y", &self.y().to_hex())?;
            // s.end()
        } else {
            let mut s = serializer.serialize_seq(Some(64))?;
            s.serialize_element(self.to_slice().as_slice())?;
            s.end()
        }
    }
}

struct PointVisitor;

impl<'de> Visitor<'de> for PointVisitor {
    type Value = Secp256k1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::from_str(v).map_err(|error| match error {
            Error::InvalidCurvePoint => E::custom("Invalid curve point"),
            Error::InvalidInputLength => E::custom("Invalid length"),
            Error::InvalidInputEncoding => E::custom("Invalid encoding (expected hex)"),
        })
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let bytes: Vec<u8> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(64, &self))?;
        if bytes.len() != 64 {
            return Err(de::Error::invalid_length(bytes.len(), &"64"));
        }
        Ok(Secp256k1Point::from_slice(bytes.as_slice()).unwrap())
    }
}

impl<'de> Deserialize<'de> for Secp256k1Point {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(PointVisitor)
        } else {
            deserializer.deserialize_seq(PointVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use bincode2;
    use rstest::rstest;

    use super::super::super::traits::ECScalar;
    use super::*;

    #[test]
    fn test_serialize_default() {
        // generate shares for a vector of secrets
        let target = Secp256k1Point::default();
        let encoded: Vec<u8> = bincode2::serialize(&target).unwrap();
        let decoded: Secp256k1Point = bincode2::deserialize(&encoded[..]).unwrap();
        assert_eq!(target, decoded);
    }

    #[test]
    fn test_serialize_de_bincode() {
        // generate shares for a vector of secrets
        let x = BigUint::from_bytes_be(
            &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap(),
        );
        let y = BigUint::from_bytes_be(
            &hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap(),
        );
        let target = Secp256k1Point::from_xy(&x, &y);
        let encoded: Vec<u8> = bincode2::serialize(&target).unwrap();
        let decoded: Secp256k1Point = bincode2::deserialize(&encoded[..]).unwrap();
        assert_eq!(target, decoded);
    }

    #[test]
    fn test_serialize() {
        let x = BigUint::from_bytes_be(
            &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap(),
        );
        let y = BigUint::from_bytes_be(
            &hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap(),
        );
        let from_xy = Secp256k1Point::from_xy(&x, &y);

        let v1 = serde_json::to_string(&from_xy).unwrap();

        let v2 = serde_json::from_str::<Secp256k1Point>(&v1).unwrap();

        assert_eq!(from_xy, v2)
    }

    #[test]
    fn test_xy() {
        let x = BigUint::from_bytes_be(
            &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap(),
        );
        let y = BigUint::from_bytes_be(
            &hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap(),
        );
        let from_xy = Secp256k1Point::from_xy(&x, &y);
        let x2 = from_xy.x().to_big_int();
        let y2 = from_xy.y().to_big_int(); // Point::from_coor(&int1, &int1);
        assert_eq!(x, x2);
        assert_eq!(y, y2);
    }

    #[test]
    fn test_from_xy() {
        let x = BigUint::from_bytes_be(
            &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap(),
        );
        let y = BigUint::from_bytes_be(
            &hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap(),
        );
        let from_xy = Secp256k1Point::from_xy(&x, &y);
        let generator = Secp256k1Point::generator(); // Point::from_coor(&int1, &int1);
        assert_eq!(from_xy, generator)
    }

    #[test]
    fn test_from_slice() {
        // let int1 = BigUint::from(1 as u64);
        let val = hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        let from_slice = Secp256k1Point::from_slice(&val).unwrap();
        let generator = Secp256k1Point::generator(); // Point::from_coor(&int1, &int1);
        assert_eq!(from_slice, generator)
    }

    #[test]
    #[should_panic]
    fn test_parse_invalid_x() {
        // let int1 = BigUint::from(1 as u64);
        let val = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        let mut raw_slice = [0u8; 64];
        raw_slice.copy_from_slice(val.as_slice());

        let _ = Secp256k1Point::parse(&raw_slice).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_invalid_y() {
        // let int1 = BigUint::from(1 as u64);
        let val = hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let mut raw_slice = [0u8; 64];
        raw_slice.copy_from_slice(val.as_slice());

        let _ = Secp256k1Point::parse(&raw_slice).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_invalid_curve_point() {
        // let int1 = BigUint::from(1 as u64);
        let val = hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B80000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut raw_slice = [0u8; 64];
        raw_slice.copy_from_slice(val.as_slice());

        let _ = Secp256k1Point::parse(&raw_slice).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_from_slice_invalid_length() {
        // let int1 = BigUint::from(1 as u64);
        let val = hex::decode("000001").unwrap();
        let _ = Secp256k1Point::from_slice(&val).unwrap();
    }

    #[test]
    fn test_to_slice() {
        // let int1 = BigUint::from(1 as u64);
        let generator_as_slice = Secp256k1Point::generator().to_slice();
        let val = hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();

        let mut raw_slice = [0u8; 64];
        raw_slice.copy_from_slice(val.as_slice());

        // Point::from_coor(&int1, &int1);
        assert!(
            raw_slice
                .iter()
                .zip(generator_as_slice.iter())
                .all(|(a, b)| a == b),
            "Arrays are not equal"
        );
    }

    #[rstest(
        x1,
        y1,
        x2,
        y2,
        case(
            "3a4cde3a84c4a18d3251e627e5b21743c3db6507f24358ae4b44a1c4ca5ee209",
            "6b903b03504de48540281d8f44e877e7f218669d6586d7cdebc78c14bc9ec198",
            "5151429ea6dcae16b8121a8e4c736614d40117985acc43ebc507ca4fa043cf9f",
            "fa5d1c0ef7501c830ceee8e7a18a8aa2346688f56c5d0a18d65cbff18316f8c9",
        ),
        case(
            "f585efa1635727674f499072cb0e8f33d31eccdc1e71226fa42954409590ae7c",
            "89e9d6baa432380901db62b23061fcf53c9b480b306c824ee1d1276b06c0d9b1",
            "2d7e195e8cc24b1cade20eefb22ad08ecb3ad7d2d5ca7f9bc958f784fa985d",
            "c6c3e103b7555fd7ad07e1e80afc689d5955c2777df50f05aedb5c4bff4ebde0",
        )
    )]
    fn test_neg(x1: &str, y1: &str, x2: &str, y2: &str) {
        // let int1 = BigUint::from(1 as u64);
        let p1 = Secp256k1Point::from_xy(
            &BigUint::from_bytes_be(&hex::decode(x1).unwrap()),
            &BigUint::from_bytes_be(&hex::decode(y1).unwrap()),
        );
        let p2 = Secp256k1Point::from_xy(
            &BigUint::from_bytes_be(&hex::decode(x2).unwrap()),
            &BigUint::from_bytes_be(&hex::decode(y2).unwrap()),
        );
        let sub_res = &p1 - &p2;
        let add_res = &p1 + &(&p2).neg();
        let add_res2 = p1 + (-p2);
        assert_eq!(sub_res, add_res);
        assert_eq!(sub_res, add_res2);
    }

    #[test]
    fn test_add() {
        // tbd: do this
        let val = hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        let from_slice = Secp256k1Point::from_slice(&val).unwrap();
        let res = from_slice.clone() + from_slice.clone();
        let _yo = res.to_big_int();
        assert_eq!(res, res);
    }

    #[rstest(
        x1,
        y1,
        x2,
        y2,
        x3,
        y3,
        case(
            "3a4cde3a84c4a18d3251e627e5b21743c3db6507f24358ae4b44a1c4ca5ee209",
            "6b903b03504de48540281d8f44e877e7f218669d6586d7cdebc78c14bc9ec198",
            "5151429ea6dcae16b8121a8e4c736614d40117985acc43ebc507ca4fa043cf9f",
            "fa5d1c0ef7501c830ceee8e7a18a8aa2346688f56c5d0a18d65cbff18316f8c9",
            "19a48c7f597f9ed54bc4a7a1f9beae250b6b56378d53fe00df4c74184fc1d682",
            "8fa425ab53bdfb7afcd76db2e036d47d2478eb8676a7a2baa5697fc892377a7a",
        ),
        case(
            "f585efa1635727674f499072cb0e8f33d31eccdc1e71226fa42954409590ae7c",
            "89e9d6baa432380901db62b23061fcf53c9b480b306c824ee1d1276b06c0d9b1",
            "2d7e195e8cc24b1cade20eefb22ad08ecb3ad7d2d5ca7f9bc958f784fa985d",
            "c6c3e103b7555fd7ad07e1e80afc689d5955c2777df50f05aedb5c4bff4ebde0",
            "8f65e831d740435855d486d6104536e137862996a07795cff14468ef0339a18d",
            "64bd3ba7a26a4013cb756a17ac22c86cecd63d9b7ef97ad49bf9fa87a4d50e47",
        )
    )]
    fn test_sub(x1: &str, y1: &str, x2: &str, y2: &str, x3: &str, y3: &str) {
        // let int1 = BigUint::from(1 as u64);
        let p1 = Secp256k1Point::from_xy(
            &BigUint::from_bytes_be(&hex::decode(x1).unwrap()),
            &BigUint::from_bytes_be(&hex::decode(y1).unwrap()),
        );
        let p2 = Secp256k1Point::from_xy(
            &BigUint::from_bytes_be(&hex::decode(x2).unwrap()),
            &BigUint::from_bytes_be(&hex::decode(y2).unwrap()),
        );
        let point_from_ref = &p1 - &p2;

        let expected_point = Secp256k1Point::from_xy(
            &BigUint::from_bytes_be(&hex::decode(x3).unwrap()),
            &BigUint::from_bytes_be(&hex::decode(y3).unwrap()),
        );

        assert_eq!(point_from_ref, expected_point);

        let point_moved = p1 - p2;
        assert_eq!(point_from_ref, point_moved);
    }

    #[rstest(
        k,
        x,
        y,
        case(
            1,
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        ),
        case(
            9,
            "ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE",
            "CC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37"
        ),
        case(
            10,
            "A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7",
            "893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7"
        ),
        case(
            11,
            "774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB",
            "D984A032EB6B5E190243DD56D7B7B365372DB1E2DFF9D6A8301D74C9C953C61B"
        ),
        case(
            12,
            "D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A",
            "A9F34FFDC815E0D7A8B64537E17BD81579238C5DD9A86D526B051B13F4062327"
        ),
        case(
            13,
            "F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8",
            "0AB0902E8D880A89758212EB65CDAF473A1A06DA521FA91F29B5CB52DB03ED81"
        ),
        case(
            14,
            "499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4",
            "CAC2F6C4B54E855190F044E4A7B3D464464279C27A3F95BCC65F40D403A13F5B"
        ),
        case(
            15,
            "D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E",
            "581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58"
        ),
        case(
            112233445566778899,
            "A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29",
            "5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76"
        )
    )]
    fn test_mul(k: u64, x: &str, y: &str) {
        let generator = Secp256k1Point::generator();
        let val = Secp256k1Scalar::from_big_int(&BigUint::from(k));
        let point = &generator * &val;

        let expected_point = Secp256k1Point::from_xy(
            &BigUint::from_bytes_be(&hex::decode(x).unwrap()),
            &BigUint::from_bytes_be(&hex::decode(y).unwrap()),
        );
        assert_eq!(point, expected_point);

        let from_genenrate = Secp256k1Point::generate(&val);
        assert_eq!(point, from_genenrate);

        // test mul with moved objects
        let point = generator * val;
        assert_eq!(point, expected_point);
    }
}
