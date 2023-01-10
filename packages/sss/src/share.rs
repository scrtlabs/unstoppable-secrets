// use crate::ec_curve::secp256k1::Point;
// //use super::ScalarElement;
use core::ops::{Sub, Add, Mul};
use ec_curve::traits::ECScalar;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use super::{Error, open};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Share<T: ECScalar + Default + Serialize + DeserializeOwned> {
    pub id: u32,
    #[serde(deserialize_with = "T::deserialize")]
    pub data: T,
    pub threshold: u8,
    pub share_count: u8,
}


#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretShares<T: ECScalar + Serialize + DeserializeOwned>(
    #[serde(bound = "")]
    pub Vec<Share<T>>
);

impl <T: ECScalar> SecretShares<T> {
    pub fn new(shares: Vec<Share<T>>) -> SecretShares<T> {
        SecretShares(shares)
    }

    pub fn recover(self) -> Result<T, Error> {
        open(self.0)
    }
}



pub trait Shareable where Self: ECScalar {
    fn split(&self) -> SecretShares<Self>;
}

impl <T: ECScalar> Add<Share<T>> for Share<T> {
    type Output = Share<T>;
    fn add(self, rhs: Share<T>) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data + rhs.data }
    }
}

impl <'a, 'b, T: ECScalar> Add<&'a Share<T>> for &'b Share<T> {
    type Output = Share<T>;
    fn add(self, rhs: &'a Share<T>) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data.clone() + rhs.data.clone() }
    }
}

impl <T: ECScalar> Sub<Share<T>> for Share<T> {
    type Output = Share<T>;
    fn sub(self, rhs: Share<T>) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data - rhs.data }
    }
}

impl <'a, 'b, T: ECScalar> Sub<&'a Share<T>> for &'b Share<T> {
    type Output = Share<T>;
    fn sub(self, rhs: &'a Share<T>) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data.clone() - rhs.data.clone() }
    }
}

impl <T: ECScalar> Add<T> for Share<T> {
    type Output = Share<T>;
    fn add(self, rhs: T) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data + rhs }
    }
}

impl <'a, 'b, T: ECScalar> Add<&'a T> for &'b Share<T> {
    type Output = Share<T>;
    fn add(self, rhs: &'a T) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data.clone() + rhs.clone() }
    }
}

impl <T: ECScalar> Sub<T> for Share<T> {
    type Output = Share<T>;
    fn sub(self, rhs: T) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data - rhs }
    }
}

impl <'a, 'b, T: ECScalar> Sub<&'a T> for &'b Share<T> {
    type Output = Share<T>;
    fn sub(self, rhs: &'a T) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data.clone() - rhs.clone() }
    }
}

impl <T: ECScalar> Mul<T> for Share<T> {
    type Output = Share<T>;
    fn mul(self, rhs: T) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data * rhs }
    }
}

impl <'a, 'b, T: ECScalar> Mul<&'a T> for &'b Share<T> {
    type Output = Share<T>;
    fn mul(self, rhs: &'a T) -> Share<T> {
        Share { id: self.id, threshold: self.threshold, share_count: self.share_count,
            data: self.data.clone() * rhs.clone() }
    }
}

impl <T: ECScalar> Add<T> for SecretShares<T> {
    type Output = SecretShares<T>;
    fn add(self, rhs: T) -> SecretShares<T> {
        let mut z = SecretShares::default();
        self.0.iter().map(|item| {
            z.0.push(item.clone() + rhs.clone())
        }).count();
        z
    }
}

impl <'a, 'b, T: ECScalar> Add<&'a T> for &'b SecretShares<T> {
    type Output = SecretShares<T>;
    fn add(self, rhs: &'a T) -> SecretShares<T> {
        let mut z = SecretShares::default();
        self.0.iter().map(|item| {
            z.0.push(item.clone() + rhs.clone())
        }).count();
        z
    }
}

impl <T: ECScalar> Sub<T> for SecretShares<T> {
    type Output = SecretShares<T>;
    fn sub(self, rhs: T) -> SecretShares<T> {
        let mut z = SecretShares::default();
        self.0.iter().map(|item| {
            z.0.push(item.clone() - rhs.clone())
        }).count();
        z
    }
}

impl <'a, 'b, T: ECScalar> Sub<&'a T> for &'b SecretShares<T> {
    type Output = SecretShares<T>;
    fn sub(self, rhs: &'a T) -> SecretShares<T> {
        let mut z = SecretShares::default();
        self.0.iter().map(|item| {
            z.0.push(item.clone() - rhs.clone())
        }).count();
        z
    }
}

impl <T: ECScalar> Mul<T> for SecretShares<T> {
    type Output = SecretShares<T>;
    fn mul(self, rhs: T) -> SecretShares<T> {
        let mut z = SecretShares::default();
        self.0.iter().map(|item| {
            z.0.push(item.clone() * rhs.clone())
        }).count();
        z
    }
}

impl <'a, 'b, T: ECScalar> Mul<&'a T> for &'b SecretShares<T> {
    type Output = SecretShares<T>;
    fn mul(self, rhs: &'a T) -> SecretShares<T> {
        let mut z = SecretShares::default();
        self.0.iter().map(|item| {
            z.0.push(item.clone() * rhs.clone())
        }).count();
        z
    }
}

impl <T: ECScalar> Add<SecretShares<T>> for SecretShares<T> {
    type Output = SecretShares<T>;
    fn add(self, rhs: SecretShares<T>) -> SecretShares<T> {
        let mut z = SecretShares::default();
        for (_i, (aval, bval)) in self.0.iter().zip(&rhs.0).enumerate() {
            z.0.push(aval + bval);
        }
        z
    }
}

impl <'a, 'b, T: ECScalar> Add<&'a SecretShares<T>> for &'b SecretShares<T> {
    type Output = SecretShares<T>;
    fn add(self, rhs: &'a SecretShares<T>) -> SecretShares<T> {
        let mut z = SecretShares::default();
        for (_i, (aval, bval)) in self.0.iter().zip(&rhs.0).enumerate() {
            z.0.push(aval + bval);
        }
        z
    }
}

impl <T: ECScalar> Sub<SecretShares<T>> for SecretShares<T> {
    type Output = SecretShares<T>;
    fn sub(self, rhs: SecretShares<T>) -> SecretShares<T> {
        let mut z = SecretShares::default();
        for (_i, (aval, bval)) in self.0.iter().zip(&rhs.0).enumerate() {
            z.0.push(aval - bval);
        }
        z
    }
}

impl <'a, 'b, T: ECScalar> Sub<&'a SecretShares<T>> for &'b SecretShares<T> {
    type Output = SecretShares<T>;
    fn sub(self, rhs: &'a SecretShares<T>) -> SecretShares<T> {
        let mut z = SecretShares::default();
        for (_i, (aval, bval)) in self.0.iter().zip(&rhs.0).enumerate() {
            z.0.push(aval - bval);
        }
        z
    }
}

//impl Mul<SecretShares> for SecretShares<T> {
//    type Output = SecretShares<T>;
//    fn mul(self, rhs: T) -> SecretShares<T> {
//        let mut z = SecretShares::default();
//        self.0.iter().map(|item| {
//            z.0.push(item.clone() * rhs.clone())
//        }).count();
//        z
//    }
//}

#[cfg(test)]
mod tests {
    use super::*;
    use ec_curve::secp256k1::scalar::ScalarElement;

    #[test]
    fn test_add() {
        let scalar = ScalarElement::from_num(1);
        let scalar_result = ScalarElement::from_num(2);

        let share = Share { id: 1, threshold: 1, share_count: 1, data: scalar.clone() };

        let expected = Share { id: 1, threshold: 1, share_count: 1, data: scalar_result.clone() };
        let val = share + scalar;

        assert_eq!(val, expected, "Test addition modulo");
    }

    #[test]
    fn test_add_secret_shares() {
        let scalar = ScalarElement::from_num(1);
        let scalar_result = ScalarElement::from_num(2);

        let share = Share { id: 1, threshold: 1, share_count: 1, data: scalar.clone() };

        let expected = Share { id: 1, threshold: 1, share_count: 1, data: scalar_result.clone() };

        let s0 = vec![share.clone(), share.clone()];
        let s1 = vec![expected.clone(), expected.clone()];
        let mut secret_shares: SecretShares<ScalarElement> = SecretShares::default();
        let mut secret_shares_expected: SecretShares<ScalarElement> = SecretShares::default();
        secret_shares.0 = s0;
        secret_shares_expected.0 = s1;

        secret_shares = secret_shares + scalar;

        assert_eq!(secret_shares, secret_shares_expected, "Test addition modulo");
    }
}

//impl_op_ex!(* |lhs: &Shares, rhs: &Shares| -> Shares {
//        let mut z = Shares::default();
//
//        /*
//            d = sub(x1, a)
//            e = sub(x2, b)
//
//            d_pub = mpc.open(d)
//            e_pub = mpc.open(e)
//            # print(f'd_pub1: {d_pub}')
//            de_pub = (d_pub * e_pub) % mpc.p
//            db = mulp(b, d_pub)
//            ea = mulp(a, e_pub)
//
//            y = add(add(addp(db, de_pub), ea), c)  # [z] = d*e + d*[b] + e*[a] + [c]
//            return y
//        */
//        for ((zref, self_val), rhs_val) in z.0.iter_mut().zip(&lhs.0).zip(&rhs.0) {
//            *zref = self_val * rhs_val;
//            }
//          z
//        });

//impl_op_ex_commutative!(* |lhs: &SecretShares, rhs: &ScalarElement| -> Shares {
//        let mut z = Shares::default();
//        for (zref, self_val) in z.0.iter_mut().zip(&lhs.0) {
//            *zref = self_val * rhs
//        }
//        z
//    });

//impl_op_ex_commutative!(+ |a: &ShamirShare, b: &Point| -> ShamirShare { ShamirShare { id: a.id, point: &a.point + b } });
//impl_op_ex_commutative!(- |a: &ShamirShare, b: &Point| -> ShamirShare { ShamirShare { id: a.id, point: &a.point - b } });
//
//impl_op_ex!(- |a: &ShamirShare, b: &ShamirShare| -> ShamirShare { ShamirShare { id: a.id, point: &a.point - &b.point } });
//impl_op_ex!(+ |a: &ShamirShare, b: &ShamirShare| -> ShamirShare { ShamirShare { id: a.id, point: &a.point + &b.point } });