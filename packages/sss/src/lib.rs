use lagrange::{evaluate_polynomial, lagrange_interpolation_at_zero, sample_polynomial};

use rand_core::{CryptoRng, RngCore};

mod lagrange;
mod share;

pub use ec_curve::secp256k1::point::Secp256k1Point;
pub use ec_curve::secp256k1::scalar::Secp256k1Scalar;
pub use ec_curve::traits::ECPoint;
pub use ec_curve::traits::ECScalar;
pub use share::Share;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    NoShares,
    // InvalidMultiplicationResult,
    NotEnoughShares,
    // InvalidScalar,
}

pub fn split<T: ECScalar, R: CryptoRng + RngCore>(
    rng: &mut R,
    data: &T,
    threshold: u8,
    num_of_shares: u8,
) -> Vec<Share<T>> {
    let poly = sample_polynomial(threshold as usize, data, rng);
    let indexes: Vec<u8> = (1..=num_of_shares).collect();
    let secret_shares = evaluate_polynomial(&poly, &indexes);

    let shares: Vec<Share<T>> = secret_shares
        .iter()
        .enumerate()
        .map(|(index, share)| Share {
            id: (index + 1) as u32,
            data: share.clone(),
            share_count: num_of_shares,
            threshold,
        })
        .collect();
    shares
}

pub fn open<T: ECScalar>(shares: Vec<Share<T>>) -> Result<T, Error> {
    // reconstruct using remaining subset of shares
    if shares.len() == 0 {
        return Err(Error::NoShares);
    } else if shares.len() < shares[0].threshold as usize {
        return Err(Error::NotEnoughShares);
    }

    let indices: Vec<usize> = shares.iter().map(|share| share.id as usize).collect();
    let values: Vec<T> = shares.iter().map(|share| share.data.clone()).collect();

    let recovered_secret = reconstruct(&indices, &values);
    Ok(recovered_secret)
}

fn reconstruct<T: ECScalar>(indices: &Vec<usize>, shares: &Vec<T>) -> T {
    assert_eq!(shares.len(), indices.len());
    // assert!(shares.len() >= self.reconstruct_limit());
    // add one to indices to get points
    let points = indices
        .iter()
        .map(|i| ECScalar::from_num(*i as u32))
        .collect::<Vec<T>>();
    lagrange_interpolation_at_zero(&points, shares)
}

#[cfg(test)]
mod tests {
    use ec_curve::secp256k1::scalar::Secp256k1Scalar;

    use super::*;

    use rand::thread_rng;

    #[test]
    fn test_open_share_funcs() {
        // generate shares for a vector of secrets
        let secret = Secp256k1Scalar::from_num(14748364);
        let k = 3;
        let n = 5;

        let mut rng = thread_rng();

        let shares = split(&mut rng, &secret, k, n);

        let recovered = open(shares).unwrap();

        assert_eq!(secret, recovered);
    }
}
//
