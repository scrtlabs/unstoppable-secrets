use ec_curve::traits::ECScalar;

//MIT License
//
//Copyright (c) 2019 KZen Networks
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.


//
//// Performs a Lagrange interpolation in field Zp at the origin
//// for a polynomial defined by `points` and `values`.
//// `points` and `values` are expected to be two arrays of the same size, containing
//// respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).
//
//// The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.
//
//// This is obviously less general than `newton_interpolation_general` as we
//// only get a single value, but it is much faster.
//
pub fn lagrange_interpolation_at_zero<T: ECScalar>(points: &Vec<T>, values: &Vec<T>) -> T {
    let vec_len = values.len();

    assert_eq!(points.len(), vec_len);
    // Lagrange interpolation for point 0
    // let mut acc = 0i64;
    let lag_coef =
        (0..vec_len)
            .map(|i| {
                let xi = &points[i];
                let yi = &values[i];
                let num = T::one();
                let denum = T::one();
                let num = points.iter().zip(0..vec_len).fold(num, |acc, x| {
                    if i != x.1 {
                        acc * x.0.clone()
                    } else {
                        acc
                    }
                });
                let denum = points.iter().zip(0..vec_len).fold(denum, |acc, (val, size) | {
                    if i != size {
                        let xj_sub_xi = val.clone() - xi.clone();
                        acc * xj_sub_xi
                    } else {
                        acc
                    }
                });
                let denum = denum.inv();
                num * denum * yi.clone()
            })
            .collect::<Vec<T>>();
    let mut lag_coef_iter = lag_coef.into_iter();
    let head = lag_coef_iter.next().unwrap();
    let tail = lag_coef_iter;
    tail.fold( head, |acc, x| acc + x)
}

pub fn evaluate_polynomial<T: ECScalar>(coefficients: &[T], index_vec: &[u8]) -> Vec<T> {
    (0..index_vec.len())
        .map(|point| {
            mod_evaluate_polynomial(coefficients, T::from_num(index_vec[point] as u32))
        })
        .collect::<Vec<T>>()
}

fn mod_evaluate_polynomial<T: ECScalar>(coefficients: &[T], point: T) -> T {
    // evaluate using Horner's rule
    //  - to combine with fold we consider the coefficients in reverse order
    let mut reversed_coefficients = coefficients.iter().rev();
    // manually split due to fold insisting on an initial value
    let head = reversed_coefficients.next().unwrap();
    let tail = reversed_coefficients;
    tail.fold(head.clone(), |acc, coef| {
        acc * point.clone() + coef.clone()
    })
}

// returns vector of coefficients
pub fn sample_polynomial<T: ECScalar, R: rand_core::RngCore + rand_core::CryptoRng>(t: usize, coef0: &T, rng: &mut R) -> Vec<T> {
    let mut coefficients = vec![coef0.clone()];
    // sample the remaining coefficients randomly using secure randomness
    let random_coefficients: Vec<T> = (0..t).map(|_| T::random(rng)).collect();
    coefficients.extend(random_coefficients);
    // return
    coefficients
}