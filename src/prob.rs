// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Probability tools

use std::cmp::min;

use {NN, RR};


/// Calculate `n choose k`, i.e. `n! / (k! (n-k)!)`.
pub fn choose(n: NN, mut k: NN) -> RR {
    assert!(n >= k);
    let mut result: RR = 1 as RR;
    k = min(k, n - k);
    for kp in 1..(k + 1) {
        // kp goes from 1 to k
        result *= ((n - kp + 1) as RR) / (kp as RR);
    }
    result
}

#[test]
fn test_choose() {
    assert_eq!(choose(15, 0) as NN, 1);
    assert_eq!(choose(1563, 1563) as NN, 1);
    assert_eq!(choose(65, 1) as NN, 65);
    assert_eq!(choose(16, 2) as NN, (8 * 15));
    assert_eq!(choose(35, 3) as NN, (35 * 17 * 11));
    assert_eq!(choose(56, 7) as NN, (8 * 11 * 9 * 53 * 13 * 17 * 25));
}

/// Calculate the probability of less than `q` "black" nodes, where there
/// are `n` total nodes ("red" + "black"), `r` red, and we choose `k`.
pub fn prob_disruption(n: NN, r: NN, k: NN, q: NN) -> RR {
    1.0 - prob_compromise(n, n - r, k, q)
}

/// Calculate the probability of choosing at least `q` "red" nodes, where there
/// are `n` total nodes, `r` red, and we choose `k`.
pub fn prob_compromise(n: NN, r: NN, k: NN, q: NN) -> RR {
    assert!(n >= r, "expected n >= r; found n={}, r={}", n, r);
    assert!(k >= q, "expected k >= q; found k={}, q={}", k, q);
    assert!(n - r >= k - q,
            "expected n-r >= k-q; found n-r = {}, k-q = {}",
            n - r,
            k - q);

    // In this we consider each node from n/r distinct, and consider recruiting
    // k nodes into a set (so order doesn't matter).

    // First, calculate the number of ways of choosing less than q red nodes
    let mut combs_compr: RR = 0 as RR;
    for x in q..(k + 1) {
        if x > r {
            continue;   // impossible: 0 combinations to add
        }

        // x is the number of red nodes that get picked; this is the number of
        // possible combinations:
        combs_compr += choose(r, x) * choose(n - r, k - x);
    }

    // Now, the total number of combinations in the set is
    let total_combs = choose(n, k);
    combs_compr / total_combs
}
