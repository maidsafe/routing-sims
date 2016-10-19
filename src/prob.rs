// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Probability tools

use super::{NN, RR, Quorum, SimTool};

use std::cmp::min;


/// Calculate `n chose k`, i.e. `n! / (k! (n-k)!)`.
pub fn choose(n: NN, mut k: NN) -> RR {
    assert!(n >= k);
    let mut result: RR = 1 as RR;
    k = min(k, n - k);
    for kp in 1...k {
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


/// Calculate the probability of choosing at least `q` "red" nodes, where there
/// are `n` total nodes, `r` red, and we choose `k`.
pub fn prob_compromise(n: NN, r: NN, k: NN, q: NN) -> RR {
    assert!(n >= r);
    assert!(n - r >= k - q,
            "expected n-r >= k-q; found {} < {}",
            n - r,
            k - q);

    // In this we consider each node from n/r distinct, and consider recruiting
    // k nodes into a set (so order doesn't matter).

    // First, calculate the number of ways of choosing less than q red nodes
    let mut combs_compr: RR = 0 as RR;
    for x in q...k {
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


pub struct DirectCalcTool {
    num_nodes: NN,
    num_malicious: NN,
    min_group_size: NN,
    quorum: NN,
    any_group: bool,
}
impl DirectCalcTool {
    pub fn new() -> Self {
        DirectCalcTool {
            num_nodes: 5000,
            num_malicious: 500,
            min_group_size: 10,
            quorum: 8,
            any_group: false,
        }
    }
}
impl Quorum for DirectCalcTool {
    fn quorum_size(&self) -> Option<NN> {
        Some(self.quorum)
    }
    fn set_quorum_size(&mut self, n: NN) {
        self.quorum = n;
    }
}
impl SimTool for DirectCalcTool {
    fn total_nodes(&self) -> NN {
        self.num_nodes
    }
    fn set_total_nodes(&mut self, n: NN) {
        self.num_nodes = n;
        assert!(self.num_nodes >= self.num_malicious);
    }

    fn malicious_nodes(&self) -> NN {
        self.num_malicious
    }
    fn set_malicious_nodes(&mut self, n: NN) {
        self.num_malicious = n;
        assert!(self.num_nodes >= self.num_malicious);
    }

    fn min_group_size(&self) -> NN {
        self.min_group_size
    }
    fn set_min_group_size(&mut self, n: NN) {
        self.min_group_size = n;
    }

    fn quorum(&self) -> &Quorum {
        self
    }
    fn quorum_mut(&mut self) -> &mut Quorum {
        self
    }

    fn set_any(&mut self, any: bool) {
        self.any_group = any;
    }

    fn print_message(&self) {
        if self.any_group {
            println!("Tool: calculate the expected number of compromised groups, \
                assuming all groups have min size");
        } else {
            println!("Tool: calculate the probability of one specific group (of \
            min size) being compromised");
        }
    }

    fn calc_p_compromise(&self) -> RR {
        let p = prob_compromise(self.num_nodes,
                                self.num_malicious,
                                self.min_group_size,
                                self.quorum);
        if self.any_group {
            p * ((self.num_nodes as RR) / (self.num_malicious as RR))
        } else {
            p
        }
    }
}
