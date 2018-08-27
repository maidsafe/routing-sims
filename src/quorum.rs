// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Quorum

use std::collections::HashMap;

use {NN, RR};
use node::{NodeName, NodeData};


/// Describes the "quorum" algorithm
pub trait Quorum {
    /// Get number of nodes needed for a quorum, given group size k.
    ///
    /// Get the number of messages needed for quorum. If the quorum algorithm
    /// does anything more complicated (e.g. check node age) then this will
    /// return `None`.
    fn quorum_size(&self, k: NN) -> Option<NN>;

    /// Specify proportion of group agreement required, range 0-1. Use slightly
    /// greater than half if number must be greater than 50%.
    fn set_quorum_proportion(&mut self, prop: RR);

    /// Returns true if there is not a quorum of good nodes in the passed group.
    fn quorum_disrupted(&self, group: &HashMap<NodeName, NodeData>) -> bool;

    /// Returns true if there is a quorum of bad nodes in the passed group.
    fn quorum_compromised(&self, group: &HashMap<NodeName, NodeData>) -> bool;
}

/// Quorum based on simply meeting some minimum proportion of the group.
pub struct SimpleQuorum {
    proportion: RR,
}

impl SimpleQuorum {
    /// New structure. Default to requiring a quorum of the entire group.
    pub fn new() -> Self {
        SimpleQuorum { proportion: 1.0 }
    }

    /// New structure, with specified proportion requried.
    pub fn from(prop: RR) -> Self {
        SimpleQuorum { proportion: prop }
    }
}

impl Quorum for SimpleQuorum {
    fn quorum_size(&self, k: NN) -> Option<NN> {
        Some((k as RR * self.proportion).ceil() as NN)
    }

    fn set_quorum_proportion(&mut self, prop: RR) {
        self.proportion = prop;
    }

    fn quorum_disrupted(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let good = group.iter().filter(|node| !node.1.is_malicious()).count() as RR;
        let all = group.len() as RR;
        good / all < self.proportion
    }

    fn quorum_compromised(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let bad = group.iter().filter(|node| node.1.is_malicious()).count() as RR;
        let all = group.len() as RR;
        bad / all >= self.proportion
    }
}

/// Quorum which requires some proportion of group age as well as number
///
/// We require the same proportion of age as of the number of nodes (although
/// these could be separated).
pub struct AgeQuorum {
    proportion: RR,
}

impl AgeQuorum {
    /// New structure. Default to requiring a quorum of the entire group.
    pub fn new() -> Self {
        AgeQuorum { proportion: 1.0 }
    }
}

impl Quorum for AgeQuorum {
    fn quorum_size(&self, _: NN) -> Option<NN> {
        None
    }

    fn set_quorum_proportion(&mut self, prop: RR) {
        self.proportion = prop;
    }

    fn quorum_disrupted(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let n_nodes = group.len() as RR;
        let mut sum_age = 0;
        let mut n_good = 0;
        let mut good_age = 0;
        for data in group.values() {
            sum_age += data.age();
            if !data.is_malicious() {
                n_good += 1;
                good_age += data.age();
            }
        }
        (n_good as RR) / n_nodes < self.proportion ||
        (good_age as RR) / (sum_age as RR) < self.proportion
    }

    fn quorum_compromised(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let n_nodes = group.len() as RR;
        let mut sum_age = 0;
        let mut n_bad = 0;
        let mut bad_age = 0;
        for data in group.values() {
            sum_age += data.age();
            if data.is_malicious() {
                n_bad += 1;
                bad_age += data.age();
            }
        }
        (n_bad as RR) / n_nodes >= self.proportion &&
        (bad_age as RR) / (sum_age as RR) >= self.proportion
    }
}
