// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Simulation tools
//!
//! These have a number of simplifications over the real network. Notably:
//!
//! *   Node join/leave and group split/merge are instantaneous.
//! *   Node names are simply random numbers
//! *   Node leaving and group merging are not simulated

use std::collections::hash_map::{Entry, HashMap};
use std::mem;

use rand::{thread_rng, Rng};

use attack::AttackStrategy;
use node::{new_node_name, NodeData, NodeName, Prefix};
use {ToolArgs, NN, RR};

#[allow(non_snake_case)]
fn sample_NN() -> NN {
    thread_rng().gen()
}

/// Controls whether a node can get added to a group
pub trait AddRestriction {
    /// May prevent add operation, for example if the group has too many nodes of this age.
    fn can_add(_node_data: &NodeData, _group: &HashMap<NodeName, NodeData>) -> bool {
        true
    }
}

/// As the name says: never reject nodes.
pub struct NoAddRestriction;
impl AddRestriction for NoAddRestriction {}

/// Limit the number of nodes of certain ages (currently only ages 0 and 1)
pub struct RestrictOnePerAge;
impl AddRestriction for RestrictOnePerAge {
    fn can_add(node_data: &NodeData, group: &HashMap<NodeName, NodeData>) -> bool {
        let age = node_data.age();
        if age > 1 {
            return true;
        }
        group.values().filter(|data| data.age() == age).count() < 2
    }
}

/// A `Group` is a collection of named nodes.
pub type Group = HashMap<NodeName, NodeData>;

/// A `Network` is a collection of groups.
///
/// This struct implements both the low-level network structure code and the high-level code used
/// to simulate network creation.
pub struct Network {
    min_group_size: usize,
    groups: HashMap<Prefix, Group>,
    // Number of new nodes allowed, and probability of a good node leaving.
    // These are accumulated between steps, not simply reset each step.
    to_join: RR,
    p_leave: RR,
    // Number of new nodes available (good and malicious):
    avail_good: NN,
    avail_malicious: NN,
    // nodes pending joining a group this step, and those joining next step:
    pending_nodes: Vec<(NodeName, NodeData)>,
    pending_next: Vec<(NodeName, NodeData)>,
}

impl Network {
    /// Create. Specify minimum group size.
    ///
    /// An initial, empty, group is created.
    pub fn new(min_group_size: usize) -> Self {
        let mut groups = HashMap::new();
        groups.insert(Prefix::new(0, 0), HashMap::new());
        Network {
            min_group_size: min_group_size,
            groups: groups,
            to_join: 0.0,
            p_leave: 0.0,
            avail_good: 0,
            avail_malicious: 0,
            pending_nodes: vec![],
            pending_next: vec![],
        }
    }

    /// Are any nodes available to be added still?
    pub fn has_avail(&self) -> bool {
        self.avail_good > 0 || self.avail_malicious > 0
    }

    /// Add (good, malicious) nodes to the queue of "available" nodes waiting to be added.
    pub fn add_avail(&mut self, n_good: NN, n_malicious: NN) {
        self.avail_good += n_good;
        self.avail_malicious += n_malicious;
    }

    /// Run a step in the simulation.
    ///
    /// Note: if a node has done proof-of-work but its original target group splits, it
    /// simply joins whichever group it would now be in. If a node has done proof of work and
    /// is not accepted due to age restrictions, it is given a new name and must redo work.
    pub fn do_step<AR: AddRestriction>(
        &mut self,
        args: &ToolArgs,
        attack: &mut dyn AttackStrategy,
    ) {
        self.to_join += args.max_join_rate;
        self.p_leave += args.leave_rate_good;

        // Add any nodes which were waiting for proof-of-work to complete
        while let Some((node_name, node_data)) = self.pending_nodes.pop() {
            let age = node_data.age();
            let opt_moved = match self.add_node::<AR>(node_name, node_data) {
                Ok(prefix) => {
                    trace!("Added node {} with age {}", node_name, age);
                    let prefix = self.maybe_split(prefix, node_name, attack);
                    // Add successful: do churn event. The churn may cause a removal from a
                    // group; however, either that was an old group which just got a new
                    // member, or it is a split result with at least one node more than the
                    // minimum number. Either way merging is not required.
                    self.churn(prefix, node_name)
                        .map(|(old_name, data)| (Some(old_name), data))
                }
                Err(node_data) => Some((None, node_data)),
            };
            if let Some((opt_old_name, data)) = opt_moved {
                let new_name = new_node_name();
                if data.is_malicious()
                    && attack.reset_on_new_name(self, opt_old_name, new_name, &data)
                {
                    // Node resets: drop data, but remember that we need another malicious node
                    self.avail_malicious += 1;
                } else {
                    self.pending_next.push((new_name, data));
                }
            }
        }

        // Add new nodes, up to the maximum allowed this step; these do not get inserted until
        // next step.
        while self.to_join >= 1.0 {
            self.to_join -= 1.0;

            // Numbers are unsigned, so not 0 implies > 0:
            let is_malicious = match (self.avail_malicious, self.avail_good) {
                (0, 0) => {
                    break;
                }
                (_m, 0) => true,
                (0, _g) => false,
                (m, g) => {
                    let p = (m as RR) / ((m + g) as RR);
                    let thresh = (p * (NN::max_value() as RR)).round() as NN;
                    sample_NN() < thresh
                }
            };
            let new_name = new_node_name();
            let data = NodeData::new(is_malicious);

            if is_malicious && attack.reset_on_new_name(self, None, new_name, &data) {
                // Attacking node resets: let a new one replace it. The only thing which changed is
                // that self.to_join has been decremented.
                continue;
            }

            self.pending_next.push((new_name, data));
            if is_malicious {
                self.avail_malicious -= 1;
            } else {
                self.avail_good -= 1;
            }
        }

        // only do anything if probability is significant, otherwise accumulate
        if self.p_leave >= 0.001 {
            let p_leave = self.p_leave;
            let n = self.probabilistic_drop(p_leave) as NN;
            // Add replacements to maintain size. Note that only good nodes leave like this.
            self.avail_good += n;
            self.p_leave = 0.0;
        }

        mem::swap(&mut self.pending_nodes, &mut self.pending_next);
    }

    /// Access groups
    pub fn groups(&self) -> &HashMap<Prefix, HashMap<NodeName, NodeData>> {
        &self.groups
    }

    /// Get the prefix for the group to which this name belongs.
    pub fn find_prefix(&self, name: NodeName) -> Prefix {
        // There are two strategies here:
        // 1) iterate through all groups, checking for prefix match
        // 2) iterate through all possible prefixes of name, looking each up in the group table
        // The second scales much better with large numbers of groups, and should
        // still be fairly fast with few groups because in this case the prefixes will be small.
        for bits in 0..(mem::size_of::<NN>() * 8) {
            let prefix = Prefix::new(bits, name);
            if self.groups.contains_key(&prefix) {
                return prefix;
            }
        }
        unreachable!()
    }

    /// Insert a node. Returns the prefix of the group added to on success, or the node data it
    /// failed to add on failure caused by an AddRestriction or name collision (in both cases the
    /// node should be renamed).
    pub fn add_node<AR: AddRestriction>(
        &mut self,
        node_name: NodeName,
        node_data: NodeData,
    ) -> Result<Prefix, NodeData> {
        let prefix = self.find_prefix(node_name);
        let group = self
            .groups
            .get_mut(&prefix)
            .expect("network must include all groups");
        if group.len() > self.min_group_size && !AR::can_add(&node_data, group) {
            return Err(node_data);
        }
        match group.entry(node_name) {
            Entry::Vacant(e) => e.insert(node_data),
            Entry::Occupied(_) => {
                return Err(node_data);
            }
        };
        Ok(prefix)
    }

    /// Probabilistically drop good nodes (`p` is the chance of each node being dropped).
    /// Return the number of nodes dropped.
    pub fn probabilistic_drop(&mut self, p: RR) -> usize {
        let thresh = (p * (NN::max_value() as RR)).round() as NN;
        let mut need_merge = vec![];
        let mut num = 0;
        for (prefix, ref mut group) in &mut self.groups {
            let to_remove: Vec<_> = group
                .iter()
                .filter_map(|(ref key, ref data)| {
                    if !data.is_malicious() && sample_NN() < thresh {
                        Some(**key)
                    } else {
                        None
                    }
                })
                .collect();
            for key in to_remove {
                group.remove(&key);
                num += 1;
            }
            if group.len() < self.min_group_size {
                need_merge.push(*prefix);
            }
        }

        // Do any merges needed (after all removals)
        while let Some(prefix) = need_merge.pop() {
            if prefix.bit_count() == 0 {
                // Not enough members in network yet; nothing we can do
                continue;
            }
            let mut group = match self.groups.remove(&prefix) {
                Some(g) => g,
                None => {
                    // we marked it twice and handled it already?
                    continue;
                }
            };
            let parent = prefix.popped();
            // Groups are disjoint, so all "compatibles" should be descendents of the new "parent"
            let compatible_prefixes: Vec<_> = self
                .groups
                .keys()
                .filter(|k| k.is_compatible(parent))
                .cloned()
                .collect();
            for p in compatible_prefixes {
                let other_group = self.groups.remove(&p).expect("has group");
                group.extend(other_group);
            }
            self.groups.insert(parent, group);
        }

        num
    }

    /// Check need_split and if true call do_split. Return the prefix matching
    /// `name` (the input prefix, if no split occurs).
    pub fn maybe_split(
        &mut self,
        prefix: Prefix,
        name: NodeName,
        attack: &mut dyn AttackStrategy,
    ) -> Prefix {
        if !self.need_split(prefix) {
            return prefix;
        }
        let (p0, p1) = self.do_split(prefix, attack);
        if p0.matches(name) {
            p0
        } else {
            assert!(p1.matches(name));
            p1
        }
    }

    /// Check whether some group needs splitting.
    pub fn need_split(&self, prefix: Prefix) -> bool {
        let group = &self.groups[&prefix];
        let prefix0 = prefix.pushed(false);
        let size_all = group.len();
        let size0 = group.iter().filter(|node| prefix0.matches(*node.0)).count();
        size0 >= self.min_new_group_size() && size_all - size0 >= self.min_new_group_size()
    }

    /// Do a split. Return prefixes of new groups.
    pub fn do_split(
        &mut self,
        prefix: Prefix,
        attack: &mut dyn AttackStrategy,
    ) -> (Prefix, Prefix) {
        let old_group = match self.groups.remove(&prefix) {
            Some(g) => g,
            None => {
                panic!("Error during split: prefix {:?} not found", prefix);
            }
        };
        let prefix0 = prefix.pushed(false);
        let prefix1 = prefix.pushed(true);
        let (group0, group1): (Group, Group) = old_group
            .into_iter()
            .partition(|node| prefix0.matches(node.0));
        for (name, data) in &group0 {
            if data.is_malicious() {
                attack.on_split(prefix, prefix0, *name, data);
            }
        }
        for (name, data) in &group1 {
            if data.is_malicious() {
                attack.on_split(prefix, prefix1, *name, data);
            }
        }
        let inserted = self.groups.insert(prefix0, group0).is_none();
        assert!(inserted);
        let inserted = self.groups.insert(prefix1, group1).is_none();
        assert!(inserted);
        (prefix0, prefix1)
    }

    /// Do a group churn event. The churn affects all members of a group specified
    /// by `prefix` except the node causing the churn, `new_node`.
    ///
    /// TODO: we could possibly make churn happen to a random group instead.
    /// The advantage is it makes it impossible for the attacker to target churn events
    /// at some group.
    ///
    /// The simulation driver chooses when
    /// to trigger this. What we do is (1) age each node by 1, (2) pick the oldest node
    /// whose age is a power of 2 (there may be none) and relocate it.
    /// On relocation, the node is returned (with its old name); the driver should
    /// create a new name and call add_node with the new name.
    pub fn churn(&mut self, prefix: Prefix, new_node: NodeName) -> Option<(NodeName, NodeData)> {
        let group = self
            .groups
            .get_mut(&prefix)
            .expect("churn called with invalid group");
        // Increment churn counters and see if any is ready to be relocated.
        let mut to_relocate: Option<(NodeName, u32)> = None;
        for (node_name, ref mut node_data) in group.iter_mut() {
            if *node_name == new_node {
                continue; // skip this node
            }
            if node_data.churn_and_can_age() {
                if to_relocate.map_or(true, |n| node_data.churns() > n.1) {
                    to_relocate = Some((*node_name, node_data.churns()));
                }
            }
        }
        let to_relocate = match to_relocate {
            Some(r) => r.0,
            None => return None,
        };

        if group.len() <= self.min_group_size {
            // Relocation is blocked to prevent the group from becoming too small,
            // but we still need the node to age.
            group.get_mut(&to_relocate).expect("have node").incr_age();
            return None;
        }

        // Remove node, age and return:
        let mut node_data = group.remove(&to_relocate).expect("have node");
        node_data.incr_age();
        trace!(
            "Relocating a node with age {} and churns {}",
            node_data.age(),
            node_data.churns()
        );
        Some((to_relocate, node_data))
    }

    fn min_new_group_size(&self) -> usize {
        // mirrors RoutingTable
        self.min_group_size + 1
    }
}
