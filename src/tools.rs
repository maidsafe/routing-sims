// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

/// Drivers of the simulations / calculations
use rayon::prelude::*;

use attack::{AttackStrategy, UntargettedAttack};
use net::{Network, NoAddRestriction, RestrictOnePerAge};
use prob::{prob_compromise, prob_disruption};
use quorum::{Quorum, SimpleQuorum};
use {ToolArgs, NN, RR};

/// First value is probability of disruption, second is probability of compromise.
#[derive(Clone, Copy)]
pub struct SimResult(RR, RR);
impl SimResult {
    pub fn p_disrupt(&self) -> RR {
        self.0
    }
    pub fn p_compromise(&self) -> RR {
        self.1
    }
}

pub trait Tool {
    /// Print a message about the computation (does not include parameters).
    fn print_message(&self);

    /// Calculate the probability of compromise (range: 0 to 1).
    ///
    /// `repetitions` is how many times to repeat the simulation; this is only applicable to the
    /// full sim.
    fn calc_p_compromise(&self, repetitions: u32) -> SimResult;
}

/// Simplest tool: assumes all groups have minimum size; cannot simulate
/// targeting or ageing.
pub struct DirectCalcTool<'a> {
    args: &'a ToolArgs,
    quorum: SimpleQuorum,
}

impl<'a> DirectCalcTool<'a> {
    pub fn new(args: &'a ToolArgs) -> Self {
        let quorum = SimpleQuorum::from(args.quorum_prop);
        DirectCalcTool {
            args: args,
            quorum: quorum,
        }
    }
}

impl<'a> Tool for DirectCalcTool<'a> {
    fn print_message(&self) {
        println!(
            "Tool: calculate probability of compromise, assuming all groups have minimum \
                  size"
        );
        let any_group = true; // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self, _: u32) -> SimResult {
        let k = self.args.min_group_size;
        let q = self.quorum.quorum_size(k).expect("simple quorum size");
        let n = self.args.num_initial + self.args.num_attacking;
        let pd = prob_disruption(n, self.args.num_attacking, k, q);
        let pc = prob_compromise(n, self.args.num_attacking, k, q);

        trace!(
            "n: {}, r: {}, k: {}, q: {}, pd: {:.e}, pc: {:.e}",
            n,
            self.args.num_attacking,
            k,
            q,
            pd,
            pc
        );

        let n_groups = (n as RR) / (self.args.min_group_size as RR);
        SimResult(
            1.0 - (1.0 - pd).powf(n_groups),
            1.0 - (1.0 - pc).powf(n_groups),
        )
    }
}

/// A tool which simulates the group structure (division of nodes in the
/// network between groups), then does direct calculations based on these
/// groups. This should be more accurate than DirectCalcTool in "any group"
/// mode, but has the same limitations.
///
/// Does not relocate nodes (node ageing).
pub struct SimStructureTool<'a> {
    args: &'a ToolArgs,
    quorum: SimpleQuorum,
}

impl<'a> SimStructureTool<'a> {
    pub fn new(args: &'a ToolArgs) -> Self {
        let quorum = SimpleQuorum::from(args.quorum_prop);
        SimStructureTool {
            args: args,
            quorum: quorum,
        }
    }
}

impl<'a> Tool for SimStructureTool<'a> {
    fn print_message(&self) {
        println!(
            "Tool: simulate allocation of nodes to groups; each has size at least the \
                  specified minimum size"
        );
        let any_group = true; // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self, _: u32) -> SimResult {
        // We need an "attack" strategy, though we only support one here
        let mut attack = UntargettedAttack {};

        // Create a network of good nodes (this tool assumes all nodes are good in the sim then
        // assumes some are bad in subsequent calculations).
        let mut net = Network::new(self.args.min_group_size as usize);
        // Yes, *attacking* nodes are *good* for this network initialisation!
        net.add_avail(self.args.num_initial + self.args.num_attacking, 0);
        while net.has_avail() {
            net.do_step::<NoAddRestriction>(&self.args, &mut attack);
        }
        // The above got all available nodes ready for insert, but the last step will have left
        // some pending insert, so do one more step. Note that we can't wait until the queues are
        // empty because background-leaving may result in a constant churn.
        net.do_step::<NoAddRestriction>(&self.args, &mut attack);

        // This isn't quite right, since one group not compromised does
        // tell you _something_ about the distribution of malicious nodes,
        // thus probabilities are not indepedent. But unless there are a lot
        // of malicious nodes it should be close.
        let mut p_no_disruption = 1.0;
        let mut p_no_compromise = 1.0;
        for (_, group) in net.groups() {
            let k = group.len() as NN;
            let q = self.quorum.quorum_size(k).expect("simple quorum size");
            let n = self.args.num_initial + self.args.num_attacking;
            let pd = prob_disruption(n, self.args.num_attacking, k, q);
            let pc = prob_compromise(n, self.args.num_attacking, k, q);
            p_no_disruption *= 1.0 - pd;
            p_no_compromise *= 1.0 - pc;
        }
        SimResult(1.0 - p_no_disruption, 1.0 - p_no_compromise)
    }
}

/// A tool which simulates group operations.
///
/// Can relocate nodes according to the node ageing RFC (roughly).
pub struct FullSimTool<'a, Q: Quorum, A: AttackStrategy + Clone> {
    args: &'a ToolArgs,
    quorum: Q,
    attack: A,
}

impl<'a, Q: Quorum, A: AttackStrategy + Clone> FullSimTool<'a, Q, A> {
    pub fn new(args: &'a ToolArgs, mut quorum: Q, strategy: A) -> Self {
        quorum.set_quorum_proportion(args.quorum_prop);
        FullSimTool {
            args: args,
            quorum: quorum,
            attack: strategy,
        }
    }

    // Run a simulation. Result has either 0 or 1 in each field, `(any_disruption, any_compromise)`.
    fn run_sim(&self) -> SimResult {
        info!("Starting sim");
        let mut attack = self.attack.clone();

        // 1. Create an initial network of good nodes.
        let mut net = Network::new(self.args.min_group_size as usize);
        net.add_avail(self.args.num_initial, 0);
        while net.has_avail() {
            net.do_step::<RestrictOnePerAge>(&self.args, &mut attack);
        }
        // The above got all available nodes ready for insert, but the last step will have left
        // some pending insert, so do one more step. Note that we can't wait until the queues are
        // empty because background-leaving may result in a constant churn.
        net.do_step::<RestrictOnePerAge>(&self.args, &mut attack);

        // 2. Start attack
        // In this model, malicious nodes are added once while good nodes can be added
        // continuously.
        net.add_avail(0, self.args.num_attacking);
        let mut to_add_good = 0.0;

        let mut disruption = false;

        for _ in 0..self.args.max_steps {
            to_add_good += self.args.add_rate_good;
            let n_new = to_add_good.floor();
            net.add_avail(n_new as NN, 0);
            to_add_good -= n_new;

            net.do_step::<RestrictOnePerAge>(&self.args, &mut attack);

            // Finally, we check if disruption or compromise occurred:
            for (_, ref group) in net.groups() {
                if self.quorum.quorum_compromised(group) {
                    // Compromise implies disruption!
                    return SimResult(1.0, 1.0);
                } else if self.quorum.quorum_disrupted(group) {
                    disruption = true;
                }
            }
        }

        // If we didn't return already, no compromise occurred, but disruption may have
        SimResult(if disruption { 1.0 } else { 0.0 }, 0.0)
    }
}

impl<'a, Q: Quorum, A: AttackStrategy + Clone> Tool for FullSimTool<'a, Q, A>
where
    Q: Sync,
    A: Sync,
{
    fn print_message(&self) {
        println!("Tool: simulate group operations");
        let any_group = true; // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self, repetitions: u32) -> SimResult {
        let result = (0..repetitions)
            .into_par_iter()
            .map(|_| self.run_sim())
            .reduce(
                || SimResult(0.0, 0.0),
                |v1, v2| SimResult(v1.0 + v2.0, v1.1 + v2.1),
            );

        let denom = repetitions as RR;
        SimResult(result.0 / denom, result.1 / denom)
    }
}
