// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

// Calculations to do with security of routing system

extern crate rand;
extern crate rustc_serialize;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rayon;

mod args;
mod attack;
mod net;
mod node;
mod prob;
mod quorum;
mod tools;

use std::cmp::max;

use rayon::par_iter::collect::collect_into;
use rayon::prelude::*;

use args::{ArgProc, RelOrAbs, SimParams};

// We could use templating but there's no reason not to do the easy thing and
// fix types.

pub type NN = u64;
pub type RR = f64;

pub const PARAM_TITLES: [&'static str; 10] = [
    "NInitial",
    "NAttack",
    "MaxJoin",
    "BackJoin",
    "PLeave",
    "MinGroup",
    "QuorumProp",
    "MaxSteps",
    "P(disruption)",
    "P(compromise)",
];
pub struct ToolArgs {
    // number initial
    num_initial: NN,
    // number malicious added at start of attack
    num_attacking: NN,
    // maximum number joining (nodes per step)
    max_join_rate: RR,
    // background rate of new good nodes during attack (nodes per step)
    add_rate_good: RR,
    // leave rate of good nodes (probability each node leaving per step)
    leave_rate_good: RR,
    min_group_size: NN,
    quorum_prop: RR,
    max_steps: NN,
}

impl ToolArgs {
    pub fn from_params(params: &SimParams) -> Self {
        let nn = params.num_initial;
        let nm = params.num_attacking.from_base(nn as RR);

        // Step length in days:
        let step_len = params.proof_time;

        assert!(params.quorum_prop >= 0.0 && params.quorum_prop <= 1.0);

        let max_join = params.max_join.from_base(nn as RR) / step_len;
        // Convert from num/day to p/step:
        let add_good = params.add_good.from_base(nn as RR) / step_len;
        let p_leave = match params.leave_good {
            RelOrAbs::Rel(r) => r * 0.01, // number per 100
            RelOrAbs::Abs(a) => a,
        };
        let leave_good = p_leave / step_len;
        assert!(max_join > add_good);
        assert!(max_join > leave_good);
        if (nn as RR) / (max_join - leave_good) > 10000.0 {
            warn!(
                "Join rate ({} nodes/step) - leave rate ({} nodes/step) requires many steps \
                   for init (estimate: {})",
                max_join,
                leave_good,
                ((nn as RR) / (max_join - leave_good)).round() as NN
            );
        }

        ToolArgs {
            num_initial: nn,
            num_attacking: nm,
            max_join_rate: max_join,
            add_rate_good: add_good,
            leave_rate_good: leave_good,
            min_group_size: params.min_group_size,
            quorum_prop: params.quorum_prop,
            max_steps: (params.max_days / step_len).round() as NN,
        }
    }
}

fn main() {
    env_logger::init().unwrap();

    let (repetitions, param_sets) = ArgProc::make_sim_params();
    // TODO: print number of sims and/or progress

    info!(
        "Starting to simulate {} different parameter sets",
        param_sets.len()
    );
    let mut results = Vec::new();
    collect_into(
        param_sets
            .into_par_iter()
            .map(|item| item.result(repetitions)),
        &mut results,
    );

    //     tool.print_message();
    let col_widths: Vec<usize> = PARAM_TITLES.iter().map(|name| max(name.len(), 8)).collect();
    for col in 0..col_widths.len() {
        print!("{1:<0$}", col_widths[col], PARAM_TITLES[col]);
        print!(" ");
    }
    println!("");

    for (args, result) in results {
        print!("{1:<0$}", col_widths[0], args.num_initial);
        print!(" ");
        print!("{1:<0$}", col_widths[1], args.num_attacking);
        print!(" ");
        print!("{1:<0$}", col_widths[2], args.max_join_rate);
        print!(" ");
        print!("{1:<0$}", col_widths[3], args.add_rate_good);
        print!(" ");
        print!("{1:<0$}", col_widths[4], args.leave_rate_good);
        print!(" ");
        print!("{1:<0$}", col_widths[5], args.min_group_size);
        print!(" ");
        print!("{1:<.*}", col_widths[6] - 2, args.quorum_prop);
        print!(" ");
        print!("{1:<.*}", col_widths[7] - 2, args.max_steps);
        print!(" ");
        print!("{1:<.*}", col_widths[8] - 2, result.p_disrupt());
        print!(" ");
        print!("{1:<.*}", col_widths[9] - 2, result.p_compromise());
        println!("");
    }
}
