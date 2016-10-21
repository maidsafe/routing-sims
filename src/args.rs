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

//! Argument processing

use docopt::Docopt;
use super::{Tool, NN, RR};

use std::str::FromStr;
use std::fmt::Debug;


const USAGE: &'static str = "
Probability computation tool.

Usage:
    routing-sims [-h | --help]
    routing-sims <tool> [-n NUM] [-r VAL] [-k RANGE] [-q RANGE] [-a] [-v]

Options:
    -h --help   Show this message
    -n NUM      Number of nodes, total.
    -r VAL      Either number of compromised nodes (e.g. 50) or percentage (default is 10%).
    -k RANGE    Minimum group size, e.g. 10-20.
    -q RANGE    Quorum size as a percentage with step size, e.g. 50-90:10.
    -a          Show probabilities of any group being compromised instead of a selected group
    -v          Verbose output to stderr (redirect either this or stdout to avoid confusion)
";

#[derive(RustcDecodable)]
struct Args {
    arg_tool: String,
    flag_n: Option<NN>,
    flag_r: Option<String>,
    flag_k: Option<String>,
    flag_q: Option<String>,
    flag_a: bool,
    flag_v: bool,
}

pub struct QuorumRange {
    pub range: (RR, RR),
    pub step: RR,
}

pub struct ArgProc {
    args: Args,
}
impl ArgProc {
    pub fn read_args() -> ArgProc {
        let args: Args = Docopt::new(USAGE)
            .and_then(|dopt| dopt.decode())
            .unwrap_or_else(|e| e.exit());

        ArgProc { args: args }
    }

    pub fn tool(&self) -> &str {
        &self.args.arg_tool
    }

    pub fn apply(&self, tool: &mut Tool) {
        if let Some(n) = self.args.flag_n {
            tool.set_total_nodes(n);
        }

        if let Some(mut s) = self.args.flag_r.clone() {
            if s.ends_with('%') {
                let _ = s.pop();
                let perc = s.parse::<RR>().expect("In '-r x%', x should be a real number");
                let n = tool.total_nodes() as RR;
                tool.set_malicious_nodes((n * perc / 100.0) as NN);
            } else {
                s.parse::<NN>().expect("In '-r N', N should be a whole number or percentage");
            }
        } else {
            let n = tool.total_nodes() as RR;
            tool.set_malicious_nodes((n * 0.1) as NN);
        };

        tool.set_any(self.args.flag_a);
        tool.set_verbose(self.args.flag_v);
    }

    pub fn group_size_range(&self) -> Option<(NN, NN)> {
        self.args.flag_k.as_ref().map(|s| Self::parse_range(&s))
    }

    pub fn quorum_size_range(&self) -> Option<QuorumRange> {
        let s: &str = match self.args.flag_q {
            Some(ref s) => s.as_ref(),
            None => {
                return None;
            }
        };
        let i = s.find(':').expect("Syntax should be a-b:step");
        let step = s[i + 1..].parse::<RR>().expect("step in a-b:step should be a valid number");
        let (a, b): (RR, RR) = Self::parse_range(&s[..i]);
        // Convert from percentages:
        Some(QuorumRange {
            range: (a * 0.01, b * 0.01),
            step: step * 0.01,
        })
    }

    // Group size and quorum have ranges:
    fn parse_range<T: FromStr>(s: &str) -> (T, T)
        where T::Err: Debug
    {
        const ERR: &'static str = "In a range, syntax should be 'x-y'";
        let i = s.find('-').expect(ERR);
        let lb = s[..i].parse::<T>().expect(ERR);
        let ub = s[i + 1..].parse::<T>().expect(ERR);
        (lb, ub)
    }
}
