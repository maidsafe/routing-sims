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
use super::{SimTool, NN, RR};


const USAGE: &'static str = "
Probability computation tool.

Usage:
    proofs [-h | --help]
    proofs [-n NUM] [-r VAL] [-k RANGE] [-q RANGE] [-a]

Options:
    -h --help   Show this message
    -n NUM      Number of nodes, total.
    -r VAL      Either number of compromised nodes (e.g. 50) or percentage (default is 10%).
    -k RANGE    Group size, e.g. 10-20.
    -q RANGE    Quorum size, e.g. 5-20.
    -a          Show probabilities of any group being compromised instead of a specific group
";

#[derive(RustcDecodable)]
struct Args {
    flag_n: Option<NN>,
    flag_r: Option<String>,
    flag_k: Option<String>,
    flag_q: Option<String>,
    flag_a: bool,
}

// Process args, apply to tool, and return k, q ranges.
pub fn apply_args(tool: &mut SimTool) -> ((NN, NN), (NN, NN)) {
    let args: Args = Docopt::new(USAGE)
        .and_then(|dopt| dopt.decode())
        .unwrap_or_else(|e| e.exit());

    if let Some(n) = args.flag_n {
        tool.set_total_nodes(n);
    }

    if let Some(mut s) = args.flag_r {
        if s.ends_with('%') {
            let _ = s.pop();
            let prop = s.parse::<RR>().expect("In '-r x%', x should be a real number");
            let n = tool.total_nodes() as RR;
            tool.set_malicious_nodes((n * prop) as NN);
        } else {
            s.parse::<NN>().expect("In '-r N', N should be a whole number or percentage");
        }
    } else {
        let n = tool.total_nodes() as RR;
        tool.set_malicious_nodes((n * 0.1) as NN);
    };

    tool.set_any(args.flag_a);

    // Group size and quorum have ranges:
    fn parse_range(s: &str) -> (NN, NN) {
        const ERR: &'static str = "In a range, syntax should be 'x-y' where x and y are whole \
                                 numbers";
        let i = s.find('-').expect(ERR);
        let lb = s[0..i].parse::<NN>().expect(ERR);
        let ub = s[i + 1..s.len()].parse::<NN>().expect(ERR);
        (lb, ub)
    }
    let k = args.flag_k.map_or((8, 12), |s| parse_range(&s));
    let q = args.flag_q.map_or((5, 12), |s| parse_range(&s));
    (k, q)
}
