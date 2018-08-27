// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Argument processing

use std::str::FromStr;
use std::fmt::Debug;
use std::ops::AddAssign;
use std::cmp::Ordering;
use std::process;

use {ToolArgs, NN, RR};
use tools::{Tool, DirectCalcTool, SimStructureTool, FullSimTool, SimResult};
use quorum::{SimpleQuorum, AgeQuorum};
use attack::{UntargettedAttack, SimpleTargettedAttack};


pub trait DefaultStep<T> {
    // Return a default step.
    //
    // The value `x` is passed so that RelOrAbs can see whether it's being
    // used in relative or absolute form.
    fn default_step(x: T) -> T;
}

impl DefaultStep<NN> for NN {
    fn default_step(_: NN) -> NN {
        1
    }
}

impl DefaultStep<RR> for RR {
    fn default_step(_: RR) -> RR {
        1.0
    }
}

pub enum SamplePoints<T> {
    Range(T, T, Option<T>), // start, stop, optional step
    List(Vec<T>),
    Number(T),
}

impl<T: Copy + Debug + AddAssign + PartialOrd<T> + DefaultStep<T>> SamplePoints<T> {
    fn iter(&self) -> SamplePointsIterator<T> {
        SamplePointsIterator {
            iterable: self,
            i: 0,
            prev: None,
        }
    }
}

impl<T: FromStr> FromStr for SamplePoints<T>
    where <T as FromStr>::Err: Debug
{
    type Err = ();  // we just panic!
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            // We have a range; check for a step:
            let (first, step) = if s.contains(':') {
                let mut parts = s.split(':');
                let first = parts.next().expect("split half");
                let second = parts.next().expect("split half");
                if parts.next() != None {
                    panic!("expected 'start-stop:step', found {}", s);
                }
                (first, Some(second.parse().expect("parse")))
            } else {
                (s, None)
            };
            let mut parts = first.split('-');
            let start = parts.next().expect("split half").parse().expect("parse");
            let stop = match parts.next() {
                    Some(part) => part,
                    None => panic!("expected 'start-stop:step', found {}", s),
                }
                .parse()
                .expect("parse");
            if parts.next() != None {
                panic!("expected 'start-stop:step', found {}", s);
            }
            Ok(SamplePoints::Range(start, stop, step))
        } else if s.contains(',') {
            // We have a list
            let parts = s.split(',');
            Ok(SamplePoints::List(parts.map(|p| p.parse().expect("parse")).collect()))
        } else {
            // Presumably we have a single number
            Ok(SamplePoints::Number(s.parse().expect("parse")))
        }
    }
}

struct SamplePointsIterator<'a, T: Copy + Debug + AddAssign + PartialOrd<T> + DefaultStep<T> + 'a> {
    iterable: &'a SamplePoints<T>,
    i: usize,
    prev: Option<T>,
}

impl<'a, T: Copy + Debug + AddAssign + PartialOrd<T> + DefaultStep<T> + 'a> Iterator
        for SamplePointsIterator<'a, T>
{
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        let i = self.i;
        match self.iterable {
            &SamplePoints::Range(start, stop, step) => {
                match self.prev {
                    None => {
                        self.prev = Some(start);
                        self.prev
                    },
                    Some(mut x) => {
                        let step = step.unwrap_or(T::default_step(start));
                        x += step;
                        self.prev = Some(x);
                        if x > stop {
                            None
                        } else {
                            Some(x)
                        }
                    },
                }
            },
            &SamplePoints::List(ref v) => {
                if i >= v.len() {
                    None
                } else {
                    self.i = i + 1;
                    Some(v[i])
                }
            },
            &SamplePoints::Number(n) => {
                if i > 0 {
                    None
                } else {
                    self.i = 1;
                    Some(n)
                }
            },
        }
    }
}

pub struct ArgProc {}

impl ArgProc {
    /// Return (repetitions, vec[sim params])
    pub fn make_sim_params() -> (u32, Vec<SimParams>) {
        let matches = clap_app!(routing_sims =>
            (version: "0.1")
            (about: "Calculates vulnerabilities of networks via simulation.\
                    \n\n\
                    Note that all RANGEs can be specified as simple number (1), \
                    a range (15-20) or range-with-step (100-200:20), and some can \
                    be specified as percentages (e.g. 10% or 10%-20%:5%).\
                    \n\n\
                    All times are specified in days and may be fractional. Step length is \
                    determined automatically.")
            (@arg about: -A --about "Print a more detailed message about the simulation and exit. \
                    This describes assumptions made in the simulation.")
            (@arg tool: -t --tool [TOOL] "Available tools are 'calc' (direct calculation, \
                    assuming all groups have minimum size, no ageing or targetting), \
                    'structure' (simulate group structure, then calculate), \
                    'full' (default option: simulate attacks). \
                    Run with --tool=TOOL --about for more details.")
            (@arg nodes: -n --nodes [RANGE] "Initial number of nodes (all uncompromised).")
            (@arg attacking: -a --attacking [RANGE] "Number of malicious nodes added in attack. \
                    Either an absolute number (e.g. 50) or a percentage of the number of initial \
                    nodes.")
            (@arg maxjoin: -j --maxjoin [RANGE] "Maximum rate at which new nodes join the network \
                    (nodes per day); can be a percentage of initial nodes.")
            (@arg backjoin: -b --backjoin [RANGE] "Background joining rate of good nodes \
                    during an attack (nodes per day); can be a percentage of initial nodes.")
            (@arg leavegood: -l --leavegood [RANGE] "Leave rate of good nodes (chance of each \
                    node leaving each day); can be a percentage (expected number per 100 per \
                    day). Nodes which leave are replaced with new nodes to maintain the target \
                    number. Leaving happens randomly.")
            (@arg group: -g --group [RANGE] "Minimum group size, e.g. 10-20.")
            (@arg quorum: -q --quorum [RANGE] "Quorum size as a proportion of group size, \
                    e.g. 0.5-0.7:0.1.")
            (@arg prooftime: --prooftime [RANGE] "Time taken to complete resource proof (days). \
                    Default is 1.")
            (@arg maxdays: -d --maxdays [RANGE] "Maximum length of an attack before giving up \
                    (days).")
            (@arg repetitions: -p --repetitions [NUM] "Number of times to repeat a true/false \
                    simulation to calculate an attack success probability.")
            (@arg quorum_alg: -Q --quorumalg "Quorum algorithm: 'simple' group proportion, \
                    'age' (age and group proportions), 'all' (run both)")
            (@arg strategy: -S --strategy "Attack targetting strategy: 'none', \
                    'simple' (naive) targetting, 'all'")
        )
            .get_matches();

        // Create initial parameter set
        let tool = match matches.value_of("tool").unwrap_or("full") {
            "calc" => SimType::DirectCalc,
            "structure" => SimType::Structure,
            "full" => SimType::FullSim,
            _ => panic!("unexpected tool"),
        };

        if matches.is_present("about") {
            println!("About tool {}:", tool.name());
            println!("");
            match tool {
                SimType::DirectCalc => {
                    println!("\
This is the simplest tool: it assumes that all groups have minimum size and
cannot simulate targeting or ageing. It does not simulate a network but
directly calculates the outcome (much faster and more precise, but limited and
may not be accurate to all assumptions).");
                }
                SimType::Structure => {
                    println!("\
This is a compromise between direct calculation and network simulations: it
simulates an initial network, then calculates the probabilities of disruction
and of compromise assuming random distribution of malicious nodes within this
network. This makes less assumptions about network behaviour than the direct
calculation method while still being fairly fast.

The simulation is divided into steps based on the proof time. All nodes are
added to the set of available nodes, and at each step some of these are added
to the network limited to the maximum join rate (--maxjoin parameter).
Additionally, if the leave rate is non-zero, each node has a chance of leaving,
in which case a replacement is added to the queue of available nodes waiting
to be added to the network.

The simulation does not, in effect, use node ageing: node ages get incremented,
but no add restrictions apply and age-based quorum cannot be used. It does
move nodes based on age, however the result should not be any different than
a few more nodes leaving and rejoining.

Results may be over-precise since they do not take network variances into
account.");
                }
                SimType::FullSim => {
                    println!("\
Simulations network creation and an attack in two phases.

The simulation is divided into two phases: firstly an initial network of good
(uncompromised) nodes is created, then malicious nodes are added. During the
first phase, the number of available nodes to be added to the network is fixed
(--nodes parameter), and all available nodes are good. At the start of the
second phase, all attacking (malicious) nodes are added to the set of available
nodes (--attacking parameter), and optionally good nodes are added to the set
each step (--backjoin parameter).

Step length is set based on the proof time. Each step nodes from the set of
available nodes are added to the network, limited by the maximum join rate.
When both malicious and good nodes are available, nodes are selected randomly
according to their ratios. If the leave rate is non-zero, each good node has a
chance of being removed (malicious nodes are assumed not to leave; all nodes
which leave are replaced by a new node in the set of available nodes).

All added nodes are delayed one step to account for proof of work time; when
actually added, a churn operation happens, which may age and move an existing
node in the target group. Malicious nodes are told their new name and group
before completing proof-of-work and may reset immediately; this is done by
removing them and adding another node to the set of available nodes (note that
the max join rate limits how many resets it is useful to do).

The simulation runs until a time limit is reached (--maxdays parameter) unless
a group is compromised before this limit. Many simulations are run
(--repetitions parameter) to calculate probabilities of compromise and
disruption.

Assumption: all nodes (malicious or not) have the same performance and take the
same time to complete proof-of-work.
                    ");
                }
            }
            process::exit(0);
        }

        let nodes_range: SamplePoints<NN> = matches.value_of("nodes")
            .map_or(SamplePoints::Number(1000), |s| s.parse().expect("parse"));
        let mut nodes_iter = nodes_range.iter();

        let at_nodes_range: SamplePoints<RelOrAbs<NN>> = matches.value_of("attacking")
            .map_or(SamplePoints::Number(RelOrAbs::Rel(0.1)),
                    |s| s.parse().expect("parse"));
        let mut at_nodes_iter = at_nodes_range.iter();

        let max_join_range: SamplePoints<RelOrAbs<RR>> = matches.value_of("maxjoin")
            .map_or(SamplePoints::Number(RelOrAbs::Rel(0.02)),
                    |s| s.parse().expect("parse"));
        let mut max_join_iter = max_join_range.iter();

        let add_good_range: SamplePoints<RelOrAbs<RR>> = matches.value_of("backjoin")
            .map_or(SamplePoints::Number(RelOrAbs::Rel(0.001)),
                    |s| s.parse().expect("parse"));
        let mut add_good_iter = add_good_range.iter();

        let leave_good_range: SamplePoints<RelOrAbs<RR>> = matches.value_of("leavegood")
            .map_or(SamplePoints::Number(RelOrAbs::Rel(0.001)),
                    |s| s.parse().expect("parse"));
        let mut leave_good_iter = leave_good_range.iter();

        let group_size_range: SamplePoints<NN> = matches.value_of("group")
            .map_or(SamplePoints::Number(10), |s| s.parse().expect("parse"));
        let mut group_size_iter = group_size_range.iter();

        let quorum_range = matches.value_of("quorum")
            .map_or(SamplePoints::Number(0.5), |s| s.parse().expect("parse"));
        let mut quorum_iter = quorum_range.iter();

        let proof_time_range: SamplePoints<RR> = matches.value_of("prooftime")
            .map_or(SamplePoints::Number(1.0), |s| s.parse().expect("parse"));
        let mut proof_time_iter = proof_time_range.iter();

        let max_days_range: SamplePoints<RR> = matches.value_of("maxdays")
            .map_or(SamplePoints::Number(100.0), |s| s.parse().expect("parse"));
        let mut max_days_iter = max_days_range.iter();

        let q_use_age = match matches.value_of("quorum_alg") {
            None => vec![false],
            Some("simple") => vec![false],
            Some("age") => vec![true],
            Some("all") => vec![false, true],
            Some(x) => panic!("unexpected: -Q {}", x),
        };
        let mut q_use_age_iter = q_use_age.iter();

        let at_type = match matches.value_of("strategy") {
            None => vec![AttackType::Untargetted],
            Some("none") => vec![AttackType::Untargetted],
            Some("simple") => vec![AttackType::SimpleTargetted],
            Some("all") => vec![AttackType::Untargetted, AttackType::SimpleTargetted],
            Some(x) => panic!("unexpected: -T {}", x),
        };
        let mut at_type_iter = at_type.iter();

        let mut v = vec![SimParams {
                             sim_type: tool,
                             num_initial: nodes_iter.next().expect("first iter item"),
                             num_attacking: at_nodes_iter.next().expect("first iter item"),
                             max_join: max_join_iter.next().expect("first iter item"),
                             add_good: add_good_iter.next().expect("first iter item"),
                             leave_good: leave_good_iter.next().expect("first iter item"),
                             min_group_size: group_size_iter.next().expect("first iter item"),
                             quorum_prop: quorum_iter.next().expect("first iter item"),
                             proof_time: proof_time_iter.next().expect("first iter item"),
                             max_days: max_days_iter.next().expect("first iter item"),
                             age_quorum: *q_use_age_iter.next().expect("first iter item"),
                             targetting: *at_type_iter.next().expect("first iter item"),
                         }];

        // TODO: check we're not going to cause out-of-memory here!

        // Replicate for all network sizes (num nodes)
        let range = 0..v.len();
        for n in nodes_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.num_initial = n;
                v.push(s);
            }
        }

        // Replicate for all numbers of malicious nodes
        let range = 0..v.len();
        for r in at_nodes_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.num_attacking = r;
                v.push(s);
            }
        }

        // Replicate for all join rates of good nodes
        let range = 0..v.len();
        for x in max_join_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.max_join = x;
                v.push(s);
            }
        }

        // Replicate for all leave rates of good nodes
        let range = 0..v.len();
        for x in add_good_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.add_good = x;
                v.push(s);
            }
        }

        // Replicate for all leave rates of good nodes
        let range = 0..v.len();
        for x in leave_good_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.leave_good = x;
                v.push(s);
            }
        }

        // Replicate for all group sizes
        let range = 0..v.len();
        for g in group_size_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.min_group_size = g;
                v.push(s);
            }
        }

        // Replicate for all quorum sizes
        let range = 0..v.len();
        for q in quorum_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.quorum_prop = q;
                v.push(s);
            }
        }

        // Replicate for all proof-of-work times
        let range = 0..v.len();
        for x in proof_time_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.proof_time = x;
                v.push(s);
            }
        }

        // Replicate for all max days
        let range = 0..v.len();
        for x in max_days_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.max_days = x;
                v.push(s);
            }
        }

        // Replicate for all quorum types
        let range = 0..v.len();
        for q in q_use_age_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.age_quorum = *q;
                v.push(s);
            }
        }

        // Replicate for all attack strategies
        let range = 0..v.len();
        for at in at_type_iter {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.targetting = *at;
                v.push(s);
            }
        }

        let repetitions = matches.value_of("repetitions")
            .map(|s| s.parse().expect("parse"))
            .unwrap_or(100);
        (repetitions, v)
    }
}

#[derive(Clone, Copy)]
pub enum SimType {
    DirectCalc,
    Structure,
    FullSim,
}

impl SimType {
    pub fn name(self) -> &'static str {
        match self {
            SimType::DirectCalc => "dir_calc",
            SimType::Structure => "structure",
            SimType::FullSim => "full_sim",
        }
    }
}

#[derive(Clone, Copy)]

pub enum AttackType {
    Untargetted,
    SimpleTargetted,
}

impl AttackType {
    pub fn name(&self) -> &'static str {
        match self {
            &AttackType::Untargetted => "untarg.",
            &AttackType::SimpleTargetted => "simp_targ",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RelOrAbs<T> {
    Rel(RR),
    Abs(T),
}

impl RelOrAbs<NN> {
    pub fn from_base(self, base: RR) -> NN {
        match self {
            RelOrAbs::Rel(r) => (base * r).round() as NN,
            RelOrAbs::Abs(n) => n,
        }
    }
}

impl RelOrAbs<RR> {
    pub fn from_base(self, base: RR) -> RR {
        match self {
            RelOrAbs::Rel(r) => base * r,
            RelOrAbs::Abs(n) => n,
        }
    }
}

impl<T: FromStr> FromStr for RelOrAbs<T>
    where <T as FromStr>::Err: Debug
{
    type Err = ();  // we just panic!
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with('%') {
            let mut s = s.to_string();
            let _ = s.pop();
            let perc = s.parse::<RR>().expect("parse");
            Ok(RelOrAbs::Rel(perc * 0.01))
        } else {
            Ok(RelOrAbs::Abs(s.parse().expect("parse")))
        }
    }
}

impl<T: AddAssign + Copy> AddAssign for RelOrAbs<T> {
    fn add_assign(&mut self, rhs: RelOrAbs<T>) {
        match (self, rhs) {
            (&mut RelOrAbs::Rel(ref mut x), RelOrAbs::Rel(y)) => *x += y,
            (&mut RelOrAbs::Abs(ref mut x), RelOrAbs::Abs(y)) => *x += y,
            _ => panic!("wrong rel/abs type!"),
        }
    }
}

impl<T: PartialOrd<T> + Copy> PartialOrd<RelOrAbs<T>> for RelOrAbs<T> {
    fn partial_cmp(&self, rhs: &RelOrAbs<T>) -> Option<Ordering> {
        match (self, rhs) {
            (&RelOrAbs::Rel(x), &RelOrAbs::Rel(ref y)) => x.partial_cmp(y),
            (&RelOrAbs::Abs(x), &RelOrAbs::Abs(ref y)) => x.partial_cmp(y),
            _ => panic!("wrong rel/abs type!"),
        }
    }
}

impl<T: From<u32>> DefaultStep<RelOrAbs<T>> for RelOrAbs<T> {
    fn default_step(x: RelOrAbs<T>) -> RelOrAbs<T> {
        match x {
            RelOrAbs::Rel(_) => RelOrAbs::Rel(0.1),
            RelOrAbs::Abs(_) => RelOrAbs::Abs(1.into()),
        }
    }
}

#[derive(Clone)]
pub struct SimParams {
    pub sim_type: SimType,
    pub age_quorum: bool,
    pub targetting: AttackType,
    pub num_initial: NN,
    pub num_attacking: RelOrAbs<NN>,
    pub max_join: RelOrAbs<RR>,
    pub add_good: RelOrAbs<RR>,
    pub leave_good: RelOrAbs<RR>,
    pub min_group_size: NN,
    pub quorum_prop: RR,
    pub proof_time: RR,
    pub max_days: RR,
}

impl SimParams {
    pub fn result(&self, repetitions: u32) -> (ToolArgs, SimResult) {
        let args = ToolArgs::from_params(self);

        let result = {
            let tool: Box<Tool> = match self.sim_type {
                SimType::DirectCalc => Box::new(DirectCalcTool::new(&args)),
                SimType::Structure => Box::new(SimStructureTool::new(&args)),
                SimType::FullSim => {
                    // note: FullSimTool is templated on quorum and attack strategy parameters, so
                    // we need to create the whole thing at once (not create parameters first)
                    match (self.age_quorum, self.targetting) {
                        (false, AttackType::Untargetted) => {
                            Box::new(FullSimTool::new(&args,
                                                      SimpleQuorum::new(),
                                                      UntargettedAttack {}))
                        }
                        (true, AttackType::Untargetted) => {
                            Box::new(FullSimTool::new(&args,
                                                      AgeQuorum::new(),
                                                      UntargettedAttack {}))
                        }
                        (false, AttackType::SimpleTargetted) => {
                            Box::new(FullSimTool::new(&args,
                                                      SimpleQuorum::new(),
                                                      SimpleTargettedAttack::new()))
                        }
                        (true, AttackType::SimpleTargetted) => {
                            Box::new(FullSimTool::new(&args,
                                                      AgeQuorum::new(),
                                                      SimpleTargettedAttack::new()))
                        }
                    }
                }
            };
            tool.calc_p_compromise(repetitions)
        };
        (args, result)
    }
}
