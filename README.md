# Routing simulations

Code to simulate the security of routing Quorums under various conditions.

|Linux|Issues|
|:---:|:----:|
|[![Build Status](https://travis-ci.com/maidsafe/routing_sims.svg?branch=master)](https://travis-ci.com/maidsafe/routing_sims)|[![Stories in Ready](https://badge.waffle.io/maidsafe/routing_sims.png?label=ready&title=Ready)](https://waffle.io/maidsafe/routing_sims)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:------:|:-------:|:-------:|

## Outputs

Two probabilities are output: the probability that any group in the network is prevented from
reaching the correct result via quorum, and the probability that any group is compromised (i.e.
reaches the wrong result via quorum).

## Tools

Three tools are available, calculating the output probabilities in different ways:

1.  DirectCalcTool — this assumes every group has the minimum size given and uses probability
    theory to calculate the result.
2.  SimStructureTool — this simulates the development of a network, then uses probability
    theory to calculate the result given these group sizes. Does not simulate node ageing.
3.  FullSimTool — this simulates the development of a network (only including the non-malicious
    nodes), then simulates an attack (where only malicious nodes are added), which may or may
    not result in lost quorum and compromised quorum. The simulation is then repeated
    many times (see -p parameter) to obtain a probability. Currently this always simulates
    relocation due to node ageing, regardless of quorum used.

## Quorum

Two types of quorum are implemented:

1.  SimpleQuorum — quorum is achieved when the given proportion of nodes send a response
2.  AgeQuorum — quorum requires both the given proportion of nodes and the given proportion
    of sum of the nodes ages.

## Attack strategy

The following strategies have been implemented. This is by no means an exhaustive list of all
possible strategies!

1.  UntargettedAttack — malicious nodes never reset themselves
2.  SimpleTargettedAttack — malicious nodes choose a target group, and reset
    themselves as soon as they are not found in that group. This strategy is completely
    useless when an age-based quorum is used since malicious nodes do not get the chance to
    age!

Possible variations:

*   target, but only reset above some age to allow ageing first
*   select some nodes for ageing and do not reset these (often), while using
    another set of nodes to age these via targetting (this strategy could be mitigated
    by applying churns to a different group than added to)


## License

This SAFE Network repository is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the MaidSafe Contributor Agreement, version 1.1 ([CONTRIBUTOR]
(CONTRIBUTOR)), shall be dual licensed as above, and you agree to be bound by the terms of the
MaidSafe Contributor Agreement, version 1.1.
