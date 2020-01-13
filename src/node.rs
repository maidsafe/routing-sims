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

use std::cmp::Ordering;
use std::mem;
use std::hash::{Hash, Hasher};
use std::fmt::{self, Formatter, Binary, Debug};
use std::u64;

use rand::{thread_rng, Rng};

use NN;


/// Name type (Xorable in routing library).
trait NameT: Ord {
    /// Returns the length of the common prefix with the `other` name; e. g.
    /// the when `other = 11110000` and `self = 11111111` this is 4.
    fn common_prefix(&self, other: Self) -> usize;

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments ar equal.)
    fn cmp_distance(&self, lhs: Self, rhs: Self) -> Ordering;

    /// Returns `true` if the `i`-th bit is `1`.
    fn bit(&self, i: usize) -> bool;

    /// Returns a copy of `self`, with the `index`-th bit set to `bit`.
    ///
    /// If `index` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    fn with_bit(self, i: usize, bit: bool) -> Self;

    /// Returns a binary format string, with leading zero bits included.
    fn binary(&self) -> String;

    /// Returns a copy of self with first `n` bits preserved, and remaining bits
    /// set to 0 (val == false) or 1 (val == true).
    fn set_remaining(self, n: usize, val: bool) -> Self;
}

impl NameT for NN {
    fn common_prefix(&self, other: Self) -> usize {
        (self ^ other).leading_zeros() as usize
    }

    fn cmp_distance(&self, lhs: Self, rhs: Self) -> Ordering {
        Ord::cmp(&(lhs ^ self), &(rhs ^ self))
    }

    fn bit(&self, i: usize) -> bool {
        let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
        self & pow_i != 0
    }

    fn with_bit(mut self, i: usize, bit: bool) -> Self {
        if i >= mem::size_of::<Self>() * 8 {
            return self;
        }
        let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
        if bit {
            self |= pow_i;
        } else {
            self &= !pow_i;
        }
        self
    }

    fn binary(&self) -> String {
        format!("{1:00$b}", mem::size_of::<Self>() * 8, self)
    }

    fn set_remaining(self, n: usize, val: bool) -> Self {
        let bits = mem::size_of::<NN>() * 8;
        if n >= bits {
            self
        } else {
            let mask = !0 >> n;
            if val { self | mask } else { self & !mask }
        }
    }
}


// A group prefix, i.e. a sequence of bits specifying the part of the network's name space
// consisting of all names that start with this sequence.
#[derive(Clone, Copy, Default, Eq, Ord)]
pub struct Prefix {
    bit_count: usize,
    name: NN,
}

impl Prefix {
    /// Creates a new `Prefix` with the first `bit_count` bits of `name`.
    /// Insignificant bits are all set to 0.
    pub fn new(bit_count: usize, name: NN) -> Prefix {
        Prefix {
            bit_count: bit_count,
            name: name.set_remaining(bit_count, false),
        }
    }

    /// Returns `self` with an appended bit: `0` if `bit` is `false`, and `1` if `bit` is `true`.
    pub fn pushed(mut self, bit: bool) -> Prefix {
        self.name = self.name.with_bit(self.bit_count, bit);
        self.bit_count += 1;
        self
    }

    /// Returns a prefix copying the first `bitcount() - 1` bits from `self`,
    /// or `self` if it is already empty.
    pub fn popped(mut self) -> Prefix {
        if self.bit_count > 0 {
            self.bit_count -= 1;
            // unused bits should be zero:
            self.name = self.name.with_bit(self.bit_count, false);
        }
        self
    }

    /// Returns the number of bits in the prefix.
    pub fn bit_count(&self) -> usize {
        self.bit_count
    }

    /// Returns `true` if `self` is a prefix of `other` or vice versa.
    pub fn is_compatible(&self, other: Prefix) -> bool {
        let i = self.name.common_prefix(other.name);
        i >= self.bit_count || i >= other.bit_count
    }

    /// Returns `true` if this is a prefix of the given `name`.
    pub fn matches(&self, name: NN) -> bool {
        self.name.common_prefix(name) >= self.bit_count
    }
}

impl PartialEq<Prefix> for Prefix {
    fn eq(&self, other: &Self) -> bool {
        self.is_compatible(*other) && self.bit_count == other.bit_count
    }
}

impl PartialOrd<Prefix> for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self.is_compatible(*other) {
            None
        } else {
            Some(self.name.cmp(&other.name))
        }
    }
}

impl Hash for Prefix {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in 0..self.bit_count {
            self.name.bit(i).hash(state);
        }
    }
}

impl Binary for Prefix {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let mut binary = self.name.binary();
        binary.truncate(self.bit_count);
        write!(formatter, "Prefix({})", binary)
    }
}

impl Debug for Prefix {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Binary::fmt(self, formatter)
    }
}


/// Type of a node name
pub type NodeName = u64;

/// Generate a new node name
pub fn new_node_name() -> NodeName {
    thread_rng().gen()
}

/// Data stored for a node
#[derive(Clone, Copy)]
pub struct NodeData {
    age: u32, // initial age is 0
    churns: u32, // initial churns is 0
    is_malicious: bool,
}

impl NodeData {
    /// New data (initial age and churns, possibly malicious depending on parrameter)
    pub fn new(malicious: bool) -> Self {
        NodeData {
            age: 0,
            churns: 0,
            is_malicious: malicious,
        }
    }

    /// Get the age
    pub fn age(&self) -> u32 {
        self.age
    }

    /// Increment age by 1
    pub fn incr_age(&mut self) {
        self.age += 1;
    }

    /// Get the number of churns
    pub fn churns(&self) -> u32 {
        self.churns
    }

    // Increment churns, and return whether this is high enough for relocation
    pub fn churn_and_can_age(&mut self) -> bool {
        self.churns += 1;
        self.churns >= 2u32.pow(self.age)
    }

    /// Is this node malicous?
    pub fn is_malicious(&self) -> bool {
        self.is_malicious
    }
}

/// Type of a node
pub type Node = (NodeName, NodeData);
