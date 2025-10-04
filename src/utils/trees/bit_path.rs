use serde::{Deserialize, Serialize};

/// `BitPath` represents a path in a binary tree as a sequence of bits.
///
/// It efficiently stores the path using:
/// - `length`: The number of bits in the path (max 64)
/// - `value`: A u64 where each bit represents a direction in the tree (0 for left, 1 for right)
///
/// This is commonly used in Merkle trees to represent paths from the root to leaves.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BitPath {
    length: u32,
    value: u64,
}

impl BitPath {
    pub fn new(length: u32, value: u64) -> Self {
        BitPath { length, value }
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn len(&self) -> u32 {
        self.length
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn pop(&mut self) -> Option<bool> {
        if self.length == 0 {
            return None;
        }
        let bit = self.value & 1;
        self.value >>= 1;
        self.length -= 1;
        Some(bit == 1)
    }

    pub fn sibling(&self) -> Self {
        // flip the last bit
        let mut path = *self;
        path.value ^= 1;
        path
    }
}
