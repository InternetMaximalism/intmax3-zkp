pub mod insertion;
pub mod leaf;

use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::u256::U256,
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::{
            error::IndexedMerkleTreeError,
            incremental_merkle_tree::{
                IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
            },
        },
    },
};
use leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget};

#[derive(Debug, Clone, Serialize)]
pub struct IndexedMerkleTree(IncrementalMerkleTree<IndexedMerkleLeaf>);

/// UTILS-01 (follow-up review 2026-10-17): `new` always installs the sentinel
/// `IndexedMerkleLeaf::default()` at index 0, and `low_index` / `insert` rely on it. The derived
/// decoder accepted `{"height":2,"leaves":[]}`, a tree no constructor can produce. Require the
/// sentinel after decoding (the inner tree's decoder already bounds height and leaf count).
impl<'de> Deserialize<'de> for IndexedMerkleTree {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let inner = IncrementalMerkleTree::<IndexedMerkleLeaf>::deserialize(deserializer)?;
        if inner.leaves().first() != Some(&IndexedMerkleLeaf::default()) {
            return Err(serde::de::Error::custom(
                "indexed Merkle tree must start with the sentinel leaf at index 0",
            ));
        }
        Ok(Self(inner))
    }
}
pub type IndexedMerkleProof = IncrementalMerkleProof<IndexedMerkleLeaf>;
pub type IndexedMerkleProofTarget = IncrementalMerkleProofTarget<IndexedMerkleLeafTarget>;

impl IndexedMerkleTree {
    pub fn new(height: usize) -> Self {
        let mut tree = IncrementalMerkleTree::<IndexedMerkleLeaf>::new(height);
        tree.push(IndexedMerkleLeaf::default());
        Self(tree)
    }

    pub fn get_root(&self) -> PoseidonHashOut {
        self.0.get_root()
    }

    pub fn get_leaf(&self, index: u64) -> IndexedMerkleLeaf {
        self.0.get_leaf(index)
    }

    pub fn prove(&self, index: u64) -> IndexedMerkleProof {
        self.0.prove(index)
    }

    pub(crate) fn low_index(&self, key: U256) -> Result<u64, IndexedMerkleTreeError> {
        let low_leaf_candidates = self
            .0
            .leaves()
            .into_iter()
            .enumerate()
            .filter(|(_, leaf)| {
                (leaf.key < key) && (key < leaf.next_key || leaf.next_key == U256::default())
            })
            .collect::<Vec<_>>();
        if low_leaf_candidates.is_empty() {
            return Err(IndexedMerkleTreeError::KeyAlreadyExists(key.to_string()));
        }
        if low_leaf_candidates.len() != 1 {
            return Err(IndexedMerkleTreeError::TooManyCandidates(
                "low_index".to_string(),
            ));
        }
        let (low_leaf_index, _) = low_leaf_candidates[0];
        Ok(low_leaf_index as u64)
    }

    pub fn index(&self, key: U256) -> Option<u64> {
        let leaf_candidates = self
            .0
            .leaves()
            .into_iter()
            .enumerate()
            .filter(|(_, leaf)| leaf.key == key)
            .collect::<Vec<_>>();
        if leaf_candidates.is_empty() {
            return None;
        }
        if leaf_candidates.len() != 1 {
            panic!("find_index: too many candidates");
        }
        let (leaf_index, _) = leaf_candidates[0];
        Some(leaf_index as u64)
    }

    pub fn key(&self, index: u64) -> U256 {
        self.0.get_leaf(index).key
    }

    pub fn update(&mut self, key: U256, value: u64) -> Result<(), IndexedMerkleTreeError> {
        let index = self
            .index(key)
            .ok_or_else(|| IndexedMerkleTreeError::KeyDoesNotExist(key.to_string()))?;
        let mut leaf = self.0.get_leaf(index);
        leaf.value = value;
        self.0.update(index, leaf);
        Ok(())
    }

    pub fn leaves(&self) -> Vec<IndexedMerkleLeaf> {
        self.0.leaves()
    }

    pub fn len(&self) -> usize {
        self.leaves().len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves().is_empty()
    }
}
