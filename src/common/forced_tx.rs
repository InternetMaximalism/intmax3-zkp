use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    common::user_id::{UserId, UserIdTarget},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
};

/// A forced transaction: an Intmax tx hash inserted by on-chain logic,
/// bypassing the normal SPHINCS+ signature requirement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForcedTx {
    /// The target user whose account tree will be updated.
    pub user_id: UserId,

    /// The transaction hash returned by the logic contract's insertIntmaxTx().
    /// Used as tx_tree_root in the SendLeaf.
    pub tx_hash: Bytes32,
}

impl Default for ForcedTx {
    fn default() -> Self {
        Self {
            user_id: UserId::dummy(),
            tx_hash: Bytes32::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForcedTxTarget {
    pub user_id: UserIdTarget,
    pub tx_hash: Bytes32Target,
}

impl ForcedTx {
    /// Compute keccak hash chain: keccak256(prev_hash || user_id || tx_hash)
    /// Matches the Solidity accumulator computation in queueForcedTx().
    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Bytes32 {
        let inputs: Vec<u32> = [
            prev_hash.to_u32_vec(),
            self.user_id.to_u32_vec(),
            self.tx_hash.to_u32_vec(),
        ]
        .concat();
        Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hashing result invalid")
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        [self.user_id.to_u64_vec(), self.tx_hash.to_u64_vec()].concat()
    }
}

impl ForcedTxTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            user_id: UserIdTarget::new(builder, is_checked),
            tx_hash: Bytes32Target::new(builder, is_checked),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &ForcedTx,
    ) -> Self {
        Self {
            user_id: UserIdTarget::constant(builder, value.user_id),
            tx_hash: Bytes32Target::constant(builder, value.tx_hash),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &ForcedTx) {
        self.user_id.set_witness(witness, value.user_id);
        self.tx_hash.set_witness(witness, value.tx_hash);
    }

    /// Compute keccak hash chain in-circuit: keccak256(prev_hash || user_id || tx_hash)
    ///
    /// Must match the Rust-side ForcedTx::hash_with_prev_hash computation.
    /// Both use u32-packed layout: prev_hash(8×u32) || user_id(2×u32) || tx_hash(8×u32).
    pub fn hash_with_prev_hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_hash: Bytes32Target,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut inputs: Vec<Target> = prev_hash.to_vec();
        // Use to_u32_vec to match the Rust-side to_u32_vec() layout (2 u32s: high, low)
        inputs.extend(self.user_id.to_u32_vec(builder));
        inputs.extend(self.tx_hash.to_vec());
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::user_id::UserId,
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_forced_tx_default() {
        let ftx = ForcedTx::default();
        assert_eq!(ftx.user_id, UserId::dummy());
        assert_eq!(ftx.tx_hash, Bytes32::default());
    }

    #[test]
    fn test_forced_tx_hash_with_prev_hash_deterministic() {
        let user_id = UserId::new(1, 42).unwrap();
        let mut rng = StdRng::seed_from_u64(123);
        let tx_hash = Bytes32::rand(&mut rng);
        let prev_hash = Bytes32::default();

        let ftx = ForcedTx { user_id, tx_hash };
        let h1 = ftx.hash_with_prev_hash(prev_hash);
        let h2 = ftx.hash_with_prev_hash(prev_hash);
        assert_eq!(h1, h2, "hash should be deterministic");
    }

    #[test]
    fn test_forced_tx_hash_chain() {
        let mut rng = StdRng::seed_from_u64(456);
        let ftx1 = ForcedTx {
            user_id: UserId::new(1, 10).unwrap(),
            tx_hash: Bytes32::rand(&mut rng),
        };
        let ftx2 = ForcedTx {
            user_id: UserId::new(2, 20).unwrap(),
            tx_hash: Bytes32::rand(&mut rng),
        };

        let chain0 = Bytes32::default();
        let chain1 = ftx1.hash_with_prev_hash(chain0);
        let chain2 = ftx2.hash_with_prev_hash(chain1);

        // Each step should produce a different hash
        assert_ne!(chain0, chain1);
        assert_ne!(chain1, chain2);
        assert_ne!(chain0, chain2);
    }

    #[test]
    fn test_forced_tx_to_u64_vec_length() {
        let ftx = ForcedTx {
            user_id: UserId::new(1, 1).unwrap(),
            tx_hash: Bytes32::default(),
        };
        // user_id: 1 element, tx_hash: 8 elements (Bytes32 = 8 u64s)
        let vec = ftx.to_u64_vec();
        assert_eq!(vec.len(), 1 + 8);
    }

    #[test]
    fn test_forced_tx_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(789);
        let ftx = ForcedTx {
            user_id: UserId::new(5, 100).unwrap(),
            tx_hash: Bytes32::rand(&mut rng),
        };
        let json = serde_json::to_string(&ftx).unwrap();
        let deserialized: ForcedTx = serde_json::from_str(&json).unwrap();
        assert_eq!(ftx, deserialized);
    }
}
