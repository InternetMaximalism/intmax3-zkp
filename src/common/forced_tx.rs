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
        inputs.extend(self.user_id.to_vec());
        inputs.extend(self.tx_hash.to_vec());
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }
}
