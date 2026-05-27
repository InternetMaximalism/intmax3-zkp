use crate::{
    common::tx::{ChannelAction, ChannelActionTarget, TxV2, TxV2Target},
    constants::TX_TREE_HEIGHT,
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::sparse_merkle_tree::{SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree},
    },
};

pub type TxV2Tree = SparseMerkleTree<TxV2>;
pub type ChannelActionTree = SparseMerkleTree<ChannelAction>;
pub type TxV2MerkleProof = SparseMerkleProof<TxV2>;
pub type TxV2MerkleProofTarget = SparseMerkleProofTarget<TxV2Target>;
pub type ChannelActionMerkleProof = SparseMerkleProof<ChannelAction>;
pub type ChannelActionMerkleProofTarget = SparseMerkleProofTarget<ChannelActionTarget>;

impl TxV2Tree {
    pub fn init() -> Self {
        Self::new(TX_TREE_HEIGHT)
    }
}

impl ChannelActionTree {
    pub fn init() -> Self {
        Self::new(TX_TREE_HEIGHT)
    }
}

pub fn compute_channel_action_root(actions: &[ChannelAction]) -> PoseidonHashOut {
    let mut tree = ChannelActionTree::init();
    for (index, action) in actions.iter().cloned().enumerate() {
        tree.update(index as u64, action);
    }
    tree.get_root()
}

pub fn compute_tx_v2_root(txs: &[TxV2]) -> PoseidonHashOut {
    let mut tree = TxV2Tree::init();
    for (index, tx) in txs.iter().cloned().enumerate() {
        tree.update(index as u64, tx);
    }
    tree.get_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            tx::{ChannelActionKind, TxClass},
            user_id::AccountId,
        },
        ethereum_types::bytes32::Bytes32,
    };

    #[test]
    fn tx_v2_root_is_deterministic() {
        let tx = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: PoseidonHashOut::default(),
            nonce: 7,
            channel_action_root: compute_channel_action_root(&[ChannelAction {
                kind: ChannelActionKind::ChannelClose,
                source_channel_id: AccountId::new(2, 10).unwrap(),
                destination_channel_id: AccountId::dummy(),
                tx_hash: Bytes32::default(),
                seal: Bytes32::default(),
                payload_hash: PoseidonHashOut::default(),
            }]),
        };

        let root_a = compute_tx_v2_root(&[tx]);
        let root_b = compute_tx_v2_root(&[tx]);
        assert_eq!(root_a, root_b);
    }
}
