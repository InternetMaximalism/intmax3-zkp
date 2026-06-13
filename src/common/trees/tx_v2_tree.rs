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
            channel_id::ChannelId,
            tx::{ChannelActionKind, TxClass},
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
                source_channel_id: ChannelId::new(2).unwrap(),
                destination_channel_id: ChannelId::dummy(),
                tx_hash: Bytes32::default(),
                seal: Bytes32::default(),
                payload_hash: PoseidonHashOut::default(),
            }]),
        };

        let root_a = compute_tx_v2_root(&[tx]);
        let root_b = compute_tx_v2_root(&[tx]);
        assert_eq!(root_a, root_b);
    }

    /// SECURITY (detail2 §C-2): the validity circuits reserve `tx_tree_root == 0` (H2 = 0)
    /// for in-channel updates and reject member signatures over a zero root. That reservation
    /// is only sound if a REAL (even empty) TxV2 tree can never produce the zero root —
    /// otherwise a legitimate empty block would be indistinguishable from the reserved value.
    #[test]
    fn empty_tx_v2_tree_root_is_not_zero() {
        let empty_root = TxV2Tree::init().get_root();
        assert_ne!(empty_root, PoseidonHashOut::default());
        // The block header carries the root as Bytes32 (`Block::new_with_tx_v2s` uses
        // `PoseidonHashOut::into::<Bytes32>()`); the encoded form must also be nonzero.
        let encoded: Bytes32 = empty_root.into();
        assert_ne!(encoded, Bytes32::default());
    }
}
