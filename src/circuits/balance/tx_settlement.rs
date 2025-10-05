use serde::{Deserialize, Serialize};

use crate::common::{
    trees::{
        account_tree::{AccountLeaf, AccountMerkleProof, SendLeaf, SendMerkleProof},
        public_state_tree::PublicState,
    },
    tx::Tx,
    user_id::UserId,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxSettlement {
    pub user_id: UserId,
    pub tx: Tx,
    pub public_state: PublicState,

    pub send_leaf: SendLeaf,
    pub send_leaf_index: u32,
    pub send_merkle_proof: SendMerkleProof,

    pub account_leaf: AccountLeaf,
    pub account_merkle_proof: AccountMerkleProof,
}
