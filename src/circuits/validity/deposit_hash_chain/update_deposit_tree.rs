use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::{
    common::{deposit::Deposit, trees::deposit_tree::DepositMerkleProof},
    utils::leafable::Leafable as _,
};

#[derive(Debug, thiserror::Error)]
pub enum UpdateDepositTreeError {
    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),
}

pub struct UpdateDepositTreeWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub prev_deposit_hash_chain_proof: ProofWithPublicInputs<F, C, D>,
    pub deposit_index: u64,
    pub deposit: Deposit,
    pub deposit_merkle_proof: DepositMerkleProof,
}

// impl UpdateDepositTreeWitness {
//     pub fn to_public_inputs(
//         &self,
//     ) -> Result<UpdateDepositTreePublicInputs, UpdateDepositTreeError> {
//         let empty_deposit = Deposit::empty_leaf();
//         self.deposit_merkle_proof
//             .verify(
//                 &empty_deposit,
//                 self.deposit_index,
//                 self.prev_deposit_tree_root,
//             )
//             .map_err(|e| {
//                 UpdateDepositTreeError::MerkleProofError(format!(
//                     "Failed to verify empty deposit merkle proof: {e}",
//                 ))
//             })?;
//         // Compute new deposit tree root
//         let new_deposit_tree_root = self
//             .deposit_merkle_proof
//             .get_root(&self.deposit, self.deposit_index);

//         // Compute new deposit hash chain
//         let new_deposit_hash_chain = self
//             .deposit
//             .hash_with_prev_hash(self.prev_deposit_hash_chain);

//         Ok(UpdateDepositTreePublicInputs {
//             prev_deposit_hash_chain: self.prev_deposit_hash_chain,
//             prev_deposit_tree_root: self.prev_deposit_tree_root,
//             new_deposit_hash_chain,
//             new_deposit_tree_root,
//         })
//     }
// }
