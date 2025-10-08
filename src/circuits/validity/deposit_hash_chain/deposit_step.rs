use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::deposit_hash_chain::deposit_chain_pis::{
        DepositChainPublicInputs, DepositChainPublicInputsError,
    },
    common::{deposit::Deposit, trees::deposit_tree::DepositMerkleProof, u63::U63},
    ethereum_types::bytes32::Bytes32,
    utils::{conversion::ToU64, leafable::Leafable as _, poseidon_hash_out::PoseidonHashOut},
};

#[derive(Debug, thiserror::Error)]
pub enum UpdateDepositTreeError {
    #[error("Invalid input: {0}")]
    InvaldInput(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),

    #[error("Deposit chain public inputs error: {0}")]
    DepositChainPublicInputsError(#[from] DepositChainPublicInputsError),
}

pub struct DepositStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<(Bytes32, PoseidonHashOut, U63)>,
    pub prev_deposit_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub deposit: Deposit,
    pub deposit_merkle_proof: DepositMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    DepositStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<DepositChainPublicInputs<F, C, D>, UpdateDepositTreeError> {
        let total_inputs = self.initial_value.is_some() as usize
            + self.prev_deposit_chain_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(UpdateDepositTreeError::InvaldInput(
                "Exactly one of initial_value or prev_deposit_chain_proof must be provided"
                    .to_string(),
            ));
        }

        // initial value case
        let prev_pis = if let Some((
            initial_deposit_hash_chain,
            initial_deposit_tree_root,
            initial_deposit_count,
        )) = &self.initial_value
        {
            DepositChainPublicInputs {
                initial_deposit_hash_chain: *initial_deposit_hash_chain,
                initial_deposit_tree_root: *initial_deposit_tree_root,
                initial_deposit_count: *initial_deposit_count,
                deposit_hash_chain: *initial_deposit_hash_chain,
                deposit_tree_root: *initial_deposit_tree_root,
                deposit_count: *initial_deposit_count,
                vd: deposit_chain_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self
                .prev_deposit_chain_proof
                .clone()
                .expect("Checked above");
            DepositChainPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &deposit_chain_vd.common.config,
            )?
        };

        // Validate empty deposit merkle proof
        let empty_deposit = Deposit::empty_leaf();
        self.deposit_merkle_proof
            .verify(
                &empty_deposit,
                prev_pis.deposit_count.as_u64(),
                prev_pis.deposit_tree_root,
            )
            .map_err(|e| {
                UpdateDepositTreeError::MerkleProofError(format!(
                    "Failed to verify empty deposit merkle proof: {e}",
                ))
            })?;
        // Compute new deposit tree root
        let new_deposit_tree_root = self
            .deposit_merkle_proof
            .get_root(&self.deposit, prev_pis.deposit_count.as_u64());

        // Increment deposit count
        let new_deposit_count = prev_pis.deposit_count.add(1).map_err(|e| {
            UpdateDepositTreeError::InvaldInput(format!("Deposit count overflow: {e}"))
        })?;

        // Compute new deposit hash chain
        let new_deposit_hash_chain = self
            .deposit
            .hash_with_prev_hash(prev_pis.deposit_hash_chain);

        Ok(DepositChainPublicInputs {
            initial_deposit_hash_chain: prev_pis.initial_deposit_hash_chain,
            initial_deposit_tree_root: prev_pis.initial_deposit_tree_root,
            initial_deposit_count: prev_pis.initial_deposit_count,
            deposit_hash_chain: new_deposit_hash_chain,
            deposit_tree_root: new_deposit_tree_root,
            deposit_count: new_deposit_count,
            vd: prev_pis.vd,
        })
    }
}
