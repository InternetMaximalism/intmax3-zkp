use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        transfer::{Transfer, TransferTarget},
        trees::asset_tree::{AssetMerkleProof, AssetMerkleProofTarget},
        tx::{TX_LEN, Tx, TxTarget},
    },
    constants::{MAX_NUM_TRANSFERS_PER_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::u256::{U256, U256Target},
    utils::{
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
        trees::get_root::get_merkle_root_from_leaves,
    },
};

pub const SPEND_PUBLIC_INPUTS_LEN: usize = POSEIDON_HASH_OUT_LEN * 2 + TX_LEN + 1;

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error("The number of inputs should be {MAX_NUM_TRANSFERS_PER_TX}")]
    InvalidNumInputs,

    #[error("Invalid Merkle proof {0}")]
    InvalidMerkleProof(String),

    #[error("Insufficient balance {0}")]
    InsufficientBalance(String),

    #[error("Invalid data {0}")]
    InvalidData(String),

    #[error("Failed to prove {0}")]
    FailedToProve(String),
}

#[derive(Clone, Debug)]
pub struct SpendPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub tx: Tx,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct SpendWitness {
    pub tx_nonce: u32,
    pub prev_private_state: PrivateState,
    pub transfers: Vec<Transfer>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub before_balances: Vec<U256>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub asset_merkle_proofs: Vec<AssetMerkleProof>, /* the length must be equal to
                                   * MAX_NUM_TRANSFERS_PER_TX */
}

impl SpendWitness {
    pub fn to_public_inputs(&self) -> Result<SpendPublicInputs, SpendError> {
        if self.transfers.len() != MAX_NUM_TRANSFERS_PER_TX
            || self.before_balances.len() != MAX_NUM_TRANSFERS_PER_TX
            || self.asset_merkle_proofs.len() != MAX_NUM_TRANSFERS_PER_TX
        {
            return Err(SpendError::InvalidNumInputs);
        }
        let mut asset_tree_root = self.prev_private_state.asset_tree_root;
        for i in 0..MAX_NUM_TRANSFERS_PER_TX {
            let prev_balance = self.before_balances[i];
            let transfer = &self.transfers[i];
            self.asset_merkle_proofs[i]
                .verify(&prev_balance, transfer.token_index as u64, asset_tree_root)
                .map_err(|e| {
                    SpendError::InvalidMerkleProof(format!(
                        "Invalid {}th asset merkle proof: {}",
                        i, e
                    ))
                })?;
            if prev_balance < transfer.amount {
                return Err(SpendError::InsufficientBalance(format!(
                    "{}th transfer: balance {}, transfer.amount {}",
                    i, prev_balance, transfer.amount
                )));
            }
            let new_balance = prev_balance - transfer.amount;
            asset_tree_root =
                self.asset_merkle_proofs[i].get_root(&new_balance, transfer.token_index as u64);
        }
        let new_private_state = PrivateState {
            asset_tree_root,
            nullifier_tree_root: self.prev_private_state.nullifier_tree_root,
            prev_private_commitment: self.prev_private_state.commitment(),
            nonce: self.prev_private_state.nonce + 1,
            salt: self.prev_private_state.salt,
        };

        // construct tx
        let transfer_tree_root = get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, &self.transfers)
            .map_err(|e| {
                SpendError::InvalidData(format!("Failed to get transfer tree root: {}", e))
            })?;
        let tx = Tx {
            transfer_tree_root,
            nonce: self.tx_nonce,
        };
        let is_valid = self.tx_nonce == self.prev_private_state.nonce;
        let prev_private_commitment = self.prev_private_state.commitment();
        let new_private_commitment = new_private_state.commitment();

        Ok(SpendPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            tx,
            is_valid,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SpendPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub tx: TxTarget,
    pub is_valid: BoolTarget,
}

impl SpendPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let mut v = vec![];
        v.extend(self.prev_private_commitment.to_vec());
        v.extend(self.new_private_commitment.to_vec());
        v.extend(self.tx.to_vec());
        v.push(self.is_valid.target);
        v
    }
}

#[derive(Clone, Debug)]
pub struct SpendTarget {
    pub tx_nonce: Target,
    pub prev_private_state: PrivateStateTarget,
    pub transfers: Vec<TransferTarget>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub before_balances: Vec<U256Target>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub asset_merkle_proofs: Vec<AssetMerkleProofTarget>, /* the length must be equal to
                                         * MAX_NUM_TRANSFERS_PER_TX */
}

#[derive(Debug)]
pub struct SpendCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SpendTarget,
}

impl<F, C, const D: usize> SpendCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let pis = SpendPublicInputsTarget {
            prev_private_commitment: todo!(),
            new_private_commitment: todo!(),
            tx: todo!(),
            is_valid: todo!(),
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(&self, w: &SpendWitness) -> Result<ProofWithPublicInputs<F, C, D>, SpendError> {
        let mut pw = PartialWitness::<F>::new();
        // set witness
        todo!();

        self.data
            .prove(pw)
            .map_err(|e| SpendError::FailedToProve(e.to_string()))
    }
}
