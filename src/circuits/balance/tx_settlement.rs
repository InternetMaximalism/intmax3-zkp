use crate::{
    circuits::balance::{
        account_state::{AccountState, AccountStateError, AccountStateTarget},
        spend_circuit::{SpendPublicInputs, SpendPublicInputsTarget},
    },
    common::{
        block_number::{BlockNumber, BlockNumberTarget},
        trees::{
            public_state_tree::{PublicState, PublicStateTarget},
            tx_tree::{TxMerkleProof, TxMerkleProofTarget},
        },
        tx::{Tx, TxTarget},
        user_id::{UserId, UserIdTarget},
    },
    utils::{conversion::ToU64, recursively_verifiable::add_proof_target_and_verify},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum TxSettlementError {
    #[error("Invalid spend proof: {0}")]
    InvalidSpendProof(String),

    #[error("Invalid tx merkle proof: {0}")]
    InvalidTxMerkleProof(String),

    #[error("Invalid account state: {0}")]
    InvalidAccountState(#[from] AccountStateError),

    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),

    #[error("Invalid public state: {0}")]
    InvalidPublicState(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TxSettlement<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub user_id: UserId,
    pub tx: Tx,
    pub public_state: PublicState,
    pub account_state: AccountState,
    pub tx_merkle_proof: TxMerkleProof,
    pub spend_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> TxSettlement<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(
        spend_vd: &VerifierCircuitData<F, C, D>,
        user_id: UserId,
        tx: Tx,
        public_state: PublicState,

        account_state: AccountState,
        tx_merkle_proof: TxMerkleProof,
        spend_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, TxSettlementError> {
        // verify the spend proof
        spend_vd.verify(spend_proof.clone()).map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("Spend proof verification failed: {}", e))
        })?;

        // verify account state
        account_state.verify()?;
        if account_state.user_id != user_id {
            return Err(TxSettlementError::InvalidUserId(
                "user_id does not match".to_string(),
            ));
        }
        if account_state.account_tree_root != public_state.account_tree_root {
            return Err(TxSettlementError::InvalidPublicState(
                "account_tree_root does not match".to_string(),
            ));
        }

        // verify tx inclusion
        let tx_tree_root = account_state.send_leaf.tx_tree_root.reduce_to_hash_out();
        tx_merkle_proof
            .verify(&tx, user_id.local_id() as u64, tx_tree_root)
            .map_err(|e| TxSettlementError::InvalidTxMerkleProof(e.to_string()))?;

        // verify public inputs
        let spend_pis = SpendPublicInputs::from_pis_u64(&spend_proof.public_inputs.to_u64_vec())
            .map_err(|e| {
                TxSettlementError::InvalidSpendProof(format!(
                    "failed to parse public inputs: {}",
                    e
                ))
            })?;
        if spend_pis.tx != tx {
            return Err(TxSettlementError::InvalidSpendProof(
                "tx in public inputs does not match".to_string(),
            ));
        }

        Ok(Self {
            user_id,
            tx,
            public_state,
            tx_merkle_proof,
            account_state,
            spend_proof,
        })
    }

    // return the block number that the tx was included in
    pub fn tx_block_number(&self) -> BlockNumber {
        self.account_state.send_leaf.cur
    }

    // return the block number before the tx was included
    pub fn send_block_number_before_tx(&self) -> BlockNumber {
        self.account_state.send_leaf.prev
    }

    // return true if the tx is valid (i.e., valid nonce)
    pub fn is_valid(&self) -> Result<bool, TxSettlementError> {
        let spend_pis = SpendPublicInputs::from_pis_u64(
            &self.spend_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("failed to parse public inputs: {}", e))
        })?;
        Ok(spend_pis.is_valid)
    }
}

#[derive(Clone, Debug)]
pub struct TxSettlementTarget<const D: usize> {
    pub user_id: UserIdTarget,
    pub tx: TxTarget,
    pub public_state: PublicStateTarget,
    pub account_state: AccountStateTarget,
    pub tx_merkle_proof: TxMerkleProofTarget,
    pub spend_proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> TxSettlementTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        spend_vd: &VerifierCircuitData<F, C, D>,
        tx_tree_height: usize,
        is_checked: bool,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let user_id = UserIdTarget::new(builder, is_checked);
        let tx = TxTarget::new(builder);
        let public_state = PublicStateTarget::new(builder, is_checked);
        let account_state = AccountStateTarget::new::<F, C, D>(builder, is_checked);
        let tx_merkle_proof = TxMerkleProofTarget::new(builder, tx_tree_height);
        let spend_proof = add_proof_target_and_verify(spend_vd, builder);

        account_state.user_id.connect(builder, &user_id);
        account_state
            .account_tree_root
            .connect(builder, public_state.account_tree_root);

        let tx_tree_root = account_state
            .send_leaf
            .tx_tree_root
            .reduce_to_hash_out(builder);
        let local_id = user_id.local_id(builder);
        tx_merkle_proof.verify::<F, C, D>(builder, &tx, local_id, tx_tree_root);

        let spend_public_inputs = SpendPublicInputsTarget::from_pis(&spend_proof.public_inputs);
        tx.connect(builder, &spend_public_inputs.tx);

        Self {
            user_id,
            tx,
            public_state,
            account_state,
            tx_merkle_proof,
            spend_proof,
        }
    }

    pub fn set_witness<F, C, W>(&self, witness: &mut W, value: &TxSettlement<F, C, D>)
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        self.user_id.set_witness(witness, value.user_id);
        self.tx.set_witness::<W, F>(witness, value.tx);
        self.public_state.set_witness(witness, &value.public_state);
        self.account_state
            .set_witness(witness, &value.account_state);
        self.tx_merkle_proof
            .set_witness(witness, &value.tx_merkle_proof);
        witness.set_proof_with_pis_target(&self.spend_proof, &value.spend_proof);
    }

    pub fn tx_block_number(&self) -> BlockNumberTarget {
        self.account_state.send_leaf.cur.clone()
    }

    pub fn send_block_number_before_tx(&self) -> BlockNumberTarget {
        self.account_state.send_leaf.prev.clone()
    }

    pub fn is_valid(&self) -> BoolTarget {
        let spend_public_inputs =
            SpendPublicInputsTarget::from_pis(&self.spend_proof.public_inputs);
        spend_public_inputs.is_valid
    }
}
