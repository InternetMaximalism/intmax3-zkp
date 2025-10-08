use crate::{
    circuits::balance::{
        common::account_state::{AccountState, AccountStateError, AccountStateTarget},
        spend_circuit::{SpendPublicInputs, SpendPublicInputsTarget},
    },
    common::{
        public_state::{PublicState, PublicStateTarget},
        trees::tx_tree::{TxMerkleProof, TxMerkleProofTarget},
        tx::{Tx, TxTarget},
        u63::{BlockNumber, BlockNumberTarget},
        user_id::{UserId, UserIdTarget},
    },
    constants::TX_TREE_HEIGHT,
    utils::{conversion::ToU64, recursively_verifiable::add_proof_target_and_verify},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::WitnessWrite,
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

    pub fn spend_pis(&self) -> Result<SpendPublicInputs, TxSettlementError> {
        let spend_pis = SpendPublicInputs::from_pis_u64(
            &self.spend_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("failed to parse public inputs: {}", e))
        })?;
        Ok(spend_pis)
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
        let tx_merkle_proof = TxMerkleProofTarget::new(builder, TX_TREE_HEIGHT);
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

    pub fn spend_pis(&self) -> SpendPublicInputsTarget {
        SpendPublicInputsTarget::from_pis(&self.spend_proof.public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::balance::spend_circuit::SPEND_PUBLIC_INPUTS_LEN,
        common::trees::{
            account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
            tx_tree::TxTree,
        },
        constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT, TX_TREE_HEIGHT},
        ethereum_types::bytes32::Bytes32,
        utils::poseidon_hash_out::PoseidonHashOut,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    type F = GoldilocksField;
    type TestConfig = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn tx_settlement_target_proves() {
        let mut spend_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let zero = spend_builder.zero();
        let mut spend_pis_targets = Vec::with_capacity(SPEND_PUBLIC_INPUTS_LEN);
        for _ in 0..SPEND_PUBLIC_INPUTS_LEN - 1 {
            spend_pis_targets.push(zero);
        }
        spend_pis_targets.push(spend_builder.one());
        spend_builder.register_public_inputs(&spend_pis_targets);
        let spend_circuit = spend_builder.build::<TestConfig>();
        let spend_vd = spend_circuit.verifier_data();
        let spend_proof = spend_circuit
            .prove(PartialWitness::<F>::new())
            .expect("spend circuit proof");

        let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        tx_tree.push(Tx::default());
        let tx = Tx::default();
        let local_id = 1u32;
        tx_tree.push(tx);
        let tx_merkle_proof = tx_tree.prove(local_id as u64);
        let tx_tree_root: PoseidonHashOut = tx_tree.get_root();
        let tx_tree_root_bytes: Bytes32 = tx_tree_root.clone().into();

        let mut send_tree = SendTree::new(SEND_TREE_HEIGHT);
        let send_leaf = SendLeaf {
            prev: BlockNumber::default(),
            cur: BlockNumber::default(),
            tx_tree_root: tx_tree_root_bytes,
        };
        let send_leaf_index = 0u32;
        send_tree.push(send_leaf.clone());
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        let account_leaf = AccountLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::default(),
            send_tree_root: send_tree.get_root(),
        };
        let user_id = UserId::new(0, local_id).expect("user id");
        account_tree.update(user_id.as_u64(), account_leaf.clone());
        let account_merkle_proof = account_tree.prove(user_id.as_u64());
        let account_tree_root = account_tree.get_root();

        let public_state = PublicState {
            block_number: BlockNumber::default(),
            account_tree_root,
            deposit_tree_root: PoseidonHashOut::default(),
            prev_public_state_root: PoseidonHashOut::default(),
        };

        let account_state = AccountState::new(
            user_id.clone(),
            public_state.account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            account_leaf,
            account_merkle_proof,
        )
        .expect("account state");

        let tx_settlement = TxSettlement::new(
            &spend_vd,
            user_id,
            tx,
            public_state,
            account_state,
            tx_merkle_proof,
            spend_proof,
        )
        .expect("tx settlement");

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let settlement_target = TxSettlementTarget::new(&mut builder, &spend_vd, true);
        let mut pw = PartialWitness::<F>::new();
        settlement_target.set_witness::<F, TestConfig, _>(&mut pw, &tx_settlement);

        let circuit = builder.build::<TestConfig>();
        circuit.prove(pw).expect("tx settlement circuit proof");
    }
}
