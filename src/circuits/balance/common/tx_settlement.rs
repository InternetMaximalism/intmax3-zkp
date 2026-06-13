use crate::{
    circuits::balance::{
        common::account_state::{AccountState, AccountStateError, AccountStateTarget},
        spend_circuit::{SpendPublicInputs, SpendPublicInputsTarget},
    },
    common::{
        channel_id::{ChannelId, ChannelIdTarget},
        public_state::{PublicState, PublicStateTarget},
        trees::{
            tx_tree::{TxMerkleProof, TxMerkleProofTarget},
            tx_v2_tree::{TxV2MerkleProof, TxV2MerkleProofTarget},
        },
        tx::{Tx, TxClass, TxTarget, TxV2, TxV2Target},
        u63::{BlockNumber, BlockNumberTarget},
    },
    constants::TX_TREE_HEIGHT,
    utils::{
        conversion::ToU64,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
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

    #[error("Invalid tx_v2 merkle proof: {0}")]
    InvalidTxV2MerkleProof(String),

    #[error("Invalid account state: {0}")]
    InvalidAccountState(#[from] AccountStateError),

    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),

    #[error("Invalid public state: {0}")]
    InvalidPublicState(String),

    #[error("Inconsistent witness data: {0}")]
    InconsistentWitness(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TxSettlement<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub channel_id: ChannelId,
    pub tx: Tx,
    pub public_state: PublicState,
    pub account_state: AccountState,
    pub tx_merkle_proof: TxMerkleProof,
    pub tx_v2_merkle_proof: Option<TxV2MerkleProof>,
    pub tx_v2: Option<TxV2>,
    pub spend_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> TxSettlement<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(
        spend_vd: &VerifierCircuitData<F, C, D>,
        channel_id: ChannelId,
        tx: Tx,
        public_state: PublicState,

        account_state: AccountState,
        tx_merkle_proof: TxMerkleProof,
        spend_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, TxSettlementError> {
        Self::new_with_optional_tx_v2(
            spend_vd,
            channel_id,
            tx,
            public_state,
            account_state,
            tx_merkle_proof,
            None,
            None,
            spend_proof,
        )
    }

    pub fn new_with_tx_v2(
        spend_vd: &VerifierCircuitData<F, C, D>,
        channel_id: ChannelId,
        tx: Tx,
        public_state: PublicState,
        account_state: AccountState,
        tx_merkle_proof: TxMerkleProof,
        tx_v2_merkle_proof: TxV2MerkleProof,
        tx_v2: TxV2,
        spend_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, TxSettlementError> {
        Self::new_with_optional_tx_v2(
            spend_vd,
            channel_id,
            tx,
            public_state,
            account_state,
            tx_merkle_proof,
            Some(tx_v2_merkle_proof),
            Some(tx_v2),
            spend_proof,
        )
    }

    fn new_with_optional_tx_v2(
        spend_vd: &VerifierCircuitData<F, C, D>,
        channel_id: ChannelId,
        tx: Tx,
        public_state: PublicState,
        account_state: AccountState,
        tx_merkle_proof: TxMerkleProof,
        tx_v2_merkle_proof: Option<TxV2MerkleProof>,
        tx_v2: Option<TxV2>,
        spend_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, TxSettlementError> {
        // verify the spend proof
        spend_vd.verify(spend_proof.clone()).map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("Spend proof verification failed: {}", e))
        })?;

        // verify account state
        account_state.verify()?;
        if account_state.channel_id != channel_id {
            return Err(TxSettlementError::InvalidUserId(
                "channel_id does not match".to_string(),
            ));
        }
        if account_state.account_tree_root != public_state.account_tree_root {
            return Err(TxSettlementError::InvalidPublicState(
                "account_tree_root does not match".to_string(),
            ));
        }

        // verify tx inclusion
        let tx_tree_root = account_state.send_leaf.tx_tree_root.reduce_to_hash_out();
        match (&tx_v2, &tx_v2_merkle_proof) {
            (Some(tx_v2), Some(tx_v2_merkle_proof)) => {
                // Two-layer identity: the block tx tree is indexed by channel_id
                // (TX_TREE_HEIGHT == CHANNEL_ID_BITS).
                tx_v2_merkle_proof
                    .verify(tx_v2, channel_id.as_u64(), tx_tree_root)
                    .map_err(|e| TxSettlementError::InvalidTxV2MerkleProof(e.to_string()))?;

                if tx_v2.tx_class != TxClass::UserTransfer {
                    return Err(TxSettlementError::InconsistentWitness(
                        "tx_v2 must be TxClass::UserTransfer".to_string(),
                    ));
                }
                if tx_v2.channel_action_root != PoseidonHashOut::default() {
                    return Err(TxSettlementError::InconsistentWitness(
                        "user transfer tx_v2 must have zero channel_action_root".to_string(),
                    ));
                }
                if tx_v2.transfer_tree_root != tx.transfer_tree_root {
                    return Err(TxSettlementError::InconsistentWitness(format!(
                        "tx_v2 transfer tree root mismatch: expected {:?}, got {:?}",
                        tx.transfer_tree_root, tx_v2.transfer_tree_root
                    )));
                }
                if tx_v2.nonce != tx.nonce {
                    return Err(TxSettlementError::InconsistentWitness(format!(
                        "tx_v2 nonce mismatch: expected {}, got {}",
                        tx.nonce, tx_v2.nonce
                    )));
                }
            }
            (None, None) => {
                tx_merkle_proof
                    .verify(&tx, channel_id.as_u64(), tx_tree_root)
                    .map_err(|e| TxSettlementError::InvalidTxMerkleProof(e.to_string()))?;
            }
            _ => {
                return Err(TxSettlementError::InconsistentWitness(
                    "tx_v2 and tx_v2_merkle_proof must be provided together".to_string(),
                ));
            }
        }

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
            channel_id,
            tx,
            public_state,
            tx_merkle_proof,
            tx_v2_merkle_proof,
            tx_v2,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TxSettlementTarget<const D: usize> {
    pub channel_id: ChannelIdTarget,
    pub tx: TxTarget,
    pub public_state: PublicStateTarget,
    pub account_state: AccountStateTarget,
    pub tx_merkle_proof: TxMerkleProofTarget,
    pub use_tx_v2: plonky2::iop::target::BoolTarget,
    pub tx_v2_merkle_proof: TxV2MerkleProofTarget,
    pub tx_v2: TxV2Target,
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
        let channel_id = ChannelIdTarget::new(builder, is_checked);
        let tx = TxTarget::new(builder);
        let public_state = PublicStateTarget::new(builder, is_checked);
        let account_state = AccountStateTarget::new::<F, C, D>(builder, is_checked);
        let tx_merkle_proof = TxMerkleProofTarget::new(builder, TX_TREE_HEIGHT);
        let use_tx_v2 = builder.add_virtual_bool_target_safe();
        let tx_v2_merkle_proof = TxV2MerkleProofTarget::new(builder, TX_TREE_HEIGHT);
        let tx_v2 = TxV2Target::new(builder);
        let spend_proof = add_proof_target_and_verify(spend_vd, builder);

        account_state.channel_id.connect(builder, &channel_id);
        account_state
            .account_tree_root
            .connect(builder, public_state.account_tree_root);

        let tx_tree_root = account_state
            .send_leaf
            .tx_tree_root
            .reduce_to_hash_out(builder);
        // Two-layer identity: the block tx tree is indexed by channel_id
        // (TX_TREE_HEIGHT == CHANNEL_ID_BITS).
        let tx_index = channel_id.channel_id(builder);
        let use_legacy_tx = builder.not(use_tx_v2);
        tx_merkle_proof.conditional_verify::<F, C, D>(
            builder,
            use_legacy_tx,
            &tx,
            tx_index,
            tx_tree_root.clone(),
        );
        tx_v2_merkle_proof.conditional_verify::<F, C, D>(
            builder,
            use_tx_v2,
            &tx_v2,
            tx_index,
            tx_tree_root,
        );

        let user_transfer_class =
            builder.constant(F::from_canonical_u32(TxClass::UserTransfer.as_u32()));
        let is_user_transfer = builder.is_equal(tx_v2.tx_class, user_transfer_class);
        builder.conditional_assert_eq(use_tx_v2.target, is_user_transfer.target, use_tx_v2.target);
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());
        zero_hash.conditional_assert_eq(builder, tx_v2.channel_action_root.clone(), use_tx_v2);
        tx_v2.transfer_tree_root.conditional_assert_eq(
            builder,
            tx.transfer_tree_root.clone(),
            use_tx_v2,
        );
        builder.conditional_assert_eq(use_tx_v2.target, tx_v2.nonce, tx.nonce);

        let spend_public_inputs = SpendPublicInputsTarget::from_pis(&spend_proof.public_inputs);
        tx.connect(builder, &spend_public_inputs.tx);

        Self {
            channel_id,
            tx,
            public_state,
            account_state,
            tx_merkle_proof,
            use_tx_v2,
            tx_v2_merkle_proof,
            tx_v2,
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
        self.channel_id.set_witness(witness, value.channel_id);
        self.tx.set_witness::<W, F>(witness, value.tx);
        self.public_state.set_witness(witness, &value.public_state);
        self.account_state
            .set_witness(witness, &value.account_state);
        self.tx_merkle_proof
            .set_witness(witness, &value.tx_merkle_proof);
        let _ = witness.set_bool_target(self.use_tx_v2, value.tx_v2.is_some());
        self.tx_v2_merkle_proof.set_witness(
            witness,
            &value
                .tx_v2_merkle_proof
                .clone()
                .unwrap_or_else(|| TxV2MerkleProof::dummy(TX_TREE_HEIGHT)),
        );
        self.tx_v2
            .set_witness::<W, F>(witness, value.tx_v2.unwrap_or_default());
        let _ = witness.set_proof_with_pis_target(&self.spend_proof, &value.spend_proof);
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
            channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
            tx_tree::TxTree,
            tx_v2_tree::TxV2Tree,
        },
        constants::{CHANNEL_TREE_HEIGHT, SEND_TREE_HEIGHT},
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

        let mut tx_tree = TxTree::init();
        let tx = Tx::default();
        let key_id = 1u32;
        tx_tree.update(key_id as u64, tx);
        let tx_merkle_proof = tx_tree.prove(key_id as u64);
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

        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        let channel_leaf = ChannelLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::default(),
            send_tree_root: send_tree.get_root(),
            member_key_ids_root: ChannelLeaf::default().member_key_ids_root,
        };
        let channel_id = ChannelId::new(key_id as u64).expect("user id");
        channel_tree.update(channel_id.as_u64(), channel_leaf.clone());
        let user_merkle_proof = channel_tree.prove(channel_id.as_u64());
        let account_tree_root = channel_tree.get_root();

        let public_state = PublicState {
            block_number: BlockNumber::default(),
            timestamp: 0,
            account_tree_root,
            deposit_tree_root: PoseidonHashOut::default(),
            prev_public_state_root: PoseidonHashOut::default(),
        };

        let account_state = AccountState::new(
            channel_id.clone(),
            public_state.account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            channel_leaf,
            user_merkle_proof,
        )
        .expect("account state");

        let tx_settlement = TxSettlement::new(
            &spend_vd,
            channel_id,
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

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn tx_settlement_target_proves_with_tx_v2_user_transfer() {
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

        let tx = Tx::default();
        let tx_v2 = TxV2 {
            tx_class: TxClass::UserTransfer,
            transfer_tree_root: tx.transfer_tree_root,
            nonce: tx.nonce,
            channel_action_root: PoseidonHashOut::default(),
        };
        let key_id = 1u32;

        let mut tx_tree = TxTree::init();
        tx_tree.update(key_id as u64, tx);
        let tx_merkle_proof = tx_tree.prove(key_id as u64);

        let mut tx_v2_tree = TxV2Tree::init();
        tx_v2_tree.update(key_id as u64, tx_v2);
        let tx_v2_merkle_proof = tx_v2_tree.prove(key_id as u64);
        let tx_tree_root: PoseidonHashOut = tx_v2_tree.get_root();
        let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();

        let mut send_tree = SendTree::new(SEND_TREE_HEIGHT);
        let send_leaf = SendLeaf {
            prev: BlockNumber::default(),
            cur: BlockNumber::default(),
            tx_tree_root: tx_tree_root_bytes,
        };
        let send_leaf_index = 0u32;
        send_tree.push(send_leaf.clone());
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        let channel_leaf = ChannelLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::default(),
            send_tree_root: send_tree.get_root(),
            member_key_ids_root: ChannelLeaf::default().member_key_ids_root,
        };
        let channel_id = ChannelId::new(key_id as u64).expect("user id");
        channel_tree.update(channel_id.as_u64(), channel_leaf.clone());
        let user_merkle_proof = channel_tree.prove(channel_id.as_u64());
        let account_tree_root = channel_tree.get_root();

        let public_state = PublicState {
            block_number: BlockNumber::default(),
            timestamp: 0,
            account_tree_root,
            deposit_tree_root: PoseidonHashOut::default(),
            prev_public_state_root: PoseidonHashOut::default(),
        };

        let account_state = AccountState::new(
            channel_id,
            public_state.account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            channel_leaf,
            user_merkle_proof,
        )
        .expect("account state");

        let tx_settlement = TxSettlement::new_with_tx_v2(
            &spend_vd,
            channel_id,
            tx,
            public_state,
            account_state,
            tx_merkle_proof,
            tx_v2_merkle_proof,
            tx_v2,
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
