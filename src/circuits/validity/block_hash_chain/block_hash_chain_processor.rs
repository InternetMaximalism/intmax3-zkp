use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use thiserror::Error;

use crate::{
    circuits::validity::{
        block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_circuit::{BlockHashChainCircuit, BlockHashChainCircuitError},
            block_step::{BlockStepCircuit, BlockStepError, BlockStepWitness},
            ext_public_state::ExtendedPublicState,
            sphincs_sig::SmallBlockMessageFields,
            update_channel_tree::{UpdateUserCircuit, UpdateUserCircuitError, UpdateUserTree},
        },
        channel_reg_hash_chain::{
            channel_reg_chain_processor::{
                ChannelRegChainProcessor, ChannelRegChainProcessorError,
            },
            channel_reg_step::ChannelRegStepWitness,
        },
        deposit_hash_chain::{
            deposit_chain_processor::{DepositChainProcessor, DepositChainProcessorError},
            deposit_step::DepositStepWitness,
        },
    },
    common::{
        block::Block,
        channel_registration::ChannelRegRecord,
        deposit::Deposit,
        trees::{
            channel_tree::{ChannelLeaf, ChannelMerkleProof, SendMerkleProof},
            deposit_tree::DepositMerkleProof,
            key_tree::MemberMerkleProof,
            public_state_tree::PublicStateMerkleProof,
            tx_v2_tree::{ChannelActionMerkleProof, TxV2MerkleProof},
        },
        tx::{ChannelAction, TxV2},
    },
    constants::{MEMBER_TREE_HEIGHT, TX_TREE_HEIGHT},
    regev::{REGEV_N, RegevPk},
    utils::{conversion::ToU64, poseidon_hash_out::PoseidonHashOut},
};

/// All-zero Regev pubkey of the correct length for inactive (non-updating) slots. The member
/// binding is gated by `should_update`, so these coefficients are never digest-checked.
fn dummy_regev_pk() -> RegevPk {
    RegevPk {
        a: vec![0u32; REGEV_N],
        b: vec![0u32; REGEV_N],
    }
}

#[derive(Debug, Error)]
pub enum BlockHashChainProcessorError {
    #[error("unsupported number of users: {0}")]
    UnsupportedUserCount(u32),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("deposit chain processor error: {0}")]
    DepositChainProcessor(#[from] DepositChainProcessorError),
    #[error("channel reg chain processor error: {0}")]
    ChannelRegChainProcessor(#[from] ChannelRegChainProcessorError),
    #[error("update account circuit error: {0}")]
    UpdateUserCircuit(#[from] UpdateUserCircuitError),
    #[error("block step error: {0}")]
    BlockStep(#[from] BlockStepError),
    #[error("block hash chain circuit error: {0}")]
    BlockHashChain(#[from] BlockHashChainCircuitError),
}

#[derive(Debug, Clone)]
pub struct BlockHashChainProcessorWitness {
    pub deposit_step_witness: Vec<(Deposit, DepositMerkleProof)>,
    /// Per-registration witnesses for a registration block (R1, mirror of `deposit_step_witness`).
    /// Empty for ordinary (non-registration) blocks — the only path exercised on this branch — in
    /// which case the channel-registration chain proof is `None` and the chain stays unchanged.
    pub channel_reg_step_witness: Vec<(ChannelRegRecord, ChannelMerkleProof)>,
    pub block: Block,
    pub prev_account_leaves: Vec<ChannelLeaf>,
    pub user_merkle_proofs: Vec<ChannelMerkleProof>,
    pub send_merkle_proofs: Vec<SendMerkleProof>,
    pub public_state_merkle_proof: PublicStateMerkleProof,
    /// Optional per-slot MemberTree inclusion proofs binding the signing pubkey to the channel's
    /// member tree (see `UpdateUserTree::member_merkle_proofs`). If None, dummy proofs are used,
    /// valid only when every slot is non-updating (signature/binding constraints skipped).
    pub member_merkle_proofs: Option<Vec<MemberMerkleProof>>,
    /// Optional per-slot Regev public keys accompanying `member_merkle_proofs`. If None, default
    /// (empty/dummy) keys are used (valid only for non-updating slots).
    pub member_regev_pks: Option<Vec<RegevPk>>,
    /// Optional per-slot `pk_b` (BabyBear hash-sig public key) accompanying `member_merkle_proofs`
    /// (P3, third `MemberLeaf` component). If None, default (zero) values are used — valid only for
    /// non-updating slots (the leaf-inclusion constraint is skipped).
    pub member_pk_bs: Option<Vec<PoseidonHashOut>>,
    /// Optional per-block IMSB `SmallBlockRootMessage` preimage fields accompanying
    /// `sig_witnesses` (detail2 §F-2). If None, default fields are used — valid only when the
    /// signature constraints are skipped (dummy witnesses).
    pub msg_fields: Option<SmallBlockMessageFields>,
    /// Optional TxV2 witnesses used to bind active hub/key_id slots to concrete tx leaves.
    pub tx_v2_indices: Option<Vec<u64>>,
    pub tx_v2s: Option<Vec<TxV2>>,
    pub tx_v2_merkle_proofs: Option<Vec<TxV2MerkleProof>>,
    pub channel_action_indices: Option<Vec<u64>>,
    pub channel_actions: Option<Vec<ChannelAction>>,
    pub channel_action_merkle_proofs: Option<Vec<ChannelActionMerkleProof>>,
}

pub struct BlockHashChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    block_hash_chain_circuit: BlockHashChainCircuit<F, C, D>,
    block_step_circuit: BlockStepCircuit<F, C, D>,
    deposit_chain_vd: VerifierCircuitData<F, C, D>,
    channel_reg_chain_vd: VerifierCircuitData<F, C, D>,
    update_account_vds: Vec<(u32, VerifierCircuitData<F, C, D>)>,
    update_user_circuits: HashMap<u32, UpdateUserCircuit<F, C, D>>,
    deposit_chain_processor: DepositChainProcessor<F, C, D>,
    channel_reg_chain_processor: ChannelRegChainProcessor<F, C, D>,
}

impl<F, C, const D: usize> BlockHashChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(supported_user_counts: &[u32]) -> Self {
        assert!(
            !supported_user_counts.is_empty(),
            "at least one supported user count is required"
        );

        let block_chain_cd = BlockHashChainCircuit::<F, C, D>::generate_cd();

        let deposit_chain_processor = DepositChainProcessor::<F, C, D>::new();
        let deposit_chain_vd = deposit_chain_processor.deposit_chain_vd();

        let channel_reg_chain_processor = ChannelRegChainProcessor::<F, C, D>::new();
        let channel_reg_chain_vd = channel_reg_chain_processor.channel_reg_chain_vd();

        let mut update_user_circuits = HashMap::new();
        let mut update_account_vds = Vec::with_capacity(supported_user_counts.len());
        for &num_users in supported_user_counts {
            let circuit = UpdateUserCircuit::<F, C, D>::new(num_users);
            let vd = circuit.data.verifier_data();
            update_account_vds.push((num_users, vd.clone()));
            update_user_circuits.insert(num_users, circuit);
        }

        let block_step_circuit = BlockStepCircuit::<F, C, D>::new(
            &block_chain_cd,
            &update_account_vds,
            &deposit_chain_vd,
            &channel_reg_chain_vd,
        );

        let block_hash_chain_circuit = BlockHashChainCircuit::<F, C, D>::new(
            &block_chain_cd,
            &block_step_circuit.data.verifier_data(),
        );

        Self {
            block_hash_chain_circuit,
            block_step_circuit,
            deposit_chain_vd,
            channel_reg_chain_vd,
            update_account_vds,
            update_user_circuits,
            deposit_chain_processor,
            channel_reg_chain_processor,
        }
    }

    pub fn block_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.block_hash_chain_circuit.data.verifier_data()
    }

    pub fn deposit_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.deposit_chain_vd.clone()
    }

    pub fn channel_reg_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.channel_reg_chain_vd.clone()
    }

    pub fn prove_block(
        &self,
        initial_public_state: Option<ExtendedPublicState>,
        prev_block_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,
        witness: &BlockHashChainProcessorWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BlockHashChainProcessorError> {
        // get corresponding update account circuit
        let num_users = witness.block.num_users;
        let update_account_circuit = self.update_user_circuits.get(&num_users).ok_or(
            BlockHashChainProcessorError::UnsupportedUserCount(num_users),
        )?;

        // require initial state or previous proof
        if initial_public_state.is_some() as u8 + prev_block_chain_proof.is_some() as u8 != 1 {
            return Err(BlockHashChainProcessorError::InvalidInput(
                "either initial public state or previous block chain proof must be provided"
                    .to_string(),
            ));
        }
        let prev_ext_public_state = if let Some(ref proof) = prev_block_chain_proof {
            self.block_hash_chain_circuit
                .verify(proof)
                .map_err(BlockHashChainProcessorError::BlockHashChain)?;

            let prev_pis = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &self.block_hash_chain_circuit.data.common.config,
            )
            .map_err(|e| {
                BlockHashChainProcessorError::InvalidInput(format!(
                    "failed to parse previous block chain proof public inputs: {:?}",
                    e
                ))
            })?;
            prev_pis.ext_public_state.clone()
        } else {
            initial_public_state
                .clone()
                .ok_or(BlockHashChainProcessorError::InvalidInput(
                    "initial public state must be provided".to_string(),
                ))?
        };

        // generate deposit chain proof
        let mut deposit_chain_proof = None;
        for (deposit, deposit_merkle_proof) in &witness.deposit_step_witness {
            let initial_value = if deposit_chain_proof.is_none() {
                Some((
                    prev_ext_public_state.deposit_hash_chain,
                    prev_ext_public_state.inner.deposit_tree_root,
                    prev_ext_public_state.deposit_count,
                ))
            } else {
                None
            };
            let deposit_step_witness = DepositStepWitness::<F, C, D> {
                initial_value,
                prev_deposit_chain_proof: deposit_chain_proof.clone(),
                deposit: deposit.clone(),
                deposit_merkle_proof: deposit_merkle_proof.clone(),
            };
            let proof = self
                .deposit_chain_processor
                .prove_step(&deposit_step_witness)?;
            deposit_chain_proof = Some(proof);
        }

        let block_number = prev_ext_public_state
            .inner
            .block_number
            .add(1)
            .map_err(|_e| {
                BlockHashChainProcessorError::InvalidInput(
                    "previous block number is at max value".to_string(),
                )
            })?;

        // Generate the channel-registration chain proof (mirror of the deposit chain above). Empty
        // for ordinary blocks, in which case the proof is `None` and the channel_reg_hash_chain in
        // the resulting ext state is unchanged. For a registration block the chain rebuilds the
        // Poseidon channel tree starting from the block's prev account_tree_root.
        let mut channel_reg_chain_proof = None;
        for (record, channel_merkle_proof) in &witness.channel_reg_step_witness {
            let initial_value = if channel_reg_chain_proof.is_none() {
                Some((
                    prev_ext_public_state.channel_reg_hash_chain,
                    prev_ext_public_state.inner.account_tree_root,
                    crate::common::u63::U63::default(),
                ))
            } else {
                None
            };
            let channel_reg_step_witness = ChannelRegStepWitness::<F, C, D> {
                initial_value,
                prev_channel_reg_chain_proof: channel_reg_chain_proof.clone(),
                record: record.clone(),
                channel_merkle_proof: channel_merkle_proof.clone(),
                block_number,
            };
            let proof = self
                .channel_reg_chain_processor
                .prove_step(&channel_reg_step_witness)?;
            channel_reg_chain_proof = Some(proof);
        }

        let num_users = witness.block.num_users;
        let dummy_tx_v2_indices = vec![0; num_users as usize];
        let dummy_tx_v2s = vec![TxV2::default(); num_users as usize];
        let dummy_tx_v2_merkle_proofs =
            vec![TxV2MerkleProof::dummy(TX_TREE_HEIGHT); num_users as usize];
        let dummy_channel_action_indices = vec![0; num_users as usize];
        let dummy_channel_actions = vec![ChannelAction::default(); num_users as usize];
        let dummy_channel_action_merkle_proofs =
            vec![ChannelActionMerkleProof::dummy(TX_TREE_HEIGHT); num_users as usize];
        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain: prev_ext_public_state.block_hash_chain,
            prev_account_tree_root: prev_ext_public_state.inner.account_tree_root,
            block_number,
            block: witness.block.clone(),
            prev_account_leaves: witness.prev_account_leaves.clone(),
            user_merkle_proofs: witness.user_merkle_proofs.clone(),
            send_merkle_proofs: witness.send_merkle_proofs.clone(),
            // P2b: the bp IMSB-signature list accumulator before this block (the prev ext-state's).
            prev_bp_sig_chain: prev_ext_public_state.bp_sig_chain,
            member_merkle_proofs: witness.member_merkle_proofs.clone().unwrap_or_else(|| {
                vec![MemberMerkleProof::dummy(MEMBER_TREE_HEIGHT); num_users as usize]
            }),
            member_regev_pks: witness
                .member_regev_pks
                .clone()
                .unwrap_or_else(|| vec![dummy_regev_pk(); num_users as usize]),
            member_pk_bs: witness
                .member_pk_bs
                .clone()
                .unwrap_or_else(|| vec![PoseidonHashOut::default(); num_users as usize]),
            msg_fields: witness.msg_fields.clone().unwrap_or_default(),
            tx_v2_indices: witness.tx_v2_indices.clone().unwrap_or(dummy_tx_v2_indices),
            tx_v2s: witness.tx_v2s.clone().unwrap_or(dummy_tx_v2s),
            tx_v2_merkle_proofs: witness
                .tx_v2_merkle_proofs
                .clone()
                .unwrap_or(dummy_tx_v2_merkle_proofs),
            channel_action_indices: witness
                .channel_action_indices
                .clone()
                .unwrap_or(dummy_channel_action_indices),
            channel_actions: witness
                .channel_actions
                .clone()
                .unwrap_or(dummy_channel_actions),
            channel_action_merkle_proofs: witness
                .channel_action_merkle_proofs
                .clone()
                .unwrap_or(dummy_channel_action_merkle_proofs),
        };
        let update_user_proof = update_account_circuit.prove(&update_channel_tree)?;

        let block_step_witness = BlockStepWitness::<F, C, D> {
            num_users,
            initial_public_state: initial_public_state.clone(),
            prev_block_chain_proof: prev_block_chain_proof.clone(),
            deposit_hash_chain_proof: deposit_chain_proof.clone(),
            channel_reg_hash_chain_proof: channel_reg_chain_proof.clone(),
            update_user_proof: update_user_proof.clone(),
            public_state_merkle_proof: witness.public_state_merkle_proof.clone(),
        };
        let block_step_proof = self.block_step_circuit.prove(
            &self.block_chain_vd(),
            &self.update_account_vds,
            &self.deposit_chain_vd,
            &self.channel_reg_chain_vd,
            &block_step_witness,
        )?;

        let block_hash_chain_proof = self.block_hash_chain_circuit.prove(&block_step_proof)?;

        Ok(block_hash_chain_proof)
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), BlockHashChainCircuitError> {
        self.block_hash_chain_circuit.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        circuits::test_utils::block_witness_generator::BlockWitnessGenerator,
        common::u63::U63,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_block_chain_proof_from_generator() {
        let supported_user_counts = vec![2];

        let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);

        let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
        let mut rng = StdRng::seed_from_u64(42);

        generator
            .add_deposit(
                Address::default(),
                Bytes32::rand(&mut rng),
                0,
                U256::from(10u32),
                Bytes32::rand(&mut rng),
            )
            .expect("add deposit");

        let initial_ext_state = generator.current_extended_public_state();
        assert_eq!(initial_ext_state.deposit_count, U63::default());

        let tx_tree_root = Bytes32::rand(&mut rng);
        let timestamp = rng.next_u64();
        // Use empty key_ids (all-padding) so should_update=false, bypassing SPHINCS+.
        generator
            .add_block(1, &[], timestamp, tx_tree_root)
            .expect("add block");

        let block_number = generator.block_number;
        assert_eq!(block_number.as_u64(), 1);

        let block_witness = generator
            .block_chain_witness
            .get(&block_number)
            .expect("block witness stored");

        let block_proof = processor
            .prove_block(Some(initial_ext_state), None, &block_witness)
            .expect("block chain proof");

        processor
            .verify(&block_proof)
            .expect("block chain proof verifies");
    }
}
