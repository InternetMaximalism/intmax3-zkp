use crate::{
    circuits::validity::block_hash_chain::sphincs_sig::{
        SPX_AUTH_GL_LEN, SPX_D, SPX_FORS_SIG_GL_LEN, SPX_WOTS_SIG_GL_LEN, SmallBlockMessageFields,
        SmallBlockMessageFieldsTarget, SpxSigTargets, SpxSigWitness,
    },
    common::{
        block::{Block, BlockError, BlockTarget},
        channel_id::{ChannelId, ChannelIdError as UserIdError, ChannelIdTarget},
        trees::{
            channel_tree::{
                ChannelLeaf, ChannelLeafTarget, ChannelMerkleProof, ChannelMerkleProofTarget,
                SendLeaf, SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
            },
            key_tree::{KeyLeaf, KeyLeafTarget},
            tx_v2_tree::{
                ChannelActionMerkleProof, ChannelActionMerkleProofTarget, TxV2MerkleProof,
                TxV2MerkleProofTarget,
            },
        },
        tx::{ChannelAction, ChannelActionKind, ChannelActionTarget, TxClass, TxV2, TxV2Target},
        u63::{BlockNumber, BlockNumberTarget, U63Target},
    },
    constants::{CHANNEL_TREE_HEIGHT, SEND_TREE_HEIGHT, TX_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u64::{U64, U64_LEN, U64Target},
    },
    utils::{
        cyclic::add_const_gate,
        leafable::Leafable as _,
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use sphincsplus_circuits::verification::{SpxVerifyWitness, verify_circuit};

#[derive(thiserror::Error, Debug)]
pub enum UpdateUserTreeError {
    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("User ID error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),
}

#[derive(Clone, Debug)]
pub struct UpdateUserPublicInputs {
    pub block_number: BlockNumber,
    pub block_timestamp: u64,
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,
    pub new_block_hash_chain: Bytes32,
    pub new_account_tree_root: PoseidonHashOut,
    pub deposit_hash_chain: Bytes32,
}

#[derive(Clone, Debug)]
pub struct UpdateUserTree {
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,

    // block number that is being processed
    pub block_number: BlockNumber,

    // contains num_users, which is circuit constant
    pub block: Block,

    // account/send merkle proofs corresponding to key_ids in the channel block
    pub prev_account_leaves: Vec<ChannelLeaf>,
    pub user_merkle_proofs: Vec<ChannelMerkleProof>,
    pub send_merkle_proofs: Vec<SendMerkleProof>,

    // SPHINCS+ signature witnesses for each key slot (index matches key_ids).
    // Use SpxSigWitness::dummy() for inactive (zero key_id) slots.
    pub sig_witnesses: Vec<SpxSigWitness>,

    // KeyTree records for each key slot (index matches key_ids), supplying the per-keyID
    // (pk_set_root, threshold). Two-layer identity: this data was moved out of `ChannelLeaf`
    // into the per-keyID `KeyLeaf`. Use KeyLeaf::default() (pk_set_root = 0) for slots whose
    // signature constraints must be skipped (dummy witnesses).
    //
    // SECURITY: TODO — these leaves are NOT yet proven included in the on-chain-bound KeyTree at
    // index key_id (tasks/channel-key-tree-design.md §3 step 2b / §6.4: key_tree_root is not yet
    // part of this circuit's public inputs / ExtendedPublicState), nor is each key_id yet proven
    // a member of the channel's member_key_ids_root (§3 step 2a). Until that binding lands, the
    // pk set used by the in-circuit SPHINCS+ check is prover-chosen.
    pub key_leaves: Vec<KeyLeaf>,

    // Per-block IMSB `SmallBlockRootMessage` preimage fields (detail2 §F-2). The signing
    // digest is recomputed in-circuit from these fields with the `channel_id` and
    // `tx_tree_root` components taken from the block targets, and every member signature in
    // this block is verified over that digest.
    pub msg_fields: SmallBlockMessageFields,

    // One bound TxV2 witness per key slot. This proves that the block tx root contains
    // a transaction attributable to the slot's channel_id/key_id authorization domain.
    pub tx_v2_indices: Vec<u64>,
    pub tx_v2s: Vec<TxV2>,
    pub tx_v2_merkle_proofs: Vec<TxV2MerkleProof>,
    pub channel_action_indices: Vec<u64>,
    pub channel_actions: Vec<ChannelAction>,
    pub channel_action_merkle_proofs: Vec<ChannelActionMerkleProof>,
}

impl UpdateUserTree {
    pub fn to_public_inputs(&self) -> Result<UpdateUserPublicInputs, UpdateUserTreeError> {
        if self.prev_account_leaves.len() != self.block.num_users as usize
            || self.user_merkle_proofs.len() != self.block.num_users as usize
            || self.send_merkle_proofs.len() != self.block.num_users as usize
            || self.key_leaves.len() != self.block.num_users as usize
            || self.tx_v2_indices.len() != self.block.num_users as usize
            || self.tx_v2s.len() != self.block.num_users as usize
            || self.tx_v2_merkle_proofs.len() != self.block.num_users as usize
            || self.channel_action_indices.len() != self.block.num_users as usize
            || self.channel_actions.len() != self.block.num_users as usize
            || self.channel_action_merkle_proofs.len() != self.block.num_users as usize
        {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "prev_account_leaves={}, user_merkle_proofs={}, send_merkle_proofs={}, tx_v2_indices={}, tx_v2s={}, tx_v2_merkle_proofs={}, channel_action_indices={}, channel_actions={}, channel_action_merkle_proofs={}, block.num_users={}",
                self.prev_account_leaves.len(),
                self.user_merkle_proofs.len(),
                self.send_merkle_proofs.len(),
                self.tx_v2_indices.len(),
                self.tx_v2s.len(),
                self.tx_v2_merkle_proofs.len(),
                self.channel_action_indices.len(),
                self.channel_actions.len(),
                self.channel_action_merkle_proofs.len(),
                self.block.num_users,
            )));
        }
        // update hash chain
        let new_block_hash_chain = self.block.hash_with_prev_hash(self.prev_block_hash_chain)?;

        // update user tree
        let mut account_tree_root = self.prev_account_tree_root;
        let block_tx_root = self.block.tx_tree_root.reduce_to_hash_out();
        let channel_id = self.block.channel_id();
        for (i, &key_id) in self.block.key_ids().iter().enumerate() {
            if key_id == 0 {
                // ignore zero key id (padding or dummy)
                continue;
            }
            // Two-layer identity: the channel-tree index is the channel id alone; key_id is the
            // member identity inside the channel (used for the SPHINCS+ message only).
            let channel_id = ChannelId::new(channel_id as u64)?;

            let prev_user_leaf = &self.prev_account_leaves[i];
            let user_merkle_proof = &self.user_merkle_proofs[i];
            let send_merkle_proof = &self.send_merkle_proofs[i];

            // verify the inclusion of prev_user_leaf in the user tree
            user_merkle_proof
                .verify(&prev_user_leaf, channel_id.as_u64(), account_tree_root)
                .map_err(|e| {
                    UpdateUserTreeError::MerkleProofError(format!(
                        "failed to verify account merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            if prev_user_leaf.prev == self.block_number {
                // already updated in this block
                continue;
            }

            // SECURITY (detail2 §C-2): tx_tree_root == 0 (H2 = 0) is reserved for in-channel
            // updates; a member signature must never be applied over it. Mirrors the in-circuit
            // `should_verify_sig → tx_tree_root != 0` constraint.
            if self.key_leaves[i].pk_set_root != PoseidonHashOut::default()
                && self.block.tx_tree_root == Bytes32::default()
            {
                return Err(UpdateUserTreeError::InvalidLength(format!(
                    "tx_tree_root must be nonzero when a member signature is applied (slot {i}; H2=0 is reserved for in-channel updates)"
                )));
            }

            let tx_v2 = &self.tx_v2s[i];
            let tx_v2_proof = &self.tx_v2_merkle_proofs[i];
            let tx_v2_index = self.tx_v2_indices[i];
            tx_v2_proof
                .verify(tx_v2, tx_v2_index, block_tx_root)
                .map_err(|e| {
                    UpdateUserTreeError::MerkleProofError(format!(
                        "failed to verify tx_v2 merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            match tx_v2.tx_class {
                TxClass::UserTransfer => {
                    if tx_v2.channel_action_root != PoseidonHashOut::default() {
                        return Err(UpdateUserTreeError::InvalidLength(format!(
                            "user-transfer tx at i {} must have zero channel_action_root",
                            i
                        )));
                    }
                }
                TxClass::ChannelAction => {
                    if tx_v2.transfer_tree_root != PoseidonHashOut::default() {
                        return Err(UpdateUserTreeError::InvalidLength(format!(
                            "channel-action tx at i {} must have zero transfer_tree_root",
                            i
                        )));
                    }

                    let channel_action = &self.channel_actions[i];
                    let channel_action_proof = &self.channel_action_merkle_proofs[i];
                    let channel_action_index = self.channel_action_indices[i];
                    channel_action_proof
                        .verify(
                            channel_action,
                            channel_action_index,
                            tx_v2.channel_action_root,
                        )
                        .map_err(|e| {
                            UpdateUserTreeError::MerkleProofError(format!(
                                "failed to verify channel action merkle proof for i {}: {}",
                                i, e
                            ))
                        })?;

                    if channel_action.source_channel_id != channel_id {
                        return Err(UpdateUserTreeError::InvalidLength(format!(
                            "channel action source_channel_id mismatch for i {}: expected {}, got {}",
                            i,
                            channel_id.as_u64(),
                            channel_action.source_channel_id.as_u64(),
                        )));
                    }

                    match channel_action.kind {
                        ChannelActionKind::InterChannelSend | ChannelActionKind::ChannelClose => {}
                    }
                }
            }

            // verify the inclusion of empty leaf in the send tree
            send_merkle_proof
                .verify(
                    &SendLeaf::empty_leaf(),
                    prev_user_leaf.index.into(),
                    prev_user_leaf.send_tree_root,
                )
                .map_err(|e| {
                    UpdateUserTreeError::MerkleProofError(format!(
                        "failed to verify send merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            // create new send leaf and compute new send tree root
            let new_send_leaf = SendLeaf {
                prev: prev_user_leaf.prev,
                cur: self.block_number,
                tx_tree_root: self.block.tx_tree_root,
            };
            let new_send_tree_root =
                send_merkle_proof.get_root(&new_send_leaf, prev_user_leaf.index.into());

            // create new account leaf and compute new user tree root
            // member_key_ids_root preserved from previous leaf across state transitions
            let new_user_leaf = ChannelLeaf {
                index: prev_user_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
                member_key_ids_root: prev_user_leaf.member_key_ids_root,
            };
            account_tree_root = user_merkle_proof.get_root(&new_user_leaf, channel_id.as_u64());
        }

        Ok(UpdateUserPublicInputs {
            block_number: self.block_number,
            block_timestamp: self.block.timestamp,
            prev_block_hash_chain: self.prev_block_hash_chain,
            prev_account_tree_root: self.prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root: account_tree_root,
            deposit_hash_chain: self.block.deposit_hash_chain,
        })
    }
}

// block_number(1) + block_timestamp(U64_LEN) + prev_block_hash_chain + prev_account_tree_root
// + new_block_hash_chain + new_account_tree_root + deposit_hash_chain
const UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN: usize =
    1 + U64_LEN + 3 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN;

impl UpdateUserPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut result = vec![self.block_number.as_u64()];
        result.extend(U64::from(self.block_timestamp).to_u64_vec());
        result.extend(self.prev_block_hash_chain.to_u64_vec());
        result.extend(self.prev_account_tree_root.to_u64_vec());
        result.extend(self.new_block_hash_chain.to_u64_vec());
        result.extend(self.new_account_tree_root.to_u64_vec());
        result.extend(self.deposit_hash_chain.to_u64_vec());
        result
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, UpdateUserTreeError> {
        if values.len() != UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "invalid update-account public inputs length: expected {UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN}, got {}",
                values.len()
            )));
        }

        let mut cursor = 0;

        let block_number = BlockNumber::new(values[cursor]).map_err(|e| {
            UpdateUserTreeError::InvalidLength(format!("invalid block number: {e}"))
        })?;
        cursor += 1;

        let block_timestamp = U64::from_u64_slice(&values[cursor..cursor + U64_LEN])
            .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;
        cursor += U64_LEN;

        let prev_block_hash_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;
        cursor += BYTES32_LEN;

        let prev_account_tree_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| UpdateUserTreeError::MerkleProofError(e.to_string()))?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let new_block_hash_chain =
            Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
                .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;
        cursor += BYTES32_LEN;

        let new_account_tree_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| UpdateUserTreeError::MerkleProofError(e.to_string()))?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let deposit_hash_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;

        Ok(Self {
            block_number,
            block_timestamp: u64::from(block_timestamp),
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
        })
    }
}

#[derive(Clone, Debug)]
pub struct UpdateUserPublicInputsTarget {
    pub block_number: BlockNumberTarget,
    pub block_timestamp: U64Target,
    pub prev_block_hash_chain: Bytes32Target,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub new_block_hash_chain: Bytes32Target,
    pub new_account_tree_root: PoseidonHashOutTarget,
    pub deposit_hash_chain: Bytes32Target,
}

impl UpdateUserPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let block_number = BlockNumberTarget::new(builder, is_checked);
        let block_timestamp = U64Target::new(builder, is_checked);
        let prev_block_hash_chain = Bytes32Target::new(builder, is_checked);
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let new_block_hash_chain = Bytes32Target::new(builder, is_checked);
        let new_account_tree_root = PoseidonHashOutTarget::new(builder);
        let deposit_hash_chain = Bytes32Target::new(builder, is_checked);
        Self {
            block_number,
            block_timestamp,
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.block_number.to_vec(),
            self.block_timestamp.to_vec(),
            self.prev_block_hash_chain.to_vec(),
            self.prev_account_tree_root.to_vec(),
            self.new_block_hash_chain.to_vec(),
            self.new_account_tree_root.to_vec(),
            self.deposit_hash_chain.to_vec(),
        ]
        .concat()
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        let inputs = self.to_vec();
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN,
            "UpdateUserPublicInputsTarget::from_slice length mismatch",
        );

        let mut cursor = 0;

        let block_number = BlockNumberTarget::from_slice(&values[cursor..cursor + 1]);
        cursor += 1;

        let block_timestamp = U64Target::from_slice(&values[cursor..cursor + U64_LEN]);
        cursor += U64_LEN;

        let prev_block_hash_chain =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let prev_account_tree_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let new_block_hash_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let new_account_tree_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let deposit_hash_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);

        Self {
            block_number,
            block_timestamp,
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdateUserPublicInputs,
    ) {
        self.block_number.set_witness(witness, value.block_number);
        self.block_timestamp
            .set_witness(witness, U64::from(value.block_timestamp));
        self.prev_block_hash_chain
            .set_witness(witness, value.prev_block_hash_chain);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.new_block_hash_chain
            .set_witness(witness, value.new_block_hash_chain);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        self.deposit_hash_chain
            .set_witness(witness, value.deposit_hash_chain);
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        Self {
            block_number: U63Target::select(
                builder,
                condition,
                &when_true.block_number,
                &when_false.block_number,
            ),
            block_timestamp: U64Target::select(
                builder,
                condition,
                when_true.block_timestamp,
                when_false.block_timestamp,
            ),
            prev_block_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.prev_block_hash_chain.clone(),
                when_false.prev_block_hash_chain.clone(),
            ),
            prev_account_tree_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.prev_account_tree_root.clone(),
                when_false.prev_account_tree_root.clone(),
            ),
            new_block_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.new_block_hash_chain.clone(),
                when_false.new_block_hash_chain.clone(),
            ),
            new_account_tree_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.new_account_tree_root.clone(),
                when_false.new_account_tree_root.clone(),
            ),
            deposit_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.deposit_hash_chain.clone(),
                when_false.deposit_hash_chain.clone(),
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UpdateUserTreeTarget {
    pub block_number: BlockNumberTarget,
    pub prev_block_hash_chain: Bytes32Target,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub block: BlockTarget,
    pub prev_account_leaves: Vec<ChannelLeafTarget>,
    pub user_merkle_proofs: Vec<ChannelMerkleProofTarget>,
    pub send_merkle_proofs: Vec<SendMerkleProofTarget>,
    pub tx_v2_indices: Vec<Target>,
    pub tx_v2_targets: Vec<TxV2Target>,
    pub tx_v2_merkle_proofs: Vec<TxV2MerkleProofTarget>,
    pub channel_action_indices: Vec<Target>,
    pub channel_action_targets: Vec<ChannelActionTarget>,
    pub channel_action_merkle_proofs: Vec<ChannelActionMerkleProofTarget>,
    pub public_inputs: UpdateUserPublicInputsTarget,
    /// SPHINCS+ signature witness targets for each user slot.
    pub spx_sig_targets: Vec<SpxSigTargets>,
    /// Per-slot KeyTree records — see `UpdateUserTree::key_leaves` SECURITY TODO.
    pub key_leaf_targets: Vec<KeyLeafTarget>,
    /// Per-block IMSB signing message fields — see `UpdateUserTree::msg_fields`.
    pub msg_fields: SmallBlockMessageFieldsTarget,
}

impl UpdateUserTreeTarget {
    pub fn new<F, C, const D: usize>(builder: &mut CircuitBuilder<F, D>, num_users: u32) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let block_number = BlockNumberTarget::new(builder, true);
        let prev_block_hash_chain = Bytes32Target::new(builder, true);
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);

        let block = BlockTarget::new(builder, num_users, true);

        let prev_account_leaves = (0..num_users)
            .map(|_| ChannelLeafTarget::new(builder, true))
            .collect::<Vec<_>>();
        let user_merkle_proofs = (0..num_users)
            .map(|_| ChannelMerkleProofTarget::new(builder, CHANNEL_TREE_HEIGHT))
            .collect::<Vec<_>>();
        let send_merkle_proofs = (0..num_users)
            .map(|_| SendMerkleProofTarget::new(builder, SEND_TREE_HEIGHT))
            .collect::<Vec<_>>();
        let block_tx_root = block.tx_tree_root.to_hash_out(builder);
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());
        let tx_v2_indices = (0..num_users)
            .map(|_| {
                let index = builder.add_virtual_target();
                builder.range_check(index, TX_TREE_HEIGHT);
                index
            })
            .collect::<Vec<_>>();
        let tx_v2_targets = (0..num_users)
            .map(|_| TxV2Target::new(builder))
            .collect::<Vec<_>>();
        let tx_v2_merkle_proofs = (0..num_users)
            .map(|_| TxV2MerkleProofTarget::new(builder, TX_TREE_HEIGHT))
            .collect::<Vec<_>>();
        let channel_action_indices = (0..num_users)
            .map(|_| {
                let index = builder.add_virtual_target();
                builder.range_check(index, TX_TREE_HEIGHT);
                index
            })
            .collect::<Vec<_>>();
        let channel_action_targets = (0..num_users)
            .map(|_| ChannelActionTarget::new(builder, true))
            .collect::<Vec<_>>();
        let channel_action_merkle_proofs = (0..num_users)
            .map(|_| ChannelActionMerkleProofTarget::new(builder, TX_TREE_HEIGHT))
            .collect::<Vec<_>>();

        let new_block_hash_chain =
            block.hash_with_prev_hash::<F, C, D>(builder, prev_block_hash_chain.clone());

        let empty_send_leaf = SendLeafTarget::constant(builder, SendLeaf::empty_leaf());
        let mut account_tree_root = prev_account_tree_root.clone();

        // ── IMSB signing digest (detail2 §F-2), recomputed ONCE per block ──
        //
        // SECURITY: the `channel_id` and `tx_tree_root` preimage components are the block's
        // own targets, so the digest every member signature is verified over is structurally
        // bound to the tx root this circuit applies — a prover cannot verify a signature over
        // a different root.
        let msg_fields = SmallBlockMessageFieldsTarget::new(builder);
        let digest_channel_id =
            ChannelIdTarget::from_parts(builder, block.channel_id(), true).value;
        let signed_digest = msg_fields.compute_signing_digest::<F, C, D>(
            builder,
            digest_channel_id,
            &block.tx_tree_root,
        );
        // detail2 §C-2: H2 = 0 is reserved for in-channel updates; precompute the zero check
        // once and enforce it per slot whenever a signature is applied.
        let tx_tree_root_is_zero = block.tx_tree_root.is_zero::<F, D, Bytes32>(builder);

        let mut spx_sig_targets: Vec<SpxSigTargets> = Vec::with_capacity(num_users as usize);
        let mut key_leaf_targets: Vec<KeyLeafTarget> = Vec::with_capacity(num_users as usize);

        for i in 0..(num_users as usize) {
            let key_id = block.key_ids[i];
            let prev_user_leaf = &prev_account_leaves[i];
            let user_merkle_proof = &user_merkle_proofs[i];
            let send_merkle_proof = &send_merkle_proofs[i];
            let tx_v2_index = tx_v2_indices[i];
            let tx_v2 = &tx_v2_targets[i];
            let tx_v2_merkle_proof = &tx_v2_merkle_proofs[i];
            let channel_action_index = channel_action_indices[i];
            let channel_action = &channel_action_targets[i];
            let channel_action_merkle_proof = &channel_action_merkle_proofs[i];
            // Two-layer identity: the channel-tree index is the channel id alone; key_id is the
            // member identity inside the channel (used for the SPHINCS+ message only).
            let channel_id = ChannelIdTarget::from_parts(builder, block.channel_id(), true).value;

            let zero = builder.zero();
            let is_dummy = builder.is_equal(key_id, zero);
            let should_check_account = builder.not(is_dummy);

            let current_root = account_tree_root.clone();
            let prev_root =
                user_merkle_proof.get_root::<F, C, D>(builder, prev_user_leaf, channel_id);
            current_root.conditional_assert_eq(builder, prev_root, should_check_account);

            let prev_matches_block = prev_user_leaf.prev.is_equal(builder, &block_number);
            let prev_differs = builder.not(prev_matches_block);
            let should_update = builder.and(should_check_account, prev_differs);

            let bound_tx_root = tx_v2_merkle_proof.get_root::<F, C, D>(builder, tx_v2, tx_v2_index);
            block_tx_root.conditional_assert_eq(builder, bound_tx_root, should_update);

            let user_transfer_class =
                builder.constant(F::from_canonical_u32(TxClass::UserTransfer.as_u32()));
            let channel_action_class =
                builder.constant(F::from_canonical_u32(TxClass::ChannelAction.as_u32()));
            let is_user_transfer = builder.is_equal(tx_v2.tx_class, user_transfer_class);
            let is_channel_action = builder.is_equal(tx_v2.tx_class, channel_action_class);
            let valid_tx_class = builder.or(is_user_transfer, is_channel_action);
            let should_check_user_transfer = builder.and(should_update, is_user_transfer);
            let should_check_channel_action = builder.and(should_update, is_channel_action);
            builder.conditional_assert_eq(
                should_update.target,
                valid_tx_class.target,
                should_update.target,
            );

            zero_hash.conditional_assert_eq(
                builder,
                tx_v2.channel_action_root.clone(),
                should_check_user_transfer,
            );
            zero_hash.conditional_assert_eq(
                builder,
                tx_v2.transfer_tree_root.clone(),
                should_check_channel_action,
            );

            let bound_channel_action_root = channel_action_merkle_proof.get_root::<F, C, D>(
                builder,
                channel_action,
                channel_action_index,
            );
            tx_v2.channel_action_root.conditional_assert_eq(
                builder,
                bound_channel_action_root,
                should_check_channel_action,
            );
            builder.conditional_assert_eq(
                should_check_channel_action.target,
                channel_action.source_channel_id.value,
                channel_id,
            );

            send_merkle_proof.conditional_verify::<F, C, D>(
                builder,
                should_update,
                &empty_send_leaf,
                prev_user_leaf.index,
                prev_user_leaf.send_tree_root.clone(),
            );

            let new_send_leaf = SendLeafTarget {
                prev: prev_user_leaf.prev.clone(),
                cur: block_number.clone(),
                tx_tree_root: block.tx_tree_root.clone(),
            };
            let new_send_tree_root = send_merkle_proof.get_root::<F, C, D>(
                builder,
                &new_send_leaf,
                prev_user_leaf.index,
            );

            let next_index = builder.add_const(prev_user_leaf.index, F::ONE);
            let new_user_leaf = ChannelLeafTarget {
                index: next_index,
                prev: block_number.clone(),
                send_tree_root: new_send_tree_root.clone(),
                // member_key_ids_root preserved unchanged across state transitions
                member_key_ids_root: prev_user_leaf.member_key_ids_root.clone(),
            };

            let updated_root =
                user_merkle_proof.get_root::<F, C, D>(builder, &new_user_leaf, channel_id);

            account_tree_root =
                PoseidonHashOutTarget::select(builder, should_update, updated_root, current_root);

            // ── SPHINCS+ signature verification ────────────────────────────
            //
            // For each active key slot whose KeyLeaf.pk_set_root is non-zero we verify that:
            //   1. Poseidon(pub_seed || root) == key_leaf.pk_set_root (for single-sig
            //      compatibility; multi-sig uses signature_aggregation circuit). Two-layer
            //      identity: the pk set data lives in the per-keyID KeyLeaf (KeyTree), no longer in
            //      the ChannelLeaf.
            //   2. The SPHINCS+ signature is valid over the IMSB digest M =
            //      SmallBlockRootMessage::signing_digest() recomputed above from the block's
            //      channel_id / tx_tree_root targets (detail2 §F-2). All members of the block sign
            //      the SAME digest.
            //
            // When key_leaf.pk_set_root == 0 (keyID has no registered key set yet) the
            // signature constraints are skipped — dummy witnesses are accepted.
            // For padding slots (should_update=false) constraints are also skipped.
            //
            // SECURITY: TODO — `key_leaf` is not yet bound to the on-chain-bound KeyTree at
            // index key_id, nor is key_id bound to prev_user_leaf.member_key_ids_root (see
            // `UpdateUserTree::key_leaves` doc; tasks/channel-key-tree-design.md §3 / §6.4).
            let key_leaf = KeyLeafTarget::new(builder, true);

            // -- Compute should_verify_sig = should_update AND has_pk_set --
            // Only enforce SPHINCS+ when the keyID has a registered key set.
            let should_verify_sig = {
                let zero = builder.zero();
                let e = &key_leaf.pk_set_root.elements;
                let z0 = builder.is_equal(e[0], zero);
                let z1 = builder.is_equal(e[1], zero);
                let z2 = builder.is_equal(e[2], zero);
                let z3 = builder.is_equal(e[3], zero);
                let all_zero_01 = builder.and(z0, z1);
                let all_zero_012 = builder.and(all_zero_01, z2);
                let all_zero = builder.and(all_zero_012, z3);
                let has_pk_set = builder.not(all_zero);
                builder.and(should_update, has_pk_set)
            };

            // SECURITY (detail2 §C-2): tx_tree_root != 0 whenever a member signature is
            // applied — H2 = 0 is reserved for in-channel updates and must never be signed
            // into a base block.
            builder.conditional_assert_eq(
                should_verify_sig.target,
                tx_tree_root_is_zero.target,
                zero,
            );

            // -- Allocate virtual targets for PK and signature components --
            let pub_seed_gl: [_; 2] = std::array::from_fn(|_| builder.add_virtual_target());
            let pub_root_gl: [_; 2] = std::array::from_fn(|_| builder.add_virtual_target());
            let r_gl: [_; 2] = std::array::from_fn(|_| builder.add_virtual_target());
            let fors_sig_gl = builder.add_virtual_targets(SPX_FORS_SIG_GL_LEN);
            let ht_sig_gls: Vec<Vec<_>> = (0..SPX_D)
                .map(|_| builder.add_virtual_targets(SPX_WOTS_SIG_GL_LEN))
                .collect();
            let ht_auth_gls: Vec<Vec<_>> = (0..SPX_D)
                .map(|_| builder.add_virtual_targets(SPX_AUTH_GL_LEN))
                .collect();

            // -- Verify pk_set_root stored in the keyID's KeyLeaf matches the provided PK --
            // NOTE: For single-sig compatibility, pk_set_root == Poseidon(pub_seed || pub_root).
            // For multi-sig, use the signature_aggregation circuit instead.
            let pk_inputs: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();
            let computed_pk_hash = PoseidonHashOutTarget::hash_inputs(builder, &pk_inputs);
            key_leaf.pk_set_root.conditional_assert_eq(
                builder,
                computed_pk_hash,
                should_verify_sig,
            );

            // -- Message: the 8 u32 limbs of the IMSB signing digest (detail2 §F-2) --
            let msg_gl: Vec<_> = signed_digest.to_vec();

            // pk_gl = pub_seed_gl || pub_root_gl (used in hash_message inside verify_circuit)
            let pk_gl: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();

            // -- Call verify_circuit from sphincsplus-circuits --
            let spx_witness = SpxVerifyWitness {
                pub_seed_gl,
                pub_root_gl,
                r_gl,
                pk_gl,
                msg_gl,
                fors_sig_gl: fors_sig_gl.clone(),
                ht_sig_gl: ht_sig_gls.clone(),
                ht_auth_gl: ht_auth_gls.clone(),
            };
            let computed_root = verify_circuit(builder, &spx_witness);

            // -- Conditionally assert computed_root == pub_root_gl --
            // (only enforced when should_verify_sig is true)
            builder.conditional_assert_eq(
                should_verify_sig.target,
                computed_root[0],
                pub_root_gl[0],
            );
            builder.conditional_assert_eq(
                should_verify_sig.target,
                computed_root[1],
                pub_root_gl[1],
            );

            spx_sig_targets.push(SpxSigTargets {
                pub_seed_gl,
                pub_root_gl,
                r_gl,
                fors_sig_gl,
                ht_sig_gls,
                ht_auth_gls,
            });
            key_leaf_targets.push(key_leaf);
        }

        let public_inputs = UpdateUserPublicInputsTarget {
            block_number: block_number.clone(),
            block_timestamp: block.timestamp.clone(),
            prev_block_hash_chain: prev_block_hash_chain.clone(),
            prev_account_tree_root: prev_account_tree_root.clone(),
            new_block_hash_chain,
            new_account_tree_root: account_tree_root.clone(),
            deposit_hash_chain: block.deposit_hash_chain.clone(),
        };

        Self {
            block_number,
            prev_block_hash_chain,
            prev_account_tree_root,
            block,
            prev_account_leaves,
            user_merkle_proofs,
            send_merkle_proofs,
            tx_v2_indices,
            tx_v2_targets,
            tx_v2_merkle_proofs,
            channel_action_indices,
            channel_action_targets,
            channel_action_merkle_proofs,
            public_inputs,
            spx_sig_targets,
            key_leaf_targets,
            msg_fields,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdateUserTree,
    ) {
        self.block_number.set_witness(witness, value.block_number);
        self.prev_block_hash_chain
            .set_witness(witness, value.prev_block_hash_chain);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.block.set_witness(witness, &value.block);

        for (target, leaf) in self
            .prev_account_leaves
            .iter()
            .zip(value.prev_account_leaves.iter())
        {
            target.set_witness(witness, leaf);
        }
        for (target, proof) in self
            .user_merkle_proofs
            .iter()
            .zip(value.user_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }
        for (target, proof) in self
            .send_merkle_proofs
            .iter()
            .zip(value.send_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }
        for (target, index) in self.tx_v2_indices.iter().zip(value.tx_v2_indices.iter()) {
            witness.set_target(*target, F::from_canonical_u64(*index));
        }
        for (target, tx_v2) in self.tx_v2_targets.iter().zip(value.tx_v2s.iter()) {
            target.set_witness(witness, *tx_v2);
        }
        for (target, proof) in self
            .tx_v2_merkle_proofs
            .iter()
            .zip(value.tx_v2_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }
        for (target, index) in self
            .channel_action_indices
            .iter()
            .zip(value.channel_action_indices.iter())
        {
            witness.set_target(*target, F::from_canonical_u64(*index));
        }
        for (target, action) in self
            .channel_action_targets
            .iter()
            .zip(value.channel_actions.iter())
        {
            target.set_witness(witness, *action);
        }
        for (target, proof) in self
            .channel_action_merkle_proofs
            .iter()
            .zip(value.channel_action_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }

        // Set SPHINCS+ signature witnesses
        for (target, sig) in self.spx_sig_targets.iter().zip(value.sig_witnesses.iter()) {
            target.set_witness(witness, sig);
        }

        // Set per-slot KeyTree records
        for (target, key_leaf) in self.key_leaf_targets.iter().zip(value.key_leaves.iter()) {
            target.set_witness(witness, key_leaf);
        }

        // Set per-block IMSB signing message fields
        self.msg_fields.set_witness(witness, &value.msg_fields);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UpdateUserCircuitError {
    #[error("Update user tree error: {0}")]
    TreeError(#[from] UpdateUserTreeError),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

pub struct UpdateUserCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub num_users: u32,
    pub data: CircuitData<F, C, D>,
    pub target: UpdateUserTreeTarget,
    pub public_inputs: UpdateUserPublicInputsTarget,
}

impl<F, C, const D: usize> UpdateUserCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(num_users: u32) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = UpdateUserTreeTarget::new::<F, C, D>(&mut builder, num_users);
        let public_inputs = target.public_inputs.clone();
        builder.register_public_inputs(&public_inputs.to_vec());

        // add constant gates to enable conditional verification
        add_const_gate(&mut builder);

        let data = builder.build();

        Self {
            num_users,
            data,
            target,
            public_inputs,
        }
    }

    pub fn prove(
        &self,
        witness: &UpdateUserTree,
    ) -> Result<ProofWithPublicInputs<F, C, D>, UpdateUserCircuitError> {
        let public_inputs = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, witness);
        self.public_inputs.set_witness(&mut pw, &public_inputs);
        self.data
            .prove(pw)
            .map_err(|e| UpdateUserCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::validity::block_hash_chain::sphincs_sig::SpxSigWitness,
        common::{
            block::Block,
            channel_id::ChannelId,
            trees::{
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                tx_v2_tree::{ChannelActionTree, TxV2Tree},
            },
            tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
            u63::BlockNumber,
        },
        ethereum_types::bytes32::Bytes32,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_update_user_tree_circuit() {
        let block_number = BlockNumber::new(20).unwrap();
        let channel_id = 5u32;
        let num_users = 2;

        let mut rng = StdRng::seed_from_u64(42);

        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        // Two-layer identity: the channel has a SINGLE leaf indexed by channel_id; the two
        // key_ids in the block are member identities of that one channel.
        let channel = ChannelId::new(channel_id as u64).unwrap();
        let mut send_tree = SendTree::init();
        // Set cur = block_number so that the channel leaf's prev == block_number.
        // This makes should_update = false → SPHINCS+ signature check is skipped.
        // A full signature test requires a SPHINCS+ signer (not yet implemented).
        let send_leaf_prev = SendLeaf {
            prev: BlockNumber::default(),
            cur: block_number, // already-at-current-block: no update triggered
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree.push(send_leaf_prev.clone());
        let prev_channel_leaf = ChannelLeaf {
            index: send_tree.len() as u32,
            prev: send_leaf_prev.cur,
            send_tree_root: send_tree.get_root(),
            member_key_ids_root: ChannelLeaf::default().member_key_ids_root,
        };

        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(channel.as_u64(), prev_channel_leaf.clone());

        let prev_account_tree_root = channel_tree.get_root();
        assert_eq!(channel_tree.get_leaf(channel.as_u64()), prev_channel_leaf);

        let timestamp = rng.next_u64();
        let block = Block::new(
            num_users,
            channel_id,
            &[1, 2],
            timestamp,
            tx_tree_root,
            deposit_hash_chain,
        )
        .unwrap();

        let send_proof = send_tree.prove(prev_channel_leaf.index.into());
        let dummy_user_leaf = ChannelLeaf::default();
        let dummy_user_merkle_proof = ChannelMerkleProof::dummy(CHANNEL_TREE_HEIGHT);
        let dummy_send_proof = SendMerkleProof::dummy(SEND_TREE_HEIGHT);

        // Both key slots reference the same (single) channel leaf.
        let mut prev_account_leaves = vec![prev_channel_leaf.clone(), prev_channel_leaf.clone()];
        prev_account_leaves.resize(num_users as usize, dummy_user_leaf);

        let mut send_merkle_proofs = vec![send_proof.clone(), send_proof.clone()];
        send_merkle_proofs.resize(num_users as usize, dummy_send_proof);

        let mut account_tree_for_proofs = channel_tree.clone();
        let mut user_merkle_proofs = Vec::with_capacity(num_users as usize);
        for (i, &key_id) in block.key_ids.iter().enumerate() {
            if key_id == 0 {
                user_merkle_proofs.push(dummy_user_merkle_proof.clone());
                continue;
            }
            let proof = account_tree_for_proofs.prove(channel.as_u64());
            user_merkle_proofs.push(proof);

            let prev_leaf = &prev_account_leaves[i];
            if prev_leaf.prev != block_number {
                let send_proof = &send_merkle_proofs[i];
                let new_send_leaf = SendLeaf {
                    prev: prev_leaf.prev,
                    cur: block_number,
                    tx_tree_root,
                };
                let new_send_root = send_proof.get_root(&new_send_leaf, prev_leaf.index.into());
                let new_user_leaf = ChannelLeaf {
                    index: prev_leaf.index + 1,
                    prev: block_number,
                    send_tree_root: new_send_root,
                    member_key_ids_root: prev_leaf.member_key_ids_root,
                };
                account_tree_for_proofs.update(channel.as_u64(), new_user_leaf);
            }
        }

        // Dummy signature witnesses for the test (no real SPHINCS+ keys needed)
        let sig_witnesses = vec![SpxSigWitness::dummy(); num_users as usize];
        // Default KeyLeaf (pk_set_root = 0) → signature constraints skipped.
        let key_leaves = vec![KeyLeaf::default(); num_users as usize];

        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves: prev_account_leaves.clone(),
            user_merkle_proofs: user_merkle_proofs.clone(),
            send_merkle_proofs: send_merkle_proofs.clone(),
            sig_witnesses,
            key_leaves,
            msg_fields: SmallBlockMessageFields::default(),
            tx_v2_indices: vec![0; num_users as usize],
            tx_v2s: vec![TxV2::default(); num_users as usize],
            tx_v2_merkle_proofs: vec![TxV2MerkleProof::dummy(TX_TREE_HEIGHT); num_users as usize],
            channel_action_indices: vec![0; num_users as usize],
            channel_actions: vec![ChannelAction::default(); num_users as usize],
            channel_action_merkle_proofs: vec![
                ChannelActionMerkleProof::dummy(TX_TREE_HEIGHT);
                num_users as usize
            ],
        };

        let public_inputs = update_channel_tree.to_public_inputs().unwrap();

        // user1 has prev == block_number → should_update = false → tree unchanged.
        // user2 also has prev == block_number → should_update = false → tree unchanged.
        let expected_tree = channel_tree.clone();

        assert_eq!(public_inputs.prev_account_tree_root, prev_account_tree_root);
        assert_eq!(
            public_inputs.new_account_tree_root,
            expected_tree.get_root()
        );
        assert_eq!(
            public_inputs.new_block_hash_chain,
            block.hash_with_prev_hash(prev_block_hash_chain).unwrap()
        );
        assert_eq!(public_inputs.deposit_hash_chain, block.deposit_hash_chain);

        let circuit = UpdateUserCircuit::<F, C, D>::new(num_users);
        let proof = circuit.prove(&update_channel_tree).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

        let expected_public_inputs: Vec<F> = public_inputs
            .to_u64_vec()
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();
        assert_eq!(proof.public_inputs, expected_public_inputs);
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_update_user_tree_binds_channel_action_to_source_account() {
        let block_number = BlockNumber::new(30).unwrap();
        let channel_id = 9u32;
        let key_id = 7u32;
        let num_users = 1;

        let mut rng = StdRng::seed_from_u64(99);
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        // Two-layer identity: channel-tree index = channel id alone.
        let channel = ChannelId::new(channel_id as u64).unwrap();
        let send_tree = SendTree::init();
        let prev_user_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::new(4).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_key_ids_root: ChannelLeaf::default().member_key_ids_root,
        };

        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(channel.as_u64(), prev_user_leaf.clone());
        let prev_account_tree_root = channel_tree.get_root();

        let channel_action = ChannelAction {
            kind: ChannelActionKind::InterChannelSend,
            source_channel_id: channel,
            destination_channel_id: ChannelId::new(10).unwrap(),
            tx_hash: Bytes32::rand(&mut rng),
            seal: Bytes32::rand(&mut rng),
            payload_hash: PoseidonHashOut::rand(&mut rng),
        };
        let mut channel_action_tree = ChannelActionTree::init();
        channel_action_tree.update(0, channel_action);
        let channel_action_proof = channel_action_tree.prove(0);

        let tx_v2 = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: PoseidonHashOut::default(),
            nonce: 1,
            channel_action_root: channel_action_tree.get_root(),
        };
        let mut tx_v2_tree = TxV2Tree::init();
        tx_v2_tree.update(0, tx_v2);
        let tx_v2_proof = tx_v2_tree.prove(0);

        let block = Block::new_with_tx_v2s(
            num_users,
            channel_id,
            &[key_id],
            rng.next_u64(),
            &[tx_v2],
            deposit_hash_chain,
        )
        .unwrap();

        let user_merkle_proof = channel_tree.prove(channel.as_u64());
        let send_merkle_proof = send_tree.prove(prev_user_leaf.index.into());

        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves: vec![prev_user_leaf.clone()],
            user_merkle_proofs: vec![user_merkle_proof],
            send_merkle_proofs: vec![send_merkle_proof],
            sig_witnesses: vec![SpxSigWitness::dummy()],
            // Default KeyLeaf (pk_set_root = 0) → signature constraints skipped.
            key_leaves: vec![KeyLeaf::default()],
            msg_fields: SmallBlockMessageFields::default(),
            tx_v2_indices: vec![0],
            tx_v2s: vec![tx_v2],
            tx_v2_merkle_proofs: vec![tx_v2_proof],
            channel_action_indices: vec![0],
            channel_actions: vec![channel_action],
            channel_action_merkle_proofs: vec![channel_action_proof],
        };

        let public_inputs = update_channel_tree.to_public_inputs().unwrap();
        let circuit = UpdateUserCircuit::<F, C, D>::new(num_users);
        let proof = circuit.prove(&update_channel_tree).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

        let expected_public_inputs: Vec<F> = public_inputs
            .to_u64_vec()
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();
        assert_eq!(proof.public_inputs, expected_public_inputs);
    }
}
