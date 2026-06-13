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
            key_tree::{MemberLeaf, MemberLeafTarget, MemberMerkleProof, MemberMerkleProofTarget},
            tx_v2_tree::{
                ChannelActionMerkleProof, ChannelActionMerkleProofTarget, TxV2MerkleProof,
                TxV2MerkleProofTarget,
            },
        },
        tx::{ChannelAction, ChannelActionKind, ChannelActionTarget, TxClass, TxV2, TxV2Target},
        u63::{BlockNumber, BlockNumberTarget, U63Target},
    },
    constants::{CHANNEL_TREE_HEIGHT, MEMBER_TREE_HEIGHT, SEND_TREE_HEIGHT, TX_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u64::{U64, U64_LEN, U64Target},
    },
    regev::{REGEV_N, REGEV_PK_POSEIDON_DOMAIN, RegevPk},
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

    // SPHINCS+ signature witnesses for each member slot (index matches key_ids/active slots).
    // Use SpxSigWitness::dummy() for inactive (zero) slots.
    pub sig_witnesses: Vec<SpxSigWitness>,

    // Per-slot MemberTree inclusion proofs binding the signing pubkey to the channel's members.
    // For active slot i, `member_merkle_proofs[i]` proves the leaf
    // `MemberLeaf { sphincs_pk_hash = Poseidon(pub_seed||pub_root), regev_pk_digest }` is at slot
    // i of `prev_account_leaves[i].member_pubkeys_root`.
    //
    // SECURITY: this closes the prior prover-choice hole. The pubkey fed to the SPHINCS+ verify
    // gadget is now committed at slot i of the channel's on-chain-bound member tree (the channel
    // leaf is itself proven in the account tree, ~670-673), so a signature can no longer be
    // verified under a pubkey of the prover's choosing.
    pub member_merkle_proofs: Vec<MemberMerkleProof>,
    // The Regev public key witnessed at each active slot; its Poseidon digest is the second leaf
    // component, so the member leaf binds BOTH the SPHINCS+ pubkey and the Regev pubkey.
    pub member_regev_pks: Vec<RegevPk>,

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
            || self.member_merkle_proofs.len() != self.block.num_users as usize
            || self.member_regev_pks.len() != self.block.num_users as usize
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

            // `should_update` is now true (active slot, prev != block_number). Bind the signing
            // pubkey to the channel's member tree at slot i.
            //
            // SECURITY: this is the native mirror of the in-circuit member binding. The signing
            // pubkey hash and the witnessed Regev pubkey form `MemberLeaf` and MUST be included at
            // slot i of the channel's trusted `member_pubkeys_root` (the channel leaf is itself
            // proven in the account tree above), closing the prover-choice hole.
            let sig = &self.sig_witnesses[i];
            let sphincs_pk_hash = PoseidonHashOut::hash_inputs_u64(&[
                sig.pk_gl[0],
                sig.pk_gl[1],
                sig.pk_gl[2],
                sig.pk_gl[3],
            ]);
            let regev_pk_digest = self.member_regev_pks[i].poseidon_digest();
            let member_leaf = MemberLeaf {
                sphincs_pk_hash,
                regev_pk_digest,
            };
            self.member_merkle_proofs[i]
                .verify(&member_leaf, i as u64, prev_user_leaf.member_pubkeys_root)
                .map_err(|e| {
                    UpdateUserTreeError::MerkleProofError(format!(
                        "failed to verify member merkle proof for slot {i}: {e}"
                    ))
                })?;

            // SECURITY (detail2 §C-2): tx_tree_root == 0 (H2 = 0) is reserved for in-channel
            // updates; a member signature must never be applied over it. Mirrors the in-circuit
            // `should_verify_sig → tx_tree_root != 0` constraint. `should_verify_sig ==
            // should_update` now, so this applies to every updating slot.
            if self.block.tx_tree_root == Bytes32::default() {
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
            // member_pubkeys_root preserved from previous leaf across state transitions
            let new_user_leaf = ChannelLeaf {
                index: prev_user_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
                member_pubkeys_root: prev_user_leaf.member_pubkeys_root,
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
    /// Per-slot MemberTree inclusion proof targets — bind the signing pubkey to the channel's
    /// member tree (closing the prover-choice hole; see `UpdateUserTree::member_merkle_proofs`).
    pub member_merkle_proof_targets: Vec<MemberMerkleProofTarget>,
    /// Per-slot witnessed Regev public-key coefficient targets (`a` then `b`, each `REGEV_N`).
    pub member_regev_pk_targets: Vec<Vec<Target>>,
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
        let mut member_merkle_proof_targets: Vec<MemberMerkleProofTarget> =
            Vec::with_capacity(num_users as usize);
        let mut member_regev_pk_targets: Vec<Vec<Target>> = Vec::with_capacity(num_users as usize);
        // Poseidon-digest domain for the Regev pubkey leaf component (mirrors
        // `RegevPk::poseidon_digest`).
        let regev_poseidon_domain =
            builder.constant(F::from_canonical_u64(REGEV_PK_POSEIDON_DOMAIN));
        let regev_n_const = builder.constant(F::from_canonical_u64(REGEV_N as u64));

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
                // member_pubkeys_root preserved unchanged across state transitions
                member_pubkeys_root: prev_user_leaf.member_pubkeys_root.clone(),
            };

            let updated_root =
                user_merkle_proof.get_root::<F, C, D>(builder, &new_user_leaf, channel_id);

            account_tree_root =
                PoseidonHashOutTarget::select(builder, should_update, updated_root, current_root);

            // ── SPHINCS+ signature verification + member-tree binding ──────────
            //
            // One SPHINCS+ key per member. For every updating slot (should_verify_sig ==
            // should_update) we:
            //   1. Allocate the witnessed pubkey targets and recompute sphincs_pk_hash =
            //      Poseidon(pub_seed || pub_root).
            //   2. Compute regev_pk_digest = Poseidon([IMRP, n, a…, b…]) over the witnessed Regev
            //      pubkey coefficients (mirrors `RegevPk::poseidon_digest`).
            //   3. Prove MemberLeaf{sphincs_pk_hash, regev_pk_digest} is included at slot i of the
            //      channel's `member_pubkeys_root` (prev_user_leaf, itself proven in the account
            //      tree above).
            //   4. Verify the SPHINCS+ signature over the SAME pub_seed/pub_root and the block's
            //      IMSB digest.
            //
            // SECURITY: step 3 binds the signing pubkey to slot i of the channel's on-chain-bound
            // member tree, closing the previous prover-choice hole — the prover can no longer feed
            // an arbitrary pubkey to verify_circuit. The channel leaf carrying member_pubkeys_root
            // is proven under account_tree_root, so the root is trusted, not prover-chosen.
            let should_verify_sig = should_update;

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

            // -- (1) sphincs_pk_hash = Poseidon(pub_seed || pub_root) --
            let pk_inputs: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();
            let sphincs_pk_hash = PoseidonHashOutTarget::hash_inputs(builder, &pk_inputs);

            // -- (2) regev_pk_digest = Poseidon([IMRP, n, a…, b…]) over witnessed Regev coeffs --
            let regev_pk_coeffs: Vec<Target> = builder.add_virtual_targets(2 * REGEV_N);
            // SECURITY: range-check each coefficient to 32 bits so a malicious witness cannot pack
            // a >2^32 value that aliases a canonical coefficient (digest malleability F1-A).
            for &c in &regev_pk_coeffs {
                builder.range_check(c, 32);
            }
            let regev_digest_inputs: Vec<Target> = [
                vec![regev_poseidon_domain, regev_n_const],
                regev_pk_coeffs.clone(),
            ]
            .concat();
            let regev_pk_digest = PoseidonHashOutTarget::hash_inputs(builder, &regev_digest_inputs);

            // -- (3) MemberLeaf slot-inclusion under the channel's member_pubkeys_root --
            let member_merkle_proof = MemberMerkleProofTarget::new(builder, MEMBER_TREE_HEIGHT);
            let member_leaf = MemberLeafTarget {
                sphincs_pk_hash: sphincs_pk_hash.clone(),
                regev_pk_digest,
            };
            let slot_index = builder.constant(F::from_canonical_u64(i as u64));
            member_merkle_proof.conditional_verify::<F, C, D>(
                builder,
                should_verify_sig,
                &member_leaf,
                slot_index,
                prev_user_leaf.member_pubkeys_root.clone(),
            );

            // -- Message: the 8 u32 limbs of the IMSB signing digest (detail2 §F-2) --
            let msg_gl: Vec<_> = signed_digest.to_vec();

            // pk_gl = pub_seed_gl || pub_root_gl (used in hash_message inside verify_circuit)
            let pk_gl: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();

            // -- (4) Call verify_circuit from sphincsplus-circuits --
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
            member_merkle_proof_targets.push(member_merkle_proof);
            member_regev_pk_targets.push(regev_pk_coeffs);
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
            member_merkle_proof_targets,
            member_regev_pk_targets,
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

        // Set per-slot MemberTree inclusion proofs.
        for (target, proof) in self
            .member_merkle_proof_targets
            .iter()
            .zip(value.member_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }

        // Set per-slot Regev pubkey coefficient witnesses (a then b), mirroring the
        // `RegevPk::poseidon_digest` preimage order.
        for (targets, pk) in self
            .member_regev_pk_targets
            .iter()
            .zip(value.member_regev_pks.iter())
        {
            assert_eq!(targets.len(), pk.a.len() + pk.b.len());
            for (t, &c) in targets.iter().zip(pk.a.iter().chain(pk.b.iter())) {
                witness.set_target(*t, F::from_canonical_u32(c));
            }
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
        circuits::{
            test_utils::sphincs_sign::{
                SpxKeyPair, pk_hash_from_pk_bytes, sphincs_keygen, sphincs_sign,
            },
            validity::block_hash_chain::sphincs_sig::SpxSigWitness,
        },
        common::{
            block::Block,
            channel::SmallBlockRootMessage,
            channel_id::ChannelId,
            trees::{
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                key_tree::{MemberLeaf, MemberTree},
                tx_v2_tree::{ChannelActionTree, TxV2Tree},
            },
            tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
            u63::BlockNumber,
        },
        ethereum_types::bytes32::Bytes32,
        regev::RegevPk,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    /// A distinct canonical Regev pubkey of the correct length, derived deterministically.
    fn regev_pk(seed: u32) -> RegevPk {
        use crate::regev::{REGEV_N, REGEV_Q};
        RegevPk {
            a: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
                .collect(),
            b: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

    fn dummy_regev_pk() -> RegevPk {
        use crate::regev::REGEV_N;
        RegevPk {
            a: vec![0u32; REGEV_N],
            b: vec![0u32; REGEV_N],
        }
    }

    /// Build the 8-byte-per-limb little-endian message bytes the native signer consumes from the
    /// 8-u32-limb IMSB signing digest (mirrors `BlockHashChainProcessor` / sphincs_sig).
    fn msg_bytes_from_digest(digest: Bytes32) -> Vec<u8> {
        digest
            .to_u32_vec()
            .into_iter()
            .flat_map(|limb| (limb as u64).to_le_bytes())
            .collect()
    }

    /// Build a `SpxSigWitness` + matching `MemberLeaf` for a real key pair signing `msg_digest`.
    fn signed_member(
        kp: &SpxKeyPair,
        msg_digest: Bytes32,
        regev: &RegevPk,
    ) -> (SpxSigWitness, MemberLeaf) {
        let sig = sphincs_sign(&msg_bytes_from_digest(msg_digest), kp);
        let witness = SpxSigWitness::from_bytes(&kp.pk_bytes, &sig);
        let leaf = MemberLeaf {
            sphincs_pk_hash: pk_hash_from_pk_bytes(&kp.pk_bytes),
            regev_pk_digest: regev.poseidon_digest(),
        };
        (witness, leaf)
    }

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
            member_pubkeys_root: ChannelLeaf::default().member_pubkeys_root,
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
                    member_pubkeys_root: prev_leaf.member_pubkeys_root,
                };
                account_tree_for_proofs.update(channel.as_u64(), new_user_leaf);
            }
        }

        // Dummy signature witnesses for the test (no real SPHINCS+ keys needed — every slot is
        // non-updating, so the binding + signature constraints are skipped).
        let sig_witnesses = vec![SpxSigWitness::dummy(); num_users as usize];
        let member_merkle_proofs =
            vec![MemberMerkleProof::dummy(MEMBER_TREE_HEIGHT); num_users as usize];
        let member_regev_pks = vec![dummy_regev_pk(); num_users as usize];

        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves: prev_account_leaves.clone(),
            user_merkle_proofs: user_merkle_proofs.clone(),
            send_merkle_proofs: send_merkle_proofs.clone(),
            sig_witnesses,
            member_merkle_proofs,
            member_regev_pks,
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
        // Build the channel's member tree: this active slot's member at slot 0, plus two other
        // members. The leaf binds the signer's SPHINCS+ pubkey hash + Regev pubkey digest.
        let signer_kp = sphincs_keygen([0x11; 16], [0x22; 16], [0x33; 16]);
        let signer_regev = regev_pk(1);
        let signer_leaf = MemberLeaf {
            sphincs_pk_hash: pk_hash_from_pk_bytes(&signer_kp.pk_bytes),
            regev_pk_digest: signer_regev.poseidon_digest(),
        };
        let mut member_tree = MemberTree::init();
        member_tree.push(signer_leaf.clone()); // slot 0 = signer
        member_tree.push(MemberLeaf {
            sphincs_pk_hash: PoseidonHashOut::hash_inputs_u64(&[2, 2, 2, 2]),
            regev_pk_digest: regev_pk(2).poseidon_digest(),
        });
        member_tree.push(MemberLeaf {
            sphincs_pk_hash: PoseidonHashOut::hash_inputs_u64(&[3, 3, 3, 3]),
            regev_pk_digest: regev_pk(3).poseidon_digest(),
        });
        let member_pubkeys_root = member_tree.get_root();

        let prev_user_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::new(4).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_pubkeys_root,
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
        let member_merkle_proof = member_tree.prove(0); // signer is at slot 0

        // The signer signs the block's IMSB digest (channel_id + block tx_tree_root + msg fields).
        let bp_sphincs_pubkey_hash: Bytes32 = signer_leaf.sphincs_pk_hash.into();
        let msg_fields = SmallBlockMessageFields {
            bp_member_slot: 0,
            bp_sphincs_pubkey_hash,
            small_block_number: 0,
            prev_small_block_root: Bytes32::default(),
            state_commitment_root: Bytes32::default(),
            medium_epoch_hint: 0,
            close_freeze_nonce: 0,
        };
        let signed_digest = msg_fields.signing_digest(channel_id, block.tx_tree_root);
        let (sig_witness, leaf_check) = signed_member(&signer_kp, signed_digest, &signer_regev);
        assert_eq!(leaf_check, signer_leaf, "member leaf must match the signer");

        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves: vec![prev_user_leaf.clone()],
            user_merkle_proofs: vec![user_merkle_proof],
            send_merkle_proofs: vec![send_merkle_proof],
            sig_witnesses: vec![sig_witness],
            member_merkle_proofs: vec![member_merkle_proof],
            member_regev_pks: vec![signer_regev.clone()],
            msg_fields,
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

    /// SECURITY (the soundness binding fix): a signature by a pubkey that is NOT in the channel's
    /// member tree must be REJECTED. Here the signer's real key pair is valid, but the member tree
    /// at slot 0 carries a DIFFERENT pubkey hash — so the in-circuit member inclusion proof against
    /// the channel's trusted `member_pubkeys_root` fails, and proof generation must error. This
    /// directly demonstrates that the prior prover-choice hole (any pubkey accepted) is closed.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn update_user_tree_rejects_pubkey_not_in_member_tree() {
        let block_number = BlockNumber::new(30).unwrap();
        let channel_id = 9u32;
        let key_id = 7u32;
        let num_users = 1;

        let mut rng = StdRng::seed_from_u64(123);
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        let channel = ChannelId::new(channel_id as u64).unwrap();
        let send_tree = SendTree::init();

        // The REAL signer.
        let signer_kp = sphincs_keygen([0x44; 16], [0x55; 16], [0x66; 16]);
        let signer_regev = regev_pk(7);

        // The member tree at slot 0 holds an ATTACKER/other pubkey hash, NOT the signer's. This is
        // the wrong-leaf case: the signer's pubkey is absent from the channel's members.
        let mut member_tree = MemberTree::init();
        member_tree.push(MemberLeaf {
            sphincs_pk_hash: PoseidonHashOut::hash_inputs_u64(&[9, 9, 9, 9]),
            regev_pk_digest: regev_pk(8).poseidon_digest(),
        });
        member_tree.push(MemberLeaf {
            sphincs_pk_hash: PoseidonHashOut::hash_inputs_u64(&[10, 10, 10, 10]),
            regev_pk_digest: regev_pk(9).poseidon_digest(),
        });
        member_tree.push(MemberLeaf {
            sphincs_pk_hash: PoseidonHashOut::hash_inputs_u64(&[11, 11, 11, 11]),
            regev_pk_digest: regev_pk(10).poseidon_digest(),
        });
        let member_pubkeys_root = member_tree.get_root();

        let prev_user_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::new(4).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_pubkeys_root,
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
        // The signer presents a proof for slot 0 against the (attacker) member root.
        let member_merkle_proof = member_tree.prove(0);

        let bp_sphincs_pubkey_hash: Bytes32 = pk_hash_from_pk_bytes(&signer_kp.pk_bytes).into();
        let msg_fields = SmallBlockMessageFields {
            bp_member_slot: 0,
            bp_sphincs_pubkey_hash,
            small_block_number: 0,
            prev_small_block_root: Bytes32::default(),
            state_commitment_root: Bytes32::default(),
            medium_epoch_hint: 0,
            close_freeze_nonce: 0,
        };
        let signed_digest = msg_fields.signing_digest(channel_id, block.tx_tree_root);
        let (sig_witness, _leaf) = signed_member(&signer_kp, signed_digest, &signer_regev);

        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block,
            prev_account_leaves: vec![prev_user_leaf],
            user_merkle_proofs: vec![user_merkle_proof],
            send_merkle_proofs: vec![send_merkle_proof],
            sig_witnesses: vec![sig_witness],
            member_merkle_proofs: vec![member_merkle_proof],
            member_regev_pks: vec![signer_regev],
            msg_fields,
            tx_v2_indices: vec![0],
            tx_v2s: vec![tx_v2],
            tx_v2_merkle_proofs: vec![tx_v2_proof],
            channel_action_indices: vec![0],
            channel_actions: vec![channel_action],
            channel_action_merkle_proofs: vec![channel_action_proof],
        };

        // Native witness building already rejects: the member leaf (signer's pubkey) is not in the
        // attacker member tree at slot 0, so `to_public_inputs` fails the inclusion check.
        assert!(
            matches!(
                update_channel_tree.to_public_inputs(),
                Err(UpdateUserTreeError::MerkleProofError(_))
            ),
            "a signature by a pubkey absent from the channel member tree must be rejected"
        );

        // And the circuit itself is unsatisfiable for this witness (the in-circuit member
        // inclusion proof under the trusted root cannot be satisfied), so proving must error.
        let circuit = UpdateUserCircuit::<F, C, D>::new(num_users);
        assert!(
            circuit.prove(&update_channel_tree).is_err(),
            "circuit must reject the out-of-tree pubkey signature"
        );
    }
}
