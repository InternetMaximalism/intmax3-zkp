use crate::{
    circuits::validity::block_hash_chain::sphincs_sig::{
        SmallBlockMessageFields, SmallBlockMessageFieldsTarget,
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
    poseidon_sig::list::{leaf_target, list_chain_step, list_leaf, chain_step_target},
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
    /// The block's `channel_reg_hash_chain` (folded into the block hash, G6). Surfaced here so
    /// block_step can constrain the block-hash-committed reg chain to equal the value the
    /// channel-reg proof consumed (= the new ext-state channel_reg_hash_chain).
    pub channel_reg_hash_chain: Bytes32,
    /// P2b: the block-producer IMSB-signature list accumulator BEFORE this block. block_step
    /// constrains it equal to the previous ext-state `bp_sig_chain`.
    pub prev_bp_sig_chain: Bytes32,
    /// P2b: the accumulator AFTER folding this block's bp `(IMSB_digest, bp_pk_g)` pair — equal to
    /// `prev_bp_sig_chain` on a non-signing block, advanced by one Poseidon chain step on a signing
    /// (base) block. Becomes the new ext-state `bp_sig_chain`.
    pub new_bp_sig_chain: Bytes32,
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

    // P2b: the bp IMSB-signature list accumulator BEFORE this block (`Bytes32::default()` at the
    // validity span's genesis). The block folds the bp's `(IMSB_digest, bp_pk_g)` pair onto it when
    // a member signature is applied; the resulting value is surfaced as `new_bp_sig_chain`.
    pub prev_bp_sig_chain: Bytes32,

    // Per-slot MemberTree inclusion proofs binding the bp's signing pubkey to the channel's members.
    // For the updating bp slot i, `member_merkle_proofs[i]` proves the leaf
    // `MemberLeaf { pk_g = msg_fields.bp_pk_g, regev_pk_digest }` is at slot i of
    // `prev_account_leaves[i].member_pubkeys_root`.
    //
    // SECURITY: this binds the folded `bp_pk_g` to slot i of the channel's on-chain-bound member
    // tree (the channel leaf is itself proven in the account tree), so the `(IMSB_digest, bp_pk_g)`
    // pair folded into `bp_sig_chain` cannot use a prover-chosen pubkey — it is a registered member.
    pub member_merkle_proofs: Vec<MemberMerkleProof>,
    // The Regev public key witnessed at each active slot; its Poseidon digest is the third leaf
    // component, so the member leaf binds `pk_g`, `pk_b` AND the Regev pubkey.
    pub member_regev_pks: Vec<RegevPk>,
    // The member's BabyBear hash-sig public key (`pk_b`) witnessed at each active slot (P3). The
    // 3-field `MemberLeaf{pk_g, pk_b, regev_pk}` inclusion requires it so the rebuilt
    // `member_pubkeys_root` matches the registration leaf (which now commits `pk_b`). `pk_b` is NOT
    // part of the IMSB signing digest — that signature is the Goldilocks list-proof, unchanged.
    pub member_pk_bs: Vec<PoseidonHashOut>,

    // Per-block IMSB `SmallBlockRootMessage` preimage fields (detail2 §F-2). The signing
    // digest is recomputed in-circuit from these fields with the `channel_id` and
    // `tx_tree_root` components taken from the block targets. `msg_fields.bp_pk_g` IS the member
    // identity whose slot inclusion is proven and whose `(digest, pk_g)` pair is folded into the
    // bp_sig_chain — the actual signature is verified by the recursive `ListCircuit` proof the
    // validity circuit consumes (P2b, decision D3), not here.
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
            || self.member_pk_bs.len() != self.block.num_users as usize
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
        // P2b: the bp IMSB-signature list accumulator, folded once for the signing (bp) slot.
        let mut bp_sig_chain = self.prev_bp_sig_chain;
        // The IMSB signing digest the bp signs (recomputed from msg_fields, same as in-circuit).
        let signed_digest = self
            .msg_fields
            .signing_digest(channel_id, self.block.tx_tree_root);
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

            // `should_update` is now true (active slot, prev != block_number). This is the signing
            // (bp) slot; bind its `bp_pk_g` to the channel's member tree at slot i and fold the
            // `(IMSB_digest, bp_pk_g)` pair into the bp_sig_chain accumulator.
            //
            // SECURITY: the updating slot MUST be the declared bp slot (`msg_fields.bp_member_slot`).
            // Only one slot updates per block (all slots reference the same channel leaf), so this
            // ties the folded bp identity to the slot that actually transitioned.
            if self.msg_fields.bp_member_slot as usize != i {
                return Err(UpdateUserTreeError::InvalidLength(format!(
                    "updating slot {i} must equal msg_fields.bp_member_slot {}",
                    self.msg_fields.bp_member_slot
                )));
            }
            // SECURITY: the member identity is `msg_fields.bp_pk_g` — the SAME value bound into the
            // IMSB signing digest above. Reusing it for the member-leaf inclusion and the chain fold
            // is what binds the folded pair to a registered member at slot i.
            let bp_pk_g = self.msg_fields.bp_pk_g;
            let pk_g: PoseidonHashOut = bp_pk_g
                .try_into()
                .map_err(|e| UpdateUserTreeError::InvalidLength(format!(
                    "bp_pk_g is not a canonical Poseidon hash out: {e}"
                )))?;
            let regev_pk_digest = self.member_regev_pks[i].poseidon_digest();
            let member_leaf = MemberLeaf {
                pk_g,
                pk_b: self.member_pk_bs[i],
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
            // `should_verify_sig → tx_tree_root != 0` constraint.
            if self.block.tx_tree_root == Bytes32::default() {
                return Err(UpdateUserTreeError::InvalidLength(format!(
                    "tx_tree_root must be nonzero when a member signature is applied (slot {i}; H2=0 is reserved for in-channel updates)"
                )));
            }

            // P2b: fold `(IMSB_digest, bp_pk_g)` into the bp_sig_chain (order-sensitive Poseidon
            // chain, `poseidon_sig::list`). The matching `ListCircuit` proof — consumed by the
            // validity circuit — proves each folded pair was a verified Poseidon single-sig.
            let prev_chain: PoseidonHashOut = bp_sig_chain
                .try_into()
                .map_err(|e| UpdateUserTreeError::InvalidLength(format!(
                    "bp_sig_chain is not a canonical Poseidon hash out: {e}"
                )))?;
            let leaf = list_leaf(signed_digest, bp_pk_g);
            bp_sig_chain = list_chain_step(prev_chain, leaf).into();

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
            channel_reg_hash_chain: self.block.channel_reg_hash_chain,
            prev_bp_sig_chain: self.prev_bp_sig_chain,
            new_bp_sig_chain: bp_sig_chain,
        })
    }
}

// block_number(1) + block_timestamp(U64_LEN) + prev_block_hash_chain + prev_account_tree_root
// + new_block_hash_chain + new_account_tree_root + deposit_hash_chain + channel_reg_hash_chain
// + prev_bp_sig_chain + new_bp_sig_chain
const UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN: usize =
    1 + U64_LEN + 6 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN;

impl UpdateUserPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut result = vec![self.block_number.as_u64()];
        result.extend(U64::from(self.block_timestamp).to_u64_vec());
        result.extend(self.prev_block_hash_chain.to_u64_vec());
        result.extend(self.prev_account_tree_root.to_u64_vec());
        result.extend(self.new_block_hash_chain.to_u64_vec());
        result.extend(self.new_account_tree_root.to_u64_vec());
        result.extend(self.deposit_hash_chain.to_u64_vec());
        result.extend(self.channel_reg_hash_chain.to_u64_vec());
        result.extend(self.prev_bp_sig_chain.to_u64_vec());
        result.extend(self.new_bp_sig_chain.to_u64_vec());
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
        cursor += BYTES32_LEN;

        let channel_reg_hash_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;
        cursor += BYTES32_LEN;

        let prev_bp_sig_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;
        cursor += BYTES32_LEN;

        let new_bp_sig_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateUserTreeError::InvalidLength(e.to_string()))?;

        Ok(Self {
            block_number,
            block_timestamp: u64::from(block_timestamp),
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
            prev_bp_sig_chain,
            new_bp_sig_chain,
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
    pub channel_reg_hash_chain: Bytes32Target,
    pub prev_bp_sig_chain: Bytes32Target,
    pub new_bp_sig_chain: Bytes32Target,
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
        let channel_reg_hash_chain = Bytes32Target::new(builder, is_checked);
        let prev_bp_sig_chain = Bytes32Target::new(builder, is_checked);
        let new_bp_sig_chain = Bytes32Target::new(builder, is_checked);
        Self {
            block_number,
            block_timestamp,
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
            prev_bp_sig_chain,
            new_bp_sig_chain,
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
            self.channel_reg_hash_chain.to_vec(),
            self.prev_bp_sig_chain.to_vec(),
            self.new_bp_sig_chain.to_vec(),
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
        cursor += BYTES32_LEN;

        let channel_reg_hash_chain =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let prev_bp_sig_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let new_bp_sig_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);

        Self {
            block_number,
            block_timestamp,
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
            prev_bp_sig_chain,
            new_bp_sig_chain,
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
        self.channel_reg_hash_chain
            .set_witness(witness, value.channel_reg_hash_chain);
        self.prev_bp_sig_chain
            .set_witness(witness, value.prev_bp_sig_chain);
        self.new_bp_sig_chain
            .set_witness(witness, value.new_bp_sig_chain);
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
            channel_reg_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.channel_reg_hash_chain.clone(),
                when_false.channel_reg_hash_chain.clone(),
            ),
            prev_bp_sig_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.prev_bp_sig_chain.clone(),
                when_false.prev_bp_sig_chain.clone(),
            ),
            new_bp_sig_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.new_bp_sig_chain.clone(),
                when_false.new_bp_sig_chain.clone(),
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
    /// P2b: the bp IMSB-signature list accumulator BEFORE this block (witnessed; surfaced as the
    /// `prev_bp_sig_chain` PI and folded into `new_bp_sig_chain`).
    pub prev_bp_sig_chain: Bytes32Target,
    /// Per-slot MemberTree inclusion proof targets — bind the bp's `pk_g` to the channel's member
    /// tree (the binding for the folded `(IMSB_digest, bp_pk_g)` pair; see
    /// `UpdateUserTree::member_merkle_proofs`).
    pub member_merkle_proof_targets: Vec<MemberMerkleProofTarget>,
    /// Per-slot witnessed Regev public-key coefficient targets (`a` then `b`, each `REGEV_N`).
    pub member_regev_pk_targets: Vec<Vec<Target>>,
    /// Per-slot witnessed `pk_b` (BabyBear hash-sig public key) targets — the third `MemberLeaf`
    /// component (P3). Bound into the leaf inclusion so the rebuilt `member_pubkeys_root` matches
    /// the registration leaf that now commits `pk_b`.
    pub member_pk_b_targets: Vec<PoseidonHashOutTarget>,
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

        // P2b: the bp IMSB-signature list accumulator. Witnessed `prev_bp_sig_chain`, folded once
        // (for the updating bp slot) into `bp_sig_chain` using the shared `poseidon_sig::list`
        // gadgets, then surfaced as `new_bp_sig_chain`.
        let prev_bp_sig_chain = Bytes32Target::new(builder, true);
        let mut bp_sig_chain = prev_bp_sig_chain.clone();
        // The bp's pk_g (Bytes32) — the SAME wire bound into the IMSB digest, the member-leaf
        // inclusion, and the chain fold.
        let bp_pk_g = msg_fields.bp_pk_g.clone();

        let mut member_merkle_proof_targets: Vec<MemberMerkleProofTarget> =
            Vec::with_capacity(num_users as usize);
        let mut member_regev_pk_targets: Vec<Vec<Target>> = Vec::with_capacity(num_users as usize);
        let mut member_pk_b_targets: Vec<PoseidonHashOutTarget> =
            Vec::with_capacity(num_users as usize);
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

            // ── P2b: bp member-tree binding + IMSB-signature chain fold ────────
            //
            // Exactly ONE IMSB signature per signing block — the block-producer's (decision D3/D5).
            // For the updating slot (which MUST be the declared bp slot) we:
            //   1. assert the updating slot equals `msg_fields.bp_member_slot` (ties the folded bp
            //      identity to the slot that actually transitioned — only one slot updates/block);
            //   2. compute regev_pk_digest = Poseidon([IMRP, n, a…, b…]) over the witnessed Regev
            //      pubkey coefficients (mirrors `RegevPk::poseidon_digest`);
            //   3. prove MemberLeaf{pk_g = bp_pk_g, regev_pk_digest} is included at slot i of the
            //      channel's `member_pubkeys_root` (prev_user_leaf, itself proven in the account
            //      tree above);
            //   4. fold `(signed_digest, bp_pk_g)` into the bp_sig_chain accumulator (shared
            //      `poseidon_sig::list` gadgets).
            //
            // SECURITY: step 3 binds the folded `bp_pk_g` to slot i of the channel's on-chain-bound
            // member tree, so the `(IMSB_digest, bp_pk_g)` pair folded into bp_sig_chain cannot use
            // a prover-chosen pubkey. The actual signature over `signed_digest` is proven by the
            // recursive `ListCircuit` proof the validity circuit consumes (D3) — it rebuilds the
            // SAME chain and verifies `C == final.bp_sig_chain`.
            let should_verify_sig = should_update;

            // SECURITY (detail2 §C-2): tx_tree_root != 0 whenever a member signature is
            // applied — H2 = 0 is reserved for in-channel updates and must never be signed
            // into a base block.
            builder.conditional_assert_eq(
                should_verify_sig.target,
                tx_tree_root_is_zero.target,
                zero,
            );

            // -- (1) the updating slot MUST be the declared bp slot --
            // SECURITY: ties the bp identity folded into the chain to the slot that actually
            // transitioned this block. Only one slot updates per block (all slots reference the
            // same channel leaf), so this is exact: a prover cannot update slot j while folding a
            // signature attributed to a different slot's member.
            // INVARIANT (single-fold soundness): this `bp_sig_chain` design folds AT MOST ONE
            // signature per block and assumes EXACTLY ONE channel-leaf transition per block. If the
            // block layout is ever changed to permit two distinct channel-leaf updates in one block,
            // the second signature would go unfolded — this loop must be revisited (fold per updating
            // leaf) before that change lands. (Flagged in the P2b security review.)
            let slot_index = builder.constant(F::from_canonical_u64(i as u64));
            builder.conditional_assert_eq(
                should_verify_sig.target,
                msg_fields.bp_member_slot,
                slot_index,
            );

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

            // -- (3) MemberLeaf{pk_g = bp_pk_g, regev_pk_digest} slot-inclusion --
            // SECURITY: `pk_g` is `bp_pk_g.to_hash_out()`, the SAME wire bound into the IMSB
            // signing digest and folded into the chain below. `to_hash_out` constrains bp_pk_g to a
            // canonical Poseidon-hash-out-derived Bytes32 (4 Goldilocks limbs each < p), matching
            // the registered member identity exactly.
            let bp_pk_g_hashout = bp_pk_g.to_hash_out(builder);
            // P3: witness the member's pk_b (BabyBear hash-sig public key) for the 3-field leaf.
            // It is a free Poseidon-hash-out witness here; its authenticity is enforced by the leaf
            // inclusion against `member_pubkeys_root`, which is bound to the L1 registration keccak
            // chain (the chain now commits pk_b, channel_reg_step R2 cross-binding).
            let member_pk_b = PoseidonHashOutTarget::new(builder);
            let member_merkle_proof = MemberMerkleProofTarget::new(builder, MEMBER_TREE_HEIGHT);
            let member_leaf = MemberLeafTarget {
                pk_g: bp_pk_g_hashout,
                pk_b: member_pk_b,
                regev_pk_digest,
            };
            member_merkle_proof.conditional_verify::<F, C, D>(
                builder,
                should_verify_sig,
                &member_leaf,
                slot_index,
                prev_user_leaf.member_pubkeys_root.clone(),
            );

            // -- (4) fold (signed_digest, bp_pk_g) into the bp_sig_chain accumulator --
            // SECURITY: identical `poseidon_sig::list` gadgets to the producer (`ListStepCircuit`)
            // and the consumer, so the chain the validity circuit rebuilds matches bit-for-bit.
            let leaf = leaf_target(builder, &signed_digest, &bp_pk_g);
            let prev_chain_hashout = bp_sig_chain.to_hash_out(builder);
            let new_chain_hashout = chain_step_target(builder, prev_chain_hashout, leaf);
            let new_chain = Bytes32Target::from_hash_out(builder, new_chain_hashout);
            bp_sig_chain =
                Bytes32Target::select(builder, should_verify_sig, new_chain, bp_sig_chain.clone());

            member_merkle_proof_targets.push(member_merkle_proof);
            member_regev_pk_targets.push(regev_pk_coeffs);
            member_pk_b_targets.push(member_pk_b);
        }

        let public_inputs = UpdateUserPublicInputsTarget {
            block_number: block_number.clone(),
            block_timestamp: block.timestamp.clone(),
            prev_block_hash_chain: prev_block_hash_chain.clone(),
            prev_account_tree_root: prev_account_tree_root.clone(),
            new_block_hash_chain,
            new_account_tree_root: account_tree_root.clone(),
            deposit_hash_chain: block.deposit_hash_chain.clone(),
            channel_reg_hash_chain: block.channel_reg_hash_chain.clone(),
            prev_bp_sig_chain: prev_bp_sig_chain.clone(),
            new_bp_sig_chain: bp_sig_chain.clone(),
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
            prev_bp_sig_chain,
            member_merkle_proof_targets,
            member_regev_pk_targets,
            member_pk_b_targets,
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

        // P2b: the bp IMSB-signature list accumulator before this block.
        self.prev_bp_sig_chain
            .set_witness(witness, value.prev_bp_sig_chain);

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

        // Set per-slot pk_b (BabyBear hash-sig public key) witnesses (P3, third leaf component).
        for (target, pk_b) in self
            .member_pk_b_targets
            .iter()
            .zip(value.member_pk_bs.iter())
        {
            target.set_witness(witness, *pk_b);
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
        circuits::validity::block_hash_chain::sphincs_sig::SmallBlockMessageFields,
        common::{
            block::Block,
            channel_id::ChannelId,
            trees::{
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                key_tree::{MemberLeaf, MemberMerkleProof, MemberTree},
                tx_v2_tree::{ChannelActionTree, TxV2Tree},
            },
            tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
            u63::BlockNumber,
        },
        ethereum_types::bytes32::Bytes32,
        poseidon_sig::{list::list_commitment, GoldilocksSecretKey},
        regev::{hash_sig::BabyBearSecretKey, RegevPk},
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

    /// A distinct member `pk_b` (BabyBear hash-sig public key), derived deterministically from a seed
    /// via the real `hash_sig` primitive — mirroring the production fixture
    /// (`block_witness_generator::ChannelMemberKeys::deterministic`). P3 third `MemberLeaf` component.
    fn member_pk_b(seed: u64) -> PoseidonHashOut {
        let mut baby_rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9e37_79b9).wrapping_add(0xb1));
        let baby = BabyBearSecretKey::random(&mut baby_rng);
        baby.public_key().to_bytes32().reduce_to_hash_out()
    }

    /// Build the channel's 3-member tree, with the signer at slot 0 (the bp). `signer_pk_b` is the
    /// signer's BabyBear hash-sig public key, committed in the slot-0 leaf so the bp's witnessed
    /// `member_pk_bs[0]` matches the registered leaf.
    fn build_member_tree(
        signer: &GoldilocksSecretKey,
        signer_regev: &RegevPk,
        signer_pk_b: PoseidonHashOut,
    ) -> MemberTree {
        let mut member_tree = MemberTree::init();
        member_tree.push(MemberLeaf {
            pk_g: signer.public_key_hash_out(),
            pk_b: signer_pk_b,
            regev_pk_digest: signer_regev.poseidon_digest(),
        });
        member_tree.push(MemberLeaf {
            pk_g: GoldilocksSecretKey::from_seed([2u8; 32]).public_key_hash_out(),
            pk_b: member_pk_b(2),
            regev_pk_digest: regev_pk(2).poseidon_digest(),
        });
        member_tree.push(MemberLeaf {
            pk_g: GoldilocksSecretKey::from_seed([3u8; 32]).public_key_hash_out(),
            pk_b: member_pk_b(3),
            regev_pk_digest: regev_pk(3).poseidon_digest(),
        });
        member_tree
    }

    /// Non-signing (all-padding-update) block: every slot has prev == block_number, so
    /// should_update is false everywhere and the bp_sig_chain is unchanged.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_update_user_tree_no_signing_block() {
        let block_number = BlockNumber::new(20).unwrap();
        let channel_id = 5u32;
        let num_users = 2;

        let mut rng = StdRng::seed_from_u64(42);
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);
        let channel_reg_hash_chain = Bytes32::rand(&mut rng);

        let channel = ChannelId::new(channel_id as u64).unwrap();
        let mut send_tree = SendTree::init();
        let send_leaf_prev = SendLeaf {
            prev: BlockNumber::default(),
            cur: block_number, // already at current block: no update triggered
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

        let timestamp = rng.next_u64();
        let block = Block::new(
            num_users,
            channel_id,
            &[1, 2],
            timestamp,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
        .unwrap();

        let send_proof = send_tree.prove(prev_channel_leaf.index.into());
        let dummy_send_proof = SendMerkleProof::dummy(SEND_TREE_HEIGHT);
        let dummy_user_merkle_proof = ChannelMerkleProof::dummy(CHANNEL_TREE_HEIGHT);

        let mut prev_account_leaves =
            vec![prev_channel_leaf.clone(), prev_channel_leaf.clone()];
        prev_account_leaves.resize(num_users as usize, ChannelLeaf::default());
        let mut send_merkle_proofs = vec![send_proof.clone(), send_proof.clone()];
        send_merkle_proofs.resize(num_users as usize, dummy_send_proof);

        let mut user_merkle_proofs = Vec::with_capacity(num_users as usize);
        for &key_id in block.key_ids.iter() {
            if key_id == 0 {
                user_merkle_proofs.push(dummy_user_merkle_proof.clone());
            } else {
                user_merkle_proofs.push(channel_tree.prove(channel.as_u64()));
            }
        }

        let prev_bp_sig_chain = Bytes32::rand(&mut rng);
        let update_channel_tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves,
            user_merkle_proofs,
            send_merkle_proofs,
            prev_bp_sig_chain,
            member_merkle_proofs: vec![
                MemberMerkleProof::dummy(MEMBER_TREE_HEIGHT);
                num_users as usize
            ],
            member_regev_pks: vec![dummy_regev_pk(); num_users as usize],
            member_pk_bs: vec![PoseidonHashOut::default(); num_users as usize],
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
        // No update ⇒ bp_sig_chain unchanged.
        assert_eq!(public_inputs.prev_bp_sig_chain, prev_bp_sig_chain);
        assert_eq!(public_inputs.new_bp_sig_chain, prev_bp_sig_chain);

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

    /// Build a real signing block: slot 0 (the bp) updates, the bp's `(IMSB_digest, pk_g)` is folded
    /// into bp_sig_chain, and the member inclusion of `pk_g` at slot 0 is proven.
    fn signing_update_tree(
        signer: &GoldilocksSecretKey,
        prev_bp_sig_chain: Bytes32,
        member_tree: &MemberTree,
        signer_regev: &RegevPk,
        signer_pk_b: PoseidonHashOut,
    ) -> (UpdateUserTree, Bytes32) {
        let block_number = BlockNumber::new(30).unwrap();
        let channel_id = 9u32;
        let key_id = 7u32;
        let num_users = 1;
        let mut rng = StdRng::seed_from_u64(99);
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        let channel = ChannelId::new(channel_id as u64).unwrap();
        let send_tree = SendTree::init();
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
            Bytes32::default(),
        )
        .unwrap();

        let user_merkle_proof = channel_tree.prove(channel.as_u64());
        let send_merkle_proof = send_tree.prove(prev_user_leaf.index.into());
        let member_merkle_proof = member_tree.prove(0); // bp is at slot 0

        let bp_pk_g: Bytes32 = signer.public_key();
        let msg_fields = SmallBlockMessageFields {
            bp_member_slot: 0,
            bp_pk_g,
            small_block_number: 0,
            prev_small_block_root: Bytes32::default(),
            state_commitment_root: Bytes32::default(),
            medium_epoch_hint: 0,
            close_freeze_nonce: 0,
        };
        let signed_digest = msg_fields.signing_digest(channel_id, block.tx_tree_root);

        let tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block,
            prev_account_leaves: vec![prev_user_leaf],
            user_merkle_proofs: vec![user_merkle_proof],
            send_merkle_proofs: vec![send_merkle_proof],
            prev_bp_sig_chain,
            member_merkle_proofs: vec![member_merkle_proof],
            member_regev_pks: vec![signer_regev.clone()],
            // The single updating slot IS the bp (slot 0); its witnessed pk_b must match the leaf at
            // slot 0 so the 3-field member inclusion against `member_pubkeys_root` holds.
            member_pk_bs: vec![signer_pk_b],
            msg_fields,
            tx_v2_indices: vec![0],
            tx_v2s: vec![tx_v2],
            tx_v2_merkle_proofs: vec![tx_v2_proof],
            channel_action_indices: vec![0],
            channel_actions: vec![channel_action],
            channel_action_merkle_proofs: vec![channel_action_proof],
        };
        (tree, signed_digest)
    }

    /// Happy path: a real signing block folds `(IMSB_digest, bp_pk_g)` into the bp_sig_chain, and
    /// the chain matches the native `list_commitment`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_update_user_tree_folds_bp_sig_chain() {
        let signer = GoldilocksSecretKey::from_seed([0x11; 32]);
        let signer_regev = regev_pk(1);
        let signer_pk_b = member_pk_b(1);
        let member_tree = build_member_tree(&signer, &signer_regev, signer_pk_b);
        let prev_bp_sig_chain = Bytes32::default();
        let (tree, signed_digest) = signing_update_tree(
            &signer,
            prev_bp_sig_chain,
            &member_tree,
            &signer_regev,
            signer_pk_b,
        );

        let public_inputs = tree.to_public_inputs().unwrap();
        // The new chain equals folding (signed_digest, pk_g) onto the empty chain.
        let expected = list_commitment(&[(signed_digest, signer.public_key())]);
        assert_eq!(public_inputs.new_bp_sig_chain, expected);
        assert_eq!(public_inputs.prev_bp_sig_chain, prev_bp_sig_chain);

        let circuit = UpdateUserCircuit::<F, C, D>::new(1);
        let proof = circuit.prove(&tree).unwrap();
        circuit.data.verify(proof.clone()).unwrap();
        let expected_public_inputs: Vec<F> = public_inputs
            .to_u64_vec()
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();
        assert_eq!(proof.public_inputs, expected_public_inputs);
    }

    /// SECURITY (A9): a bp pk_g that is NOT in the channel's member tree at slot 0 must be rejected
    /// — the member inclusion against the trusted `member_pubkeys_root` fails.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn update_user_tree_rejects_pubkey_not_in_member_tree() {
        let signer = GoldilocksSecretKey::from_seed([0x44; 32]);
        let signer_regev = regev_pk(7);
        // Member tree at slot 0 holds a DIFFERENT key, not the signer's.
        let other = GoldilocksSecretKey::from_seed([0x99; 32]);
        let member_tree = build_member_tree(&other, &regev_pk(8), member_pk_b(8));
        let (tree, _digest) = signing_update_tree(
            &signer,
            Bytes32::default(),
            &member_tree,
            &signer_regev,
            member_pk_b(7),
        );

        // Native witness building already rejects (member leaf not in tree at slot 0).
        assert!(matches!(
            tree.to_public_inputs(),
            Err(UpdateUserTreeError::MerkleProofError(_))
        ));

        let circuit = UpdateUserCircuit::<F, C, D>::new(1);
        assert!(
            circuit.prove(&tree).is_err(),
            "circuit must reject the out-of-tree pubkey signature"
        );
    }
}

