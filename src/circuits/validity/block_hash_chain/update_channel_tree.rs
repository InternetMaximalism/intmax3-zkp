use crate::{
    circuits::validity::{
        block_hash_chain::channel_state_message::{
            ChannelStateMessageFields, ChannelStateMessageFieldsTarget,
        },
        channel_reg_hash_chain::channel_reg_step::{compute_member_tree_root, lt_const_threshold},
    },
    common::{
        block::{Block, BlockError, BlockTarget},
        channel_id::{ChannelId, ChannelIdError as UserIdError, ChannelIdTarget},
        trees::{
            channel_tree::{
                ChannelLeaf, ChannelLeafTarget, ChannelMerkleProof, ChannelMerkleProofTarget,
                SendLeaf, SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
            },
            key_tree::{MemberLeaf, MemberLeafTarget, MemberTree},
            tx_v2_tree::{
                ChannelActionMerkleProof, ChannelActionMerkleProofTarget, TxV2MerkleProof,
                TxV2MerkleProofTarget,
            },
        },
        tx::{ChannelAction, ChannelActionKind, ChannelActionTarget, TxClass, TxV2, TxV2Target,
            member_set_update_payload},
        u63::{BlockNumber, BlockNumberTarget, U63Target},
    },
    constants::{CHANNEL_TREE_HEIGHT, MAX_SIG_CLUSTER, SEND_TREE_HEIGHT, TX_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u64::{U64, U64_LEN, U64Target},
    },
    falcon_sig::agg_list::{
        agg_list_leaf, agg_list_leaf_target, agg_pk_list_digest, agg_pk_list_digest_target,
    },
    poseidon_sig::list::{chain_step_target, list_chain_step},
    regev::{REGEV_N, REGEV_PK_POSEIDON_DOMAIN, RegevPk},
    utils::{
        cyclic::add_const_gate,
        leafable::{Leafable as _, LeafableTarget as _},
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
    /// The N-of-N signature list accumulator BEFORE this block. block_step constrains it equal to
    /// the previous ext-state `bp_sig_chain`.
    pub prev_bp_sig_chain: Bytes32,
    /// The accumulator AFTER folding this block's `(IMCH_digest, signer_count, pk_list_digest)`
    /// statement — equal to `prev_bp_sig_chain` on a non-signing block, advanced by one Poseidon
    /// chain step on a signing (base) block. Becomes the new ext-state `bp_sig_chain`.
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

    // The N-of-N signature list accumulator BEFORE this block (`Bytes32::default()` at the
    // validity span's genesis). The block folds the channel's `(IMCH_digest, signer_count,
    // pk_list_digest)` statement onto it when a member signature is applied; the resulting value
    // is surfaced as `new_bp_sig_chain`.
    pub prev_bp_sig_chain: Bytes32,

    /// ALL `MAX_SIG_CLUSTER` registered member leaves in slot order, padding slots empty (design
    /// §4 M2′). The circuit recomputes `member_pubkeys_root` from these and connects it to the
    /// channel leaf's committed root, which is what turns "some registered key signed" into
    /// "exactly the registered set signed":
    ///   * a leaf that is not the registered one changes the root (non-membership is refused);
    ///   * one member's `pk_g` in two slots changes the root (duplicates are unrepresentable —
    ///     `FalconAggCircuit` deliberately allows them, `falcon_sig::agg`, and this is where that
    ///     consumer obligation is discharged);
    ///   * an empty slot below `signer_count`, or a non-empty slot at or above it, is refused — so
    ///     `occupancy == signer_count` is a theorem, not a premise about left-packing.
    pub member_leaves: Vec<MemberLeaf>,
    /// detail2 §Q-3: the NEW registered member leaves when this block carries a
    /// `MemberSetUpdate` channel action — empty otherwise. When present the strict mirror (and
    /// the circuit) validates the single-slot delta against `member_leaves` (the OLD set, which
    /// this block's N-of-N is verified against), re-derives the action `payload_hash` from the
    /// two folded roots, and writes the NEW root into the channel leaf instead of copying.
    pub new_member_leaves: Vec<MemberLeaf>,
    /// N — how many members signed. Constrained `2 <= signer_count <= MAX_SIG_CLUSTER` in-circuit
    /// (design §5.4 item 2: the registration floor is repeated here IN-CIRCUIT rather than
    /// natively, deliberately not repeating `close_circuit`'s `>= 1` in-circuit / `>= 2` native
    /// split), and equal to the channel's registered `member_count` by the root recompute above.
    pub signer_count: u32,
    // The Regev public key witnessed at each block slot; only the updating (bp) slot's is
    // constrained — its Poseidon digest must equal that slot's member-leaf component, so the bp's
    // Regev key stays bound exactly as it was before the N-of-N rewire (design §4 "cost trap":
    // the other MAX_SIG_CLUSTER-1 slots' `regev_pk_digest` are free witnesses authenticated by
    // the root recompute, because MAX_SIG_CLUSTER x 2 x REGEV_N range checks would blow the
    // circuit up).
    pub member_regev_pks: Vec<RegevPk>,

    /// Per-block IMCH `ChannelState::signing_digest()` preimage limbs (detail2 §C-3), EXCLUDING
    /// `channel_id` and `h2_tag` which the circuit supplies from its own block targets. The digest
    /// is recomputed in-circuit and folded; the N real Falcon signatures over it are proven by the
    /// recursive aggregate-list proof the validity circuit consumes (design §5.2 P-b), not here.
    pub channel_state_fields: ChannelStateMessageFields,

    // One bound TxV2 witness per key slot. This proves that the block tx root contains
    // a transaction attributable to the slot's channel_id/key_id authorization domain.
    pub tx_v2_indices: Vec<u64>,
    pub tx_v2s: Vec<TxV2>,
    pub tx_v2_merkle_proofs: Vec<TxV2MerkleProof>,
    pub channel_action_indices: Vec<u64>,
    pub channel_actions: Vec<ChannelAction>,
    pub channel_action_merkle_proofs: Vec<ChannelActionMerkleProof>,
}

/// detail2 §Q-3: THE predicate + fold that decides what `member_pubkeys_root` one block slot
/// writes into its `ChannelLeaf` — `is_member_update ? fold(new_member_leaves) : copy`.
///
/// SECURITY (M-2): this is the SINGLE derivation. Both the proven side
/// (`UpdateUserTree::compute_public_inputs`, whose in-circuit twin gates the same write on
/// `should_check_channel_action ∧ is_msu_kind`) and the daemon's authoritative base-state mirror
/// (`BlockWitnessGenerator::add_block_with_tx_v2_inner`, which writes the leaf into
/// `channel_tree`) CALL it. They must not restate it: M-2 was reported precisely because the
/// generator copied `prev_user_leaf.member_pubkeys_root` unconditionally, so the daemon's base
/// state would have diverged from the proven root on the first member-set-update block and every
/// later Merkle opening against that channel would have broken.
///
/// `new_member_leaves` is empty on every block that carries no member-set transition; a caller
/// that has no `TxV2` for the slot at all passes the default (`TxClass::UserTransfer`), which
/// short-circuits to the copy arm exactly as the dummy substitution in
/// `block_hash_chain_processor` does.
pub fn channel_leaf_member_root(
    tx_v2: &TxV2,
    channel_action: Option<&ChannelAction>,
    new_member_leaves: &[MemberLeaf],
    prev_member_pubkeys_root: PoseidonHashOut,
) -> PoseidonHashOut {
    let is_member_update = tx_v2.tx_class == TxClass::ChannelAction
        && channel_action
            .map(|a| a.kind == ChannelActionKind::MemberSetUpdate)
            .unwrap_or(false)
        && !new_member_leaves.is_empty();
    if is_member_update {
        let mut t = MemberTree::init();
        for l in new_member_leaves.iter() {
            t.push(l.clone());
        }
        t.get_root()
    } else {
        prev_member_pubkeys_root
    }
}

/// detail2 §Q-3: the structural delta a `MemberSetUpdate` block may apply to the registered
/// member leaves — EXACTLY one slot changes, and that change is one of:
///   * ROTATE — the slot was occupied and stays occupied, `regev_pk_digest` is PRESERVED (§Q-6:
///     balances stay decryptable), and the signing identity (pk_g/pk_b) actually changes;
///   * ADD — the slot was the left-packed boundary's first EMPTY slot and becomes occupied.
/// Anything else — two slots changed, a removal, a regev swap, an add off the boundary — is
/// refused. Mirrors `wallet_core::verify_member_set_update`'s structural half (the consent /
/// N-of-N halves live at the co-sign gate and in the block's signature chain respectively).
pub fn validate_member_set_delta(
    old: &[MemberLeaf],
    new: &[MemberLeaf],
) -> Result<(), String> {
    if old.len() != MAX_SIG_CLUSTER || new.len() != MAX_SIG_CLUSTER {
        return Err(format!(
            "member leaf arrays must be exactly MAX_SIG_CLUSTER ({MAX_SIG_CLUSTER}) long, got old {} new {}",
            old.len(),
            new.len()
        ));
    }
    let empty = MemberLeaf::empty_leaf();
    let changed: Vec<usize> = (0..MAX_SIG_CLUSTER).filter(|&i| old[i] != new[i]).collect();
    let [j] = changed[..] else {
        return Err(format!(
            "exactly one slot may change, got {} changed slots",
            changed.len()
        ));
    };
    // SECURITY (M-1, §Q-3): the changed slot's NEW `pk_g` must be DISTINCT from every other slot's.
    // Applies to BOTH arms (a rotate and an add are equally able to name a sitting member's key).
    //
    // What it stops: without this, a rotate-to-duplicate is an EFFECTIVE REMOVAL that bypasses the
    // explicit no-removal rule below — slot j is re-pointed at slot k's `pk_g`, so slot j's holder
    // can no longer sign and the cluster silently shrinks. It also breaks two things that other
    // code TREATS AS THEOREMS: `signer_count` stops counting DISTINCT signers (`FalconAggCircuit`
    // deliberately allows a repeated key, `falcon_sig::agg`), and the "one member's `pk_g` in two
    // slots changes the root — duplicates are unrepresentable" obligation documented on
    // `member_leaves` above becomes FALSE (the member tree happily represents a duplicate; only
    // this gate makes it unreachable). Comparing against ALL slots — padding included — is exact,
    // not over-strict: an occupied changed slot's `pk_g` is nonzero while padding `pk_g` is zero,
    // and the in-circuit mirror asserts the same over the same 8 slots.
    if let Some(k) = (0..MAX_SIG_CLUSTER).find(|&i| i != j && new[i].pk_g == new[j].pk_g) {
        return Err(format!(
            "slot {j}: the new pk_g already occupies slot {k} — duplicate signing identities are \
             refused (M-1: a rotate-to-duplicate is a removal in disguise and would make \
             signer_count stop counting distinct signers)"
        ));
    }
    if old[j] == empty {
        // ADD: must be at the left-packed boundary (every slot below occupied), new occupied.
        if new[j] == empty {
            return Err("add: new leaf is empty".to_string());
        }
        if (0..j).any(|i| old[i] == empty) {
            return Err(format!(
                "add at slot {j} is not at the left-packed boundary (an earlier slot is empty)"
            ));
        }
        Ok(())
    } else {
        // ROTATE: stays occupied, regev preserved, signing identity actually changes.
        if new[j] == empty {
            return Err(format!("slot {j}: removal is not a supported member-set op (§Q-6)"));
        }
        if new[j].regev_pk_digest != old[j].regev_pk_digest {
            return Err(format!(
                "slot {j}: rotation must preserve regev_pk_digest (§Q-6 — Regev rotation is out of scope)"
            ));
        }
        Ok(())
    }
}

impl UpdateUserTree {
    /// Native mirror of the N-of-N constraints the circuit enforces on a SIGNING slot `i`.
    ///
    /// Every check here has an in-circuit twin; this is the honest-prover error path, not the
    /// security boundary (the circuit is). Each message names the constraint so a negative test
    /// can pin WHICH one refused, rather than asserting "something failed".
    fn check_n_of_n_witness(
        &self,
        i: usize,
        prev_user_leaf: &ChannelLeaf,
    ) -> Result<(), UpdateUserTreeError> {
        // SECURITY (detail2 §C-2): tx_tree_root == 0 (H2 = 0) is reserved for in-channel updates;
        // a member signature must never be applied over it. KEPT VERBATIM across the N-of-N
        // rewire (design §5.4 item 6) — a signed H2 = 0 would be a base block authorizing nothing.
        if self.block.tx_tree_root == Bytes32::default() {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "tx_tree_root must be nonzero when a member signature is applied (slot {i}; H2=0 is reserved for in-channel updates)"
            )));
        }

        // The bp posts from a member slot, so a block slot beyond the member tree cannot sign.
        // (Before the rewire this was implied by opening a height-MEMBER_TREE_HEIGHT inclusion
        // proof at index `i`; it is now stated directly.)
        if i >= MAX_SIG_CLUSTER {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "signing block slot {i} is outside the {MAX_SIG_CLUSTER} member slots"
            )));
        }

        // design §5.4 item 2 — the registration floor, restated where the signature is applied.
        if !(2..=MAX_SIG_CLUSTER as u32).contains(&self.signer_count) {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "signer_count {} out of range 2..={MAX_SIG_CLUSTER}",
                self.signer_count
            )));
        }
        let signer_count = self.signer_count as usize;

        // design §5.4 item 3 — occupancy is exactly `signer_count`: nothing above it, nothing
        // missing below it. Together with the root connect below, this is what makes
        // `signer_count == member_count` a theorem rather than a premise about left-packing.
        for (slot, leaf) in self.member_leaves.iter().enumerate() {
            let is_signer = slot < signer_count;
            if !is_signer && *leaf != MemberLeaf::empty_leaf() {
                return Err(UpdateUserTreeError::InvalidLength(format!(
                    "member slot {slot} is at or above signer_count {signer_count} but is not the empty leaf"
                )));
            }
            if is_signer && leaf.pk_g == PoseidonHashOut::default() {
                return Err(UpdateUserTreeError::InvalidLength(format!(
                    "member slot {slot} is below signer_count {signer_count} but carries no pk_g"
                )));
            }
        }
        if i >= signer_count {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "signing block slot {i} is not an active member slot (signer_count {signer_count})"
            )));
        }

        // design §5.4 item 5 — the recomputed root IS the channel's committed member root.
        let mut tree = MemberTree::init();
        for leaf in self.member_leaves.iter() {
            tree.push(leaf.clone());
        }
        if tree.get_root() != prev_user_leaf.member_pubkeys_root {
            return Err(UpdateUserTreeError::MerkleProofError(format!(
                "recomputed member_pubkeys_root does not match the channel leaf's committed root (slot {i})"
            )));
        }

        // design §4 "cost trap" / §5.4 item 6 — the bp slot's Regev pubkey is still opened and
        // rebound, unchanged; the other 15 slots' digests ride on the root recompute.
        if self.member_regev_pks[i].poseidon_digest() != self.member_leaves[i].regev_pk_digest {
            return Err(UpdateUserTreeError::MerkleProofError(format!(
                "witnessed Regev pubkey at slot {i} does not match that slot's member leaf"
            )));
        }
        Ok(())
    }

    /// The validating native mirror: computes the public inputs AND cross-checks the witness
    /// against every in-circuit constraint it can cheaply restate, so an honest prover gets a
    /// named error instead of an opaque proving failure.
    pub fn to_public_inputs(&self) -> Result<UpdateUserPublicInputs, UpdateUserTreeError> {
        self.compute_public_inputs(true)
    }

    /// The same mirror with EVERY cross-check skipped: it only computes the public inputs.
    ///
    /// The skipped checks are all verification-only — the Merkle openings, the tx-class rules and
    /// the N-of-N witness rules. None of them contributes to a public input (the account root is
    /// recomputed with `get_root`, never read from a proof), so this returns exactly what
    /// [`Self::to_public_inputs`] would for any witness the strict mirror accepts.
    ///
    /// TEST-ONLY, and it exists for exactly one reason: a negative test that must pin an
    /// IN-CIRCUIT constraint cannot go through [`Self::to_public_inputs`], because the native
    /// restatement of that same constraint would reject first and the test would pass without the
    /// circuit ever being consulted (a vacuous pass). Negative tests therefore assert the strict
    /// mirror rejects — naming the reason — and then feed the circuit these unchecked public
    /// inputs, so the proving failure is attributable to the constraint under test and to nothing
    /// else. It is never reachable from production code.
    #[cfg(test)]
    pub(crate) fn to_public_inputs_unchecked(
        &self,
    ) -> Result<UpdateUserPublicInputs, UpdateUserTreeError> {
        self.compute_public_inputs(false)
    }

    fn compute_public_inputs(
        &self,
        strict: bool,
    ) -> Result<UpdateUserPublicInputs, UpdateUserTreeError> {
        if self.prev_account_leaves.len() != self.block.num_users as usize
            || self.user_merkle_proofs.len() != self.block.num_users as usize
            || self.send_merkle_proofs.len() != self.block.num_users as usize
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

        if self.member_leaves.len() != MAX_SIG_CLUSTER {
            return Err(UpdateUserTreeError::InvalidLength(format!(
                "member_leaves must cover all {MAX_SIG_CLUSTER} slots, got {}",
                self.member_leaves.len()
            )));
        }

        // update user tree
        let mut account_tree_root = self.prev_account_tree_root;
        let block_tx_root = self.block.tx_tree_root.reduce_to_hash_out();
        let channel_id = self.block.channel_id();
        // The N-of-N signature list accumulator, folded once for the signing (bp) slot.
        let mut bp_sig_chain = self.prev_bp_sig_chain;
        // The IMCH channel-state digest all `signer_count` members signed, recomputed from the
        // witnessed limbs with `channel_id` and `h2_tag` taken from THIS block (design §5.4,
        // Design B variant) — exactly as the circuit does it.
        let signed_digest = self
            .channel_state_fields
            .signing_digest(channel_id, self.block.tx_tree_root);
        // The block's folded statement: `(digest, signer_count, pk_list_digest)` over all
        // MAX_SIG_CLUSTER slots. SHARED formula with the aggregate-list step that proves the
        // signatures (`falcon_sig::agg_list`) — called, never restated.
        //
        // The digest covers ALL slots, padding included — NOT `[0..signer_count]`. For a witness
        // the circuit accepts the two are identical (slots at or above `signer_count` are the
        // empty leaf, i.e. a zero `pk_g`), but for a REJECTED witness they are not, and this
        // mirror must reproduce what the circuit computes rather than what it should have
        // computed: otherwise a negative test would fail on a public-input mismatch and silently
        // stop testing the constraint it was written for.
        let signer_pks: Vec<Bytes32> = self
            .member_leaves
            .iter()
            .map(|leaf| leaf.pk_g.into())
            .collect();
        let sig_leaf = agg_list_leaf(
            signed_digest,
            self.signer_count as u64,
            agg_pk_list_digest(&signer_pks),
        );
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
            if strict {
                user_merkle_proof
                    .verify(&prev_user_leaf, channel_id.as_u64(), account_tree_root)
                    .map_err(|e| {
                        UpdateUserTreeError::MerkleProofError(format!(
                            "failed to verify account merkle proof for i {}: {}",
                            i, e
                        ))
                    })?;
            }

            if prev_user_leaf.prev == self.block_number {
                // already updated in this block
                continue;
            }

            // `should_update` is now true (active slot, prev != block_number). This is the signing
            // (bp) slot: the whole registered member set must have signed this block's IMCH
            // digest, and the `(digest, signer_count, pk_list_digest)` statement is folded into
            // the accumulator.
            if strict {
                self.check_n_of_n_witness(i, prev_user_leaf)?;
            }

            // P2b/N-of-N: fold the block statement into the chain (order-sensitive Poseidon chain,
            // `poseidon_sig::list` step, `falcon_sig::agg_list` leaf). The matching aggregate-list
            // proof — consumed by the validity circuit — proves that for each folded statement
            // `signer_count` real Falcon signatures over `digest` exist, one per listed `pk_g`.
            let prev_chain: PoseidonHashOut = bp_sig_chain.try_into().map_err(|e| {
                UpdateUserTreeError::InvalidLength(format!(
                    "bp_sig_chain is not a canonical Poseidon hash out: {e}"
                ))
            })?;
            bp_sig_chain = list_chain_step(prev_chain, sig_leaf).into();

            let tx_v2 = &self.tx_v2s[i];
            let tx_v2_proof = &self.tx_v2_merkle_proofs[i];
            let tx_v2_index = self.tx_v2_indices[i];
            if strict {
                tx_v2_proof
                    .verify(tx_v2, tx_v2_index, block_tx_root)
                    .map_err(|e| {
                        UpdateUserTreeError::MerkleProofError(format!(
                            "failed to verify tx_v2 merkle proof for i {}: {}",
                            i, e
                        ))
                    })?;
                if tx_v2.nonce != prev_user_leaf.index {
                    return Err(UpdateUserTreeError::InvalidLength(format!(
                        "tx_v2 nonce at i {i} must equal the previous channel send index \
                         (expected {}, got {})",
                        prev_user_leaf.index, tx_v2.nonce
                    )));
                }
            }

            if strict {
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
                            ChannelActionKind::InterChannelSend
                            | ChannelActionKind::ChannelClose => {}
                            ChannelActionKind::MemberSetUpdate => {
                                // detail2 §Q-3, strict half: the delta and the payload binding.
                                // (The root override itself is computed OUTSIDE `strict` below so
                                // the account root advances identically in both modes.)
                                validate_member_set_delta(
                                    &self.member_leaves,
                                    &self.new_member_leaves,
                                )
                                .map_err(|e| {
                                    UpdateUserTreeError::InvalidLength(format!(
                                        "member-set update delta at i {i}: {e}"
                                    ))
                                })?;
                                let prev_root = {
                                    let mut t = MemberTree::init();
                                    for l in self.member_leaves.iter() {
                                        t.push(l.clone());
                                    }
                                    t.get_root()
                                };
                                let new_root = {
                                    let mut t = MemberTree::init();
                                    for l in self.new_member_leaves.iter() {
                                        t.push(l.clone());
                                    }
                                    t.get_root()
                                };
                                // The signed block commits EXACTLY this transition: the action's
                                // payload_hash must be the canonical Poseidon commitment of the
                                // two folded roots (reached from the signed digest via
                                // tx_tree_root → channel_action_root → payload).
                                if channel_action.payload_hash
                                    != member_set_update_payload(prev_root, new_root)
                                {
                                    return Err(UpdateUserTreeError::InvalidLength(format!(
                                        "member-set update payload_hash at i {i} does not commit \
                                         the (prev_root, new_root) transition"
                                    )));
                                }
                                // And it must be THIS channel's own set the block advances.
                                if prev_root != prev_user_leaf.member_pubkeys_root {
                                    return Err(UpdateUserTreeError::InvalidLength(format!(
                                        "member-set update at i {i}: old leaves do not fold to \
                                         the channel's committed member root"
                                    )));
                                }
                            }
                        }
                    }
                }
            }

            // detail2 §Q-3: the ONLY transition that may advance the channel leaf's registered
            // member root. Computed unconditionally (both strict and non-strict modes) so the
            // account tree root is mode-independent; the strict arm above is what VALIDATES the
            // transition, exactly as every other strict/circuit split in this file.
            //
            // SECURITY (M-2): CALLED, never restated. `BlockWitnessGenerator` writes the very same
            // leaf into the daemon's authoritative channel tree and must reach the same root by
            // the same predicate — a second derivation that agrees only by luck is exactly the
            // divergence M-2 reported.
            let member_root_for_leaf = channel_leaf_member_root(
                tx_v2,
                self.channel_actions.get(i),
                &self.new_member_leaves,
                prev_user_leaf.member_pubkeys_root,
            );

            // verify the inclusion of empty leaf in the send tree
            if strict {
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
            }

            // create new send leaf and compute new send tree root
            let new_send_leaf = SendLeaf {
                prev: prev_user_leaf.prev,
                cur: self.block_number,
                tx_tree_root: self.block.tx_tree_root,
            };
            let new_send_tree_root =
                send_merkle_proof.get_root(&new_send_leaf, prev_user_leaf.index.into());

            // create new account leaf and compute new user tree root
            // member_pubkeys_root preserved from previous leaf across state transitions —
            // UNLESS this block is an authorized MemberSetUpdate (detail2 §Q-3), the one
            // transition that may advance it (ChannelSafetyQ.member_set_changes_iff_update).
            let new_user_leaf = ChannelLeaf {
                index: prev_user_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
                member_pubkeys_root: member_root_for_leaf,
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
    /// The N-of-N signature list accumulator BEFORE this block (witnessed; surfaced as the
    /// `prev_bp_sig_chain` PI and folded into `new_bp_sig_chain`).
    pub prev_bp_sig_chain: Bytes32Target,
    /// All `MAX_SIG_CLUSTER` witnessed member leaves in slot order — see
    /// `UpdateUserTree::member_leaves`. Block-level, NOT per block slot: every slot of a block
    /// references the same channel leaf and therefore the same member set.
    pub member_leaf_targets: Vec<MemberLeafTarget>,
    /// detail2 §Q-3: the NEW member leaves for a MemberSetUpdate block (all-empty padding on any
    /// other block — the delta/payload gates below are conditioned off and the leaf-root select
    /// falls back to the copy). Block-level like `member_leaf_targets`.
    pub new_member_leaf_targets: Vec<MemberLeafTarget>,
    /// Witnessed `signer_count` (N).
    pub signer_count: Target,
    /// Per-block-slot witnessed Regev public-key coefficient targets (`a` then `b`, each
    /// `REGEV_N`), for block slots below `MAX_SIG_CLUSTER` — the only slots that can sign.
    pub member_regev_pk_targets: Vec<Vec<Target>>,
    /// Per-block IMCH channel-state message fields — see `UpdateUserTree::channel_state_fields`.
    pub channel_state_fields: ChannelStateMessageFieldsTarget,
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

        // ── IMCH channel-state signing digest (detail2 §C-3), recomputed ONCE per block ──
        //
        // SECURITY (design §5.4, Design B): the digest the channel's members ALREADY sign on every
        // state transition carries `h2_tag`, which IS the small block's `tx_tree_root` for an
        // inter-channel send. Its `channel_id` (both occurrences) and its `h2_tag` limbs are this
        // block's OWN targets, not witnesses, so:
        //   * a signature collected for channel A cannot be applied inside channel B's block, and
        //   * the digest is structurally bound to the tx root this circuit applies — there is no
        //     wire on which a prover could place a different `h2_tag`.
        // Everything else in the preimage may be a free witness: the digest is fully determined by
        // the limbs, and the aggregate proof is over THIS digest, so the members' signatures are
        // what authenticate the remaining limbs.
        let channel_state_fields = ChannelStateMessageFieldsTarget::new(builder);
        let digest_channel_id =
            ChannelIdTarget::from_parts(builder, block.channel_id(), true).value;
        let signed_digest = channel_state_fields.signing_digest::<F, C, D>(
            builder,
            digest_channel_id,
            &block.tx_tree_root,
        );
        // detail2 §C-2: H2 = 0 is reserved for in-channel updates; precompute the zero check
        // once and enforce it per slot whenever a signature is applied.
        let tx_tree_root_is_zero = block.tx_tree_root.is_zero::<F, D, Bytes32>(builder);

        // ── The signer set: all MAX_SIG_CLUSTER member leaves, thermometered by `signer_count` ──
        //
        // design §5.4 items 1-5 (M2′). This is block-level, not per block slot: all slots of a
        // block reference the same channel leaf, hence the same member set.
        let signer_count = builder.add_virtual_target();
        // `is_signer[i] = (i < signer_count)`, the SHARED thermometer `channel_reg_step` builds
        // over its own `active_count` — called, not restated. (Well-defined for ANY witnessed
        // `signer_count`: at most one of its equality terms can fire, so the result is boolean
        // even before the range bound below pins the value.)
        let is_signer: Vec<BoolTarget> = (0..MAX_SIG_CLUSTER)
            .map(|i| lt_const_threshold(builder, i, signer_count))
            .collect();

        let mut member_leaf_targets: Vec<MemberLeafTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut member_leaf_hashes: Vec<PoseidonHashOutTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut member_pk_limbs: Vec<Target> = Vec::with_capacity(MAX_SIG_CLUSTER * BYTES32_LEN);
        let mut member_pk_is_zero: Vec<BoolTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        for _ in 0..MAX_SIG_CLUSTER {
            let leaf = MemberLeafTarget::new(builder);
            // The pk-list slot as the aggregate exposes it: the canonical 8-limb form of the
            // member identity, zero for padding — byte-identical to the zero padding
            // `FalconAggCircuit` constrains its inactive slots to.
            let pk_bytes = Bytes32Target::from_hash_out(builder, leaf.pk_g);
            member_pk_is_zero.push(pk_bytes.is_zero::<F, D, Bytes32>(builder));
            member_pk_limbs.extend(pk_bytes.to_vec());
            member_leaf_hashes.push(leaf.hash::<F, C, D>(builder));
            member_leaf_targets.push(leaf);
        }
        // design §5.4 item 5: the root the channel leaf commits, recomputed from the SAME fold the
        // registration step used to write it (shared `compute_member_tree_root`).
        let recomputed_member_root =
            compute_member_tree_root::<F, C, D>(builder, &member_leaf_hashes);

        // ── detail2 §Q-3: the NEW member set of a MemberSetUpdate block ──
        //
        // Witnessed unconditionally (all-empty padding when unused); its fold becomes the channel
        // leaf's member root ONLY under the per-slot `is_member_update` select below, and the
        // structural delta + payload gates are all conditioned on the same flag, so on every other
        // block these targets are free padding with no constraint force.
        let mut new_member_leaf_targets: Vec<MemberLeafTarget> =
            Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_member_leaf_hashes: Vec<PoseidonHashOutTarget> =
            Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_member_pk_is_zero: Vec<BoolTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        for _ in 0..MAX_SIG_CLUSTER {
            let leaf = MemberLeafTarget::new(builder);
            let pk_bytes = Bytes32Target::from_hash_out(builder, leaf.pk_g);
            new_member_pk_is_zero.push(pk_bytes.is_zero::<F, D, Bytes32>(builder));
            new_member_leaf_hashes.push(leaf.hash::<F, C, D>(builder));
            new_member_leaf_targets.push(leaf);
        }
        let new_member_root =
            compute_member_tree_root::<F, C, D>(builder, &new_member_leaf_hashes);

        // ── The folded block statement (design §5.3) ──
        //
        // `(message, signer_count, pk_list_digest)` with the SHARED `falcon_sig::agg_list`
        // gadgets, so the chain this block commits to is bit-identical to the one the aggregate
        // list proof rebuilds from its recursively verified aggregation proofs. Calling those
        // gadgets rather than restating the formulas is deliberate: a second derivation that
        // agrees only by luck is precisely the failure this repo keeps hitting.
        let pk_list_digest = agg_pk_list_digest_target(builder, &member_pk_limbs);
        let sig_leaf = agg_list_leaf_target(builder, &signed_digest, signer_count, pk_list_digest);

        // The N-of-N signature list accumulator. Witnessed `prev_bp_sig_chain`, folded once (for
        // the updating bp slot) into `bp_sig_chain` using the shared `poseidon_sig::list` chain
        // step, then surfaced as `new_bp_sig_chain`.
        let prev_bp_sig_chain = Bytes32Target::new(builder, true);
        let mut bp_sig_chain = prev_bp_sig_chain.clone();

        let mut member_regev_pk_targets: Vec<Vec<Target>> =
            Vec::with_capacity((num_users as usize).min(MAX_SIG_CLUSTER));
        // Does this block apply a member signature at all? COMPUTED from the per-slot
        // `should_update` flags below (never a prover flag — the same rule the validity circuit's
        // list gate follows), and used to gate the block-level well-formedness of the signer set:
        // a block that signs nothing must not be forced to carry a member set it has no business
        // knowing, and a block that signs must satisfy every one of those constraints.
        let mut any_sign = builder._false();
        // detail2 §Q-3: true iff some slot's action is a MemberSetUpdate — gates the block-level
        // structural-delta constraints emitted after the loop.
        let mut any_member_update = builder._false();
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
            // SECURITY (base-send replay): H2 authenticates this TxV2, including its nonce.  The
            // channel leaf's `index` is the persisted base-account send cursor, so binding the two
            // makes an already-applied signed H2 unusable after the leaf advances.  Do NOT bind the
            // independent `small_block_number` here: incoming and other channel transitions may
            // advance that counter without consuming a base nonce.
            builder.conditional_assert_eq(
                should_update.target,
                tx_v2.nonce,
                prev_user_leaf.index,
            );

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

            // ── detail2 §Q-3: is THIS slot's action a MemberSetUpdate? ──
            let member_update_kind = builder.constant(F::from_canonical_u32(
                ChannelActionKind::MemberSetUpdate.as_u32(),
            ));
            let is_msu_kind = builder.is_equal(channel_action.kind, member_update_kind);
            let is_member_update = builder.and(should_check_channel_action, is_msu_kind);
            any_member_update = builder.or(any_member_update, is_member_update);
            // The signed block commits EXACTLY the (prev_root, new_root) transition: the action's
            // payload_hash must be the canonical Poseidon commitment of the two folds. The prev
            // fold is bound to the channel leaf's committed root by the N-of-N section below
            // (design §5.4 item 2), closing the chain signed-digest → tx_tree_root →
            // channel_action_root → payload → root transition.
            let msu_domain = builder.constant(F::from_canonical_u32(
                crate::constants::MEMBER_SET_UPDATE_DOMAIN,
            ));
            let mut payload_preimage: Vec<Target> = vec![msu_domain];
            payload_preimage.extend(recomputed_member_root.to_vec());
            payload_preimage.extend(new_member_root.to_vec());
            let expected_msu_payload =
                PoseidonHashOutTarget::hash_inputs::<F, D>(builder, &payload_preimage);
            channel_action.payload_hash.conditional_assert_eq(
                builder,
                expected_msu_payload,
                is_member_update,
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
            // member_pubkeys_root preserved unchanged across state transitions — UNLESS this
            // slot's action is an authorized MemberSetUpdate (detail2 §Q-3), the ONE transition
            // that may advance it (ChannelSafetyQ.member_set_changes_iff_update).
            let leaf_member_root = PoseidonHashOutTarget::select(
                builder,
                is_member_update,
                new_member_root,
                prev_user_leaf.member_pubkeys_root.clone(),
            );
            let new_user_leaf = ChannelLeafTarget {
                index: next_index,
                prev: block_number.clone(),
                send_tree_root: new_send_tree_root.clone(),
                member_pubkeys_root: leaf_member_root,
            };

            let updated_root =
                user_merkle_proof.get_root::<F, C, D>(builder, &new_user_leaf, channel_id);

            account_tree_root =
                PoseidonHashOutTarget::select(builder, should_update, updated_root, current_root);

            // ── N-of-N member-set binding + signature chain fold (design §5.4) ────────
            //
            // Exactly ONE folded statement per signing block, and that statement says the WHOLE
            // registered member set signed this block's IMCH digest. For the updating slot we:
            //   1. keep the `tx_tree_root != 0` gate;
            //   2. connect the recomputed member root to the channel leaf's committed
            //      `member_pubkeys_root` — the binding that makes the MAX_SIG_CLUSTER witnessed leaves
            //      (and hence the folded pk list, the occupancy and `signer_count`) the channel's
            //      REGISTERED set rather than a prover-chosen one;
            //   3. compute regev_pk_digest = Poseidon([IMRP, n, a…, b…]) over the witnessed Regev
            //      pubkey coefficients (mirrors `RegevPk::poseidon_digest`) and bind it to THIS
            //      slot's member leaf — the bp's Regev binding, unchanged in strength;
            //   4. fold `(signed_digest, signer_count, pk_list_digest)` into the accumulator.
            //
            // SECURITY: step 2 is what the old per-slot inclusion proof could not do. An inclusion
            // proof says "this key is SOME registered member" (1-of-N); connecting the whole
            // recomputed root says "these are ALL of them, in these slots, and there are exactly
            // `signer_count` of them" — the N-of-N statement the aggregate then discharges. The
            // signatures themselves are proven by the recursive aggregate-list proof the validity
            // circuit consumes (design §5.2 P-b), which rebuilds the SAME chain and verifies
            // `C == final.bp_sig_chain`.
            let should_verify_sig = should_update;
            any_sign = builder.or(any_sign, should_verify_sig);

            // -- (1) SECURITY (detail2 §C-2): tx_tree_root != 0 whenever a member signature is
            // applied — H2 = 0 is reserved for in-channel updates and must never be signed
            // into a base block. KEPT VERBATIM (design §5.4 item 6).
            builder.conditional_assert_eq(
                should_verify_sig.target,
                tx_tree_root_is_zero.target,
                zero,
            );

            if i >= MAX_SIG_CLUSTER {
                // SECURITY: a block slot beyond the member tree has no member leaf to bind its
                // Regev key to, so it must not be able to sign. Before the rewire this was implied
                // rather than stated: the slot opened a height-MEMBER_TREE_HEIGHT inclusion proof
                // at index `i`, and no such index exists for `i >= MAX_SIG_CLUSTER`. That opening
                // was built UNCONDITIONALLY (the index decomposition is outside the
                // `should_update` gate), so it also constrained non-signing out-of-range slots —
                // i.e. the old form refused at least as much as this one. Stating the rule
                // directly can therefore only ADMIT witnesses the old form refused, never the
                // reverse, and the ones it admits are blocks whose out-of-range slots do not sign.
                builder.assert_zero(should_verify_sig.target);
                continue;
            }

            // -- (2) the recomputed member root IS the channel's committed member root --
            prev_user_leaf.member_pubkeys_root.conditional_assert_eq(
                builder,
                recomputed_member_root,
                should_verify_sig,
            );
            // The posting slot must itself be an active member slot. (Implied by (3) — the empty
            // leaf's zero `regev_pk_digest` is not a Poseidon image of any coefficient vector —
            // but an implication that rests on preimage resistance is worth one gate to state.)
            let not_signer_here = builder.not(is_signer[i]);
            let posts_from_empty_slot = builder.and(should_verify_sig, not_signer_here);
            builder.assert_zero(posts_from_empty_slot.target);

            // -- (3) regev_pk_digest = Poseidon([IMRP, n, a…, b…]) over witnessed Regev coeffs --
            // KEPT VERBATIM for the bp slot only (design §4 "cost trap"): doing this for every
            // slot would be MAX_SIG_CLUSTER x 2 x REGEV_N range checks. The others' `regev_pk_digest` are
            // free witnesses authenticated by the root connect in (2).
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
            regev_pk_digest.conditional_assert_eq(
                builder,
                member_leaf_targets[i].regev_pk_digest,
                should_verify_sig,
            );

            // -- (4) fold the block statement into the accumulator --
            // SECURITY: the leaf comes from the SHARED `falcon_sig::agg_list` gadget, so the chain
            // the validity circuit rebuilds from real aggregation proofs matches bit-for-bit.
            //
            // INVARIANT (single-fold soundness): this `bp_sig_chain` design folds AT MOST ONE
            // statement per block and assumes EXACTLY ONE channel-leaf transition per block. If the
            // block layout is ever changed to permit two distinct channel-leaf updates in one
            // block, the second transition's authorization would go unfolded — this loop must be
            // revisited (fold per updating leaf) before that change lands. (Flagged in the P2b
            // security review; unchanged by the N-of-N rewire, which widened the folded TUPLE but
            // not the number of folds.)
            let prev_chain_hashout = bp_sig_chain.to_hash_out(builder);
            let new_chain_hashout = chain_step_target(builder, prev_chain_hashout, sig_leaf);
            let new_chain = Bytes32Target::from_hash_out(builder, new_chain_hashout);
            bp_sig_chain =
                Bytes32Target::select(builder, should_verify_sig, new_chain, bp_sig_chain.clone());

            member_regev_pk_targets.push(regev_pk_coeffs);
        }

        // ── Block-level well-formedness of the signer set (design §5.4 items 2-3) ──
        //
        // ── detail2 §Q-3: the structural delta of a MemberSetUpdate block ──
        //
        // Gated on `any_member_update`; on every other block the new-leaf targets are free
        // padding. Rules (mirror of `validate_member_set_delta`, native):
        //   * exactly ONE slot changes;
        //   * a changed slot that was EMPTY (¬is_signer[i], the occupancy theorem) is an ADD and
        //     must sit exactly at the boundary `i == signer_count`;
        //   * a changed slot that was OCCUPIED is a ROTATE and must preserve `regev_pk_digest`
        //     (§Q-6 — balances stay decryptable);
        //   * a changed slot's NEW leaf is never empty (removal is not a supported op);
        //   * (M-1) the changed slot's NEW `pk_g` is DISTINCT from every other slot's.
        {
            let one = builder.one();
            let mut sum_changed = builder.zero();
            let mut changed_flags: Vec<plonky2::iop::target::BoolTarget> =
                Vec::with_capacity(MAX_SIG_CLUSTER);
            for i in 0..MAX_SIG_CLUSTER {
                let old_l = &member_leaf_targets[i];
                let new_l = &new_member_leaf_targets[i];
                let eq_pkg = old_l.pk_g.is_equal(builder, &new_l.pk_g);
                let eq_pkb = old_l.pk_b.is_equal(builder, &new_l.pk_b);
                let eq_rgv = old_l.regev_pk_digest.is_equal(builder, &new_l.regev_pk_digest);
                let eq_all = {
                    let a = builder.and(eq_pkg, eq_pkb);
                    builder.and(a, eq_rgv)
                };
                let changed = builder.not(eq_all);
                let changed_g = builder.and(changed, any_member_update);
                sum_changed = builder.add(sum_changed, changed_g.target);

                // ADD: changed ∧ was-empty ⇒ i == signer_count (the left-packed boundary).
                let not_signer = builder.not(is_signer[i]);
                let add_here = builder.and(changed_g, not_signer);
                let i_const = builder.constant(F::from_canonical_usize(i));
                builder.conditional_assert_eq(add_here.target, i_const, signer_count);

                // ROTATE: changed ∧ was-occupied ⇒ regev preserved.
                let rot_here = builder.and(changed_g, is_signer[i]);
                old_l.regev_pk_digest.conditional_assert_eq(
                    builder,
                    new_l.regev_pk_digest,
                    rot_here,
                );

                // Never a removal: a changed slot's NEW pk is non-zero.
                let removed = builder.and(changed_g, new_member_pk_is_zero[i]);
                builder.assert_zero(removed.target);

                changed_flags.push(changed_g);
            }
            // Exactly one changed slot on an update block; zero otherwise (sum is already gated).
            builder.conditional_assert_eq(any_member_update.target, sum_changed, one);

            // SECURITY (M-1, §Q-3): NO DUPLICATE SIGNING IDENTITIES. The changed slot's NEW `pk_g`
            // must differ from every other slot's NEW `pk_g`. Mirror of the identical rule now in
            // `validate_member_set_delta` (native) — the two layers must stay byte-identical.
            //
            // What it stops: a rotate-to-duplicate. Nothing above forbids re-pointing slot j at
            // slot k's key, and that is an EFFECTIVE REMOVAL that walks straight past the
            // "removal is not a supported op" rule three lines up — slot j's holder can no longer
            // sign anything, so the cluster shrinks without any of the §Q-1 removal ceremony. It
            // also falsifies the `member_leaves` doc obligation ("one member's `pk_g` in two slots
            // changes the root — duplicates are unrepresentable"): the tree represents duplicates
            // perfectly well, and THIS is the gate that makes them unreachable, discharging the
            // consumer obligation `FalconAggCircuit` leaves open (`falcon_sig::agg` deliberately
            // permits a repeated key, so `signer_count` counts SIGNATURES, not DISTINCT signers —
            // only distinct leaves make the two equal).
            //
            // Formulated over unordered pairs (28 comparisons for MAX_SIG_CLUSTER = 8 rather than
            // 56): exactly one flag is set on an update block, so gating a pair on
            // `changed[i] ∨ changed[k]` selects precisely the pairs containing the changed slot,
            // and leaves every all-unchanged pair free (the OLD set's distinctness is already a
            // theorem via the root connect). Padding slots are included: an occupied changed slot's
            // `pk_g` is nonzero (the `removed` assert above) while padding `pk_g` is zero, so the
            // comparison is exact rather than over-strict.
            for i in 0..MAX_SIG_CLUSTER {
                for k in (i + 1)..MAX_SIG_CLUSTER {
                    let touches_changed = builder.or(changed_flags[i], changed_flags[k]);
                    let dup = new_member_leaf_targets[i]
                        .pk_g
                        .is_equal(builder, &new_member_leaf_targets[k].pk_g);
                    let bad = builder.and(touches_changed, dup);
                    builder.assert_zero(bad.target);
                }
            }
        }

        // Gated on the COMPUTED `any_sign`: on a block that applies no member signature nothing
        // here is bound to anything, and requiring a well-formed member set there would force the
        // witness to invent one (padding blocks do not know the channel's members). On a signing
        // block all of it is mandatory.
        //
        // design §5.4 item 2: `2 <= signer_count <= MAX_SIG_CLUSTER`. The registration floor is 2
        // (`channel_reg_step`), and a 1-of-N "aggregate" is exactly the defect this whole change
        // exists to remove, so the floor is asserted IN-CIRCUIT — the in-circuit `>= 1` / native
        // `>= 2` split in `close_circuit` is a gap not to repeat. The range check is applied to a
        // value that falls back to the constant 2 when the block does not sign, so gating it costs
        // one select rather than a conditional decomposition.
        let two = builder.constant(F::from_canonical_u64(2));
        let max_cosigners = builder.constant(F::from_canonical_u64(MAX_SIG_CLUSTER as u64));
        let checked_signer_count = builder.select(any_sign, signer_count, two);
        let sc_minus_two = builder.sub(checked_signer_count, two);
        builder.range_check(sc_minus_two, 4); // [0, 15] ⊇ [0, 14]
        let max_minus_sc = builder.sub(max_cosigners, checked_signer_count);
        builder.range_check(max_minus_sc, 4);

        for i in 0..MAX_SIG_CLUSTER {
            let not_signer = builder.not(is_signer[i]);
            // design §5.4 item 3: slots at or above `signer_count` are the EMPTY leaf. A real
            // member parked in such a slot changes the recomputed root, so "sign with all but one
            // member" is not representable: the prover must either keep the real leaf (and fail
            // this) or blank it (and fail the root connect).
            let must_be_empty = builder.and(any_sign, not_signer);
            member_leaf_targets[i]
                .pk_g
                .conditional_assert_eq(builder, zero_hash, must_be_empty);
            member_leaf_targets[i]
                .pk_b
                .conditional_assert_eq(builder, zero_hash, must_be_empty);
            member_leaf_targets[i]
                .regev_pk_digest
                .conditional_assert_eq(builder, zero_hash, must_be_empty);
            // SECURITY (the other direction of occupancy): an ACTIVE slot must carry a real key.
            // Without this, a prover could claim `signer_count > member_count` by padding the
            // extra slots with the empty leaf — the root would still match, and the only thing
            // stopping it would be the aggregate's inability to produce a Falcon signature under
            // the all-zero pk. That is a real argument, but it lives in another circuit; making
            // `occupancy == signer_count` a theorem HERE keeps this statement self-contained.
            let active_slot = builder.and(any_sign, is_signer[i]);
            let empty_active_slot = builder.and(active_slot, member_pk_is_zero[i]);
            builder.assert_zero(empty_active_slot.target);
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
            member_leaf_targets,
            new_member_leaf_targets,
            signer_count,
            member_regev_pk_targets,
            channel_state_fields,
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

        // The N-of-N signature list accumulator before this block.
        self.prev_bp_sig_chain
            .set_witness(witness, value.prev_bp_sig_chain);

        // Set the channel's MAX_SIG_CLUSTER member leaves (slot order, padding included).
        assert_eq!(
            value.member_leaves.len(),
            self.member_leaf_targets.len(),
            "member_leaves must cover all {} slots",
            self.member_leaf_targets.len()
        );
        for (target, leaf) in self
            .member_leaf_targets
            .iter()
            .zip(value.member_leaves.iter())
        {
            target.set_witness(witness, leaf);
        }
        // §Q-3: NEW member leaves — all-empty padding when the block is not a MemberSetUpdate.
        {
            let empty = MemberLeaf::empty_leaf();
            for (i, target) in self.new_member_leaf_targets.iter().enumerate() {
                let leaf = value.new_member_leaves.get(i).unwrap_or(&empty);
                target.set_witness(witness, leaf);
            }
        }
        witness.set_target(self.signer_count, F::from_canonical_u32(value.signer_count));

        // Set per-slot Regev pubkey coefficient witnesses (a then b), mirroring the
        // `RegevPk::poseidon_digest` preimage order. Only block slots below MAX_SIG_CLUSTER have
        // targets (the others cannot sign), so the zip is deliberately shorter than the witness.
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

        // Set per-block IMCH channel-state signing message fields.
        self.channel_state_fields
            .set_witness(witness, &value.channel_state_fields);
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
        self.prove_with_public_inputs(witness, &public_inputs)
    }

    /// Prove against CALLER-SUPPLIED public inputs instead of the validating native mirror's.
    ///
    /// `pub(crate)` and used only by this module's negative tests, together with
    /// [`UpdateUserTree::to_public_inputs_unchecked`]: a test that must pin an in-circuit
    /// constraint has to reach the prover, and [`Self::prove`] would stop at the native
    /// restatement of the same constraint. See that method's docs.
    pub(crate) fn prove_with_public_inputs(
        &self,
        witness: &UpdateUserTree,
        public_inputs: &UpdateUserPublicInputs,
    ) -> Result<ProofWithPublicInputs<F, C, D>, UpdateUserCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, witness);
        self.public_inputs.set_witness(&mut pw, public_inputs);
        self.data
            .prove(pw)
            .map_err(|e| UpdateUserCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use once_cell::sync::Lazy;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        common::{
            block::Block,
            channel_id::ChannelId,
            trees::{
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                key_tree::{MemberLeaf, MemberTree},
                tx_v2_tree::{ChannelActionTree, TxV2Tree},
            },
            tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
            u63::BlockNumber,
        },
        constants::MAX_CHANNEL_TOKENS,
        ethereum_types::{bytes32::Bytes32, u256::U256},
        falcon_sig::{
            FalconKeys, FalconSignature,
            agg_list::{AggListEntry, agg_list_commitment},
        },
        regev::{RegevPk, hash_sig::BabyBearSecretKey},
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    /// ONE shared `num_users = 1` circuit for the whole module: every case proves (or fails to
    /// prove) against the SAME constraint system, so sharing weakens nothing, and rebuilding a
    /// 2^16 circuit per case is minutes and gigabytes.
    static CIRCUIT: Lazy<UpdateUserCircuit<F, C, D>> =
        Lazy::new(|| UpdateUserCircuit::<F, C, D>::new(1));

    /// Circuit builds and proofs are the heaviest operations here; cases hold this lock so the
    /// suite never runs two of them concurrently, whatever `--test-threads` is set to.
    static HEAVY: Mutex<()> = Mutex::new(());

    fn heavy() -> std::sync::MutexGuard<'static, ()> {
        HEAVY.lock().unwrap_or_else(|e| e.into_inner())
    }

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

    /// A distinct member `pk_b` (BabyBear hash-sig public key), derived deterministically from a
    /// seed via the real `hash_sig` primitive — mirroring the production fixture
    /// (`block_witness_generator::ChannelMemberKeys::deterministic`).
    fn member_pk_b(seed: u64) -> PoseidonHashOut {
        let mut baby_rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9e37_79b9).wrapping_add(0xb1));
        let baby = BabyBearSecretKey::random(&mut baby_rng);
        baby.public_key().to_bytes32().reduce_to_hash_out()
    }

    /// A channel exactly as REGISTRATION leaves it: `n` members left-packed into the
    /// `MAX_SIG_CLUSTER`-slot member tree, the rest empty. Everything a signing block must witness
    /// is derived from here, so a test can only diverge from the registered set on purpose.
    struct RegisteredChannel {
        /// Real Falcon signing keys, slot order. Not `Clone` on purpose (it is what stops a test
        /// from silently duplicating a signer).
        keys: Vec<FalconKeys>,
        regev: Vec<RegevPk>,
        /// ALL `MAX_SIG_CLUSTER` leaves in slot order — what the circuit witnesses.
        leaves: Vec<MemberLeaf>,
        /// The committed `member_pubkeys_root`.
        root: PoseidonHashOut,
    }

    impl RegisteredChannel {
        fn new(n: usize, seed0: u8) -> Self {
            let mut tree = MemberTree::init();
            let mut keys = Vec::with_capacity(n);
            let mut regev = Vec::with_capacity(n);
            for slot in 0..n {
                let key = FalconKeys::from_seed([seed0.wrapping_add(slot as u8); 32]);
                let pk = regev_pk(seed0 as u32 * 97 + slot as u32 + 1);
                tree.push(MemberLeaf {
                    pk_g: key.pk_g().try_into().expect("canonical pk_g"),
                    pk_b: member_pk_b(seed0 as u64 * 31 + slot as u64),
                    regev_pk_digest: pk.poseidon_digest(),
                });
                keys.push(key);
                regev.push(pk);
            }
            let root = tree.get_root();
            let leaves = (0..MAX_SIG_CLUSTER)
                .map(|slot| tree.get_leaf(slot as u64))
                .collect();
            Self {
                keys,
                regev,
                leaves,
                root,
            }
        }

        fn signer_count(&self) -> u32 {
            self.keys.len() as u32
        }

        /// Every member's REAL Falcon signature over `digest`, verified natively before it is
        /// handed to a test — so a case that says "a validly N-of-N-signed digest" is one.
        fn sign_all(&self, digest: Bytes32) -> Vec<FalconSignature> {
            self.keys
                .iter()
                .map(|key| {
                    let sig = key.sign(digest);
                    assert!(
                        crate::falcon_sig::verify(&key.pk_coefficients(), digest, &sig),
                        "the test's own signature must verify natively"
                    );
                    sig
                })
                .collect()
        }
    }

    /// A plausible, non-degenerate IMCH channel-state preimage. Every limb is nonzero-ish so a
    /// mis-strided segment cannot pass unnoticed.
    fn channel_state_fields(seed: u64) -> ChannelStateMessageFields {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut fund_amounts = [U256::default(); MAX_CHANNEL_TOKENS];
        for (i, slot) in fund_amounts.iter_mut().enumerate() {
            *slot = U256::from(1_000u64 + i as u64 + (rng.next_u32() % 1000) as u64);
        }
        ChannelStateMessageFields {
            epoch: 3,
            small_block_number: 30,
            close_freeze_nonce: 0,
            fund_amounts,
            fund_intmax_state_root: Bytes32::rand(&mut rng),
            balance_state_h1: Bytes32::rand(&mut rng),
            shared_native_nullifier_root: Bytes32::rand(&mut rng),
            unallocated_confirmed_incoming: U256::from(7u64),
            prev_digest: Bytes32::rand(&mut rng),
            state_version: 11,
        }
    }

    const TEST_CHANNEL_ID: u32 = 9;

    /// A real signing block for `channel`: one block slot (the bp, slot 0), a channel-action tx,
    /// and the channel's whole registered member set. Returns the witness and the IMCH digest the
    /// members must sign.
    fn signing_block(channel: &RegisteredChannel, channel_id: u32) -> (UpdateUserTree, Bytes32) {
        let block_number = BlockNumber::new(30).unwrap();
        let key_id = 7u32;
        let num_users = 1;
        let mut rng = StdRng::seed_from_u64(99);
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        let channel_target = ChannelId::new(channel_id as u64).unwrap();
        let send_tree = SendTree::init();
        let prev_user_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::new(4).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_pubkeys_root: channel.root,
        };
        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(channel_target.as_u64(), prev_user_leaf.clone());
        let prev_account_tree_root = channel_tree.get_root();

        let channel_action = ChannelAction {
            kind: ChannelActionKind::InterChannelSend,
            source_channel_id: channel_target,
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
            nonce: 0,
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

        let user_merkle_proof = channel_tree.prove(channel_target.as_u64());
        let send_merkle_proof = send_tree.prove(prev_user_leaf.index.into());

        let fields = channel_state_fields(0xc1a1_0000 + channel_id as u64);
        // `h2_tag` is the block's OWN tx root: this is the whole binding.
        let signed_digest = fields.signing_digest(channel_id, block.tx_tree_root);

        let tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block,
            prev_account_leaves: vec![prev_user_leaf],
            user_merkle_proofs: vec![user_merkle_proof],
            send_merkle_proofs: vec![send_merkle_proof],
            prev_bp_sig_chain: Bytes32::default(),
            member_leaves: channel.leaves.clone(),
            new_member_leaves: Vec::new(),
            signer_count: channel.signer_count(),
            // The bp posts from slot 0, so slot 0's Regev key is the one opened.
            member_regev_pks: vec![channel.regev[0].clone()],
            channel_state_fields: fields,
            tx_v2_indices: vec![0],
            tx_v2s: vec![tx_v2],
            tx_v2_merkle_proofs: vec![tx_v2_proof],
            channel_action_indices: vec![0],
            channel_actions: vec![channel_action],
            channel_action_merkle_proofs: vec![channel_action_proof],
        };
        (tree, signed_digest)
    }

    /// detail2 §Q-3 harness: a MEMBER-SET-UPDATE signing block over `channel`, transitioning the
    /// registered leaves to `new_leaves`. Identical to `signing_block` except the channel action:
    /// kind = MemberSetUpdate, payload = the canonical (prev_root, new_root) commitment, and the
    /// witness carries `new_member_leaves`.
    fn member_update_block(
        channel: &RegisteredChannel,
        channel_id: u32,
        new_leaves: Vec<MemberLeaf>,
    ) -> (UpdateUserTree, Bytes32) {
        let block_number = BlockNumber::new(30).unwrap();
        let key_id = 7u32;
        let num_users = 1;
        let mut rng = StdRng::seed_from_u64(4242);
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        let channel_target = ChannelId::new(channel_id as u64).unwrap();
        let send_tree = SendTree::init();
        let prev_user_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::new(4).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_pubkeys_root: channel.root,
        };
        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(channel_target.as_u64(), prev_user_leaf.clone());
        let prev_account_tree_root = channel_tree.get_root();

        let new_root = {
            let mut t = MemberTree::init();
            for l in new_leaves.iter() {
                t.push(l.clone());
            }
            t.get_root()
        };
        let channel_action = ChannelAction {
            kind: ChannelActionKind::MemberSetUpdate,
            source_channel_id: channel_target,
            destination_channel_id: channel_target,
            tx_hash: Bytes32::rand(&mut rng),
            seal: Bytes32::default(),
            payload_hash: member_set_update_payload(channel.root, new_root),
        };
        let mut channel_action_tree = ChannelActionTree::init();
        channel_action_tree.update(0, channel_action);
        let channel_action_proof = channel_action_tree.prove(0);
        let tx_v2 = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: PoseidonHashOut::default(),
            nonce: 0,
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

        let user_merkle_proof = channel_tree.prove(channel_target.as_u64());
        let send_merkle_proof = send_tree.prove(prev_user_leaf.index.into());

        let fields = channel_state_fields(0xc1a1_0000 + channel_id as u64);
        let signed_digest = fields.signing_digest(channel_id, block.tx_tree_root);

        let tree = UpdateUserTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block,
            prev_account_leaves: vec![prev_user_leaf],
            user_merkle_proofs: vec![user_merkle_proof],
            send_merkle_proofs: vec![send_merkle_proof],
            prev_bp_sig_chain: Bytes32::default(),
            member_leaves: channel.leaves.clone(),
            new_member_leaves: new_leaves,
            signer_count: channel.signer_count(),
            member_regev_pks: vec![channel.regev[0].clone()],
            channel_state_fields: fields,
            tx_v2_indices: vec![0],
            tx_v2s: vec![tx_v2],
            tx_v2_merkle_proofs: vec![tx_v2_proof],
            channel_action_indices: vec![0],
            channel_actions: vec![channel_action],
            channel_action_merkle_proofs: vec![channel_action_proof],
        };
        (tree, signed_digest)
    }

    /// The statement a well-formed block must fold: `(IMCH digest, signer_count, pk list)`.
    fn expected_entry(channel: &RegisteredChannel, digest: Bytes32) -> AggListEntry {
        AggListEntry {
            message: digest,
            signer_pks: channel.keys.iter().map(FalconKeys::pk_g).collect(),
        }
    }

    /// Assert a witness the CIRCUIT must refuse is refused, without letting the native mirror's
    /// restatement of the same rule mask it: the strict mirror must reject with `expected_reason`
    /// in its message (that is the "right reason" pin), and the circuit must then also refuse the
    /// witness when handed the public inputs the mirror would have produced anyway.
    fn assert_refused(tree: &UpdateUserTree, expected_reason: &str) {
        let native = tree.to_public_inputs();
        let message = match &native {
            Ok(_) => panic!("the native mirror accepted a witness the circuit must refuse"),
            Err(e) => e.to_string(),
        };
        assert!(
            message.contains(expected_reason),
            "native mirror refused for the wrong reason: got {message:?}, expected it to mention \
             {expected_reason:?}"
        );
        let pis = tree
            .to_public_inputs_unchecked()
            .expect("the unchecked mirror computes public inputs for any witness");
        assert!(
            CIRCUIT.prove_with_public_inputs(tree, &pis).is_err(),
            "the circuit proved a witness it must refuse ({expected_reason})"
        );
    }

    // ── POSITIVES ────────────────────────────────────────────────────────────────────────────

    /// Positive 1 (design §9 Phase 3): a real 2-of-2 signing block proves and verifies, and the
    /// folded chain is exactly the native `(digest, signer_count, pk_list_digest)` statement the
    /// aggregate-list proof will rebuild. The two members' REAL Falcon signatures over that digest
    /// are produced and natively verified here, so this is a 2-of-2 block and not a shape test.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_real_2_of_2_signing_block_proves() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x10);
        let (tree, digest) = signing_block(&channel, TEST_CHANNEL_ID);
        assert_eq!(channel.sign_all(digest).len(), 2);

        let public_inputs = tree.to_public_inputs().unwrap();
        assert_eq!(
            public_inputs.new_bp_sig_chain,
            agg_list_commitment(&[expected_entry(&channel, digest)]),
            "the block must commit to the N-of-N statement, not to a single signer"
        );
        assert_eq!(public_inputs.prev_bp_sig_chain, Bytes32::default());

        println!(
            "MEASURE update_channel_tree(num_users=1) degree=2^{} pis={}",
            CIRCUIT.data.common.degree_bits(),
            CIRCUIT.data.common.num_public_inputs,
        );
        let t = std::time::Instant::now();
        let proof = CIRCUIT.prove(&tree).unwrap();
        println!(
            "MEASURE update_channel_tree prove(2-of-2)={:?}",
            t.elapsed()
        );
        CIRCUIT.data.verify(proof.clone()).unwrap();

        let expected_public_inputs: Vec<F> = public_inputs
            .to_u64_vec()
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();
        assert_eq!(proof.public_inputs, expected_public_inputs);
    }

    /// Positive 2: a FULL full-cluster block — every member slot active, no padding anywhere — proves
    /// and verifies. The extreme the thermometer and the pk-list padding agreement are most likely
    /// to get wrong.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_real_16_of_16_signing_block_proves() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(MAX_SIG_CLUSTER, 0x30);
        let (tree, digest) = signing_block(&channel, TEST_CHANNEL_ID);
        assert_eq!(channel.sign_all(digest).len(), MAX_SIG_CLUSTER);

        let public_inputs = tree.to_public_inputs().unwrap();
        assert_eq!(
            public_inputs.new_bp_sig_chain,
            agg_list_commitment(&[expected_entry(&channel, digest)])
        );
        let t = std::time::Instant::now();
        let proof = CIRCUIT.prove(&tree).unwrap();
        println!(
            "MEASURE update_channel_tree prove(full-cluster)={:?}",
            t.elapsed()
        );
        CIRCUIT.data.verify(proof).unwrap();
    }

    /// A block that transitions no channel leaf applies no signature: the chain is unchanged, and
    /// — deliberately — the witness carries NO member set at all. The N-of-N well-formedness is
    /// gated on the COMPUTED "this block signs" flag, so a padding block is not forced to invent a
    /// member set it has no business knowing.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_non_signing_block_leaves_the_chain_untouched() {
        let _heavy = heavy();
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

        let mut prev_account_leaves = vec![prev_channel_leaf.clone(), prev_channel_leaf.clone()];
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
            member_leaves: vec![MemberLeaf::default(); MAX_SIG_CLUSTER],
            new_member_leaves: Vec::new(),
            signer_count: 0,
            member_regev_pks: vec![dummy_regev_pk(); num_users as usize],
            channel_state_fields: ChannelStateMessageFields::default(),
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
        assert_eq!(public_inputs.prev_bp_sig_chain, prev_bp_sig_chain);
        assert_eq!(public_inputs.new_bp_sig_chain, prev_bp_sig_chain);

        let circuit = UpdateUserCircuit::<F, C, D>::new(num_users);
        println!(
            "MEASURE update_channel_tree(num_users=2) degree=2^{} pis={}",
            circuit.data.common.degree_bits(),
            circuit.data.common.num_public_inputs,
        );
        let proof = circuit.prove(&update_channel_tree).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

        let expected_public_inputs: Vec<F> = public_inputs
            .to_u64_vec()
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();
        assert_eq!(proof.public_inputs, expected_public_inputs);
    }

    // ── NEGATIVES (design §9 Phase 3 acceptance (a)-(h)) ─────────────────────────────────────

    /// (a) A block signed by all but ONE member. Both ways of expressing it are refused, and by
    /// DIFFERENT constraints — which is the point: the pair is what makes exclusion impossible.
    ///
    ///   a1. Lower `signer_count` and keep the real leaves: the excluded member's leaf now sits at
    ///       or above `signer_count`, so the thermometer refuses it. (The recomputed root still
    ///       matches, so this case is isolated to the padding rule.)
    ///   a2. Lower `signer_count` and blank the excluded member's leaf: the padding rule is now
    ///       satisfied, and the recomputed root no longer matches the channel's committed one.
    ///
    /// Under the OLD single-signature rule this witness was the normal case; that is the defect.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn excluding_one_member_is_unprovable() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(3, 0x50);

        let (mut a1, _) = signing_block(&channel, TEST_CHANNEL_ID);
        a1.signer_count = channel.signer_count() - 1;
        assert_refused(&a1, "is not the empty leaf");

        let (mut a2, _) = signing_block(&channel, TEST_CHANNEL_ID);
        a2.signer_count = channel.signer_count() - 1;
        a2.member_leaves[(channel.signer_count() - 1) as usize] = MemberLeaf::default();
        assert_refused(&a2, "does not match the channel leaf's committed root");
    }

    /// (b) One member's `pk_g` in two active slots — the shape that lets `signer_count` signatures
    /// come from fewer than `signer_count` keys. `FalconAggCircuit` deliberately permits it
    /// (`falcon_sig::agg`: "the same leaf proof may be placed in two slots"), so distinctness is
    /// a CONSUMER obligation and this is where it is discharged: a duplicated key is a different
    /// leaf multiset, hence a different root.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_duplicated_member_pk_is_unprovable() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(3, 0x60);
        let (mut tree, digest) = signing_block(&channel, TEST_CHANNEL_ID);
        // Slot 1 now claims slot 0's identity: two "signatures", one key.
        tree.member_leaves[1].pk_g = tree.member_leaves[0].pk_g;
        assert_refused(&tree, "does not match the channel leaf's committed root");

        // ... and the statement it would have folded is not the channel's, either.
        assert_ne!(
            tree.to_public_inputs_unchecked().unwrap().new_bp_sig_chain,
            agg_list_commitment(&[expected_entry(&channel, digest)])
        );
    }

    /// (c) A key that was never registered, placed in an active slot. This is the old 1-of-N
    /// defect's dual: previously ANY registered key sufficed and the rest of the set was never
    /// examined; now the whole set is recomputed, so an unregistered key cannot hide in it.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn an_unregistered_member_pk_is_unprovable() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(3, 0x70);
        let (mut tree, _) = signing_block(&channel, TEST_CHANNEL_ID);
        let outsider = FalconKeys::from_seed([0xee; 32]);
        tree.member_leaves[1].pk_g = outsider.pk_g().try_into().unwrap();
        assert_refused(&tree, "does not match the channel leaf's committed root");
    }

    /// (d) A non-empty leaf at or above `signer_count`. Stated on a channel whose REGISTERED set
    /// really has four members while the block claims three: the recomputed root MATCHES (the
    /// leaves are the registered ones), so nothing but the thermometer can refuse it. That
    /// isolation is the point — it shows the padding rule is doing the work, not the root connect.
    ///
    /// The second variant plants a stranger's leaf above `signer_count` in a three-member channel;
    /// there BOTH the padding rule and the root connect are violated, and the native mirror names
    /// the padding one first. Kept because it is the shape an attacker would actually try.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_nonempty_slot_above_signer_count_is_unprovable() {
        let _heavy = heavy();
        let four = RegisteredChannel::new(4, 0x80);
        let (mut prefix, _) = signing_block(&four, TEST_CHANNEL_ID);
        prefix.signer_count = 3;
        // Control: the leaves ARE the registered ones, so the root recompute is satisfied and the
        // refusal below cannot be attributed to it.
        let mut root_check = MemberTree::init();
        for leaf in prefix.member_leaves.iter() {
            root_check.push(leaf.clone());
        }
        assert_eq!(
            root_check.get_root(),
            prefix.prev_account_leaves[0].member_pubkeys_root,
            "the isolation this case depends on"
        );
        assert_refused(&prefix, "is not the empty leaf");

        let three = RegisteredChannel::new(3, 0x88);
        let (mut planted, _) = signing_block(&three, TEST_CHANNEL_ID);
        let stranger = FalconKeys::from_seed([0xef; 32]);
        planted.member_leaves[3] = MemberLeaf {
            pk_g: stranger.pk_g().try_into().unwrap(),
            pk_b: member_pk_b(0xef),
            regev_pk_digest: regev_pk(0xef).poseidon_digest(),
        };
        assert_refused(&planted, "is not the empty leaf");
    }

    /// (e) `signer_count = 1` — the defect restated as an aggregate. Stated on a channel whose
    /// registered set really is one member, so the root recompute, the padding rule and the
    /// active-slot rule are ALL satisfied and only the `>= 2` floor can refuse it. (Registration
    /// itself will not mint such a channel — `channel_reg_step` range-checks `member_count` to
    /// `[2, MAX_SIG_CLUSTER]` — which is exactly why the floor has to be restated where the signature is
    /// applied rather than assumed upstream.)
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_single_signer_is_unprovable() {
        let _heavy = heavy();
        let solo = RegisteredChannel::new(1, 0x90);
        let (tree, _) = signing_block(&solo, TEST_CHANNEL_ID);
        assert_eq!(tree.signer_count, 1);
        let mut root_check = MemberTree::init();
        for leaf in tree.member_leaves.iter() {
            root_check.push(leaf.clone());
        }
        assert_eq!(
            root_check.get_root(),
            tree.prev_account_leaves[0].member_pubkeys_root,
            "the isolation this case depends on: only the floor may refuse this witness"
        );
        assert_refused(&tree, "out of range 2..=8");
    }

    /// (f) `tx_tree_root == 0` with a signature applied (detail2 §C-2: H2 = 0 is reserved for
    /// in-channel updates). KEPT VERBATIM across the rewire.
    ///
    /// HONEST NOTE on isolation: this one cannot be isolated the way (d) and (e) are. A zero tx
    /// root is also not the Merkle root of any tx tree, so the block's `tx_v2` binding refuses the
    /// same witness — and no witness can satisfy that binding at zero without a Poseidon preimage
    /// of zero. What the test therefore pins is that the DEDICATED gate is present and fires
    /// first: the native mirror names H2 = 0 rather than the tx binding, and the same witness with
    /// a nonzero root proves (the control, so the refusal tracks the root value and not the
    /// witness's shape).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_signature_over_a_zero_tx_tree_root_is_unprovable() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0xa0);
        let (mut tree, _) = signing_block(&channel, TEST_CHANNEL_ID);
        // Control: the same witness with a nonzero root is accepted, so the refusal below tracks
        // the ROOT VALUE and not something else about this witness.
        assert!(tree.to_public_inputs().is_ok());
        assert!(CIRCUIT.prove(&tree).is_ok());

        tree.block.tx_tree_root = Bytes32::default();
        assert_refused(&tree, "H2=0 is reserved for in-channel updates");
    }

    /// A correctly signed H2 is not a timeless bearer token. The TxV2 nonce committed below H2
    /// must be the channel leaf's current base-send cursor; after one application the leaf advances
    /// and the same signed root is unusable. `small_block_number` is intentionally independent:
    /// incoming and other channel transitions can advance it without consuming this base cursor.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_tx_v2_nonce_not_equal_to_the_current_send_index_is_unprovable() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0xa1);
        let (mut tree, _) = signing_block(&channel, TEST_CHANNEL_ID);
        assert_eq!(tree.prev_account_leaves[0].index, 0);
        assert_eq!(tree.tx_v2s[0].nonce, 0);
        assert!(tree.to_public_inputs().is_ok());
        assert!(CIRCUIT.prove(&tree).is_ok());

        tree.tx_v2s[0].nonce = 1;
        let mut tx_tree = TxV2Tree::init();
        tx_tree.update(tree.tx_v2_indices[0], tree.tx_v2s[0]);
        tree.tx_v2_merkle_proofs[0] = tx_tree.prove(tree.tx_v2_indices[0]);
        tree.block.tx_tree_root = Bytes32::from(tx_tree.get_root());
        assert_refused(&tree, "tx_v2 nonce");
    }

    /// (g) An IMCH `h2_tag` differing from the block's `tx_tree_root` — unsatisfiable BY
    /// CONSTRUCTION.
    ///
    /// There is no `h2_tag` on [`ChannelStateMessageFields`] and no `h2_tag` target on its circuit
    /// twin: the value hashed at limbs 129..137 is the block's own `tx_tree_root` wire
    /// (`channel_state_message::preimage_target_wires_are_the_connected_ones` compares Target
    /// identity, so a future edit that witnesses it fails there). The same holds for the two
    /// `channel_id` limbs. What is left to state HERE is that the witness type offers a prover no
    /// other route: whatever the prover puts in `channel_state_fields`, the folded digest is
    /// `signing_digest(block.channel_id, block.tx_tree_root)`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn the_signed_h2_tag_is_the_block_tx_root_by_construction() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0xb0);
        let (tree, digest) = signing_block(&channel, TEST_CHANNEL_ID);

        // The folded message is the digest over THIS block's tx root...
        assert_eq!(
            digest,
            tree.channel_state_fields
                .signing_digest(tree.block.channel_id(), tree.block.tx_tree_root)
        );
        // ... and not the digest over any other one. (A `h2_tag` the prover would prefer is a
        // different digest, so the aggregate over it cannot match this block's fold.)
        let other_root = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_ne!(
            digest,
            tree.channel_state_fields
                .signing_digest(tree.block.channel_id(), other_root)
        );
        assert_eq!(
            tree.to_public_inputs().unwrap().new_bp_sig_chain,
            agg_list_commitment(&[expected_entry(&channel, digest)])
        );
    }

    /// (h) A REAL, validly N-of-N-signed IMCH digest that belongs somewhere else.
    ///
    ///   h1. …to a DIFFERENT channel. The signatures are produced and natively verified here, and
    ///       deliberately by THIS channel's own members — the hardest version of the case, since
    ///       then the ONLY thing separating the stolen statement from an acceptable one is the
    ///       `channel_id` limbs (with a foreign key set the pk list would differ too, and the test
    ///       would no longer isolate the channel binding). The limbs are hashed under THIS block's
    ///       `channel_id` at both of its occurrences, so the digest this block folds is a different
    ///       value and the stolen aggregate does not match it.
    ///   h2. …to the SAME channel at a different `h2_tag` — a state its members signed for another
    ///       small block. Same conclusion via the connected `h2_tag` limbs. This is the closest
    ///       thing to the replay the design explicitly does NOT close (§6.2): note it is refused
    ///       here only because the tx root differs, not because the state is stale.
    ///
    /// Both directions are asserted twice: the honest fold does not equal the stolen statement,
    /// AND a prover who states the stolen chain as the block's output cannot prove it.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_foreign_or_stale_n_of_n_signature_cannot_be_applied() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0xc0);
        let (tree, honest_digest) = signing_block(&channel, TEST_CHANNEL_ID);
        let block_tx_root = tree.block.tx_tree_root;

        // h1 — the same state limbs, genuinely signed for channel 42.
        const FOREIGN_CHANNEL_ID: u32 = 42;
        assert_ne!(FOREIGN_CHANNEL_ID, TEST_CHANNEL_ID);
        let foreign_digest = tree
            .channel_state_fields
            .signing_digest(FOREIGN_CHANNEL_ID, block_tx_root);
        assert_eq!(channel.sign_all(foreign_digest).len(), 2);
        assert_ne!(foreign_digest, honest_digest);

        // h2 — the same channel, a state signed for a DIFFERENT small block's tx root.
        let stale_tx_root = Bytes32::from_u32_slice(&[9, 9, 9, 9, 9, 9, 9, 9]).unwrap();
        assert_ne!(stale_tx_root, block_tx_root);
        let stale_digest = tree
            .channel_state_fields
            .signing_digest(TEST_CHANNEL_ID, stale_tx_root);
        assert_eq!(channel.sign_all(stale_digest).len(), 2);
        assert_ne!(stale_digest, honest_digest);

        let honest_pis = tree.to_public_inputs().unwrap();
        for stolen in [foreign_digest, stale_digest] {
            let stolen_chain = agg_list_commitment(&[AggListEntry {
                message: stolen,
                signer_pks: channel.keys.iter().map(FalconKeys::pk_g).collect(),
            }]);
            assert_ne!(
                honest_pis.new_bp_sig_chain, stolen_chain,
                "the block must not commit to a digest signed for another channel / tx root"
            );
            let mut forged = honest_pis.clone();
            forged.new_bp_sig_chain = stolen_chain;
            assert!(
                CIRCUIT.prove_with_public_inputs(&tree, &forged).is_err(),
                "a prover must not be able to state the stolen chain as this block's output"
            );
        }
    }

    // ── detail2 §Q-3: MemberSetUpdate blocks ────────────────────────────────────────────────

    /// Positive: a rotate block proves, and the account tree advances to a channel leaf carrying
    /// the NEW registered member root (the frozen-copy rule's one sanctioned exception).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_rotate_block_proves_and_advances_the_root() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x51);
        let mut rng = StdRng::seed_from_u64(0x515);
        let mut new_leaves = channel.leaves.clone();
        // Rotate slot 1's signing identity; regev preserved (§Q-6).
        new_leaves[1].pk_g = PoseidonHashOut::rand(&mut rng);
        new_leaves[1].pk_b = PoseidonHashOut::rand(&mut rng);
        let (tree, _digest) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves.clone());

        let pis = tree.to_public_inputs().expect("a valid rotate block is accepted natively");
        // The advanced account root commits the NEW member root.
        let new_member_root = {
            let mut t = MemberTree::init();
            for l in new_leaves.iter() {
                t.push(l.clone());
            }
            t.get_root()
        };
        assert_ne!(new_member_root, channel.root, "the rotation must actually move the root");
        let expected_account_root = {
            let send_tree = SendTree::init();
            let new_send_leaf = SendLeaf {
                prev: BlockNumber::new(4).unwrap(),
                cur: BlockNumber::new(30).unwrap(),
                tx_tree_root: tree.block.tx_tree_root,
            };
            let send_proof = send_tree.prove(0);
            let new_send_root = send_proof.get_root(&new_send_leaf, 0);
            let leaf = ChannelLeaf {
                index: 1,
                prev: BlockNumber::new(30).unwrap(),
                send_tree_root: new_send_root,
                member_pubkeys_root: new_member_root,
            };
            let mut t = ChannelTree::new(CHANNEL_TREE_HEIGHT);
            t.update(ChannelId::new(TEST_CHANNEL_ID as u64).unwrap().as_u64(), leaf);
            t.get_root()
        };
        assert_eq!(
            pis.new_account_tree_root, expected_account_root,
            "the channel leaf must carry the NEW registered member root"
        );

        // And the circuit agrees byte-for-byte with the native mirror.
        let proof = CIRCUIT.prove(&tree).expect("the rotate block proves");
        CIRCUIT.data.verify(proof.clone()).unwrap();
        let expected: Vec<F> = pis.to_u64_vec().into_iter().map(F::from_canonical_u64).collect();
        assert_eq!(proof.public_inputs, expected);
    }

    /// Positive: an ADD at the left-packed boundary proves.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_add_at_boundary_proves() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x52);
        let mut rng = StdRng::seed_from_u64(0x525);
        let mut new_leaves = channel.leaves.clone();
        new_leaves[2] = MemberLeaf {
            pk_g: PoseidonHashOut::rand(&mut rng),
            pk_b: PoseidonHashOut::rand(&mut rng),
            regev_pk_digest: PoseidonHashOut::rand(&mut rng),
        };
        let (tree, _d) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves);
        let pis = tree.to_public_inputs().expect("a boundary add is accepted natively");
        let proof = CIRCUIT.prove(&tree).expect("the add block proves");
        CIRCUIT.data.verify(proof.clone()).unwrap();
        let expected: Vec<F> = pis.to_u64_vec().into_iter().map(F::from_canonical_u64).collect();
        assert_eq!(proof.public_inputs, expected);
    }

    /// Refusal: a rotation that swaps the Regev digest (decryption-key substitution, §Q-6).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_regev_swap_is_refused() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x53);
        let mut rng = StdRng::seed_from_u64(0x535);
        let mut new_leaves = channel.leaves.clone();
        new_leaves[1].pk_g = PoseidonHashOut::rand(&mut rng);
        new_leaves[1].regev_pk_digest = PoseidonHashOut::rand(&mut rng);
        let (tree, _d) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves);
        assert_refused(&tree, "must preserve regev_pk_digest");
    }

    /// Refusal (audit M-1): a ROTATE-TO-DUPLICATE — slot 1's signing identity re-pointed at slot
    /// 0's `pk_g`. This witness satisfies every §Q-3 rule that existed before M-1: exactly one
    /// slot changes, the slot stays occupied, `regev_pk_digest` is preserved, and the new `pk_g`
    /// is nonzero so the explicit no-removal assert is untouched. It is nonetheless an EFFECTIVE
    /// REMOVAL — slot 1's holder can never sign again — and it makes `signer_count` stop counting
    /// DISTINCT signers, falsifying the "duplicates are unrepresentable" obligation documented on
    /// `member_leaves` that `FalconAggCircuit` (which deliberately permits a repeated key) leaves
    /// for THIS layer to discharge.
    ///
    /// `assert_refused` pins BOTH layers: the native `validate_member_set_delta` mirror refuses it
    /// for the stated reason, AND the circuit refuses it when driven with unchecked public inputs
    /// (the malicious-prover path, where the native mirror is not a defence).
    ///
    /// Confirmed RED without the fix: reverting either the native guard or the in-circuit pairwise
    /// gate makes the corresponding half of this assertion fail.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_rotate_to_duplicate_is_refused() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x57);
        let mut new_leaves = channel.leaves.clone();
        new_leaves[1].pk_g = channel.leaves[0].pk_g;
        assert_ne!(
            new_leaves[1], channel.leaves[1],
            "the rotation really does change slot 1"
        );
        assert_eq!(
            new_leaves[1].regev_pk_digest, channel.leaves[1].regev_pk_digest,
            "regev is preserved — the §Q-6 rule is NOT what rejects this"
        );
        let (tree, _d) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves);
        assert_refused(&tree, "already occupies slot");
    }

    /// Refusal: two slots changed in one update.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_two_slot_change_is_refused() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x54);
        let mut rng = StdRng::seed_from_u64(0x545);
        let mut new_leaves = channel.leaves.clone();
        new_leaves[0].pk_g = PoseidonHashOut::rand(&mut rng);
        new_leaves[1].pk_g = PoseidonHashOut::rand(&mut rng);
        let (tree, _d) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves);
        assert_refused(&tree, "exactly one slot may change");
    }

    /// Refusal: an add OFF the left-packed boundary (slot 4 with only 2 occupied).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_add_off_boundary_is_refused() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x55);
        let mut rng = StdRng::seed_from_u64(0x555);
        let mut new_leaves = channel.leaves.clone();
        new_leaves[4] = MemberLeaf {
            pk_g: PoseidonHashOut::rand(&mut rng),
            pk_b: PoseidonHashOut::rand(&mut rng),
            regev_pk_digest: PoseidonHashOut::rand(&mut rng),
        };
        let (tree, _d) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves);
        assert_refused(&tree, "left-packed boundary");
    }

    /// Refusal: a payload_hash that does not commit the transition — the signed block must bind
    /// EXACTLY the (prev_root, new_root) pair.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn member_update_payload_mismatch_is_refused() {
        let _heavy = heavy();
        let channel = RegisteredChannel::new(2, 0x56);
        let mut rng = StdRng::seed_from_u64(0x565);
        let mut new_leaves = channel.leaves.clone();
        new_leaves[1].pk_g = PoseidonHashOut::rand(&mut rng);
        let (mut tree, _d) = member_update_block(&channel, TEST_CHANNEL_ID, new_leaves);
        // Tamper: swap in DIFFERENT new leaves than the payload committed.
        tree.new_member_leaves[1].pk_g = PoseidonHashOut::rand(&mut rng);
        assert_refused(&tree, "payload_hash");
    }
}
