use crate::{
    circuits::{
        balance::common::{
            account_state::AccountState,
            update_public_state::{UpdatePublicState, UpdatePublicStateError},
        },
        test_utils::sphincs_sign::{
            SpxKeyPair, pk_hash_from_pk_bytes, sphincs_keygen, sphincs_sign,
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessorWitness,
            ext_public_state::ExtendedPublicState,
            sphincs_sig::{SmallBlockMessageFields, SpxSigWitness},
        },
    },
    common::{
        block::{Block, BlockError},
        channel_id::{ChannelId, ChannelIdError as UserIdError},
        deposit::Deposit,
        public_state::{PublicState, get_num_users},
        trees::{
            channel_tree::{
                ChannelLeaf, ChannelMerkleProof, ChannelTree, SendLeaf, SendMerkleProof, SendTree,
            },
            deposit_tree::{DepositMerkleProof, DepositTree},
            key_tree::{MemberLeaf, MemberMerkleProof, MemberTree},
            public_state_tree::{PublicStateMerkleProof, PublicStateTree},
            tx_v2_tree::TxV2MerkleProof,
        },
        tx::TxV2,
        u63::{BlockNumber, BlockNumberError, U63},
    },
    constants::{CHANNEL_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::{REGEV_N, REGEV_Q, RegevPk},
};
use std::collections::HashMap;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(target_arch = "wasm32")]
use std::{
    cell::{Ref, RefCell, RefMut},
    rc::Rc,
};

/// Shared handle to a [`BlockWitnessGenerator`] that works on native and wasm targets.
#[derive(Clone, Debug)]
pub struct BlockWitnessGeneratorHandle {
    #[cfg(target_arch = "wasm32")]
    inner: Rc<RefCell<BlockWitnessGenerator>>,
    #[cfg(not(target_arch = "wasm32"))]
    inner: Arc<RwLock<BlockWitnessGenerator>>,
}

#[cfg(target_arch = "wasm32")]
type BlockWitnessGeneratorReadGuard<'a> = Ref<'a, BlockWitnessGenerator>;
#[cfg(target_arch = "wasm32")]
type BlockWitnessGeneratorWriteGuard<'a> = RefMut<'a, BlockWitnessGenerator>;

#[cfg(not(target_arch = "wasm32"))]
type BlockWitnessGeneratorReadGuard<'a> = RwLockReadGuard<'a, BlockWitnessGenerator>;
#[cfg(not(target_arch = "wasm32"))]
type BlockWitnessGeneratorWriteGuard<'a> = RwLockWriteGuard<'a, BlockWitnessGenerator>;

impl BlockWitnessGeneratorHandle {
    pub fn new(generator: BlockWitnessGenerator) -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                inner: Rc::new(RefCell::new(generator)),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self {
                inner: Arc::new(RwLock::new(generator)),
            }
        }
    }

    pub fn borrow(&self) -> BlockWitnessGeneratorReadGuard<'_> {
        #[cfg(target_arch = "wasm32")]
        {
            self.inner.borrow()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner
                .read()
                .expect("block witness generator read lock")
        }
    }

    pub fn borrow_mut(&self) -> BlockWitnessGeneratorWriteGuard<'_> {
        #[cfg(target_arch = "wasm32")]
        {
            self.inner.borrow_mut()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner
                .write()
                .expect("block witness generator write lock")
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BlockWitnessGeneratorError {
    #[error("Too many key IDs: {0}")]
    TooManyKeyIds(usize),

    #[error("ChannelId error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("Block number error: {0}")]
    BlockNumber(#[from] BlockNumberError),

    #[error("Update public state error: {0}")]
    UpdatePublicState(#[from] UpdatePublicStateError),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Active member count for test channels (pad-to-MAX D6): these fixtures register 3 active members
/// per channel; the member tree is height MEMBER_TREE_HEIGHT (MAX_CHANNEL_MEMBERS = 16 slots) with
/// slots 3..16 left as empty leaves (padding). Kept at 3 so existing validity/balance tests are
/// unchanged.
pub const TEST_ACTIVE_MEMBERS: usize = 3;

/// Test-only per-channel member key material (one SPHINCS+ key per member, F1-F6).
///
/// Holds the channel's `TEST_ACTIVE_MEMBERS` active SPHINCS+ keypairs + Regev public keys (slot
/// order) and the Poseidon `MemberTree` (height MEMBER_TREE_HEIGHT, padding slots = empty leaves)
/// whose root is committed into the channel's `ChannelLeaf`. When a slot `i` updates, `add_block`
/// signs the block's IMSB digest with member `i`'s key and opens member `i`'s leaf at tree index
/// `i` against this root — exactly what the live `update_channel_tree` binding now requires.
#[derive(Debug, Clone)]
pub struct ChannelMemberKeys {
    pub keypairs: Vec<SpxKeyPair>,
    pub regev_pks: Vec<RegevPk>,
    pub member_tree: MemberTree,
}

impl ChannelMemberKeys {
    /// Build deterministic member keys + tree for `channel_id`. Seeds are derived from the channel
    /// id so the same channel always yields the same members (stable across re-runs). Active
    /// members occupy slots `0..TEST_ACTIVE_MEMBERS`; the remaining `MemberTree` slots stay empty
    /// (pad-to-MAX D6).
    fn deterministic(channel_id: u32) -> Self {
        let mut keypairs = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut regev_pks = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut member_tree = MemberTree::init();
        for slot in 0..TEST_ACTIVE_MEMBERS as u32 {
            // Distinct 16-byte seeds per (channel, slot, role) — domain-separated by role byte.
            let seed = |role: u8| {
                let mut s = [0u8; 16];
                s[0..4].copy_from_slice(&channel_id.to_le_bytes());
                s[4..8].copy_from_slice(&slot.to_le_bytes());
                s[8] = role;
                s
            };
            let kp = sphincs_keygen(seed(1), seed(2), seed(3));
            let regev = deterministic_regev_pk(channel_id.wrapping_mul(31).wrapping_add(slot + 1));
            member_tree.push(MemberLeaf {
                sphincs_pk_hash: pk_hash_from_pk_bytes(&kp.pk_bytes),
                regev_pk_digest: regev.poseidon_digest(),
            });
            keypairs.push(kp);
            regev_pks.push(regev);
        }
        Self {
            keypairs,
            regev_pks,
            member_tree,
        }
    }
}

/// A distinct canonical Regev pubkey of the correct length, derived deterministically (coeffs < q).
fn deterministic_regev_pk(seed: u32) -> RegevPk {
    RegevPk {
        a: (0..REGEV_N as u32)
            .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
            .collect(),
        b: (0..REGEV_N as u32)
            .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
            .collect(),
    }
}

#[derive(Debug, Clone)]
pub struct BlockWitnessGenerator {
    pub supported_user_counts: Vec<u32>,

    pub block_number: BlockNumber,
    pub channel_tree: ChannelTree,
    pub send_leaves: HashMap<ChannelId, Vec<SendLeaf>>,
    pub deposit_tree: DepositTree,
    pub public_state_tree: PublicStateTree,
    /// Per-channel member key material (test-only). Populated by [`Self::register_channel`] before
    /// the channel's first updating block.
    pub channel_members: HashMap<ChannelId, ChannelMemberKeys>,

    pub block_hash_chain: Bytes32,
    pub deposit_hash_chain: Bytes32,

    pub blocks: Vec<Block>,
    pub deposits: HashMap<BlockNumber, Vec<Deposit>>,
    pub deposit_counts: u64,
    pub block_chain_witness: HashMap<BlockNumber, BlockHashChainProcessorWitness>,
}

impl BlockWitnessGenerator {
    pub fn new(supported_user_counts: &[u32]) -> Self {
        Self {
            supported_user_counts: supported_user_counts.to_vec(),
            block_number: BlockNumber::default(),
            channel_tree: ChannelTree::init(),
            send_leaves: HashMap::new(),
            deposit_tree: DepositTree::init(),
            public_state_tree: PublicStateTree::init(),
            channel_members: HashMap::new(),
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),
            blocks: vec![Block::default()], // genesis block placeholder
            deposits: HashMap::new(),
            deposit_counts: 0,
            block_chain_witness: HashMap::new(),
        }
    }

    /// Register a channel's member set (test-only) BEFORE its first updating block.
    ///
    /// Builds the deterministic `MemberTree` for `channel_id` and seeds the channel's `ChannelLeaf`
    /// with `member_pubkeys_root = member_tree.get_root()`. This MUST run before any block is
    /// produced for the channel: the live `update_channel_tree` binding opens each signing
    /// member's leaf against this root taken from the channel leaf, and that root must be in place
    /// from the channel's genesis (writing it later would break the per-block
    /// prev/new account-tree-root chain the validity proof verifies).
    ///
    /// Idempotent: re-registering an already-registered channel is a no-op (returns the existing
    /// keys). Returns the (clone of the) member keys for the caller to drive signing/encryption.
    pub fn register_channel(&mut self, channel_id: u32) -> ChannelMemberKeys {
        let channel = ChannelId::new(channel_id as u64).expect("channel id");
        if let Some(existing) = self.channel_members.get(&channel) {
            return existing.clone();
        }
        let keys = ChannelMemberKeys::deterministic(channel_id);
        let member_pubkeys_root = keys.member_tree.get_root();

        // Seed the channel leaf carrying the member root. The leaf is otherwise the default
        // (index 0, prev 0, empty send tree) so the first updating block transitions it normally.
        let mut channel_leaf = ChannelLeaf::default();
        channel_leaf.member_pubkeys_root = member_pubkeys_root;
        self.channel_tree.update(channel.as_u64(), channel_leaf);

        self.channel_members.insert(channel, keys.clone());
        keys
    }

    fn current_public_state(&self) -> PublicState {
        let timestamp = self
            .blocks
            .last()
            .map(|block| block.timestamp)
            .unwrap_or_default();

        PublicState {
            block_number: self.block_number,
            timestamp,
            account_tree_root: self.channel_tree.get_root(),
            deposit_tree_root: self.deposit_tree.get_root(),
            prev_public_state_root: self.public_state_tree.get_root(),
        }
    }

    pub fn current_extended_public_state(&self) -> ExtendedPublicState {
        ExtendedPublicState::new(
            self.current_public_state(),
            self.block_hash_chain,
            self.deposit_hash_chain,
            U63::new(self.deposit_tree.len() as u64).expect("deposit count fits in 63 bits"),
        )
    }

    pub fn add_deposit(
        &mut self,
        depositor: Address,
        recipient: Bytes32,
        token_index: u32,
        amount: U256,
        aux_data: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        let target_block_number = self
            .block_number
            .add(1)
            .map_err(BlockWitnessGeneratorError::BlockNumber)?;

        let deposit = Deposit {
            deposit_index: U63::new(self.deposit_counts).unwrap(),
            depositor,
            recipient,
            token_index,
            amount,
            block_number: target_block_number,
            aux_data,
        };

        self.deposits
            .entry(target_block_number)
            .or_default()
            .push(deposit);
        self.deposit_counts += 1;

        Ok(())
    }

    pub fn add_block(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        // Legacy path: no per-slot TxV2 witness. The block_hash_chain_processor fills dummy
        // TxV2 witnesses; this is only sound for genuinely-empty blocks (tx_tree_root == default),
        // where the dummy proof verifies by empty-tree consistency.
        self.add_block_with_tx_v2(channel_id, key_ids, timestamp, tx_tree_root, None)
    }

    /// Like [`add_block`], but threads a real per-slot TxV2 witness into the block-hash-chain
    /// witness so that `update_channel_tree`'s tx_v2 inclusion check passes for non-empty blocks.
    ///
    /// `tx_v2_witness` must be sized to `num_users` (one entry per key slot, padded for zero
    /// key_id slots). `tx_tree_root` MUST equal the root of the `TxV2Tree` the witness proofs
    /// open against — the caller is the single source of truth for that tree (the same root the
    /// balance-side `TxSettlement` opens against). SECURITY: the channel-action sub-witness stays
    /// dummy here because every slot in this model is a `TxClass::UserTransfer`, whose branch in
    /// `update_channel_tree` does not verify the channel-action proof.
    pub fn add_block_with_tx_v2(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        tx_v2_witness: Option<BlockTxV2Witness>,
    ) -> Result<(), BlockWitnessGeneratorError> {
        let num_users = get_num_users(key_ids.len(), &self.supported_user_counts)
            .ok_or(BlockWitnessGeneratorError::TooManyKeyIds(key_ids.len()))?;

        // A non-padding slot means the block updates a real channel; `channel_id == 0` is reserved
        // for dummy/deposit-only blocks (`key_ids` all zero) and never constructs a `ChannelId`.
        let has_active_slot = key_ids.iter().any(|&k| k != 0);
        let channel_opt = if has_active_slot {
            Some(ChannelId::new(channel_id as u64)?)
        } else {
            None
        };

        // Real member witnesses are emitted only for REGISTERED channels (member set built into
        // the channel's leaf). Unregistered channels fall back to DUMMY member/sig witnesses — the
        // prior behavior, sound for balance-only tests that never feed the block witness to the
        // validity proof. See `register_channel` and the F6 blocker note in `tasks/todo.md`:
        // registering a channel at genesis would change the genesis account-tree root, which the
        // balance circuit's hardcoded `PublicState::default()` genesis (empty channel tree) does
        // NOT match — so a chained validity proof over a real-member-signed block cannot currently
        // share a generator with the balance proofs.
        let channel_registered = channel_opt
            .map(|c| self.channel_members.contains_key(&c))
            .unwrap_or(false);

        if let Some(witness) = &tx_v2_witness {
            if witness.tx_v2_indices.len() != num_users as usize
                || witness.tx_v2s.len() != num_users as usize
                || witness.tx_v2_merkle_proofs.len() != num_users as usize
            {
                return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                    "tx_v2 witness arrays must each have num_users={} entries (got indices={}, txs={}, proofs={})",
                    num_users,
                    witness.tx_v2_indices.len(),
                    witness.tx_v2s.len(),
                    witness.tx_v2_merkle_proofs.len(),
                )));
            }
        }

        let new_block_number = self
            .block_number
            .add(1)
            .map_err(BlockWitnessGeneratorError::BlockNumber)?;

        let mut pending_deposits = self.deposits.remove(&new_block_number).unwrap_or_default();
        let mut projected_deposit_hash_chain = self.deposit_hash_chain;
        for deposit in pending_deposits.iter() {
            projected_deposit_hash_chain =
                deposit.hash_with_prev_hash(projected_deposit_hash_chain);
        }

        let block = Block::new(
            num_users,
            channel_id,
            key_ids,
            timestamp,
            tx_tree_root,
            projected_deposit_hash_chain,
        )?;

        let prev_ext_state = self.current_extended_public_state();
        let public_state_index = self.block_number.as_u64();
        let public_state_merkle_proof: PublicStateMerkleProof =
            self.public_state_tree.prove(public_state_index);
        self.public_state_tree.push(prev_ext_state.inner.clone());

        let mut prev_account_leaves = Vec::with_capacity(num_users as usize);
        let mut user_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut send_merkle_proofs = Vec::with_capacity(num_users as usize);

        let dummy_account_proof = ChannelMerkleProof::dummy(CHANNEL_TREE_HEIGHT);
        let dummy_send_proof = SendMerkleProof::dummy(SEND_TREE_HEIGHT);

        let mut account_tree_for_proofs = self.channel_tree.clone();

        // ── Member-signature witnesses (live `update_channel_tree` binding) ────────
        //
        // For every slot `i` whose channel leaf actually transitions this block (`prev !=
        // new_block_number`, the circuit's `should_update`), member `i` signs the block's IMSB
        // digest and opens member `i`'s leaf at tree index `i` against the channel's
        // `member_pubkeys_root`. Non-updating / padding slots carry dummy witnesses (their
        // signature + binding constraints are skipped in-circuit).
        //
        // `channel` is bound above (auto-register check).
        // `updating[i] = true` iff slot i triggers a leaf transition. All slots reference the SAME
        // channel leaf, so only the FIRST non-padding slot actually transitions it (subsequent
        // slots observe the already-updated leaf with `prev == new_block_number` and do NOT update
        // — this mirrors the per-slot loop below exactly). That first updating slot is the IMSB
        // block proposer (`bp_member_slot`).
        let mut updating = vec![false; num_users as usize];
        let mut any_update_slot: Option<usize> = None;
        // Real member witnesses require a registered channel; otherwise fall back to dummies.
        if channel_registered {
            if let Some(channel) = channel_opt {
                let prev_for_channel = account_tree_for_proofs.get_leaf(channel.as_u64());
                if prev_for_channel.prev != new_block_number {
                    if let Some(i) = block.key_ids.iter().position(|&k| k != 0) {
                        updating[i] = true;
                        any_update_slot = Some(i);
                    }
                }
            }
        }

        // Build the block-level IMSB message fields (`bp_member_slot` = first updating slot). The
        // signed digest is recomputed once and signed by EACH updating member at their own slot.
        let member_keys = channel_opt.and_then(|c| self.channel_members.get(&c).cloned());
        let (msg_fields, signed_digest) = if let Some(bp_slot) = any_update_slot {
            let keys = member_keys.as_ref().ok_or_else(|| {
                BlockWitnessGeneratorError::InvalidRequest(format!(
                    "channel {} has an updating slot but is not registered; call register_channel first",
                    channel_id
                ))
            })?;
            let bp_hash: Bytes32 = keys
                .member_tree
                .get_leaf(bp_slot as u64)
                .sphincs_pk_hash
                .into();
            let fields = SmallBlockMessageFields {
                bp_member_slot: bp_slot as u32,
                bp_sphincs_pubkey_hash: bp_hash,
                small_block_number: 0,
                prev_small_block_root: Bytes32::default(),
                state_commitment_root: Bytes32::default(),
                medium_epoch_hint: 0,
                close_freeze_nonce: 0,
            };
            let digest = fields.signing_digest(channel_id, tx_tree_root);
            (fields, Some(digest))
        } else {
            (SmallBlockMessageFields::default(), None)
        };

        let mut sig_witnesses = Vec::with_capacity(num_users as usize);
        let mut member_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut member_regev_pks = Vec::with_capacity(num_users as usize);
        let dummy_member_proof = MemberMerkleProof::dummy(crate::constants::MEMBER_TREE_HEIGHT);
        let dummy_regev = RegevPk {
            a: vec![0u32; REGEV_N],
            b: vec![0u32; REGEV_N],
        };

        for (i, &key_id) in block.key_ids.iter().enumerate() {
            if key_id == 0 {
                prev_account_leaves.push(ChannelLeaf::default());
                user_merkle_proofs.push(dummy_account_proof.clone());
                send_merkle_proofs.push(dummy_send_proof.clone());
                sig_witnesses.push(SpxSigWitness::dummy());
                member_merkle_proofs.push(dummy_member_proof.clone());
                member_regev_pks.push(dummy_regev.clone());
                continue;
            }

            // Two-layer identity: channel-tree index = channel id alone (key_id is the member
            // identity inside the channel, not part of the base-layer index). A non-zero key_id
            // implies `channel_opt.is_some()` (set above from a non-padding `key_ids`).
            let channel = channel_opt.expect("non-zero key_id implies a channel");
            let send_entries = self.send_leaves.entry(channel).or_insert_with(Vec::new);

            let mut send_tree = SendTree::init();
            for leaf in send_entries.iter() {
                send_tree.push(leaf.clone());
            }

            let prev_user_leaf = account_tree_for_proofs.get_leaf(channel.as_u64());
            prev_account_leaves.push(prev_user_leaf.clone());

            let account_proof = account_tree_for_proofs.prove(channel.as_u64());
            user_merkle_proofs.push(account_proof);

            let send_proof = send_tree.prove(prev_user_leaf.index.into());
            send_merkle_proofs.push(send_proof.clone());

            // Real member witness for an updating slot; dummy otherwise.
            if updating[i] {
                let keys = member_keys.as_ref().ok_or_else(|| {
                    BlockWitnessGeneratorError::InvalidRequest(format!(
                        "channel {} updating slot {} but not registered",
                        channel_id, i
                    ))
                })?;
                let digest = signed_digest.expect("updating slot implies a signed digest");
                let msg_bytes: Vec<u8> = digest
                    .to_u32_vec()
                    .into_iter()
                    .flat_map(|limb| (limb as u64).to_le_bytes())
                    .collect();
                let kp = &keys.keypairs[i];
                let sig = sphincs_sign(&msg_bytes, kp);
                sig_witnesses.push(SpxSigWitness::from_bytes(&kp.pk_bytes, &sig));
                member_merkle_proofs.push(keys.member_tree.prove(i as u64));
                member_regev_pks.push(keys.regev_pks[i].clone());
            } else {
                sig_witnesses.push(SpxSigWitness::dummy());
                member_merkle_proofs.push(dummy_member_proof.clone());
                member_regev_pks.push(dummy_regev.clone());
            }

            if prev_user_leaf.prev != new_block_number {
                let new_send_leaf = SendLeaf {
                    prev: prev_user_leaf.prev,
                    cur: new_block_number,
                    tx_tree_root,
                };
                let new_send_root =
                    send_proof.get_root(&new_send_leaf, prev_user_leaf.index.into());
                send_tree.push(new_send_leaf.clone());
                send_entries.push(new_send_leaf.clone());

                // member_pubkeys_root preserved from previous leaf
                let new_user_leaf = ChannelLeaf {
                    index: prev_user_leaf.index + 1,
                    prev: new_block_number,
                    send_tree_root: new_send_root,
                    member_pubkeys_root: prev_user_leaf.member_pubkeys_root,
                };
                account_tree_for_proofs.update(channel.as_u64(), new_user_leaf.clone());
                self.channel_tree.update(channel.as_u64(), new_user_leaf);
            }
        }

        let mut deposit_step_witness = Vec::with_capacity(pending_deposits.len());
        let mut deposit_hash_chain_acc = self.deposit_hash_chain;
        for deposit in pending_deposits.drain(..) {
            let deposit_index = self.deposit_tree.len() as u64;
            let deposit_merkle_proof = self.deposit_tree.prove(deposit_index);
            deposit_step_witness.push((deposit.clone(), deposit_merkle_proof));
            self.deposit_tree.push(deposit.clone());
            deposit_hash_chain_acc = deposit.hash_with_prev_hash(deposit_hash_chain_acc);
        }
        self.deposit_hash_chain = deposit_hash_chain_acc;

        let block_witness = BlockHashChainProcessorWitness {
            deposit_step_witness,
            block: block.clone(),
            prev_account_leaves,
            user_merkle_proofs,
            send_merkle_proofs,
            public_state_merkle_proof,
            // Real per-slot member witnesses (updating slots) + dummies (padding/non-updating).
            sig_witnesses: Some(sig_witnesses),
            member_merkle_proofs: Some(member_merkle_proofs),
            member_regev_pks: Some(member_regev_pks),
            msg_fields: Some(msg_fields),
            tx_v2_indices: tx_v2_witness.as_ref().map(|w| w.tx_v2_indices.clone()),
            tx_v2s: tx_v2_witness.as_ref().map(|w| w.tx_v2s.clone()),
            tx_v2_merkle_proofs: tx_v2_witness
                .as_ref()
                .map(|w| w.tx_v2_merkle_proofs.clone()),
            // UserTransfer-only model: channel-action sub-witness stays dummy (not verified).
            channel_action_indices: None,
            channel_actions: None,
            channel_action_merkle_proofs: None,
        };

        self.block_chain_witness
            .insert(new_block_number, block_witness);

        self.block_hash_chain = block.hash_with_prev_hash(self.block_hash_chain)?;
        self.blocks.push(block);
        self.block_number = new_block_number;

        Ok(())
    }

    pub fn get_send_status(
        &self,
        channel_id: ChannelId,
        at_block: BlockNumber,
    ) -> Result<SendStatus, BlockWitnessGeneratorError> {
        let send_leaves = self
            .send_leaves
            .get(&channel_id)
            .cloned()
            .unwrap_or_default();
        if send_leaves.is_empty() {
            return Ok(SendStatus {
                last_send_block: BlockNumber::default(),
                next_send_block: None,
            });
        }
        if let Some(send_leaf) = send_leaves
            .iter()
            .find(|leaf| leaf.prev <= at_block && at_block < leaf.cur)
        {
            // at_block is in the range of this send leaf
            Ok(SendStatus {
                last_send_block: send_leaf.prev,
                next_send_block: Some(send_leaf.cur),
            })
        } else {
            // at_block is greater than or equal to the last send leaf's cur
            Ok(SendStatus {
                last_send_block: send_leaves.last().unwrap().cur,
                next_send_block: None,
            })
        }
    }

    pub fn get_account_state(
        &self,
        channel_id: ChannelId,
        block_number: BlockNumber,
    ) -> Result<(BlockNumber, AccountState), BlockWitnessGeneratorError> {
        let current_block_number = self.block_number;
        if block_number > current_block_number {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "Requested block number {} is greater than current block number {}",
                block_number.as_u64(),
                current_block_number.as_u64()
            )));
        }

        // find send tree for the user
        let send_leaves = self
            .send_leaves
            .get(&channel_id)
            .cloned()
            .unwrap_or_default();
        let mut send_tree = SendTree::init();
        for leaf in send_leaves.iter() {
            send_tree.push(leaf.clone());
        }

        // find send leaves that send_leaf.prev <= block_number < send_leaf.cur if any, 0 otherwise
        let send_leaf_index = match send_leaves
            .iter()
            .position(|leaf| leaf.prev <= block_number && block_number < leaf.cur)
        {
            Some(index) => index as u32,
            None => 0, // use default
        };
        let send_leaf = send_tree.get_leaf(send_leaf_index as u64);
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let account_tree_root = self.channel_tree.get_root();
        let channel_leaf = self.channel_tree.get_leaf(channel_id.as_u64());
        let user_merkle_proof = self.channel_tree.prove(channel_id.as_u64());

        Ok((
            current_block_number,
            AccountState {
                channel_id,
                account_tree_root,
                send_leaf,
                send_leaf_index,
                send_merkle_proof,
                channel_leaf,
                user_merkle_proof,
            },
        ))
    }

    pub fn get_account_state_for_tx(
        &self,
        channel_id: ChannelId,
        tx_tree_root: Bytes32,
    ) -> Result<(BlockNumber, AccountState), BlockWitnessGeneratorError> {
        let current_block_number = self.block_number;

        // find send tree for the user
        let send_leaves = self
            .send_leaves
            .get(&channel_id)
            .cloned()
            .unwrap_or_default();
        let send_leaf_index = send_leaves
            .iter()
            .position(|leaf| leaf.tx_tree_root == tx_tree_root)
            .ok_or(BlockWitnessGeneratorError::InvalidRequest(format!(
                "No send leaf found for user {:?} with tx_tree_root {:?}",
                channel_id, tx_tree_root
            )))? as u32;

        let mut send_tree = SendTree::init();
        for leaf in send_leaves.iter() {
            send_tree.push(leaf.clone());
        }
        let send_leaf = send_tree.get_leaf(send_leaf_index as u64);
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let account_tree_root = self.channel_tree.get_root();
        let channel_leaf = self.channel_tree.get_leaf(channel_id.as_u64());
        let user_merkle_proof = self.channel_tree.prove(channel_id.as_u64());

        Ok((
            current_block_number,
            AccountState {
                channel_id,
                account_tree_root,
                send_leaf,
                send_leaf_index,
                send_merkle_proof,
                channel_leaf,
                user_merkle_proof,
            },
        ))
    }

    pub fn get_update_public_state_witness(
        &self,
        block_number: BlockNumber,
    ) -> Result<UpdatePublicState, BlockWitnessGeneratorError> {
        let current_block_number = self.block_number;
        if block_number > current_block_number {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "Requested block number {} is greater than current block number {}",
                block_number.as_u64(),
                current_block_number.as_u64()
            )));
        }

        let new = self.current_public_state();
        if block_number == current_block_number {
            return Ok(UpdatePublicState::new(new.clone(), new.clone(), None)?);
        }
        let merkle_proof = self.public_state_tree.prove(block_number.as_u64());
        let old = self.public_state_tree.get_leaf(block_number.as_u64());
        Ok(UpdatePublicState::new(new, old, Some(merkle_proof))?)
    }

    pub fn get_deposit_merkle_proof(
        &self,
        receiver: Bytes32,
    ) -> Result<(Deposit, DepositMerkleProof), BlockWitnessGeneratorError> {
        let deposits = self.deposit_tree.leaves();
        let deposit_index = deposits
            .iter()
            .position(|d| d.recipient == receiver)
            .ok_or(BlockWitnessGeneratorError::InvalidRequest(format!(
                "No deposit found for receiver {:?}",
                receiver
            )))? as u64;
        let deposit = deposits[deposit_index as usize].clone();
        let deposit_merkle_proof = self.deposit_tree.prove(deposit_index);
        Ok((deposit, deposit_merkle_proof))
    }
}

/// Per-slot TxV2 witness for a non-empty block, sized to `num_users`.
///
/// Entry `i` corresponds to key slot `i` of the block. For the 1-block = 1-channel = 1-tx model
/// (detail2 §A-2) the active slot's `tx_v2_indices[i]` is the channel id (the TxV2Tree is indexed
/// by channel_id, matching `TxSettlement` and `TX_TREE_HEIGHT == CHANNEL_ID_BITS`). Padding slots
/// (zero key_id) may carry dummy values — `update_channel_tree` skips them.
#[derive(Debug, Clone)]
pub struct BlockTxV2Witness {
    pub tx_v2_indices: Vec<u64>,
    pub tx_v2s: Vec<TxV2>,
    pub tx_v2_merkle_proofs: Vec<TxV2MerkleProof>,
}

#[derive(Debug, Clone)]
pub struct SendStatus {
    // the block number of the last send tx. If there is no send tx, it is 0.
    pub last_send_block: BlockNumber,

    // the block number of the next send tx. If there is no next send tx, it is None.
    pub next_send_block: Option<BlockNumber>,
}
