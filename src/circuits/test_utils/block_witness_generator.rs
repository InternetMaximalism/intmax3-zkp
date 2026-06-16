use crate::{
    circuits::{
        balance::common::{
            account_state::AccountState,
            update_public_state::{UpdatePublicState, UpdatePublicStateError},
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessorWitness,
            ext_public_state::ExtendedPublicState,
            small_block_message::SmallBlockMessageFields,
        },
    },
    poseidon_sig::GoldilocksSecretKey,
    common::{
        block::{Block, BlockError},
        channel_id::{ChannelId, ChannelIdError as UserIdError},
        channel_registration::{ChannelRegRecord, MemberRegEntry},
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
    constants::{CHANNEL_TREE_HEIGHT, MAX_CHANNEL_MEMBERS, SEND_TREE_HEIGHT},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::{REGEV_N, REGEV_Q, RegevPk, hash_sig::BabyBearSecretKey},
    utils::poseidon_hash_out::PoseidonHashOut,
};
use rand::SeedableRng as _;
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

/// Test-only per-channel member key material (one Goldilocks signing key per member, P2b).
///
/// Holds the channel's `TEST_ACTIVE_MEMBERS` active `GoldilocksSecretKey`s + Regev public keys
/// (slot order) and the Poseidon `MemberTree` (height MEMBER_TREE_HEIGHT, padding slots = empty
/// leaves) whose root is committed into the channel's `ChannelLeaf`. When the block-producer slot
/// updates, `add_block` records the block's IMSB digest as the bp's signing message and opens the
/// bp's leaf against this root; the actual single-sig + list proofs are produced at the validity
/// level (P2b decision D3).
#[derive(Debug, Clone)]
pub struct ChannelMemberKeys {
    pub secret_keys: Vec<GoldilocksSecretKey>,
    /// Per-member BabyBear hash-sig secret keys (P3). Their `pk_b` digests are committed into the
    /// 3-field `MemberLeaf` / registration record.
    pub baby_keys: Vec<BabyBearSecretKey>,
    pub regev_pks: Vec<RegevPk>,
    pub member_tree: MemberTree,
}

impl ChannelMemberKeys {
    /// Build deterministic member keys + tree for `channel_id`. Seeds are derived from the channel
    /// id so the same channel always yields the same members (stable across re-runs). Active
    /// members occupy slots `0..TEST_ACTIVE_MEMBERS`; the remaining `MemberTree` slots stay empty
    /// (pad-to-MAX D6).
    fn deterministic(channel_id: u32) -> Self {
        let mut secret_keys = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut baby_keys = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut regev_pks = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut member_tree = MemberTree::init();
        for slot in 0..TEST_ACTIVE_MEMBERS as u32 {
            // Distinct 32-byte seed per (channel, slot), domain-separated so the secret keys are
            // distinct across channels and slots. Non-zero (avoids the degenerate all-zero key the
            // single-sig circuit rejects).
            let mut seed = [0u8; 32];
            seed[0..4].copy_from_slice(&channel_id.to_le_bytes());
            seed[4..8].copy_from_slice(&slot.to_le_bytes());
            seed[8] = 0xa5;
            seed[31] = slot as u8 + 1;
            let sk = GoldilocksSecretKey::from_seed(seed);
            // Deterministic BabyBear hash-sig key (P3): seed an RNG from the (channel, slot) so pk_b
            // is stable across re-runs and distinct per member.
            let baby_seed = (channel_id as u64)
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add((slot as u64) << 8)
                .wrapping_add(0xb1);
            let mut baby_rng = rand::rngs::StdRng::seed_from_u64(baby_seed);
            let baby = BabyBearSecretKey::random(&mut baby_rng);
            let pk_b: PoseidonHashOut = baby.public_key().to_bytes32().reduce_to_hash_out();
            let regev = deterministic_regev_pk(channel_id.wrapping_mul(31).wrapping_add(slot + 1));
            member_tree.push(MemberLeaf {
                pk_g: sk.public_key_hash_out(),
                pk_b,
                regev_pk_digest: regev.poseidon_digest(),
            });
            secret_keys.push(sk);
            baby_keys.push(baby);
            regev_pks.push(regev);
        }
        Self {
            secret_keys,
            baby_keys,
            regev_pks,
            member_tree,
        }
    }

    /// Build `ChannelMemberKeys` from REAL wallet `MemberKeys` (Goldilocks + BabyBear + REAL Regev),
    /// so a channel registered in the validity proof has EXACTLY the same `(pk_g, pk_b,
    /// regev_pk_digest)` member set as the channel-layer `build_record` (B-2: the small-block
    /// `bp_pk_g` the validity circuit verifies is a genuine registered member, and the channel's
    /// `member_pubkeys_root` matches the registration's). Unlike `deterministic`, the Regev keys are
    /// real keypairs (the secret lives with the wallet, NOT here — validity never decrypts).
    pub fn from_member_keys(keys: &[crate::wallet_core::MemberKeys]) -> Self {
        let mut member_tree = MemberTree::init();
        let (mut secret_keys, mut baby_keys, mut regev_pks) = (Vec::new(), Vec::new(), Vec::new());
        for k in keys.iter().take(TEST_ACTIVE_MEMBERS) {
            let pk_b: PoseidonHashOut = k.baby_key.public_key().to_bytes32().reduce_to_hash_out();
            member_tree.push(MemberLeaf {
                pk_g: k.signing_key.public_key_hash_out(),
                pk_b,
                regev_pk_digest: k.regev_pk.poseidon_digest(),
            });
            secret_keys.push(k.signing_key.clone());
            baby_keys.push(k.baby_key.clone());
            regev_pks.push(k.regev_pk.clone());
        }
        Self { secret_keys, baby_keys, regev_pks, member_tree }
    }

    /// Build the on-chain [`ChannelRegRecord`] for `channel_id` from this member key material.
    ///
    /// SECURITY (R2 cross-binding consistency): each active slot's `pk_g` /
    /// `regev_pk_digest` is the canonical `Bytes32::from(PoseidonHashOut)` of the SAME Poseidon
    /// identity stored in `member_tree`. The `channel_reg_step` circuit witnesses these as
    /// `PoseidonHashOut` via `reduce_to_hash_out` and recomputes the member root, so the
    /// `member_pubkeys_root` it writes equals `member_tree.get_root()` — exactly the root the later
    /// updating-block member-signature binding opens against. The `recipient` is a deterministic
    /// test L1 address; it only enters the keccak preimage, not the Poseidon member tree.
    pub fn to_reg_record(&self, channel_id: u32) -> ChannelRegRecord {
        let mut members: [MemberRegEntry; MAX_CHANNEL_MEMBERS] = Default::default();
        for i in 0..TEST_ACTIVE_MEMBERS {
            let leaf = self.member_tree.get_leaf(i as u64);
            members[i] = MemberRegEntry {
                pk_g: Bytes32::from(leaf.pk_g),
                pk_b: Bytes32::from(leaf.pk_b),
                regev_pk_digest: Bytes32::from(leaf.regev_pk_digest),
                // Deterministic per-(channel, slot) test recipient (keccak preimage only).
                recipient: Address::from_u32_slice(
                    &[0x3333_0000u32
                        .wrapping_add(channel_id.wrapping_mul(16))
                        .wrapping_add(i as u32); 5],
                )
                .expect("address from u32 slice"),
            };
        }
        ChannelRegRecord {
            channel_id: ChannelId::new(channel_id as u64).expect("channel id"),
            // Block proposer is slot 0 by convention (matches the first updating slot the later
            // blocks sign with).
            bp_member_slot: 0,
            member_count: TEST_ACTIVE_MEMBERS as u32,
            delegate_count: 0,
            members,
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
    /// On-chain keccak channel-registration hash chain (genesis = default). Non-registration
    /// blocks (the only path exercised on this branch) leave it unchanged; G5 will advance it
    /// when an in-band registration block is queued.
    pub channel_reg_hash_chain: Bytes32,

    pub blocks: Vec<Block>,
    pub deposits: HashMap<BlockNumber, Vec<Deposit>>,
    pub deposit_counts: u64,
    /// Channels queued for in-band registration (mirror of `deposits`). Each entry is the keccak
    /// registration record + the channel's member key material; drained into a dedicated
    /// registration block by [`Self::add_registration_block`]. Queued, not yet applied to
    /// `channel_tree` (the registration block applies it).
    pub channel_registrations: Vec<(ChannelRegRecord, ChannelMemberKeys)>,
    pub block_chain_witness: HashMap<BlockNumber, BlockHashChainProcessorWitness>,
    /// P2b: the ordered list of bp IMSB signing events `(bp_secret_key, IMSB_digest)` over the
    /// whole span, in block order. The validity-level e2e turns each into a `SingleSigCircuit`
    /// proof and folds them into one `ListCircuit` proof whose commitment must equal the final
    /// `bp_sig_chain` (decision D3).
    pub bp_sig_events: Vec<(GoldilocksSecretKey, Bytes32)>,
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
            channel_reg_hash_chain: Bytes32::default(),
            blocks: vec![Block::default()], // genesis block placeholder
            deposits: HashMap::new(),
            deposit_counts: 0,
            channel_registrations: Vec::new(),
            block_chain_witness: HashMap::new(),
            bp_sig_events: Vec::new(),
        }
    }

    /// Queue an in-band channel registration (mirror of [`Self::add_deposit`]).
    ///
    /// Builds the deterministic member key material + the on-chain [`ChannelRegRecord`] for
    /// `channel_id` and queues it for the NEXT registration block. Does NOT mutate `channel_tree`
    /// yet — the registration block (produced by [`Self::add_registration_block`]) applies it,
    /// advancing the channel-registration keccak chain and writing the channel's `ChannelLeaf`
    /// (with `member_pubkeys_root = member_tree.get_root()`) deterministically, exactly as the
    /// `channel_reg_step` validity circuit does. The member keys are recorded immediately in
    /// `channel_members` so the caller can drive signing for the channel's later updating blocks.
    ///
    /// This MUST be followed by a registration block (and that block MUST land before the channel's
    /// first updating block): the live `update_channel_tree` binding opens each signing member's
    /// leaf against the channel leaf's `member_pubkeys_root`, which only exists once the
    /// registration block has written it.
    ///
    /// Idempotent: registering an already-registered (or already-queued) channel is a no-op that
    /// returns the existing keys. Returns the (clone of the) member keys.
    pub fn add_channel_registration(&mut self, channel_id: u32) -> ChannelMemberKeys {
        let channel = ChannelId::new(channel_id as u64).expect("channel id");
        if let Some(existing) = self.channel_members.get(&channel) {
            return existing.clone();
        }
        let keys = ChannelMemberKeys::deterministic(channel_id);
        let record = keys.to_reg_record(channel_id);
        record
            .validate()
            .expect("deterministic test registration record must be valid");
        self.channel_registrations.push((record, keys.clone()));
        self.channel_members.insert(channel, keys.clone());
        keys
    }

    /// Register `channel_id` with PROVIDED real member keys (B-2): the same `(pk_g, pk_b, regev_pk)`
    /// triple the channel-layer `build_record` uses, so the small-block signature the validity proof
    /// verifies (`bp_pk_g ∈ member_pubkeys_root`) is a genuine registered member and the channel's
    /// `member_pubkeys_root` equals the registration's.
    pub fn add_channel_registration_keys(
        &mut self,
        channel_id: u32,
        keys: ChannelMemberKeys,
    ) -> ChannelMemberKeys {
        let channel = ChannelId::new(channel_id as u64).expect("channel id");
        if let Some(existing) = self.channel_members.get(&channel) {
            return existing.clone();
        }
        let record = keys.to_reg_record(channel_id);
        record.validate().expect("registration record must be valid");
        self.channel_registrations.push((record, keys.clone()));
        self.channel_members.insert(channel, keys.clone());
        keys
    }

    /// Produce a dedicated REGISTRATION block consuming exactly ONE queued registration (R6: a
    /// registration block carries no user updates, so `key_ids` is empty/all-padding and the
    /// account tree is mutated solely by the registration's channel-tree write).
    ///
    /// Drains the front of `channel_registrations`, builds the `(record, ChannelMerkleProof)`
    /// witness against the CURRENT (unregistered) channel tree, advances the projected
    /// `channel_reg_hash_chain` via `ChannelRegRecord::hash_with_prev_hash`, applies the
    /// registration to `channel_tree` (writing the real `ChannelLeaf` with the member root), and
    /// stores the block witness with the channel-reg step witness populated so `block_step`'s
    /// channel-reg proof is generated and consumed. Returns the registered `ChannelId`.
    ///
    /// One registration per block keeps the channel_reg_step chain a single step (simplest sound
    /// form); call repeatedly to register several channels.
    pub fn add_registration_block(
        &mut self,
        timestamp: u64,
    ) -> Result<ChannelId, BlockWitnessGeneratorError> {
        if self.channel_registrations.is_empty() {
            return Err(BlockWitnessGeneratorError::InvalidRequest(
                "no queued channel registration to produce a registration block".to_string(),
            ));
        }
        let (record, _keys) = self.channel_registrations.remove(0);
        let channel = record.channel_id;

        // R5 unregistered guard (native mirror): the channel must currently be the default leaf.
        let prev_leaf = self.channel_tree.get_leaf(channel.as_u64());
        if prev_leaf != ChannelLeaf::default() {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "channel {} is already registered; one-time registration only (R5)",
                channel.as_u64()
            )));
        }

        let new_block_number = self
            .block_number
            .add(1)
            .map_err(BlockWitnessGeneratorError::BlockNumber)?;

        // A registration block must NOT carry deposits (it would change the deposit hash chain and
        // entangle two account-tree-root sources). Reject if any deposit was queued for this slot.
        if self.deposits.contains_key(&new_block_number) {
            return Err(BlockWitnessGeneratorError::InvalidRequest(
                "a registration block cannot also process deposits; sequence them in separate blocks"
                    .to_string(),
            ));
        }

        // num_users from empty key_ids (all-padding ⇒ no user update ⇒ R6 satisfied).
        let key_ids: [u32; 0] = [];
        let num_users = get_num_users(0, &self.supported_user_counts)
            .ok_or(BlockWitnessGeneratorError::TooManyKeyIds(0))?;

        // Advance the projected channel-reg keccak chain (single step) — this is the POST-apply
        // chain that the registration block carries in its block hash (G6).
        let new_channel_reg_hash_chain = record.hash_with_prev_hash(self.channel_reg_hash_chain);

        // Deposit hash chain is unchanged (no deposits this block); the channel_reg_hash_chain is
        // the post-registration value, mirroring how `deposit_hash_chain` carries the post-deposit
        // value. Both are folded into the block hash (G6).
        let block = Block::new(
            num_users,
            0,
            &key_ids,
            timestamp,
            Bytes32::default(),
            self.deposit_hash_chain,
            new_channel_reg_hash_chain,
        )?;

        let prev_ext_state = self.current_extended_public_state();
        let public_state_index = self.block_number.as_u64();
        let public_state_merkle_proof: PublicStateMerkleProof =
            self.public_state_tree.prove(public_state_index);
        self.public_state_tree.push(prev_ext_state.inner.clone());

        // ── Channel-reg step witness: prove against the CURRENT (unregistered) channel tree ──
        let channel_merkle_proof = self.channel_tree.prove(channel.as_u64());

        // Apply the registration to the channel tree (write the real member root leaf), exactly as
        // `channel_reg_step` does in-circuit.
        let member_pubkeys_root = _keys.member_tree.get_root();
        let registered_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::default(),
            send_tree_root: ChannelLeaf::default().send_tree_root,
            member_pubkeys_root,
        };
        self.channel_tree.update(channel.as_u64(), registered_leaf);

        // ── update_user witness: all-padding slots (no leaf transition ⇒ account tree unchanged)
        // ──
        let dummy_account_proof = ChannelMerkleProof::dummy(CHANNEL_TREE_HEIGHT);
        let dummy_send_proof = SendMerkleProof::dummy(SEND_TREE_HEIGHT);
        let dummy_member_proof = MemberMerkleProof::dummy(crate::constants::MEMBER_TREE_HEIGHT);
        let dummy_regev = RegevPk {
            a: vec![0u32; REGEV_N],
            b: vec![0u32; REGEV_N],
        };
        let mut prev_account_leaves = Vec::with_capacity(num_users as usize);
        let mut user_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut send_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut member_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut member_regev_pks = Vec::with_capacity(num_users as usize);
        let mut member_pk_bs = Vec::with_capacity(num_users as usize);
        for _ in 0..num_users {
            prev_account_leaves.push(ChannelLeaf::default());
            user_merkle_proofs.push(dummy_account_proof.clone());
            send_merkle_proofs.push(dummy_send_proof.clone());
            member_merkle_proofs.push(dummy_member_proof.clone());
            member_regev_pks.push(dummy_regev.clone());
            member_pk_bs.push(PoseidonHashOut::default());
        }

        let block_witness = BlockHashChainProcessorWitness {
            deposit_step_witness: Vec::new(),
            // The single registration drives the channel-reg chain proof in `prove_block`.
            channel_reg_step_witness: vec![(record, channel_merkle_proof)],
            block: block.clone(),
            prev_account_leaves,
            user_merkle_proofs,
            send_merkle_proofs,
            public_state_merkle_proof,
            member_merkle_proofs: Some(member_merkle_proofs),
            member_regev_pks: Some(member_regev_pks),
            member_pk_bs: Some(member_pk_bs),
            msg_fields: Some(SmallBlockMessageFields::default()),
            tx_v2_indices: None,
            tx_v2s: None,
            tx_v2_merkle_proofs: None,
            channel_action_indices: None,
            channel_actions: None,
            channel_action_merkle_proofs: None,
        };

        self.block_chain_witness
            .insert(new_block_number, block_witness);

        self.channel_reg_hash_chain = new_channel_reg_hash_chain;
        self.block_hash_chain = block.hash_with_prev_hash(self.block_hash_chain)?;
        self.blocks.push(block);
        self.block_number = new_block_number;

        Ok(channel)
    }

    /// Convenience wrapper: queue a registration and immediately produce its registration block.
    /// Returns the channel's member key material. Kept so existing call sites that just want a
    /// registered channel before its first updating block keep working with the in-band path.
    pub fn register_channel(&mut self, channel_id: u32) -> ChannelMemberKeys {
        let channel = ChannelId::new(channel_id as u64).expect("channel id");
        if self.channel_tree.get_leaf(channel.as_u64()) != ChannelLeaf::default() {
            // Already registered on-chain: return the existing keys (idempotent).
            return self
                .channel_members
                .get(&channel)
                .cloned()
                .expect("registered channel must have recorded member keys");
        }
        let keys = self.add_channel_registration(channel_id);
        self.add_registration_block(0)
            .expect("produce registration block");
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
            self.channel_reg_hash_chain,
            self.current_bp_sig_chain(),
        )
    }

    /// P2b: the running bp IMSB-signature list commitment over all signing events so far (the
    /// authoritative value the validity proof's `final.bp_sig_chain` must equal). Folds
    /// `(IMSB_digest, bp_pk_g)` pairs with the shared `poseidon_sig::list` native helper.
    pub fn current_bp_sig_chain(&self) -> Bytes32 {
        let pairs: Vec<(Bytes32, Bytes32)> = self
            .bp_sig_events
            .iter()
            .map(|(sk, digest)| (*digest, sk.public_key()))
            .collect();
        crate::poseidon_sig::list::list_commitment(&pairs)
    }

    /// P2b: build the recursive `ListCircuit` proof over all recorded bp IMSB signing events (block
    /// order). Returns `None` when there were no signing blocks in the span (the validity circuit
    /// then gates the list verification off). Each event becomes one `SingleSigCircuit` proof over
    /// the bp's IMSB digest, folded into the running `ListCircuit` proof; its final commitment
    /// equals [`Self::current_bp_sig_chain`].
    pub fn build_bp_sig_list_proof(
        &self,
        single_sig: &crate::poseidon_sig::circuit::SingleSigCircuit,
        list: &crate::poseidon_sig::list::ListCircuit,
    ) -> anyhow::Result<
        Option<
            plonky2::plonk::proof::ProofWithPublicInputs<
                plonky2::field::goldilocks_field::GoldilocksField,
                plonky2::plonk::config::PoseidonGoldilocksConfig,
                2,
            >,
        >,
    > {
        if self.bp_sig_events.is_empty() {
            return Ok(None);
        }
        let pairs: Vec<(Bytes32, Bytes32)> = self
            .bp_sig_events
            .iter()
            .map(|(sk, digest)| (*digest, sk.public_key()))
            .collect();
        let mut prev = None;
        for (i, (sk, digest)) in self.bp_sig_events.iter().enumerate() {
            let sig = single_sig.prove(sk, *digest)?;
            let prefix = crate::poseidon_sig::list::list_commitment(&pairs[0..i]);
            prev = Some(list.prove_append(&sig, prefix, &prev)?);
        }
        Ok(prev)
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

        // Ordinary (non-registration) block: the channel_reg_hash_chain is unchanged. It is folded
        // into the block hash (G6), mirroring how the unchanged deposit_hash_chain is carried.
        let block = Block::new(
            num_users,
            channel_id,
            key_ids,
            timestamp,
            tx_tree_root,
            projected_deposit_hash_chain,
            self.channel_reg_hash_chain,
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
                .pk_g
                .into();
            let fields = SmallBlockMessageFields {
                bp_member_slot: bp_slot as u32,
                bp_pk_g: bp_hash,
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

        let mut member_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut member_regev_pks = Vec::with_capacity(num_users as usize);
        let mut member_pk_bs = Vec::with_capacity(num_users as usize);
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
                member_merkle_proofs.push(dummy_member_proof.clone());
                member_regev_pks.push(dummy_regev.clone());
                member_pk_bs.push(PoseidonHashOut::default());
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

            // Real member witness for the updating (bp) slot; dummy otherwise. P2b: instead of an
            // inline SPHINCS+ signature, we record the bp's `(secret_key, IMSB_digest)` signing
            // event so the validity level can produce the `SingleSigCircuit` proof and fold it into
            // the `ListCircuit` proof (decision D3). The folded `(digest, pk_g)` pair is bound here
            // via the member-leaf inclusion.
            if updating[i] {
                let keys = member_keys.as_ref().ok_or_else(|| {
                    BlockWitnessGeneratorError::InvalidRequest(format!(
                        "channel {} updating slot {} but not registered",
                        channel_id, i
                    ))
                })?;
                let digest = signed_digest.expect("updating slot implies a signed digest");
                // Record the bp signing event (block order) for the list proof.
                self.bp_sig_events.push((keys.secret_keys[i], digest));
                member_merkle_proofs.push(keys.member_tree.prove(i as u64));
                member_regev_pks.push(keys.regev_pks[i].clone());
                // P3: the bp slot's pk_b for the 3-field MemberLeaf inclusion (matches the leaf
                // pushed into `member_tree` at construction).
                member_pk_bs.push(keys.member_tree.get_leaf(i as u64).pk_b);
            } else {
                member_merkle_proofs.push(dummy_member_proof.clone());
                member_regev_pks.push(dummy_regev.clone());
                member_pk_bs.push(PoseidonHashOut::default());
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
            // Ordinary (non-registration) block: no channel registrations, so the channel-reg chain
            // proof is None and the channel_reg_hash_chain stays unchanged (G5 adds the in-band
            // registration-block path).
            channel_reg_step_witness: Vec::new(),
            block: block.clone(),
            prev_account_leaves,
            user_merkle_proofs,
            send_merkle_proofs,
            public_state_merkle_proof,
            // Real per-slot member witnesses (updating slots) + dummies (padding/non-updating).
            member_merkle_proofs: Some(member_merkle_proofs),
            member_regev_pks: Some(member_regev_pks),
            member_pk_bs: Some(member_pk_bs),
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
