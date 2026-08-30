use crate::{
    circuits::{
        balance::common::{
            account_state::AccountState,
            update_public_state::{UpdatePublicState, UpdatePublicStateError},
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessorWitness,
            channel_state_message::ChannelStateMessageFields,
            ext_public_state::ExtendedPublicState,
            update_channel_tree::channel_leaf_member_root,
        },
    },
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
            key_tree::{MemberLeaf, MemberTree},
            public_state_tree::{PublicStateMerkleProof, PublicStateTree},
            tx_v2_tree::{ChannelActionMerkleProof, TxV2MerkleProof},
        },
        tx::{ChannelAction, TxClass, TxV2},
        u63::{BlockNumber, BlockNumberError, U63},
    },
    constants::{CHANNEL_TREE_HEIGHT, MAX_CHANNEL_TOKENS, MAX_SIG_CLUSTER, SEND_TREE_HEIGHT},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    falcon_sig::{
        FalconKeys,
        agg::{FalconAggCircuit, FalconAggWitness},
        agg_list::{AggListCircuit, AggListEntry, agg_list_commitment},
        gadget::FalconSigGadgetWitness,
    },
    regev::{REGEV_N, REGEV_Q, RegevPk, hash_sig::BabyBearSecretKey},
    utils::{leafable::Leafable as _, poseidon_hash_out::PoseidonHashOut},
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
/// per channel; the member tree is height MEMBER_TREE_HEIGHT (MAX_SIG_CLUSTER = 8 slots) with
/// slots 3..8 left as empty leaves (padding). Kept at 3 so existing validity/balance tests are
/// unchanged.
pub const TEST_ACTIVE_MEMBERS: usize = 3;

/// The ONE canonical per-(channel, slot) deterministic Falcon member-key derivation.
///
/// `close_circuit::test_fixture::deterministic_falcon_keys` delegates here, so the L1 REGISTRATION
/// member set (`ChannelMemberKeys::deterministic` -> `to_reg_record`) and the CLOSE fixture's
/// signing keys are derived from the same seeds and therefore commit to the same `pk_g` values.
/// (Before falcon-sig Phase 3 they did not: registration used the Goldilocks key.)
pub fn deterministic_member_falcon_keys(channel_id: u32, n: usize) -> Vec<FalconKeys> {
    (0..n)
        .map(|slot| {
            // SECURITY (Phase-3 review MINOR): the slot rides one byte, so two slots >= 255 apart
            // would collide into ONE identity — and this repo has already shipped and fixed a
            // u8-slot-256 bug once (project_option_b_1024). Unreachable at MAX_SIG_CLUSTER = 8,
            // but assert rather than rely on that staying true.
            assert!(
                slot < 255,
                "slot {slot} exceeds the single-byte seed encoding"
            );
            let mut s = [0u8; 32];
            s[0..4].copy_from_slice(&channel_id.to_le_bytes());
            s[8] = 0xfa;
            s[31] = slot as u8 + 1;
            FalconKeys::from_seed(s)
        })
        .collect()
}

/// The member identity committed in a `MemberLeaf`: the Falcon `pk_g = Poseidon(IMFK ‖ encode(h))`
/// as a `PoseidonHashOut`. `falcon_pk_digest` returns a canonical Poseidon-hash-out `Bytes32`, so
/// the conversion is exact (never a reduction).
fn falcon_pk_g_hash_out(key: &FalconKeys) -> PoseidonHashOut {
    key.pk_g()
        .try_into()
        .expect("Falcon pk_g is a canonical Poseidon hash out")
}

/// One recorded N-of-N signing event: for one signing block, the channel's IMCH channel-state
/// digest and the signature of EVERY active member over it (small-block N-of-N design §5.3).
///
/// The Falcon signatures are produced NATIVELY at `add_block` time (~ms each) and stored as the
/// exact gadget witnesses `FalconAggWitness` consumes (`FalconAggWitness { message: digest,
/// active: witnesses }`), so the generator never has to hold a signing key open until proving
/// time. `signer_pks` are the signers' Falcon identities in SLOT ORDER — the same values committed
/// in the member leaves, folded into the block's `pk_list_digest`.
#[derive(Debug, Clone)]
pub struct BpSigEvent {
    pub digest: Bytes32,
    pub signer_pks: Vec<Bytes32>,
    pub witnesses: Vec<FalconSigGadgetWitness>,
}

impl BpSigEvent {
    /// The statement this block folds into the chain.
    pub fn entry(&self) -> AggListEntry {
        AggListEntry {
            message: self.digest,
            signer_pks: self.signer_pks.clone(),
        }
    }
}

/// Test-only per-channel member key material (one **Falcon-512/Poseidon** signing key per member).
///
/// Holds the channel's `TEST_ACTIVE_MEMBERS` active [`FalconKeys`] + Regev public keys (slot order)
/// and the Poseidon `MemberTree` (height MEMBER_TREE_HEIGHT, padding slots = empty leaves) whose
/// root is committed into the channel's `ChannelLeaf`. When the block-producer slot updates,
/// `add_block` signs the block's IMSB digest with the bp's Falcon key and records the signing event
/// (`BpSigEvent`); the list proof over those events is produced at the validity level (P2b decision
/// D3, falcon-sig Phase 3).
///
/// SECURITY (DD-2, falcon-sig): the `MemberLeaf.pk_g` committed here is the FALCON identity
/// `Poseidon(IMFK ‖ encode(h))` — the same 32-byte slot, a different derivation. It MUST equal the
/// `pk_g` the list step derives from the witnessed `h`, or the validity circuit's
/// `C == final.bp_sig_chain` assertion fails.
///
/// Each key is behind an `Arc` only because [`FalconKeys`] is deliberately NOT `Clone` (that
/// non-`Clone`ness is what stops tests from silently duplicating a signer) while this struct is
/// cloned all over the generator. Per-key (rather than one `Arc` over the whole `Vec`) so
/// [`ChannelMemberKeys::from_member_keys`] can share the wallet's OWN key objects instead of
/// re-deriving twins — see the finding-7 note there.
#[derive(Clone)]
pub struct ChannelMemberKeys {
    pub falcon_keys: Vec<std::sync::Arc<FalconKeys>>,
    /// Per-member BabyBear hash-sig secret keys (P3). Their `pk_b` digests are committed into the
    /// 3-field `MemberLeaf` / registration record.
    pub baby_keys: Vec<BabyBearSecretKey>,
    pub regev_pks: Vec<RegevPk>,
    pub member_tree: MemberTree,
}

/// Public-only channel material needed by the validity witness generator.
///
/// This deliberately contains no Falcon or BabyBear secret key. A production block producer
/// learns the member leaves from the in-band [`ChannelRegRecord`], receives the full Regev public
/// keys needed by `update_channel_tree`, and consumes the members' already-collected Falcon
/// cosignatures through [`ChannelCosignBundle`]. Keeping this separate from [`ChannelMemberKeys`]
/// prevents the production path from accidentally inheriting the fixture harness's ability to
/// sign for every member.
#[derive(Clone, Debug)]
pub struct RegisteredChannelPublicData {
    pub regev_pks: Vec<RegevPk>,
    pub member_tree: MemberTree,
    pub member_count: usize,
}

#[derive(Clone)]
struct LocalTestSigners(Vec<std::sync::Arc<FalconKeys>>);

impl core::fmt::Debug for LocalTestSigners {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("LocalTestSigners")
            .field(&format_args!("<{} secret keys redacted>", self.0.len()))
            .finish()
    }
}

impl RegisteredChannelPublicData {
    fn from_record_and_regev_pks(
        record: &ChannelRegRecord,
        regev_pks: Vec<RegevPk>,
    ) -> Result<Self, BlockWitnessGeneratorError> {
        record.validate().map_err(|e| {
            BlockWitnessGeneratorError::InvalidRequest(format!(
                "invalid channel registration record: {e}"
            ))
        })?;
        if record.delegate_count != 0 {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "channel {} registration has delegate_count {}: the validity registration \
                 circuit is cosigner-only and requires zero delegates",
                record.channel_id.as_u64(),
                record.delegate_count
            )));
        }
        let member_count = record.member_count as usize;
        if regev_pks.len() != member_count {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "channel {} registration has {member_count} members but {} Regev public keys",
                record.channel_id.as_u64(),
                regev_pks.len()
            )));
        }

        let mut member_tree = MemberTree::init();
        for (slot, (entry, regev_pk)) in record
            .members
            .iter()
            .zip(regev_pks.iter())
            .take(member_count)
            .enumerate()
        {
            let actual_regev_digest = Bytes32::from(regev_pk.poseidon_digest());
            if actual_regev_digest != entry.regev_pk_digest {
                return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                    "channel {} slot {slot}: supplied Regev public key digest {} does not match \
                     the registered digest {}",
                    record.channel_id.as_u64(),
                    actual_regev_digest,
                    entry.regev_pk_digest
                )));
            }
            member_tree.push(MemberLeaf {
                pk_g: entry.pk_g.reduce_to_hash_out(),
                pk_b: entry.pk_b.reduce_to_hash_out(),
                regev_pk_digest: entry.regev_pk_digest.reduce_to_hash_out(),
            });
        }

        Ok(Self {
            regev_pks,
            member_tree,
            member_count,
        })
    }
}

impl core::fmt::Debug for ChannelMemberKeys {
    // INTENTIONALLY SIMPLE: `FalconKeys` has no `Debug` (secret material); print only the count.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelMemberKeys")
            .field(
                "falcon_keys",
                &format_args!("<{} redacted>", self.falcon_keys.len()),
            )
            .field("baby_keys", &self.baby_keys.len())
            .field("regev_pks", &self.regev_pks.len())
            .field("member_tree_root", &self.member_tree.get_root())
            .finish()
    }
}

impl ChannelMemberKeys {
    /// Build deterministic member keys + tree for `channel_id`. Seeds are derived from the channel
    /// id so the same channel always yields the same members (stable across re-runs). Active
    /// members occupy slots `0..TEST_ACTIVE_MEMBERS`; the remaining `MemberTree` slots stay empty
    /// (pad-to-MAX D6).
    ///
    /// `pub` (multitoken Phase 5b): `generate_close_fixture` derives the CLOSE fixture's signing
    /// keys from THIS function so the close proof's `member_set_commitment` equals the member set
    /// that `generate_withdrawal_fixture` registers (both fixture generators share the single
    /// deterministic derivation — the co-generation `CloseLifecycleE2E` requires to run its
    /// close-intent section).
    pub fn deterministic(channel_id: u32) -> Self {
        // SECURITY / single-derivation: the member Falcon keys come from the ONE canonical
        // per-(channel, slot) formula, `close_circuit::test_fixture::deterministic_falcon_keys`,
        // which the close fixture generator also uses — so the registered member set and the close
        // proof's `member_set_commitment` are derived from the SAME keys (this closes half of the
        // falcon-sig Phase-2 seam; the wallet's own `MemberKeys` is still Phase-4 work).
        let falcon_keys = deterministic_member_falcon_keys(channel_id, TEST_ACTIVE_MEMBERS);
        let mut baby_keys = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut regev_pks = Vec::with_capacity(TEST_ACTIVE_MEMBERS);
        let mut member_tree = MemberTree::init();
        for slot in 0..TEST_ACTIVE_MEMBERS as u32 {
            // Deterministic BabyBear hash-sig key (P3): seed an RNG from the (channel, slot) so
            // pk_b is stable across re-runs and distinct per member.
            let baby_seed = (channel_id as u64)
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add((slot as u64) << 8)
                .wrapping_add(0xb1);
            let mut baby_rng = rand::rngs::StdRng::seed_from_u64(baby_seed);
            let baby = BabyBearSecretKey::random(&mut baby_rng);
            let pk_b: PoseidonHashOut = baby.public_key().to_bytes32().reduce_to_hash_out();
            let regev = deterministic_regev_pk(channel_id.wrapping_mul(31).wrapping_add(slot + 1));
            member_tree.push(MemberLeaf {
                pk_g: falcon_pk_g_hash_out(&falcon_keys[slot as usize]),
                pk_b,
                regev_pk_digest: regev.poseidon_digest(),
            });
            baby_keys.push(baby);
            regev_pks.push(regev);
        }
        Self {
            falcon_keys: falcon_keys.into_iter().map(std::sync::Arc::new).collect(),
            baby_keys,
            regev_pks,
            member_tree,
        }
    }

    /// Build `ChannelMemberKeys` from REAL wallet `MemberKeys` (Falcon + BabyBear + REAL
    /// Regev), so a channel registered in the validity proof has EXACTLY the same `(pk_g, pk_b,
    /// regev_pk_digest)` member set as the channel-layer `build_record` (B-2: the small-block
    /// `bp_pk_g` the validity circuit verifies is a genuine registered member, and the channel's
    /// `member_pubkeys_root` matches the registration's). Unlike `deterministic`, the Regev keys
    /// are real keypairs (the secret lives with the wallet, NOT here — validity never
    /// decrypts).
    ///
    /// SECURITY (falcon-sig Phase 4, closing the Phase-3 seam): the member's FALCON identity is
    /// read off `MemberKeys` itself — the SAME key object the wallet co-signs channel states
    /// with, shared by refcount rather than re-derived. There is therefore no second derivation
    /// that could disagree with the first (Phase-3 review finding 7), and no `falcon_keys`
    /// argument for a caller to pass inconsistently.
    pub fn from_member_keys(keys: &[crate::wallet_core::MemberKeys]) -> Self {
        let falcon_keys: Vec<std::sync::Arc<FalconKeys>> =
            keys.iter().map(|k| k.falcon_key_handle()).collect();
        let mut member_tree = MemberTree::init();
        let (mut baby_keys, mut regev_pks) = (Vec::new(), Vec::new());
        // SECURITY (Option B): this is the REGISTERED member tree — cosigners only, at most
        // `MAX_SIG_CLUSTER` slots. Callers MUST pass exactly the co-signing member set (delegates
        // are NOT registered on L1; they are authenticated by the cosigner-signed H1 slot tree
        // and never enter this tree). The `MemberTree::init()` height caps at `MAX_SIG_CLUSTER`
        // leaves, so passing more panics loudly rather than silently truncating.
        assert!(
            keys.len() <= MAX_SIG_CLUSTER,
            "from_member_keys: {} keys exceed the cosigner-only registered tree capacity \
             ({MAX_SIG_CLUSTER}); delegates must not be registered (Option B)",
            keys.len()
        );
        for (k, falcon) in keys.iter().zip(falcon_keys.iter()) {
            let pk_b: PoseidonHashOut = k.baby_key.public_key().to_bytes32().reduce_to_hash_out();
            member_tree.push(MemberLeaf {
                pk_g: falcon_pk_g_hash_out(falcon),
                pk_b,
                regev_pk_digest: k.regev_pk.poseidon_digest(),
            });
            baby_keys.push(k.baby_key.clone());
            regev_pks.push(k.regev_pk.clone());
        }
        Self {
            falcon_keys,
            baby_keys,
            regev_pks,
            member_tree,
        }
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
        self.to_reg_record_split(channel_id, TEST_ACTIVE_MEMBERS as u32, 0)
    }

    /// Like [`Self::to_reg_record`] but with an explicit `member_count` / `delegate_count` split.
    /// `active = member_count + delegate_count` entries are emitted from the member tree.
    ///
    /// SECURITY (Option B): the reg record has only `MAX_SIG_CLUSTER` slots — registration is
    /// cosigners-only, and registration-producing paths emit `delegate_count = 0`. A nonzero
    /// `delegate_count` is accepted only within the fixed 8-slot registration capacity;
    /// anything beyond is rejected here (and by `ChannelRegRecord::validate`).
    ///
    /// SECURITY (small-block N-of-N Phase 1): `delegate_count == 0` is now a CIRCUIT CONSTRAINT in
    /// `ChannelRegStepCircuit`. `validate()` still accepts a nonzero split, but the resulting
    /// record is UNPROVABLE — do not build one here expecting the reg-chain step to fold it.
    pub fn to_reg_record_split(
        &self,
        channel_id: u32,
        member_count: u32,
        delegate_count: u32,
    ) -> ChannelRegRecord {
        let active = (member_count + delegate_count) as usize;
        assert!(
            active <= MAX_SIG_CLUSTER,
            "active participants {active} exceed the reg record's MAX_SIG_CLUSTER slots (Option B: \
             registration carries cosigners only)"
        );
        let mut members: [MemberRegEntry; MAX_SIG_CLUSTER] =
            std::array::from_fn(|_| MemberRegEntry::default());
        for (i, entry) in members.iter_mut().enumerate().take(active) {
            let leaf = self.member_tree.get_leaf(i as u64);
            *entry = MemberRegEntry {
                pk_g: Bytes32::from(leaf.pk_g),
                pk_b: Bytes32::from(leaf.pk_b),
                regev_pk_digest: Bytes32::from(leaf.regev_pk_digest),
                // Deterministic per-(channel, slot) test recipient (keccak preimage only).
                recipient: test_recipient_for(channel_id, i),
            };
        }
        ChannelRegRecord {
            channel_id: ChannelId::new(channel_id as u64).expect("channel id"),
            // Block proposer is slot 0 by convention (matches the first updating slot the later
            // blocks sign with).
            bp_member_slot: 0,
            member_count,
            delegate_count,
            members,
        }
    }
}

/// The canonical deterministic per-(channel, slot) TEST L1 recipient — the SINGLE formula used by
/// the reg record (`to_reg_record_split`), the withdraw-pipeline registration
/// (`wallet_core::build_channel_withdrawal`), and the CLI cosigners' B-1b balance-slot recipients
/// (`channel_member` genesis). Always NONZERO (0x3333_0000-based), so it passes the
/// `BalanceState::validate()` / `registerChannel` zero-recipient rejections.
///
/// SECURITY (B-1b): keeping the reg-record recipient and the balance-slot leaf recipient equal for
/// cosigners means `registeredRecipientOf[pk_g]` (the current Manager check) and the leaf-bound
/// claim recipient agree — the B-2 Manager switch changes WHICH one is authoritative without
/// changing the paid address for cosigners.
pub fn test_recipient_for(channel_id: u32, slot: usize) -> Address {
    Address::from_u32_slice(
        &[0x3333_0000u32
            .wrapping_add(channel_id.wrapping_mul(16))
            .wrapping_add(slot as u32); 5],
    )
    .expect("address from u32 slice")
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
    /// Public per-channel registration material used by both production and fixture paths.
    pub channel_members: HashMap<ChannelId, RegisteredChannelPublicData>,
    /// Fixture-only local Falcon signers. Production registration never populates this map and
    /// therefore cannot take the historical local re-signing fallback.
    local_test_signers: HashMap<ChannelId, LocalTestSigners>,
    /// Full fixture material retained only to preserve the historical idempotent test helpers.
    /// Production registration never populates this map.
    fixture_channel_keys: HashMap<ChannelId, ChannelMemberKeys>,

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
    /// registration record + the channel's public member material; drained into a dedicated
    /// registration block by [`Self::add_registration_block`]. Queued, not yet applied to
    /// `channel_tree` (the registration block applies it).
    pub channel_registrations: Vec<(ChannelRegRecord, RegisteredChannelPublicData)>,
    pub block_chain_witness: HashMap<BlockNumber, BlockHashChainProcessorWitness>,
    /// P2b: the ordered list of N-of-N IMCH signing events over the whole span, in block order.
    /// The validity level folds each into one `falcon_sig::agg_list::AggListCircuit` step (one
    /// recursively verified `FalconAggCircuit` aggregate per signing block) whose commitment must
    /// equal the final `bp_sig_chain` (decision D3, small-block N-of-N Phase 4).
    pub bp_sig_events: Vec<BpSigEvent>,
    /// B-2: the `state_commitment_root` (= post-debit `BalanceState::h1()`, detail2 §C-7) to bind
    /// in the NEXT updating block's IMSB message, so the bp signs the genuine `hash(H1',
    /// tx_tree_root)` channelStateSig (structural atomicity D-3) instead of `hash(H1'=0,
    /// tx_tree_root)`. Consumed by the next `add_block_with_tx_v2`; `None` ⇒ zero (correct for
    /// intra/base-layer blocks).
    pub next_imsb_state_commitment_root: Option<Bytes32>,
    /// Phase 6 (block-producer half): the WALLET's own co-signed `ChannelState` plus the N real
    /// IMCH cosignatures the members produced over it, to back the NEXT updating block.
    ///
    /// When set, the block producer signs NOTHING: it projects the supplied state with
    /// [`ChannelStateMessageFields::from_channel_state`] and decodes the members' existing blobs
    /// into gadget witnesses. Aggregating signatures is public work, so no key material is
    /// involved — the reason Design B needs no second signing round.
    ///
    /// When `None`, the generator falls back to the pre-Phase-6 behaviour: it projects the block's
    /// own fields and signs locally with every member's key. That path is kept because it is what
    /// the checked-in fixture generators drive; switching them over would move every
    /// `bp_sig_chain` and force a fixture regeneration. Consumed by the next
    /// `add_block_with_tx_v2`.
    pub next_channel_cosign: Option<ChannelCosignBundle>,
}

/// A wallet's co-signed channel state and the N real member cosignatures over its IMCH digest —
/// what a block producer actually receives, holding no key of its own.
#[derive(Clone, Debug)]
pub struct ChannelCosignBundle {
    /// The co-signed post-transition state. Its `h2_tag` MUST be the block's `tx_tree_root`; that
    /// is the binding `update_channel_tree` enforces in-circuit, and it is asserted on use.
    pub state: crate::common::channel::ChannelState,
    /// One real Falcon cosignature per active member, slot order (i.e. `state.member_signatures`).
    pub signatures: Vec<crate::common::channel::MemberSignature>,
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
            local_test_signers: HashMap::new(),
            fixture_channel_keys: HashMap::new(),
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),
            channel_reg_hash_chain: Bytes32::default(),
            blocks: vec![Block::default()], // genesis block placeholder
            deposits: HashMap::new(),
            deposit_counts: 0,
            channel_registrations: Vec::new(),
            block_chain_witness: HashMap::new(),
            bp_sig_events: Vec::new(),
            next_imsb_state_commitment_root: None,
            next_channel_cosign: None,
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
    /// The public member tree is recorded immediately in `channel_members`; fixture-only signers
    /// live in a separate private map.
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
        if self.channel_members.contains_key(&channel) {
            return self
                .fixture_channel_keys
                .get(&channel)
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "channel {channel_id} was registered through the public-only production \
                         path and has no fixture keys"
                    )
                });
        }
        let keys = ChannelMemberKeys::deterministic(channel_id);
        let record = keys.to_reg_record(channel_id);
        self.add_channel_registration_material(
            record,
            keys.regev_pks.clone(),
            Some(keys.falcon_keys.clone()),
        )
        .expect("deterministic test registration record must be valid");
        self.fixture_channel_keys.insert(channel, keys.clone());
        keys
    }

    /// Register `channel_id` with PROVIDED real member keys (B-2): the same `(pk_g, pk_b,
    /// regev_pk)` triple the channel-layer `build_record` uses, so the small-block signature
    /// the validity proof verifies (`bp_pk_g ∈ member_pubkeys_root`) is a genuine registered
    /// member and the channel's `member_pubkeys_root` equals the registration's.
    pub fn add_channel_registration_keys(
        &mut self,
        channel_id: u32,
        keys: ChannelMemberKeys,
    ) -> ChannelMemberKeys {
        self.add_channel_registration_keys_split(channel_id, keys, TEST_ACTIVE_MEMBERS as u32, 0)
    }

    /// Like [`Self::add_channel_registration_keys`] but with an explicit member/delegate split
    /// (P5-B). The `keys` member tree must hold `member_count + delegate_count` active leaves.
    pub fn add_channel_registration_keys_split(
        &mut self,
        channel_id: u32,
        keys: ChannelMemberKeys,
        member_count: u32,
        delegate_count: u32,
    ) -> ChannelMemberKeys {
        let channel = ChannelId::new(channel_id as u64).expect("channel id");
        if self.channel_members.contains_key(&channel) {
            return self
                .fixture_channel_keys
                .get(&channel)
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "channel {channel_id} was registered through the public-only production \
                         path and has no fixture keys"
                    )
                });
        }
        let record = keys.to_reg_record_split(channel_id, member_count, delegate_count);
        let active = (member_count + delegate_count) as usize;
        self.add_channel_registration_material(
            record,
            keys.regev_pks[..active].to_vec(),
            Some(keys.falcon_keys[..active].to_vec()),
        )
        .expect("registration record must be valid");
        self.fixture_channel_keys.insert(channel, keys.clone());
        keys
    }

    /// Queue a production registration using public data only.
    ///
    /// No signing key is accepted or retained. Consequently the next updating block MUST stage a
    /// real [`ChannelCosignBundle`]; otherwise block construction fails closed instead of signing
    /// locally. `regev_pks` are checked against every registered digest before any state mutates.
    pub fn add_channel_registration_public(
        &mut self,
        record: ChannelRegRecord,
        regev_pks: Vec<RegevPk>,
    ) -> Result<(), BlockWitnessGeneratorError> {
        self.add_channel_registration_material(record, regev_pks, None)
    }

    fn add_channel_registration_material(
        &mut self,
        record: ChannelRegRecord,
        regev_pks: Vec<RegevPk>,
        local_test_signers: Option<Vec<std::sync::Arc<FalconKeys>>>,
    ) -> Result<(), BlockWitnessGeneratorError> {
        let channel = record.channel_id;
        if self.channel_members.contains_key(&channel)
            || self
                .channel_registrations
                .iter()
                .any(|(queued, _)| queued.channel_id == channel)
        {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "channel {} is already registered or queued",
                channel.as_u64()
            )));
        }
        let public = RegisteredChannelPublicData::from_record_and_regev_pks(&record, regev_pks)?;
        if let Some(signers) = local_test_signers {
            if signers.len() != public.member_count {
                return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                    "channel {} fixture signer count {} does not match member_count {}",
                    channel.as_u64(),
                    signers.len(),
                    public.member_count
                )));
            }
            self.local_test_signers
                .insert(channel, LocalTestSigners(signers));
        }
        self.channel_registrations.push((record, public.clone()));
        self.channel_members.insert(channel, public);
        Ok(())
    }

    /// Security introspection used by production-boundary tests and startup checks.
    pub fn holds_local_signing_keys(&self, channel: ChannelId) -> bool {
        self.local_test_signers.contains_key(&channel)
    }

    /// TEST-ONLY (`#[cfg(test)]`, therefore absent from every non-test build): re-seat the fixture
    /// harness's per-slot Falcon signing keys after a §Q-3 member-set update rotated or added a
    /// member. [`Self::advance_registered_member_set`] DROPS the stale list on purpose, so an
    /// MSU round-trip test has to hand the harness the new member's key explicitly — which is the
    /// point: it makes the key change visible in the test instead of letting a stale key ride
    /// along. Production registrations hold no signing key here and never call this.
    #[cfg(test)]
    pub(crate) fn replace_local_test_signers(
        &mut self,
        channel: ChannelId,
        signers: Vec<std::sync::Arc<FalconKeys>>,
    ) {
        self.local_test_signers
            .insert(channel, LocalTestSigners(signers));
    }

    /// detail2 §Q-3 — SECURITY (M-2): advance the generator's authoritative mirror of a channel's
    /// REGISTERED member set after a member-set-update block wrote the new root into the channel
    /// leaf. Called from exactly one place: the leaf write in
    /// [`Self::add_block_with_tx_v2_inner`], gated on the shared
    /// `channel_leaf_member_root` predicate having actually changed the root — so the mirror and
    /// the proven leaf cannot advance independently.
    ///
    /// `new_member_leaves` is the same all-`MAX_SIG_CLUSTER`-slots array the circuit folds, so the
    /// mirror's `member_tree` reproduces the leaf's committed root by construction, and
    /// `member_count` is its occupancy (left-packed and equal to `signer_count`, which
    /// `check_n_of_n_witness` turns into a theorem).
    fn advance_registered_member_set(
        &mut self,
        channel: ChannelId,
        new_member_leaves: &[MemberLeaf],
    ) -> Result<(), BlockWitnessGeneratorError> {
        if new_member_leaves.len() != MAX_SIG_CLUSTER {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "channel {}: a member-set update must carry all {MAX_SIG_CLUSTER} member leaves, \
                 got {}",
                channel.as_u64(),
                new_member_leaves.len()
            )));
        }
        let public = self.channel_members.get_mut(&channel).ok_or_else(|| {
            BlockWitnessGeneratorError::InvalidRequest(format!(
                "channel {} advanced its member root but is not registered in this generator",
                channel.as_u64()
            ))
        })?;
        let mut member_tree = MemberTree::init();
        for leaf in new_member_leaves.iter() {
            member_tree.push(leaf.clone());
        }
        public.member_tree = member_tree;
        public.member_count = new_member_leaves
            .iter()
            .filter(|leaf| **leaf != MemberLeaf::empty_leaf())
            .count();

        // FAIL-CLOSED (fixture path only): the harness's local Falcon keys are per-slot and are
        // NOT rotated by a §Q-3 update — an ADD brings a member whose key the harness never held,
        // and a ROTATE replaces one it does. Keeping a stale list would let the next block be
        // built with signatures over the wrong `pk_g`s and fail thousands of constraints deep in
        // proving. Drop it instead, so the next block for this channel fails at witness
        // construction with the existing "no cosignatures staged and no local signing keys"
        // message. Production registrations hold no keys here at all and are unaffected.
        let leaves_match = self
            .local_test_signers
            .get(&channel)
            .map(|signers| {
                signers.0.len() == public.member_count
                    && signers.0.iter().enumerate().all(|(slot, key)| {
                        key.pk_g().reduce_to_hash_out() == new_member_leaves[slot].pk_g
                    })
            })
            .unwrap_or(true);
        if !leaves_match {
            self.local_test_signers.remove(&channel);
        }
        Ok(())
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
        let (record, public) = self.channel_registrations.remove(0);
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
        let member_pubkeys_root = public.member_tree.get_root();
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
        let dummy_regev = RegevPk {
            a: vec![0u32; REGEV_N],
            b: vec![0u32; REGEV_N],
        };
        let mut prev_account_leaves = Vec::with_capacity(num_users as usize);
        let mut user_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut send_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut member_regev_pks = Vec::with_capacity(num_users as usize);
        for _ in 0..num_users {
            prev_account_leaves.push(ChannelLeaf::default());
            user_merkle_proofs.push(dummy_account_proof.clone());
            send_merkle_proofs.push(dummy_send_proof.clone());
            member_regev_pks.push(dummy_regev.clone());
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
            // A registration block transitions no channel leaf, so it applies no member
            // signature and carries no member set (the N-of-N binding is gated on a block
            // actually signing).
            member_leaves: None,
            new_member_leaves: None,
            signer_count: None,
            member_regev_pks: Some(member_regev_pks),
            channel_state_fields: None,
            // A registration block is all-padding (R6): no key slot transitions a leaf, so
            // `update_channel_tree` skips every slot and there is no TxV2 — and therefore no
            // channel action — to open. `None` here is structural, not the M-2 hard-coding: the
            // §Q wiring lives on the ordinary-block path, which is the only one that can carry a
            // `TxClass::ChannelAction` slot.
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
                .fixture_channel_keys
                .get(&channel)
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "channel {channel_id} was registered through the public-only production \
                         path and has no fixture keys"
                    )
                });
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

    /// The running N-of-N signature list commitment over all signing events so far (the
    /// authoritative value the validity proof's `final.bp_sig_chain` must equal). Folds
    /// `(IMCH_digest, signer_count, pk_list_digest)` statements with the shared
    /// `falcon_sig::agg_list` native helper — the SAME formula `update_channel_tree` folds
    /// in-circuit.
    pub fn current_bp_sig_chain(&self) -> Bytes32 {
        let entries: Vec<AggListEntry> = self.bp_sig_events.iter().map(BpSigEvent::entry).collect();
        agg_list_commitment(&entries)
    }

    /// Build the recursive N-of-N `AggListCircuit` proof over every recorded signing event (block
    /// order, ONE `FalconAggCircuit` aggregate per signing block over ALL that block's members).
    /// Returns `None` when there were no signing blocks in the span — the case
    /// `ValidityCircuit::prove` takes with its dummy proof.
    ///
    /// This is the ONLY list-proof builder (small-block N-of-N design §9 Phase 4). The former
    /// `build_legacy_single_sig_list_proof`, which folded ONE signature per step against
    /// `falcon_sig::list::ListCircuit`, was deleted rather than left dead: since the Phase-3 rewire
    /// of `update_channel_tree` the block folds `(IMCH_digest, signer_count, pk_list_digest)`, so
    /// that proof's commitment is NOT [`Self::current_bp_sig_chain`], and the two list wrappers'
    /// `CommonCircuitData` are byte-identical — meaning a caller wiring the stale builder to a
    /// `ValidityCircuit` would COMPILE and only fail deep inside proving.
    ///
    /// The commitment this returns is exactly [`Self::current_bp_sig_chain`], which is what the
    /// validity circuit asserts against `final.bp_sig_chain`.
    pub fn build_agg_sig_list_proof(
        &self,
        agg: &FalconAggCircuit<
            plonky2::field::goldilocks_field::GoldilocksField,
            plonky2::plonk::config::PoseidonGoldilocksConfig,
            2,
        >,
        agg_list: &AggListCircuit<
            plonky2::field::goldilocks_field::GoldilocksField,
            plonky2::plonk::config::PoseidonGoldilocksConfig,
            2,
        >,
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
        let entries: Vec<AggListEntry> = self.bp_sig_events.iter().map(BpSigEvent::entry).collect();
        let mut prev = None;
        for (i, event) in self.bp_sig_events.iter().enumerate() {
            // One aggregate over EVERY member that signed this block's IMCH digest. The recorded
            // gadget witnesses are exactly `FalconAggWitness`'s `active` slice, in slot order.
            let witness = FalconAggWitness {
                message: event.digest,
                active: event.witnesses.clone(),
            };
            let agg_proof = agg.prove(&witness)?;
            let prefix = agg_list_commitment(&entries[0..i]);
            prev = Some(agg_list.prove_append(&agg_proof, prefix, &prev)?);
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
        // Construct on a private snapshot and commit only after every native check succeeds.
        // Several validation failures occur after deposit/public-state projections are built;
        // mutating `self` directly would otherwise consume queued deposits or advance Merkle
        // state even though no block was produced.
        let mut candidate = self.clone();
        candidate.add_block_with_tx_v2_inner(
            channel_id,
            key_ids,
            timestamp,
            tx_tree_root,
            tx_v2_witness,
        )?;
        *self = candidate;
        Ok(())
    }

    fn add_block_with_tx_v2_inner(
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
            // detail2 §Q-2/§Q-3 — SECURITY (M-2): a `TxClass::ChannelAction` slot whose
            // channel-action sub-witness is missing would be silently replaced downstream by
            // `ChannelAction::default()` (kind = `InterChannelSend`), which
            //   (a) turns `is_member_update` off, so the proven leaf keeps the OLD member root
            //       while the caller believes it advanced one, and
            //   (b) fails the circuit's channel-action inclusion opening anyway, but only at
            //       proving time, thousands of constraints deep.
            // Refuse here, at witness construction, where the message can name the cause.
            let has_channel_action_slot = witness
                .tx_v2s
                .iter()
                // `key_ids` is the unpadded prefix of `block.key_ids`; every slot beyond it is
                // padding (key_id 0), which `update_channel_tree` skips.
                .zip(key_ids.iter())
                .any(|(tx, &k)| k != 0 && tx.tx_class == TxClass::ChannelAction);
            let action_lens = (
                witness.channel_action_indices.as_ref().map(|v| v.len()),
                witness.channel_actions.as_ref().map(|v| v.len()),
                witness.channel_action_merkle_proofs.as_ref().map(|v| v.len()),
            );
            let n = Some(num_users as usize);
            if has_channel_action_slot && action_lens != (n, n, n) {
                return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                    "a TxClass::ChannelAction slot requires a channel-action sub-witness with \
                     num_users={num_users} entries (got indices={:?}, actions={:?}, proofs={:?}); \
                     without it the proven block would carry ChannelAction::default() and §Q \
                     would silently not apply (M-2)",
                    action_lens.0, action_lens.1, action_lens.2,
                )));
            }
            if !has_channel_action_slot && action_lens != (None, None, None)
                && action_lens != (n, n, n)
            {
                return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                    "channel-action sub-witness arrays must all be absent or all have \
                     num_users={num_users} entries (got indices={:?}, actions={:?}, proofs={:?})",
                    action_lens.0, action_lens.1, action_lens.2,
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

        // ── Member-signature witnesses (live `update_channel_tree` N-of-N binding) ────────
        //
        // When a slot `i` transitions the channel leaf this block (`prev != new_block_number`, the
        // circuit's `should_update`), EVERY active member of the channel signs the block's IMCH
        // channel-state digest — that is the N-of-N rule the base layer now enforces (small-block
        // N-of-N design §5.3/§5.4) — and the block carries the channel's whole registered member
        // set so the circuit can recompute `member_pubkeys_root` from it. Blocks that transition
        // nothing carry no member set at all (the binding is gated on signing).
        //
        // `channel` is bound above (auto-register check).
        // `updating[i] = true` iff slot i triggers a leaf transition. All slots reference the SAME
        // channel leaf, so only the FIRST non-padding slot actually transitions it (subsequent
        // slots observe the already-updated leaf with `prev == new_block_number` and do NOT update
        // — this mirrors the per-slot loop below exactly). That first updating slot is the block
        // proposer's slot; posting is NOT a security control (design G5) — the authorization is
        // the N signatures.
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

        // Build the block-level IMCH channel-state message the members sign, and the channel's
        // registered member set.
        //
        // The preimage limbs are a REAL `ChannelState` projection, not filler: `balance_state_h1`
        // is the genuine post-debit H1' the caller supplied for this block (detail2 §C-7, the same
        // value the retired IMSB `state_commitment_root` carried), and `small_block_number` /
        // `state_version` advance with the block. What Phase 6 changes is WHERE the state comes
        // from — the wallet's own `ChannelState` instead of this projection — not that it is real:
        // the digest below is signed by the members' real Falcon keys either way, and `h2_tag` is
        // the block's actual `tx_tree_root`, exactly as the circuit recomputes it.
        let member_keys = channel_opt.and_then(|c| self.channel_members.get(&c).cloned());
        // B-2: bind the real post-debit H1' (detail2 §C-7) if provided for this block
        // (inter-channel small block); `None`/zero is correct for intra-channel and
        // base-layer blocks.
        let imsb_h1 = self
            .next_imsb_state_commitment_root
            .take()
            .unwrap_or_default();
        // Phase 6: a wallet-supplied co-signed state supersedes the projection below.
        let staged_cosign = self.next_channel_cosign.take();
        let (channel_state_fields, signer_leaves, signed_digest) = if any_update_slot.is_some() {
            let public = member_keys.as_ref().ok_or_else(|| {
                BlockWitnessGeneratorError::InvalidRequest(format!(
                    "channel {} has an updating slot but is not registered; call register_channel first",
                    channel_id
                ))
            })?;
            let fields = match staged_cosign.as_ref() {
                // Phase 6: the REAL wallet state. `h2_tag` must already BE this block's tx root —
                // the members signed a preimage containing it, so a mismatch means their
                // signatures authorise some other block. Fail closed rather than sign around it.
                Some(bundle) => {
                    if bundle.state.h2_tag != tx_tree_root {
                        return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                            "channel {channel_id}: the co-signed state's h2_tag does not equal \
                             this block's tx_tree_root; the members did not authorise this block"
                        )));
                    }
                    // FAIL-CLOSED HYGIENE: `from_channel_state` DROPS `channel_fund.channel_id`,
                    // and `preimage` refills that limb ([8]) with the block-level `channel_id`.
                    // The projection therefore reproduces `ChannelState::signing_digest()` limb for
                    // limb ONLY while `channel_fund.channel_id == channel_id` — the documented
                    // production invariant (channel_state_message.rs:112-117), which nothing in
                    // `ChannelState::validate()` actually asserts. If it were violated, the
                    // members' signatures would be over a DIFFERENT digest than
                    // the one recomputed here and would surface as an opaque
                    // verification failure deep in proving. Name it.
                    if bundle.state.channel_fund.channel_id != bundle.state.channel_id {
                        return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                            "channel {channel_id}: the co-signed state's channel_fund.channel_id \
                             ({}) != its channel_id ({}) — the IMCH projection would not reproduce \
                             the digest the members signed",
                            bundle.state.channel_fund.channel_id.as_u64(),
                            bundle.state.channel_id.as_u64()
                        )));
                    }
                    ChannelStateMessageFields::from_channel_state(&bundle.state)
                }
                // Pre-Phase-6 projection, kept because the checked-in fixture generators drive it.
                None => ChannelStateMessageFields {
                    epoch: 0,
                    small_block_number: new_block_number.as_u64(),
                    close_freeze_nonce: 0,
                    fund_amounts: [U256::default(); MAX_CHANNEL_TOKENS],
                    fund_intmax_state_root: Bytes32::default(),
                    balance_state_h1: imsb_h1,
                    shared_native_nullifier_root: Bytes32::default(),
                    unallocated_confirmed_incoming: U256::default(),
                    prev_digest: Bytes32::default(),
                    state_version: new_block_number.as_u64(),
                },
            };
            // `h2_tag` IS this block's tx root (channel.rs: "the own small block's tx_tree_root
            // for an inter-channel send"), which is the entire point of the binding.
            let digest = fields.signing_digest(channel_id, tx_tree_root);
            let leaves: Vec<MemberLeaf> = (0..MAX_SIG_CLUSTER)
                .map(|slot| public.member_tree.get_leaf(slot as u64))
                .collect();
            (fields, Some(leaves), Some(digest))
        } else {
            (ChannelStateMessageFields::default(), None, None)
        };

        // Record the statement this block folds. The recorded gadget witnesses are exactly what
        // `FalconAggWitness { message, active }` consumes, so `build_agg_sig_list_proof` builds the
        // aggregate proofs from them without holding a signing key open until proving time.
        if let (Some(digest), Some(public)) = (signed_digest, member_keys.as_ref()) {
            let (signer_pks, witnesses) = match staged_cosign.as_ref() {
                // Phase 6: DECODE the members' existing cosignatures. The producer holds no key —
                // `FalconAggWitness` consumes only `(h, sig)`, both public, so aggregating is
                // public work. This is the path a real block producer takes.
                Some(bundle) => {
                    let n = public.member_count;
                    if bundle.signatures.len() != n {
                        return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                            "channel {channel_id}: expected {n} member cosignatures (N-of-N), got \
                             {} — block production is blockable by any single member",
                            bundle.signatures.len()
                        )));
                    }
                    let mut signer_pks = Vec::with_capacity(n);
                    let mut witnesses = Vec::with_capacity(n);
                    for (slot, entry) in bundle.signatures.iter().enumerate() {
                        if entry.member_slot as usize != slot {
                            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                                "channel {channel_id}: cosignature {slot} carries member_slot {} \
                                 (must be slot order)",
                                entry.member_slot
                            )));
                        }
                        let (sig, h) = crate::falcon_sig::decode_cosign_blob(&entry.signature)
                            .map_err(|e| {
                                BlockWitnessGeneratorError::InvalidRequest(format!(
                                    "channel {channel_id} slot {slot}: cosignature blob failed to \
                                     decode: {e:?} (a structural placeholder reaching here means \
                                     the co-sign round never completed)"
                                ))
                            })?;
                        // The blob's own `h` is bound to the claimed identity by `pk_g =
                        // Poseidon(IMFK||encode(h))`; reject a substituted public polynomial.
                        if crate::falcon_sig::falcon_pk_digest(&h) != entry.pk_g {
                            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                                "channel {channel_id} slot {slot}: cosignature's public polynomial \
                                 does not hash to the claimed pk_g"
                            )));
                        }
                        signer_pks.push(entry.pk_g);
                        witnesses.push(FalconSigGadgetWitness::for_signature(&h, digest, &sig));
                    }
                    (signer_pks, witnesses)
                }
                // Pre-Phase-6: the harness holds every member's key and signs locally (~ms each).
                None => {
                    let local_signers = channel_opt
                        .and_then(|channel| self.local_test_signers.get(&channel))
                        .ok_or_else(|| {
                            BlockWitnessGeneratorError::InvalidRequest(format!(
                                "channel {channel_id}: no wallet-supplied N-of-N cosignatures were \
                                 staged and this production registration holds no local signing \
                                 keys; collect the members' signatures before producing the block"
                            ))
                        })?;
                    let mut signer_pks = Vec::with_capacity(local_signers.0.len());
                    let mut witnesses = Vec::with_capacity(local_signers.0.len());
                    for key in local_signers.0.iter() {
                        let sig = key.sign(digest);
                        signer_pks.push(key.pk_g());
                        witnesses.push(FalconSigGadgetWitness::for_signature(
                            &key.pk_coefficients(),
                            digest,
                            &sig,
                        ));
                    }
                    (signer_pks, witnesses)
                }
            };
            self.bp_sig_events.push(BpSigEvent {
                digest,
                signer_pks,
                witnesses,
            });
        }

        let mut member_regev_pks = Vec::with_capacity(num_users as usize);
        let dummy_regev = RegevPk {
            a: vec![0u32; REGEV_N],
            b: vec![0u32; REGEV_N],
        };

        for (i, &key_id) in block.key_ids.iter().enumerate() {
            if key_id == 0 {
                prev_account_leaves.push(ChannelLeaf::default());
                user_merkle_proofs.push(dummy_account_proof.clone());
                send_merkle_proofs.push(dummy_send_proof.clone());
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

            // The posting (bp) slot opens its own Regev public key: that binding survives the
            // N-of-N rewire unchanged (design §5.4 item 6 / §4 "cost trap"). Its digest must equal
            // the `regev_pk_digest` of the member leaf at the SAME slot of the witnessed set.
            if updating[i] {
                let keys = member_keys.as_ref().ok_or_else(|| {
                    BlockWitnessGeneratorError::InvalidRequest(format!(
                        "channel {} updating slot {} but not registered",
                        channel_id, i
                    ))
                })?;
                // detail2 §Q-3 residual: `new_member_leaves` commits only a member's
                // `regev_pk_digest`, not the full Regev public key, so an ADD grows
                // `member_count` past the registered `regev_pks`. A ROTATE is safe by §Q-6 (the
                // digest is PRESERVED). Fail closed with a nameable message rather than panicking
                // on an out-of-range slot index.
                let regev_pk = keys.regev_pks.get(i).ok_or_else(|| {
                    BlockWitnessGeneratorError::InvalidRequest(format!(
                        "channel {channel_id} slot {i} is the posting slot but this generator \
                         holds no Regev public key for it (a §Q-3 member-set ADD does not carry \
                         the new member's Regev key; re-supply the channel's registration \
                         material before that member posts)"
                    ))
                })?;
                member_regev_pks.push(regev_pk.clone());
            } else {
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

                // SECURITY (M-2), detail2 §Q-3: the daemon's authoritative channel tree must write
                // the SAME `member_pubkeys_root` the circuit proves. CALL the one shared
                // derivation instead of restating the predicate here.
                //
                // This line used to copy `prev_user_leaf.member_pubkeys_root` unconditionally,
                // which was consistent ONLY because the channel-action sub-witness was hard-coded
                // `None` and `is_member_update` was therefore identically false. Those are M-2's
                // two coupled halves: wiring the actions through without this would have diverged
                // the base state from the proven root on the very first member-set-update block,
                // and every later Merkle opening for the channel would have broken.
                let slot_tx_v2 = tx_v2_witness
                    .as_ref()
                    .map(|w| w.tx_v2s[i])
                    .unwrap_or_default();
                let slot_channel_action = tx_v2_witness
                    .as_ref()
                    .and_then(|w| w.channel_actions.as_ref())
                    .and_then(|actions| actions.get(i))
                    .copied();
                let new_member_leaves: &[MemberLeaf] = tx_v2_witness
                    .as_ref()
                    .and_then(|w| w.new_member_leaves.as_deref())
                    .unwrap_or(&[]);
                let member_pubkeys_root = channel_leaf_member_root(
                    &slot_tx_v2,
                    slot_channel_action.as_ref(),
                    new_member_leaves,
                    prev_user_leaf.member_pubkeys_root,
                );
                let new_user_leaf = ChannelLeaf {
                    index: prev_user_leaf.index + 1,
                    prev: new_block_number,
                    send_tree_root: new_send_root,
                    member_pubkeys_root,
                };
                account_tree_for_proofs.update(channel.as_u64(), new_user_leaf.clone());
                self.channel_tree.update(channel.as_u64(), new_user_leaf);

                // detail2 §Q-3: the leaf advanced, so the REGISTERED set every LATER block is
                // witnessed against advances with it. `UpdateUserTree::check_n_of_n_witness`
                // connects the recomputed member root to the channel leaf's committed
                // `member_pubkeys_root`, so a mirror left on the old set makes the next block for
                // this channel unprovable — the second half of M-2.
                if member_pubkeys_root != prev_user_leaf.member_pubkeys_root {
                    self.advance_registered_member_set(channel, new_member_leaves)?;
                }
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
            // The channel's whole registered member set on a signing block; nothing on a block
            // that transitions no leaf.
            signer_count: signer_leaves
                .as_ref()
                .and_then(|_| member_keys.as_ref().map(|k| k.member_count as u32)),
            member_leaves: signer_leaves,
            // §Q-3: present only when the block's TxV2 witness carries a member-set transition.
            new_member_leaves: tx_v2_witness
                .as_ref()
                .and_then(|w| w.new_member_leaves.clone()),
            member_regev_pks: Some(member_regev_pks),
            channel_state_fields: Some(channel_state_fields),
            tx_v2_indices: tx_v2_witness.as_ref().map(|w| w.tx_v2_indices.clone()),
            tx_v2s: tx_v2_witness.as_ref().map(|w| w.tx_v2s.clone()),
            tx_v2_merkle_proofs: tx_v2_witness
                .as_ref()
                .map(|w| w.tx_v2_merkle_proofs.clone()),
            // detail2 §Q-2/§Q-3 — SECURITY (M-2): forwarded, no longer hard-coded `None`. A block
            // whose slots are all `TxClass::UserTransfer` still passes `None` (the processor's
            // dummy substitution is correct there — that branch verifies no channel-action
            // opening), but a `TxClass::ChannelAction` slot now carries its real action, index and
            // Merkle proof, which is what makes `is_member_update` reachable outside unit tests.
            channel_action_indices: tx_v2_witness
                .as_ref()
                .and_then(|w| w.channel_action_indices.clone()),
            channel_actions: tx_v2_witness
                .as_ref()
                .and_then(|w| w.channel_actions.clone()),
            channel_action_merkle_proofs: tx_v2_witness
                .as_ref()
                .and_then(|w| w.channel_action_merkle_proofs.clone()),
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

    /// Return the exact producer-assigned deposit leaf rather than the first leaf sharing a
    /// recipient. Production balance settlement must bind the L1 event index: a recipient may
    /// legitimately receive more than one deposit, and selecting by recipient alone would make
    /// every later leaf unspendable after the first nullifier is consumed.
    pub fn get_deposit_merkle_proof_at_index(
        &self,
        deposit_index: u64,
        expected_receiver: Bytes32,
    ) -> Result<(Deposit, DepositMerkleProof), BlockWitnessGeneratorError> {
        let deposit = self
            .deposit_tree
            .leaves()
            .get(deposit_index as usize)
            .cloned()
            .ok_or_else(|| {
                BlockWitnessGeneratorError::InvalidRequest(format!(
                    "No deposit found at index {deposit_index}"
                ))
            })?;
        if deposit.deposit_index.as_u64() != deposit_index {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "deposit tree leaf {deposit_index} carries index {}",
                deposit.deposit_index.as_u64()
            )));
        }
        if deposit.recipient != expected_receiver {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "deposit {deposit_index} recipient {:?} differs from expected {:?}",
                deposit.recipient, expected_receiver
            )));
        }
        Ok((deposit, self.deposit_tree.prove(deposit_index)))
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
    /// detail2 §Q-3: the NEW registered member leaves when this block carries a
    /// `MemberSetUpdate` channel action; `None` for every other block.
    pub new_member_leaves: Option<Vec<MemberLeaf>>,
    /// detail2 §Q-2/§Q-3: the per-slot channel-action sub-witness — the `ChannelAction` a
    /// `TxClass::ChannelAction` slot's `tx_v2.channel_action_root` opens to, its index in the
    /// action tree, and the opening proof.
    ///
    /// SECURITY (M-2): `None` here is NOT "unused padding" — it is what makes the whole of §Q
    /// unreachable. `block_hash_chain_processor` substitutes `ChannelAction::default()` (kind =
    /// `InterChannelSend`), so `is_member_update = should_check_channel_action ∧ is_msu_kind` is
    /// identically FALSE for every block whose producer left these `None`. A slot that carries a
    /// `TxClass::ChannelAction` TxV2 MUST populate them, and `add_block_with_tx_v2_inner` refuses
    /// the block if it does not.
    pub channel_action_indices: Option<Vec<u64>>,
    pub channel_actions: Option<Vec<ChannelAction>>,
    pub channel_action_merkle_proofs: Option<Vec<ChannelActionMerkleProof>>,
}

#[derive(Debug, Clone)]
pub struct SendStatus {
    // the block number of the last send tx. If there is no send tx, it is 0.
    pub last_send_block: BlockNumber,

    // the block number of the next send tx. If there is no next send tx, it is None.
    pub next_send_block: Option<BlockNumber>,
}

#[cfg(test)]
mod production_boundary_tests {
    use super::*;

    #[test]
    fn public_registration_cannot_fall_back_to_local_resigning() {
        const CHANNEL: u32 = 41;
        let fixture_keys = ChannelMemberKeys::deterministic(CHANNEL);
        let record = fixture_keys.to_reg_record(CHANNEL);
        let regev_pks = fixture_keys.regev_pks.clone();
        drop(fixture_keys);

        let mut producer = BlockWitnessGenerator::new(&[1]);
        producer
            .add_channel_registration_public(record, regev_pks)
            .expect("valid public registration");
        let channel = ChannelId::new(CHANNEL as u64).unwrap();
        assert!(!producer.holds_local_signing_keys(channel));
        producer
            .add_registration_block(0)
            .expect("registration block");
        producer
            .add_deposit(
                Address::default(),
                Bytes32::from_u32_slice(&[9; 8]).unwrap(),
                0,
                U256::from(5u32),
                Bytes32::default(),
            )
            .expect("queue deposit for the refused block");

        let before = producer.block_number;
        let before_state = producer.current_extended_public_state();
        let before_deposits = producer.deposits.clone();
        let before_deposit_count = producer.deposit_counts;
        let before_blocks = producer.blocks.len();
        let before_witnesses = producer.block_chain_witness.len();
        let tx_tree_root = Bytes32::from_u32_slice(&[7; 8]).unwrap();
        let err = producer
            .add_block(CHANNEL, &[1], 1, tx_tree_root)
            .expect_err("an unsigned production block must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("no wallet-supplied N-of-N cosignatures")
                && message.contains("holds no local signing keys"),
            "the refusal must identify the missing external cosign round: {message}"
        );
        assert_eq!(
            producer.block_number, before,
            "a refused unsigned block must not advance the producer state"
        );
        let after_state = producer.current_extended_public_state();
        assert_eq!(after_state.inner, before_state.inner);
        assert_eq!(after_state.block_hash_chain, before_state.block_hash_chain);
        assert_eq!(
            after_state.deposit_hash_chain,
            before_state.deposit_hash_chain
        );
        assert_eq!(after_state.deposit_count, before_state.deposit_count);
        assert_eq!(
            after_state.channel_reg_hash_chain,
            before_state.channel_reg_hash_chain
        );
        assert_eq!(after_state.bp_sig_chain, before_state.bp_sig_chain);
        assert_eq!(producer.deposits, before_deposits);
        assert_eq!(producer.deposit_counts, before_deposit_count);
        assert_eq!(producer.blocks.len(), before_blocks);
        assert_eq!(producer.block_chain_witness.len(), before_witnesses);
    }
}

/// M-2 (detail2 §Q): the member-set-update block must round-trip through the PRODUCTION witness
/// path — the generator's authoritative channel tree and the circuit's `new_account_tree_root`
/// agreeing on the SAME advanced member root, and the next ordinary block still opening against
/// it.
///
/// Before the fix these tests could not have been written: `channel_actions` was hard-coded
/// `None` on every production path, `block_hash_chain_processor` substituted
/// `ChannelAction::default()` (kind `InterChannelSend`), and `is_member_update` was identically
/// false — §Q was reachable only from `update_channel_tree`'s own unit tests.
#[cfg(test)]
mod member_set_update_production_path_tests {
    use super::*;
    use crate::circuits::validity::block_hash_chain::update_channel_tree::validate_member_set_delta;
    use crate::common::tx::ChannelActionKind;
    use crate::wallet_core::{
        canonical_member_set_update_action_index, canonical_member_set_update_block,
    };

    const CHANNEL: u32 = 63;
    /// A second deterministic key set, seeded off a different channel, so its per-slot Falcon and
    /// BabyBear identities are genuinely distinct from `CHANNEL`'s.
    const REPLACEMENT_SEED: u32 = CHANNEL + 1_000;

    fn fold(leaves: &[MemberLeaf]) -> PoseidonHashOut {
        let mut tree = MemberTree::init();
        for leaf in leaves.iter() {
            tree.push(leaf.clone());
        }
        tree.get_root()
    }

    fn registered_leaves(keys: &ChannelMemberKeys) -> Vec<MemberLeaf> {
        (0..MAX_SIG_CLUSTER)
            .map(|slot| keys.member_tree.get_leaf(slot as u64))
            .collect()
    }

    /// A legal §Q-3 ROTATE: one slot takes a new signing identity, `regev_pk_digest` PRESERVED
    /// (§Q-6 — Regev rotation is out of scope, balances must stay decryptable).
    fn rotate(old: &[MemberLeaf], slot: usize, replacement: &ChannelMemberKeys) -> Vec<MemberLeaf> {
        let incoming = replacement.member_tree.get_leaf(slot as u64);
        let mut new = old.to_vec();
        new[slot] = MemberLeaf {
            pk_g: incoming.pk_g,
            pk_b: incoming.pk_b,
            regev_pk_digest: old[slot].regev_pk_digest,
        };
        new
    }

    /// The MSU block exactly as `ProductionBlockProducer::produce_member_set_update_block` builds
    /// it — same `canonical_member_set_update_block` construction, same action opening.
    fn msu_witness(
        channel: ChannelId,
        num_users: usize,
        old: &[MemberLeaf],
        new: &[MemberLeaf],
    ) -> (BlockTxV2Witness, Bytes32) {
        let (action, action_tree, tx_v2, tx_v2_tree, tx_tree_root) =
            canonical_member_set_update_block(channel, fold(old), fold(new));
        let action_index = canonical_member_set_update_action_index();
        let mut tx_v2_indices = vec![0u64; num_users];
        let mut tx_v2s = vec![TxV2::default(); num_users];
        tx_v2_indices[0] = channel.as_u64();
        tx_v2s[0] = tx_v2;
        (
            BlockTxV2Witness {
                tx_v2_indices,
                tx_v2s,
                tx_v2_merkle_proofs: vec![tx_v2_tree.prove(channel.as_u64()); num_users],
                new_member_leaves: Some(new.to_vec()),
                channel_action_indices: Some(vec![action_index; num_users]),
                channel_actions: Some(vec![action; num_users]),
                channel_action_merkle_proofs: Some(vec![
                    action_tree.prove(action_index);
                    num_users
                ]),
            },
            tx_tree_root,
        )
    }

    /// An ORDINARY `TxClass::UserTransfer` block for the same channel — no channel action.
    fn transfer_witness(channel: ChannelId, num_users: usize) -> (BlockTxV2Witness, Bytes32) {
        use crate::common::trees::tx_v2_tree::TxV2Tree;
        let tx_v2 = TxV2 {
            tx_class: TxClass::UserTransfer,
            transfer_tree_root: Bytes32::from_u32_slice(&[5; 8])
                .unwrap()
                .reduce_to_hash_out(),
            nonce: 1,
            channel_action_root: PoseidonHashOut::default(),
        };
        let mut tree = TxV2Tree::init();
        tree.update(channel.as_u64(), tx_v2);
        let mut tx_v2_indices = vec![0u64; num_users];
        let mut tx_v2s = vec![TxV2::default(); num_users];
        tx_v2_indices[0] = channel.as_u64();
        tx_v2s[0] = tx_v2;
        (
            BlockTxV2Witness {
                tx_v2_indices,
                tx_v2s,
                tx_v2_merkle_proofs: vec![tree.prove(channel.as_u64()); num_users],
                new_member_leaves: None,
                channel_action_indices: None,
                channel_actions: None,
                channel_action_merkle_proofs: None,
            },
            Bytes32::from(tree.get_root()),
        )
    }

    struct MsuFixture {
        generator: BlockWitnessGenerator,
        channel: ChannelId,
        old_leaves: Vec<MemberLeaf>,
        new_leaves: Vec<MemberLeaf>,
        replacement: ChannelMemberKeys,
        prev_ext: ExtendedPublicState,
        block_number: BlockNumber,
    }

    /// Register a channel and post ONE member-set-update block through the production witness API.
    fn produce_msu_block() -> MsuFixture {
        let mut generator = BlockWitnessGenerator::new(&[1]);
        let keys = generator.register_channel(CHANNEL);
        let channel = ChannelId::new(CHANNEL as u64).unwrap();
        let old_leaves = registered_leaves(&keys);
        assert_eq!(
            generator
                .channel_tree
                .get_leaf(channel.as_u64())
                .member_pubkeys_root,
            fold(&old_leaves),
            "registration must commit the registered member root"
        );

        let replacement = ChannelMemberKeys::deterministic(REPLACEMENT_SEED);
        let new_leaves = rotate(&old_leaves, 1, &replacement);
        validate_member_set_delta(&old_leaves, &new_leaves)
            .expect("a slot-1 rotation with preserved regev is a legal §Q-3 delta");

        let (witness, tx_tree_root) = msu_witness(channel, 1, &old_leaves, &new_leaves);
        let prev_ext = generator.current_extended_public_state();
        generator
            .add_block_with_tx_v2(CHANNEL, &[1], 1, tx_tree_root, Some(witness))
            .expect("the MSU block must be producible on the production witness path");
        let block_number = generator.block_number;

        MsuFixture {
            generator,
            channel,
            old_leaves,
            new_leaves,
            replacement,
            prev_ext,
            block_number,
        }
    }

    #[test]
    fn msu_block_advances_generator_and_circuit_to_the_same_member_root() {
        let f = produce_msu_block();
        let new_root = fold(&f.new_leaves);
        assert_ne!(
            new_root,
            fold(&f.old_leaves),
            "the fixture rotation must actually move the member root"
        );

        // M-2 (1): the channel action really is carried by the production witness. Without this
        // the processor substitutes `ChannelAction::default()` and §Q silently does nothing.
        let stored = f
            .generator
            .block_chain_witness
            .get(&f.block_number)
            .expect("the MSU block's witness must be stored");
        let actions = stored
            .channel_actions
            .as_ref()
            .expect("M-2: the production path must forward the channel action, not None");
        assert_eq!(
            actions[0].kind,
            ChannelActionKind::MemberSetUpdate,
            "the forwarded action must be the member-set update, so is_member_update is TRUE"
        );

        // M-2 (2a): the generator's own authoritative channel tree advanced.
        assert_eq!(
            f.generator
                .channel_tree
                .get_leaf(f.channel.as_u64())
                .member_pubkeys_root,
            new_root,
            "the daemon's base-state leaf must carry the NEW member root, not a copy of the old one"
        );
        // ...and so did the registered set every LATER block is witnessed against.
        assert_eq!(
            f.generator.channel_members[&f.channel]
                .member_tree
                .get_root(),
            new_root,
            "the registered member mirror must advance with the leaf"
        );

        // M-2 (2b): what the circuit PROVES for this block, resolved through the production
        // Option-substitution, agrees with what the generator wrote.
        let pis = stored
            .to_update_channel_tree(&f.prev_ext, f.block_number)
            .to_public_inputs()
            .expect("the strict mirror must accept the production MSU witness");
        assert_eq!(
            pis.prev_account_tree_root, f.prev_ext.inner.account_tree_root,
            "the proof must start from the pre-block account root"
        );
        assert_eq!(
            pis.new_account_tree_root,
            f.generator.channel_tree.get_root(),
            "M-2: the proven account root and the daemon's base state must not diverge on an MSU \
             block"
        );
    }

    #[test]
    fn the_block_after_an_msu_still_opens_against_the_advanced_tree() {
        let mut f = produce_msu_block();

        // The fixture harness's stale slot-1 key was dropped when the set advanced (fail-closed:
        // the next block would otherwise be built with a signature over the OLD pk_g and fail
        // deep in proving). Hand it the rotated member's real key, as a wallet would.
        assert!(
            !f.generator.holds_local_signing_keys(f.channel),
            "a rotation must invalidate the fixture signer list rather than leave it stale"
        );
        let registered = ChannelMemberKeys::deterministic(CHANNEL);
        f.generator.replace_local_test_signers(
            f.channel,
            vec![
                registered.falcon_keys[0].clone(),
                f.replacement.falcon_keys[1].clone(),
                registered.falcon_keys[2].clone(),
            ],
        );

        let (witness, tx_tree_root) = transfer_witness(f.channel, 1);
        let prev_ext = f.generator.current_extended_public_state();
        f.generator
            .add_block_with_tx_v2(CHANNEL, &[1], 2, tx_tree_root, Some(witness))
            .expect("an ordinary block must still be producible after a member-set update");
        let block_number = f.generator.block_number;

        // `check_n_of_n_witness` folds this block's `member_leaves` and requires the result to BE
        // the channel leaf's committed `member_pubkeys_root`, and the account Merkle proof is
        // opened against the advanced tree. A generator mirror left on the old set fails here —
        // this is the "subsequent blocks' Merkle openings break" half of M-2.
        let pis = f
            .generator
            .block_chain_witness
            .get(&block_number)
            .expect("the follow-on block's witness must be stored")
            .to_update_channel_tree(&prev_ext, block_number)
            .to_public_inputs()
            .expect(
                "the block AFTER an MSU must open against the advanced tree and connect its \
                 member root to the advanced leaf",
            );
        assert_eq!(
            pis.prev_account_tree_root, prev_ext.inner.account_tree_root,
            "the follow-on block must chain onto the post-MSU account root"
        );
        assert_eq!(
            pis.new_account_tree_root,
            f.generator.channel_tree.get_root(),
            "the follow-on block's proven root must still match the daemon's base state"
        );
        // A UserTransfer block must not touch the member root.
        assert_eq!(
            f.generator
                .channel_tree
                .get_leaf(f.channel.as_u64())
                .member_pubkeys_root,
            fold(&f.new_leaves),
            "an ordinary block must leave the advanced member root alone"
        );
    }

    #[test]
    fn a_channel_action_slot_without_its_sub_witness_is_refused() {
        let mut generator = BlockWitnessGenerator::new(&[1]);
        let keys = generator.register_channel(CHANNEL);
        let channel = ChannelId::new(CHANNEL as u64).unwrap();
        let old_leaves = registered_leaves(&keys);
        let replacement = ChannelMemberKeys::deterministic(REPLACEMENT_SEED);
        let new_leaves = rotate(&old_leaves, 1, &replacement);

        // Exactly the shape M-2 reported: a ChannelAction TxV2 with the action dropped. The
        // processor would substitute `ChannelAction::default()`, `is_member_update` would be
        // FALSE, and the block would prove a leaf that did NOT advance while the producer's
        // registry believed it had.
        let (mut witness, tx_tree_root) = msu_witness(channel, 1, &old_leaves, &new_leaves);
        witness.channel_action_indices = None;
        witness.channel_actions = None;
        witness.channel_action_merkle_proofs = None;

        let before_block = generator.block_number;
        let before_root = generator.channel_tree.get_root();
        let err = generator
            .add_block_with_tx_v2(CHANNEL, &[1], 1, tx_tree_root, Some(witness))
            .expect_err("a ChannelAction slot with no sub-witness must fail closed");
        assert!(
            err.to_string().contains("channel-action sub-witness"),
            "the refusal must name the missing sub-witness, got: {err}"
        );
        assert_eq!(
            generator.block_number, before_block,
            "the refused block must not advance the generator"
        );
        assert_eq!(
            generator.channel_tree.get_root(),
            before_root,
            "the refused block must not touch the channel tree"
        );
    }

    #[test]
    fn a_member_root_the_block_does_not_commit_is_caught() {
        let f = produce_msu_block();
        let stored = f
            .generator
            .block_chain_witness
            .get(&f.block_number)
            .expect("the MSU block's witness must be stored")
            .clone();

        // The daemon wrote the slot-1 rotation into its channel tree. Hand the circuit a slot-2
        // rotation instead — structurally a legal delta, but NOT the transition this block's
        // signed action commits. This is the generator/circuit disagreement M-2 warned about,
        // injected directly.
        let divergent = rotate(&f.old_leaves, 2, &f.replacement);
        assert_ne!(divergent, f.new_leaves);
        validate_member_set_delta(&f.old_leaves, &divergent).expect(
            "the divergent set must itself be a structurally legal delta, so the payload binding \
             is what refuses it — not the delta rule",
        );

        let mut tampered = stored.to_update_channel_tree(&f.prev_ext, f.block_number);
        tampered.new_member_leaves = divergent.clone();

        let err = tampered
            .to_public_inputs()
            .expect_err("the strict mirror must refuse a member set the block does not commit");
        assert!(
            err.to_string().contains("payload_hash"),
            "the refusal must name the (prev_root, new_root) payload binding, got: {err}"
        );

        // And the divergence is REAL, not absorbed: the root such a witness would prove differs
        // from the one the daemon's base state holds.
        let unchecked = tampered
            .to_public_inputs_unchecked()
            .expect("the unchecked mirror still computes public inputs");
        assert_ne!(
            unchecked.new_account_tree_root,
            f.generator.channel_tree.get_root(),
            "a divergent member root must move the proven account root — otherwise the strict \
             check above would be testing nothing"
        );
    }
}
