//! `BalanceState` — the hidden-balance core of the v2 channel layer
//! (abstract2 §2.1, detail2 §C-2/§C-6, approved deviation D3).
//!
//! Channel balances live in state only as Regev ciphertexts (one per member slot, in
//! member slot order). `H1 = h1()` commits to the full balance state WITHOUT any proof
//! object, so all three members can sign `hash(H1, H2)` at state-authoring time (audit finding 3:
//! no signing-time proof circularity). The settled-tx hash chain (`settled_tx_chain`) is the
//! mechanical link between a signed `BalanceState` and the balance proof that imported the same
//! settle history (detail2 §F-1).

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::builder::BuilderKeccak256 as _;
use serde::{Deserialize, Serialize};

use crate::{
    common::channel::{ChannelError, ChannelId, hash_words, split_u64},
    constants::{BALANCE_SLOT_TREE_HEIGHT, MAX_CHANNEL_MEMBERS, MAX_COSIGNERS},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    regev::{MAX_HOMO_ADDS_BEFORE_REFRESH, RegevCiphertext},
    utils::{
        leafable_hasher::{LeafableHasher as _, PoseidonLeafableHasher},
        poseidon_hash_out::PoseidonHashOut,
        trees::incremental_merkle_tree::IncrementalMerkleTree,
    },
};

/// Domain separator for [`BalanceState::h1`] ("IMBS").
pub const BALANCE_STATE_DOMAIN: u32 = 0x494d4253;
/// Domain separator for [`balance_slot_leaf_hash`] ("IMSL") — the per-slot leaf of the H1
/// balance-slot Poseidon Merkle tree. Listed in `poseidon_sig`'s repo-wide domain non-collision
/// test.
pub const BALANCE_SLOT_LEAF_DOMAIN: u32 = 0x494d534c;
/// Domain separator for [`balance_state_hash`] ("IMBH").
pub const BALANCE_STATE_HASH_DOMAIN: u32 = 0x494d4248;
/// Domain separator for the two wings of [`tx_leaf_hash`] ("IMTL").
pub const TX_LEAF_DOMAIN: u32 = 0x494d544c;
/// Domain separator for [`settled_tx_chain_push`] ("IMTC").
pub const SETTLED_TX_CHAIN_DOMAIN: u32 = 0x494d5443;

/// abstract2 §2.1: `BalanceState { encBalances, settledTxChain, stateVersion }`, extended with
/// per-member homomorphic-add counters (approved deviation D3 from detail2 §C-2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceState {
    pub channel_id: ChannelId,
    /// Number of ACTIVE members (2..=MAX_CHANNEL_MEMBERS). Active members occupy slots
    /// `0..member_count`; slots `member_count..MAX_CHANNEL_MEMBERS` are padding
    /// (`RegevCiphertext::padding()` balances, zero `pending_adds`).
    ///
    /// SECURITY (D6 pad-to-MAX): `member_count` is part of the H1 preimage (see [`Self::h1`]) so
    /// the active/padding split is fixed by the same all-member signatures that bind the balances;
    /// a state could not silently re-interpret a padding slot as active or vice-versa.
    pub member_count: u8,
    /// Number of DELEGATE participants (send/receive/withdraw, but NOT co-signing the N-of-N
    /// state). Delegates occupy the contiguous slot region
    /// `member_count..member_count+delegate_count`; slots `member_count+delegate_count..MAX` are
    /// padding. Invariant: `member_count + delegate_count <= MAX_CHANNEL_MEMBERS`.
    ///
    /// SECURITY (delegate account, Phase 1): `delegate_count` is part of the H1 preimage (see
    /// [`Self::h1`]) IMMEDIATELY AFTER `member_count`, so the member/delegate/padding split is
    /// fixed by the same all-member signatures that bind the balances. A state could not
    /// silently re-interpret a delegate slot as a member (or vice-versa) or a padding slot as
    /// a delegate. Delegate slots are ACTIVE balance slots (non-padding ciphertexts) exactly
    /// like member slots.
    pub delegate_count: u8,
    /// One balance ciphertext per slot, in member slot order. Slots `>= member_count` are
    /// `RegevCiphertext::padding()`.
    // MAX_CHANNEL_MEMBERS > 32: std serde only derives arrays up to 32, so use serde-big-array.
    #[serde(with = "serde_big_array::BigArray")]
    pub enc_balances: [RegevCiphertext; MAX_CHANNEL_MEMBERS],
    /// Decryption Stage 1: per-slot Regev public-key Poseidon digests, in member slot order.
    /// Active slots carry `Bytes32::from(RegevPk::poseidon_digest())` (the SAME injective
    /// encoding as the validity-side `MemberLeaf.regev_pk_digest`, so decryption Stage 2 can
    /// bind the witnessed `(a, b)` to this committed value via a one-hot select). Padding
    /// slots (`>= active`) carry `Bytes32::default()`.
    ///
    /// SECURITY: committed into [`Self::h1`] via slot leaf i of the balance-slot Poseidon tree
    /// (`balance_slot_leaf_hash`), so each member's registered Regev pk is bound by the same
    /// all-member signatures that bind the balances. This is the H1-commitment prerequisite that
    /// makes the decryption-core pk binding (MUST-FIX #1) satisfiable without deployer trust.
    #[serde(with = "serde_big_array::BigArray")]
    pub regev_pk_digests: [Bytes32; MAX_CHANNEL_MEMBERS],
    /// Hash chain over the settles this state has absorbed (genesis = 0x00…00).
    pub settled_tx_chain: Bytes32,
    /// Stage 3 (post-close source-tx anchoring): the root of the per-channel settled-tx Merkle
    /// ACCUMULATOR — an `IncrementalMerkleTree<Bytes32>` of height `H = 20` whose leaves are the
    /// `tx_hash` of every settle this state has absorbed (genesis = the empty-tree root). Encoded
    /// as `Bytes32::from(IncrementalMerkleTree::get_root())` — the SAME injective
    /// Poseidon→Bytes32 encoding Stage 1 uses for `regev_pk_digests`.
    ///
    /// SECURITY: the accumulator and `settled_tx_chain` are INDEPENDENT commitments storing
    /// DIFFERENT leaves. The chain stores `tx_leaf` for send/bundle and `tx_hash` for fund-import;
    /// the accumulator stores `tx_hash` UNIFORMLY at every settle advancement, giving the
    /// post-close claim ONE canonical membership predicate (`incoming_tx_hash`). Folded into
    /// [`Self::h1`] (the signed preimage) IMMEDIATELY AFTER `settled_tx_chain`, so the
    /// accumulator root is attested by the same all-member signatures that bind the chain. The
    /// close circuit exposes it as a dedicated close PI (`final_settled_tx_accumulator_root`);
    /// L1 finalizes that value; the post-close claim binds a Merkle inclusion of
    /// `incoming_tx_hash` against the finalized root.
    pub settled_tx_accumulator_root: Bytes32,
    /// Monotone state counter, +1 on every in-channel AND inter-channel update. Independent of
    /// `epoch` / `small_block_number` (in-channel transfers produce no small block).
    pub state_version: u64,
    /// Homomorphic-add counters per member slot since that member's last fresh re-encryption
    /// (approved deviation D3 from detail2 §C-2; closes the noise/digit-flooding exit-liveness
    /// DoS). Co-signers must refuse adds at `MAX_HOMO_ADDS_BEFORE_REFRESH`. Padding slots are 0.
    #[serde(with = "serde_big_array::BigArray")]
    pub pending_adds: [u32; MAX_CHANNEL_MEMBERS],
}

impl BalanceState {
    /// Pad `active` ciphertexts (len = `member_count`, the active prefix) to a full
    /// `MAX_CHANNEL_MEMBERS`-sized array, filling slots `member_count..MAX` with
    /// `RegevCiphertext::padding()`. Convenience constructor for callers/tests that work with the
    /// active prefix only.
    pub fn pad_enc_balances(active: &[RegevCiphertext]) -> [RegevCiphertext; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| {
            active
                .get(i)
                .cloned()
                .unwrap_or_else(RegevCiphertext::padding)
        })
    }

    /// Pad `active` add-counters (len = `member_count`) to a full `MAX_CHANNEL_MEMBERS`-sized
    /// array, filling padding slots with 0.
    pub fn pad_pending_adds(active: &[u32]) -> [u32; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or(0))
    }

    /// Decryption Stage 1: pad `active` Regev pk digests (len = `member_count + delegate_count`,
    /// each `Bytes32::from(RegevPk::poseidon_digest())`) to a full `MAX_CHANNEL_MEMBERS`-sized
    /// array, filling padding slots with `Bytes32::default()`.
    pub fn pad_regev_pk_digests(active: &[Bytes32]) -> [Bytes32; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    /// The per-slot leaf hashes of the H1 balance-slot Poseidon Merkle tree, in member slot
    /// order (ALL `MAX_CHANNEL_MEMBERS` slots — the tree, and hence H1, is a function of the
    /// FULL slot array, exactly like the retired flat keccak).
    ///
    /// PERF: padding slots share one canonical `(default pk digest, padding ct digest, 0)` leaf,
    /// so the padding leaf hash (and the padding ciphertext's keccak digest) is computed once and
    /// reused. This is a pure memoization: the reused value equals the per-slot recompute.
    pub fn slot_leaf_hashes(&self) -> Vec<PoseidonHashOut> {
        let padding_ct = RegevCiphertext::padding();
        let padding_ct_digest = padding_ct.digest();
        let padding_leaf =
            balance_slot_leaf_hash(Bytes32::default(), padding_ct_digest, 0);
        (0..MAX_CHANNEL_MEMBERS)
            .map(|i| {
                let is_padding_slot = self.regev_pk_digests[i] == Bytes32::default()
                    && self.pending_adds[i] == 0
                    && self.enc_balances[i] == padding_ct;
                if is_padding_slot {
                    padding_leaf
                } else {
                    balance_slot_leaf_hash(
                        self.regev_pk_digests[i],
                        self.enc_balances[i].digest(),
                        self.pending_adds[i],
                    )
                }
            })
            .collect()
    }

    /// The FULL balance-slot tree (height [`BALANCE_SLOT_TREE_HEIGHT`], all
    /// `MAX_CHANNEL_MEMBERS` leaves populated). Used by the claim witness builders to produce
    /// per-slot inclusion proofs; [`Self::slot_tree_root`] computes the same root without the
    /// tree bookkeeping.
    pub fn slot_tree(&self) -> IncrementalMerkleTree<PoseidonHashOut> {
        let mut tree = IncrementalMerkleTree::<PoseidonHashOut>::new(BALANCE_SLOT_TREE_HEIGHT);
        for leaf in self.slot_leaf_hashes() {
            tree.push(leaf);
        }
        tree
    }

    /// The balance-slot tree ROOT — the value committed inside [`Self::h1`]. Bottom-up fold
    /// (`PoseidonLeafableHasher::two_to_one`, the same node hash `slot_tree()` /
    /// `IncrementalMerkleProofTarget` use; equality is pinned by
    /// `slot_tree_root_matches_incremental_tree` below).
    pub fn slot_tree_root(&self) -> PoseidonHashOut {
        let mut level = self.slot_leaf_hashes();
        debug_assert_eq!(level.len(), 1 << BALANCE_SLOT_TREE_HEIGHT);
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| PoseidonLeafableHasher::two_to_one(pair[0], pair[1]))
                .collect();
        }
        level[0]
    }

    /// H1 (detail2 §C-2 + D3, pad-to-MAX deviation D6, decryption Stage 1, Stage 3 accumulator;
    /// Poseidon-root form — see `tasks/h1-poseidon-root-threat-model.md`): the canonical
    /// `PoseidonHashOut → Bytes32` encoding of a FIXED-width (26-element) Poseidon header
    ///
    /// `Poseidon([BALANCE_STATE_DOMAIN, channel_id, member_count, delegate_count,
    ///            slot_tree_root (4 Goldilocks elements), settled_tx_chain (8 u32 limbs),
    ///            settled_tx_accumulator_root (8 u32 limbs), split_u64(state_version) (hi, lo)])`
    ///
    /// where `slot_tree_root` is the height-[`BALANCE_SLOT_TREE_HEIGHT`] Poseidon Merkle root
    /// over ALL `MAX_CHANNEL_MEMBERS` per-slot leaves
    /// `balance_slot_leaf_hash(regev_pk_digests[i], enc_balances[i].digest(), pending_adds[i])`.
    /// This must stay element-identical to the in-circuit recompute in
    /// `circuits::channel::h1_gadget::recompute_h1` (the L1 mirror only pins/compares the value).
    ///
    /// SECURITY: every value the retired flat keccak bound remains bound — the per-slot triples
    /// via the Merkle root (slot ORDER = Merkle position), the scalars via the header. Hashing
    /// `member_count`/`delegate_count` in the header fixes the active/padding split under the
    /// member signatures (D6/delegate account); `pending_adds[i]` rides in leaf i (D3, F5-A).
    /// The header and leaf encodings are injective (fixed width, canonical u32 limbs / canonical
    /// Goldilocks root elements, leading domain constants).
    pub fn h1(&self) -> Bytes32 {
        let root = self.slot_tree_root();
        let mut inputs: Vec<u64> = vec![
            BALANCE_STATE_DOMAIN as u64,
            self.channel_id.to_u32_vec()[0] as u64,
            self.member_count as u64,
            // delegate_count is committed IMMEDIATELY AFTER member_count, fixing the
            // member/delegate/padding region split under the member signatures.
            self.delegate_count as u64,
        ];
        inputs.extend(root.elements);
        inputs.extend(self.settled_tx_chain.to_u32_vec().iter().map(|&w| w as u64));
        // Stage 3: the settled-tx accumulator root sits IMMEDIATELY AFTER settled_tx_chain and
        // BEFORE state_version, mirroring the retired keccak header order.
        inputs.extend(
            self.settled_tx_accumulator_root
                .to_u32_vec()
                .iter()
                .map(|&w| w as u64),
        );
        inputs.extend(split_u64(self.state_version).iter().map(|&w| w as u64));
        Bytes32::from(PoseidonHashOut::hash_inputs_u64(&inputs))
    }

    /// Canonicality / budget check. MUST run on every balance state that crosses a trust
    /// boundary: each ciphertext must be canonical (otherwise its digest — and hence H1 — is
    /// malleable, F1-A) and every add counter must respect the D3 refresh budget. Also enforces
    /// the pad-to-MAX (D6) invariants: `2 <= member_count <= MAX_CHANNEL_MEMBERS`, and every
    /// padding slot (`>= member_count`) is the default/empty value.
    pub fn validate(&self) -> Result<(), ChannelError> {
        // member_count = COSIGNERS (the N-of-N close signers), capped at MAX_COSIGNERS — NOT the
        // balance-slot capacity MAX_CHANNEL_MEMBERS. Mirrors ChannelRecord::validate /
        // ChannelRegRecord::validate; the close/cancel circuits enforce the same cap in-circuit
        // via the MAX_COSIGNERS-bit unary decomposition.
        let count = self.member_count as usize;
        if count < 2 || count > MAX_COSIGNERS {
            return Err(ChannelError::InvalidBalanceState(format!(
                "member_count {count} out of range (must be 2..={MAX_COSIGNERS} cosigners)"
            )));
        }
        // Delegate account regions: members occupy `0..member_count`, delegates occupy
        // `member_count..member_count+delegate_count`, padding occupies
        // `member_count+delegate_count..MAX`. Active = members + delegates. `delegate_count` may be
        // 0; `member_count + delegate_count` must not exceed MAX (no overflow / over-allocation).
        let delegate_count = self.delegate_count as usize;
        let active = count
            .checked_add(delegate_count)
            .filter(|&a| a <= MAX_CHANNEL_MEMBERS)
            .ok_or_else(|| {
                ChannelError::InvalidBalanceState(format!(
                    "member_count {count} + delegate_count {delegate_count} exceeds \
                     MAX_CHANNEL_MEMBERS = {MAX_CHANNEL_MEMBERS}"
                ))
            })?;
        for (index, ct) in self.enc_balances.iter().enumerate() {
            ct.validate().map_err(|err| {
                ChannelError::InvalidBalanceState(format!(
                    "enc_balances[{index}] is not canonical: {err}"
                ))
            })?;
            // Padding slots MUST be the canonical empty ciphertext (D6 + delegate account): a
            // non-default padding slot would smuggle hidden value past the active accounting.
            // Active slots = members (`< member_count`) + delegates
            // (`member_count..member_count+delegate_count`). Padding = `>= active`.
            if index >= active && *ct != RegevCiphertext::padding() {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "enc_balances[{index}] is a padding slot (>= member_count+delegate_count \
                     {active}) and must be RegevCiphertext::padding()"
                )));
            }
        }
        // Decryption Stage 1: padding slots (`>= active`) must carry the default (zero) Regev pk
        // digest, mirroring the padding canonicality of `enc_balances`/`pending_adds`. A
        // non-default padding digest would be folded into H1 and could smuggle an
        // unregistered key past the active accounting. Active-slot digests are arbitrary
        // (the registered member pk digests).
        for (index, d) in self.regev_pk_digests.iter().enumerate() {
            if index >= active && *d != Bytes32::default() {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "regev_pk_digests[{index}] is a padding slot (>= member_count+delegate_count \
                     {active}) and must be Bytes32::default()"
                )));
            }
        }
        for (index, &adds) in self.pending_adds.iter().enumerate() {
            if adds > MAX_HOMO_ADDS_BEFORE_REFRESH {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "pending_adds[{index}] = {adds} exceeds MAX_HOMO_ADDS_BEFORE_REFRESH = \
                     {MAX_HOMO_ADDS_BEFORE_REFRESH}"
                )));
            }
            if index >= active && adds != 0 {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "pending_adds[{index}] is a padding slot (>= member_count+delegate_count \
                     {active}) and must be 0"
                )));
            }
        }
        Ok(())
    }
}

/// The per-slot leaf of the H1 balance-slot Poseidon Merkle tree (member slot order; the leaf
/// INDEX is the Merkle position, so slot order is bound structurally):
///
/// `leaf_i = Poseidon([BALANCE_SLOT_LEAF_DOMAIN, regev_pk_digest (8 u32 limbs),
///                     enc_balance_digest (8 u32 limbs), pending_adds (1 u32 limb)])`
///
/// SECURITY: FIXED 18-element width with a leading domain constant and canonical u32 payload
/// limbs — injective on the `(regev_pk_digest, enc_balance_digest, pending_adds)` triple.
/// MUST stay element-identical to the in-circuit twin
/// `circuits::channel::h1_gadget::balance_slot_leaf_hash_circuit`.
pub fn balance_slot_leaf_hash(
    regev_pk_digest: Bytes32,
    enc_balance_digest: Bytes32,
    pending_adds: u32,
) -> PoseidonHashOut {
    let mut inputs = vec![BALANCE_SLOT_LEAF_DOMAIN];
    inputs.extend(regev_pk_digest.to_u32_vec());
    inputs.extend(enc_balance_digest.to_u32_vec());
    inputs.push(pending_adds);
    PoseidonHashOut::hash_inputs_u32(&inputs)
}

/// abstract2 §3.1 signing target: `balanceStateHash = hash(H1, H2)`.
///
/// NOTE: in this implementation the member signatures normally go over
/// `ChannelState::signing_digest()`, which internalizes `hash(H1, H2)` (detail2 §C-3/§D); this
/// standalone helper exists for components that bind H1/H2 directly.
pub fn balance_state_hash(h1: Bytes32, h2: Bytes32) -> Bytes32 {
    hash_words(
        &[
            vec![BALANCE_STATE_HASH_DOMAIN],
            h1.to_u32_vec(),
            h2.to_u32_vec(),
        ]
        .concat(),
    )
}

/// detail2 §C-6 `TxLeafHash`:
/// `hash( hash([TX_LEAF_DOMAIN, source_pubkey_hash(8), sender_delta_digest]),
///        hash([TX_LEAF_DOMAIN, receiver_pubkey_hash(8), receiver_delta_digest]) )`.
///
/// SECURITY: both wings carry the member SPHINCS+ pubkey hash AND the Regev delta-ciphertext
/// digest, so the chain leaf binds the sending member, the receiving member and both hidden
/// balance deltas. The leaf is computable at small-block signing time (flowSend1 step 6) — unlike
/// the base-layer nullifier, which embeds the (then unknown) block number.
pub fn tx_leaf_hash(
    source_pk_g: Bytes32,
    sender_delta_digest: Bytes32,
    receiver_pk_g: Bytes32,
    receiver_delta_digest: Bytes32,
) -> Bytes32 {
    let sender_wing = hash_words(
        &[
            vec![TX_LEAF_DOMAIN],
            source_pk_g.to_u32_vec(),
            sender_delta_digest.to_u32_vec(),
        ]
        .concat(),
    );
    let receiver_wing = hash_words(
        &[
            vec![TX_LEAF_DOMAIN],
            receiver_pk_g.to_u32_vec(),
            receiver_delta_digest.to_u32_vec(),
        ]
        .concat(),
    );
    hash_words(&[sender_wing.to_u32_vec(), receiver_wing.to_u32_vec()].concat())
}

/// detail2 §C-6 chain update: `chain' = keccak([SETTLED_TX_CHAIN_DOMAIN, chain, leaf])`.
/// Used with `leaf = tx_leaf_hash(…)` for inter-channel settles and `leaf = deposit hash` for
/// deposit/fund imports. In-channel transfers leave the chain unchanged.
pub fn settled_tx_chain_push(chain: Bytes32, leaf: Bytes32) -> Bytes32 {
    hash_words(
        &[
            vec![SETTLED_TX_CHAIN_DOMAIN],
            chain.to_u32_vec(),
            leaf.to_u32_vec(),
        ]
        .concat(),
    )
}

/// In-circuit twin of [`settled_tx_chain_push`] (detail2 §C-6/§F-1):
/// `chain' = keccak256([SETTLED_TX_CHAIN_DOMAIN, chain limbs, leaf limbs])` over solidity-packed
/// u32 words, mirroring the off-chain limb order exactly.
///
/// SECURITY: the preimage layout (domain constant, then the 8 chain limbs, then the 8 leaf limbs)
/// MUST stay byte-identical to `hash_words` in [`settled_tx_chain_push`]; any divergence makes
/// every in-circuit chain PI disagree with the signed off-chain `BalanceState.settled_tx_chain`.
/// Inputs must already be constrained to 32-bit limbs by the caller (the keccak gadget does not
/// range-check its inputs).
pub fn settled_tx_chain_push_circuit<F, C, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    chain: Bytes32Target,
    leaf: Bytes32Target,
) -> Bytes32Target
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let domain = builder.constant(F::from_canonical_u32(SETTLED_TX_CHAIN_DOMAIN));
    let inputs = [vec![domain], chain.to_vec(), leaf.to_vec()].concat();
    Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regev::{REGEV_N, REGEV_Q};

    /// Deterministic canonical ciphertext (raw seed-derived coefficients < q). These are not
    /// decryptable — digest/H1 tests only need canonical, distinct ring elements.
    fn ciphertext(seed: u32) -> RegevCiphertext {
        RegevCiphertext {
            c1: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
                .collect(),
            c2: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

    fn sample_state() -> BalanceState {
        BalanceState {
            channel_id: ChannelId::new(7).unwrap(),
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[
                ciphertext(1),
                ciphertext(2),
                ciphertext(3),
            ]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 5,
            pending_adds: BalanceState::pad_pending_adds(&[0, 1, 2]),
        }
    }

    /// A distinct, canonical member SPHINCS+ pubkey hash (Bytes32) per seed.
    fn pubkey_hash(seed: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
            seed + 7,
        ])
        .unwrap()
    }

    #[test]
    fn h1_is_deterministic_and_sensitive_to_every_field() {
        let base = sample_state();
        let h1 = base.h1();
        assert_eq!(h1, sample_state().h1(), "h1 must be deterministic");

        let mut s = sample_state();
        s.channel_id = ChannelId::new(8).unwrap();
        assert_ne!(h1, s.h1(), "channel_id must affect h1");

        // member_count is part of the H1 preimage (D6): changing it must change H1.
        let mut s = sample_state();
        s.member_count = 4;
        assert_ne!(h1, s.h1(), "member_count must affect h1");

        for slot in 0..sample_state().member_count as usize {
            let mut s = sample_state();
            s.enc_balances[slot] = ciphertext(99 + slot as u32);
            assert_ne!(h1, s.h1(), "enc_balances[{slot}] must affect h1");
        }

        let mut s = sample_state();
        s.settled_tx_chain = Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(h1, s.h1(), "settled_tx_chain must affect h1");

        // Stage 3: the accumulator root is part of the H1 preimage (signed) and distinct from the
        // chain — flipping it (while leaving the chain unchanged) must change H1.
        let mut s = sample_state();
        s.settled_tx_accumulator_root = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(
            h1,
            s.h1(),
            "settled_tx_accumulator_root must affect h1 (Stage 3)"
        );

        let mut s = sample_state();
        s.state_version += 1;
        assert_ne!(h1, s.h1(), "state_version must affect h1");

        for slot in 0..sample_state().member_count as usize {
            let mut s = sample_state();
            s.pending_adds[slot] += 1;
            assert_ne!(h1, s.h1(), "pending_adds[{slot}] must affect h1 (D3)");
        }
    }

    /// Build a `BalanceState` with `count` ACTIVE members (distinct canonical ciphertexts in
    /// slots 0..count, padding = `RegevCiphertext::padding()`) for multi-N coverage below.
    fn state_with_members(count: u8) -> BalanceState {
        let active: Vec<RegevCiphertext> = (0..count as u32).map(|i| ciphertext(1 + i)).collect();
        BalanceState {
            channel_id: ChannelId::new(7).unwrap(),
            member_count: count,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&active),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 5,
            pending_adds: BalanceState::pad_pending_adds(&vec![0u32; count as usize]),
        }
    }

    /// Multi-N (D6 pad-to-MAX): `BalanceState::validate()` ACCEPTS member_count = 2 / 8 / 16 with
    /// canonical active ciphertexts + `RegevCiphertext::padding()` padding, and REJECTS the D6
    /// boundary violations (out-of-range count, nonzero padding slot, nonzero padding add-counter).
    #[test]
    fn balance_state_validate_multi_n() {
        for count in [2u8, 8, 16] {
            state_with_members(count)
                .validate()
                .unwrap_or_else(|e| panic!("member_count {count} must validate: {e}"));
        }

        // member_count < 2 rejected.
        let mut too_few = state_with_members(2);
        too_few.member_count = 1;
        assert!(matches!(
            too_few.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // member_count > MAX_COSIGNERS rejected (cosigner cap, NOT the 1024 balance-slot
        // capacity — the old `(MAX_CHANNEL_MEMBERS + 1) as u8` truncated to 1 at MAX=1024 and
        // passed for the wrong reason).
        let mut too_many = state_with_members(16);
        too_many.member_count = (MAX_COSIGNERS + 1) as u8;
        assert!(matches!(
            too_many.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // A non-default (nonzero) PADDING ciphertext slot is rejected (would smuggle hidden value).
        let mut nonzero_pad = state_with_members(8);
        nonzero_pad.enc_balances[8] = ciphertext(99);
        assert!(matches!(
            nonzero_pad.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // A nonzero PADDING add-counter is rejected.
        let mut nonzero_add = state_with_members(8);
        nonzero_add.pending_adds[8] = 1;
        assert!(matches!(
            nonzero_add.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));
    }

    /// Delegate account (Phase 1): `delegate_count` is part of the H1 preimage AND drives the
    /// active/padding region split. A state with delegates in `member_count..member_count+
    /// delegate_count` (active ciphertexts) validates; padding only begins at
    /// `member_count+delegate_count`. `member_count + delegate_count > MAX` is rejected, and a
    /// nonzero slot inside the would-be padding region (but now a delegate slot) is accepted.
    #[test]
    fn balance_state_delegate_count_regions_and_h1() {
        // Base: member_count = 3, delegate_count = 0.
        let base = state_with_members(3);
        let base_h1 = base.h1();

        // delegate_count is in the H1 preimage: bumping it (with a matching active delegate slot)
        // changes H1.
        let mut with_delegate = state_with_members(3);
        with_delegate.delegate_count = 2;
        with_delegate.enc_balances[3] = ciphertext(100);
        with_delegate.enc_balances[4] = ciphertext(101);
        assert_ne!(base_h1, with_delegate.h1(), "delegate_count must affect h1");
        with_delegate
            .validate()
            .expect("members + delegates + padding must validate");

        // The cosigner cap binds: member_count > MAX_COSIGNERS is rejected even with delegates.
        // (The old assertion targeted `member_count + delegate_count > MAX_CHANNEL_MEMBERS`, which
        // is unreachable with u8 counts at MAX=1024 — 16 cosigners + up to 255 delegates = 271
        // slots, far under 1024. The slot-capacity check remains in validate() as defense in
        // depth; the live boundary is the cosigner cap.)
        let mut overflow = state_with_members(16);
        overflow.member_count = (MAX_COSIGNERS + 1) as u8;
        overflow.delegate_count = 1;
        assert!(
            matches!(
                overflow.validate(),
                Err(ChannelError::InvalidBalanceState(_))
            ),
            "member_count > MAX_COSIGNERS must be rejected"
        );
        // 16 cosigners + 1 active delegate is well within the 1024 balance slots and must
        // validate (the delegate slot 16 carries an active ciphertext).
        let mut full_members = state_with_members(16);
        full_members.delegate_count = 1;
        full_members.enc_balances[16] = ciphertext(60);
        full_members
            .validate()
            .expect("16 cosigners + 1 active delegate must validate at MAX=1024 slots");

        // A slot inside the delegate region must be ACTIVE (non-padding): if a declared delegate
        // slot is left as padding it is fine (padding ct is canonical), but a slot BEYOND
        // member_count+delegate_count that is non-default is rejected.
        let mut bad_pad = state_with_members(3);
        bad_pad.delegate_count = 1; // active region = 0..4
        bad_pad.enc_balances[3] = ciphertext(50); // the single delegate slot
        bad_pad.enc_balances[5] = ciphertext(51); // a padding slot (>= 4) — must be rejected
        assert!(
            matches!(
                bad_pad.validate(),
                Err(ChannelError::InvalidBalanceState(_))
            ),
            "non-default slot in the padding region (>= member_count+delegate_count) is rejected"
        );

        // The delegate region shifts the H1-committed split: same ciphertexts, different
        // member/delegate boundary => different H1.
        let mut split_a = state_with_members(2);
        split_a.delegate_count = 2;
        for s in 0..4u32 {
            split_a.enc_balances[s as usize] = ciphertext(200 + s);
        }
        let mut split_b = split_a.clone();
        split_b.member_count = 3;
        split_b.delegate_count = 1; // same active span (4) but different member/delegate boundary
        assert_ne!(
            split_a.h1(),
            split_b.h1(),
            "moving the member/delegate boundary must change H1"
        );
    }

    /// `BalanceState::h1()` binds `member_count`: two states identical except for `member_count`
    /// (active prefix repadded to match) produce DIFFERENT H1 digests across the supported range.
    /// Proves member_count is genuinely part of the H1 preimage (D6), so the active/padding split
    /// cannot be silently reinterpreted under the all-member signatures.
    #[test]
    fn h1_binds_member_count_multi_n() {
        // Cosigner range 2..=MAX_COSIGNERS (the old `..MAX_CHANNEL_MEMBERS as u8` became an EMPTY
        // range at MAX=1024 — `1024 as u8 == 0` — silently testing nothing).
        for count in 2u8..MAX_COSIGNERS as u8 {
            assert_ne!(
                state_with_members(count).h1(),
                state_with_members(count + 1).h1(),
                "member_count {count} vs {} must change h1",
                count + 1
            );
        }
    }

    /// H1 Poseidon-root form: the fast bottom-up `slot_tree_root()` fold MUST equal the
    /// `IncrementalMerkleTree` root the claim witness builders prove inclusion against — if the
    /// two ever diverge, every claim inclusion proof would disagree with the signed H1 header.
    /// Also proves the padding-leaf memoization is a pure memoization (padding slots hash to the
    /// same leaf as a per-slot recompute) and that ACTIVE slot leaf data flips the root.
    #[test]
    fn slot_tree_root_matches_incremental_tree() {
        let state = sample_state();
        assert_eq!(
            state.slot_tree_root(),
            state.slot_tree().get_root(),
            "fold root must equal the IncrementalMerkleTree root"
        );

        // Explicit per-slot recompute (no padding memoization) — same leaves, same root.
        let naive: Vec<PoseidonHashOut> = (0..MAX_CHANNEL_MEMBERS)
            .map(|i| {
                balance_slot_leaf_hash(
                    state.regev_pk_digests[i],
                    state.enc_balances[i].digest(),
                    state.pending_adds[i],
                )
            })
            .collect();
        assert_eq!(state.slot_leaf_hashes(), naive);

        // A pk digest / add-counter change in an ACTIVE slot flips the root (leaf binding).
        let mut s = sample_state();
        s.regev_pk_digests[1] = Bytes32::from_u32_slice(&[5, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        assert_ne!(state.slot_tree_root(), s.slot_tree_root());
        assert_eq!(s.slot_tree_root(), s.slot_tree().get_root());
    }

    /// The new H1 is the CANONICAL `PoseidonHashOut → Bytes32` encoding of the header hash —
    /// it must round-trip through the canonical decode (the same property the claim circuits'
    /// `to_hash_out` round-trip check enforces for the accumulator root).
    #[test]
    fn h1_is_canonical_poseidon_bytes32_encoding() {
        let h1 = sample_state().h1();
        let decoded: PoseidonHashOut = h1
            .try_into()
            .expect("H1 must be a canonical Poseidon->Bytes32 encoding");
        assert_eq!(Bytes32::from(decoded), h1);
    }

    /// Leaf-encoding injectivity: each component of the slot leaf triple is binding, and the
    /// leaf carries its own domain constant (distinct from the header hash on identical-prefix
    /// inputs).
    #[test]
    fn balance_slot_leaf_hash_binds_every_component() {
        let pk = pubkey_hash(1);
        let enc = pubkey_hash(100);
        let leaf = balance_slot_leaf_hash(pk, enc, 3);
        assert_eq!(leaf, balance_slot_leaf_hash(pk, enc, 3));
        assert_ne!(leaf, balance_slot_leaf_hash(pubkey_hash(2), enc, 3));
        assert_ne!(leaf, balance_slot_leaf_hash(pk, pubkey_hash(101), 3));
        assert_ne!(leaf, balance_slot_leaf_hash(pk, enc, 4));
        // Swapping the pk/enc positions must change the leaf (fixed-position encoding).
        assert_ne!(leaf, balance_slot_leaf_hash(enc, pk, 3));
    }

    #[test]
    fn validate_enforces_canonicality_and_add_budget() {
        sample_state().validate().unwrap();

        let mut s = sample_state();
        s.enc_balances[1].c1[0] = REGEV_Q; // non-canonical
        assert!(matches!(
            s.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        let mut s = sample_state();
        s.pending_adds[2] = MAX_HOMO_ADDS_BEFORE_REFRESH;
        s.validate().unwrap(); // at the bound is still representable…
        s.pending_adds[2] = MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
        assert!(matches!(
            s.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        )); // …above it is not.
    }

    /// Golden vector pinning the chain-push preimage layout `[IMTC, chain, leaf]` over
    /// solidity-packed keccak. If this changes, every signed settled_tx_chain changes.
    #[test]
    fn settled_tx_chain_push_golden_vector() {
        let chain = Bytes32::default();
        let leaf = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let pushed = settled_tx_chain_push(chain, leaf);
        assert_eq!(
            pushed.to_string(),
            "0xb6b0dc5967d87831d967413a5ce4e960d9a69f584d1d898f4abc25437925471a"
        );
        // Chaining is order-sensitive: push(push(0, a), b) != push(push(0, b), a).
        let other = Bytes32::from_u32_slice(&[8, 7, 6, 5, 4, 3, 2, 1]).unwrap();
        assert_ne!(
            settled_tx_chain_push(pushed, other),
            settled_tx_chain_push(settled_tx_chain_push(chain, other), leaf)
        );
    }

    /// Proves the in-circuit chain push is byte-identical to the off-chain fold for random
    /// inputs. This is the soundness anchor for the balance-circuit `settled_tx_chain` PI: if
    /// the two ever diverge, signed `BalanceState.settled_tx_chain` values would no longer match
    /// any provable balance proof PI (detail2 §F-1 equality check).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn settled_tx_chain_push_circuit_matches_off_chain() {
        use plonky2::{
            field::goldilocks_field::GoldilocksField,
            iop::witness::PartialWitness,
            plonk::{
                circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
                config::PoseidonGoldilocksConfig,
            },
        };

        use crate::ethereum_types::u32limb_trait::U32LimbTargetTrait as _;

        const D: usize = 2;
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let chain_t = Bytes32Target::new(&mut builder, true);
        let leaf_t = Bytes32Target::new(&mut builder, true);
        let pushed_t = settled_tx_chain_push_circuit::<F, C, D>(&mut builder, chain_t, leaf_t);
        builder.register_public_inputs(&pushed_t.to_vec());
        let data = builder.build::<C>();

        let mut rng = rand::thread_rng();
        for _ in 0..3 {
            let chain = Bytes32::rand(&mut rng);
            let leaf = Bytes32::rand(&mut rng);
            let expected = settled_tx_chain_push(chain, leaf);

            let mut pw = PartialWitness::<F>::new();
            chain_t.set_witness(&mut pw, chain);
            leaf_t.set_witness(&mut pw, leaf);
            let proof = data.prove(pw).expect("chain push circuit proof");
            data.verify(proof.clone()).expect("chain push verification");

            let actual_limbs = proof
                .public_inputs
                .iter()
                .map(|x| {
                    u32::try_from(plonky2::field::types::PrimeField64::to_canonical_u64(x))
                        .expect("PI limb must be u32")
                })
                .collect::<Vec<_>>();
            let actual = Bytes32::from_u32_slice(&actual_limbs).unwrap();
            assert_eq!(actual, expected, "circuit chain push must match off-chain");
        }
    }

    #[test]
    fn tx_leaf_hash_is_wing_order_sensitive() {
        let sender = pubkey_hash(10);
        let receiver = pubkey_hash(21);
        let d_send = ciphertext(11).digest();
        let d_recv = ciphertext(12).digest();

        let leaf = tx_leaf_hash(sender, d_send, receiver, d_recv);
        assert_eq!(leaf, tx_leaf_hash(sender, d_send, receiver, d_recv));
        // Swapping the wings (who sends / who receives) must change the leaf.
        assert_ne!(leaf, tx_leaf_hash(receiver, d_recv, sender, d_send));
        // Each component is binding.
        assert_ne!(
            leaf,
            tx_leaf_hash(pubkey_hash(11), d_send, receiver, d_recv)
        );
        assert_ne!(leaf, tx_leaf_hash(sender, d_recv, receiver, d_recv));
        assert_ne!(leaf, tx_leaf_hash(sender, d_send, pubkey_hash(22), d_recv));
        assert_ne!(leaf, tx_leaf_hash(sender, d_send, receiver, d_send));
    }

    #[test]
    fn balance_state_hash_binds_both_halves() {
        let h1 = sample_state().h1();
        let h2 = Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let bound = balance_state_hash(h1, h2);
        assert_ne!(bound, balance_state_hash(h1, Bytes32::default()));
        assert_ne!(bound, balance_state_hash(Bytes32::default(), h2));
        assert_ne!(bound, balance_state_hash(h2, h1));
    }
}
