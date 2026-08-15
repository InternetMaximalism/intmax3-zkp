//! IMCH channel-state signing-preimage mirror for the validity proof circuit.
//!
//! Under **Design B** of `doc/tasks/small-block-nofn-design.md` (§4A, decision D0) the N-of-N
//! small-block authorization is an aggregate over the **IMCH channel-state digest** — the digest
//! `ChannelState::signing_digest()` (`common/channel.rs`) that every co-signer already signs on
//! every state transition — rather than over a reshaped IMSB small-block digest.
//! `update_channel_tree` will therefore witness the IMCH preimage limbs, recompute the digest
//! in-circuit, and connect the `h2_tag` segment to the block's `tx_tree_root` targets (§5.4,
//! "Design B variant").
//!
//! This module is the **native half** of that recompute: the limb layout, in one place, with a
//! golden-vector test against the canonical `ChannelState::signing_digest()`.
//!
//! SECURITY — why this exists as its own mirror (design §5.4): a limb-order divergence between the
//! circuit's recompute and the digest members actually sign is a silent COMPLETENESS break (no
//! real signature would ever verify), and a limb OMISSION is a SOUNDNESS break (the omitted field
//! becomes forgeable while the aggregate still verifies). Both are invisible to any test that only
//! checks "the circuit proves". The golden-vector test below is the guard; the mutation test beside
//! it pins that every one of the 139 limbs is load-bearing.
//!
//! SECURITY — what may be a free witness and what may not: every limb here EXCEPT the connected
//! ones may be a free prover witness, because the digest is fully determined by the limbs and a
//! valid N-of-N aggregate over it requires the registered members to have signed those exact limbs
//! — the signature is the authenticator (design §4A.2). The limbs the enclosing circuit MUST
//! supply from its own block-level targets, never witness, are:
//!   * `channel_id` (limb [`CHANNEL_ID_LIMB`]) and the fund's `channel_id` (limb
//!     [`FUND_CHANNEL_ID_LIMB`]) — otherwise a channel-A signature applies to channel B;
//!   * `h2_tag` (limbs [`H2_TAG_LIMBS`]) — this is the entire security content of the binding: the
//!     state's `h2_tag` IS the small block's `tx_tree_root` for an inter-channel send
//!     (`common/channel.rs`, detail2 §C-2/§D), so connecting it is what makes a state signature an
//!     authorization for THIS block's tx root.
//!
//! That is why [`ChannelStateMessageFields`] deliberately does NOT carry those fields: they are
//! parameters of [`ChannelStateMessageFields::signing_digest`], exactly as `channel_id` /
//! `tx_tree_root` are for the IMSB mirror in `small_block_message.rs`.
//!
//! NOTE (design-doc correction): §4A.4 numbers the preimage segments "domain 1, channel_id 1,
//! epoch 2, …" and §5.4 refers to "`channel_id` (limb 1) and `channel_fund.channel_id` (limb 6)".
//! Those are SEGMENT ordinals, not limb offsets. The actual u32-limb offsets are pinned by the
//! constants below and by `channel_state_preimage_limb_offsets_are_pinned`.
//!
//! Phase 1 scope: native only. The `…Target` twin lands with the `update_channel_tree` rewire
//! (design §9 Phase 3) and must be built from the same [`ChannelStateMessageFields::preimage`]
//! layout.

use crate::{
    common::channel::{CHANNEL_STATE_DOMAIN, hash_words, split_u64},
    constants::MAX_CHANNEL_TOKENS,
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
};

/// Total u32-limb width of the IMCH signing preimage. Fixed-width and injective.
pub const CHANNEL_STATE_PREIMAGE_U32_LEN: usize = 139;

/// Limb offset of the channel id (connected, not witnessed).
pub const CHANNEL_ID_LIMB: usize = 1;
/// Limb offset of `channel_fund.channel_id` (connected, not witnessed).
pub const FUND_CHANNEL_ID_LIMB: usize = 8;
/// Limb offsets of the `h2_tag` segment — connected to the block's `tx_tree_root`.
pub const H2_TAG_LIMBS: std::ops::Range<usize> = 129..137;

/// Witnessed components of the IMCH `ChannelState::signing_digest()` preimage, EXCLUDING the
/// channel id (both of its occurrences) and `h2_tag`, which the enclosing circuit supplies from
/// its block-level targets so the signed digest stays structurally bound to the channel and to the
/// tx root actually applied.
///
/// Field order mirrors the preimage order; see [`Self::preimage`] for the limb layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelStateMessageFields {
    pub epoch: u64,
    pub small_block_number: u64,
    pub close_freeze_nonce: u64,
    /// `channel_fund.amounts` — ALWAYS the full `MAX_CHANNEL_TOKENS` width, zero-padded (TM-11).
    pub fund_amounts: [U256; MAX_CHANNEL_TOKENS],
    pub fund_intmax_state_root: Bytes32,
    /// `balance_state.h1()` — the legacy `channel_balance_root` slot.
    pub balance_state_h1: Bytes32,
    pub shared_native_nullifier_root: Bytes32,
    pub unallocated_confirmed_incoming: U256,
    pub prev_digest: Bytes32,
    /// `balance_state.state_version` — the v2 tail, after `h2_tag`.
    pub state_version: u64,
}

impl ChannelStateMessageFields {
    /// Native mirror of `ChannelState::signing_digest()`'s preimage.
    ///
    /// Limb order (139 u32 limbs, offsets in brackets):
    /// `[0] IMCH domain (1), [1] channel_id (1), [2] epoch (2), [4] small_block_number (2),`
    /// `[6] close_freeze_nonce (2), [8] channel_fund.channel_id (1),`
    /// `[9] channel_fund.amounts[0..MAX_CHANNEL_TOKENS] (10 x 8 = 80),`
    /// `[89] channel_fund.intmax_state_root (8), [97] balance_state.h1() (8),`
    /// `[105] shared_native_nullifier_root (8), [113] unallocated_confirmed_incoming (8),`
    /// `[121] prev_digest (8), [129] h2_tag (8), [137] balance_state.state_version (2)`.
    ///
    /// SECURITY: `channel_id` fills BOTH the `[1]` and `[8]` limbs. The enclosing circuit will
    /// connect both to the same block-level channel target (design §5.4), which is sound only
    /// because `channel_fund.channel_id == channel_id` is the production invariant — the close
    /// circuit already recomputes this same preimage that way, feeding
    /// `public_inputs.channel_id` into both positions (`circuits/channel/close_circuit.rs`, the
    /// IMCH recompute). A state whose fund carries a FOREIGN channel id has never been
    /// constructible and would be refused by that connect rather than mis-hashed here.
    pub fn preimage(&self, channel_id: u32, h2_tag: Bytes32) -> Vec<u32> {
        let limbs = [
            vec![CHANNEL_STATE_DOMAIN],
            vec![channel_id],
            split_u64(self.epoch),
            split_u64(self.small_block_number),
            split_u64(self.close_freeze_nonce),
            vec![channel_id],
            self.fund_amounts
                .iter()
                .flat_map(U256::to_u32_vec)
                .collect(),
            self.fund_intmax_state_root.to_u32_vec(),
            self.balance_state_h1.to_u32_vec(),
            self.shared_native_nullifier_root.to_u32_vec(),
            self.unallocated_confirmed_incoming.to_u32_vec(),
            self.prev_digest.to_u32_vec(),
            h2_tag.to_u32_vec(),
            split_u64(self.state_version),
        ]
        .concat();
        debug_assert_eq!(limbs.len(), CHANNEL_STATE_PREIMAGE_U32_LEN);
        limbs
    }

    /// Native mirror of `ChannelState::signing_digest()`.
    ///
    /// SECURITY: `channel_id` and `h2_tag` MUST be the enclosing circuit's block-level values —
    /// `h2_tag` being the block's `tx_tree_root`. See the module docs.
    pub fn signing_digest(&self, channel_id: u32, h2_tag: Bytes32) -> Bytes32 {
        hash_words(&self.preimage(channel_id, h2_tag))
    }

    /// Project a `ChannelState` onto its witnessed IMCH limbs. The two connected components
    /// (`channel_id`, `h2_tag`) are intentionally dropped — pass them to [`Self::signing_digest`].
    ///
    /// This recomputes `balance_state.h1()`, which is the expensive part of the IMCH digest.
    pub fn from_channel_state(state: &crate::common::channel::ChannelState) -> Self {
        Self {
            epoch: state.epoch,
            small_block_number: state.small_block_number,
            close_freeze_nonce: state.close_freeze_nonce,
            fund_amounts: state.channel_fund.amounts,
            fund_intmax_state_root: state.channel_fund.intmax_state_root,
            balance_state_h1: state.balance_state.h1(),
            shared_native_nullifier_root: state.shared_native_nullifier_root,
            unallocated_confirmed_incoming: state.unallocated_confirmed_incoming,
            prev_digest: state.prev_digest,
            state_version: state.balance_state.state_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            balance_state::BalanceState,
            channel::{ChannelFund, ChannelState},
            channel_id::ChannelId,
        },
        ethereum_types::address::Address,
        regev::{REGEV_N, REGEV_Q, RegevCiphertext},
    };

    /// Deterministic 64-bit xorshift — a self-contained PRNG so the "randomized states" coverage
    /// is reproducible from the seed printed in any failure.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn bytes32(&mut self) -> Bytes32 {
            let limbs: Vec<u32> = (0..8).map(|_| self.next_u32()).collect();
            Bytes32::from_u32_slice(&limbs).unwrap()
        }
        fn u256(&mut self) -> U256 {
            // Keep the top limb small so the value stays inside the canonical U256 range that
            // `from_u32_slice` accepts for every backend.
            let mut limbs: Vec<u32> = (0..8).map(|_| self.next_u32()).collect();
            limbs[0] &= 0x00ff_ffff;
            U256::from_u32_slice(&limbs).unwrap()
        }
    }

    fn ciphertext(seed: u32) -> RegevCiphertext {
        RegevCiphertext {
            c1: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(31_337).wrapping_add(i)) % REGEV_Q)
                .collect(),
            c2: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

    /// A MULTI-TOKEN balance state (`token_count = 3`) with 3 active slots. Built once: `h1()`
    /// walks all `MAX_CHANNEL_MEMBERS` slot leaves, so it is the expensive part of the test.
    fn multitoken_balance_state(channel_id: ChannelId) -> BalanceState {
        let enc: Vec<RegevCiphertext> = (0..3u32).map(|i| ciphertext(1 + i)).collect();
        let mut token_registry = BalanceState::single_token_registry(0);
        token_registry[1] = 77;
        token_registry[2] = 4242;
        BalanceState {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&enc),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            recipients: BalanceState::pad_recipients(
                &(0..3u32)
                    .map(|i| Address::from_u32_slice(&[0x7E57_0000u32.wrapping_add(i); 5]).unwrap())
                    .collect::<Vec<_>>(),
            ),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 9,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0u32; 3]),
            token_registry,
            token_count: 3,
        }
    }

    /// SECURITY (design §9 Phase 1, Design B): guards against drift between the circuit-side IMCH
    /// preimage (`ChannelStateMessageFields`, to be mirrored limb-for-limb by the
    /// `update_channel_tree` recompute in Phase 3) and the canonical
    /// `ChannelState::signing_digest()` that channel members actually sign. A divergence here is a
    /// completeness break (real signatures stop verifying); an omission is a soundness break (the
    /// omitted field becomes forgeable under a still-valid aggregate).
    ///
    /// Coverage: randomized states, INCLUDING a non-trivial multi-token `amounts` vector (all 10
    /// positions distinct and nonzero) and a nonzero `h2_tag` — the two segments the aggregate
    /// binding depends on most and the two most likely to be mis-laid-out.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_state_message_fields_digest_matches_canonical_state() {
        const SEED: u64 = 0x5eed_494d_4348_0001;
        let mut rng = Rng(SEED);

        let base_channel_id = ChannelId::new(5).unwrap();
        let mut balance_state = multitoken_balance_state(base_channel_id);
        // Guards against a vacuous pass: if every randomized state collapsed to one digest, the
        // equality below would hold while proving nothing.
        let mut seen: Vec<Bytes32> = Vec::new();
        let mut seen_h1: Vec<Bytes32> = Vec::new();

        for iteration in 0..6 {
            let channel_id_raw = (rng.next_u32() % 0x00ff_ffff).max(1);
            let channel_id = ChannelId::new(channel_id_raw as u64).unwrap();

            // Vary the balance state too, so the `h1` and `state_version` segments are not pinned
            // to a single value across the run. These are the cheap H1 header fields — the
            // expensive per-slot tree is reused.
            balance_state.channel_id = channel_id;
            balance_state.state_version = rng.next_u64();
            balance_state.settled_tx_chain = rng.bytes32();

            // A NON-TRIVIAL multi-token amounts vector: all MAX_CHANNEL_TOKENS positions distinct
            // and nonzero, so a truncated or mis-strided 80-limb segment cannot pass.
            let mut fund_amounts = [U256::default(); MAX_CHANNEL_TOKENS];
            for slot in fund_amounts.iter_mut() {
                *slot = rng.u256();
            }
            // A NONZERO h2_tag: this is the segment Design B connects to `tx_tree_root`.
            let h2_tag = rng.bytes32();
            assert_ne!(h2_tag, Bytes32::default());

            let state = ChannelState {
                channel_id,
                epoch: rng.next_u64(),
                small_block_number: rng.next_u64(),
                close_freeze_nonce: rng.next_u64(),
                channel_fund: ChannelFund {
                    channel_id,
                    amounts: fund_amounts,
                    intmax_state_root: rng.bytes32(),
                },
                balance_state: balance_state.clone(),
                h2_tag,
                shared_native_nullifier_root: rng.bytes32(),
                unallocated_confirmed_incoming: rng.u256(),
                prev_digest: rng.bytes32(),
                digest: Bytes32::default(),
                member_signatures: vec![],
            };

            let canonical = state.signing_digest();
            let fields = ChannelStateMessageFields::from_channel_state(&state);
            let mirrored = fields.signing_digest(channel_id.to_u32_vec()[0], h2_tag);

            assert_eq!(
                mirrored, canonical,
                "IMCH mirror diverged from ChannelState::signing_digest() on iteration \
                 {iteration} (seed {SEED:#x})"
            );
            assert_ne!(canonical, Bytes32::default());
            assert_eq!(
                fields.preimage(channel_id.to_u32_vec()[0], h2_tag).len(),
                CHANNEL_STATE_PREIMAGE_U32_LEN
            );
            assert!(
                !seen.contains(&canonical),
                "iteration {iteration} repeated an earlier digest — the randomization is not \
                 reaching the preimage"
            );
            assert!(
                !seen_h1.contains(&fields.balance_state_h1),
                "iteration {iteration} repeated an earlier balance_state.h1() — the H1 segment is \
                 not being varied"
            );
            seen.push(canonical);
            seen_h1.push(fields.balance_state_h1);
        }
    }

    /// SECURITY: pins the limb OFFSETS of the three components the enclosing circuit must CONNECT
    /// rather than witness (`channel_id` twice, `h2_tag`). Phase 3 wires its connects at these
    /// offsets; if the preimage layout ever shifts, the connect would silently land on the wrong
    /// limbs — binding the block's `tx_tree_root` to, say, `prev_digest` — which is exactly the
    /// soundness break the aggregate is meant to prevent. This test fails first.
    #[test]
    fn channel_state_preimage_limb_offsets_are_pinned() {
        let fields = ChannelStateMessageFields {
            state_version: 0xdead_beef_0000_0001,
            ..Default::default()
        };
        let channel_id = 0x1234_5678u32;
        let h2_tag = Bytes32::from_u32_slice(&[9, 10, 11, 12, 13, 14, 15, 0xffff_ffff]).unwrap();
        let limbs = fields.preimage(channel_id, h2_tag);

        assert_eq!(limbs.len(), CHANNEL_STATE_PREIMAGE_U32_LEN);
        assert_eq!(limbs[0], CHANNEL_STATE_DOMAIN);
        assert_eq!(limbs[0], u32::from_be_bytes(*b"IMCH"));
        assert_eq!(limbs[CHANNEL_ID_LIMB], channel_id);
        assert_eq!(limbs[FUND_CHANNEL_ID_LIMB], channel_id);
        assert_eq!(&limbs[H2_TAG_LIMBS], &h2_tag.to_u32_vec()[..]);
        // Tail: state_version is the LAST segment, after h2_tag (detail2 §C-3 v2 tail).
        assert_eq!(&limbs[137..139], &[0xdead_beef, 0x0000_0001]);
    }

    /// SECURITY (design §9 Phase 1 acceptance, Design B): every one of the 139 limbs is
    /// load-bearing. DROPPING any single limb, or TRANSPOSING any adjacent pair, must change the
    /// digest. A limb that could be dropped without changing the digest would be a field the
    /// members believe they signed but that no verifier binds; a transposable pair would let a
    /// prover re-interpret one segment as another.
    ///
    /// This is a property of the preimage encoding, so it is asserted against the keccak of the
    /// mutated limb streams directly rather than through a second mirror.
    #[test]
    fn every_channel_state_preimage_limb_is_load_bearing() {
        let mut rng = Rng(0x0a11_11b5_0000_0139);
        let mut fund_amounts = [U256::default(); MAX_CHANNEL_TOKENS];
        for slot in fund_amounts.iter_mut() {
            *slot = rng.u256();
        }
        let fields = ChannelStateMessageFields {
            epoch: rng.next_u64(),
            small_block_number: rng.next_u64(),
            close_freeze_nonce: rng.next_u64(),
            fund_amounts,
            fund_intmax_state_root: rng.bytes32(),
            balance_state_h1: rng.bytes32(),
            shared_native_nullifier_root: rng.bytes32(),
            unallocated_confirmed_incoming: rng.u256(),
            prev_digest: rng.bytes32(),
            state_version: rng.next_u64(),
        };
        let channel_id = 0x0abc_def0u32;
        let h2_tag = rng.bytes32();
        let limbs = fields.preimage(channel_id, h2_tag);
        let baseline = hash_words(&limbs);
        assert_eq!(baseline, fields.signing_digest(channel_id, h2_tag));

        // No limb may be dropped without changing the digest.
        for i in 0..CHANNEL_STATE_PREIMAGE_U32_LEN {
            let mut dropped = limbs.clone();
            dropped.remove(i);
            assert_eq!(dropped.len(), CHANNEL_STATE_PREIMAGE_U32_LEN - 1);
            assert_ne!(
                hash_words(&dropped),
                baseline,
                "dropping limb {i} left the IMCH digest unchanged"
            );
        }

        // No adjacent pair may be transposed without changing the digest. (Equal-valued neighbours
        // would be a false negative; assert there are none, rather than skipping them silently.)
        for i in 0..(CHANNEL_STATE_PREIMAGE_U32_LEN - 1) {
            assert_ne!(
                limbs[i],
                limbs[i + 1],
                "limbs {i}/{} are equal — the reorder check would be vacuous there; \
                 re-seed the fixture",
                i + 1
            );
            let mut swapped = limbs.clone();
            swapped.swap(i, i + 1);
            assert_ne!(
                hash_words(&swapped),
                baseline,
                "transposing limbs {i}/{} left the IMCH digest unchanged",
                i + 1
            );
        }
    }
}
