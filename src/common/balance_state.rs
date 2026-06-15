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
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    regev::{MAX_HOMO_ADDS_BEFORE_REFRESH, RegevCiphertext},
};

/// Domain separator for [`BalanceState::h1`] ("IMBS").
pub const BALANCE_STATE_DOMAIN: u32 = 0x494d4253;
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
    /// One balance ciphertext per slot, in member slot order. Slots `>= member_count` are
    /// `RegevCiphertext::padding()`.
    pub enc_balances: [RegevCiphertext; MAX_CHANNEL_MEMBERS],
    /// Hash chain over the settles this state has absorbed (genesis = 0x00…00).
    pub settled_tx_chain: Bytes32,
    /// Monotone state counter, +1 on every in-channel AND inter-channel update. Independent of
    /// `epoch` / `small_block_number` (in-channel transfers produce no small block).
    pub state_version: u64,
    /// Homomorphic-add counters per member slot since that member's last fresh re-encryption
    /// (approved deviation D3 from detail2 §C-2; closes the noise/digit-flooding exit-liveness
    /// DoS). Co-signers must refuse adds at `MAX_HOMO_ADDS_BEFORE_REFRESH`. Padding slots are 0.
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

    /// H1 (detail2 §C-2 + D3, pad-to-MAX deviation D6): keccak over
    /// `[BALANCE_STATE_DOMAIN, channel_id, member_count, d_0, …, d_{MAX-1}, settled_tx_chain,
    /// split_u64(state_version), pending_adds[0..MAX]]` where `d_i = enc_balances[i].digest()`.
    ///
    /// PREIMAGE (exact, one u32 word per limb): `member_count` is placed as a single u32 limb
    /// RIGHT AFTER `channel_id` (before the ciphertext digests); ALL `MAX_CHANNEL_MEMBERS`
    /// ciphertext digests and pending-add counters are hashed (padding slots use
    /// `RegevCiphertext::padding()` digests and 0 counters). This must stay byte-identical to the
    /// in-circuit recompute in `circuits::channel::close_circuit` and to the L1 mirror.
    ///
    /// SECURITY: hashing `member_count` and ALL 16 slots fixes the active/padding split under the
    /// member signatures (D6). `pending_adds` is part of the preimage so the D3 add-counters are
    /// enforced by the same all-member signatures that bind the balances (adversarial review F5-A).
    pub fn h1(&self) -> Bytes32 {
        let mut words = vec![BALANCE_STATE_DOMAIN];
        words.extend(self.channel_id.to_u32_vec());
        words.push(self.member_count as u32);
        for ct in &self.enc_balances {
            words.extend(ct.digest().to_u32_vec());
        }
        words.extend(self.settled_tx_chain.to_u32_vec());
        words.extend(split_u64(self.state_version));
        words.extend_from_slice(&self.pending_adds);
        hash_words(&words)
    }

    /// Canonicality / budget check. MUST run on every balance state that crosses a trust
    /// boundary: each ciphertext must be canonical (otherwise its digest — and hence H1 — is
    /// malleable, F1-A) and every add counter must respect the D3 refresh budget. Also enforces
    /// the pad-to-MAX (D6) invariants: `2 <= member_count <= MAX_CHANNEL_MEMBERS`, and every
    /// padding slot (`>= member_count`) is the default/empty value.
    pub fn validate(&self) -> Result<(), ChannelError> {
        let count = self.member_count as usize;
        if count < 2 || count > MAX_CHANNEL_MEMBERS {
            return Err(ChannelError::InvalidBalanceState(format!(
                "member_count {count} out of range (must be 2..={MAX_CHANNEL_MEMBERS})"
            )));
        }
        for (index, ct) in self.enc_balances.iter().enumerate() {
            ct.validate().map_err(|err| {
                ChannelError::InvalidBalanceState(format!(
                    "enc_balances[{index}] is not canonical: {err}"
                ))
            })?;
            // Padding slots MUST be the canonical empty ciphertext (D6): a non-default padding slot
            // would smuggle hidden value past the active/member_count accounting.
            if index >= count && *ct != RegevCiphertext::padding() {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "enc_balances[{index}] is a padding slot (>= member_count {count}) and must be \
                     RegevCiphertext::padding()"
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
            if index >= count && adds != 0 {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "pending_adds[{index}] is a padding slot (>= member_count {count}) and must be 0"
                )));
            }
        }
        Ok(())
    }
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
            enc_balances: BalanceState::pad_enc_balances(&[
                ciphertext(1),
                ciphertext(2),
                ciphertext(3),
            ]),
            settled_tx_chain: Bytes32::default(),
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
            enc_balances: BalanceState::pad_enc_balances(&active),
            settled_tx_chain: Bytes32::default(),
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

        // member_count > MAX_CHANNEL_MEMBERS rejected.
        let mut too_many = state_with_members(16);
        too_many.member_count = (MAX_CHANNEL_MEMBERS + 1) as u8;
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

    /// `BalanceState::h1()` binds `member_count`: two states identical except for `member_count`
    /// (active prefix repadded to match) produce DIFFERENT H1 digests across the supported range.
    /// Proves member_count is genuinely part of the H1 preimage (D6), so the active/padding split
    /// cannot be silently reinterpreted under the all-member signatures.
    #[test]
    fn h1_binds_member_count_multi_n() {
        for count in 2u8..MAX_CHANNEL_MEMBERS as u8 {
            assert_ne!(
                state_with_members(count).h1(),
                state_with_members(count + 1).h1(),
                "member_count {count} vs {} must change h1",
                count + 1
            );
        }
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
