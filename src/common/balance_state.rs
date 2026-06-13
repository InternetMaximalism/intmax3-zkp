//! `BalanceState` — the hidden-balance core of the v2 channel layer
//! (abstract2 §2.1, detail2 §C-2/§C-6, approved deviation D3).
//!
//! Channel balances live in state only as Regev ciphertexts (one per member slot, in
//! `member_key_ids` order). `H1 = h1()` commits to the full balance state WITHOUT any proof
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
    common::channel::{ChannelError, ChannelId, UserId, hash_words, split_u64},
    constants::CHANNEL_MEMBERS,
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
    /// One balance ciphertext per member, in `member_key_ids` order.
    pub enc_balances: [RegevCiphertext; CHANNEL_MEMBERS],
    /// Hash chain over the settles this state has absorbed (genesis = 0x00…00).
    pub settled_tx_chain: Bytes32,
    /// Monotone state counter, +1 on every in-channel AND inter-channel update. Independent of
    /// `epoch` / `small_block_number` (in-channel transfers produce no small block).
    pub state_version: u64,
    /// Homomorphic-add counters per member slot since that member's last fresh re-encryption
    /// (approved deviation D3 from detail2 §C-2; closes the noise/digit-flooding exit-liveness
    /// DoS). Co-signers must refuse adds at `MAX_HOMO_ADDS_BEFORE_REFRESH`.
    pub pending_adds: [u32; CHANNEL_MEMBERS],
}

impl BalanceState {
    /// H1 (detail2 §C-2 + D3): keccak over
    /// `[BALANCE_STATE_DOMAIN, channel_id, d0, d1, d2, settled_tx_chain,
    /// split_u64(state_version), pending_adds[0..3]]` where `d_i = enc_balances[i].digest()`.
    ///
    /// SECURITY: `pending_adds` is part of the H1 preimage so the D3 add-counters are enforced by
    /// the same all-member signatures that bind the balances — an out-of-state counter would be
    /// unenforceable (adversarial review finding F5-A).
    pub fn h1(&self) -> Bytes32 {
        let mut words = vec![BALANCE_STATE_DOMAIN];
        words.extend(self.channel_id.to_u32_vec());
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
    /// malleable, F1-A) and every add counter must respect the D3 refresh budget.
    pub fn validate(&self) -> Result<(), ChannelError> {
        for (index, ct) in self.enc_balances.iter().enumerate() {
            ct.validate().map_err(|err| {
                ChannelError::InvalidBalanceState(format!(
                    "enc_balances[{index}] is not canonical: {err}"
                ))
            })?;
        }
        for (index, &adds) in self.pending_adds.iter().enumerate() {
            if adds > MAX_HOMO_ADDS_BEFORE_REFRESH {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "pending_adds[{index}] = {adds} exceeds MAX_HOMO_ADDS_BEFORE_REFRESH = \
                     {MAX_HOMO_ADDS_BEFORE_REFRESH}"
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
/// `hash( hash([TX_LEAF_DOMAIN, source_user_id, sender_delta_digest]),
///        hash([TX_LEAF_DOMAIN, receiver_user_id, receiver_delta_digest]) )`.
///
/// SECURITY: both wings carry the user id AND the Regev delta-ciphertext digest, so the chain
/// leaf binds the sending key, the receiving key and both hidden balance deltas. The leaf is
/// computable at small-block signing time (flowSend1 step 6) — unlike the base-layer nullifier,
/// which embeds the (then unknown) block number.
pub fn tx_leaf_hash(
    source_user_id: UserId,
    sender_delta_digest: Bytes32,
    receiver_user_id: UserId,
    receiver_delta_digest: Bytes32,
) -> Bytes32 {
    let sender_wing = hash_words(
        &[
            vec![TX_LEAF_DOMAIN],
            source_user_id.to_u32_vec(),
            sender_delta_digest.to_u32_vec(),
        ]
        .concat(),
    );
    let receiver_wing = hash_words(
        &[
            vec![TX_LEAF_DOMAIN],
            receiver_user_id.to_u32_vec(),
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
    use crate::{
        common::channel::KeyId,
        regev::{REGEV_N, REGEV_Q},
    };

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
            enc_balances: [ciphertext(1), ciphertext(2), ciphertext(3)],
            settled_tx_chain: Bytes32::default(),
            state_version: 5,
            pending_adds: [0, 1, 2],
        }
    }

    fn user(channel: u64, key: u64) -> UserId {
        UserId::from_parts(ChannelId::new(channel).unwrap(), KeyId::new(key).unwrap())
    }

    #[test]
    fn h1_is_deterministic_and_sensitive_to_every_field() {
        let base = sample_state();
        let h1 = base.h1();
        assert_eq!(h1, sample_state().h1(), "h1 must be deterministic");

        let mut s = sample_state();
        s.channel_id = ChannelId::new(8).unwrap();
        assert_ne!(h1, s.h1(), "channel_id must affect h1");

        for slot in 0..CHANNEL_MEMBERS {
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

        for slot in 0..CHANNEL_MEMBERS {
            let mut s = sample_state();
            s.pending_adds[slot] += 1;
            assert_ne!(h1, s.h1(), "pending_adds[{slot}] must affect h1 (D3)");
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
        let sender = user(5, 10);
        let receiver = user(7, 21);
        let d_send = ciphertext(11).digest();
        let d_recv = ciphertext(12).digest();

        let leaf = tx_leaf_hash(sender, d_send, receiver, d_recv);
        assert_eq!(leaf, tx_leaf_hash(sender, d_send, receiver, d_recv));
        // Swapping the wings (who sends / who receives) must change the leaf.
        assert_ne!(leaf, tx_leaf_hash(receiver, d_recv, sender, d_send));
        // Each component is binding.
        assert_ne!(leaf, tx_leaf_hash(user(5, 11), d_send, receiver, d_recv));
        assert_ne!(leaf, tx_leaf_hash(sender, d_recv, receiver, d_recv));
        assert_ne!(leaf, tx_leaf_hash(sender, d_send, user(7, 22), d_recv));
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
