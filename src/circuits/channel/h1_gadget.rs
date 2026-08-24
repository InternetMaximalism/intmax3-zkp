//! Shared in-circuit `BalanceState::h1()` recompute (Poseidon-root form), extracted so the
//! channel-close, cancel-close, withdrawal-claim and post-close-claim circuits share ONE
//! definition of the H1 header — no drift. See `tasks/h1-poseidon-root-threat-model.md` and
//! detail2 §N-1/§N-2 (multi-token v2 layouts).
//!
//! SECURITY: this MUST stay element-identical to the native
//! `common::balance_state::BalanceState::h1`. The header is the FIXED-width (37-element) v2
//! Poseidon preimage
//!
//!   `[BALANCE_STATE_DOMAIN_V2, channel_id, member_count, delegate_count, token_count,
//!     token_registry (10 canonical u32 limbs, zero-padded), slot_tree_root (4 Goldilocks
//!     elements), settled_tx_chain (8 u32 limbs), settled_tx_accumulator_root (8 u32 limbs),
//!     state_version (hi, lo u32 limbs)]`
//!
//! and the exposed H1 is the canonical `PoseidonHashOut → Bytes32` encoding of its hash
//! (`Bytes32Target::from_hash_out`, whose `safe_split_lo_and_hi` forbids the non-canonical
//! decomposition — exactly ONE Bytes32 encodes a given header hash). The per-slot data
//! (regev pk digest, 10 ciphertext digests, 10 per-token add counters, recipient) is NO LONGER
//! hashed here: it is committed by `slot_tree_root`, the height-`BALANCE_SLOT_TREE_HEIGHT`
//! Poseidon Merkle root over the `MAX_CHANNEL_MEMBERS` slot leaves
//! ([`balance_slot_leaf_hash_circuit`]). Circuits that must OPEN a slot (the claim circuits)
//! prove a Merkle inclusion of that slot's leaf against the root; circuits that only pin the
//! signed scalars (close/cancel) witness the root directly — it is attested by the cosigner
//! signatures over H1.
//!
//! SECURITY (TM-9, multi-token): `token_count` and the FULL zero-padded `token_registry` are
//! part of the signed header, immediately after `delegate_count` — mirroring the
//! member_count/delegate_count discipline. Any circuit consuming the registry (the claim
//! circuits' `registry[token_slot]` resolution, the close circuit's injectivity re-check) MUST
//! feed the SAME targets into this recompute, so the values used are exactly the signed ones.
//!
//! Poseidon inputs are FIELD elements (no keccak-style byte decomposition), so a non-canonical
//! witness limb simply produces a different hash rather than an alias; the u32 range checks the
//! callers keep on these limbs are load-bearing for the OTHER (keccak) preimages the same wires
//! feed, and defense-in-depth here.

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    constants::{BALANCE_SLOT_LEAF_DOMAIN_V2, BALANCE_STATE_DOMAIN_V2, MAX_CHANNEL_TOKENS},
    ethereum_types::{
        address::AddressTarget, bytes32::Bytes32Target, u32limb_trait::U32LimbTargetTrait as _,
        u64::U64Target,
    },
    utils::poseidon_hash_out::PoseidonHashOutTarget,
};

/// Recompute `BalanceState::h1()` in-circuit (v2, detail2 §N-1) from the witnessed slot-tree
/// root and the PI/witness-bound scalars.
///
/// Inputs (all caller-allocated; the u32 limbs 32-bit range-checked by the callers):
/// - `channel_id`: the single base-identity u32 limb.
/// - `member_count`, `delegate_count`: single u32 limbs (the active/padding split).
/// - `token_count`: single u32 limb (the active/unused TOKEN boundary, TM-8/TM-9).
/// - `token_registry`: the FULL `MAX_CHANNEL_TOKENS` canonical u32 limbs (zero-padded beyond
///   `token_count`) — the signed local-slot -> base-token mapping (TM-9). Callers that resolve
///   `registry[token_slot]` MUST select from THESE targets.
/// - `slot_tree_root`: the balance-slot Poseidon Merkle root (4 raw Goldilocks elements). For
///   close/cancel this is a free witness — SOUND because the root rides INSIDE the signed H1 (the
///   cosigner signatures attest it); the claim circuits additionally open one leaf against it via a
///   Merkle inclusion proof.
/// - `settled_tx_chain`, `settled_tx_accumulator_root`: 8 u32 limbs each (accumulator root
///   IMMEDIATELY AFTER the chain, mirroring the native order).
/// - `state_version`: the monotone state counter (2 u32 limbs, `U64Target` `[hi, lo]` order =
///   native `split_u64`).
///
/// Returns the recomputed H1 as a `Bytes32Target` (canonical Poseidon→Bytes32 encoding). The
/// caller `connect`s it to the H1 PI.
#[allow(clippy::too_many_arguments)]
pub(crate) fn recompute_h1<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    channel_id: Target,
    member_count: Target,
    delegate_count: Target,
    token_count: Target,
    token_registry: &[Target; MAX_CHANNEL_TOKENS],
    slot_tree_root: PoseidonHashOutTarget,
    settled_tx_chain: &Bytes32Target,
    settled_tx_accumulator_root: &Bytes32Target,
    state_version: &U64Target,
) -> Bytes32Target
where
    F: RichField + Extendable<D>,
{
    let balance_state_domain = builder.constant(F::from_canonical_u32(BALANCE_STATE_DOMAIN_V2));
    let h1_inputs = [
        vec![
            balance_state_domain,
            channel_id,
            member_count,
            delegate_count,
            // SECURITY (TM-9): token_count + the full registry sit right after the
            // member/delegate counts, element-identical to native `h1_header_preimage`.
            token_count,
        ],
        token_registry.to_vec(),
        slot_tree_root.to_vec(),
        settled_tx_chain.to_vec(),
        // Stage 3: the accumulator root sits IMMEDIATELY AFTER settled_tx_chain and BEFORE
        // state_version, element-identical to native `BalanceState::h1`.
        settled_tx_accumulator_root.to_vec(),
        state_version.to_vec(),
    ]
    .concat();
    let header_hash = PoseidonHashOutTarget::hash_inputs(builder, &h1_inputs);
    Bytes32Target::from_hash_out(builder, header_hash)
}

/// In-circuit twin of `common::balance_state::balance_slot_leaf_hash` (v2, detail2 §N-2): the
/// per-slot leaf of the H1 balance-slot tree,
/// `Poseidon([BALANCE_SLOT_LEAF_DOMAIN_V2, regev_pk_digest (8),
/// enc_balance_digest[0..10] (80, one 8-limb keccak digest per token slot),
/// pending_adds[0..10] (10), recipient (5)])` — FIXED 104-element width, injective on the slot
/// tuple.
///
/// The claim circuits hash the slot they open with this gadget and verify a height-
/// `BALANCE_SLOT_TREE_HEIGHT` `IncrementalMerkleProofTarget<PoseidonHashOutTarget>` inclusion of
/// the result (leaf value = leaf hash; `LeafableTarget::hash` is the identity for
/// `PoseidonHashOutTarget`) against the `slot_tree_root` fed to [`recompute_h1`].
///
/// SECURITY (TM-2/TM-8, multi-token): ALL `MAX_CHANNEL_TOKENS` ciphertext digests and add
/// counters enter the leaf — the full-width layout is what makes a one-hot select over
/// `enc_balance_digests` binding (the non-selected 9 positions are still leaf-committed, so a
/// prover cannot relocate a ciphertext to another token position without changing the leaf and
/// breaking the inclusion against the signed root).
///
/// SECURITY (B-1b): `recipient` is the slot's cosigner-signed L1 exit address (5 u32 limbs; the
/// claim circuits pass their range-checked `recipient` PI `AddressTarget` here, which CONNECTS
/// the leaf-opened recipient to the claim's exposed recipient — the payout-redirection defense
/// for delegates, which have no L1 registration under Option B).
pub(crate) fn balance_slot_leaf_hash_circuit<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    regev_pk_digest: &Bytes32Target,
    enc_balance_digests: &[Bytes32Target; MAX_CHANNEL_TOKENS],
    pending_adds: &[Target; MAX_CHANNEL_TOKENS],
    recipient: &AddressTarget,
) -> PoseidonHashOutTarget
where
    F: RichField + Extendable<D>,
{
    let leaf_domain = builder.constant(F::from_canonical_u32(BALANCE_SLOT_LEAF_DOMAIN_V2));
    let leaf_inputs = [
        vec![leaf_domain],
        regev_pk_digest.to_vec(),
        enc_balance_digests
            .iter()
            .flat_map(|digest| digest.to_vec())
            .collect(),
        pending_adds.to_vec(),
        recipient.to_vec(),
    ]
    .concat();
    PoseidonHashOutTarget::hash_inputs(builder, &leaf_inputs)
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field as _, PrimeField64},
        },
        iop::witness::{PartialWitness, WitnessWrite as _},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use super::*;
    use crate::{
        common::{
            balance_state::{BalanceState, TokenCiphertexts, balance_slot_leaf_hash},
            channel::ChannelId,
        },
        constants::MAX_CHANNEL_MEMBERS,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u64::U64,
        },
        regev::{REGEV_N, REGEV_Q, RegevCiphertext},
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    /// A random canonical ciphertext (coefficients < q). Digest/H1 tests only need canonical,
    /// distinct ring elements — these are not decryptable.
    fn rand_ciphertext(rng: &mut impl Rng) -> RegevCiphertext {
        RegevCiphertext {
            c1: (0..REGEV_N).map(|_| rng.gen_range(0..REGEV_Q)).collect(),
            c2: (0..REGEV_N).map(|_| rng.gen_range(0..REGEV_Q)).collect(),
        }
    }

    /// The soundness anchor for the Poseidon-root H1 (v2 multi-token layouts): for a RANDOM
    /// `BalanceState` (random regev pk digests, per-token ciphertexts, adds, registry, scalars),
    /// the native `BalanceState::h1()` MUST equal the in-circuit `recompute_h1` over the natively
    /// computed `slot_tree_root()`, AND the in-circuit leaf gadget must equal the native
    /// `balance_slot_leaf_hash` for the opened slot. If the native and circuit header/leaf
    /// encodings ever drift, every signed H1 PI would disagree with any provable
    /// close/cancel/claim proof — this catches encoding/order drift before it ships.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn recompute_h1_matches_native_balance_state_h1_randomized() {
        // Build a tiny circuit: witness the header inputs, recompute H1, register it as the PI,
        // and additionally recompute ONE slot leaf with the leaf gadget.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        let channel_id_t = u32_limb(&mut builder);
        let member_count_t = u32_limb(&mut builder);
        let delegate_count_t = u32_limb(&mut builder);
        let token_count_t = u32_limb(&mut builder);
        let token_registry_t: [Target; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| u32_limb(&mut builder));
        let slot_tree_root_t = PoseidonHashOutTarget::new(&mut builder);
        let settled_tx_chain_t = Bytes32Target::new(&mut builder, true);
        let settled_tx_accumulator_root_t = Bytes32Target::new(&mut builder, true);
        let state_version_t = U64Target::new(&mut builder, true);
        let recomputed = recompute_h1::<F, D>(
            &mut builder,
            channel_id_t,
            member_count_t,
            delegate_count_t,
            token_count_t,
            &token_registry_t,
            slot_tree_root_t,
            &settled_tx_chain_t,
            &settled_tx_accumulator_root_t,
            &state_version_t,
        );
        // Leaf gadget twin (v2, 104 elems): leaf over witnessed slot data — 10 ct digests + 10
        // per-token add counters (B-1b: recipient limbs range-checked, exactly as the claim
        // circuits' recipient PI is).
        let leaf_pk_t = Bytes32Target::new(&mut builder, true);
        let leaf_enc_t: [Bytes32Target; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| Bytes32Target::new(&mut builder, true));
        let leaf_adds_t: [Target; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| u32_limb(&mut builder));
        let leaf_recipient_t = AddressTarget::new(&mut builder, true);
        let leaf_t = balance_slot_leaf_hash_circuit::<F, D>(
            &mut builder,
            &leaf_pk_t,
            &leaf_enc_t,
            &leaf_adds_t,
            &leaf_recipient_t,
        );
        builder.register_public_inputs(&recomputed.to_vec());
        builder.register_public_inputs(&leaf_t.to_vec());
        let data = builder.build::<C>();

        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            // member_count over the FULL cosigner range 2..=MAX_SIG_CLUSTER; delegate_count 0..=16;
            // token_count over the FULL 1..=MAX_CHANNEL_TOKENS range with a random INJECTIVE
            // active registry prefix (zero-padded beyond). The padding suffix exercises the
            // memoized padding leaf; per-token ciphertexts populate a random subset of the
            // active token positions (inactive positions stay the canonical zero ct, TM-8).
            let member_count = rng.gen_range(2usize..=crate::constants::MAX_SIG_CLUSTER);
            let delegate_count = rng.gen_range(0usize..=16);
            let active = member_count + delegate_count;
            let token_count = rng.gen_range(1usize..=MAX_CHANNEL_TOKENS);
            let mut token_registry = [0u32; MAX_CHANNEL_TOKENS];
            // Injective active prefix: token slot 0 = ETH (0), further slots distinct nonzero.
            for (t, entry) in token_registry.iter_mut().enumerate().take(token_count) {
                *entry = if t == 0 {
                    0
                } else {
                    1 + rng.gen_range(0..u32::MAX - 1)
                };
            }
            let enc_active: Vec<TokenCiphertexts> = (0..active)
                .map(|_| {
                    let mut row = crate::common::balance_state::zero_token_row();
                    for (t, ct) in row.iter_mut().enumerate().take(token_count) {
                        // Random subset of active token positions holds a real ciphertext.
                        if t == 0 || rng.r#gen::<bool>() {
                            *ct = rand_ciphertext(&mut rng);
                        }
                    }
                    row
                })
                .collect();
            let pk_active: Vec<Bytes32> = (0..active).map(|_| Bytes32::rand(&mut rng)).collect();
            let adds_active: Vec<[u32; MAX_CHANNEL_TOKENS]> = (0..active)
                .map(|_| {
                    std::array::from_fn(|t| {
                        if t < token_count {
                            rng.gen_range(0..=crate::regev::MAX_HOMO_ADDS_BEFORE_REFRESH)
                        } else {
                            0
                        }
                    })
                })
                .collect();
            // B-1b: RANDOM nonzero recipients for the active slots (padding slots stay zero via
            // pad_recipients — exercising both leaf forms). Address::rand is 160 random bits, so
            // a zero draw is negligible; validate() below would catch it fail-closed anyway.
            let recipients_active: Vec<Address> =
                (0..active).map(|_| Address::rand(&mut rng)).collect();
            let state = BalanceState {
                channel_id: ChannelId::new(rng.gen_range(1..u32::MAX as u64)).unwrap(),
                member_count: member_count as u8,
                delegate_count: delegate_count as u16,
                enc_balances: BalanceState::pad_enc_balances(&enc_active),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&pk_active),
                recipients: BalanceState::pad_recipients(&recipients_active),
                settled_tx_chain: Bytes32::rand(&mut rng),
                settled_tx_accumulator_root: Bytes32::rand(&mut rng),
                state_version: rng.r#gen(),
                pending_adds: BalanceState::pad_pending_adds(&adds_active),
                token_registry,
                token_count: token_count as u8,
            };
            state.validate().expect("constructed state must be valid");
            let expected = state.h1();
            let root = state.slot_tree_root();
            // Alternate between an ACTIVE slot (random nonzero recipient) and a PADDING slot
            // (zero recipient, all-zero token row) so the circuit leaf gadget is exercised on
            // BOTH leaf forms of the widened 104-element encoding.
            let slot = if rng.r#gen::<bool>() {
                rng.gen_range(0..active)
            } else {
                MAX_CHANNEL_MEMBERS - 1 // always padding: active <= MAX_SIG_CLUSTER + 16 < 1023
            };
            let slot_ct_digests = BalanceState::token_ct_digests(&state.enc_balances[slot]);
            let expected_leaf = balance_slot_leaf_hash(
                state.regev_pk_digests[slot],
                &slot_ct_digests,
                &state.pending_adds[slot],
                state.recipients[slot],
            );

            let mut pw = PartialWitness::<F>::new();
            pw.set_target(
                channel_id_t,
                F::from_canonical_u32(state.channel_id.to_u32_vec()[0]),
            )
            .unwrap();
            pw.set_target(member_count_t, F::from_canonical_u8(state.member_count))
                .unwrap();
            pw.set_target(
                delegate_count_t,
                F::from_canonical_u16(state.delegate_count),
            )
            .unwrap();
            pw.set_target(token_count_t, F::from_canonical_u8(state.token_count))
                .unwrap();
            for (t, &limb) in state.token_registry.iter().enumerate() {
                pw.set_target(token_registry_t[t], F::from_canonical_u32(limb))
                    .unwrap();
            }
            slot_tree_root_t.set_witness(&mut pw, root);
            settled_tx_chain_t.set_witness(&mut pw, state.settled_tx_chain);
            settled_tx_accumulator_root_t.set_witness(&mut pw, state.settled_tx_accumulator_root);
            state_version_t.set_witness(&mut pw, U64::from(state.state_version));
            leaf_pk_t.set_witness(&mut pw, state.regev_pk_digests[slot]);
            for (t, digest) in slot_ct_digests.iter().enumerate() {
                leaf_enc_t[t].set_witness(&mut pw, *digest);
            }
            for (t, &adds) in state.pending_adds[slot].iter().enumerate() {
                pw.set_target(leaf_adds_t[t], F::from_canonical_u32(adds))
                    .unwrap();
            }
            leaf_recipient_t.set_witness(&mut pw, state.recipients[slot]);

            let proof = data.prove(pw).expect("h1 recompute proof");
            data.verify(proof.clone()).expect("h1 recompute verify");

            let limbs = proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .collect::<Vec<_>>();
            let actual = Bytes32::from_u32_slice(
                &limbs[0..8]
                    .iter()
                    .map(|&x| u32::try_from(x).expect("H1 PI limb must be u32"))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert_eq!(
                actual, expected,
                "in-circuit recompute_h1 must equal native BalanceState::h1 (header encoding/order)"
            );
            assert_eq!(
                &limbs[8..12],
                &expected_leaf.elements[..],
                "in-circuit leaf gadget must equal native balance_slot_leaf_hash"
            );

            // Sanity: MAX_CHANNEL_MEMBERS stays in sync with the tree the native root builds.
            assert_eq!(state.slot_leaf_hashes().len(), MAX_CHANNEL_MEMBERS);
        }
    }
}
