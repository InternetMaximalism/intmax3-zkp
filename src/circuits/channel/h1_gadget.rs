//! Shared in-circuit `BalanceState::h1()` recompute (Poseidon-root form), extracted so the
//! channel-close, cancel-close, withdrawal-claim and post-close-claim circuits share ONE
//! definition of the H1 header — no drift. See `tasks/h1-poseidon-root-threat-model.md`.
//!
//! SECURITY: this MUST stay element-identical to the native
//! `common::balance_state::BalanceState::h1`. The header is the FIXED-width (26-element) Poseidon
//! preimage
//!
//!   `[BALANCE_STATE_DOMAIN, channel_id, member_count, delegate_count,
//!     slot_tree_root (4 Goldilocks elements), settled_tx_chain (8 u32 limbs),
//!     settled_tx_accumulator_root (8 u32 limbs), state_version (hi, lo u32 limbs)]`
//!
//! and the exposed H1 is the canonical `PoseidonHashOut → Bytes32` encoding of its hash
//! (`Bytes32Target::from_hash_out`, whose `safe_split_lo_and_hi` forbids the non-canonical
//! decomposition — exactly ONE Bytes32 encodes a given header hash). The per-slot data
//! (regev pk digest, ciphertext digest, pending adds) is NO LONGER hashed here: it is committed
//! by `slot_tree_root`, the height-`BALANCE_SLOT_TREE_HEIGHT` Poseidon Merkle root over the
//! `MAX_CHANNEL_MEMBERS` slot leaves ([`balance_slot_leaf_hash_circuit`]). Circuits that must
//! OPEN a slot (the claim circuits) prove a Merkle inclusion of that slot's leaf against the
//! root; circuits that only pin the signed scalars (close/cancel) witness the root directly —
//! it is attested by the cosigner signatures over H1.
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
    common::balance_state::{BALANCE_SLOT_LEAF_DOMAIN, BALANCE_STATE_DOMAIN},
    ethereum_types::{
        address::AddressTarget, bytes32::Bytes32Target, u32limb_trait::U32LimbTargetTrait as _,
        u64::U64Target,
    },
    utils::poseidon_hash_out::PoseidonHashOutTarget,
};

/// Recompute `BalanceState::h1()` in-circuit from the witnessed slot-tree root and the
/// PI/witness-bound scalars.
///
/// Inputs (all caller-allocated; the u32 limbs 32-bit range-checked by the callers):
/// - `channel_id`: the single base-identity u32 limb.
/// - `member_count`, `delegate_count`: single u32 limbs (the active/padding split).
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
pub(crate) fn recompute_h1<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    channel_id: Target,
    member_count: Target,
    delegate_count: Target,
    slot_tree_root: PoseidonHashOutTarget,
    settled_tx_chain: &Bytes32Target,
    settled_tx_accumulator_root: &Bytes32Target,
    state_version: &U64Target,
) -> Bytes32Target
where
    F: RichField + Extendable<D>,
{
    let balance_state_domain = builder.constant(F::from_canonical_u32(BALANCE_STATE_DOMAIN));
    let h1_inputs = [
        vec![
            balance_state_domain,
            channel_id,
            member_count,
            delegate_count,
        ],
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

/// In-circuit twin of `common::balance_state::balance_slot_leaf_hash`: the per-slot leaf of the
/// H1 balance-slot tree,
/// `Poseidon([BALANCE_SLOT_LEAF_DOMAIN, regev_pk_digest (8), enc_balance_digest (8),
/// pending_adds (1), recipient (5)])` — FIXED 23-element width, injective on the slot quadruple.
///
/// The claim circuits hash the slot they open with this gadget and verify a height-
/// `BALANCE_SLOT_TREE_HEIGHT` `IncrementalMerkleProofTarget<PoseidonHashOutTarget>` inclusion of
/// the result (leaf value = leaf hash; `LeafableTarget::hash` is the identity for
/// `PoseidonHashOutTarget`) against the `slot_tree_root` fed to [`recompute_h1`].
///
/// SECURITY (B-1b): `recipient` is the slot's cosigner-signed L1 exit address (5 u32 limbs; the
/// claim circuits pass their range-checked `recipient` PI `AddressTarget` here, which CONNECTS
/// the leaf-opened recipient to the claim's exposed recipient — the payout-redirection defense
/// for delegates, which have no L1 registration under Option B).
pub(crate) fn balance_slot_leaf_hash_circuit<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    regev_pk_digest: &Bytes32Target,
    enc_balance_digest: &Bytes32Target,
    pending_adds: Target,
    recipient: &AddressTarget,
) -> PoseidonHashOutTarget
where
    F: RichField + Extendable<D>,
{
    let leaf_domain = builder.constant(F::from_canonical_u32(BALANCE_SLOT_LEAF_DOMAIN));
    let leaf_inputs = [
        vec![leaf_domain],
        regev_pk_digest.to_vec(),
        enc_balance_digest.to_vec(),
        vec![pending_adds],
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
            balance_state::{BalanceState, balance_slot_leaf_hash},
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

    /// The soundness anchor for the Poseidon-root H1: for a RANDOM `BalanceState` (random
    /// regev pk digests, ciphertexts, adds, scalars), the native `BalanceState::h1()` MUST equal
    /// the in-circuit `recompute_h1` over the natively computed `slot_tree_root()`, AND the
    /// in-circuit leaf gadget must equal the native `balance_slot_leaf_hash` for every active
    /// slot. If the native and circuit header/leaf encodings ever drift, every signed H1 PI
    /// would disagree with any provable close/cancel/claim proof — this catches encoding/order
    /// drift before it ships.
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
        let slot_tree_root_t = PoseidonHashOutTarget::new(&mut builder);
        let settled_tx_chain_t = Bytes32Target::new(&mut builder, true);
        let settled_tx_accumulator_root_t = Bytes32Target::new(&mut builder, true);
        let state_version_t = U64Target::new(&mut builder, true);
        let recomputed = recompute_h1::<F, D>(
            &mut builder,
            channel_id_t,
            member_count_t,
            delegate_count_t,
            slot_tree_root_t,
            &settled_tx_chain_t,
            &settled_tx_accumulator_root_t,
            &state_version_t,
        );
        // Leaf gadget twin: leaf over witnessed slot data (B-1b: recipient limbs range-checked,
        // exactly as the claim circuits' recipient PI is).
        let leaf_pk_t = Bytes32Target::new(&mut builder, true);
        let leaf_enc_t = Bytes32Target::new(&mut builder, true);
        let leaf_adds_t = u32_limb(&mut builder);
        let leaf_recipient_t = AddressTarget::new(&mut builder, true);
        let leaf_t = balance_slot_leaf_hash_circuit::<F, D>(
            &mut builder,
            &leaf_pk_t,
            &leaf_enc_t,
            leaf_adds_t,
            &leaf_recipient_t,
        );
        builder.register_public_inputs(&recomputed.to_vec());
        builder.register_public_inputs(&leaf_t.to_vec());
        let data = builder.build::<C>();

        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            // member_count over the FULL cosigner range 2..=MAX_COSIGNERS; delegate_count 0..=16.
            // The padding suffix exercises the memoized padding leaf. pending_adds over the full
            // VALID budget 0..=MAX_HOMO_ADDS_BEFORE_REFRESH (validate() rejects larger); the leaf
            // encoding is a single limb so the budget max exercises the whole live range.
            // channel_id over the full u32 range.
            let member_count = rng.gen_range(2usize..=crate::constants::MAX_COSIGNERS);
            let delegate_count = rng.gen_range(0usize..=16);
            let active = member_count + delegate_count;
            let enc_active: Vec<RegevCiphertext> =
                (0..active).map(|_| rand_ciphertext(&mut rng)).collect();
            let pk_active: Vec<Bytes32> = (0..active).map(|_| Bytes32::rand(&mut rng)).collect();
            let adds_active: Vec<u32> = (0..active)
                .map(|_| rng.gen_range(0..=crate::regev::MAX_HOMO_ADDS_BEFORE_REFRESH))
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
            };
            state.validate().expect("constructed state must be valid");
            let expected = state.h1();
            let root = state.slot_tree_root();
            // Alternate between an ACTIVE slot (random nonzero recipient) and a PADDING slot
            // (zero recipient, padding ciphertext) so the circuit leaf gadget is exercised on
            // BOTH leaf forms of the widened 23-element encoding.
            let slot = if rng.r#gen::<bool>() {
                rng.gen_range(0..active)
            } else {
                MAX_CHANNEL_MEMBERS - 1 // always padding: active <= MAX_COSIGNERS + 16 < 1023
            };
            let expected_leaf = balance_slot_leaf_hash(
                state.regev_pk_digests[slot],
                state.enc_balances[slot].digest(),
                state.pending_adds[slot],
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
            pw.set_target(delegate_count_t, F::from_canonical_u16(state.delegate_count))
                .unwrap();
            slot_tree_root_t.set_witness(&mut pw, root);
            settled_tx_chain_t.set_witness(&mut pw, state.settled_tx_chain);
            settled_tx_accumulator_root_t.set_witness(&mut pw, state.settled_tx_accumulator_root);
            state_version_t.set_witness(&mut pw, U64::from(state.state_version));
            leaf_pk_t.set_witness(&mut pw, state.regev_pk_digests[slot]);
            leaf_enc_t.set_witness(&mut pw, state.enc_balances[slot].digest());
            pw.set_target(leaf_adds_t, F::from_canonical_u32(state.pending_adds[slot]))
                .unwrap();
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
