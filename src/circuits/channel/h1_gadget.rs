//! Shared in-circuit `BalanceState::h1()` recompute (IMBS keccak), extracted so the channel-close
//! circuit (`close_circuit.rs`) and the withdrawal-claim circuit (`withdrawal_claim_circuit.rs`)
//! share ONE definition of the H1 preimage — no drift.
//!
//! SECURITY: this MUST stay byte-identical to the native `common::balance_state::BalanceState::h1`
//! and to the L1 mirror. The preimage limb order (pad-to-MAX D6 + delegate account + decryption
//! Stage 1) is:
//!   `[BALANCE_STATE_DOMAIN, channel_id, member_count, delegate_count,
//!     p_0 .. p_{MAX-1}, d_0 .. d_{MAX-1}, settled_tx_chain, settled_tx_accumulator_root,
//!     split_u64(state_version), pending_adds[0..MAX]]`
//! where `p_i = regev_pk_digests[i]` (8 u32 limbs) and `d_i = enc_balances[i].digest()`. The
//! Stage-3 `settled_tx_accumulator_root` (8 u32 limbs) sits IMMEDIATELY AFTER `settled_tx_chain`
//! and BEFORE `split_u64(state_version)`.
//! `delegate_count` is the single u32 limb IMMEDIATELY AFTER `member_count`; the Regev pk digests
//! `p_i` come IMMEDIATELY AFTER `delegate_count` and BEFORE the ciphertext digests `d_i`
//! (decryption Stage 1). The keccak gadget does NOT range-check its inputs, so every limb fed here
//! must be 32-bit range-checked by the caller (the PI allocators already do this).

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig},
};
use plonky2_keccak::builder::BuilderKeccak256 as _;

use crate::{
    common::balance_state::BALANCE_STATE_DOMAIN,
    ethereum_types::{
        bytes32::Bytes32Target, u32limb_trait::U32LimbTargetTrait as _, u64::U64Target,
    },
};

/// Recompute `BalanceState::h1()` in-circuit from the witnessed slot data and PI-bound scalars.
///
/// Inputs (all caller-allocated, all 32-bit range-checked):
/// - `channel_id`: the single base-identity u32 limb.
/// - `member_count`, `delegate_count`: single u32 limbs (the active/padding split).
/// - `regev_pk_digests`: exactly `MAX_CHANNEL_MEMBERS` per-slot Regev pk Poseidon digests `p_i`
///   (encoded as `Bytes32Target` = 8 u32 limbs each), decryption Stage 1. Inserted IMMEDIATELY
///   AFTER `delegate_count` and BEFORE the ciphertext digests, mirroring the native order.
/// - `enc_balance_digests`: exactly `MAX_CHANNEL_MEMBERS` per-slot ciphertext digests `d_i`.
/// - `settled_tx_chain`: the settle hash-chain Bytes32.
/// - `settled_tx_accumulator_root`: the Stage-3 settled-tx accumulator root Bytes32. Inserted
///   IMMEDIATELY AFTER `settled_tx_chain` and BEFORE `state_version`, mirroring the native order.
/// - `state_version`: the monotone state counter (split into 2 u32 limbs by `U64Target`).
/// - `pending_adds`: exactly `MAX_CHANNEL_MEMBERS` per-slot homomorphic-add counters.
///
/// Returns the recomputed H1 as a `Bytes32Target`. The caller `connect`s it to the H1 PI.
pub(crate) fn recompute_h1<F, C, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    channel_id: Target,
    member_count: Target,
    delegate_count: Target,
    regev_pk_digests: &[Bytes32Target],
    enc_balance_digests: &[Bytes32Target],
    settled_tx_chain: &Bytes32Target,
    settled_tx_accumulator_root: &Bytes32Target,
    state_version: &U64Target,
    pending_adds: &[Target],
) -> Bytes32Target
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
{
    let balance_state_domain = builder.constant(F::from_canonical_u32(BALANCE_STATE_DOMAIN));
    let h1_inputs = [
        vec![balance_state_domain],
        vec![channel_id],
        vec![member_count],
        vec![delegate_count],
        // Decryption Stage 1: the per-slot Regev pk digests come IMMEDIATELY AFTER delegate_count
        // and BEFORE the ciphertext digests, byte-identical to native `BalanceState::h1`.
        regev_pk_digests
            .iter()
            .flat_map(Bytes32Target::to_vec)
            .collect::<Vec<_>>(),
        enc_balance_digests
            .iter()
            .flat_map(Bytes32Target::to_vec)
            .collect::<Vec<_>>(),
        settled_tx_chain.to_vec(),
        // Stage 3: the accumulator root sits IMMEDIATELY AFTER settled_tx_chain and BEFORE
        // state_version, byte-identical to native `BalanceState::h1`.
        settled_tx_accumulator_root.to_vec(),
        state_version.to_vec(),
        pending_adds.to_vec(),
    ]
    .concat();
    Bytes32Target::from_slice(&builder.keccak256::<C>(&h1_inputs))
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field as _, PrimeField64},
        },
        iop::witness::{PartialWitness, WitnessWrite as _},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    use super::*;
    use crate::{
        common::{balance_state::BalanceState, channel::ChannelId},
        constants::MAX_CHANNEL_MEMBERS,
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u64::U64},
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

    /// Decryption Stage 1 — the soundness anchor for the per-slot Regev pk digest commitment: for a
    /// RANDOM `BalanceState` (random `regev_pk_digests`, random ciphertexts, random scalars), the
    /// native `BalanceState::h1()` MUST equal the in-circuit `recompute_h1` over the same witnessed
    /// slot data. If the native and circuit preimage orders (or the
    /// `Bytes32::from(poseidon_digest)` → 8-u32-limb encoding) ever drift, every signed H1 PI
    /// would disagree with any provable close/withdrawal proof — so this catches encoding/order
    /// drift before it ships.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn recompute_h1_matches_native_balance_state_h1_randomized() {
        use plonky2::plonk::circuit_builder::CircuitBuilder;

        // Build a tiny circuit: witness all H1 inputs, recompute H1, register it as the PI.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        let channel_id_t = u32_limb(&mut builder);
        let member_count_t = u32_limb(&mut builder);
        let delegate_count_t = u32_limb(&mut builder);
        let regev_pk_digest_ts: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let enc_digest_ts: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let settled_tx_chain_t = Bytes32Target::new(&mut builder, true);
        let settled_tx_accumulator_root_t = Bytes32Target::new(&mut builder, true);
        let state_version_t = U64Target::new(&mut builder, true);
        let pending_add_ts: Vec<Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| u32_limb(&mut builder))
            .collect();
        let recomputed = recompute_h1::<F, C, D>(
            &mut builder,
            channel_id_t,
            member_count_t,
            delegate_count_t,
            &regev_pk_digest_ts,
            &enc_digest_ts,
            &settled_tx_chain_t,
            &settled_tx_accumulator_root_t,
            &state_version_t,
            &pending_add_ts,
        );
        builder.register_public_inputs(&recomputed.to_vec());
        let data = builder.build::<C>();

        let mut rng = rand::thread_rng();
        for _ in 0..3 {
            // member_count in 2..=MAX, delegate_count in 0..=(MAX-member_count). Active prefix
            // (members + delegates) carries random ciphertexts + random pk digests; padding slots
            // use the canonical padding values (so the state is a `validate()`-legal one).
            let member_count = rng.gen_range(2..=MAX_CHANNEL_MEMBERS);
            let delegate_count = rng.gen_range(0..=(MAX_CHANNEL_MEMBERS - member_count));
            let active = member_count + delegate_count;
            let enc_active: Vec<RegevCiphertext> =
                (0..active).map(|_| rand_ciphertext(&mut rng)).collect();
            let pk_active: Vec<Bytes32> = (0..active).map(|_| Bytes32::rand(&mut rng)).collect();
            let adds_active: Vec<u32> = (0..active).map(|_| rng.gen_range(0..4)).collect();
            let state = BalanceState {
                channel_id: ChannelId::new(rng.gen_range(1..1_000)).unwrap(),
                member_count: member_count as u8,
                delegate_count: delegate_count as u8,
                enc_balances: BalanceState::pad_enc_balances(&enc_active),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&pk_active),
                settled_tx_chain: Bytes32::rand(&mut rng),
                settled_tx_accumulator_root: Bytes32::rand(&mut rng),
                state_version: rng.r#gen(),
                pending_adds: BalanceState::pad_pending_adds(&adds_active),
            };
            state.validate().expect("constructed state must be valid");
            let expected = state.h1();

            let mut pw = PartialWitness::<F>::new();
            pw.set_target(
                channel_id_t,
                F::from_canonical_u32(state.channel_id.to_u32_vec()[0]),
            )
            .unwrap();
            pw.set_target(member_count_t, F::from_canonical_u8(state.member_count))
                .unwrap();
            pw.set_target(delegate_count_t, F::from_canonical_u8(state.delegate_count))
                .unwrap();
            for (t, d) in regev_pk_digest_ts.iter().zip(state.regev_pk_digests.iter()) {
                t.set_witness(&mut pw, *d);
            }
            for (t, ct) in enc_digest_ts.iter().zip(state.enc_balances.iter()) {
                t.set_witness(&mut pw, ct.digest());
            }
            settled_tx_chain_t.set_witness(&mut pw, state.settled_tx_chain);
            settled_tx_accumulator_root_t.set_witness(&mut pw, state.settled_tx_accumulator_root);
            state_version_t.set_witness(&mut pw, U64::from(state.state_version));
            for (t, &a) in pending_add_ts.iter().zip(state.pending_adds.iter()) {
                pw.set_target(*t, F::from_canonical_u32(a)).unwrap();
            }

            let proof = data.prove(pw).expect("h1 recompute proof");
            data.verify(proof.clone()).expect("h1 recompute verify");

            let actual_limbs = proof
                .public_inputs
                .iter()
                .map(|x| u32::try_from(x.to_canonical_u64()).expect("PI limb must be u32"))
                .collect::<Vec<_>>();
            let actual = Bytes32::from_u32_slice(&actual_limbs).unwrap();
            assert_eq!(
                actual, expected,
                "in-circuit recompute_h1 must equal native BalanceState::h1 (Stage 1 encoding/order)"
            );
        }
    }
}
