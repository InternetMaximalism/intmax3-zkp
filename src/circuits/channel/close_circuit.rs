//! P7 (detail2 §F-3, decision D4): the FULL channel-close circuit.
//!
//! For a unanimous close the circuit proves, in one statement, that the L1-facing close public
//! inputs (the 77-limb `closePIHash` preimage pinned by `ChannelSettlementVerifier.sol`) are
//! consistent with:
//!
//! 1. the recomputed `BalanceState.h1()` (IMBS keccak) — anchoring `final_settled_tx_chain` and
//!    `final_state_version` as the UNIQUE values inside the signed H1 preimage;
//! 2. the recomputed `ChannelState::signing_digest()` (IMCH keccak, h1 in the balance-root slot,
//!    h2_tag + state_version appended) and the IMCL / IMCI digests derived from it;
//! 3. a recursively verified final BALANCE proof whose `settled_tx_chain` and `channel_id` public
//!    inputs equal the close PIs (detail2 §H-2 chain binding);
//! 4. three member SPHINCS+ signatures over the recomputed `final_channel_state_digest` (all-member
//!    unanimity; no threshold relaxation).

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::builder::BuilderKeccak256 as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::{
        balance::balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalancePublicInputsTarget},
        channel::close_pis::{
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs, ChannelCloseWitness,
            ChannelCloseWitnessError,
        },
    },
    common::{balance_state::BALANCE_STATE_DOMAIN, channel::close_member_set_commitment},
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::{U64, U64Target},
        u256::{U256_LEN, U256Target},
    },
    poseidon_sig::list::{chain_step_target, leaf_target},
    utils::{
        conversion::ToU64 as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify, add_proof_target_and_verify_cyclic,
        },
    },
};

const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348;
const CLOSE_TX_DOMAIN: u32 = 0x494d434c;
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349;
/// "IMCM" — domain separator for the F5 member-set commitment. MUST equal
/// `common::channel::CLOSE_MEMBER_SET_DOMAIN` so the in-circuit keccak agrees with the native
/// `close_member_set_commitment` helper byte-for-byte.
const CLOSE_MEMBER_SET_DOMAIN: u32 = 0x494d434d;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelClosePublicInputsTarget {
    /// Single u32 limb — the unified channel-id-only base identity.
    pub channel_id: [Target; 1],
    pub close_nonce: U64Target,
    pub final_epoch: U64Target,
    pub final_small_block_number: U64Target,
    pub close_freeze_nonce: U64Target,
    pub final_channel_state_digest: Bytes32Target,
    pub final_balance_state_h1: Bytes32Target,
    pub channel_fund_amount: U256Target,
    pub channel_fund_intmax_state_root: Bytes32Target,
    pub burn_tx_hash: Bytes32Target,
    pub close_withdrawal_digest: Bytes32Target,
    pub close_intent_digest: Bytes32Target,
    pub snapshot_medium_block_number: U64Target,
    pub final_state_version: U64Target,
    pub final_settled_tx_chain: Bytes32Target,
    /// Stage 3 (post-close source-tx anchoring): the finalized settled-tx accumulator root,
    /// exposed as a dedicated close PI immediately after `final_settled_tx_chain` (the
    /// precedent sibling). L1 `finalizeClose` stores it; the post-close claim binds a Merkle
    /// inclusion of `incoming_tx_hash` against this value. It rides in the signed H1 (so it is
    /// attested) and is recomputed into the inline H1 below at the matching preimage position.
    pub final_settled_tx_accumulator_root: Bytes32Target,
    /// F5 binding: keccak commitment over the verified member SPHINCS+ pubkey hashes
    /// (`[IMCM, member_count, h_0..h_15]`, padding zeroed). Computed in-circuit from the signing
    /// keys and matched on L1 against the channel's registered member set.
    pub member_set_commitment: Bytes32Target,
    /// D6 (pad-to-MAX): number of ACTIVE members, range-checked `< MAX_CHANNEL_MEMBERS+1` and used
    /// to gate per-slot SPHINCS+ verification and the member_set_commitment select. Single limb.
    pub member_count: Target,
    /// Delegate account: number of DELEGATE participants. Single limb, appended at the END of the
    /// close PI vector (right after `member_count`). Anchored in-circuit ONLY into the H1
    /// recompute (immediately after `member_count` in the IMBS preimage); delegates do NOT
    /// enter the member_set_commitment (they do not co-sign).
    pub delegate_count: Target,
}

impl ChannelClosePublicInputsTarget {
    /// Allocates the PI targets. Every limb is range-checked to 32 bits: the limbs feed the
    /// IMBS/IMCH/IMCL/IMCI keccak preimages and the keccak gadget does NOT range-check its
    /// inputs (see `plonky2_keccak::builder` NOTICE), so the checks here are load-bearing for
    /// the digest constraints below.
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        Self {
            channel_id: [u32_limb(builder)],
            close_nonce: U64Target::new(builder, true),
            final_epoch: U64Target::new(builder, true),
            final_small_block_number: U64Target::new(builder, true),
            close_freeze_nonce: U64Target::new(builder, true),
            final_channel_state_digest: Bytes32Target::new(builder, true),
            final_balance_state_h1: Bytes32Target::new(builder, true),
            channel_fund_amount: U256Target::new(builder, true),
            channel_fund_intmax_state_root: Bytes32Target::new(builder, true),
            burn_tx_hash: Bytes32Target::new(builder, true),
            close_withdrawal_digest: Bytes32Target::new(builder, true),
            close_intent_digest: Bytes32Target::new(builder, true),
            snapshot_medium_block_number: U64Target::new(builder, true),
            final_state_version: U64Target::new(builder, true),
            final_settled_tx_chain: Bytes32Target::new(builder, true),
            final_settled_tx_accumulator_root: Bytes32Target::new(builder, true),
            member_set_commitment: Bytes32Target::new(builder, true),
            member_count: u32_limb(builder),
            delegate_count: u32_limb(builder),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let v = [
            self.channel_id.to_vec(),
            self.close_nonce.to_vec(),
            self.final_epoch.to_vec(),
            self.final_small_block_number.to_vec(),
            self.close_freeze_nonce.to_vec(),
            self.final_channel_state_digest.to_vec(),
            self.final_balance_state_h1.to_vec(),
            self.channel_fund_amount.to_vec(),
            self.channel_fund_intmax_state_root.to_vec(),
            self.burn_tx_hash.to_vec(),
            self.close_withdrawal_digest.to_vec(),
            self.close_intent_digest.to_vec(),
            self.snapshot_medium_block_number.to_vec(),
            self.final_state_version.to_vec(),
            self.final_settled_tx_chain.to_vec(),
            self.final_settled_tx_accumulator_root.to_vec(),
            self.member_set_commitment.to_vec(),
            vec![self.member_count],
            vec![self.delegate_count],
        ]
        .concat();
        debug_assert_eq!(v.len(), CHANNEL_CLOSE_PUBLIC_INPUTS_LEN);
        v
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(values.len(), CHANNEL_CLOSE_PUBLIC_INPUTS_LEN);
        let mut cursor = 0;
        let channel_id = [values[cursor]];
        cursor += 1;
        let close_nonce = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_epoch = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_small_block_number = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let close_freeze_nonce = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_channel_state_digest =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let final_balance_state_h1 =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let channel_fund_amount = U256Target::from_slice(&values[cursor..cursor + U256_LEN]);
        cursor += U256_LEN;
        let channel_fund_intmax_state_root =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let burn_tx_hash = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let close_withdrawal_digest =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let close_intent_digest = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let snapshot_medium_block_number = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_state_version = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_settled_tx_chain =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let final_settled_tx_accumulator_root =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let member_set_commitment =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let member_count = values[cursor];
        cursor += 1;
        let delegate_count = values[cursor];
        Self {
            channel_id,
            close_nonce,
            final_epoch,
            final_small_block_number,
            close_freeze_nonce,
            final_channel_state_digest,
            final_balance_state_h1,
            channel_fund_amount,
            channel_fund_intmax_state_root,
            burn_tx_hash,
            close_withdrawal_digest,
            close_intent_digest,
            snapshot_medium_block_number,
            final_state_version,
            final_settled_tx_chain,
            final_settled_tx_accumulator_root,
            member_set_commitment,
            member_count,
            delegate_count,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ChannelClosePublicInputs,
    ) {
        witness
            .set_target(
                self.channel_id[0],
                F::from_canonical_u64(value.channel_id.to_u64_vec()[0]),
            )
            .unwrap();
        self.close_nonce
            .set_witness(witness, U64::from(value.close_nonce));
        self.final_epoch
            .set_witness(witness, U64::from(value.final_epoch));
        self.final_small_block_number
            .set_witness(witness, U64::from(value.final_small_block_number));
        self.close_freeze_nonce
            .set_witness(witness, U64::from(value.close_freeze_nonce));
        self.final_channel_state_digest
            .set_witness(witness, value.final_channel_state_digest);
        self.final_balance_state_h1
            .set_witness(witness, value.final_balance_state_h1);
        self.channel_fund_amount
            .set_witness(witness, value.channel_fund_amount);
        self.channel_fund_intmax_state_root
            .set_witness(witness, value.channel_fund_intmax_state_root);
        self.burn_tx_hash.set_witness(witness, value.burn_tx_hash);
        self.close_withdrawal_digest
            .set_witness(witness, value.close_withdrawal_digest);
        self.close_intent_digest
            .set_witness(witness, value.close_intent_digest);
        self.snapshot_medium_block_number
            .set_witness(witness, U64::from(value.snapshot_medium_block_number));
        self.final_state_version
            .set_witness(witness, U64::from(value.final_state_version));
        self.final_settled_tx_chain
            .set_witness(witness, value.final_settled_tx_chain);
        self.final_settled_tx_accumulator_root
            .set_witness(witness, value.final_settled_tx_accumulator_root);
        self.member_set_commitment
            .set_witness(witness, value.member_set_commitment);
        witness
            .set_target(self.member_count, F::from_canonical_u8(value.member_count))
            .unwrap();
        witness
            .set_target(
                self.delegate_count,
                F::from_canonical_u8(value.delegate_count),
            )
            .unwrap();
    }
}

#[derive(Debug, Error)]
pub enum ChannelCloseCircuitError {
    #[error("witness error: {0}")]
    Witness(#[from] ChannelCloseWitnessError),
    #[error("invalid member auth: {0}")]
    InvalidMemberAuth(String),
    #[error("balance proof binding mismatch: {0}")]
    BalanceBindingMismatch(String),
    #[error("failed to prove: {0}")]
    FailedToProve(String),
}

/// Per-member authentication material for the close statement (P2b).
///
/// SECURITY (F5 binding): the close circuit commits each ACTIVE member's `pk_g` (slot order) into
/// `member_set_commitment = keccak([IMCM, member_count, pk_g_0..pk_g_{MAX-1}])`, an exposed public
/// input. L1 (`ChannelSettlementManager`) matches this commitment against `keccak([IMCM, registered
/// member_pk_gs])` from the channel's `ChannelRecord`, so a prover cannot substitute non-member
/// keys. The signatures themselves are proven by the recursive `ListCircuit` proof (decision D3):
/// the close circuit rebuilds the SAME list commitment from `(IMCH_digest, pk_g_i)` over the active
/// slots and asserts it equals the verified list's commitment, so all N active members signed the
/// final IMCH digest (unanimous close; no threshold relaxation).
#[derive(Clone, Debug)]
pub struct MemberCloseAuth {
    /// The member's Goldilocks signing public key `pk_g` (`GoldilocksSecretKey::public_key()`),
    /// the registered member identity. Drives both the member_set_commitment and the C' rebuild.
    pub pk_g: Bytes32,
}

/// Full prover witness for [`ChannelCloseCircuit`]: the close data trio, the recursive balance
/// proof, the per-member `pk_g`s, and the recursive `ListCircuit` proof over the N member IMCH
/// single-sigs (D4: the close circuit verifies everything).
#[derive(Clone, Debug)]
pub struct ChannelCloseFullWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub close: ChannelCloseWitness,
    /// The member-signed final BALANCE proof (cyclic `BalanceCircuit` proof). Its
    /// `settled_tx_chain` / `channel_id` public inputs are constrained equal to the close PIs;
    /// its verifier data is pinned as circuit constants (see `ChannelCloseCircuit::new`).
    pub final_balance_proof: ProofWithPublicInputs<F, C, D>,
    /// Exactly `member_count` ACTIVE entries, one per active member slot (pad-to-MAX D6) — ALL
    /// active members sign the final channel state digest (unanimous close).
    pub member_auth: Vec<MemberCloseAuth>,
    /// The recursive `poseidon_sig::list::ListCircuit` proof over the N member single-sigs of the
    /// final IMCH digest (slot order). Its commitment `C` must equal the close circuit's rebuilt
    /// `C'` over `(IMCH_digest, pk_g_i)`.
    pub list_proof: ProofWithPublicInputs<F, C, D>,
}

/// Native mirror of the in-circuit member-set commitment: take each ACTIVE member's `pk_g` (slot
/// order), pad to MAX_CHANNEL_MEMBERS (padding = `Bytes32::default()`), and keccak `[IMCM,
/// member_count, pk_g_0..pk_g_{MAX-1}]`. MUST agree byte-for-byte with the in-circuit keccak in
/// [`ChannelCloseCircuit::new`].
fn member_set_commitment_for_auth(member_auth: &[MemberCloseAuth]) -> Bytes32 {
    let hashes: [Bytes32; MAX_CHANNEL_MEMBERS] =
        std::array::from_fn(|i| member_auth.get(i).map(|a| a.pk_g).unwrap_or_default());
    close_member_set_commitment(&hashes, member_auth.len() as u8)
}

pub struct ChannelCloseCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub public_inputs: ChannelClosePublicInputsTarget,
    final_state_close_freeze_nonce: U64Target,
    final_state_shared_native_nullifier_root: Bytes32Target,
    final_state_unallocated_confirmed_incoming: U256Target,
    final_state_prev_digest: Bytes32Target,
    final_state_h2_tag: Bytes32Target,
    /// Per-member Regev balance ciphertext digests `d_i = enc_balances[i].digest()` — the H1
    /// preimage body (detail2 §C-2).
    enc_balance_digests: Vec<Bytes32Target>,
    /// Decryption Stage 1: per-slot Regev pk Poseidon digests (H1 preimage, between delegate_count
    /// and the ciphertext digests).
    regev_pk_digests: Vec<Bytes32Target>,
    /// Per-member homomorphic-add counters (D3), 32-bit range-checked.
    pending_adds: Vec<Target>,
    /// The recursively verified final balance proof.
    final_balance_proof: ProofWithPublicInputsTarget<D>,
    /// The recursively verified `ListCircuit` proof over the N member IMCH single-sigs (P2b D3).
    list_proof: ProofWithPublicInputsTarget<D>,
    /// Per-slot member `pk_g` targets (length MAX_CHANNEL_MEMBERS). Drive both the member_set
    /// commitment keccak and the C' rebuild; padding slots are forced to the registered-set zero.
    member_pk_g_targets: Vec<Bytes32Target>,
    /// D6 per-slot activeness flags `active_bits[i] = (i < member_count)`. Set from member_count
    /// in `fill_witness`.
    active_bits: Vec<plonky2::iop::target::BoolTarget>,
}

impl<F, C, const D: usize> ChannelCloseCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Builds the close circuit against a FIXED balance verifier key.
    ///
    /// SECURITY (VD binding): `balance_vd` is baked into this circuit as constants
    /// (`constant_verifier_data` inside `add_proof_target_and_verify_cyclic`), and the verifier
    /// data EMBEDDED in the balance proof's own public inputs (the cyclic-IVC self-reference) is
    /// additionally connected to those constants. A prover therefore cannot substitute a proof
    /// from any circuit other than the canonical `BalanceCircuit`, nor a cyclic proof whose
    /// inner self-reference points elsewhere. This is the strongest binding pattern available
    /// in-repo (`utils::recursively_verifiable::add_proof_target_and_verify_cyclic`).
    ///
    /// `list_vd` is the `poseidon_sig::list::ListCircuit` verifier data (baked in as a build-time
    /// constant, A7) — its proof carries the N member IMCH single-sigs (decision D3).
    pub fn new(
        balance_vd: &VerifierCircuitData<F, C, D>,
        list_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = ChannelClosePublicInputsTarget::new(&mut builder);
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        let final_state_close_freeze_nonce = U64Target::new(&mut builder, true);
        let final_state_shared_native_nullifier_root = Bytes32Target::new(&mut builder, true);
        let final_state_unallocated_confirmed_incoming = U256Target::new(&mut builder, true);
        let final_state_prev_digest = Bytes32Target::new(&mut builder, true);
        let final_state_h2_tag = Bytes32Target::new(&mut builder, true);
        let enc_balance_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        // Decryption Stage 1: per-slot Regev pk digests (range-checked like enc_balance_digests),
        // folded into H1 IMMEDIATELY AFTER delegate_count (byte-identical to native h1).
        let regev_pk_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let pending_adds: Vec<Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| u32_limb(&mut builder))
            .collect();

        // D6: per-slot activeness flags `slot_is_active[i] = (i < member_count)`. Built from a
        // unary decomposition: `member_count = Σ_i active_bits[i]` with each bit Boolean and the
        // sequence monotonically non-increasing (1*…1*0*…). This forces `active_bits[i] = (i <
        // member_count)` for member_count in 0..=MAX_CHANNEL_MEMBERS. These flags gate the
        // per-slot SPHINCS+ verification and the member_set_commitment select below.
        let mut active_bits: Vec<plonky2::iop::target::BoolTarget> =
            Vec::with_capacity(MAX_CHANNEL_MEMBERS);
        for _ in 0..MAX_CHANNEL_MEMBERS {
            active_bits.push(builder.add_virtual_bool_target_safe());
        }
        // Monotonicity: active_bits[i+1] => active_bits[i] (no active slot after a padding slot).
        // Equivalent to active_bits[i] >= active_bits[i+1], i.e.
        // active_bits[i+1]*(1-active_bits[i]) == 0.
        let one = builder.one();
        let zero_t = builder.zero();
        for i in 0..MAX_CHANNEL_MEMBERS - 1 {
            let one_minus_prev = builder.sub(one, active_bits[i].target);
            let prod = builder.mul(active_bits[i + 1].target, one_minus_prev);
            builder.connect(prod, zero_t);
        }
        // member_count == Σ active_bits (binds the witnessed flags to the PI limb).
        let mut count_sum = builder.zero();
        for bit in &active_bits {
            count_sum = builder.add(count_sum, bit.target);
        }
        builder.connect(count_sum, public_inputs.member_count);

        let one = U64Target::constant(&mut builder, U64::from(1u64));
        let incremented_close_freeze_nonce = final_state_close_freeze_nonce.add(&mut builder, &one);
        incremented_close_freeze_nonce.connect(&mut builder, public_inputs.close_freeze_nonce);

        let zero = builder.zero();
        for limb in final_state_unallocated_confirmed_incoming.to_vec() {
            builder.connect(limb, zero);
        }

        let balance_state_domain = builder.constant(F::from_canonical_u32(BALANCE_STATE_DOMAIN));
        let channel_state_domain = builder.constant(F::from_canonical_u32(CHANNEL_STATE_DOMAIN));
        let close_tx_domain = builder.constant(F::from_canonical_u32(CLOSE_TX_DOMAIN));
        let close_intent_domain = builder.constant(F::from_canonical_u32(CLOSE_INTENT_DOMAIN));

        // ── (b) H1 in-circuit recompute (IMBS, detail2 §C-2 + D3) ──────────
        //
        // SECURITY: this anchors `final_settled_tx_chain`, `final_state_version`, `member_count`
        // AND `delegate_count` as the unique values inside the signed H1 — the same PI
        // targets feed the H1 preimage, the IMCH/IMCI tails AND the balance-proof equality
        // below, so no two of those bindings can diverge. Preimage limb order matches
        // `BalanceState::h1()` exactly (pad-to-MAX D6 + delegate account + decryption Stage 1 +
        // Stage 3): [IMBS, channel_id, member_count, delegate_count, p_0..p_{MAX-1},
        //  d_0..d_{MAX-1}, settled_tx_chain, settled_tx_accumulator_root, split_u64(state_version),
        //  pending_adds[0..MAX]]. `delegate_count` is the single u32 limb IMMEDIATELY AFTER
        // `member_count`; the Stage-3 `settled_tx_accumulator_root` is the 8 u32 limbs IMMEDIATELY
        // AFTER `settled_tx_chain` — byte-identical to the off-chain `BalanceState::h1`.
        let h1_inputs = [
            vec![balance_state_domain],
            public_inputs.channel_id.to_vec(),
            vec![public_inputs.member_count],
            vec![public_inputs.delegate_count],
            // Decryption Stage 1: Regev pk digests IMMEDIATELY AFTER delegate_count, BEFORE the
            // ciphertext digests (byte-identical to native `BalanceState::h1`).
            regev_pk_digests
                .iter()
                .flat_map(Bytes32Target::to_vec)
                .collect::<Vec<_>>(),
            enc_balance_digests
                .iter()
                .flat_map(Bytes32Target::to_vec)
                .collect::<Vec<_>>(),
            public_inputs.final_settled_tx_chain.to_vec(),
            // Stage 3: the accumulator root sits IMMEDIATELY AFTER settled_tx_chain and BEFORE
            // state_version, byte-identical to native `BalanceState::h1` and `h1_gadget`.
            public_inputs.final_settled_tx_accumulator_root.to_vec(),
            public_inputs.final_state_version.to_vec(),
            pending_adds.clone(),
        ]
        .concat();
        let recomputed_h1 = Bytes32Target::from_slice(&builder.keccak256::<C>(&h1_inputs));
        recomputed_h1.connect(&mut builder, public_inputs.final_balance_state_h1);

        // ── (c) IMCH recompute (`ChannelState::signing_digest()`) ───────────
        //
        // The legacy balance-root slot carries the RECOMPUTED h1 (same wire as the
        // `final_balance_state_h1` PI after the connection above); the v2 tail appends
        // h2_tag + split_u64(state_version) (detail2 §C-3).
        let state_digest_inputs = [
            vec![channel_state_domain],
            public_inputs.channel_id.to_vec(),
            public_inputs.final_epoch.to_vec(),
            public_inputs.final_small_block_number.to_vec(),
            final_state_close_freeze_nonce.to_vec(),
            public_inputs.channel_id.to_vec(),
            public_inputs.channel_fund_amount.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            recomputed_h1.to_vec(),
            final_state_shared_native_nullifier_root.to_vec(),
            final_state_unallocated_confirmed_incoming.to_vec(),
            final_state_prev_digest.to_vec(),
            final_state_h2_tag.to_vec(),
            public_inputs.final_state_version.to_vec(),
        ]
        .concat();
        let state_digest = Bytes32Target::from_slice(&builder.keccak256::<C>(&state_digest_inputs));
        state_digest.connect(&mut builder, public_inputs.final_channel_state_digest);

        let close_withdrawal_inputs = [
            vec![close_tx_domain],
            public_inputs.channel_id.to_vec(),
            public_inputs.final_channel_state_digest.to_vec(),
            public_inputs.final_balance_state_h1.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            public_inputs.burn_tx_hash.to_vec(),
            public_inputs.channel_fund_amount.to_vec(),
        ]
        .concat();
        let close_withdrawal_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_withdrawal_inputs));
        close_withdrawal_digest.connect(&mut builder, public_inputs.close_withdrawal_digest);

        // ── (d) IMCI recompute (`CloseIntent::signing_digest()`) ────────────
        //
        // The v2 tail appends `final_state_version` + `final_settled_tx_chain` (detail2 §C-8) —
        // the SAME PI targets that were hashed into H1 above, so the IMCI values are
        // constrained equal to the H1-anchored ones by construction. Byte-identical to the Rust
        // IMCI preimage (and hence to Solidity `computeCloseIntentDigest`, shared test vector in
        // `common::channel::tests`).
        let close_intent_inputs = [
            vec![close_intent_domain],
            public_inputs.channel_id.to_vec(),
            public_inputs.close_nonce.to_vec(),
            public_inputs.final_epoch.to_vec(),
            public_inputs.final_small_block_number.to_vec(),
            public_inputs.close_freeze_nonce.to_vec(),
            public_inputs.final_channel_state_digest.to_vec(),
            public_inputs.final_balance_state_h1.to_vec(),
            public_inputs.channel_id.to_vec(),
            public_inputs.channel_fund_amount.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            public_inputs.burn_tx_hash.to_vec(),
            public_inputs.close_withdrawal_digest.to_vec(),
            public_inputs.snapshot_medium_block_number.to_vec(),
            public_inputs.final_state_version.to_vec(),
            public_inputs.final_settled_tx_chain.to_vec(),
        ]
        .concat();
        let close_intent_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_intent_inputs));
        close_intent_digest.connect(&mut builder, public_inputs.close_intent_digest);

        // ── (e) Recursive final balance proof verification (detail2 §H-2) ──
        let final_balance_proof = add_proof_target_and_verify_cyclic(balance_vd, &mut builder);
        let balance_pis = BalancePublicInputsTarget::from_pis(
            &final_balance_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN],
        );
        // The settle history the members signed (H1-anchored chain PI) must be EXACTLY the
        // settle history the balance proof absorbed, for THIS channel.
        builder.connect(balance_pis.channel_id.value, public_inputs.channel_id[0]);
        balance_pis
            .settled_tx_chain
            .connect(&mut builder, public_inputs.final_settled_tx_chain);

        // ── (f) N-member IMCH signatures via the recursive ListCircuit proof (P2b D3, pad-to-MAX)
        // ─
        //
        // Message = the 8 u32 limbs of the RECOMPUTED `final_channel_state_digest` (IMCH). All N
        // active members sign it (unanimous close; no threshold relaxation). Instead of inline
        // per-slot signature verification, we recursively verify ONE `ListCircuit` proof and
        // rebuild the SAME order-sensitive Poseidon list commitment from `(IMCH_digest,
        // pk_g_i)` over the ACTIVE slots only (select prev on padding, mirroring the
        // member_set_commitment gating).
        //
        // SECURITY:
        //  - The list proof's commitment `C` (its public output [0..8]) is asserted equal to the
        //    rebuilt `C'`, so each active member's `(IMCH_digest, pk_g_i)` pair was backed by a
        //    verified Poseidon single-sig (A8: all-required-members-present, exact count/order).
        //  - pk_g distinctness over the active set forbids one key faking N signatures (A5).
        //  - member_set_commitment = keccak([IMCM, member_count, pk_g_0..pk_g_{MAX-1}]) (padding
        //    zeroed) is exposed and matched on L1 against the registered member set, so the
        //    verified keys cannot be substituted with non-member keys. Byte-identical to the native
        //    `common::channel::close_member_set_commitment`.
        //  - The IMCH digest message domain (IMCH keccak) differs from the validity IMSB digest, so
        //    an IMSB list entry cannot satisfy this close predicate and vice versa (A4).
        let close_member_set_domain =
            builder.constant(F::from_canonical_u32(CLOSE_MEMBER_SET_DOMAIN));
        let mut member_set_inputs: Vec<Target> =
            vec![close_member_set_domain, public_inputs.member_count];

        // Per-slot member pk_g targets (range-checked). Padding slots are not used in C' (select
        // prev) and are forced to zero in the keccak preimage.
        let member_pk_g_targets: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();

        // member_set_commitment preimage: each slot's pk_g, zeroed on padding.
        for (i, is_active) in active_bits.iter().enumerate() {
            for &limb in &member_pk_g_targets[i].to_vec() {
                let selected = builder.select(*is_active, limb, zero_t);
                member_set_inputs.push(selected);
            }
        }

        // Recursively verify the ListCircuit proof (constant VD, A7). A close always has >= 2
        // active members, so the commitment is never the empty (zero) list — verify
        // unconditionally. We pass a Boolean `_true` so
        // `add_proof_target_and_conditionally_verify` is exercised uniformly with the
        // validity path.
        let always = builder._true();
        let list_proof = add_proof_target_and_conditionally_verify(list_vd, &mut builder, always);
        let committed_c = Bytes32Target::from_slice(&list_proof.public_inputs[0..BYTES32_LEN]);

        // Rebuild C' = fold (state_digest, pk_g_i) over ACTIVE slots only (select prev on padding),
        // using the SHARED poseidon_sig::list gadgets so it matches the producer bit-for-bit.
        let mut chain = PoseidonHashOutTarget::constant(&mut builder, PoseidonHashOut::default());
        for (i, is_active) in active_bits.iter().enumerate() {
            let leaf = leaf_target(&mut builder, &state_digest, &member_pk_g_targets[i]);
            let stepped = chain_step_target(&mut builder, chain.clone(), leaf);
            // On padding slots keep the previous chain (only active members contribute, in order).
            chain = PoseidonHashOutTarget::select(&mut builder, *is_active, stepped, chain);
        }
        let rebuilt_c = Bytes32Target::from_hash_out(&mut builder, chain);
        rebuilt_c.connect(&mut builder, committed_c);

        // pk_g distinctness over the ACTIVE set (A5: one key cannot fake N signatures). Only
        // enforced for pairs where BOTH slots are active.
        for i in 0..MAX_CHANNEL_MEMBERS {
            for j in (i + 1)..MAX_CHANNEL_MEMBERS {
                let both_active = builder.and(active_bits[i], active_bits[j]);
                let eq = member_pk_g_targets[i].is_equal(&mut builder, &member_pk_g_targets[j]);
                let conflict = builder.and(both_active, eq);
                builder.assert_zero(conflict.target);
            }
        }

        let member_set_commitment =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&member_set_inputs));
        member_set_commitment.connect(&mut builder, public_inputs.member_set_commitment);

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            final_state_close_freeze_nonce,
            final_state_shared_native_nullifier_root,
            final_state_unallocated_confirmed_incoming,
            final_state_prev_digest,
            final_state_h2_tag,
            enc_balance_digests,
            regev_pk_digests,
            pending_adds,
            final_balance_proof,
            list_proof,
            member_pk_g_targets,
            active_bits,
        }
    }

    /// Fills the full partial witness for `public_inputs` + close witness data. Tests use this
    /// directly (bypassing the native mirrors in [`Self::prove`]) to exercise the in-circuit
    /// constraints against tampered public inputs.
    fn fill_witness(
        &self,
        public_inputs: &ChannelClosePublicInputs,
        witness_value: &ChannelCloseFullWitness<F, C, D>,
    ) -> Result<PartialWitness<F>, ChannelCloseCircuitError> {
        let state = &witness_value.close.final_channel_state;
        let member_count = state.balance_state.member_count as usize;
        if !(2..=MAX_CHANNEL_MEMBERS).contains(&member_count) {
            return Err(ChannelCloseCircuitError::InvalidMemberAuth(format!(
                "member_count {member_count} out of range (must be 2..={MAX_CHANNEL_MEMBERS})"
            )));
        }
        if witness_value.member_auth.len() != member_count {
            return Err(ChannelCloseCircuitError::InvalidMemberAuth(format!(
                "expected {member_count} active member signatures (member_count), got {}",
                witness_value.member_auth.len()
            )));
        }
        let mut witness = PartialWitness::<F>::new();
        // D6: set the per-slot activeness flags `active_bits[i] = (i < member_count)`.
        for (i, bit) in self.active_bits.iter().enumerate() {
            witness.set_bool_target(*bit, i < member_count).unwrap();
        }
        // NOTE: `public_inputs.member_set_commitment` is honored AS GIVEN here — the in-circuit
        // keccak (`ChannelCloseCircuit::new`) constrains it to equal keccak(recomputed pubkey
        // hashes), so a tampered commitment PI is rejected at proving. `Self::prove` fills the
        // correct value via `member_set_commitment_for_auth`; tests pass a wrong value to exercise
        // the rejection.
        self.public_inputs.set_witness(&mut witness, public_inputs);
        self.final_state_close_freeze_nonce
            .set_witness(&mut witness, U64::from(state.close_freeze_nonce));
        self.final_state_shared_native_nullifier_root
            .set_witness(&mut witness, state.shared_native_nullifier_root);
        self.final_state_unallocated_confirmed_incoming
            .set_witness(&mut witness, state.unallocated_confirmed_incoming);
        self.final_state_prev_digest
            .set_witness(&mut witness, state.prev_digest);
        self.final_state_h2_tag
            .set_witness(&mut witness, state.h2_tag);
        for (target, ciphertext) in self
            .enc_balance_digests
            .iter()
            .zip(state.balance_state.enc_balances.iter())
        {
            target.set_witness(&mut witness, ciphertext.digest());
        }
        // Decryption Stage 1: fill the per-slot Regev pk digests (same order as the H1 preimage).
        for (target, digest) in self
            .regev_pk_digests
            .iter()
            .zip(state.balance_state.regev_pk_digests.iter())
        {
            target.set_witness(&mut witness, *digest);
        }
        for (target, &adds) in self
            .pending_adds
            .iter()
            .zip(state.balance_state.pending_adds.iter())
        {
            witness
                .set_target(*target, F::from_canonical_u32(adds))
                .unwrap();
        }

        witness
            .set_proof_with_pis_target(
                &self.final_balance_proof,
                &witness_value.final_balance_proof,
            )
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))?;

        // P2b: the recursive ListCircuit proof over the N member IMCH single-sigs (D3).
        witness
            .set_proof_with_pis_target(&self.list_proof, &witness_value.list_proof)
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))?;

        // Per-slot member pk_g: ACTIVE slots get the member's registered pk_g; PADDING slots get
        // `Bytes32::default()` (zeroed in the keccak preimage and excluded from C' by the active
        // gating, so the value is inert).
        for (slot, pk_g_target) in self.member_pk_g_targets.iter().enumerate() {
            let pk_g = if slot < member_count {
                witness_value.member_auth[slot].pk_g
            } else {
                Bytes32::default()
            };
            pk_g_target.set_witness(&mut witness, pk_g);
        }
        Ok(witness)
    }

    pub fn prove(
        &self,
        witness_value: &ChannelCloseFullWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelCloseCircuitError> {
        let member_count = witness_value
            .close
            .final_channel_state
            .balance_state
            .member_count as usize;
        if witness_value.member_auth.len() != member_count {
            return Err(ChannelCloseCircuitError::InvalidMemberAuth(format!(
                "expected {member_count} active member signatures (member_count), got {}",
                witness_value.member_auth.len()
            )));
        }
        // F5: the exposed commitment binds the verified active signing keys (member_count + slot
        // order, padding zeroed); the in-circuit keccak constrains it, so this native value must
        // match the recomputed hashes.
        let mut public_inputs = witness_value.close.to_public_inputs()?;
        public_inputs.member_set_commitment =
            member_set_commitment_for_auth(&witness_value.member_auth);

        // Native mirrors of the in-circuit balance-binding constraints — same checks, earlier
        // and with structured errors (the circuit constraints remain authoritative).
        let balance_pis = crate::circuits::balance::balance_pis::BalancePublicInputs::from_u64(
            &witness_value.final_balance_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN]
                .to_u64_vec(),
        )
        .map_err(|e| ChannelCloseCircuitError::BalanceBindingMismatch(e.to_string()))?;
        if balance_pis.settled_tx_chain != public_inputs.final_settled_tx_chain {
            return Err(ChannelCloseCircuitError::BalanceBindingMismatch(format!(
                "balance proof settled_tx_chain {} != close final_settled_tx_chain {}",
                balance_pis.settled_tx_chain, public_inputs.final_settled_tx_chain
            )));
        }
        if balance_pis.channel_id != public_inputs.channel_id {
            return Err(ChannelCloseCircuitError::BalanceBindingMismatch(format!(
                "balance proof channel_id {:?} != close channel_id {:?}",
                balance_pis.channel_id, public_inputs.channel_id
            )));
        }

        let witness = self.fill_witness(&public_inputs, witness_value)?;
        self.data
            .prove(witness)
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
pub(crate) mod test_fixture {
    //! Shared heavy artifacts for the close-circuit and channel-e2e test suites: ONE balance
    //! circuit family build and ONE close circuit build per test-binary run.

    use std::sync::OnceLock;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

    use plonky2::plonk::proof::ProofWithPublicInputs;

    use super::{ChannelCloseCircuit, MemberCloseAuth};
    use crate::{
        circuits::balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
        ethereum_types::bytes32::Bytes32,
        poseidon_sig::{
            GoldilocksSecretKey,
            circuit::SingleSigCircuit,
            list::{ListCircuit, list_commitment},
        },
    };

    pub(crate) const D: usize = 2;
    pub(crate) type F = GoldilocksField;
    pub(crate) type C = PoseidonGoldilocksConfig;

    /// Active member count used by the close-circuit test suite (pad-to-MAX D6: 3 active members,
    /// the remaining `MAX_CHANNEL_MEMBERS - 3` slots are padding).
    pub(crate) const TEST_ACTIVE_MEMBERS: usize = 3;

    pub(crate) struct CloseCircuitFixture {
        pub balance_processor: BalanceProcessor<F, C, D>,
        pub single_sig: SingleSigCircuit,
        pub list: ListCircuit,
        pub close_circuit: ChannelCloseCircuit<F, C, D>,
    }

    pub(crate) fn fixture() -> &'static CloseCircuitFixture {
        static FIXTURE: OnceLock<CloseCircuitFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let t0 = std::time::Instant::now();
            let spend_circuit = SpendCircuit::<F, C, D>::new();
            let balance_processor =
                BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
            println!(
                "[close fixture] balance circuit family build: {:?}",
                t0.elapsed()
            );
            let single_sig = SingleSigCircuit::new();
            let list = ListCircuit::new(&single_sig.verifier_data());
            let t1 = std::time::Instant::now();
            let close_circuit = ChannelCloseCircuit::<F, C, D>::new(
                &balance_processor.balance_vd(),
                &list.verifier_data(),
            );
            println!(
                "[close fixture] close circuit build: {:?} (degree bits {})",
                t1.elapsed(),
                close_circuit.data.common.degree_bits()
            );
            CloseCircuitFixture {
                balance_processor,
                single_sig,
                list,
                close_circuit,
            }
        })
    }

    /// Deterministic per-(seed, slot) Goldilocks signing key for the close test suite.
    fn close_member_sk(seed: u64, slot: usize) -> GoldilocksSecretKey {
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&seed.to_le_bytes());
        s[8] = 0xc1;
        s[31] = slot as u8 + 1;
        GoldilocksSecretKey::from_seed(s)
    }

    /// P2b close member auth + the recursive `ListCircuit` proof for `active` members each signing
    /// the given IMCH `digest`. Returns `(member_auth (slot order), list_proof)`. The list folds
    /// the `(digest, pk_g_i)` pairs in slot order — exactly the order the close circuit
    /// rebuilds C'.
    pub(crate) fn member_auth_for_digest_n(
        digest: Bytes32,
        seed: u64,
        active: usize,
    ) -> (Vec<MemberCloseAuth>, ProofWithPublicInputs<F, C, D>) {
        let fx = fixture();
        let sks: Vec<GoldilocksSecretKey> = (0..active).map(|i| close_member_sk(seed, i)).collect();
        let member_auth: Vec<MemberCloseAuth> = sks
            .iter()
            .map(|sk| MemberCloseAuth {
                pk_g: sk.public_key(),
            })
            .collect();
        let pairs: Vec<(Bytes32, Bytes32)> =
            sks.iter().map(|sk| (digest, sk.public_key())).collect();
        // Build the list proof by folding one SingleSig proof per member, in slot order.
        let mut prev: Option<ProofWithPublicInputs<F, C, D>> = None;
        for (i, sk) in sks.iter().enumerate() {
            let sig = fx.single_sig.prove(sk, digest).expect("single sig proof");
            let prefix = list_commitment(&pairs[0..i]);
            prev = Some(
                fx.list
                    .prove_append(&sig, prefix, &prev)
                    .expect("list append"),
            );
        }
        (member_auth, prev.expect("at least one member"))
    }

    /// P2b close member auth + list proof for `TEST_ACTIVE_MEMBERS` members signing `digest`.
    pub(crate) fn member_auth_for_digest(
        digest: Bytes32,
        seed: u64,
    ) -> (Vec<MemberCloseAuth>, ProofWithPublicInputs<F, C, D>) {
        member_auth_for_digest_n(digest, seed, TEST_ACTIVE_MEMBERS)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use plonky2::field::types::PrimeField64;

    use super::{test_fixture::*, *};
    use crate::{
        common::{
            balance_state::{BalanceState, settled_tx_chain_push},
            channel::{
                ChannelFund, ChannelId, ChannelState, CloseIntent, CloseWithdrawal, MemberSignature,
            },
            salt::Salt,
        },
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
        poseidon_sig::GoldilocksSecretKey,
    };

    fn ciphertext(seed: u32) -> crate::regev::RegevCiphertext {
        use crate::regev::{REGEV_N, REGEV_Q};
        crate::regev::RegevCiphertext {
            c1: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
                .collect(),
            c2: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

    /// A closable final state for `channel_id` 5 with `member_count` ACTIVE members (pad-to-MAX
    /// D6) whose `settled_tx_chain` matches the genesis chain (= 0) of a REAL initial balance
    /// proof. Active slots carry distinct canonical ciphertexts; padding slots are
    /// `RegevCiphertext::padding()`.
    fn final_state_n(member_count: usize, settled_tx_chain: Bytes32) -> ChannelState {
        let id = ChannelId::new(5).unwrap();
        let enc: Vec<_> = (0..member_count as u32)
            .map(|i| ciphertext(1 + i))
            .collect();
        ChannelState {
            channel_id: id,
            epoch: 3,
            small_block_number: 7,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: id,
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::from_u32_slice(&[1, 2, 3, 4, 0, 0, 0, 0]).unwrap(),
            },
            balance_state: BalanceState {
                channel_id: id,
                member_count: member_count as u8,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances(&enc),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                settled_tx_chain,
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 9,
                pending_adds: BalanceState::pad_pending_adds(&vec![0u32; member_count]),
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0])
                .unwrap(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                pk_g: Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap(),
                signature: vec![1],
            }],
        }
        .with_computed_digest()
    }

    /// Three-active-member closable final state (existing default; pad-to-MAX D6).
    fn final_state(settled_tx_chain: Bytes32) -> ChannelState {
        final_state_n(TEST_ACTIVE_MEMBERS, settled_tx_chain)
    }

    fn close_witness_for(state: ChannelState) -> ChannelCloseWitness {
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 8, 7, 6, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![1, 2, 3],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();
        ChannelCloseWitness {
            final_channel_state: state,
            close_tx,
            close_intent,
        }
    }

    /// Build a full close witness for `member_count` ACTIVE members (pad-to-MAX D6 multi-N): the
    /// final state, a REAL genesis balance proof (settled_tx_chain = 0), and a REAL recursive
    /// `ListCircuit` proof over the `member_count` Poseidon single-sigs of the recomputed IMCH
    /// digest.
    fn full_witness_n(member_count: usize) -> ChannelCloseFullWitness<F, C, D> {
        let fx = fixture();
        // settled_tx_chain = 0: the channel never settled an inter-channel tx, so the genesis
        // (initial) balance proof carries the matching chain PI.
        let state = final_state_n(member_count, Bytes32::default());
        let digest = state.digest;
        let close = close_witness_for(state);
        let mut rng = rand::thread_rng();
        let final_balance_proof = fx
            .balance_processor
            .prove_initial(ChannelId::new(5).unwrap(), Salt::rand(&mut rng))
            .expect("initial balance proof");
        let (member_auth, list_proof) = member_auth_for_digest_n(digest, 0xc105e, member_count);
        ChannelCloseFullWitness {
            close,
            final_balance_proof,
            member_auth,
            list_proof,
        }
    }

    fn full_witness() -> ChannelCloseFullWitness<F, C, D> {
        full_witness_n(TEST_ACTIVE_MEMBERS)
    }

    /// Prove AND verify a full close for `member_count` ACTIVE members and assert the exposed
    /// `member_set_commitment` PI equals the native `close_member_set_commitment(&hashes,
    /// member_count)` for that N. Shared by the multi-N happy-path tests below.
    fn prove_and_verify_close_for(member_count: usize) {
        let fx = fixture();
        let witness = full_witness_n(member_count);
        let t0 = std::time::Instant::now();
        let proof = fx
            .close_circuit
            .prove(&witness)
            .unwrap_or_else(|e| panic!("close proof for member_count {member_count} failed: {e}"));
        println!(
            "[close N={member_count}] full close proof: {:?} (degree bits {})",
            t0.elapsed(),
            fx.close_circuit.data.common.degree_bits()
        );
        fx.close_circuit.data.verify(proof.clone()).unwrap();

        // Exposed PIs equal the close layout with the F5 commitment filled from member_auth.
        let mut expected_pis = witness.close.to_public_inputs().unwrap();
        let expected_commitment = member_set_commitment_for_auth(&witness.member_auth);
        expected_pis.member_set_commitment = expected_commitment;
        assert_eq!(expected_pis.member_count as usize, member_count);
        let expected = expected_pis.to_u64_vec();
        assert_eq!(expected.len(), CHANNEL_CLOSE_PUBLIC_INPUTS_LEN);
        let actual = proof
            .public_inputs
            .iter()
            .map(|field| field.to_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(expected, actual);

        // The exposed member_set_commitment must equal the NATIVE close_member_set_commitment over
        // the active member pk_g (padding zeroed) for THIS member_count.
        let hashes: [Bytes32; MAX_CHANNEL_MEMBERS] = std::array::from_fn(|i| {
            witness
                .member_auth
                .get(i)
                .map(|a| a.pk_g)
                .unwrap_or_default()
        });
        let native_commitment =
            crate::common::channel::close_member_set_commitment(&hashes, member_count as u8);
        assert_eq!(
            expected_commitment, native_commitment,
            "exposed member_set_commitment must equal close_member_set_commitment for N={member_count}"
        );
    }

    /// Multi-N happy path (D6 pad-to-MAX): full close for member_count = 2 (minimum). One close
    /// proof at the close-circuit degree; runs in release.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_proves_full_close_statement_n2() {
        prove_and_verify_close_for(2);
    }

    /// Multi-N happy path (D6 pad-to-MAX): full close for member_count = MAX_CHANNEL_MEMBERS = 16
    /// (all slots active, NO padding — every gated SPHINCS+ slot is a real active signature).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_proves_full_close_statement_n16() {
        assert_eq!(MAX_CHANNEL_MEMBERS, 16);
        prove_and_verify_close_for(MAX_CHANNEL_MEMBERS);
    }

    /// Negative — under-signed active set (A8): claim member_count = 3 but supply a `ListCircuit`
    /// proof over only 2 of the 3 members. The close circuit rebuilds `C'` by folding `(IMCH,
    /// pk_g_i)` over ALL 3 active slots, so `C' != C` (the verified list's commitment over 2
    /// entries) → the close proof is rejected. This binds member_count to the genuinely-signing
    /// active slots: a prover cannot under-sign an active slot.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_undersigned_active_slot() {
        let fx = fixture();
        // member_count = 3, three member pk_g, but the list proof only covers the FIRST TWO.
        let mut witness = full_witness_n(3);
        let digest = witness.close.final_channel_state.digest;
        // Rebuild the list proof over only the first two members (same seed/keys as
        // full_witness_n).
        let (auth2, list2) = member_auth_for_digest_n(digest, 0xc105e, 2);
        // The 3-member auth/commitment is kept (so member_set_commitment is the correct 3-key
        // value); only the list proof is short. Sanity: the first two pk_g match.
        assert_eq!(witness.member_auth[0].pk_g, auth2[0].pk_g);
        witness.list_proof = list2;

        let mut public_inputs = witness.close.to_public_inputs().unwrap();
        public_inputs.member_set_commitment = member_set_commitment_for_auth(&witness.member_auth);

        let pw = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a list proof missing an active member's signature must be rejected (C' != C)"
        );
    }

    /// Negative — member_count vs auth-length consistency (native pre-check): a close witness
    /// whose declared `member_count` (3) disagrees with the number of supplied member signatures
    /// (here 2) is refused structurally before proving. This binds the auth set size to the
    /// state's member_count.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_member_count_auth_length_mismatch() {
        let fx = fixture();
        // State declares member_count = 3, but only 2 signatures are provided.
        let mut witness = full_witness_n(3);
        witness.member_auth.truncate(2);
        assert!(matches!(
            fx.close_circuit.prove(&witness),
            Err(ChannelCloseCircuitError::InvalidMemberAuth(_))
        ));

        // And the in-circuit witness fill is likewise refused (active_bits would not match the
        // supplied auths).
        let public_inputs = witness.close.to_public_inputs().unwrap();
        assert!(matches!(
            fx.close_circuit.fill_witness(&public_inputs, &witness),
            Err(ChannelCloseCircuitError::InvalidMemberAuth(_))
        ));
    }

    /// Happy path: the FULL close statement (digest chain + H1 recompute + recursive balance
    /// proof + 3 real SPHINCS+ signatures) proves and verifies, and the 85 exposed limbs equal
    /// the P8-pinned `ChannelClosePublicInputs` layout (incl. the F5 `member_set_commitment`).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_proves_full_close_statement() {
        let fx = fixture();
        let witness = full_witness();
        let t0 = std::time::Instant::now();
        let proof = fx.close_circuit.prove(&witness).unwrap();
        println!("[close] full close proof: {:?}", t0.elapsed());
        fx.close_circuit.data.verify(proof.clone()).unwrap();

        // The exposed PIs equal the close layout with the F5 commitment filled from member_auth.
        let mut expected_pis = witness.close.to_public_inputs().unwrap();
        let expected_commitment = member_set_commitment_for_auth(&witness.member_auth);
        expected_pis.member_set_commitment = expected_commitment;
        let expected = expected_pis.to_u64_vec();
        assert_eq!(expected.len(), CHANNEL_CLOSE_PUBLIC_INPUTS_LEN);
        let actual = proof
            .public_inputs
            .iter()
            .map(|field| field.to_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(expected, actual);

        // F5 binding: the exposed commitment is exactly keccak([IMCM, member_count, the active
        // signing-key hashes, padding zeroed]).
        assert_eq!(
            expected_commitment,
            member_set_commitment_for_auth(&witness.member_auth),
            "member_set_commitment must commit exactly the active verified signing keys (slot order)"
        );
        assert_eq!(
            expected.len(),
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
            "close PI is 87 limbs (incl. member_count + delegate_count)"
        );
    }

    /// F5 negative — member-set binding: substituting ANY signing key changes
    /// `member_set_commitment`, so a non-member key set can no longer pass the L1 member-set
    /// match. We assert (a) the value commits exactly the keys that signed, (b) a different key
    /// set yields a DIFFERENT commitment, and (c) an explicitly-tampered commitment PI is rejected
    /// in-circuit (the keccak constrains it to the recomputed hashes).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_binds_member_set_commitment() {
        let fx = fixture();
        let witness = full_witness();

        // (a) the committed value is keccak over exactly the active signing keys (member_count +
        // slot order, padding zeroed).
        let commitment = member_set_commitment_for_auth(&witness.member_auth);

        // (b) a DIFFERENT (non-member) key set commits to a different value — substitution is
        // detectable by L1's member-set match.
        let (other_auth, _other_list) =
            member_auth_for_digest(witness.close.final_channel_state.digest, 0xdecafe);
        assert_ne!(
            commitment,
            member_set_commitment_for_auth(&other_auth),
            "substituting the signing keys MUST change member_set_commitment"
        );

        // (c) an explicitly tampered commitment PI is rejected by the in-circuit keccak: bypass
        // the native `prove` (which would recompute the correct value) and feed `fill_witness` a
        // PI whose member_set_commitment is wrong.
        let mut tampered_pis = witness.close.to_public_inputs().unwrap();
        tampered_pis.member_set_commitment =
            Bytes32::from_u32_slice(&[1, 1, 1, 1, 1, 1, 1, 1]).unwrap();
        let pw = fx
            .close_circuit
            .fill_witness(&tampered_pis, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a member_set_commitment PI not matching the verified keys must be rejected"
        );
    }

    /// Negative (i) — chain binding (detail2 §H-2): a balance proof whose `settled_tx_chain`
    /// (here: genesis = 0) differs from the close `final_settled_tx_chain` (here: one pushed
    /// leaf) must be rejected, both by the native mirror in `prove` and by the in-circuit
    /// equality constraint when the mirror is bypassed.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_balance_chain_mismatch() {
        let fx = fixture();
        let mut witness = full_witness();
        let pushed = settled_tx_chain_push(
            Bytes32::default(),
            Bytes32::from_u32_slice(&[6, 6, 6, 0, 0, 0, 0, 0]).unwrap(),
        );
        let state = final_state(pushed);
        let (member_auth, list_proof) = member_auth_for_digest(state.digest, 0xbad0);
        witness.member_auth = member_auth;
        witness.list_proof = list_proof;
        witness.close = close_witness_for(state);

        // Native mirror fires first…
        assert!(matches!(
            fx.close_circuit.prove(&witness),
            Err(ChannelCloseCircuitError::BalanceBindingMismatch(_))
        ));

        // …and the circuit-level constraint rejects even when the mirror is bypassed.
        let public_inputs = witness.close.to_public_inputs().unwrap();
        let pw = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "in-circuit settled_tx_chain equality must reject the mismatched balance proof"
        );
    }

    /// Negative (ii) — unanimity / wrong key: if ANY single member's `pk_g` in the close auth does
    /// not match the key that actually signed in the list proof, the rebuilt `C'` diverges from the
    /// verified list commitment `C` → the close statement is unprovable; there is no 2-of-3
    /// fallback. This exercises both the C'==C binding and the member_set_commitment binding.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_wrong_member_key() {
        let fx = fixture();
        let mut witness = full_witness();
        // Replace member 1's pk_g with an unrelated key (NOT the one that signed in the list
        // proof).
        let imposter = GoldilocksSecretKey::from_seed([0x5a; 32]).public_key();
        assert_ne!(witness.member_auth[1].pk_g, imposter);
        witness.member_auth[1].pk_g = imposter;

        // Use the member_set_commitment the circuit will recompute from the (now-wrong) pk_g set,
        // so the failure is isolated to the C' == C list-binding (not the commitment
        // keccak).
        let mut public_inputs = witness.close.to_public_inputs().unwrap();
        public_inputs.member_set_commitment = member_set_commitment_for_auth(&witness.member_auth);
        let pw = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a member pk_g not matching the list-proof signer must make the close proof fail (C' != C)"
        );

        // A wrong auth length is refused structurally before proving.
        let mut witness = full_witness();
        witness.member_auth.truncate(2);
        assert!(matches!(
            fx.close_circuit.prove(&witness),
            Err(ChannelCloseCircuitError::InvalidMemberAuth(_))
        ));
    }

    /// Negative (iii) — H1/version anchoring: claiming a `final_state_version` PI different
    /// from the one inside the signed H1 preimage must fail — the version PI feeds the H1, IMCH
    /// and IMCI keccaks, so the tampered value breaks the recomputed-digest connections.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_tampered_final_state_version() {
        let fx = fixture();
        let witness = full_witness();
        let mut public_inputs = witness.close.to_public_inputs().unwrap();
        public_inputs.final_state_version += 1;

        let pw = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a version PI not matching the signed H1 preimage must be rejected"
        );
    }
}
