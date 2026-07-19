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
//! 4. the N active members' Poseidon single-sigs over the recomputed `final_channel_state_digest`,
//!    carried by ONE recursively verified level-`AGG_LEVELS` aggregated sign-zkp proof
//!    (`poseidon_sig::aggregate`) whose message/count/pk-list PIs are bound in-circuit (all-member
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
        channel::{
            close_pis::{
                CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs, ChannelCloseWitness,
                ChannelCloseWitnessError,
            },
            h1_gadget::recompute_h1,
        },
    },
    common::channel::close_member_set_commitment,
    constants::{MAX_COSIGNERS, MEMBER_DISTINCTNESS_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::{U64, U64Target},
        u256::{U256, U256_LEN, U256Target},
    },
    poseidon_sig::aggregate::{
        AGG_COUNT_OFFSET, AGG_LEVELS, AGG_MSG_OFFSET, AGG_PK_LIST_OFFSET, MAX_AGG_SIGNERS,
        agg_public_inputs_len,
    },
    utils::{
        conversion::ToU64 as _,
        poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::{add_proof_target_and_verify, add_proof_target_and_verify_cyclic},
        trees::indexed_merkle_tree::{
            IndexedMerkleTree,
            insertion::{IndexedInsertionProof, IndexedInsertionProofTarget},
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
    /// Number of ACTIVE cosigners, range-checked `2..=MAX_COSIGNERS` (enforced in-circuit by the
    /// MAX_COSIGNERS-bit unary decomposition) and used to gate per-slot signature verification and
    /// the member_set_commitment select. Single limb. Cosigners only — delegates never sign.
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
                F::from_canonical_u16(value.delegate_count),
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
/// keys. The signatures themselves are proven by the recursively verified level-`AGG_LEVELS`
/// `AggLevelCircuit` proof (binary-tree aggregated sign-zkp): its exposed pk list IS the in-circuit
/// member key vector (no re-witnessing), its `message` is bound to the recomputed IMCH digest and
/// its `signer_count` to `member_count`, so all N active members signed the final IMCH digest
/// (unanimous close; no threshold relaxation).
#[derive(Clone, Debug)]
pub struct MemberCloseAuth {
    /// The member's Goldilocks signing public key `pk_g` (`GoldilocksSecretKey::public_key()`),
    /// the registered member identity. Native mirror of slot `i` of the aggregated proof's pk
    /// list; drives the native member_set_commitment and the A5 distinctness insertion witness.
    pub pk_g: Bytes32,
}

/// Full prover witness for [`ChannelCloseCircuit`]: the close data trio, the recursive balance
/// proof, the per-member `pk_g`s, and the level-`AGG_LEVELS` aggregated sign-zkp proof over the N
/// member IMCH single-sigs (D4: the close circuit verifies everything).
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
    /// The level-`AGG_LEVELS` `poseidon_sig::aggregate::AggLevelCircuit` proof over the N member
    /// single-sigs of the final IMCH digest (slot order, left-packed; build via
    /// `SigAggregator::aggregate_to_level(sigs, AGG_LEVELS)`). Its `message` PI must equal the
    /// recomputed IMCH digest, its `signer_count` must equal `member_count`, and its pk list IS
    /// the circuit's member key vector.
    pub agg_proof: ProofWithPublicInputs<F, C, D>,
}

/// Native mirror of the in-circuit member-set commitment: take each ACTIVE cosigner's `pk_g` (slot
/// order), pad to MAX_COSIGNERS (padding = `Bytes32::default()`), and keccak `[IMCM,
/// member_count, pk_g_0..pk_g_{MAX_COSIGNERS-1}]`. MUST agree byte-for-byte with the in-circuit
/// keccak in [`ChannelCloseCircuit::new`]. Cosigners only — delegates never enter the member set.
fn member_set_commitment_for_auth(member_auth: &[MemberCloseAuth]) -> Bytes32 {
    let hashes: [Bytes32; MAX_COSIGNERS] =
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
    /// The balance-slot Poseidon Merkle root committed inside H1 (Poseidon-root form). Witnessed
    /// directly — SOUND because it rides INSIDE the signed H1 header (the cosigner signatures
    /// over IMCH attest it); the close statement never opens individual slots. Replaces the
    /// retired MAX_CHANNEL_MEMBERS-wide enc-digest/pk-digest/pending-adds target vectors.
    slot_tree_root: PoseidonHashOutTarget,
    /// The recursively verified final balance proof.
    final_balance_proof: ProofWithPublicInputsTarget<D>,
    /// The recursively verified level-`AGG_LEVELS` aggregated sign-zkp proof over the N member
    /// IMCH single-sigs. Its pk-list PI slices ARE the in-circuit member key vector (no separate
    /// witnessed `pk_g` targets), its `message` is connected to the recomputed IMCH digest and its
    /// `signer_count` to the `member_count` PI.
    agg_proof: ProofWithPublicInputsTarget<D>,
    /// Per-slot cosigner activeness flags `active_bits[i] = (i < member_count)` (length
    /// MAX_COSIGNERS). Set from member_count in `fill_witness`.
    active_bits: Vec<plonky2::iop::target::BoolTarget>,
    /// A5 pk_g distinctness: per-slot indexed-Merkle insertion proofs (length MAX_COSIGNERS).
    /// In `fill_witness` the active slots' pk_g are inserted IN SLOT ORDER into a fresh
    /// `IndexedMerkleTree`; padding slots get a dummy (non-inserting) proof. The in-circuit
    /// `conditional_get_new_root` chain asserts each active key's non-membership = distinctness.
    member_insertion_proofs: Vec<IndexedInsertionProofTarget>,
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
    /// `agg_vd` is the LEVEL-`AGG_LEVELS` `poseidon_sig::aggregate::AggLevelCircuit` verifier
    /// data (baked in as a build-time constant, A7) — its proof carries the N member IMCH
    /// single-sigs as a binary aggregation tree whose exposed pk list is provably left-packed and
    /// backed one-for-one by verified signatures.
    pub fn new(
        balance_vd: &VerifierCircuitData<F, C, D>,
        agg_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        // The close circuit reads MAX_COSIGNERS pk slots out of the aggregated proof, so the two
        // capacities must agree, and `agg_vd` must be the level-AGG_LEVELS circuit (build-time
        // arity check; the security binding is the constant VK below).
        const { assert!(MAX_COSIGNERS == MAX_AGG_SIGNERS) };
        assert_eq!(
            agg_vd.common.num_public_inputs,
            agg_public_inputs_len(AGG_LEVELS),
            "agg_vd must be the level-{AGG_LEVELS} AggLevelCircuit verifier data"
        );
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = ChannelClosePublicInputsTarget::new(&mut builder);
        let final_state_close_freeze_nonce = U64Target::new(&mut builder, true);
        let final_state_shared_native_nullifier_root = Bytes32Target::new(&mut builder, true);
        let final_state_unallocated_confirmed_incoming = U256Target::new(&mut builder, true);
        let final_state_prev_digest = Bytes32Target::new(&mut builder, true);
        let final_state_h2_tag = Bytes32Target::new(&mut builder, true);
        // The balance-slot tree root (H1 Poseidon-root form): 4 raw Goldilocks elements,
        // witnessed directly — attested by the cosigner signatures over H1 (see the field doc).
        let slot_tree_root = PoseidonHashOutTarget::new(&mut builder);

        // Per-slot COSIGNER activeness flags `slot_is_active[i] = (i < member_count)`. Built from a
        // unary decomposition: `member_count = Σ_i active_bits[i]` with each bit Boolean and the
        // sequence monotonically non-increasing (1*…1*0*…). This forces `active_bits[i] = (i <
        // member_count)` for member_count in 0..=MAX_COSIGNERS. These flags gate the per-slot
        // signature verification and the member_set_commitment select below.
        //
        // SECURITY (cosigner/delegate split): sized to MAX_COSIGNERS (16), NOT the balance-slot
        // capacity MAX_CHANNEL_MEMBERS — only COSIGNERS sign the close, delegates hold balances
        // without signing. The sum-binding below then also enforces `member_count <= MAX_COSIGNERS`
        // IN-CIRCUIT (a sum of MAX_COSIGNERS bits cannot exceed MAX_COSIGNERS).
        let mut active_bits: Vec<plonky2::iop::target::BoolTarget> =
            Vec::with_capacity(MAX_COSIGNERS);
        for _ in 0..MAX_COSIGNERS {
            active_bits.push(builder.add_virtual_bool_target_safe());
        }
        // Monotonicity: active_bits[i+1] => active_bits[i] (no active slot after a padding slot).
        // Equivalent to active_bits[i] >= active_bits[i+1], i.e.
        // active_bits[i+1]*(1-active_bits[i]) == 0.
        let one = builder.one();
        let zero_t = builder.zero();
        for i in 0..MAX_COSIGNERS - 1 {
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

        let channel_state_domain = builder.constant(F::from_canonical_u32(CHANNEL_STATE_DOMAIN));
        let close_tx_domain = builder.constant(F::from_canonical_u32(CLOSE_TX_DOMAIN));
        let close_intent_domain = builder.constant(F::from_canonical_u32(CLOSE_INTENT_DOMAIN));

        // ── (b) H1 in-circuit recompute (Poseidon-root form; SHARED `h1_gadget`) ──────────
        //
        // SECURITY: this anchors `final_settled_tx_chain`, `final_settled_tx_accumulator_root`,
        // `final_state_version`, `member_count` AND `delegate_count` as the unique values inside
        // the signed H1 — the same PI targets feed the O(1) H1 header, the IMCH/IMCI tails AND
        // the balance-proof equality below, so no two of those bindings can diverge. The
        // per-slot data is committed by the witnessed `slot_tree_root` (inside the signed H1;
        // the close statement never opens individual slots) — see
        // `tasks/h1-poseidon-root-threat-model.md` §4/A4 and the shared gadget doc.
        let recomputed_h1 = recompute_h1::<F, D>(
            &mut builder,
            public_inputs.channel_id[0],
            public_inputs.member_count,
            public_inputs.delegate_count,
            slot_tree_root,
            &public_inputs.final_settled_tx_chain,
            &public_inputs.final_settled_tx_accumulator_root,
            &public_inputs.final_state_version,
        );
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

        // ── (f) N-member IMCH signatures via the aggregated sign-zkp proof (binary tree) ──
        //
        // Message = the 8 u32 limbs of the RECOMPUTED `final_channel_state_digest` (IMCH). All N
        // active members sign it (unanimous close; no threshold relaxation). We recursively verify
        // ONE level-AGG_LEVELS `AggLevelCircuit` proof at a CONSTANT VK and consume its exposed
        // statement `[message(8), signer_count(1), pk_0..pk_{MAX_AGG_SIGNERS-1}]` directly.
        //
        // SECURITY (consumer obligations of the aggregation circuit, see its module doc):
        //  - MESSAGE binding: the agg proof's message PI is connected to the recomputed IMCH
        //    `state_digest` — the SAME wires as the `final_channel_state_digest` PI — so every
        //    aggregated signature is over exactly this close's final state (A4: the IMCH keccak
        //    domain differs from the validity IMSB digest, so cross-protocol reuse fails).
        //  - COUNT binding: the agg proof's `signer_count` is connected to the `member_count` PI
        //    (single limb). By the aggregator's padding soundness, `signer_count` equals the number
        //    of GENUINELY VERIFIED leaf signatures, so a prover cannot under-sign (A8:
        //    all-required-members-present).
        //  - LIST binding (no re-witnessing): `member_pk_g_targets` below are SLICES of the
        //    verified agg proof's pk-list PIs — wired functions of the verified children, with no
        //    witnessed freedom. Left-packing (enforced in-circuit by the aggregator) guarantees the
        //    nonzero pks are exactly the first `signer_count` slots and the zero padding is
        //    strictly a suffix, so the `active_bits` gating (i < member_count) aligns with the real
        //    signer prefix.
        //  - pk_g distinctness over the active set forbids one key faking N signatures (A5) — the
        //    aggregator deliberately ACCEPTS duplicate leaves; the insertion chain below is the
        //    consumer-side rejection.
        //  - member_set_commitment = keccak([IMCM, member_count, pk_g_0..pk_g_{MAX-1}]) (padding
        //    zeroed) is exposed and matched on L1 against the registered member set, so the
        //    verified keys cannot be substituted with non-member keys. Byte-identical to the native
        //    `common::channel::close_member_set_commitment`.
        //  - RANGE: every limb read from the agg proof is u32 by construction inside the verified
        //    proof chain (leaf pk limbs come from `Bytes32Target::from_hash_out`'s safe 32-bit
        //    split, messages are range-checked in the leaf circuit, and aggregation only copies or
        //    boolean-gates them), so feeding them to the keccak gadget (which does NOT range-check)
        //    is sound without re-checking.
        let agg_proof = add_proof_target_and_verify(agg_vd, &mut builder);

        // (f-i) message == recomputed IMCH digest (the same digest the members must sign).
        let agg_message = Bytes32Target::from_slice(
            &agg_proof.public_inputs[AGG_MSG_OFFSET..AGG_MSG_OFFSET + BYTES32_LEN],
        );
        agg_message.connect(&mut builder, state_digest);

        // (f-ii) signer_count == member_count.
        builder.connect(
            agg_proof.public_inputs[AGG_COUNT_OFFSET],
            public_inputs.member_count,
        );

        // (f-iii) the member key vector := the verified pk-list PI slices, slot for slot.
        let member_pk_g_targets: Vec<Bytes32Target> = (0..MAX_COSIGNERS)
            .map(|i| {
                let start = AGG_PK_LIST_OFFSET + i * BYTES32_LEN;
                Bytes32Target::from_slice(&agg_proof.public_inputs[start..start + BYTES32_LEN])
            })
            .collect();

        let close_member_set_domain =
            builder.constant(F::from_canonical_u32(CLOSE_MEMBER_SET_DOMAIN));
        let mut member_set_inputs: Vec<Target> =
            vec![close_member_set_domain, public_inputs.member_count];

        // member_set_commitment preimage: each slot's pk_g, zeroed on padding. (Left-packing
        // already makes the padding slots zero in the agg PIs; the select keeps the preimage
        // definition independent of that property and byte-identical to the native helper.)
        for (i, is_active) in active_bits.iter().enumerate() {
            for &limb in &member_pk_g_targets[i].to_vec() {
                let selected = builder.select(*is_active, limb, zero_t);
                member_set_inputs.push(selected);
            }
        }

        // ── pk_g distinctness over the ACTIVE set (A5: one key cannot fake N signatures) ──
        //
        // Replaces the former O(MAX^2) all-pairs equality loop with an O(MAX·height) indexed-Merkle
        // insertion chain that proves the SAME property: no two ACTIVE member slots share a pk_g.
        //
        // MECHANISM: starting from a fresh (empty) IndexedMerkleTree root, we insert each slot's
        // pk_g IN SLOT ORDER, gated by the SAME `active_bits` that gate the member_set_commitment
        // select. The audited insertion gadget
        // (`IndexedInsertionProofTarget::conditional_get_new_root`) asserts, for every active
        // insert, that `prev_low.key < key < next_key (or next_key == 0)` = NON-MEMBERSHIP =
        // the key is not already present. A duplicate active pk_g therefore makes one of the
        // inserts UNSATISFIABLE (the low-leaf bound fails). Padding slots (condition = false) are
        // skipped: the gadget returns the previous root and gates off the bound assertions, so
        // padding pk_g (provably zero in the agg proof's left-packed suffix) never enters the
        // tree and never masks a real collision.
        //
        // SECURITY:
        //  - The keys checked here are EXACTLY `member_pk_g_targets` — the pk-list PI slices of the
        //    VERIFIED aggregated sign-zkp proof, the same targets the member_set_commitment keccak
        //    (above) consumes — converted limb-for-limb to a `U256Target` (Bytes32Target and
        //    U256Target are both `[Target; 8]`). No fresh key vector is witnessed, so distinctness
        //    binds the verified signing keys, not a prover-chosen aside.
        //  - pk_g is compared as the canonical full 256-bit value: the conversion copies all 8
        //    32-bit limbs unchanged (no `remove_3bits` masking is applied), so the ordering used by
        //    the insertion bound (`U256Target::is_lt`) sees the same value the keccak sees.
        //  - The tree only enforces distinctness; the final root is INTENTIONALLY discarded (not a
        //    PI, not connected anywhere). The per-insert bound assertions are the whole point.
        // INTENTIONALLY SIMPLE: the inserted `value` is a constant 1 (the leaf value is irrelevant
        // to distinctness — only the KEY's non-membership matters).
        let member_insertion_proofs: Vec<IndexedInsertionProofTarget> = (0..MAX_COSIGNERS)
            .map(|_| {
                IndexedInsertionProofTarget::new::<F, D>(
                    &mut builder,
                    MEMBER_DISTINCTNESS_TREE_HEIGHT,
                    true,
                )
            })
            .collect();
        let distinctness_value = builder.one();
        let empty_distinctness_root =
            IndexedMerkleTree::new(MEMBER_DISTINCTNESS_TREE_HEIGHT).get_root();
        let mut distinctness_root =
            PoseidonHashOutTarget::constant(&mut builder, empty_distinctness_root);
        for (i, is_active) in active_bits.iter().enumerate() {
            let key_i = U256Target::from_slice(&member_pk_g_targets[i].to_vec());
            distinctness_root = member_insertion_proofs[i].conditional_get_new_root::<F, C, D>(
                &mut builder,
                *is_active,
                key_i,
                distinctness_value,
                distinctness_root,
            );
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
            slot_tree_root,
            final_balance_proof,
            agg_proof,
            active_bits,
            member_insertion_proofs,
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
        if !(2..=MAX_COSIGNERS).contains(&member_count) {
            return Err(ChannelCloseCircuitError::InvalidMemberAuth(format!(
                "member_count {member_count} out of range (must be 2..={MAX_COSIGNERS} cosigners)"
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
        // H1 Poseidon-root form: the slot data enters the statement ONLY through the slot-tree
        // root inside the signed H1 header (recomputed natively here, exactly as `h1()` does).
        self.slot_tree_root
            .set_witness(&mut witness, state.balance_state.slot_tree_root());

        witness
            .set_proof_with_pis_target(
                &self.final_balance_proof,
                &witness_value.final_balance_proof,
            )
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))?;

        // The level-AGG_LEVELS aggregated sign-zkp proof over the N member IMCH single-sigs. The
        // in-circuit member key vector is sliced from THIS proof's pk-list PIs, so there are no
        // per-slot pk_g targets to fill — `member_auth` must mirror the aggregation leaf order
        // (slot order) or the member_set_commitment / distinctness constraints become
        // unsatisfiable.
        witness
            .set_proof_with_pis_target(&self.agg_proof, &witness_value.agg_proof)
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))?;

        // A5 pk_g distinctness witness: build a fresh IndexedMerkleTree and insert each ACTIVE
        // member's pk_g IN SLOT ORDER (the SAME order/values the aggregated proof exposes and the
        // member_set_commitment keccak consumes). `prove_and_insert` proves non-membership of the
        // key against the current tree, then inserts it; a DUPLICATE active pk_g makes
        // `prove_and_insert` return `Err(KeyAlreadyExists)` (the duplicate has no valid low-leaf),
        // which we surface as a proving failure — there is NO witness that satisfies the in-circuit
        // insertion bound for a repeated key. Padding slots get a dummy (non-inserting) proof whose
        // gated assertions are skipped in-circuit (condition = active_bits[slot] = false).
        let mut distinctness_tree = IndexedMerkleTree::new(MEMBER_DISTINCTNESS_TREE_HEIGHT);
        for (slot, insertion_target) in self.member_insertion_proofs.iter().enumerate() {
            let insertion_proof: IndexedInsertionProof = if slot < member_count {
                let pk_g = witness_value.member_auth[slot].pk_g;
                let key: U256 = pk_g.into();
                // value MUST equal the circuit-side `distinctness_value` (a constant 1,
                // close_circuit ~702): the native leaf hash folds `value`, so
                // inserting with any other value makes the witnessed merkle root
                // disagree with the in-circuit `get_new_root` recomputation ("Wire
                // set twice"). The value is irrelevant to distinctness (only the
                // KEY's non-membership matters), so 1 on both sides is the canonical choice.
                distinctness_tree.prove_and_insert(key, 1u64).map_err(|e| {
                    ChannelCloseCircuitError::InvalidMemberAuth(format!(
                        "pk_g distinctness (A5): slot {slot} pk_g {pk_g} is a duplicate of an \
                             earlier active member — cannot insert: {e}"
                    ))
                })?
            } else {
                distinctness_tree.prove_dummy()
            };
            insertion_target.set_witness(&mut witness, &insertion_proof);
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

#[cfg(any(test, feature = "close-fixture-bin"))]
pub mod test_fixture {
    //! Shared heavy artifacts for the close-circuit and channel-e2e test suites: ONE balance
    //! circuit family build and ONE close circuit build per test-binary run.

    use std::sync::OnceLock;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

    use plonky2::plonk::proof::ProofWithPublicInputs;

    use super::{
        ChannelCloseCircuit, ChannelCloseFullWitness, ChannelCloseWitness, MemberCloseAuth,
    };
    use crate::{
        circuits::balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
        common::{
            balance_state::BalanceState,
            channel::{
                ChannelFund, ChannelId, ChannelState, CloseIntent, CloseWithdrawal, MemberSignature,
            },
            salt::Salt,
        },
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
        poseidon_sig::{
            GoldilocksSecretKey,
            aggregate::{AGG_LEVELS, SigAggregator},
            circuit::SingleSigCircuit,
        },
        regev::RegevCiphertext,
    };

    pub(crate) const D: usize = 2;
    pub(crate) type F = GoldilocksField;
    pub(crate) type C = PoseidonGoldilocksConfig;

    /// Active member count used by the close-circuit test suite (pad-to-MAX D6: 3 active members,
    /// the remaining `MAX_CHANNEL_MEMBERS - 3` slots are padding).
    pub const TEST_ACTIVE_MEMBERS: usize = 3;

    pub struct CloseCircuitFixture {
        pub balance_processor: BalanceProcessor<F, C, D>,
        pub single_sig: SingleSigCircuit,
        pub aggregator: SigAggregator,
        pub close_circuit: ChannelCloseCircuit<F, C, D>,
    }

    pub fn fixture() -> &'static CloseCircuitFixture {
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
            let aggregator = SigAggregator::new(&single_sig.verifier_data());
            let t1 = std::time::Instant::now();
            let close_circuit = ChannelCloseCircuit::<F, C, D>::new(
                &balance_processor.balance_vd(),
                &aggregator.levels[AGG_LEVELS - 1].verifier_data(),
            );
            println!(
                "[close fixture] close circuit build: {:?} (degree bits {})",
                t1.elapsed(),
                close_circuit.data.common.degree_bits()
            );
            CloseCircuitFixture {
                balance_processor,
                single_sig,
                aggregator,
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

    /// Close member auth + the LEVEL-`AGG_LEVELS` aggregated sign-zkp proof for the given signing
    /// keys, each signing the IMCH `digest` (leaf order = slot order). The aggregator itself
    /// accepts DUPLICATE keys by design (distinctness is the close circuit's consumer obligation),
    /// so tests can pass a duplicated `sks` list to build an otherwise-valid forged tree.
    pub(crate) fn member_auth_for_sks(
        digest: Bytes32,
        sks: &[GoldilocksSecretKey],
    ) -> (Vec<MemberCloseAuth>, ProofWithPublicInputs<F, C, D>) {
        let fx = fixture();
        let member_auth: Vec<MemberCloseAuth> = sks
            .iter()
            .map(|sk| MemberCloseAuth {
                pk_g: sk.public_key(),
            })
            .collect();
        let leaves: Vec<ProofWithPublicInputs<F, C, D>> = sks
            .iter()
            .map(|sk| fx.single_sig.prove(sk, digest).expect("single sig proof"))
            .collect();
        let agg_proof = fx
            .aggregator
            .aggregate_to_level(&leaves, AGG_LEVELS)
            .expect("aggregate to level 4");
        (member_auth, agg_proof)
    }

    /// Deterministic signing keys for `active` close-test members under `seed` (slot order).
    pub(crate) fn close_member_sks(seed: u64, active: usize) -> Vec<GoldilocksSecretKey> {
        (0..active).map(|i| close_member_sk(seed, i)).collect()
    }

    /// Close member auth + aggregated sign-zkp proof for `active` deterministic members signing
    /// `digest`. Returns `(member_auth (slot order), level-AGG_LEVELS agg proof)`.
    pub(crate) fn member_auth_for_digest_n(
        digest: Bytes32,
        seed: u64,
        active: usize,
    ) -> (Vec<MemberCloseAuth>, ProofWithPublicInputs<F, C, D>) {
        member_auth_for_sks(digest, &close_member_sks(seed, active))
    }

    /// Close member auth + agg proof for `TEST_ACTIVE_MEMBERS` members signing `digest`.
    pub(crate) fn member_auth_for_digest(
        digest: Bytes32,
        seed: u64,
    ) -> (Vec<MemberCloseAuth>, ProofWithPublicInputs<F, C, D>) {
        member_auth_for_digest_n(digest, seed, TEST_ACTIVE_MEMBERS)
    }

    /// Deterministic canonical ciphertext for active slot `seed` (test/fixture data).
    pub(crate) fn ciphertext(seed: u32) -> RegevCiphertext {
        use crate::regev::{REGEV_N, REGEV_Q};
        RegevCiphertext {
            c1: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
                .collect(),
            c2: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

    /// A closable final state for channel 5 with `member_count` ACTIVE members (pad-to-MAX D6);
    /// `settled_tx_chain` matches the genesis chain (= 0) of a REAL initial balance proof.
    pub(crate) fn final_state_n(member_count: usize, settled_tx_chain: Bytes32) -> ChannelState {
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
                // B-1b: nonzero per-active-slot exit addresses (validate() rejects zero actives).
                recipients: BalanceState::pad_recipients(
                    &(0..member_count)
                        .map(|i| {
                            crate::ethereum_types::address::Address::from_u32_slice(
                                &[0x7E57_0000u32.wrapping_add(i as u32); 5],
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>(),
                ),
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

    pub(crate) fn close_witness_for(state: ChannelState) -> ChannelCloseWitness {
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

    /// Build a full close witness for `member_count` ACTIVE members: the final state, a REAL
    /// genesis balance proof (settled_tx_chain = 0), and a REAL level-`AGG_LEVELS` aggregated
    /// sign-zkp proof over the member Poseidon single-sigs. Consumed by `generate_close_fixture`
    /// AND the in-tree tests.
    pub fn build_close_full_witness_n(member_count: usize) -> ChannelCloseFullWitness<F, C, D> {
        let fx = fixture();
        let state = final_state_n(member_count, Bytes32::default());
        let digest = state.digest;
        let close = close_witness_for(state);
        let mut rng = rand::thread_rng();
        let final_balance_proof = fx
            .balance_processor
            .prove_initial(ChannelId::new(5).unwrap(), Salt::rand(&mut rng))
            .expect("initial balance proof");
        let (member_auth, agg_proof) = member_auth_for_digest_n(digest, 0xc105e, member_count);
        ChannelCloseFullWitness {
            close,
            final_balance_proof,
            member_auth,
            agg_proof,
        }
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
                // B-1b: nonzero per-active-slot exit addresses (validate() rejects zero actives).
                recipients: BalanceState::pad_recipients(
                    &(0..member_count)
                        .map(|i| {
                            crate::ethereum_types::address::Address::from_u32_slice(
                                &[0x7E57_0000u32.wrapping_add(i as u32); 5],
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>(),
                ),
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
    /// final state, a REAL genesis balance proof (settled_tx_chain = 0), and a REAL
    /// level-`AGG_LEVELS` aggregated sign-zkp proof over the `member_count` Poseidon single-sigs
    /// of the recomputed IMCH digest.
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
        let (member_auth, agg_proof) = member_auth_for_digest_n(digest, 0xc105e, member_count);
        ChannelCloseFullWitness {
            close,
            final_balance_proof,
            member_auth,
            agg_proof,
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
        let hashes: [Bytes32; MAX_COSIGNERS] = std::array::from_fn(|i| {
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

    /// Multi-N happy path: full close for member_count = MAX_COSIGNERS = 16 (all COSIGNER slots
    /// active, NO padding — every gated signature slot is a real active cosigner signature).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_proves_full_close_statement_n16() {
        assert_eq!(MAX_COSIGNERS, 16);
        prove_and_verify_close_for(MAX_COSIGNERS);
    }

    /// Negative — under-signed active set (A8): claim member_count = 3 but supply an aggregated
    /// sign-zkp proof over only 2 of the 3 members. The agg proof's `signer_count` PI (provably
    /// the number of genuinely verified leaf signatures) is connected to the `member_count` PI,
    /// so 2 != 3 makes the close proof unsatisfiable. This binds member_count to the
    /// genuinely-signing active slots: a prover cannot under-sign an active slot.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_undersigned_active_slot() {
        let fx = fixture();
        // member_count = 3, three member pk_g, but the agg proof only covers the FIRST TWO.
        let mut witness = full_witness_n(3);
        let digest = witness.close.final_channel_state.digest;
        // Rebuild the agg proof over only the first two members (same seed/keys as
        // full_witness_n).
        let (auth2, agg2) = member_auth_for_digest_n(digest, 0xc105e, 2);
        // The 3-member auth/commitment is kept (so member_set_commitment is the correct 3-key
        // value); only the agg proof is short. Sanity: the first two pk_g match.
        assert_eq!(witness.member_auth[0].pk_g, auth2[0].pk_g);
        witness.agg_proof = agg2;

        let mut public_inputs = witness.close.to_public_inputs().unwrap();
        public_inputs.member_set_commitment = member_set_commitment_for_auth(&witness.member_auth);

        let pw = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "an agg proof missing an active member's signature must be rejected \
             (signer_count != member_count)"
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
        let (member_auth, agg_proof) = member_auth_for_digest(state.digest, 0xbad0);
        witness.member_auth = member_auth;
        witness.agg_proof = agg_proof;
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
    /// not match the key that actually signed in the aggregated proof, the close statement is
    /// unprovable; there is no 2-of-3 fallback. The in-circuit member key vector IS the verified
    /// agg proof's pk list, so a substituted auth key desyncs the member_set_commitment PI (native
    /// keccak over the imposter set vs in-circuit keccak over the real signers) AND the A5
    /// distinctness insertion witness — either mismatch is unsatisfiable.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_wrong_member_key() {
        let fx = fixture();
        let mut witness = full_witness();
        // Replace member 1's pk_g with an unrelated key (NOT the one that signed in the agg
        // proof).
        let imposter = GoldilocksSecretKey::from_seed([0x5a; 32]).public_key();
        assert_ne!(witness.member_auth[1].pk_g, imposter);
        witness.member_auth[1].pk_g = imposter;

        // Use the member_set_commitment computed from the (now-wrong) pk_g set — the forgery a
        // prover would attempt: claim the imposter set on L1 while the verified signatures came
        // from the real keys.
        let mut public_inputs = witness.close.to_public_inputs().unwrap();
        public_inputs.member_set_commitment = member_set_commitment_for_auth(&witness.member_auth);
        let pw = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a member pk_g not matching the agg-proof signer must make the close proof fail"
        );

        // A wrong auth length is refused structurally before proving.
        let mut witness = full_witness();
        witness.member_auth.truncate(2);
        assert!(matches!(
            fx.close_circuit.prove(&witness),
            Err(ChannelCloseCircuitError::InvalidMemberAuth(_))
        ));
    }

    /// Negative — A5 pk_g distinctness (the indexed-Merkle insertion chain). Two ACTIVE member
    /// slots sharing a pk_g would let ONE key satisfy two of the N-of-N close signatures. The
    /// aggregation circuit ACCEPTS duplicate leaves BY DESIGN (each slot is backed by its own
    /// verified signature; dedup is an explicit consumer obligation), so we build a REAL forged
    /// aggregation tree with the same leaf key in slots 0 and 1 — an otherwise fully
    /// self-consistent "one key signs two slots" witness whose ONLY violated invariant is
    /// distinctness — and confirm the close is UNPROVABLE: the second insertion of the repeated
    /// key has no valid low-leaf (`prev_low.key < key < next_key` cannot hold for a key already in
    /// the tree), so the in-circuit insertion bound is unsatisfiable and witness generation
    /// refuses it.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_duplicate_member_pk_g() {
        let fx = fixture();
        let mut witness = full_witness();
        assert!(witness.member_auth.len() >= 2, "need >=2 active members");
        assert_ne!(
            witness.member_auth[0].pk_g, witness.member_auth[1].pk_g,
            "precondition: slots 0 and 1 start distinct"
        );
        // Forge the aggregation tree: duplicate slot 0's signing key into slot 1 and rebuild the
        // REAL agg proof over [sk0, sk0, sk2] — the aggregator accepts this (boundary check
        // below), the close circuit must not.
        let digest = witness.close.final_channel_state.digest;
        let mut sks = close_member_sks(0xc105e, witness.member_auth.len());
        sks[1] = sks[0];
        let (dup_auth, dup_agg) = member_auth_for_sks(digest, &sks);
        assert_eq!(
            dup_auth[0].pk_g, dup_auth[1].pk_g,
            "slots 0/1 now duplicated"
        );
        // Boundary: the aggregated proof itself VERIFIES — distinctness is not its job.
        fx.aggregator.levels[crate::poseidon_sig::aggregate::AGG_LEVELS - 1]
            .verifier_data()
            .verify(dup_agg.clone())
            .expect("the aggregator accepts duplicate leaves by design");
        witness.member_auth = dup_auth;
        witness.agg_proof = dup_agg;

        let result = fx.close_circuit.prove(&witness);
        assert!(
            matches!(&result, Err(ChannelCloseCircuitError::InvalidMemberAuth(m)) if m.contains("distinctness")),
            "duplicate active pk_g must be rejected by the A5 indexed-insertion distinctness check, got: {result:?}"
        );
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

    /// Negative — slot_tree_root anchoring (H1 = Poseidon balance-slot tree root): the root is
    /// WITNESSED in the close circuit (not recomputed from the 1024 slots), justified because it
    /// rides inside the signed H1. This test pins that justification: mutate ONE balance slot
    /// AFTER the cosigners signed (so the witnessed `slot_tree_root()` diverges from the root
    /// inside the signed H1 / the honest PIs) and confirm the close is UNPROVABLE — the in-circuit
    /// `recompute_h1(witnessed_root, …)` no longer matches the `final_balance_state_h1` PI / the
    /// IMCH digest the aggregated sign-zkp attests.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn channel_close_circuit_rejects_tampered_slot_tree_root() {
        let fx = fixture();
        let mut witness = full_witness();
        // PIs derived from the HONEST (signed) state.
        let public_inputs = witness.close.to_public_inputs().unwrap();
        // Post-signing mutation of one balance slot => different slot_tree_root at witness time.
        let honest_root = witness
            .close
            .final_channel_state
            .balance_state
            .slot_tree_root();
        witness.close.final_channel_state.balance_state.enc_balances[1] =
            witness.close.final_channel_state.balance_state.enc_balances[0].clone();
        assert_ne!(
            honest_root,
            witness
                .close
                .final_channel_state
                .balance_state
                .slot_tree_root(),
            "precondition: the mutation must change the slot tree root"
        );

        let result = fx
            .close_circuit
            .fill_witness(&public_inputs, &witness)
            .map(|pw| {
                catch_unwind(AssertUnwindSafe(|| fx.close_circuit.data.prove(pw)))
                    .map_err(|_| ())
                    .and_then(|r| r.map(|_| ()).map_err(|_| ()))
            });
        assert!(
            !matches!(result, Ok(Ok(()))),
            "a witnessed slot_tree_root diverging from the signed H1 must make the close unprovable"
        );
    }
}
