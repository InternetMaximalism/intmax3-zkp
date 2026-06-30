//! Corrected cancelClose circuit (Phase C1).
//!
//! Proves: the registered channel members N-of-N signed a channel state (IMCH) at a
//! `state_version` STRICTLY GREATER than the pending close's `final_state_version` ⇒ the members
//! agreed to keep operating ⇒ the pending close froze a stale state ⇒ cancel. See
//! `tasks/phase-c-challenge-stubs-threat-model.md` ("CORRECTED cancelClose statement") and
//! `cancel_close_pis.rs` for the layout/security rationale. This mirrors `close_circuit.rs`'s
//! proven machinery (IMCH/H1 recompute, recursive `ListCircuit` member-sig verification,
//! `member_set_commitment` keccak with pad-to-MAX + active-bits + pk_g distinctness) and fixes the
//! two findings the legacy 41-limb design failed on:
//!
//!  - Finding D (member binding): `member_set_commitment` is exposed and matched on L1 against the
//!    channel's registered member set, so a third party cannot forge a cancel with their own keys.
//!  - Finding B (staleness): `revived_state_version > close.final_state_version` is enforced
//!    in-circuit (u64 strict-greater via `U64Target::is_lt`), with the operands anchored inside the
//!    revived IMCH (via H1) and the recomputed `close_intent_digest` respectively.
//!  - Finding C (era fence): `revived.close_freeze_nonce + 1 == close.close_freeze_nonce` (kept;
//!    not relaxed to `>=`).

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
use thiserror::Error;

use crate::{
    circuits::channel::cancel_close_pis::{
        CANCEL_CLOSE_PUBLIC_INPUTS_LEN, CancelClosePublicInputs, CancelCloseWitness,
        CancelCloseWitnessError,
    },
    common::{balance_state::BALANCE_STATE_DOMAIN, channel::close_member_set_commitment},
    constants::{MAX_CHANNEL_MEMBERS, MEMBER_DISTINCTNESS_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::{U64, U64Target},
        u256::{U256, U256Target},
    },
    poseidon_sig::list::{chain_step_target, leaf_target},
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_conditionally_verify,
        trees::indexed_merkle_tree::{
            IndexedMerkleTree,
            insertion::{IndexedInsertionProof, IndexedInsertionProofTarget},
        },
    },
};

// Domain constants — MUST equal the native ones in `common::channel` / `common::balance_state`.
const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348; // "IMCH"
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349; // "IMCI"
const CLOSE_WITHDRAWAL_DOMAIN: u32 = 0x494d434c; // "IMCL"
const CANCEL_MEMBER_SET_DOMAIN: u32 = 0x494d434d; // "IMCM" (same as the close member-set domain)

/// In-circuit public-input targets for the cancel-close statement. Every limb is 32-bit
/// range-checked: the limbs feed keccak preimages and the keccak gadget does NOT range-check its
/// inputs.
#[derive(Clone)]
pub struct CancelClosePublicInputsTarget {
    pub channel_id: [Target; 1],
    pub close_intent_digest: Bytes32Target,
    pub member_set_commitment: Bytes32Target,
    pub revived_state_version: U64Target,
    pub revived_channel_state_digest: Bytes32Target,
}

impl CancelClosePublicInputsTarget {
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
            close_intent_digest: Bytes32Target::new(builder, true),
            member_set_commitment: Bytes32Target::new(builder, true),
            revived_state_version: U64Target::new(builder, true),
            revived_channel_state_digest: Bytes32Target::new(builder, true),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let v = [
            self.channel_id.to_vec(),
            self.close_intent_digest.to_vec(),
            self.member_set_commitment.to_vec(),
            self.revived_state_version.to_vec(),
            self.revived_channel_state_digest.to_vec(),
        ]
        .concat();
        debug_assert_eq!(v.len(), CANCEL_CLOSE_PUBLIC_INPUTS_LEN);
        v
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &CancelClosePublicInputs,
    ) {
        witness
            .set_target(
                self.channel_id[0],
                F::from_canonical_u64(value.channel_id.to_u64_vec()[0]),
            )
            .unwrap();
        self.close_intent_digest
            .set_witness(witness, value.close_intent_digest);
        self.member_set_commitment
            .set_witness(witness, value.member_set_commitment);
        self.revived_state_version
            .set_witness(witness, U64::from(value.revived_state_version));
        self.revived_channel_state_digest
            .set_witness(witness, value.revived_channel_state_digest);
    }
}

#[derive(Debug, Error)]
pub enum CancelCloseCircuitError {
    #[error("witness error: {0}")]
    Witness(#[from] CancelCloseWitnessError),
    #[error("invalid member auth: {0}")]
    InvalidMemberAuth(String),
    #[error("failed to prove: {0}")]
    FailedToProve(String),
}

/// Per-member authentication material for the revived state's N-of-N signatures (mirror of
/// `close_circuit::MemberCloseAuth`).
#[derive(Clone, Debug)]
pub struct MemberCancelAuth {
    pub pk_g: Bytes32,
}

/// Full prover witness: the cancel witness (revived state + close intent), the per-member `pk_g`s,
/// and the recursive `ListCircuit` proof over the N member single-sigs of the revived IMCH digest.
#[derive(Clone, Debug)]
pub struct CancelCloseFullWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub cancel: CancelCloseWitness,
    /// Exactly `member_count` ACTIVE entries (slot order) — ALL active members sign the revived
    /// IMCH digest (unanimous; mirrors the close path).
    pub member_auth: Vec<MemberCancelAuth>,
    /// The recursive `poseidon_sig::list::ListCircuit` proof over the N member single-sigs of the
    /// revived IMCH digest. Its commitment `C` must equal the circuit's rebuilt `C'`.
    pub list_proof: ProofWithPublicInputs<F, C, D>,
}

/// Native mirror of the in-circuit member-set commitment (byte-identical to the close path).
fn member_set_commitment_for_auth(member_auth: &[MemberCancelAuth]) -> Bytes32 {
    let hashes: [Bytes32; MAX_CHANNEL_MEMBERS] =
        std::array::from_fn(|i| member_auth.get(i).map(|a| a.pk_g).unwrap_or_default());
    close_member_set_commitment(&hashes, member_auth.len() as u8)
}

pub struct CancelCloseCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub public_inputs: CancelClosePublicInputsTarget,

    // ── revived ChannelState auxiliary fields (drive the IMCH/H1 recompute) ──
    revived_member_count: Target,
    revived_delegate_count: Target,
    revived_epoch: U64Target,
    revived_small_block_number: U64Target,
    revived_close_freeze_nonce: U64Target,
    revived_channel_fund_amount: U256Target,
    revived_channel_fund_intmax_state_root: Bytes32Target,
    revived_balance_state_h1: Bytes32Target,
    revived_shared_native_nullifier_root: Bytes32Target,
    revived_unallocated_confirmed_incoming: U256Target,
    revived_prev_digest: Bytes32Target,
    revived_h2_tag: Bytes32Target,
    revived_settled_tx_chain: Bytes32Target,
    revived_settled_tx_accumulator_root: Bytes32Target,
    revived_enc_balance_digests: Vec<Bytes32Target>,
    revived_regev_pk_digests: Vec<Bytes32Target>,
    revived_pending_adds: Vec<Target>,

    // ── close CloseIntent auxiliary fields (drive the IMCI recompute) ──
    close_nonce: U64Target,
    close_final_epoch: U64Target,
    close_final_small_block_number: U64Target,
    close_freeze_nonce: U64Target,
    close_final_channel_state_digest: Bytes32Target,
    close_final_balance_state_h1: Bytes32Target,
    close_channel_fund_amount: U256Target,
    close_channel_fund_intmax_state_root: Bytes32Target,
    close_burn_tx_hash: Bytes32Target,
    close_withdrawal_digest: Bytes32Target,
    close_snapshot_medium_block_number: U64Target,
    close_final_state_version: U64Target,
    close_final_settled_tx_chain: Bytes32Target,

    // ── member auth / list proof ──
    list_proof: ProofWithPublicInputsTarget<D>,
    member_pk_g_targets: Vec<Bytes32Target>,
    active_bits: Vec<plonky2::iop::target::BoolTarget>,
    /// A5 pk_g distinctness: per-slot indexed-Merkle insertion proofs (length MAX_CHANNEL_MEMBERS).
    /// Filled in `fill_witness` by inserting active pk_g in slot order into a fresh tree (padding
    /// slots get a dummy proof). The in-circuit chain asserts each active key's non-membership.
    member_insertion_proofs: Vec<IndexedInsertionProofTarget>,
}

impl<F, C, const D: usize> CancelCloseCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Builds the cancel-close circuit against a FIXED `ListCircuit` verifier key (`list_vd`),
    /// baked in as a build-time constant. No balance proof is verified — the revived IMCH digest
    /// (which hashes H1, which hashes `state_version`) is what the members sign, and that is the
    /// sole anchor the staleness predicate needs.
    pub fn new(list_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = CancelClosePublicInputsTarget::new(&mut builder);
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };

        // ── revived ChannelState auxiliary targets ──
        let revived_member_count = u32_limb(&mut builder);
        let revived_delegate_count = u32_limb(&mut builder);
        let revived_epoch = U64Target::new(&mut builder, true);
        let revived_small_block_number = U64Target::new(&mut builder, true);
        let revived_close_freeze_nonce = U64Target::new(&mut builder, true);
        let revived_channel_fund_amount = U256Target::new(&mut builder, true);
        let revived_channel_fund_intmax_state_root = Bytes32Target::new(&mut builder, true);
        let revived_shared_native_nullifier_root = Bytes32Target::new(&mut builder, true);
        let revived_unallocated_confirmed_incoming = U256Target::new(&mut builder, true);
        let revived_prev_digest = Bytes32Target::new(&mut builder, true);
        let revived_h2_tag = Bytes32Target::new(&mut builder, true);
        let revived_settled_tx_chain = Bytes32Target::new(&mut builder, true);
        let revived_settled_tx_accumulator_root = Bytes32Target::new(&mut builder, true);
        let revived_enc_balance_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let revived_regev_pk_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let revived_pending_adds: Vec<Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| u32_limb(&mut builder))
            .collect();

        // ── close CloseIntent auxiliary targets ──
        let close_nonce = U64Target::new(&mut builder, true);
        let close_final_epoch = U64Target::new(&mut builder, true);
        let close_final_small_block_number = U64Target::new(&mut builder, true);
        let close_freeze_nonce = U64Target::new(&mut builder, true);
        let close_final_channel_state_digest = Bytes32Target::new(&mut builder, true);
        let close_final_balance_state_h1 = Bytes32Target::new(&mut builder, true);
        let close_channel_fund_amount = U256Target::new(&mut builder, true);
        let close_channel_fund_intmax_state_root = Bytes32Target::new(&mut builder, true);
        let close_burn_tx_hash = Bytes32Target::new(&mut builder, true);
        let close_withdrawal_digest = Bytes32Target::new(&mut builder, true);
        let close_snapshot_medium_block_number = U64Target::new(&mut builder, true);
        let close_final_state_version = U64Target::new(&mut builder, true);
        let close_final_settled_tx_chain = Bytes32Target::new(&mut builder, true);

        let zero_t = builder.zero();
        let one = builder.one();

        // ── D6 per-slot activeness flags for the revived member set (mirror of the close path) ──
        let mut active_bits: Vec<plonky2::iop::target::BoolTarget> =
            Vec::with_capacity(MAX_CHANNEL_MEMBERS);
        for _ in 0..MAX_CHANNEL_MEMBERS {
            active_bits.push(builder.add_virtual_bool_target_safe());
        }
        for i in 0..MAX_CHANNEL_MEMBERS - 1 {
            let one_minus_prev = builder.sub(one, active_bits[i].target);
            let prod = builder.mul(active_bits[i + 1].target, one_minus_prev);
            builder.connect(prod, zero_t);
        }
        let mut count_sum = builder.zero();
        for bit in &active_bits {
            count_sum = builder.add(count_sum, bit.target);
        }
        builder.connect(count_sum, revived_member_count);

        // `unallocated_confirmed_incoming` is part of the IMCH preimage; the revived state may have
        // a non-zero value (it is not a close), so we DO NOT force it to zero here (unlike the
        // close circuit). It is hashed into the IMCH as-is.

        let balance_state_domain = builder.constant(F::from_canonical_u32(BALANCE_STATE_DOMAIN));
        let channel_state_domain = builder.constant(F::from_canonical_u32(CHANNEL_STATE_DOMAIN));
        let close_intent_domain = builder.constant(F::from_canonical_u32(CLOSE_INTENT_DOMAIN));
        let close_withdrawal_domain =
            builder.constant(F::from_canonical_u32(CLOSE_WITHDRAWAL_DOMAIN));

        // ── (a) revived H1 recompute (IMBS) — byte-identical to `BalanceState::h1` ──
        //
        // SECURITY: anchors `revived_state_version` and the member/delegate counts as the unique
        // values inside the signed H1. The SAME `revived_state_version` PI target feeds the H1
        // preimage AND the strict-greater comparison below, so the version proven newer is exactly
        // the one the members signed.
        let revived_h1_inputs = [
            vec![balance_state_domain],
            public_inputs.channel_id.to_vec(),
            vec![revived_member_count],
            vec![revived_delegate_count],
            revived_regev_pk_digests
                .iter()
                .flat_map(Bytes32Target::to_vec)
                .collect::<Vec<_>>(),
            revived_enc_balance_digests
                .iter()
                .flat_map(Bytes32Target::to_vec)
                .collect::<Vec<_>>(),
            revived_settled_tx_chain.to_vec(),
            revived_settled_tx_accumulator_root.to_vec(),
            public_inputs.revived_state_version.to_vec(),
            revived_pending_adds.clone(),
        ]
        .concat();
        let revived_balance_state_h1 =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&revived_h1_inputs));

        // ── (b) revived IMCH recompute (`ChannelState::signing_digest`) ──
        let revived_state_digest_inputs = [
            vec![channel_state_domain],
            public_inputs.channel_id.to_vec(),
            revived_epoch.to_vec(),
            revived_small_block_number.to_vec(),
            revived_close_freeze_nonce.to_vec(),
            public_inputs.channel_id.to_vec(),
            revived_channel_fund_amount.to_vec(),
            revived_channel_fund_intmax_state_root.to_vec(),
            revived_balance_state_h1.to_vec(),
            revived_shared_native_nullifier_root.to_vec(),
            revived_unallocated_confirmed_incoming.to_vec(),
            revived_prev_digest.to_vec(),
            revived_h2_tag.to_vec(),
            public_inputs.revived_state_version.to_vec(),
        ]
        .concat();
        let revived_state_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&revived_state_digest_inputs));
        revived_state_digest.connect(&mut builder, public_inputs.revived_channel_state_digest);

        // ── (c) close IMCL recompute (`CloseWithdrawal::signing_digest`) → close_withdrawal_digest
        // ──
        let close_withdrawal_inputs = [
            vec![close_withdrawal_domain],
            public_inputs.channel_id.to_vec(),
            close_final_channel_state_digest.to_vec(),
            close_final_balance_state_h1.to_vec(),
            close_channel_fund_intmax_state_root.to_vec(),
            close_burn_tx_hash.to_vec(),
            close_channel_fund_amount.to_vec(),
        ]
        .concat();
        let recomputed_close_withdrawal_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_withdrawal_inputs));
        recomputed_close_withdrawal_digest.connect(&mut builder, close_withdrawal_digest);

        // ── (d) close IMCI recompute (`CloseIntent::signing_digest`) → close_intent_digest PI ──
        //
        // SECURITY: this is the Finding-B/era-fence anchor. `close_final_state_version` and
        // `close_freeze_nonce` are the SAME wires used in the staleness comparison and era fence
        // below, AND they are hashed into `close_intent_digest`, which the manager binds against
        // `pendingClose.closeIntentDigest`. So the prover cannot supply a real close digest while
        // using a different (lower) version or wrong era in the comparison.
        let close_intent_inputs = [
            vec![close_intent_domain],
            public_inputs.channel_id.to_vec(),
            close_nonce.to_vec(),
            close_final_epoch.to_vec(),
            close_final_small_block_number.to_vec(),
            close_freeze_nonce.to_vec(),
            close_final_channel_state_digest.to_vec(),
            close_final_balance_state_h1.to_vec(),
            public_inputs.channel_id.to_vec(),
            close_channel_fund_amount.to_vec(),
            close_channel_fund_intmax_state_root.to_vec(),
            close_burn_tx_hash.to_vec(),
            close_withdrawal_digest.to_vec(),
            close_snapshot_medium_block_number.to_vec(),
            close_final_state_version.to_vec(),
            close_final_settled_tx_chain.to_vec(),
        ]
        .concat();
        let recomputed_close_intent_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_intent_inputs));
        recomputed_close_intent_digest.connect(&mut builder, public_inputs.close_intent_digest);

        // ── (e) Finding B: revived_state_version > close_final_state_version (strict) ──
        //
        // `a > b` ⟺ `b < a`. `U64Target::is_lt` is the U64-correct comparator (both limbs,
        // internal range-check, `[hi, lo]` lexicographic order).
        let revived_gt_close =
            close_final_state_version.is_lt(&mut builder, &public_inputs.revived_state_version);
        builder.assert_one(revived_gt_close.target);

        // ── (f) Finding C: era fence revived.close_freeze_nonce + 1 == close.close_freeze_nonce ──
        let one_u64 = U64Target::constant(&mut builder, U64::from(1u64));
        let revived_nonce_plus_one = revived_close_freeze_nonce.add(&mut builder, &one_u64);
        revived_nonce_plus_one.connect(&mut builder, close_freeze_nonce);

        // ── (g) N-member revived-IMCH signatures via the recursive ListCircuit proof ──
        let member_set_domain = builder.constant(F::from_canonical_u32(CANCEL_MEMBER_SET_DOMAIN));
        let mut member_set_inputs: Vec<Target> = vec![member_set_domain, revived_member_count];

        let member_pk_g_targets: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();

        for (i, is_active) in active_bits.iter().enumerate() {
            for &limb in &member_pk_g_targets[i].to_vec() {
                let selected = builder.select(*is_active, limb, zero_t);
                member_set_inputs.push(selected);
            }
        }

        let always = builder._true();
        let list_proof = add_proof_target_and_conditionally_verify(list_vd, &mut builder, always);
        let committed_c = Bytes32Target::from_slice(&list_proof.public_inputs[0..BYTES32_LEN]);

        // Rebuild C' = fold (revived_state_digest, pk_g_i) over ACTIVE slots only.
        let mut chain = PoseidonHashOutTarget::constant(&mut builder, PoseidonHashOut::default());
        for (i, is_active) in active_bits.iter().enumerate() {
            let leaf = leaf_target(&mut builder, &revived_state_digest, &member_pk_g_targets[i]);
            let stepped = chain_step_target(&mut builder, chain.clone(), leaf);
            chain = PoseidonHashOutTarget::select(&mut builder, *is_active, stepped, chain);
        }
        let rebuilt_c = Bytes32Target::from_hash_out(&mut builder, chain);
        rebuilt_c.connect(&mut builder, committed_c);

        // ── pk_g distinctness over the ACTIVE set (A5: one key cannot fake N signatures) ──
        //
        // Replaces the former O(MAX^2) all-pairs equality loop with an O(MAX·height) indexed-Merkle
        // insertion chain proving the SAME property (no two active slots share a pk_g). See the
        // matching block in `close_circuit.rs` for the full rationale; identical mechanism here.
        //
        // SECURITY: the inserted keys are EXACTLY `member_pk_g_targets` (the same targets used by
        // the member_set_commitment keccak and the C' fold), converted limb-for-limb to a
        // `U256Target` (both are `[Target; 8]`, no `remove_3bits` masking). The active gating uses
        // the SAME `active_bits`; padding slots are skipped. The insertion gadget asserts
        // `prev_low.key < key < next_key (or 0)` per active insert = non-membership = distinctness,
        // so a duplicate active pk_g is UNSATISFIABLE. The final root is intentionally discarded.
        // INTENTIONALLY SIMPLE: inserted `value` is a constant 1 (irrelevant to distinctness).
        let member_insertion_proofs: Vec<IndexedInsertionProofTarget> = (0..MAX_CHANNEL_MEMBERS)
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
            revived_member_count,
            revived_delegate_count,
            revived_epoch,
            revived_small_block_number,
            revived_close_freeze_nonce,
            revived_channel_fund_amount,
            revived_channel_fund_intmax_state_root,
            revived_balance_state_h1,
            revived_shared_native_nullifier_root,
            revived_unallocated_confirmed_incoming,
            revived_prev_digest,
            revived_h2_tag,
            revived_settled_tx_chain,
            revived_settled_tx_accumulator_root,
            revived_enc_balance_digests,
            revived_regev_pk_digests,
            revived_pending_adds,
            close_nonce,
            close_final_epoch,
            close_final_small_block_number,
            close_freeze_nonce,
            close_final_channel_state_digest,
            close_final_balance_state_h1,
            close_channel_fund_amount,
            close_channel_fund_intmax_state_root,
            close_burn_tx_hash,
            close_withdrawal_digest,
            close_snapshot_medium_block_number,
            close_final_state_version,
            close_final_settled_tx_chain,
            list_proof,
            member_pk_g_targets,
            active_bits,
            member_insertion_proofs,
        }
    }

    /// Fills the full partial witness. Tests use this directly (bypassing the native mirrors in
    /// [`Self::prove`]) to exercise the in-circuit constraints against tampered public inputs.
    fn fill_witness(
        &self,
        public_inputs: &CancelClosePublicInputs,
        witness_value: &CancelCloseFullWitness<F, C, D>,
    ) -> Result<PartialWitness<F>, CancelCloseCircuitError> {
        let revived = &witness_value.cancel.revived_state;
        let close = &witness_value.cancel.close_intent;
        let member_count = revived.balance_state.member_count as usize;
        if !(2..=MAX_CHANNEL_MEMBERS).contains(&member_count) {
            return Err(CancelCloseCircuitError::InvalidMemberAuth(format!(
                "member_count {member_count} out of range (must be 2..={MAX_CHANNEL_MEMBERS})"
            )));
        }
        if witness_value.member_auth.len() != member_count {
            return Err(CancelCloseCircuitError::InvalidMemberAuth(format!(
                "expected {member_count} active member signatures, got {}",
                witness_value.member_auth.len()
            )));
        }
        let mut witness = PartialWitness::<F>::new();
        for (i, bit) in self.active_bits.iter().enumerate() {
            witness.set_bool_target(*bit, i < member_count).unwrap();
        }
        // member_set_commitment is honored AS GIVEN — the in-circuit keccak constrains it, so a
        // tampered commitment PI is rejected at proving (tests exercise the rejection).
        self.public_inputs.set_witness(&mut witness, public_inputs);

        // revived ChannelState fields.
        witness
            .set_target(
                self.revived_member_count,
                F::from_canonical_u8(revived.balance_state.member_count),
            )
            .unwrap();
        witness
            .set_target(
                self.revived_delegate_count,
                F::from_canonical_u8(revived.balance_state.delegate_count),
            )
            .unwrap();
        self.revived_epoch
            .set_witness(&mut witness, U64::from(revived.epoch));
        self.revived_small_block_number
            .set_witness(&mut witness, U64::from(revived.small_block_number));
        self.revived_close_freeze_nonce
            .set_witness(&mut witness, U64::from(revived.close_freeze_nonce));
        self.revived_channel_fund_amount
            .set_witness(&mut witness, revived.channel_fund.amount);
        self.revived_channel_fund_intmax_state_root
            .set_witness(&mut witness, revived.channel_fund.intmax_state_root);
        self.revived_shared_native_nullifier_root
            .set_witness(&mut witness, revived.shared_native_nullifier_root);
        self.revived_unallocated_confirmed_incoming
            .set_witness(&mut witness, revived.unallocated_confirmed_incoming);
        self.revived_prev_digest
            .set_witness(&mut witness, revived.prev_digest);
        self.revived_h2_tag
            .set_witness(&mut witness, revived.h2_tag);
        self.revived_settled_tx_chain
            .set_witness(&mut witness, revived.balance_state.settled_tx_chain);
        self.revived_settled_tx_accumulator_root.set_witness(
            &mut witness,
            revived.balance_state.settled_tx_accumulator_root,
        );
        // `revived_balance_state_h1` is a derived (keccak-output) target — not a virtual input — so
        // it is not set here; it is computed by the circuit.
        let _ = &self.revived_balance_state_h1;
        for (target, ciphertext) in self
            .revived_enc_balance_digests
            .iter()
            .zip(revived.balance_state.enc_balances.iter())
        {
            target.set_witness(&mut witness, ciphertext.digest());
        }
        for (target, digest) in self
            .revived_regev_pk_digests
            .iter()
            .zip(revived.balance_state.regev_pk_digests.iter())
        {
            target.set_witness(&mut witness, *digest);
        }
        for (target, &adds) in self
            .revived_pending_adds
            .iter()
            .zip(revived.balance_state.pending_adds.iter())
        {
            witness
                .set_target(*target, F::from_canonical_u32(adds))
                .unwrap();
        }

        // close CloseIntent fields.
        self.close_nonce
            .set_witness(&mut witness, U64::from(close.close_nonce));
        self.close_final_epoch
            .set_witness(&mut witness, U64::from(close.final_epoch));
        self.close_final_small_block_number
            .set_witness(&mut witness, U64::from(close.final_small_block_number));
        self.close_freeze_nonce
            .set_witness(&mut witness, U64::from(close.close_freeze_nonce));
        self.close_final_channel_state_digest
            .set_witness(&mut witness, close.final_channel_state_digest);
        self.close_final_balance_state_h1
            .set_witness(&mut witness, close.final_balance_state_h1);
        self.close_channel_fund_amount
            .set_witness(&mut witness, close.channel_fund_snapshot.amount);
        self.close_channel_fund_intmax_state_root
            .set_witness(&mut witness, close.channel_fund_snapshot.intmax_state_root);
        self.close_burn_tx_hash
            .set_witness(&mut witness, close.burn_tx_hash);
        self.close_withdrawal_digest
            .set_witness(&mut witness, close.close_withdrawal_digest);
        self.close_snapshot_medium_block_number
            .set_witness(&mut witness, U64::from(close.snapshot_medium_block_number));
        self.close_final_state_version
            .set_witness(&mut witness, U64::from(close.final_state_version));
        self.close_final_settled_tx_chain
            .set_witness(&mut witness, close.final_settled_tx_chain);

        // list proof.
        witness
            .set_proof_with_pis_target(&self.list_proof, &witness_value.list_proof)
            .map_err(|e| CancelCloseCircuitError::FailedToProve(e.to_string()))?;

        // per-slot member pk_g (active slots = the member's pk_g; padding slots = default).
        for (slot, pk_g_target) in self.member_pk_g_targets.iter().enumerate() {
            let pk_g = if slot < member_count {
                witness_value.member_auth[slot].pk_g
            } else {
                Bytes32::default()
            };
            pk_g_target.set_witness(&mut witness, pk_g);
        }

        // A5 pk_g distinctness witness: insert each ACTIVE pk_g IN SLOT ORDER into a fresh
        // IndexedMerkleTree (same order/values as `member_pk_g_targets` / member_set_commitment /
        // C' fold). A DUPLICATE active pk_g makes `prove_and_insert` return `Err(KeyAlreadyExists)`
        // (no valid low-leaf) → surfaced as a proving failure; there is no witness satisfying the
        // in-circuit non-membership bound for a repeated key. Padding slots get a dummy proof whose
        // gated assertions are skipped in-circuit.
        let mut distinctness_tree = IndexedMerkleTree::new(MEMBER_DISTINCTNESS_TREE_HEIGHT);
        for (slot, insertion_target) in self.member_insertion_proofs.iter().enumerate() {
            let insertion_proof: IndexedInsertionProof = if slot < member_count {
                let pk_g = witness_value.member_auth[slot].pk_g;
                let key: U256 = pk_g.into();
                // value MUST equal the circuit-side `distinctness_value` (constant 1, ~line 474):
                // the native leaf hash folds `value`, so any other value desyncs the witnessed
                // merkle root from the in-circuit recomputation ("Wire set twice"). Irrelevant to
                // distinctness (only the KEY matters), so 1 on both sides.
                distinctness_tree
                    .prove_and_insert(key, 1u64)
                    .map_err(|e| {
                        CancelCloseCircuitError::InvalidMemberAuth(format!(
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
        witness_value: &CancelCloseFullWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, CancelCloseCircuitError> {
        let member_count = witness_value
            .cancel
            .revived_state
            .balance_state
            .member_count as usize;
        if witness_value.member_auth.len() != member_count {
            return Err(CancelCloseCircuitError::InvalidMemberAuth(format!(
                "expected {member_count} active member signatures, got {}",
                witness_value.member_auth.len()
            )));
        }
        let mut public_inputs = witness_value.cancel.to_public_inputs()?;
        // Fill the member-set commitment from the verified active signing keys (the in-circuit
        // keccak constrains it).
        public_inputs.member_set_commitment =
            member_set_commitment_for_auth(&witness_value.member_auth);

        let witness = self.fill_witness(&public_inputs, witness_value)?;
        self.data
            .prove(witness)
            .map_err(|e| CancelCloseCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(any(test, feature = "cancel-close-fixture-bin"))]
pub mod test_fixture {
    //! Shared heavy artifacts for the cancel-close-circuit tests and the fixture-gen binary: ONE
    //! `SingleSigCircuit` + `ListCircuit` + `CancelCloseCircuit` build per test-binary run.

    use std::sync::OnceLock;

    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
    };

    use super::{CancelCloseCircuit, CancelCloseFullWitness, MemberCancelAuth};
    use crate::{
        circuits::channel::cancel_close_pis::CancelCloseWitness,
        common::{
            balance_state::BalanceState,
            channel::{
                ChannelFund, ChannelId, ChannelState, CloseIntent, CloseWithdrawal, MemberSignature,
            },
        },
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
        poseidon_sig::{
            GoldilocksSecretKey,
            circuit::SingleSigCircuit,
            list::{ListCircuit, list_commitment},
        },
        regev::{REGEV_N, REGEV_Q, RegevCiphertext},
    };

    pub const D: usize = 2;
    pub type F = GoldilocksField;
    pub type C = PoseidonGoldilocksConfig;

    /// Active member count used by the cancel-close test suite (pad-to-MAX D6).
    pub const TEST_ACTIVE_MEMBERS: usize = 3;

    pub struct CancelCloseCircuitFixture {
        pub single_sig: SingleSigCircuit,
        pub list: ListCircuit,
        pub cancel_circuit: CancelCloseCircuit<F, C, D>,
    }

    pub fn fixture() -> &'static CancelCloseCircuitFixture {
        static FIXTURE: OnceLock<CancelCloseCircuitFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let single_sig = SingleSigCircuit::new();
            let list = ListCircuit::new(&single_sig.verifier_data());
            let cancel_circuit = CancelCloseCircuit::<F, C, D>::new(&list.verifier_data());
            CancelCloseCircuitFixture {
                single_sig,
                list,
                cancel_circuit,
            }
        })
    }

    /// The built cancel-close circuit (for the fixture-gen binary; mirrors
    /// `post_close_claim_circuit::test_fixture::circuit`).
    pub fn circuit() -> &'static CancelCloseCircuit<F, C, D> {
        &fixture().cancel_circuit
    }

    fn cancel_member_sk(seed: u64, slot: usize) -> GoldilocksSecretKey {
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&seed.to_le_bytes());
        s[8] = 0xca;
        s[31] = slot as u8 + 1;
        GoldilocksSecretKey::from_seed(s)
    }

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

    /// Member auth + the recursive `ListCircuit` proof for `active` members each signing the given
    /// revived IMCH `digest` (slot order). Mirrors the close-circuit helper.
    pub fn member_auth_for_digest_n(
        digest: Bytes32,
        seed: u64,
        active: usize,
    ) -> (Vec<MemberCancelAuth>, ProofWithPublicInputs<F, C, D>) {
        let fx = fixture();
        let sks: Vec<GoldilocksSecretKey> =
            (0..active).map(|i| cancel_member_sk(seed, i)).collect();
        let member_auth: Vec<MemberCancelAuth> = sks
            .iter()
            .map(|sk| MemberCancelAuth {
                pk_g: sk.public_key(),
            })
            .collect();
        let pairs: Vec<(Bytes32, Bytes32)> =
            sks.iter().map(|sk| (digest, sk.public_key())).collect();
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

    /// Builds a revived `ChannelState` at `(revived_era_nonce, revived_version)` whose member set
    /// is the `active` signing keys, plus a `CloseIntent` built off a closing state at
    /// `(closing_era_nonce, close_version)`. The era fence holds iff `revived_era_nonce ==
    /// closing_era_nonce` (since `CloseIntent::new` advances the closing nonce by +1). Returns the
    /// full prover witness. For a VALID cancel pass equal era nonces and `revived_version >
    /// close_version`.
    pub fn build_full_witness_n(
        active: usize,
        revived_era_nonce: u64,
        closing_era_nonce: u64,
        revived_version: u64,
        close_version: u64,
    ) -> CancelCloseFullWitness<F, C, D> {
        let channel_id = ChannelId::new(3).unwrap();
        let close_freeze_nonce = revived_era_nonce;
        // member pk_g hashes are stored as the regev_pk_digests slots so the H1 is non-degenerate;
        // not load-bearing for the cancel statement (only the IMCH digest the members sign
        // matters).
        let revived_state = ChannelState {
            channel_id,
            epoch: 8,
            small_block_number: 4,
            close_freeze_nonce,
            channel_fund: ChannelFund {
                channel_id,
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: BalanceState {
                channel_id,
                member_count: active as u8,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances(
                    &(0..active)
                        .map(|i| ciphertext(i as u32 + 1))
                        .collect::<Vec<_>>(),
                ),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                settled_tx_chain: Bytes32::default(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: revived_version,
                pending_adds: BalanceState::pad_pending_adds(&vec![0u32; active]),
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                pk_g: Bytes32::default(),
                signature: vec![1],
            }],
        }
        .with_computed_digest();

        // The state that was closed: `closing_era_nonce` era, lower version. When
        // `closing_era_nonce == revived_era_nonce` the era fence holds.
        let closing_state = ChannelState {
            close_freeze_nonce: closing_era_nonce,
            balance_state: BalanceState {
                state_version: close_version,
                ..revived_state.balance_state.clone()
            },
            digest: Bytes32::default(),
            ..revived_state.clone()
        }
        .with_computed_digest();
        let close_withdrawal = CloseWithdrawal {
            channel_id,
            final_channel_state_digest: closing_state.digest,
            final_balance_state_h1: closing_state.balance_state.h1(),
            intmax_state_root: closing_state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: closing_state.channel_fund.amount,
            zkp: vec![7],
        };
        let close_intent = CloseIntent::new(5, &closing_state, &close_withdrawal, 123).unwrap();

        let (member_auth, list_proof) =
            member_auth_for_digest_n(revived_state.signing_digest(), seed_for(active), active);

        CancelCloseFullWitness {
            cancel: CancelCloseWitness {
                revived_state,
                close_intent,
            },
            member_auth,
            list_proof,
        }
    }

    fn seed_for(_active: usize) -> u64 {
        0xca_1107
    }

    /// Default valid full witness (TEST_ACTIVE_MEMBERS members, era nonce 0, revived version 9 >
    /// close version 7).
    pub fn build_full_witness() -> CancelCloseFullWitness<F, C, D> {
        build_full_witness_n(TEST_ACTIVE_MEMBERS, 0, 0, 9, 7)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::PrimeField64;

    use super::test_fixture::{
        build_full_witness, build_full_witness_n, fixture, member_auth_for_digest_n,
    };
    use crate::{
        circuits::channel::cancel_close_pis::{
            CANCEL_CLOSE_PUBLIC_INPUTS_LEN, CancelClosePublicInputs,
        },
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    };

    #[test]
    fn cancel_close_circuit_proves_and_pi_matches() {
        let fx = fixture();
        let witness = build_full_witness();
        let proof = fx.cancel_circuit.prove(&witness).expect("prove");
        fx.cancel_circuit
            .data
            .verify(proof.clone())
            .expect("verify");

        let limbs: Vec<u64> = proof.public_inputs[0..CANCEL_CLOSE_PUBLIC_INPUTS_LEN]
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        let pis = CancelClosePublicInputs::from_u64_slice(&limbs).expect("decode pis");
        let expected = witness.cancel.to_public_inputs().expect("native pis");
        assert_eq!(pis.channel_id, expected.channel_id);
        assert_eq!(pis.close_intent_digest, expected.close_intent_digest);
        assert_eq!(pis.revived_state_version, expected.revived_state_version);
        assert_eq!(
            pis.revived_channel_state_digest,
            expected.revived_channel_state_digest
        );
        // member_set_commitment is non-default (filled from member_auth).
        assert_ne!(pis.member_set_commitment, Bytes32::default());
    }

    #[test]
    fn cancel_close_circuit_rejects_stale_revived_version() {
        // revived version 5 <= close version 7 → the native to_public_inputs rejects, and even if
        // bypassed the in-circuit strict-greater fails. Here we assert the native guard fires
        // (prove() routes through to_public_inputs).
        let fx = fixture();
        let witness = build_full_witness_n(3, 0, 0, 5, 7);
        let err = fx.cancel_circuit.prove(&witness).err();
        assert!(err.is_some(), "stale revived version must be rejected");
    }

    #[test]
    fn cancel_close_circuit_rejects_wrong_era_fence() {
        // Genuine era mismatch: revived era nonce 0 (so revived.close_freeze_nonce + 1 = 1) but the
        // close was built off era nonce 5 (so close.close_freeze_nonce = 6). 1 != 6 → rejection.
        // First confirm the native guard fires via prove().
        let fx = fixture();
        let witness = build_full_witness_n(3, 0, 5, 9, 7);
        let err = fx.cancel_circuit.prove(&witness).err();
        assert!(
            err.is_some(),
            "wrong era fence must be rejected (native guard)"
        );

        // Now bypass the native guard (fill_witness directly with a hand-built PI carrying the real
        // recomputed digests) to confirm the IN-CIRCUIT era fence catches it independently. We
        // build the PI from the close intent + revived state directly (skipping to_public_inputs's
        // era check) and prove the raw circuit.
        let close = &witness.cancel.close_intent;
        let revived = &witness.cancel.revived_state;
        let pis = CancelClosePublicInputs {
            channel_id: close.channel_id,
            close_intent_digest: close.signing_digest(),
            member_set_commitment: super::member_set_commitment_for_auth(&witness.member_auth),
            revived_state_version: revived.balance_state.state_version,
            revived_channel_state_digest: revived.signing_digest(),
        };
        let pw = fx.cancel_circuit.fill_witness(&pis, &witness);
        let proof = pw.and_then(|w| {
            fx.cancel_circuit
                .data
                .prove(w)
                .map_err(|e| super::CancelCloseCircuitError::FailedToProve(e.to_string()))
        });
        assert!(
            proof.is_err(),
            "in-circuit era fence (revived.close_freeze_nonce + 1 == close.close_freeze_nonce) \
             must reject a cross-era revived state"
        );
    }

    #[test]
    fn cancel_close_circuit_rejects_non_registered_member_keys() {
        // Finding D forgery: sign the revived IMCH with ATTACKER keys (a different seed), but claim
        // a member_set_commitment over DIFFERENT keys. The in-circuit member-set keccak binds the
        // commitment to the keys that actually signed, so a mismatched commitment is rejected.
        //
        // Concretely: build a valid witness, then replace the list_proof + member_auth with proofs
        // over attacker keys while keeping the (now-wrong) member_set_commitment PI from the
        // honest auth. The circuit's keccak(attacker pk_g) != claimed commitment → reject.
        let fx = fixture();
        let mut witness = build_full_witness();
        let honest_pis = witness.cancel.to_public_inputs().unwrap();
        let honest_commitment = {
            // member_set_commitment as the circuit would fill from the honest auth.
            super::member_set_commitment_for_auth(&witness.member_auth)
        };
        // Re-sign the SAME revived digest with a different attacker seed.
        let digest = witness.cancel.revived_state.signing_digest();
        let (attacker_auth, attacker_list) = member_auth_for_digest_n(digest, 0xdead_beef, 3);
        witness.member_auth = attacker_auth;
        witness.list_proof = attacker_list;

        // Force the public inputs to keep the HONEST member_set_commitment (the forgery target):
        // attacker keys sign, but the commitment claims the registered (honest) set.
        let mut tampered_pis = honest_pis.clone();
        tampered_pis.member_set_commitment = honest_commitment;
        let pw = fx.cancel_circuit.fill_witness(&tampered_pis, &witness);
        let proof = pw.and_then(|w| {
            fx.cancel_circuit
                .data
                .prove(w)
                .map_err(|e| super::CancelCloseCircuitError::FailedToProve(e.to_string()))
        });
        assert!(
            proof.is_err(),
            "member_set_commitment over non-registered (honest) keys while signing with attacker \
             keys must be rejected (Finding D binding)"
        );
    }

    /// Negative — A5 pk_g distinctness (indexed-Merkle insertion, replacing the former O(MAX²)
    /// all-pairs loop). Two ACTIVE slots sharing a pk_g would let one key satisfy two of the
    /// N-of-N signatures. Duplicate slot 0's full identity (pk_g + valid single-sig) into slot 1 —
    /// isolating distinctness — and confirm the cancel is UNPROVABLE (the repeated key has no valid
    /// low-leaf for insertion).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn cancel_close_circuit_rejects_duplicate_member_pk_g() {
        let fx = fixture();
        let mut witness = build_full_witness();
        assert!(witness.member_auth.len() >= 2, "need >=2 active members");
        assert_ne!(
            witness.member_auth[0].pk_g, witness.member_auth[1].pk_g,
            "precondition: slots 0 and 1 start distinct"
        );
        witness.member_auth[1] = witness.member_auth[0].clone();
        let pis = witness.cancel.to_public_inputs().unwrap();
        let result = fx.cancel_circuit.fill_witness(&pis, &witness);
        assert!(
            matches!(&result, Err(super::CancelCloseCircuitError::InvalidMemberAuth(m)) if m.contains("distinctness")),
            "duplicate active pk_g must be rejected by the A5 indexed-insertion distinctness check, got: {:?}",
            result.as_ref().err()
        );
    }

    #[test]
    fn cancel_close_circuit_rejects_tampered_revived_digest() {
        // Tamper the revived_channel_state_digest PI: the in-circuit IMCH recompute won't match.
        let fx = fixture();
        let witness = build_full_witness();
        let mut pis = witness.cancel.to_public_inputs().unwrap();
        pis.member_set_commitment = super::member_set_commitment_for_auth(&witness.member_auth);
        pis.revived_channel_state_digest =
            Bytes32::from_u32_slice(&[9, 9, 9, 9, 9, 9, 9, 9]).unwrap();
        let pw = fx.cancel_circuit.fill_witness(&pis, &witness);
        let proof = pw.and_then(|w| {
            fx.cancel_circuit
                .data
                .prove(w)
                .map_err(|e| super::CancelCloseCircuitError::FailedToProve(e.to_string()))
        });
        assert!(
            proof.is_err(),
            "tampered revived_channel_state_digest must be rejected"
        );
    }

    #[test]
    fn cancel_close_circuit_rejects_wrong_channel() {
        // close intent for channel 3, revived state for channel 4 → native channel mismatch.
        let fx = fixture();
        let mut witness = build_full_witness();
        witness.cancel.revived_state.channel_id =
            crate::common::channel::ChannelId::new(4).unwrap();
        witness.cancel.revived_state = witness.cancel.revived_state.clone().with_computed_digest();
        let err = fx.cancel_circuit.prove(&witness).err();
        assert!(err.is_some(), "wrong channel must be rejected");
    }
}
