//! MemberSetUpdateCircuit — detail2 §Q-4 (stage Q3, slice B): the L1-facing proof that a
//! channel's registered sig-cluster advanced from one set to the next under the PREVIOUS set's
//! full N-of-N.
//!
//! STATEMENT. Given the (baked-in, A7) `FalconBatchAggCircuit` verifier key, the proof shows:
//!
//!   1. an aggregated Falcon proof verifies, carrying `old_count` real signatures — one per listed
//!      pk — over ONE 32-byte message;
//!   2. that message IS the wallet-layer IMMS digest
//!      `keccak([IMMS, channel_id, set_version(2), prev_root(8), new_root(8), op_digest(8)])`
//!      (`wallet_core::MemberSetUpdate::signing_digest`, byte-identical preimage), where
//!      `prev_root` / `new_root` are the Poseidon folds of the OLD / NEW witnessed member leaves
//!      and `op_digest` is recomputed in-circuit from the leaf delta — so the OLD set's unanimous
//!      signatures authorize EXACTLY this transition;
//!   3. the OLD leaves' signing keys are slot-for-slot the aggregated proof's verified pk list
//!      (the poseidon world and the signature world name the same set);
//!   4. the delta obeys detail2 §Q-3: exactly one slot changes; a changed empty slot is an ADD at
//!      the left-packed boundary (`slot == old_count`); a changed occupied slot is a ROTATE that
//!      preserves `regev_pk_digest` (§Q-6 — balances stay decryptable); never a removal;
//!   5. the exposed `old_commitment` / `new_commitment` are the close-path IMCM keccaks
//!      (`keccak([IMCM, count, pk_g_0..pk_g_{MAX-1}])`, padding zeroed) over the old / new key
//!      sets — the exact form `ChannelSettlementManager` stores and compares, so the L1 apply is
//!      `require(old_commitment == stored); store(new set verified against new_commitment)`.
//!
//! The joiner/rotation CONSENT signatures (IMKR/IMJC) are deliberately NOT re-verified here: they
//! are inputs to the co-sign gate (`verify_member_set_update`) that every previous-set member ran
//! BEFORE signing IMMS, and the N-of-N — which includes the affected member — is what this proof
//! verifies (detail2 §Q-3's native-only-consent rationale; `ChannelSafetyQ.lean` T2 is enforced at
//! that gate).
//!
//! Public-input limbs (`MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN = 26`, u64-encoded):
//!   `[ channelId(1) | setVersion(2, hi/lo) | oldCommitment(8) | newCommitment(8)
//!    | oldCount(1) | newCount(1) | recipient(5, zero unless AddCosigner) ]`

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
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
    circuits::validity::{
        block_hash_chain::update_channel_tree::validate_member_set_delta,
        channel_reg_hash_chain::channel_reg_step::compute_member_tree_root,
    },
    common::{
        channel::close_member_set_commitment,
        channel_id::ChannelId,
        trees::key_tree::{MemberLeaf, MemberLeafTarget},
    },
    constants::{MAX_SIG_CLUSTER, MEMBER_SET_UPDATE_DOMAIN},
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    falcon_sig::agg::{
        FALCON_AGG_COUNT_OFFSET, FALCON_AGG_MSG_OFFSET, FALCON_AGG_PK_LIST_OFFSET,
        FALCON_AGG_PUBLIC_INPUTS_LEN,
    },
    utils::{
        leafable::{Leafable as _, LeafableTarget as _},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

/// MUST equal `common::channel::CLOSE_MEMBER_SET_DOMAIN` ("IMCM") so the in-circuit keccak agrees
/// with `close_member_set_commitment` (and the Manager's `closeMemberSetCommitment`)
/// byte-for-byte.
const IMCM_DOMAIN: u32 = 0x494d434d;

const BYTES32_LEN: usize = 8;
pub const MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN: usize = 1 + 2 + 8 + 8 + 1 + 1 + 5;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSetUpdatePublicInputs {
    pub channel_id: ChannelId,
    /// The NEW set version (`old + 1`); the Manager checks strict monotonicity on-chain.
    pub set_version: u64,
    /// IMCM keccak over the OLD key set — must equal the Manager's stored commitment.
    pub old_commitment: Bytes32,
    /// IMCM keccak over the NEW key set — the Manager verifies its calldata array against this.
    pub new_commitment: Bytes32,
    pub old_count: u32,
    pub new_count: u32,
    /// The joiner's B-1b exit address for an AddCosigner; the zero address for a rotation.
    pub recipient: Address,
}

impl MemberSetUpdatePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut v: Vec<u64> = Vec::with_capacity(MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN);
        v.extend(self.channel_id.to_u32_vec().into_iter().map(u64::from));
        v.push(self.set_version >> 32);
        v.push(self.set_version & 0xffff_ffff);
        v.extend(self.old_commitment.to_u32_vec().into_iter().map(u64::from));
        v.extend(self.new_commitment.to_u32_vec().into_iter().map(u64::from));
        v.push(u64::from(self.old_count));
        v.push(u64::from(self.new_count));
        v.extend(self.recipient.to_u32_vec().into_iter().map(u64::from));
        debug_assert_eq!(v.len(), MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN);
        v
    }
}

#[derive(Clone, Debug)]
pub struct MemberSetUpdatePublicInputsTarget {
    pub channel_id: Target,
    pub set_version_hi: Target,
    pub set_version_lo: Target,
    pub old_commitment: Bytes32Target,
    pub new_commitment: Bytes32Target,
    pub old_count: Target,
    pub new_count: Target,
    pub recipient: AddressTarget,
}

impl MemberSetUpdatePublicInputsTarget {
    fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        Self {
            channel_id: u32_limb(builder),
            set_version_hi: u32_limb(builder),
            set_version_lo: u32_limb(builder),
            old_commitment: Bytes32Target::new(builder, true),
            new_commitment: Bytes32Target::new(builder, true),
            old_count: u32_limb(builder),
            new_count: u32_limb(builder),
            recipient: AddressTarget::new(builder, true),
        }
    }

    fn to_vec(&self) -> Vec<Target> {
        let mut v = vec![self.channel_id, self.set_version_hi, self.set_version_lo];
        v.extend(self.old_commitment.to_vec());
        v.extend(self.new_commitment.to_vec());
        v.push(self.old_count);
        v.push(self.new_count);
        v.extend(self.recipient.to_vec());
        v
    }
}

/// The prover-side witness. `old_leaves`/`new_leaves` are the full padded `MAX_SIG_CLUSTER`
/// arrays (`wallet_core::registered_cosigner_leaves`); `agg_proof` is the batch aggregate over
/// the IMMS digest.
#[derive(Clone, Debug)]
pub struct MemberSetUpdateCircuitWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub channel_id: ChannelId,
    pub set_version: u64,
    pub old_leaves: Vec<MemberLeaf>,
    pub new_leaves: Vec<MemberLeaf>,
    /// Zero for a rotation; the joiner's exit address for an add.
    pub recipient: Address,
    pub agg_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> MemberSetUpdateCircuitWitness<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// The native strict mirror: validates the delta and derives the public inputs this witness
    /// must prove — the same dual-check discipline as `UpdateUserTree::to_public_inputs`.
    pub fn expected_public_inputs(&self) -> Result<MemberSetUpdatePublicInputs, String> {
        validate_member_set_delta(&self.old_leaves, &self.new_leaves)?;
        let changed: Vec<usize> = (0..MAX_SIG_CLUSTER)
            .filter(|&i| self.old_leaves[i] != self.new_leaves[i])
            .collect();
        let [j] = changed[..] else {
            return Err("exactly one changed slot".to_string());
        };
        let empty = MemberLeaf::empty_leaf();
        let is_add = self.old_leaves[j] == empty;
        let old_count = self
            .old_leaves
            .iter()
            .take_while(|l| **l != empty)
            .count() as u32;
        let new_count = old_count + u32::from(is_add);
        if !is_add && self.recipient != Address::default() {
            return Err("a rotation must carry the zero recipient".to_string());
        }
        let mut old_pks = [Bytes32::default(); MAX_SIG_CLUSTER];
        let mut new_pks = [Bytes32::default(); MAX_SIG_CLUSTER];
        for i in 0..MAX_SIG_CLUSTER {
            old_pks[i] = Bytes32::from(self.old_leaves[i].pk_g);
            new_pks[i] = Bytes32::from(self.new_leaves[i].pk_g);
        }
        Ok(MemberSetUpdatePublicInputs {
            channel_id: self.channel_id,
            set_version: self.set_version,
            old_commitment: close_member_set_commitment(&old_pks, old_count as u8),
            new_commitment: close_member_set_commitment(&new_pks, new_count as u8),
            old_count,
            new_count,
            recipient: self.recipient,
        })
    }
}

#[derive(Debug, Error)]
pub enum MemberSetUpdateCircuitError {
    #[error("witness rejected: {0}")]
    Witness(String),
    #[error("proving failed: {0}")]
    Prove(String),
}

pub struct MemberSetUpdateCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    public_inputs: MemberSetUpdatePublicInputsTarget,
    agg_proof: ProofWithPublicInputsTarget<D>,
    old_leaf_targets: Vec<MemberLeafTarget>,
    new_leaf_targets: Vec<MemberLeafTarget>,
    active_bits: Vec<BoolTarget>,
}

impl<F, C, const D: usize> MemberSetUpdateCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    #[allow(clippy::too_many_lines)]
    pub fn new(agg_vd: &VerifierCircuitData<F, C, D>) -> Self {
        assert_eq!(
            agg_vd.common.num_public_inputs, FALCON_AGG_PUBLIC_INPUTS_LEN,
            "agg_vd must be the FalconBatchAggCircuit verifier data"
        );
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = MemberSetUpdatePublicInputsTarget::new(&mut builder);
        let zero = builder.zero();
        let one = builder.one();

        // ── The OLD set's aggregated N-of-N (constant VK, A7) ──
        let agg_proof = add_proof_target_and_verify(agg_vd, &mut builder);
        let agg_message = Bytes32Target::from_slice(
            &agg_proof.public_inputs[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN],
        );
        builder.connect(
            agg_proof.public_inputs[FALCON_AGG_COUNT_OFFSET],
            public_inputs.old_count,
        );

        // ── Thermometer over old_count: active_bits[i] = (i < old_count) ──
        let mut active_bits: Vec<BoolTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        for _ in 0..MAX_SIG_CLUSTER {
            active_bits.push(builder.add_virtual_bool_target_safe());
        }
        for i in 0..MAX_SIG_CLUSTER - 1 {
            let one_minus_prev = builder.sub(one, active_bits[i].target);
            let prod = builder.mul(active_bits[i + 1].target, one_minus_prev);
            builder.connect(prod, zero);
        }
        let mut count_sum = builder.zero();
        for bit in &active_bits {
            count_sum = builder.add(count_sum, bit.target);
        }
        builder.connect(count_sum, public_inputs.old_count);
        // A registered cluster has >= 2 members (the boundary math also relies on it).
        builder.assert_one(active_bits[1].target);

        // ── Member leaves: OLD (pk_g bound to the agg pk list) and NEW; all byte forms upfront ──
        let mut old_leaf_targets: Vec<MemberLeafTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_leaf_targets: Vec<MemberLeafTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut old_leaf_hashes: Vec<PoseidonHashOutTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_leaf_hashes: Vec<PoseidonHashOutTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut old_pk_bytes: Vec<Bytes32Target> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_pk_bytes: Vec<Bytes32Target> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_pkb_bytes: Vec<Bytes32Target> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut new_regev_bytes: Vec<Bytes32Target> = Vec::with_capacity(MAX_SIG_CLUSTER);
        for i in 0..MAX_SIG_CLUSTER {
            let old_l = MemberLeafTarget::new(&mut builder);
            let new_l = MemberLeafTarget::new(&mut builder);
            let old_pk = Bytes32Target::from_hash_out(&mut builder, old_l.pk_g);
            let new_pk = Bytes32Target::from_hash_out(&mut builder, new_l.pk_g);
            let new_pkb = Bytes32Target::from_hash_out(&mut builder, new_l.pk_b);
            let new_rgv = Bytes32Target::from_hash_out(&mut builder, new_l.regev_pk_digest);
            // (3) the OLD signing keys ARE the verified signer list, slot for slot. Padding is
            // zero on both sides (the batch circuit left-packs; from_hash_out(0) == 0), so the
            // unconditional connect is exact.
            let start = FALCON_AGG_PK_LIST_OFFSET + i * BYTES32_LEN;
            let agg_pk = Bytes32Target::from_slice(
                &agg_proof.public_inputs[start..start + BYTES32_LEN],
            );
            old_pk.connect(&mut builder, agg_pk);
            old_leaf_hashes.push(old_l.hash::<F, C, D>(&mut builder));
            new_leaf_hashes.push(new_l.hash::<F, C, D>(&mut builder));
            old_pk_bytes.push(old_pk);
            new_pk_bytes.push(new_pk);
            new_pkb_bytes.push(new_pkb);
            new_regev_bytes.push(new_rgv);
            old_leaf_targets.push(old_l);
            new_leaf_targets.push(new_l);
        }
        let zero_hash = PoseidonHashOutTarget::constant(&mut builder, PoseidonHashOut::default());
        // OLD padding slots are fully empty (fold determinism; soundness is anchored by the
        // signatures regardless — junk padding changes prev_root, hence the IMMS digest, hence no
        // valid N-of-N exists for it).
        for (i, bit) in active_bits.iter().enumerate() {
            let not_active = builder.not(*bit);
            old_leaf_targets[i]
                .pk_b
                .conditional_assert_eq(&mut builder, zero_hash, not_active);
            old_leaf_targets[i]
                .regev_pk_digest
                .conditional_assert_eq(&mut builder, zero_hash, not_active);
        }
        let prev_root = compute_member_tree_root::<F, C, D>(&mut builder, &old_leaf_hashes);
        let new_root = compute_member_tree_root::<F, C, D>(&mut builder, &new_leaf_hashes);

        // ── (4) The §Q-3 delta ──
        let mut changed_bits: Vec<BoolTarget> = Vec::with_capacity(MAX_SIG_CLUSTER);
        let mut sum_changed = builder.zero();
        for i in 0..MAX_SIG_CLUSTER {
            let eq_pkg =
                old_leaf_targets[i].pk_g.is_equal(&mut builder, &new_leaf_targets[i].pk_g);
            let eq_pkb =
                old_leaf_targets[i].pk_b.is_equal(&mut builder, &new_leaf_targets[i].pk_b);
            let eq_rgv = old_leaf_targets[i]
                .regev_pk_digest
                .is_equal(&mut builder, &new_leaf_targets[i].regev_pk_digest);
            let eq_all = {
                let a = builder.and(eq_pkg, eq_pkb);
                builder.and(a, eq_rgv)
            };
            let changed = builder.not(eq_all);
            sum_changed = builder.add(sum_changed, changed.target);
            changed_bits.push(changed);
        }
        builder.connect(sum_changed, one);

        let mut is_add = builder._false();
        for i in 0..MAX_SIG_CLUSTER {
            let not_active = builder.not(active_bits[i]);
            let add_here = builder.and(changed_bits[i], not_active);
            // ADD must be at the boundary: i == old_count.
            let i_const = builder.constant(F::from_canonical_usize(i));
            builder.conditional_assert_eq(add_here.target, i_const, public_inputs.old_count);
            is_add = builder.or(is_add, add_here);

            // ROTATE preserves the Regev digest.
            let rot_here = builder.and(changed_bits[i], active_bits[i]);
            old_leaf_targets[i].regev_pk_digest.conditional_assert_eq(
                &mut builder,
                new_leaf_targets[i].regev_pk_digest,
                rot_here,
            );

            // Never a removal: a changed slot's NEW pk is nonzero.
            let new_pk_zero = new_pk_bytes[i].is_zero::<F, D, Bytes32>(&mut builder);
            let removed = builder.and(changed_bits[i], new_pk_zero);
            builder.assert_zero(removed.target);
        }

        // SECURITY (M-1, §Q-3): NO DUPLICATE SIGNING IDENTITIES — the changed slot's NEW `pk_g`
        // must differ from every other slot's. Byte-for-byte the same rule as the in-circuit gate
        // in `validity::block_hash_chain::update_channel_tree` and the native
        // `validate_member_set_delta`; all three layers must stay identical.
        //
        // What it stops: a rotate-to-duplicate, which re-points slot j at slot k's key and is an
        // EFFECTIVE REMOVAL — it bypasses the "never a removal" assert directly above, since the
        // new pk is nonzero yet slot j's original holder can never sign again. It also restores
        // the property `old_count`/`new_count` are assumed to have: a count of DISTINCT signers.
        //
        // Unordered pairs (28 for MAX_SIG_CLUSTER = 8): `sum_changed == 1` is already connected
        // above, so gating on `changed[i] ∨ changed[k]` selects exactly the pairs containing the
        // changed slot. Padding slots are included and the comparison stays exact — a changed
        // slot's new `pk_g` is nonzero (the `removed` assert), padding `pk_g` is the zero hash.
        for i in 0..MAX_SIG_CLUSTER {
            for k in (i + 1)..MAX_SIG_CLUSTER {
                let touches_changed = builder.or(changed_bits[i], changed_bits[k]);
                let dup =
                    new_leaf_targets[i].pk_g.is_equal(&mut builder, &new_leaf_targets[k].pk_g);
                let bad = builder.and(touches_changed, dup);
                builder.assert_zero(bad.target);
            }
        }
        // new_count = old_count + is_add.
        let expected_new_count = builder.add(public_inputs.old_count, is_add.target);
        builder.connect(expected_new_count, public_inputs.new_count);

        // NEW padding slots are fully empty: new_active[i] = active[i] OR (is_add ∧ i==old_count).
        for i in 0..MAX_SIG_CLUSTER {
            let i_const = builder.constant(F::from_canonical_usize(i));
            let at_boundary = builder.is_equal(i_const, public_inputs.old_count);
            let add_slot = builder.and(is_add, at_boundary);
            let new_active = builder.or(active_bits[i], add_slot);
            let not_new_active = builder.not(new_active);
            new_leaf_targets[i]
                .pk_g
                .conditional_assert_eq(&mut builder, zero_hash, not_new_active);
            new_leaf_targets[i]
                .pk_b
                .conditional_assert_eq(&mut builder, zero_hash, not_new_active);
            new_leaf_targets[i]
                .regev_pk_digest
                .conditional_assert_eq(&mut builder, zero_hash, not_new_active);
        }

        // ── (5) IMCM commitments, byte-identical to `close_member_set_commitment` ──
        let imcm = builder.constant(F::from_canonical_u32(IMCM_DOMAIN));
        let mut old_ci: Vec<Target> = vec![imcm, public_inputs.old_count];
        for pk in &old_pk_bytes {
            old_ci.extend(pk.to_vec());
        }
        let old_commitment = Bytes32Target::from_slice(&builder.keccak256::<C>(&old_ci));
        old_commitment.connect(&mut builder, public_inputs.old_commitment);
        let mut new_ci: Vec<Target> = vec![imcm, public_inputs.new_count];
        for pk in &new_pk_bytes {
            new_ci.extend(pk.to_vec());
        }
        let new_commitment = Bytes32Target::from_slice(&builder.keccak256::<C>(&new_ci));
        new_commitment.connect(&mut builder, public_inputs.new_commitment);

        // ── (2) The IMMS digest the OLD set signed — recomputed and pinned to the agg message ──
        //
        // Changed-slot selections: exactly one changed bit is set, so Σ bit·limb IS the changed
        // slot's value.
        let mut changed_slot_index = builder.zero();
        let mut changed_new_pkg = vec![builder.zero(); BYTES32_LEN];
        let mut changed_new_pkb = vec![builder.zero(); BYTES32_LEN];
        let mut changed_new_rgv = vec![builder.zero(); BYTES32_LEN];
        for i in 0..MAX_SIG_CLUSTER {
            let b = changed_bits[i].target;
            let i_const = builder.constant(F::from_canonical_usize(i));
            let contrib = builder.mul(b, i_const);
            changed_slot_index = builder.add(changed_slot_index, contrib);
            let pkg = new_pk_bytes[i].to_vec();
            let pkb = new_pkb_bytes[i].to_vec();
            let rgv = new_regev_bytes[i].to_vec();
            for w in 0..BYTES32_LEN {
                let c1 = builder.mul(b, pkg[w]);
                changed_new_pkg[w] = builder.add(changed_new_pkg[w], c1);
                let c2 = builder.mul(b, pkb[w]);
                changed_new_pkb[w] = builder.add(changed_new_pkb[w], c2);
                let c3 = builder.mul(b, rgv[w]);
                changed_new_rgv[w] = builder.add(changed_new_rgv[w], c3);
            }
        }

        // op_digest, both shapes (wallet_core::MemberSetOp::digest, byte-identical preimages):
        //   rotate: keccak([2, slot, new_pk_g(8), new_pk_b(8)])
        //   add:    keccak([1, pk_g(8), pk_b(8), regev(8), recipient(5)])
        let two_c = builder.constant(F::from_canonical_u32(2));
        let one_c = builder.constant(F::from_canonical_u32(1));
        let mut rot_pre: Vec<Target> = vec![two_c, changed_slot_index];
        rot_pre.extend(changed_new_pkg.iter().copied());
        rot_pre.extend(changed_new_pkb.iter().copied());
        let rot_digest = Bytes32Target::from_slice(&builder.keccak256::<C>(&rot_pre));
        let mut add_pre: Vec<Target> = vec![one_c];
        add_pre.extend(changed_new_pkg.iter().copied());
        add_pre.extend(changed_new_pkb.iter().copied());
        add_pre.extend(changed_new_rgv.iter().copied());
        add_pre.extend(public_inputs.recipient.to_vec());
        let add_digest = Bytes32Target::from_slice(&builder.keccak256::<C>(&add_pre));
        let op_digest = Bytes32Target::select(&mut builder, is_add, add_digest, rot_digest);

        // A rotation exposes the ZERO recipient (the PI is meaningful only for adds).
        let not_add = builder.not(is_add);
        for limb in public_inputs.recipient.to_vec() {
            let gated = builder.mul(not_add.target, limb);
            builder.connect(gated, zero);
        }

        // IMMS preimage: [IMMS, channel_id, ver_hi, ver_lo, prev_root(8), new_root(8), op(8)].
        let imms = builder.constant(F::from_canonical_u32(MEMBER_SET_UPDATE_DOMAIN));
        let prev_root_bytes = Bytes32Target::from_hash_out(&mut builder, prev_root);
        let new_root_bytes = Bytes32Target::from_hash_out(&mut builder, new_root);
        let mut imms_pre: Vec<Target> = vec![
            imms,
            public_inputs.channel_id,
            public_inputs.set_version_hi,
            public_inputs.set_version_lo,
        ];
        imms_pre.extend(prev_root_bytes.to_vec());
        imms_pre.extend(new_root_bytes.to_vec());
        imms_pre.extend(op_digest.to_vec());
        let imms_digest = Bytes32Target::from_slice(&builder.keccak256::<C>(&imms_pre));
        imms_digest.connect(&mut builder, agg_message);

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            agg_proof,
            old_leaf_targets,
            new_leaf_targets,
            active_bits,
        }
    }

    pub fn prove(
        &self,
        witness: &MemberSetUpdateCircuitWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, MemberSetUpdateCircuitError> {
        let expected = witness
            .expected_public_inputs()
            .map_err(MemberSetUpdateCircuitError::Witness)?;
        self.prove_with_public_inputs(witness, &expected)
    }

    /// TEST SEAM (audit M-1). Proves `witness` against CALLER-SUPPLIED public inputs instead of
    /// the native mirror's — i.e. exactly what a malicious prover does: it never calls
    /// [`Self::prove`], it computes the PIs for the set it WANTS and drives the circuit directly,
    /// so `expected_public_inputs`'s `validate_member_set_delta` is not a defence. Used by
    /// `member_set_update_circuit_rejects_rotate_to_duplicate` to show the IN-CIRCUIT §Q-3 gates
    /// stand on their own. Every production path goes through [`Self::prove`].
    pub(crate) fn prove_with_public_inputs(
        &self,
        witness: &MemberSetUpdateCircuitWitness<F, C, D>,
        expected: &MemberSetUpdatePublicInputs,
    ) -> Result<ProofWithPublicInputs<F, C, D>, MemberSetUpdateCircuitError> {
        let mut pw = PartialWitness::new();
        use plonky2::iop::witness::WitnessWrite as _;
        let _ = pw.set_proof_with_pis_target(&self.agg_proof, &witness.agg_proof);
        let set_u32 = |pw: &mut PartialWitness<F>, t: Target, v: u32| {
            let _ = pw.set_target(t, F::from_canonical_u32(v));
        };
        set_u32(&mut pw, self.public_inputs.channel_id, witness.channel_id.as_u64() as u32);
        set_u32(
            &mut pw,
            self.public_inputs.set_version_hi,
            (witness.set_version >> 32) as u32,
        );
        set_u32(
            &mut pw,
            self.public_inputs.set_version_lo,
            (witness.set_version & 0xffff_ffff) as u32,
        );
        self.public_inputs
            .old_commitment
            .set_witness(&mut pw, expected.old_commitment);
        self.public_inputs
            .new_commitment
            .set_witness(&mut pw, expected.new_commitment);
        set_u32(&mut pw, self.public_inputs.old_count, expected.old_count);
        set_u32(&mut pw, self.public_inputs.new_count, expected.new_count);
        self.public_inputs
            .recipient
            .set_witness(&mut pw, witness.recipient);
        for (t, l) in self.old_leaf_targets.iter().zip(witness.old_leaves.iter()) {
            t.set_witness(&mut pw, l);
        }
        for (t, l) in self.new_leaf_targets.iter().zip(witness.new_leaves.iter()) {
            t.set_witness(&mut pw, l);
        }
        for (i, bit) in self.active_bits.iter().enumerate() {
            let _ = pw.set_bool_target(*bit, (i as u32) < expected.old_count);
        }
        self.data
            .prove(pw)
            .map_err(|e| MemberSetUpdateCircuitError::Prove(format!("{e:?}")))
    }
}
