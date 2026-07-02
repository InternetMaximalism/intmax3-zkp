//! Per-registration step of the channel-registration hash chain.
//!
//! Mirrors `deposit_step.rs`. Each step consumes one `ChannelRegRecord`, folds it into the keccak
//! `channel_reg_hash_chain`, and deterministically writes the channel's `ChannelLeaf` into the
//! Poseidon channel tree with the in-circuit-computed `member_pubkeys_root`.
//!
//! ## Security properties
//!
//! * **R2 cross-binding (keccak ↔ Poseidon).** The 16 members' `pk_g` and `regev_pk_digest` are
//!   witnessed ONCE as `PoseidonHashOutTarget`s. They feed BOTH the keccak preimage (split to 32
//!   bytes via `Bytes32Target::from_hash_out`) AND the Poseidon `MemberLeaf`s. Reusing the same
//!   targets is the binding — no separate equality constraint is needed, so the keccak chain the
//!   contract recorded and the Poseidon `member_pubkeys_root` the circuit writes are guaranteed to
//!   commit to the same member set.
//! * **R5 unregistered guard.** The previous `ChannelLeaf` at `channel_id` MUST equal
//!   `ChannelLeaf::default()` (one-time registration); re-registering an active channel is
//!   rejected. This is asserted on the FULL default leaf, not just the member root.
//! * **Padding.** Slots `i >= member_count` are forced empty (`sphincs == 0 && regev == 0`), so
//!   their `MemberLeaf` hash equals the empty-leaf hash and the computed root matches a native
//!   `MemberTree` with exactly `member_count` active leaves.
//! * **Distinctness / nonzero of active SPHINCS+ hashes is delegated to the contract** (the keccak
//!   chain binds the exact bytes the contract validated). Re-proving O(k²) distinctness in-circuit
//!   is intentionally avoided.

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::channel_reg_hash_chain::channel_reg_chain_pis::{
        ChannelRegChainPublicInputs, ChannelRegChainPublicInputsError,
        ChannelRegChainPublicInputsTarget,
    },
    common::{
        channel_id::{ChannelId, ChannelIdTarget},
        channel_registration::{
            ChannelRegRecord, MemberRegEntryTarget, channel_reg_hash_with_prev_hash_circuit,
        },
        trees::{
            channel_tree::{
                ChannelLeaf, ChannelLeafTarget, ChannelMerkleProof, ChannelMerkleProofTarget,
            },
            key_tree::{MemberLeaf, MemberLeafTarget, MemberTree},
        },
        u63::{BlockNumber, BlockNumberTarget, U63, U63Target},
    },
    constants::{CHANNEL_TREE_HEIGHT, MAX_CHANNEL_MEMBERS, MEMBER_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        conversion::ToU64,
        cyclic::conditionally_connect_vd,
        dummy::{DummyProof, conditionally_verify_proof},
        leafable::{Leafable as _, LeafableTarget as _},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ChannelRegStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),

    #[error("Channel reg record error: {0}")]
    RecordError(#[from] crate::common::channel_registration::ChannelRegRecordError),

    #[error("Channel reg chain public inputs error: {0}")]
    ChannelRegChainPublicInputsError(#[from] ChannelRegChainPublicInputsError),
}

/// Build the native `MemberTree` root for `record`'s active members (slots
/// `0..member_count`), with the remaining slots empty. Mirrors the in-circuit root computation.
pub fn member_pubkeys_root_for(record: &ChannelRegRecord) -> PoseidonHashOut {
    let mut tree = MemberTree::init();
    // Delegate account: the member tree covers ALL active participants — members
    // (`0..member_count`) AND delegates (`member_count..member_count+delegate_count`). Delegates
    // carry a real `MemberLeaf` identity so they can send and withdraw. Phase 1 `delegate_count =
    // 0` makes this identical to the legacy `0..member_count` loop.
    let active = record.member_count as usize + record.delegate_count as usize;
    for i in 0..active {
        let leaf = MemberLeaf {
            pk_g: record.members[i].pk_g.reduce_to_hash_out(),
            pk_b: record.members[i].pk_b.reduce_to_hash_out(),
            regev_pk_digest: record.members[i].regev_pk_digest.reduce_to_hash_out(),
        };
        tree.push(leaf);
    }
    tree.get_root()
}

pub struct ChannelRegStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<(Bytes32, PoseidonHashOut, U63)>,
    pub prev_channel_reg_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub record: ChannelRegRecord,
    pub channel_merkle_proof: ChannelMerkleProof,
    pub block_number: BlockNumber,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ChannelRegStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        channel_reg_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<ChannelRegChainPublicInputs<F, C, D>, ChannelRegStepError> {
        let total_inputs = self.initial_value.is_some() as usize
            + self.prev_channel_reg_chain_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(ChannelRegStepError::InvalidInput(
                "Exactly one of initial_value or prev_channel_reg_chain_proof must be provided"
                    .to_string(),
            ));
        }

        self.record.validate()?;

        let prev_pis = if let Some((
            initial_channel_reg_hash_chain,
            initial_channel_tree_root,
            initial_channel_reg_count,
        )) = &self.initial_value
        {
            ChannelRegChainPublicInputs {
                initial_channel_reg_hash_chain: *initial_channel_reg_hash_chain,
                initial_channel_tree_root: *initial_channel_tree_root,
                initial_channel_reg_count: *initial_channel_reg_count,
                channel_reg_hash_chain: *initial_channel_reg_hash_chain,
                channel_tree_root: *initial_channel_tree_root,
                channel_reg_count: *initial_channel_reg_count,
                block_number: self.block_number,
                vd: channel_reg_chain_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self
                .prev_channel_reg_chain_proof
                .clone()
                .expect("Checked above");
            let prev_pis = ChannelRegChainPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &channel_reg_chain_vd.common.config,
            )?;
            if prev_pis.block_number != self.block_number {
                return Err(ChannelRegStepError::InvalidInput(format!(
                    "Block number mismatch: prev {}, current {}",
                    prev_pis.block_number.as_u64(),
                    self.block_number.as_u64()
                )));
            }
            prev_pis
        };

        // R5 unregistered guard: prev leaf at channel_id must be the full default leaf.
        let channel_index = self.record.channel_id.as_u64();
        let default_leaf = ChannelLeaf::default();
        self.channel_merkle_proof
            .verify(&default_leaf, channel_index, prev_pis.channel_tree_root)
            .map_err(|e| {
                ChannelRegStepError::MerkleProofError(format!(
                    "Failed to verify unregistered channel leaf: {e}"
                ))
            })?;

        // Build new leaf with the computed member_pubkeys_root.
        let member_pubkeys_root = member_pubkeys_root_for(&self.record);
        let new_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::default(),
            send_tree_root: default_leaf.send_tree_root,
            member_pubkeys_root,
        };
        let new_channel_tree_root = self.channel_merkle_proof.get_root(&new_leaf, channel_index);

        let new_channel_reg_count = prev_pis.channel_reg_count.add(1).map_err(|e| {
            ChannelRegStepError::InvalidInput(format!("Channel reg count overflow: {e}"))
        })?;

        let new_channel_reg_hash_chain = self
            .record
            .hash_with_prev_hash(prev_pis.channel_reg_hash_chain);

        Ok(ChannelRegChainPublicInputs {
            initial_channel_reg_hash_chain: prev_pis.initial_channel_reg_hash_chain,
            initial_channel_tree_root: prev_pis.initial_channel_tree_root,
            initial_channel_reg_count: prev_pis.initial_channel_reg_count,
            channel_reg_hash_chain: new_channel_reg_hash_chain,
            channel_tree_root: new_channel_tree_root,
            channel_reg_count: new_channel_reg_count,
            block_number: self.block_number,
            vd: prev_pis.vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ChannelRegStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub initial_channel_reg_hash_chain: Bytes32Target,
    pub initial_channel_tree_root: PoseidonHashOutTarget,
    pub initial_channel_reg_count: U63Target,
    pub prev_channel_reg_chain_proof: ProofWithPublicInputsTarget<D>,

    // Record fields
    pub channel_id: ChannelIdTarget,
    pub bp_member_slot: Target,
    pub member_count: Target,
    /// Number of DELEGATE participants (delegate account). Active participants (members +
    /// delegates) occupy slots `0..member_count+delegate_count`; padding is the rest.
    pub delegate_count: Target,
    /// The 16 members' Poseidon identity components, witnessed ONCE and reused for both the keccak
    /// preimage and the Poseidon member-tree leaves (R2 cross-binding).
    pub member_pk_ges: [PoseidonHashOutTarget; MAX_CHANNEL_MEMBERS],
    /// The 16 members' BabyBear hash-sig public keys (`pk_b`), witnessed once and reused for both
    /// the keccak preimage and the 3-field Poseidon member-tree leaves (R2 cross-binding, P3).
    pub member_pk_bs: [PoseidonHashOutTarget; MAX_CHANNEL_MEMBERS],
    pub member_regev_pk_digests: [PoseidonHashOutTarget; MAX_CHANNEL_MEMBERS],
    pub member_recipients: [crate::ethereum_types::address::AddressTarget; MAX_CHANNEL_MEMBERS],
    pub channel_merkle_proof: ChannelMerkleProofTarget,
    pub block_number: BlockNumberTarget,

    pub new_pis: ChannelRegChainPublicInputsTarget,
}

impl<const D: usize> ChannelRegStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        channel_reg_chain_cd: &CommonCircuitData<F, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let is_initial = builder.add_virtual_bool_target_safe();
        let not_initial = builder.not(is_initial);

        let initial_channel_reg_hash_chain = Bytes32Target::new::<F, D>(builder, true);
        let initial_channel_tree_root = PoseidonHashOutTarget::new(builder);
        let initial_channel_reg_count = U63Target::new(builder, true);
        let block_number = BlockNumberTarget::new(builder, true);

        // -- Record header --
        let channel_id = ChannelIdTarget::new(builder, true);
        let bp_member_slot = builder.add_virtual_target();
        builder.range_check(bp_member_slot, 32);
        let member_count = builder.add_virtual_target();
        builder.range_check(member_count, 32);
        // Delegate account: number of delegates registered after the members.
        let delegate_count = builder.add_virtual_target();
        builder.range_check(delegate_count, 32);

        // -- Member identity components (witnessed once; R2 cross-binding) --
        let member_pk_ges: [PoseidonHashOutTarget; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|_| PoseidonHashOutTarget::new(builder));
        let member_pk_bs: [PoseidonHashOutTarget; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|_| PoseidonHashOutTarget::new(builder));
        let member_regev_pk_digests: [PoseidonHashOutTarget; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|_| PoseidonHashOutTarget::new(builder));
        let member_recipients: [crate::ethereum_types::address::AddressTarget;
            MAX_CHANNEL_MEMBERS] = std::array::from_fn(|_| {
            crate::ethereum_types::address::AddressTarget::new(builder, true)
        });

        let channel_merkle_proof = ChannelMerkleProofTarget::new(builder, CHANNEL_TREE_HEIGHT);

        // ── prev chain proof: conditionally verify ──
        let prev_channel_reg_chain_proof = builder.add_virtual_proof_with_pis(channel_reg_chain_cd);
        let prev_pis = ChannelRegChainPublicInputsTarget::from_pis(
            &prev_channel_reg_chain_proof.public_inputs,
            &channel_reg_chain_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_channel_reg_chain_proof,
            &prev_pis.vd,
            channel_reg_chain_cd,
        );
        let channel_reg_chain_vd =
            builder.add_virtual_verifier_data(channel_reg_chain_cd.config.fri_config.cap_height);
        conditionally_connect_vd(builder, not_initial, &prev_pis.vd, &channel_reg_chain_vd);

        // ── Select previous state ──
        let prev_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            initial_channel_reg_hash_chain.clone(),
            prev_pis.channel_reg_hash_chain.clone(),
        );
        let prev_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_channel_tree_root.clone(),
            prev_pis.channel_tree_root.clone(),
        );
        let prev_count = U63Target::select(
            builder,
            is_initial,
            &initial_channel_reg_count,
            &prev_pis.channel_reg_count,
        );
        // block number consistency for the chained case.
        builder.conditional_assert_eq(
            not_initial.target,
            prev_pis.block_number.value,
            block_number.value,
        );

        // ── Select initial state ──
        let selected_initial_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            initial_channel_reg_hash_chain.clone(),
            prev_pis.initial_channel_reg_hash_chain.clone(),
        );
        let selected_initial_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_channel_tree_root.clone(),
            prev_pis.initial_channel_tree_root.clone(),
        );
        let selected_initial_count = U63Target::select(
            builder,
            is_initial,
            &initial_channel_reg_count,
            &prev_pis.initial_channel_reg_count,
        );

        // ── member_count ∈ [2, 16] range check ──
        // member_count - 2 in [0, 14] and 16 - member_count in [0, 14].
        let two = builder.constant(F::from_canonical_u64(2));
        let max = builder.constant(F::from_canonical_u64(MAX_CHANNEL_MEMBERS as u64));
        let mc_minus_two = builder.sub(member_count, two);
        builder.range_check(mc_minus_two, 4); // [0, 15] ⊇ [0, 14]
        let max_minus_mc = builder.sub(max, member_count);
        builder.range_check(max_minus_mc, 4);

        // bp_member_slot < member_count: member_count - 1 - bp_member_slot in [0, 15].
        let one = builder.one();
        let mc_minus_one = builder.sub(member_count, one);
        let slot_diff = builder.sub(mc_minus_one, bp_member_slot);
        builder.range_check(slot_diff, 4);

        // ── delegate account: active = member_count + delegate_count, with active ∈ [2, 16] ──
        // SECURITY: `active <= MAX_CHANNEL_MEMBERS` (no over-allocation past the fixed 16 slots);
        // `delegate_count >= 0` so `active >= member_count >= 2` holds automatically. The
        // thermometer mask below uses `active` as the threshold, so delegate slots
        // (`member_count..active`) are treated as ACTIVE (non-forced-zero) exactly like members and
        // padding only begins at `active`. Phase 1 `delegate_count = 0` makes `active ==
        // member_count`, so the mask is byte-for-byte the legacy one.
        let active_count = builder.add(member_count, delegate_count);
        let max_minus_active = builder.sub(max, active_count);
        builder.range_check(max_minus_active, 4); // active in [member_count, 16] ⊆ [0,15] above 16-mc

        // ── is_active thermometer mask: is_active[i] = (i < active_count) ──
        // `active_count` is a single threshold, so the mask is monotonic non-increasing by
        // construction; `lt_const_threshold` pins each bit uniquely against the range-checked
        // `active_count` (range [2, MAX_CHANNEL_MEMBERS]).
        let is_active: Vec<BoolTarget> = (0..MAX_CHANNEL_MEMBERS)
            .map(|i| lt_const_threshold(builder, i, active_count))
            .collect();

        // ── Build MemberLeaf targets + member_pubkeys_root (Poseidon) ──
        // Padding slots forced empty: when !is_active, sphincs==0 && regev==0.
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());
        let mut leaf_hashes: Vec<PoseidonHashOutTarget> = Vec::with_capacity(MAX_CHANNEL_MEMBERS);
        for i in 0..MAX_CHANNEL_MEMBERS {
            let not_active = builder.not(is_active[i]);
            // Force pk_g == 0, pk_b == 0 and regev == 0 on inactive slots (empty-leaf padding).
            member_pk_ges[i].conditional_assert_eq(builder, zero_hash, not_active);
            member_pk_bs[i].conditional_assert_eq(builder, zero_hash, not_active);
            member_regev_pk_digests[i].conditional_assert_eq(builder, zero_hash, not_active);

            let member_leaf = MemberLeafTarget {
                pk_g: member_pk_ges[i],
                pk_b: member_pk_bs[i],
                regev_pk_digest: member_regev_pk_digests[i],
            };
            leaf_hashes.push(member_leaf.hash::<F, C, D>(builder));
        }
        let member_pubkeys_root = compute_member_tree_root::<F, C, D>(builder, &leaf_hashes);

        // ── keccak preimage: build 32-byte forms from the SAME Poseidon targets (R2) ──
        let members_reg_entries: [MemberRegEntryTarget; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|i| MemberRegEntryTarget {
                pk_g: Bytes32Target::from_hash_out(builder, member_pk_ges[i]),
                pk_b: Bytes32Target::from_hash_out(builder, member_pk_bs[i]),
                regev_pk_digest: Bytes32Target::from_hash_out(builder, member_regev_pk_digests[i]),
                recipient: member_recipients[i],
            });
        let new_hash_chain = channel_reg_hash_with_prev_hash_circuit::<F, C, D>(
            builder,
            &prev_hash_chain,
            &channel_id,
            bp_member_slot,
            member_count,
            delegate_count,
            &members_reg_entries,
        );

        // ── R5 unregistered guard + write new leaf ──
        let channel_index = channel_id.channel_id(builder);
        let default_leaf = ChannelLeafTarget::empty_leaf(builder);
        // Verify prev leaf at channel_id IS the default (unregistered) leaf.
        channel_merkle_proof.verify::<F, C, D>(
            builder,
            &default_leaf,
            channel_index,
            prev_tree_root.clone(),
        );
        // New leaf: index 0, prev 0, empty send tree root (from default), computed member root.
        let new_leaf = ChannelLeafTarget {
            index: builder.zero(),
            prev: BlockNumberTarget::constant(builder, BlockNumber::default()),
            send_tree_root: default_leaf.send_tree_root.clone(),
            member_pubkeys_root,
        };
        let new_channel_tree_root =
            channel_merkle_proof.get_root::<F, C, D>(builder, &new_leaf, channel_index);

        // ── channel_reg_count += 1 (63-bit range check) ──
        let incremented_count = builder.add_const(prev_count.value, F::ONE);
        builder.range_check(incremented_count, 63);
        let new_channel_reg_count = U63Target {
            value: incremented_count,
        };

        let new_pis = ChannelRegChainPublicInputsTarget {
            initial_channel_reg_hash_chain: selected_initial_hash_chain,
            initial_channel_tree_root: selected_initial_tree_root,
            initial_channel_reg_count: selected_initial_count,
            channel_reg_hash_chain: new_hash_chain,
            channel_tree_root: new_channel_tree_root,
            channel_reg_count: new_channel_reg_count,
            block_number: block_number.clone(),
            vd: channel_reg_chain_vd,
        };

        Self {
            is_initial,
            initial_channel_reg_hash_chain,
            initial_channel_tree_root,
            initial_channel_reg_count,
            prev_channel_reg_chain_proof,
            channel_id,
            bp_member_slot,
            member_count,
            delegate_count,
            member_pk_ges,
            member_pk_bs,
            member_regev_pk_digests,
            member_recipients,
            channel_merkle_proof,
            block_number,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &ChannelRegStepWitness<F, C, D>,
        new_pis: &ChannelRegChainPublicInputs<F, C, D>,
        dummy_proof: &ProofWithPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let is_initial = value.initial_value.is_some();
        witness.set_bool_target(self.is_initial, is_initial);

        if let Some((hash_chain, tree_root, count)) = value.initial_value {
            self.initial_channel_reg_hash_chain
                .set_witness(witness, hash_chain);
            self.initial_channel_tree_root
                .set_witness(witness, tree_root);
            self.initial_channel_reg_count.set_witness(witness, count);
        } else {
            self.initial_channel_reg_hash_chain
                .set_witness(witness, Bytes32::default());
            self.initial_channel_tree_root
                .set_witness(witness, PoseidonHashOut::default());
            self.initial_channel_reg_count
                .set_witness(witness, U63::default());
        }
        if let Some(proof) = &value.prev_channel_reg_chain_proof {
            witness.set_proof_with_pis_target(&self.prev_channel_reg_chain_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_channel_reg_chain_proof, dummy_proof);
        }

        // Record header
        self.channel_id
            .set_witness(witness, value.record.channel_id);
        witness.set_target(
            self.bp_member_slot,
            F::from_canonical_u32(value.record.bp_member_slot),
        );
        witness.set_target(
            self.member_count,
            F::from_canonical_u32(value.record.member_count),
        );
        witness.set_target(
            self.delegate_count,
            F::from_canonical_u32(value.record.delegate_count),
        );
        // Members: split each 32-byte digest to its reduced PoseidonHashOut (the witnessed value).
        for i in 0..MAX_CHANNEL_MEMBERS {
            let m = &value.record.members[i];
            self.member_pk_ges[i].set_witness(witness, m.pk_g.reduce_to_hash_out());
            self.member_pk_bs[i].set_witness(witness, m.pk_b.reduce_to_hash_out());
            self.member_regev_pk_digests[i]
                .set_witness(witness, m.regev_pk_digest.reduce_to_hash_out());
            self.member_recipients[i].set_witness(witness, m.recipient);
        }
        self.channel_merkle_proof
            .set_witness(witness, &value.channel_merkle_proof);
        self.block_number.set_witness(witness, value.block_number);

        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
    }
}

/// `is_active = (i < member_count)` as a BoolTarget, for the small constant `i` and a
/// range-checked `member_count` (in `[2, MAX_CHANNEL_MEMBERS]`).
///
/// DETERMINISTIC (no free witness): `member_count` takes exactly one value in
/// `[2, MAX_CHANNEL_MEMBERS]`, so `is_active[i] = Σ_{t = i+1..=MAX} is_equal(member_count, t)`.
/// Exactly one `is_equal` fires (when `member_count == t`), and it is in the sum iff `t > i`, i.e.
/// iff `i < member_count`. The sum is therefore 0 or 1 and has standard generators (no unfilled
/// witness). INTENTIONALLY SIMPLE: the constant range is tiny (<= 16), so unrolling is cheap.
fn lt_const_threshold<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    i: usize,
    member_count: Target,
) -> BoolTarget {
    let mut sum = builder.zero();
    for t in (i + 1)..=MAX_CHANNEL_MEMBERS {
        let t_const = builder.constant(F::from_canonical_u64(t as u64));
        let eq = builder.is_equal(member_count, t_const);
        sum = builder.add(sum, eq.target);
    }
    // `sum` is provably 0/1 (member_count hits exactly one t in [2, MAX]); wrap as a bool. Use the
    // safe constructor path via assert_bool to keep the boolean constraint explicit.
    let active = BoolTarget::new_unsafe(sum);
    builder.assert_bool(active);
    active
}

/// Compute the root of a full balanced tree (height = `MEMBER_TREE_HEIGHT`) over its leaf hashes,
/// folding pairwise `two_to_one(left, right)` with the lower index as the left child — exactly the
/// convention of `IncrementalMerkleTree` / `MerkleTree::update_leaf`.
fn compute_member_tree_root<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_hashes: &[PoseidonHashOutTarget],
) -> PoseidonHashOutTarget
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    assert_eq!(leaf_hashes.len(), 1 << MEMBER_TREE_HEIGHT);
    let mut level = leaf_hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(PoseidonHashOutTarget::two_to_one(builder, pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

#[derive(Debug)]
pub struct ChannelRegStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ChannelRegStepTarget<D>,
    pub public_inputs: ChannelRegChainPublicInputsTarget,

    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> ChannelRegStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(channel_reg_chain_cd: &CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = ChannelRegStepTarget::new::<F, C>(&mut builder, channel_reg_chain_cd);
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&channel_reg_chain_cd.config));
        let data = builder.build::<C>();
        let dummy_proof = DummyProof::new(channel_reg_chain_cd);
        Self {
            data,
            target,
            public_inputs,
            dummy_proof: dummy_proof.proof,
        }
    }

    pub fn prove(
        &self,
        channel_reg_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &ChannelRegStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelRegStepError> {
        let new_pis = witness.to_public_inputs(channel_reg_chain_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_proof);
        self.public_inputs
            .set_witness::<F, C, D, _>(&mut pw, &new_pis);
        self.data
            .prove(pw)
            .map_err(|e| ChannelRegStepError::FailedToProve(e.to_string()))
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<(), ChannelRegStepError> {
        self.data
            .verify(proof)
            .map_err(|e| ChannelRegStepError::InvalidProof(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::validity::channel_reg_hash_chain::channel_reg_chain_pis::CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN,
        common::{
            channel_id::ChannelId,
            channel_registration::{ChannelRegRecord, MemberRegEntry},
            trees::channel_tree::ChannelTree,
        },
        ethereum_types::{address::Address, u32limb_trait::U32LimbTrait as _},
        utils::{conversion::ToField as _, cyclic::TestCyclicCircuit},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn make_record(channel_id: u32, member_count: u32) -> ChannelRegRecord {
        // MAX_CHANNEL_MEMBERS > 32 exceeds the std array `Default` arity; build elementwise.
        let mut members: [MemberRegEntry; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|_| MemberRegEntry::default());
        for i in 0..(member_count as usize) {
            let s = (i as u32) + 1;
            members[i] = MemberRegEntry {
                pk_g: Bytes32::from(PoseidonHashOut::hash_inputs_u64(&[
                    channel_id as u64,
                    s as u64,
                    0x5e,
                ])),
                pk_b: Bytes32::from(PoseidonHashOut::hash_inputs_u64(&[
                    channel_id as u64,
                    s as u64,
                    0x7e,
                ])),
                regev_pk_digest: Bytes32::from(PoseidonHashOut::hash_inputs_u64(&[
                    channel_id as u64,
                    s as u64,
                    0x6e,
                ])),
                recipient: Address::from_u32_slice(&[0x3333_0000 + s; 5]).unwrap(),
            };
        }
        ChannelRegRecord {
            channel_id: ChannelId::new(channel_id as u64).unwrap(),
            bp_member_slot: 0,
            member_count,
            delegate_count: 0,
            members,
        }
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_channel_reg_step_circuit() {
        let cfg = CircuitConfig::standard_recursion_config();
        let pis_len = CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN;
        let chain_cd = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let chain_circuit = TestCyclicCircuit::<F, C, D>::new(cfg, pis_len, &chain_cd);
        let chain_vd = chain_circuit.data.verifier_data();

        let initial_hash_chain = Bytes32::default();
        let channel_tree = ChannelTree::init();
        let initial_tree_root = channel_tree.get_root();
        let initial_count = U63::default();
        let block_number = BlockNumber::new(7).unwrap();

        let record = make_record(5, 3);
        let channel_index = record.channel_id.as_u64();
        let merkle_proof = channel_tree.prove(channel_index);

        // Expected: native member root + native channel tree after registration.
        let expected_member_root = member_pubkeys_root_for(&record);
        let mut channel_tree_after = channel_tree.clone();
        let new_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::default(),
            send_tree_root: ChannelLeaf::default().send_tree_root,
            member_pubkeys_root: expected_member_root,
        };
        channel_tree_after.update(channel_index, new_leaf.clone());
        let expected_tree_root = channel_tree_after.get_root();
        let expected_hash_chain = record.hash_with_prev_hash(initial_hash_chain);

        let witness = ChannelRegStepWitness::<F, C, D> {
            initial_value: Some((initial_hash_chain, initial_tree_root, initial_count)),
            prev_channel_reg_chain_proof: None,
            record: record.clone(),
            channel_merkle_proof: merkle_proof,
            block_number,
        };

        let pis = witness.to_public_inputs(&chain_vd).expect("public inputs");
        assert_eq!(pis.channel_reg_count.as_u64(), 1);
        assert_eq!(pis.channel_tree_root, expected_tree_root);
        assert_eq!(pis.channel_reg_hash_chain, expected_hash_chain);
        // (c) keccak chain output equals native ChannelRegRecord::hash_with_prev_hash.
        assert_eq!(
            pis.channel_reg_hash_chain,
            record.hash_with_prev_hash(initial_hash_chain)
        );

        let circuit = ChannelRegStepCircuit::<F, C, D>::new(&chain_cd);
        println!(
            "channel_reg_step degree_bits = {}",
            circuit.data.common.degree_bits()
        );
        let proof = circuit
            .prove(&chain_vd, &witness)
            .expect("channel reg step proof");
        circuit.verify(proof).expect("proof verifies");

        // (a) the new channel tree root contains the channel's leaf with the computed member root.
        assert_eq!(channel_tree_after.get_leaf(channel_index), new_leaf);
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_channel_reg_step_rejects_already_registered() {
        // (b) NEGATIVE R5 guard: registering over an already-registered channel must fail.
        let cfg = CircuitConfig::standard_recursion_config();
        let pis_len = CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN;
        let chain_cd = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let chain_circuit = TestCyclicCircuit::<F, C, D>::new(cfg, pis_len, &chain_cd);
        let chain_vd = chain_circuit.data.verifier_data();

        let record = make_record(5, 3);
        let channel_index = record.channel_id.as_u64();

        // Pre-populate the channel tree with a NON-default leaf at channel_id (already registered).
        let mut channel_tree = ChannelTree::init();
        let existing_leaf = ChannelLeaf {
            index: 0,
            prev: BlockNumber::default(),
            send_tree_root: ChannelLeaf::default().send_tree_root,
            member_pubkeys_root: member_pubkeys_root_for(&record), // nonempty → not default
        };
        channel_tree.update(channel_index, existing_leaf);
        let initial_tree_root = channel_tree.get_root();
        let merkle_proof = channel_tree.prove(channel_index);

        let witness = ChannelRegStepWitness::<F, C, D> {
            initial_value: Some((Bytes32::default(), initial_tree_root, U63::default())),
            prev_channel_reg_chain_proof: None,
            record: record.clone(),
            channel_merkle_proof: merkle_proof,
            block_number: BlockNumber::new(7).unwrap(),
        };

        // Native to_public_inputs must already reject (the R5 verify against the default leaf fails
        // because the actual leaf is non-default).
        let native = witness.to_public_inputs(&chain_vd);
        assert!(
            native.is_err(),
            "R5 guard must reject registration over an already-registered channel"
        );
    }
}
