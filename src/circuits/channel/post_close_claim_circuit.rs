//! Phase B-D (Option D) + Stage 3: the post-close incoming-claim BINDING circuit
//! (abstract2 §3.5.5 `claimLateTx`, detail2 §C-8;
//! tasks/stage3-postclose-anchoring-threat-model.md).
//!
//! MLE/WHIR-wrapped, verified on-chain by `@mle/MleVerifier.sol`. Concretely it constrains:
//!
//! 1. `close_intent_digest`, `receiver_channel_id`, `incoming_tx_hash`, `receiver_pk_g`,
//!    `recipient`, `final_balance_state_h1`, `final_settled_tx_accumulator_root` are bound as PI
//!    limbs.
//! 2. STAGE 3 SOURCE-TX ANCHORING (Fork B). The `incoming_tx_hash` is NO LONGER a free witness: the
//!    circuit recomputes `tx_leaf` (keccak `tx_leaf_hash`) and `tx_hash` (`inter_channel_tx_hash`)
//!    IN-CIRCUIT from the witnessed delta (src_pk_g, sender-delta digest, receiver_pk_g,
//!    receiver-delta digest, tx_tree_root, source/destination channel ids), connects the recomputed
//!    `tx_hash` to the `incoming_tx_hash` PI, and proves a Merkle INCLUSION of that `tx_hash`
//!    against the closed channel's `final_settled_tx_accumulator_root`
//!    (`IncrementalMerkleProofTarget::verify`, height [`SETTLED_TX_ACCUMULATOR_HEIGHT`]). The
//!    accumulator root rides in the SIGNED H1 (recomputed below) — so the inclusion is against a
//!    member-signed, finalized commitment, not a fabricated tx. This closes the "vacuous inclusion"
//!    residual: a claimant can no longer fabricate a delta that was never in a signed inter-channel
//!    tx the closed channel received.
//! 3. STAGE 3 RECEIVER-PK BIND (threat-model #3). The circuit recomputes the closed channel's
//!    `h1()` from the witnessed final-state slot data (SHARED `h1_gadget`, byte-identical to close
//!    + native), connects it to the `final_balance_state_h1` PI, and ALSO connects the
//!    accumulator-root inside that H1 to the dedicated `final_settled_tx_accumulator_root` PI (so
//!    the inclusion root equals the one in the signed H1). It then binds the witnessed receiver
//!    Regev `(a, b)` to the H1-committed `regev_pk_digests[receiver_member_index]` via the SAME
//!    one-hot select the withdrawal claim uses (poseidon_digest(a,b) == selected digest, slot
//!    ACTIVE). This makes the decryption NON-vacuous.
//! 4. HAZARD #8: `shared_native_nullifier = keccak([POST_CLOSE_NULLIFIER_DOMAIN] ++
//!    close_intent_digest ++ incoming_tx_hash ++ receiver_pk_g)` is derived IN-CIRCUIT and
//!    connected to the PI (the L1 manager recomputes the SAME value as the
//!    `usedSharedNativeNullifiers` key).
//! 5. DECRYPTION STAGE 2 (over-claim CLOSED for post-close): `amount` is bound in-circuit to the
//!    plaintext of the receiver-delta ciphertext via `decryption_core` + the IMRC ct-digest
//!    binding, under the now-H1-bound receiver key. After this, `amount` is NO LONGER a free PI.

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_keccak::builder::BuilderKeccak256 as _;
use thiserror::Error;

use crate::{
    circuits::channel::{
        decryption_gadget::{
            DecryptionCoreInputs, DecryptionCoreTargets, build_decryption_core_witness,
            decryption_core, fill_decryption_core, regev_ct_digest_gadget,
            regev_pk_poseidon_digest_gadget,
        },
        h1_gadget::recompute_h1,
        post_close_claim_pis::{POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN, PostCloseClaimPublicInputs},
    },
    common::balance_state::{TX_LEAF_DOMAIN, settled_tx_chain_push_circuit},
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        address::AddressTarget,
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
        u64::{U64, U64Target},
    },
    regev::REGEV_N,
    utils::trees::incremental_merkle_tree::{IncrementalMerkleProof, IncrementalMerkleProofTarget},
    wallet_core::SETTLED_TX_ACCUMULATOR_HEIGHT,
};

/// "IMCK" — post-close shared-native nullifier domain. MUST equal `common::channel`'s
/// `POST_CLOSE_NULLIFIER_DOMAIN` so the in-circuit keccak agrees with the native
/// `PostCloseIncomingClaim::derive_shared_native_nullifier` and the L1 mirror byte-for-byte.
const POST_CLOSE_NULLIFIER_DOMAIN: u32 = 0x494d434b;

#[derive(Clone, Debug)]
pub struct PostCloseClaimPublicInputsTarget {
    pub close_intent_digest: Bytes32Target,
    pub receiver_channel_id: [Target; 1],
    pub incoming_tx_hash: Bytes32Target,
    pub receiver_pk_g: Bytes32Target,
    pub recipient: AddressTarget,
    pub shared_native_nullifier: Bytes32Target,
    pub amount: U64Target,
    /// Stage 3: closed channel final H1 (receiver-pk bind anchor).
    pub final_balance_state_h1: Bytes32Target,
    /// Stage 3: closed channel settled-tx accumulator root (source-tx inclusion anchor).
    pub final_settled_tx_accumulator_root: Bytes32Target,
}

impl PostCloseClaimPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        Self {
            close_intent_digest: Bytes32Target::new(builder, true),
            receiver_channel_id: [u32_limb(builder)],
            incoming_tx_hash: Bytes32Target::new(builder, true),
            receiver_pk_g: Bytes32Target::new(builder, true),
            recipient: AddressTarget::new(builder, true),
            shared_native_nullifier: Bytes32Target::new(builder, true),
            amount: U64Target::new(builder, true),
            final_balance_state_h1: Bytes32Target::new(builder, true),
            final_settled_tx_accumulator_root: Bytes32Target::new(builder, true),
        }
    }

    /// PI limb vector in EXACT `PostCloseClaimPublicInputs::to_u64_vec()` order
    /// (close_intent_digest, receiver_channel_id, incoming_tx_hash, receiver_pk_g, recipient,
    /// shared_native_nullifier, split_u64(amount), final_balance_state_h1,
    /// final_settled_tx_accumulator_root).
    pub fn to_vec(&self) -> Vec<Target> {
        let v = [
            self.close_intent_digest.to_vec(),
            self.receiver_channel_id.to_vec(),
            self.incoming_tx_hash.to_vec(),
            self.receiver_pk_g.to_vec(),
            self.recipient.to_vec(),
            self.shared_native_nullifier.to_vec(),
            self.amount.to_vec(),
            self.final_balance_state_h1.to_vec(),
            self.final_settled_tx_accumulator_root.to_vec(),
        ]
        .concat();
        debug_assert_eq!(v.len(), POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN);
        v
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &PostCloseClaimPublicInputs,
    ) {
        self.close_intent_digest
            .set_witness(witness, value.close_intent_digest);
        witness
            .set_target(
                self.receiver_channel_id[0],
                F::from_canonical_u64(value.receiver_channel_id.to_u64_vec()[0]),
            )
            .unwrap();
        self.incoming_tx_hash
            .set_witness(witness, value.incoming_tx_hash);
        self.receiver_pk_g.set_witness(witness, value.receiver_pk_g);
        self.recipient.set_witness(witness, value.recipient);
        self.shared_native_nullifier
            .set_witness(witness, value.shared_native_nullifier);
        self.amount.set_witness(witness, U64::from(value.amount));
        self.final_balance_state_h1
            .set_witness(witness, value.final_balance_state_h1);
        self.final_settled_tx_accumulator_root
            .set_witness(witness, value.final_settled_tx_accumulator_root);
    }
}

#[derive(Debug, Error)]
pub enum PostCloseClaimCircuitError {
    #[error("receiver_member_index {0} out of range (>= MAX_CHANNEL_MEMBERS)")]
    MemberIndexOutOfRange(usize),
    #[error("failed to prove: {0}")]
    FailedToProve(String),
}

/// Prover witness for [`PostCloseClaimCircuit`].
#[derive(Clone, Debug)]
pub struct PostCloseClaimFullWitness {
    pub public_inputs: PostCloseClaimPublicInputs,
    // --- Stage 3 tx_hash recompute inputs (the witnessed delta + small-block facts). ---
    /// `source_tx.source_pk_g` (sender member SPHINCS+ pubkey hash) — tx_leaf sender wing.
    pub source_pk_g: Bytes32,
    /// `source_tx.sender_delta_ct.digest()` — tx_leaf sender wing digest.
    pub sender_delta_digest: Bytes32,
    /// `source_tx.receiver_deltas[0].amount.digest()` — tx_leaf receiver wing digest (== claimed
    /// ct digest, bound to the witnessed (c1, c2) below).
    pub receiver_delta_digest: Bytes32,
    /// `source_tx.signed_small_block.message.tx_tree_root` (= H2) — inter_channel_tx_hash input.
    pub tx_tree_root: Bytes32,
    /// `source_tx.source_channel_id` — inter_channel_tx_hash id mix.
    pub source_channel_id: u32,
    // --- Stage 3 accumulator inclusion proof for the recomputed tx_hash. ---
    /// The Merkle inclusion proof of `tx_hash` at `incoming_tx_index` in the closed channel's
    /// accumulator (`final_settled_tx_accumulator_root`).
    pub incoming_tx_inclusion: IncrementalMerkleProof<Bytes32>,
    /// The leaf index of `tx_hash` in the accumulator.
    pub incoming_tx_index: u64,
    // --- Stage 3 H1 recompute (closed channel final balance state slot data). ---
    pub enc_balance_digests: [Bytes32; MAX_CHANNEL_MEMBERS],
    pub regev_pk_digests: [Bytes32; MAX_CHANNEL_MEMBERS],
    pub settled_tx_chain: Bytes32,
    pub state_version: u64,
    pub pending_adds: [u32; MAX_CHANNEL_MEMBERS],
    pub member_count: u8,
    pub delegate_count: u8,
    /// Receiver slot index in the closed channel (`< member_count + delegate_count`) — the one-hot
    /// pk-digest select index.
    pub receiver_member_index: usize,
    // --- Decryption Stage 2: receiver Regev pk (a, b) + the delta ct (c1, c2) + secret s. ---
    pub regev_a: Vec<u32>,
    pub regev_b: Vec<u32>,
    pub delta_c1: Vec<u32>,
    pub delta_c2: Vec<u32>,
    pub regev_s: Vec<i8>,
}

pub struct PostCloseClaimCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub public_inputs: PostCloseClaimPublicInputsTarget,
    // Stage 3 tx_hash recompute handles.
    source_pk_g: Bytes32Target,
    sender_delta_digest: Bytes32Target,
    receiver_delta_digest: Bytes32Target,
    tx_tree_root: Bytes32Target,
    source_channel_id: Target,
    // Stage 3 inclusion proof handles.
    incoming_tx_inclusion: IncrementalMerkleProofTarget<Bytes32Target>,
    incoming_tx_index: Target,
    // Stage 3 H1 recompute handles.
    member_count: Target,
    delegate_count: Target,
    enc_balance_digests: Vec<Bytes32Target>,
    regev_pk_digests: Vec<Bytes32Target>,
    settled_tx_chain: Bytes32Target,
    state_version: U64Target,
    pending_adds: Vec<Target>,
    index_bits: Vec<BoolTarget>,
    // Decryption Stage 2 handles.
    regev_a: Vec<Target>,
    regev_b: Vec<Target>,
    delta_c1: Vec<Target>,
    delta_c2: Vec<Target>,
    dec_core: DecryptionCoreTargets,
}

impl<F, C, const D: usize> PostCloseClaimCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = PostCloseClaimPublicInputsTarget::new(&mut builder);
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };

        // ── Stage 3: recompute incoming_tx_hash in-circuit from the witnessed delta. ──
        //
        // tx_leaf = keccak( keccak([IMTL, src_pk_g, sender_delta_digest]),
        //                   keccak([IMTL, receiver_pk_g, receiver_delta_digest]) )
        // tx_hash = push( ids, push(tx_tree_root, tx_leaf) ), push = keccak([IMTC, a, b])
        //   where ids = Bytes32[ 0,0,0,0,0,0, destination_channel_id, source_channel_id ].
        let source_pk_g = Bytes32Target::new(&mut builder, true);
        let sender_delta_digest = Bytes32Target::new(&mut builder, true);
        let receiver_delta_digest = Bytes32Target::new(&mut builder, true);
        let tx_tree_root = Bytes32Target::new(&mut builder, true);
        let source_channel_id = u32_limb(&mut builder);

        let tx_leaf_domain = builder.constant(F::from_canonical_u32(TX_LEAF_DOMAIN));
        let sender_wing_inputs = [
            vec![tx_leaf_domain],
            source_pk_g.to_vec(),
            sender_delta_digest.to_vec(),
        ]
        .concat();
        let sender_wing = Bytes32Target::from_slice(&builder.keccak256::<C>(&sender_wing_inputs));
        let receiver_wing_inputs = [
            vec![tx_leaf_domain],
            public_inputs.receiver_pk_g.to_vec(),
            receiver_delta_digest.to_vec(),
        ]
        .concat();
        let receiver_wing =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&receiver_wing_inputs));
        let tx_leaf_inputs = [sender_wing.to_vec(), receiver_wing.to_vec()].concat();
        let tx_leaf = Bytes32Target::from_slice(&builder.keccak256::<C>(&tx_leaf_inputs));

        // mixed = push(tx_tree_root, tx_leaf).
        let mixed = settled_tx_chain_push_circuit::<F, C, D>(&mut builder, tx_tree_root, tx_leaf);
        // ids = [0,0,0,0,0,0, destination_channel_id, source_channel_id]. The native helper writes
        // source into the LSW (limb 7) and destination into limb 6; destination == the
        // receiver_channel_id PI.
        let zero = builder.zero();
        let mut ids_limbs = vec![zero; BYTES32_LEN];
        ids_limbs[BYTES32_LEN - 1] = source_channel_id;
        ids_limbs[BYTES32_LEN - 2] = public_inputs.receiver_channel_id[0];
        let ids = Bytes32Target::from_slice(&ids_limbs);
        let recomputed_tx_hash = settled_tx_chain_push_circuit::<F, C, D>(&mut builder, ids, mixed);
        // (2) incoming_tx_hash == the recomputed tx_hash (REPLACES the old free connect).
        recomputed_tx_hash.connect(&mut builder, public_inputs.incoming_tx_hash);

        // ── Stage 3: Merkle inclusion of tx_hash in the closed channel's accumulator. ──
        let incoming_tx_inclusion = IncrementalMerkleProofTarget::<Bytes32Target>::new(
            &mut builder,
            SETTLED_TX_ACCUMULATOR_HEIGHT,
        );
        let incoming_tx_index = builder.add_virtual_target();
        // The accumulator root PI (a Bytes32 = Bytes32::from(PoseidonHashOut)) is decoded to a
        // PoseidonHashOutTarget; `to_hash_out` also `connect`s the round-trip, enforcing the root
        // is a CANONICAL Poseidon→Bytes32 encoding (no non-canonical alias).
        let accumulator_root_hash = public_inputs
            .final_settled_tx_accumulator_root
            .to_hash_out(&mut builder);
        // verify panics-at-build if shapes mismatch; the constraint fails to prove if the leaf is
        // not at `index` under `root`.
        incoming_tx_inclusion.verify::<F, C, D>(
            &mut builder,
            &public_inputs.incoming_tx_hash,
            incoming_tx_index,
            accumulator_root_hash,
        );

        // ── Stage 3: H1 recompute (SHARED gadget) + receiver-pk one-hot bind. ──
        let member_count = u32_limb(&mut builder);
        let delegate_count = u32_limb(&mut builder);
        let enc_balance_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let regev_pk_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let settled_tx_chain = Bytes32Target::new(&mut builder, true);
        let state_version = U64Target::new(&mut builder, true);
        let pending_adds: Vec<Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| u32_limb(&mut builder))
            .collect();

        let recomputed_h1 = recompute_h1::<F, C, D>(
            &mut builder,
            public_inputs.receiver_channel_id[0],
            member_count,
            delegate_count,
            &regev_pk_digests,
            &enc_balance_digests,
            &settled_tx_chain,
            &public_inputs.final_settled_tx_accumulator_root,
            &state_version,
            &pending_adds,
        );
        // H1 == the final_balance_state_h1 PI (so the slot data is pinned to the signed final
        // state, AND the accumulator root fed to recompute_h1 == the dedicated
        // inclusion-root PI: the inclusion proof is verified against the SAME root that
        // rides in the signed H1).
        recomputed_h1.connect(&mut builder, public_inputs.final_balance_state_h1);

        // One-hot index select over the 16 slots (exactly-one-hot, active-region check) — the SAME
        // construction the withdrawal claim uses, here selecting the receiver's slot pk digest.
        let mut index_bits: Vec<BoolTarget> = Vec::with_capacity(MAX_CHANNEL_MEMBERS);
        for _ in 0..MAX_CHANNEL_MEMBERS {
            index_bits.push(builder.add_virtual_bool_target_safe());
        }
        let mut onehot_sum = builder.zero();
        for bit in &index_bits {
            onehot_sum = builder.add(onehot_sum, bit.target);
        }
        let one = builder.one();
        builder.connect(onehot_sum, one);

        let active = builder.add(member_count, delegate_count);
        {
            let max_active = builder.constant(F::from_canonical_usize(MAX_CHANNEL_MEMBERS));
            builder.range_check(active, 8);
            let max_plus_one = builder.add_const(max_active, F::ONE);
            let active_le_max = less_than_u32(&mut builder, active, max_plus_one);
            builder.assert_one(active_le_max.target);
        }

        let zero_b32 = Bytes32Target::constant(&mut builder, Bytes32::default());
        let mut selected_regev_pk_digest = zero_b32;
        let mut selected_active = builder.zero();
        for (i, bit) in index_bits.iter().enumerate() {
            let masked_pk = regev_pk_digests[i].mul_bool(&mut builder, *bit);
            selected_regev_pk_digest =
                add_bytes32(&mut builder, &selected_regev_pk_digest, &masked_pk);
            let i_const = builder.constant(F::from_canonical_usize(i));
            let is_active_i = less_than_u32(&mut builder, i_const, active);
            let contrib = builder.mul(bit.target, is_active_i.target);
            selected_active = builder.add(selected_active, contrib);
        }
        builder.connect(selected_active, one);

        // ── Decryption Stage 2 (closes post-close over-claim): bind amount to the delta plaintext.
        let regev_a: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let regev_b: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let delta_c1: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let delta_c2: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();

        // (pk binding, MUST-FIX #1) poseidon_digest(a, b) == one-hot-selected H1 regev_pk_digest.
        let pk_digest = regev_pk_poseidon_digest_gadget::<F, D>(&mut builder, &regev_a, &regev_b);
        pk_digest.connect(&mut builder, selected_regev_pk_digest);

        // (ct binding) IMRC_digest(c1, c2) == the signed receiver-delta ct digest; AND the receiver
        // delta digest is the tx_leaf receiver wing input — so the SAME ciphertext is anchored in
        // the tx_hash (hence the accumulator) and decrypted.
        let ct_digest = regev_ct_digest_gadget::<F, C, D>(&mut builder, &delta_c1, &delta_c2);
        ct_digest.connect(&mut builder, receiver_delta_digest);

        // (decryption + amount binding) bind the claim's U64 amount to the decrypted plaintext.
        let dec_inputs = DecryptionCoreInputs {
            a: &regev_a,
            b: &regev_b,
            c1: &delta_c1,
            c2: &delta_c2,
        };
        let (dec_core, amount_limbs) = decryption_core(&mut builder, &dec_inputs, true);
        let (amount_lo, amount_hi) =
            amount_limbs.expect("expose_amount = true yields amount limbs");
        let amount_pi = public_inputs.amount.to_vec(); // [hi, lo]
        builder.connect(amount_pi[0], amount_hi);
        builder.connect(amount_pi[1], amount_lo);

        // ── (4) HAZARD #8: derive shared_native_nullifier in-circuit and bind to the PI. ──
        let nullifier_domain = builder.constant(F::from_canonical_u32(POST_CLOSE_NULLIFIER_DOMAIN));
        let nullifier_inputs = [
            vec![nullifier_domain],
            public_inputs.close_intent_digest.to_vec(),
            public_inputs.incoming_tx_hash.to_vec(),
            public_inputs.receiver_pk_g.to_vec(),
        ]
        .concat();
        let shared_native_nullifier =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&nullifier_inputs));
        shared_native_nullifier.connect(&mut builder, public_inputs.shared_native_nullifier);

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            source_pk_g,
            sender_delta_digest,
            receiver_delta_digest,
            tx_tree_root,
            source_channel_id,
            incoming_tx_inclusion,
            incoming_tx_index,
            member_count,
            delegate_count,
            enc_balance_digests,
            regev_pk_digests,
            settled_tx_chain,
            state_version,
            pending_adds,
            index_bits,
            regev_a,
            regev_b,
            delta_c1,
            delta_c2,
            dec_core,
        }
    }

    fn fill_witness(
        &self,
        witness_value: &PostCloseClaimFullWitness,
    ) -> Result<PartialWitness<F>, PostCloseClaimCircuitError> {
        if witness_value.receiver_member_index >= MAX_CHANNEL_MEMBERS {
            return Err(PostCloseClaimCircuitError::MemberIndexOutOfRange(
                witness_value.receiver_member_index,
            ));
        }
        let mut witness = PartialWitness::<F>::new();
        self.public_inputs
            .set_witness(&mut witness, &witness_value.public_inputs);

        // Stage 3 tx_hash recompute inputs.
        self.source_pk_g
            .set_witness(&mut witness, witness_value.source_pk_g);
        self.sender_delta_digest
            .set_witness(&mut witness, witness_value.sender_delta_digest);
        self.receiver_delta_digest
            .set_witness(&mut witness, witness_value.receiver_delta_digest);
        self.tx_tree_root
            .set_witness(&mut witness, witness_value.tx_tree_root);
        witness
            .set_target(
                self.source_channel_id,
                F::from_canonical_u32(witness_value.source_channel_id),
            )
            .unwrap();

        // Stage 3 inclusion proof.
        self.incoming_tx_inclusion
            .set_witness(&mut witness, &witness_value.incoming_tx_inclusion);
        witness
            .set_target(
                self.incoming_tx_index,
                F::from_canonical_u64(witness_value.incoming_tx_index),
            )
            .unwrap();

        // Stage 3 H1 recompute slot data.
        witness
            .set_target(
                self.member_count,
                F::from_canonical_u8(witness_value.member_count),
            )
            .unwrap();
        witness
            .set_target(
                self.delegate_count,
                F::from_canonical_u8(witness_value.delegate_count),
            )
            .unwrap();
        for (target, digest) in self
            .enc_balance_digests
            .iter()
            .zip(witness_value.enc_balance_digests.iter())
        {
            target.set_witness(&mut witness, *digest);
        }
        for (target, digest) in self
            .regev_pk_digests
            .iter()
            .zip(witness_value.regev_pk_digests.iter())
        {
            target.set_witness(&mut witness, *digest);
        }
        self.settled_tx_chain
            .set_witness(&mut witness, witness_value.settled_tx_chain);
        self.state_version
            .set_witness(&mut witness, U64::from(witness_value.state_version));
        for (target, &adds) in self
            .pending_adds
            .iter()
            .zip(witness_value.pending_adds.iter())
        {
            witness
                .set_target(*target, F::from_canonical_u32(adds))
                .unwrap();
        }
        for (i, bit) in self.index_bits.iter().enumerate() {
            witness
                .set_bool_target(*bit, i == witness_value.receiver_member_index)
                .unwrap();
        }

        // Decryption Stage 2.
        let set_poly = |witness: &mut PartialWitness<F>, targets: &[Target], vals: &[u32]| {
            for (&t, &v) in targets.iter().zip(vals) {
                witness.set_target(t, F::from_canonical_u32(v)).unwrap();
            }
        };
        set_poly(&mut witness, &self.regev_a, &witness_value.regev_a);
        set_poly(&mut witness, &self.regev_b, &witness_value.regev_b);
        set_poly(&mut witness, &self.delta_c1, &witness_value.delta_c1);
        set_poly(&mut witness, &self.delta_c2, &witness_value.delta_c2);
        let core_w = build_decryption_core_witness(
            &witness_value.regev_a,
            &witness_value.regev_b,
            &witness_value.delta_c1,
            &witness_value.delta_c2,
            &witness_value.regev_s,
        )
        .map_err(|()| {
            PostCloseClaimCircuitError::FailedToProve(
                "decryption-core witness build failed (inconsistent pk/sk/ct or out-of-budget noise)"
                    .to_string(),
            )
        })?;
        fill_decryption_core::<F, D, _>(&mut witness, &self.dec_core, &core_w);

        Ok(witness)
    }

    pub fn prove(
        &self,
        witness_value: &PostCloseClaimFullWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, PostCloseClaimCircuitError> {
        let witness = self.fill_witness(witness_value)?;
        self.data
            .prove(witness)
            .map_err(|e| PostCloseClaimCircuitError::FailedToProve(e.to_string()))
    }
}

impl<F, C, const D: usize> Default for PostCloseClaimCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Limb-wise add of two `Bytes32Target`s (one-hot digest accumulation; see the withdrawal claim's
/// twin for the no-overflow argument: the EXACTLY-one-hot `index_bits` masks all-but-one term).
fn add_bytes32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &Bytes32Target,
    b: &Bytes32Target,
) -> Bytes32Target {
    let limbs: Vec<Target> = a
        .to_vec()
        .iter()
        .zip(b.to_vec().iter())
        .map(|(x, y)| builder.add(*x, *y))
        .collect();
    Bytes32Target::from_slice(&limbs)
}

/// Strict less-than on two SMALL u32-range targets (mirror of the withdrawal claim's helper). Both
/// operands are `<= MAX_CHANNEL_MEMBERS` here. Returns `a < b`.
fn less_than_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> BoolTarget {
    let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));
    let diff = builder.sub(b, a);
    let shifted = builder.add(diff, two_pow_32);
    let bits = builder.split_le(shifted, 33);
    let no_borrow = bits[32];
    let low: Vec<Target> = bits[0..32].iter().map(|b| b.target).collect();
    let low_sum = builder.add_many(low);
    let zero = builder.zero();
    let is_zero = builder.is_equal(low_sum, zero);
    let is_nonzero = builder.not(is_zero);
    builder.and(no_borrow, is_nonzero)
}

// SECURITY / TEST-GATING: shared witness builders, compiled for the test suite AND for the
// `post-close-claim-fixture-bin` feature (the fixture generator). Single canonical copy, off by
// default.
#[cfg(any(test, feature = "post-close-claim-fixture-bin"))]
pub mod test_fixture {
    use std::sync::OnceLock;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::{PostCloseClaimCircuit, PostCloseClaimFullWitness};
    use crate::{
        circuits::channel::post_close_claim_pis::{
            PostCloseClaimPublicInputs, PostCloseClaimWitness,
        },
        common::{
            balance_state::{BalanceState, tx_leaf_hash},
            channel::{
                ChannelId, ChannelProofEnvelope, InterChannelTx, MerkleInclusionProof,
                PostCloseIncomingClaim, ProofBackend, ReceiverBalanceDelta, SignedSmallBlock,
                SmallBlockRootMessage, TransitionProofRole,
            },
        },
        constants::MAX_CHANNEL_MEMBERS,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
        regev::{
            REGEV_N, REGEV_Q, RegevCiphertext, RegevSecurityLevel, channel_keygen, encrypt_amount,
            prove_withdraw_claim,
        },
        utils::trees::incremental_merkle_tree::IncrementalMerkleTree,
        wallet_core::SETTLED_TX_ACCUMULATOR_HEIGHT,
    };

    pub const D: usize = 2;
    pub type F = GoldilocksField;
    pub type C = PoseidonGoldilocksConfig;

    pub fn circuit() -> &'static PostCloseClaimCircuit<F, C, D> {
        static CIRCUIT: OnceLock<PostCloseClaimCircuit<F, C, D>> = OnceLock::new();
        CIRCUIT.get_or_init(PostCloseClaimCircuit::<F, C, D>::new)
    }

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

    /// `inter_channel_tx_hash` mirror (native), kept private to the fixture so the recompute the
    /// circuit performs is checked against a known-good value.
    fn inter_channel_tx_hash(
        source: ChannelId,
        destination: ChannelId,
        tx_tree_root: Bytes32,
        tx_leaf: Bytes32,
    ) -> Bytes32 {
        use crate::common::balance_state::settled_tx_chain_push;
        let mixed = settled_tx_chain_push(tx_tree_root, tx_leaf);
        let mut w = [0u32; 8];
        w[7] = source.as_u64() as u32;
        w[6] = destination.as_u64() as u32;
        let ids = Bytes32::from_u32_slice(&w).unwrap();
        settled_tx_chain_push(ids, mixed)
    }

    /// Build a REAL, self-consistent post-close-claim witness (single receiver delta, real receiver
    /// key, the recomputed tx_hash inserted into a real accumulator) and the matching
    /// `PostCloseClaimFullWitness`. SHARED by the unit tests and the fixture-generator binary.
    pub fn build_full_witness() -> PostCloseClaimFullWitness {
        let mut rng = SmallRng::seed_from_u64(0x9C105E);
        let (receiver_pk, receiver_sk) = channel_keygen(&mut rng);
        let (other_pk, _) = channel_keygen(&mut rng);
        let amount = 21u64;
        let (delta_ct, _) = encrypt_amount(&mut rng, &receiver_pk, amount).unwrap();
        let receiver_pk_g = pubkey_hash(11);
        let source_pk_g = pubkey_hash(10);
        let closed_channel_id = ChannelId::new(7).unwrap();
        let source_channel_id = ChannelId::new(5).unwrap();
        let close_intent_digest = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let tx_tree_root = Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let sender_delta_ct = ciphertext(1);

        // The REAL tx_leaf / tx_hash (the circuit recomputes the same).
        let tx_leaf = tx_leaf_hash(
            source_pk_g,
            sender_delta_ct.digest(),
            receiver_pk_g,
            delta_ct.digest(),
        );
        let tx_hash =
            inter_channel_tx_hash(source_channel_id, closed_channel_id, tx_tree_root, tx_leaf);

        // Insert tx_hash into a real accumulator at index 0 (a few extra leaves around it).
        let mut accumulator = IncrementalMerkleTree::<Bytes32>::new(SETTLED_TX_ACCUMULATOR_HEIGHT);
        accumulator.push(tx_hash);
        accumulator.push(pubkey_hash(77));
        let incoming_tx_index = 0u64;
        let incoming_tx_inclusion = accumulator.prove(incoming_tx_index);
        let accumulator_root = Bytes32::from(accumulator.get_root());

        let source_tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            signed_small_block: SignedSmallBlock {
                message: SmallBlockRootMessage {
                    channel_id: source_channel_id,
                    bp_member_slot: 0,
                    bp_pk_g: source_pk_g,
                    small_block_number: 1,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root,
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![],
                aggregated_signature_proof: vec![1],
                medium_block_number: 3,
                confirmation_proof: vec![2],
            },
            sender_delta_ct: sender_delta_ct.clone(),
            source_channel_id,
            destination_channel_id: closed_channel_id,
            source_pk_g,
            seal: Bytes32::default(),
            tx_hash,
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_pk_g,
                amount: delta_ct.clone(),
            }],
            channel_update_zkp: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: vec![3],
            },
            transport_proof: vec![5],
        };
        let claim_proof = prove_withdraw_claim(
            RegevSecurityLevel::Test,
            &receiver_pk,
            &receiver_sk,
            &delta_ct,
            amount,
        )
        .unwrap();
        let shared_native_nullifier = PostCloseIncomingClaim::derive_shared_native_nullifier(
            close_intent_digest,
            tx_hash,
            receiver_pk_g,
        );
        let claim = PostCloseIncomingClaim {
            close_intent_digest,
            incoming_tx_hash: tx_hash,
            receiver_pk_g,
            l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            receiver_amount: delta_ct.clone(),
            shared_native_nullifier,
            recipient_memo: vec![5, 6],
            claim_proof,
        };

        // Closed channel final balance state: receiver in slot 0, accumulator root exposed.
        let final_balance_state = BalanceState {
            channel_id: closed_channel_id,
            member_count: 2,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[delta_ct.clone(), ciphertext(2)]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(receiver_pk.poseidon_digest()),
                Bytes32::from(other_pk.poseidon_digest()),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: accumulator_root,
            state_version: 9,
            pending_adds: BalanceState::pad_pending_adds(&[0, 0]),
        };

        let native = PostCloseClaimWitness {
            close_intent_digest,
            closed_channel_id,
            source_tx: source_tx.clone(),
            claim,
            receiver_pk: receiver_pk.clone(),
            amount,
            final_balance_state: final_balance_state.clone(),
            receiver_member_index: 0,
        };
        let public_inputs: PostCloseClaimPublicInputs =
            native.to_public_inputs(RegevSecurityLevel::Test).unwrap();

        let enc_balance_digests: [Bytes32; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|i| final_balance_state.enc_balances[i].digest());

        PostCloseClaimFullWitness {
            public_inputs,
            source_pk_g,
            sender_delta_digest: sender_delta_ct.digest(),
            receiver_delta_digest: delta_ct.digest(),
            tx_tree_root,
            source_channel_id: source_channel_id.as_u64() as u32,
            incoming_tx_inclusion,
            incoming_tx_index,
            enc_balance_digests,
            regev_pk_digests: final_balance_state.regev_pk_digests,
            settled_tx_chain: final_balance_state.settled_tx_chain,
            state_version: final_balance_state.state_version,
            pending_adds: final_balance_state.pending_adds,
            member_count: final_balance_state.member_count,
            delegate_count: final_balance_state.delegate_count,
            receiver_member_index: 0,
            regev_a: receiver_pk.a.clone(),
            regev_b: receiver_pk.b.clone(),
            delta_c1: delta_ct.c1.clone(),
            delta_c2: delta_ct.c2.clone(),
            regev_s: receiver_sk.s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use plonky2::field::types::PrimeField64;

    use super::{test_fixture::*, *};
    use crate::circuits::channel::post_close_claim_pis::POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN;

    /// Happy path: a real post-close-claim binding proves and the exposed limbs equal the
    /// `PostCloseClaimPublicInputs::to_u64_vec()` layout (56 limbs).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_proves_and_exposes_pis() {
        let circuit = circuit();
        let witness = build_full_witness();
        let proof = circuit.prove(&witness).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

        let expected = witness.public_inputs.to_u64_vec();
        assert_eq!(expected.len(), POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN);
        let actual: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        assert_eq!(expected, actual);
    }

    /// Negative — forged incoming_tx_hash NOT in the accumulator: tamper the PI tx hash (and the
    /// dependent nullifier) so the in-circuit tx_hash recompute no longer equals it (and the
    /// inclusion proof no longer matches). The proof must fail.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_tx_hash_not_in_accumulator() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        // A tx hash that is NOT the recomputed one and NOT in the accumulator.
        witness.public_inputs.incoming_tx_hash =
            Bytes32::from_u32_slice(&[9, 9, 9, 9, 9, 9, 9, 9]).unwrap();
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a tx_hash that is not the recomputed/accumulated one must be rejected"
        );
    }

    /// Negative — tampered inclusion (wrong index): the real tx_hash is in the accumulator at
    /// index 0; pointing the proof at index 1 (a different leaf) must fail the inclusion verify.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_wrong_inclusion_index() {
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.incoming_tx_index = 1; // index 1 holds a different leaf.
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a wrong inclusion index must fail the Merkle verify"
        );
    }

    /// Negative — fake receiver pk: a fresh (a, b, s) keypair UNRELATED to the closed channel's
    /// committed `regev_pk_digests[0]`. The pk-digest one-hot connect must fail (without it the
    /// decryption would be vacuous).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_fake_receiver_pk() {
        use rand010::{SeedableRng, rngs::SmallRng};

        use crate::regev::channel_keygen;
        let circuit = circuit();
        let mut witness = build_full_witness();
        let mut rng = SmallRng::seed_from_u64(0xFA4E_1111);
        let (fake_pk, fake_sk) = channel_keygen(&mut rng);
        witness.regev_a = fake_pk.a.clone();
        witness.regev_b = fake_pk.b.clone();
        witness.regev_s = fake_sk.s.clone();
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a fake receiver pk must fail the H1-committed pk-digest one-hot binding"
        );
    }

    /// Negative — over-claim: an `amount` PI that is NOT the delta plaintext is rejected by the
    /// decryption-core amount binding (the residual Stage 3 + decryption Stage 2 close together).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_over_claim() {
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.public_inputs.amount = 1_000_000u64; // honest plaintext is 21.
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "an amount != the decrypted plaintext must be rejected (over-claim CLOSED)"
        );
    }

    /// Negative — forged shared_native_nullifier: a PI not equal to the in-circuit keccak
    /// derivation is rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_forged_nullifier() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.public_inputs.shared_native_nullifier =
            Bytes32::from_u32_slice(&[2, 2, 2, 2, 2, 2, 2, 2]).unwrap();
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a forged shared_native_nullifier must be rejected"
        );
    }

    /// Negative — tampered H1: a final_balance_state_h1 PI not matching the recompute over the
    /// witnessed slot data is rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_tampered_h1() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.public_inputs.final_balance_state_h1 =
            Bytes32::from_u32_slice(&[7, 7, 7, 7, 7, 7, 7, 7]).unwrap();
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a tampered final_balance_state_h1 must be rejected"
        );
    }
}
