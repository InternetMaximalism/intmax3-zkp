//! Phase B-D (Option D): the withdrawal-claim BINDING circuit (detail2 §E-3 / abstract2 §3.5.4).
//!
//! This circuit proves the complete §E-3 withdrawal claim, including Regev decryption of the slot
//! ciphertext. The decryption stage that was formerly deferred is now embedded directly in this
//! Plonky2 statement, which is MLE/WHIR-wrapped and verified on-chain by `@mle/MleVerifier.sol`:
//!
//! 1. `final_balance_state_h1` is the Poseidon-root v2 H1 header of the witnessed final balance
//!    state (the SHARED `h1_gadget::recompute_h1`, element-identical to the close circuit and to
//!    native `BalanceState::h1`; detail2 §N-1). The manager supplies the FINALIZED H1 as the PI, so
//!    the header scalars (incl. `token_count` + the token registry, TM-9) AND the `slot_tree_root`
//!    the claim opens against are pinned to the members' signed final state.
//! 2. the claimant occupies an ACTIVE slot: `member_index < member_count + delegate_count` (members
//!    AND delegates own a withdrawable balance; padding slots do not).
//! 3. the claimant's FULL v2 slot leaf `balance_slot_leaf_hash(regev_pk_digest, ct_digests[0..10],
//!    pending_adds[0..10], recipient)` (104 elems, detail2 §N-2) is INCLUDED at `member_index` in
//!    the H1-committed `slot_tree_root` (a height-`BALANCE_SLOT_TREE_HEIGHT` Merkle inclusion; the
//!    Merkle POSITION is the slot index). This binds ALL TEN token positions, the registered Regev
//!    pk digest AND the L1 exit address (`recipient` PI — B-1b).
//! 4. PER-(SLOT, TOKEN) claim (detail2 §N-6, TM-2/TM-8): the claim's `token_slot` PI ONE-HOT
//!    selects `ct_digests[token_slot]`, which is constrained equal to the `user_amount_digest` PI
//!    (the ciphertext actually decrypted) — the selected position IS the PI token_slot, as circuit
//!    constraints; `token_slot < token_count` is enforced in-circuit (TM-8); and the resolved BASE
//!    `token_index = registry[token_slot]` (selected from the H1-bound registry limbs) is exposed
//!    as a PI so L1 pays the right asset (review finding m8: the PI base token_index is the
//!    H1-committed `registry[token_slot]` — no prover choice).
//! 5. `withdrawal_nullifier = keccak([IMW2, close_intent_digest(8), pk_digest(8), token_slot])` —
//!    keyed on the LEAF-BOUND slot Regev pk digest (B-2 blocker fix), NOT the slot-free
//!    `member_pk_g`, PLUS the token slot (TM-5: exactly one nullifier per (slot, token)) — is
//!    derived in-circuit and connected to the PI (mirrors `WithdrawalClaim::derive_nullifier`).
//! 6. `channel_id`, `member_pk_g` (informational; inert — NOT the nullifier key), `recipient`,
//!    `close_intent_digest` are bound as PI limbs.
//!
//! DECRYPTION STAGE 2 (over-claim CLOSED for withdrawal): `amount` is bound in-circuit to the
//! plaintext of `user_amount_ct`. The claimant's Regev pk `(a, b)` is (1) bound to the H1-committed
//! `regev_pk_digests[member_index]` — its in-circuit Poseidon digest is a FIELD of the SAME slot
//! leaf that carries the ciphertext digest, opened at `member_index` by the Merkle inclusion (THE
//! pk binding, MUST-FIX #1), (2) tied to the secret `s` by the decryption-core key-binding gate,
//! and the ciphertext `(c1, c2)` is bound to `user_amount_digest` via the IMRC keccak digest.
//! `decryption_core` then proves `amount == decrypt(c1, c2; s)`. After this, `amount` is NO
//! LONGER a free PI — over-claim is closed at the proof level, not merely bounded by the on-chain
//! `finalizedChannelFundAmount` cap.

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
        h1_gadget::{balance_slot_leaf_hash_circuit, recompute_h1},
        withdrawal_claim_pis::{WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN, WithdrawalClaimPublicInputs},
    },
    constants::{
        BALANCE_SLOT_TREE_HEIGHT, MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS,
        WITHDRAWAL_CLAIM_DOMAIN_V2,
    },
    ethereum_types::{
        address::AddressTarget,
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
        u64::{U64, U64Target},
    },
    regev::REGEV_N,
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::incremental_merkle_tree::{IncrementalMerkleProof, IncrementalMerkleProofTarget},
    },
};

#[derive(Clone, Debug)]
pub struct WithdrawalClaimPublicInputsTarget {
    pub close_intent_digest: Bytes32Target,
    pub channel_id: [Target; 1],
    pub final_balance_state_h1: Bytes32Target,
    pub member_pk_g: Bytes32Target,
    pub recipient: AddressTarget,
    pub user_amount_digest: Bytes32Target,
    pub withdrawal_nullifier: Bytes32Target,
    pub amount: U64Target,
    /// Multi-token (§N-6, TM-2/TM-8): the claimed LOCAL token slot (single u32 limb). Drives the
    /// in-circuit one-hot ct select, the `< token_count` bound, the registry resolution AND the
    /// IMW2 nullifier limb — one wire, so none of those bindings can diverge.
    pub token_slot: [Target; 1],
    /// Multi-token (§N-6, review m8): the resolved BASE `token_index = registry[token_slot]`
    /// (single u32 limb), selected in-circuit from the H1-committed registry limbs — the formal
    /// link between the channel-local slot and the Manager's per-base-token accounting. L1 pays
    /// the claim in THIS asset.
    pub token_index: [Target; 1],
}

impl WithdrawalClaimPublicInputsTarget {
    /// Allocates the PI targets, range-checking every limb to 32 bits (load-bearing: the limbs feed
    /// the IMBS/IMCW keccak preimages and the keccak gadget does not range-check its inputs).
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
            channel_id: [u32_limb(builder)],
            final_balance_state_h1: Bytes32Target::new(builder, true),
            member_pk_g: Bytes32Target::new(builder, true),
            recipient: AddressTarget::new(builder, true),
            user_amount_digest: Bytes32Target::new(builder, true),
            withdrawal_nullifier: Bytes32Target::new(builder, true),
            amount: U64Target::new(builder, true),
            token_slot: [u32_limb(builder)],
            token_index: [u32_limb(builder)],
        }
    }

    /// PI limb vector in EXACT `WithdrawalClaimPublicInputs::to_u64_vec()` order
    /// (close_intent_digest, channel_id, final_balance_state_h1, member_pk_g, recipient,
    /// user_amount_digest, withdrawal_nullifier, split_u64(amount), token_slot, token_index).
    pub fn to_vec(&self) -> Vec<Target> {
        let v = [
            self.close_intent_digest.to_vec(),
            self.channel_id.to_vec(),
            self.final_balance_state_h1.to_vec(),
            self.member_pk_g.to_vec(),
            self.recipient.to_vec(),
            self.user_amount_digest.to_vec(),
            self.withdrawal_nullifier.to_vec(),
            self.amount.to_vec(),
            self.token_slot.to_vec(),
            self.token_index.to_vec(),
        ]
        .concat();
        debug_assert_eq!(v.len(), WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN);
        v
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &WithdrawalClaimPublicInputs,
    ) {
        self.close_intent_digest
            .set_witness(witness, value.close_intent_digest);
        witness
            .set_target(
                self.channel_id[0],
                F::from_canonical_u64(value.channel_id.to_u64_vec()[0]),
            )
            .unwrap();
        self.final_balance_state_h1
            .set_witness(witness, value.final_balance_state_h1);
        self.member_pk_g.set_witness(witness, value.member_pk_g);
        self.recipient.set_witness(witness, value.recipient);
        self.user_amount_digest
            .set_witness(witness, value.user_amount_digest);
        self.withdrawal_nullifier
            .set_witness(witness, value.withdrawal_nullifier);
        self.amount.set_witness(witness, U64::from(value.amount));
        witness
            .set_target(self.token_slot[0], F::from_canonical_u8(value.token_slot))
            .unwrap();
        witness
            .set_target(
                self.token_index[0],
                F::from_canonical_u32(value.token_index),
            )
            .unwrap();
    }
}

#[derive(Debug, Error)]
pub enum WithdrawalClaimCircuitError {
    #[error("member_index {0} out of range (>= MAX_CHANNEL_MEMBERS)")]
    MemberIndexOutOfRange(usize),
    #[error("failed to prove: {0}")]
    FailedToProve(String),
}

/// Prover witness for [`WithdrawalClaimCircuit`]: the final balance state's H1 header scalars,
/// the balance-slot tree root, and the claimant slot's leaf data + Merkle inclusion proof
/// (H1 Poseidon-root form — the full 1024-slot vectors are gone; the tree lives in storage/DB).
#[derive(Clone, Debug)]
pub struct WithdrawalClaimFullWitness {
    pub public_inputs: WithdrawalClaimPublicInputs,
    /// The balance-slot tree root of the final balance state
    /// (`BalanceState::slot_tree_root()`, committed inside the signed H1 header).
    pub slot_tree_root: PoseidonHashOut,
    /// Merkle inclusion proof of the claimant's slot leaf at `member_index` in the slot tree
    /// (`BalanceState::slot_tree().prove(member_index)`).
    pub slot_inclusion: IncrementalMerkleProof<PoseidonHashOut>,
    /// The claimant slot's FULL per-token ciphertext digest row
    /// (`BalanceState::token_ct_digests(&enc_balances[member_index])`, leaf fields). Position
    /// `token_slot` is constrained equal to the `user_amount_digest` PI by the in-circuit
    /// one-hot select; the other 9 positions are bound by the leaf hash + inclusion.
    pub slot_ct_digests: [Bytes32; MAX_CHANNEL_TOKENS],
    /// The claimant slot's FULL per-token homomorphic-add counter row
    /// (`pending_adds[member_index]`, leaf fields).
    pub slot_pending_adds: [u32; MAX_CHANNEL_TOKENS],
    /// The final state's signed `token_count` (H1 header scalar, TM-8/TM-9).
    pub token_count: u8,
    /// The final state's signed `token_registry` (H1 header limbs, TM-9); the circuit selects
    /// `registry[token_slot]` as the exposed base `token_index`.
    pub token_registry: [u32; MAX_CHANNEL_TOKENS],
    pub settled_tx_chain: Bytes32,
    /// Stage 3: the settled-tx accumulator root of the final balance state (in the signed H1).
    pub settled_tx_accumulator_root: Bytes32,
    pub state_version: u64,
    /// active region size = member_count + delegate_count.
    pub member_count: u8,
    /// WIDTH: u16 — delegate slots span the full 1024 balance-slot space (Option B).
    pub delegate_count: u16,
    /// claimant slot index (`< member_count + delegate_count`).
    pub member_index: usize,
    /// Decryption Stage 2: the claimant's Regev public key `(a, b)` coefficients (canonical `< q`,
    /// length `REGEV_N` each). Bound in-circuit to `regev_pk_digests[member_index]` (the
    /// H1-committed digest) AND to the secret key via the key-binding gate — THE pk binding
    /// (MUST-FIX #1).
    pub regev_a: Vec<u32>,
    pub regev_b: Vec<u32>,
    /// Decryption Stage 2: the slot ciphertext `(c1, c2)` (canonical `< q`, length `REGEV_N`
    /// each). Bound in-circuit to `user_amount_digest` via the IMRC digest gadget.
    pub ct_c1: Vec<u32>,
    pub ct_c2: Vec<u32>,
    /// Decryption Stage 2: the claimant's ternary secret key `s ∈ {−1,0,1}^REGEV_N`. Private
    /// witness; drives the key-binding + decryption gates. NEVER exposed.
    pub regev_s: Vec<i8>,
}

pub struct WithdrawalClaimCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    /// Gate count before power-of-two padding, for profiling regressions.
    pub num_gates_before_padding: usize,
    /// Cumulative gate counts at the principal construction boundaries.
    pub profile: WithdrawalClaimCircuitProfile,
    pub public_inputs: WithdrawalClaimPublicInputsTarget,
    member_count: Target,
    delegate_count: Target,
    /// The H1-committed balance-slot tree root (4 raw Goldilocks elements). Bound to the
    /// `final_balance_state_h1` PI via the shared header recompute.
    slot_tree_root: PoseidonHashOutTarget,
    settled_tx_chain: Bytes32Target,
    settled_tx_accumulator_root: Bytes32Target,
    state_version: U64Target,
    /// Claimant slot index (Merkle position; `split_le(index, height)` inside the inclusion
    /// verify bounds it to `< MAX_CHANNEL_MEMBERS`).
    member_index: Target,
    /// The final state's signed `token_count` (H1 header scalar; TM-8 bound `token_slot <
    /// token_count`).
    token_count: Target,
    /// The final state's signed `token_registry` limbs (H1 header; `registry[token_slot]` is
    /// the exposed base `token_index`).
    token_registry: [Target; MAX_CHANNEL_TOKENS],
    /// The claimant slot's FULL per-token ciphertext digest row (leaf fields; position
    /// `token_slot` one-hot-connected to the `user_amount_digest` PI).
    slot_ct_digests: [Bytes32Target; MAX_CHANNEL_TOKENS],
    /// The claimant slot's FULL per-token `pending_adds` leaf fields.
    slot_pending_adds: [Target; MAX_CHANNEL_TOKENS],
    /// Height-`BALANCE_SLOT_TREE_HEIGHT` inclusion proof of the claimant's slot leaf.
    slot_inclusion: IncrementalMerkleProofTarget<PoseidonHashOutTarget>,
    /// Decryption Stage 2: witnessed Regev pk/ct polynomials and the decryption-core witness
    /// handles.
    regev_a: Vec<Target>,
    regev_b: Vec<Target>,
    ct_c1: Vec<Target>,
    ct_c2: Vec<Target>,
    dec_core: DecryptionCoreTargets,
}

#[derive(Clone, Copy, Debug)]
pub struct WithdrawalClaimCircuitProfile {
    pub inputs: usize,
    pub header_and_selectors: usize,
    pub regev_digests: usize,
    pub slot_inclusion: usize,
    pub decryption: usize,
    pub nullifier: usize,
}

impl<F, C, const D: usize> WithdrawalClaimCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = WithdrawalClaimPublicInputsTarget::new(&mut builder);
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };

        let member_count = u32_limb(&mut builder);
        let delegate_count = u32_limb(&mut builder);
        // Multi-token header scalars (§N-1, TM-9): the signed token_count + full zero-padded
        // registry — witnessed, then bound to the finalized H1 PI by the header recompute below,
        // so the TM-8 bound and the registry resolution both read member-signed values.
        let token_count = u32_limb(&mut builder);
        let token_registry: [Target; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| u32_limb(&mut builder));
        // The H1-committed balance-slot tree root (4 raw Goldilocks elements) — bound to the
        // finalized H1 PI by the header recompute below, then OPENED at the claimant's slot by
        // the Merkle inclusion proof.
        let slot_tree_root = PoseidonHashOutTarget::new(&mut builder);
        let settled_tx_chain = Bytes32Target::new(&mut builder, true);
        let settled_tx_accumulator_root = Bytes32Target::new(&mut builder, true);
        let state_version = U64Target::new(&mut builder, true);
        // Claimant slot index. `split_le(member_index, BALANCE_SLOT_TREE_HEIGHT)` inside the
        // inclusion verify bounds it to `< MAX_CHANNEL_MEMBERS`.
        let member_index = builder.add_virtual_target();
        // The claimant slot's FULL per-token leaf fields (v2 104-element leaf, §N-2): 10
        // ciphertext digests + 10 pending-adds counters (all 32-bit range-checked; the leaf hash
        // binds them to the H1-committed slot data).
        let slot_ct_digests: [Bytes32Target; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| Bytes32Target::new(&mut builder, true));
        let slot_pending_adds: [Target; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| u32_limb(&mut builder));
        let gates_after_inputs = builder.num_gates();

        // ── (1) H1 header recompute (SHARED v2 gadget; element-identical to close + native) ──
        let recomputed_h1 = recompute_h1::<F, D>(
            &mut builder,
            public_inputs.channel_id[0],
            member_count,
            delegate_count,
            token_count,
            &token_registry,
            slot_tree_root,
            &settled_tx_chain,
            &settled_tx_accumulator_root,
            &state_version,
        );
        recomputed_h1.connect(&mut builder, public_inputs.final_balance_state_h1);

        // ── (2) active-region check: member_index < member_count + delegate_count ──
        //
        // `active = member_count + delegate_count`; both are part of the H1 header above, so the
        // active/padding boundary is fixed under the members' signed final state. Padding slots
        // (`member_index >= active`) are rejected.
        let one = builder.one();
        let active = builder.add(member_count, delegate_count);
        // SECURITY (defense-in-depth, adversarial review O1): bound `active` to
        // `[0, MAX_CHANNEL_MEMBERS]` IN-CIRCUIT so padding-slot safety does NOT rely solely on the
        // upstream signed `BalanceState::validate()` invariant (member_count + delegate_count <=
        // MAX). Without this, an oversized witnessed `active` could make the `less_than_u32`
        // comparison below misbehave; with it, `active` is small and canonical, so the
        // active-region check is self-contained. `member_count`/`delegate_count` are individually
        // 32-bit range-checked above; here we additionally pin their SUM <= MAX_CHANNEL_MEMBERS.
        {
            let max_active = builder.constant(F::from_canonical_usize(MAX_CHANNEL_MEMBERS));
            // Range-check active to ceil(log2(MAX_CHANNEL_MEMBERS)) + 1 = 11 bits (MAX = 1024
            // needs 11 bits to represent), then assert active <= MAX via the strict less-than
            // (active < MAX + 1). NOTE: the former 8-bit check was a stale MAX = 16 leftover
            // that would have REJECTED legal states with active > 255 (completeness, not
            // soundness).
            builder.range_check(active, 11);
            let max_plus_one = builder.add_const(max_active, F::ONE);
            let active_le_max = less_than_u32(&mut builder, active, max_plus_one);
            builder.assert_one(active_le_max.target);
        }
        let is_active = less_than_u32(&mut builder, member_index, active);
        builder.connect(is_active.target, one);

        // ── (2') PER-(SLOT, TOKEN) claim constraints (detail2 §N-6, TM-2/TM-8) ──
        //
        // One-hot flags derived from the `token_slot` PI ITSELF: `flag[t] = (token_slot == t)`.
        // Σ flags == 1 forces `token_slot ∈ {0..MAX_CHANNEL_TOKENS-1}` exactly (any other value
        // zeroes every flag and the sum constraint is unsatisfiable) — the selector is canonical
        // and IS the exposed PI, so "the selected position equals the PI token_slot" holds by
        // construction (TM-2 in-claim analogue: no separately-witnessed select index exists to
        // diverge).
        let token_slot = public_inputs.token_slot[0];
        let mut token_slot_flags: Vec<BoolTarget> = Vec::with_capacity(MAX_CHANNEL_TOKENS);
        let mut flags_sum = builder.zero();
        for t in 0..MAX_CHANNEL_TOKENS {
            let t_const = builder.constant(F::from_canonical_usize(t));
            let is_sel = builder.is_equal(token_slot, t_const);
            flags_sum = builder.add(flags_sum, is_sel.target);
            token_slot_flags.push(is_sel);
        }
        builder.connect(flags_sum, one);

        // TM-8: the claimed position must be ACTIVE — `token_slot < token_count`, with
        // `token_count` the H1-bound signed header scalar (positions >= token_count are the
        // canonical zero ciphertext; a claim there is refused outright rather than relying on
        // zero-decryption).
        let token_slot_active = less_than_u32(&mut builder, token_slot, token_count);
        builder.connect(token_slot_active.target, one);

        // ONE-HOT ct select: `ct_digests[token_slot] == user_amount_digest` PI, limb for limb.
        // The select chain reads the SAME `slot_ct_digests` targets the leaf hash (and hence the
        // Merkle inclusion against the signed root) commits, so the ciphertext being decrypted
        // is provably the one stored at the claimed token position — feeding another position's
        // ciphertext breaks this equality (TM-2).
        let zero_t = builder.zero();
        for k in 0..8 {
            let mut selected = zero_t;
            for (t, flag) in token_slot_flags.iter().enumerate() {
                let limb = slot_ct_digests[t].to_vec()[k];
                selected = builder.select(*flag, limb, selected);
            }
            builder.connect(selected, public_inputs.user_amount_digest.to_vec()[k]);
        }

        // BASE token resolution (review m8): `token_index` PI == `registry[token_slot]`,
        // selected from the H1-bound registry limbs — the prover has NO choice of payout asset
        // beyond the signed registry mapping of the claimed slot.
        let mut selected_index = zero_t;
        for (t, flag) in token_slot_flags.iter().enumerate() {
            selected_index = builder.select(*flag, token_registry[t], selected_index);
        }
        builder.connect(selected_index, public_inputs.token_index[0]);
        let gates_after_header_and_selectors = builder.num_gates();

        // ── Decryption Stage 2 (closes over-claim): bind `amount` to the slot ciphertext
        // plaintext.
        //
        // 1. Witness the claimant's Regev pk (a, b) and the slot ct (c1, c2). `decryption_core`
        //    pins all four to canonical `< q` and rejects a == 0 / c1 == 0.
        // 2. (CRITICAL pk-binding, MUST-FIX #1) `poseidon_digest(a, b)` is a FIELD of the slot leaf
        //    opened at `member_index` below (H1-committed, signed). This forces (a, b) to be the
        //    member's REGISTERED key, so the key-binding gate ties `s` to the registered secret.
        // 3. `IMRC_digest(c1, c2)` == `user_amount_digest` (the PI that is ALSO a field of the same
        //    slot leaf) — ties the decryption to the finalized slot ciphertext.
        // 4. `decryption_core(..., expose_amount = true)` recomputes the plaintext `v = c2 − c1·s`
        //    under the key-bound `s`, decodes the 64-bit amount, and exposes (lo, hi) limbs; we
        //    connect them to the `amount` PI U64. After this, `amount` is NO LONGER free.
        let regev_a: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let regev_b: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let ct_c1: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let ct_c2: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();

        // (pk digest) poseidon_digest(a, b) — becomes the leaf's regev_pk_digest field below.
        let pk_digest = regev_pk_poseidon_digest_gadget::<F, D>(&mut builder, &regev_a, &regev_b);

        // (ct binding) IMRC_digest(c1, c2) == user_amount_digest (the slot ct, leaf-bound below).
        let ct_digest = regev_ct_digest_gadget::<F, C, D>(&mut builder, &ct_c1, &ct_c2);
        ct_digest.connect(&mut builder, public_inputs.user_amount_digest);
        let gates_after_regev_digests = builder.num_gates();

        // ── (3) slot-leaf Merkle inclusion (v2 104-element leaf, §N-2) ──
        //
        // leaf = Poseidon([IMS2, pk_digest, ct_digests[0..10], pending_adds[0..10], recipient])
        // MUST be included at `member_index` in the H1-committed `slot_tree_root`. ONE leaf binds
        // ALL slot fields to the SAME index (the Merkle position IS the slot index), so the full
        // per-token ciphertext row (position `token_slot` of which is the `user_amount_digest` PI
        // via the one-hot select above), the registered Regev pk digest (via the gadget output —
        // THE pk binding, MUST-FIX #1), the slot's add counters AND the slot's L1 exit address
        // are exactly the signed slot-`member_index` values. `pk_digest`'s limbs are u32 by
        // construction (`Bytes32Target::from_hash_out` safe split); the ct digests, counters and
        // `recipient` are range-checked above.
        //
        // SECURITY (B-1b — THE delegate recipient binding): the leaf's recipient field IS the
        // claim's `recipient` PI (`public_inputs.recipient` is fed directly into the leaf hash),
        // so a proof only exists when the exposed recipient equals the cosigner-signed per-slot
        // exit address inside H1. Under Option B delegates have no `registeredRecipientOf` entry
        // on L1, so this connection is the ONLY thing preventing a delegate payout redirection.
        // (The Manager-side switch from `registeredRecipientOf` to this PI is B-2.)
        let slot_leaf = balance_slot_leaf_hash_circuit::<F, D>(
            &mut builder,
            &pk_digest,
            &slot_ct_digests,
            &slot_pending_adds,
            &public_inputs.recipient,
        );
        let slot_inclusion = IncrementalMerkleProofTarget::<PoseidonHashOutTarget>::new(
            &mut builder,
            BALANCE_SLOT_TREE_HEIGHT,
        );
        slot_inclusion.verify::<F, C, D>(&mut builder, &slot_leaf, member_index, slot_tree_root);
        let gates_after_slot_inclusion = builder.num_gates();

        // (decryption + amount binding) bind the claim's U64 amount to the decrypted plaintext.
        let dec_inputs = DecryptionCoreInputs {
            a: &regev_a,
            b: &regev_b,
            c1: &ct_c1,
            c2: &ct_c2,
        };
        let (dec_core, amount_limbs) = decryption_core(&mut builder, &dec_inputs, true);
        let (amount_lo, amount_hi) =
            amount_limbs.expect("expose_amount = true yields amount limbs");
        // The amount PI U64 is `to_vec() = [hi, lo]` (U64Target limb order).
        let amount_pi = public_inputs.amount.to_vec();
        builder.connect(amount_pi[0], amount_hi);
        builder.connect(amount_pi[1], amount_lo);
        let gates_after_decryption = builder.num_gates();

        // ── (4) withdrawal_nullifier = keccak([IMW2, close_intent_digest, pk_digest,
        // token_slot]) — the v2 per-(slot, token) nullifier (detail2 §N-6, TM-5) ──
        //
        // SECURITY (B-2 blocker fix, preserved): the nullifier is keyed on the LEAF-BOUND slot
        // Regev pk digest `pk_digest` (bound at `member_index` in `slot_tree_root` via the
        // inclusion at step (3)), NOT the slot-free `member_pk_g` PI. This makes the nullifier
        // slot-unique: a slot owner cannot grind `member_pk_g` to mint distinct nullifiers and
        // multi-withdraw the same slot once the Manager admits delegate claims (B-2).
        // `member_pk_g` remains an informational PI and MUST NOT be trusted as the nullifier key
        // on-chain.
        //
        // SECURITY (TM-5, multi-token): `token_slot` — the SAME PI wire that drives the one-hot
        // ct select and the `< token_count` bound — is the final preimage limb, so each
        // (slot, token) pair yields exactly ONE nullifier and a nullifier minted for token t
        // cannot be replayed for token t'. Mirrors the native
        // `WithdrawalClaim::derive_nullifier` ("IMW2", 18 limbs) byte-for-byte.
        let withdrawal_domain = builder.constant(F::from_canonical_u32(WITHDRAWAL_CLAIM_DOMAIN_V2));
        let nullifier_inputs = [
            vec![withdrawal_domain],
            public_inputs.close_intent_digest.to_vec(),
            pk_digest.to_vec(),
            vec![token_slot],
        ]
        .concat();
        let withdrawal_nullifier =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&nullifier_inputs));
        withdrawal_nullifier.connect(&mut builder, public_inputs.withdrawal_nullifier);
        let gates_after_nullifier = builder.num_gates();

        // (5) channel_id / member_pk_g / close_intent_digest are bound as PI limbs by
        // construction (they are the registered PI targets, re-registered verbatim below);
        // `recipient` is additionally LEAF-BOUND (B-1b, step (3) above) — it is no longer a free
        // PI. `amount` is range-checked to u64 by `U64Target::new(builder, true)` and
        // decryption-bound above.

        builder.register_public_inputs(&public_inputs.to_vec());
        let num_gates_before_padding = builder.num_gates();
        let profile = WithdrawalClaimCircuitProfile {
            inputs: gates_after_inputs,
            header_and_selectors: gates_after_header_and_selectors,
            regev_digests: gates_after_regev_digests,
            slot_inclusion: gates_after_slot_inclusion,
            decryption: gates_after_decryption,
            nullifier: gates_after_nullifier,
        };
        let data = builder.build::<C>();
        Self {
            data,
            num_gates_before_padding,
            profile,
            public_inputs,
            member_count,
            delegate_count,
            token_count,
            token_registry,
            slot_tree_root,
            settled_tx_chain,
            settled_tx_accumulator_root,
            state_version,
            member_index,
            slot_ct_digests,
            slot_pending_adds,
            slot_inclusion,
            regev_a,
            regev_b,
            ct_c1,
            ct_c2,
            dec_core,
        }
    }

    fn fill_witness(
        &self,
        witness_value: &WithdrawalClaimFullWitness,
    ) -> Result<PartialWitness<F>, WithdrawalClaimCircuitError> {
        if witness_value.member_index >= MAX_CHANNEL_MEMBERS {
            return Err(WithdrawalClaimCircuitError::MemberIndexOutOfRange(
                witness_value.member_index,
            ));
        }
        let mut witness = PartialWitness::<F>::new();
        self.public_inputs
            .set_witness(&mut witness, &witness_value.public_inputs);
        witness
            .set_target(
                self.member_count,
                F::from_canonical_u8(witness_value.member_count),
            )
            .unwrap();
        witness
            .set_target(
                self.delegate_count,
                F::from_canonical_u16(witness_value.delegate_count),
            )
            .unwrap();
        // H1 Poseidon-root form: the slot tree root + the claimant slot's inclusion proof
        // (leaf fields: pk digest and ct digest are derived in-circuit; pending_adds is set here).
        self.slot_tree_root
            .set_witness(&mut witness, witness_value.slot_tree_root);
        self.slot_inclusion
            .set_witness(&mut witness, &witness_value.slot_inclusion);
        witness
            .set_target(
                self.member_index,
                F::from_canonical_usize(witness_value.member_index),
            )
            .unwrap();
        // Multi-token (v2): the signed token_count/registry (H1 header) + the claimant slot's
        // full per-token leaf fields.
        witness
            .set_target(
                self.token_count,
                F::from_canonical_u8(witness_value.token_count),
            )
            .unwrap();
        for (t, &limb) in witness_value.token_registry.iter().enumerate() {
            witness
                .set_target(self.token_registry[t], F::from_canonical_u32(limb))
                .unwrap();
        }
        for (t, digest) in witness_value.slot_ct_digests.iter().enumerate() {
            self.slot_ct_digests[t].set_witness(&mut witness, *digest);
        }
        for (t, &adds) in witness_value.slot_pending_adds.iter().enumerate() {
            witness
                .set_target(self.slot_pending_adds[t], F::from_canonical_u32(adds))
                .unwrap();
        }
        self.settled_tx_chain
            .set_witness(&mut witness, witness_value.settled_tx_chain);
        self.settled_tx_accumulator_root
            .set_witness(&mut witness, witness_value.settled_tx_accumulator_root);
        self.state_version
            .set_witness(&mut witness, U64::from(witness_value.state_version));

        // Decryption Stage 2: set the Regev pk/ct polynomials and the decryption-core witness.
        let set_poly = |witness: &mut PartialWitness<F>, targets: &[Target], vals: &[u32]| {
            for (&t, &v) in targets.iter().zip(vals) {
                witness.set_target(t, F::from_canonical_u32(v)).unwrap();
            }
        };
        set_poly(&mut witness, &self.regev_a, &witness_value.regev_a);
        set_poly(&mut witness, &self.regev_b, &witness_value.regev_b);
        set_poly(&mut witness, &self.ct_c1, &witness_value.ct_c1);
        set_poly(&mut witness, &self.ct_c2, &witness_value.ct_c2);
        let core_w = build_decryption_core_witness(
            &witness_value.regev_a,
            &witness_value.regev_b,
            &witness_value.ct_c1,
            &witness_value.ct_c2,
            &witness_value.regev_s,
        )
        .map_err(|()| {
            WithdrawalClaimCircuitError::FailedToProve(
                "decryption-core witness build failed (inconsistent pk/sk/ct or out-of-budget noise)"
                    .to_string(),
            )
        })?;
        fill_decryption_core::<F, D, _>(&mut witness, &self.dec_core, &core_w);

        Ok(witness)
    }

    pub fn prove(
        &self,
        witness_value: &WithdrawalClaimFullWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalClaimCircuitError> {
        let witness = self.fill_witness(witness_value)?;
        self.data
            .prove(witness)
            .map_err(|e| WithdrawalClaimCircuitError::FailedToProve(e.to_string()))
    }
}

impl<F, C, const D: usize> Default for WithdrawalClaimCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Strict less-than on two SMALL u32-range targets (`a, b < 2^32`; here `member_index <
/// MAX_CHANNEL_MEMBERS` via the inclusion proof's `split_le` and `active <= MAX_CHANNEL_MEMBERS`
/// via its 11-bit range check). Returns a Boolean `a < b` from the canonical 33-bit borrow
/// comparison of `b - a + 2^32` (bit 32 = "no borrow" ⇔ a <= b; nonzero low limbs ⇔ a != b).
fn less_than_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> BoolTarget {
    // a < b  ⇔  a + 1 <= b. Compute (b - a) and test it lies in [1, 2^32). Decompose
    // `b - a + 2^32` into 33 bits; bit 32 is the "no-borrow" flag (a <= b), and the low 32 bits
    // being non-zero gives strict inequality. We combine: result = (a <= b) && (b - a != 0).
    let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));
    let diff = builder.sub(b, a); // = b - a (mod p); valid since both small.
    let shifted = builder.add(diff, two_pow_32);
    let bits = builder.split_le(shifted, 33);
    let no_borrow = bits[32]; // 1 iff b - a >= 0, i.e. a <= b.
    // low 32 bits == 0 iff b == a.
    let low: Vec<Target> = bits[0..32].iter().map(|b| b.target).collect();
    let low_sum = builder.add_many(low);
    let zero = builder.zero();
    let is_zero = builder.is_equal(low_sum, zero);
    let is_nonzero = builder.not(is_zero);
    builder.and(no_borrow, is_nonzero)
}

// SECURITY / TEST-GATING: shared witness builders for the withdrawal-claim circuit, compiled for
// the test suite AND for the `withdrawal-claim-fixture-bin` feature (the fixture generator). Single
// canonical copy, off by default — normal builds are unaffected.
#[cfg(any(test, feature = "withdrawal-claim-fixture-bin"))]
pub mod test_fixture {
    use std::sync::OnceLock;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::{WithdrawalClaimCircuit, WithdrawalClaimFullWitness};
    use crate::{
        circuits::channel::withdrawal_claim_pis::{
            WithdrawalClaimPublicInputs, WithdrawalClaimWitness,
        },
        common::{
            balance_state::BalanceState,
            channel::{
                ChannelFund, ChannelId, ChannelMember, ChannelState, CloseIntent, CloseWithdrawal,
                MemberSignature, WithdrawalClaim,
            },
        },
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
        regev::{RegevSecurityLevel, channel_keygen, encrypt_amount, prove_withdraw_claim},
    };

    pub const D: usize = 2;
    pub type F = GoldilocksField;
    pub type C = PoseidonGoldilocksConfig;

    pub fn circuit() -> &'static WithdrawalClaimCircuit<F, C, D> {
        static CIRCUIT: OnceLock<WithdrawalClaimCircuit<F, C, D>> = OnceLock::new();
        CIRCUIT.get_or_init(WithdrawalClaimCircuit::<F, C, D>::new)
    }

    /// Build a REAL, self-consistent withdrawal-claim witness (3 members, claimant in slot 0) and
    /// the matching `WithdrawalClaimFullWitness` for the circuit. The E-3 decryption proof is
    /// produced too (so the NATIVE `to_public_inputs` validates), but the CIRCUIT does NOT verify
    /// it (Option D). SHARED by the unit tests and the fixture-generator binary.
    pub fn build_full_witness() -> WithdrawalClaimFullWitness {
        build_full_witness_with_state().0
    }

    /// [`build_full_witness`] plus the underlying final `BalanceState` (so negative tests can
    /// doctor the slot tree / H1 consistently).
    pub fn build_full_witness_with_state() -> (WithdrawalClaimFullWitness, BalanceState) {
        let mut rng = SmallRng::seed_from_u64(0xC1A1_u64);
        let channel_id = ChannelId::new(3).unwrap();
        let (pk0, sk0) = channel_keygen(&mut rng);
        let (pk1, _) = channel_keygen(&mut rng);
        let (pk2, _) = channel_keygen(&mut rng);

        let amount = 77u64;
        let (ct0, _) = encrypt_amount(&mut rng, &pk0, amount).unwrap();
        let (ct1, _) = encrypt_amount(&mut rng, &pk1, 5).unwrap();
        let (ct2, _) = encrypt_amount(&mut rng, &pk2, 11).unwrap();
        let final_balance_state = BalanceState {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&[ct0.clone(), ct1, ct2]),
            // Decryption Stage 1: the active slots carry the real member Regev pk Poseidon digests
            // (Bytes32::from(poseidon_digest)); padding slots are Bytes32::default().
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(pk0.poseidon_digest()),
                Bytes32::from(pk1.poseidon_digest()),
                Bytes32::from(pk2.poseidon_digest()),
            ]),
            // B-1b: each active slot's cosigner-signed L1 exit address. Slot 0 (the claimant) is
            // the SAME address the claim exposes as its `recipient` PI below.
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
                Address::from_u32_slice(&[31, 32, 33, 34, 35]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 6,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        };
        let state = ChannelState {
            channel_id,
            epoch: 8,
            small_block_number: 5,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amounts: ChannelFund::single_token_amounts(U256::from(93u32)),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: final_balance_state.clone(),
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                pk_g: Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap(),
                signature: vec![1],
            }],
        }
        .with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::default(),
            burn_amount: state.channel_fund.amounts[0],
            zkp: vec![9],
        };
        let close_intent = CloseIntent::new(&state, &close_tx).unwrap();
        let member = ChannelMember {
            pk_g: Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap(),
            member_slot: 0,
            l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        };
        let claim_proof =
            prove_withdraw_claim(RegevSecurityLevel::Test, &pk0, &sk0, &ct0, amount).unwrap();
        let claim = WithdrawalClaim {
            token_slot: 0,
            close_intent_digest: close_intent.signing_digest(),
            member_pk_g: member.pk_g,
            l1_recipient: member.l1_withdrawal_recipient,
            user_amount_ct: ct0.clone(),
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                Bytes32::from(pk0.poseidon_digest()),
                0,
            ),
            claim_proof,
        };
        let native = WithdrawalClaimWitness {
            close_intent,
            close_tx,
            member,
            claim,
            final_balance_state: final_balance_state.clone(),
            member_index: 0,
            user_pk: pk0.clone(),
            amount,
        };
        let public_inputs: WithdrawalClaimPublicInputs =
            native.to_public_inputs(RegevSecurityLevel::Test).unwrap();

        // H1 Poseidon-root form: the slot tree + the claimant's (slot 0) inclusion proof.
        let slot_tree = final_balance_state.slot_tree();
        let member_index = 0usize;

        let full_witness = WithdrawalClaimFullWitness {
            public_inputs,
            slot_tree_root: slot_tree.get_root(),
            slot_inclusion: slot_tree.prove(member_index as u64),
            // Multi-token (v2): the FULL per-token leaf fields of the claimant slot + the
            // signed token header scalars.
            slot_ct_digests: BalanceState::token_ct_digests(
                &final_balance_state.enc_balances[member_index],
            ),
            slot_pending_adds: final_balance_state.pending_adds[member_index],
            token_count: final_balance_state.token_count,
            token_registry: final_balance_state.token_registry,
            settled_tx_chain: final_balance_state.settled_tx_chain,
            settled_tx_accumulator_root: final_balance_state.settled_tx_accumulator_root,
            state_version: final_balance_state.state_version,
            member_count: final_balance_state.member_count,
            delegate_count: final_balance_state.delegate_count,
            member_index,
            // Decryption Stage 2: the claimant's (slot 0) real Regev key + slot ciphertext.
            regev_a: pk0.a.clone(),
            regev_b: pk0.b.clone(),
            ct_c1: ct0.c1.clone(),
            ct_c2: ct0.c2.clone(),
            regev_s: sk0.s.clone(),
        };
        (full_witness, final_balance_state)
    }

    /// The claimant's per-token plaintexts in [`build_multitoken_witness_with_state`]:
    /// token slot 0 holds 77, token slot 1 holds 33.
    pub const MT_AMOUNTS: [u64; 2] = [77, 33];
    /// The base token_index registered at local token slot 1 in the multi-token fixture.
    pub const MT_TOKEN1_INDEX: u32 = 7;

    /// Multi-token claim fixture (detail2 §N-6): 3 members, `token_count = 2`, registry
    /// `[0 (ETH), MT_TOKEN1_INDEX]`. The claimant (slot 0) holds REAL ciphertexts at BOTH active
    /// token positions under the SAME Regev key (`MT_AMOUNTS`); `token_slot` selects which
    /// position the claim withdraws. Routed through the NATIVE
    /// `WithdrawalClaimWitness::to_public_inputs` (state validation + E-3 verification), exactly
    /// like the single-token builder. Non-genesis channel-FUND amounts stay zero (per-token L1
    /// settlement is Phase 3); member BALANCES at token 1 are unconstrained by the close intent.
    pub fn build_multitoken_witness_with_state(
        token_slot: u8,
    ) -> (WithdrawalClaimFullWitness, BalanceState) {
        use crate::common::balance_state::zero_token_row;
        assert!(token_slot < 2, "fixture has two active token positions");
        let mut rng = SmallRng::seed_from_u64(0xC1A2_u64);
        let channel_id = ChannelId::new(3).unwrap();
        let (pk0, sk0) = channel_keygen(&mut rng);
        let (pk1, _) = channel_keygen(&mut rng);
        let (pk2, _) = channel_keygen(&mut rng);

        let (ct0_t0, _) = encrypt_amount(&mut rng, &pk0, MT_AMOUNTS[0]).unwrap();
        let (ct0_t1, _) = encrypt_amount(&mut rng, &pk0, MT_AMOUNTS[1]).unwrap();
        let (ct1, _) = encrypt_amount(&mut rng, &pk1, 5).unwrap();
        let (ct2, _) = encrypt_amount(&mut rng, &pk2, 11).unwrap();
        let mut row0 = zero_token_row();
        row0[0] = ct0_t0;
        row0[1] = ct0_t1;
        let mut row1 = zero_token_row();
        row1[0] = ct1;
        let mut row2 = zero_token_row();
        row2[0] = ct2;
        let mut token_registry = BalanceState::single_token_registry(0);
        token_registry[1] = MT_TOKEN1_INDEX;
        let final_balance_state = BalanceState {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[row0, row1, row2]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(pk0.poseidon_digest()),
                Bytes32::from(pk1.poseidon_digest()),
                Bytes32::from(pk2.poseidon_digest()),
            ]),
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
                Address::from_u32_slice(&[31, 32, 33, 34, 35]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 6,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
            token_registry,
            token_count: 2,
        };
        final_balance_state
            .validate()
            .expect("multi-token fixture state must be valid");
        let state = ChannelState {
            channel_id,
            epoch: 8,
            small_block_number: 5,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amounts: ChannelFund::single_token_amounts(U256::from(93u32)),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: final_balance_state.clone(),
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                pk_g: Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap(),
                signature: vec![1],
            }],
        }
        .with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::default(),
            burn_amount: state.channel_fund.amounts[0],
            zkp: vec![9],
        };
        let close_intent = CloseIntent::new(&state, &close_tx).unwrap();
        let member = ChannelMember {
            pk_g: Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap(),
            member_slot: 0,
            l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        };
        let amount = MT_AMOUNTS[token_slot as usize];
        let ct = final_balance_state.enc_balances[0][token_slot as usize].clone();
        let claim_proof =
            prove_withdraw_claim(RegevSecurityLevel::Test, &pk0, &sk0, &ct, amount).unwrap();
        let claim = WithdrawalClaim {
            token_slot,
            close_intent_digest: close_intent.signing_digest(),
            member_pk_g: member.pk_g,
            l1_recipient: member.l1_withdrawal_recipient,
            user_amount_ct: ct.clone(),
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                Bytes32::from(pk0.poseidon_digest()),
                token_slot,
            ),
            claim_proof,
        };
        let native = WithdrawalClaimWitness {
            close_intent,
            close_tx,
            member,
            claim,
            final_balance_state: final_balance_state.clone(),
            member_index: 0,
            user_pk: pk0.clone(),
            amount,
        };
        let public_inputs: WithdrawalClaimPublicInputs =
            native.to_public_inputs(RegevSecurityLevel::Test).unwrap();

        let slot_tree = final_balance_state.slot_tree();
        let member_index = 0usize;
        let full_witness = WithdrawalClaimFullWitness {
            public_inputs,
            slot_tree_root: slot_tree.get_root(),
            slot_inclusion: slot_tree.prove(member_index as u64),
            slot_ct_digests: BalanceState::token_ct_digests(
                &final_balance_state.enc_balances[member_index],
            ),
            slot_pending_adds: final_balance_state.pending_adds[member_index],
            token_count: final_balance_state.token_count,
            token_registry: final_balance_state.token_registry,
            settled_tx_chain: final_balance_state.settled_tx_chain,
            settled_tx_accumulator_root: final_balance_state.settled_tx_accumulator_root,
            state_version: final_balance_state.state_version,
            member_count: final_balance_state.member_count,
            delegate_count: final_balance_state.delegate_count,
            member_index,
            regev_a: pk0.a.clone(),
            regev_b: pk0.b.clone(),
            ct_c1: ct.c1.clone(),
            ct_c2: ct.c2.clone(),
            regev_s: sk0.s.clone(),
        };
        (full_witness, final_balance_state)
    }
}

#[cfg(test)]
mod tests {

    // Multitoken Phase 2: the close/claim circuits now compute the v2 H1 header (37 elems,
    // "IMB2") and slot leaf (104 elems, "IMS2"), so the tests below run against v2-signed
    // states (the Phase 1 #[ignore] gates are lifted; assertions unchanged).
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        time::Instant,
    };

    use plonky2::field::types::PrimeField64;

    use super::test_fixture::*;
    use crate::circuits::channel::withdrawal_claim_pis::WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN;

    /// Happy path: a real withdrawal-claim binding proves and the 48 exposed limbs equal the
    /// `WithdrawalClaimPublicInputs::to_u64_vec()` layout.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_proves_and_exposes_pis() {
        let build_started = Instant::now();
        let circuit = circuit();
        let build = build_started.elapsed();
        let witness = build_full_witness();
        let prove_started = Instant::now();
        let proof = circuit.prove(&witness).unwrap();
        let prove = prove_started.elapsed();
        let proof_bytes = proof.to_bytes().len();
        let verify_started = Instant::now();
        circuit.data.verify(proof.clone()).unwrap();
        let verify = verify_started.elapsed();

        println!(
            "withdrawal-claim: gates={} degree=2^{} build={build:?} prove={prove:?} \
             verify={verify:?} proof={proof_bytes} B profile={:?}",
            circuit.num_gates_before_padding,
            circuit.data.common.degree_bits(),
            circuit.profile,
        );

        let expected = witness.public_inputs.to_u64_vec();
        assert_eq!(expected.len(), WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN);
        let actual: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        assert_eq!(expected, actual);
    }

    /// Negative — wrong member_index: claiming a slot whose digest is not the PI
    /// `user_amount_digest` is rejected by the balance-slot-tree Merkle inclusion binding (the
    /// leaf opened at `member_index` fixes that slot's digests; a mismatching index breaks the
    /// root equality).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_wrong_member_index() {
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.member_index = 1; // slot 1's digest != PI user_amount_digest (slot 0).
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "claiming the wrong slot must violate the digest select binding"
        );
    }

    /// Negative — B-1b recipient redirection: a `recipient` PI that differs from the
    /// cosigner-signed per-slot exit address (the leaf's recipient field) is UNPROVABLE: the
    /// recipient PI is fed directly into the slot leaf hash, so a redirected recipient changes
    /// the leaf and the Merkle inclusion against the H1-committed slot-tree root fails. This is
    /// THE binding that protects delegates, which have no L1 `registeredRecipientOf` entry under
    /// Option B.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_redirected_recipient() {
        use crate::ethereum_types::{address::Address, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        // The leaf-bound recipient is [1,2,3,4,5]; expose a DIFFERENT (attacker) address.
        witness.public_inputs.recipient =
            Address::from_u32_slice(&[0xBAD, 0xBAD, 0xBAD, 0xBAD, 0xBAD]).unwrap();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a recipient PI != the leaf-bound (cosigner-signed) recipient must be UNPROVABLE"
        );
    }

    /// Decryption Stage 2 — CRITICAL-1 over-claim: an `amount` PI that is NOT the slot ciphertext's
    /// plaintext is rejected by the decryption-core amount binding. This is the residual the whole
    /// sub-phase closes: before Stage 2 the amount was a free PI bounded only by the on-chain fund
    /// cap; now it must equal `decrypt(c1, c2; s)`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_over_claim() {
        use crate::ethereum_types::u64::U64;
        let circuit = circuit();
        let mut witness = build_full_witness();
        // The honest plaintext is 77 (see build_full_witness). Claim 1_000_000 instead.
        witness.public_inputs.amount = 1_000_000u64;
        assert_eq!(
            U64::from(witness.public_inputs.amount),
            U64::from(1_000_000u64)
        );
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "an amount != the decrypted plaintext must be rejected (over-claim CLOSED)"
        );
    }

    /// Decryption Stage 2 — CRITICAL-1 fake key: a prover supplies a DIFFERENT, self-consistent
    /// `(a, b, s)` keypair for the fixed victim slot ciphertext. The key-binding gate accepts
    /// (b = a·s + e_pk holds for the fake key), but `poseidon_digest(a, b)` no longer equals the
    /// H1-committed `regev_pk_digests[0]`, so the pk-binding connect fails. Without the pk binding
    /// this would let an attacker pick any `s` and read off any amount.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_fake_pk_for_victim_ct() {
        use rand010::{SeedableRng, rngs::SmallRng};

        use crate::regev::channel_keygen;
        let circuit = circuit();
        let mut witness = build_full_witness();
        // A fresh, valid keypair UNRELATED to the committed slot-0 digest.
        let mut rng = SmallRng::seed_from_u64(0xFA4E_0000);
        let (fake_pk, fake_sk) = channel_keygen(&mut rng);
        witness.regev_a = fake_pk.a.clone();
        witness.regev_b = fake_pk.b.clone();
        witness.regev_s = fake_sk.s.clone();
        // NOTE: the slot ciphertext (ct_c1/ct_c2) and the committed regev_pk_digests stay the
        // victim's, so decrypt(victim ct; fake s) is garbage AND the pk digest mismatches. Either
        // the key-binding/decryption gate or the pk-digest connect rejects.
        let pw = circuit.fill_witness(&witness);
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw.unwrap())));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a fake (a,b,s) for the victim ct must fail the H1-committed pk-digest binding"
        );
    }

    /// Negative — padding slot: a slot `>= member_count + delegate_count` is not active and must
    /// be rejected even when EVERYTHING else is consistent. We doctor the final balance state so
    /// slot 5 (padding: active = 3) carries the claimant's real leaf data, recompute the doctored
    /// H1/tree/inclusion so the header and Merkle constraints are all satisfied — the ONLY
    /// violated constraint is the active-region check `member_index < active`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_padding_slot() {
        let circuit = circuit();
        let (mut witness, mut state) = build_full_witness_with_state();
        // Move the claimant's slot data into padding slot 5 (NOT validate()-legal, but h1() /
        // slot_tree() are pure functions — exactly the adversarial state a prover would try).
        state.regev_pk_digests[5] = state.regev_pk_digests[0];
        state.enc_balances[5] = state.enc_balances[0].clone();
        state.pending_adds[5] = state.pending_adds[0];
        state.recipients[5] = state.recipients[0];
        let tree = state.slot_tree();
        witness.member_index = 5;
        witness.slot_tree_root = tree.get_root();
        witness.slot_inclusion = tree.prove(5);
        witness.slot_ct_digests =
            crate::common::balance_state::BalanceState::token_ct_digests(&state.enc_balances[5]);
        witness.slot_pending_adds = state.pending_adds[5];
        witness.public_inputs.final_balance_state_h1 = state.h1();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a padding slot must fail the active-region check"
        );
    }

    /// Security (B-2 blocker fix): the withdrawal nullifier keys on the LEAF-BOUND slot Regev pk
    /// digest, NOT the slot-free `member_pk_g` PI. Flipping `member_pk_g` (leaving the pk_digest-
    /// keyed nullifier intact) must NOT break the proof — otherwise a slot owner could grind
    /// `member_pk_g` to mint distinct nullifiers and multi-withdraw the same slot up to the fund
    /// cap once the Manager admits delegate claims (B-2). This locks that `member_pk_g` is inert.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_nullifier_independent_of_member_pk_g() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        // Arbitrary different member_pk_g; the (pk_digest-keyed) nullifier PI is left unchanged.
        witness.public_inputs.member_pk_g =
            Bytes32::from_u32_slice(&[42, 42, 42, 42, 42, 42, 42, 42]).unwrap();
        let pw = circuit.fill_witness(&witness).unwrap();
        let proof = circuit
            .data
            .prove(pw)
            .expect("member_pk_g is inert — flipping it must NOT break the proof");
        circuit.data.verify(proof).expect("proof must verify");
    }

    /// Negative — forged nullifier: a withdrawal_nullifier PI not equal to keccak(IMCW,
    /// close_intent_digest, pk_digest) is rejected by the in-circuit derivation.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_forged_nullifier() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.public_inputs.withdrawal_nullifier =
            Bytes32::from_u32_slice(&[1, 1, 1, 1, 1, 1, 1, 1]).unwrap();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a forged withdrawal_nullifier must be rejected"
        );
    }

    /// Negative — tampered H1: a final_balance_state_h1 PI not matching the recomputed H1 over the
    /// witnessed slot data is rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_tampered_h1() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.public_inputs.final_balance_state_h1 =
            Bytes32::from_u32_slice(&[7, 7, 7, 7, 7, 7, 7, 7]).unwrap();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a tampered final_balance_state_h1 must be rejected"
        );
    }

    /// Multi-token happy path + TM-5 nullifier separation, BOTH directions at circuit level:
    /// (a) the same member claims token slot 0 AND token slot 1 of a 2-token state — both prove,
    /// the exposed base `token_index` PIs resolve through the signed registry (0 and
    /// MT_TOKEN1_INDEX), and the two nullifiers are DISTINCT (completeness: all of a member's
    /// tokens are claimable); (b) reusing the token-0 nullifier limbs as the PI of the token-1
    /// claim is UNPROVABLE (the in-circuit IMW2 recompute pins the token_slot limb — no
    /// cross-token nullifier replay).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_multitoken_claims_and_nullifier_cross_token() {
        let circuit = circuit();
        let (witness_t0, _) = build_multitoken_witness_with_state(0);
        let (witness_t1, _) = build_multitoken_witness_with_state(1);

        // (a) both per-(slot, token) claims prove and verify.
        let proof_t0 = circuit.prove(&witness_t0).expect("token-0 claim proof");
        circuit.data.verify(proof_t0).expect("token-0 verify");
        let proof_t1 = circuit.prove(&witness_t1).expect("token-1 claim proof");
        circuit.data.verify(proof_t1).expect("token-1 verify");
        assert_eq!(witness_t0.public_inputs.amount, MT_AMOUNTS[0]);
        assert_eq!(witness_t1.public_inputs.amount, MT_AMOUNTS[1]);
        // The base token_index PIs are the H1-committed registry resolutions (review m8).
        assert_eq!(witness_t0.public_inputs.token_index, 0);
        assert_eq!(witness_t1.public_inputs.token_index, MT_TOKEN1_INDEX);
        // TM-5 direction 1: distinct (slot, token) pairs mint DISTINCT nullifiers.
        let n0 = witness_t0.public_inputs.withdrawal_nullifier;
        let n1 = witness_t1.public_inputs.withdrawal_nullifier;
        assert_ne!(n0, n1, "per-token nullifiers must be distinct (TM-5)");

        // (b) TM-5 direction 2: a token-1 claim exposing the token-0 nullifier is UNPROVABLE —
        // the in-circuit keccak recompute includes the token_slot PI limb, so the replayed
        // nullifier PI cannot match.
        let mut replay = witness_t1.clone();
        replay.public_inputs.withdrawal_nullifier = n0;
        let pw = circuit.fill_witness(&replay).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "replaying the token-0 nullifier for a token-1 claim must be rejected (TM-5)"
        );
    }

    /// Negative — tampered token_slot (TM-2 in-claim analogue): take an honest token-0 claim and
    /// flip ONLY the `token_slot` PI to 1 (an ACTIVE position, so the TM-8 bound is satisfied).
    /// The one-hot select now reads position 1's leaf-committed ciphertext digest, which does
    /// not equal the `user_amount_digest` the decryption is bound to — and the IMW2 nullifier
    /// recompute diverges too. Unprovable: a prover cannot claim under one token slot while
    /// decrypting another's ciphertext.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_tampered_token_slot() {
        let circuit = circuit();
        let (mut witness, _) = build_multitoken_witness_with_state(0);
        witness.public_inputs.token_slot = 1;
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a token_slot PI diverging from the claimed position must be rejected (TM-2)"
        );
    }

    /// Negative — inactive token position (TM-8): a claim at `token_slot >= token_count` must be
    /// rejected by the in-circuit `token_slot < token_count` bound EVEN when everything else is
    /// self-consistent. We doctor the signed header down to `token_count = 1` while position 1
    /// still holds a real ciphertext (validate() would reject such a state, but `h1()` is a pure
    /// function — the adversarial signing scenario), recompute the doctored H1 so the header
    /// constraint is satisfied — the ONLY violated constraint is the TM-8 bound.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_inactive_token_slot() {
        let circuit = circuit();
        let (mut witness, mut state) = build_multitoken_witness_with_state(1);
        state.token_count = 1; // registry/leaves untouched: position 1 keeps its real ct.
        witness.token_count = 1;
        witness.public_inputs.final_balance_state_h1 = state.h1();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a claim at token_slot >= token_count must be rejected (TM-8)"
        );
    }

    /// Negative — cross-position ciphertext (TM-2): keep `token_slot = 0` (and its nullifier)
    /// but decrypt token position 1's ciphertext (witness ct + `user_amount_digest` PI + amount
    /// all switched to token 1's, mutually consistent). The ONLY violated constraint is the
    /// one-hot select `ct_digests[0] == user_amount_digest` — the select is fed the SAME
    /// leaf-committed digest row the Merkle inclusion binds, so relocating the decrypted
    /// ciphertext across token positions is unprovable.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_cross_position_ciphertext() {
        let circuit = circuit();
        let (mut witness, state) = build_multitoken_witness_with_state(0);
        let ct_t1 = state.enc_balances[0][1].clone();
        witness.public_inputs.user_amount_digest = ct_t1.digest();
        witness.public_inputs.amount = MT_AMOUNTS[1];
        witness.ct_c1 = ct_t1.c1.clone();
        witness.ct_c2 = ct_t1.c2.clone();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "decrypting another position's ciphertext under token_slot 0 must be rejected (TM-2)"
        );
    }

    /// Negative — tampered base token_index (review m8): the `token_index` PI must equal the
    /// H1-committed `registry[token_slot]`; exposing any other base token (here 42) is
    /// unprovable. Without this, a claim on local slot 1 (base token MT_TOKEN1_INDEX) could be
    /// presented to L1 as a claim on a different asset's escrow (TM-3 boundary).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_tampered_token_index() {
        let circuit = circuit();
        let (mut witness, _) = build_multitoken_witness_with_state(1);
        assert_eq!(witness.public_inputs.token_index, MT_TOKEN1_INDEX);
        witness.public_inputs.token_index = 42;
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a token_index PI != the H1-committed registry[token_slot] must be rejected (m8)"
        );
    }
}
