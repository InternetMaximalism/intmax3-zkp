//! Phase B-D (Option D): the withdrawal-claim BINDING circuit (detail2 §E-3 / abstract2 §3.5.4).
//!
//! This circuit proves EVERYTHING the §E-3 withdrawal claim asserts EXCEPT the Regev decryption of
//! the slot ciphertext (the decryption core is a deferred sub-phase — see
//! `tasks/phase-b-claims-threat-model.md` RESIDUAL). Concretely it constrains, in one plonky2
//! statement that is MLE/WHIR-wrapped and verified on-chain by `@mle/MleVerifier.sol`:
//!
//! 1. `final_balance_state_h1` is the Poseidon-root H1 header of the witnessed final balance state
//!    (the SHARED `h1_gadget::recompute_h1`, element-identical to the close circuit and to native
//!    `BalanceState::h1`; see `tasks/h1-poseidon-root-threat-model.md`). The manager supplies the
//!    FINALIZED H1 as the PI, so the header scalars AND the `slot_tree_root` the claim opens
//!    against are pinned to the members' signed final state.
//! 2. the claimant occupies an ACTIVE slot: `member_index < member_count + delegate_count` (members
//!    AND delegates own a withdrawable balance; padding slots do not).
//! 3. the claimant's slot leaf `balance_slot_leaf_hash(regev_pk_digest, user_amount_digest,
//!    pending_adds, recipient)` is INCLUDED at `member_index` in the H1-committed `slot_tree_root`
//!    (a height-`BALANCE_SLOT_TREE_HEIGHT` Merkle inclusion; the Merkle POSITION is the slot
//!    index). This binds WHICH ciphertext (`user_amount_digest` PI), WHICH registered Regev pk
//!    digest AND WHICH L1 exit address (`recipient` PI — B-1b) the claim is against — replacing the
//!    retired 1024-slot one-hot select.
//! 4. `withdrawal_nullifier = keccak([WITHDRAWAL_CLAIM_DOMAIN] ++ close_intent_digest ++
//!    member_pk_g)` is derived in-circuit and connected to the PI (mirrors
//!    `WithdrawalClaim::derive_nullifier`).
//! 5. `channel_id`, `member_pk_g`, `recipient`, `close_intent_digest` are bound as PI limbs.
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
    constants::{BALANCE_SLOT_TREE_HEIGHT, MAX_CHANNEL_MEMBERS},
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

/// "IMCW" — withdrawal-claim nullifier domain. MUST equal `common::channel`'s
/// `WITHDRAWAL_CLAIM_DOMAIN` so the in-circuit keccak agrees with the native
/// `WithdrawalClaim::derive_nullifier` byte-for-byte.
const WITHDRAWAL_CLAIM_DOMAIN: u32 = 0x494d4357;

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
        }
    }

    /// PI limb vector in EXACT `WithdrawalClaimPublicInputs::to_u64_vec()` order
    /// (close_intent_digest, channel_id, final_balance_state_h1, member_pk_g, recipient,
    /// user_amount_digest, withdrawal_nullifier, split_u64(amount)).
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
    /// The claimant slot's homomorphic-add counter `pending_adds[member_index]` (leaf field; the
    /// other two leaf fields are derived in-circuit from the witnessed Regev pk and the
    /// `user_amount_digest` PI).
    pub slot_pending_adds: u32,
    pub settled_tx_chain: Bytes32,
    /// Stage 3: the settled-tx accumulator root of the final balance state (in the signed H1).
    pub settled_tx_accumulator_root: Bytes32,
    pub state_version: u64,
    /// active region size = member_count + delegate_count.
    pub member_count: u8,
    pub delegate_count: u8,
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
    /// The claimant slot's `pending_adds` leaf field.
    slot_pending_adds: Target,
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
        // The claimant slot's pending-adds leaf field (32-bit range-checked; the leaf hash binds
        // it to the H1-committed slot data).
        let slot_pending_adds = u32_limb(&mut builder);

        // ── (1) H1 header recompute (SHARED gadget; element-identical to close + native) ──
        let recomputed_h1 = recompute_h1::<F, D>(
            &mut builder,
            public_inputs.channel_id[0],
            member_count,
            delegate_count,
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

        // ── (3) slot-leaf Merkle inclusion (replaces the retired 1024-slot one-hot select) ──
        //
        // leaf = Poseidon([IMSL, pk_digest, user_amount_digest, pending_adds, recipient]) MUST be
        // included at `member_index` in the H1-committed `slot_tree_root`. ONE leaf binds all four
        // slot fields to the SAME index (the Merkle position IS the slot index), so the claimed
        // ciphertext digest (`user_amount_digest` PI), the registered Regev pk digest (via the
        // gadget output — THE pk binding, MUST-FIX #1), the slot's add counter AND the slot's L1
        // exit address are exactly the signed slot-`member_index` values. `pk_digest`'s limbs are
        // u32 by construction (`Bytes32Target::from_hash_out` safe split); `user_amount_digest`
        // and `recipient` are range-checked PIs.
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
            &public_inputs.user_amount_digest,
            slot_pending_adds,
            &public_inputs.recipient,
        );
        let slot_inclusion = IncrementalMerkleProofTarget::<PoseidonHashOutTarget>::new(
            &mut builder,
            BALANCE_SLOT_TREE_HEIGHT,
        );
        slot_inclusion.verify::<F, C, D>(&mut builder, &slot_leaf, member_index, slot_tree_root);

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

        // ── (4) withdrawal_nullifier = keccak([IMCW, close_intent_digest, member_pk_g]) ──
        let withdrawal_domain = builder.constant(F::from_canonical_u32(WITHDRAWAL_CLAIM_DOMAIN));
        let nullifier_inputs = [
            vec![withdrawal_domain],
            public_inputs.close_intent_digest.to_vec(),
            public_inputs.member_pk_g.to_vec(),
        ]
        .concat();
        let withdrawal_nullifier =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&nullifier_inputs));
        withdrawal_nullifier.connect(&mut builder, public_inputs.withdrawal_nullifier);

        // (5) channel_id / member_pk_g / close_intent_digest are bound as PI limbs by
        // construction (they are the registered PI targets, re-registered verbatim below);
        // `recipient` is additionally LEAF-BOUND (B-1b, step (3) above) — it is no longer a free
        // PI. `amount` is range-checked to u64 by `U64Target::new(builder, true)` and
        // decryption-bound above.

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            member_count,
            delegate_count,
            slot_tree_root,
            settled_tx_chain,
            settled_tx_accumulator_root,
            state_version,
            member_index,
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
                F::from_canonical_u8(witness_value.delegate_count),
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
        witness
            .set_target(
                self.slot_pending_adds,
                F::from_canonical_u32(witness_value.slot_pending_adds),
            )
            .unwrap();
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
            enc_balances: BalanceState::pad_enc_balances(&[ct0.clone(), ct1, ct2]),
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
            pending_adds: BalanceState::pad_pending_adds(&[0, 0, 0]),
        };
        let state = ChannelState {
            channel_id,
            epoch: 8,
            small_block_number: 5,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amount: U256::from(93u32),
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
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![9],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();
        let member = ChannelMember {
            pk_g: Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap(),
            member_slot: 0,
            l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        };
        let claim_proof =
            prove_withdraw_claim(RegevSecurityLevel::Test, &pk0, &sk0, &ct0, amount).unwrap();
        let claim = WithdrawalClaim {
            close_intent_digest: close_intent.signing_digest(),
            member_pk_g: member.pk_g,
            l1_recipient: member.l1_withdrawal_recipient,
            user_amount_ct: ct0.clone(),
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                member.pk_g,
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
            slot_pending_adds: final_balance_state.pending_adds[member_index],
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
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use plonky2::field::types::PrimeField64;

    use super::test_fixture::*;
    use crate::circuits::channel::withdrawal_claim_pis::WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN;

    /// Happy path: a real withdrawal-claim binding proves and the 48 exposed limbs equal the
    /// `WithdrawalClaimPublicInputs::to_u64_vec()` layout.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_proves_and_exposes_pis() {
        let circuit = circuit();
        let witness = build_full_witness();
        let proof = circuit.prove(&witness).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

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
        witness.slot_pending_adds = state.pending_adds[5];
        witness.public_inputs.final_balance_state_h1 = state.h1();
        let pw = circuit.fill_witness(&witness).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a padding slot must fail the active-region check"
        );
    }

    /// Negative — forged nullifier: a withdrawal_nullifier PI not equal to keccak(IMCW,
    /// close_intent_digest, member_pk_g) is rejected by the in-circuit derivation.
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
}
