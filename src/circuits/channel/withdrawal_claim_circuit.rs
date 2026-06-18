//! Phase B-D (Option D): the withdrawal-claim BINDING circuit (detail2 §E-3 / abstract2 §3.5.4).
//!
//! This circuit proves EVERYTHING the §E-3 withdrawal claim asserts EXCEPT the Regev decryption of
//! the slot ciphertext (the decryption core is a deferred sub-phase — see
//! `tasks/phase-b-claims-threat-model.md` RESIDUAL). Concretely it constrains, in one plonky2
//! statement that is MLE/WHIR-wrapped and verified on-chain by `@mle/MleVerifier.sol`:
//!
//! 1. `final_balance_state_h1` is the IMBS keccak of the witnessed final balance state (the SHARED
//!    `h1_gadget`, byte-identical to the close circuit and to native `BalanceState::h1`). The
//!    manager supplies the FINALIZED H1 as the PI, so the slot data the claim selects from is
//!    pinned to the members' signed final state.
//! 2. the claimant occupies an ACTIVE slot: `member_index < member_count + delegate_count` (members
//!    AND delegates own a withdrawable balance; padding slots do not).
//! 3. `user_amount_digest` (a PI limb) equals `enc_balance_digests[member_index]` — a select over
//!    the 16 slots gated by an index one-hot. This binds WHICH ciphertext the claim is against.
//! 4. `withdrawal_nullifier = keccak([WITHDRAWAL_CLAIM_DOMAIN] ++ close_intent_digest ++
//!    member_pk_g)` is derived in-circuit and connected to the PI (mirrors
//!    `WithdrawalClaim::derive_nullifier`).
//! 5. `channel_id`, `member_pk_g`, `recipient`, `close_intent_digest` are bound as PI limbs.
//!
//! DECRYPTION STAGE 2 (over-claim CLOSED for withdrawal): `amount` is bound in-circuit to the
//! plaintext of `user_amount_ct`. The claimant's Regev pk `(a, b)` is (1) bound to the H1-committed
//! `regev_pk_digests[member_index]` via the in-circuit Poseidon digest + the SAME one-hot select
//! used for the ciphertext digest (THE pk binding, MUST-FIX #1), (2) tied to the secret `s` by the
//! decryption-core key-binding gate, and the ciphertext `(c1, c2)` is bound to `user_amount_digest`
//! via the IMRC keccak digest. `decryption_core` then proves `amount == decrypt(c1, c2; s)`. After
//! this, `amount` is NO LONGER a free PI — over-claim is closed at the proof level, not merely
//! bounded by the on-chain `finalizedChannelFundAmount` cap.

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
        withdrawal_claim_pis::{WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN, WithdrawalClaimPublicInputs},
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        address::{ADDRESS_LEN, Address, AddressTarget},
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u64::{U64, U64Target},
    },
    regev::REGEV_N,
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

/// Prover witness for [`WithdrawalClaimCircuit`]: the full final balance state slot data (so H1 is
/// recomputed in-circuit) plus the claimed slot index. Built from a real
/// [`crate::circuits::channel::withdrawal_claim_pis::WithdrawalClaimWitness`] in [`Self::prove`].
#[derive(Clone, Debug)]
pub struct WithdrawalClaimFullWitness {
    pub public_inputs: WithdrawalClaimPublicInputs,
    /// member slot order, MAX_CHANNEL_MEMBERS entries: `enc_balances[i].digest()`.
    pub enc_balance_digests: [Bytes32; MAX_CHANNEL_MEMBERS],
    /// member slot order, MAX_CHANNEL_MEMBERS entries: `regev_pk_digests[i]` (decryption Stage 1;
    /// active = `Bytes32::from(regev_pk_i.poseidon_digest())`, padding = `Bytes32::default()`).
    pub regev_pk_digests: [Bytes32; MAX_CHANNEL_MEMBERS],
    pub settled_tx_chain: Bytes32,
    /// Stage 3: the settled-tx accumulator root of the final balance state (in the signed H1).
    pub settled_tx_accumulator_root: Bytes32,
    pub state_version: u64,
    pub pending_adds: [u32; MAX_CHANNEL_MEMBERS],
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
    enc_balance_digests: Vec<Bytes32Target>,
    regev_pk_digests: Vec<Bytes32Target>,
    settled_tx_chain: Bytes32Target,
    settled_tx_accumulator_root: Bytes32Target,
    state_version: U64Target,
    pending_adds: Vec<Target>,
    /// per-slot one-hot index selector `index_bits[i] = (i == member_index)`.
    index_bits: Vec<BoolTarget>,
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
        let enc_balance_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        // Decryption Stage 1: per-slot Regev pk digests (range-checked like enc_balance_digests).
        let regev_pk_digests: Vec<Bytes32Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| Bytes32Target::new(&mut builder, true))
            .collect();
        let settled_tx_chain = Bytes32Target::new(&mut builder, true);
        let settled_tx_accumulator_root = Bytes32Target::new(&mut builder, true);
        let state_version = U64Target::new(&mut builder, true);
        let pending_adds: Vec<Target> = (0..MAX_CHANNEL_MEMBERS)
            .map(|_| u32_limb(&mut builder))
            .collect();

        // ── (1) H1 recompute (SHARED gadget; byte-identical to close + native) ──
        let recomputed_h1 = recompute_h1::<F, C, D>(
            &mut builder,
            public_inputs.channel_id[0],
            member_count,
            delegate_count,
            &regev_pk_digests,
            &enc_balance_digests,
            &settled_tx_chain,
            &settled_tx_accumulator_root,
            &state_version,
            &pending_adds,
        );
        recomputed_h1.connect(&mut builder, public_inputs.final_balance_state_h1);

        // ── (2)+(3) index one-hot + active-region check + slot-digest select ──
        //
        // `index_bits[i]` is a Boolean one-hot: exactly one bit is 1 (Σ = 1). `member_index =
        // Σ i*index_bits[i]`. The selected digest `Σ index_bits[i]*enc_digests[i]` must equal the
        // `user_amount_digest` PI. The selected ACTIVE flag `Σ index_bits[i]*(i < active)` must be
        // 1, i.e. the chosen slot is in the active region `[0, member_count + delegate_count)` —
        // padding slots are rejected. `active = member_count + delegate_count`; both are part of
        // the H1 preimage above, so the active/padding boundary is fixed under the members' signed
        // final state.
        let mut index_bits: Vec<BoolTarget> = Vec::with_capacity(MAX_CHANNEL_MEMBERS);
        for _ in 0..MAX_CHANNEL_MEMBERS {
            index_bits.push(builder.add_virtual_bool_target_safe());
        }
        // exactly-one-hot: Σ index_bits == 1.
        let mut onehot_sum = builder.zero();
        for bit in &index_bits {
            onehot_sum = builder.add(onehot_sum, bit.target);
        }
        let one = builder.one();
        builder.connect(onehot_sum, one);

        let active = builder.add(member_count, delegate_count);
        // SECURITY (defense-in-depth, adversarial review O1): bound `active` to
        // `[0, MAX_CHANNEL_MEMBERS]` IN-CIRCUIT so padding-slot safety does NOT rely solely on the
        // upstream signed `BalanceState::validate()` invariant (member_count + delegate_count <=
        // MAX). Without this, an oversized witnessed `active` (>= 2^32) could make the
        // `less_than_u32` comparison below misbehave; with it, `active` is small and
        // canonical, so the active-region check is self-contained.
        // `member_count`/`delegate_count` are individually 32-bit range-checked above; here
        // we additionally pin their SUM <= MAX_CHANNEL_MEMBERS.
        {
            let max_active = builder.constant(F::from_canonical_usize(MAX_CHANNEL_MEMBERS));
            // active <= MAX  ⇔  MAX - active does not underflow, i.e. (MAX - active) is
            // range-checkable to a small width. Range-check active itself to
            // ceil(log2(MAX+1)) bits, then assert active <= MAX via the strict
            // less-than (active < MAX+1).
            builder.range_check(active, 8); // MAX_CHANNEL_MEMBERS = 16 fits in 8 bits comfortably.
            let max_plus_one = builder.add_const(max_active, F::ONE);
            let active_le_max = less_than_u32(&mut builder, active, max_plus_one);
            builder.assert_one(active_le_max.target);
        }

        // Select the slot digest, the slot Regev-pk digest, and the active flag at the one-hot
        // index in a single pass. The SAME `index_bits` one-hot binds all three to the SAME
        // slot.
        let zero_b32 = Bytes32Target::constant(&mut builder, Bytes32::default());
        let mut selected_digest = zero_b32;
        let mut selected_regev_pk_digest = zero_b32;
        let mut selected_active = builder.zero();
        for (i, bit) in index_bits.iter().enumerate() {
            // accumulate digest: selected_digest += bit ? enc_digests[i] : 0
            let masked = enc_balance_digests[i].mul_bool(&mut builder, *bit);
            selected_digest = add_bytes32(&mut builder, &selected_digest, &masked);
            // Decryption Stage 2: accumulate the Regev pk digest at the one-hot index.
            let masked_pk = regev_pk_digests[i].mul_bool(&mut builder, *bit);
            selected_regev_pk_digest =
                add_bytes32(&mut builder, &selected_regev_pk_digest, &masked_pk);
            // active flag for slot i: (i < active) as a Boolean.
            let i_const = builder.constant(F::from_canonical_usize(i));
            // i < active  ⇔  active - i is in {1, …}. Use range_check-free comparison via
            // `list_lt`-style: i < active iff is_active_i. We compute it as a Boolean from the
            // strict less-than helper on small u32 values.
            let is_active_i = less_than_u32(&mut builder, i_const, active);
            let contrib = builder.mul(bit.target, is_active_i.target);
            selected_active = builder.add(selected_active, contrib);
        }
        // bound user_amount_digest to the selected slot digest.
        selected_digest.connect(&mut builder, public_inputs.user_amount_digest);
        // the selected slot must be ACTIVE (== 1).
        builder.connect(selected_active, one);

        // ── Decryption Stage 2 (closes over-claim): bind `amount` to the slot ciphertext
        // plaintext.
        //
        // 1. Witness the claimant's Regev pk (a, b) and the slot ct (c1, c2). `decryption_core`
        //    pins all four to canonical `< q` and rejects a == 0 / c1 == 0.
        // 2. (CRITICAL pk-binding, MUST-FIX #1) `poseidon_digest(a, b)` == the one-hot-selected
        //    `regev_pk_digests[member_index]` (H1-committed, signed). This forces (a, b) to be the
        //    member's REGISTERED key, so the key-binding gate ties `s` to the registered secret.
        // 3. `IMRC_digest(c1, c2)` == `user_amount_digest` (the H1-pinned slot ct, already
        //    one-hot-selected above) — ties the decryption to the finalized slot ciphertext.
        // 4. `decryption_core(..., expose_amount = true)` recomputes the plaintext `v = c2 − c1·s`
        //    under the key-bound `s`, decodes the 64-bit amount, and exposes (lo, hi) limbs; we
        //    connect them to the `amount` PI U64. After this, `amount` is NO LONGER free.
        let regev_a: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let regev_b: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let ct_c1: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let ct_c2: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();

        // (pk binding) poseidon_digest(a, b) == selected regev_pk_digest (H1-committed).
        let pk_digest = regev_pk_poseidon_digest_gadget::<F, D>(&mut builder, &regev_a, &regev_b);
        pk_digest.connect(&mut builder, selected_regev_pk_digest);

        // (ct binding) IMRC_digest(c1, c2) == user_amount_digest (the selected slot ct).
        let ct_digest = regev_ct_digest_gadget::<F, C, D>(&mut builder, &ct_c1, &ct_c2);
        ct_digest.connect(&mut builder, public_inputs.user_amount_digest);

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

        // (5) channel_id / member_pk_g / recipient / close_intent_digest are bound as PI limbs by
        // construction (they are the registered PI targets, re-registered verbatim below). `amount`
        // is range-checked to u64 by `U64Target::new(builder, true)` (NOT decryption-bound — see
        // module SECURITY note).

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            member_count,
            delegate_count,
            enc_balance_digests,
            regev_pk_digests,
            settled_tx_chain,
            settled_tx_accumulator_root,
            state_version,
            pending_adds,
            index_bits,
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
        for (target, digest) in self
            .enc_balance_digests
            .iter()
            .zip(witness_value.enc_balance_digests.iter())
        {
            target.set_witness(&mut witness, *digest);
        }
        // Decryption Stage 1: per-slot Regev pk digests, mirroring enc_balance_digests.
        for (target, digest) in self
            .regev_pk_digests
            .iter()
            .zip(witness_value.regev_pk_digests.iter())
        {
            target.set_witness(&mut witness, *digest);
        }
        self.settled_tx_chain
            .set_witness(&mut witness, witness_value.settled_tx_chain);
        self.settled_tx_accumulator_root
            .set_witness(&mut witness, witness_value.settled_tx_accumulator_root);
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
                .set_bool_target(*bit, i == witness_value.member_index)
                .unwrap();
        }

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

/// Limb-wise add of two `Bytes32Target`s. SECURITY: used only to accumulate the one-hot digest
/// select — the caller masks all-but-one digest to zero via the EXACTLY-one-hot `index_bits`
/// (Σ = 1, each Boolean), so per limb the sum has exactly one nonzero term (each < 2^32). The
/// no-field-overflow guarantee comes from the one-hot constraint, NOT from any padding-zeroness
/// (padding-slot digests are nonzero keccak outputs).
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

/// Strict less-than on two SMALL u32-range targets (`a, b < 2^32`, here both `<=
/// MAX_CHANNEL_MEMBERS <= 2^32`). Returns a Boolean `a < b`. Implemented via the 33-bit
/// decomposition of `b - a + (1<<32)`: the top bit is 1 iff `a <= b`... we want strict `<`, so
/// compute `a < b` as `!(b <= a)` is avoided; instead use `(b - a)` non-zero AND `a <= b`. Simpler
/// and sound here: since both operands are `<= MAX_CHANNEL_MEMBERS` (16), `a < b ⇔ b - a ∈
/// {1..16}`. We compute `d = b - a`, range-check `d` to 32 bits via a witnessed split, and return
/// `d != 0 && (b >= a)`. To keep this airtight we use the canonical `BoolTarget` from a 33-bit
/// borrow comparison.
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
        constants::MAX_CHANNEL_MEMBERS,
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

        let enc_balance_digests: [Bytes32; MAX_CHANNEL_MEMBERS] =
            std::array::from_fn(|i| final_balance_state.enc_balances[i].digest());

        WithdrawalClaimFullWitness {
            public_inputs,
            enc_balance_digests,
            regev_pk_digests: final_balance_state.regev_pk_digests,
            settled_tx_chain: final_balance_state.settled_tx_chain,
            settled_tx_accumulator_root: final_balance_state.settled_tx_accumulator_root,
            state_version: final_balance_state.state_version,
            pending_adds: final_balance_state.pending_adds,
            member_count: final_balance_state.member_count,
            delegate_count: final_balance_state.delegate_count,
            member_index: 0,
            // Decryption Stage 2: the claimant's (slot 0) real Regev key + slot ciphertext.
            regev_a: pk0.a.clone(),
            regev_b: pk0.b.clone(),
            ct_c1: ct0.c1.clone(),
            ct_c2: ct0.c2.clone(),
            regev_s: sk0.s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use plonky2::field::types::PrimeField64;

    use super::{test_fixture::*, *};
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
    /// `user_amount_digest` is rejected by the one-hot select binding.
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

    /// Negative — padding slot: a slot `>= member_count + delegate_count` is not active and must be
    /// rejected even if its digest is fed as user_amount_digest.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_circuit_rejects_padding_slot() {
        let circuit = circuit();
        let mut witness = build_full_witness();
        // Point the claim at slot 5 (padding: active = 3) and set the PI digest to that slot's
        // (padding) digest so ONLY the active-region check can fire.
        witness.member_index = 5;
        witness.public_inputs.user_amount_digest = witness.enc_balance_digests[5];
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
