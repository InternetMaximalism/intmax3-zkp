//! Phase-2 Falcon-512/Poseidon signature AGGREGATION circuit (plonky2).
//!
//! Replaces the deleted `poseidon_sig::aggregate` binary-tree aggregator. Where the old
//! aggregator recursively verified `2^AGG_LEVELS` `SingleSigCircuit` proofs and re-exposed their
//! signer list, this circuit verifies `MAX_COSIGNERS` Falcon signatures DIRECTLY in-circuit (one
//! [`FalconSigVerifyTarget`] per slot) over ONE shared message digest, and exposes EXACTLY the
//! same public-input contract the close / cancel-close circuits already consume:
//!
//! ```text
//!   [ message (8 u32 limbs) | signer_count (1) | pk_g_0 (8) | ... | pk_g_{MAX_COSIGNERS-1} (8) ]
//! ```
//!
//! i.e. `FALCON_AGG_MSG_OFFSET = 0`, `FALCON_AGG_COUNT_OFFSET = 8`, `FALCON_AGG_PK_LIST_OFFSET =
//! 9`, total `FALCON_AGG_PUBLIC_INPUTS_LEN = 137` — byte-for-byte the layout and offsets of the old
//! `agg_public_inputs_len(AGG_LEVELS=4)`. The close / cancel-close circuits therefore change by a
//! VK swap + a constant rename ONLY; their downstream (member-set commitment, A5 distinctness,
//! MLE wrapper) is unchanged. This realizes the owner's directive: "Falcon replaces the signature;
//! aggregate with plonky2 as usual; on-chain MLE unchanged."
//!
//! # Padding soundness (TM-C7 / O-8) — the analogue of the old left-packing invariant
//!
//! `signer_count` = the number of ACTIVE slots. Active slots are a strict PREFIX (monotone
//! `is_active` bits, enforced below), so the nonzero pk list is left-packed and the zero padding
//! is a suffix — exactly the property the old aggregator enforced (aggregate.rs:385-416) and the
//! property the close circuit's `active_bits = (i < member_count)` gating relies on.
//!
//! The three integrity properties, re-argued at THIS site:
//!  - **active ⟹ valid signature.** Slot `i`'s gadget is [`FalconSigVerifyTarget::new_conditional`]
//!    gated by `is_active[i]`: with `is_active[i] = 1` the constraint set is EXACTLY the
//!    unconditional Falcon verifier (norm bound live), so a prover cannot mark a slot active
//!    without a genuine Falcon signature over the shared message under that slot's derived pk_g.
//!  - **inactive ⟹ pk_g = 0 EXPOSED.** The exposed pk list limb is `select(is_active[i], pk_g_i,
//!    0)`, so an inactive slot contributes EXACTLY zero to the exposed statement — byte-identical
//!    to the old left-packed zero suffix and to the native `close_member_set_commitment` padding.
//!    (The gadget internally forces an inactive slot's INTERNAL `pk_g` to the fixed public constant
//!    `Poseidon(IMFK || encode(0))` = [`super::falcon_padding_pk_g`]; the select zeroes it before
//!    it is ever exposed, so that constant never enters any identity-bearing structure.)
//!  - **signer_count = #{genuinely verified signatures}.** `signer_count = Σ is_active[i]` (bound
//!    below), and by the two properties above every active slot carries a valid signature and every
//!    inactive slot exposes pk_g = 0. A prover cannot claim `is_active = 1` without a valid sig,
//!    nor `is_active = 0` while exposing a nonzero pk_g. The only residual — an "active" slot whose
//!    h hashes to the ZERO digest (so it exposes pk_g = 0 while inflating the count) — requires a
//!    Poseidon preimage of the zero digest under IMFK (same strength as today's padding argument),
//!    AND such a slot would still need a valid Falcon signature under that h, AND it would inject a
//!    zero limb into a prefix position of the member-set commitment, which then fails to match the
//!    L1-registered commitment. It is therefore neither reachable nor useful.
//!
//! # Message binding (TM-C5 item 4 / TM-C6)
//!
//! There is ONE `message` public input; every slot's gadget `message_digest` input is `connect`ed
//! to it, so all `MAX_COSIGNERS` signatures are verified over the SAME digest. The CONSUMER (close
//! / cancel-close) connects `message` to its in-circuit-recomputed IMCH digest, so `c` is fully
//! determined by the real state digest and never a free witness.

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::{
    FALCON_N, FalconSignature,
    gadget::{FalconSigGadgetWitness, FalconSigVerifyTarget},
};
use crate::{
    constants::MAX_COSIGNERS,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
};

// PUBLIC-INPUT LAYOUT (identical offsets/width to the retired `poseidon_sig::aggregate`)
// ================================================================================================

/// Offset of the 8 message limbs (the shared IMCH/IMSB digest all signers sign).
pub const FALCON_AGG_MSG_OFFSET: usize = 0;
/// Offset of the single `signer_count` field element.
pub const FALCON_AGG_COUNT_OFFSET: usize = BYTES32_LEN;
/// Offset of the first pk_g slot; slot `i` begins at `FALCON_AGG_PK_LIST_OFFSET + i * BYTES32_LEN`.
pub const FALCON_AGG_PK_LIST_OFFSET: usize = BYTES32_LEN + 1;
/// Total public-input length: `message(8) + count(1) + MAX_COSIGNERS * pk_g(8)` = 137 for
/// MAX_COSIGNERS = 16. Equals the old `agg_public_inputs_len(AGG_LEVELS = 4)`.
pub const FALCON_AGG_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + 1 + MAX_COSIGNERS * BYTES32_LEN;

// WITNESS
// ================================================================================================

/// Prover witness for [`FalconAggCircuit`]: the shared message digest and the ACTIVE signers'
/// per-slot gadget witnesses (salt / h / s2), in slot order. `active.len()` = `signer_count`,
/// which must be in `1..=MAX_COSIGNERS`; the remaining slots are padded automatically with the
/// all-zero [`FalconSigGadgetWitness::padding`] (verify = 0, exposed pk_g = 0).
#[derive(Debug, Clone)]
pub struct FalconAggWitness {
    pub message: Bytes32,
    pub active: Vec<FalconSigGadgetWitness>,
}

impl FalconAggWitness {
    /// Builds the witness from the active signers' public polynomials + native signatures over
    /// `message` (slot order). Each `(h, sig)` becomes a [`FalconSigGadgetWitness::for_signature`].
    ///
    /// SECURITY (message binding): `message` MUST be the caller's domain-separated IMCH/IMSB
    /// digest; each signature must have been produced over exactly this digest, or the norm
    /// bound rejects the slot in-circuit.
    pub fn for_signatures(
        message: Bytes32,
        signers: &[(&[u16; FALCON_N], &FalconSignature)],
    ) -> Self {
        let active = signers
            .iter()
            .map(|(h, sig)| FalconSigGadgetWitness::for_signature(h, message, sig))
            .collect();
        Self { message, active }
    }
}

// CIRCUIT
// ================================================================================================

struct FalconAggSlot {
    is_active: BoolTarget,
    sig: FalconSigVerifyTarget,
}

/// Direct in-circuit aggregation of up to [`MAX_COSIGNERS`] Falcon-512/Poseidon signatures over one
/// shared message digest. Built with `standard_recursion_config` so its proof is recursively
/// verifiable by the close / cancel-close circuits at a constant VK (exactly as the old
/// `AggLevelCircuit` level-4 proof was).
pub struct FalconAggCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    /// The shared message digest input (also PI at offset 0). CONSUMERS connect it to their
    /// recomputed IMCH/IMSB digest.
    message: Bytes32Target,
    slots: Vec<FalconAggSlot>,
    /// Builder gate count before padding (reported alongside `data.common.degree_bits()`).
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> Default for FalconAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> FalconAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // PI offset 0: the shared message digest (canonical u32 limbs).
        let message = Bytes32Target::new(&mut builder, true);
        builder.register_public_inputs(&message.to_vec());

        let zero = builder.zero();

        // One conditional Falcon verifier per slot; its message_digest input is bound to the shared
        // message (TM-C5 item 4). `add_virtual_bool_target_safe` range-checks each `is_active` to
        // {0,1} — REQUIRED for the gadget's norm gate (`is_active * norm`) and the sum below to be
        // sound.
        let mut slots: Vec<FalconAggSlot> = Vec::with_capacity(MAX_COSIGNERS);
        for _ in 0..MAX_COSIGNERS {
            let is_active = builder.add_virtual_bool_target_safe();
            let sig = FalconSigVerifyTarget::new_conditional(&mut builder, is_active);
            sig.message_digest.connect(&mut builder, message);
            slots.push(FalconAggSlot { is_active, sig });
        }

        // Left-packing: `is_active[i+1] ⟹ is_active[i]` (monotone non-increasing), i.e.
        // `is_active[i+1] * (1 - is_active[i]) == 0`. Reproduces the old aggregator's left-packing
        // invariant so the nonzero pk list is a prefix and the zero padding a suffix.
        let one = builder.one();
        for i in 0..MAX_COSIGNERS - 1 {
            let one_minus_prev = builder.sub(one, slots[i].is_active.target);
            let prod = builder.mul(slots[i + 1].is_active.target, one_minus_prev);
            builder.assert_zero(prod);
        }

        // SECURITY (review Phase-2 Finding 1, MAJOR): slot 0 MUST be active, i.e.
        // `signer_count >= 1`. The retired `AggLevelCircuit` got this for free — it verified its
        // LEFT child unconditionally at every level, and a level-1 leaf hard-coded a count of 1 —
        // so `signer_count >= 1` was an in-circuit invariant that the close/cancel circuits
        // INHERITED and therefore never asserted themselves. Direct N-of-N verification has no
        // such structural floor: without this line a prover can witness `is_active[0..16] = 0`,
        // which satisfies monotonicity, yields `signer_count = 0`, gates OFF every norm bound,
        // and leaves the `message` PI entirely free (nothing consumes it) — producing a close
        // proof carrying ZERO verified signatures over an arbitrary digest. L1 rejects it
        // (`MIN_MEMBER_COUNT = 2`, plus the injected `registeredMemberSetCommitment()` never
        // matches `keccak([IMCM, 0, 0x128])`), but that would make L1 the SOLE gate for a
        // property this circuit's own docs claim to enforce. Restore the floor here, where the
        // retired aggregator enforced it. Compare `close_circuit.rs`'s token path, which asserts
        // its analogous floor explicitly.
        builder.assert_one(slots[0].is_active.target);

        // PI offset 8: signer_count = Σ is_active. A monotone prefix sum, so it equals the prefix
        // length; the close circuit connects it to `member_count`.
        let active_targets: Vec<Target> = slots.iter().map(|s| s.is_active.target).collect();
        let signer_count = builder.add_many(&active_targets);
        builder.register_public_input(signer_count);

        // PI offset 9..: the exposed pk_g list. SECURITY (padding-zero, O-8): each limb is
        // `select(is_active, internal_pk_g, 0)`, so an inactive slot exposes EXACTLY zero (the
        // gadget's internal pk_g for a padding slot is the fixed `falcon_padding_pk_g`, never
        // exposed). Active slots expose the gadget-derived `Poseidon(IMFK || encode(h))`.
        for slot in &slots {
            for &limb in slot.sig.pk_g.to_vec().iter() {
                let exposed = builder.select(slot.is_active, limb, zero);
                builder.register_public_input(exposed);
            }
        }

        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        debug_assert_eq!(data.common.num_public_inputs, FALCON_AGG_PUBLIC_INPUTS_LEN);

        Self {
            data,
            message,
            slots,
            num_gates_before_padding,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Proves aggregation of `witness.active` signatures (slot order) over `witness.message`,
    /// padding the remaining slots with the all-zero padding witness.
    ///
    /// The gadget's `pk_g` and each slot's `message_digest` are DERIVED wires (pk_g from `h` via
    /// the internal Poseidon binding; message_digest from the shared `message` via the copy
    /// constraint), so only `is_active` + salt/h/s2 are set here.
    pub fn prove(&self, witness: &FalconAggWitness) -> Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            (1..=MAX_COSIGNERS).contains(&witness.active.len()),
            "FalconAggCircuit: active signer count {} out of range 1..={MAX_COSIGNERS}",
            witness.active.len()
        );
        let mut pw = PartialWitness::<F>::new();
        self.message
            .set_witness::<F, Bytes32>(&mut pw, witness.message);

        for (i, slot) in self.slots.iter().enumerate() {
            let active = i < witness.active.len();
            pw.set_bool_target(slot.is_active, active)?;
            let gw = if active {
                witness.active[i].clone()
            } else {
                FalconSigGadgetWitness::padding(witness.message)
            };
            // Only salt/h/s2 — pk_g is bound to Poseidon(IMFK||encode(h)) and message_digest is
            // connected to the shared message, both derived by witness generation.
            slot.sig.set_signature_witness(&mut pw, &gw)?;
        }
        self.data.prove(pw)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use once_cell::sync::Lazy;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;
    use crate::{
        ethereum_types::u32limb_trait::U32LimbTrait as _,
        falcon_sig::{FalconKeys, falcon_padding_pk_g, falcon_pk_digest},
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// ONE shared aggregation circuit for the whole suite (build is ~1 min; every case proves /
    /// fails against the same constraint system, so sharing weakens nothing).
    static AGG: Lazy<FalconAggCircuit<F, C, D>> = Lazy::new(FalconAggCircuit::new);

    fn digest(tag: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_4348, tag as u32, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    /// `n` distinct deterministic keys signing `msg`, as `(h, sig)` gadget-witness inputs.
    fn signers(n: usize, msg: Bytes32, seed0: u8) -> (Vec<[u16; FALCON_N]>, Vec<FalconSignature>) {
        let mut hs = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..n {
            let keys = FalconKeys::from_seed([seed0 + i as u8; 32]);
            hs.push(keys.pk_coefficients());
            sigs.push(keys.sign(msg));
        }
        (hs, sigs)
    }

    fn witness_for(
        hs: &[[u16; FALCON_N]],
        sigs: &[FalconSignature],
        msg: Bytes32,
    ) -> FalconAggWitness {
        let refs: Vec<(&[u16; FALCON_N], &FalconSignature)> = hs.iter().zip(sigs.iter()).collect();
        FalconAggWitness::for_signatures(msg, &refs)
    }

    /// Asserts the exposed PI layout: message@0, signer_count@8, pk_g_i@(9 + 8i) selected to zero
    /// on padding slots. Returns nothing; panics on mismatch.
    fn check_pis(proof: &ProofWithPublicInputs<F, C, D>, msg: Bytes32, active_pks: &[Bytes32]) {
        use plonky2::field::types::PrimeField64 as _;
        let pis = &proof.public_inputs;
        assert_eq!(pis.len(), FALCON_AGG_PUBLIC_INPUTS_LEN);
        // message
        for (limb, want) in pis[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN]
            .iter()
            .zip(msg.to_u32_vec())
        {
            assert_eq!(limb.to_canonical_u64(), want as u64, "message limb");
        }
        // signer_count
        assert_eq!(
            pis[FALCON_AGG_COUNT_OFFSET].to_canonical_u64(),
            active_pks.len() as u64,
            "signer_count"
        );
        // pk list: active prefix = real pk_g, padding suffix = EXACTLY zero.
        for i in 0..MAX_COSIGNERS {
            let start = FALCON_AGG_PK_LIST_OFFSET + i * BYTES32_LEN;
            let got: Vec<u64> = pis[start..start + BYTES32_LEN]
                .iter()
                .map(|f| f.to_canonical_u64())
                .collect();
            let want: Vec<u64> = if i < active_pks.len() {
                active_pks[i]
                    .to_u32_vec()
                    .iter()
                    .map(|&l| l as u64)
                    .collect()
            } else {
                vec![0u64; BYTES32_LEN]
            };
            assert_eq!(got, want, "pk slot {i} (padding must be EXACTLY zero)");
        }
    }

    /// Happy path, N = 2 (minimum close cosigner count): both signatures verify, the exposed
    /// statement is left-packed with a zero padding suffix.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_happy_n2() {
        let msg = digest(1);
        let (hs, sigs) = signers(2, msg, 10);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let w = witness_for(&hs, &sigs, msg);
        let proof = AGG.prove(&w).expect("prove n2");
        AGG.data.verify(proof.clone()).expect("verify n2");
        check_pis(&proof, msg, &pks);
    }

    /// Happy path, N = MAX_COSIGNERS = 16 (all cosigner slots active, no padding).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_happy_n16() {
        let msg = digest(2);
        let (hs, sigs) = signers(MAX_COSIGNERS, msg, 30);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let w = witness_for(&hs, &sigs, msg);
        let proof = AGG.prove(&w).expect("prove n16");
        AGG.data.verify(proof.clone()).expect("verify n16");
        check_pis(&proof, msg, &pks);
    }

    /// Sanity: the fixed padding pk_g the gadget forces internally is `Poseidon(IMFK||encode(0))`,
    /// and it is NEVER exposed (all padding slots expose EXACTLY zero) — the check_pis assertions
    /// above already enforce this; here we pin the constant is nonzero (so the zeroing is load-
    /// bearing evidence, not a tautology).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn padding_pk_g_is_nonzero_but_never_exposed() {
        assert_ne!(
            falcon_padding_pk_g(),
            Bytes32::default(),
            "padding pk_g must be a nonzero digest, so exposing zero for padding is a real select"
        );
        let msg = digest(3);
        let (hs, sigs) = signers(3, msg, 50);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let proof = AGG.prove(&witness_for(&hs, &sigs, msg)).expect("prove");
        check_pis(&proof, msg, &pks); // padding slots 3..16 are asserted EXACTLY zero here
    }

    // ---- adversarial suite (each rejected at witness-gen, proving, or verification) ----------

    fn assert_rejected(build: impl FnOnce() -> Result<ProofWithPublicInputs<F, C, D>>, msg: &str) {
        let result = catch_unwind(AssertUnwindSafe(build));
        let rejected = match result {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(proof)) => AGG.data.verify(proof).is_err(),
        };
        assert!(rejected, "{msg}");
    }

    /// O-6 (message binding / cross-context): a signature produced over message A is rejected when
    /// aggregated against a DIFFERENT shared message B — the norm bound fails for the wrong `c`.
    /// This is the circuit-level guarantee that an IMCH cosignature cannot be replayed as an IMSB
    /// signature (and vice versa): the verifier recomputes `c` from ITS message, never the
    /// signer's.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn wrong_message_rejected() {
        let msg_a = digest(4);
        let msg_b = digest(5);
        let (hs, sigs) = signers(2, msg_a, 60);
        // Build a witness that CLAIMS message B but carries signatures over A.
        let mut w = witness_for(&hs, &sigs, msg_a);
        w.message = msg_b;
        for gw in w.active.iter_mut() {
            gw.message_digest = msg_b;
        }
        assert_rejected(
            || AGG.prove(&w),
            "signatures over A must not aggregate under message B",
        );
    }

    /// active ⟹ valid: claim an extra active slot with a padding (all-zero) witness. `is_active`
    /// is set to true for that slot, so its norm bound is LIVE and `||c||^2 >> beta^2` rejects.
    /// (A prover cannot inflate signer_count with an unsigned slot.)
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn active_slot_without_signature_rejected() {
        let msg = digest(6);
        let (hs, sigs) = signers(2, msg, 70);
        let mut w = witness_for(&hs, &sigs, msg);
        // Append a THIRD "active" entry that is really the padding witness (no signature).
        w.active.push(FalconSigGadgetWitness::padding(msg));
        assert_rejected(
            || AGG.prove(&w),
            "an active slot backed by the all-zero padding witness must be rejected by the norm bound",
        );
    }

    /// SECURITY (review Phase-2 Finding 1, MAJOR): `signer_count = 0` must be UNPROVABLE.
    ///
    /// WHAT THIS PROVES: the retired `AggLevelCircuit` verified its left child unconditionally at
    /// every level, so `signer_count >= 1` was a structural in-circuit invariant that the
    /// close/cancel circuits INHERITED and never asserted themselves. Direct N-of-N Falcon
    /// verification has no such floor. Without the `assert_one(slots[0].is_active)` this test
    /// guards, a prover witnesses every slot as padding: monotonicity holds, `signer_count = 0`,
    /// EVERY norm bound is gated off, and the `message` PI becomes a free witness because nothing
    /// consumes it — yielding a close proof that carries ZERO verified signatures over an
    /// arbitrary digest. L1 would still reject it (`MIN_MEMBER_COUNT = 2`, and the injected
    /// `registeredMemberSetCommitment()` never equals `keccak([IMCM, 0, 0 x 128])`), but that
    /// would make L1 the SOLE gate for a property this circuit documents as its own.
    ///
    /// The witness is built directly rather than through `FalconAggCircuit::prove`, whose
    /// `len == 0` guard is a native prover-side check, NOT a constraint — bypassing it is exactly
    /// the point.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn zero_signers_rejected() {
        let msg = digest(11);
        let w = FalconAggWitness {
            message: msg,
            active: Vec::new(),
        };
        assert_rejected(
            || AGG.prove(&w),
            "an all-padding aggregate (signer_count = 0) must be rejected by the slot-0 floor",
        );
    }

    /// Pins the padding-digest identity the gadget relies on: `Poseidon(IMFK || encode(0))` =
    /// `falcon_padding_pk_g`, so the fixed internal padding pk_g the conditional gadget forces on
    /// h = 0 is exactly the public constant the select zeroes out.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn padding_digest_identity() {
        assert_eq!(falcon_pk_digest(&[0u16; FALCON_N]), falcon_padding_pk_g());
    }

    /// Measurement (the number the owner asked for): gate count / degree / prove time of the
    /// FalconAggCircuit at N = MAX_COSIGNERS. Run in isolation with --nocapture.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_measure_n16() {
        let t0 = std::time::Instant::now();
        let circuit = FalconAggCircuit::<F, C, D>::new();
        let build = t0.elapsed();
        let msg = digest(9);
        let (hs, sigs) = signers(MAX_COSIGNERS, msg, 100);
        let w = witness_for(&hs, &sigs, msg);
        let t1 = std::time::Instant::now();
        let proof = circuit.prove(&w).expect("prove");
        let prove = t1.elapsed();
        let t2 = std::time::Instant::now();
        circuit.data.verify(proof).expect("verify");
        let verify = t2.elapsed();
        println!(
            "[falcon-agg N={MAX_COSIGNERS}] gates(before pad)={} degree_bits={} num_pis={} build={:?} prove={:?} verify={:?}",
            circuit.num_gates_before_padding,
            circuit.data.common.degree_bits(),
            circuit.data.common.num_public_inputs,
            build,
            prove,
            verify,
        );
    }
}
