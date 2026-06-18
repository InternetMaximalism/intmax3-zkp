//! Phase B-D (Option D): the post-close incoming-claim BINDING circuit
//! (abstract2 §3.5.5 `claimLateTx`, detail2 §C-8).
//!
//! MLE/WHIR-wrapped, verified on-chain by `@mle/MleVerifier.sol`. Concretely it constrains:
//!
//! 1. `close_intent_digest`, `receiver_channel_id`, `incoming_tx_hash`, `receiver_pk_g`,
//!    `recipient` are bound as PI limbs.
//! 2. receiver-delta inclusion: detail2 §A-2 mandates EXACTLY ONE receiver per inter-channel tx, so
//!    `receiver_deltas[0]` is THE receiver. The witnessed delta's `receiver_pk_g` is connected to
//!    the PI `receiver_pk_g`, and the witnessed delta amount-ciphertext digest is connected to the
//!    witnessed claimed `receiver_amount` digest — binding the claim to the signed tx's receiver
//!    delta (the non-decryption half of `PostCloseClaimWitness::to_public_inputs`).
//! 3. `incoming_tx_hash` is connected to the witnessed `source_tx.tx_hash` (== claim binding).
//! 4. HAZARD #8 FIX: `shared_native_nullifier = keccak([POST_CLOSE_NULLIFIER_DOMAIN] ++
//!    close_intent_digest ++ incoming_tx_hash ++ receiver_pk_g)` is derived IN-CIRCUIT and
//!    connected to the PI. Today the claim field is attacker-chosen/opaque (free-standing, not tied
//!    to any tree — verified against `channel.rs`/`balance_state.rs`), so deriving it
//!    deterministically closes the double-claim / cross-channel-replay surface. The L1 manager
//!    recomputes the SAME value as the `usedSharedNativeNullifiers` key.
//!
//! DECRYPTION STAGE 2 (PARTIAL — over-claim NOT fully closed for post-close): `amount` is now bound
//! in-circuit to the plaintext of the receiver-delta ciphertext via the shared `decryption_core`
//! gadget + the IMRC ct-digest binding (see the detailed SECURITY caveat in `new`). BUT the
//! receiver's Regev pk is a FREE witness here (no in-circuit commitment to anchor it against,
//! unlike the withdrawal claim's H1-committed slot pk), so the pk-binding MUST-FIX #1 is NOT
//! discharged and the binding does NOT by itself close over-claim. Stage 3 source-tx anchoring is
//! ALSO still required. Until both land, post-close over-claim stays bounded only by the on-chain
//! `finalizedChannelFundAmount` cap. DO NOT read this circuit as "post-close over-claim closed".

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
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
        },
        post_close_claim_pis::{POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN, PostCloseClaimPublicInputs},
    },
    ethereum_types::{
        address::AddressTarget,
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u64::{U64, U64Target},
    },
    regev::REGEV_N,
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
        }
    }

    /// PI limb vector in EXACT `PostCloseClaimPublicInputs::to_u64_vec()` order
    /// (close_intent_digest, receiver_channel_id, incoming_tx_hash, receiver_pk_g, recipient,
    /// shared_native_nullifier, split_u64(amount)).
    pub fn to_vec(&self) -> Vec<Target> {
        let v = [
            self.close_intent_digest.to_vec(),
            self.receiver_channel_id.to_vec(),
            self.incoming_tx_hash.to_vec(),
            self.receiver_pk_g.to_vec(),
            self.recipient.to_vec(),
            self.shared_native_nullifier.to_vec(),
            self.amount.to_vec(),
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
    }
}

#[derive(Debug, Error)]
pub enum PostCloseClaimCircuitError {
    #[error("failed to prove: {0}")]
    FailedToProve(String),
}

/// Prover witness for [`PostCloseClaimCircuit`]: the public inputs plus the witnessed
/// source-tx fields the circuit binds against (the single receiver delta, the tx hash, the claimed
/// ct digest). Built from a real
/// [`crate::circuits::channel::post_close_claim_pis::PostCloseClaimWitness`] in [`Self::prove`].
#[derive(Clone, Debug)]
pub struct PostCloseClaimFullWitness {
    pub public_inputs: PostCloseClaimPublicInputs,
    /// `source_tx.tx_hash` (connected to PI incoming_tx_hash).
    pub source_tx_hash: Bytes32,
    /// `source_tx.receiver_deltas[0].receiver_pk_g` (connected to PI receiver_pk_g).
    pub delta_receiver_pk_g: Bytes32,
    /// `source_tx.receiver_deltas[0].amount.digest()` (connected to the claimed ct digest).
    pub delta_amount_digest: Bytes32,
    /// `claim.receiver_amount.digest()` — the claimed ciphertext digest (== delta digest above).
    pub claimed_amount_digest: Bytes32,
    /// Decryption Stage 2: the receiver's Regev pk `(a, b)` and the delta ciphertext `(c1, c2)`
    /// (canonical `< q`, length `REGEV_N`), plus the receiver ternary secret `s`. See the SECURITY
    /// note on `PostCloseClaimCircuit::new` — the pk is NOT yet anchored in this circuit, so the
    /// decryption binding here is NOT sufficient to close over-claim (Stage 3 still required).
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
    source_tx_hash: Bytes32Target,
    delta_receiver_pk_g: Bytes32Target,
    delta_amount_digest: Bytes32Target,
    claimed_amount_digest: Bytes32Target,
    /// Decryption Stage 2 witness handles.
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

        let source_tx_hash = Bytes32Target::new(&mut builder, true);
        let delta_receiver_pk_g = Bytes32Target::new(&mut builder, true);
        let delta_amount_digest = Bytes32Target::new(&mut builder, true);
        let claimed_amount_digest = Bytes32Target::new(&mut builder, true);

        // (3) incoming_tx_hash == source_tx.tx_hash.
        source_tx_hash.connect(&mut builder, public_inputs.incoming_tx_hash);

        // (2) receiver-delta inclusion (single receiver, detail2 §A-2):
        //  - the delta's receiver_pk_g equals the claimed/PI receiver_pk_g;
        //  - the delta's amount-ct digest equals the claimed amount-ct digest (binds the claim's
        //    ciphertext to the signed tx's receiver delta — the non-decryption half of the native
        //    `to_public_inputs` membership check).
        delta_receiver_pk_g.connect(&mut builder, public_inputs.receiver_pk_g);
        delta_amount_digest.connect(&mut builder, claimed_amount_digest);

        // (4) HAZARD #8 FIX: derive shared_native_nullifier in-circuit and bind to the PI.
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

        // ── Decryption Stage 2 (PARTIAL — see the SECURITY caveat below): bind `amount` to the
        // receiver-delta ciphertext plaintext.
        //
        // We witness the receiver Regev pk (a, b) and the delta ct (c1, c2), tie (c1, c2) to the
        // signed delta via the IMRC digest gadget, run the decryption core under the witnessed
        // secret s, and connect the decoded (lo, hi) amount limbs to the `amount` PI.
        //
        // ❗ SECURITY CAVEAT (over-claim NOT fully closed for post-close — escalated, NOT a silent
        // workaround):
        //   (a) PK BINDING IS NOT DISCHARGED HERE (MUST-FIX #1). Unlike the withdrawal claim —
        // whose       slot Regev pk digest is committed in the signed H1 and
        // one-hot-selected — this circuit       has NO in-circuit commitment to the
        // receiver's Regev pk. `(a, b)` is a FREE witness,       so an attacker can supply
        // any self-consistent (a, b, s) and decrypt the (signed) delta       ct to ANY
        // chosen amount. The decryption core + ct-digest binding therefore do NOT, on
        //       their own, close over-claim for post-close. Anchoring the receiver pk requires
        //       threading the receiver channel's `regev_pk_root` / a member-tree inclusion (the
        // same       class of protocol-data change as decryption Stage 1) and is OUT OF
        // SCOPE for Stage 2.   (b) STAGE 3 (source-tx anchoring) IS STILL REQUIRED. Even
        // with a pk anchor, the post-close       residual "the receiver-delta ct was never
        // in a signed InterChannelTx" is only closed       by recomputing
        // `InterChannelTx::signing_digest` in-circuit + Merkle/signature       inclusion
        // (tasks/decryption-subphase-design.md §"Post-close ALSO needs source-tx
        //       anchoring"). Until BOTH (a) and (b) land, post-close over-claim stays bounded ONLY
        // by       the on-chain `finalizedChannelFundAmount` cap.
        // The binding is added now so the witness plumbing and the decryption arithmetic are in
        // place and tested; it MUST NOT be read as "post-close over-claim is closed".
        let regev_a: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let regev_b: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let delta_c1: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let delta_c2: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();

        // (ct binding) IMRC_digest(c1, c2) == the claimed/delta amount-ct digest (signed delta).
        let ct_digest = regev_ct_digest_gadget::<F, C, D>(&mut builder, &delta_c1, &delta_c2);
        ct_digest.connect(&mut builder, claimed_amount_digest);

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

        // (1) close_intent_digest / receiver_channel_id / receiver_pk_g / recipient are bound as PI
        // limbs by construction (re-registered verbatim below).

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            source_tx_hash,
            delta_receiver_pk_g,
            delta_amount_digest,
            claimed_amount_digest,
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
        let mut witness = PartialWitness::<F>::new();
        self.public_inputs
            .set_witness(&mut witness, &witness_value.public_inputs);
        self.source_tx_hash
            .set_witness(&mut witness, witness_value.source_tx_hash);
        self.delta_receiver_pk_g
            .set_witness(&mut witness, witness_value.delta_receiver_pk_g);
        self.delta_amount_digest
            .set_witness(&mut witness, witness_value.delta_amount_digest);
        self.claimed_amount_digest
            .set_witness(&mut witness, witness_value.claimed_amount_digest);

        // Decryption Stage 2: set the Regev pk/ct polynomials and the decryption-core witness.
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
        common::channel::{
            ChannelId, ChannelProofEnvelope, InterChannelTx, MerkleInclusionProof,
            PostCloseIncomingClaim, ProofBackend, ReceiverBalanceDelta, SignedSmallBlock,
            SmallBlockRootMessage, TransitionProofRole,
        },
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
        regev::{
            REGEV_N, REGEV_Q, RegevCiphertext, RegevSecurityLevel, channel_keygen, encrypt_amount,
            prove_withdraw_claim,
        },
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

    /// Build a REAL, self-consistent post-close-claim witness (single receiver delta) and the
    /// matching `PostCloseClaimFullWitness`. The shared_native_nullifier is derived via the native
    /// helper, so the circuit's in-circuit derivation matches. SHARED by the unit tests and the
    /// fixture-generator binary.
    pub fn build_full_witness() -> PostCloseClaimFullWitness {
        let mut rng = SmallRng::seed_from_u64(0x9C105E);
        let (receiver_pk, receiver_sk) = channel_keygen(&mut rng);
        let amount = 21u64;
        let (delta_ct, _) = encrypt_amount(&mut rng, &receiver_pk, amount).unwrap();
        let receiver_pk_g = pubkey_hash(11);
        let closed_channel_id = ChannelId::new(7).unwrap();
        let close_intent_digest = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();

        let source_tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            signed_small_block: SignedSmallBlock {
                message: SmallBlockRootMessage {
                    channel_id: ChannelId::new(5).unwrap(),
                    bp_member_slot: 0,
                    bp_pk_g: pubkey_hash(10),
                    small_block_number: 1,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root: Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![],
                aggregated_signature_proof: vec![1],
                medium_block_number: 3,
                confirmation_proof: vec![2],
            },
            sender_delta_ct: ciphertext(1),
            source_channel_id: ChannelId::new(5).unwrap(),
            destination_channel_id: closed_channel_id,
            source_pk_g: pubkey_hash(10),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
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
            source_tx.tx_hash,
            receiver_pk_g,
        );
        let claim = PostCloseIncomingClaim {
            close_intent_digest,
            incoming_tx_hash: source_tx.tx_hash,
            receiver_pk_g,
            l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            receiver_amount: delta_ct.clone(),
            shared_native_nullifier,
            recipient_memo: vec![5, 6],
            claim_proof,
        };
        let native = PostCloseClaimWitness {
            close_intent_digest,
            closed_channel_id,
            source_tx: source_tx.clone(),
            claim,
            receiver_pk: receiver_pk.clone(),
            amount,
        };
        let public_inputs: PostCloseClaimPublicInputs =
            native.to_public_inputs(RegevSecurityLevel::Test).unwrap();

        PostCloseClaimFullWitness {
            public_inputs,
            source_tx_hash: source_tx.tx_hash,
            delta_receiver_pk_g: receiver_pk_g,
            delta_amount_digest: delta_ct.digest(),
            claimed_amount_digest: delta_ct.digest(),
            // Decryption Stage 2: the receiver's real Regev key + the delta ciphertext.
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

    /// Negative — forged shared_native_nullifier (#8): a PI not equal to keccak(IMCK,
    /// close_intent_digest, incoming_tx_hash, receiver_pk_g) is rejected by the in-circuit
    /// derivation, so an attacker cannot pick a fresh nullifier to double-claim.
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

    /// Negative — receiver-delta mismatch: a claimed ct digest not equal to the source tx's
    /// receiver-delta digest is rejected by the inclusion binding.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_delta_mismatch() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.claimed_amount_digest = Bytes32::from_u32_slice(&[5, 5, 5, 5, 5, 5, 5, 5]).unwrap();
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a claimed ct digest not matching the receiver delta must be rejected"
        );
    }

    /// Negative — wrong incoming_tx_hash: a PI tx hash not equal to the witnessed source tx hash is
    /// rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn post_close_claim_circuit_rejects_wrong_tx_hash() {
        use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
        let circuit = circuit();
        let mut witness = build_full_witness();
        witness.source_tx_hash = Bytes32::from_u32_slice(&[8, 8, 8, 8, 8, 8, 8, 8]).unwrap();
        let result = match circuit.fill_witness(&witness) {
            Ok(pw) => catch_unwind(AssertUnwindSafe(|| circuit.data.prove(pw))),
            Err(_) => Ok(Err(anyhow::anyhow!("fill_witness rejected"))),
        };
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a PI incoming_tx_hash not matching source_tx.tx_hash must be rejected"
        );
    }
}
