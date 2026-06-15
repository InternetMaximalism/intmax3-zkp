//! Plonky2 single-signature circuit for the Goldilocks Poseidon-preimage signature (P2a).
//!
//! Statement (public `(pk, m)`, witness `sk`):
//!   - `pk = Poseidon([DOMAIN_PK_G] ‖ sk)` — proves knowledge of the preimage `sk` of the public key.
//!   - `m` is a **public input**, so the proof is cryptographically bound to exactly this message
//!     (a proof minted for `m1` does not verify against `m2`). This binding IS the signature.
//!   - `sig = Poseidon([DOMAIN_SIG_G] ‖ sk ‖ m)` is computed in-circuit as defense-in-depth so the
//!     message provably flows through the secret key (threat model §1.2). It is **witness-only** — not
//!     a public input — to avoid exposing a deterministic per-(key, message) tag (A6).
//!   - `sk` is asserted non-degenerate (not all-zero), the concrete part of the A1 range/format check.
//!
//! Public-input layout: `[ pk : Bytes32 (8 u32 limbs), m : Bytes32 (8 u32 limbs) ]` = 16 field elements.
//!
//! The native reference for `(pk, m)` is `GoldilocksSecretKey::public_key()` + the caller-chosen
//! message; the in-circuit Poseidon (`PoseidonHashOutTarget::hash_inputs`) matches the native
//! `PoseidonHashOut::hash_inputs_u64` (same `hash_no_pad`, same element order, domain in the first lane).

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field as _},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::PoseidonHashOutTarget,
};

use super::{GoldilocksSecretKey, DOMAIN_PK_G, DOMAIN_SIG_G, SECRET_KEY_LEN};

pub const D: usize = 2;
pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;

/// Number of public-input field elements: `pk` (8 limbs) + `m` (8 limbs).
pub const SINGLE_SIG_PUBLIC_INPUTS_LEN: usize = 2 * BYTES32_LEN;

/// A standalone Plonky2 circuit proving one Goldilocks Poseidon-preimage signature.
pub struct SingleSigCircuit {
    pub data: CircuitData<F, C, D>,
    sk: [Target; SECRET_KEY_LEN],
    message: Bytes32Target,
}

impl SingleSigCircuit {
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // Private witness: the 4 secret-key limbs.
        let sk: [Target; SECRET_KEY_LEN] =
            core::array::from_fn(|_| builder.add_virtual_target());

        // Public message (range-checked so each limb is a genuine u32 — keeps the native/in-circuit
        // hash inputs identical and prevents a malformed message from diverging from the reference).
        let message = Bytes32Target::new(&mut builder, true);

        // A1: reject the degenerate all-zero secret key. `all_zero` is true iff every limb is zero;
        // asserting it is zero (false) forbids that single low-entropy key. (Broader entropy cannot be
        // enforced in-circuit; this pins the concrete degenerate case.)
        let zero = builder.zero();
        let mut all_zero = builder._true();
        for &limb in &sk {
            let is_zero = builder.is_equal(limb, zero);
            all_zero = builder.and(all_zero, is_zero);
        }
        builder.assert_zero(all_zero.target);

        // pk = Poseidon([DOMAIN_PK_G] ‖ sk)
        let dom_pk = builder.constant(F::from_canonical_u32(DOMAIN_PK_G));
        let mut pk_inputs = Vec::with_capacity(1 + SECRET_KEY_LEN);
        pk_inputs.push(dom_pk);
        pk_inputs.extend_from_slice(&sk);
        let pk_hash = PoseidonHashOutTarget::hash_inputs(&mut builder, &pk_inputs);
        let pk_bytes = Bytes32Target::from_hash_out(&mut builder, pk_hash);

        // sig = Poseidon([DOMAIN_SIG_G] ‖ sk ‖ m)  (defense-in-depth; witness-only, not registered).
        // Computing it forces the message limbs through the secret key inside the constraint system.
        // SECURITY: this is NOT the message-binding mechanism — `m` is bound by being a registered
        // PUBLIC INPUT (a proof minted for one `m` does not verify against another). Do not delete the
        // `register_public_inputs(&message...)` below thinking this sig computation covers the binding.
        let dom_sig = builder.constant(F::from_canonical_u32(DOMAIN_SIG_G));
        let mut sig_inputs = Vec::with_capacity(1 + SECRET_KEY_LEN + BYTES32_LEN);
        sig_inputs.push(dom_sig);
        sig_inputs.extend_from_slice(&sk);
        sig_inputs.extend_from_slice(&message.to_vec());
        let _sig_hash = PoseidonHashOutTarget::hash_inputs(&mut builder, &sig_inputs);

        // Public inputs: [pk(8), m(8)].
        builder.register_public_inputs(&pk_bytes.to_vec());
        builder.register_public_inputs(&message.to_vec());

        let data = builder.build::<C>();
        Self { data, sk, message }
    }

    /// Verifier data for embedding this circuit's proofs in the recursive list circuit.
    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Prove a signature by `sk` over `message`. The resulting proof's public inputs are
    /// `[pk = sk.public_key(), message]`.
    pub fn prove(
        &self,
        sk: &GoldilocksSecretKey,
        message: Bytes32,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        for (target, &value) in self.sk.iter().zip(sk.limbs.iter()) {
            pw.set_target(*target, F::from_canonical_u64(value))?;
        }
        self.message.set_witness(&mut pw, message);
        self.data.prove(pw)
    }
}

impl Default for SingleSigCircuit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng as _};

    fn message(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 1, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    #[test]
    fn prove_and_verify_happy_path() {
        let circuit = SingleSigCircuit::new();
        let sk = GoldilocksSecretKey::from_seed([3u8; 32]);
        let m = message(0xab);
        let proof = circuit.prove(&sk, m).expect("proving should succeed");

        // Public inputs expose the correct (pk, m).
        let pk = sk.public_key();
        let pi: Vec<u32> = proof
            .public_inputs
            .iter()
            .map(|f| f.0 as u32)
            .collect();
        assert_eq!(pi[0..BYTES32_LEN], pk.to_u32_vec()[..]);
        assert_eq!(pi[BYTES32_LEN..], m.to_u32_vec()[..]);

        circuit.data.verify(proof).expect("verification should succeed");
    }

    #[test]
    fn rejects_all_zero_secret_key() {
        let circuit = SingleSigCircuit::new();
        let degenerate = GoldilocksSecretKey::from_limbs([0; SECRET_KEY_LEN]);
        let err = circuit.prove(&degenerate, message(0x01));
        assert!(err.is_err(), "all-zero sk must be rejected by the circuit");
    }

    #[test]
    fn tampered_public_key_fails_verification() {
        let circuit = SingleSigCircuit::new();
        let sk = GoldilocksSecretKey::from_seed([4u8; 32]);
        let mut proof = circuit.prove(&sk, message(0x02)).unwrap();
        // Flip one limb of the pk public input — the proof must no longer verify.
        proof.public_inputs[0] = proof.public_inputs[0] + F::ONE;
        assert!(circuit.data.verify(proof).is_err());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let circuit = SingleSigCircuit::new();
        let sk = GoldilocksSecretKey::from_seed([5u8; 32]);
        let mut proof = circuit.prove(&sk, message(0x03)).unwrap();
        // Flip one limb of the message public input.
        proof.public_inputs[BYTES32_LEN] = proof.public_inputs[BYTES32_LEN] + F::ONE;
        assert!(circuit.data.verify(proof).is_err());
    }

    #[test]
    fn distinct_keys_distinct_proof_public_keys() {
        let circuit = SingleSigCircuit::new();
        let mut rng = StdRng::seed_from_u64(11);
        let sk_a = GoldilocksSecretKey::rand(&mut rng);
        let sk_b = GoldilocksSecretKey::rand(&mut rng);
        let m = message(0x07);
        let pa = circuit.prove(&sk_a, m).unwrap();
        let pb = circuit.prove(&sk_b, m).unwrap();
        assert_ne!(pa.public_inputs[0..BYTES32_LEN], pb.public_inputs[0..BYTES32_LEN]);
        circuit.data.verify(pa).unwrap();
        circuit.data.verify(pb).unwrap();
    }
}
