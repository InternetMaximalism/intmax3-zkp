//! Recursive single-signature **list proof** (P2a).
//!
//! Accumulates verified `(message, public_key)` pairs into an order-sensitive Poseidon hash chain:
//!   - `leaf_i  = Poseidon([LIST_LEAF_DOMAIN] ‖ m_i ‖ pk_i)`
//!   - `C_0     = 0` (the empty chain)
//!   - `C_i     = Poseidon(C_{i-1} ‖ leaf_i)`   (two-to-one)
//!
//! The final `C_N` (a `Bytes32`) commits to the exact ordered multiset of `(m, pk)` pairs that were
//! each backed by a verified [`SingleSigCircuit`](super::circuit::SingleSigCircuit) proof. A
//! consumer (validity / close, Phase 2b) recursively verifies the list proof, rebuilds the same
//! chain from the `(m, pk)` pairs it requires, and asserts equality — so it learns "these messages
//! were signed by these keys" without re-running any signature check.
//!
//! Recursion reuses the in-tree [`CyclicChainCircuit`]: the per-step [`ListStepCircuit`] exposes
//! `[prev_chain(8), new_chain(8)]`, exactly the `(prev_hash, hash)` shape the cyclic wrapper
//! chains. The cyclic wrapper enforces `prev_chain_i == C_{i-1}` and `C_0 == 0`, and
//! self-references its own verifier data (constant-VD) so only proofs from this circuit can extend
//! the list (A7).

use plonky2::{
    field::{extension::Extendable, types::Field as _},
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        hash_chain::cyclic_chain_circuit::CyclicChainCircuit,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

use super::circuit::{C, D, F};

/// Domain separator for a list leaf `Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)`. ASCII "IMLL".
pub const LIST_LEAF_DOMAIN: u32 = 0x494d_4c4c;

// ----------------------------------------------------------------------------------------------
// Native reference (must match the in-circuit computation bit-for-bit; used by consumers + tests).
// ----------------------------------------------------------------------------------------------

/// `leaf = Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)` — message first, then public key (the `<message,
/// pubkey>` list semantics).
pub fn list_leaf(message: Bytes32, public_key: Bytes32) -> PoseidonHashOut {
    let mut inputs = Vec::with_capacity(1 + 2 * BYTES32_LEN);
    inputs.push(LIST_LEAF_DOMAIN as u64);
    inputs.extend(message.to_u32_vec().into_iter().map(u64::from));
    inputs.extend(public_key.to_u32_vec().into_iter().map(u64::from));
    PoseidonHashOut::hash_inputs_u64(&inputs)
}

/// `C' = Poseidon(prev ‖ leaf)` (two-to-one), matching `PoseidonHashOutTarget::two_to_one`.
pub fn list_chain_step(prev: PoseidonHashOut, leaf: PoseidonHashOut) -> PoseidonHashOut {
    let mut inputs = Vec::with_capacity(2 * crate::utils::poseidon_hash_out::POSEIDON_HASH_OUT_LEN);
    inputs.extend_from_slice(&prev.elements);
    inputs.extend_from_slice(&leaf.elements);
    PoseidonHashOut::hash_inputs_u64(&inputs)
}

/// The chain commitment over an ordered list of `(message, public_key)` pairs, folded from `C_0 =
/// 0`.
pub fn list_commitment(pairs: &[(Bytes32, Bytes32)]) -> Bytes32 {
    let mut chain = PoseidonHashOut::default();
    for (message, public_key) in pairs {
        chain = list_chain_step(chain, list_leaf(*message, *public_key));
    }
    chain.into()
}

// ----------------------------------------------------------------------------------------------
// Shared in-circuit gadgets — used by BOTH the producer (`ListStepCircuit`) and the consumer
// (`super::consumer`), so the folded commitment is computed by identical constraints on both sides.
// ----------------------------------------------------------------------------------------------

/// In-circuit `leaf = Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)`. Mirrors [`list_leaf`].
///
/// Generic over the field so the SAME gadget can be used by the producer (`ListStepCircuit`), the
/// consumer, and the validity/close circuits — guaranteeing the folded commitment is computed by
/// identical constraints everywhere (the validity path uses `F = GoldilocksField, D = 2`).
pub(crate) fn leaf_target<GF: RichField + Extendable<GD>, const GD: usize>(
    builder: &mut CircuitBuilder<GF, GD>,
    message: &Bytes32Target,
    public_key: &Bytes32Target,
) -> PoseidonHashOutTarget {
    let dom = builder.constant(GF::from_canonical_u32(LIST_LEAF_DOMAIN));
    let mut inputs = Vec::with_capacity(1 + 2 * BYTES32_LEN);
    inputs.push(dom);
    inputs.extend(message.to_vec());
    inputs.extend(public_key.to_vec());
    PoseidonHashOutTarget::hash_inputs(builder, &inputs)
}

/// In-circuit `C' = Poseidon(prev ‖ leaf)`. Mirrors [`list_chain_step`]. Generic over the field
/// for the same shared-gadget reason as [`leaf_target`].
pub(crate) fn chain_step_target<GF: RichField + Extendable<GD>, const GD: usize>(
    builder: &mut CircuitBuilder<GF, GD>,
    prev: PoseidonHashOutTarget,
    leaf: PoseidonHashOutTarget,
) -> PoseidonHashOutTarget {
    PoseidonHashOutTarget::two_to_one(builder, prev, leaf)
}

// ----------------------------------------------------------------------------------------------
// In-circuit per-step chain folder. Verifies one SingleSig proof, folds its (m, pk) into the chain.
// ----------------------------------------------------------------------------------------------

/// One list step: verify a [`SingleSigCircuit`](super::circuit::SingleSigCircuit) proof and fold
/// its `(m, pk)` into the running chain. Public inputs: `[prev_chain(8), new_chain(8)]`.
pub struct ListStepCircuit {
    pub data: CircuitData<F, C, D>,
    single_sig_proof: ProofWithPublicInputsTarget<D>,
    prev_chain: Bytes32Target,
}

impl ListStepCircuit {
    pub fn new(single_sig_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // Verify the embedded single-signature proof and read its public (pk, m).
        // SECURITY (A7): `add_proof_target_and_verify` bakes `single_sig_vd` in as a CONSTANT
        // verifier data, so only proofs from the genuine SingleSigCircuit can be folded — a
        // proof from any other circuit (even with the same 16-PI shape) fails verification
        // at build-fixed VK.
        let single_sig_proof = add_proof_target_and_verify(single_sig_vd, &mut builder);
        let pk = Bytes32Target::from_slice(&single_sig_proof.public_inputs[0..BYTES32_LEN]);
        let message = Bytes32Target::from_slice(
            &single_sig_proof.public_inputs[BYTES32_LEN..2 * BYTES32_LEN],
        );

        // leaf = Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)  (shared gadget — identical to the
        // consumer).
        let leaf = leaf_target(&mut builder, &message, &pk);

        // new_chain = Poseidon(prev_chain ‖ leaf). `to_hash_out` enforces that prev_chain is a
        // valid hash-out-derived Bytes32 (it always is: 0 on the first step, or a previous
        // new_chain).
        let prev_chain = Bytes32Target::new(&mut builder, true);
        let prev_hashout = prev_chain.to_hash_out(&mut builder);
        let new_hashout = chain_step_target(&mut builder, prev_hashout, leaf);
        let new_chain = Bytes32Target::from_hash_out(&mut builder, new_hashout);

        builder.register_public_inputs(&prev_chain.to_vec());
        builder.register_public_inputs(&new_chain.to_vec());

        let data = builder.build::<C>();
        Self {
            data,
            single_sig_proof,
            prev_chain,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    pub fn prove(
        &self,
        single_sig_proof: &ProofWithPublicInputs<F, C, D>,
        prev_chain: Bytes32,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.single_sig_proof, single_sig_proof)?;
        self.prev_chain.set_witness(&mut pw, prev_chain);
        self.data.prove(pw)
    }
}

// ----------------------------------------------------------------------------------------------
// The recursive list proof = the per-step folder wrapped in the cyclic chain accumulator.
// ----------------------------------------------------------------------------------------------

/// The recursive single-signature list proof. Its public output `[0..8]` is the running chain
/// commitment `C` (a `Bytes32`); compare it against [`list_commitment`].
pub struct ListCircuit {
    pub step: ListStepCircuit,
    pub cyclic: CyclicChainCircuit<F, C, D>,
}

impl ListCircuit {
    pub fn new(single_sig_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let step = ListStepCircuit::new(single_sig_vd);
        let cyclic = CyclicChainCircuit::new(&step.verifier_data());
        Self { step, cyclic }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.cyclic.data.verifier_data()
    }

    /// Append one verified single-signature proof to the list. `prev_chain` is the running native
    /// commitment over all previously-appended pairs (`Bytes32::zero()` for the first).
    /// `prev_cyclic` is the previous list proof (`None` for the first).
    pub fn prove_append(
        &self,
        single_sig_proof: &ProofWithPublicInputs<F, C, D>,
        prev_chain: Bytes32,
        prev_cyclic: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let step_proof = self.step.prove(single_sig_proof, prev_chain)?;
        self.cyclic
            .prove(&step_proof, prev_cyclic)
            .map_err(|e| anyhow::anyhow!("cyclic list proof failed: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_sig::{GoldilocksSecretKey, circuit::SingleSigCircuit};

    fn message(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 9, 8, 7, 6, 5, 4, 3]).unwrap()
    }

    #[test]
    fn native_chain_is_order_sensitive_and_deterministic() {
        let a = (message(1), message(0x10));
        let b = (message(2), message(0x20));
        assert_eq!(list_commitment(&[a, b]), list_commitment(&[a, b]));
        assert_ne!(list_commitment(&[a, b]), list_commitment(&[b, a]));
        assert_ne!(list_commitment(&[a]), list_commitment(&[a, b]));
        // LIST_LEAF_DOMAIN is distinct from the signature domains.
        assert_eq!(LIST_LEAF_DOMAIN, u32::from_be_bytes(*b"IMLL"));
        assert_ne!(LIST_LEAF_DOMAIN, super::super::DOMAIN_PK_G);
        assert_ne!(LIST_LEAF_DOMAIN, super::super::DOMAIN_SIG_G);
    }

    #[test]
    fn recursive_list_matches_native_commitment() {
        let single = SingleSigCircuit::new();
        let list = ListCircuit::new(&single.verifier_data());

        // Three (sk, m) pairs → their (pk, m) entries.
        let entries: Vec<(GoldilocksSecretKey, Bytes32)> = vec![
            (GoldilocksSecretKey::from_seed([1u8; 32]), message(0xa1)),
            (GoldilocksSecretKey::from_seed([2u8; 32]), message(0xa2)),
            (GoldilocksSecretKey::from_seed([3u8; 32]), message(0xa3)),
        ];
        let pairs: Vec<(Bytes32, Bytes32)> = entries
            .iter()
            .map(|(sk, m)| (*m, sk.public_key()))
            .collect();

        let mut prev_cyclic: Option<ProofWithPublicInputs<F, C, D>> = None;
        for (i, (sk, m)) in entries.iter().enumerate() {
            let sig_proof = single.prove(sk, *m).unwrap();
            let prev_chain = list_commitment(&pairs[0..i]);
            let cyclic = list
                .prove_append(&sig_proof, prev_chain, &prev_cyclic)
                .unwrap();
            // Each step's output commitment equals the native fold over the prefix.
            let expected = list_commitment(&pairs[0..=i]);
            let out = Bytes32::from_u32_slice(
                &cyclic.public_inputs[0..BYTES32_LEN]
                    .iter()
                    .map(|f| f.0 as u32)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert_eq!(out, expected, "step {i} commitment mismatch");
            prev_cyclic = Some(cyclic);
        }

        // The final list proof verifies and commits to the full ordered list.
        let final_proof = prev_cyclic.unwrap();
        list.verifier_data()
            .verify(final_proof.clone())
            .expect("final list proof must verify");
        let out = Bytes32::from_u32_slice(
            &final_proof.public_inputs[0..BYTES32_LEN]
                .iter()
                .map(|f| f.0 as u32)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(out, list_commitment(&pairs));
    }

    #[test]
    fn first_step_must_start_from_zero_chain() {
        // The cyclic wrapper forces C_0 == 0 (cyclic_chain_circuit.rs:71-73). A first append whose
        // prev_chain is a valid-but-non-zero commitment must be rejected, so the list cannot be
        // seeded mid-chain to hide earlier entries. (prev_chain here is a real reducible
        // commitment, so the ListStep itself proves fine; the cyclic first-step zero-check
        // is what must reject it.)
        let single = SingleSigCircuit::new();
        let list = ListCircuit::new(&single.verifier_data());

        let sk = GoldilocksSecretKey::from_seed([0x21; 32]);
        let m = message(0xc0);
        let bogus_prev = list_commitment(&[(message(0xee), sk.public_key())]); // reducible, non-zero
        let sig = single.prove(&sk, m).unwrap();
        let bad = list.prove_append(&sig, bogus_prev, &None);
        assert!(bad.is_err(), "first step must start from a zero chain");
    }

    #[test]
    fn duplicate_entries_are_accepted_at_list_level() {
        // SECURITY (documents the boundary): the list circuit binds the ORDERED pairs but does NOT
        // enforce pubkey distinctness — appending the same (m, pk) twice yields a well-defined,
        // distinct commitment. Distinctness / all-members-present / pk-∈-member-set are
        // CONSUMER obligations (threat model §2.4.3, A5/A8), enforced in P2b, not here.
        let sk = GoldilocksSecretKey::from_seed([0x22; 32]);
        let pair = (message(0xd0), sk.public_key());
        assert_ne!(list_commitment(&[pair]), list_commitment(&[pair, pair]));
        // The native fold and the recursive circuit agree on this (covered end-to-end by
        // `recursive_list_matches_native_commitment`, which is the native↔in-circuit equivalence
        // guard).
    }

    #[test]
    fn list_step_rejects_wrong_prev_chain() {
        // A step proof whose prev_chain does not match the previous commitment must not let the
        // cyclic wrapper chain it: the cyclic circuit connects prev_chain to the previous
        // proof's output, so a mismatched prev_chain breaks the recursion (second append
        // fails).
        let single = SingleSigCircuit::new();
        let list = ListCircuit::new(&single.verifier_data());

        let sk0 = GoldilocksSecretKey::from_seed([7u8; 32]);
        let m0 = message(0xb0);
        let sig0 = single.prove(&sk0, m0).unwrap();
        let cyclic0 = list.prove_append(&sig0, Bytes32::zero(), &None).unwrap();

        // Append a second entry but lie about the running chain (use zero instead of the real C_1).
        let sk1 = GoldilocksSecretKey::from_seed([8u8; 32]);
        let sig1 = single.prove(&sk1, message(0xb1)).unwrap();
        let bad = list.prove_append(&sig1, Bytes32::zero(), &Some(cyclic0));
        assert!(
            bad.is_err(),
            "mismatched prev_chain must break the cyclic chain"
        );
    }
}
