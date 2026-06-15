//! In-circuit consumer of the recursive single-signature list proof (P2b-0).
//!
//! A consumer (the validity / close circuits in P2b-2/3) needs to learn "these exact `(message,
//! public_key)` pairs were each signed" from a [`ListCircuit`](super::list::ListCircuit) proof. This
//! gadget provides that check, decoupled from any live circuit so it can be tested in isolation:
//!
//!   1. recursively verify the list proof (its commitment `C` is public output `[0..8]`);
//!   2. rebuild `C'` from the caller-supplied ordered `(m, pk)` pairs using the **same** in-circuit
//!      gadgets the producer used ([`super::list::leaf_target`] / [`super::list::chain_step_target`]);
//!   3. assert `C' == C` — this binds the EXACT set, order, and **count** (a different number of pairs
//!      yields a different commitment), closing the "skip / insert / reorder" gaps (A8);
//!   4. assert the public keys are pairwise **distinct** — closing the duplicate-key fake-N-of-N gap (A5).
//!
//! What this gadget does NOT do (left to each concrete consumer, because it is context-specific):
//!   - bind each `pk` to the registered member set (`member_pubkeys_root` / `member_set_commitment`, A9);
//!   - bind each `m` to the right per-context message (IMSB digest / IMCH digest) with domain
//!     separation so a close entry can't satisfy a validity predicate (A4).
//! The caller supplies the `(m, pk)` targets already derived from those bound sources.

use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

use super::{
    circuit::{C, D, F},
    list::{chain_step_target, leaf_target},
};

/// Verify a list proof and bind it to exactly `num_pairs` ordered, pubkey-distinct `(m, pk)` pairs.
pub struct ListConsumerCircuit {
    pub data: CircuitData<F, C, D>,
    list_proof: ProofWithPublicInputsTarget<D>,
    pairs: Vec<(Bytes32Target, Bytes32Target)>,
}

impl ListConsumerCircuit {
    pub fn new(list_vd: &VerifierCircuitData<F, C, D>, num_pairs: usize) -> Self {
        assert!(num_pairs > 0, "a consumer must bind at least one pair");
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // (1) recursively verify the list proof (constant VD pins the list circuit, A7).
        let list_proof = add_proof_target_and_verify(list_vd, &mut builder);
        let committed_c = Bytes32Target::from_slice(&list_proof.public_inputs[0..BYTES32_LEN]);

        // Caller-supplied (m, pk) pairs (range-checked u32 limbs).
        let pairs: Vec<(Bytes32Target, Bytes32Target)> = (0..num_pairs)
            .map(|_| {
                (
                    Bytes32Target::new(&mut builder, true),
                    Bytes32Target::new(&mut builder, true),
                )
            })
            .collect();

        // (2)+(3) rebuild C' from C_0 = 0 and assert it equals the committed C.
        let mut chain = PoseidonHashOutTarget::constant(&mut builder, PoseidonHashOut::default());
        for (message, public_key) in &pairs {
            let leaf = leaf_target(&mut builder, message, public_key);
            chain = chain_step_target(&mut builder, chain, leaf);
        }
        let rebuilt_c = Bytes32Target::from_hash_out(&mut builder, chain);
        rebuilt_c.connect(&mut builder, committed_c);

        // (4) pubkeys pairwise distinct (A5: forbids one key faking N signatures).
        for i in 0..num_pairs {
            for j in (i + 1)..num_pairs {
                let eq = pairs[i].1.is_equal(&mut builder, &pairs[j].1);
                builder.assert_zero(eq.target);
            }
        }

        let data = builder.build::<C>();
        Self {
            data,
            list_proof,
            pairs,
        }
    }

    pub fn prove(
        &self,
        list_proof: &ProofWithPublicInputs<F, C, D>,
        pairs: &[(Bytes32, Bytes32)],
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        assert_eq!(pairs.len(), self.pairs.len(), "pair count must match the circuit");
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.list_proof, list_proof)?;
        for ((m_t, pk_t), (m, pk)) in self.pairs.iter().zip(pairs.iter()) {
            m_t.set_witness(&mut pw, *m);
            pk_t.set_witness(&mut pw, *pk);
        }
        self.data.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_sig::{
        circuit::SingleSigCircuit,
        list::{list_commitment, ListCircuit},
        GoldilocksSecretKey,
    };

    fn message(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 3, 1, 4, 1, 5, 9, 2]).unwrap()
    }

    /// Build a recursive list proof over the given (sk, m) entries and return it with the (m, pk) pairs.
    fn build_list(
        entries: &[(GoldilocksSecretKey, Bytes32)],
    ) -> (
        ListCircuit,
        ProofWithPublicInputs<F, C, D>,
        Vec<(Bytes32, Bytes32)>,
    ) {
        let single = SingleSigCircuit::new();
        let list = ListCircuit::new(&single.verifier_data());
        let pairs: Vec<(Bytes32, Bytes32)> =
            entries.iter().map(|(sk, m)| (*m, sk.public_key())).collect();
        let mut prev: Option<ProofWithPublicInputs<F, C, D>> = None;
        for (i, (sk, m)) in entries.iter().enumerate() {
            let sig = single.prove(sk, *m).unwrap();
            let prefix = list_commitment(&pairs[0..i]);
            prev = Some(list.prove_append(&sig, prefix, &prev).unwrap());
        }
        (list, prev.unwrap(), pairs)
    }

    #[test]
    fn accepts_exact_pairs() {
        let entries = vec![
            (GoldilocksSecretKey::from_seed([1u8; 32]), message(0x01)),
            (GoldilocksSecretKey::from_seed([2u8; 32]), message(0x02)),
            (GoldilocksSecretKey::from_seed([3u8; 32]), message(0x03)),
        ];
        let (list, proof, pairs) = build_list(&entries);
        let consumer = ListConsumerCircuit::new(&list.verifier_data(), pairs.len());
        let p = consumer.prove(&proof, &pairs).expect("exact pairs must verify");
        consumer.data.verify(p).unwrap();
    }

    #[test]
    fn rejects_reordered_pairs() {
        let entries = vec![
            (GoldilocksSecretKey::from_seed([1u8; 32]), message(0x01)),
            (GoldilocksSecretKey::from_seed([2u8; 32]), message(0x02)),
            (GoldilocksSecretKey::from_seed([3u8; 32]), message(0x03)),
        ];
        let (list, proof, mut pairs) = build_list(&entries);
        let consumer = ListConsumerCircuit::new(&list.verifier_data(), pairs.len());
        pairs.swap(0, 2); // wrong order → rebuilt C' ≠ committed C
        assert!(consumer.prove(&proof, &pairs).is_err());
    }

    #[test]
    fn rejects_wrong_pair() {
        let entries = vec![
            (GoldilocksSecretKey::from_seed([1u8; 32]), message(0x01)),
            (GoldilocksSecretKey::from_seed([2u8; 32]), message(0x02)),
        ];
        let (list, proof, mut pairs) = build_list(&entries);
        let consumer = ListConsumerCircuit::new(&list.verifier_data(), pairs.len());
        // Replace one pk with an unrelated key → mismatch.
        pairs[1].1 = GoldilocksSecretKey::from_seed([9u8; 32]).public_key();
        assert!(consumer.prove(&proof, &pairs).is_err());
    }

    #[test]
    fn rejects_duplicate_pubkey() {
        // A5: a list built with the SAME key signing two slots must be rejected by the consumer's
        // distinctness check, even though the commitment matches.
        let sk = GoldilocksSecretKey::from_seed([7u8; 32]);
        let entries = vec![(sk, message(0x10)), (sk, message(0x11))];
        let (list, proof, pairs) = build_list(&entries);
        assert_eq!(pairs[0].1, pairs[1].1); // same pk twice
        let consumer = ListConsumerCircuit::new(&list.verifier_data(), pairs.len());
        assert!(
            consumer.prove(&proof, &pairs).is_err(),
            "duplicate pubkey must be rejected (fake N-of-N)"
        );
    }
}
