//! End-to-end tests: encrypt → prove → verify, plus soundness checks that
//! tampered statements and tampered proofs are rejected.
#![allow(clippy::cloned_ref_to_slice_refs)] // `&[ct.clone()]` reads clearly in tests

use p3_field::PrimeCharacteristicRing;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use regev_plonky3::*;

const TEST_PARAMS: RegevParams = RegevParams { n: 256, eta: 2, plain_bits: 8 };

fn setup(
    seed: u64,
    batch: usize,
) -> (
    PublicKey,
    SecretKey,
    Vec<Vec<u8>>,
    Vec<Ciphertext>,
    Vec<EncryptionWitness>,
) {
    let mut rng = SmallRng::seed_from_u64(seed);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);
    let mut msgs = Vec::new();
    let mut cts = Vec::new();
    let mut wits = Vec::new();
    for _ in 0..batch {
        let m: Vec<u8> = (0..TEST_PARAMS.n).map(|_| rng.random_range(0..=1)).collect();
        let (ct, w) = encrypt(&mut rng, &TEST_PARAMS, &pk, &m);
        msgs.push(m);
        cts.push(ct);
        wits.push(w);
    }
    (pk, sk, msgs, cts, wits)
}

#[test]
fn prove_verify_single() {
    let (pk, sk, msgs, cts, wits) = setup(1, 1);
    assert_eq!(decrypt(&TEST_PARAMS, &sk, &cts[0]), msgs[0]);

    let config = test_config();
    let proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);
    verify_encryptions(&config, &TEST_PARAMS, &pk, &cts, &proof).expect("honest proof verifies");
}

#[test]
fn prove_verify_batch() {
    let (pk, _, _, cts, wits) = setup(2, 4);
    let config = test_config();
    let proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);
    verify_encryptions(&config, &TEST_PARAMS, &pk, &cts, &proof).expect("batch proof verifies");

    // Proof size for the curious (postcard, unoptimized).
    let bytes = postcard::to_allocvec(&proof).unwrap();
    println!("batch of 4: proof size = {} bytes", bytes.len());
}

#[test]
fn rejects_wrong_ciphertext() {
    let (pk, _, _, cts, wits) = setup(3, 1);
    let config = test_config();
    let proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);

    // Same proof, different claimed ciphertext. The ciphertext is part of
    // the public values, so the transcript already diverges and the inner
    // STARK rejects (before the evaluation-binding check even runs).
    let mut other = cts.clone();
    other[0].c2[7] += Val::ONE;
    assert!(verify_encryptions(&config, &TEST_PARAMS, &pk, &other, &proof).is_err());
}

/// The critical soundness path for the evaluation binding: a malicious
/// prover commits trace columns for a *different* (validly formed)
/// ciphertext while presenting the real one as the statement. The inner
/// STARK is fully self-consistent in that case — only the comparison of the
/// published evaluations `c1(z), c2(z)` against the claimed statement
/// catches it.
#[test]
fn rejects_malicious_prover_with_forged_columns() {
    use p3_batch_stark::common::ProverData;
    use p3_batch_stark::prover::StarkInstance;
    
    use p3_lookup::LookupAir;
    use regev_plonky3::air::{generate_trace, public_values, RegevEncAir};

    let (pk, _, _, cts, _) = setup(7, 1);
    let mut rng = SmallRng::seed_from_u64(77);

    // A forged-but-valid encryption of a different message.
    let m2: Vec<u8> = (0..TEST_PARAMS.n).map(|_| rng.random_range(0..=1)).collect();
    let (forged_ct, forged_wit) = encrypt(&mut rng, &TEST_PARAMS, &pk, &m2);

    let config = test_config();
    let air = RegevEncAir::new(
        TEST_PARAMS.n,
        Val::from_u32(TEST_PARAMS.delta()),
    );
    // Trace for the forged ciphertext, public values for the real one.
    let trace = generate_trace(&pk, &forged_ct, &forged_wit);
    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: public_values(&pk, &cts[0]),
        lookups: air.clone().get_lookups(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = regev_plonky3::stark::prove_batch(&config, &instances, &prover_data);

    let err = verify_encryptions(&config, &TEST_PARAMS, &pk, &cts, &proof).unwrap_err();
    match err {
        RegevVerifyError::StatementMismatch { poly, .. } => {
            assert!(poly == "c1" || poly == "c2");
        }
        e => panic!("expected StatementMismatch, got {e}"),
    }
}

#[test]
fn rejects_wrong_public_key() {
    let (pk, _, _, cts, wits) = setup(4, 1);
    let config = test_config();
    let proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);

    let mut other_pk = pk.clone();
    other_pk.b[0] += Val::ONE;
    // Changing the public key changes the transcript (public values), so the
    // inner STARK itself must fail.
    assert!(verify_encryptions(&config, &TEST_PARAMS, &other_pk, &cts, &proof).is_err());
}

#[test]
fn rejects_tampered_published_evaluation() {
    let (pk, _, _, cts, wits) = setup(5, 1);
    let config = test_config();
    let mut proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);

    // Tamper with the published evaluation of c1. Both the transcript and the
    // first-row constraint depend on it, so verification must fail.
    proof.global_lookup_data[0][2].expected_cumulated += Challenge::ONE;
    assert!(verify_encryptions(&config, &TEST_PARAMS, &pk, &cts, &proof).is_err());
}

#[test]
fn rejects_swapped_instances() {
    // A batch proof for (ct0, ct1) must not verify as (ct1, ct0).
    let (pk, _, _, cts, wits) = setup(6, 2);
    let config = test_config();
    let proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);

    let swapped = vec![cts[1].clone(), cts[0].clone()];
    assert!(verify_encryptions(&config, &TEST_PARAMS, &pk, &swapped, &proof).is_err());
}

#[test]
fn prove_verify_zero_knowledge_config() {
    let (pk, _, _, cts, wits) = setup(8, 2);
    // Same masking seed on both sides is NOT required — the verifier never
    // uses the prover's rng — but the config constructor takes one.
    let config = regev_plonky3::config::zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(99));
    let proof = prove_encryptions(&config, &TEST_PARAMS, &pk, &cts, &wits);
    assert!(proof.commitments.random.is_some(), "zk proof carries random commitment");
    verify_encryptions(&config, &TEST_PARAMS, &pk, &cts, &proof).expect("zk proof verifies");
}

// ---------------------------------------------------------------------------
// Plaintext range proofs
// ---------------------------------------------------------------------------

/// Build a length-`n` binary message whose low `value_bits` coefficients
/// encode `value` little-endian (high coefficients zero).
fn message_for_value(value: u64, value_bits: usize, n: usize) -> Vec<u8> {
    let mut m = vec![0u8; n];
    for (i, slot) in m.iter_mut().enumerate().take(value_bits) {
        *slot = ((value >> i) & 1) as u8;
    }
    m
}

fn setup_with_value(
    seed: u64,
    value: u64,
    value_bits: usize,
) -> (PublicKey, SecretKey, Ciphertext, EncryptionWitness) {
    let mut rng = SmallRng::seed_from_u64(seed);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);
    let m = message_for_value(value, value_bits, TEST_PARAMS.n);
    let (ct, w) = encrypt(&mut rng, &TEST_PARAMS, &pk, &m);
    (pk, sk, ct, w)
}

#[test]
fn range_proof_accepts_in_range() {
    let spec = RangeSpec {
        value_bits: 16,
        bound: 1000,
    };
    let (pk, sk, ct, w) = setup_with_value(20, 742, spec.value_bits);
    // decrypt recovers the message encoding 742.
    assert_eq!(
        decrypt(&TEST_PARAMS, &sk, &ct),
        message_for_value(742, spec.value_bits, TEST_PARAMS.n)
    );

    let config = test_config();
    let proof = prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], spec);
    verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &proof, spec)
        .expect("in-range proof verifies");
}

#[test]
fn range_proof_boundary_values() {
    let spec = RangeSpec {
        value_bits: 12,
        bound: 4096, // == 2^12, so value can be 0..=4095
    };
    let config = test_config();
    for value in [0u64, 1, 4095] {
        let (pk, _, ct, w) = setup_with_value(21 + value, value, spec.value_bits);
        let proof =
            prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], spec);
        verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &proof, spec)
            .unwrap_or_else(|e| panic!("value {value} should verify: {e}"));
    }
}

#[test]
#[should_panic(expected = "is not in")]
fn range_proof_prover_rejects_out_of_range() {
    let spec = RangeSpec {
        value_bits: 16,
        bound: 500,
    };
    // value 742 >= bound 500: the prover cannot build a valid witness.
    let (pk, _, ct, w) = setup_with_value(22, 742, spec.value_bits);
    let config = test_config();
    let _ = prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &[w], spec);
}

#[test]
fn range_proof_verifier_rejects_different_bound() {
    let prove_spec = RangeSpec {
        value_bits: 16,
        bound: 1000,
    };
    let (pk, _, ct, w) = setup_with_value(23, 742, prove_spec.value_bits);
    let config = test_config();
    let proof =
        prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], prove_spec);

    // The proof was for bound 1000; a verifier checking bound 800 (which 742
    // also satisfies) must still reject — the committed accumulator encodes
    // bound-1 = 999, not 799.
    let verify_spec = RangeSpec {
        value_bits: 16,
        bound: 800,
    };
    assert!(
        verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &proof, verify_spec)
            .is_err()
    );
}

#[test]
fn range_proof_plain_verifier_rejects_ranged_proof() {
    // A proof produced with a range argument has a different trace width and
    // preprocessed commitment, so the plain (no-range) verifier rejects it.
    let spec = RangeSpec {
        value_bits: 16,
        bound: 1000,
    };
    let (pk, _, ct, w) = setup_with_value(24, 100, spec.value_bits);
    let config = test_config();
    let proof = prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], spec);
    assert!(verify_encryptions(&config, &TEST_PARAMS, &pk, &[ct], &proof).is_err());
}

#[test]
fn range_proof_batch() {
    let spec = RangeSpec {
        value_bits: 20,
        bound: 1_000_000,
    };
    let mut rng = SmallRng::seed_from_u64(25);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let values = [0u64, 1, 12345, 999_999];
    let mut cts = Vec::new();
    let mut wits = Vec::new();
    for &v in &values {
        let m = message_for_value(v, spec.value_bits, TEST_PARAMS.n);
        let (ct, w) = encrypt(&mut rng, &TEST_PARAMS, &pk, &m);
        cts.push(ct);
        wits.push(w);
    }
    let config = test_config();
    let proof = prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &cts, &wits, spec);
    verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &cts, &proof, spec)
        .expect("batched range proof verifies");
}

#[test]
fn range_proof_zero_knowledge() {
    let spec = RangeSpec {
        value_bits: 16,
        bound: 50000,
    };
    let (pk, _, ct, w) = setup_with_value(26, 31337, spec.value_bits);
    let config = regev_plonky3::config::zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(7));
    let proof = prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], spec);
    verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &proof, spec)
        .expect("zk range proof verifies");
}

#[test]
fn range_proof_value_uses_full_window() {
    // A value that needs the *high* bit of the window (bit 15) must still be
    // bound — the count constraint forces exactly `value_bits` active bits,
    // so a malicious prover cannot shrink the window to drop the high bit.
    let spec = RangeSpec {
        value_bits: 16,
        bound: 1 << 16,
    };
    let value = (1u64 << 15) | 7; // high bit set
    let (pk, _, ct, w) = setup_with_value(27, value, spec.value_bits);
    let config = test_config();
    let proof = prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], spec);
    verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &proof, spec)
        .expect("high-bit value within 2^16 verifies");
}

#[test]
fn range_proof_verifier_rejects_different_value_bits() {
    let prove_spec = RangeSpec {
        value_bits: 16,
        bound: 1000,
    };
    let (pk, _, ct, w) = setup_with_value(28, 742, prove_spec.value_bits);
    let config = test_config();
    let proof =
        prove_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct.clone()], &[w], prove_spec);

    // Verifier insists on value_bits = 20; the committed cnt accumulator
    // encodes 16, so the cnt[0] = value_bits constraint fails.
    let verify_spec = RangeSpec {
        value_bits: 20,
        bound: 1000,
    };
    assert!(
        verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[ct], &proof, verify_spec)
            .is_err()
    );
}
