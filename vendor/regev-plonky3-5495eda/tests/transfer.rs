//! Tests for value-level functionality:
//!
//! 1. Additive homomorphism — `decrypt_value(Enc(A) + Enc(B)) = A + B`
//!    (digit decoding with `Δ = q/t`, so per-coefficient sums don't wrap).
//! 2. The transfer AIR — in-circuit proof of `before = after + delta`.
#![allow(clippy::cloned_ref_to_slice_refs)]

use rand::rngs::SmallRng;
use rand::SeedableRng;
use regev_plonky3::*;

const TEST_PARAMS: RegevParams = RegevParams {
    n: 256,
    eta: 2,
    plain_bits: 8,
};

// ---------------------------------------------------------------------------
// Additive homomorphism (value level)
// ---------------------------------------------------------------------------

#[test]
fn homomorphic_add_5_plus_3_is_8() {
    let mut rng = SmallRng::seed_from_u64(1);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);

    let (ct_a, _) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(5, TEST_PARAMS.n));
    let (ct_b, _) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(3, TEST_PARAMS.n));

    let ct_sum = add_ciphertexts(&ct_a, &ct_b);
    assert_eq!(decrypt_value(&TEST_PARAMS, &sk, &ct_sum), 8);
}

#[test]
fn homomorphic_add_random_values() {
    let mut rng = SmallRng::seed_from_u64(2);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);

    for (a, b) in [(0u64, 0u64), (1, 1), (123_456, 654_321), (u32::MAX as u64, 1)] {
        let (ca, _) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(a, TEST_PARAMS.n));
        let (cb, _) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(b, TEST_PARAMS.n));
        let sum = add_ciphertexts(&ca, &cb);
        assert_eq!(
            decrypt_value(&TEST_PARAMS, &sk, &sum),
            (a + b) as u128,
            "Enc({a}) + Enc({b})"
        );
    }
}

#[test]
fn homomorphic_add_many_ciphertexts() {
    // Stack 100 additions; digits stay below t = 256 and noise far below Δ/2.
    let mut rng = SmallRng::seed_from_u64(3);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);

    let mut acc: Option<Ciphertext> = None;
    let mut expected: u128 = 0;
    for v in 0..100u64 {
        let (ct, _) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(v, TEST_PARAMS.n));
        expected += v as u128;
        acc = Some(match acc {
            Some(a) => add_ciphertexts(&a, &ct),
            None => ct,
        });
    }
    assert_eq!(decrypt_value(&TEST_PARAMS, &sk, &acc.unwrap()), expected);
}

#[test]
fn homomorphic_sum_of_proven_ciphertexts() {
    // The composition that matters in practice: prove both inputs are
    // well-formed, then add them publicly. By linearity the sum is a valid
    // encryption of A + B with doubled (still tiny) noise.
    let mut rng = SmallRng::seed_from_u64(4);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);

    let (ca, wa) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(700, TEST_PARAMS.n));
    let (cb, wb) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(42, TEST_PARAMS.n));

    let config = test_config();
    let proof = prove_encryptions(
        &config,
        &TEST_PARAMS,
        &pk,
        &[ca.clone(), cb.clone()],
        &[wa, wb],
    );
    verify_encryptions(&config, &TEST_PARAMS, &pk, &[ca.clone(), cb.clone()], &proof).unwrap();

    let sum = add_ciphertexts(&ca, &cb);
    assert_eq!(decrypt_value(&TEST_PARAMS, &sk, &sum), 742);
}

// ---------------------------------------------------------------------------
// Transfer proofs: before = after + delta
// ---------------------------------------------------------------------------

fn make_transfer(
    rng: &mut SmallRng,
    pk: &PublicKey,
    before_v: u64,
    delta_v: u64,
) -> (Transfer, TransferWitness) {
    let after_v = before_v - delta_v;
    let n = TEST_PARAMS.n;
    let (before, w_before) = encrypt(rng, &TEST_PARAMS, pk, &encode_value_message(before_v, n));
    let (delta, w_delta) = encrypt(rng, &TEST_PARAMS, pk, &encode_value_message(delta_v, n));
    let (after, w_after) = encrypt(rng, &TEST_PARAMS, pk, &encode_value_message(after_v, n));
    (
        Transfer {
            before,
            delta,
            after,
        },
        TransferWitness {
            before: w_before,
            delta: w_delta,
            after: w_after,
        },
    )
}

#[test]
fn transfer_proves_conservation() {
    let mut rng = SmallRng::seed_from_u64(10);
    let (pk, sk) = keygen(&mut rng, &TEST_PARAMS);
    let (t, w) = make_transfer(&mut rng, &pk, 100, 42);

    // Sanity: the three ciphertexts decrypt to consistent values.
    assert_eq!(decrypt_value(&TEST_PARAMS, &sk, &t.before), 100);
    assert_eq!(decrypt_value(&TEST_PARAMS, &sk, &t.delta), 42);
    assert_eq!(decrypt_value(&TEST_PARAMS, &sk, &t.after), 58);

    let config = test_config();
    let proof = prove_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &[w]);
    verify_transfers(&config, &TEST_PARAMS, &pk, &[t], &proof).expect("transfer verifies");
}

#[test]
fn transfer_with_carry_chain() {
    // 256 = 255 + 1 exercises a long carry ripple (0b11111111 + 1).
    let mut rng = SmallRng::seed_from_u64(11);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let (t, w) = make_transfer(&mut rng, &pk, 256, 1);

    let config = test_config();
    let proof = prove_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &[w]);
    verify_transfers(&config, &TEST_PARAMS, &pk, &[t], &proof).expect("carry chain verifies");
}

#[test]
fn transfer_batch() {
    let mut rng = SmallRng::seed_from_u64(12);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let cases = [(1_000_000u64, 1u64), (5, 5), (u32::MAX as u64, 12345)];
    let (ts, ws): (Vec<_>, Vec<_>) = cases
        .iter()
        .map(|&(b, d)| make_transfer(&mut rng, &pk, b, d))
        .unzip();

    let config = test_config();
    let proof = prove_transfers(&config, &TEST_PARAMS, &pk, &ts, &ws);
    verify_transfers(&config, &TEST_PARAMS, &pk, &ts, &proof).expect("batch verifies");
}

#[test]
#[should_panic(expected = "transfer witness inconsistent")]
fn transfer_prover_rejects_non_conserving_witness() {
    // before = 100, delta = 42, but after = 60 (should be 58): the prover
    // cannot build a valid carry chain.
    let mut rng = SmallRng::seed_from_u64(13);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let n = TEST_PARAMS.n;
    let (before, w_before) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(100, n));
    let (delta, w_delta) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(42, n));
    let (after, w_after) = encrypt(&mut rng, &TEST_PARAMS, &pk, &encode_value_message(60, n));

    let t = Transfer {
        before,
        delta,
        after,
    };
    let w = TransferWitness {
        before: w_before,
        delta: w_delta,
        after: w_after,
    };
    let config = test_config();
    let _ = prove_transfers(&config, &TEST_PARAMS, &pk, &[t], &[w]);
}

#[test]
fn transfer_rejects_swapped_statement() {
    // A proof for (before, delta, after) must not verify with delta and
    // after swapped (i.e. claiming the transferred amount was 58, not 42).
    let mut rng = SmallRng::seed_from_u64(14);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let (t, w) = make_transfer(&mut rng, &pk, 100, 42);

    let config = test_config();
    let proof = prove_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &[w]);

    let swapped = Transfer {
        before: t.before.clone(),
        delta: t.after.clone(),
        after: t.delta.clone(),
    };
    assert!(verify_transfers(&config, &TEST_PARAMS, &pk, &[swapped], &proof).is_err());
}

#[test]
fn transfer_rejects_unrelated_ciphertext() {
    // Replace `after` in the statement with an encryption of the wrong value.
    let mut rng = SmallRng::seed_from_u64(15);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let (t, w) = make_transfer(&mut rng, &pk, 100, 42);
    let (wrong_after, _) = encrypt(
        &mut rng,
        &TEST_PARAMS,
        &pk,
        &encode_value_message(59, TEST_PARAMS.n),
    );

    let config = test_config();
    let proof = prove_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &[w]);

    let forged = Transfer {
        before: t.before.clone(),
        delta: t.delta.clone(),
        after: wrong_after,
    };
    assert!(verify_transfers(&config, &TEST_PARAMS, &pk, &[forged], &proof).is_err());
}

#[test]
fn transfer_zero_knowledge_config() {
    let mut rng = SmallRng::seed_from_u64(16);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let (t, w) = make_transfer(&mut rng, &pk, 1_000, 999);

    let config = regev_plonky3::config::zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(17));
    let proof = prove_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &[w]);
    verify_transfers(&config, &TEST_PARAMS, &pk, &[t], &proof).expect("zk transfer verifies");
}

#[test]
fn transfer_composes_with_delta_range_proof() {
    // Composition pattern: the transfer proof shows conservation; a separate
    // range-proof instance on the *same* delta ciphertext caps the amount.
    // Both proofs bind to the identical statement ciphertext, so a verifier
    // accepting both knows: before = after + delta AND delta < 2^16.
    let mut rng = SmallRng::seed_from_u64(18);
    let (pk, _) = keygen(&mut rng, &TEST_PARAMS);
    let (t, w) = make_transfer(&mut rng, &pk, 100_000, 42_000);

    let config = test_config();
    let transfer_proof = prove_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &[w.clone()]);
    verify_transfers(&config, &TEST_PARAMS, &pk, &[t.clone()], &transfer_proof).unwrap();

    let spec = RangeSpec {
        value_bits: 16,
        bound: 1 << 16,
    };
    let range_proof = prove_encryptions_with_range(
        &config,
        &TEST_PARAMS,
        &pk,
        &[t.delta.clone()],
        &[w.delta],
        spec,
    );
    verify_encryptions_with_range(&config, &TEST_PARAMS, &pk, &[t.delta], &range_proof, spec)
        .unwrap();
}
