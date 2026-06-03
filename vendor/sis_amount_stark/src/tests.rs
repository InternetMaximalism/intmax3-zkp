use std::time::Instant;

use p3_air::check_constraints;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use proptest::prelude::*;

use crate::air::AmountAir;
use crate::commitment::{amount_to_limbs, compute_commitment, compute_quotients};
use crate::config::{DEFAULT_BETA, ProofSystemOptions};
use crate::params::{M, N, Q, SECURITY_PROFILE, b_coeff, g_coeff};
use crate::prove::{
    Error, deserialize_envelope, prepare_system, proof_size_bytes, prove_amount,
    prove_amount_prepared, prove_amount_with_options, serialize_envelope, verify_amount,
    verify_amount_prepared, verify_amount_with_options,
};
use crate::trace::generate_trace;
use crate::witness::Witness;

fn randomness_from_prefix(prefix: &[i64]) -> [i64; N] {
    let mut r = [0_i64; N];
    for (dst, src) in r.iter_mut().zip(prefix.iter().copied()) {
        *dst = src;
    }
    r
}

#[test]
fn valid_proof_verifies() {
    let (proof, public_inputs) =
        prove_amount(12_345, randomness_from_prefix(&[3, -2, 5, 1])).expect("proof should succeed");
    verify_amount(&proof, &public_inputs).expect("verification should succeed");
}

#[test]
fn wrong_public_commitment_fails() {
    let (proof, mut public_inputs) =
        prove_amount(12_345, randomness_from_prefix(&[3, -2, 5, 1])).expect("proof should succeed");
    public_inputs.c[0] = (public_inputs.c[0] + 1) % Q;
    assert!(verify_amount(&proof, &public_inputs).is_err());
}

#[test]
#[should_panic(expected = "constraints not satisfied on row")]
fn corrupted_amount_bits_fail() {
    let amount = 12_345_u64;
    let r = randomness_from_prefix(&[3, -2, 5, 1]);
    let c = compute_commitment(amount, &r);
    let k = compute_quotients(amount, &r, &c).expect("quotients should succeed");
    let witness = Witness { amount, r, k };
    let options = ProofSystemOptions::default();
    let range = options.range_parameters().expect("range should succeed");
    let mut trace = generate_trace::<Goldilocks>(&witness, &range).expect("trace should succeed");
    trace.row_mut(0)[crate::air::COL_CHUNK_BIT_START] = Goldilocks::from_u64(2);
    let air = AmountAir { range };
    let public_values: Vec<_> = c.into_iter().map(Goldilocks::from_u64).collect();
    check_constraints(&air, &trace, &public_values);
}

#[test]
#[should_panic(expected = "constraints not satisfied on row")]
fn wrong_quotient_fails() {
    let amount = 12_345_u64;
    let r = randomness_from_prefix(&[3, -2, 5, 1]);
    let c = compute_commitment(amount, &r);
    let mut k = compute_quotients(amount, &r, &c).expect("quotients should succeed");
    k[0] += 1;
    let witness = Witness { amount, r, k };
    let options = ProofSystemOptions::default();
    let range = options.range_parameters().expect("range should succeed");
    let trace = generate_trace::<Goldilocks>(&witness, &range).expect("trace should succeed");
    let air = AmountAir { range };
    let public_values: Vec<_> = c.into_iter().map(Goldilocks::from_u64).collect();
    check_constraints(&air, &trace, &public_values);
}

#[test]
fn max_amount_proves() {
    let (proof, public_inputs) = prove_amount(u64::MAX, randomness_from_prefix(&[3, -2, 5, 1]))
        .expect("proof should succeed");
    verify_amount(&proof, &public_inputs).expect("verification should succeed");
}

#[test]
fn out_of_range_randomness_is_rejected() {
    let mut r = [0_i64; N];
    r[0] = DEFAULT_BETA + 1;
    match prove_amount(12_345, r) {
        Err(Error::InvalidWitness(_)) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("proof should fail"),
    }
}

#[test]
fn quotient_relation_matches_public_commitment() {
    let amount = 12_345_u64;
    let r = randomness_from_prefix(&[3, -2, 5, 1]);
    let c = compute_commitment(amount, &r);
    let k = compute_quotients(amount, &r, &c).expect("quotients should succeed");
    let amount_limbs = amount_to_limbs(amount);

    for j in 0..M {
        let mut expr = 0_i128;
        for (limb_idx, limb) in amount_limbs.iter().enumerate() {
            expr += i128::from(g_coeff(j, limb_idx)) * i128::from(*limb);
        }
        for (i, r_i) in r.iter().enumerate() {
            expr += i128::from(b_coeff(j, i)) * i128::from(*r_i);
        }
        expr -= i128::from(c[j]);
        expr -= i128::from(k[j]) * i128::from(Q);
        assert_eq!(expr, 0);
    }
}

#[test]
fn commitment_distinguishes_amounts_separated_by_q() {
    let r = randomness_from_prefix(&[3, -2, 5, 1]);
    assert_ne!(compute_commitment(56, &r), compute_commitment(56 + Q, &r));
}

#[test]
fn proof_envelope_roundtrip() {
    let options = ProofSystemOptions::default();
    let (proof, public_inputs) =
        prove_amount_with_options(12_345, randomness_from_prefix(&[3, -2, 5, 1]), &options)
            .expect("proof should succeed");
    let encoded = serialize_envelope(&proof, &public_inputs, &options).expect("serialize");
    let (decoded_proof, decoded_public_inputs, decoded_options) =
        deserialize_envelope(&encoded).expect("deserialize");

    assert_eq!(decoded_public_inputs, public_inputs);
    assert_eq!(decoded_options, options);
    verify_amount_with_options(&decoded_proof, &decoded_public_inputs, &decoded_options)
        .expect("roundtrip proof should verify");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prove_verify_property_holds(
        amount in any::<u64>(),
        r0 in -DEFAULT_BETA..=DEFAULT_BETA,
        r1 in -DEFAULT_BETA..=DEFAULT_BETA,
        r2 in -DEFAULT_BETA..=DEFAULT_BETA,
        r3 in -DEFAULT_BETA..=DEFAULT_BETA,
    ) {
        let r = randomness_from_prefix(&[r0, r1, r2, r3]);
        let (proof, public_inputs) = prove_amount(amount, r).expect("proof should succeed");
        verify_amount(&proof, &public_inputs).expect("verification should succeed");
    }
}

#[test]
fn non_power_of_two_beta_proves() {
    let options = ProofSystemOptions {
        beta: 150_000,
        ..ProofSystemOptions::default()
    };
    let (proof, public_inputs) = prove_amount_with_options(
        12_345,
        randomness_from_prefix(&[300, -200, 500, 1_500]),
        &options,
    )
    .expect("proof should succeed");
    verify_amount_with_options(&proof, &public_inputs, &options)
        .expect("verification should succeed");
}

#[test]
#[ignore]
fn benchmark_prove_verify() {
    let amount = 12_345_u64;
    let r = randomness_from_prefix(&[3, -2, 5, 1]);
    let prepared = prepare_system(&ProofSystemOptions::default()).expect("prepare should succeed");

    let prove_start = Instant::now();
    let (proof, public_inputs) =
        prove_amount_prepared(&prepared, amount, r).expect("proof should succeed");
    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    verify_amount_prepared(&prepared, &proof, &public_inputs).expect("verification should succeed");
    let verify_time = verify_start.elapsed();

    eprintln!("prove time: {:?}", prove_time);
    eprintln!("verify time: {:?}", verify_time);
    eprintln!(
        "profile: {}, proof size: {} bytes",
        SECURITY_PROFILE,
        proof_size_bytes(&proof).expect("size should serialize")
    );
}

#[test]
#[ignore]
fn benchmark_prepare_system() {
    let start = Instant::now();
    let prepared = prepare_system(&ProofSystemOptions::default()).expect("prepare should succeed");
    let elapsed = start.elapsed();

    eprintln!(
        "profile: {}, prepare time: {:?}, trace_rows={}, active_rows={}, r_bits={}",
        SECURITY_PROFILE,
        elapsed,
        prepared.range().trace_rows,
        prepared.range().active_rows,
        prepared.range().r_bits,
    );
}
