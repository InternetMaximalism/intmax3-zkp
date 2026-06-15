#![cfg(not(debug_assertions))]
use std::time::Instant;
use intmax3_zkp::circuits::test_utils::sphincs_sign::{sphincs_keygen, sphincs_sign};
use sphincsplus_poseidon::verify::crypto_sign_verify;

#[test]
fn time_sphincs_native() {
    let t = Instant::now();
    let kp = sphincs_keygen([1u8;16],[2u8;16],[3u8;16]);
    eprintln!("NATIVE keygen: {:?}", t.elapsed());

    let msg = vec![7u8; 64];
    let t = Instant::now();
    let sig = sphincs_sign(&msg, &kp);
    eprintln!("NATIVE sign:   {:?}", t.elapsed());

    let t = Instant::now();
    crypto_sign_verify(&sig, &msg, &kp.pk_bytes).unwrap();
    eprintln!("NATIVE verify: {:?}", t.elapsed());
}
