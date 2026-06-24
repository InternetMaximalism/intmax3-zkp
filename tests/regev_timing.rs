#![cfg(not(debug_assertions))]
use intmax3_zkp::regev::{
    RegevSecurityLevel, channel_keygen, encrypt_amount, prove_channel_tx, verify_channel_tx,
};
use rand010::{SeedableRng, rngs::StdRng};
use std::time::Instant;

#[test]
fn time_regev_e1() {
    let mut rng = StdRng::seed_from_u64(1);
    let (spk, _) = channel_keygen(&mut rng);
    let (rpk, _) = channel_keygen(&mut rng);
    let before = encrypt_amount(&mut rng, &spk, 100).unwrap();
    let amount = encrypt_amount(&mut rng, &rpk, 30).unwrap();
    let after = encrypt_amount(&mut rng, &spk, 70).unwrap();

    let t = Instant::now();
    let (ct, w) = encrypt_amount(&mut rng, &spk, 42).unwrap();
    eprintln!("REGEV encrypt_amount: {:?}", t.elapsed());
    let _ = (ct, w);

    let t = Instant::now();
    let proof = prove_channel_tx(
        RegevSecurityLevel::Production,
        &spk,
        &rpk,
        (&before.0, &before.1),
        (&amount.0, &amount.1),
        (&after.0, &after.1),
    )
    .unwrap();
    eprintln!(
        "REGEV E-1 prove (Production, single-thread test): {:?}, {} bytes",
        t.elapsed(),
        proof.len()
    );

    let t = Instant::now();
    verify_channel_tx(
        RegevSecurityLevel::Production,
        &spk,
        &rpk,
        &before.0,
        &amount.0,
        &after.0,
        &proof,
    )
    .unwrap();
    eprintln!("REGEV E-1 verify (Production): {:?}", t.elapsed());
}
