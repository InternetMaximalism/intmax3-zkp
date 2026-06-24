//! Diagnostic: verify a wasm-generated E-1 SendPayload natively. Skips if the repro files are
//! absent. Tells us whether a wasm-produced proof verifies under the native verifier (portability).
#![cfg(not(debug_assertions))]

use std::path::Path;

use intmax3_zkp::{
    ethereum_types::bytes32::Bytes32,
    regev::{RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberInfo, MemberKeys, SendPayload, add_signature,
        assemble_genesis_state, build_record, build_send, default_settled_tx_accumulator,
        sign_state, verify_send_transition,
    },
};
use rand010::{SeedableRng, rngs::StdRng};

/// B-5a: this is a MANUAL repro diagnostic, not a CI test. It needs `/tmp/repro/*` artifacts from a
/// prior wasm proving run. It used to `return;` (vacuous green) when those files were absent, so it
/// passed in every normal CI run WITHOUT verifying anything. It is now `#[ignore]` (excluded from
/// the default run) AND fails loudly if invoked without the artifacts — so a green result always
/// means a wasm-generated proof was actually verified natively. Run explicitly with:
///   cargo test --release --test verify_wasm_proof native_verifies_wasm_e1_proof -- --ignored
#[test]
#[ignore = "manual repro diagnostic: requires /tmp/repro/{payload1,channel_snapshot}.json; run with --ignored"]
fn native_verifies_wasm_e1_proof() {
    let payload_path = "/tmp/repro/payload1.json";
    let snap_path = "/tmp/repro/channel_snapshot.json";
    if !Path::new(payload_path).exists() || !Path::new(snap_path).exists() {
        panic!(
            "repro artifacts absent ({payload_path}, {snap_path}). This ignored diagnostic must be \
             run only after a wasm proving run produced them — refusing to pass vacuously."
        );
    }
    let payload: SendPayload =
        serde_json::from_str(&std::fs::read_to_string(payload_path).unwrap()).unwrap();
    let snapshot: ChannelSnapshot =
        serde_json::from_str(&std::fs::read_to_string(snap_path).unwrap()).unwrap();
    let res = verify_send_transition(
        &snapshot.state,
        &snapshot.record,
        &payload,
        RegevSecurityLevel::Production,
        None,
        None,
    );
    eprintln!("native verify of wasm-generated E-1 proof: {res:?}");
    res.expect("native verification of a wasm-generated E-1 proof");
}

fn member_info(slot: u8, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

/// DECISIVE: build a send NATIVELY, round-trip the payload + snapshot through JSON (exactly the
/// browser↔CLI transport), then verify NATIVELY. If this PASSES, the JSON transport + statement
/// rebuild are sound, so the wasm-proof failure is genuinely in the proof bytes (cross-target
/// arithmetic). If it FAILS, the test harness/transport is the culprit, not the prover.
#[test]
fn native_json_roundtrip_verifies() {
    let mut rng = StdRng::seed_from_u64(0xABCDEF);
    let m0 = MemberKeys::generate(&mut rng);
    let m1 = MemberKeys::generate(&mut rng);
    let members = vec![member_info(0, &m0), member_info(1, &m1)];
    let record = build_record(5, &members, 0, 0).unwrap();
    let (bal0, bal1) = (50u64, 30u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).unwrap();
    let (ct1, _w1) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).unwrap();
    let digests = [
        Bytes32::from(m0.regev_pk.poseidon_digest()),
        Bytes32::from(m1.regev_pk.poseidon_digest()),
    ];
    let mut genesis = assemble_genesis_state(&record, &[ct0, ct1], &digests, bal0 + bal1).unwrap();
    let g0 = sign_state(&m0, 0, &genesis).expect("sign g0");
    add_signature(&mut genesis, g0);
    let g1 = sign_state(&m1, 1, &genesis).expect("sign g1");
    add_signature(&mut genesis, g1);
    let snapshot = ChannelSnapshot {
        record,
        state: genesis,
        members,
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };

    let nonce = Bytes32::default();
    let BuiltSend { payload, .. } = build_send(
        &m0,
        &snapshot,
        0,
        1,
        7,
        bal0,
        &w0,
        nonce,
        RegevSecurityLevel::Production,
        &mut rng,
    )
    .unwrap();

    // In-memory verify (control).
    verify_send_transition(
        &snapshot.state,
        &snapshot.record,
        &payload,
        RegevSecurityLevel::Production,
        None,
        None,
    )
    .expect("in-memory native verify");

    // JSON round-trip BOTH the snapshot and the payload (same path as browser↔CLI), then verify.
    let snap_json = serde_json::to_string(&snapshot).unwrap();
    let payload_json = serde_json::to_string(&payload).unwrap();
    let snapshot2: ChannelSnapshot = serde_json::from_str(&snap_json).unwrap();
    let payload2: SendPayload = serde_json::from_str(&payload_json).unwrap();
    let res = verify_send_transition(
        &snapshot2.state,
        &snapshot2.record,
        &payload2,
        RegevSecurityLevel::Production,
        None,
        None,
    );
    eprintln!("native verify after JSON round-trip: {res:?}");
    res.expect("native verify of a JSON-round-tripped native proof");
}
