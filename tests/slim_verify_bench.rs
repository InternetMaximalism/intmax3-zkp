//! Timing breakdown of ONE slim-tx verification at PRODUCTION level — where do the
//! ~0.14 s/tx of the 1000-batch verification go? (enc_balances is always the full padded
//! 1024-slot array, so the state-hash cost here matches a 1016-member channel.)
//! Run: cargo test --release --test slim_verify_bench -- --nocapture
#![cfg(not(debug_assertions))]

use std::time::Instant;

use intmax3_zkp::{
    ethereum_types::bytes32::Bytes32,
    regev::{RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        build_record, build_send, default_settled_tx_accumulator, sign_state, solo_next_state,
        verify_slim_send_tx,
    },
};
use rand010::{SeedableRng, rngs::StdRng};

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;

fn member_info(slot: u16, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

#[test]
fn slim_verify_timing_breakdown() {
    let mut rng = StdRng::seed_from_u64(0xBE9C4);
    let m0 = MemberKeys::generate(&mut rng);
    let m1 = MemberKeys::generate(&mut rng);
    let members = vec![member_info(0, &m0), member_info(1, &m1)];
    let record = build_record(7, &members, 0, 0).expect("record");
    let (bal0, bal1) = (50u64, 30u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).expect("enc0");
    let (ct1, _) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).expect("enc1");
    let digests: Vec<Bytes32> = [&m0, &m1]
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let recipients: Vec<_> = (0..2u32)
        .map(|i| {
            use intmax3_zkp::ethereum_types::u32limb_trait::U32LimbTrait as _;
            intmax3_zkp::ethereum_types::address::Address::from_u32_slice(&[0x7E57 + i; 5]).unwrap()
        })
        .collect();
    let mut genesis =
        assemble_genesis_state(&record, &[ct0, ct1], &digests, &recipients, bal0 + bal1)
            .expect("genesis");
    for (slot, keys) in [(0u8, &m0), (1u8, &m1)] {
        let sig = sign_state(keys, slot, &genesis).expect("sign");
        add_signature(&mut genesis, sig);
    }
    let snapshot = ChannelSnapshot {
        record,
        state: genesis,
        members,
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };

    // 1) proof GENERATION (sender side)
    let t = Instant::now();
    let BuiltSend { payload, .. } = build_send(
        &m0, &snapshot, 0, 1, 5, bal0, &w0, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("build_send");
    let t_gen = t.elapsed();

    let slim = payload.to_slim();

    // 2) serde: slim JSON size + parse cost (what the CLI pays per manifest file)
    let t = Instant::now();
    let json = serde_json::to_string(&slim).expect("ser");
    let t_ser = t.elapsed();
    let t = Instant::now();
    let slim2: intmax3_zkp::wallet_core::SlimSendPayload =
        serde_json::from_str(&json).expect("de");
    let t_de = t.elapsed();

    // 3) solo next-state reconstruction (1024-slot clone + full-state digest)
    let t = Instant::now();
    let _ns = solo_next_state(
        &snapshot.state,
        slim2.sender_index,
        slim2.recipient_index,
        &slim2.after_ct,
        &slim2.channel_tx.enc_amount,
    )
    .expect("solo_next_state");
    let t_next = t.elapsed();

    // 4) full slim verification (includes 3 again + A11 + E-1 STARK verify + witness checks)
    let t = Instant::now();
    verify_slim_send_tx(
        &snapshot.state,
        &snapshot.record,
        &snapshot.members,
        &slim2,
        LEVEL,
        None,
        None,
    )
    .expect("verify");
    let t_verify = t.elapsed();

    println!("== slim tx timing (Production level, padded 1024-slot state) ==");
    println!("proof generation (build_send): {:?}", t_gen);
    println!("slim JSON size: {:.2} MB", json.len() as f64 / 1e6);
    println!("serde serialize: {:?}   parse: {:?}", t_ser, t_de);
    println!("solo_next_state (1024-slot clone + full digest): {:?}", t_next);
    println!("verify_slim_send_tx TOTAL: {:?}", t_verify);
    println!(
        "  -> of which next-state rebuild ~{:?}, rest (A11 + E-1 STARK verify + witness checks) ~{:?}",
        t_next,
        t_verify.saturating_sub(t_next)
    );
}
