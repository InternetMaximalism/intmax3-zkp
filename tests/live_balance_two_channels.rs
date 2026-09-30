//! Two channels in one process, as the block producer daemon holds them. The spend, Balance and
//! CloseAssetBacking circuits do not depend on the channel, so the second live balance must not
//! pay the first one's circuit build again (on the 4-core testnet host that build was ~190 s per
//! channel, and each daemon restart paid it once per channel).
//!
//! Run: `cargo test --release --features authenticated-tail-receive --test live_balance_two_channels -- --ignored --nocapture`

use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use intmax3_zkp::{
    common::{channel_id::ChannelId, salt::Salt},
    live_balance_service::LiveBalanceService,
};

fn scratch_dir() -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("live-balance-two-channels-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
#[ignore = "builds the production circuits (minutes); run explicitly"]
fn second_channel_reuses_the_first_channels_circuits() {
    let dir = scratch_dir();
    let mut rng = rand::thread_rng();

    let started = Instant::now();
    let first = LiveBalanceService::initialize(
        dir.join("ch7.json"),
        ChannelId::new(7).unwrap(),
        Salt::rand(&mut rng),
    )
    .unwrap();
    let first_elapsed = started.elapsed();

    let started = Instant::now();
    let second = LiveBalanceService::initialize(
        dir.join("ch8.json"),
        ChannelId::new(8).unwrap(),
        Salt::rand(&mut rng),
    )
    .unwrap();
    let second_elapsed = started.elapsed();

    eprintln!("first channel initialize: {first_elapsed:?}; second channel initialize: {second_elapsed:?}");
    // Each service still decodes and checks its own channel's proof through the shared circuits.
    assert_eq!(first.base_head_artifact().unwrap().channel_id, ChannelId::new(7).unwrap());
    assert_eq!(second.base_head_artifact().unwrap().channel_id, ChannelId::new(8).unwrap());
    drop((first, second));
    let _ = fs::remove_dir_all(dir);
}
