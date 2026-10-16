//! Phase-level profiler: prints `tracing` span durations for one prove call
//! so we can see where time actually goes.
//!
//! ```sh
//! cargo run --release --example profile            # transfer, batch 8
//! cargo run --release --example profile -- enc 32  # encryption, batch 32
//! ```

use std::time::Instant;

use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use regev_plonky3::*;
use tracing_subscriber::fmt::format::FmtSpan;

fn main() {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::CLOSE)
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let kind = args.get(1).map(|s| s.as_str()).unwrap_or("xfer");
    let batch: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
    let n = 1024;
    let params = RegevParams {
        n,
        eta: 2,
        plain_bits: 8,
    };
    let mut rng = SmallRng::seed_from_u64(0xabcd);
    let (pk, _sk) = keygen(&mut rng, &params);
    let config = default_config();

    match kind {
        "enc" => {
            let mut cts = Vec::new();
            let mut wits = Vec::new();
            for _ in 0..batch {
                let m: Vec<u8> = (0..n).map(|_| rng.random_range(0..=1)).collect();
                let (ct, w) = encrypt(&mut rng, &params, &pk, &m);
                cts.push(ct);
                wits.push(w);
            }
            let t = Instant::now();
            let _ = prove_encryptions(&config, &params, &pk, &cts, &wits);
            eprintln!("=== enc batch {batch}: {:?} ===", t.elapsed());
        }
        _ => {
            let mut ts = Vec::new();
            let mut ws = Vec::new();
            for k in 0..batch as u64 {
                let before = 1_000_000 + k * 999;
                let delta = 12_345 + k;
                let after = before - delta;
                let (cb, wb) = encrypt(&mut rng, &params, &pk, &encode_value_message(before, n));
                let (cd, wd) = encrypt(&mut rng, &params, &pk, &encode_value_message(delta, n));
                let (ca, wa) = encrypt(&mut rng, &params, &pk, &encode_value_message(after, n));
                ts.push(Transfer {
                    before: cb,
                    delta: cd,
                    after: ca,
                });
                ws.push(TransferWitness {
                    before: wb,
                    delta: wd,
                    after: wa,
                });
            }
            let t = Instant::now();
            let _ = prove_transfers(&config, &params, &pk, &ts, &ws);
            eprintln!("=== xfer batch {batch}: {:?} ===", t.elapsed());
        }
    }
}
