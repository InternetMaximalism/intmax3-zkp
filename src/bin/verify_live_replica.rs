//! Opens a standby replica of a channel's private base state (producer journal + sealed live
//! snapshot, as api/lib/live-replica.js stores it) with the daemon's own `open()` paths, which
//! run the full checks: journal hash chain and replay, Balance proof verification, private
//! commitment equality, nonce cursor, N-of-N pinned head, exit-kit backing proof and exact
//! producer-receipt reconciliation. Prints the live status JSON on success; exits non-zero with
//! the failure on stderr otherwise. Read-only apart from the daemon's own lock files.
//!
//! usage: verify_live_replica JOURNAL_JSON BALANCE_SNAPSHOT [SUPPORTED_USER_COUNTS=2,4,8,16]
use intmax3_zkp::{block_producer_service::BlockProducerService, live_balance_service::LiveBalanceService};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("usage: verify_live_replica JOURNAL_JSON BALANCE_SNAPSHOT [SUPPORTED_USER_COUNTS]");
        std::process::exit(2);
    }
    let counts: Vec<u32> = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("2,4,8,16")
        .split(',')
        .map(|t| t.trim().parse::<u32>().unwrap_or_else(|e| {
            eprintln!("bad supported user count {t:?}: {e}");
            std::process::exit(2);
        }))
        .collect();
    let producer = match BlockProducerService::open(&args[1], &counts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("replica journal {} does not open [{}]: {e}", args[1], e.code());
            std::process::exit(1);
        }
    };
    let live = match LiveBalanceService::open(&args[2], &producer) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("replica live snapshot {} does not open: {e}", args[2]);
            std::process::exit(1);
        }
    };
    match live.status() {
        Ok(status) => println!("{}", serde_json::to_string(&status).expect("status serializes")),
        Err(e) => {
            eprintln!("replica live status failed: {e}");
            std::process::exit(1);
        }
    }
}
