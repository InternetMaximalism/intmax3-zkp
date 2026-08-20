# Resident validity prover benchmark — 2026-08-20

Command:

```text
/usr/bin/time -lp cargo test --release --test validity_prover_service --locked -- --nocapture
```

Host: Apple M5 Max, 48 GiB RAM, Darwin arm64. The test uses a two-member production channel,
persists a first candidate, restarts and verifies it, L1-acknowledges it, then proves an independent
second one-block span while extending the genesis-rooted Falcon aggregate-list proof.

## Second-span measurements

| Item | Measurement |
|---|---:|
| Resident circuit construction | 35.804 s |
| Total second-span proving | 14.990 s |
| Block-hash-chain proof | 4.490 s / 134,136 bytes / 164 PIs |
| Falcon aggregate-list append | 7.777 s / 146,964 bytes / 76 PIs |
| Final validity wrapper | 2.722 s / 159,396 bytes / 8 PIs |
| Process peak RSS | **12,055,429,120 bytes (11.23 GiB)** |

The focused test itself took 107.52 s after compilation because it deliberately constructs the
resident circuits twice (initial process plus restart), proves two independent spans and verifies
all persisted recursive proofs on recovery. The full command took 261.35 s including an LTO release
rebuild.

## Shipping assessment

Proof sizes are modest (roughly 131–156 KiB each), and the steady resident service removes the
35.8-second circuit-build penalty from each span. The **11.23 GiB peak RSS is operationally large**:
the testnet prover host should have at least 16 GiB available to this process, and 24 GiB is the
safer floor when the producer and live-balance services share the daemon. This is not a correctness
blocker, but it is the largest measured capacity risk in this path. The Falcon aggregate-list stage
is also the dominant second-span latency (52% of proving time); replacing Falcon with the retired
signature scheme is not recommended because the cumulative proof is now cached and only one new
event is appended per span.
