# intmax3-zkp

Zero-knowledge proof circuits for INTMAX3, built with [Plonky2](https://github.com/0xPolygonZero/plonky2).

## Overview

intmax3-zkp implements the core ZKP circuits for the INTMAX3 rollup protocol:

- **Validity Proof** — proves that a sequence of blocks is valid, including account-tree updates verified against aggregated SPHINCS+ post-quantum signatures.
- **Balance Proof** — proves a user's private balance state across deposits, transfers and withdrawals.
- **Withdrawal Proof** — aggregates withdrawals for on-chain settlement.

### Post-Quantum Signature Integration

The validity circuit enforces [SPHINCS+](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) (SPX-128s Poseidon variant) signatures for account-tree updates. When a user has registered a public key (`pk_hash ≠ 0` in their `AccountLeaf`), each block that contains their transaction must carry a valid SPHINCS+ signature over the message:

```
M_i = [block_number ‖ aggregator_id ‖ local_id ‖ tx_tree_root]   (11 GL elements / 88 bytes)
```

Users whose `pk_hash` is still the zero default (unregistered) can still transact without a SPHINCS+ signature.

**SPHINCS+ parameters (SPX-128s Poseidon):**

| Parameter | Value |
|-----------|-------|
| Security level | 128-bit post-quantum |
| Hash | Poseidon (Goldilocks) |
| `N` (byte security) | 16 |
| Hypertree layers `D` | 7 |
| FORS trees `k` | 14, height `a`=12 |
| WOTS+ chain length | 35 |
| Signature size | 7 856 bytes |
| Public key size | 32 bytes |

## Requirements

- Rust nightly (`nightly-2025-03-23`, managed via `rust-toolchain.toml`)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (for WebAssembly builds and tests)

## Setup

### Install wasm-pack

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Or via Cargo:

```bash
cargo install wasm-pack
```

## Build

```bash
cargo build --release
```

## Test

### Native tests

```bash
cargo test --release
```

All 140 unit tests plus the end-to-end integration test pass in release mode.

### WASM tests

First, generate the test fixtures required by the WASM tests:

```bash
cargo run -r --bin generate_wasm_fixtures
```

Then run tests in a headless Firefox browser:

```bash
wasm-pack test --release --firefox --headless
```

You can also use `--chrome` or `--safari` instead of `--firefox`.

## Benchmark (release mode, Apple M-series)

Results from the `e2e_deposit_validity_withdrawal` integration test:

| Proof | Time |
|-------|------|
| Deposit balance proof | 1.16 s |
| Spend proof (internal transfer) | 0.28 s |
| Send-tx proof (internal transfer) | 1.14 s |
| Receive-transfer proof | 1.43 s |
| Spend proof (withdrawal) | 0.26 s |
| Send-tx proof (withdrawal) | 1.12 s |
| Single withdrawal proof | 1.50 s |
| Withdrawal chain proof | 2.68 s |
| Withdrawal final proof | 2.31 s |
| Block hash-chain proof (block 1) | 8.06 s |
| Block hash-chain proof (block 2) | 5.27 s |
| Block hash-chain proof (block 3) | 5.43 s |
| Validity proof | 2.28 s |
| **End-to-end total** | **≈ 83 s** |

> **Note:** The `BalanceProcessor` prover key serializes to ~508 MB. This is inherent to
> Plonky2's LDE-polynomial-based prover keys and does not affect proof sizes (a few KB each).

## Dependencies

| Crate | Purpose |
|-------|---------|
| [plonky2](https://github.com/0xPolygonZero/plonky2) | ZK proof system |
| [sphincsplus-circuits](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) | In-circuit SPHINCS+ verification |
| [sphincsplus-poseidon](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) | Native SPHINCS+ primitives |
