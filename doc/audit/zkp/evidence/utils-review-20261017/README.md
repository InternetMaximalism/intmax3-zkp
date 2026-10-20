# Utilities review evidence — 2026-10-17

Run from the repository root with the existing local dependency patches. See baseline.json for commit/toolchain context and source-sha256.json for every reviewed utility file.

```sh
/Users/andropov/.cargo/bin/cargo test --offline --release --locked --lib utils:: -- --test-threads=1
/Users/andropov/.cargo/bin/cargo test --offline --release --locked --test mle_gate_support -- --test-threads=1
CARGO_TARGET_DIR=/Users/andropov/repos/intmax3-zkp/target /Users/andropov/.cargo/bin/cargo run --offline --release --locked --manifest-path doc/audit/zkp/evidence/utils-review-20261017/fixture/Cargo.toml
```

The first test suite passed. The second failed 12 of 18 checks because it expects legacy top-level fixture fields; mle-validation-context.json records the current wire-v3 schema and the Ext3 source gate IDs. Do not interpret that suite as passing.

The fixture's default mode asserts the observed defective behavior for index bounds, sparse-tree commitments, indexed-tree deserialization, and Poseidon representation canonicality. It verifies one ordinary small circuit proof exposing canonical field values. No production invalid proof is constructed or submitted.

Separate arguments `incremental_decode`, `snapshot_decode`, and `chain_end_decode` exercise bounded malformed inputs and intentionally hit assertions. Each was run in its own subprocess with core dumps disabled. The logs and panic-results.json record SIGABRT (-6). These diagnostic assertions will need to be inverted/updated after remediation; their current success is not a security pass.

All 30 utility source files and the root Cargo.toml/Cargo.lock were rechecked as unchanged. Product code and prior audit reports were not edited.
