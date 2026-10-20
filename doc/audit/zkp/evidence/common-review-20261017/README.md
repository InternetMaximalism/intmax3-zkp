# Common review evidence — 2026-10-17

Run from the repository root. This evidence describes the existing working tree and its local dependency patches; see baseline.json and source-sha256.json. Product code was not changed by this audit.

```sh
/Users/andropov/.cargo/bin/cargo test --offline --release --locked --lib common:: -- --test-threads=1
/Users/andropov/.cargo/bin/cargo test --offline --release --locked --test u63_ordering -- --test-threads=1
CARGO_TARGET_DIR=/Users/andropov/repos/intmax3-zkp/target /Users/andropov/.cargo/bin/cargo run --offline --release --locked --manifest-path doc/audit/zkp/evidence/common-review-20261017/fixture/Cargo.toml
```

The U63 test executable was also run directly once it had been linked, while Cargo was still building incidental binary targets. That result is in u63-ordering-direct.log. The single test checks 144 comparison cases.

The fixture's default mode checks U63 serde invariants, Tx/TxV2/ChannelAction numeric decoding, ChannelClose decoding, PublicState padded root consistency using an ordinary verified circuit proof, and FullPublicState mutation on error. Assertions intentionally establish the existing defective behavior; passing this diagnostic is not a security pass.

The fixture's `withdrawal` argument separately exercises the panic-return boundary. Its nonzero exit is expected evidence of the defect. The subprocess log and return code distinguish that outcome from the normal fixture run.

The snapshot u63-at-head.rs.txt and patch u63-preexisting-working.patch distinguish the HEAD comparison defect from the pre-existing local repair. No HEAD rollback was performed.
