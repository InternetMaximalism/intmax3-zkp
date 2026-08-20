# Settlement proving benchmark — 2026-08-19

Release-mode measurements after adding state-finalization Falcon aggregation, persistent circuit
contexts, withdrawal-claim profiling, and the IMSW binary slim wire.

Environment: Apple M5 Max, 48 GiB RAM, macOS/Darwin 25.6.0, rustc
`1.87.0-nightly (b48576b4d 2025-03-22)`, Forge 1.5.1. Times are wall-clock and should not be used as
cross-machine performance guarantees.

## Falcon aggregate arity

Command: `cargo test --release --locked --test falcon_arity_bench -- --nocapture`

| Slots | Gates | Degree | Build | Prove | Verify | Proof |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 8,084 | 2^13 | 0.594 s | 0.686 s | 5.696 ms | 133,680 B |
| 4 | 16,157 | 2^14 | 1.141 s | 1.210 s | 5.874 ms | 147,212 B |
| 8 | 32,303 | 2^15 | 2.131 s | 2.544 s | 8.136 ms | 153,548 B |
| 16 | 64,597 | 2^16 | 4.416 s | 5.548 s | 9.764 ms | 159,948 B |

The production fixed-16 artifact benchmark measured build 4.883 s, prove 5.213 s, full cached
artifact validation 18.998 ms, serialized artifact 160,262 B, and inner proof 159,948 B. The cache
therefore removes roughly five seconds from each close/PW/cancel critical path after state
finalization. It does not make the first aggregation free.

In the subsequent full-library run, after the fixed circuit had been warmed, the same artifact path
measured build 2.177 s, prove 2.553 s, and full cached validation 11.855 ms. Native Falcon measured
342.1 ms key generation, 7.721 ms per signature, and 0.078 ms per verification in that run. These
measurements confirm that the earlier regression was dominated by circuit construction and the old
standalone/recursive verification route, rather than Falcon signing itself.

Decision: keep one fixed-16 settlement VK for now. Arity-specific VKs materially reduce finalization
latency for small channels, but they also require downstream close/cancel VK variants and contract
routing. Reconsider them if finalization latency, rather than close latency, becomes a user-visible
problem.

## Withdrawal claim

Command: release happy-path circuit benchmark and
`cargo test --release --locked --lib a3_withdrawal_claim_prover_builds_and_verifies -- --nocapture`.

| Metric | Result |
|---|---:|
| Gates before padding | 886,927 |
| Degree | 2^20 |
| Circuit build | 140.951 s |
| Prove | 132.848 s |
| Verify | 165.700 ms |
| Inner proof | 197,664 B |
| End-to-end high-level prover test | 298.04 s |

Cumulative gate profile: inputs 171; header/selectors 209; Regev digests 730; slot inclusion 754;
decryption 886,927; nullifier 886,927. The direct two-product Regev decryption adds about 886,173
gates and dominates the circuit. The redundant external E-3 proof was removed from witness
construction, saving roughly 223 KiB of transient proof material, but the final circuit still
proves decryption directly and remains the primary performance blocker. An O(n log n) relation or
recursive verification of the E-3 STARK is required for a large improvement.

The proof-identity Schwartz-Zippel bound at `REGEV_N = 2048` is approximately 2^-113, not the old
n=128 estimate of 2^-117. This is tracked as an explicit soundness-target decision before testnet.

## Slim send wire

Command: `cargo test --release --locked --test slim_verify_bench -- --nocapture`.

| Metric | JSON | IMSW v1 binary |
|---|---:|---:|
| Payload size | about 1.46 MiB | about 0.40 MiB (27.7%) |
| Encode/serialize | 1.993 ms | 0.355 ms |
| Decode/parse | 4.656 ms | 0.935 ms |

The browser-to-relay route now streams binary directly to a spool file. Legacy slim JSON remains a
rolling-upgrade input, but malformed IMSW input never falls back to JSON.

## Integrated-path observations

`partial_withdrawal_e2e` completed in 190.21 s. Its close portion measured circuit construction
14.082 s, Falcon aggregation+witness 4.947 s, close proof 17.495 s / 169,372 B, and wrap+MLE+self
verify 5.678 s / 210,416 B JSON. The payout deliberately remained fail-closed because
`cmd_partial_withdraw` and live base-IVC persistence are still absent.

The ignored two-token CLI/Anvil lifecycle completed in 757.31 s and paid both the native and ERC-20
lanes with conservation checks. During its ordinary `channel_member withdraw` step, process
inspection observed about 10.6 GB RSS (10,621,536 KiB reported by `ps`) before the Forge broadcast
stage. Treat this as a testnet capacity warning even though the lifecycle passed.

The native deposit/validity/withdrawal proof pipeline completed in 257.69 s. It reported a
1,991 MB `BalanceProcessor`; deposit 6.594 s; internal/withdrawal spend 0.551/0.641 s; send-tx
6.096/6.171 s; receive-transfer 6.433 s; withdrawal single/chain/final
2.884/5.058/4.369 s; four block-hash-chain steps 6.843–12.159 s; and final validity 4.433 s.
This roughly 2 GB warm component must be included in persistent-prover capacity planning.

Inter-channel release guards also passed without skips: deposit-backed E2E 2/2 (119.28 s), unified
E2E 1/1 (206.67 s), live positive/negative coverage 3/3 (8.55 s), and real two-channel CLI coverage
15/15 (32.77 s).

Solidity: guarded Foundry run passed 316 tests across 21 suites with zero skipped tests.
`forge build --sizes` reported runtime sizes: IntmaxRollup 23,468 B (1,108 B EIP-170 margin),
ChannelSettlementVerifier 22,575 B (2,001 B margin), and ChannelSettlementManager 18,537 B (6,039 B
margin). IntmaxRollup's remaining margin warrants a size regression gate.

## Full-library stress run

`cargo test --release --locked --lib -- --test-threads=1` completed 540/540 tests with zero failures,
zero ignored tests, and a wall time of 4,852.31 s. The 40-case Regev decryption property/oracle test
alone occupied about 36 minutes. Process inspection observed an approximately 31.7 GB RSS high-water
mark during that accumulated single-process test run; this is not the memory cost of one production
claim, but it does show that retaining every warmed proving component indefinitely is unsafe on a
small host. A production prover should use an explicit circuit-retention budget and isolate or evict
the withdrawal-claim context.
