# Audit status — 2026-10-20

**Branch:** `claude/bold-hertz-0f2708` at `039e9e63` (identical tree on
`claude/abstract-detail-spec-audit-738841` at `861d44c5`; 28 commits ahead of `main` `0a2f5a28`).
**Scope of this note:** everything the audit sessions of 2026-10-15 … 2026-10-20 found, what was
fixed, what is measured, and what remains open. Every number below was measured on this branch in
those sessions; nothing is carried over from older reports without re-checking.

## 1. Findings and their state

| Source | Finding | State on `039e9e63` |
| --- | --- | --- |
| Spec audit (10-15) | F1 double draw of a burn before close | fixed `8acbe309` |
| Spec audit (10-15) | F2 | not a bug |
| Spec audit (10-15) | F3 stranded L1 deposit (two-head import) | fixed `9ef32e3c` |
| Spec audit (10-15) | F4 close on an unpostable head | liveness only; fallback `7f129334` |
| Circuit/contract pass 1 | C1 agg-list VD unbound, free tx index, sender order | fixed `f5f14ff4` |
| Circuit/contract pass 1 | C2 witnessed Regev fallback | fixed `5957f094` |
| Circuit/contract pass 1 | C3 fraud proof over the EIP-7825 cap, reporter paid from escrow | fixed `aa03f0c0` |
| Pass 3 (Mythos) | H1 post-close claim slot not bound to the receiver | fixed `60df5b5e` (58-limb statement) |
| Pass 3 (Mythos) | H2 `registerSettlementManager` / `_materialize` trust | fixed `3ef40ed8` + deploy-order rule `5f1946da` |
| Pass 3 (Mythos) | M1 delegate own-slot Regev digest | fixed `3fc6e5e9` |
| Crypto review (10-16) | C01 cyclic VK binding | fixed by C1 |
| Crypto review (10-16) | C02, C04 decrypt-before-verify, digest-before-validate | fixed `cb6cbe28` |
| Crypto review (10-16) | C03, C05, C06, C07 vendored Plonky3 boundaries | fixed `702c8c88` (N > 2 MMCS binding open, not instantiated) |
| Crypto review (10-16) | C08, C09, C10 BN128 decoding, zeroization | fixed `bd4fa490` |
| Crypto review (10-16) | RNG clone (salts = masks), ignored `eta` | fixed `36ebfac0`; NTT/DFT repairs `78f90a0a` |
| Pass 2 "B-series" | U63 modular wrap, fund identity, 65th credit, unsigned sub-block post | fixed `ff6ca4b4`, `fe3ecf8f` |
| Pass 2 "B-series" design items | delegate ceiling, EIP-7825 margin, one-tx truncation, late cursor stall | **open** (owner decisions) |
| Submodule HEAD review (10-16) | P2 STARVED misclassification | fixed submodule `7437d3d5` |
| Submodule HEAD review (10-16) | P2 `paper/mle_whir_v1_security.md` claims the 128-bit profile is current | **open** (docs) |
| Wallet-core review (10-18) | Medium: record/state counts, member `pk_g` binding, tree deserialization panic | fixed `717abffd` |
| Wallet-core review (10-18) | L1 import gate trusted the proposal's accumulator root | fixed `717abffd` |
| Wallet-core review (10-18) | Lows: zero-amount grief, 2^64 cell cap, duplicate signatures tolerated, small-block +1 unpinned, synthetic recipients in `withdraw` | **open**, documented in detail3 §2.8 |
| Follow-up reviews (10-17) | 13 records over `src/common`, `src/utils`, `src/ethereum_types` | all closed: COMMON-01 `ff6ca4b4`, the rest `717abffd` + `861d44c5` |

No finding in any of these reviews was an end-to-end production proof forgery or a demonstrated
fund-loss path; the Highs were binding gaps in statements and gates, the Mediums were
defence-in-depth and denial-of-service gaps.

## 2. Artefacts regenerated

The wire-v3 fixture cohort was regenerated on 2026-10-16 after the C1 / H1 / U63 circuit changes:
16 proof-free configurations, 16 full proofs, 18 companions (50 files; the `pw_close_intent` family
was retired because its producer left in `909658b1`). `cancel_close` and `withdrawal_claim`
configurations came back byte-identical; `post_close_claim` is 58 public inputs, `close_asset_backing`
35. The close family is generated against Manager `0xEfAea6aF473Aa1c3e87266D8C3D9B1C1e37258EB` /
Rollup `0xCD7a6A5FeE0C47eb768EA8cC991f2E87aAC32d20` (CREATE2 addresses of the test deployment, which
moved because the test base's initcodes were brought back in line with the constructors).

The 2026-10-16 cryptographic reviews, the 2026-10-16 submodule HEAD review and the 2026-10-17
follow-up reviews are checked in with their evidence directories under `doc/audit/docs/` and
`doc/audit/zkp/evidence/`.

## 3. Measured test state

| Gate | Result |
| --- | --- |
| `mle_v2_fixture_release` | 10 / 10 |
| `mle_onchain_e2e` | PASSED |
| `V2FixtureCompleteness` | 16 / 16 |
| `CloseLifecycleE2E` | 2 / 2 |
| CI forge guard (`.github/ci/forge-test-guard.sh`) | PASS, 614 tests / 53 suites, no skip |
| submodule `mle/contracts` forge suite | 395 / 395 |
| `ManagerCloseGas` (real 103-limb close proof) | 19,073,837 gas incl. intrinsic (< 20M, > 2^24) |
| Rust lib suite, one module per process, `--test-threads=1` | 804 / 804 (2026-10-19) + 11 new regressions and the modules touched on 2026-10-20 (common 87, utils 70, ethereum_types 47, services/publishers/circuits::validity/circuits::balance all green) |
| Production-level Regev proving / verification | 134.6–136.6 ms / 8.1–8.4 ms per tx (unchanged by the RNG and NTT changes) |
| wallet wasm (`hosting/build-wallet-wasm.sh`) | builds |

Operational lesson recorded: the whole lib suite in one process reaches 37 GB RSS and crashed the
48 GB machine; run it module by module.

## 4. Not verified on this branch

- Production-level end-to-end flows (`inter_channel_*` E2Es, browser UI on the testnet deployment).
- The testnet deployment itself still runs the pre-regeneration verifiers; redeploy per
  `doc/tasks/regen-and-redeploy-runbook.md` (settlement stack before the first deposit).
- The Lean source manifests: `.github/ci/lean-safety-guard.py` reports 60 of 497 files drifted (already
  drifted at the branch base); the submodule's `check-wire3.py` needs a Lean build for its last stage.
- The remaining lib modules after the 2026-10-20 decoder changes (wallet_core, channel circuits,
  falcon_sig, regev) were not re-run; they do not call the changed decoders.

## 5. Open items (design decisions)

1. EIP-7825: `submitCloseIntent`, `withdrawNative` and multi-block finalize exceed 2^24 gas on
   Fusaka chains.
2. Verifier delegate-count ceiling (owner decision 2026-09-29), one-transaction truncation,
   late-incoming cursor stall.
3. Zero-amount sends consume credit budget (64 force a refresh); no cap keeps a cell under 2^64
   base units.
4. N > 2 MMCS schedule binding in the vendored Merkle library (no production instantiation).
5. Documentation: the submodule's security addendum (128-bit profile), stale code comments listed
   in detail3 Appendix A, Lean manifests.
