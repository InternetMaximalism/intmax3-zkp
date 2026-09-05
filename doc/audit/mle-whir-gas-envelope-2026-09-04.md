# MLE/WHIR close path: 20,000,000-gas envelope at about 100-bit security (2026-09-04)

Supersedes the gas section of `mle-whir-pcs-repair-progress-handoff-2026-09-04.md`. Branch:
`codex/mle-whir-pcs-repair-20260904` (parent) with submodule branch
`codex/whir-leaf-consistency-20260830`.

## Decision

The target-133 / inverse-rate-4 profile that closed the constituent-batching forgery pushed the
cold Manager close transaction to about 29.4 M gas. The release owner set the design point at about
100-bit aggregate generic work and a 20 M-gas cold close transaction. plonky2 and MLE/WHIR proofs
are produced server-side only (`doc/docs/proving-boundaries.md`), so WHIR parameters are chosen
for gas and security, not for prover time.

## Profile

| Parameter | Retired (target-133) | Current |
|---|---:|---:|
| `whirSecurityLevel` | 133 | 105 |
| `whirPowBits` | 22 | 22 |
| `whirMaxStartingLogInvRate` | 4 | 6 |
| folding factor | 4 | 4 |
| dimension-21 sample schedule | `[58,33,23,18,14]` | `[29,19,14,12,10]` |
| native union work, dimension 21 | 2^-128.356 | 2^-101.535 |
| maximum internal PoW | 22.25 bits | 21.99 bits |
| WHIR NARG cap / hint cap | 2,032 / 180,408 B | 1,904 / 112,408 B |

`outer_soundness_budget.rs` pins the 101.534561723-bit union and keeps target 104
(100.674765149 bits) as the negative regression. The local conventional work factor is therefore
the WHIR union itself (about 101.5 bits), below generic 128-bit Keccak collision work; that is the
intended design point. The raw-oracle caveat is unchanged: the coarse bound loses `log2(H)` bits
(about 69.5 bits at `H = 2^32`).

## Verifier optimizations (submodule)

- `PackedClaimExt3`: one shared scratch buffer and an in-place Yul butterfly for the used-cell fold.
- `TranscriptV2`: vector absorbs write little-endian limbs straight into one keccak frame.
- `Plonky2GateEvaluatorExt3`: arithmetic, arithmetic-extension, mul-extension, base-sum,
  reducing and random-access gates evaluated in Yul with pointer-based limb helpers.
- `WhirLinearAlgebra.mleEvaluateUnivariateFrom`: base-field fast path.
- `SpongefishWhir._leModReduce64`: word-wise Yul reduction (`addmod(low, high * 2^32 mod p)`).

Max-row resource fixture (submodule `V2ResourceEnvelope`):

| Entry point | Execution | Intrinsic calldata | Upper bound |
|---|---:|---:|---:|
| `MleVerifierV2.verify` | 11,689,441 | 2,299,260 | 13,988,701 |
| `PinnedMleVerifierV2.verifyCompact` | 12,666,921 | 2,014,964 | 14,681,885 |
| compact PI return | 12,667,290 | 2,014,964 | 14,682,254 |
| compact fraud classifier | 12,724,559 | 2,015,092 | 14,739,651 |

Runtime sizes: `MleVerifierV2` 20,053 B, `PinnedMleVerifierV2` 12,570 B, `SpongefishWhirVerify`
23,656 B.

## Parent close path

Measured on the regenerated canonical partial-withdrawal proof (103 public inputs, compact proof
129,028 bytes):

| Measurement | Gas |
|---|---:|
| cold harness Manager `submitPartialWithdrawalIntent` execution (`ManagerCloseGas`) | 16,901,877 |
| transaction intrinsic calldata gas | 2,017,528 |
| cold harness total | 18,919,405 |
| real Anvil transaction (`partial_withdrawal_e2e`) | 18,919,366 |
| headroom under 20,000,000 | 1,080,595 |

Trajectory for the same statement, PI-return execution gas: 25.90 M (target-133 / rate-4) ->
21.17 M (target-105 / rate-6) -> 20.09 M (fold and transcript) -> 18.66 M (Yul gates) ->
16.90 M (`_leModReduce64`, univariate fast path). Calldata intrinsic gas fell from about 3.00 M to
2.06 M with the halved WHIR hint payload.

The repository gas gate is now 20,000,000 in all four places that encode it:
`contracts/test/ManagerCloseGas.t.sol`, `contracts/test/ClaimMleVerify.t.sol`,
`contracts/script/SubmitPartialWithdrawal.s.sol` and `tests/partial_withdrawal_e2e.rs` (Anvil block
gas limit). Proof-to-proof variance for this statement was a few thousand gas across the retired
profile's samples, so the roughly 968 k margin is expected to hold; a later verifier change must
re-run `ManagerCloseGasTest` and the Anvil E2E before it lands.

## Regeneration notes

- Size caps changed after some configs had been generated; every config embeds `compactShape`,
  so all 15 proof-free configs and all 16 full proofs were regenerated under the final profile.
- The Manager address printer (`test_printCloseManagerAddress`) skips unless all six close-family
  configs exist; generate `close_intent_mle_config.json` (`--mle-config-only`) before running it.
- MLE proving at inverse rate 6: about 80 s and 19-25 GB RSS per close-family proof on this host.

## Acceptance

All gates were run on this host after the final regeneration (2026-09-04):

| Gate | Result |
|---|---|
| submodule `cargo test -p plonky2_mle --all-targets` (debug) | pass (run on the committed submodule code; only README changed afterwards) |
| submodule `forge test --offline` | 347 tests, 27 suites, 0 failed, 0 skipped |
| parent `.github/ci/forge-test-guard.sh` | PASS, 578 tests across 45 suites, no skips |
| `ManagerCloseGasTest` (cold harness, 20 M gate) | 16,901,877 execution + 2,017,528 intrinsic |
| `partial_withdrawal_e2e` on Anvil with a 20 M block limit | submit used 18,919,366 gas, margin 1,080,634 |
| `mle_onchain_e2e`, `mle_v2_fixture_release` (release) | pass (release pins re-derived from the regenerated configs) |
| `cargo check --all-targets` | pass |
| `node` (`npm ci && npm test`) | 446 tests, 438 pass, 0 fail, 8 skipped |
| `V2FixtureCompletenessTest`, `forge build --sizes` (parent and submodule), `git diff --check`, `git submodule status` | pass |
| WASM packages (`hosting/build-wallet-wasm.sh`, `hosting/build-wallet-node-wasm.sh`) | built from the final source; `pkg/intmax3_zkp_bg.wasm` sha256 365851bc…a6b56, `pkg-node/intmax3_zkp_bg.wasm` sha256 5f30623e…2d390 (untracked outputs) |

Pins that had to follow the profile change outside the submodule: `tests/mle_v2_fixture_release.rs`
(per-statement config ABI keccaks and compact grammar maxima), `contracts/test/ProofDaCodec.t.sol` and
`contracts/test/BlobKzgPairing.t.sol` (tracked max-resource compact proof: 129,284 bytes, still two
blobs), `node/delegate/claim-settlement.js` and `hosting/wallet/wallet-live.html` (WHIR NARG/hint
caps, canonical packed-21 WHIR parameters digest and protocol id). The retired target-133 cutover
switch (`MLE_WHIR_133_CONFIG_CUTOVER`) was removed from `src/utils/mle_prover.rs`.

Release status is otherwise unchanged from the previous handoff: NO-GO for public value until the
protocol-specific Fiat-Shamir/grinding analysis, the external cryptographic review and the
operational blockers are closed. This work changes the local PCS design point to about 100 bits;
it does not close any of those items.
