# Integration record: MLE update and node safety remediation

Date: 2026-09-06.
Parent branch: `codex/node-presign-safety-20260905`.
Working location: `/private/tmp/intmax3-node-preflight-audit-20260905.m7xtV6/checkout`.
The integration described here is local only. No push, no deployment, and no L1 submission was performed.

## 1. What was pulled in

Checking the remote showed that the new MLE repair integration was
`origin/codex/main-mle-whir-repair-20260905`,
`ca5c8fc6a4d3bd40bc9616af0e62df82ff764a2f`, in
`InternetMaximalism/intmax-plonky2`.

However, it is not a direct descendant of `b569e0d7`, which the parent was already using.
It diverges from the common ancestor `5b1c28ae`, so a plain pin replacement would lose the
existing target-105 / inverse-rate-6 and the gas optimizations.
We therefore created a real merge inside the submodule that keeps both.

| Item | Commit |
| --- | --- |
| Base of the node remediation | `a2886fff08c2619ba47604e4d2fa5634b9e17471` |
| Commit that preserved the previous node remediation | `b5bafb7` |
| MLE pin before the update | `b569e0d71c6a7a180fe616915b7a76976540b155` |
| MLE update that was pulled in | `ca5c8fc6a4d3bd40bc9616af0e62df82ff764a2f` |
| MLE pin after integration | `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78` |

The branch on the MLE side is `codex/mle-node-safety-integration-20260906`.
The merge commit has both the pre-update pin and the pulled-in update as parents.
Neither the parent repository's `main` as a whole nor any other branch that reverts the earlier PCS repair was pulled in.

## 2. What was kept and what was changed

- The previous node remediation for pre-signing, pre-deposit, persistence, and recovery is kept as
  preserved in `b5bafb7`. Details are in `doc/audit/audit05-09-2026-node-presign-remediation.md`.
- The production wire format, the profile JSON, the generated Solidity constants, the v3 verifier,
  and the canonical v3 fixtures are identical to the existing optimized versions. The parent's
  proof/config/companion set was not regenerated either.
- As new changes, we integrated the `legacy-conformance` isolation of the old Rust API, making the old
  Solidity `MleVerifier` abstract, CI, and the historical Lean documents.
- The parent's `deprecated-msu` propagates `plonky2_mle/legacy-conformance` only for builds explicitly
  targeting the old fixtures. The old API and MSU are not enabled in the normal or WASM builds.
- The `.gitmodules` tracking target was corrected to the integration branch. What a release uses is
  always the parent's gitlink. Use `git submodule update --init --recursive`; do not move to the older,
  divergent line with `--remote`.
- Documentation conflicts were resolved by keeping the two histories distinct. The old transcript tests
  reference generated constants with the same values. We stated explicitly that the old Lean audit and
  the upstream Plonky2 audit must not be reread as a guarantee covering the whole of the current MLE/WHIR.

The original `/Users/andropov/repos/intmax3-zkp` checkout and its untracked audit documents were not modified.
The exported source copies that were in the dedicated working tree were replaced with real Git working trees at the same pin.
The old copies are preserved as `polygon-plonky2-b569-export-backup` and
`forge-std-export-backup` inside the dedicated temporary directory. The forge-std dependency pin was not changed.

## 3. Verification results

Rust was checked with the pinned nightly `nightly-2025-03-23` and `--locked --offline`;
Solidity with `0.8.29` / via-IR / optimizer 200 / Prague.

| Check | Result |
| --- | --- |
| Compilation of all parent Rust targets plus the 4 current fixture-generation features | succeeded |
| Compilation of the WASM library | succeeded |
| MLE normal-build old-API isolation doctests | 4/4 |
| Drift check of the MLE v3 schema and the WHIR profile | 3/3 |
| Old-schema check of the explicit legacy build | 1/1 |
| Fresh proof generation on a small happy-path circuit, plus native/JSON/compact/ABI/config roundtrip | 1/1 |
| Solidity tests for MLE legacy-artifact isolation and the frozen transcript | 5/5 |
| The parent's existing happy-path proof, public-input, and gas checks | 32/32 |
| The parent's release fixture consistency (existing cohort/config/proof/companion) | 9/9 of those selected, 0 failures |
| Size check of the production Solidity | succeeded |

The parent's 32 consist of 17 fixture-coverage, 5 happy-path claim verification, 3 happy-path compact
verification, 6 public-input-return gas, and 1 Manager close gas.
Of the 10 Rust fixture tests in `mle_v2_fixture_release`, we selected the 9 that check the consistency
of the existing artifacts. The 1 helper test that mutates inputs was outside this selection.
The gas a test reports as a whole also includes fixture loading and setup, so it must not be confused
with the gas of a real transaction.

The measured cold Manager close with the current fixture is
execution `16,963,263` + intrinsic calldata `2,060,788` = **`19,024,051` gas**.
That leaves `975,949` gas of headroom against the 20,000,000 limit. The compact proof is `131,716` bytes.
This is a local-harness measurement with this fixture, not a direct comparison against measurements
taken with a different fixture in the past.

The main runtime sizes are `MleVerifierV2` 20,053 B, `PinnedMleVerifierV2` 12,570 B, and
`SpongefishWhirVerify` 23,656 B, the same as the existing record.
`ChannelSettlementManager` is 24,398 B, 178 B below the EIP-170 limit.
No comparative proving-time benchmark was run. The production proof-generation algorithm and
configuration were kept, but we do not claim to have measured that performance is unchanged in every
execution environment.

The pre-existing unused / dead-code / Solidity lint and similar warnings remain.
This round of checking verifies integration compatibility; it is not a new comprehensive vulnerability
audit or an attack reproduction.

## 4. Next steps and sharing order

1. If pushing, push the MLE-side `codex/mle-node-safety-integration-20260906` first and confirm that
   `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78` can be fetched from the remote.
   Then push the parent's `codex/node-presign-safety-20260905`.
   Sharing the parent alone first leaves it referencing a submodule commit that cannot be fetched.
2. In another environment, fetch the parent's pinned gitlink and rebuild native and WASM.
   Do not delete existing state, signing history, deposit reservations, the outbox, or exit kits merely
   because of this merge.
3. Continue the work outstanding since last time: automatic wiring of the exact backing attestation for
   the normal PW path, deposit classification by the watcher using finalized history, and
   production-equivalent E2E through browser/daemon/chain.
   This integration alone does not make any of these complete.
4. For a production rollout, follow the existing `doc/tasks/regen-and-redeploy-runbook.md` and
   cross-check the circuit/config/profile/runtime hashes against the actual deployment targets.
   Since there is no format change to the existing fixtures in scope here, no blanket regeneration or
   redeployment was performed during the merge work.
5. The independent MLE review and the remaining release gates are to be handled within the scope defined
   by the submodule's `mle/README.md` and `mle/audit/node-safety-integration-2026-09-06.md`.

The trust in the KZG ceremony, the off-chain checking by at least one honest signer,
the acceptance of collusion by all signers within one's own channel, and the policy of retiring MSU are unchanged.
