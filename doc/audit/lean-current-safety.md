# Current implementation / Lean safety boundary — 2026-09-05

## Target and document precedence

This update is based on parent `c533e710a2d8787624fe429fceee70cdbe000221` and its actual
`contracts/lib/polygon-plonky2` gitlink `b569e0d71c6a7a180fe616915b7a76976540b155` (wire v3).
It does not certify the submodule's unrelated legacy `main` or a different checkout.
The reviewed source bytes, model bytes, specification bytes, and checks are recorded in
[`lean-current-source-manifest.json`](./lean-current-source-manifest.json).

There is no tracked `design2*` file in this target. The design lineage used here is
[`abstract2.md`](../architecture-audit/abstract2.md),
[`abstract2-1.md`](../architecture-audit/abstract2-1.md), and
[`detail2.md`](../architecture-audit/detail2.md), including the explicitly superseding sections
and implementation notes. `abstract2-1` takes precedence for its block/bulk structure; later
implementation dispositions in `detail2` and this dated boundary take precedence over historical
capability and release claims. File suffix or filesystem modification time alone is not precedence.

This is a deliberately bounded implementation-alignment pass: protect finalized anchors and actual
fund release first. It is **not** a wholesale re-verification of all circuit, wallet, signature,
encryption, PCS, or contract semantics.

## Machine-checked scope

### 1. Current compact verification and finalization

[`Zkp/Contracts/CurrentVerification.lean`](./zkp/Zkp/Contracts/CurrentVerification.lean) is the
current verification-boundary model. The previous `degreeBits == 0`/`allowMleDisabled` model is
historical, not a branch of this new model.

The model follows the current dependency order: the fixed verifier consumes the same compact
proof bytes authenticated by the DA journal; public inputs are returned only after core acceptance;
application-state and explicit VPI-preimage checks must pass before the submission is finalized.
The endpoint height belongs to that submission, not merely to another batch with the same root.
The trace result distinguishes initial trusted roots from newly finalized roots.

The proof establishes control-flow provenance. It does **not** prove that a successful native or
Solidity WHIR verifier has a satisfying circuit witness, nor that a KZG journal entry proves DA.
Those are separate cryptographic/interface obligations. Fixed parameters are not approval of a
maliciously deployed verifier or VK.

The principal results are `newly_finalized_requires_pinned_core`,
`finalize_authenticated_pi_are_u32`, `run_height_nondecreasing`, and
`run_finalized_roots_persist`. The new-root theorem needs only that the particular root was not
initially finalized; other trusted genesis roots may already exist. The PI result checks eight
full values, each below `2^32`, not equality after masking caller-supplied high bits.

### 2. Fraud classification without treating evaluation failure as invalidity

The current compact classifier has materially different outcomes:

| Observation | On-time fraud consequence |
|---|---|
| Core accepts and authenticated PI matches | No proof-invalid conviction |
| Core accepts but caller's PI preimage differs | No proof-invalid conviction |
| Exact proof-dependent decoder/core invalidity | Eligible for proof-invalid conviction only after the surrounding authentication/state checks |
| Wrong chain, configuration/unknown failure, evaluation failure | Unevaluable, not proof-invalid conviction |
| Insufficient gas / starvation | Non-convicting evaluation failure |

The order matters: `compactFraudVerdictBody` calculates PI equality, but runs the core before
returning `VALID` or `PI_MISMATCH`. An invalid proof is not protected by supplying the wrong
preimage. A timeout removal is a **separate** policy: the current contract can slash/remove an
unfinalized expired submission without obtaining an `INVALID` result. A theorem saying “all
slashing requires cryptographic invalidity” would be false for this implementation.

The principal results are `verifyFraud_conviction_requires_attested_invalid`,
`compact_invalid_requires_exact_failure`, `valid_proof_wrong_pi_is_nonconvicting`, and
`proof_removal_requires_typed_conviction`. The raw four-byte revert-selector decoder and gas
observation are interface boundaries, not proved EVM parsers or gas-cost theorems.

### 3. Nullifier-scoped, per-token channel payouts

[`ChannelSafetyCurrent.lean`](../architecture-audit/ChannelSafetyCurrent.lean) models one
Manager instance with its channel and finalized configuration fixed. It follows the current
`submitWithdrawalClaim` → `claimWithdrawalCredit(bytes32)` path and exact-cap backing pull.
The payout key fixes recipient, base token, and amount. Claiming one record subtracts exactly its
amount from the aggregate; it does not erase or merge other payouts to the same recipient.
Claim registration need not wait for backing pull; successful payment needs both. The trace model
allows these orders rather than imposing a stronger honest-workflow ordering on all callers.

The important quantities are separated: lifetime accepted claims (`totalWithdrawn`), live credit,
actual recognized backing (`receivedChannelFunds`), and successful paid amount (`totalCreditedOut`).
The proved accounting invariants are per base token, not a sum of incomparable currencies. Conservation is
over the modeled backing and payout events, not the contract's entire balance including donations.
The fixed-channel scope is not a proof about arbitrarily shared or maliciously configured Managers.

Proof acceptance, terminal authorization observations, registered token resolution, and external
transfer observations remain explicit interfaces. EVM all-or-nothing revert and non-reentrant
execution are modeling assumptions; Lean does not prove EVM bytecode execution or arbitrary ERC-20
behavior. There is no unconditional exit-liveness result: fresh terminal proof/signature availability,
inclusion, gas, and a supported transferable asset are required.

The principal results are `trace_caps`, `trace_token_conservation`,
`trace_recipient_conservation`, `trace_backing_conservation`, and `trace_payout_at_most_once`.
These quantify over arbitrary traces of the specified transitions, not merely one immediate retry.
The positive two-record example includes a failed payment and demonstrates that paying one record
leaves the other recipient credit and payout record intact. `submitWithdrawalClaim` itself is
not `nonReentrant`; callback interleavings involving registration and their serialization into this
atomic model require a separate EVM refinement argument.

### 4. Current close replay fences and strict finalization deadline

The second, independent slice of `ChannelSafetyCurrent` transcribes the current
`requestClose`/participant request, first/replacement `submitCloseIntent`, `cancelClose`,
and `finalizeCloseGuarded` control flow. It uses checked 64-bit generation/freeze counters and
preserves the explicit modulo-`2^64` timestamp casts in Solidity. Replacement uses strict
lexicographic `(epoch, version)` ordering; cancel uses the two actual strict **version** checks,
not a newly invented epoch ordering, and has no deadline restriction.

The replay fences are the lifetime request generation and cancelled-version floor. Cancel
restores the freeze nonce, so a theorem claiming that nonce never decreases would be wrong.
Guarded finalization binds the expected pending digest and request generation, and requires
strictly later than the pending deadline. A complete cancel/request cycle cannot make the old
generation valid again; consumed cancellation versions cannot be reused after later interleavings.

The principal results are `lifecycle_run_fences_monotone`,
`lifecycle_cancel_replay_rejected_after_trace`,
`lifecycle_old_request_rejected_after_cancel_trace`,
`lifecycle_old_finalize_rejected_after_new_request_trace`,
`lifecycle_finalize_rejects_deadline_equality`, and
`lifecycle_finalized_state_unchanged_after_trace`. The last result means that after successful
finalization this **projected lifecycle** stays closed under all of its request/submit/cancel/finalize
operations; it does not freeze withdrawal accounting or characterize every EVM call.

This slice includes the first-intent grace period and the actual clamped response-tail deadline
formula. It does not prove that the globally latest honest state is available, signed, or submitted
before the deadline. The final cap calculation, partial-withdrawal high-water adjustment and external
token-funds digest call are represented by an explicit successful-tail observation, not silently
assumed always to succeed. The lifecycle slice and the finalized accounting slice are **not yet
composed** into a proof of the complete Manager/Rollup state machine.

### Reviewed source correspondence

These are the principal manually reviewed function boundaries at the pinned source snapshot;
the manifest includes the complete source files, not only these excerpts.

| Current implementation | Lean definitions | Main safety obligation |
|---|---|---|
| `PinnedMleVerifierV2.verifyCompactPublicInputs`; `IntmaxRollup.fullVerify` / `finalize` | `CurrentVerification.verifyCompactPublicInputs`, `fullVerify`, `finalize`, `run` | DA/proof-byte provenance, exact authenticated PI, persistent finalized anchors |
| `PinnedMleVerifierV2.fraudVerdictCompact` / `compactFraudVerdictBody`; Rollup fraud classification | `CurrentVerification.compactVerdict`, `verifyFraud`, `fraudProof` | Exact typed invalidity versus unevaluable result; separate timeout policy |
| Manager `submitWithdrawalClaim`, `_pullChannelFunds`, `claimWithdrawalCredit(bytes32)` | `ChannelSafetyCurrent.Step`, `Trace` | Per-token bounds, conservation, exact-record payout, permanent nullifier consumption |
| Manager `_requestClose`, `submitCloseIntent`, `_storePendingClose`, `cancelClose`, `finalizeCloseGuarded`, `_isNewer` | `ChannelSafetyCurrent.lifecycleRequest`, `lifecycleSubmit`, `lifecycleStore`, `lifecycleCancel`, `lifecycleFinalize`, `lifecycleRun` | Request/cancel replay fences, strict replacement order, strict finalization deadline |

## Alignment corrections and historical material

The original corpora remain useful but are not silently relabeled as current:

- `ChannelSafety2` / `ChannelSafety21`: frozen abstract accounting/signature models; their finite
  three-member representation is not the current eight-cosigner / larger balance-slot implementation.
- `ChannelSafetyQ`: a historical direct-MSU prototype. `detail2` §Q and production retired it on
  2026-09-02. Its positive rotation/join theorems are not evidence of a supported current feature.
- `ChannelSafetyClose` / `ChannelSafetyPW`: historical simplified lifecycle models, not a complete
  translation of current freshness comparisons, freeze-nonce updates, terminal funding, and
  partial-withdrawal/close high-water accounting. Specifically, the old close model increments
  nonce on cancel and permits deadline equality; current Manager increments on request, decrements
  on cancel, uses `closeRequestGeneration`/`highestCancelledRevivedStateVersion` replay fences,
  and requires `now > challengeDeadline`. The new replay-fence slice models these current rules;
  the old positive theorems cannot be reused as its proofs. The old PW model's cancel-as-fund-restoration is likewise not the
  current burn/high-water transition.
- The legacy implementation-model `Assumptions`, `IntmaxRollupWithdraw`, `EndToEnd`, and Manager
  models include removed `claimAuthorizedWithdrawal`, the old zero-degree bypass, or aggregate
  claim semantics. Their theorems stay attached to those definitions. The new modules do not import
  these models or reuse their acceptance assumptions as current facts.
- Special close, late-outgoing correction, post-close extra-credit claims, and direct MSU are not
  activated by a formal proof. Their current rejection/absence is preserved.

The documentary descriptions of exit and privacy must also match the interface: a current close
claim exposes its `amount`, recipient, and token in calldata. Encryption while operating a channel
does not imply hidden holdings after an on-chain claim.

## What the implementation correspondence check does — and does not do

The Lean CI guard builds **all** architecture roots and the entire `Zkp` import root. Previously a
bare architecture `lake build` selected only `ChannelSafety21` and its imports, leaving the independent
MT/Q/Close/PW/IC roots unchecked despite the CI label. The updated default-target list removes this gap.

The guard checks the manifest's source/spec/model hashes and actual submodule gitlink/checkout,
then asks Lean to resolve each named theorem and print its proof dependencies. The new proofs may
depend on Lean's standard logical axioms (`propext`, `Classical.choice`, `Quot.sound`), not `sorryAx`
or custom cryptographic axioms. Explicit theorem parameters and operational observations are still
assumptions even when this axiom list is empty. An empty checklist is an error, not success.

**Hash equality is a drift alarm, not semantic refinement.** The source-to-model translation has
been manually reviewed against the pinned functions. Neither a source checksum nor a passing
Solidity regression suite proves the Lean transition is equivalent to all executions of compiled
Rust/Solidity. An independent refinement review remains necessary, especially when broadening the
modeled operation universe. Changes require updating the model/spec and reviewed manifest together;
blindly refreshing hashes defeats this control.

## Remaining security and release obligations

1. Prove/review the PCS/Fiat–Shamir/grinding and recursive-circuit composition. Current target105
   WHIR parameters have a repository-model estimate of about 101.5 bits, not a Lean proof of
   128-bit end-to-end security. This update does not change or certify that budget.
2. Compose the new close replay-fence and finalized accounting slices, then extend to the complete
   close/partial-withdrawal transition universe and independently review actual code-to-model
   refinement. The `finalizePartialWithdrawal`/`_finalizeClose` high-water checks and the
   cross-contract Materializer/Rollup funding provenance are not discharged here. Nor does the
   burn snapshot capture every later outgoing transfer: source comments at Manager 1660–1664
   explicitly retain the challenge/watchtower dependency. Accounting caps alone do not establish
   every party's rightful share in a stale close.
3. Check deployment provenance: exact runtime/library code, circuit/config/VK, role, chain, and
   trusted setup/DA interfaces. The fixed-verifier model assumes the configured instance is the
   intended one.
4. Preserve release containment. Gas reachability, proof availability, real token behavior,
   transaction inclusion, and recovery from unavailable signers are not consequences of accounting
   safety. In particular the existing 25M fraud-classifier floor needs its own chain gas envelope.
5. The separate parent `mle_gate_support` migration failure reported by the 2026-09-05 audit is
   not repaired or waived by a successful Lean build. No release-wide all-green assertion follows.

No theorem in this update is an external audit certificate or authorization to deploy.

## Local validation result

The checks below passed on 2026-09-05 in the isolated parent worktree on
`codex/lean-current-safety-20260905`. No Rust/Solidity implementation or submodule gitlink was
changed by this update. The existing user checkouts were left untouched, and no push was performed.

| Check | Result |
|---|---|
| Pinned Lean 4.10.0 builds | All 55 modules: 9 architecture modules and 46 `Zkp` modules |
| Current theorem dependency audit | All 103 named theorems: 36 payout, 32 close-lifecycle, 35 verification/fraud; only the three allowed standard logical axioms |
| Reviewed-source manifest | All 43 source hashes and actual `b569e0d7` gitlink/clean checkout verified before and after the build |
| Lean guard self-tests | 19 passed; includes empty/omitted theorem lists, drift and malformed/forbidden dependency output rejection |
| Existing parent Solidity regression guard (`--offline`) | 578 tests across 45 suites passed, zero skipped; required-suite/fixture guard passed |
| Workflow/shell syntax and patch whitespace | Passed |

The theorem count includes helper lemmas and ordinary non-vacuity examples; it is not a security
score. Remote GitHub Actions was not run. A new full Rust regression run was not performed, and
the previously reported `mle_gate_support` failure remains an open release issue. Successful
existing tests do not establish that there are no other soundness defects.

## Reproduce the checks

Use the repository's pinned Lean 4.10.0 toolchain (with `lake` on `PATH`) and initialized, clean
submodules at the recorded gitlinks. The source-hash manifest is checked before and after building.

```sh
python3 -B .github/ci/test-lean-safety-guard.py
bash .github/ci/lean-safety-guard.sh
FORGE_TEST_ARGS=--offline .github/ci/forge-test-guard.sh
git diff --check
```

The guard has no skip/refresh option. A new theorem must be listed in the manifest, and a changed
source hash requires a correspondence review. Ordinary positive examples are model non-vacuity
checks, not freshly generated cryptographic proofs. Existing Solidity tests check the actual
implementation separately; neither kind of test is substituted for the other.
