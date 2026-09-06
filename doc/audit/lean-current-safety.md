# Current design / Lean safety boundary — 2026-09-06

> **Implementation continuation:** the five-module / 219-theorem checkpoint below describes
> `acfaa78`. The subsequent source-oriented translation, exact line inventory and additional
> conditional theorems are tracked in
> [implementation-linewise-progress.md](./zkp/implementation-linewise-progress.md).
> Neither checkpoint certifies every implementation line or whole-system fund safety.

## Target, continuation and document precedence

Runtime source base: parent **`05ec7ae94701f05d2aaf97ff796b7f800a6ce1f8`**, including
node/pre-sign repairs `b5bafb7501c482f65c4db864c02ca411413e64a1`.
MLE submodule: **`6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78`** (wire v3,
target 105 / inverse-rate 6). The previous Lean work at `3e2d45c5` is integrated
and extended on `codex/design2-lean-safety-sync-20260906`; it is not replaced by a new,
disconnected proof project. This pass edits documentation, Lean and its CI guard, not runtime
code, proof parameters, proof formats or production circuit artifacts.

No tracked `design2*.md` exists at this snapshot. The corresponding existing design lineage is
[abstract2.md](../architecture-audit/abstract2.md),
[abstract2-1.md](../architecture-audit/abstract2-1.md),
[detail2.md](../architecture-audit/detail2.md) and
[detail2-implementation-notes.md](../architecture-audit/detail2-implementation-notes.md).
Their dated **current** sections now govern; the older hypothetical specification and D1–D16 /
§A–R engineering record remain explicitly historical. The old Lean models keep their original
meaning; compiling them does not promote their assumptions or retired features to current facts.

Exact reviewed source/spec/model/tooling bytes and the actual submodule gitlink are recorded in
[lean-current-source-manifest.json](./lean-current-source-manifest.json).
This is a manual implementation-alignment and conditional proof effort, **not** a complete
Rust/Solidity/JS/EVM refinement proof or deployment approval.

## Accepted trust model

All co-signers colluding to redistribute their own channel's funds is accepted by design.
Protection of an honest participant's rightful share relies on at least one honest sig-cluster
member validating transitions before signing. This does not authorize consuming another channel's
backing. A theorem about a correct caller, proof or durable store is not a proof those premises
always hold in production. KZG ceremony is accepted as a trust assumption, not a release blocker.

The exit requirement is H plus its retained matching kit: the latest available N-of-N signed
state must support exit without **another channel signature**. A public L1 transaction signer,
gas, usable proof/config material, canonical finalized backing and an accessible recipient are
still needed. Latest-H availability, timely challenge and eventual inclusion are not inferred
from a safety invariant. Close claims reveal recipient, token and amount on chain.

## What is machine-checked

The five independent current modules import only Lean's standard library. The results below
are proved from defined checks, transitions and explicit premises, not a state field that simply
asserts the desired invariant. Some small interface lemmas are deliberately definitional;
the stronger preservation results quantify over arbitrary finite traces. These slices are
**not yet composed into the entire protocol state machine**.

| Current module | Security properties / representative theorems | Main source boundary |
|---|---|---|
| [ChannelSafetyAdmission](../architecture-audit/ChannelSafetyAdmission.lean) | Changed-cell u64 safety from sound conservative bounds; authenticated per-token pooling; unchanged unknown cells need not halt unrelated updates; reserved capacity survives arbitrary admitted updates/imports; other-token frame | `channel_credit_safety.rs`, `channel_member.rs`, `deposit_capacity.rs`; preceding transition authentication remains an interface |
| [ChannelSafetyRecovery](../architecture-audit/ChannelSafetyRecovery.lean) | Durable raw transaction and intent binding, byte-identical automatic retries, terminal tombstones, safe pre-WAL abandonment, durable signature release/non-equivocation, exact before/after WAL roll-forward and idempotence | Deposit spend/outboxes, browser signature release, native signing and deposit/burn recovery |
| [ChannelSafetyExit](../architecture-audit/ChannelSafetyExit.lean) | Both burn high-water floors, same-coordinate identity, one whole final vector, inverse journal rollback, freeze/thaw generations, one-shot atomic vector credit and per-token escrow conservation | Manager, Materializer, Rollup |
| [ChannelSafetyCurrent](../architecture-audit/ChannelSafetyCurrent.lean) | Nullifier-scoped payout accounting and arbitrary-trace no-repeat payout; strict deadline, replacement and cancellation/request replay fences | Current Manager claim, pull and lifecycle projections |
| [CurrentVerification](./zkp/Zkp/Contracts/CurrentVerification.lean) | Exact compact-proof/DA provenance, authenticated public inputs, core-before-finalize, persistent finalized roots/heights, typed fraud verdicts | Pinned verifier interfaces and Rollup finalization/fraud |

### 1. Admission: amount safety without unnecessary global stops

`token_accounting_pool` derives an upper bound on changed balances from nonnegative per-token
accounting equations. `pooled_evidence_sound` and `accounted_changed_cell_is_u64` connect it to
the executable private-bound admission check. The premises include authenticated conservation,
unchanged-cell identity and the conservative allocation-release bound: these are not proved
by ciphertext shape alone. Known exact own-key openings are separate trusted local evidence.

Unknown evidence is `none`, not a zero balance. `unknown_unchanged_not_blocked`,
`known_bound_no_global_cap` and `owned_exact_admitted` demonstrate paths that avoid a blanket
channel stop or global u64 fund cap. An affected unknown cell may still be conservatively refused.
Mathematical fund amounts overapproximate U256; this range-only proof is not a proof of every
full-width fund arithmetic operation or of the separate 64-add noise budget.

`public_credit_preflight_safe` supplies the reservation gate; `reserve_from_public_preflight`
and `update_from_reserved_preflight` connect accepted capacity checks to transitions.
`capacity_trace_preserves` proves balance plus outstanding reserved amount never exceeds u64
for any cell over arbitrary modeled traces. Import converts reserved room to actual balance;
spending/signing alone does not release it. Alternative candidate slots each reserve the full
amount, conservatively. Exact intent/transaction WAL binding, cache provenance and persistence
remain refinement obligations.

On completion, the selected candidate receives the credit and unused candidates release only
their reserved room. `unused_release_requires_committed_exact_wal` and
`unused_release_blocked_before_completion` expose the exact committed-observation checks;
the new transition preserves all balances while decreasing only the corresponding pending amount.
The successful two-candidate example reaches the correct credited and unreserved result.
This sequential conservative projection does not prove the real multi-cell atomic WAL;
observation truth and exactly-once enumeration of unused candidates remain refinement premises.

### 2. Recovery: preserve spent intents, allow safe pre-spend restart

The outbox model distinguishes volatile signing from durable raw storage and broadcast.
`automatic_rebroadcast_is_byte_identical` and `broadcast_has_exact_durable_intent` hold across
arbitrary traces. A terminal request remains terminal after crash/retry and cannot broadcast again.

Initial intent reservations are **not** universally permanent: `resumeExact` can discard an
interrupted initial reservation with no durable raw record. The model includes that explicit
pre-WAL abandonment and a successful new-reservation example. Once raw bytes are recorded, their
intent is retained and the automatic path cannot silently create a different payment. Operator
fee replacement/fresh-nonce policy is outside this automatic exact-retry slice; EVM exactly-once
execution and honest finality are also outside it.

The signature ledger returns original saved bytes on an exact retry and refuses a conflicting
successor/purpose/plan. `released_signatures_cannot_equivocate` proves the release fence over
arbitrary traces, with signer/channel/predecessor identity modeled explicitly.
Native persistence is not complete merely when an in-memory signature exists; browser release
waits for strict IndexedDB transaction completion. Clearing or rolling back storage, reusing a
key in another profile, or bypassing the supplied worker is not covered.

`publication_trace_retains_recovery_until_outputs_durable`,
`recovery_finishes_exact_outputs`, `recovery_is_idempotent` and
`unrelated_head_cannot_be_overwritten_by_recovery` cover an already validated signed
before/after publication and its frozen output records. The recovery result has an actual
allowed write trace, not only an abstract output equation. Whole inter-channel two-phase commit
and every recovery validator/call site are not extracted into this model.

Durable-write assumptions require a supported filesystem honoring fsync/rename/directory sync,
strict IndexedDB, mutual exclusion and nonrollback. Some API directory-sync errors are tolerated
by `api/lib/cli.js`; that response alone cannot establish the model's durability premise.
No Lean theorem here proves an OS, browser, disk, RPC or finality service correct.

### 3. Exact whole-state close and channel-scoped history

`both_burn_floors_are_enforced` covers authorized and pending burn floors; equal epoch/version
requires the exact close identity. `same_coordinate_has_one_whole_vector` additionally needs
**composite authenticated state/statement binding**: close proof, IMCH/IMCS digest bindings,
canonical encodings and hash collision resistance on verified states. This is stronger than
IMCS collision resistance alone and remains an explicit premise.

`finalization_never_splices_components` transcribes copying one pending registry/vector.
Use B itself at an equal ordering key or a strictly newer whole admissible state; do not compute
per-token min/max from V and B. This small theorem is a specification of the copy, not proof
that compiled Solidity implements it. The separate admission and authenticated-binding lemmas
supply its conditions.

`descending_rollback_restores_journal` proves exact recovery of channel tips **and** predecessor
entries after arbitrarily many interleaved channel posts are rolled back in reverse order.
The source's fresh global post slots, rollback eligibility and finalized floor are environmental
preconditions, not an arbitrary reorg oracle proved honest. Exact-generation thaw, frozen/exited
post rejection and other-channel tip framing are modeled separately.

Materialization checks the bound Manager, closed state, matching frozen generation, nonzero
identity, current anchor, attested exact proof and full finalized vector. The backing root and
signed fund root may differ; both dependencies require their specified authentication.
`no_second_materialization_after_any_trace` preserves the exit latch through arbitrary context
changes, other-channel successes and failures. Per-token escrow debit/Manager credit conserve
amounts; other Manager credits and other channel exit markers are unchanged.

`atomic_failure_discards_partial_vector` specifies whole-transaction rollback even after a
partial vector was staged. It does not prove EVM rollback. Pooled escrow decreases on legitimate
other-channel exits, so **other channels' pooled escrow is not claimed invariant**. Authentic
economic ownership of the vector, proof soundness, trusted binding and correct finality are
required separately; a global escrow balance check alone does not prove cross-channel theft
impossible.

### 4. Manager payout accounting and replay fences

The payout slice fixes one registered Manager/channel/finalized configuration. Each record binds
nullifier, recipient, token and amount. Claim registration may precede backing pull; payment
needs both. Lifetime accepted claims, remaining credit, received backing and successful paid
amount are separate counters. `trace_caps`, `trace_token_conservation`,
`trace_recipient_conservation`, `trace_backing_conservation` and
`trace_payout_at_most_once` prove per-token/per-recipient accounting across arbitrary traces.

This update removes the obsolete terminal-funding authorization observation. Funding now observes
the exact materialized close identity plus exact balance delta. It does **not** require fresh N-of-N
terminal signatures. Supported token behavior, EVM revert/serialization and registered token
resolution are assumptions. Callback interleavings are not a proved bytecode semantics.

The lifecycle projection keeps the actual u64 generation/freeze checks, timestamp casts, strict
lexicographic replacement, cancel version floors and strictly-later finalization deadline.
`lifecycle_run_fences_monotone` and the `lifecycle_*_rejected_after_*trace` results prohibit
replay after intervening requests/cancels. Cancel restores the freeze nonce; it does not restore
the lifetime generation or consumed cancellation floor.

The projection deliberately permits more operations than the complete runtime: Materializer
freeze/thaw failures and both burn floors are separate Exit slices. Its successful traces are
not guaranteed-success Solidity calls. Freeze-counter rollover/timestamp assumptions, latest
head availability and the timely honest challenge remain separate obligations.

### 5. Compact verification/fraud provenance

CurrentVerification covers all seven statement purpose labels, including close backing, as fixed
profile interfaces. Successful finalization consumes the exact authenticated compact proof
bytes, obtains PI only after core acceptance and checks application state/preimage before adding
a finalized root at that submission's endpoint height. Newly finalized roots require pinned-core
acceptance; existing trusted genesis roots are distinguished.

A valid proof with wrong supplied PI is non-convicting. Exact proof-dependent invalidity can
support a proof-invalid verdict only with surrounding authentication/state guards. Wrong-chain,
configuration/unknown failure, evaluation failure or gas starvation is unevaluable, not proof
invalidity. Timeout removal/slashing is a **different policy**; not all slashing requires an
invalid cryptographic proof. Raw error-selector decoding and gas classification are interfaces,
not proved EVM parsers or resource bounds. Deployment-chain validation is outside this projection.

These theorems establish control-flow provenance, **not** that verifier acceptance implies an
actual satisfying witness, or that a KZG receipt establishes DA. No MLE/WHIR cryptographic
soundness, target105 security-bit count, recursive-circuit composition or trusted-VK authenticity
is newly proved here.

## Validation and drift protection

The following local checks passed on 2026-09-06 after integrating the five current modules and
reviewing all listed source changes:

| Check | Result |
|---|---|
| Pinned Lean 4.10.0 complete builds | **58 modules**: 12 architecture roots and 46 Zkp modules |
| Current named-theorem dependency audit | **219 theorems**: Current 68, Verification 35, Admission 44, Recovery 33, Exit 39; only the three standard logical axioms below |
| Reviewed source manifest | **72 file hashes**, actual `6cefc6ac` gitlink and clean submodule checkout; checked before and after building |
| Lean guard self-tests | **23 passed**, including missing/duplicate module coverage, omitted theorem, unsupported declaration syntax, source drift and forbidden dependency rejection |
| Current-document local links | **149 checked**, none missing |
| Runtime preservation / patch whitespace | No changes against `05ec7ae` in src, contracts, node, api, hosting, Cargo inputs or submodule link; `git diff --check` passed |

The manifest has no automatic refresh or skip mode. It must include
every named theorem in every current module; omission, duplicate module substitution, source
drift, wrong gitlink or forbidden transitive proof dependency fails closed.

The guard builds all architecture roots and the complete Zkp import root. It rejects explicit
`sorry`, `admit`, custom `axiom` and `native_decide`, resolves every named current theorem
through Lean, and permits only `propext`, `Classical.choice` and `Quot.sound` as transitive
logical axioms. **Explicit theorem parameters still are assumptions**, even with an empty
printed axiom list. Checksums detect drift; they do not prove semantic correspondence.
The named-theorem inventory supports the ordinary unqualified ASCII declarations used in these
five files and rejects unsupported name syntax. It is not a general parser of arbitrary Lean
macros or namespace-generated declarations; expanding that style requires guard review.

Independent cross-review corrected three modeling gaps before finalization: (1) labeling composite
whole-state binding as mere IMCS collision resistance; (2) falsely treating pre-WAL outbox
reservations as permanent; (3) omitting release of unused deposit candidate reservations.
The latter two now have explicit checked transitions and successful recovery examples. No runtime
vulnerability is inferred merely from these modeling corrections.

No production source, circuit/config/VK, wire format or submodule content is changed in this pass.
Consequently it adds no proving work, proof bytes or contract instructions. A new runtime
benchmark, full Rust/Solidity regression, remote CI or real-chain/browser acceptance run is
**not** claimed. The previous runtime integration checks remain separately dated in
[mle-node-safety-integration-2026-09-06.md](./mle-node-safety-integration-2026-09-06.md).

## Remaining obligations / handoff order

1. Independently review and progressively prove actual source-to-model refinement; compose
   admission, release, close/PW, materialization and claims across their complete operation
   universe. Special-close, historical late-proof/extra-credit and retired direct MSU models
   are not enabled features or current liveness evidence.
2. Complete ordinary PW automatic exact backing attestation and authoritative watcher
   required/unrelated/unresolved deposit classification, without skipping unresolved events.
3. Resolve the exposed WASM withdrawal-claim Plonky2/MLE producer versus the no-client-proving
   policy, preserving witness privacy. This documentation/proof task does not change that API.
4. Exercise real browser durability, native daemon, L1 posting/finality, latest-H kit production,
   multi-token exit/claim and interrupted recovery end to end. Include chain gas envelope,
   recipient access, supported token semantics, backup/nonrollback and operational performance.
5. Maintain exact deployment/config/VK/chain pins; review PCS/Fiat–Shamir/grinding, Regev/Falcon,
   recursion and full canonical statement binding independently. KZG ceremony stays accepted.
   No fixed parameter choice proves whole-system 128-bit security or release readiness.

The 2026-09-05 Lean report's full Solidity test counts and reported Rust migration issue belong
to that earlier snapshot. They are neither rerun results nor automatically open/closed findings
for this one. Preserve the earlier commit for that historical evidence.

Publication is separate: this task does not push or certify remote reachability. Before a later
parent push, ensure the runtime's existing `6cefc6ac` submodule commit is reachable on its intended
remote, then publish the parent integration branch. The local Lean guard does not substitute for
the CI pinned-input remote-reachability check.

## Reproduce

Use the pinned Lean 4.10.0 toolchain with `lake` on PATH and clean initialized submodules at
the recorded gitlinks, from this integrated worktree:

```sh
python3 -B .github/ci/test-lean-safety-guard.py
bash .github/ci/lean-safety-guard.sh
git diff --check
```

The theorem total includes helper lemmas and finite positive examples; it is not a security
score. Positive examples demonstrate some allowed progress under stated conditions, not
unconditional eventual exit. No theorem here is an external audit certificate.
