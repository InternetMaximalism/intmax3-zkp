# INTMAX3 final security-closure audit (2026-08-30)

> **Release verdict: NO-GO.** This report supersedes the release conclusions in
> `audit30-08-2026-integrated.md`. It records the exact state reached after merging the independent
> Opus audit, three attacker/defender rounds, and a final independent review. It is not a claim that
> the production protocol is ready.

## Executive decision

The requested protocol seams were either repaired or made fail-closed:

- proof DA now authenticates the exact canonical `abi.encode(MleProof)` bytes across one or two
  EIP-4844 blobs;
- malformed/invalid proof verdicts, evaluator failures, and gas starvation are distinct, so an
  unevaluable proof cannot falsely convict an honest submission;
- the Node watcher is finalized-head and block-hash aware, persists its checkpoint atomically, and
  enters a sticky safety halt on canonicality violations;
- member-set updates are disabled at every production entry point rather than pretending that the
  Manager and validity-tree updates are atomic;
- close metadata and cancel identity are canonical and version-monotone;
- delegate close/claim completion is bound to authenticated participant membership and the exact
  Manager payout event, rather than any global rollup withdrawal event.

The final independent red team nevertheless found a new **Critical** MLE soundness break. The WHIR
PCS commits only a random-linear combination of each oracle group, while the batching scalar is
known before the corresponding root. Terminal equations consume separately claimed constituent
evaluations. A prover can move those evaluations in the batching kernel and preserve both the PCS
opening and terminal equations. This affects validity, close, cancel and withdrawal statements.

The real `MleVerifier` now pins a non-zero execution chain in its constructor. Deployment requires
the configured chain id to equal the current chain, and `verify` plus `fraudVerdictEncoded` repeat
the immutable check at runtime. Official scripts default the pin to `31337`; selecting another
chain through `MLE_VERIFIER_CHAIN_ID` is an explicit unsafe opt-in, not a PCS repair or release
approval. A wrong-chain failure remains distinct from `InvalidMleProof`, so the fraud path treats
it as unevaluable and cannot slash an honest submission. Independently, the rollup's zero-degree
test bypass and value-moving entry points remain limited to `31337`; short-window Managers and
development mock verifiers retain their fixed runtime checks. Thus merely configuring the verifier
for a public chain does not enable audited Rollup value flow, and development state cannot become
payable after a chain-id migration. This is operational containment, not a cryptographic repair,
and it does not retroactively protect a legacy deployment or a rollup deliberately wired to a
different verifier.

Two independent exit-liveness blockers also remain:

1. `ClosePending -> CloseSubmitted` still needs a durable public balance attestation and a local
   close-proof producer. A hostile coordinator can withhold the required proof material.
2. A finalized close does not create rollup credit for its Manager. `pullChannelFunds` can transfer
   only an already-existing `pendingWithdrawals[manager]`; the repository has no production
   live-state full-withdrawal producer that creates this backing.

Therefore no public deployment, production validity finalization, production settlement proof, or
claim of autonomous close-to-L1 exit is approved by this audit.

## Scope and provenance

| Item | Audited state |
|---|---|
| Upstream `main` | `492c80346153e46fee34041471dca5fa323ef6b4` |
| Requested source branch | `claude/live-balance-validity-finalize-b73981`, same `492c803` |
| Integration base | `e431deb6f3d0f7ac0358d7ce5618aa5686a8df60` |
| Final working branch | `codex/final-security-closure-20260830` |
| Parent commit | The commit containing this report; recorded in the handoff output |
| MLE submodule commit | Recorded after the submodule-first commit in the handoff output |
| KZG ceremony | **Owner-accepted trust assumption; not a blocker in this report** |

The audit covered every changed Solidity and MLE/WHIR verifier file, the channel close/cancel/
withdrawal circuits and public-input layouts, production CLI/service gates, watcher/journal state,
delegate exit code, deployment scripts, and the prior audit claims. The Lean corpus was built, but
it explicitly models MLE/WHIR internals as uninterpreted and is stale relative to this tree; a green
Lean build is not evidence against the Critical PCS finding.

## Final disposition matrix

| Area | Disposition | Evidence / exact limitation |
|---|---|---|
| KZG trusted setup | **ACCEPTED ASSUMPTION** | Per owner instruction, the Ethereum ceremony is trusted. No release block is assigned to ceremony scale or participants. |
| Proof-DA binding/codec | **FIXED locally; public E2E unavailable** | Lossless SimpleCoder reconstruction for one/two blobs; exact blob count/order, proof hash/length, root, block and submission id are domain-bound; standard point-evaluation precompile evidence is journaled before finalize/fraud. There is no public-chain post -> attest -> finalize release evidence while Rollup value boundaries and the full-withdrawal CLI remain 31337-only. |
| Invalid-proof fraud verdict | **FIXED as a classifier; public release unavailable** | Only canonical decode failure or `InvalidMleProof()` is proof-invalid. OOG, unsupported/config errors, wrong-chain use and unknown reverts are UNEVALUABLE/STARVED. Configuring the verifier for a public chain does not make its PCS sound. |
| MLE/WHIR PCS soundness | **CRITICAL; chain-pinned containment only, redesign open** | Constituent evals are not committed before batching. The verifier has an immutable deploy-time chain pin and official scripts default it to 31337, but an operator can explicitly select another chain. Such selection is unsafe and does not change the NO-GO verdict. |
| Reorg-aware head/watcher | **FIXED** | Finalized tag required off-devnet; durable cursor includes block hash/parent; logs and head are revalidated before/after processing; replacement/removal/malformed history causes sticky halt. |
| MSU atomicity | **SAFE BY DISABLE** | Manager entry always reverts, producer/service paths reject, and validity circuit constrains the update target to zero. Cross-layer atomic MSU is not implemented. |
| Close-intent authorization (M-9) | **FIXED for metadata/cancel replay only** | `closeNonce = freezeNonce + 1`, snapshot block and burn hash are canonical zero; cancel digest binds channel/final-state/freeze nonce; revived version is strictly newer and lifetime replay floor is enforced. The zero sentinels do not authenticate a burn, live withdrawal or Manager funding. |
| Delegate participant close | **FIXED locally** | Immutable depth-10 participant root/count binds slot, pkG and recipient; a delegate can freeze via membership proof without coordinator signature. The audited Rollup value path remains 31337-only while PCS soundness is unresolved. |
| Delegate claim/payout completion | **FIXED locally** | Claim is self-proved with the session Regev secret and submitted directly; `EXIT_DONE` requires the exact finalized Manager `WithdrawalClaimed` event, accepted claim, tx hash, recipient, token and amount for every claim. Browser/live public-chain claim E2E was not run and operational delegate/recipient keys are required. |
| Delegate close-proof availability | **OPEN / NO-GO** | Unilateral freeze exists, but no independently recoverable public balance attestation/local close prover guarantees progression to a submitted close. |
| Production full withdrawal | **OPEN, fail-closed** | Public CLI release gate allows only 31337 because the builder creates a fresh demo history rather than importing the live finalized/pending chains. |
| Rollup -> Manager backing | **OPEN / NO-GO** | Close finalization does not mint/credit backing. `pullChannelFunds` only pulls pre-existing rollup credit. Paying from global escrow without a channel-bound proof would introduce a drain. |
| Post-close claim | **DISABLED** | Unconditionally reverting surface; not advertised as available. |
| EIP-170 | **PASS with dangerously low margin** | `IntmaxRollup` runtime 24,514 B (62 B margin), `ChannelSettlementVerifier` 23,888 B (688 B), Manager 22,976 B (1,600 B), and `MleVerifier` 19,387 B (5,189 B). Only test-only `BlockHashHarness` exceeded the limit, by 82 B. Any production source change requires a repeat size gate. |

## Critical PCS finding and concrete exploit

The proof contains both WHIR-bound batched evaluations (`*WhirEval`) and prover-supplied individual
evaluations used by gate/logUp terminal checks. The verifier checks that individual values sum to a
claimed `*EvalValue`, but does not bind that value or its decomposition to the WHIR-opened
polynomial. More fundamentally, the witness, inverse-helper and auxiliary batching scalars are
available before their roots. The usual Schwartz-Zippel batching argument therefore does not apply:
the alleged constituent polynomials were never fixed before the challenge.

The independent attacker produced a three-field mutation of the checked-in validity fixture that
changes no root, WHIR transcript/hints, sumcheck proof, public input or claimed batch value:

| Field | Before | After |
|---|---:|---:|
| `witnessIndividualEvalsAtRInv[0]` | 8093513556413711660 | 8093513556413711661 |
| `witnessIndividualEvalsAtRInv[80]` | 2800508231593448274 | 15862999140234155880 |
| `inverseHelpersEvalsAtRInv[1]` | 17516173920822186472 | 6112368312529039975 |

Before and after, the witness batch is `12944411284857403794` and the `_invInner` result is
`580551468794229723`. Index 80 is outside the `numRoutedWires = 80` terminal loop, so it cancels the
batch delta; the inverse-helper change cancels the terminal delta. The same construction was
calculated for the submodule `small_mul.json` fixture and is frozen in the immutable-chain-pin
regression.

Merely reversing the WHIR point order or comparing Ext3 `c0` with the base-field batch does not fix
this attack: the mutation intentionally preserves the batch. A sound redesign must commit the
constituent oracle polynomials before sampling their batching coefficients, or use an equivalent
vector commitment/opening argument that binds every terminal value. Until then, the constructor pin
is only an operational wrong-network boundary; official scripts default to 31337 and any public
selection is explicitly outside this audit's release approval.

## Three attacker/defender rounds

### Round 1 — proof DA and fraud-state attacks

The attack side exercised proof substitution, non-canonical ABI, malformed transcript/hints,
gas-starvation, unsupported gates, false-returning verifiers, stale submission reuse, and one/two
blob boundary/order mutations. The defense added exact raw-proof attestation, domain-separated
submission identity, canonical decoding and a five-way verdict (`INVALID`, `VALID`, `UNEVALUABLE`,
`STARVED`, `PI_MISMATCH`). Only the reserved invalid-proof selector can convict; unknown execution
failures cannot move bonds or roll back state.

### Round 2 — channel lifecycle and exit attacks

The attack side exercised unsigned close metadata variants, cancel replay, stale close replacement,
response-window blackout, burn/close ordering, non-atomic MSU, delegate-count drift, false
`EXIT_DONE`, reorged receipts and cross-token/cross-recipient payout substitutions. The defense
canonicalized M-9 metadata, bound cancel identity and monotone versions, preserved a response tail,
disabled MSU, authenticated the participant tree, made watcher state canonical-hash aware, and
required exact Manager payout evidence before exit completion.

The canonical `burnTxHash = 0` and `snapshotMediumBlockNumber = 0` values are sentinels that remove
unauthenticated metadata degrees of freedom. They are not evidence that a burn occurred, that a
live withdrawal was produced, or that the Manager received channel-scoped backing.

### Round 3 — independent proof-system break and release containment

The independent attack side rejected the prior audit's PCS-bound claims and produced the correlated
three-field acceptance mutation above. The defense did not relabel a partial check as sound. It
added an immutable constructor-selected execution-chain pin, kept the official default and the
rollup's zero-VK/value-flow boundaries at 31337, reserved a non-convicting unavailability result,
and added wrong-chain tests for valid, malformed and correlated-forgery inputs. The final
frozen-diff bypass review found no remaining path
in the audited deployment scripts, development mock verifiers, short-window Manager mutations, or
rollup value boundaries that could turn 31337-prepared state into public-chain value movement. The
cryptographic redesign remains an explicit blocker.

## Lightning-derived checks

The channel review used the following failure classes as protocol requirements, not analogies:

- [BOLT #5](https://github.com/lightning/bolts/blob/master/05-onchain.md): a close is safe only if
  the honest party retains the exact enforceable artifact, watches the canonical chain, and has a
  usable response/confirmation window. This drove durable snapshots, finalized-head validation,
  reorg halt behavior and replacement-window tests.
- [BOLT #2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md): state advancement is
  sequenced, not a bag of independently valid messages. This drove canonical close identity,
  strict revived versions, replay floors and the refusal to call two independent MSU updates atomic.
- [Flood & Loot](https://arxiv.org/abs/2006.08513): timeout designs must account for congestion and
  adversarial timing. This drove the bounded replacement ladder and non-zero response tail, but it
  also reinforces why withheld close-proof material remains a release blocker.
- [lnd reorg disclosure](https://delvingbitcoin.org/t/disclosure-lnd-doesnt-wait-for-enough-confirmations-when-closing-channels/2800): a mined event is not durable completion. This drove finalized-head use, block-hash pairing and post-read canonicality checks.

## Verification evidence

The completed final frozen-tree matrix was:

| Check | Result |
|---|---|
| Parent Forge, all suites/invariants | 503 / 503 pass |
| MLE submodule Forge | 109 / 109 pass |
| Node tests, unrestricted localhost rerun | 335 / 335 pass |
| Rust `cargo check --all-targets` | pass (existing warnings) |
| Lean `lake build` | pass; model staleness/uninterpreted-MLE caveat applies |
| Native withdrawal-claim prove/self-verify | 1 / 1 pass |
| WASM native + wasm32 + wasm-threads checks | pass |
| Node CommonJS WASM build/load smoke | pass |
| Root and submodule `git diff --check` | pass |

`cargo fmt --all -- --check` is not green: it reports repository-wide formatting drift, including
unchanged baseline files. No bulk formatter was run because that would mix unrelated changes into
the security commit.

## Required work before changing NO-GO

1. Redesign the MLE PCS so every terminal constituent evaluation is committed before its batching
   challenge (or is bound by an equivalent sound vector-opening argument); add the correlated
   mutation and a fully synthesized arbitrary-statement proof as negative E2E tests.
2. Do not configure the verifier for a public chain or relax the Rollup's 31337-only value boundary
   until an independent cryptographic review of the new transcript order, commitment format, Rust
   verifier and Solidity verifier. Redeploy the audited verifier and pin/verify deployed bytecode;
   the constructor chain pin does not repair legacy or substituted verifier deployments.
3. Build close proofs from durable authenticated public balance data without coordinator
   availability, and test restart/reorg recovery from `ClosePending` through payout.
4. Implement a channel-bound production live-withdrawal producer that creates the exact rollup
   credit consumed by the Manager; do not source claims from unscoped global escrow.
5. Complete browser/live public-chain delegate claim E2E with production key custody, restart and
   reorg recovery; development fixtures and local secrets are not release evidence.
6. Keep MSU disabled until one proof/receipt atomically advances both the Manager member set and the
   validity-tree member set.
7. Repeat the complete clean-clone matrix, regenerate and hash every VK/fixture, verify deployed
   runtime bytecode and EIP-170 margins, and record reachable remote parent/submodule commits.
