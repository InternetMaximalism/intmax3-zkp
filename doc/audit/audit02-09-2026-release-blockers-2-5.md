# Release blockers 2–5 security closure audit (2026-09-02)

> **Release verdict: NO-GO.** This branch implements and hardens the requested blocker 2–5
> plumbing, but it does not repair the separately owned MLE/WHIR PCS soundness defect, does not yet
> provide a signer-independent terminal exit kit for the latest accepted head, and has not been
> exercised as a real public-chain browser-to-payout deployment. “Implemented locally” below is
> therefore not a production-release approval.

## Scope and provenance

| Item | Audited state |
|---|---|
| Upstream `main` at integration start | `492c80346153e46fee34041471dca5fa323ef6b4` |
| Requested source branch | `claude/live-balance-validity-finalize-b73981`, the same `492c803` |
| Security-closure parent | `5f50d03` |
| Working branch | `codex/release-blockers-2-5-20260831` |
| Parent MLE submodule recorded by this branch | `54c0b86a353e13c4ac738b020fc0d2bcb184a200` |
| MLE/WHIR PCS repair | Explicitly out of scope and isolated in a separate submodule/thread |
| KZG ceremony | **Owner-accepted trust assumption; not a release blocker** |

This report covers the production close-proof availability path, terminal live-withdrawal
production, Rollup-to-Manager channel-scoped backing, direct delegate/browser claim recovery,
shared L1-signer durability, exact payout behavior, and retirement of the old in-place member-set
update prototype. The proof-system repair handoff remains in
`doc/audit/mle-whir-pcs-repair-handoff.md`.

The working checkout also contained an independent, unfinished PCS repair. Its submodule changes,
new proof fields, generated fixtures, and mixed Solidity ABI hunks were deliberately excluded from
this branch's commit. The release evidence for this report must be collected from a clean checkout
of the committed parent/submodule pair, not from that dirty combined checkout.

## Executive disposition

| Release item | Disposition | Exact boundary |
|---|---|---|
| 2. Public close-proof availability | **Implemented and fail-closed locally** | A head is not accepted unless its exact bounded public backing is independently verified and durably archived. A keyless native prover and journaled publisher can progress a requested close through guarded finalization without coordinator secrets. |
| 3. Live withdrawal producer | **Implemented for cooperative terminal funding; unilateral liveness still open** | The live service constructs, verifies, admits, finalizes, and publishes a terminal funding child. That child is a fresh state and still requires fresh N-of-N Falcon signatures. |
| 4. Manager channel-scoped backing | **Implemented locally** | The immutable materializer consumes the exact proof-bound complete token lane and installs Manager authorizations atomically. Donated/global credit cannot substitute for channel-scoped evidence. |
| 5. Browser/public claim path | **Implemented locally; public-chain E2E open** | The browser keeps the Regev secret, creates the claim, and uses exact journaled transactions. Deployment/runtime identities, finalized observations, nullifier, token, amount, recipient, and exact payout are bound. No real public deployment has yet supplied release evidence. |
| Direct in-place MSU | **Retired, not implemented** | Active circuit, Manager ABI, producer, service, CLI, deploy, and verifier paths no longer construct or accept it. Historical code is isolated behind an explicit deprecated feature, and regression calldata pins the pre-retirement selector as a literal independent of future PCS tuple changes. |
| MLE/WHIR PCS | **Critical / separate blocker** | Nothing in blockers 2–5 repairs constituent-evaluation non-binding. Public value movement remains unapproved until the separate repair is independently reviewed and integrated. |

## 1. Public close availability

### Accepted-head admission

The producer/API may advance its accepted signed head only after all of the following hold:

1. the public backing envelope is schema-valid, canonical, and within the configured byte limit;
2. its state/head identities match the independently verified candidate exactly;
3. native verification succeeds against an independently pinned verification-data digest;
4. the byte-exact envelope is copied into an immutable private vault and file plus directory data
   are durably synchronized before the accepted-head journal advances; and
5. restart revalidates the archived identity instead of trusting a mutable caller path.

This makes close availability an admission invariant rather than a best-effort backup after a head
has already become authoritative.

### Keyless proving and publication

`public_close_prover` reads only the authenticated accepted head and immutable public backing. It
rechecks all identities and native verification before producing the close bundle. It neither
loads nor requires a member signing key.

`public_close_publisher` uses a durable state machine for submit, proof-DA attestation, challenge
deadline, guarded finalize, receipt adoption, and restart. It pins the raw deployment manifest,
chain, contracts, runtime hashes, selectors, calldata, expected state transition, exact transaction
bytes, canonical receipt block, and durable finalized checkpoint. A reorg, replaced checkpoint,
ambiguous receipt, changed manager state, or missing signer reservation stops the lane.

Finalization is bound to both the exact pending close digest and the Manager-lifetime monotone
`closeRequestGeneration`. The old no-argument `finalizeClose()` selector is absent from the
production ABI. The publisher records the generation, checkpoint, calldata, and calldata hash in
journal schema v3 before signing; once raw bytes exist, neither a cancellation nor a later reuse of
the same close digest can redirect those bytes into a new close era.

The publisher also handles permissionless semantic winners conservatively. A foreign transaction
may satisfy the protocol transition, but it does not by itself prove that this publisher's signed
nonce is harmless. The local losing raw transaction remains reserved until it is broadcast and a
canonical finalized revert consumes that nonce; only then can the semantic winner and loser be
recorded together and the signer lane released.

## 2. Cooperative terminal funding and live withdrawal

The live service now exposes a two-phase terminal-funding workflow:

1. `prepare` derives a canonical terminal child and complete `CloseFundingPlan` from the current
   bound live head without pretending to hold missing member authority;
2. every member signs that exact child; `commit` rejects incomplete, reordered, stale, or
   non-canonical signatures and state;
3. the block producer admits the terminal transition through the ordinary validity rules;
4. the validity publisher waits for exact canonical finalization; and
5. the close-funding publisher submits the proof-bound withdrawal lane and reconciles exact
   materializer/Rollup/Manager effects.

The plan binds chain, Rollup, Manager, materializer, channel, terminal state/root, base account and
nonce, token registry and complete fund vector, withdrawal ordering, aux data, proof/public-input
hashes, deployment/runtime hashes, selectors, and activation checkpoint. Schema-v2 publication
rejects a legacy manifest that omits the materializer or any runtime identity.

### Important liveness limit

This is not a fully unilateral exit. The terminal state is a new child of the accepted head and its
ordinary authorization is a fresh N-of-N signature set. If any member disappears after the last
accepted head, the public close can still reach `Closed`, but the terminal validity/withdrawal
proof cannot be created from the retained public material alone. The detailed trace and minimum
safe redesign are in `doc/audit/close-funding-unilateral-liveness-review.md`.

A naive pre-signed sibling is not an acceptable patch: it collides with the one-successor signing
ledger, lacks authoritative old-kit invalidation, and still lacks the producer/global/private
witness material needed after coordinator loss. The release-grade repair is a protocol-level
head-plus-exit-kit acceptance rule or an equivalent domain-separated system exit authorization,
with atomic availability and revocation semantics.

## 3. Channel-scoped funding and exact payout

`CloseFundingMaterializer` is immutable-linked to the Rollup. The Manager is immutable-linked to
both the Rollup and that materializer. A materialization transaction validates the complete lane,
every token/asset class/recipient/amount/aux-data field, uniqueness, and proof identity before it
can install all Manager authorizations and consume the Rollup proof. A partial loop or later revert
rolls back the whole transaction.

The Manager then pulls exactly the finalized per-token cap and records proof consumption. It does
not accept an aggregate recipient credit, unrelated Manager balance, or donated Rollup credit as
evidence for this channel. Claims are scoped by close digest, participant identity, token, amount,
and withdrawal nullifier.

The final ERC-20 sends in both `IntmaxRollup.withdrawToken` and
`ChannelSettlementManager.claimWithdrawalCredit` now require the recipient's `balanceOf` increase
to equal the claimed amount exactly. A token that returns `true` while charging a sender-selective
fee, burning the transfer, or otherwise underpaying causes the whole transaction to revert, so the
credit/nullifier/payout latch is not consumed. Native sends retain revert-on-failure behavior.

One conservative liveness caveat remains: after stale authorized-burn reconciliation, the Manager
uses the adjusted per-token cap vector. Mixed-direction changes across different tokens can yield a
safe fail-closed vector that is not itself one signed historical head. It cannot overpay, but the
result may be unprovable/unfundable and strand liveness. This requires an exact protocol rule for a
single authenticated post-burn vector before release claims may call it fully live.

## 4. Direct delegate and browser claim

The production direct path no longer treats a global Rollup withdrawal event or a matching
recipient as completion. It:

- reconstructs the finalized per-token balance report from the browser/WASM-held Regev secret;
- checks all public inputs against the exact finalized Manager/channel/settlement binding;
- persists the first exact randomized proof calldata and transaction bytes for replay;
- binds Manager, Rollup, verifier, materializer, chain, channel, activation checkpoint, runtime
  hashes, close digest, member key, slot, token, amount, recipient, and nullifier;
- accepts permissionless progress only after canonical finalized receipt plus same-block getter and
  exact event reconciliation; and
- emits `EXIT_DONE` only after every positive claim has an exact finalized Manager payout.

The browser coordinator does not trust JSON deployment identity alone. Its trusted-authority step
invokes the native settlement-binding verifier, which re-reads the Manager's immutable verifier,
Rollup, and materializer links, the materializer's Rollup link, runtime code hashes, and activation
checkpoint. The browser route then compares that verified output with the claimed settlement
manifest.

The remaining item is operational evidence: deploy the repaired PCS stack on the intended public
chain, exercise browser-only prepare through exact payout, restart at every journal boundary, and
reorg each receipt class. Local fixtures and a localhost RPC are not that evidence.

## 5. Shared signer durability and close races

Every Node raw transaction is protected by a signer-global durable reservation. The reservation is
written and synchronized before offline signing, then advanced to the exact raw transaction hash
only after the action WAL is durable. A crash at reservation, signing, persistence, broadcast,
receipt, terminal journal, or lease-unlink boundaries resumes the same semantic action and bytes.
A second claim/close action cannot allocate that signer lane while the first action is unresolved.

Three race classes received explicit treatment:

1. **Sign-before-reservation crash:** fixed by reserving the exact nonce and intent before signing.
2. **Fee replacement/restart:** pending replacements retain the same nonce and intent; a finalized
   revert is required before a fresh nonce, and an interrupted reservation cannot be silently
   overwritten if RPC nonce state changed.
3. **Foreign participant close front-run:** a foreign finalized `CloseRequested` does not simply
   delete the local close action. The exact local raw is retained/rebroadcast; the lane is released
   only after either the local transaction succeeds and is normally finalized, or its active nonce
   has a canonical finalized revert and the foreign manager transition remains canonical. A
   cancellation cannot discard an unresolved signed raw; restart continues its reconciliation.

The same terminal rule is applied at all five Node value/control seams: participant request,
guarded finalize, `WithdrawalClaimAccepted`, `ChannelFundsPulled`, and `WithdrawalClaimed` credit.
Each action writes deterministic prepared Store metadata before entering code that may sign. Own
success requires its exact canonical receipt event and receipt-block getters. A permissionless
semantic winner is stored with transaction/log identity, but a local raw action releases the signer
only after its own nonce has a canonical-finalized revert. Watcher callbacks only record finalized
effects; a later recovery tick starts the dependent transaction, avoiding same-block log-order
loss. Completion is emitted only after every positive claim has an exact finalized payout.

Member close requests are similarly one-shot across cancellation. Both member and participant
entry points bind the expected `currentCloseFreezeNonce` and monotone
`highestCancelledRevivedStateVersion`; the Rust member CLI obtains both from one durable,
hash-authenticated checkpoint and revalidates that checkpoint immediately before submission.

This is the same basic discipline required by Lightning implementations: protocol-semantic
adoption and wallet nonce finality are separate facts, and both must be durable before dependent
fund movement proceeds.

## 6. MSU retirement

The old direct member-set update tried to span two independently mutable layers without one atomic
proof/receipt. It is not advertised as partially atomic:

- the active validity circuit has no constructive MSU gadget;
- default Rust builds do not compile the historical circuit/fixture generator;
- producer, service, API, and CLI entry points reject the retired wire action;
- the Solidity verifier has no MSU VK or verify function;
- the Manager production ABI contains no `applyMemberSetUpdate` selector; regression tests send
  raw calldata under the fixed historical selector `0x66e3ff78` and require an empty, fail-closed
  unknown-selector revert with no state change; and
- historical code/data are isolated below `src/deprecated/member_set_update` and
  `contracts/test/data/deprecated/member_set_update`.

The replacement product task is `doc/tasks/channel-change-msu.md`: unanimous authorization, normal
final close of the old channel, new channel registration, and exact migration of assets and all
commitments under one versioned manifest. It is a TODO, not a release capability.

Removing the dormant circuit gadget intentionally rotates the validity circuit digest and VK.
Old validity fixtures/deployments are incompatible. This is not a benchmark-neutral metadata
change and must be regenerated and measured with the final PCS generation.

## Three attack/defense rounds

### Round 1 — value conservation and hostile assets

The attacker exercised pre-existing global credit, partial materialization, token/lane permutation,
duplicate token entries, aux-data substitution, cross-channel/nullifier replay, stale authorized
burns, and hostile ERC-20 return behavior. The new finding was sender-selective underpayment after a
successful return value. The defense added exact recipient-delta checks at both final payout
boundaries and regression tokens/tests. Focused Rollup/Manager/materializer and Fenwick/burn suites
passed after the fix.

### Round 2 — publisher crash, nonce, and semantic-adoption races

The attacker cut power before/after reservation, sign, raw-WAL fsync, broadcast, receipt,
semantic-adoption read, terminal fsync, and lease removal; it also raced same-nonce replacements,
permissionless winners, missing receipts, and reorged checkpoints. The Rust close publisher now
reserves before signing, while the Node outbox persists a schema-v2 intent reservation before
signing, refuses a changed nonce after restart, replays only the byte-exact WAL transaction, and
requires canonical loser-nonce consumption before adopting a permissionless winner.

### Round 3 — cross-participant close and final seam review

The independent reviewer front-ran a delegate's journaled participant-close transaction with
another participant. The foreign close froze the Manager, the local raw reverted or disappeared,
and the old implementation completed only its Store action while leaving the signer-global outbox
lease alive. Every later claim using that recipient key could then fail with
`OUTBOX_SIGNER_RESERVED`. The defense couples semantic-winner adoption to conclusive local-nonce
consumption, preserves unresolved raw bytes across cancellation/restart, and tests that claim
signing remains blocked until this proof is durable, then becomes available.

The integration review then found the same class at four additional seams—guarded finalize,
withdrawal-claim acceptance, channel-fund pull, and credit payout—plus delayed member-request and
unguarded-finalize replay across cancellation. The defense extended prepared-before-sign journals,
exact receipt/getter adoption, recovery-tick sequencing, and signer-lane settlement to every seam;
made member requests bind the freeze/cancellation era; added monotone request-generation binding to
finalize; and removed the legacy unguarded selector. The post-fix review and tests reported below
found no additional High/Critical bypass in this scoped replay analysis. This statement deliberately
excludes the known PCS Critical and the unilateral terminal-exit liveness blocker described above.

An independent read-only post-fix review rechecked every production caller and all five Node seams
and ran 94 focused tests without finding a High/Critical issue. It recorded one explicit trust
boundary: after canonical finalized receipt/block/checkpoint evidence is written and synchronized
in a terminal WAL, restart finishes lease cleanup from that durable record rather than querying the
chain again. This relies on the configured finalized source not rewriting finalized history. The
normal verification path pins the receipt block and durable checkpoint before, after, and immediately
before the terminal write; a contradictory finalized provider or post-finality consensus failure is
a chain-safety halt/reconciliation event, not something this application can safely guess through.

A final independent delta review likewise found no new High/Critical issue. It did find two test
and release-evidence weaknesses: the CREATE2 address printer could appear green while the plain and
close fixtures belonged to different generations, and the ignored two-token CLI E2E still called
removed aggregate claim overloads. The printer now rejects a mixed fixture generation, and the
nightly test now calls only `claimWithdrawalCredit(bytes32)` with exact missing nullifiers. The
review's lower-severity stale documentation and PCS-dependent historical-selector interface were
also removed; MSU retirement tests now pin the literal pre-retirement selector. A post-remediation
read-only replay found no unresolved High/Critical/Medium issue and no safety regression. One
non-operative stale comment in `CloseLifecycleE2E.t.sol` remains intentionally untouched because
that file carries the separately owned PCS integration hunk in the shared working checkout.

## Verification and performance evidence

The first clean replay, before the final size patch, found two integration defects hidden by the
dirty PCS checkout: the Manager was 106 bytes over EIP-170, and the CREATE2 lifecycle helper omitted
the new materializer constructor argument. The release patch removed only retired/dead ABI decoders
and made the helper predict and deploy the materializer before the Manager. Production checks used
a fresh clone of validation snapshot `7aca890c...`; the complete Forge suite and clean two-token
nightly target were then re-run at test-hardened snapshot `31147b8...`. Both used recorded submodule
`54c0b86...` and nested Forge standard library `0844d7e...`; the final report-only amendment changes
no code.

| Clean check | Result |
|---|---|
| `git diff --check HEAD^..HEAD` | pass |
| Rust formatting for all 51 Rust files changed by the release patch | pass, edition 2024 |
| Whole-tree `cargo fmt --all -- --check` | one pre-existing comment-wrap difference in excluded PCS file `src/utils/mle_prover.rs:258`; that file is byte-identical in `HEAD^` and `HEAD` |
| `cargo check --locked --all-targets` | pass; no errors, existing warnings only |
| Clean ignored two-token nightly target, `cargo test --release --locked --test two_token_cli_e2e --no-run` | pass; exact-nullifier claim caller compiles, existing warnings only |
| Rust publisher unit selection | 65 / 65 pass |
| Rust public-close publisher | 21 / 21 pass |
| Changed production JavaScript syntax | 29 / 29 files pass `node --check` |
| Node suite | effective 438 / 438 pass, 0 fail, 0 skip; the only four sandbox failures were denied localhost binds and passed 4 / 4 outside the sandbox |
| Real release `block_producer_service` integration | outer test plus 6 / 6 nested checks pass; `liveInit` completed in 43.24 s |
| Ignored live ch7 snapshot matrix | 9 / 9 pass against 549,219-byte fixture SHA-256 `bf6fe10e477644df05c1d604ebcafd8f82070abcb8b14875c0257a6e5b961321`; delta 102 KiB versus full 536 KiB (81.0% smaller) |
| Focused Node signer/close/claim/watcher matrix | 80 / 80 pass |
| Independent post-fix Node review matrix | 94 / 94 pass |
| `ChannelSettlementManagerTest` | 78 / 78 pass |
| `CloseLifecycleHardeningTest` | 17 / 17 pass |
| Focused Forge value/materializer/burn suites | 57 / 57 pass |
| Retired-MSU selector/verifier regressions | 2 / 2 pass |
| Production deployer removed-MSU guard | 1 / 1 pass |
| Full final clean Forge suite | 538 / 540 pass, 0 skip; both failures are deliberate hard stops on the two stale-fixture identities described below; every other suite passes |

The Manager ABI inspection retains the exact proof-scoped `claimWithdrawalCredit(bytes32)` and the
three intentional pure-revert safety tombstones for special close, late debit, and post-close claim.
It contains no direct-MSU selector, no aggregate claim overload, and no dead
`computeSpecialCloseDigest` helper. Legacy raw MSU and aggregate-claim calldata still fail closed
through the contract's absent fallback, and regression tests require that it cannot mutate state.

The full Forge replay confirms that the CREATE2 helper now deploys MLE verifier → Rollup →
settlement verifier → materializer → Manager without the old constructor-decoding panic. It then
stops at the intended byte-exact fixture check: the newly derived Manager is
`0x96e946C1a5b19495542dC5d5a2762dd6D10E275C`, while the checked-in payout proof names
`0x83834b012D26b8f1304830158D0d5aBFa99a5292`. The address-printer's plain fixture pair derives a
third address, `0xE16F35710a9398Eef764AB854C7a2384c71d994f`; it now refuses to print that address because the
close fixture instead derives `0x96e946...`. The plain and close validity fixtures have different
preprocessed commitment roots and circuit digests, so the promised same-generation input identity
is currently false. These failures are not waived: after the PCS repair lands, the plain validity,
close validity, payout, close-intent, and deployment artifacts must be regenerated together, then
the 540-test suite must reach 540 / 540 before public deployment.

Clean runtime/initcode measurements are:

| Contract | Runtime | EIP-170 margin | Initcode |
|---|---:|---:|---:|
| `ChannelSettlementManager` | 23,969 bytes | 607 bytes | 26,491 bytes |
| `IntmaxRollup` | 24,304 bytes | 272 bytes | 28,270 bytes |
| `ChannelSettlementVerifier` | 22,932 bytes | 1,644 bytes | 22,999 bytes |
| `CloseFundingMaterializer` | 6,059 bytes | 18,517 bytes | 6,224 bytes |

The Manager is now deployable in this pinned generation, but both the Manager and Rollup margins
remain release gates: the separately owned PCS repair can change ABI decoders and linked runtime
code, so the single finally integrated generation must be measured again before deployment.

No claim of unchanged proof time is made. Other than the deliberate removal of the retired MSU
gadget, blocker 2–5 changes add no ZKP gates or proof-serialization fields; they add off-circuit
journals, native verification, RPC checks, and L1 transactions. MSU removal rotates the validity
circuit, while the separate PCS redesign changes the proving/verification code under measurement.
Final proof bytes, three warm prove/verify medians, peak RSS, calldata, gas, and contract sizes must
be measured on the single integrated PCS generation. Inventing a comparison across mixed
generations would be misleading.

## Required work before changing NO-GO

1. Complete and independently review the MLE/WHIR constituent-binding repair, then integrate the
   exact parent/submodule pair and regenerate every affected VK/fixture/deployment manifest.
2. Implement a signer-independent latest-head exit kit or equivalent protocol transition. It must
   be atomically available when a head is accepted, authoritatively invalidate older kits, and be
   publishable without coordinator/private producer state.
3. Resolve the multi-token stale-burn hybrid-vector liveness rule using one authenticated exact fund
   vector; retain the present fail-closed behavior until then.
4. Run a real intended-public-chain browser/public-claim E2E through exact per-token payout,
   including process deletion/restart, fee replacement, permissionless winners, congestion, and
   reorg recovery.
5. Repeat the complete clean-clone Rust, Node, Forge/invariant, WASM, proof self-verification,
   bytecode identity, EIP-170, gas, and proof-performance matrix. Pin reachable parent and submodule
   commits and the deployed runtime hashes.

Until all five are complete, documentation and UI must describe the new funding path as
**cooperative terminal funding followed by permissionless publication**, not as a fully unilateral
close-to-L1 exit.
