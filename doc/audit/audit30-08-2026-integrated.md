# INTMAX3 integrated pre-release security audit (2026-08-30)

> **INTEGRATION EVIDENCE, NOT RELEASE APPROVAL.** The runtime source was frozen after the final
> no-skip Forge runs and bytecode measurements below. The parent SHA is the commit containing this
> report (reported at handoff rather than embedded self-referentially). Full clean-clone Rust/Lean,
> remote submodule reachability, deployment code hashes and all regenerated VK/fixture hashes remain
> explicit release gates.

## Release decision

**NO-GO.** The integrated tree closes the reproduced A11 final-wire failure, the validity
signed-H2 replay gap, snapshot cross-channel record substitution, and the live outgoing-nonce
race. It also has a materially stronger Rust-to-Solidity MLE gate-envelope guard than the Opus
report describes. The final integration pass additionally found and repaired three independent WHIR
verifier defects: a Merkle scratch-buffer alias that both false-rejected honest proofs and bypassed
duplicate-row consistency, a **critical soundness gap** that left the last polynomial commitment
completely unbound from `finalVector`, and non-canonical opening-row encodings that gave one field
oracle multiple Merkle/Fiat-Shamir commitments. The WHIR fixes are frozen in submodule commit
`8f0be2f7e025a17a5a3acb281c14c33d87658932` and were repeated against that exact source. The repository is therefore not a release
candidate until the following are resolved on the exact final source tree:

1. Regenerate every affected verifier key and proof fixture and run the real Rust-proof-to-Solidity
   joins without a mock, skip, or verifier bypass. The validity circuit changed during this
   integration, so a green result from an earlier tree is not a release result.
2. Either pin the KZG trusted-setup material in immutable, deployment-authenticated storage or
   disable the pre-timeout KZG fraud route. The active caller-parameterized opening is not a sound
   data-availability binding. Its present impact is bounded liveness/griefing rather than false
   conviction, but it must not be advertised as a DA proof.
3. Make the pre-timeout fraud verdict reachable for an invalid committed proof. The deployed MLE
   verifier returns `true` on success and uses reverts for every failed equation/boundary check, but
   `_verifyFraud` convicts only a returned `false`. Thus malformed committed proofs are currently
   `UNEVALUABLE` until the roughly 12-hour timeout, never `MLE_INVALID`.
4. Implement a production withdrawal lifecycle and lossless proof-DA encoding. `cmd_withdraw`
   intentionally refuses every chain except 31337 because it posts an all-zero demo blob. Its
   current diagnostic says the checked-in encoded validity proof exceeds one EIP-4844 blob, but the
   final regenerated proof size was **not measured for this handoff**; a green local withdrawal is not a usable
   mainnet/testnet exit either way.
5. Bind recovered snapshots and signing authority to an authenticated, durable, reorg-aware L1
   lifecycle/canonical head. The new internal channel-ID equality is necessary but does not make a
   self-consistent stale snapshot current.
6. Resolve the two live channel-design seams before enabling them in production: M-4, atomic
   agreement between the Manager member set and the validity-tree member set; and M-9, the unsigned
   close-intent fields that make `closeIntentDigest` coordinator-malleable. M-9 requires a product
   decision because the strongest fix costs unilateral-close availability.
7. Make fresh balance backing mandatory on every production deposit co-sign path, and add an
   explicit one-blob proof-size/domain gate (or a designed multi-blob protocol).
8. Replace the number-only chain watcher with a canonical-hash/rollback-aware state machine, and
   add confirmation depth plus post-restart canonical revalidation to payout completion. The payout
   journal now binds caller/nonce/target/calldata, scans canonical blocks and checks atomic
   postconditions, but one mined receipt is still promoted to durable completion without a depth or
   rollback policy. Then close the remaining burn/PW crash windows described below.
9. Freeze the tree, run the full Rust/Node/Forge/Lean release matrix from a clean clone, verify that
   no required suite skipped, and record the final VK, fixture, bytecode, main-repository and
   submodule identities below.
10. Refuse `DeployCloseCli` for a delegate-bearing live channel until its **settlement input** (not
    the cosigner-only L1 registration limb, which must remain zero) is built from an authenticated
    live snapshot. The current producer emits
    `active_delegate_count = 0` and no delegate bindings, making the Manager's delegate-count floor
    vacuous even when the live off-chain channel already has delegates. Because that floor is
    immutable, either freeze later delegate joins or add an authenticated monotone Manager update
    for every join. Also reconcile the Manager's present 8-total-participant deployment cap with
    the Rust/close-proof 1,024-slot model.

Post-close claims remain deliberately disabled. Duplicate Regev-key rejection is not in this
NO-GO list: with the current leaf-bound nullifier it is self-loss/nullifier collapse, not a route to
steal another member's funds. It remains worthwhile availability hardening if bytecode budget and
registration policy permit it.

## Repository and integration provenance

| Item | Integrated fact |
|---|---|
| Upstream `main` used for integration | `492c80346153e46fee34041471dca5fa323ef6b4` |
| Source audit branch | `claude/live-balance-validity-finalize-b73981`, at the same `492c803` base when integration began |
| Integration branch | `codex/integrate-opus-audit-20260830`; the integration SHA is the commit containing this report and is recorded in the handoff output. |
| MLE submodule gitlink | `8f0be2f7e025a17a5a3acb281c14c33d87658932` on `codex/whir-leaf-consistency-20260830`, based on user-reported/pinned `e7172b993ff27c332bb8c1e37fd8d965172ea545`. The parent integration commit records the new gitlink. Neither branch was pushed by this audit; a fresh-clone release run must first make this submodule commit reachable from an authenticated remote ref. |
| Opus remediation report | `d8c897a4bb4f149136027d7f3cf14bd857c2893f` |
| Already-integrated equivalent code lineage | Opus material commit `91d281d1ed081c4b1547df35c47e53a463f7086a` and current-ancestry commit `a6ea6437d3ef5b7e4ab5efc884268fceaf570285` are sibling commits with the identical tree `5411552ac11e737cf70538abfdff443595a5d13c` |

`d8c897a` is **report-only**: `git show --stat d8c897a` changes only
`doc/audit/audit28-08-2026-remediation.md`. It contains no code or test fix to merge. Its parent
`91d281d` carries the material round-2 tree; the present ancestry carries the byte-identical sibling
`a6ea643` (both descend from `300720e`). A wholesale merge/cherry-pick of `d8c897a` would therefore
add only stale, internally overclaimed prose; this integration instead reproduced each important
claim against the current code and selected the valid fixes.

## Classification method

- **SUPPORTED/CURRENT** — reproduced in current code, with a load-bearing check or executable
  regression at the relevant boundary.
- **STALE/SUPERSEDED** — described a real older state, but a later design implements the objective
  differently.
- **FALSE/OVERCLAIMED** — the report says a feature is disabled or a property is enforced when the
  current tree shows otherwise, or it assigns a stronger impact than the reproduced attack has.
- **PARTIAL** — a narrower invariant holds, but the prose bundles it with an unimplemented one.

Audit prose was treated as untrusted input. A passing test was not treated as proof of a claim
unless the test reached the production verifier or the relevant native/circuit boundary and had a
non-vacuous negative case.

## Opus claim-by-claim matrix

| Report claim | Disposition | Current evidence and exact impact |
|---|---|---|
| Caller-parameterized KZG fraud verification was disabled (`remediation.md:31-33,89-91`) | **FALSE/OVERCLAIMED** | `IntmaxRollup.setKzgVerifier` and `fraudProof` are active (`contracts/src/IntmaxRollup.sol:835-840,1474-1526`), and `_verifyFraud` calls the satellite (`:1981-1985`). `lagrangeBasisG1`, `vanishingG2`, and `openingProof` remain calldata fields (`contracts/src/BlobKZGVerifier.sol:61-67,142-166,347-354`); the contract's own warning at `:22-43` correctly says they are not tied to trusted setup. |
| The KZG defect lets arbitrary calldata convict an honest submission | **FALSE as current impact; diagnosis of DA unsoundness is valid** | Commitment precondition 1 pins `keccak256(proofBytes)` (`IntmaxRollup.sol:1956-1963`) and precondition 4 pins `abi.encode(mleProof)` to the same bytes (`:1993-2002`), followed by PI-preimage binding (`:2004-2025`). A forged opening cannot substitute a different proof or cause an unauthorized state transition. A dishonest submitter can instead post a junk blob while committing to unavailable bytes, causing bounded timeout/liveness grief and loss of its own bond (`BlobKZGVerifier.sol:45-58`). |
| Finalization is bound to the submitted root and exact batch end (`:34-35`) | **SUPPORTED/CURRENT** | `_submit` stores `stateRoot` (`IntmaxRollup.sol:1321-1340`); `finalize` requires the same root (`:1385`) and exact `_batchMetadata[submissionId].endBlockNumber` (`:1409-1411`). |
| Rollback no longer restores live pending deposit/registration accumulators (`:36`) | **SUPPORTED/CURRENT** | `_rollbackBatch` rewinds only batch-owned state and explicitly leaves `_pendingDepositHashChain` and `_pendingChannelRegHashChain` untouched (`IntmaxRollup.sol:2243-2283`). |
| Post-close claims are disabled (`:37-38`) | **SUPPORTED/CURRENT** | `submitPostCloseClaim` is a pure reverting stub (`ChannelSettlementManager.sol:2188-2242`, entry at `:2240-2242`). Its verifier/VK remain unreachable scaffolding and must not be presented as enabled functionality. |
| Close deadlines are absolute (`:39`) | **SUPPORTED/CURRENT, evolved** | The first intent fixes `closeChallengeHorizon = now + 2*challengePeriod` (`ChannelSettlementManager.sol:1228-1234`). Replacements are bounded by one `horizon + minResponse` absolute end (`:1203-1208,1288-1303`), while the response tail remains usable. |
| Active Regev digests are pinned and frozen (`:40-41`) | **PARTIAL** | Ordinary transitions freeze `regev_pk_digests` (`src/circuits/channel/state_update_verifier.rs:1497-1522`), and snapshot import anchors transported member Regev keys to `record.regev_pk_root` (`src/wallet_core.rs:1180-1195`). The generic snapshot verifier does not independently prove that each active `balance_state.regev_pk_digests` value equals the transported member key; writers must preserve the genesis/join/MSU construction discipline. |
| Funds are restricted to a common `u64` domain and high limbs are rejected (`:42-43`) | **STALE/SUPERSEDED** | The current multi-token design stores `[U256; MAX_CHANNEL_TOKENS]` in `ChannelFund` (`src/common/channel.rs:485-505`) and imports an L1 `u64` amount by exact `u64_to_u256` addition. Non-truncation is preserved, but “all fund values are u64 / all high limbs are zero” is no longer the protocol invariant. |
| Member-set updates are disabled and their VK/fixture removed (`:44-45,78-79`) | **FALSE/OVERCLAIMED** | MSU is active: set-once nonzero VK initialization and strict 26-limb binding run a real MLE proof (`ChannelSettlementVerifier.sol:215-290`), and `applyMemberSetUpdate` mutates the Manager (`ChannelSettlementManager.sol:1033-1112`). The required real-join suite remains in `.github/ci/forge-test-guard.sh:51-71`. M-4 cross-layer atomicity remains open; disabling prose must not hide it. |
| Partial-withdrawal cancellation is disabled (`:44-45,89-91`) | **FALSE/OVERCLAIMED** | `cancelPartialWithdrawal` is live and verifies the corrected cancel proof (`ChannelSettlementManager.sol:2011-2124`). It uses a per-logical-burn replay floor rather than a global close floor. |
| Burn descriptor includes its source channel (`:51-52`) | **SUPPORTED/CURRENT, evolved** | The current `IMD2` descriptor additionally binds the outgoing base nonce; Rust constructs it and the Manager recomputes it under its own channel/nonce (`src/common/channel.rs` burn descriptor; `ChannelSettlementManager.sol:1745-1762`). |
| The proof-only withdrawal nullifier was removed from `IMPW` (`:53-55`) | **SUPPORTED/CURRENT, evolved** | Current domain is `IPW2`; the authorization digest binds recipient/token/amount/aux data, while withdrawal-proof nullifier validity and one-shot consumption are separate (`IntmaxRollup.sol:1631-1674,1746-1764`). |
| PW replacement is restricted to the same authorization (`:56-57`) | **SUPPORTED/CURRENT, evolved** | The pending logical burn is keyed by the stable burn/chain identity; replacement cannot substitute an unrelated burn, and the existing deadline is preserved (`ChannelSettlementManager.sol:1780-1816`). |
| Duplicate active Falcon and Regev identities are rejected (`:58-59`) | **PARTIAL / FALSE for Regev** | Falcon/`pk_g` distinctness is enforced natively (`src/common/channel.rs:314-339`) and on registration (`IntmaxRollup.sol:1183-1188`). Neither loop compares Regev digests. Current withdrawal nullifiers intentionally document duplicate Regev keys as one collapsed claim/self-loss (`src/common/channel.rs:1208-1218`), not a theft primitive. Treat Regev distinctness as availability hardening, not a release soundness claim. |
| Registration is deployer-gated (`:59`) | **SUPPORTED/CURRENT** | `registerChannel` requires `msg.sender == deployer` (`IntmaxRollup.sol:1150-1163`). This prevents channel-ID squatting but creates a registrar availability/key-management dependency. |
| L1 registration accepts records the validity circuit cannot represent | **SUPPORTED defect; FIXED in integration** | `registerChannel` now rejects nonzero `delegateCount` before any accumulator/state write and rejects every pkG/pkB/Regev `bytes32` containing a Goldilocks limb `>= 0xFFFF_FFFF_0000_0001` (`IntmaxRollup.sol:1150-1188,1231-1257`). Rust native validation mirrors zero delegates, canonical limbs, nonzero pkG and duplicate-pkG rejection (`channel_registration.rs:130-166`); L1 additionally rejects zero Regev/recipient. The circuit independently retains its zero-delegate constraint. Forge regressions assert that a rejected ID is not poisoned and can subsequently be registered canonically; their frozen-tree run is still TBD below. |
| Snapshot record/state/fund/balance IDs are equal (`:60`) | **SUPPORTED/CURRENT after integration fix** | `verify_snapshot` now fail-closes before nested validation unless all four IDs equal (`src/wallet_core.rs:1139-1156`). The regression mutates each field separately and re-signs state mutations, proving this seam rather than merely triggering stale signatures. |
| A close-version floor survives cancel and PW finalization (`:61-62`) | **FALSE/unsafe design for the close lane** | Current code intentionally has no minimum version floor on new closes. `highestCancelledRevivedStateVersion` is read only by `cancelClose` (`ChannelSettlementManager.sol:701-706,1406-1424`); the comments explicitly reject a close floor because the withholding canceller may be the only holder of the completed newer signature set (`:1381-1405,1474-1483`). An honest party may re-close an older available state; the same cancel proof cannot replay. |
| Validity binds signed `small_block_number` to `prev leaf index + 1`, high limb zero (`:69-71`) | **FALSE/unsafe proposed fix; narrower replay defect fixed** | `small_block_number` also advances on incoming/other channel transitions. The current regression constructs an incoming-only transition whose head has `small_block_number = 1` while the base-send cursor remains zero; its next outgoing message advances the former to two while retaining TxV2/base nonce zero (`src/wallet_core.rs:9948-10036`). The proposed equality would instead demand one and makes that honest sequence unprovable. The actual replay seam is closed by requiring signed `TxV2.nonce == prev_user_leaf.index` in native conversion and the circuit (`src/circuits/validity/block_hash_chain/update_channel_tree.rs:513-518,1238-1245`); the real-proof negative is at `:2536-2557`. Public compatibility send/burn builders now require that authenticated pre-block cursor explicitly (`src/wallet_core.rs:2337-2435,2809-2875`). This makes an applied H2 unusable after the leaf advances without conflating independent counters. |
| A11 signs the immutable small-block message and survives final signature attachment (`:72-75`) | **SUPPORTED/CURRENT after integration fix** | `InterChannelTx::signing_digest` uses `signed_small_block.message.signing_digest()` (`src/common/channel.rs:793-810`), while the broader `SignedSmallBlock::signing_digest` still includes mutable signature/proof carriers (`:443-480`). Attachment happens on a clone and asserts A11 invariance (`src/wallet_core.rs:2316-2330`); the final-wire regression recomputes and verifies the real sender proof (`:10410-10528`). |
| A11 was an unauthorized-transition/soundness exploit | **FALSE as impact** | The pre-fix sender proof was created over the placeholder form, then final N-of-N blobs changed the digest; the final verifier recomputed the new digest and rejected. This is deterministic honest proof rejection/liveness, not acceptance of an unauthorized state. IMCH/H2 binds the co-signed state to `tx_tree_root` and H1 (`wallet_core.rs:2290-2313`), but does not hash the mutable signature carrier blobs and therefore was not an implicit substitute for the corrected A11 message. |
| Live nonce lookup is fail-closed (`:76-77`) | **SUPPORTED/CURRENT** | A missing/malformed authoritative head refuses before the CLI (`node/cosigner/branches/cosign.js:99-115`). |
| Live nonce allocation is not atomic (`:117-122`) | **PARTIAL: local race fixed, rejection recovery open** | The handler reserves before invocation and keeps ambiguous outcomes fenced (`cosign.js:50-95`). The store uses a durable file plus exclusive lock and compare/reserve semantics (`node/common/store.js:79-127,179-214`); concurrency, restart, fetch-failure, and ambiguous-child regressions are covered. But a deterministic pre-sign rejection after CLI launch is also treated as ambiguous and leaves the same nonce fenced indefinitely. Multi-host deployment additionally needs a shared authority or single-writer rule. |
| No affected fixture changed and real joins were not regenerated (`:95-101`) | **STALE as a tree description; release gate remains** | The integrated worktree contains changed close/validity/withdrawal MLE fixtures and a mandatory MSU join. Nevertheless, the final validity-circuit edit means all affected artifacts must be regenerated and rejoined once more from the exact frozen tree. Do not infer closure from file timestamps or an earlier green run. |
| Reported `forge 433/433` and Rust `mle_gate_support 17/17` are sufficient merge evidence | **STALE / NON-TRANSFERABLE** | The frozen Forge guard passed 473 tests/37 suites after the parser and WHIR regressions; 433 cannot describe this tree. `mle_gate_support` passed its current 18/18 cases, so the reported 17/17 is likewise an earlier source set. The submodule's green cases also patch stale `numCommitments = 2` fixture metadata to four in-test. Preserve the user-reported numbers only as source-branch history, never as final integration evidence. |
| `cancelClose` plus a version floor permanently DA-locks the channel (`:103-109`) | **FALSE/OVERCLAIMED for current protocol** | The alleged close floor does not exist. With at least one independent honest cosigner, a hidden v21 state can cancel an honest v20 close once; v20 may be submitted again, and the same cancel proof is then consumed, bounding grief by the distinct N-of-N-signed states withheld. In the current single-operator-all-N-key deployment this bound is a custody/trust assumption, not an independent-party guarantee. The cancel PI remains an opaque digest/version statement (`ChannelSettlementVerifier.sol:1113-1151`), so state recovery is still operationally desirable. |
| Snapshot recovery is not bound to current L1 lifecycle/canonical head (`:111-115`) | **SUPPORTED/CURRENT blocker** | `verify_snapshot` now proves internal identity, members, signatures and balance validity, but its API accepts no expected lifecycle era or canonical-head object (`src/wallet_core.rs:1139-1217`). Service-specific checks do not turn this generic import into reorg-aware L1 authority. |
| Migration/fresh deployment is required (`:124-128`) | **SUPPORTED/CURRENT** | Digest domains, multi-token layouts, proof/VK shapes, manager storage and settlement behavior have evolved further (`IMD2`, `IPW2`, per-burn keys, gate parameters). Do not mix pending authorizations, old snapshots or old VKs with this tree. |
| Generic `sign_state_if_backed` is not a complete transition verifier (`:134-136`) | **SUPPORTED/CURRENT** | It verifies the balance proof/channel/settled-chain seam and then signs (`src/wallet_core.rs:1066-1087`). A production caller must first run the transition-specific verifier and trusted-record checks. |
| Proof payload needs a one-blob size gate (`:137`) | **SUPPORTED/CURRENT blocker** | `postBlockAndSubmit` accepts a caller-provided `uint32 proofLength` and `_submit` commits it without an explicit one-blob maximum (`IntmaxRollup.sol:915-950,1321-1340`). |
| CLI/API advertises only contract-disabled paths (`:138-139`) | **PARTIAL/STALE** | Post-close claim remains contract-disabled and its operator surface must say so. PW cancel is now an active, tested protocol path and must not be removed merely because the Opus report says it is disabled. |
| Fraud resolution is timeout-only because KZG is disabled (`:140-141`) | **PARTIAL: cause false, effective result true for another reason** | The entry point and KZG call are active, so “KZG is disabled” is false. But `MleVerifier.verify` returns only `true` and reverts on every failed proof check; `_verifyFraud` convicts only a returned `false`. Invalid committed proofs therefore become `UNEVALUABLE`, making effective invalid-proof resolution timeout-only. Fix both the unsound KZG opening and the unreachable `MLE_INVALID` verdict; merely documenting the route as active or disabled is insufficient. |

### Opus remediation adoption decision

- **Adopted after reproduction:** immutable A11 message signing; signed `TxV2.nonce` binding to the
  current base-send leaf; snapshot channel-ID equality; zero-delegate/canonical registration
  fail-closed checks; local durable nonce reservation; the diagnosis that KZG setup inputs are not
  authenticated; and the requirement to regenerate/freeze all affected proof artifacts.
- **Rejected or narrowed:** `small_block_number == prev.index + 1` (breaks an honest lifecycle), a
  global post-cancel close-version floor (can grant the withholding party the only closeable state),
  claims that MSU/PW cancel/KZG are disabled, duplicate Regev as theft, A11 as unauthorized
  acceptance, and arbitrary-calldata KZG conviction. The exact surviving impacts are recorded in
  the matrix instead of importing the Opus severity labels.
- **Not merged as code:** `d8c897a` is report-only and its material parent has a byte-identical
  sibling already in current ancestry. Valid findings were revalidated and integrated selectively;
  stale conclusions and proposed unsafe fixes were not cherry-picked as authority.

## Three attacker/defender integration rounds

### Round 1 — final-wire and proof-sequence attacks

**Attack.** Reconstructed the inter-channel sender proof at the exact order used by the wallet:
sender A11 over a placeholder small block, N-of-N state completion, signature attachment, then
final-wire verification. This reproduced digest mutation and showed that IMCH/H2 did not hash the
later signature/proof carriers. Separately, the validity witness did not bind the signed H2
transaction nonce to the current base-send cursor, leaving a replay seam after
`ChannelLeaf.index` advanced. The Opus proposal instead equated `small_block_number` with that
cursor.

**Defense.** A11 now commits only the immutable small-block message, attachment asserts invariance,
and the real final-wire proof is verified in regression. The proposed small-block equality was
rejected because an incoming-then-outgoing honest sequence advances that counter without first
consuming a base nonce. Native and circuit paths now
instead require `TxV2.nonce == prev.index`; a mutated nonce is unprovable and an already-applied H2
cannot replay after the leaf advances. Exact A11 impact was recorded as proof rejection/liveness.

### Round 2 — close, cancel and partial-withdrawal adversary

**Attack.** Challenged the Opus proposal to preserve a global minimum close version. The
withholding coordinator can be the only party holding the complete revived N-of-N artifact, so a
close floor converts a stale-close defense into “only the attacker can close.” Replayed
cancel-close and PW-cancel capabilities, deadline ladders, final-hour replacement, and burn/close
ordering were considered under delayed observation and transaction inclusion.

**Defense.** Retained the manager-lifetime floor only on repeated `cancelClose`, and a per-logical-
burn floor only on PW cancel. Neither gates a new close or burn finalization. The close window uses
one absolute horizon plus a fixed response tail; it does not reset per replacement. Post-close
double-credit stays hard-disabled. The Opus “permanent DA lock” and “close version floor” claims
were rejected rather than merged.

### Round 3 — cross-language verifier, snapshot and live-service attack

**Attack.** Treated fixture metadata and audit prose as attacker-controlled. Independently checked
every emitted gate ID and name-derived gate parameter against the deployed Solidity dispatcher,
then exercised the finite CosetInterpolation envelope and the Exponentiation gate. The exporter
itself compares layout/count metadata with live `CommonCircuitData`; the cheap checked-in fixture
scan cannot independently reconstruct those values without rebuilding the circuit. A regenerated
close fixture then exposed an honest WHIR rejection at an initial query for index zero. Following
that failure through `SpongefishMerkle.verify` found a scratch-buffer alias that also made the
claimed duplicate-row check bypassable. Comparing the final phase line by line with Rust found the
more severe independent defect: Solidity authenticated final Merkle rows and checked `finalVector`,
but never equated those rows with evaluations of that vector. A final parity pass then found that
Rust's Arkworks decoder rejected opening-row limbs `>= p`, whereas Solidity reduced them modulo `p`
after hashing their raw bytes into a Merkle root. Replayed a valid signed state under a
different record channel ID, raced two outgoing requests at one live nonce, and forced ambiguous
child-process outcomes as the non-WHIR part of this round.

**Defense.** The exporter fails closed on unsupported/mismatched IDs, layouts and parameters and on
CosetInterpolation values outside the deployed table. Duplicate query rows are now compared while
their sorted leaf hashes are still intact, before the Merkle verifier can reuse those arrays as
scratch space. The final phase evaluates `finalVector` at every transcript-derived query and equates
it with the opened committed row, including vector-RLC recombination for split commitments. Arkworks
`Vec` prefixes are checked instead of skipped, every base/Ext3 opening limb must be canonical, and
both Rust and Solidity require the transcript/hints to be consumed exactly. Snapshot
import now equates record/state/fund/balance-state IDs before accepting signatures. The relay
reserves a live nonce durably before invocation and keeps uncertain outcomes sticky. Remaining
cross-layer blockers — KZG trusted setup, M-4 member-set atomicity, M-9 close-intent authorization,
L1 canonical-head recovery and mandatory fresh backing — are not papered over.

### WHIR verifier findings from round 3

#### WHIR-MERKLE-ALIAS — honest rejection and duplicate-row authentication bypass

The old duplicate consistency check ran *after* `SpongefishMerkle.verify`. That verifier alternates
the caller-supplied `indices`/`leafHashes` arrays with newly allocated arrays as per-layer scratch
buffers (`SpongefishMerkle.sol:41-62`). The arrays returned by `_sortAndDedupWithHashes` were
therefore no longer the sorted authenticated leaves when `_verifyLeafHashConsistency` searched
them. On the checked-in close parameters, the 13-layer initial opening leaves internal indices
`{0,1}` in the aliased input buffer after 39 uniform queries over 8,192 leaves; the following
12-layer opening leaves root index `0` after 22 queries over 4,096 leaves. Under the Fiat-Shamir
uniform-query model, the honest false-reject probability per close proof was therefore

`1 - (1 - 2/8192)^39 * (1 - 1/4096)^22 = 0.014784...`, or approximately **1.48%**.

For duplicate indices other than those scratch residues, the post-Merkle lookup found no matching
index and silently performed no equality check. A prover could therefore supply a different second
row for a repeated query: the first row was retained for Merkle authentication while the unverified
second row still fed intermediate constraint accumulation. In the repaired final-opening path, a
coordinated second-row change can likewise preserve its weighted dot product, so explicit row
identity remains necessary there too. The fix moves equality enforcement into
`_sortAndDedupWithHashes`: equal adjacent indices must have equal leaf hashes before compaction and
before any Merkle mutation (`SpongefishWhirVerify.sol:641-668`). This both accepts the honest
index-zero proof and rejects a mismatched duplicate row with `DuplicateLeafMismatch`.

#### WHIR-FINAL-BINDING — critical final commitment / `finalVector` soundness break

The old `_phaseFinalVectorAndMerkle` read `finalVector` from the transcript and separately verified
Merkle openings against the initial/last commitment, but it never checked that an opened row was an
evaluation of `finalVector` (`SpongefishWhirVerify.sol` before the integration patch, old
`:350-431`). Consequently the final claim constrained one polynomial while the authenticated root
could commit to another. This is not merely proof-extension malleability; it removes the last
commitment-to-polynomial link on which WHIR soundness depends.

A concrete algebraic attack exists for the current `finalSize = 2`. If the final-claim covector is
`c = (c0,c1)`, choose nonzero `delta` and perturb the vector by
`Delta = (delta*c1, -delta*c0)`. Then `dot(c, Delta) = 0`, so the old Solidity final-claim equation
is preserved. The prover follows the new transcript, opens its existing last-commitment witness and
generates the final sumcheck, but the Rust-required opening equality changes by
`delta * (c1 - x*c0)` at query point `x` and rejects generically. The old Solidity verifier omitted
that equality and accepted the two independently valid halves. This construction is confirmed, but
a checked-in malicious-proof fixture has not yet been added; it must not be conflated with the
checked-in dot-preserving duplicate-row negative described below.

The current patch derives the same final commitment parameters used by an intermediate opening,
computes the final folding weights and query evaluation points, and requires
`reduceWithPowers(finalVector, x) == dot(weights, openedRow)` for every raw query
(`SpongefishWhirVerify.sol:363-493`). In split-initial mode it first combines each commitment's row
with the transcript-derived vector RLC, matching the Rust verifier. This is a **critical fix** now
committed in `8f0be2f7e025a17a5a3acb281c14c33d87658932`; the direct malicious-vector regression remains a
release gate even though the frozen full suites are green.

#### WHIR-HINT-CANON — non-canonical field-oracle commitment grinding

Rust reads every opening row through
`prover_hint_ark::<Vec<Field64/Field64_3>>()`. Arkworks' `Fp::from_bigint` rejects each serialized
limb `>= p`. The old Solidity `_dotEqWithRow`, however, hashed the raw row into the authenticated
Merkle leaf and then used `mulmod(..., p)` without a canonicality check. Thus raw `p` was semantic
zero and `p + x` was semantic `x` for small `x`, while their leaf hashes—and therefore the
Fiat-Shamir-absorbed Merkle root—differed from the canonical encoding. A prover with zero/small
oracle entries could grind multiple commitments for one field oracle, violating the Rust proof
language and the commitment uniqueness assumed by the Fiat-Shamir soundness argument.

The base-field branch now rejects `b0 >= p`; the Ext3 branch rejects if any of `b0,b1,b2 >= p`
before arithmetic (`SpongefishWhirVerify.sol:1194-1270`). Test-only calls into that exact internal
decoder cover both encodings, while all real fixtures cover the positive path
(`WhirVerifyTest.t.sol:10-41`). This added 43 bytes under the submodule production profile: the
library runtime is 24,357 bytes, leaving only 219 bytes below EIP-170. That margin is itself a
freeze gate; optimizer/profile drift must be measured rather than assumed.

#### Canonical proof shape and fixed-fixture evidence

All intermediate, final and split opening paths now consume an eight-byte Arkworks `Vec` length
prefix only after checking that it is present and equals `query_count * row_columns`; the old code
blindly advanced eight bytes. The verifier also requires `hintPos == hints.length`, rejecting both
truncated/misaligned encodings through their consuming checks and trailing-hint extensions
(`SpongefishWhirVerify.sol:145-150,819-830,885-973`). Rust's `verify_split`, `verify_aux` and
`verify_with_session` entry points now likewise call `check_eof()` after the final claim; dedicated
negatives append one hint byte and one transcript byte. The fixed checked-in
`close_intent_mle.json` has 76,368 hint bytes, an initial query at index zero, and a duplicated final
query at index 869. Its final-vector prefix begins at byte offset 67,272 and the second serialized
row for that duplicate begins at byte offset 71,888 (`ClaimMleVerify.t.sol:39-45,107-187`). These
sentinels make fixture regeneration explicit rather than letting a changed layout silently weaken
the negatives.

## Lightning protocol lens

The mapping is by failure mechanism, not by claiming INTMAX3 is Lightning or inherits Bitcoin's
exact transaction rules.

| Lightning source | Relevant lesson | INTMAX3 disposition |
|---|---|---|
| [BOLT #5: on-chain transaction handling](https://github.com/lightning/bolts/blob/master/05-onchain.md) | An off-chain state is useful only if the honest party retains the right signed artifact, monitors the chain, broadcasts the right state, and has time/fees to get its remedy confirmed; reorg handling and output resolution are continuing duties. | Motivates an absolute but usable response window, no attacker-only close floor, durable artifact/head storage, and fail-closed refusal to sign from a stale view. `cancelClose` proof possession alone is not a substitute for recoverable close data. |
| [BOLT #2: peer protocol](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) | Commitment advancement is a sequenced state machine: the next update/revocation step is not interchangeable with an independently valid local transition, and both peers must know which state is current. | Motivates the immutable A11/H2 message, nonce-to-current-leaf binding and durable request IDs. It also exposes why M-4 remains open: a Manager MSU and a validity-tree MSU that each verify separately are not yet one atomic protocol transition. |
| [lnd PR #10331](https://github.com/lightningnetwork/lnd/pull/10331) | Closure observation is a state machine: wait for an appropriate confirmation depth, consume negative-confirmation/reorg events, and re-register when a different spend confirms. The PR also states that deeper post-confirmation reorg recovery remains special work. | B-3 remains open. A snapshot or one observed finalization must not become irrevocable local authority. The production watcher needs a persisted L1 lifecycle state machine that can invalidate/reconcile a recovered snapshot after reorg, rather than a one-shot “seen” flag. |
| [Flood & Loot](https://arxiv.org/abs/2006.08513) | A remedy that is valid in isolation can fail systemically when many channels must land time-sensitive transactions in scarce block space; fee and replacement policy are part of security. | The close response interval must include proof-generation and congested inclusion budget. Stress/fault testing must model many simultaneous closes and retries; a nominal wall-clock challenge period is not itself proof of exit liveness. |
| [Time-Dilation Attacks](https://arxiv.org/abs/2006.01418) | Delaying a victim's chain view shortens the effective reaction window and can turn a correct timelock design into fund loss. | Canonical-head freshness, independent observation, clock/chain-lag alarms and refusal to sign from stale lifecycle state are release requirements. The absolute horizon prevents an attacker from extending time forever, but it cannot protect a signer whose view is delayed for most of the horizon. |
| [BOLT issue #783: mempool pinning](https://github.com/lightning/bolts/issues/783) and [replacement cycling disclosure](https://delvingbitcoin.org/t/full-disclosure-replacement-cycling-attacks-on-bitcoin-miners-block-templates/1405) | A valid remedy can still be censored by transaction-policy interactions, replacements and adversarial descendants; repeated rebroadcast/replacement behavior must be part of the threat model. | Bitcoin's mempool rules are not inherited by EVM contracts, so these are not claimed as direct exploits. The analogous INTMAX3 surfaces are repeated permissionless pending-chain pins, one-slot PW occupation, transaction replacement/receipt journals, gas/fee budgeting and inclusion before one absolute deadline. They remain production liveness gates rather than being dismissed because each transaction is valid in isolation. |

## Residual blockers and accepted hardening

| ID | Release disposition | Required action |
|---|---|---|
| KZG-DA | **NO-GO** | Pin fixed-domain Ethereum-ceremony setup data immutably and test the real pairing route, or disable pre-timeout KZG fraud verification consistently in contract, deploy scripts and clients. Add a proof/blob size-domain bound. |
| FRAUD-VERDICT | **NO-GO** | Redesign the verifier boundary so an invalid committed proof produces an authenticated invalid verdict without turning OOG or an evaluator bug into fraud. Today the production `MleVerifier.verify` enters at `MleVerifier.sol:169-177`, reaches only `return true` on the core success path (`:185-255`), and otherwise reverts in that core or its helpers. `_verifyFraud` convicts only `MLE_INVALID` (`IntmaxRollup.sol:2027-2050`), which itself requires the external call to return `false` (`:2149-2155`). The green “invalid proof is convictable” tests use a synthetic `RejectingMleVerifier`; they do not make this production verdict reachable. |
| WITHDRAW-DA | **NO-GO** | Implement lossless proof DA and a production lifecycle importer. `cmd_withdraw` refuses non-31337 chains because it attaches a zero demo blob and the current field-mask packing is not reversible (`src/bin/channel_member.rs:3535-3544`). That diagnostic hardcodes the current checked-in proof as 131,264 bytes / 192 bytes over one blob; independently measure the regenerated frozen artifact and record it below rather than treating this mutable-tree number as final. |
| ARTIFACT-JOIN | **NO-GO** | Regenerate VKs and all affected fixtures from the frozen tree; run real Rust proof → deployed Solidity verifier joins and reject every skip. Record hashes. |
| WHIR-MERKLE-ALIAS | **FIXED/FROZEN** | `SpongefishMerkle.verify` intentionally reuses caller arrays as alternating scratch buffers. The old post-verification duplicate check therefore read internal nodes rather than the authenticated leaf set, causing about 1.48% honest close-proof rejection and skipping equality for most duplicate indices. The patch compares equal-index leaf hashes during sort/dedup, before Merkle mutation (`SpongefishWhirVerify.sol:641-668`). The real close fixture hits initial index zero and final duplicate index 869; frozen `ClaimMleVerifyTest` passed 8/8, including honest acceptance and a dot-preserving mismatched-second-row rejection. |
| WHIR-FINAL-BINDING | **CRITICAL, FIXED/FROZEN; direct attack fixture still required** | The old final phase authenticated a Merkle opening and checked `finalVector` without ever equating them, so the final commitment could represent a different polynomial. The patch checks every opened row against `finalVector` at its transcript-derived evaluation point and implements the Rust vector-RLC rule for split commitments (`SpongefishWhirVerify.sol:363-493`). Add the explicit `Delta = (delta*c1,-delta*c0)` malicious-vector proof fixture and prove old-Solidity acceptance/new-Solidity and Rust rejection before release. The existing duplicate-row negative is related coverage but is not that attack fixture. |
| WHIR-PROOF-SHAPE | **FIXED/FROZEN; short-input coverage open** | Every serialized Arkworks `Vec` prefix must equal the expected row-element count; Solidity requires exact hint/transcript EOF, and Rust now calls `check_eof()` in split/aux/legacy verification (`SpongefishWhirVerify.sol:145-150,819-830,885-973`; `whir_pcs.rs:460-467,622-629,822-829`). Frozen negatives reject a wrong final prefix and trailing hint/transcript bytes. Add explicit short/misaligned-input coverage. |
| WHIR-HINT-CANON | **HIGH, FIXED/FROZEN** | Solidity formerly hashed raw opening bytes but reduced non-canonical limbs modulo `p`, unlike Rust's Arkworks decoder. This gave zero/small field values alternate Merkle/Fiat-Shamir commitments. Base and every Ext3 limb now reject `>= p` before arithmetic (`SpongefishWhirVerify.sol:1194-1270`); direct production-decoder regressions pass in `WhirVerifyTest` 9/9. |
| DEPLOY-DELEGATES | **NO-GO before delegate-bearing production use** | `DeployCloseCli` passes the settlement record's `activeDelegateCount` into the Manager (`contracts/script/DeployCloseCli.s.sol:247-275`), while keeping the separate L1 registration count zero as the validity circuit requires. But the only real-chain producer hardcodes the settlement count to zero and emits no delegate bindings (`src/bin/channel_member.rs:4011-4057`); the script itself admits that the Manager floor is vacuous (`DeployCloseCli.s.sol:262-266`). The immutable deployment-time floor also cannot follow a later delegate join. Even after authenticating the initial live count/bindings, the Manager constructor currently requires members + delegates `<= 8` (`ChannelSettlementManager.sol:911-915`), while the close verifier/Rust balance model permits 1,024 total participants (`ChannelSettlementVerifier.sol:46-55,351-360`). Refuse delegate-bearing use unless joins are frozen or an authenticated monotone Manager update follows each join, and make the 8-participant cap an explicit product restriction or reconcile it in code. |
| B-3 / L1 head | **NO-GO** | Pass authenticated expected channel/lifecycle/era/head into snapshot recovery and persist a reorg-aware canonical-head state machine. |
| WATCHER-REORG | **NO-GO for production relay** | Persist canonical block hashes and a rollback/LCA journal. `ChainWatcher.pollOnce` advances only a numeric cursor after a confirmation offset (`node/common/chain-watcher.js:206-246`); it cannot detect or unwind a reorg that replaces already-processed logs. The payout driver is stronger than the old one-receipt description: it persists the exact caller/nonce/target/calldata intent, scans current canonical blocks for a crash-window transaction, validates a nonzero block hash and atomic postconditions (`src/bin/channel_member.rs:8074-8080,8688-8778,8829-8890`; `src/partial_withdrawal_payout.rs:822-918`). It still records completion after the first mined receipt, with no confirmation-depth threshold or post-restart canonical-block revalidation/rollback. Add those rather than discarding the existing exact-intent journal. |
| EXIT-CRASH | **NO-GO for unattended operation** | Journal and recover the cross-file/on-chain boundaries. Burn-send commits `cli_state` before `last_burn.json` (`channel_member.rs:5810-5869`), and `pw-submit` broadcasts before writing `pw_auth.json` (`:7974-8028`). A crash in either window strands the next step despite a committed state/transaction. |
| SERVICE-JOURNALS | **Production gate** | Add explicit abort/retry state for deterministic child rejection. The local nonce reservation correctly stays sticky for ambiguous execution, but a fully authenticated deterministic pre-sign rejection can also occupy it permanently. Likewise, API `prepared`/`burn_pending` records can poison retries unless deterministic rejection rolls them back or records a terminal reason. |
| M-4 | **NO-GO before MSU production use** | Atomically bind `ChannelSettlementManager.applyMemberSetUpdate` (`ChannelSettlementManager.sol:1033-1112`) to the validity-tree `MemberSetUpdate` transition (`update_channel_tree.rs:1288-1563`) or enforce one authenticated cross-layer receipt. Two independently valid roots are not one transition. |
| M-9 | **NO-GO product decision** | Decide which currently unsigned close fields must be member-authorized. Implement the chosen detached-signing/L1-pin design and preserve the intended unilateral-close property explicitly. Current characterization is in `src/common/channel.rs:1029-1042,1137-1158`, `close_pis.rs:54-76`, and `close_circuit.rs:688-706`. |
| H-8 fresh backing | **NO-GO for production relay** | Make the API and Node deposit flows install and require the live backing artifact before co-signing; do not leave it as an optional CLI flag or operator convention. |
| PENDING-PIN | **Production liveness gate** | Bind or authorize `pendingChainsPin`, or make proof construction tolerant of a competing pin. The permissionless pin can be front-run to force reproving and can repeatedly censor a prepared submitter without stealing state. |
| PW-SINGLETON | **Production liveness gate** | Add per-burn queuing/rate policy. The Manager has one pending partial-withdrawal slot, so a valid distinct minimal burn can occupy the challenge window and delay another member. |
| SIGNED-HEAD FORKS | **Conditional design risk, not a reproduced exploit** | Under the intended one-honest-member N-of-N path, no late-outgoing double draw was reproduced. If all N signers collude or a custom producer can equivocate, however, `ChannelLeaf` does not commit the complete signed-head digest/version. The new TxV2 nonce binding prevents base-H2 replay after its cursor advances, but it is not a proof that arbitrary signed-head forks are impossible. Specify the threat model and bind any stronger head invariant before claiming it. |
| KEY/EXIT MODEL | **Product gate** | Document and mitigate that ordinary channels require all N cosigner keys, the operator commonly holds all N in the current deployment flow, and delegates have no unilateral exit. These are custody/availability properties, not ZKP soundness claims. |
| Registration authority | Operational gate | Replace the immutable deployer hot/cold-key dependency with a bounded, rotatable registrar process, while preserving anti-squatting and one-shot registration. |
| Duplicate Regev digest | Hardening, not theft blocker | Reject duplicate active Regev digests when code-size policy permits, or document that duplicates intentionally collapse claims and can self-lock funds. Do not describe it as a theft fix under the current nullifier. |
| Multi-host nonce | Deployment gate when applicable | The implemented disk lock is atomic among local processes sharing the reservation path. A horizontally scaled relay requires a single writer or shared transactional reservation service. |
| Compatibility nonce builders | **FIXED in integration / freeze check** | Public inter-channel and burn compatibility builders now require `prev_user_leaf_index` explicitly and forward that cursor unchanged (`src/wallet_core.rs:2337-2435,2809-2875`); the burn-nullifier documentation uses the same `prev_user_leaf.index` equation (`:3939-3957`). The incoming-only regression proves `small_block_number + 1` has diverged while both builders retain nonce zero (`:9948-10036`). Re-run it from the frozen tree. |
| Burn nonce test oracle | **FIXED in integration / freeze check** | Production `pw-submit` reads the explicit `base_nonce`/legacy-named `tx_nonce` from `last_burn.json`, bounds it to `u32`, and refuses to reconstruct it from the channel counter (`src/bin/channel_member.rs:7777-7789`). The integration test now independently asserts `TxV2.nonce = 0` from the supplied prior base leaf while the post-burn `small_block_number = 1` (`tests/inter_channel_cli.rs:591-602`), replacing its stale equality. Re-run from the frozen tree. |
| Deployment fixture parser | **FIXED/FROZEN** | `FixtureLib.countGates` now decodes the actual `.gates` dynamic-array length, requires `1..64`, and requires a uint `gateId` for every present element (`contracts/script/FixtureLib.sol:234-260`). This distinguishes EOF from malformed rows and closes both the terminal-malformed and `malformed row64 + hidden row65` bypasses. Block numbers, WHIR generators and Ext3 limbs are range/canonicality checked through shared helpers (`:106-115,272-280,329-379`). The 17-case guard covers all listed boundaries and passed inside the final 473/37 no-skip guard; authenticating every production fixture hash remains separate. |
| Script-local JSON narrowing | Operator input gate | The `FixtureLib` fix is not a repository-wide checked-cast abstraction. `RunC2C.s.sol:26-27,48,61-64,86,108`, `RunClose.s.sol:31-34,56,125,139-152,189-193,220,250-252`, and `RunPartialWithdrawalPayout.s.sol:31` still narrow JSON values with Solidity casts. Proof-bound mismatches normally fail closed, and the other affected scripts are classified below as demo/legacy, but aliases still undermine human review of an unauthenticated manifest. Do not promote them to a production runbook without checked conversions and frozen input hashes. |
| MLE submodule fixture fidelity | Release-evidence gate | Seven of the eight checked-in JSON fixtures under `contracts/lib/polygon-plonky2/mle/contracts/test/fixtures/` — exactly the seven exercised by current `MleE2ETest.t.sol:26-57` — serialize `whirParams.numCommitments = 2` (for example `small_mul.json:1379`), while the current verifier path expects four. The eighth, legacy `xlarge_mul.json`, omits that key and is not exercised by the suite. `MleE2ETest` overwrites the parsed field with four (`:122-130`); `BoundaryCheckTest` and `WhirVerifyTest` do the same (`BoundaryCheckTest.t.sol:274-284`; `WhirVerifyTest.t.sol:208-214,246-251`). A green submodule Forge run therefore proves acceptance under a test-patched parameter, not exporter/fixture fidelity. Regenerate the seven live fixtures, remove the overrides and assert the serialized value; migrate or remove the unused legacy fixture explicitly. The parent fixture already serializes four (`contracts/test/data/mle_fixture.json:1948`). |
| Test guard floor | **FIXED/FROZEN PASS** | `.github/ci/forge-test-guard.sh:25-31,69-79` requires 473 tests/37 suites and explicitly requires all 8 `ClaimMleVerify`, 7 `AuthorizedBurnFenwick` and 17 `FixtureParsingGuards` cases. The final frozen-source run passed 473/473 across 37 suites with zero skips and every named floor satisfied. |
| Fixed-width comments | **RESOLVED in integration / freeze check** | Current comments distinguish the 8-slot cosigner/signature cluster from the 1,024-slot balance-participant tree and describe the Solidity legacy constant name without asserting a mismatch (`src/constants.rs:68-110`; `src/common/channel.rs:1693-1707`; `ChannelSettlementManager.sol:181-186,994-998`; `ChannelSettlementVerifier.sol:42-55`; `IntmaxRollup.sol:1190-1194`). Recheck the frozen diff so documentation-only cleanup cannot be mistaken for a runtime-cap change. |

## Per-file circuit review disposition

Disposition labels in this inventory are intentionally narrow:

- **HOLD** — no new file-local soundness defect identified; still inherits the global artifact/join
  release gate.
- **FIXED** — the integrated tree contains the reviewed load-bearing fix/regression.
- **OPEN** — this file participates in an unresolved release/design issue.
- **DISABLED** — code remains, but the production entry point is intentionally unreachable; it is
  not approved for re-enablement.
- **GLUE** — module/re-export/test support with no independent predicate.

Every Rust file under `src/circuits/**/*.rs` is named exactly once below: **64/64**.

### Balance circuits

| File | Disposition |
|---|---|
| `src/circuits/balance/balance_circuit.rs` | **HOLD** — recursive balance transition selector/composition reviewed; no new free PI or cross-circuit substitution found. |
| `src/circuits/balance/balance_pis.rs` | **HOLD** — PI ordering/length and verifier-data split are explicit; deployed joins must pin the exact regenerated layout. |
| `src/circuits/balance/balance_processor.rs` | **HOLD** — genesis/transition recursion composition; no independent finding. |
| `src/circuits/balance/common/account_state.rs` | **HOLD** — account nonce/tree state encoding; outgoing nonce is also guarded at the live service boundary. |
| `src/circuits/balance/common/deposit_witness.rs` | **HOLD** — deposit witness fields and hash-chain inputs; production receipt/canonical-head authority remains an external requirement. |
| `src/circuits/balance/common/mod.rs` | **GLUE** — module surface only. |
| `src/circuits/balance/common/recipient.rs` | **HOLD** — UID/address recipient derivation and domain separation reviewed. |
| `src/circuits/balance/common/transfer_witness.rs` | **HOLD** — transfer index/leaf witness binding; no new issue. |
| `src/circuits/balance/common/tx_settlement.rs` | **HOLD** — settled-chain fold reviewed against channel-side canonical transfer construction. |
| `src/circuits/balance/common/update_private_state.rs` | **HOLD** — private-state update and token index binding; no new issue. |
| `src/circuits/balance/common/update_public_state.rs` | **HOLD** — public root/nonce advancement; exact fixture join remains mandatory. |
| `src/circuits/balance/mod.rs` | **GLUE** — module surface only. |
| `src/circuits/balance/receive_deposit_circuit.rs` | **HOLD** — receipt/deposit-chain absorption; freshness and reorg handling are service-level B-3/H-8 blockers. |
| `src/circuits/balance/receive_transfer_circuit.rs` | **HOLD** — incoming transfer and settled-chain binding reviewed; no independent bypass found. |
| `src/circuits/balance/send_tx_circuit.rs` | **HOLD** — send nonce/transfer commitment binding; live duplicate allocation is fixed locally and must be single-writer across hosts. |
| `src/circuits/balance/spend_circuit.rs` | **HOLD** — spend validity switch and private commitment; no new issue. |
| `src/circuits/balance/switch_board.rs` | **HOLD** — recursive branch selection; no branch-forgery finding after PI/VK binding review. |

### Channel circuits

| File | Disposition |
|---|---|
| `src/circuits/channel/cancel_close_circuit.rs` | **HOLD** — strict newer-version, era/digest and registered-member proof statement; current anti-replay floor is correctly enforced at Manager consumption, not as a close floor. |
| `src/circuits/channel/cancel_close_pis.rs` | **HOLD** — 27-limb corrected statement matches the Solidity strict binder; opaque revived-state data remains a recovery concern, not a permanent lock proof. |
| `src/circuits/channel/close_circuit.rs` | **OPEN (M-9)** — state signatures/H1/funds/member-set bindings hold, but the documented free close-intent fields are not member-authorized; do not call `closeIntentDigest` an N-of-N authorization. |
| `src/circuits/channel/close_pis.rs` | **OPEN (M-9)** — correctly documents the unsigned/free PI fields; requires the product-level signing/L1-pin decision. |
| `src/circuits/channel/decryption_gadget.rs` | **HOLD** — ciphertext/key/canonical remainder constraints and `< q` discipline reviewed; no alias-based withdrawal bypass found. |
| `src/circuits/channel/e2e_flow.rs` | **GLUE** — circuit E2E construction/test support; not a separate deployed predicate. |
| `src/circuits/channel/h1_gadget.rs` | **HOLD** — fixed-width H1 header, token registry/count and slot-tree commitment reviewed. |
| `src/circuits/channel/member_set_update_circuit.rs` | **OPEN (M-4 integration)** — circuit-local old-set N-of-N, structural delta and new commitment hold; Manager/validity-tree atomicity is not established by this proof alone. |
| `src/circuits/channel/mod.rs` | **GLUE** — module surface only. |
| `src/circuits/channel/post_close_claim_circuit.rs` | **DISABLED** — statement lacks “incoming delta was unapplied”; Manager entry permanently reverts. Re-enablement requires a new signed unapplied commitment or split accumulator. |
| `src/circuits/channel/post_close_claim_pis.rs` | **DISABLED** — retained ABI/PI scaffolding only; not a release-approved claim path. |
| `src/circuits/channel/state_update_verifier.rs` | **FIXED/HOLD** — channel linkage, recipients, Regev digests and registry are frozen across ordinary transitions; dedicated token/MSU paths are separated. |
| `src/circuits/channel/withdrawal_claim_circuit.rs` | **HOLD** — slot leaf, Regev decryption, recipient, token and final-H1 bindings reviewed; duplicate Regev remains self-loss hardening. |
| `src/circuits/channel/withdrawal_claim_pis.rs` | **HOLD** — public amount/token/nullifier layout requires the exact real Solidity join. |

### Circuit root and test support

| File | Disposition |
|---|---|
| `src/circuits/mod.rs` | **GLUE** — top-level module surface. |
| `src/circuits/test_utils/mod.rs` | **GLUE** — test-only construction utilities; tests using it are not substitutes for real proof/deployment joins. |

### Validity block-hash-chain circuits

| File | Disposition |
|---|---|
| `src/circuits/validity/block_hash_chain/block_chain_pis.rs` | **HOLD** — initial/final block-chain and extended-state PI serialization reviewed. |
| `src/circuits/validity/block_hash_chain/block_hash_chain_circuit.rs` | **HOLD** — recursive block-chain composition; changed descendants require regenerated artifacts. |
| `src/circuits/validity/block_hash_chain/block_hash_chain_processor.rs` | **HOLD** — witness-to-proof orchestration, including optional member-set witnesses, reviewed. |
| `src/circuits/validity/block_hash_chain/block_step.rs` | **HOLD** — one-block transition composition and channel-update plumbing; no independent bypass found. |
| `src/circuits/validity/block_hash_chain/channel_state_message.rs` | **HOLD** — IMCH target construction binds the block's own channel/H2 wires rather than free duplicates. |
| `src/circuits/validity/block_hash_chain/ext_public_state.rs` | **HOLD** — cumulative extended-state commitment fields reviewed. |
| `src/circuits/validity/block_hash_chain/mod.rs` | **GLUE** — module surface only. |
| `src/circuits/validity/block_hash_chain/nofn_attack.rs` | **FIXED regression** — adversarial signer-count/member-root cases pin the N-of-N and registered-set constraints. |
| `src/circuits/validity/block_hash_chain/small_block_message.rs` | **HOLD** — immutable message binds channel/sequence/H1/H2/era; A11 correctly hashes this message, not carrier blobs. |
| `src/circuits/validity/block_hash_chain/update_channel_tree.rs` | **FIXED / OPEN (M-4 integration)** — signed `TxV2.nonce` is bound to the current base-send leaf index; `small_block_number` intentionally remains an independent channel-sequence counter. Member-set delta constraints are present, but the separate Manager transition still needs atomic cross-layer authority. |
| `src/circuits/validity/block_hash_chain/validity_circuit.rs` | **HOLD** — final validity composition/PI binding reviewed; the circuit change makes exact-tree VK/fixture regeneration a release gate. |

### Channel-registration validity circuits

| File | Disposition |
|---|---|
| `src/circuits/validity/channel_reg_hash_chain/channel_reg_chain_pis.rs` | **HOLD** — registration-chain PI ordering reviewed. |
| `src/circuits/validity/channel_reg_hash_chain/channel_reg_chain_processor.rs` | **HOLD** — native processor mirrors registered leaf construction. |
| `src/circuits/validity/channel_reg_hash_chain/channel_reg_hash_chain_circuit.rs` | **HOLD** — recursive registration-chain fold; no overwrite/re-registration path found in this layer. |
| `src/circuits/validity/channel_reg_hash_chain/channel_reg_step.rs` | **FIXED with hardening note** — pkG/pkB/Regev leaf cross-binding, canonical encodings, zero delegates and active padding are enforced across native/L1/circuit boundaries. The circuit negative deliberately bypasses native validation so the `delegate_count == 0` constraint itself remains tested. Duplicate Regev distinctness is not enforced and is classified as availability/self-loss hardening. |
| `src/circuits/validity/channel_reg_hash_chain/mod.rs` | **GLUE** — module surface only. |

### Deposit validity circuits

| File | Disposition |
|---|---|
| `src/circuits/validity/deposit_hash_chain/deposit_chain_pis.rs` | **HOLD** — deposit-chain PI ordering reviewed. |
| `src/circuits/validity/deposit_hash_chain/deposit_chain_processor.rs` | **HOLD** — native/circuit chain orchestration; pending-chain rollback fix is in Solidity. |
| `src/circuits/validity/deposit_hash_chain/deposit_hash_chain_circuit.rs` | **HOLD** — recursive hash-chain fold; exact artifact join required. |
| `src/circuits/validity/deposit_hash_chain/deposit_step.rs` | **HOLD** — deposit leaf/previous-chain linkage reviewed. |
| `src/circuits/validity/deposit_hash_chain/mod.rs` | **GLUE** — module surface only. |
| `src/circuits/validity/mod.rs` | **GLUE** — validity module surface. |

### Withdrawal circuits

| File | Disposition |
|---|---|
| `src/circuits/withdraw/mod.rs` | **GLUE** — module surface only. |
| `src/circuits/withdraw/single_withdrawal_circuit.rs` | **HOLD** — one withdrawal leaf/nullifier/amount statement reviewed. |
| `src/circuits/withdraw/withdrawal_chain_circuit.rs` | **HOLD** — withdrawal-chain recursive fold reviewed. |
| `src/circuits/withdraw/withdrawal_circuit.rs` | **HOLD** — aggregate withdrawal proof and PI construction; real Solidity join remains mandatory. |
| `src/circuits/withdraw/withdrawal_processor.rs` | **HOLD** — proof orchestration; no independent authorization bypass found. |
| `src/circuits/withdraw/withdrawal_step.rs` | **HOLD** — per-step root/nullifier transition reviewed. |

### Witness generators

| File | Disposition |
|---|---|
| `src/circuits/witness/balance_witness_generator.rs` | **HOLD** — balance witness construction follows circuit fields; stale/canonical L1 authority remains outside the witness. |
| `src/circuits/witness/block_witness_generator.rs` | **FIXED/HOLD** — production MemberSetUpdate action and member-root advancement path are present; M-4 remains the external atomicity seam. |
| `src/circuits/witness/mod.rs` | **GLUE** — witness module surface. |

## Per-file Solidity review disposition

Every first-party file matching `contracts/src/*.sol` is named exactly once: **5/5**.

| File | Disposition |
|---|---|
| `contracts/src/BlobKZGVerifier.sol` | **OPEN / NO-GO** — EIP-2537 address/encoding fixes are present, but caller-controlled trusted-setup elements make the opening unsound as DA binding. Keccak preconditions bound conviction impact to liveness/grief. |
| `contracts/src/ChannelSettlementManager.sol` | **OPEN (M-4/M-9), otherwise HOLD** — real close/cancel/MSU/PW gates and bounded close lifecycle are active; post-close claim is disabled. Manager member-set mutation is not atomic with validity-tree mutation, and close-intent unsigned fields remain a design decision. |
| `contracts/src/ChannelSettlementVerifier.sol` | **HOLD** — close, cancel, withdrawal and MSU public limbs are strictly rebound and real MLE verification is invoked. Post-close verifier is unreachable through the Manager. Exact final VK/rail joins remain release gates. |
| `contracts/src/IntmaxRollup.sol` | **FIXED registration / OPEN / NO-GO** — finalization/rollback/withdrawal binding fixes hold; registration is deployer-only, zero-delegate and canonical-Goldilocks fail-closed. Active KZG DA unsoundness, unreachable invalid fraud verdict and absent explicit blob-proof size/domain gate remain. The deployer registrar is an operational dependency. |
| `contracts/src/SafeERC20.sol` | **HOLD** — low-level return-data handling reviewed; no independent token-transfer bypass found. Token-specific nonstandard behavior still belongs in deployment allowlisting. |

## Per-file Solidity deployment/input review disposition

Every Solidity file directly under `contracts/script/` is named exactly once: **16/16**. A script
that uses a real verifier is still not proof that its fixture, target address, RPC view or signing
key came from the intended frozen deployment; those are separate operator input boundaries.

| File | Disposition |
|---|---|
| `contracts/script/Deploy.s.sol` | **PRODUCTION INPUT / inherits NO-GO** — deploys the real rollup and real validity/withdrawal rails with production MLE enabled, but also enables the unsound caller-parameterized KZG satellite; final artifacts, treasury, producer and chain must be manifest-pinned. |
| `contracts/script/DeployC2C.s.sol` | **DEMO / PUBLIC-TESTNET ONLY** — real validity and withdrawal verification, but fixture-driven and without an explicit supported-chain allowlist; not a mainnet deployment runbook. |
| `contracts/script/DeployClose.s.sol` | **DEVNET ONLY** — guarded to chain 31337 and deliberately omits settlement VKs; useful for address/lifecycle dry runs, never production evidence. |
| `contracts/script/DeployCloseCli.s.sol` | **NO-GO for delegate-bearing channels** — the real settlement deploy path initializes the required VKs and registers its Manager, but its current real-chain record producer supplies zero active delegates and no bindings, leaving the B-2 delegate floor vacuous (`:247-275`; `channel_member.rs:4011-4057`). The immutable floor cannot follow later joins, and the Manager additionally caps members + delegates at eight. The separate L1 registration delegate count must remain zero. |
| `contracts/script/DeployConfig.sol` | **HOLD / POLICY HELPER** — selects a 1-second local window and the 86,400-second public-chain floor, which the Manager independently enforces; it does not authenticate an RPC, chain deployment or contract address. |
| `contracts/script/DeployPartialWithdrawalE2E.s.sol` | **DEVNET MOCK ONLY** — always-true settlement verifier and short challenge window are guarded to chain 31337; a green flow is lifecycle/binding evidence, not proof-soundness evidence. |
| `contracts/script/DeployTestnetBlockProducer.s.sol` | **TESTNET ONLY / OPERATOR GATE** — deploys real rails but has no positive testnet-chain allowlist and defaults a testnet producer address; a reviewed manifest must prevent accidental mainnet use. |
| `contracts/script/DeployWalletSettlement.s.sol` | **DEVNET MOCK ONLY** — chain-31337 guard contains its always-true verifier; it exercises delegate-bearing Manager wiring but supplies no production cryptographic assurance. |
| `contracts/script/Finalize.s.sol` | **PRODUCTION SMOKE INPUT** — drives real `finalize`, but selects the rollup and fixture via environment/files without a deployment-manifest hash; pin both before broadcast. |
| `contracts/script/FixtureLib.sol` | **FIXED INPUT BOUNDS / PRODUCTION PROVENANCE GATE** — the parser reads the actual `.gates` array length, requires `1..64`, and validates every present row's uint `gateId` before materializing all remaining fields with checked widths (`:215-280`). Validity block numbers, WHIR generators and Ext3 limbs are checked before narrowing; field elements must be canonical Goldilocks values `< P` (`:106-115,272-280,329-379`). This closes the reproduced truncation/alias class; production still must authenticate exact frozen input hashes before broadcast. |
| `contracts/script/RegRecordLib.sol` | **FIXED SHAPE / NOT LIVENESS AUTHORITY** — rejects narrow-integer truncation, nonzero registration delegates and inconsistent arrays, but cannot establish that `active_delegate_count` is the live authenticated channel count. |
| `contracts/script/RegisterTokens.s.sol` | **PRODUCTION INPUT / HOLD** — chain ID, rollup address, u32 indices, uniqueness, array overflow and readback are fail-closed; token allowlisting and manifest provenance remain operator decisions. |
| `contracts/script/RunC2C.s.sol` | **DEMO / PUBLIC-TESTNET DRIVER** — sends real registration/finalization/withdrawal calldata from fixtures, but lacks a supported-chain/deployment manifest, contains unchecked JSON downcasts, and is not a durable reorg-aware journal. |
| `contracts/script/RunClose.s.sol` | **LEGACY / MIXED** — real proof-bearing calls coexist with a still-advertised `submitPostCloseClaimStep` that can only revert, independently supplied `ROLLUP`/`MANAGER` addresses and numerous unchecked JSON downcasts; do not use as the production close runbook without checked parsing and target preflight. |
| `contracts/script/RunPartialWithdrawalPayout.s.sol` | **PRODUCTION TRANSACTION BUILDER / OPEN INPUT+REORG GATE** — builds the exact proof-backed payout used by the Rust nonce/calldata journal, but narrows JSON `token_index` without a pre-cast check and neither this script nor one matching receipt establishes finality/canonicality. Freeze/hash both fixture inputs, add checked parsing and retain the exact-intent journal. |
| `contracts/script/SubmitPartialWithdrawal.s.sol` | **DEVNET E2E ONLY** — chain-31337 guard now runs before fixture reads; remaining fixture casts are contained by the local-only boundary and proof/Manager checks. |

## Per-file first-party Solidity test disposition

The recursive current inventory is **44/44 Solidity files** under `contracts/test/`: 42 at the
directory root plus two token-support contracts under `contracts/test/tokens/`. This is one more
than the earlier 43-file observation because `FixtureParsingGuards.t.sol` was added during
integration. The table distinguishes real production-verifier joins from lifecycle tests that use
an always-true/controllable verifier, and calls out suites that can skip when fixtures are absent.

| File | Disposition |
|---|---|
| `contracts/test/AuthorizedBurnFenwick.t.sol` | **MODEL REGRESSION / MOCK MLE** — exercises authorized-burn high-water accounting; its final test explicitly preserves the known limitation that outgoing value after the latest burn is unobserved. |
| `contracts/test/BlobKzgPairing.t.sol` | **REAL SATELLITE REGRESSION** — checks the deployed pairing precompile/address and well-formed/tampered opening equations, but synthesizes the versioned hash in-test and calls the satellite directly (`:109-134,156-191`). It neither cures caller-controlled trusted-setup parameters nor proves EIP-4844 blob inclusion/availability. |
| `contracts/test/C2CBlockHash.t.sol` | **FIXTURE HASH DIFFERENTIAL, NO PROOF / SKIP-SENSITIVE** — replays registration/deposit/posting and compares the on-chain hash chain with the Rust-produced expected value, but never calls `finalize` or verifies a proof (`:9-15,43-67,91-105`). Absence sets `ready=false` and the test skips. `blobhash(0)` is mocked (`:46-48`), so it adds no blob-DA/canonicality evidence. |
| `contracts/test/C2CFullE2E.t.sol` | **REAL E2E, SKIP-SENSITIVE** — real validity plus withdrawal verification through a C2C lifecycle; every security conclusion depends on the frozen fixtures being present and no skip occurring. `blobhash(0)` is mocked on both postings (`:64-66,125-127`), so the proof/contract join is real but EIP-4844 availability and canonical inclusion are not tested. |
| `contracts/test/ChannelSettlementAdversarial.t.sol` | **ACCOUNTING/LIFECYCLE, MOCK MLE** — useful adversarial cap, pull and credit checks through real Manager state transitions; it does not test WHIR soundness. |
| `contracts/test/ChannelSettlementInvariant.t.sol` | **STATEFUL INVARIANT, MOCK MLE** — exercises conservation/lifecycle invariants with a controllable verifier; non-vacuity and handler call coverage must be retained. |
| `contracts/test/ChannelSettlementManager.t.sol` | **BINDING/LIFECYCLE, MOCK MLE** — extensive strict-limb, member, deadline and accounting coverage, but comments correctly state that the cryptographic verdict is stubbed. |
| `contracts/test/ClaimMleVerify.t.sol` | **REAL MLE + WHIR REGRESSION, PARTIAL JOIN** — real withdrawal-claim, post-close, cancel-close and close fixtures reach `MleVerifier`, including transcript tamper rejection. The close fixture pins a 76,368-byte hint layout, initial query zero, final duplicate index 869, final `Vec` prefix offset 67,272 and duplicate-row offset 71,888. Negatives reject a dot-preserving mismatched duplicate row, wrong `Vec` length and trailing hints (`:39-45,107-187`). The frozen suite passed 8/8. It still is not the Manager's full public-input binding path, post-close remains disabled, and it does not contain the direct malicious `finalVector` attack proof. |
| `contracts/test/CloseE2EBase.sol` | **TEST SUPPORT** — fixture/deployment helpers for real close E2Es; contains no independent test or production predicate. |
| `contracts/test/CloseExitLivenessInvariant.t.sol` | **LIVENESS INVARIANT, MOCK MLE** — adversarial close/PW state-machine exploration; cannot establish real proof acceptance or real-chain inclusion. |
| `contracts/test/CloseLifecycleE2E.t.sol` | **REAL MULTI-RAIL E2E, SKIP-SENSITIVE** — real validity, aggregate withdrawal and close proof reach `finalizeClose`; it self-skips only when an explicitly probed close fixture is absent (`:47-67`). A stale Manager address or member-set binding hard-fails (`:73-108,152-184`). It deliberately stops before a real withdrawal-claim through the Manager because that claim/VK is not yet co-generated with this lifecycle (`:244-260`), so it is not a full close-to-member-payout join. `blobhash(0)` is mocked (`:324-328`), so this is not blob-DA or canonical-inclusion evidence. |
| `contracts/test/CloseLifecycleHardening.t.sol` | **LIFECYCLE REGRESSION, MOCK MLE** — pins cancel/reclose, absolute deadlines, burn ordering and disabled post-close behavior; proof cryptography is outside its scope. |
| `contracts/test/CloseLifecycleRedTeam.t.sol` | **ADVERSARIAL LIFECYCLE, MOCK MLE** — captures reproduced/refuted close, cancel and ladder attacks; passing results are state-machine evidence only. |
| `contracts/test/CloseManagerAddr.t.sol` | **POINTER ONLY** — intentionally contains no test; it redirects address generation to the linking context inside `CloseLifecycleE2E.t.sol`. |
| `contracts/test/CloseSettlementBase.sol` | **MOCK TEST SUPPORT** — common Manager/registry/proof builders wire `MockMleVerifier`; inherited tests must not be described as real proof joins. |
| `contracts/test/CloseTestLib.sol` | **MOCK TEST SUPPORT** — defines the always-true verifier and sparse proof builders; no production assurance by itself. |
| `contracts/test/DeployGuards.t.sol` | **DEPLOYMENT-WIRING REGRESSION, MIXED** — executes real scripts/chain guards and checks required VK wiring, but settlement cryptography in its harness is mocked and fixture substitution is deliberate. |
| `contracts/test/ExponentiationGate.t.sol` | **REAL EVALUATOR REGRESSION** — bit-exact gate-8 vectors, dispatcher and malformed cases; vector generation provenance must still be reproducible from the frozen submodule. |
| `contracts/test/ExponentiationGateAdversarial.t.sol` | **REAL EVALUATOR ADVERSARIAL** — checks large widths, bounds, trailing wires and dispatcher behavior against the deployed evaluator; not a full proof join. |
| `contracts/test/ExponentiationGateVectors.sol` | **VECTOR SUPPORT / PROVENANCE LIMIT** — checked-in expected values are consumed by the gate tests, but the stated generator is a throw-away program outside the repository. |
| `contracts/test/FixtureParsingGuards.t.sol` | **FIXED INPUT-BOUNDARY REGRESSION** — 17 cases cover 64-row acceptance, 65-row rejection, an interior malformed row, a malformed terminal row, `malformed row64 + valid row65`, every narrowed GateInfo field and both validity block numbers. They exercise overflow at both WHIR generator positions and all three Ext3 limbs, representative non-canonical Goldilocks `P`, and registration scalar bounds/preservation (`:52-169`). The frozen guarded run passed 17/17. This is the new 44th inventory file. |
| `contracts/test/IntmaxRollup.t.sol` | **CORE UNIT/BINDING, MIXED** — strong registration fail-closed/no-poison, finalization, rollback and accounting tests. The default suite deploys a real `MleVerifier` but explicitly sets `degreeBits = 0`, so verification bypasses (`:377-393`); mere verifier instantiation is therefore not cryptographic evidence. One invalid-input path enters the real verifier, while fraud-conviction paths use `RejectingMleVerifier` (`:1413-1438,1661-1679`). Count `MleE2E`/`MleFinalizeE2E`, not this default harness, as positive real-proof joins. |
| `contracts/test/IntmaxTestTokenITX.t.sol` | **TESTNET TOKEN REGRESSION** — fixed-supply/ERC-20 conservation and ABI checks for the faucet asset; not a protocol verifier test. |
| `contracts/test/MemberSetUpdateE2E.t.sol` | **REAL MSU MLE JOIN / MOCK REGISTRY** — real circuit proof reaches `applyMemberSetUpdate` and checks the shared WHIR rail; the registry is mocked and the suite does not close M-4 cross-layer atomicity. |
| `contracts/test/MleE2E.t.sol` | **REAL STANDALONE MLE** — validates and tampers the real validity proof directly against `MleVerifier`; it does not by itself bind a Rollup submission. |
| `contracts/test/MleFinalizeE2E.t.sol` | **REAL ROLLUP+MLE JOIN** — real validity proof passes post/finalize and tamper rejection; `blobhash(0)` is mocked, so it is not real EIP-4844 DA evidence. |
| `contracts/test/MultiTokenEscrow.t.sol` | **REAL TOKEN ACCOUNTING / MOCK MLE** — strong measured-delta, nonstandard-token, cap and reentrancy coverage; withdrawal cryptography is deliberately stubbed. |
| `contracts/test/MultiTokenSettlement.t.sol` | **SETTLEMENT ACCOUNTING / MOCK MLE** — strict token-vector/cap/registry binding and payout behavior with mock verification; disabled post-close behavior must not be inferred to be enabled from older cases. |
| `contracts/test/PartialWithdrawal.t.sol` | **PW STATE MACHINE / MOCK MLE** — broad submit/replace/cancel/finalize and descriptor-binding coverage; not a real close-proof or real inclusion/finality test. |
| `contracts/test/PartialWithdrawalBurnPayout.t.sol` | **REAL WITHDRAWAL MLE, SKIP-SENSITIVE** — proves burn-leaf authorization/nullifier rules when fixtures exist; one fixture-shape test returns early and the proof tests skip if absent, so use the anti-skip guard. Its inherited lifecycle mocks `blobhash(0)` (`WithdrawNativeE2EBase.sol:88-117`, especially `:91-94`), so the real proof/contract join is not EIP-4844 availability or canonical-inclusion evidence. |
| `contracts/test/PartialWithdrawalPayout.t.sol` | **REAL NORMAL-WITHDRAWAL MLE, SKIP-SENSITIVE** — proves that authorization alone cannot substitute for a proof, that a proven normal leaf pays, and that `auxData`/nullifiers remain proof-bound (`:67-109,147-185,217-242`). It explicitly lacks a valid burn-leaf proof (`:188-197`), so positive burn authorization belongs to `PartialWithdrawalBurnPayout.t.sol`; it also skips without fixtures. Its inherited lifecycle mocks `blobhash(0)` (`WithdrawNativeE2EBase.sol:91-94`), so this is not EIP-4844 availability, receipt-canonicality or canonical-inclusion evidence. |
| `contracts/test/ReclaimStake.t.sol` | **REAL VALIDITY/FUND FLOW, SKIP-SENSITIVE** — exercises reclaim/finalize/truncation stake accounting with a real validity fixture; absence skips the suite's cases. Its `blobhash(0)` values are mocked (`:127,176,218`), so this does not establish real blob availability or canonical inclusion. |
| `contracts/test/RedTeamBlsProbe.t.sol` | **PRECOMPILE/CONSTANT PROBE** — reproduces historical pairing address and malformed-generator failures; not an end-to-end proof test. |
| `contracts/test/RedTeamFraudBreaks.t.sol` | **FRAUD ADVERSARIAL / STUB CAVEAT** — valuable gas, unsupported-gate, submission-binding and KZG attacks, but its successful invalid-verdict case uses `RejectingMleVerifier`, not production `MleVerifier`. |
| `contracts/test/RedTeamRound3.t.sol` | **CLOSE/PW ADVERSARIAL, MOCK MLE** — attack/fix/refutation scenarios for response windows and burn ordering; lifecycle evidence only. |
| `contracts/test/RedTeamRound3Fraud.t.sol` | **GAS-CLASSIFICATION ADVERSARIAL** — probes nested EIP-150 behavior using specialized harnesses; it protects non-conviction on evaluation failure but does not make production `MLE_INVALID` reachable. |
| `contracts/test/RegisterTokens.t.sol` | **SCRIPT/REGISTRY REGRESSION, MIXED** — checks public-chain fixture-read ordering, manifest bounds, uniqueness and readback; its rollup proof verifier is mocked because token registration is the target. |
| `contracts/test/RollupChainPinDoS.t.sol` | **REPRODUCTION, NOT CLOSURE** — shows raced pins make the post revert cleanly and registration is deployer-only; it does not prevent repeated permissionless pinning/reproving grief. |
| `contracts/test/RollupFinalizeDiagnostics.t.sol` | **DIAGNOSTIC SURFACE** — reason-code and fail-closed tests use EVM mocks for unevaluable calls; useful observability evidence, not proof-soundness evidence. |
| `contracts/test/RollupFraudHardening.t.sol` | **FRAUD UNIT / STUB CAVEAT** — verifies false-conviction and rollback defenses, but both “genuinely invalid proof” cases substitute `RejectingMleVerifier`; they do not close FRAUD-VERDICT. |
| `contracts/test/WithdrawNativeE2E.t.sol` | **REAL WITHDRAWAL MLE, SKIP-SENSITIVE** — real lifecycle, tamper, replay and VK gates; requires frozen fixtures and a no-skip run. Its inherited lifecycle mocks `blobhash(0)` (`WithdrawNativeE2EBase.sol:91-94`), so the proof/contract join is not real blob-availability or canonical-inclusion evidence. |
| `contracts/test/WithdrawNativeE2EBase.sol` | **REAL-E2E TEST SUPPORT** — builds/finalizes the real validity fixture and mocks only blob availability; helper code, not an independent test. |
| `contracts/test/tokens/IntmaxTestTokenITX.sol` | **TESTNET ASSET SUPPORT** — fixed-supply faucet ERC-20 used by its conformance suite; not a verifier or production allowlist decision. |
| `contracts/test/tokens/TestTokens.sol` | **ADVERSARIAL TOKEN MOCKS** — standard, fee-on-transfer, false/short-return and reentrant tokens for escrow tests; never deploy as protocol assets. |

## Per-file MLE Solidity review disposition

The MLE inventory covers every verifier source under
`contracts/lib/polygon-plonky2/mle/contracts/src/**/*.sol`: **16/16**. Vendored `forge-std` and test
contracts are not first-party verifier sources and are excluded from this source disposition table.

| File | Disposition |
|---|---|
| `contracts/lib/polygon-plonky2/mle/contracts/src/ConstraintEvaluator.sol` | **HOLD** — terminal constraint combination delegates to the supported gate evaluator; fixture layout/parameter equality is enforced at export. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/CosetInterpolationConstants.sol` | **FIXED/HOLD** — finite subgroup table is explicit; Rust export now rejects `subgroup_bits`/degree outside this deployed envelope. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/EqPolyLib.sol` | **HOLD** — equality-polynomial evaluation reviewed; no independent canonicality gap identified. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/GoldilocksField.sol` | **HOLD** — base-field arithmetic/canonical reduction primitive; callers enforce canonical public limbs. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/MleVerifier.sol` | **FIXED dependency frozen / OPEN fraud integration** — transcript, VK anchors and gate digest feed the WHIR library fixed in submodule `8f0be2f7e025a17a5a3acb281c14c33d87658932`; exact cross-rail proof/VK regeneration remains mandatory. All invalid checks revert and success alone returns `true`, so the separate parent fraud API's returned-`false` verdict remains unreachable. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol` | **FIXED/HOLD** — gate IDs 0 through 13 are dispatched, including Exponentiation and CosetInterpolation; unsupported active gates revert rather than vanish. Rust structurally re-derives every gate parameter. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/PoseidonConstants.sol` | **HOLD** — fixed constants only. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/PoseidonGate.sol` | **HOLD** — Poseidon gate constraints are implemented and selected by the common dispatcher. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/SumcheckVerifier.sol` | **HOLD** — round/challenge/final evaluation flow reviewed; no file-local acceptance shortcut found. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/TranscriptLib.sol` | **HOLD** — transcript absorb/squeeze ordering must remain byte-identical to Rust and is covered by cross-language fixtures. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/spongefish/GoldilocksExt3.sol` | **HOLD** — extension-field arithmetic primitive. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/spongefish/Keccak256Chain.sol` | **HOLD** — chained transcript hashing primitive; no independent state-reset issue found. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/spongefish/SpongefishMerkle.sol` | **HOLD with caller contract documented** — Merkle authentication itself verifies the root, but it alternates the caller's arrays with scratch arrays and mutates them (`:41-62`). WHIR callers must perform leaf-level duplicate consistency before this call and must not treat those arrays as preserved authenticated leaves afterward. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/spongefish/SpongefishWhir.sol` | **HOLD** — WHIR data structures/parameter definitions; deployment must use the matching rail. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/spongefish/SpongefishWhirVerify.sol` | **CRITICAL/HIGH FIX frozen / remaining regression gate** — fixes the Merkle scratch-alias duplicate bypass/1.48% honest false-reject, binds final committed rows to `finalVector` in both standard and split modes, validates every Arkworks `Vec` length prefix, rejects non-canonical base/Ext3 opening limbs and consumes hints exactly (`:145-150,363-493,641-668,819-973,1194-1270`). Frozen in submodule `8f0be2f7e025a17a5a3acb281c14c33d87658932`; the direct malicious-vector fixture and remote fresh-clone join remain required. |
| `contracts/lib/polygon-plonky2/mle/contracts/src/spongefish/WhirLinearAlgebra.sol` | **HOLD** — linear-algebra helpers used by WHIR; no independent issue found. |

The first-party MLE Solidity test/vector files were also dispositioned individually: **13/13**.
They are evidence for the source review, not additional deployed predicates:

| File | Disposition |
|---|---|
| `contracts/lib/polygon-plonky2/mle/contracts/test/BoundaryCheckTest.t.sol` | **STALE-FIXTURE-PATCHED regression** — useful canonical/boundary rejection cases, but the parser overwrites serialized `whirParams.numCommitments` with four (`:274-284`); not exporter-fidelity or an exact artifact join until the fixture is regenerated and the override removed. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/CosetInterpolationTest.t.sol` | **FIXED regression** — evaluator positive/negative cases for the finite interpolation envelope. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/CosetInterpolationVectors.sol` | **FIXED vectors** — checked constants/vectors consumed by the interpolation tests. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/E2EFixtureTest.t.sol` | **LEGACY COMPONENT FIXTURE** — inline transcript/sumcheck/constraint checks; it does not call the current `MleVerifier`, WHIR verifier, or parent contract and is not a release join. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/ExponentiationGateTest.t.sol` | **FIXED regression** — gate-8 evaluator vectors and rejection behavior. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/ExponentiationGateVectors.sol` | **FIXED vectors / provenance limitation** — checked inputs/outputs for gate 8, but the file states that its Rust generator was a throw-away binary kept outside the repository; reproduce and retain the generator before treating regeneration as independently auditable. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/GasBenchmark.t.sol` | **COMPONENT-ONLY GAS measurement** — the deployed `MleVerifier` instance is unused; every test/benchmark calls only `MleVerifierTest` field, equality-polynomial or sumcheck primitives (`:11-17,23-83`). It is neither proof-verification evidence nor a full-verifier deployment/gas budget. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/LagrangeTest.t.sol` | **HOLD regression** — interpolation algebra checks. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/MleE2ETest.t.sol` | **STALE-FIXTURE-PATCHED MLE path** — reaches the current verifier, but overwrites serialized `numCommitments = 2` with four (`:122-130`). The frozen-source targeted run passed 6/6; it is verifier compatibility under patched test input, not proof that the exporter emitted deployable metadata. Regenerate and remove the override. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/MleVerifierTest.sol` | **COMPONENT TEST SUPPORT** — external-callable field/equality/sumcheck primitives; it does not exercise the current `MleProof`/WHIR path or the parent-contract PI bind. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/TranscriptCompat.t.sol` | **HOLD regression** — Rust/Solidity transcript compatibility. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/TranscriptE2ETrace.t.sol` | **COMPONENT TRANSCRIPT TRACE** — imports only `TranscriptLib` and pins challenge checkpoints through the constraint-sumcheck transcript (`:4,48-133`); despite the filename, it does not invoke `MleVerifier`, WHIR, or any parent-contract public-input binding. |
| `contracts/lib/polygon-plonky2/mle/contracts/test/WhirVerifyTest.t.sol` | **STALE-FIXTURE-PATCHED WHIR path + canonical decoder negatives** — the frozen-source run passed 9/9 against the patched verifier, including direct base/Ext3 `p`-encoding rejection through the production row decoder. The suite still explicitly replaces the fixture's v1 `numCommitments = 2` with four (`:208-214,246-251`). This is useful component compatibility evidence, not an exact serialized-fixture/deployment-parameter join or the missing direct final-vector attack regression. |

## Targeted verification record (not a full release matrix)

The explicitly frozen-source results below apply to the runtime tree committed by this integration.
Rows still marked TBD were reproduced earlier in the integration or remain unexecuted and are not
promoted to final release evidence. Nothing here copies `433/433`, `17/17` or another result from
the Opus branch as final integration evidence.

| Required targeted reproduction | Frozen-tree command/result |
|---|---|
| Final-wire inter-channel A11 proof after real N-of-N attachment | **NOT RE-RUN AFTER FREEZE / release gate.** |
| Wrong signed `TxV2.nonce` rejected natively and by the real circuit; regenerated honest lifecycle joins Solidity | **NOT RE-RUN AFTER FREEZE / release gate.** |
| Snapshot record/state/fund/balance-state channel-ID substitutions reject, including re-signed mutations | **NOT RE-RUN AFTER FREEZE / release gate.** |
| Checked-in MLE gate IDs/name-derived parameters, CosetInterpolation envelope and tamper negatives | **FROZEN-SOURCE TARGETED: `cargo test --release --locked --test mle_gate_support` 18/18 PASS.** The cheap scan does not reconstruct layout/count without live `CommonCircuitData`, so this is envelope evidence rather than a replacement for the regenerated real joins. |
| WHIR honest close fixture with initial query zero and final duplicate index 869; duplicate-row, `Vec` prefix and trailing-hint negatives | **FROZEN-SOURCE: parent `ClaimMleVerifyTest` 8/8 PASS.** Fixed sentinels are hints length 76,368, prefix offset 67,272 and duplicate second-row offset 71,888. This proves the honest fixture and checked-in negatives, not the direct malicious `finalVector` construction. |
| WHIR submodule compatibility after final-opening/alias/hint/canonicality patch | **FROZEN-SOURCE: `WhirVerifyTest` 9/9 PASS, parent `MleE2ETest` 6/6 PASS, submodule Forge 94/94 across 11 suites with zero skips, and Rust WHIR PCS tests 8/8 PASS.** The Solidity fixture suites still patch stale `numCommitments` metadata, so they are not exporter-fidelity evidence. Rust negatives prove exact EOF in the exercised split entry point and all three production verification entry points call the same check; Solidity negatives cover non-canonical base and Ext3 opening rows. |
| Direct final-commitment / `finalVector` separation attack (`Delta = (delta*c1,-delta*c0)`) | **CONSTRUCTION CONFIRMED; CHECKED-IN MALICIOUS PROOF NOT IMPLEMENTED / release gate.** Do not substitute the dot-preserving duplicate-row negative for this regression. |
| Live outgoing nonce restart/concurrency/unavailable-authority/ambiguous-child cases | **FROZEN-SOURCE Node suite covered the checked-in regressions; logical full result 293/293 across the sandbox/full-boundary split described below.** |
| Production verifier receives a malformed committed proof and reaches an authenticated invalid verdict | **BLOCKED / NO-GO** — no valid production test exists; current “false verdict” tests use `RejectingMleVerifier`. |

## Frozen release evidence

| Evidence | Final value |
|---|---|
| Integration commit | Parent commit containing this report; exact SHA printed in the audit handoff (not embedded self-referentially). Runtime source did not change after the final test runs. |
| Rust toolchain and full test totals | Cargo `1.87.0-nightly`; **full workspace not run**. Targeted gate envelope 18/18 and submodule WHIR PCS 8/8 passed. Full clean-clone Rust remains a release gate. |
| Node version and full test totals | Node `v26.7.0`; npm `11.19.0`. Logical coverage is **293/293 distinct cases passed across two environments**. Sandboxed `npm test` enumerated 293 tests and reported 292 pass / 1 fail; the sole case failed before its assertions because the sandbox denied `listen 127.0.0.1` with `EPERM`. Re-running only `node --test test/api-blocks-boundary.test.js` outside the sandbox passed 1/1. There was no single 293/293 full-suite process; this is not 294 distinct tests. |
| Foundry version, suites/tests/passed/failed/skipped | Forge `1.5.1-v1.5.1`; guarded parent run **473/473 passed across 37 suites, 0 failed, 0 skipped**. All ten named anti-vacuity suites met their exact floors. |
| MLE submodule Forge version and suites/tests/passed/failed/skipped | Forge `1.5.1-v1.5.1`; **94/94 passed across 11 suites, 0 failed, 0 skipped**. `WhirVerifyTest` was 9/9. |
| Lean version and full test totals | **NOT RUN / release gate.** |
| `SpongefishWhirVerify` deployed runtime bytecode size | Submodule profile: **24,357 bytes** (219-byte EIP-170 margin). Parent profile: **22,637 bytes** (1,939-byte margin). |
| `ChannelSettlementVerifier` deployed runtime bytecode size | **23,955 bytes** (621-byte EIP-170 margin). |
| `IntmaxRollup` deployed runtime bytecode size | **24,552 bytes**—only **24 bytes** below EIP-170. Any compiler/profile/source drift must hard-fail deployment CI. |
| `ChannelSettlementManager` deployed runtime bytecode size | **23,130 bytes** (1,446-byte EIP-170 margin). |
| Encoded validity/withdrawal proof and blob-payload sizes | **NOT MEASURED / release gate.** |
| Validity, withdrawal, close, cancel-close, MSU and PW/burn VK + fixture hashes | **PARTIAL only.** Final close-set hashes are recorded immediately below; the complete cross-rail VK/fixture manifest remains a release gate. |
| Deployment manifest, RPC chain ID, deployed addresses and runtime code hashes | **TBD / release gate.** The deterministic local close Manager used by the frozen fixtures is `0x75457b6613e1f9Db10a3ce1b9dE5217cacB7f3E9`; this is not a live-chain deployment assertion. |

Frozen local close-set SHA-256 values:

| Fixture | SHA-256 |
|---|---|
| `close_intent.json` | `900589f98e3d476ab8b1855c0687a55d63785c472f76fb896f1dbd6b27416b66` |
| `close_intent_mle.json` | `c8e58dbdb6a6b634e5f500e73873b9b22e5bb40c4f71065e2b9cd879ff48baf2` |
| `close_withdrawal_mle.json` | `f8795628a4f3f018eb5ed6ee86f3469c5fc8f2bcf8d12feb7082b4ff97b41175` |
| `close_lifecycle_validity_mle.json` | `32eb9d572ed987b8ee6ba8b9d637bea389b40df2525a0e7ce2796a0df78c645e` |
| `close_lifecycle.json` | `e76c31d9e60687be23c5dcec9bff5e0119d7376482eb03c920c332c0de40d1e4` |
| `close_withdrawal_payout.json` | `f57973ac3505096b2398b4666607bed92f0ccee66bc5497a8d557a977c6f6363` |

## Final GO checklist (to be completed by the integrator)

- [x] Local integration commit and exact submodule identity recorded; both worktrees clean at the
      handoff boundary.
- [x] WHIR patch committed as `8f0be2f7e025a17a5a3acb281c14c33d87658932` on
      `codex/whir-leaf-consistency-20260830`, with the parent gitlink updated to that exact commit.
- [ ] Push/document an authenticated remote ref for both branches and prove recursive resolution
      from a fresh clone.
- [ ] All modified circuit VKs and fixtures regenerated from that commit and hashes recorded.
- [ ] Real validity, close, cancel, MSU, withdrawal and PW/burn Rust-proof-to-Solidity joins pass;
      no required test is skipped.
- [ ] Direct malicious final-vector/last-commitment separation fixture checked in: the old verifier
      accepts the constructed proof while Rust and the patched Solidity verifier reject it. Keep
      this distinct from the duplicate-row negative.
- [ ] Honest query-zero/final-duplicate close fixture, mismatched duplicate row, wrong Arkworks
      `Vec` prefix, trailing hints and short/misaligned hints all rerun against the frozen verifier.
- [ ] All seven in-use MLE submodule fixtures regenerated with `numCommitments = 4`; test-side
      parameter overrides removed; serialized metadata is the value actually verified; unused
      legacy `xlarge_mul.json` migrated or removed explicitly.
- [ ] `DeployCloseCli` refuses delegate-bearing use until its settlement-side live count/bindings
      are authenticated; the L1 registration count stays zero, and later joins are either frozen or
      update the immutable-at-present Manager floor through a new authenticated protocol.
- [ ] KZG DA decision implemented in code: immutable trusted setup or explicit disable.
- [ ] M-4 member-set atomicity and M-9 close-intent authorization decisions implemented or affected
      features disabled end to end.
- [ ] Snapshot recovery bound to authenticated, durable, reorg-aware L1 lifecycle/head.
- [ ] Fresh backing mandatory in production deposit co-sign paths; explicit blob-size/domain limit.
- [ ] Full Rust, Node, Forge and Lean suites pass from the clean clone; final totals, bytecode sizes,
      fixture hashes and deployment runbook appended here.
- [x] Forge anti-vacuity totals/required suites updated and passed from the frozen inventory, including
      all 8 `ClaimMleVerify`, 7 `AuthorizedBurnFenwick` and 17 `FixtureParsingGuards` cases.
- [x] Fixture parser's 17-case suite rerun from the frozen tree; exact array length, malformed
      terminal row and malformed row 64 followed by a later row all reject in the guarded run.
