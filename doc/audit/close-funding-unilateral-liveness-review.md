# Close-funding unilateral-liveness review (2026-09-02)

## Decision

**Release disposition: NO-GO for an advertised unilateral full exit.** The new terminal-funding
pipeline is soundly fail-closed and can complete a *cooperative* shutdown, but it does not remove
the last member-liveness dependency. After an ordinary N-of-N channel head is accepted, the only
production funding path constructs a fresh child of that head and requires a fresh N-of-N Falcon
signature set over the child. A member/key custodian that refuses or disappears can therefore let
the public close reach `Closed` while permanently preventing Rollup backing from reaching the
Manager.

This finding is independent of the accepted KZG-ceremony assumption and of the separately tracked
MLE/WHIR PCS defect. Fixing the PCS does not create the missing authorization or proof artifacts.

## Code evidence

| Boundary | Enforced behavior | Liveness consequence |
|---|---|---|
| `src/close_funding.rs::build_close_funding_proposal` | Clones the current signed head, increments epoch/small-block/state version, installs a new non-zero H2/settled-chain value, and clears `member_signatures`. | The terminal state is a new signing message, not an operation already authorized by the accepted head's signatures. |
| `src/live_balance_service.rs::prepare_close_funding` | Reads the current bound N-of-N head and returns the unsigned proposal. | The resident service has no authority to complete the signature set. |
| `src/bin/channel_member.rs::cmd_sign_close_funding` | Invokes every controlled member key and requires `verify_all_signatures` over the new terminal state. | This is the missing online-member round. The command cannot be reproduced by a delegate or keyless watchtower. |
| `api/routes/full-withdrawal.js` `/close-funding/prepare` and `/close-funding/commit` | Phase 1 returns an unsigned child. Phase 2 accepts caller-supplied `signedState` and the producer rejects it unless it is N-of-N. | The HTTP service intentionally has no fallback signer; an unavailable member leaves the ticket at `close_funding_signatures_pending`. |
| `src/block_producer.rs::produce_close_funding_block` | Verifies the canonical proposal and the ordinary N-of-N signed-state rules before admitting the terminal block. | A valid public close proof for the predecessor cannot substitute for the missing child signatures. |
| `contracts/src/ChannelSettlementManager.sol::authorizeCloseFunding` | Authorizes a payout only after the Manager is `Closed`, and only through its immutable materializer. | Closing the Manager alone creates no Rollup credit. |
| `contracts/src/ChannelSettlementManager.sol::_pullChannelFunds` | Requires an issued-and-consumed close-funding authorization before pulling the exact channel cap. | A closed channel without the terminal proof fails with `CloseFundingProofNotMaterialized`; unrelated/donated Rollup credit correctly cannot bypass it. |

The public backing vault, `public_close_prover`, and `public_close_publisher` close the earlier
`ClosePending -> CloseSubmitted -> Closed` censorship seam. They deliberately consume signatures
already present on the accepted head. They do **not** build or authorize the later terminal child.
The materializer closes the authorization/proof atomicity race after a terminal proof exists; it
does not create that proof.

## Concrete failure trace

1. Head `H` is fully N-of-N signed, bound to the live balance proof, accepted by a delegate, and
   archived with public close material.
2. One member/key custodian becomes malicious or permanently unavailable before signing another
   message.
3. The delegate uses its participant proof to call `requestCloseAsParticipant`, then uses the
   public close prover/publisher to submit and finalize `H`. The Manager is now `Closed` and its
   per-token claim caps are correct.
4. `build_close_funding_proposal(H, ...)` yields terminal child `T(H)` with an empty signature set.
   The unavailable member never signs `T(H)`.
5. The producer cannot admit `T(H)`, so no terminal validity result or terminal withdrawal proof
   can be finalized.
6. `CloseFundingMaterializer.materialize*` has no proof to consume. Manager pull functions remain
   fail-closed, participant claims have no channel-scoped backing, and the value stays in the
   Rollup/base account.

There is no timeout branch that changes step 4 into an authorization by `H`; waiting longer cannot
repair it. The current deployment's "one operator holds all N keys" assumption merely concentrates
this availability dependency in one process/operator. It does not make a delegate's exit
unilateral against that operator.

## Why a naive pre-signed child is unsafe

A Lightning-style retained exit artifact is the correct *class* of solution, but adding one call to
`sign-close-funding` after every head is not a safe patch.

1. **It collides with anti-equivocation.** `state_signing_ledger` permits one successor for each
   `(channel, predecessor, member slot)` and makes a terminal reservation permanent. `T(H)` and the
   next ordinary update `H'` are siblings of `H`; signing both is exactly what the current ledger
   forbids. Removing this refusal without a protocol-specific replacement creates general sibling
   signing.
2. **Old-kit invalidation is not atomic with head acceptance.** If `T(H)` and `H'` are both valid,
   the producer can receive either first. Existing API flows persist N-of-N channel state before
   producer admission, and inter-channel/deposit flows cross two channel/live journals. An old exit
   winning that race can strand a locally accepted sibling or one side of the transfer.
3. **The terminal economics change.** The plan binds the base nonce, full token-fund vector,
   settled chain, rollup, manager, freeze nonce and H2 root. Deposits, inter-channel sends, burns,
   and token changes invalidate an earlier plan. An old over/under-funded terminal proof cannot be
   reinterpreted as the new Manager cap because the IMCF/IPW2 bindings correctly reject it.
4. **The Manager identity may not exist yet.** The real-network exit helper correctly says
   settlement must be deployed before funding, but channel initialization/deposit/head acceptance
   does not make a verified exit kit an admission condition (and devnet/legacy flows still deploy
   on demand). A safe plan binds a particular chain, Rollup and Manager, so any channel funded
   before immutable settlement activation cannot have a usable pre-signed plan for that deployment.
5. **Signatures alone are not a self-contained exit kit.** The current terminal validity candidate
   needs the producer's global-state witness and the payout path needs the resident live service's
   private spend state. Those are intentionally absent from the public backing archive. A true
   watchtower kit must contain verified, refreshable proof material or a protocol statement that a
   public prover can complete without those secrets. A terminal branch proof tied to an old global
   validity anchor also becomes stale as unrelated blocks advance.

Consequently, relaxing `state_signing_ledger`, accepting an unsigned child natively, or storing only
`{plan, signedState}` would trade a visible liveness failure for sibling/race or unavailable-witness
failures. None is release-safe.

## Minimum safe protocol work

The smallest design that preserves the current proof statements as much as possible is a new,
explicit **head-plus-exit-kit acceptance protocol**, not an endpoint patch:

1. **Activate settlement before value enters the channel.** The immutable Rollup, Manager,
   materializer, chain ID, runtime hashes, participant policy and activation checkpoint must be
   known before the first fund-bearing head is accepted. Later participant changes require the
   already planned close-and-migrate channel replacement.
2. **Define `ExitKitV1`.** At minimum bind the source-head digest, complete canonical
   `CloseFundingPlan`, N-of-N terminal authorization, base/global producer anchor, public backing
   hash, settlement deployment hash, and every proof/DA artifact needed by a signerless publisher.
   The kit is valid only after independent native self-verification.
3. **Make head acceptance atomic with kit availability.** A wallet/delegate must never acknowledge
   `H'` merely because its N-of-N state exists. The durable transition must stage `H'` and
   `ExitKit(H')`, verify both, make the producer/base-state decision, archive the new kit to every
   participant/watchtower, and only then publish `H'` as accepted. Crash recovery needs one joint
   journal across these phases.
4. **Specify the only allowed sibling pair.** The signing ledger needs separate ordinary and
   canonical-exit domains, exact pair identities, and a terminal-commit latch. It may never become
   a generic "two successors are allowed" exception. Retry must return byte-identical signatures.
5. **Invalidate the previous kit at an authoritative layer.** A local producer journal is
   insufficient against the producer whose disappearance/censorship the kit is meant to survive.
   Either advance an L1-recognized monotone channel/base nonce before acknowledging the next head,
   or introduce a rigorously specified revocation/penalty/update mechanism. Base-changing
   cross-channel/deposit transitions need atomicity across both affected channels and the L1
   validity anchor.
6. **Remove private-prover dependence.** Archive precomputed spend/withdrawal material in the kit
   or add a proof statement allowing a public prover to derive the terminal spend from the closed,
   authenticated head. The publication account, stake/fee budget, replacement policy, finalized
   receipt checks and reorg recovery must be independently available as well.

An alternative is a protocol-level system transition derived from an already N-of-N signed head,
so the validity circuit accepts only the one canonical full-fund transfer to the immutable Manager
without a fresh child signature. That can remove sibling authorization, but it is a circuit and
state-machine redesign and still must solve public witness availability and base-account replay.
Another defensible representation is a separate domain-separated `ExitAuthorizationV1` signed
alongside each head, committing to `H.digest` and the complete canonical plan rather than pretending
that the terminal and ordinary states are the same successor. The validity circuit would then
verify that authorization and the exact system transition. This avoids weakening the ordinary
one-successor ledger, but it is still a new verified statement, needs authoritative old-kit
invalidation, and requires the same public proof/witness package. It is not a proof-neutral patch.

## Performance disposition

No code change was made in this review. Therefore this branch gains no proof-size or proving-time
regression from the review itself.

The retained-branch design can keep the *individual* validity/withdrawal proof formats unchanged,
but it precomputes and refreshes additional proofs. It therefore increases aggregate proving work,
storage and bandwidth even if each proof remains byte-identical. Because a validity branch is
anchor-specific, refreshing only when this channel changes is not obviously sufficient. The
system-transition alternative changes circuit constraints and must be benchmarked against the
frozen degree, proof byte count, peak RSS, and end-to-end wall time before it can replace this
NO-GO item. "Same proof ABI" must not be reported as "no performance regression."

## Required adversarial acceptance tests

- A member disappears immediately after each supported head type: intra-channel send/refresh,
  deposit import, inter-channel source/destination, burn, and token registration. The remaining
  participant must reach exact per-token L1 payout from archived material only.
- Race `ExitKit(H)` against `H'` at every crash boundary. Exactly one outcome becomes authoritative;
  the losing path cannot alter either channel, nonce, fund vector, settled chain, Manager cap, or
  signing ledger.
- Restart after every stage/write/broadcast; delete all coordinator services and private runtime
  state after head acceptance; continue using only participant/watchtower artifacts.
- Advance unrelated Rollup blocks between kit creation and publication and prove the recovery path
  does not require the vanished coordinator's global witness.
- Reorg the head/terminal/close/materialization/pull receipts independently; no orphaned evidence
  may release a newer kit or complete an exit.
- Exercise simultaneous mass exits, fee replacement and deadline exhaustion. A valid artifact that
  cannot be included in the required window is an availability failure, not a passing crypto test.

Until those properties are implemented and tested, documentation/UI must call the current path
**cooperative terminal funding followed by permissionless publication**, not unilateral full exit.
