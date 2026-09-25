# Wallet recovery follow-up (2026-09-25)

Scope: the three open items from `wallet-reliability-audit-2026-09-25.md`.
Existing user Anvil state and identities must survive this work.

## Burn recovery

`api/lib/burn-operation.js` owns the exact debit proof/descriptor before any signing call.
A `burn_pending` ticket points to this owner; the native checksummed burn publication WAL owns
signature/state publication. Startup and periodic reconciliation continue the same operation.
Failures never delete a prepared exit kit on the assumption that a missing response means no
signature was released. Native recovery precedes inspection of `burn_cosigned.json`.

Producer admission uses the original request ID; live settlement is replayed idempotently.
A completed result is archived by request ID. Ticket progress is not downgraded when a process
dies after writing the burn completion ticket, or an old completed burn is retried on upgrade.
Both versioned API aliases and the local browser relay use the same recovery owner.
The existing Step 1 resumes pending burns, including after page reload; no button is added.

Validation:

- File-backed orchestration tests cover prepare/sign/producer/live/ticket interruptions,
  altered input, corrupt input, token mismatch, and conflicting withdrawal phases.
- Six actual child-process SIGKILL boundaries cover preparation, native-signature return loss,
  signed journal, producer, live proof, and ticket. Crypto/L1 effects in these process tests are
  simulated; this is not a claim to have SIGKILL-tested a real prover at every instruction.
- Actual browser on isolated UI fixture port8093: interrupt after simulated signing, reload,
  open Withdraw, use Step 1, advance to Step 2. Burn counter remains exactly one.

## Lost batched-send response

The native signer records each verified slim request's canonical hash (plus exact wire hash for
streamed inputs), and archives the N-of-N signed batch head. The acceptance index and debit head
are committed together inside the atomic `cli_state.json` replacement. An orphan result written
before that commit cannot acknowledge a payment. A missing HTTP response or public output after
that commit cannot erase the request's acceptance.

The local relay resolves indexed requests before stale-anchor filtering, republishes/reconciles
the committed head, and returns the original accepted state. EC2 queued slim/fat requests perform
lookup under their channel lock, including duplicates queued while the first batch was signing.
The browser's existing Send recovery retains the original request and imports the current snapshot.

Validation:

- A real stored public send payload produces the same SHA-256 ID in JS and native Rust.
- Native test signs a state with actual member keys, commits multiple acceptance IDs and private
  state, omits public/result publication, reopens, and verifies archived N-of-N signatures.
- Historical lookup, uncommitted orphan, altered payload/token/nonce/proof, missing/corrupt archive.
- No full EC2 deployment or new live multi-member batched transaction has been exercised here.
- Pre-upgrade batches without retained per-request evidence cannot be retroactively assigned an
  acceptance receipt by guessing. The existing exact-current-head solo fallback remains.

## Receive-after-send protocol change — not activated on existing channels

The authenticated latest channel leaf commits the last outgoing block. If that block is already
covered by the balance cursor (`last_send <= block_r`), no outgoing send remains in the tail through
the authenticated public block. A receive can therefore advance in this tail without inventing a
next send. Otherwise the existing authenticated send-leaf interval checks remain mandatory.
Both native witness validation and circuit constraints implement this condition. All account-root,
public-state, inclusion, nullifier, monotonic-cursor and upper-bound checks remain.

This changes balance verifier data and derived exit proofs. It is deliberately gated by Cargo
feature `authenticated-tail-receive`, off by default. Default builds preserve the old deployed
circuit. Do not enable this feature against an existing live snapshot, replace `balance_vd.bin`,
or replace immutable exit verifier configuration merely to make a check pass.

Passed real Plonky2 tests with the feature:

- `authenticated_tail_comparison_including_u63_boundaries` (including maximum 63-bit counters).
- `test_receive_deposit_after_last_send` (nonzero last send, no later send).
- `test_receive_transfer_after_last_send` (same tail for an inter-channel receipt).
- The deposit test also changes the prior proof cursor to leave the last send unprocessed and
  bypasses native validation: direct circuit proving rejects the attempted skip. A forged latest
  channel leaf fails account authentication.

Remaining before calling the third issue resolved for the user's stack:

1. Exercise the full new BalanceProcessor/producer/exit-kit pipeline and new pinned L1 exit
   verifier deployment on a separate Anvil instance, including receive → spend → idle close.
2. Specify and execute a value-preserving migration from old channels/contracts, or implement a
   separately verified compatibility mechanism. Existing recursive proofs cannot simply be read
   under a changed verifier. Existing close-funding verifier configuration is immutable.
3. Recover the old channel7 pending credit from its original evidence without fabricating a
   completed receipt, duplicating credit, or resetting the user's chain.

The circuit tests establish the new condition and its local rejection boundary; they do not by
 themselves establish end-to-end migration or repair existing channel7. Do not describe all three
issues as completely resolved until the remaining acceptance checks are complete.
