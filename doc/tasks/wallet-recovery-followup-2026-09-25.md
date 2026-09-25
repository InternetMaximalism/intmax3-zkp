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

1. **Passed:** the new pinned L1 exit verifier deployment test on the separate Anvil instance,
   including real burn-signature SIGKILL, recovery, proof submission and exact 0.005 ETH payout.
   The resident receive → spend → receive → idle-kit restart test also passes.
2. Specify and execute a value-preserving migration from old channels/contracts, or implement a
   separately verified compatibility mechanism. Existing recursive proofs cannot simply be read
   under a changed verifier. Existing close-funding verifier configuration is immutable.
3. Recover the old channel7 pending credit from its original evidence without fabricating a
   completed receipt, duplicating credit, or resetting the user's chain.

The full resident-service test `receive_after_send_roundtrip_has_durable_idle_exit_kit` also
passed (372.86s). It constructs the real recursive balance/producer pipeline, sends A→B, spends
B's just-received credit back to A, receives into A after A's last send with no future send,
replays the receipt without another credit, and reopens A with the exact signed head and exit kit.
It uses the existing test Regev security level for member payloads, not a production-strength
browser transcript. The separate WASM/Anvil run covers the deployed wallet path.

The circuit/service tests establish the new condition and its local rejection boundary; they do not by
themselves establish end-to-end migration or repair existing channel7. Do not describe all three
issues as completely resolved until the remaining acceptance checks are complete.

## Compatible runtime activation

Recovery commits: `fb17561`, `24fbc73`. Broad Node suite: **656/656** (including final Anvil read-lag retry cases). `cargo check --all-targets`, native receipt persistence and actual-payload JS/Rust
identity checks pass. Six SIGKILL boundaries pass as described above.

On the dedicated existing Anvil (RPC8558), replaying the latest completed burn twice through the
new recovery owner returned HTTP200 and the exact same signed digest. The authoritative channel
head and terminal ticket bytes were unchanged (`audit-burn-journal-upgrade.json`).

User relay was restarted with default-feature binaries pinned in
`wallet-live-work-v2-20260924/runtime-bin`; Anvil was preserved. All three snapshot endpoints
returned their original signed digests and both user L1 balances were unchanged. Evidence:
`recovery-activation-before.json` and `recovery-activation-after.json` in that runtime directory.

`CHANNEL_MEMBER_BIN`, `BLOCK_PRODUCER_BIN`, and `PUBLIC_CLOSE_PROVER_BIN` isolate operational
binaries from experiments. Cargo integration-test builds can also rebuild top-level executable
artifacts; feature experiments should additionally use a separate `CARGO_TARGET_DIR`.
The separate protocol Anvil under `/tmp/intmax-tail-protocol-20260925` uses RPC8560 and relay8040/8041.

## Final recovery hardening

New burns are checked with native `--propose-exit-kit` before acquiring a durable owner. This
mode releases no signatures. Invalid/stale input therefore cannot create an unrecoverable owner
that blocks all subsequent channel mutations. Existing signed legacy burns additionally require
exact original proof/descriptor equality, not only a caller-supplied matching digest.

A batch signing call may commit and then fail to publish its output or bind its backing. Both
local and EC2 catch paths now inspect committed acceptance before any solo fallback. An accepted
payment can never become a `staleAnchor` instruction to create a new payment. Recovery failures
retain the same request. Route-level tests cover both successful reconciliation and another
publication failure, including streamed slim and fat EC2 requests. These are deterministic route
fault tests; they do not claim an EC2 deployment was exercised.

The user relay was updated again with `24fbc73` (PID58612 at activation). All three signed heads
and both user L1 balances remained byte-for-byte equal in `recovery-final-before.json` and
`recovery-final-after.json`. User RPC8545 and its contracts were not reset or replaced.

## Real WASM / Anvil authenticated-tail acceptance

`hosting/wallet/test/wallet-tail-e2e.js` passed against the isolated RPC8560 deployment at
`/tmp/intmax-tail-protocol-20260925` (relay8040/8041). It used real WASM proofs and real deposits:

1. Deposit 0.01 ETH into each of two channels.
2. A sends 0.002 ETH to B; B spends its received balance by sending 0.001 ETH back to A.
3. A receives without any later outgoing send, then imports an additional 0.001 ETH deposit.
4. Replay each exact transfer; the recipient head does not advance again.
5. Final delegate balances: A = 0.010 ETH, B = 0.011 ETH. Evidence: `roundtrip-success.json`.

The full resident-service and circuit tests listed above also passed. Final
`cargo check --all-targets --features authenticated-tail-receive` passed. The feature remains off
for the existing user deployment because its recursive proofs and immutable verifier pins are
for the prior circuit.

For a separate L1 payout check, `/tmp/intmax-tail-configured-20260925` has an isolated contracts
copy and newly generated feature-matching exit configurations. Build `generate_close_fixture`
with `authenticated-tail-receive,close-fixture-bin`, run `--mle-config-only` in the isolated root,
and use the generated close withdrawal configuration for `withdrawal_mle_config.json` too.
Do not reuse the repository's prior circuit fixtures: although the generic
`verificationConfigDigest` may stay equal, `preprocessedCommitmentRoot`, `circuitConfigDigest`
and `circuitDigest` change. `CONTRACTS_DIR` now applies to JS deployment/attestation as well as
native publication, avoiding writes to the shared test fixture directory.

This new rollup is `0xc351628EB244ec633d5f21fBD6621e1a683B1181` on RPC8560, relay8042/8043.
The explicit test preload `hosting/wallet/test/kill-after-burn-sign.cjs` killed the real relay
immediately after the native signer returned, before the relay recorded `op.head`. The one-shot
marker was consumed; `burn_operation.json` remained `prepared` without a head. Restart resumed
the exact saved request, finished it as `complete`, and retained 0.005 ETH after one 0.005 ETH burn
from a 0.01 ETH deposit. Real L1 validity publication, proof submission and payout verification **passed**. A repeated
submission reused the same authorization without another transaction. The independent balance
check in `verified-payout.json` confirms exactly 5,000,000,000,000,000 wei received, after adding
back 134,899,240 wei in gas. The payout nullifier is consumed on L1.

Authorization: `0x97e689e46f3b26f35e4e3572d0b694f4ebedf402ecc22edae6ff658e14bb1baa`.
Payout transaction: `0x74b162f7e858b0be78528555bd12fe8896f29c410945dc9aaa07183a7b5e5c51`.
Recipient pull: `0x454d687dc8fc004460f0c994ea028698a6036fb0f518a6455bbadf1f6bf1469e`.

The first finalize attempt encountered an Anvil `BlockOutOfRangeError` at the exact finalized
block immediately after empty-block mining. The same historical call later succeeded, and the
same saved payout resumed successfully. This was transient state-read availability, not evidence
of a deleted channel or a reason to use `latest`. The local relay now retries this exact class
of Anvil historical-call failure at most twice, re-entering the journaled native payout driver
with unchanged authorization/artifacts. Public-network, transaction and proof failures are not
retried by that helper. Five regression cases cover the boundary.

Code commit for authenticated tail: `cef88b9`. Existing user channels still use the original
verifier pins. A migration decision was requested only after the new protocol payout passed:
retain the old stack, withdraw/redeposit with the user wallet, and separately preserve/recover
old channel7 pending receipts. No funds were migrated and no old contract was replaced.


Final verification after `acec00f`: the isolated relay was restarted, then `/api/pw-finalize`
was called again for the completed authorization. It returned the same digest; both recipient
L1 balance and operator transaction nonce stayed unchanged (`finalize-replay-verified.json`).
The regular user relay was restarted with all recovery fixes (PID59751 at activation), using
its original default-feature pinned binaries. All three channel digests and both L1 balances
still match `recovery-final-before.json`. Final Node suite: 656/656. No new UI button was added.
The third issue is solved in the new protocol test deployment, but is **not yet resolved for
existing legacy channels**, pending migration/compatibility and the old channel7 recovery.
