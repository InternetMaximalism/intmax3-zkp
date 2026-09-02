# Delegate raw-signed transaction outbox

Status: implemented for participant close, guarded close finalization, withdrawal-claim submission,
channel-fund pull, and withdrawal-credit claim.

This document describes deployment identity and nonce safety only. It does not change the accepted
KZG ceremony trust assumption, a proof circuit, or the PCS implementation.

## Release safety boundary

The Node delegate signs L1 writes with `INTMAX_DELEGATE_L1_PRIVATE_KEY`. At startup it requires:

- one canonical `l1SignerLockRoot`;
- `rustPublisherSignerAddresses.publicValidity`;
- `rustPublisherSignerAddresses.publicClose`; and
- `rustPublisherSignerAddresses.closeFunding`.

All three configured Rust publisher addresses must be valid and nonzero, and the delegate signer
must differ from every one of them. The values must be the addresses actually resolved by the
publisher account configuration, not labels or placeholders.

This separation is a release requirement. The Node mutex/reservation implementation is not claimed
to be a universal Rust/Node or multi-host nonce broker. In particular, a different lock root or an
independent host cannot safely coordinate the same signer. Until every writer uses one shared,
signer-scoped durable nonce ledger, do not configure the delegate key for a Rust publisher and do
not run the delegate signer from another lock root or host.

## Durable order and invariants

`node/delegate/signed-transaction-outbox.js` applies this order to every delegate-owned L1 write:

1. Acquire the per-chain/per-signer mutex in the canonical lock root.
2. Refuse another semantic action while the signer has a persistent reservation.
3. Reserve the pending nonce, obtain EIP-1559 fee caps and estimate gas.
4. Sign the exact type-2 transaction locally with an offline wallet.
5. Atomically write and fsync the action journal, including the exact raw bytes.
6. Atomically write and fsync the signer reservation.
7. Release the transient mutex.
8. Broadcast only the raw bytes already present in the journal.
9. Retain the signer reservation until a hash-authenticated durable watcher proves both a successful
   receipt and the expected protocol transition.

The immutable action binding contains chain ID, signer, destination, calldata hash, and value. Each
attempt additionally binds nonce, gas limit, both EIP-1559 fee caps, raw signed bytes, and transaction
hash. Loading a journal decodes the raw transaction and rechecks every field and signature-derived
sender; a mismatch fails closed.

The ordinary delegate Store and logs receive only action IDs, transaction hashes, and public
lifecycle metadata. The private key is environment-only. Raw signed bytes exist only under the
private outbox directory. The outbox and lock directories are mode `0700`; journals, reservations,
and lock owner files are mode `0600`.

## Mutex and persistent reservation

For signer address `A` on chain `C`, Node uses:

- mutex directory: `.intmax-l1-signer-C-A.lock`;
- mutex owner: `.intmax-l1-signer-C-A.lock/owner.json`; and
- durable lease: `.intmax-l1-signer-C-A.reservation.json`.

The mutex is acquired by atomically renaming a fully fsynced private staging directory. Its owner
record binds hostname, PID, and a random token. Only a well-formed owner for a dead PID on the same
host can be reclaimed. A live, remote, malformed, permission-unsafe, regular-file, or symlink lock
fails closed. Release rechecks the ownership token before removing the directory.

The mutex alone is insufficient: a crash after journal fsync but before broadcast would release any
process-scoped lock. The persistent reservation therefore binds the canonical journal identity,
chain, signer, lock root, nonce, and current transaction hash. It remains after the mutex is released
and prevents a different semantic action from reserving that signer. Only the same journal can
recover it after restart. The reservation is removed only after the terminal record itself has been
fsynced.

Each journal also stores the canonical real path of its lock root. Opening that action through a
different root is rejected. This detects accidental local reconfiguration; it cannot coordinate two
independent roots, which is why single-root/single-host operation and signer separation remain
mandatory.

## Restart, replacement, and finality

A restart never reconstructs a transaction from intent. It loads and validates the journal, checks
all journaled attempts, and rebroadcasts only a byte-identical raw transaction when the RPC has no
transaction or receipt for it.

Fee replacement is explicit:

- a pending or dropped attempt may be replaced only with the same nonce, destination, calldata, and
  value, a nonempty operator reason, and at least a 10% bump to both EIP-1559 fee caps;
- every same-nonce raw transaction remains eligible to win, so the outbox reconciles receipts for
  all attempts rather than trusting only the newest hash;
- a mined `status=0` receipt consumed its nonce and can never be replaced at that nonce;
- only after that failed receipt is durable and canonical may an explicit new attempt use a fresh
  nonce; and
- more than one mined raw transaction for the same nonce, or more than one successful attempt for
  one semantic action, is treated as an ambiguous RPC/chain view and fails closed.

Neither a pending nor a merely mined transaction is terminal. Terminalization requires the exact
journaled transaction hash, a successful receipt, the watcher observation's exact block number and
hash, a durable head covering that block, a canonical block recheck before and after the protocol
state read, and an action-specific expected-transition check. The same receipt block and durable
checkpoint are rechecked while holding the commit mutex immediately before the terminal fsync.

## Protocol action identity

- Participant requests use an era-specific action ID. The identity includes chain, manager,
  channel, participant slot, expected current close-freeze nonce, hash-authenticated checkpoint, and
  the canonical cancellation transaction/block/log observation when re-requesting after cancel.
  Thus a cancel followed by identical request calldata cannot inherit an old terminal receipt.
- Guarded finalization uses the exact Store close-observation key. A digest-only action ID is
  rejected.
- Claims use `claim:<channel>:<participant-slot>:<token-slot>`.
- Credit claims use `credit-pull:<channel>:<withdrawal-nullifier>`; their channel-fund prerequisite
  uses the same ID with `:channel-funds` appended.

The Store ID and private outbox ID are identical. When multiple fee-bump hashes exist, finalized
events are accepted only if the event hash belongs to that exact action journal. A transaction from
another action, manager, channel, nullifier, token, recipient, amount, or close era cannot complete
the action.

## Crash and adversarial tests

Run the focused suite from `node/`:

```sh
node --test test/delegate-signed-transaction-outbox.test.js test/delegate-close-lifecycle.test.js
```

The suite injects crashes after nonce reservation, signing, journal/reservation fsync, broadcast,
receipt observation, and terminal-record fsync. It also covers byte-identical restart, target/data/
value mismatch, cross-process contention, persistent-lease exclusion, different-root rejection,
dead/live/remote/malformed/symlink locks, pending and reverted replacement rules, an older same-nonce
transaction winning after a fee bump, canonical receipt checks, expected-transition failure, and a
durable-head reorg during verification.

## Operator handling

Never delete or edit a journal or reservation merely to restore liveness. A retained reservation
means the signer nonce or semantic transition is not yet safely reconciled. Confirm the canonical
receipt, every journaled hash, and the expected manager state first. A finalized revert requires an
explicit fresh-nonce attempt; a dropped/pending transaction requires an explicit same-nonce fee
bump. Remote-owner, malformed, or lost-reservation errors require operator investigation and remain
fail-closed.
