# Production public close publisher

> **Integration precondition:** public close and every resulting value movement remain
> release-blocked while the separately tracked MLE/WHIR PCS soundness repair and a real
> public-chain acceptance run are unfinished. This publisher hardens transport, recovery, and
> reconciliation; it does not repair the PCS or make a local/mock run a release acceptance result.

`public_close_publisher` is the release path from the keyless artifacts produced by
`public_close_prover` to `ChannelSettlementManager.submitCloseIntent`, followed by the exact-digest
and exact-request-era guarded `finalizeCloseGuarded(bytes32,uint64)` call. It changes no circuit,
proof, or verifier data, so it does not change proof size or proving time.

The delegate workflow no longer needs a cooperative coordinator after a finalized
`CloseRequested`: any participant can archive `/backing`, run `public_close_prover`, and hand its
immutable output directory to this publisher. The publisher account does not need to be a channel
member because proof submission and finalization are permissionless. A participant key is still
required for the earlier `requestClose` transaction.

## Release deployment manifest

Create this manifest from independently reviewed deployment records and runtime bytecode. Do not
copy addresses or hashes from the downloaded `/backing` response.

```json
{
  "schemaVersion": 1,
  "chainId": 1,
  "rollup": "0x1111111111111111111111111111111111111111",
  "rollupRuntimeCodeHash": "0x<keccak256-runtime-bytecode>",
  "manager": "0x2222222222222222222222222222222222222222",
  "managerDeploymentBlock": 12345678,
  "managerRuntimeCodeHash": "0x<keccak256-runtime-bytecode>",
  "settlementVerifier": "0x3333333333333333333333333333333333333333",
  "settlementVerifierRuntimeCodeHash": "0x<keccak256-runtime-bytecode>",
  "mleVerifier": "0x4444444444444444444444444444444444444444",
  "mleVerifierRuntimeCodeHash": "0x<keccak256-runtime-bytecode>",
  "balanceVerifierDataSha256": "0x<sha256-canonical-balance-vd>",
  "mleProofAbiVersion": 2,
  "submitCloseIntentSelector": "0x<4-byte-selector>",
  "finalizeCloseGuardedSelector": "0x<4-byte-selector>",
  "closeSubmittedTopic": "0x<32-byte-event-topic>",
  "closeFinalizedTopic": "0x<32-byte-event-topic>"
}
```

The binary recomputes all four selector/topic values from its compiled ABI and rejects a typo. At
the finalized block it additionally checks all four runtime code hashes and the live linkage
`manager.registry == rollup`, `manager.verifier == settlementVerifier`,
`settlementVerifier.closeMleVerifier == mleVerifier`, `mleVerifier.allowedChainId == chainId`, the
initialized close VK, channel id, challenge-period floor, member-set commitment, member count, and
delegate count.

`managerDeploymentBlock` is the release-reviewed deployment receipt block. It bounds a complete
event search used to adopt an exact permissionless submission/finalization performed by another
participant; guessing a recent search window is not accepted.

Useful derivations are:

```sh
cast sig 'submitCloseIntent((uint64,uint64,uint64,uint64,bytes32,bytes32,uint256[10],uint32[10],uint8,bytes32,bytes32,bytes32,uint64,uint64,bytes32,bytes32),(<audited-MleProof-v2-tuple>))'
cast sig 'finalizeCloseGuarded(bytes32,uint64)'
cast keccak 'CloseSubmitted(bytes32,bytes32,uint64,uint64,uint64,uint256,uint64,uint64,bytes32)'
cast keccak 'CloseFinalized(bytes32,bytes32,uint64,uint256,uint64,bytes32)'
cast code <address> --block finalized --rpc-url "$ETH_RPC_URL" | cast keccak
```

Use the exact MLE tuple printed by the audited deployment ABI; the publisher rejects anything
other than release ABI v2.

## Run

Build with the pinned dependency graph and select an encrypted Foundry account:

```sh
cargo build --release --locked --bin public_close_publisher
target/release/public_close_publisher \
  --bundle-dir public-close-output \
  --expected-final-channel-state-digest "0x<authenticated-final-signed-head-digest>" \
  --deployment-manifest close-deployment.json \
  --deployment-manifest-sha256 "0x$(shasum -a 256 close-deployment.json | cut -d' ' -f1)" \
  --journal private/channel-7-close-publisher.json \
  --signer-lock-root private/l1-signer-locks \
  --rpc-url "$ETH_RPC_URL" \
  --account intmax-close-publisher \
  --watch
```

`--expected-final-channel-state-digest` is independent channel authority from the authenticated
accepted signed head; it must not be copied from the bundle being checked. The publisher binds it
to the close descriptor, full intent, close/MLE public inputs, and private WAL before signing. A
coherent bundle for another (including older) head is rejected before WAL creation or signing with
an actionable deterministic diagnostic; it is never silently overwritten or quarantined.

The deployment SHA-256 is likewise independent startup authority, not a field read from the
manifest itself. The publisher hashes the exact bytes it parses and rejects a path replacement.
The account argument is a keystore selector. There is no raw-key CLI option. The journal and lock
directories are forced to private permissions. Every INTMAX publisher using the same account must
use the same canonical `--signer-lock-root`; the lock filename is
`.intmax-l1-signer-{chain}-{address}.lock`, preventing cross-publisher nonce races.

Without `--watch`, the command performs one durable transition and prints JSON describing what it
is waiting for. This makes it suitable for systemd timers or a delegate supervisor. With
`--watch`, it retries until completion or the bounded timeout.

## Crash, reorg, and race behavior

- The six proof-bundle files are regular-file checked, size bounded, individually SHA-256 bound,
  and cross-checked against the full Rust intent, all 103 close public inputs, and MLE public
  inputs before ABI encoding.
- The exact signed transaction is written with mode 0600, file fsync, atomic rename, and directory
  fsync before broadcast. Recovery decodes the raw bytes and only resends that transaction. If its
  nonce was consumed by an unknown sibling, publication stops.
- A receipt is accepted only after an independently read `finalized` head covers its canonical
  block. The receipt is read twice, the finalized checkpoint is re-read, and the exact manager
  event plus getters are checked at the receipt block. For semantic adoption, the outer
  transaction may target a batch/watchtower wrapper: authority is the event emitted by the pinned
  Manager address plus the complete Manager getter vector, never `receipt.to`. Same-topic events
  for other close identities are filtered out before requiring exactly one complete match; zero or
  multiple exact matches fail closed. Chain 31337 may explicitly use `latest`; this escape is
  rejected everywhere else.
- A stale pending close may be replaced only by the proof's strictly newer `(epoch,stateVersion)`
  inside the contract's bounded response tail. Equal/conflicting or newer pending state stops the
  publisher.
- Finalization exclusively calls
  `finalizeCloseGuarded(closeIntentDigest, closeRequestGeneration)`. The Manager's monotone
  `closeRequestGeneration` is read at one canonical durable checkpoint, then the generation,
  checkpoint, calldata, and calldata hash are fsynced in journal version 3 before signer access.
  The publisher re-reads the complete Manager state immediately before signing and again before
  broadcast. Cancellation never restores the generation, so an old signed finalizer cannot become
  valid if a later request reuses the same proof digest and freeze nonce. Prepared authorization
  metadata may rotate to a later generation only while no finalize raw WAL exists; once raw bytes
  exist, their generation, calldata, hash, and signer reservation remain immutable.
- A participant or watchtower may front-run either permissionless action safely. Submission
  adoption scans from the pinned deployment block, decodes every same-digest candidate, discards
  cancelled eras whose freeze nonce/deadline/event fields and receipt-block pending vector differ,
  and adopts only the canonically latest event matching the complete current pending state. An
  ambiguous latest transaction position fails closed. After closure, the adopted submission must
  be the latest exact event strictly before the unique guarded-finalization receipt. Finalization
  additionally reconciles the complete finalized getter vector, including every per-token payout
  cap. Missing, malformed, orphaned, or merely digest-adjacent evidence fails closed; locally signed
  but unbroadcast raw bytes remain recorded and are never relabelled as the external transaction.
- A completed journal is not treated as a cache. Every rerun revalidates its receipt, event,
  checkpoint, and current finalized manager state.

This implementation has mock/fault-injection coverage and Solidity lifecycle coverage. It has not
been exercised against a real public-chain deployment; that remains a release acceptance test,
not a claim made by this runbook.

## Delegate handoff

The delegate constructs the publisher once at startup from trusted configuration, then supplies
only its WASM-authenticated `acceptedHead` and the immutable snapshot/backing vaults on recovery
ticks. `CloseRequested`, `CloseSubmitted`, and an in-flight finalization all enter the same native
restart-safe state machine. JavaScript never accepts an event/request override for RPC, manager,
chain, deployment manifest, account selector, or signer-lock root, and no longer emits the old
`CLOSE_PROOF_DEFERRED` terminal log.

Required delegate settings are `publicClosePublisherBin`, `publicCloseDeploymentManifest`,
`publicCloseDeploymentManifestSha256`, `publicClosePublisherAccount`, `l1SignerLockRoot`, and
`balanceVerifierDataSha256`. `publicCloseProveTimeoutMs` and `publicClosePublishTimeoutMs` are
bounded operational settings. The same canonical `l1SignerLockRoot` must be supplied to every L1
publisher sharing the account. A failure leaves the channel in its existing close phase and retries
the native WAL on the next recovery tick; it never falls back to unguarded `finalizeClose()`.
