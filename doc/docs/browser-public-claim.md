# Browser-owned public claim and backing recovery

> **RELEASE STATUS (2026-09-03): NO-GO.** The browser/delegate path now consumes only strict
> MLE/WHIR V2 compact proofs, but independent cryptographic review, public-chain acceptance, and
> the separate final-audit blockers are not complete. `IntmaxRollup.releaseRuntime` remains
> chain-31337-only. Do not describe a local browser claim as approval for public value movement.
> Old claim operations, journals, pending closes and V1 artifacts require clean retirement; none
> may be reinterpreted as V2.

This path lets a participant claim a finalized channel balance without giving the relay either
its Regev witness or its L1 signing key. It replaces the retired relay-owned `/api/claim` route.

## Security boundary

The browser worker owns the Regev secret. `wallet_withdrawal_claim` receives only the exact
Manager-finalized close digest, channel-state digest, balance H1, and token slot. It returns a
public claim tuple plus the MLE/WHIR proof; no secret key or decrypted witness is sent to the
relay. MetaMask (or another EIP-1193 wallet) owns the L1 recipient key and signs every transaction.

The relay is treated as untrusted for economic and contract authority. For every operation it
re-derives and revalidates:

- chain, channel, Manager, Rollup, verifier, close-funding materializer, and activation checkpoint
  from `settlement.json`, `channel_backing.json`, RPC, and the keyless
  `verify-settlement-binding` read-back;
- the `Closed` Manager state and exact finalized close/state/H1/token registry at one durable
  block (`finalized` on public chains, `latest` only on chain `31337`);
- recipient, amount, token slot/index, nullifier, and all 50 proof public inputs through the shared
  strict claim decoder.

Request bodies may carry only a public artifact and token slot when preparing, or an operation ID
and transaction hash when reconciling. Supplying `manager`, `rollup`, `recipient`, `tokenIndex`,
close context, calldata, or another authority field is rejected.

The browser independently compares the relay response with its WASM artifact, connected recipient
account, finalized registry, and the complete locally held compact-proof bytes before asking the
wallet to sign. It reconstructs the complete `submitWithdrawalClaim` calldata, including the
dynamic-byte length and zero padding, rather than checking only its tuple prefix. It similarly
reconstructs funding calldata and the exact payout calldata. For the proof submission it also
serializes every human-readable proof field back into the compact wire grammar, requires byte-for-
byte equality, and binds all 50 decoded public-input limbs to the claim tuple and finalized
context. Immediately before every signature request, the connected wallet provider executes an
`eth_call` over the exact sender/target/value/calldata; a deterministic verifier, schema, or state
revert therefore never reaches `eth_sendTransaction`.

The claim path accepts exactly the full `plonky2-mle-v3-solidity` schema/protocol version 3,
WHIR PoW 22 artifact and the compact `MLEWHIR3` encoding. Its sole Manager selector is `0x0b0f2d14` for
`submitWithdrawalClaim(WithdrawalClaim,bytes)`. V1, partially versioned, flattened, unknown-field,
non-canonical-hex, over-cap, mismatched full/compact, and mixed-schema artifacts are rejected before
calldata preparation. The Node decoder reconstructs the entire 16-field proof from the compact
bytes and requires equality with the human-readable proof, re-encodes both Solidity proof/config
ABI views, recomputes their Keccak and circuit/WHIR configuration digests, and checks every
proof/VK/config/pinned-verifier dimension and duplicate view. There is no devnet V1 exception.

Before any claim operation, the trusted settlement binding must identify the exact Rollup,
Manager, settlement verifier, close-funding materializer, and withdrawal-claim adapter/core. Its
finalized activation evidence and local config pins must agree with runtime code, adapter `core()`,
chain IDs, verification/circuit/WHIR digests, 64-byte protocol ID, and session ID. A proof whose
embedded identities disagree is rejected before transaction preparation.

## Transaction and replay protocol

The browser uses these routes:

1. `GET /api/browser-claim/context`
2. `POST /api/browser-claim/prepare`
3. `POST /api/browser-claim/reconcile-submit`
4. `POST /api/browser-claim/next`
5. `POST /api/browser-claim/reconcile-action`
6. `POST /api/browser-claim/status` to resume after a restart

The operation ID is content-addressed by the domain `IMBC`, chain, Manager, close-funding
materializer, channel, and proof-bound withdrawal nullifier. The first exact calldata for that semantic claim is persisted in
`browser_claim_journal.json`; a regenerated randomized proof cannot replace it. The file is written
0600 using write/fsync/atomic-rename/directory-fsync under a per-channel lock.

Every receipt, including a reverted receipt, is classified only after the transaction is at the durable head, its block is still
canonical, and a second receipt read agrees. Target, calldata hash, zero value, recipient sender,
Manager log address, event kind, nullifier, close digest, member key, recipient, token, amount, block
hash, and transaction hash are reconciled. A finalized revert releases only that transaction hash;
the immutable operation remains retryable. A missing/dropped transaction stays fail-closed rather
than silently allocating a replacement nonce.

Submission and nullifier-scoped payout are permissionless semantic races. If the locally prepared
transaction is pending, missing, or canonically reverted because another participant completed the
same action first, reconciliation searches only the pinned Manager's finalized history. Adoption
requires exactly one event matching the complete close digest/nullifier/member/recipient/token/
amount identity, a stable canonical receipt, and the corresponding nullifier and payout getters at
that receipt block. Other valid same-topic events are ignored before uniqueness is evaluated;
duplicate exact events, a same-height head replacement, changing receipt/log/body reads, or
durable-head and receipt-block getter stitching fail closed. The winning transaction may target an
account-abstraction or watchtower wrapper: its outer `to`, sender, and calldata are not semantic
authority. When the browser's own transaction body is available it is still checked against the
durable prepared target, calldata hash, zero value, and leaf-bound sender before any external result
can be adopted. Funding transactions retain their existing exact local transaction reconciliation.

The payout step always calls:

```text
claimWithdrawalCredit(bytes32 withdrawalNullifier)
```

The Manager's immutable `withdrawalPayouts(nullifier)` record supplies the proof-accepted recipient,
token, and amount. The browser interface deliberately omits every legacy aggregate/pay-all and
token-plus-amount overload. It never requires the recipient's aggregate credit to become zero,
because several accepted claims for the same recipient/token may coexist. Completion requires the
nullifier record to be consumed and exactly one matching
`WithdrawalClaimed(nullifier, recipient, tokenIndex, amount)` event from the bound Manager and
transaction. A fresh relay can therefore distinguish an already-paid claim from another claim's
remaining aggregate credit without trusting an off-chain journal.

## Hostile-coordinator recovery archive

The browser stores every complete snapshot that passes `wallet_import_channel` in IndexedDB under
`channelId:stateDigest`, using non-overwriting `add`. A bare state accepted through
`wallet_finalize` is not reported as complete until the browser fetches the exact published full
snapshot, verifies it again in WASM, and commits the IndexedDB transaction. Before proving a claim
for an older finalized head it reloads that exact snapshot and makes WASM verify it again. Archive
failure is fail-closed; users who need independently backed coordinator-withholding recovery should
also run the delegate archive below and back it up.

The Node delegate stores two immutable files before it advances `acceptedHead`:

```text
<workDir>/delegate-snapshots/<channelId>/<stateDigest>.json
<workDir>/delegate-backings/<channelId>/<stateDigest>.json
<workDir>/delegate-backings/<channelId>/<stateDigest>.verified.json
```

`BackingVault` requires `/backing` schema v2 and checks its source, chain, rollup, every nested
channel ID, complete signed head and record, signed-head digest, settled transaction chain,
binding status, proof length, a 64 MiB envelope limit, and 16 MiB per proof/verifier-data limit.
On every public chain it also requires `balanceVerifierDataSha256` in the top-level delegate config;
this must be the independently shipped audited BalanceProcessor verifier-data SHA-256, not a hash
learned from the downloaded response. Chain `31337` may omit the pin.

The canonical backing JSON is written to a fsynced 0600 stage. Before it becomes an archive, the
delegate invokes the release `public_close_prover --verify-only` binary with that exact file and
independently configured chain/rollup/channel/VD pin. This verifies the N-of-N signatures and the
recursive BalanceProcessor proof without constructing a close proof. The compact receipt must
exactly match the stage's chain, rollup, channel, signed-head digest, VD SHA-256 and proof byte
length. The archive marker additionally binds the backing SHA-256/byte length and settled chain.

Both files are published without overwrite using exclusive hard links. The verification marker is
installed first and the canonical backing pathname is the commit point; only an exact backing plus
exact marker is a valid archive. The order is:

```text
fetch and context-check exact backing
  -> native verify-only checks the exact fsynced backing file
  -> reconcile and stage the immutable verification receipt
  -> WASM authenticates complete snapshot
  -> publish immutable backing
  -> publish immutable snapshot
  -> persist participant close proof/balance
  -> advance acceptedHead
```

Bare states returned by send, refresh, inter-channel send, and burn are not special cases: the
delegate first obtains the exact complete published snapshot and sends it through the same gate.

If native verification fails, the stage is deleted before WASM import and neither backing pathname,
verification marker, snapshot nor `acceptedHead` is published. Exact idempotent replays reuse the
content-bound durable receipt, avoiding a proof-verification cost on every polling cycle. The
binary defaults to `target/release/public_close_prover`; `publicCloseProverBin` and
`publicBackingVerifyTimeoutMs` are operator-controlled config overrides. Missing binaries and
malformed, oversized, timed-out or nonzero-exit receipts are fail-closed at delegate startup/import.

## Tests

Run the focused suite with:

```sh
node --test \
  node/test/mle-v2-artifact-binding.test.js \
  node/test/browser-public-claim.test.js \
  node/test/delegate-backing-vault.test.js \
  node/test/delegate-sendability.test.js
```

The tests cover full/compact/ABI/config/pinned-view mutations, old/new schema mixing, malformed and
oversized compact encodings, caller authority substitution, browser-only claim generation wiring,
exact compact-proof calldata/signer/receipt/event reconciliation, permissionless submit/payout front-runs through
wrappers, unrelated and duplicate events, receipt/head/getter read stitching, aggregate-credit
races, journal idempotency, backing size and verifier-data pins, native verify-only argument binding, receipt/backing mismatch,
non-overwrite behavior, invalid/withheld backing, no-publication failure behavior, crash-safe
ordering, and own-transaction head admission.
