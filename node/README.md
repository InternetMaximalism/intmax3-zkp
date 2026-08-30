# INTMAX3 Node Programs

Two long-running agents that compose the `api/` REST surface, the `channel_member` CLI, the WASM
wallet, and the L1 contracts into a single supervisory loop with explicit branches for normal,
own-transaction, and abnormal flows. See [DESIGN.md](DESIGN.md) for the full specification.

- **Co-signer node** (`cosigner/`) — trusted N-of-N member: watches the chain, validates and
  co-signs peers' transitions (via the CLI's fail-closed gate), drives deposits/close lifecycle, and
  responds to abnormal on-chain events (stale close → challenge/cancel, attack → defensive mode).
- **Delegate account** (`delegate/`) — send-only client: generates its own tx/ZKP (WASM), submits
  for co-signing, **verifies** the co-signed result before finalizing, refreshes when required, and
  can freeze the channel itself with `requestCloseAsParticipant` on co-signer fault.

## Layout
```
common/   chain-watcher  api-client  cli  wallet  store  policy  log  alert
cosigner/ classify  state-machine  loop  index  branches/{cosign,deposit,close,abnormal}
delegate/ classify  state-machine  verify  loop  index  branches/{sync,owntx,exit}
test/     unit suites (classify truth tables, state machines, policy, store, verifyCosigned)
```

## Run
```bash
npm install
cp config.example.json config.json          # edit rpcUrl, channels[].{rollup,manager,verifier,workDir}
# co-signer (needs target/release/channel_member built + an api/ or anvil reachable):
INTMAX_NODE_CONFIG=config.json npm run cosigner
# delegate (secret-preserving Node WASM wallet plus the L1 key for account.recipient):
../hosting/build-wallet-node-wasm.sh
INTMAX_NODE_CONFIG=config.json \
DELEGATE_SEED_HEX=<persistent-32-byte-hex-secret> \
INTMAX_DELEGATE_L1_PRIVATE_KEY=<recipient-key> npm run delegate
npm test                                     # pure-logic unit suite (no network/WASM needed)
```

The co-signer listens only on `127.0.0.1` by default. If `cosignerHost` is configured to expose it
remotely, set the same high-entropy `INTMAX_COSIGNER_BEARER_TOKEN` on the co-signer and delegates,
and put the connection behind TLS/VPN; startup otherwise fails closed.
`INTMAX_API_TOKEN` is separate: set it on both the coordinator API and co-signer process so the
authenticated `/close/claim` proxy can reach the native prover without reusing the peer-signing
bearer.

`DELEGATE_SEED_HEX` is mandatory for the daemon and must be retained in an operator secret store:
it deterministically restores the same Falcon/Regev identity after restart. It is never written to
the node store or snapshot vault. Losing it makes the signed delegate slot unspendable; exposing it
gives control of that slot. Browser localStorage seed persistence remains testnet-only.

`chainId` is required and checked against the RPC before polling. Durable chain actions use the
RPC's `finalized` head. `confirmations` is consulted only when
`allowUnfinalizedDevnet: true`, which is rejected unless the configured chain ID is exactly 31337.
That escape hatch is for anvil-style tests; do not enable it on a public chain. The persisted cursor
includes the finalized block hash and parent hash. If either changes, the node records a sticky
chain-safety halt and refuses signing/actions until an operator reconciles the deployment and store.
The co-signer does not open its HTTP listener until the first finalized scan completes; an ordinary
poll outage after startup temporarily returns `CHAIN_UNAVAILABLE` and inhibits deadline timers until
a later complete scan restores readiness.

## Design invariants (enforced)
- **Orchestrators, not crypto.** Soundness is the CLI/WASM/on-chain gate; the loops add policy +
  liveness and never weaken a check.
- **Fail-closed classification.** Ambiguous/unknown events route to the defensive (co-signer) /
  exit (delegate) branch. Peers are refused when the channel is not Active or in defensive mode.
- **verifyCosigned before finalize.** The delegate never commits a co-signed state until it has
  verified signatures, head-extension, +1 version, and tx binding (`delegate/verify.js`).
- **Idempotent + resumable.** Action ids dedupe externally-visible effects; cursors/tickets persist
  crash-safely (`common/store.js`), so a restart resumes rather than double-acts.
- **Finalized chain authority.** Public-chain logs drive durable actions only at/below the RPC
  `finalized` head; every cursor is hash-checkpointed and a changed checkpoint fails stop.

## Status / limitations (see DESIGN.md §6.3)
- Delegate close **initiation** is unilateral: after importing an N-of-N-authenticated snapshot it
  derives the immutable depth-10 participant path, checks the configured L1 key owns the signed
  recipient, checks the manager's root/count, and submits `requestCloseAsParticipant` itself.
- Once a close is finalized, delegate claim proving/submission is local and multi-token: every
  WASM-authenticated snapshot is archived by digest, `wallet_withdrawal_claim` re-imports the
  exact finalized state,
  proves with the in-WASM Regev secret, and exports only public claim/MLE calldata. The delegate
  validates all 50 public inputs and submits each positive token claim. If a production live
  withdrawal has already created the manager's rollup backing, the delegate permissionlessly pulls
  that existing backing and its own credit with the signed recipient key. Those pull functions do
  not create `pendingWithdrawals[manager]`; the live withdrawal producer is a separate availability
  requirement. The
  co-signer's `/close/claim` route remains an authenticated legacy compatibility proxy, not the
  production delegate path.
- A hostile coordinator can still withhold the public balance attestation needed to build and
  submit the close-intent proof after the delegate freezes the channel. That availability seam is
  distinct from claim secrecy and remains explicit in DESIGN.md §6.3.
- Post-close claims are disabled on-chain because an incoming transfer present in a closeable
  state is already included in the ordinary slot-balance claim; a second claim would double-credit.
- A45 partial-withdrawal cancel is alert-only (era-fence unsatisfiable — see `api/API-DESIGN.md`).
