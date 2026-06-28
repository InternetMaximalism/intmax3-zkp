# INTMAX3 Node Programs

Two long-running agents that compose the `api/` REST surface, the `channel_member` CLI, the WASM
wallet, and the L1 contracts into a single supervisory loop with explicit branches for normal,
own-transaction, and abnormal flows. See [DESIGN.md](DESIGN.md) for the full specification.

- **Co-signer node** (`cosigner/`) — trusted N-of-N member: watches the chain, validates and
  co-signs peers' transitions (via the CLI's fail-closed gate), drives deposits/close lifecycle, and
  responds to abnormal on-chain events (stale close → challenge/cancel, attack → defensive mode).
- **Delegate account** (`delegate/`) — send-only client: generates its own tx/ZKP (WASM), submits
  for co-signing, **verifies** the co-signed result before finalizing, refreshes when required, and
  exits autonomously (claim / post-close claim) on co-signer fault.

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
# delegate (needs the WASM wallet: wasm-pack build --release --target nodejs --out-dir pkg-node):
INTMAX_NODE_CONFIG=config.json npm run delegate
npm test                                     # pure-logic unit suite (no network/WASM needed)
```

## Design invariants (enforced)
- **Orchestrators, not crypto.** Soundness is the CLI/WASM/on-chain gate; the loops add policy +
  liveness and never weaken a check.
- **Fail-closed classification.** Ambiguous/unknown events route to the defensive (co-signer) /
  exit (delegate) branch. Peers are refused when the channel is not Active or in defensive mode.
- **verifyCosigned before finalize.** The delegate never commits a co-signed state until it has
  verified signatures, head-extension, +1 version, and tx binding (`delegate/verify.js`).
- **Idempotent + resumable.** Action ids dedupe externally-visible effects; cursors/tickets persist
  crash-safely (`common/store.js`), so a restart resumes rather than double-acts.

## Status / limitations (see DESIGN.md §6.3)
- Adversarial-co-signer exit for a delegate currently uses the cooperative claim API; a standalone
  client-side withdrawal-claim prover (WASM) is the tracked follow-up.
- A45 partial-withdrawal cancel is alert-only (era-fence unsatisfiable — see `api/API-DESIGN.md`).
