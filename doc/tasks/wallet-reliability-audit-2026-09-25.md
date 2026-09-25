# Wallet reliability audit — 2026-09-25

## Baseline checkpoint

The user requested a committed checkpoint followed by autonomous fault/retry testing and repairs.
Use existing UI components; do not add recovery buttons or channel-specific navigation.
Worktree: `.claude/worktrees/handoff-wallet-session-998f4c`, branch `claude/handoff-wallet-session-998f4c`.
Keep the user's RPC8545, HTTPS8000, wallets and original channel data intact. Fault injection belongs
in a separate local test environment, never the user's running stack.

The baseline implements real Anvil validity publication/backing attestation, durable partial
withdrawal recovery and recipient pull, shared materializer deployment, safe HTTP error statuses,
verified TEST registration and signed-head exit-kit refresh after token registration. The browser
retains its simple Join, Send, Deposit and Withdraw components with collapsed messages.

Observed real user flow: channel19 imported0.01 ETH, sent0.001 ETH to17-0, then withdrew0.001 ETH
to0x9d4f46b2b701aa2875a18e8803338eaf3d466374. Recipient transfer was verified at Anvil block1597:
0xd8cc51f7a292ac22313b2646e0ed10f9d1188ec6f60bf97af641fb93fabb29ea.
Its internal ETH transfer succeeded and the actual balance increased by0.000968615999780312 ETH
net of gas. The local receipt's effectiveGasPrice differed from transaction gasPrice; the latter
reconciled the balance. Full public evidence remains in the gitignored runtime directory.

Previous validation:583 Node regressions (excluding the long resident live-balance suite), real
isolated ETH payouts and TEST deposit, four settlement deployment tests, and focused tests for
subsequent UI/HTTP/recovery fixes. These are historical results, not a claim that this audit passed.
Runtime dependency symlinks, browser/CLI keys, chain state, generated live proof fixtures and process
logs are not source deliverables. Generated tracked fixtures are preserved in the runtime backup
before restoring the checked-in baseline fixtures.

## Audit matrix

For each operation, check single action, repeat action, lost response after commit, failed request
before commit, reload, and recovery using the same component. Assert that failures never trigger
a second transfer/deposit/burn, discard the only recovery record, or strand a disabled button.

- Join: duplicate contribution; mismatched identity; deployment interruption; retry after commit.
- Deposit: wallet rejection; approval failure; receipt delay; lost import response; reload/retry.
- Send: double click; lost co-sign response; restart after source commit; stale destination/head.
- Withdrawal: lost burn response; repeated submit/finalize; claim rejection; reload after wallet tx.
- General: relay unavailable; malformed/failed ticket response; slow proof; unexpected exception.
- Shared deployment: multiple channels, unrelated rollup, retry after preparation.

Known structural limitation: receive-after-send windows remain a protocol-level liveness issue
(see receive-after-send-design.md). Do not remove proof checks, reset state, or disguise queued work
as complete. Separate verified recovery improvements from unresolved protocol work.

## Iterations

Results and fixes will be appended here with exact test commands/artifacts and remaining limits.

### Checkpoint

Baseline source checkpoint: `7d05a30` (`fix(wallet): checkpoint live Anvil wallet and withdrawal recovery`).
No push was requested. The user's Anvil chain and browser identity were preserved.

### Repairs in this audit

1. Deposit previously swallowed a failed ticket read and could start another payment. Failed or
   malformed pending-operation reads now stop new payments. Burn also re-reads tickets before proving.
2. L1 deposit and recipient-pull intents now persist **before** asking the wallet to send. The nonce,
   exact call, deployment/account context, and eventual transaction hash survive reload. A lost wallet
   response is reconciled against the exact mined nonce/call; changed amounts in the form cannot create
   a second payment. Explicit wallet rejection releases the intent; an ambiguous result retains it.
   Web Locks serialize wallet transmission across tabs where supported.
3. Both Send paths persist the exact proof request in IndexedDB before contacting the relay. Its add
   operation refuses to overwrite another pending request. The existing Send button becomes
   `Send (resume)` and replays that request after reload, independently of current form values. Requests
   are bound to channel, deployment and a hash of the saved channel identity. Recovery clears the
   record only after WASM verifies/imports the signed snapshot. Fresh solo sends retain slim/delta
   transport and worker finalization. Exact solo retries at the current head are reconciled by the
   local relay without signing again. Automatic generation of a replacement proof after an ambiguous
   stale-head response was removed.
4. Different buttons could mutate the same worker session concurrently. All guarded mutations now
   exclude each other, including Refresh and Clear. Clear refuses to discard identity while a locally
   journaled Send/Deposit exists.
5. Wallet selection hid the picker before MetaMask approval completed; the 200 ms poll then treated
   slow approval as cancellation. Selection now stays pending until the wallet resolves. Cancellation
   and rejection release Join; events from a previously selected provider no longer switch accounts.
6. Ticket/history files used non-atomic writes and treated any read failure as an empty queue. They
   now use fsync + same-directory rename and distinguish missing files from corrupt/unreadable files.
   Completion is archived before active-ticket replacement; the archive repairs that intermediate
   crash window on read. Full-withdrawal `settle_done` is not terminal: recipient claim is still needed,
   and neither the UI nor TTL cleanup may drop it early.
7. Repeated deposit-ticket registration and exact completed payout confirmation are idempotent,
   including when a newer operation exists. A replay does not modify the newer ticket.
8. Pending-operation rows no longer add separate Resume buttons. Existing Deposit / Withdraw controls
   perform recovery. Full-withdrawal controls restore from the saved step, including pending steps.
9. **Real Anvil reproduction:** importing an already-credited deposit after a later burn failed with
   `a generic signed-snapshot bind requires h2_tag == 0`. Deposit orchestration now checks the live
   authority: if the exact signed head is already durably bound and is not awaiting binding, there is
   no new generic bind to perform. Different/unbound heads still undergo the existing full validation.
   No proof checks, finality checks or protocol restrictions were removed.

### Browser fault runs (actual UI, simulated boundaries)

The fixture `hosting/wallet/test/wallet-ui-fault-server.js` serves the actual wallet HTML/components.
It substitutes the worker, wallet RPC and relay endpoints, binds only loopback, and has no Anvil or
MetaMask connection. These runs establish UI recovery behavior; they are **not** ZKP or L1 payout
proofs. Drive `/test/scenario` from a test runner; `/test/state` reports side-effect counters. Run with
`WALLET_UI_TEST_PORT=8092 node hosting/wallet/test/wallet-ui-fault-server.js` and open that origin.

| Scenario actually exercised through the browser | Observed result |
| --- | --- |
| Join opens wallet selection and then Deposit | Same Join component completes; no payment on Join |
| Ticket endpoint unavailable | Deposit stays usable; payment count remains zero |
| Malformed ticket array | Error indication; no additional payment |
| Wallet rejects approval | No payment; Deposit available again |
| Wallet broadcasts, response lost, page reload | Existing Deposit locates original nonce/call; one payment and one import |
| Import commits, response becomes HTTP 503, page reload | Same Deposit resumes; one payment and one import |
| Inter-channel send commits, response becomes HTTP 503, page reload | Same Send replays original proof; send count remains one |
| Double-click Deposit | Exactly one additional payment and import |
| Burn commits, response becomes HTTP 503 | Burn disabled; original Step 2 enabled; saved amount/recipient locked |
| Settle fails, then page reload | Original Step 2 retries; final ticket `settle_done`; total burns remains one |

Final isolated UI counters: port8091 = payments2/imports2/sends1; port8092 = burns1, ticket settled.
Port8090 separately exercised wallet-response loss (payments1/imports1 immediately after recovery).
A later socket-destroy experiment on8090 was retried transparently by the browser, so the stronger
HTTP503-after-commit fixture on8091 was used to force a user-visible interrupted import.

### Real isolated Anvil and process-termination runs

Dedicated environment: `/tmp/intmax-wallet-l1-e2e-v2-20260924`, RPC8558, relay8020/8021.
User RPC8545 and channels17/18/19 were not used for fault injection.

- Restarted the dedicated relay, then repeated completed recipient-pull confirmation three times:
  HTTP200 each time, recipient/operator balances and nonces unchanged. Existing transaction:
  `0x64a61b52e883d48818ac455ec2e61dae9479a1efc1f435af22f7d441420e8ed0`.
  Evidence: `audit-claim-repeat.json` in that test directory.
- Temporarily corrupted its ticket JSON: `/api/tickets` returned500, never an empty queue. Restored
  original bytes in `finally`: HTTP200 and both tickets recovered. Evidence: `audit-corrupt-ticket.json`.
- Repeated old deposit import after later withdrawals: reproduced HTTP500 before the fix; after the
  fix, two calls returned200 with **exactly the same signed-head digest**. No new L1 deposit was sent.
  Evidence: `audit-deposit-repeat.json` and `audit-deposit-repeat-fixed.json`.
- Killed actual child writers with SIGKILL during repeated updates and deterministically at four
  boundaries: partial temporary write, after file fsync, before rename, after rename. Readers saw a
  complete old or complete new ticket, never partial JSON. Tests also simulate archive-before-active
  interruption and ensure full settlement tickets survive TTL while awaiting recipient claim.

### Remaining limits — do not describe these as solved

- Receive-after-send windows remain a protocol-level liveness constraint; this audit does not reset
  the stack or bypass the receiver proof.
- A batched/slim send whose acknowledgment is lost, or a solo send whose exact head has subsequently
  advanced, still needs a durable per-request acceptance index for guaranteed automatic completion.
  The browser preserves the exact request and refuses to manufacture another transfer. That prevents
  an unsafe retry but can require operator recovery; it is not a claim of universal liveness.
- There is still a server crash window between a burn being signed and the withdrawal ticket being
  created. The existing producer/CLI recovery artifacts are retained, but a dedicated burn recovery
  journal and startup reconciliation need a separate follow-up. The UI burn-loss test covers loss
  **after ticket persistence**, not arbitrary death at every proving boundary.
- Unknown/unmined wallet broadcasts and nonce replacement by a different call retain their journal
  instead of guessing that no money moved. The bounded block scan may need more than one retry.
- Full-withdrawal restored controls and ticket retention are regression-tested; this audit did not
  execute a new full-close proof, ERC-20 withdrawal, testnet deployment, or MetaMask extension signing.
- EC2 relay behavior was not changed/tested end-to-end. New backend idempotence is for the local relay.

### Validation

Final broad run: **632/632 Node tests passed**, 76 test files (resident
`live-balance-service.test.js` excluded; this audit made no Rust changes). Command: Node test runner
on `node/test/*.test.js` excluding that long service file. The first sandboxed run could not bind
loopback for five HTTP tests; rerunning with local-network permission passed. New bind-idempotence
checks, exact solo replay checks, storage crash tests, wallet approval delays, and UI recovery tests
also passed independently. Syntax checks and `git diff --check` passed.

Local relay activation should retain RPC8545 and the existing runtime directory; browser changes
require reloading the page. Never clear browser identity or reset Anvil to apply these repairs.
