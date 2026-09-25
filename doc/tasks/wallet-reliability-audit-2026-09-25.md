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
