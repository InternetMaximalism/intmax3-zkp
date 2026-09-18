# A-3 follow-up: channel close / withdraw-to-L1 / settle lifecycle (the real implementation)

Status: **the real implementation is essentially complete** (2026-06, A-3 P1–P6). The "hardening done in the audit pass" below has been **superseded** by this implementation (kept as a historical record).
Full details of what is done are in `doc/tasks/a3-impl-todo.md`. What remains is the **P5-B full CLI E2E** (consistency between the CLI members and the
on-chain registration on the close path = it needs an extension binding the withdraw pipeline to the channel's real members/deposit.
`withdraw` on its own has been verified live on anvil. close-intent shares a root cause with the existing gap where CloseLifecycleE2E skips because of a member-set mismatch).

## Done (the real implementation, replacing the old stubs)
- ✅ anchor uses real values (P1). ✅ close/settle/withdraw/claim CLI (P3/P4; withdraw verified live on anvil).
- ✅ C2/C3 stub revert (P6-A, attacker review GO). ✅ relay /api/close|settle|withdraw|claim (P5-A).

## Old: background / status (★ resolved by the real implementation; historical record)
- Deposits are really on-chain (`setup-backing` makes a real deposit into IntmaxRollup).
- However, **there is no L1 withdrawal path (close/withdraw/settle)**.
- The L1-close anchor (`ChannelFund.intmax_state_root`) is an all-zero
  **PLACEHOLDER** in `setup-backing` (`PLACEHOLDER_L1_CLOSE_ANCHOR_HEX`, `src/bin/channel_member.rs`),
  because the registration-time procedure that derives the real anchor (detail2 §K-4) is not implemented.
- Consistent with the memory `project_channel_close_unification.md`: "settlement is currently a stub".

## Hardening carried out in the audit pass (included in this PR)
- Turned the all-zero anchor into a named constant, making it explicit (and greppable) that it is an unimplemented placeholder.
- Added `close`/`withdraw`/`settle` subcommands to `channel_member` as **fail-closed stubs**.
  If they are called by mistake while unimplemented, they stop with a clear error and do not consume the placeholder anchor.

## What the real implementation needs (separate PR, a full threat model is mandatory)
- [ ] Derive the **real L1-close anchor** via the registration-time procedure in detail2 §K-4 and replace the placeholder.
- [ ] Verify that the close circuit (`src/circuits/channel/close_circuit.rs`) binds the anchor to a genuine rollup state root
      (rejecting zero/placeholder anchors).
- [ ] Implement `close`/`withdraw`/`settle` in `channel_member` so that they can actually drive real close-intent generation → on-chain
      submission to `ChannelSettlementManager` → the challenge period → payout.
- [ ] Connect the E2E with on-chain settlement (`ChannelSettlementManager` / `ChannelSettlementVerifier`) using real proofs
      (today `CloseLifecycleE2E` is fixture-based).
- [ ] Threat model: cover stale-state close, post-close over-claim, placeholder-anchor contamination,
      member-binding bypass, and double withdrawal.

## Related files
- `src/bin/channel_member.rs` (anchor placeholder + fail-closed stubs)
- `src/circuits/channel/close_circuit.rs`, `close_pis.rs`
- `contracts/src/ChannelSettlementManager.sol`, `ChannelSettlementVerifier.sol`
- `doc/architecture-audit/detail2.md` §K-4
