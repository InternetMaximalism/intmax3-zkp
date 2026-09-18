# A-3 P5 and beyond — plan (relay + full E2E + stub revert + cleanup)

Base documents: `doc/tasks/a3-close-lifecycle-spec.md` (the approved full scope), `doc/tasks/a3-impl-todo.md` (progress).
Prerequisite: P1–P4 complete (P4 is closed out by `withdraw` in `doc/tasks/a3-p4-withdraw-handoff.md`).

---

## P5 — relay endpoints + full anvil E2E

### P5-A. relay endpoints (`wallet/wallet-relay.js`)
Same shape as the existing `/api/inter/send` etc. (launch the CLI in the channel dir, switching cwd). Additions:
- `POST /api/close` → `channel_member close <manager>` (co-signing is a single command because the relay owns all members)
- `POST /api/settle` → `channel_member settle <manager>`
- `POST /api/withdraw` → `channel_member withdraw <manager>`
- `POST /api/claim` → `channel_member claim <manager> <slot>` (CLAIM_RECIPIENT env)
- Each passes ROLLUP/MANAGER/SV via env. Same for `wallet-relay-ec2.js`.

### P5-B. Full E2E test (`tests/close_lifecycle_cli_e2e.rs`, new, heavy, anvil)
**This is the live verification point for every CLI command in the close lifecycle.** Flow:
1. Start anvil + deploy IntmaxRollup + ChannelSettlementVerifier + ChannelSettlementManager with the existing deploy (`DeployClose.s.sol`).
2. **VK initialization** (a mandatory prerequisite after deploy):
   - `IntmaxRollup.initializeWithdrawalVk(...)` (for the existing withdrawNative)
   - `ChannelSettlementVerifier.initializeCloseVk(...)` (for close, the VK from `generate_close_fixture`)
   - `initializeWithdrawalClaimVk(...)` (for claim)
   - Each VK is the degreeBits/preprocessedRoot/gatesDigest/whirParams/kIs/subgroupGenPowers emitted by the corresponding `generate_*_fixture`. It must match the VK of the MLE the CLI generates.
3. `registerChannel` (register the member set / bp / recipients → must match the manager's member_set_commitment).
4. CLI-driven: `setup-backing` (real deposit) → `init` → arbitrary sends → **`close`** (requestClose+submitCloseIntent) → advance the challenge period with `anvil` / `cast rpc evm_increaseTime` → **`settle`** (finalizeClose) → **`withdraw`** (withdrawNative+pullChannelFunds) → **`claim`** (submitWithdrawalClaim+claimWithdrawalCredit).
5. **assert**: the member's L1 ETH balance increases after claim (within the global solvency bound `totalCreditedOut ≤ receivedChannelFunds`). Strong negatives (rejecting a tampered close, stale challenge, etc.) using the fixed error-string patterns from `inter_channel_live.rs`.
- Challenge-period manipulation: anvil's `evm_increaseTime` + `evm_mine` (via cast rpc).
- **Requires user permission** (heavy proving + anvil). `#[cfg_attr(debug_assertions, ignore)]` + release.

### The key to verifying P5
Consistency between VK initialization and registerChannel is the biggest pitfall (matching member_set_commitment / gatesDigest / finalizedStateRoots). `CloseLifecycleE2E.t.sol` already has this consistency green in the fixture version, so the safe approach is to transcribe its set-up into the CLI-driven version.

---

## P6 — §H-3 stub revert (resolving the conformance divergence) + cleanup

### P6-A. Make specialClose (C2) / lateOutgoingDebit (C3) revert [SECURITY]
A **live divergence** found in the conformance audit: detail2 §H-3 explicitly states that both are "forgeable stubs, so the entry points must revert". Today, `submitSpecialClose` / `submitLateOutgoingDebitCorrection` in `ChannelSettlementManager.sol` are **live** (anyone can call them and a forged `_matches` stub passes). There is no loss of funds, but **freeze-grief** is possible.
- Fix: make both entry points `revert` immediately (dedicated errors, e.g. `SpecialCloseDisabled` / `LateDebitDisabled`). The stub verifiers may remain, but the entries are closed off.
- **Impact**: Manager bytecode change → CREATE2 manager address drift → **close-lifecycle fixture regeneration** (same procedure as A-2: confirm the new address with `WD_RECIPIENT=<new manager> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture`, then regenerate). Re-confirm that all of forge is green.
- Update detail2 §H-3 to "disposition implemented".

### P6-B. Cleanup
- Remove `cmd_close_lifecycle_unimplemented` (once all commands are implemented).
- Mark `doc/tasks/a3-close-lifecycle-followup.md` as closed.
- Check off everything in `doc/tasks/a3-impl-todo.md`.
- Record the (approved) decision not to adopt the §K-4 anchor on-chain check in detail2-implementation-notes.md as an "approved deviation".
- (Optional) If the defensive improvements raised by the P2 security review are to be made (early cancel era-fence check, post-close `incoming_tx_index < accumulator.len()`, Regev pk length validation), do them in P6.

---

## Overall remaining effort (rough estimate)
| Item | Size | Weight |
|---|---|---|
| P4 `withdraw` (separate handoff) | Large (porting the rollup withdrawal subsystem) | Heavy proving |
| P5-A relay | Small (existing pattern) | Light |
| P5-B full E2E | Medium–large (VK init / register consistency + driving all commands) | Heavy (anvil + real proofs) |
| P6-A stub revert + fixture regeneration | Small–medium | One fixture regeneration |
| P6-B cleanup | Small | Light |

## Invariant rules (common to all Ps)
- If the bytecode of IntmaxRollup / Manager changes, regenerate the close-lifecycle fixture (CREATE2 drift stemming from the metadata hash).
- Get user permission before running heavy proving / anvil E2E.
- Soundness is in-circuit. The CLI/relay is wiring only (verified by the P2 builder). Any change that touches proofs needs a threat model → review by a separate agent.
- Do not read private keys from `.claude/priv`; use shell expansion only (CLAUDE.md).
