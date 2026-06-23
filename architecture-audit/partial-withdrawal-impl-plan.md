# Partial withdrawal (channel → L1, channel stays open) — implementation plan + threat model

**Spec:** [abstract2-1.md](./abstract2-1.md) §0 (B-burn), §2.6, §3.6, §6.5–6.6 (added 2026-06-23).
**Design (approved):** cooperative N-of-N signed send whose leg targets `BURN_CHANNEL_ID`, settled as a base-layer L1 `Withdrawal`. Channel stays open. Non-cooperative exit remains the close game.

## Code grounding (what already exists — reuse, do not reinvent)

- Base-layer withdrawal stack is COMPLETE + tested: `src/circuits/withdraw/single_withdrawal_circuit.rs` (Transfer→`Withdrawal`, recipient via `extract_address_from_recipient`, `ADDRESS_TAG=0x02`), → `withdrawal_step` → `withdrawal_chain_circuit` → `withdrawal_circuit`; on-chain `IntmaxRollup.withdrawNative(Withdrawal[], prover, MleProof)` (MLE verify + `extCommitment ∈ finalizedStateRoots` + `withdrawalNullifierUsed` + `totalEscrowed` underflow + `pendingWithdrawals` credit). `withdrawNative` is UNCHANGED.
- Withdrawal nullifier = `SettledTransfer::nullifier()` (binds source `channel_id`+`block_number`+`transfer_index`) — verified canonical/position-bound (C14 test).
- `Tx` carries `destination_channel_id: ChannelId` (`src/common/tx.rs:229`); `ChannelId::new` already reserves `0` (=`dummy`).
- `generate_c2c_fixture.rs` already proves a channel→L1 withdrawal (the c2c RECEIVER channel withdraws via `single_withdrawal`). Inter-channel receive credit: `src/circuits/balance/receive_transfer_circuit.rs`.

## THE core security question to resolve first (exclusivity)

A single sent transfer must be consumed **exactly once**: either RECEIVED by a destination channel (`receive_transfer_circuit`) OR WITHDRAWN to L1 (`single_withdrawal` → `withdrawNative`) — **never both** (else value goes to a channel AND L1 = double-spend). Must determine + PIN how exclusivity is enforced today and extend it for burn legs:
- Hypothesis: exclusivity is **recipient-format-driven** — an `ADDRESS_TAG` (L1-address) recipient is only withdrawable (no channel member matches it in `receive_transfer_circuit`), and a channel-member recipient is only receivable (not `ADDRESS_TAG`, so `extract_address_from_recipient` rejects it). VERIFY this in `receive_transfer_circuit` (recipient match) and `single_withdrawal` (ADDRESS_TAG requirement). If a transfer could be BOTH received and withdrawn (same nullifier, different on-chain used-sets) → that is a pre-existing soundness bug; STOP + escalate.
- `BURN_CHANNEL_ID` role: make burn intent explicit + ensure the validity settlement never treats it as a creditable destination (`dest_channel_id = BURN_CHANNEL_ID` ⇒ no `ChannelLeaf` credit). Reconcile with the recipient-format mechanism (is `dest_channel_id` even read at withdrawal extraction, or only the recipient?).

## Threat model (attacker enumeration — must hold before merge)

| Attack | Mitigation (must verify in code) |
|---|---|
| Withdraw more than owned | `sender_delta = -Σamount` range-proven (sender post-balance ≥ total); on-chain `totalEscrowed` underflow. |
| Double-withdraw / replay same leg | `SettledTransfer::nullifier()` (channel+block+index) + on-chain `withdrawalNullifierUsed` check-then-set. |
| Cross-channel replay | nullifier binds source `channel_id` (a burn leg from chan X ≠ chan Y). |
| Burn AND credit a channel (double-spend) | burn leg `recipient_delta = ⊥`; settlement must credit no channel for `dest_channel_id = BURN_CHANNEL_ID`; exclusivity above. |
| Unauthorized withdrawal (non-member / unsigned) | leg rides N-of-N `signSmallBlock` over `hash(H1', H2)`. |
| Register a real channel at `BURN_CHANNEL_ID` | `registerChannel` (L1) + `ChannelId` validation must reject `BURN_CHANNEL_ID`. |
| Withdraw during/after close (race) | `requestClose` freezes sends; verify a burn-send cannot settle after freeze; finalized close uses latest agreed state. |
| Non-burn leg extracted as a withdrawal | `extract_address_from_recipient` must reject non-`ADDRESS_TAG` recipients (real channel-member recipients). |

## Implementation phases (ordered; each ends in `cargo test --release` + the relevant adversarial tests)

0. **Investigate + pin exclusivity** (above). Write a Rust test asserting a channel-member-recipient transfer is NOT withdrawable and an L1-address-recipient transfer is NOT receivable. (No code change; soundness gate.) **← do this BEFORE any fund-logic change.**
1. **`BURN_CHANNEL_ID` constant** (`src/constants.rs`) + reject it in `ChannelId` validation / `registerChannel` (L1) + the channel registration path. Sentinel e.g. `0xFFFF_FFFF`. Low risk; no fund logic.
2. **Validity/settlement burn-leg routing:** a settled leg with `destination_channel_id = BURN_CHANNEL_ID` (and `ADDRESS_TAG` recipient) is NOT credited to any channel; reject `recipient_delta ≠ ⊥`. Confirm `single_withdrawal` extracts it. (Core change — security review by a SEPARATE subagent, attacker subagent on the change.)
3. **Send path:** let a channel member build a burn-leg send (CLI `channel_member.rs` partial-withdraw command / witness generator), produce the `single_withdrawal` proof, and call `withdrawNative`. Likely mirrors `generate_c2c_fixture` (receiver-withdraws) but sender-side.
4. **Tests:** happy path (member partial-withdraws real ETH; channel stays open + keeps transacting), + adversarial: double-withdraw revert (nullifier), over-withdraw revert (totalEscrowed/range), burn-and-credit attempt rejected, withdraw-after-freeze blocked, non-member unsigned rejected, register-at-BURN_CHANNEL_ID rejected.

## Open decisions for next step
- Exact `BURN_CHANNEL_ID` value + whether `ChannelId::new` should reject it globally vs only at registration.
- Whether burn routing keys on `destination_channel_id == BURN_CHANNEL_ID`, on recipient `ADDRESS_TAG`, or BOTH (defense in depth) — resolve in phase 0.
- Single-leg (current impl is single inter-channel `receiver_deltas[0]`; abstract2-1 bulk is ahead of impl) vs bulk burn legs — start single-leg.
