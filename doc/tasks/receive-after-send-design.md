# Receive-after-send recovery: design findings (2026-09-22)

Status: original queue design. A feature-gated authenticated-tail circuit implementation and
its remaining deployment/migration requirements are recorded in
[`wallet-recovery-followup-2026-09-25.md`](wallet-recovery-followup-2026-09-25.md).
It is not enabled on existing channels. Follow-up to `HANDOFF-2026-09-22.md` §3.

## Verified constraints

- `receive_transfer_circuit.rs` requires `send_leaf.prev <= prev_block_r` and
  `new_block_r < send_leaf.cur` after a channel has sent. The received transfer's
  block must also be at most `new_block_r`. Deposit reception has the analogous window.
- `BlockWitnessGenerator::get_send_status` returns no next send for a balance cursor
  at or beyond the last send. `get_account_state` then chooses send leaf index zero;
  this is not evidence of an open receive window. The live-service rejection must remain.
- `LiveBalanceService::receive_inter_channel` currently proves reception before updating
  the signed head, applied-transition journal, private state, and signed-head exit kit.
  A queued item cannot truthfully return the existing completed `LiveBalanceReceipt`.
- The CLI allows a pure destination credit using its predecessor's verified exit kit.
  `adopt_head_with_exit_kit_receipts` then clears an incompatible receipt. Ordinary H2=0
  signing on that credited head fails as KIT-PENDING until the new kit is installed.
- Debit proposals already have a staged producer view in `prepare_exit_kit`, but
  `build_send_candidate` checks continuity against the durable live signed head and
  builds its spend witness from the durable private state. Both must be reconciled with
  pending receipts before proving a debit that spends received value.
- Current close behavior uses the existing signed head and its exit kit. The cooperative
  terminal-child close-funding path is explicitly retired (`enforce_exit_kit_before_signature_release`
  and `IMMEDIATE_CLOSE_FUNDING_RETIRED_REASON`). It cannot be reused as an implicit queue drain.

## Consequence for the handoff recommendation

Persisting inputs and replaying them before the next send is necessary scheduling work,
not a complete liveness fix. A receiver that never sends still needs a way to obtain a kit
and exit. Channel 7's existing credited CLI head also differs from its live-service head;
queue persistence alone does not repair that difference.

Do not remove the receive-window check, manufacture a completed receipt, exempt KIT-PENDING
from signing checks, or accept a receipt for a different head to make progress.

## Proposed implementation boundary

1. Persist a versioned per-channel pending-receive journal before acknowledging **queued**.
   Entries must bind the original request/fingerprint, producer receipt, source proof material,
   descriptor/nullifier, and destination predecessor/import/bundle states. Deposit entries
   must retain the verified deposit identity, index and salt. Exact retry is idempotent;
   changed input under one identity fails closed. Revalidate proof material when consuming it.
2. Expose pending versus proved status explicitly. Do not make queued balances spendable in
   the UI or mark the inter-channel operation completed until proof and exit-kit installation
   finish. Preserve recovery sidecars while queued. Limit queue size and input bytes.
3. Refactor candidate construction so a cloned live snapshot can consume eligible entries
   against a staged next-send block, then construct spend/send proofs and the successor kit.
   Require `received_block <= next_send_block - 1`; retain later entries. Bind this exact
   sequence to producer staging and signed-head continuity rather than mutating the durable
   live cursor during preparation.
4. Commit the candidate, consumed identities and applied receipts atomically only after the
   authoritative producer transition is committed. Recovery must distinguish queued,
   staged, producer-committed, and fully installed state. A crash must never double-credit
   or lose the source proof needed for recipient-independent completion.
5. **Resolve idle-recipient/close liveness before shipping:** specify and prove a valid
   window-opening channel action, or change the base protocol to support tail reception.
   A no-value send is a candidate, not an existing verified primitive: its TxV2/nonce/H2,
   signer-independent exit preparation, validity inclusion and no-value conservation all
   need validation. A queue-only implementation must not claim to restore unconditional
   receive/close availability. Do not reinstate retired cooperative close funding.

## Required acceptance scenarios

- A sends, then B credits A: real balance proof, exact kit installation and restart recovery.
- Multiple transfers and deposits, same-block boundaries, replay and altered descriptor/proof.
- Send spends newly received funds: queued receives precede spend-witness generation.
- An idle recipient closes without another user's transfer or sender cooperation.
- Crash before/after enqueue, staging, producer commit, candidate commit and kit installation.
- Existing channel 7 recovery from its original sidecars, without reset or duplicate credit.
- No-next-send refusal remains enforced unless a cryptographically valid window exists.

The next design decision is how to satisfy item 5. The original queue-versus-reset choice
omits this exit-liveness dependency; resetting the local stack would only hide it.
