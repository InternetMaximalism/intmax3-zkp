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

## Status (2026-06-23)
- Phase 0 DONE (`tests/partial_withdrawal_exclusivity.rs`, committed `e5aa15e`): exclusivity is recipient-tag-driven (receive XOR withdraw); proven disjoint. Build on the existing `single_withdrawal` path.
- Phase 1 DONE (committed `c53384d`): `BURN_CHANNEL_ID` constant + registration guards (Rust `ChannelRecord::validate` + Solidity `registerChannel`). Both layers compile.
- Phase 2 LARGELY SUBSUMED: the validity circuit updates the SOURCE `ChannelLeaf` only (no auto-credit of destinations; destination credit is the receiver's voluntary `receive_transfer`, which a burn leg's `ADDRESS_TAG` recipient cannot satisfy). So a burn send is settled normally and extracted by `single_withdrawal` — no new routing circuit. Phase 2 reduces to: verify the validity settlement is unaffected by `dest = BURN_CHANNEL_ID`.
- Phase 3 (send-path command) + Phase 4 (heavy E2E + adversarial tests) REMAIN. The c2c fixture (`generate_c2c_fixture.rs`) already proves a channel→L1 withdrawal end-to-end (sender-side adaptation needed).

### Phase 3 grounded design (2026-06-23 investigation)
The withdrawal EXTRACTION recipe is `generate_c2c_fixture.rs` "Block 5" (`spend_witness([Transfer{recipient=calculate_recipient_from_address(L1), amount}]) → prove_send_tx → single_withdrawal_witness → SingleWithdawalCircuit → WithdrawalProcessor`). The base `Tx` here has NO `destination_channel_id` — `BURN_CHANNEL_ID` is a CHANNEL-LAYER (abstract2-1) marker, while the actual fund movement is this BASE-LAYER `ADDRESS_TAG` send. The base "native user IS the channel" (constants.rs): the `channel_id`'s base account holds the channel total; a channel withdrawal debits that base account.

What is NEW (fund-critical):
- `cmd_send` (channel_member.rs:1702) is INTRA-channel ONLY — `to` is a member SLOT (0..2), recipient is a member, value stays in the channel. There is NO "burn send" (ADDRESS_TAG / L1 recipient) command. Need a new `cmd_partial_withdraw` (+ `build_burn_send`): a member sends `calculate_recipient_from_address(member_L1_addr)` for a PARTIAL amount, debiting their own Regev encBalance (sender_delta = -amount), crediting NO member, then drive `single_withdrawal` → `withdrawNative` (recipient = member L1 addr, NOT the close manager).
- N-of-N cosign of the burn send (reuse `cmd_cosign*`), then the channel STAYS OPEN (stateVersion advances; members keep transacting).

DECIDED (owner, 2026-06-24): **(a) full channel-layer cryptographic binding.** A member can withdraw
only their OWN proven share — the burn send's `sender_delta` debits the withdrawing member's encBalance
under N-of-N agreement, and the base `single_withdrawal` withdrawal is bound to that agreed channel-state
debit. No reliance on co-signer honesty for the per-member share.

KEY REUSE INSIGHT (owner): the sender-side cryptographic balance proof for a burn send is ALMOST
IDENTICAL to a normal inter-channel send — both prove the SAME `sender_delta` debit on the member's
encBalance; only the destination differs (real channel credit vs L1 exit). So (a) is mostly REUSE, not
new crypto:
- Reuse the inter-channel send sender-side machinery (`InterChannelDebitPayload` /
  `InterChannelTransferDescriptor` / `cmd_cosign_inter_transfer`, channel_member.rs:1986) — the member's
  range-proven `sender_delta = -amount` debit + N-of-N cosign is unchanged.
- The ONLY new routing: `recipient = calculate_recipient_from_address(member_L1_addr)` (ADDRESS_TAG)
  instead of `calculate_recipient_from_user_id(dest_channel)`; `destination_channel_id = BURN_CHANNEL_ID`;
  NO destination-channel credit (no sibling B-state write — the inter-channel code's B-side step is
  replaced by the base withdrawal).
- Then the EXISTING base withdrawal extraction (c2c block-5 recipe: `single_withdrawal_witness` →
  `SingleWithdawalCircuit` → `WithdrawalProcessor`) → on-chain `withdrawNative` (recipient = member L1
  addr). The `single_withdrawal` proof binds the SAME settled transfer the cosigned send committed, so the
  base withdrawal is bound to the agreed member debit — that is the (a) cryptographic binding.

Remaining Phase 3 work: `build_burn_send` (fork the inter-channel debit build: ADDRESS_TAG recipient,
dest=BURN_CHANNEL_ID, no B-side credit) + `cmd_partial_withdraw` (cosign-inter-transfer reuse → post block
→ finalize → single_withdrawal → withdrawNative). Phase 4: heavy E2E (opt-in `INTMAX_RUN_HEAVY_E2E`,
member partial-withdraws real ETH, channel stays open) + adversarial (double-withdraw, over-withdraw, a
member withdrawing ANOTHER member's share must FAIL, non-member, post-freeze, register-at-burn-id).

### BIG REUSE FINDING (2026-06-24): `build_channel_withdrawal` already exists
`wallet_core::build_channel_withdrawal(&ChannelWithdrawalParams, ...)` (wallet_core.rs:3034) ALREADY
builds a complete channel→L1 withdrawal and **already supports a PARTIAL `withdrawal_amount`** (legacy
fixture: deposit 10, withdraw 3 — doc: "The withdrawal must not exceed it"). Params: `channel_id`,
`deposit_amount`, `withdrawal_amount` (the partial amount), `withdrawal_recipient` (L1 addr),
`deposit_salt`. Used by `generate_withdrawal_fixture.rs` and the close-lifecycle `cmd_withdraw`. So the
BASE-layer withdrawal extraction (spend ADDRESS_TAG → single_withdrawal → WithdrawalProcessor →
`withdrawNative`) for a partial amount is DONE and tested.
- For the close path, `withdrawal_recipient` = the settlement manager. For PARTIAL withdrawal,
  `withdrawal_recipient` = the withdrawing MEMBER's L1 address, and there is NO close/manager — pay the
  rollup `withdrawNative` straight to the member.
- WHAT (a) STILL NEEDS on top: the CHANNEL-LAYER binding so the base withdrawal debits the withdrawing
  MEMBER's encBalance share (not just the channel base total). I.e. couple a cosigned channel-layer burn
  send (`sender_delta = -amount` on the member's encBalance, reusing the inter-channel send sender proof)
  to the `build_channel_withdrawal` base withdrawal of the SAME amount, and bind them (the channel
  BalanceState debit ⇔ the base settled-transfer the `single_withdrawal` proves). This base⇔channel
  binding is the core remaining design+code (analogous to how the close proof binds the channel balance
  to the base withdrawal). Investigate how the close path binds `finalBalanceState` ⇔ base withdrawal and
  mirror it mid-channel.
- Net: `build_channel_withdrawal` covers the base half; the channel-layer member-debit + the base⇔channel
  binding is the genuinely new fund-critical work. Heavy E2E validation required.

### (a) DESIGN — FINAL (verified against the close-path binding, 2026-06-24)
Investigated the close binding (`close_circuit.rs` H1/IMCH recompute + balance-proof `settled_tx_chain`
connect; `withdrawal_claim_circuit.rs` + `decryption_gadget.rs` per-member decrypt; `state_update_verifier.rs`
inter-channel send). Result: (a) is sound and mostly REUSE. One **single `amount`** is bound at every step:

1. **Channel-layer member debit (per-member attribution — THE soundness crux):**
   `state_update_verifier.rs:556-582` (InterChannelSend) locates the sender slot by `source_pk_g`, then
   `ensure_slot_unchanged` on ALL OTHER slots (556-563) — **a member can only debit their OWN encBalance.**
   The `channel_update_zkp` proves `enc_balances[sender]_after = before + sender_delta` with `sender_delta`
   encrypting `-amount` (RegevStatement::ChannelUpdate, 569-582), and the channel total decreases by
   `amount` (540-543). N-of-N agree → new `BalanceState`/`H1'` commits the reduced encBalance + advanced
   `settled_tx_chain` (same H1 recompute the close proof checks, `h1_gadget.rs`).
2. **Base settlement of the SAME Transfer:** the burn `Transfer { recipient=calculate_recipient_from_address(member_L1), amount }`
   folds its `aux_data`=tx_leaf_hash into `settled_tx_chain` (send_tx circuit, gated on valid spend) and
   spends the base account by `amount`.
3. **Base withdrawal:** `single_withdrawal` extracts the burn Transfer → `withdrawNative` pays member_L1.
4. **The bind:** `H1'` (signed) commits BOTH the reduced encBalance share AND the `settled_tx_chain` (the
   base Transfer). `withdrawNative.amount == Transfer.amount == sender_delta debit == member encBalance
   reduction`. ⇒ a member withdraws EXACTLY their proven share. Over-claim + cross-member-claim CLOSED at
   the proof level (same guarantee class as `withdrawClaimZKP`, but mid-channel + partial).

**CORRECTION to the earlier "no extra binding needed" note:** per-member attribution is NOT automatic from
the base spend (which debits the channel TOTAL); it comes from the channel-layer burn update's `sender_delta`
on the sender's slot with all other slots fixed. The base withdrawal binds to it via the shared `amount`/
Transfer + `H1'`/`settled_tx_chain`.

**NEW code (small, channel-layer):** a **"ChannelWithdraw/burn" variant of `InterChannelSend`** that drops the
RECEIVER side — `sender_delta` debits the sender slot, NO `recipient_pk`/`receiver_delta` (value exits to L1,
credits no channel), channel total −= `amount`; reuse the Regev verifier + `channel_update_zkp`. Plus the
burn-update digest (signed like any state update).
**REUSE (no new crypto):** base withdrawal (`build_channel_withdrawal`/`single_withdrawal`/`WithdrawalProcessor`/
`withdrawNative`, partial supported); the per-slot Regev update machinery; N-of-N cosign (`cmd_cosign*`).

**Soundness checklist (mirrors close):** can't take another's share (only sender slot changes); can't
over-withdraw (`sender_delta` range-proven + `totalEscrowed` underflow); can't double-withdraw
(`SettledTransfer::nullifier` + `withdrawalNullifierUsed`); channel stays open (normal signed state update;
`stateVersion`/`settled_tx_chain` advance).

**ONE open question before coding `build_burn_send`:** does the channel maintain BOTH a base account
(`channel_id`) balance AND per-member encBalances, updated consistently per send? (c2c spends the base
balance; the channel layer has encBalances.) Pin the consistency invariant + where a burn send updates both.

---

## RELATED FEATURE — Additional deposit (mid-channel top-up). Requested 2026-06-23.

Symmetric to partial withdrawal: deposit more ETH to L1 **mid-channel** and add it to the channel
balance, WITHOUT re-creating the channel. Partial withdrawal is the EXIT half; additional deposit is
the ENTRY half. Both reuse existing base-layer machinery.

**Mechanism:** a member calls L1 `IntmaxRollup.deposit{value}(recipient, tokenIndex, amount, auxData)`
(escrows real ETH, `totalEscrowed += amount`, appends to the deposit tree); the channel then folds
that deposit into its balance state via `receive_deposit_circuit` (Merkle-proves the deposit at
`deposit_index` against `deposit_tree_root`, mints the amount, marks the deposit nullifier), advancing
`stateVersion` with N-of-N member agreement. This is exactly what `setup-backing` does at genesis,
repeated MID-CHANNEL.

**Reuse (do not reinvent):** `IntmaxRollup.deposit`, the deposit tree, `receive_deposit_circuit`
(C15-verified: deposit nullifier = leaf hash; binds `deposit_index`+`block_number`; double-fold blocked
by the nullifier tree), `Deposit::nullifier()`.

**Open questions (investigate first):**
- The channel uses per-member Regev `encBalances`; does a deposit fold into a member's encBalance via a
  channel-specific (Regev) deposit-fold, or does base `receive_deposit` suffice? Pin where the plaintext
  L1 deposit amount is added to the (encrypted) channel balance, and which member is credited.
- Recipient form of a channel deposit (the `recipient` Bytes32) must point to the channel/member identity
  (USER_ID_TAG form), NOT `ADDRESS_TAG` (which is withdraw-only by the phase-0 exclusivity).
- N-of-N agreement on the post-deposit state (abstract2 §3.3.2b accepts the deposit mint without a
  per-deposit signature, but the resulting `BalanceState` update is member-agreed).

**Threat model:**

| Attack | Mitigation |
|---|---|
| Fold a deposit not escrowed on L1 | deposit Merkle inclusion vs on-chain `deposit_tree_root`; `deposit()` escrows real ETH. |
| Double-fold the same deposit (mint 2×) | `Deposit::nullifier()` + nullifier tree (C15 — double-insertion blocked). |
| Credit a non-depositor / wrong amount | recipient binding + amount folded verbatim from the on-chain deposit. |
| Top-up racing a close | close freeze; a deposit fold must not race a finalized close. |

**Phases:** A. investigate the channel deposit-fold (Regev) + recipient form + which member is credited.
B. `channel_member` top-up command (L1 `deposit` → `receive_deposit` fold → N-of-N agree). C. tests
(happy: channel balance += deposit, channel stays open; adversarial: double-fold reject, unescrowed-
deposit reject, post-close reject) — happy E2E is heavy (opt-in `INTMAX_RUN_HEAVY_E2E`).
