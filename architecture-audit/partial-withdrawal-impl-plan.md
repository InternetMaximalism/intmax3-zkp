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

### PRE-IMPLEMENTATION FACTS (verified 2026-06-24) — the burn Regev statement is THE soundness crux
- **FACT 1 (consistency) — RESOLVED:** `wallet_core::build_inter_channel_send` (1548-1554) debits BOTH
  `enc_balances[sender]` (→ `after_ct`) AND `channel_fund.amount -= amount` in ONE `ChannelState`
  transition; in-channel sends leave `channel_fund` unchanged (`ensure_same_channel_fund`,
  state_update_verifier.rs:316). So `build_burn_send` MUST debit both by `amount` in one transition —
  it is a FORK of `build_inter_channel_send` (the base Transfer recipient becomes
  `calculate_recipient_from_address(member_L1)` (ADDRESS_TAG) instead of the destination member pk;
  `destination_channel_id = BURN_CHANNEL_ID`). The SAME `Transfer{ADDRESS_TAG, amount}` is committed in
  the small block's `tx_tree_root`/H2 AND later extracted by `single_withdrawal` — that IS the bind.
- **FACT 2 (Regev burn statement) — SOUNDNESS-CRITICAL, NOT trivial reuse:** the E-2 ChannelUpdate AIR
  FORCES `sender_delta plaintext == receiver_delta plaintext == amount` (transfer_stark.rs:22-24, 97-99;
  `E2_SHAPE.expose_m=[_,_,true,true]`). `RegevProofPurpose` = {ChannelTx, ChannelUpdate, WithdrawClaim,
  BalanceRefresh} — NO sender-only/burn variant. So a burn (sender debits `amount`, NO channel receiver)
  CANNOT reuse E-2 with `receiver_delta=encrypt(0)` (fails the amount check). E-3 WithdrawClaim proves a
  FULL ct decryption (`ct == amount`), not a partial debit (`after = before − amount`), so it doesn't fit
  a partial burn either. **The burn needs a protocol-level decision:**
  - **(i) New `ChannelBurn` Regev AIR** — a variant of E-2 dropping the `receiver_delta` column: prove
    `before = after + sender_delta`, `sender_delta == amount`, sender-only. Cleanest semantics, but NEW
    hand-rolled lattice AIR + prover + verifier + a new `RegevProofPurpose` — and per detail2 the hand-
    rolled lattice constraints are pending independent audit, so adding an AIR carries audit weight.
  - **(ii) Padding-receiver reuse of E-2** — `receiver_delta = encrypt(amount, RESERVED_BURN_PK)` to a
    reserved sentinel Regev key no channel may register. E-2 passes (`receiver_delta == amount`); the
    phantom credit is unclaimable (no channel holds `RESERVED_BURN_PK`); the real fund movement is the
    base `withdrawNative`. MINIMAL code, but needs an explicit soundness argument: (1) `RESERVED_BURN_PK`
    is truly unregisterable/unclaimable, (2) the phantom `receiver_delta` cannot be replayed/credited
    anywhere, (3) the tx_leaf/settled_tx_chain binding stays sound with a sentinel receiver.
  **ESCALATED (do not pick unilaterally for crypto fund code):** option (i) vs (ii) is a Regev-protocol
  soundness decision needing lattice review. (ii) is far less code; (i) is cleaner but heavier+audit.
  Resolve this BEFORE writing `build_burn_send`. Everything else (FACT 1 fork, base withdrawal reuse,
  cosign, single_withdrawal, withdrawNative) is settled and ready once the Regev statement is chosen.

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

---

## DECIDED: burn Regev statement = (ii) padding-receiver reuse of E-2 (owner, 2026-06-24)

`build_burn_send` reuses E-2 ChannelUpdate UNCHANGED, with `receiver_delta = encrypt(amount, RESERVED_BURN_PK)`
to a reserved sentinel Regev key. No new lattice AIR/prover/verifier. The E-2 amount check
(`sender_delta==receiver_delta==amount`) is satisfied because the phantom credit IS `amount`.

### THREAT MODEL (adversarial — must be re-reviewed by a dedicated attacker subagent before merge, CLAUDE.md)
| Attack | Why blocked |
|---|---|
| Claim the phantom `receiver_delta` (credit a channel for the burned value) | PRIMARY: `dest_channel_id = BURN_CHANNEL_ID` is unregisterable (Phase-1 guard) — the receive side filters by `dest_channel_id = D`; no channel D = BURN_CHANNEL_ID exists, so no one credits the entry. DEFENSE-IN-DEPTH: `RESERVED_BURN_PK` has no known secret key, so even a mis-routed entry can't be decrypted/claimed. |
| Withdraw AND credit the same value (double-spend across layers) | base Transfer recipient is `ADDRESS_TAG` ⇒ withdraw-only (Phase-0 exclusivity, `tests/partial_withdrawal_exclusivity.rs`); never receivable by a channel. |
| Withdraw more than the member's share | E-2 forces `after = before + sender_delta`, `sender_delta == amount`, range ⇒ `before ≥ amount`; the base `withdrawNative` amount == the SAME Transfer's `amount`; on-chain `totalEscrowed` underflow caps L1. |
| Withdraw ANOTHER member's share | the E-2 + `InterChannelSend` update debit ONLY the sender slot (`ensure_slot_unchanged` on all others, state_update_verifier.rs:558-563); sender located by `source_pk_g`. |
| Double-withdraw / replay the burn | `SettledTransfer::nullifier` (channel+block+index) + on-chain `withdrawalNullifierUsed`; `settled_tx_chain`/`ChannelLeaf.prev` forbid re-settling the small block. |
| Privacy leak from the phantom delta | `amount` is public by design for an L1 exit (same boundary as inter-channel send); publishing the delta `m(z)` leaks nothing new. |
| Unauthorized burn (no N-of-N) | rides the normal N-of-N `signSmallBlock` over `hash(H1', H2)`. |

**RESERVED_BURN_PK:** a deterministic, well-known sentinel `RegevPk` (no secret); reject it in channel
registration (Rust `ChannelRecord::validate` + Solidity) as defense-in-depth (primary guard is BURN_CHANNEL_ID).

### Implementation steps (ready; (ii) chosen)
1. `RESERVED_BURN_PK` (canonical sentinel `RegevPk` + digest) in the regev module + registration guard
   (defense-in-depth alongside the BURN_CHANNEL_ID guard). Compilable, low-risk — START HERE.
2. `build_burn_send` = fork of `wallet_core::build_inter_channel_send`: `destination_recipient_pk =
   RESERVED_BURN_PK`, `receiver_delta = encrypt(amount, RESERVED_BURN_PK)`, base `Transfer.recipient =
   calculate_recipient_from_address(member_L1)` (ADDRESS_TAG), `destination_channel_id = BURN_CHANNEL_ID`;
   debit `enc_balances[sender]` + `channel_fund -= amount` (same as inter-channel send). Reuse
   `prove_channel_update` UNCHANGED.
3. Burn state-update verification — **RESOLVED (verified 2026-06-24): clean fork, NO new circuit code.**
   `state_update_verifier.rs:511-528` requires exactly 1 `receiver_delta` (burn supplies the phantom) but
   does NOT validate the receiver's channel membership ("Cross-channel membership of the receiver is the
   receiving channel's concern", 520-522) and imposes NO transport/delivery requirement on the sender
   side. The sender-side checks are: 1 receiver_delta, fund −= amount (537-539), sender-slot-only debit
   (558-563), tx_leaf chain push (524-528), H2/H1' atomicity (499-509). A burn (phantom receiver to
   `RESERVED_BURN_PK`, dest=`BURN_CHANNEL_ID`) satisfies ALL of these → accepted unchanged. NO new
   `PartialWithdrawalBurn` kind needed; `build_burn_send` is a pure fork of `build_inter_channel_send`.
4. `cmd_partial_withdraw`: build_burn_send → N-of-N cosign → post block → finalize → `single_withdrawal`
   over the burn Transfer → `withdrawNative` (recipient = member L1).
5. Heavy E2E (opt-in `INTMAX_RUN_HEAVY_E2E`): a member partial-withdraws real ETH, channel STAYS OPEN and
   keeps transacting; + adversarial (over-withdraw, double-withdraw, withdraw-another's-share FAILS,
   non-member, post-freeze). Needs real proving + ~15min anvil — validation is the long pole.

### STATUS (2026-06-24) — channel-layer burn DONE + VALIDATED
- Step 1 (`RESERVED_BURN_PK`): reused `RegevPk::padding()` (canonical all-zero, no secret, passes
  `validate()`/encryptable) — no new constant needed.
- Step 2 (`build_burn_send`): **DONE + VALIDATED** (commits `9836da4` + `f4b3397`). A thin wrapper over
  `build_inter_channel_send`. The test `build_burn_send_debits_only_sender_and_targets_l1`
  (tests/inter_channel_cli.rs) runs the REAL E-2 STARK + self-check and PASSES → the (ii) padding-receiver
  is SOUND at the channel layer (debits only the sender slot by `amount`, channel total drops, ADDRESS_TAG
  L1 recipient, dest=BURN_CHANNEL_ID). The hardest/most soundness-critical part is settled.
- Step 3: RESOLVED (clean fork, no new circuit code).
- REMAINING: **step 4** `cmd_partial_withdraw` — couple `build_burn_send` (channel layer) to the BASE
  withdrawal so `single_withdrawal` extracts the SAME burn Transfer (the c2c block-5 / build_channel_withdrawal
  base balance proof must reflect the burn send; this base⇔channel reconciliation is the next concrete
  piece) → N-of-N cosign → finalize → `withdrawNative`. **step 5** heavy anvil E2E (the long pole) +
  the dedicated attacker-subagent review (CLAUDE.md) before merge.

### STEP 4 PRECISE SCOPING (2026-06-24) — the (a) binding needs the channel's LIVE base balance proof
`cmd_withdraw` (channel_member.rs:1017) builds the base withdrawal via `build_channel_withdrawal`
(wallet_core.rs:3092), which constructs a SELF-CONTAINED lifecycle (its OWN registration + deposit +
ADDRESS_TAG send + `single_withdrawal`) — it is NOT integrated with the channel's live `ChannelState` nor
with `build_burn_send`'s burn `Transfer`. So for the (a) cryptographic binding, `cmd_partial_withdraw`
CANNOT just call `build_burn_send` + `build_channel_withdrawal` side-by-side (that is two independent
proofs moving the same amount — an attacker could run the base withdrawal WITHOUT the encBalance debit;
unsound). The (a) flow needs:
  1. `build_burn_send` → the channel small block (E-2 member debit + the burn `Transfer` in the TxV2),
     N-of-N cosign, post + the BP validity proof SETTLES the burn `Transfer`.
  2. A base BALANCE proof of the CHANNEL's LIVE account AFTER that settlement (the burn `Transfer` in its
     `settled_tx_chain`), then `single_withdrawal` over THAT proof → `withdrawNative`.
  3. The bind = `H1'` (N-of-N signed) commits the encBalance debit AND the `settled_tx_chain` (the burn
     `Transfer`); `single_withdrawal` extracts the same `Transfer`. This is exactly how the CLOSE proof
     binds `finalBalanceState ⇄ base withdrawal`, applied mid-channel.
This is a DEEP integration (a new base-withdrawal path over the channel's live state, not a fork of the
standalone `build_channel_withdrawal`), + the heavy anvil E2E (step 5). NOT a trivial fork; needs a fresh
focused fund-implementation session. The channel-layer half (build_burn_send) is done + validated and is
the foundation; the base-half integration + E2E is the remaining major work.

### CRITICAL BINDING FINDING (2026-06-24, heavy investigation) — two real gaps for the (a) base half
Mapped the base-withdrawal recipe (BalanceWitnessGenerator `spend_witness`/`send_tx_witness`/
`commit_send_tx`/`single_withdrawal_witness` + `BalanceProcessor::prove_send_tx`). Two soundness-critical
gaps surfaced that make the base half NEW design, not wiring:
1. **`settled_tx_chain` push mismatch.** The base `send_tx` circuit advances `settled_tx_chain` by
   `transfer.aux_data` ONLY when `spend_valid && aux_data != 0` (send_tx_circuit.rs:281-297;
   `settled_tx_chain_push`, balance_state.rs:306-315). But `build_inter_channel_send` sets the burn
   `Transfer.aux_data = Bytes32::default()` (wallet_core.rs:1508) while pushing the CHANNEL state's
   `settled_tx_chain` with a SEPARATE `tx_leaf` (line 1559). So a base withdrawal of the burn Transfer
   would push NOTHING (aux=0) ⇒ its `settled_tx_chain` ≠ the signed channel `H1'` chain ⇒ the binding
   silently breaks. FIX OPTION: make the burn `Transfer.aux_data = tx_leaf` so the base push matches the
   channel push (requires a burn-specific path in `build_inter_channel_send`, or a fork; must NOT change
   normal inter-channel sends, whose receiver-side credit assumes aux semantics).
2. **No mid-channel binding circuit.** The CLOSE path binds `finalBalanceState ⇄ base withdrawal` via the
   close circuit + the on-chain manager. There is NO equivalent for a mid-channel withdrawal: the base
   `single_withdrawal` → `withdrawNative` is NOT cryptographically tied to the signed channel `H1'`. So
   even with the chains matching (gap 1), nothing on-chain ENFORCES that the withdrawn member actually
   debited their encBalance under N-of-N. The (a) guarantee requires a NEW binding (a circuit/contract
   check that the withdrawal's `settled_tx_chain`/H1 equals a finalized, N-of-N-signed channel state that
   committed the encBalance debit) — modeled on the close `finalBalanceState`/`settledTxChain` match but
   for mid-channel. This is genuinely new fund/circuit design.

CONCLUSION: the (a) base half is NOT wiring — it is (i) the `aux_data=tx_leaf` consistency fix + (ii) a
new mid-channel base⇔channel binding (the close-path analogue). Both are fund/circuit-level changes
needing design + heavy validation + the attacker-subagent review. The channel-layer burn (build_burn_send,
validated) stands; the base half is a focused new fund-design effort. Pushing it through unvalidated would
be unsound (per CLAUDE.md) — surfaced here so the next session starts from the exact gaps, not a wrong
"just wire it together" assumption.
