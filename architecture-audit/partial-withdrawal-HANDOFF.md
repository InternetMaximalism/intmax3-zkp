# HANDOFF — Mid-channel PARTIAL WITHDRAWAL (channel → L1, channel stays open)

**Date:** 2026-06-24 · **Branch:** `fix/audit-soundness-and-tests` (main repo `/Users/plasma/repos/intmax3-zkp`, HEAD `586bac0`).
**Authoritative design doc:** [`partial-withdrawal-impl-plan.md`](./partial-withdrawal-impl-plan.md) (read it — this is a summary).
**Spec:** [`abstract2-1.md`](./abstract2-1.md) §0 (B-burn), §2.6, §3.6, §6.

## 0. Goal
A channel member withdraws **part** of their balance to L1 **without closing** the channel. Design (a):
the member debits ONLY their **own** Regev `enc_balances[slot]` by `amount` under N-of-N agreement, and a
base-layer `single_withdrawal` → on-chain `withdrawNative` pays their L1 address. Channel stays open
(`state_version`/`settled_tx_chain` advance, members keep transacting). The withdrawn `amount` must be
**cryptographically bound** to the member's proven encBalance debit — a member can withdraw only their
own share (over-claim / cross-member-claim closed at the proof level).

## 1. DONE + committed (do NOT redo)
| commit | what |
|---|---|
| `ad72f1b` | Spec into abstract2-1 §0/§2.6/§3.6/§6 + the impl-plan doc |
| `e5aa15e` | **Phase 0** exclusivity soundness gate (`tests/partial_withdrawal_exclusivity.rs`): receive XOR withdraw is recipient-tag-driven (USER_ID_TAG vs ADDRESS_TAG=0x02 disjoint). 3 tests pass. |
| `c53384d` | **Phase 1** `BURN_CHANNEL_ID = 0xFFFF_FFFF` (src/constants.rs) + registration guards (Rust `ChannelRecord::validate` + Solidity `IntmaxRollup.registerChannel`). Both layers compile. |
| `0c6d103`,`4c75454`,`db40564`,`2f900eb` | Design locked: (a) full channel-layer binding; the burn Regev statement = **(ii) padding-receiver** (decided by owner); threat model. |
| `9836da4` | **`build_burn_send`** (`src/wallet_core.rs`, right after `build_inter_channel_send` ~line 1684): thin wrapper, dest=`BURN_CHANNEL_ID`, phantom receiver=`RegevPk::padding()`, base Transfer recipient=`calculate_recipient_from_address(member_L1)` (ADDRESS_TAG). |
| `f4b3397` | **VALIDATED** `build_burn_send` (`tests/inter_channel_cli.rs::build_burn_send_debits_only_sender_and_targets_l1`): real E-2 STARK + self-check PASS → the (ii) padding-receiver is sound at the channel layer (debits ONLY sender slot, channel_fund drops, ADDRESS_TAG recipient, dest=BURN_CHANNEL_ID). |
| `2fda8d0`,`586bac0` | Step-4 scoping + the CRITICAL binding finding (see §3). |

**Channel-layer half is DONE + VALIDATED.** The base half (steps below) is the remaining work.

## 2. The reusable / validated pieces to build on
- `wallet_core::build_burn_send(keys, snapshot, sender_slot, withdrawal_l1_address: Address, amount, before_amount, before_witness, new_nullifier_root, level, rng) -> WResult<BuiltInterChannelSend>` — produces the channel small block: E-2 encBalance debit + the burn `Transfer` (in `transfer_descriptor.tx_v2`/`tx_tree_root`) + post-debit `proposed_next_state` (with `settled_tx_chain'` = push(prev, `tx_leaf`)). N-of-N cosign is separate (`cmd_cosign*`).
- Base withdrawal recipe (REUSABLE, real proving, NO anvil): `src/circuits/test_utils/balance_witness_generator.rs` — `BalanceWitnessGenerator::new(channel_id, salt, block_gen, &balance_processor)` → `spend_witness(&[transfer])` → `spend_circuit.prove` → build `Tx`/`TxV2`/transfer trees → `add_block_with_tx_v2` → `send_tx_witness(SendTxData{..})` → `balance_processor.prove_send_tx` → `commit_send_tx` → `single_withdrawal_witness(SingleWithdrawalData{transfer, transfer_index:0, ..})` → `SingleWithdawalCircuit::prove`. Worked example: `src/bin/generate_c2c_fixture.rs` "Block 5" (lines ~509-633).
- `single_withdrawal` derives `Withdrawal{recipient=extract_address_from_recipient(transfer.recipient), amount, nullifier=SettledTransfer::nullifier(channel_id, transfer_index, block_number)}` (single_withdrawal_circuit.rs:369-393). C14-verified canonical.
- Validation harness (NO anvil, real STARKs): `tests/inter_channel_cli.rs` (`#![cfg(not(debug_assertions))]`) — `build_cli_channel(id, &[balances])`, `cli_keys(slot)`, `LEVEL`, `fresh_root(tag)`. The `build_burn_send` test already lives here — add the integration test next to it.

## 3. THE REMAINING WORK — base half = NEW design, 2 soundness gaps (NOT wiring)
Heavy investigation found the base half is **not** "call build_burn_send + build_channel_withdrawal side by
side" (that is two independent proofs moving the same amount — unsound: the base withdrawal could run
WITHOUT the encBalance debit). Two concrete gaps:

### GAP 1 — `settled_tx_chain` push mismatch (fixable)
- Base `send_tx` circuit advances `settled_tx_chain` by `transfer.aux_data` ONLY if `spend_valid && aux_data != 0` (`src/circuits/balance/send_tx_circuit.rs:281-297`; `settled_tx_chain_push`, `src/common/balance_state.rs:306-315`).
- But `build_inter_channel_send` sets the burn `Transfer.aux_data = Bytes32::default()` (0) (`src/wallet_core.rs:1508`) while pushing the CHANNEL state's `settled_tx_chain` with a SEPARATE `tx_leaf` (line 1559: `tx_leaf = tx_leaf_hash(source_pk_g, sender_delta.digest, receiver_pk_g, receiver_delta.digest)`).
- ⇒ a base withdrawal of the burn Transfer pushes NOTHING (aux=0); its `settled_tx_chain` ≠ the signed channel `H1'` chain ⇒ binding silently breaks.
- **FIX:** give the burn `Transfer` `aux_data = tx_leaf` so the base push matches the channel push. Needs a burn-specific path (param/fork of `build_inter_channel_send` — must NOT change normal inter-channel sends, whose receiver-side credit relies on the current aux semantics). FIRST STEP: confirm empirically with a heavy integration test (build_burn_send → base send_tx over the same Transfer → compare `proposed_next_state.settled_tx_chain` vs the base `BalancePublicInputs.settled_tx_chain`).

### GAP 2 — no mid-channel binding circuit (deep, the real work)
- The CLOSE path binds `finalBalanceState ⇄ base withdrawal` via the close circuit (`close_circuit.rs`: H1 recompute + balance-proof `settled_tx_chain` connect) + the on-chain `ChannelSettlementManager`.
- There is **NO equivalent for a mid-channel withdrawal**: `single_withdrawal` → `withdrawNative` (base rollup, not the manager) is NOT cryptographically tied to the signed channel `H1'`. So even with GAP 1 fixed, nothing ENFORCES that the withdrawing member debited their encBalance under N-of-N.
- **NEEDS:** a NEW binding — a circuit/contract check that the withdrawal's `settled_tx_chain`/H1 equals a FINALIZED, N-of-N-signed channel state that committed the encBalance debit. Model it on the close `finalBalanceState`/`settledTxChain` match, but mid-channel (no close, no manager). This is genuinely new fund/circuit design + heavy validation + the mandated attacker-subagent review (CLAUDE.md).

## 4. Recommended next-session order
1. **Confirm GAP 1 empirically** — write a heavy Rust integration test in `tests/inter_channel_cli.rs`: `build_burn_send` → build a base `send_tx` proof over the SAME burn `Transfer` (BalanceWitnessGenerator recipe) → assert whether the base `settled_tx_chain` matches `proposed_next_state.settled_tx_chain`. (Likely FAILS → proves GAP 1.) Then implement the `aux_data = tx_leaf` fix (burn-specific path) and re-run until they match.
2. **Design GAP 2** — write a full threat model + design for the mid-channel base⇔channel binding (the close-path analogue). Spawn a dedicated ATTACKER subagent on the design (CLAUDE.md). Decide circuit vs contract enforcement. THEN implement + heavy-validate.
3. **`cmd_partial_withdraw`** (channel_member.rs, mirror `cmd_withdraw` at line 1017 but: `withdrawal_recipient` = member L1 (not manager), use `build_burn_send` + the bound base withdrawal, NO close/manager).
4. **Heavy anvil E2E** (opt-in `INTMAX_RUN_HEAVY_E2E`, gate it like `tests/c16_demo_deposit_fold_mismatch.rs`): a member partial-withdraws real ETH, channel stays open + keeps transacting; adversarial (over-withdraw, double-withdraw, withdraw-ANOTHER's-share FAILS, non-member, post-freeze, register-at-burn-id).

## 5. Environment notes (IMPORTANT)
- The main repo is intermittently modified by an external tool **`epitaxy`** (branch-switcher): it stashes/applies OTHER branches' work mid-session (seen: `MAX_CHANNEL_MEMBERS` flipped 16→1024, an unmerged file, untracked `*.olean`/`audit/`). Before building/proving, run `git status` and verify `src/constants.rs` has `MAX_CHANNEL_MEMBERS = 16`. Commit your own files with pathspec (`git commit -- <files>`) to avoid capturing foreign changes. Don't touch the untracked `*.olean`/`audit/` (external audit/Lean work).
- A SEPARATE worktree `/Users/plasma/repos/intmax3-zkp-heavy` (branch `test/heavy-close-scenarios`, pushed to origin) holds last session's close-settlement adversarial test suite — unrelated to partial withdrawal.
- Tests run release-only (`cargo test --release`). The `inter_channel_cli`/E-2 path is real STARKs but FAST + no anvil; the full lifecycle E2E (`close_lifecycle_cli_e2e`, c2c) is ~15min anvil + flaky on a loaded box — use a generous deploy timeout.

## 6. Related, separate TODO (in the plan doc)
**Additional deposit (mid-channel top-up)** — the symmetric ENTRY feature (L1 `deposit` → `receive_deposit`
fold mid-channel, reuse, C15-verified). Scoped in `partial-withdrawal-impl-plan.md` (phases A-C). Not started.
