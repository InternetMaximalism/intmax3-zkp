# Phase C1 — real verifyCancelClose (cancel-close circuit + on-chain MLE/WHIR)

Authoritative: doc/tasks/phase-c-challenge-stubs-threat-model.md (C1).
Template: close_circuit.rs (ListCircuit member-sig binding) + post_close_claim_circuit.rs
(Stage-3 in-circuit digest recompute, less_than_u32 helper, test_fixture/fixture-bin) +
verifyWithdrawalClaim (Solidity strict-limb + set-once VK + MleVerifier).

## Statement
A SIGNED `InterChannelTx` from this channel that STRICTLY POST-DATES the close snapshot
exists ⇒ the close froze a stale state ⇒ cancel is justified.

## Soundness obligations the circuit MUST enforce (falsifiable)
- [ ] revived tx member signatures verified via recursive ListCircuit over single-sigs of the
      IMSB digest (`SmallBlockRootMessage::signing_digest()`), rebuilding C' over (IMSB, pk_g_i)
      — same machinery as close_circuit, but the signed message is the IMSB digest (not IMCH).
- [ ] `revived_small_block_root` == in-circuit IMSB recompute (SmallBlockMessageFieldsTarget),
      connected to PI. This is the value members sign AND the value ListCircuit folds.
- [ ] `revived_inter_channel_tx_digest` == in-circuit IMIT recompute, connected to PI.
- [ ] `revived_tx_hash` == witnessed tx_hash field; embedded in the IMIT preimage so bound by IMIT.
- [ ] `revived_seal` == witnessed seal field; embedded in the IMIT preimage so bound by IMIT.
- [ ] `close_intent_digest` == in-circuit IMCI recompute, connected to PI.
- [ ] Channel binding: revived block channel_id == close_intent.channel_id == channel_id PI.
- [ ] STALENESS (MUST-FIX): revived.small_block_number > close_intent.final_small_block_number
      (in-circuit u64 strict-greater, two-limb lexicographic via less_than_u32). assert_one.
- [ ] close_freeze era consistency: revived.close_freeze_nonce + 1 == close_intent.close_freeze_nonce
      (CloseIntent::new advances close_freeze_nonce by +1; the revived block must be from the
      SAME frozen era the close claimed final). assert via U64 add+connect.

## Files
- [ ] src/circuits/channel/cancel_close_circuit.rs (NEW)
- [ ] src/circuits/channel/mod.rs (register module)
- [ ] src/bin/generate_cancel_close_fixture.rs (NEW, feature-gated)
- [ ] Cargo.toml: feature `cancel-close-fixture-bin` + [[bin]]
- [ ] contracts/src/ChannelSettlementVerifier.sol
- [ ] contracts/src/ChannelSettlementManager.sol
- [ ] Tests (Rust + Solidity + golden vector)

## Security review — RAN FIRST (adversarial subagent, pre-implementation). HALTED.

STATUS: ⛔ IMPLEMENTATION HALTED — escalating to user. The dedicated adversarial review
(CLAUDE.md §Adversarial Thinking) found TWO blocking issues that the pinned 41-limb spec
cannot satisfy as written. Per CLAUDE.md ("Escalate, Don't Patch"; "stop and surface to user"),
no circuit/Solidity code was written. Findings VERIFIED against ground truth:

- [D] CRITICAL / TOTAL BREAK — no member-set binding. An IMSB small block is authorized by the
  block producer's SINGLE signature (`bp_pk_g`/`bp_member_slot` are IN the IMSB preimage,
  channel.rs:338). The BP's key is bound to the channel's registered members by a MemberTree
  INCLUSION proof against `member_pubkeys_root` (update_channel_tree.rs:108-130, 218-223) — NOT
  by the ListCircuit (the list only proves "this key signed", never "this key is a member",
  list.rs:300-310). The pinned `CancelClosePublicInputs` (41 limbs, cancel_close_pis.rs:14-21)
  has NO member_set_commitment / member_pubkeys_root field, and `verifyCancelClose` /
  `cancelClose` pass NO registered-member value (Manager:804-835). ⇒ ANY third party can fabricate
  an IMSB with arbitrary keys, run the single-sig + ListCircuit over their OWN keys, satisfy every
  proposed constraint, and forge a cancel → permanent denial of settlement for an honest closer.
  Compare close (Manager:592,1116-1154 match memberSetCommitment vs registry) — cancel must do the
  same. FIX REQUIRES CHANGING THE 41-LIMB PI LAYOUT (add a member binding) + threading the
  registered-member commitment from the manager — a structural change to the pinned spec.

- [B] HIGH / SPEC-LEVEL — statement may be unsound. "a signed IMSB strictly post-dating the close
  exists ⇒ close froze a stale state" does NOT hold: the BP unilaterally produces small blocks, so
  a colluding/racing BP can always sign block `final_small_block_number + 1` AFTER an honest close
  is initiated (requestClose→submit is a grace-windowed two-step, Manager:657-723). That later block
  satisfies `small_block_number > final` + the era fence, yet the honest closer was NOT obligated to
  include it. The predicate needs a finalization/obligation condition (medium-block confirmation vs
  `snapshot_medium_block_number`), NOT bare block-number succession. This is a SPECIFICATION decision
  for the threat-model author — cannot be resolved in implementation.

- [A] MEDIUM (manager-side: cosmetic; cross-binding: real) — `cancelClose` (Manager:824-834) consumes
  revivedTxHash/Seal/InterChannelTxDigest ONLY to delete pendingClose + emit an event (no nullifier,
  no dedup keyed on them), so leaving them witnessed-but-unrecomputed is not a manager soundness hole.
  BUT without recomputing IMIT/tx_leaf + verifying tx_inclusion_proof against the IMSB tx_tree_root,
  the circuit proves only "a BLOCK exists", not "a TX exists" — the per-tx evidence is fabricable
  relative to the signed block. Document as a trust boundary or add the leaf-inclusion binding.

- [C] era fence: `revived.close_freeze_nonce + 1 == close_intent.close_freeze_nonce` is CORRECT
  (do NOT relax to >=; that allows cross-era replay). Only meaningful once [D] is fixed.

## Notes
- IMSB (BP single-signs) != IMSS (embedded in IMIT) != IMIT (tx digest). Don't conflate.
- `inter_channel_tx_hash` is NOT a free fn; tx_hash is a stored field. tx_leaf via tx_leaf_hash.
- EIP-170: IntmaxRollup is 130B under cap; edits would touch only Verifier (5272B margin) + Manager.
- NO git commands run. NO .rs/.sol files edited. Only this planning file written.

---

# Partial Withdrawal (GAP2) — remaining work (2026-06-24)

GAP2 contract-level gate is DONE (IntmaxRollup + ChannelSettlementManager + tests). Remaining:

- [ ] `cmd_partial_withdraw` CLI command in `channel_member.rs` (mirror `cmd_withdraw` at line 1017 but: withdrawal_recipient = member L1, use `build_burn_send` + bound base withdrawal, NO close/manager)
- [x] Heavy anvil E2E (`tests/partial_withdrawal_e2e.rs`, port 8553): deposit → build_burn_send → submitPartialWithdrawalIntent → finalizePartialWithdrawal → authDigest cross-boundary parity verified; adversarial double-submit rejected (PartialWithdrawalChainUsed)
- [ ] `IntmaxRollup.registerSettlementManager` deploy script call (needed for real deployment)
- [ ] Commit GAP2 changes with pathspec (uncommitted on branch `fix/audit-soundness-and-tests`)

---

# Mid-Channel Deposit (L1 → channel top-up, channel stays open) — 2026-06-24

Status: DESIGN PHASE — reading detail2 + abstract2-1 specs first.
