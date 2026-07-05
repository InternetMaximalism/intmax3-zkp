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

---

# B-1a — reg record shrinks to cosigners (Option B, 2026-07-03)

Scope: tasks/reg-chain-1024-threat-model.md Phase B-1a ONLY (no B-1b/c, no Solidity).

## Member-tree scope trace (pre-implementation)
Comparison sites of wallet root vs registered root:
1. block_witness_generator::add_registration_block — generator ChannelLeaf root :=
   ChannelMemberKeys.member_tree.get_root(), must equal channel_reg_step's
   member_pubkeys_root_for(record). Load-bearing AT REGISTRATION only; root preserved forever after
   (update_channel_tree keeps member_pubkeys_root across transitions).
2. update_channel_tree bp slot inclusion — forever load-bearing, but ONLY for cosigner slots
   (bp_member_slot < member_count <= 16), against the REGISTERED root; proofs sourced from the
   same ChannelMemberKeys.member_tree.
3. wallet_core::member_pubkeys_root (ChannelRecord.member_pubkeys_root) — wallet-INTERNAL P4-1/A11
   anchoring (recomputed vs record); NEVER equated to the ChannelLeaf/registered root in code (the
   doc comment claiming equality is documentation only).
4. No close/cancel/claim circuit consumes member_pubkeys_root.
=> Equality is registration-genesis-load-bearing only. DECISION: registered/validity tree =
   cosigner height 4 (1<<4 == MAX_COSIGNERS); wallet live-membership tree stays height 10
   (WALLET_MEMBER_TREE_HEIGHT), documented as a DIFFERENT tree.

## Plan (falsifiable)
- [x] constants.rs: MEMBER_TREE_HEIGHT 10 -> 4 + const assert == log2(MAX_COSIGNERS); add
      WALLET_MEMBER_TREE_HEIGHT = 10 + const assert == log2(MAX_CHANNEL_MEMBERS)
- [x] key_tree.rs: MemberTree::init_wallet_membership(); docs split the two trees
- [x] channel_registration.rs: members [MemberRegEntry; MAX_COSIGNERS] (plain serde);
      preimage back to 476 u32; validate: member_count + delegate_count <= MAX_COSIGNERS;
      pinned differential constants UNCHANGED (byte-compat gate vs deployed Solidity fixed-16)
      -> test_channel_reg_preimage_pinned_differential PASSES with the pre-1024 constants; the
      Foundry test pins the IDENTICAL three constants (IntmaxRollup.t.sol:447/449/451), and the
      Solidity header+slot layout (IntmaxRollup.sol registerChannel + _channelRegHashChain) was
      re-read and matches the Rust u32 stream field-for-field.
- [x] channel_reg_step.rs: arrays -> MAX_COSIGNERS; range-check max = MAX_COSIGNERS (the 1024 max
      made mc unsatisfiable: mc-2 in [0,15] AND 1024-mc in [0,15] has no solution); root over 16
      leaves (height 4). degree_bits back to 16.
- [x] block_witness_generator.rs: from_member_keys = cosigners only (assert <= MAX_COSIGNERS);
      to_reg_record_split capacity = MAX_COSIGNERS
- [x] wallet_core.rs: member_pubkeys_root -> wallet tree (height 10, values unchanged);
      build_channel_withdrawal registers cosigner-only record (delegate_count = 0, arrays over
      TEST_ACTIVE_MEMBERS)
- [x] channel_member.rs: cmd_export_reg_record emits cosigner-only record (delegate_count = 0)
- [x] wrapper CD: existing 2^12 noop padding fits — the `Common data mismatch` assert passes
      inside test_channel_reg_chain_processor; NO padding re-derivation needed
- [x] tests (all release):
      channel_reg filter (step + processor + preimage + block differential): 6 passed
      update_channel_tree: 3 passed / block_step: 1 passed / block_hash_chain_processor: 1 passed
      close_circuit: 18 passed (untouched-green) / h1_gadget: 1 passed (untouched-green)
      delegate_send_tests (whole module incl. THE GATE a3_channel_withdrawal_builds_and_verifies,
      also re-run --exact: ok, 112s): 12 passed
      full `--lib` suite: running (result recorded below when done)

## Known deferred dependency (report, do not hack)
On-chain close of a DELEGATE-bearing channel compares the close PI delegate_count limb against the
Manager-registered counts; under B the registration emits delegate_count = 0, so that lifecycle
needs B-2 (Solidity) — out of B-1a scope. a3 uses 0 delegates and is unaffected.
