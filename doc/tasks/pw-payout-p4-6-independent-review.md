# P4-6 — independent adversarial review of the partial-withdrawal burn payout path

Discharges `doc/tasks/partial-withdrawal-payout-design.md` **P4-6** ("Dedicated attacker-subagent
review of the whole path, separate from whoever implemented it"). Target: `main` @ `74c93e4`.
Reviewers were three independent agents, none of which wrote any of the reviewed code, each given a
disjoint scope, no shared findings, and no statement of the expected conclusion. Every finding below
that is marked CONFIRMED was then re-verified against the source by a fourth party before being
recorded here; findings marked RELAYED are the reviewer's, not independently re-derived.

**Verdict on the core security claim: it holds.** No amount-substitution, recipient-substitution,
double-pay, replay or reentrancy attack was constructed. The §2 (recommendation C) design does what
it says. **All three findings below are fund-stranding (griefing / liveness), not theft**, plus one
material overstatement in the design doc's own Phase 4 claims.

**Scope this review did NOT cover.** It judged the implementation against its own `doc/tasks/`
threat-model documents and the code's internal consistency. It did **not** evaluate the design
against the intmax2 paper's stateless-rollup model — the reviewers had not read it. That matters for
finding 1 specifically: under a stateless protocol an inert or wrong on-chain post should be a
non-event, and the fact that this lane makes one permanently damaging is where the implementation
appears to have drifted from the protocol's intent. Read finding 1's root-cause section with that
lens; a protocol-level sign-off is still owed by someone who has read the paper. This review also does
not discharge P0-2, the P0/P1 security inspection, or the cosigner-key operational response (§9).

---

## 1. HIGH — an outsider can permanently destroy any burn's L1 payout for one transaction of gas

**CONFIRMED.** `contracts/src/ChannelSettlementManager.sol:1134` (no `msg.sender` check), `:1250`
(the nullifier's only use), `:1235-1236` (chain-key single-use), `:1289` (permanent consumption).

`withdrawal.nullifier` is caller-supplied and bound to nothing. It is not in the IMBD descriptor
preimage and not in the settled-tx chain; it enters only the IMPW auth digest at `:1250`. The
comment at `:1166` states that the nullifier "remains supplied by the base withdrawal proof path" —
but nothing enforces that the supplied value is the one the proof will carry, and
`submitPartialWithdrawalIntent` has no caller restriction of any kind (the first statement is the
`channelStatus` check).

**Attack.** Alice broadcasts her intent. Any observer — membership not required — copies the
calldata, replaces the single `nullifier` word, and front-runs. Every check passes: `auxData` is
chain-bound (`:1157-1160`), `recipient`/`tokenIndex`/`amount`/`txLeaf` are IMBD-bound
(`:1222-1233`), `recipient` is participant-checked (`:1212`). After the challenge period anyone
calls the permissionless `finalizePartialWithdrawal()`, which sets
`usedPartialWithdrawalChains[chainKey] = true` at `:1289` and authorizes the *wrong* digest. Alice's
correct re-submit is then refused forever by `PartialWithdrawalChainUsed` at `:1236` — `auxData` is
the last push of exactly one chain value, so the burn has exactly one chain key. Meanwhile
`withdrawNative` recomputes the digest from the *proof's* leaf (`IntmaxRollup.sol:1519`,
`:1602-1613`), which carries the real nullifier, so it reverts `PartialWithdrawalNotAuthorized`.

The value was already debited on both the channel side and the base side. It is unrecoverable on L1.

Nothing is stolen — every economic field is bound, so the attacker gains nothing. This is pure
griefing, and it is **not** the hazard §0.4 / T10 / §6-4 record. Those describe a *self-inflicted*
misconfiguration, and their mitigation (§1.7: "the CLI must derive every intent field from the burn
artefact, never from environment or request body") is client-side and has no effect on a third-party
front-runner.

### Root cause: the consumed chain key is a fossil of the deleted proof-free payout path

The permanent damage flows through exactly one piece of state — `usedPartialWithdrawalChains` — and
that mapping guards nothing that still exists.

Its only stated rationale is `pw-auth-threat-model.md:190-191`: it "ensures a given
`(channelId, finalSettledTxChain)` mints **at most one** authorization ever. Unchanged." That is a
**double-payout** argument, and it only bites in a world where an authorization *alone* can pay. That
world was `claimAuthorizedWithdrawal`, the proof-free payout removed on 2026-07-28 (commit `42640f1`;
`IntmaxRollup.sol:792`, `:1601` — *"the only historical consumer of this digest … was removed"*).

Post-removal, `partialWithdrawalAuthorized` has exactly two readers, both a **conjunction with the
proof** inside the payout loop (`IntmaxRollup.sol:1519`, `:1567`), and the flag *"can only VETO a
proven leaf; it can never supply a field … must never become a standalone payout gate"* (`:1516-1525`).
Minting two authorizations for one chain is therefore harmless — the second payout is stopped by the
proof-side `withdrawalNullifierUsed` (`:1500`), which `pw-auth-threat-model.md:180-183` itself names as
the real double-payout guard. **The chain-key single-use is redundant with the nullifier and load-
bearing for nothing.** The threat model's word "Unchanged" is the tell: when the payout model moved
from authorization-pays to proof-gated-veto, nobody re-examined whether this guard was still needed.

So a garbage submit consuming a permanent, un-replenishable slot is exactly the "an inert wrong post
should stay inert" property that a stateless design would give for free. The slot has no reason to be
consumable.

**This is independent of the P0-9 veto — an earlier draft of this review wrongly bundled them.** The
1-of-N veto lives entirely in the freeze-nonce comparison: recorded at submit
(`pendingPartialWithdrawalCloseFreezeNonce`, `:1267`), re-checked at finalize against
`currentCloseFreezeNonce` which `requestClose()` advances (`:1285` vs `:908`). `usedPartialWithdrawalChains`
appears nowhere in that path; finalize sets it (`:1289`) only *after* the veto check passes. Deleting
the chain key leaves the veto byte-for-byte identical.

**Candidate fixes, cheapest first.**
1. **Remove `usedPartialWithdrawalChains` entirely** (drop `:1236` and `:1289`), or consume it **only
   on a successful payout** rather than at finalize. Soundness is unchanged (the nullifier is the real
   guard), the veto is untouched, and the HIGH collapses: with no permanent slot, Alice waits out the
   window, finalizes the attacker's harmless garbage to clear the pending slot, and re-submits her
   correct intent. The attack degrades to a repeatable **one-challenge-window delay** (MEDIUM/LOW
   grief), never permanent loss. This is the fix that matches the "inert wrong post" principle.
2. `require(msg.sender == withdrawal.recipient)` in `submitPartialWithdrawalIntent`. Also closes it,
   but it treats the symptom (who may submit) rather than the cause (a consumable slot), and it
   changes the deployment model: the submit tx is broadcast by the operator/relay key
   (`SubmitPartialWithdrawal.s.sol:66` is a bare `vm.startBroadcast()`, `INTMAX_L1_ACCOUNT`), so
   relay-submits-on-behalf would become member-submits. Withdrawn as the primary recommendation.
3. Put the nullifier inside the IMBD descriptor preimage (`src/common/channel.rs:879-893`) so it is
   co-signer-bound. Orthogonal — it stops the *wrong-nullifier* variant but not a garbage submit that
   copies the *right* nullifier, so it does not by itself remove the consumable-slot grief.

**Caveat, now discharged.** The one open question in the earlier draft — whether the chain key has a
rationale beyond redundancy — was resolved by reading `pw-auth-threat-model.md` §3: its only
justification is double-payout prevention for a payout path that no longer exists.

Any Manager edit moves the CREATE2 address and breaks baked fixtures — **HEAVY / USER ACTION** per
`doc/tasks/pw-auth-threat-model.md:486-510`. Not implemented by this review.

> **Scope limit of this review.** The analysis above judged the implementation against its own
> threat-model documents and the code's internal consistency; it did **not** check the design against
> the intmax2 paper's stateless-rollup model. The reviewer has not read that paper. A wrong or
> inert on-chain post should, under a stateless protocol, be a non-event; the finding that this lane
> makes such a post permanently damaging is precisely where the implementation may have drifted from
> the protocol's intent, and that judgement is owed to someone who has read the paper.

---

## 2. HIGH — the burn-time base-nonce guard reads a mirror nothing advances; the second burn strands

**CONFIRMED.** `src/bin/channel_member.rs:2140` (the only writer), `:5406` and `:5063` (the readers),
`src/wallet_core.rs:3050` (the guard), `api/routes/channel-state.js:145` and
`hosting/wallet/public-backing.js:27` (the browser's source), `src/live_balance_service.rs:871`
(the daemon's real cursor).

`channel_backing.json`'s `base_private_state` has, across all of `src/`, exactly one declaration,
**one write**, and two reads. The write is inside `cmd_setup_backing` at `:2140`. No code path
advances it; `record_backing_deposit_tx` read-modify-writes the file but leaves the field alone.

`verify_base_nonce_available` demands strict equality (`send_nonce != base_private.nonce` ⇒ bail), so
a value frozen at setup means the guard accepts only nonce 0, forever. Both branches out of that are
broken, and the live one is the silent branch: `GET /base-head` reads the *same* frozen file, so the
browser and the guard agree with each other and the guard passes. The authoritative cursor lives in
the daemon and is never written back.

**Sequence.** Burn #1 at nonce 0 settles; the daemon's cursor advances to 1; the backing file still
says 0. Burn #2: the browser is served 0; the guard compares 0 == 0 and passes; the slot-occupancy
check is skipped because `(0 as usize) < sent_len(=0)` is false. The members sign and the
`channel_fund` debit is final. Only then does the daemon refuse —
*"descriptor base nonce/TxV2 nonce (0/0) must equal live private nonce 1"*. No `send_material` is
journaled, so no `single_withdrawal` proof can be built and no payout exists, ever.

The mirror-image branch is a hard liveness break: had the browser used the correct live nonce, the
guard would have refused and the channel could never co-sign a second outgoing send at all.

Two comments assert the opposite of the behaviour and should be corrected with the fix:
`api/routes/channel-state.js:143-144` says co-signers "re-check it against the persisted IVC head" —
the re-check is against the same file, so it is circular, not independent; and
`src/bin/channel_member.rs:5402-5404` says the value "is not a best-effort local replay ledger" —
it is exactly that, frozen at setup.

**Fix.** Have `cosign-burn-send` (and `cosign-inter-transfer`, `:5062-5075`, same defect) query the
daemon's `liveBaseHead` and require equality against it; make `GET /base-head` proxy `liveBaseHead`
rather than reading `channel_backing.json`; and/or have `LiveBalanceService::commit` write
`base_private_state` back on every applied transition. Fail closed if the daemon is unreachable.

---

## 3. MEDIUM — `cosign-burn-send` does not check the destination, and shows the co-signer neither the destination nor the payout address

**RELAYED** (not independently re-derived). `src/bin/channel_member.rs:5378-5569`.

The command checks the source (`:5421-5427`) but never requires
`descriptor.inter_channel_tx.destination_channel_id.channel_id() == BURN_CHANNEL_ID`. The daemon
does check it (`src/live_balance_service.rs:1296-1300`); neither
`verify_inter_channel_descriptor_matches_debit` nor `InterChannelSendUpdateWitness::verify` does —
both merely branch on burn-ness.

So a coordinator can hand a member the material for an ordinary channel-to-channel send to an
attacker-controlled channel and tell them to run `cosign-burn-send`. It is a structurally valid,
E-2-proved, conservation-correct debit, so every check passes. The success line at `:5560-5568`
prints amount and token slot only — **the destination channel and the L1 payout address are never
displayed**, even though `burn_leaf.recipient` was computed three lines earlier at `:5524-5532`.

**Fix.** `die` unless the destination is `BURN_CHANNEL_ID`; print the destination and the L1
recipient before signing. Suggested regression test: feed a normal C2C `(debit_payload, descriptor)`
pair to `cosign-burn-send` and assert refusal.

---

## 4. The design doc's P4-1 claim is materially overstated

**CONFIRMED, by experiment and by reading.** This is the most actionable output of the review.

`partial-withdrawal-payout-design.md:925` claims *"P0-4's negative test now **passes** (the `Y > X`
leaf is rejected), and is kept."* P0-4 (`:659-661`) requires a test that **fails on the pre-fix
code**: given an honest co-signed burn of `X`, a base leaf of `Y > X` **with the same `auxData`** is
accepted end to end. Closing that is the entire purpose of the Manager's IMBD recompute
(`ChannelSettlementManager.sol:1216-1233`).

`test_burnLeaf_amountAboveBurn_rejected` does something different: it mutates the **calldata** amount
against the *same* proof, which breaks the keccak re-fold. That property has held since Phase 2 and
is independent of the F-AUX-1 fix. The real P0-4 attack needs a *second real proof* — one for `Y`
reusing `X`'s descriptor — driven through the real Manager.

The reviewer demonstrated this by mutation: **disabling the IMBD recompute entirely
(`ChannelSettlementManager.sol:1231` → no-op) leaves all 8 tests passing with byte-identical gas.**
The reason is structural and independently confirmed here: the suite's `settlementManager` is
`makeAddr("burnSettlementManager")` (`contracts/test/PartialWithdrawalBurnPayout.t.sol:34`), an
**EOA** that `vm.prank`s `authorizePartialWithdrawal` directly. `ChannelSettlementManager` is never
executed by this suite. (The repo does catch that mutation elsewhere — 4 tests in
`PartialWithdrawal.t.sol` fail — so the fix is covered; it is just not covered *here*, and P4-1 is
not the item that covers it.)

**Recommended doc correction:** restate P4-1 as what it proves — calldata/leaf-binding on a real
`aux != 0` proof — and either reopen P0-4 or record explicitly that P0-4's end-to-end form remains
undischarged pending a second fixture.

### Related: the fixture cannot be authorized by a real Manager

`src/bin/generate_burn_withdrawal_fixture.rs:58-69` admits the descriptor is IMBD-*shaped* but uses
stand-in limbs (`0xB0E1`) rather than `(2<<248)|recipient`. The real IMBD check at
`ChannelSettlementManager.sol:1219-1233` would refuse to authorize this exact leaf. So "the repo's
first on-chain `aux != 0` payout" is a payout of a leaf no honest Manager would ever authorize. That
end-to-end realizability is precisely what the live anvil rehearsal must establish.

---

## 5. What the suite *does* prove (independently checked, and it is real work)

The suite is **not** vacuous. Verified: `WithdrawNativeE2EBase.sol:65` deploys the real
`MleVerifier` — no mock in the path, and the `degreeBits==0` bypass applies to validity, not to the
withdrawal path (`IntmaxRollup.sol:1714-1726`); the fixture's `aux_data` is nonzero and its leaf fold
was recomputed offline and matches `publicInputs[0..8]` exactly; every `expectRevert` asserts a
specific selector, never a bare revert; and the positive control asserts real balance deltas
(`pendingWithdrawals`, `totalEscrowed`), not merely "did not revert".

Four of five injected production defects were caught. **P4-3 is the strongest result**: with the IMPW
gate disabled the call *succeeds*, which conclusively proves `_verifyWithdrawalSet` passed first and
the revert really does come from the flag check — the branch `PartialWithdrawalPayout.t.sol:198-210`
could never reach. **P4-4 is proven** rollup-side. **P4-5 is partially proven** — `(amount,
recipient)` calldata substitution only, single leaf, one revert class. **P4-2** remains half-done, as
the doc already concedes.

---

## 6. Coverage holes, ranked

1. **The F-AUX-1 fix is untouched by this suite** (§4). Fix the doc's wording or write the real P0-4
   test.
2. **Missing fixtures produce a green CI.** With `burn_withdrawal_payout.json` renamed, the suite
   reports `1 passed; 7 skipped`, **exit 0**. Worse, `test_fixtureLeafIsABurn`
   (`PartialWithdrawalBurnPayout.t.sol:64`) — whose docblock says *"If this fails the whole suite is
   meaningless"* — uses a bare `return` and reports **PASS** in exactly that case. It should
   `vm.skip`, and CI should assert the `burn_` fixture set is present.
3. **`withdrawERC20`'s IMPW mirror (`IntmaxRollup.sol:1566-1570`) has zero coverage repo-wide.**
   `test_provenBurnLeaf_notPayableViaErc20Path` dies on the asset guard at `:1558` and never reaches
   it. The same mutation applied there would go undetected everywhere.
4. **No multi-leaf chain**, so "each burn leaf in a chain needs its own authorization" (a mixed
   burn + normal chain) is untested.
5. **End-to-end realizability** — no test exhibits a leaf that both the Manager *and* `withdrawNative`
   accept (§4).
6. **P4-2 cross-lane conservation** — absent, correctly flagged `[~]` in the doc.
7. Minor: the fuzz test's 256 runs all land in one equivalence class (~60s of the suite's 63s) and
   fuzz only `amount`/`recipient`; `PartialWithdrawalBurnPayout.t.sol:150` asserts
   `totalEscrowed() > 0` under the label `"escrow untouched"` — it would pass if escrow were drained
   99%.

---

## 7. Lower-severity items worth recording

- **MEDIUM (relayed)** — the P0-9 veto is 1-of-(N + delegates), not 1-of-N.
  `ChannelSettlementManager.sol:863` sets `isMemberRecipient[d.recipient] = true` for delegate
  recipients, and `requestClose` gates on that map at `:906`. Delegates do not co-sign, yet can
  freeze the channel and kill a pending PW; `cancelClose` does not decrement
  `currentCloseFreezeNonce`, so the killed PW stays dead. The doc comments at `:900-901` and
  `:1280-1284` say "member" and are wrong against the code.
- **MEDIUM (relayed)** — `registerChannel` is permissionless and one-time
  (`IntmaxRollup.sol:1064-1072`, `:1078`), so any channel id can be squatted, permanently preventing
  the legitimate manager from deploying for it.
- **MEDIUM (relayed)** — `auxData != 0` is the sole on-chain discriminator for "needs channel
  consent" (`IntmaxRollup.sol:1518`, `:1566`). The contract cannot tell a channel-sourced withdrawal
  from an ordinary one; this is a hard dependency on the base circuit forcing every burn leaf to
  carry a nonzero descriptor. Worth an explicit negative circuit test and a written assumption at the
  call site. Related: there is **no per-channel ceiling on the PW lane on-chain** — only the global
  `totalEscrowed` / `escrowedByToken` — in contrast to the close lane's `receivedChannelFunds` cap.
- **MEDIUM (relayed)** — `partialWithdrawalAuthorized` is a global, unnamespaced, irrevocable
  `bytes32 → bool` (`IntmaxRollup.sol:786-790`), and `registerSettlementManager` has no removal path.
  No live exploit was found (the attacker's own manager cannot authorize a victim channel's digest),
  so this is missing defence-in-depth, not a break.
- **LOW (relayed)** — `token_index` reaches a `single_withdrawal` public input without a local range
  check (`src/common/transfer.rs:143-153`, versus `src/common/withdrawal.rs:132-135` which does check).
  The attack is blocked transitively by `spend_circuit`'s 32-height merkle index split, so this is a
  latent hazard, not a live one. Fix: `range_check(token_index, 32)` in `TransferTarget::new`.
  This discharges the "confirm during the P4-6 adversarial review; do not assume" instruction at
  design-doc §1.13.
- **LOW (relayed)** — `_limbsToBytes32` masks (`IntmaxRollup.sol:1696`) where its sibling explicitly
  rejects (`:1701-1712`); not exploitable, but it contradicts the stated policy two functions down.
- **LOW (relayed)** — `settlement.json` is read unauthenticated for the `manager` address
  (`src/bin/channel_member.rs:7393-7399`); a substituted manager sends the intent to an attacker
  contract while the operator is told `pw-submit OK`. The real chain key is not consumed, so it is
  recoverable.
- **INFO** — `Withdrawal::from_u64_slice` panics via `assert!` on caller-supplied proof PIs
  (`src/common/withdrawal.rs:88-92`); a decoder of untrusted input should return `Err`.
- **INFO** — IMTC is used for two structurally different folds (chain push, and nested inside
  `inter_channel_tx_hash`, `src/common/channel.rs:916-928`), so the "last push" check rests on a
  collision assumption rather than structural separation. The doc's claim of clean domain separation
  at `:658` is stronger than what the code provides.
- **INFO** — several stale line citations, including the load-bearing one at
  `ChannelSettlementManager.sol:1206-1208` (real `isMemberRecipient` writes are `:805` and `:863` —
  and `:863` is the one that reveals the delegate issue above).

---

## 8. Clean negatives — attacks confirmed NOT to work

Recorded because a negative result from an adversarial pass is a deliverable, not an absence of one.

- **Amount / recipient / token / nullifier substitution on the payout.** Every field of the paid leaf
  is re-folded into `withdrawalHash → pisHash` and strict-matched against proof limbs 0..7
  (`IntmaxRollup.sol:1653-1659`, leaf fold `:1668-1672`). Nothing paid is caller-declared.
- **A chosen `txLeaf` reaching a different `(recipient, tokenIndex, amount)`.** That is a keccak
  second-preimage against a proof-fixed target; the IMBD preimage is fixed-length (104 bytes), so
  there is no `encodePacked` ambiguity.
- **Domain-tag collision.** IMBD `0x494d4244`, IMPW, IMTC are pairwise-distinct against ~45 domains,
  asserted by `src/constants.rs:290-400`.
- **Rust/Solidity descriptor divergence.** One formula, both sides, pinned by a frozen cross-language
  vector (`src/common/channel.rs:1724` and `contracts/test/PartialWithdrawal.t.sol:450-457`). **No JS
  implementation exists** — the JS layers only move the JSON around.

  Byte-level parity was confirmed from the dependency's own serialization rather than from in-repo
  comments: `plonky2_keccak`'s `solidity_keccak256` (`src/utils.rs:7-15` in the Cargo checkout)
  serializes each input `u32` **big-endian** (`v.to_be_bytes()`) and reads the 8 output words back
  big-endian. The IMBD preimage is therefore domain `0x494d4244` (4 B) ‖ `tx_leaf` (32 B) ‖
  `recipient` in ADDRESS_TAG form (32 B) ‖ `token_index` (4 B) ‖ `amount` (32 B) = **104 bytes**,
  byte-identical to `abi.encodePacked(bytes4(0x494d4244), txLeaf, baseRecipient, tokenIndex, amount)`
  at `ChannelSettlementManager.sol:1222-1230`. The frozen vector is
  `0xe53d8cf5a9b6cebadd222943673c931958739afde63b4a95c0cbc4ae0ddb5a0d`.
- **A second live nullifier formula.** None. The old keccak form survives only as a negative-test
  oracle (`tests/burn_withdrawal_nullifier.rs`), asserted never-equal; no `0xBEEF` nullifier remains.
- **Showing a co-signer one amount and signing another.** Three independent bindings before any
  signature (`src/wallet_core.rs:3016`, `:2977-3006`, `state_update_verifier.rs:676-731`).
- **Free targets reaching withdrawal public inputs.** None; `recipient` canonicality is re-encoded
  and connected, `amount`/`aux_data` are range-checked and merkle-bound, the nullifier is derived.
- **Nonce/sent-tx-tree lockstep** and **no-underflow** are enforced in-circuit
  (`spend_circuit.rs:262-263`, `:389-396`, `:412`; `u256.rs:318-319`).
- **Era fence, every ordering** — submit→requestClose, requestClose→submit,
  requestClose→cancelClose→finalize, and the close-lane race are all blocked, with no off-by-one.
  The attacker cannot block the veto.
- **Reentrancy / CEI** on `finalizePartialWithdrawal`, `withdrawNative`/`withdrawERC20` (pull-payment
  only), exact `withdraw(amount)`, `pullChannelFunds`.
- **Double-pay** via shared nullifier, ETH/ERC-20 lane confusion, or chain-key reuse.

**Scope caveat.** The claimed binding of the base transfer to the channel's N-of-N `h2_tag` is a
*composition* of the withdrawal circuit and the validity circuit
(`src/circuits/validity/block_hash_chain/channel_state_message.rs:74`, `:146`), not a property of the
payout path alone. Its existence was verified; the validity side was **not** audited by this review.

---

## 9. What this review does NOT discharge

- **P0-2** — the independent review of the §2.2 chain-pinning loop. Not in scope here.
- **The full live anvil rehearsal.** Still the immediate next step, and §4 raises its importance: no
  test yet exhibits a leaf that both the real Manager and `withdrawNative` accept.
- **The P0/P1 security inspection** and the `cosigner-key-provenance.md` operational response. A
  subagent review is not a substitute for either.
