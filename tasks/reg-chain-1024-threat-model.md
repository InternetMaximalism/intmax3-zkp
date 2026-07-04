# Registration at 1024 delegates — threat model + OWNER-DECISION

## The wall
Raising the balance capacity to 1024 exposes that on-chain REGISTRATION is built for the fixed-16
model and cannot scale as-is:

1. **`delegateCount` is uint8 (max 255)** on-chain: `memberAndDelegateCount = (memberCount<<8) |
   delegateCount` (ChannelSettlementManager.sol:1277 packing; Verifier PI limbs 93/94). A channel
   literally cannot represent >255 delegates on L1 today.
2. **`registerChannel` takes the FULL active arrays as calldata** (IntmaxRollup.sol:895-898:
   `memberPkGs/pkBs/regevPkDigests/recipients`, one entry per active participant) and the CONTRACT
   enforces pairwise distinctness in an **O(N²)** loop (IntmaxRollup.sol:927-934) + folds a fixed
   header via iterative `abi.encodePacked` (`_channelRegHashChain`, :1020-1050 — O(N²) memory). At
   1024: calldata ≈ 1024×116B ≈ **118 KB**, distinctness ≈ 523k compares, and the reg preimage is
   rebuilt slot-by-slot → **block-gas-limit blow-up**.
3. **The validity reg-STEP circuit** (`channel_reg_step.rs`) witnesses ALL 1024 `MemberRegEntry`
   and folds the ~118KB keccak preimage in-circuit (`ChannelRegRecord::hash_with_prev_hash`,
   channel_registration.rs) → circuit blow-up + the "Common data mismatch" against the pinned 2^12
   wrapper CD (`channel_reg_hash_chain_circuit.rs:71`). This is the SAME flat-keccak disease H1 had
   (fixed in a43e16f by tree-rooting).

## What registration actually IS today (traced)
- `registerChannel` is called ONCE per channel (channel_member.rs:1554-1585: "one-time; skip if
  already registered"), from the withdraw/deploy path — NOT per delegate join.
- Delegates join the channel's OFF-CHAIN state via the relay/CLI (`join_delegate`), which extends
  the cosigner-signed `BalanceState` (their slot's `regev_pk_digest` + balance enter the
  cosigner-signed H1 — now the height-10 slot-tree root). There is NO per-join L1 tx.
- The Manager stores only `bytes32[MAX_MEMBER_COUNT=16] memberPkGs` (Manager:475) — it has no room
  for delegates today; delegate recipients are bound via the reg-chain / registeredRecipientOf
  path, NOT the 16-slot array.
- A withdrawal CLAIM authenticates: the claim ZK proof exposes `memberPkG` + `member_index` + the
  balance-state binding (now via slot-tree inclusion, D14), and the Manager checks membership +
  `registeredRecipientOf[claim.memberPkG] == claim.recipient` (Manager:1043-1050).

## OWNER-DECISION: what does "register 1024 delegates on L1" mean?
The recipient/distinctness enforcement currently lives ON-CHAIN over the full active set. That
does not scale. Two coherent directions:

### Option A — keep per-delegate L1 registration, just make it scale
Widen `delegateCount` uint8→uint16; rewrite the two `abi.encodePacked` builders with assembly
preallocation; move the O(N²) distinctness in-circuit (a 1024-wide indexed-Merkle chain in the
validity path, ~11k Poseidon); restructure the reg record to a fixed header + the height-10
MemberTree root (the step already computes it). Still: 118KB calldata per registration, and every
delegate must be known at registration time (contradicts the dynamic-join demo).
- Cost: heavy (contract + validity circuit + calldata gas). Semantics: genesis-fixed membership.

### Option B (RECOMMENDED) — L1 registers only the ≤16 COSIGNERS + the channel member-tree ROOT; delegates are authenticated by the cosigner-signed balance state, not by prior L1 registration
- `registerChannel` shrinks to the ≤16 cosigners (calldata + distinctness stay O(16), gas trivial,
  uint8 stays valid for member_count). It additionally pins the channel's `member_pubkeys_root`
  (height-10 Poseidon MemberTree root already in the reg record).
- A delegate's balance + identity are ALREADY bound by the cosigner N-of-N signature over H1 (the
  slot-tree root commits every slot's `regev_pk_digest` + balance, D14). A delegate WITHDRAWAL
  proves, in the claim circuit, inclusion of its `(regev_pk_digest, …)` at its slot against the
  signed slot-tree root (D14 already does the balance side) — no prior per-delegate L1 registration.
- **THE SECURITY CRUX — recipient binding.** Today the L1 exit address is `registeredRecipientOf
  [pk_g]`, set from the per-slot `recipient` in the reg record. Under Option B delegates aren't in
  that map. The balance-slot leaf is currently `Poseidon(regev_pk_digest, enc_balance_digest,
  pending_adds)` — it does NOT bind a recipient. So the recipient must be bound somewhere the
  cosigners sign, or a delegate's payout could be redirected. Sub-options:
  - **B1**: extend the balance-slot leaf to `Poseidon(regev_pk_digest, enc_balance_digest,
    pending_adds, recipient)` → recipient rides in the cosigner-signed H1; the claim opens it by
    inclusion. Clean, but changes the H1 leaf (re-review D14, regen fixtures/VK). RECOMMENDED.
  - **B2**: derive recipient deterministically from pk (recipient = f(pk_g)) so no separate binding
    is needed — only viable if the protocol already ties an exit address to the key.
- Cost: contract simplifies (O(16)); the validity reg circuit shrinks to O(16)+root; one added
  leaf field (B1). Semantics: dynamic delegate membership (matches the demo + the "1000 delegates"
  goal). delegateCount can stay in the balance state (widen to u16 there) without an on-chain
  per-delegate array.

## Threat checklist (to satisfy under the chosen option, mirroring the H1 review)
- Injectivity of the new (fixed-width) reg preimage; bp_member_slot binding; replay of an old
  record (prev_hash chain); member-tree root reuse across channels/prev-hashes.
- **Recipient binding for delegates** (the crux above) — no redirection of a delegate's L1 exit.
- Cosigner distinctness stays enforced (A5 chain, ≤16); DELEGATE pk collisions: analyze impact —
  delegates don't co-sign, so a duplicate delegate pk_g affects only claim routing/nullifier; is
  that exploitable given the nullifier is pk_g-keyed (existing accepted intra-channel risk)?
- member_set_commitment (cosigners) binding unchanged; every reg-chain consumer (validity circuit,
  Manager registered* reads) stays uniquely bound.
- Wrapper CD noop padding re-derived; validity + settlement VKs + all fixtures regenerate.

## Invalidated artifacts (either option)
Validity `channel_reg_step` + `channel_reg_hash_chain` VKs; all lifecycle/withdrawal/reg fixtures;
Solidity `registerChannel` / `_channelRegHashChain` / Manager registration + `registeredRecipientOf`
(+ memberPkGs array under B) + the uint8→uint16 count surgery under A; redeploy.

## RECOMMENDATION
**Option B1**: register only the ≤16 cosigners + member-tree root on L1; bind delegate recipients by
extending the balance-slot leaf with `recipient` (rides the cosigner-signed H1); authenticate
delegate withdrawals by slot-tree inclusion at claim time. This is the only direction that makes
~1000 delegates actually feasible on-chain and matches the dynamic-join reality, at the cost of one
H1-leaf field change (needs its own adversarial review) + a coordinated contract/circuit/fixture
regen. Option A is a dead end for the 1000-delegate goal (118KB calldata + genesis-fixed set).

## Status: OWNER-DECISION pending (A vs B, and B1 vs B2). No code until decided.

---

## DECISION (owner, 2026-07-03): **Option B** — L1 registers only the <=16 cosigners (+ the channel
member-tree root); delegates are authenticated by the cosigner-signed H1 slot tree, recipients bound
via **B1** (balance-slot leaf extended with `recipient`).

## Implementation phases (each: tests green + adversarial review before the next)
### STATUS (2026-07-04)
- ✅ **B-1a** (046a51c) — reg record → cosigners; "Common data mismatch" fixed; a3 gate green.
- ✅ **B-1b** (6c345eb) — recipient into the 23-element leaf; claim recipient→PI connection.
  Adversarial review SOUND-UNDER-CONDITION.
- ✅ **B-1b obligation 1** (ff3af59) — delegate asserts its own leaf-bound recipient on import.
- ✅ **B-2 blocker** (fbcf448) — withdrawal nullifier re-keyed on the leaf-bound Regev pk digest
  (member_pk_g was slot-free → grinding theft under naive B-2). Adversarial review **SOUND**.
- ✅ **B-2** (6d2b9d8) — removed the proof-subsumed `NotChannelMember`/`RecipientMismatch` claim
  gates so delegates can withdraw. Foundry Manager 66/66, Adversarial 10/10, Invariant 6/6.
  Independent adversarial review: IN FLIGHT.
- ⏳ **B-3** — fixtures/VKs regen (withdrawal-claim nullifier + B-1b leaf changed every H1; stale
  baked close fixture already breaks CloseLifecycleE2E setUp) + full Rust+Foundry suite + redeploy.
  NOTE: B-1c folded into B-1b (claims already open + pay the leaf-bound recipient; the Manager now
  pays `claim.recipient` which the proof binds to the leaf). registerChannel cosigners-only-arrays
  cleanup is optional and NOT required for delegate withdrawal (deferred).

### Original phase plan (for reference)
- **B-1a — reg record shrinks to cosigners**: `ChannelRegRecord.members` -> `[MemberRegEntry;
  MAX_COSIGNERS]`; the reg keccak preimage returns to the small fixed form (~476 u32 words) so the
  reg-step circuit shrinks back and the pinned 2^12 wrapper CD fits (fixes "Common data mismatch" /
  the a3 test). Registration carries NO delegates (delegate_count leaves the reg preimage or is
  pinned 0 — decide against the close-PI/Manager consumers); the validity MemberTree scope: decide
  cosigners-only (height back toward 4) vs keep height 10 for headroom — document.
- **B-1b — recipient into the balance-slot leaf (B1)**: `BalanceState.recipients: [Address; MAX]`
  (serde-big-array, padding = zero address), leaf = Poseidon([IMSL] || regev_pk_digest ||
  enc_balance_digest || pending_adds || recipient(5 limbs)); update native + h1_gadget + all leaf
  consumers; joins set the recipient; cosigners refuse a join whose recipient is empty. Re-review
  D14 (leaf width changes: fixed-width discipline).
- **B-1c — claims pay the leaf-bound recipient**: claim circuits open `recipient` from the included
  leaf and expose it as a PI; Manager pays `claim.recipient` for delegate slots (registeredRecipientOf
  stays for cosigners or is dropped entirely — decide with the contract change).
- **B-2 — Solidity**: registerChannel -> cosigners-only arrays (O(16)); Manager claim path per B-1c;
  no uint16 surgery needed on-chain (delegateCount stays off-chain/in-state; the close PI
  delegate_count limb still exists — widen ONLY that if >255 delegates must appear in a close).
- **B-3 — fixtures/VKs regen + full-suite + redeploy.**

## ⚠️ B-2 BLOCKER (found 2026-07-04, pre-implementation trace): the withdrawal nullifier is keyed on a SLOT-FREE `member_pk_g`
Tracing `withdrawal_claim_circuit.rs` before touching the contract: `member_pk_g` is a PI that is
used ONLY to key `withdrawal_nullifier = keccak([IMCW] ++ close_intent_digest ++ member_pk_g)`
(:384-394) and is **NEVER bound to the claimant's slot**. The signed slot leaf binds the *Regev* key
digest `pk_digest = poseidon(a,b)` (:333,358), the amount digest, and the recipient — NOT `pk_g`.
Today this is sound ONLY because the Manager gates on `registeredMemberIndexPlusOne[memberPkG]` +
`registeredRecipientOf[memberPkG]` (Manager:1045-1050), which tie `member_pk_g` to a registered
cosigner (one registered pkG ⇒ one nullifier ⇒ one withdrawal).

**If B-2 merely relaxes those on-chain gates to admit delegates (obligation-3 as written),
`member_pk_g` becomes fully free for delegates ⇒ NULLIFIER-GRINDING theft:** a delegate who owns
slot i (knows its Regev secret, so can produce valid proofs) submits N proofs varying `member_pk_g`
→ N distinct nullifiers → slot i's amount paid N times to its (leaf-bound) recipient, up to the fund
cap → **drains other members' funds.** (Cosigner path unaffected; post-close path is NOT affected —
its `receiver_pk_g` is bound into the settled-tx `tx_hash` accumulator inclusion, :11-12,27-28.)

**⇒ B-2 is NOT contract-only.** Enabling delegate withdrawal safely requires re-binding the
withdrawal nullifier to a LEAF-COMMITTED slot identity. RECOMMENDED: key it on the already-computed,
leaf-bound `pk_digest` (the slot's Regev pk digest) instead of the free `member_pk_g`. Then each
signed slot ⇒ exactly one nullifier; only the slot owner (needs the Regev secret) can mint it;
duplicate-Regev-key across slots collapses to one withdrawal (self-loss, symmetric to the accepted
duplicate-pk_g risk). This is a CIRCUIT change (withdrawal_claim VK + fixtures regen — folds into
B-3) plus the Manager derives/checks the nullifier over the same leaf-bound value. `member_pk_g` may
stay as an informational PI but MUST NOT be the nullifier key.
Alternative (rejected): bind `pk_g` into the leaf (re-widen H1 leaf again) — delegates' `pk_g` has
no other on-chain role under Option B, so this adds a field for nothing; `pk_digest` re-key is
strictly cheaper.

### BLOCKER RESOLVED (2026-07-04, commit fbcf448 — owner chose the recommended pk_digest re-key)
`WithdrawalClaim::derive_nullifier` + the in-circuit keccak now key on the leaf-bound
`Bytes32::from(RegevPk::poseidon_digest())`; `member_pk_g` stays as an INERT informational PI (new
circuit test `withdrawal_nullifier_independent_of_member_pk_g` locks it). PI LAYOUT UNCHANGED ⇒ no
Verifier.sol signature change; only the withdrawal-claim VK DIGEST + fixtures change (B-3). Full lib
suite 377/377. Independent adversarial review of the re-key: **VERDICT SOUND** (2026-07-04) — native↔
circuit byte-match confirmed, `pk_digest` a single leaf-bound target, `member_pk_g` proven inert,
(a,b) pinned via decryption_core key-binding gate, cross-close replay safe (close_intent_digest embeds
channel_id), post-close unaffected (receiver_pk_g tx_hash-bound). ⇒ B-2 unblocked.

## B-2 THREAT MODEL (removing the two on-chain claim gates)
**Change:** delete `NotChannelMember` (`registeredMemberIndexPlusOne == 0`) + `RecipientMismatch`
(`registeredRecipientOf != recipient`) from `submitWithdrawalClaim` and `submitPostCloseClaim`.
**Adversary goals & why each fails post-change:**
- *Claim a slot not in the signed final state (steal from a channel you're not in):* the proof's
  slot/receiver inclusion is verified against `finalizedBalanceStateH1` (signed N-of-N by cosigners);
  no witness exists for a slot absent from the signed tree, and the claimant needs the Regev secret
  to decrypt `amount`. Membership is proof-enforced, not map-enforced.
- *Redirect a delegate's payout:* `claim.recipient` is leaf-bound (B-1b) and connected in-circuit;
  `withdrawalCredits[claim.recipient]` pays exactly the signed exit address. The removed
  `registeredRecipientOf` map was empty for delegates anyway (the very thing that blocked them).
- *Double-withdraw one slot:* nullifier is leaf-`pk_digest`-bound (fbcf448) + `usedWithdrawalNullifiers`
  / `usedSharedNativeNullifiers` one-shot; grinding neutralized.
- *Over-withdraw the channel:* `totalWithdrawn <= finalizedChannelFundAmount` cap UNCHANGED; every
  accepted claim (cosigner or delegate) is a signed-state slot amount ⇒ Σ claims ≤ fund. Value
  conservation does NOT depend on the removed gates.
- *Affect close/cancel:* those read `registeredMemberSetCommitment` (cosigners), a DIFFERENT map,
  untouched. The registration writes to `registeredMemberIndexPlusOne`/`registeredRecipientOf` stay
  (harmless, now unread by the claim path).
**Invariant preserved:** the two removed gates were an EARLIER (pre-B1b) recipient/membership
authZ that the proof now subsumes; removing them ADMITS delegates (the goal) without widening what a
cosigner could already do. **`RecipientMismatch` becomes unused** (only these 2 sites) ⇒ remove its
declaration; `NotChannelMember` stays (still used by the `withdrawNative` member-recipient gate).
Foundry tests asserting these reverts must flip to delegate-claim POSITIVE tests.

### B-2 ADVERSARIAL REVIEW (2026-07-04): VERDICT SOUND-UNDER-CONDITION
Independent Solidity/protocol audit of 6d2b9d8 found NO reachable theft/replay/conservation attack
through the removed gates. All removed authZ is subsumed by `_bindLimbsStrict` (every claim field —
finalBalanceStateH1, channelId, closeIntentDigest, memberPkG, recipient, userAmountDigest,
withdrawalNullifier, amount — is limb-bound to the proof) + `MleVerifier.verify` against the distinct
withdrawal/post-close VKs (cross-function replay blocked by gatesDigest) + the fund cap + nullifier
one-shot. `finalizedBalanceStateH1` is the cosigner-signed value from finalizeClose (close proof
forced its in-circuit member_set_commitment == the registered COSIGNER set), so membership is
genuinely proof-enforced. Recipient is a strict-bound limb == the paid `withdrawalCredits` key.
Conditions = the B-3 residuals below. Foundry: Manager 66/66, Adversarial+Invariant 16/16.

### Residual dispositions (from both B-2 reviews)
- **R4 — withdrawal `amount`↔ciphertext binding: ALREADY CLOSED at the circuit level.** The reviewer
  (Solidity-only) read a STALE `ChannelSettlementVerifier` comment claiming decryption is deferred.
  In fact `withdrawal_claim_circuit.rs` binds `amount` via `decryption_core(expose_amount=true)` →
  `connect(amount_pi, amount_lo/hi)` — a member can claim ONLY what their signed slot ciphertext
  decrypts to. Over-claim is prevented at the proof level, not merely fund-capped. Stale Solidity
  comment corrected in this change.
- **R3 — close proof does NOT bind Σ(signed-slot amounts) ≤ channel_fund_amount.** CONFIRMED (balances
  are Regev-encrypted; the close circuit binds `channel_fund_amount` as a PI but never sums the
  slots). This is PRE-EXISTING and NOT introduced by Option B. It is a LIVENESS/griefing risk within
  the N-of-N trust model (colluding/erring cosigners could sign an over-inflated state, letting early
  claimants over-draw and starving late ones), NOT a solvency/theft breach — the hard ETH backstop
  `totalCreditedOut <= receivedChannelFunds` (Manager:1168) means the manager can never pay out more
  ETH than it actually received. FLAGGED for the owner/circuit auditor as a separate item; out of
  Option B scope.
- **R5 — test coverage shift.** The Foundry mock verifier cannot model ZK slot-inclusion, so on-chain
  membership rejection is no longer Foundry-testable; that property now lives ONLY in the Rust
  circuit tests (`withdrawal_claim` rejects a non-included slot / fake pk). Foundry still covers the
  strict limb bind, fund cap, and nullifier one-shot. B-3 must regenerate the CloseLifecycleE2E baked
  fixture so the full close→finalize→delegate-withdraw→stranger-reject lifecycle runs against a REAL
  proof end-to-end.
- **B-3 MUST preserve** the complete strict-bound limb set (finalBalanceStateH1, recipient, amount,
  nullifier, channelId, closeIntentDigest) byte-exact vs the Rust `*PublicInputs::to_u64_vec()`
  pinning tests when VKs regenerate; the circuit-side B-1b recipient binding + fbcf448 pk_digest
  nullifier are the linchpin the on-chain layer cannot re-check.

## B-2 scope (Solidity Manager) — READY once the re-key review clears
Traced `ChannelSettlementManager.submitWithdrawalClaim` (:1043-1050) and `submitPostCloseClaim`
(:1093-1098): both gate on `registeredMemberIndexPlusOne[pkG] != 0` (membership) AND
`registeredRecipientOf[pkG] == claim.recipient` (recipient). Under Option B + B-1b BOTH are now
**subsumed by the proof** and BLOCK delegates (who are never registered):
- **Membership** = the proof's `slot_inclusion.verify` of the claimant slot leaf against
  `slot_tree_root` committed in the signed `finalizedBalanceStateH1` — only slots in the cosigner-
  signed final state can be claimed; an attacker cannot add themselves without cosigner sigs, and
  needs the Regev secret to decrypt the amount. The on-chain membership map is redundant.
- **Recipient** = B-1b leaf binding: the circuit connects `claim.recipient` to the signed slot
  leaf's `recipient` field, so `claim.recipient` provably equals the cosigner-signed exit address
  (cosigners' genesis recipients are set identically to their reg-record recipients, so dropping the
  map does not change their payout).
- **Withdrawal nullifier** is caller-supplied and the Manager only records it
  (`usedWithdrawalNullifiers`); after fbcf448 the PROOF binds it to the leaf-bound `pk_digest`, so
  the Manager MUST NOT recompute it from `member_pk_g` (it doesn't today) and MUST keep trusting the
  proof-committed value. Post-close keeps its on-chain `_deriveSharedNativeNullifier` recompute
  (unchanged; receiver_pk_g is tx_hash-bound).
**B-2 change = REMOVE the two gates (`NotChannelMember` + `RecipientMismatch`) from BOTH claim
functions.** Keep the registration writes for now (harmless; cosigner-only registration cleanup is
optional). `withdrawalCredits` keys on `claim.recipient` (leaf-bound) and the fund cap is unchanged
⇒ value conservation preserved. This needs its OWN independent adversarial review (removing an
on-chain authZ gate is value-flow-critical) + B-3 VK re-pin + fixture regen + redeploy. Do NOT
implement until the fbcf448 re-key review returns SOUND.
