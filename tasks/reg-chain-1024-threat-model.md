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
