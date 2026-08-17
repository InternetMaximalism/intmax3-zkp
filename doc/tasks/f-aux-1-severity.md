# F-AUX-1 — severity re-assessment

Scope: analysis only, no code changed. Branch `feat/falcon-poseidon-sig`, HEAD `69a8599`.
Method: read the code at every cited line; prior documents were read but re-verified against code
before being relied on. No tests were run (no `forge test`, no proving).

**Finding under review (audit row `doc/audit/audit28-06-2026.md:342`)**: nothing on the
partial-withdrawal payout path checks that the base-layer `Transfer.amount` equals the channel-layer
debit.

---

## 0. Verdict up front

1. **The binding gap is real and is NOT demoted.** No artefact on the payout path, and no artefact
   at close, ever compares the base `Transfer.amount` to the channel-layer debit. The commitment
   that *would* fix it (`h2_tag`) exists and is N-of-N-signed, and is read by exactly one thing: a
   client-side pre-flight in the CLI (`src/bin/channel_member.rs:6317-6331`) that an attacker simply
   does not run.
2. **It is not exploitable today**, for a reason that has nothing to do with the binding: the payout
   leg does not exist and cannot be built without a persisted live base-layer balance proof
   (`doc/tasks/partial-withdrawal-payout-design.md:752-760`).
3. **The constraint I was asked to work under does not hold as stated, and that is the larger
   finding.** The stated model — "the only party that can move channel base-layer funds without
   channel consent is a delegate account" — is inverted by the code. In the base layer:
   * a **delegate can never** author a base-layer block for the channel (delegates are *never* in
     the registered member tree, `src/common/trees/key_tree.rs:16-17`);
   * **any single genesis cosigner can**, over an arbitrary transfer tree, bounded only by the
     channel's own base-layer asset balance (`update_channel_tree.rs:950-1027`,
     `spend_circuit.rs:141-149`).
4. Consequently F-AUX-1's *marginal* severity is bounded by a strictly cheaper attack available to
   the same actor: the same cosigner can emit an `aux_data == 0` transfer and withdraw it with **no**
   IMPW authorization and **no** channel consent at all (`IntmaxRollup.sol:1512-1516`). Closing
   F-AUX-1 alone does not restore the property the spec claims (`abstract2-1.md:33`, `:405`: "no
   unilateral path", "no unilateral withdrawal").

Recommended disposition: keep F-AUX-1 at its current severity **as a binding defect** (it is a latent
trap, §3), and **open a separate, higher finding** for base-layer spend authority (§2.4). Do not
merge them: they have different fixes and different fix owners.

---

## 1. Is F-AUX-1 exploitable at all? Worked through concretely

### 1.1 What is bound, demonstrated

* The payout economics are proof-bound, not caller-declared. `withdrawNative` /`withdrawERC20` call
  `_verifyWithdrawalSet` (`contracts/src/IntmaxRollup.sol:1485`, `:1548`, definition `:1614+`), which
  re-folds `ws` into the proof's `pis_hash`. Every leaf field paid at `:1518-1522` is the proof's.
* The IMPW authorization commits all five leaf fields (`IntmaxRollup.sol:1596-1607`), so it cannot be
  re-read as a different tuple, and it can only veto (`:1512-1516`, `:1560-1564`).
* The base `Transfer` is built in exactly one place, `inter_channel_base_transfer`
  (`src/wallet_core.rs:2421-2433`), called by the send builder (`:2106-2113`) and by
  `burn_withdrawal_leaf` (`:2496`), so the leaf the CLI authorizes and the leaf inside the co-signed
  tx tree cannot drift **when both are produced by this code path**.
* That transfer's tree root becomes `h2_tag` (`src/wallet_core.rs:2119-2126`, `:2181`), which sits in
  the IMCH signing preimage (`src/common/channel.rs:598`) and is enforced equal to the descriptor's
  small-block `tx_tree_root` (`src/circuits/channel/state_update_verifier.rs:612-616`).

So the co-signers *do* commit to the amount. The question is whether anything downstream reads that
commitment.

### 1.2 What is not bound, demonstrated

* `auxData` = `tx_leaf_hash` over two Regev **ciphertext digests** plus the two `pk_g`s
  (`src/common/balance_state.rs:873-896`). No plaintext amount, no token index, no L1 address.
* The Manager binds only `auxData` into the co-signed chain (`ChannelSettlementManager.sol:1139-1146`)
  and says so (`:1150-1164`). `amount` is caller-supplied, capped only by the whole per-token channel
  fund (`:1174-1191`); `recipient` only has to be some registered participant (`:1200-1202`).
* **The channel-layer transition verifier never sees the base `Transfer`.** `InterChannelTx`
  (`src/common/channel.rs:722-756`) carries no `Transfer` and no transfer tree — only `tx_tree_root`
  inside the signed small-block message. `validate_signed_small_block`
  (`state_update_verifier.rs:1846-1899`) checks channel id, bp slot, freeze nonce and signature slot
  structure; it never reconstructs the tree from `(recipient, token_index, amount, aux_data)`. The
  fund-debit check at `:661-668` compares the channel fund against `self.amount`, a *separate* scalar
  from anything inside `tx_tree_root`.
* **The close-time cross-layer reconciliation is amount-blind.** `send_tx_circuit` folds only
  `aux_data` into the base balance proof's `settled_tx_chain`
  (`src/circuits/balance/send_tx_circuit.rs:281-298`), and the close circuit forces that chain equal
  to the N-of-N-signed channel chain (`close_circuit.rs:727-730`, native mirror `:1045-1048`). Two
  transfers that differ only in `amount` but share `aux_data` produce the *same* chain value. So even
  the strongest existing base↔channel reconciliation cannot see an amount divergence.
* `h2_tag` enters the close circuit only as a witness folded into the IMCH digest
  (`close_circuit.rs:479`, `:647`, `:940-941`). It is not a close public input and is never compared
  to any base-layer artefact. Grep for `h2Tag` in `contracts/src/*.sol` returns nothing.

### 1.3 Who can author a divergent base transfer — demonstrated

This is the part the earlier analysis never established. The answer is in the validity circuit, not
in the channel layer.

A channel's base-layer block is authorized by **exactly one signature**:

* `let should_verify_sig = should_update;` — one fold per block
  (`src/circuits/validity/block_hash_chain/update_channel_tree.rs:950`), with the in-circuit comment
  at `:933` "Exactly ONE IMSB signature per signing block".
* The only identity constraint is that the declared `bp_member_slot` equals the updating index `i`
  (`:961-977`) and that `MemberLeaf{pk_g = bp_pk_g, pk_b, regev_pk_digest}` is included at slot `i`
  of the channel leaf's `member_pubkeys_root` (`:1010-1016`; native mirror `:225-252`).
* `ChannelLeaf` carries **no** `bp_member_slot` (`src/common/trees/channel_tree.rs:95-105`), so the
  circuit cannot and does not pin the signer to the channel record's designated block producer. That
  check exists only in the off-chain channel-layer verifier
  (`state_update_verifier.rs:1863-1873`), which the base layer never runs.
* The signed message is the IMSB digest, which contains `tx_tree_root`
  (`small_block_message.rs:63-82`); every other field (`small_block_number`, `prev_small_block_root`,
  `state_commitment_root`, …) is a free witness with no continuity constraint.
* The spend side is bounded only by the channel's own base asset tree
  (`src/circuits/balance/spend_circuit.rs:141-149`).

**Therefore: any one holder of a registered slot key can sign a base-layer small block whose transfer
tree contains whatever they like, up to the channel's entire base balance.** Nothing about that
requires the channel-layer co-signature, and nothing later compares the two.

### 1.4 The concrete F-AUX-1 construction

Actor: one genesis cosigner of the channel (holds their own Falcon key; slot in the registered member
tree). Preconditions beyond the key are operational, see §5.

1. Propose an honest burn of `X` of the member's own funds. Co-signers verify E-2, the fund debit
   (`state_update_verifier.rs:661-668`) and the chain push, and sign. State now has
   `settled_tx_chain = push(prev, L)` with `L = tx_leaf` and `h2_tag = root(Transfer{R, t, X, L})`.
2. Do **not** publish that tx tree. Build a base-layer small block for the channel whose transfer
   tree is `{Transfer{R, t, Y, L}}` with `Y > X`, `R` an `ADDRESS_TAG` recipient the attacker
   controls, and sign the IMSB digest with the attacker's own slot key (§1.3). The base layer accepts
   it: only the attacker's signature is checked, and `Y` is within the channel's base balance.
3. Derive the withdrawal leaf for `Y`: `burn_withdrawal_leaf(channel_id, R, t, Y, L, nonce)`
   (`wallet_core.rs:2483-2517`). Every input is fixed at burn time (F-WD-2 property, `:2469-2479`),
   so the nullifier is computable.
4. `submitPartialWithdrawalIntent` with the co-signed intent for the post-burn state and
   `withdrawal = {R, t, Y, nullifier_Y, auxData = L}`. Chain check passes — it only recomputes
   `push(prev, L)` (`ChannelSettlementManager.sol:1143-1146`). Amount cap passes for any
   `Y <= channelFundAmounts[t]` (`:1180`). Recipient check passes (`:1200`).
5. Wait ≥ `challengePeriod`; `finalizePartialWithdrawal` (`:1243-1265`). `cancelPartialWithdrawal`
   requires a cancel-close proof, i.e. N-of-N (`:1279-1288`), and the attacker is one of the N.
6. `withdrawNative` with the real withdrawal proof for step 2's leaf. `auxData != 0` gate satisfied
   by the authorization from step 5. Payout `Y` from the **global** `totalEscrowed` (`:1520`).

Net: channel state debits `X`, L1 pays `Y`. The `Y − X` difference is exactly the double-count the
12B comment (`ChannelSettlementManager.sol:1246-1248`) assumes cannot happen.

**So F-AUX-1 is exploitable in principle, by a cosigner, and not by an ordinary non-cosigner or a
delegate.** The amount is *not* de facto fixed by the co-signed `h2_tag`, because nothing outside the
honest CLI ever opens `h2_tag`'s preimage.

### 1.5 Why this does not by itself justify raising F-AUX-1's severity

Step 2 already gives the attacker everything. With the same capability they can set `aux_data = 0`,
skip steps 1, 4 and 5 entirely, and call `withdrawNative` directly: the IMPW gate is conditional on
`w.auxData != bytes32(0)` (`IntmaxRollup.sol:1512`, `:1560`). That path needs no co-signature at all,
no 24-hour window, and no channel-layer artefact. It is strictly cheaper and strictly larger (the
whole channel base balance, not `channelFundAmounts[t]`).

An amount-committing `aux_data` (design §2 recommendation C) closes the burn lane but cannot close the
`aux_data == 0` lane, because the chain fold is gated on `aux_data != 0`
(`send_tx_circuit.rs:293-297`) — a rogue zero-aux send is invisible to the chain equality at close.

---

## 2. The delegate lane

The design doc's open question (`partial-withdrawal-payout-design.md:1010-1014`) was: is a delegate's
base-layer reach bounded to its own slot? I verified against code rather than the prior threat models.

### 2.1 Demonstrated: a delegate's base-layer *authoring* reach is zero, not "bounded"

* The tree the validity circuit proves bp-slot inclusion against is the **registered** `MemberTree`
  (`MemberTree::init`, height `MEMBER_TREE_HEIGHT`), and its doc comment states the rule outright:
  "Delegates are NEVER in this tree — they are authenticated by the cosigner-signed H1 balance-slot
  tree" (`src/common/trees/key_tree.rs:10-17`).
* The registered root covers only genesis cosigners and never changes:
  `member_pubkeys_root_for` (`channel_reg_step.rs:93-113`) with "Registration-producing paths emit
  `delegate_count = 0`" (`:97`), corroborated by `src/common/channel_registration.rs:85-99`.
* `update_channel_tree` preserves `member_pubkeys_root` across every transition
  (`update_channel_tree.rs:359-364`), so a post-genesis `join_delegate` can never enter it. The
  wallet's live root is a different tree that is "never compared" to it
  (`src/wallet_core.rs:605-613`).

So a delegate cannot be the signer of a channel small block, cannot author a base-layer transfer, and
therefore cannot move base-layer funds at all — with or without channel consent. Its reach is the
channel-layer send (co-signed by the members) and the close-time claim, whose recipient and amount are
proof-bound to the cosigner-signed slot leaf.

### 2.2 The stated model and the code disagree — in both directions

The recorded owner answer (`partial-withdrawal-payout-design.md:440-442`) says the delegate is the
only party that can move base funds without channel consent, and the doc then struck Phase 0 items on
that basis (`:444-447`). Against the code:

| Stated | Code |
|---|---|
| delegate can move base funds without channel consent | delegate cannot author any base-layer block (`key_tree.rs:16-17`) |
| members cannot ("the wall is closed for members", `:451-453`) | any genesis cosigner can, over an arbitrary tx tree (`update_channel_tree.rs:950-1027`) |

This is not a nuance: the doc's `:449-455` argument that the IMPW second factor is "a genuine
chokepoint for the actor F-AUX-1 concerns" rests on the wall being closed for members. It is not.

**Where 1-of-N honesty is actually carrying more weight than documented:** not in the delegate lane
(which is inert at the base layer) but in the *cosigner* lane, where a single cosigner's key is
sufficient to authorize a base-layer spend of the whole channel fund, and the only recorded control
is honest-member watching. The delegate threat model's DA6 ("Σ over ALL active balance slots ≤ channel
fund", `doc/tasks/delegate-account-threat-model.md:113-115`) states this as an obligation, not a
verified property, and I found no in-circuit or on-chain enforcement of it for the mid-channel base
lane.

### 2.3 Speculation (labeled)

I did **not** demonstrate that the owner's statement is simply wrong; it may describe an intent for a
different mechanism (e.g. that a delegate's *channel-layer* send is the only participant action not
requiring that participant's own co-signature). What I demonstrate is that, read as a statement about
who can spend the channel's base-layer account, the code delivers the opposite allocation.

### 2.4 Suggested separate finding (not part of F-AUX-1)

> **F-BASE-AUTH-1 — a channel's base-layer spend authority is 1-of-N cosigner, not N-of-N.**
> The validity circuit authenticates a channel small block with a single member signature over a
> freely chosen `tx_tree_root` (`update_channel_tree.rs:931-1027`), while `abstract2-1.md:33` and
> `:405` specify the burn leg as N-of-N-authorized with "no unilateral path". The `aux_data == 0`
> variant reaches `withdrawNative` with no channel-side gate whatsoever
> (`IntmaxRollup.sol:1512-1516`).

---

## 3. "No exploit today" vs "no binding" — stated plainly

Both statements below are true, and they are different statements.

**(a) There is no binding.** Demonstrated in §1.2. The equality `base Transfer.amount == channel-layer
debit` is not checked in any circuit, in any contract, or in any co-sign-time verifier. It holds only
because one honest code path builds both sides from the same function (`wallet_core.rs:2101-2113`) and
one client-side pre-flight re-derives H2 and compares (`channel_member.rs:6317-6331`). Both are
*producer-side* properties: they bind honest tooling to itself, not an adversary to the protocol. The
existing SECURITY comment is accurate in the narrow sense it claims — `aux_data` is merkle-bound and
the fold is faithful (`send_tx_circuit.rs:285-291`) — and it explicitly defers the semantics
off-circuit ("enforced off-circuit at co-sign time", `:288-289`; also
`doc/architecture-audit/detail2-implementation-notes.md:313-319`). The co-sign-time enforcement it
defers to does not exist for the *amount*: the co-signer never receives the base `Transfer` (§1.2).

**(b) There is no exploit today**, for reasons unrelated to (a):
* No payout leg. `cmd_partial_withdraw` is unwritten, and building it requires a persisted live
  base-layer balance proof for the channel, which does not exist
  (`partial-withdrawal-payout-design.md:752-760`, decision D4).
* The proof-free door was already removed (`IntmaxRollup.sol:792-807`), so a forged authorization is
  currently inert.

This is precisely the latent-trap shape the repo has been bitten by before: an unchecked value that is
"correct by construction" as long as exactly one producer exists. The single-source-of-truth comment
at `wallet_core.rs:2101-2113` is itself the scar tissue from the last instance of this class (the
nullifier that "could never match a provable leaf", HEAD~1 `533dd79`). The value should be *bound*,
not *documented as consistent*.

---

## 4. What `cmd_partial_withdraw` needs — which Phase 0 items survive

Against `doc/tasks/partial-withdrawal-payout-design.md` §2.3 (`:633-651`) and §5 (`:804-847`):

| Item | Survives? | Why |
|---|---|---|
| **P0-1** (owner answers §1.11, recorded) | **RE-OPEN** | The recorded answer (`:440-442`) is contradicted by `key_tree.rs:16-17` and `update_channel_tree.rs:950-1027` (§2.2). The items "struck from Phase 0" at `:446-447` were struck on a premise the code does not support — **un-strike them**, and re-ask the question as: *is 1-of-N cosigner base-layer spend authority intended?* |
| **P0-2** (adversarial review of the `finalSettledTxChain` pin for a mid-channel state) | **Survives, unchanged** | Independent of the actor question. |
| **P0-3** (descriptor layout + domain-tag collision check) | **Survives** | Mechanical prerequisite of the fix. |
| **P0-4** (negative test: `Y > X` with the same `auxData` is accepted end to end) | **Survives, and must be extended** | Add a second negative test for the `aux_data == 0` lane (a base transfer from the channel account with no channel consent reaching `withdrawNative`). If P0-4 alone passes after the fix, the property proven is narrower than "a member cannot over-withdraw". |
| **P0-5/P0-6/P0-7** (amount-committing burn descriptor: builder, Manager recompute, co-sign check) | **Survive** | These are the actual fix for F-AUX-1 and remain correct: they make the co-signed amount readable at the chokepoint without a circuit or VK change. Note P0-7 is the first place the *co-signer* ever sees the base amount — today it does not (§1.2). |
| **P0-8** (Lean records the conjunct) | **Survives** | |
| **P0-9** (era fence on the PW lane) | **Survives as necessary, but is now known to be insufficient** | The reasoning behind the D3 reversal (`:990-997`) is intact and does **not** depend on the delegate question: `cancelPartialWithdrawal` needs N-of-N (`ChannelSettlementManager.sol:1279-1288`) and nothing in `:1129-1241` reads `currentCloseFreezeNonce`. But an era fence cannot reach the `aux_data == 0` lane, which never touches the Manager. Keep P0-9; do not present it as making 1-of-N honesty real for base-layer funds generally. Its stated dependency on P1-1 (`:834-841`) is unaffected. |

**On the reversal the brief asks about.** There are two in that document, and they fare differently:

* **D3 "defer" → Phase 0 P0-9** (`:381-386`, `:538-539`, `:990-999`) — **the reversal still holds.**
  Its premises are contract-level facts I re-verified, not the delegate model.
* **§1.11's self-retraction** (`:444-447`: "my §1.11 observation was a correct reading of the
  mechanism and a wrong inference about intent", followed by striking Phase 0 items) — **the
  retraction does not hold.** The mechanism reading was correct; the code does not implement the
  intent that was offered in exchange for it. The struck items should return.

**Additional prerequisites for `cmd_partial_withdraw` that this re-assessment does not change**:
D4 base-state persistence (`:752-760`), nonce/`small_block_number` lockstep (`:757-760`), P3-3's
"read every field out of the proof's PIs" (`:884-887`), and the first `aux_data != 0` fixture
(`:892-897`).

---

## 5. What I could not establish

* **Operational reachability of §1.3.** `postBlockAndSubmit` is permissioned —
  `isBlockProducer[msg.sender] || msg.sender == blockProducerAdmin`
  (`contracts/src/IntmaxRollup.sol:839-841`, set at `:749`). So a rogue cosigner needs a registered
  block producer to include their sub-block. I did **not** establish whether the operator applies any
  policy filter, and I note that it *cannot* filter on channel consent, since the N-of-N signature is
  not visible on-chain or in the block. Whether the permissioned producer set is intended as a
  security control for this property is unrecorded in any document I read. I found no API relay for
  channel small blocks (`api/routes`, `api/lib`: no `postBlock` reference); today the CLI itself posts
  blocks (`src/bin/channel_member.rs:2565-2572`).
* **Whether a non-BP cosigner can in practice reconstruct the channel's base-layer private state**
  (asset tree + prior balance-proof chain) well enough to produce a valid IVC balance proof. Deposits
  are on-chain and sends are in posted blocks, so I believe it is reconstructible, but I did not
  demonstrate it and it is a real engineering barrier. Labeled speculation.
* **Whether an unpublished-but-co-signed burn creates a detectable divergence at the channel layer**
  (i.e. whether honest members would notice that the small block that landed is not the one they
  signed). The descriptor carries no way to check (§1.2), but I did not audit the wallet's snapshot
  / sync path for an independent comparison against posted blocks.
* **Whether `escrowedByToken` / manager-level accounting bounds the loss per channel.** I confirmed
  `totalEscrowed` (`IntmaxRollup.sol:1520`) and `escrowedByToken` (`:1568`) are global/per-token, not
  per-channel, but did not trace the full close-time accounting to quantify who absorbs the shortfall.
* I did not run any test, so every claim here is a code-reading claim. In particular P0-4's assertion
  that the `Y > X` case is "accepted end to end" is *consistent with* my reading but is not
  empirically confirmed — and cannot be until the payout leg exists.
