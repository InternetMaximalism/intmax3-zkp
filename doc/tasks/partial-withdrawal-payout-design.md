# Threat model + design: the proof-backed partial-withdrawal payout (`cmd_partial_withdraw`)

Original design branch: `feat/falcon-poseidon-sig` (HEAD `ea87604`). Current status:
**PHASES 0–2 IMPLEMENTED AND PROVING END-TO-END ON CURRENT `main`; PHASE 3 PAYOUT REMAINS
UNIMPLEMENTED.** The implementer adversarial review for P0-2 is recorded below, but the required
independent review must still be performed by someone other than the implementer before deployment.

Predecessors, read first: `doc/tasks/pw-auth-threat-model.md` (why the old payout was deleted),
`doc/tasks/todo.md:85-105` (the tracked GAP2 work), `doc/tasks/b2-delegate-close-threat-model.md`
(the plan format this follows), commit `42640f1` (the removal).

---

## 0. Framing corrections — read before §1

The task framing was right about the shape of the problem and wrong in four places that materially
change the plan. All four are evidence-backed, and two of them make the job **easier** than it looks
while one makes it **worse**.

### 0.1 `api/API-DESIGN.md` no longer overclaims — it is already honest (and was corrected on HEAD)

The brief says `api/API-DESIGN.md` "says `pw-finalize` is implemented". It does say that, but in a
sentence that continues *"— and **exits 1 by design after recording the authorization**. That is
fail-closed, not a bug"* (`api/API-DESIGN.md:562-563`), under a section header reading
**`Current status: AUTHORIZATION ONLY — NO PAYOUT ON ANY CHAIN.`** (`:556`), with
**`Payout: NOT IMPLEMENTED.`** at `:568` and a pointer to *this* file at `:582`. The uncommitted
working-tree edit to `api/API-DESIGN.md` (see `git status`) already did this work.

The route contract is honest too. `POST …/finalize` and `POST …/settle` return **501** with
`{authorized: true, paidOut: false}` and set the ticket to `settle_blocked`, never `settle_done`
(`api/routes/partial-withdrawal.js:24-49`, `:138-141`, `:167-170`); the honesty note at `:19-23`
records that the old `{ok: true}` branch "was unreachable — the request always landed in the catch".

**Three real doc/code divergences remain** and should be fixed as bookkeeping, not as part of this
design:

| Claim | Site | Reality |
|---|---|---|
| "`pw-submit` calls `build_channel_withdrawal` internally" | `api/API-DESIGN.md:520-521` | The **only** call site of `build_channel_withdrawal` in the binary is `cmd_withdraw` (`src/bin/channel_member.rs:2720`). `cmd_pw_submit` never proves anything. |
| "`pw-submit` calls deploy-settlement if needed" | `api/API-DESIGN.md:536` | `cmd_pw_submit` only *reads* `settlement.json` (`src/bin/channel_member.rs:6219-6225`); the deploy is the route's job (`api/routes/partial-withdrawal.js:113`). |
| `finalize` `Response: { ok: true, authDigest }` | `api/API-DESIGN.md:586-590` | The route returns 501 (`api/routes/partial-withdrawal.js:35-48`). The prose above it is right; the code block below it is stale. |

Also worth knowing: `node/cosigner/branches/close.js:22-39` **drives `pw-finalize` automatically**
from a watcher loop and logs the deliberate exit-1 as a generic `PW_FINALIZE_FAILED` (`:36-38`). It
does not lose money, but it is a recurring alarm on a fail-closed state.

### 0.2 The "co-signer assumption" is weaker than "assumption" — the co-signers *do* commit the base transfer, but **nothing on the payout path ever checks their commitment**

This is the single most important finding in this document, and it changes what the fix has to be.

The base-layer `Transfer` a burn will later withdraw against is built **at burn time**, inside the
same function that builds the channel-layer debit:

```rust
// src/wallet_core.rs:2101-2108
transfer_tree.push(Transfer {
    recipient: destination_recipient_pk_g,   // ADDRESS_TAG form of withdrawal_l1_address
    token_index,
    amount: u64_to_u256(amount),
    aux_data: burn_aux,                      // = tx_leaf for a burn (`:2095-2100`)
});
```

That tree's root becomes `tx_v2.transfer_tree_root` → `tx_tree_root` (H2) (`src/wallet_core.rs:2109-2120`),
and the post-burn channel state records `h2_tag = tx_tree_root` (`src/wallet_core.rs:2174`), enforced
natively at `src/circuits/channel/state_update_verifier.rs:612-616`. **`h2_tag` is inside the IMCH
signing preimage** (`src/common/channel.rs:597`, inside `ChannelState::signing_digest` at `:579-602`)
— so every co-signer's Falcon signature covers H2, and therefore covers the burn's base `Transfer`
in full: recipient, token index, **amount**, and aux_data.

So the co-signers are not making an unverifiable promise about a value they never saw. They
**cryptographically commit** to it. The defect is on the other side:

- The base `single_withdrawal` circuit binds the transfer to *its own* tx's transfer tree
  (Merkle membership at `src/circuits/balance/common/transfer_witness.rs:88-93`, root pinned to the
  tx at `src/circuits/withdraw/single_withdrawal_circuit.rs:466-468`; on the send side
  `src/circuits/balance/send_tx_circuit.rs:275-279`) — but that tx is whichever tx the base prover
  got into a block. Nothing compares it to `h2_tag`.
- The manager's partial-withdrawal gate binds **only `auxData`**:
  `keccak(0x494d5443, prevSettledTxChain, withdrawal.auxData) == intent.finalSettledTxChain`
  (`contracts/src/ChannelSettlementManager.sol:1143-1146`). `auxData` for a burn is `tx_leaf`, and
  `tx_leaf = H(H(IMTL, sender_pk_g, sender_delta_digest), H(IMTL, receiver_pk_g, receiver_delta_digest))`
  (`src/common/balance_state.rs:873-895`) — over **Regev ciphertext digests**. It commits no
  plaintext amount, no token index, no L1 address.
- The close proof's only link to the base layer is
  `balance_pis.settled_tx_chain.connect(final_settled_tx_chain)`
  (`src/circuits/channel/close_circuit.rs:729-730`). That chain folds `aux_data`
  (`src/circuits/balance/send_tx_circuit.rs:290-297`) — the same value on both sides, so it is
  satisfied by *any* base tx carrying that `aux_data`, regardless of its amount.
- `channel_fund_intmax_state_root` is a **free witnessed PI** in the close circuit — allocated at
  `src/circuits/channel/close_circuit.rs:151`, only folded into digests (`:642`, `:659`, `:688`), and
  never connected to the balance proof's public state. So there is no in-circuit equality
  `channel_fund == base asset-tree balance` either.

**Consequence.** A prover who obtains an *honest* N-of-N co-signature for a burn of `X` can then
build a **different** base tx whose transfer carries amount `Y > X` and the **same** `aux_data`, and
every check on the payout path still passes: the chain fold matches, the manager mints the
authorization, and the withdrawal proof is genuine. Honest co-signers cannot stop it — the artefact
they signed (H2) is simply never consulted again.

The corollary that decides the design: **this is a *binding* problem, not a *commitment* problem.**
The commitment already exists and is already N-of-N-signed. Something on the payout path just has to
read it. That is why §2 can offer a fix with **no circuit change and no VK change**.

### 0.3 Blast radius: bounded by the channel's **own base-layer balance**, not global — but the bound is a *proof* bound, not an on-chain one

Asked directly: *can a channel burn X internally and withdraw Y > X, and does the loss reach other
channels' funds?*

**Yes to the first; no to the second — and the reason is worth stating precisely, because the
on-chain layer does not provide it.**

- On-chain there is **no per-channel escrow at all**. ETH lives in the single global `totalEscrowed`
  (`contracts/src/IntmaxRollup.sol:528`, credited `:983`, debited `:1520`); ERC-20 lives in
  `escrowedByToken[tokenIndex]` (`:545`, `:1006`, `:1568`) — keyed by **token**, not channel. The
  only channel-keyed rollup state is identity (`channelMemberSetCommitment` `:485`,
  `channelBpMemberSlot` `:487`, `channelBpPkG` `:489`). `deposit()` does not even take a channelId
  (`:969-974`). The in-code comment at `:1476-1478` says as much.
- The manager's per-channel ceiling (`receivedChannelFunds` / `totalCreditedOut`,
  `contracts/src/ChannelSettlementManager.sol:665`, `:1512-1514`) governs `claimWithdrawalCredit`
  only. **A partial withdrawal never passes through it** — `withdrawNative` credits
  `pendingWithdrawals[w.recipient]` directly (`IntmaxRollup.sol:1521`) and the PW recipient is a
  member's L1 address, not the manager.
- The containment therefore comes entirely from the **base-layer proof**: the spend circuit debits
  the asset tree by `transfer.amount` with a no-underflow constraint
  (`src/circuits/balance/spend_circuit.rs:372` → `src/ethereum_types/u256.rs:304-330`, final borrow
  `connect`ed to zero at `:319-320`), and the resulting chain is anchored on-chain to a finalized
  state root (`IntmaxRollup.sol:1637-1638`).

So `Y` is capped by the channel's own base asset-tree balance for that token — i.e. by what was
deposited to that channel plus what it received. **Cross-channel theft is impossible on this path**,
which is a genuine, categorical improvement over the deleted `claimAuthorizedWithdrawal` (which had
no proof and so no cap but `totalEscrowed`).

What `Y > X` *does* buy is **intra-channel theft up to the whole channel**: the burner drains value
the channel-layer accounting still attributes to other members, and — because the close's burn leg
must later be covered by the same base asset tree — the honest members' close either pays out short
or becomes unprovable. Bounded, but total within the channel.

**Who must collude: one member, with honest co-signers.** Not a majority, not N-of-N. The burner
needs (a) an honest N-of-N co-signature on a burn of `X` (which honest members give, because the
burn is honest as far as they can see), and (b) the ability to build the base-layer proof — which is
a *separate*, later act (§0.4). It requires no key compromise and no protocol break.

### 0.4 Blocker #1 (the nullifier) is a **liveness / fund-lock** bug, not a soundness bug — and it is already fixable with no design change

`cmd_pw_submit` computes

```rust
// src/bin/channel_member.rs:6282-6288 — 64-byte preimage, no domain tag, raw keccak_hash::keccak
let mut data = Vec::with_capacity(32 + 32);
data.extend_from_slice(&tx_leaf.to_bytes_be());
data.extend_from_slice(&pre_burn_chain.to_bytes_be());
let hash = keccak_hash::keccak(&data);
```

The provable leaf's nullifier is instead
`SettledTransfer::nullifier() = Poseidon(recipient(8) ‖ token_index(1) ‖ amount(8) ‖ aux_data(8) ‖
channel_id ‖ transfer_index ‖ nonce)` (`src/common/transfer.rs:124-126` over `:110-118`;
in-circuit at `src/circuits/withdraw/single_withdrawal_circuit.rs:518-525`, and natively at `:376-390`).

Different hash family, different preimage, different domain. They can never coincide.

**What that breaks, precisely.** The nullifier is caller-supplied into the intent
(`ChannelSettlementManager.sol` `submitPartialWithdrawalIntent`, `withdrawal.nullifier` is entirely
free) and enters the IMPW `authDigest`
(`keccak(0x494d5057, nullifier, recipient, tokenIndex, amount, auxData)` —
`IntmaxRollup.sol:1596-1607`, mirrored in Rust at `src/wallet_core.rs:2398-2413`). `withdrawNative`
requires `partialWithdrawalAuthorized[_withdrawalAuthDigest(w)]` for the **proven** leaf `w`
(`:1512-1516`). A wrong nullifier therefore produces an authorization that **no provable leaf can
ever match**. Fail-closed. **No value can be stolen with it.**

But it is not harmless: `submitPartialWithdrawalIntent` consumes the chain key
`keccak(channelId, intent.finalSettledTxChain)` into `usedPartialWithdrawalChains`
(`ChannelSettlementManager.sol:1204-1205`, set at `:1250`), **permanently**. The channel-layer debit
has already happened (`src/wallet_core.rs:2153-2168`). So a single bad `pw-submit` leaves the
member's balance debited on the channel side with **no reachable L1 payout for that burn, ever** —
the value is stranded in the base asset tree, outside the channel's accounting. That is a fund-loss
bug, and it is live today in `cmd_pw_submit`.

The preimage is 28 Goldilocks elements — `recipient(8) ‖ token_index(1) ‖ amount(8) ‖ aux_data(8) ‖
from(1) ‖ transfer_index(1) ‖ nonce(1)` (`src/common/transfer.rs:110-118`) — with **no domain tag**.
(The withdrawal-leaf keccak fold has none either: `src/common/withdrawal.rs:97-100`, mirrored at
`IntmaxRollup.sol:1659-1664`. Separation between the two rests on distinct field counts and hash
families. Recorded, not proposed for change — altering either preimage would move a VK or a
cross-boundary parity assertion for no security gain.)

**Good news:** the nullifier is fully computable at burn time and needs no circuit change. F-WD-2
already made it settlement-independent — the SECURITY comment at
`src/circuits/withdraw/single_withdrawal_circuit.rs:372-375` and `:513-517` says it binds the sender
`nonce`, not the block number. At burn time the CLI knows every input:
`recipient` and `token_index` and `amount` and `aux_data` from the burn's own `Transfer`
(`src/wallet_core.rs:2101-2108`); `channel_id` from the record; `transfer_index = 0`, which
`send_tx_circuit` *asserts* (`src/circuits/balance/send_tx_circuit.rs:279`); and
`nonce = prev.small_block_number + 1`, which is `tx_v2.nonce` (`src/wallet_core.rs:2110-2115`) and
which the withdrawal circuit forces equal to `tx.nonce`
(`src/circuits/withdraw/single_withdrawal_circuit.rs:508`).

The one coupling this creates is stated as an acceptance criterion in Phase 2: the base account's
sent-tx tree slot at index `nonce` must be **empty** at proving time, because
`sent_tx_merkle_proof.verify` demands an empty leaf there
(`src/circuits/balance/spend_circuit.rs:387-395`). If the channel's `small_block_number` and the base
account's send nonce ever diverge, the burn becomes unprovable — a liveness break that must be
detected at burn time, not at payout time.

### 0.5 A fourth thing the framing did not mention: the PW submit path is **entirely mocked today**

`cmd_pw_submit` writes a close-intent JSON in which `close_nonce = 1`, `close_freeze_nonce = 0`,
`burn_tx_hash = 0` and `close_withdrawal_digest = 0` are **hardcoded literals**
(`src/bin/channel_member.rs:6310`, `:6313`, `:6318`, `:6319`), and the forge script it drives sets

```solidity
proof.publicInputs = verifier.expectedCloseLimbs(fields, ...);
```

(`contracts/script/SubmitPartialWithdrawal.s.sol:81-84`) — i.e. it hands the verifier the very limbs
the verifier is about to expect. On top of that, `DeployPartialWithdrawalE2E.s.sol` installs an
always-true `E2EMockMleVerifier` with a 1-second challenge period and **no chain-id guard** (recorded
already at `doc/tasks/pw-auth-threat-model.md:433-440`).

So the "valid close proof for your own channel" precondition in the original exploit narrative is,
on the CLI path as shipped, **not even required**. Any design that assumes `submitPartialWithdrawalIntent`
is backed by a real close proof must make that true first. It is Phase 1 below.

---

## 1. Threat model

### 1.0 Actors and capabilities

| Actor | Capability assumed |
|---|---|
| **Burner** | One channel participant. Holds their own Falcon key, can propose a burn, and — critically — operates or can reach the base-layer proving path for the channel account. |
| **Honest co-signers** | The other N−1 members. Verify what the co-sign code puts in front of them (`verify_inter_channel_send_transition`, `src/wallet_core.rs:2415+`; `cmd_cosign_burn_send`, `src/bin/channel_member.rs:4627-4740`) and nothing else. |
| **Coordinator / relay** | Runs the CLI on behalf of members (`api/lib/cli.js:41-49`), chooses `PW_RECIPIENT` (`api/routes/partial-withdrawal.js:114-116`), sequences on-chain calls. Untrusted for integrity. |
| **Block producer (BP)** | A designated member slot; signs the small block that carries the tx. |
| **Anyone** | `submitPartialWithdrawalIntent` and `finalizePartialWithdrawal` are **permissionless** (no `msg.sender` check in either body). `withdrawNative`/`withdrawERC20` are permissionless. |

### 1.1 T1 — Amount substitution (F-AUX-1). **CRITICAL. Open. Phase 0.**

*Attack.* Burner obtains an honest co-signature for a burn of `X`, then builds the base proof with a
transfer of `Y > X` carrying the same `aux_data = tx_leaf`, and submits the intent with `amount = Y`.

*What stops it today.* **Nothing on the payout path.** The chain fold matches (only `aux_data` is
folded, `send_tx_circuit.rs:290-297` / `ChannelSettlementManager.sol:1143-1146`); the amount cap
`withdrawal.amount <= intent.channelFundAmounts[slot]`
(`ChannelSettlementManager.sol:1174-1191`) caps `Y` at the **whole channel's** fund for that token,
not the burner's share, so it is not a defence against this; the withdrawal proof is genuine. The
one artefact that would stop it — the co-signed `h2_tag` — is never read
(§0.2). The only real ceiling is the base asset-tree balance (§0.3).

*What stops it in the design.* §2: make the value that **both** layers fold commit the plaintext
`(recipient, tokenIndex, amount)`, and have the manager recompute it. Then a `Y ≠ X` intent cannot
reproduce the co-signed `finalSettledTxChain`.

*Residual after the fix.* N-of-N collusion — identical to the trust the close path already places in
N-of-N. See §6.

### 1.2 T2 — Recipient substitution

*Attack.* Pay a burn to an address other than the burning member's registered L1 address.

*What stops it today.* On the intent side, almost nothing: `withdrawal_recipient` comes from the
`PW_RECIPIENT` **environment variable** (`src/bin/channel_member.rs:6277-6280`), set by the relay
from request body or ticket (`api/routes/partial-withdrawal.js:114-116`,
`hosting/wallet/wallet-relay-ec2.js:966`), and is never compared to the
`withdrawal_l1_address` that `build_burn_send` baked into the burn
(`src/wallet_core.rs:2370`). The only constraint is `isMemberRecipient[withdrawal.recipient]`
(`ChannelSettlementManager.sol:1200-1202`), which admits **any** participant of the channel,
including delegates.

*What stops it in the design.* Two layers, both free. (a) On the proof-backed path the recipient in
the paid leaf is the **proven** one — `extract_address_from_recipient` of the transfer's ADDRESS_TAG
recipient (`single_withdrawal_circuit.rs:510-511`), which was fixed at burn time — and the IMPW
digest binds `recipient`, so a mismatched intent simply never authorizes the proven leaf
(fail-closed). (b) The §2 descriptor puts the recipient inside the co-signed fold, so a substituted
recipient cannot reproduce the chain either. `isMemberRecipient` stays as containment.

*Note.* T2 is therefore **already fail-closed** once the payout is proof-backed. It is listed
because today it is the source of a confusing failure mode (a mismatched `PW_RECIPIENT` burns the
chain key exactly as §0.4 describes), not because it is a theft vector on the new path.

### 1.3 T3 — Nullifier collision or reuse across the partial and full lanes

*Sub-case (a): the same leaf paid twice.* `withdrawalNullifierUsed` is a single mapping shared by
both entry points, checked at `IntmaxRollup.sol:1494` / `:1554` and set at `:1518` / `:1566`, CEI,
both `nonReentrant`. The token guards (`:1493` `tokenIndex == 0`, `:1552` `tokenIndex != 0`) make the
two paths disjoint, and the IMPW digest itself binds `tokenIndex`. **Closed today; unchanged by this
design.**

*Sub-case (b): a partial-lane nullifier colliding with a full-lane one.* Both lanes derive the
nullifier from the *same* function over the *same* struct
(`SettledTransfer::nullifier()`), so a collision requires two distinct
`(recipient, token_index, amount, aux_data, channel_id, transfer_index, nonce)` tuples with equal
Poseidon output. `aux_data` differs structurally between the lanes (`0` for a normal withdrawal —
`src/wallet_core.rs:4585` — vs the burn descriptor), so the tuples are separated in a field that
enters the hash. **Reduces to Poseidon collision resistance.** Acceptable; recorded, not fixed.

*Sub-case (c): the CLI's invented nullifier.* Covered in §0.4 — fail-closed but fund-locking. The fix
is Phase 2.

*Design obligation.* Do **not** introduce a second nullifier formula for the partial lane. One
formula, one function, used by the circuit and by the CLI. The current three-way disagreement —
CLI `keccak(tx_leaf ‖ pre_burn_chain)` (`src/bin/channel_member.rs:6282-6288`), the proof-committed
leaf (`src/wallet_core.rs:4897-4901`), and the E2E's literal `0xBEEF`
(`tests/partial_withdrawal_e2e.rs:452-458`) — is the defect class to close.

### 1.4 T4 — Replay across channels, eras and tokens

*Across channels.* The nullifier hashes `from = channel_id`
(`src/common/transfer.rs:113-116`), the withdrawal chain re-fold on-chain hashes every leaf field
(`IntmaxRollup.sol:1662-1666`), and the manager's chain key is
`keccak(channelId, finalSettledTxChain)` (`ChannelSettlementManager.sol:1204`). A leaf from channel A
cannot be replayed as channel B's. **Closed.**

*Across tokens.* `tokenIndex` is in the leaf, in the fold, and in the IMPW digest; the two payout
entry points are disjoint by token class; escrow is debited per token
(`escrowedByToken[w.tokenIndex] -= w.amount`, `:1568`). **Closed.**

*Across eras.* See T6 — this is the one that is **not** closed on the PW lane.

*Across time.* Worth stating because it surprises people: `_verifyWithdrawalSet` anchors against
`finalizedStateRoots[extCommitment]` — the **permanent set of every historically finalized root**
(`IntmaxRollup.sol:1637-1638`) — not `latestFinalizedStateRoot`. (The `withdrawNative` docblock at
`:1472` says "must equal `latestFinalizedStateRoot`" and is **stale**; the rationale for the set
semantics is at `:1633-1636`.) So a burn leaf, once provable, is provable **forever**. That is
intentional and is what makes single-use nullifiers load-bearing, but it means §1.5 must be analysed
without any implicit expiry.

### 1.5 T5 — Double-spend between a partial withdrawal and a later full close

*Attack.* Burn `X` mid-channel, do not redeem the leaf, close the channel, take the close payout,
then redeem the burn leaf afterwards.

*What stops it today (assuming the payout existed).* Partially, and by an argument that lives in the
base layer rather than in the contracts:

- The burn debits `channel_fund.amounts[slot]` at burn time (`src/wallet_core.rs:2158-2165`), so the
  close's `channelFundAmounts` — strict-bound to close PI limbs 95..102 via the recomputed
  `tokenFundsDigest` (`contracts/src/ChannelSettlementVerifier.sol:527-530`, `:421-442`) — already
  excludes it. The close pays out less by exactly `X`.
- The base asset tree was debited by the burn transfer's amount at spend time
  (`spend_circuit.rs:372`), so the close's own burn-leg withdrawal is drawn from what remains. The
  two withdrawals cannot jointly exceed the base balance, by the no-underflow constraint.
- The burn leaf's nullifier is single-use, so it pays at most once whenever it is redeemed.

**So T5 is sound only because the channel-layer debit and the base-layer debit are the same `X`.
Under T1 (`Y > X`) it is not** — the channel deducts `X` from the fund vector while the base deducts
`Y`, and the honest members' close is short by `Y − X`. T5 is therefore *downstream of T1*, and
closing T1 is what closes it.

*What the design adds.* Nothing new is needed beyond T1, but Phase 4 must include an explicit E2E
that burns, closes, and *then* redeems, asserting conservation across both lanes.

### 1.6 T6 — Close-freeze nonce, the era fence, and A45

*Facts.* `close_freeze_nonce` is inside the IMCH preimage (`src/common/channel.rs:586`) and is
incremented in exactly one place, `CloseIntent::new` (`src/common/channel.rs:1028`). The burn's
small block carries `close_freeze_nonce: prev.close_freeze_nonce` (`src/wallet_core.rs:2194`),
validated at `src/circuits/channel/state_update_verifier.rs:1874-1877`. On L1, the manager increments
`currentCloseFreezeNonce` in `requestClose` (`ChannelSettlementManager.sol:903`) and fences
`submitCloseIntent` against it at `:932-934` and `:948-950`.

*Gap 1 — `submitPartialWithdrawalIntent` has no era fence.* Nothing between
`ChannelSettlementManager.sol:1135` and `:1241` reads `currentCloseFreezeNonce`. The nonce is
proof-authenticated (close PI limbs 7..8, `ChannelSettlementVerifier.sol:501`) but is not compared to
the manager's live era. A PW intent proved against a stale era is accepted.

*Gap 2 — the CLI hardcodes it to zero.* `"close_freeze_nonce": 0u64`
(`src/bin/channel_member.rs:6313`; the E2E mirrors it at `tests/partial_withdrawal_e2e.rs:470`).

*Consequence, already documented.* The cancel path (A45) is **unenableable**: the cancel circuit's
era fence is `revived.close_freeze_nonce + 1 == close_intent.close_freeze_nonce`
(native `src/circuits/channel/cancel_close_pis.rs:115-119`, in-circuit
`src/circuits/channel/cancel_close_circuit.rs:469-472`), unsatisfiable at 0. The route returns an
unconditional 501 with that exact reasoning (`api/routes/partial-withdrawal.js:173-182`, quoted in
full there). So **a partial withdrawal, once submitted, cannot be cancelled** — the only defence
against a malicious PW intent during the challenge window does not exist.

*What the design must do.* Phase 1 makes the intent carry the **real** proved
`close_freeze_nonce`, which is a precondition for A45 ever being enableable.

**Revised after the owner's 2026-08-13 answer (§1.11, §1.12):** adding the era fence to the PW lane
is **no longer a deferrable "decision D3"** — it is the mechanism that makes 1-of-N honesty real for
this lane, and it moves into Phase 0 as **P0-9**. Its interaction with the deliberate absence of a
`channelStatus` check in `finalizePartialWithdrawal` (`ChannelSettlementManager.sol:1245-1248`) is
now understood rather than merely noted: that omission is justified by a no-double-counting argument
whose premise is exactly what F-AUX-1 breaks (§1.12 item 3).

This design still does **not** enable A45; it removes the blocker that makes A45 impossible, and
A45 remains an N-of-N control regardless (§1.12 item 2).

### 1.7 T7 — Malicious coordinator

The coordinator picks `PW_RECIPIENT` (T2), sequences the calls, and can call the permissionless
`submitPartialWithdrawalIntent` / `finalizePartialWithdrawal` itself. Post-§2 it can still:

- **Grief.** Submit a PW intent for a burn with a *wrong* recipient/nullifier, consuming the chain key
  (`ChannelSettlementManager.sol:1204-1205`, `:1250`) and stranding that burn permanently (§0.4).
  **Not fixed by this design.** Mitigation is client-side: the CLI must derive every intent field
  from the burn artefact, never from environment or request body. That is a Phase 2 acceptance
  criterion, and it reduces the attack to "a coordinator that lies about its own inputs", which the
  member can detect by recomputing the digest locally (the CLI already prints both the Rust and the
  on-chain digest, `src/bin/channel_member.rs:6300-6301`, `:6391-6394`).
- **Not steal.** Every payout field comes from the proven leaf; the authorization can only veto
  (`IntmaxRollup.sol:1500-1516`).

### 1.8 T8 — Colluding co-signer majority, and N-of-N

A *majority* short of N buys nothing: the burn state needs N-of-N (`verify_all_signatures`,
`src/bin/channel_member.rs:4677-4691`), and the close proof binds `signer_count` to `member_count`
(`src/circuits/channel/close_circuit.rs:749-757`).

**N-of-N** already owns the channel: it can sign any final state, hence any `channelFundAmounts`, and
close to any per-member split. Post-§2 the residual F-AUX-1 exposure reduces to exactly this — N-of-N
can co-sign a burn descriptor whose declared amount does not match the E-2 debit. That is **not a new
capability**; it is the capability they already have via the close. Stating it plainly is the point:
after §2, PW's trust base equals close's trust base. Before §2, it is strictly weaker (one member
suffices).

### 1.9 T9 — Forged / absent close proof on the submit path

Today the CLI submits a mock proof against a mock verifier (§0.5). Under that configuration
`submitPartialWithdrawalIntent` will mint an authorization for **any** `(prevSettledTxChain, auxData)`
pair the caller invents, because the caller also supplies the `finalSettledTxChain` the check
compares against. The keccak chain check becomes self-referential.

*What stops it today.* Only that the payout does not exist.

*What stops it in the design.* Phase 1: the CLI must submit a **real** close proof produced by the
real `CloseProver`, verified by a real `ChannelSettlementVerifier` against a real close VK, and the
E2E deploy scripts must refuse to run off chain-id 31337 (the recommendation already recorded at
`doc/tasks/pw-auth-threat-model.md:433-440`, still unapplied).

### 1.10 T10 — Chain-key exhaustion / stranded burn

Covered in §0.4 and §1.7. Recorded here as its own row because it is the **only** way this design
can lose money after §2, and because it is live today.

### 1.11 Base-layer spend authority — **ANSWERED by the owner (2026-08-13)**

> **Owner's answer:** the only party that can move funds from the channel's base-layer account
> without channel consent is a **delegate account**. The security model relies on at least one
> honest member being present in the channel (**1-of-N honesty**).

This resolves the open question as **design intent, not an unnoticed hole**. The `auxData == 0`
lane is the delegate lane operating as designed; my §1.11 observation was a correct reading of the
mechanism and a wrong inference about intent. Recorded as such, and the corresponding items are
struck from Phase 0.

**What the answer buys the IMPW second factor.** It makes it meaningful rather than decorative. If
*any* party could emit `auxData == 0` leaves for the channel account, the burn lane would be a door
next to an open wall and §2 would be near-worthless. Under the owner's model the wall is closed for
members: a member's only route to the channel's base funds is the consented burn lane, which is
gated by `auxData != 0` ⇒ `partialWithdrawalAuthorized` (`IntmaxRollup.sol:1512`, `:1560`). So the
IMPW flag is a genuine chokepoint for the actor F-AUX-1 concerns, and §2's fix applies at exactly
that chokepoint. **The answer raises the value of this design; it does not reduce the work.**

**What it does not buy — and this is §1.12.** The delegate lane and the F-AUX-1 lane are covered by
the same stated assumption, but the assumption has to *do different work* in each. In the delegate
lane, "one honest member" is a liveness assumption: the honest member watches, and the levers exist.
For F-AUX-1 the required work is different, and the code does not deliver it.

### 1.12 Does 1-of-N honesty cover F-AUX-1? **No. Stated plainly.**

The coordinator's instinct is right, and the code confirms it. Working the question exactly as posed
— *after the honest signature is given and before the base withdrawal lands, what can one honest
member actually do?*

**The attack does pass through a real window.** This is the part that at first looks like it saves
the model, so it is worth being precise about. The burn leaf has `auxData != 0` by construction, so
the payout requires `partialWithdrawalAuthorized` (`IntmaxRollup.sol:1512`, `:1560`), which requires
`submitPartialWithdrawalIntent` → wait → `finalizePartialWithdrawal`. The wait is real and long:
`challengePeriod` is immutable, floored at `CHALLENGE_PERIOD_SECS = 86_400`
(`ChannelSettlementManager.sol:552`, enforced `:765-766`), with the sole exception of a named local
devnet chain (`:556`). So there **is** ≥ 24 h between the intent and the payout.

**Detection inside that window is easy.** The honest member co-signed the burn, so they know `X`.
`withdrawal.amount` is plain calldata to `submitPartialWithdrawalIntent`, and
`PartialWithdrawalSubmitted` (`ChannelSettlementManager.sol:336-341`) fires with the deadline. A
watcher comparing the submitted amount against the co-signed one is trivial to write. **Detection is
not the problem.**

**Prevention is the problem. I enumerated every lever and none is unilateral.**

1. **At co-sign time — nothing to refuse.** The honest member is asked to sign a burn of `X`, which
   is honest. `Y` does not exist yet; the base proof is built later and unilaterally. This is the
   whole shape of the attack.
2. **`cancelPartialWithdrawal` — requires N-of-N, so the attacker vetoes it.** This is the decisive
   finding. The function (`ChannelSettlementManager.sol:1267-1304`) requires
   `verifier.verifyCancelClose(...)` (`:1279-1288`), i.e. a **cancel-close proof**. That circuit
   demands a strictly newer revived state signed by **every active member**:
   *"Exactly `member_count` ACTIVE entries (slot order) — ALL active members sign the revived
   [state]"* (`src/circuits/channel/cancel_close_circuit.rs:168-175`), with
   `signer_count == revived_member_count` bound in-circuit so a prover cannot under-sign
   (`:493-497`), and `assert_one(revived_gt_close)` forcing strict newness (`:467`).
   **The malicious burner is one of the N. They simply do not sign.** The only control that can stop
   a pending partial withdrawal is therefore an **N-of-N-honesty control**, not a 1-of-N one.
3. **The era fence — exists, works, and is deliberately not wired to this lane.** `requestClose()`
   *is* the unilateral lever the owner's model expects: any registered member can call it
   (`isMemberRecipient[msg.sender]`, `ChannelSettlementManager.sol:898`) and it increments
   `currentCloseFreezeNonce` (`:903`). For the **close** lane that is decisive — `submitCloseIntent`
   rejects a stale era at `:932-934` and `:948-950` with `InvalidFreezeNonce`. For the **partial
   withdrawal** lane it is inert: nothing between `:1129` and `:1241` reads
   `currentCloseFreezeNonce`, and `finalizePartialWithdrawal` explicitly declines to check status:

   ```solidity
   // ChannelSettlementManager.sol:1245-1248
   if (block.timestamp <= pendingPartialWithdrawalDeadline) revert ChallengeWindowOpen();
   // SECURITY (12B fix): NO channelStatus check. If requestClose races during the challenge
   // period, the partial withdrawal can still finalize — the burned amount is already excluded
   // from the close's channelFundAmount, so no double-counting.
   ```

   **That rationale is sound if and only if F-AUX-1 is closed.** "The burned amount is already
   excluded from the close's `channelFundAmount`" is true of `X` — the channel-layer debit
   (`src/wallet_core.rs:2158-2165`). Under `Y > X` the excluded amount is `X` while the payout is
   `Y`, so `Y − X` **is** double-counted, and the 12B decision has removed the honest member's only
   unilateral lever in exactly the case where it was needed. The comment is not wrong; its premise
   is the thing F-AUX-1 breaks.
4. **After finalize — nothing.** `finalizePartialWithdrawal` and `withdrawNative` are both
   permissionless; the attacker (or anyone) calls them.
5. **Racing a close — does not help.** Close needs N-of-N too (`close_circuit.rs:749-757`), and per
   (3) a `requestClose` does not stop the pending PW anyway.

**Verdict.** The base withdrawal proof is self-contained and verifies on its own; the one gate in
front of it is the IMPW flag, and the only way to stop that flag being set is a control that itself
requires the attacker's signature. **So the 1-of-N honesty assumption does not cover F-AUX-1.
Phase 0 stands as a real requirement, not something the trust model already absorbs.**

The model and the code disagree here, and that gap *is* the finding: 1-of-N honesty is implemented
for the close lane (`requestClose` → `InvalidFreezeNonce`) and is **not** implemented for the
partial-withdrawal lane.

**Corollary — a second, cheaper thing worth doing.** The gap has an independent fix that is much
smaller than §2: wire the existing era fence into the PW lane, so a single honest member's
`requestClose()` invalidates a pending partial withdrawal. That converts the control from N-of-N back
to 1-of-N and makes the code deliver the owner's stated model. It is **not a substitute for §2** —
it is a 24-hour watch-and-veto, so it depends on the honest member being online and correct, whereas
§2 makes the bad intent unconstructible in the first place. Do both. This is why decision **D3 is
upgraded from "defer" to Phase 0** (§7).

### 1.13 Recorded, not acted on: `token_index` is not range-checked on the withdrawal path

`TransferTarget::new` allocates `token_index` as a bare virtual target with no range check
(`src/common/transfer.rs:149`), and the withdrawal circuit copies it straight into the leaf
(`single_withdrawal_circuit.rs:527`). `WithdrawalTarget::new` *does* `range_check(token_index, 32)`
(`src/common/withdrawal.rs:132-135`) — but it is not the constructor the withdrawal circuit uses.

Believed fail-closed rather than exploitable: a `token_index ≥ 2^32` would make the Rust keccak fold
(which packs each limb as 4 big-endian bytes) diverge from the Solidity `uint32` fold
(`IntmaxRollup.sol:1659-1664`), so `_verifyWithdrawalSet` would reject at the `pis_hash` comparison.
Flagged because the argument is indirect, and because a burn's `token_index` also enters the §2
descriptor and the IMPW digest. **Confirm during the P4-6 adversarial review; do not assume.**

---

## 2. Phase 0 — what must be true before any payout path is safe

**Stated as plainly as the brief asked: F-AUX-1 must be closed before `cmd_partial_withdraw` is
written. It is not acceptable to build the CLI first "and fix the binding later".** A working
`cmd_partial_withdraw` on today's binding is a one-member intra-channel theft primitive (§1.1, §0.3),
which is the same *class* of defect as the one `42640f1` deleted, just with a proof stapled to it and
a smaller blast radius. Building it first would be exactly the "working-but-unsound payout" that
threat model refused.

### 2.1 The three candidate fixes

Common idea: make the value that both layers fold commit the plaintext economics, instead of only the
Regev ciphertext digests. Today, for a burn:

```
burn aux_data = tx_leaf = H( H(IMTL, sender_pk_g, sender_delta_digest),
                             H(IMTL, receiver_pk_g, receiver_delta_digest) )   // src/common/balance_state.rs:873-895
```

Proposed, **for burns only** (normal inter-channel sends keep `aux_data = 0`, which
`src/wallet_core.rs:2094-2100` already guarantees and which the receive side depends on):

```
burn aux_data = keccak( IMBD_domain ‖ tx_leaf ‖ recipient(32) ‖ tokenIndex(4) ‖ amount(32) )
```

where `recipient`, `tokenIndex`, `amount` are **the burn's own base `Transfer` fields**. There is no
circularity: `aux_data` is a sibling field of those three inside the same leaf, not a hash of itself.

| | Where the equality is enforced | Circuit change | VK change | Fixture regen |
|---|---|---|---|---|
| **A. In `send_tx_circuit`** | in-circuit, on every burn send | `send_tx_circuit.rs` | **balance VK → validity VK → close VK → withdrawal VK** | **everything** |
| **B. In `single_withdrawal_circuit`** | in-circuit, at withdrawal time | `single_withdrawal_circuit.rs` | withdrawal VK only | all withdrawal payout fixtures + on-chain withdrawal VK |
| **C. In the Manager (Solidity) + native co-sign check** | on-chain, at intent time | **none** | **none** | new burn fixture only |

### 2.2 Recommendation: **C**, with B as a defence-in-depth follow-up

**Why C is sufficient.** The argument is a closed loop and uses only components that already exist:

1. The co-signed close proof pins `finalSettledTxChain` (close PI limbs 69..76,
   `ChannelSettlementVerifier.sol:511`, strict-bound at `:276`/`:290-297`).
2. The manager already forces `keccak(IMTC, prevSettledTxChain, auxData) == finalSettledTxChain`
   (`ChannelSettlementManager.sol:1143-1146`). Given the co-signed chain, `auxData` is pinned to one
   value.
3. **New:** the manager additionally recomputes
   `auxData == keccak(IMBD, txLeaf, withdrawal.recipient, withdrawal.tokenIndex, withdrawal.amount)`
   with `txLeaf` supplied by the caller. By keccak collision resistance, the pinned `auxData`
   determines `(recipient, tokenIndex, amount)` uniquely. The caller cannot vary the amount.
4. The IMPW `authDigest` binds all five leaf fields (`IntmaxRollup.sol:1596-1607`), and
   `withdrawNative` requires the flag for the **proven** leaf (`:1512-1516`). So the proven leaf's
   amount and recipient must equal the intent's, which equal the co-signed ones. ∎

**Why C needs no circuit change.** No circuit constrains `aux_data`'s *formula* — that is precisely
what F-AUX-1 records (`doc/audit/zkp/Zkp/Circuits/Balance/SendTxCircuit.lean:110-119`,
`doc/audit/audit28-06-2026.md:342`). Both layers fold whatever 32 bytes the transfer carries:
base at `send_tx_circuit.rs:290-297`, channel at `src/wallet_core.rs:2168`. Changing the *value*
is a witness change, not a constraint change. **No VK moves.** This is the whole payoff of §0.2.

**What C leaves native.** The co-signers must still check that the `amount` inside the descriptor
equals the E-2 debit. That check is a plain integer comparison against a value the E-2 statement
already carries as a public input (`prove_channel_update(..., amount, token_index)`,
`src/wallet_core.rs:2066-2077`), performed inside `verify_inter_channel_send_transition` /
`cmd_cosign_burn_send` — which **already** does the per-token conservation check `after + amount ==
before` at the burn slot (`src/bin/channel_member.rs:4693-4718`). Adding "and the descriptor's
declared amount is that same `amount`" is a few lines in the same function. After that the residual
is N-of-N collusion (§1.8), i.e. parity with close.

**Why B is worth doing eventually but is not Phase 0.** B would make the equality unforgeable even by
N-of-N, by constraining in-circuit that a nonzero `aux_data` is the keccak of the leaf's own fields.
It costs a withdrawal-VK rotation. It is the right *eventual* state and should be scheduled, but it
is not required to make the payout safe, and Phase 0 should not carry a VK rotation.

**Why A is the wrong shape.** Constraining it in `send_tx_circuit` moves the balance VK, which
cascades into the validity VK, the close VK (which recursively verifies a balance proof,
`close_circuit.rs:721-730`) and the withdrawal VK — i.e. every fixture and every on-chain VK constant
in the repo. Same security as B for strictly more blast radius. Reject.

### 2.3 Phase 0 acceptance criteria (falsifiable)

- [x] **P0-1.** ~~§1.11 answered in writing by the owner and recorded in this file.~~ **DONE
      (2026-08-13).** Answer: the delegate account is the only party that can move base funds without
      channel consent; the model is 1-of-N honesty. Recorded at §1.11. It does **not** discharge
      F-AUX-1 (§1.12), so the phase proceeds unchanged in substance and gains **P0-9**.
- [ ] **P0-2.** An adversarial subagent review (separate from any implementer, per CLAUDE.md) of the
      §2.2 loop, specifically: is `finalSettledTxChain` genuinely pinned for a *mid-channel* state, or
      can a prover choose a different `prevSettledTxChain`/`auxData` pair for the same chain value?
      (The fold is `keccak(IMTC, prev, aux)`; two preimages hitting one output is a collision, but the
      *choice of which link in the chain* to point at is caller-controlled and needs explicit
      analysis.)
      **Implementer adversarial pass (2026-08-19; not the required independent sign-off):** the
      close circuit connects the same `finalSettledTxChain` target to (a) the recomputed, member-
      signed H1 and (b) the recursively verified balance proof's `settled_tx_chain`. The Manager
      then requires `keccak(IMTC, prevSettledTxChain, withdrawal.auxData)` to equal that target. A
      caller may choose which historical link to *claim*, but for any choice other than the actual
      predecessor it must find a second preimage (or collision) for Keccak; there is no unconstrained
      selector or alternative chain input in the close proof. The additional IMBD equality then
      binds the accepted `auxData` to `txLeaf/recipient/token/amount`. No forgery was found. This
      paragraph deliberately does not check P0-2: a separate reviewer must reproduce the result.
- [x] **P0-3.** Decision D1 (§7) taken: descriptor layout frozen, domain tag allocated and checked
      against every existing 4-byte tag in the repo for collisions (`IMTL 0x494d544c`,
      `IMTC 0x494d5443`, `IMPW 0x494d5057`, `IMTF`, `IMCH`, `IMCI`, `IMSB`, `IMBS`, …).
- [x] **P0-4.** A negative test exists and **fails on the pre-fix code**: given an honest co-signed burn of
      `X`, a base leaf of `Y > X` with the same `auxData` is accepted end to end. This is the
      regression this whole phase exists to prevent; if it cannot be made to fail today, the threat
      model is wrong and must be revised before proceeding.

---

## 3. The design

### 3.1 End-to-end sequence (post-Phase-0)

```
  member                     co-signers                 L1 manager              L1 rollup
    │
 1  ├─ build_burn_send_token(l1_addr, token, X) ────────────────────────────────────────────
    │    base Transfer{recipient=ADDR_TAG(l1_addr), token, amount=X, aux_data=BURN_DESC}
    │    channel: enc_balance -= X, channel_fund[slot] -= X,
    │             settled_tx_chain ⊕= BURN_DESC, h2_tag = H2, close_freeze_nonce carried
 2  ├─────────────────► cosign-burn-send ──┐
    │                   • conservation X    │  N-of-N Falcon over IMCH (covers H2 AND the chain)
    │                   • NEW: BURN_DESC == keccak(IMBD, tx_leaf, recip, token, X)
    │                   • NEW: X == E-2 public amount
    │                   └─ writes last_burn.json (+ nullifier, + descriptor preimage)
    │
 3  ├─ cmd_partial_withdraw  ── proves the base leg ───────────────────────────────────────
    │    spend → send_tx → single_withdrawal → withdrawal_chain → wrapper → MLE/WHIR
    │    emits pw_withdrawal_payout.json (leaf from the PROOF) + pw_withdrawal_mle.json
    │
 4  ├─ close prover (REAL) ──► submitPartialWithdrawalIntent(intent, realProof, prev, w)
    │                            • _checkCloseProof (real VK)
    │                            • chain: keccak(IMTC, prev, w.auxData) == finalSettledTxChain
    │                            • NEW: w.auxData == keccak(IMBD, txLeaf, w.recipient,
    │                                                        w.tokenIndex, w.amount)
    │                            • cap + isMemberRecipient (containment, unchanged)
    │                            • chainKey single-use
 5  ├─ wait challengePeriod ──► finalizePartialWithdrawal() ──► authorizePartialWithdrawal(d)
    │                                                                    │
 6  ├─ withdrawNative(ws, prover, mleProof) / withdrawERC20(...) ────────┤
    │    • _verifyWithdrawalSet: real WHIR + finalizedStateRoots anchor + keccak re-fold
    │    • auxData != 0 ⇒ partialWithdrawalAuthorized[authDigest(w)]  ← the second factor
    │    • nullifier single-use; totalEscrowed -= amount
    │    • pendingWithdrawals[recipient] += amount
 7  └─ withdraw() ─ member pulls their own ETH (msg.sender only, IntmaxRollup.sol:1385-1391)
```

Steps 1, 2, 5, 6, 7 exist. Step 3 is the new command. Step 4 exists but must be de-mocked (§0.5) and
gains one check.

### 3.2 What `cmd_partial_withdraw` builds, and where each input comes from

It is **not** a copy of `cmd_withdraw`. `cmd_withdraw`
(`src/bin/channel_member.rs:2585-3057`) drives `build_channel_withdrawal`
(`src/wallet_core.rs:4327`), which **synthesises a whole channel from scratch** — its own
registration block, its own deposit, its own withdrawal tx, with a fixed RNG seed
(`:4398-4399`) and `aux_data: Bytes32::default()` (`:4585`). That is a fixture generator wearing a
CLI's clothes. `cmd_partial_withdraw` must instead prove against the channel's **live** base history.

| Witness input | Source | Cite |
|---|---|---|
| base `Transfer` (recipient, token, amount, aux_data) | the burn artefact, **not** recomputed | written by `cmd_cosign_burn_send`, `src/bin/channel_member.rs:4728-4740`; constructed at `src/wallet_core.rs:2101-2108` |
| `transfer_index` | constant `0` | asserted in-circuit, `src/circuits/balance/send_tx_circuit.rs:279` |
| `tx.nonce` | `prev.small_block_number + 1` | `src/wallet_core.rs:2110-2115`; forced `== tx_v2.nonce` at `single_withdrawal_circuit.rs:508` |
| `transfer_tree_root` / `tx_v2` / merkle proof | recomputed from the burn's single-transfer tree | `src/wallet_core.rs:2101-2120` |
| prior balance proof (IVC head) | the channel's persisted base balance proof | must be persisted — see §3.4 |
| `update_public_state` / block inclusion | the block that settled the burn tx | via the block-hash-chain / validity path |
| `nullifier` | `SettledTransfer::nullifier()` over the above | `src/common/transfer.rs:124-126` |
| `withdrawal_prover`, chain fold | as `cmd_withdraw`'s payout artefact | `src/wallet_core.rs:4897-4914` |

Output artefacts, mirroring the existing payout schema (`src/wallet_core.rs:4233-4304`) so the
existing forge step can consume them: `pw_withdrawal_payout.json` (leaf read **out of the proof's
public inputs**, exactly as `:5013-5025` does) and `pw_withdrawal_mle.json`.

On-chain leg: reuse the `withdrawNativeStep()` / `withdrawErc20Step()` shape at
`src/bin/channel_member.rs:2975-3027`, then **stop** — no `pullChannelFunds`, no manager
involvement. The member pulls with `withdraw()` (`IntmaxRollup.sol:1385-1391`).

### 3.3 Circuit reuse — **no new circuit, no new PI layout, no VK rotation**

Say it loudly because the brief asked: **under recommendation C, nothing about the proving stack
changes.**

- `single_withdrawal_circuit` already carries `aux_data` end to end
  (`:389`, `:531`) and already computes the correct nullifier (`:518-525`). It was built for this.
  Its PI vector stays `SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN = 45`
  (`= public_state(15) ‖ withdrawal(30)`, `single_withdrawal_circuit.rs:53`, registered at `:621`).
- `withdrawal_chain_circuit` / `withdrawal_step` fold whatever leaves they are given
  (`IntmaxRollup.sol:1662-1666` mirrors the Rust fold at `src/common/withdrawal.rs:97-100`). Step and
  chain PIs stay `WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN = 23` plus the cyclic verifier-data tail
  (`withdrawal_step.rs:43`, `withdrawal_chain_circuit.rs:59-63`, `:90`). Chain seed stays
  `Bytes32::default()` (`withdrawal_step.rs:376-386`).
- The on-chain withdrawal PI layout stays 17 limbs: `pis_hash(8) ‖ ext_commitment(8) ‖ block_number(1)`
  (`IntmaxRollup.sol:1625-1631`; producer `src/circuits/withdraw/withdrawal_circuit.rs:206-208`, with
  the 23-limb keccak preimage at `:58-68` and `remove_3bits` at `:203-205`). Unchanged.
- The close PI layout stays 103 limbs (`ChannelSettlementVerifier.sol:65`, table at `:456-479`).
  Unchanged.

**If the owner picks B instead of C in §7/D2, that changes: `single_withdrawal_circuit` gains a
constraint ⇒ the withdrawal VK rotates ⇒ `withdrawal_payout.json` + `withdrawal_mle.json` +
`close_withdrawal_*` + `c2c_withdrawal_*` + `sepolia_withdrawal_*` all regenerate (minutes of proving
each, per `doc/tasks/regen-and-redeploy-runbook.md:72`) and the on-chain withdrawal VK constant must
be redeployed.** That is a USER ACTION under CLAUDE.md §"No Unauthorized Heavy Computation".

### 3.4 Two structural prerequisites the current tree does not satisfy

**(i) There is no persisted live base-layer balance proof for a channel.** Every base proof in the
repo is produced by `build_channel_withdrawal`, which regenerates the channel's entire base history
from a seed. A live `cmd_partial_withdraw` needs the channel's *actual* IVC head, plus the block that
settled the burn tx. Whether that head exists on disk (alongside `channel_backing.json`,
`src/bin/channel_member.rs:131`) or must be re-derived is **decision D4 (§7)** and is, realistically,
the largest engineering item in this plan — larger than the security fix.

**(ii) The base send nonce and the channel `small_block_number` must stay in lockstep.** §0.4. If
they diverge the burn is unprovable and the value strands. Detect at burn time.

---

## 4. What must NOT change — and how this design respects it

| Invariant | Site | Respected because |
|---|---|---|
| Withdrawal PI layout (17 limbs) | `IntmaxRollup.sol:1625-1631` | untouched under C |
| Close PI layout (103 limbs) | `ChannelSettlementVerifier.sol:65`, `:456-479` | untouched; the new manager check reads `withdrawal.*`, not PI limbs |
| Leaf fold preimage (152 bytes) | `IntmaxRollup.sol:1659-1666` | untouched; only the *value* of `auxData` changes |
| IMPW digest preimage (124 bytes, tag `0x494d5057`) | `IntmaxRollup.sol:1596-1607` = `src/wallet_core.rs:2398-2413` | untouched — the cross-boundary parity assertion in `tests/partial_withdrawal_e2e.rs:521-524` must stay green |
| IMTC chain push (tag `0x494d5443`) | `ChannelSettlementManager.sol:1143-1146` | untouched; the new check is *additional*, applied to the same `auxData` |
| Balance / validity / close / withdrawal VKs | all fixtures | untouched under C |
| The payout predicate is `provenLeaf ∧ authorized` — never a disjunction | `IntmaxRollup.sol:1512-1516`, `:1560-1564`; argument at `doc/tasks/pw-auth-threat-model.md:118-126` | this design **adds** a conjunct at the manager; it never adds a payout path. Strictly monotone-decreasing in permissiveness. |
| The flag may veto, never supply, a field | `IntmaxRollup.sol:1500-1511` | unchanged; §2.2 makes the *minting* of the flag derive the fields, which is the property that was missing |
| Nullifier single-use across both lanes | `IntmaxRollup.sol:1494`/`:1518`, `:1554`/`:1566` | unchanged; no new consumer added |
| Chain-key single-use | `ChannelSettlementManager.sol:1204-1205`, `:1250` | unchanged |
| Fail-closed reverts | `PartialWithdrawalNotAuthorized`, `WithdrawalPublicInputsMismatch`, `TokenRegistryMismatch`, `PartialWithdrawalRecipientNotParticipant`, `PartialWithdrawalAmountExceedsFund` | all retained; one new revert added, none removed |
| **A PW cannot pay more than the channel's own escrow** | see below | see below |

### 4.1 The last invariant, checked honestly

The invariant as written — *"a partial withdrawal cannot pay more than the channel's own escrow"* —
**is not enforced on-chain and cannot be, because on-chain escrow is not per-channel** (§0.3;
`IntmaxRollup.sol:528`, `:545`, `:1476-1478`). What actually holds, and what this design preserves,
is the weaker-sounding but real statement:

> A partial withdrawal cannot pay more than the channel's **base-layer asset-tree balance** for that
> token, because the spend circuit's debit is a no-underflow subtraction
> (`spend_circuit.rs:372` → `u256.rs:319-320`) against a tree anchored to a finalized state root
> (`IntmaxRollup.sol:1637-1638`); and, after §2, it cannot pay more than the **co-signed channel-layer
> debit**, because the intent's amount is derived from the co-signed `auxData`.

Both bounds hold post-design. The second is the one §2 adds. Neither is an on-chain per-channel
segregation, and no part of this plan should be described as providing one.

---

## 5. Phased plan

Each phase is gated on the previous one. Acceptance criteria are falsifiable; "heavy" marks phases
that require proving and are therefore USER ACTIONS.

### Phase 0 — close F-AUX-1's amount binding *(no payout code written)*

See §2.3 for P0-1..P0-4, plus:

- [x] **P0-5.** `burn_aux` becomes the descriptor in `src/wallet_core.rs:2094-2100`, and identically
      in `src/wasm_wallet.rs:596` and anywhere the browser/node stack recomputes it. **Falsifiable:**
      a cross-language parity test asserts Rust and JS produce the same 32 bytes for the same burn.
- [x] **P0-6.** `submitPartialWithdrawalIntent` gains the recompute check and a new revert
      (`PartialWithdrawalDescriptorMismatch`). **Falsifiable:** (a) a Foundry test where the intent's
      `amount` is tampered by ±1 reverts with the new error; (b) the honest tuple still passes;
      (c) `forge test` total ≥ current baseline with 0 failures.
- [x] **P0-7.** The co-sign path checks the descriptor against the E-2 public amount
      (`src/bin/channel_member.rs:4693-4718` neighbourhood). **Falsifiable:** a Rust test where the
      descriptor declares `X+1` while E-2 proves `X` is rejected at co-sign, with a named error.
- [x] **P0-8.** The Lean model records the new conjunct, or explicitly records it as unmodelled.
      `cd doc/audit/zkp && lake build` clean, zero `sorry`.
- [x] ⚠ **Fixture impact:** no circuit/VK regeneration was required by C itself. `forge test` is
      green with the existing VKs; the separate Manager-address fixture refresh below was required.
- [x] **P0-9 (NEW — makes 1-of-N honesty real for this lane, §1.12).** Wire the era fence into the PW
      lane so one honest member's `requestClose()` invalidates a pending partial withdrawal.
      **Correction found during implementation (2026-08-19):** the close circuit exposes
      `signedState.close_freeze_nonce + 1` (`close_circuit.rs`,
      `incremented_close_freeze_nonce`), so an Active-era PW must require
      `intent.closeFreezeNonce == currentCloseFreezeNonce + 1`, then persist the manager's current
      era separately. The former equality written here would brick every real genesis-era proof
      (`1 != 0`) and only worked with the mocked zero PI. `finalizePartialWithdrawal`
      re-checks that the era has not moved since submission. The 12B comment at `:1245-1248` is
      rewritten to state its real premise — that it was sound *because* the burned amount equalled
      the payout, which is what §2 now enforces — rather than being silently deleted.
      **Falsifiable:** (a) a Foundry test where `requestClose()` is called during the challenge
      window makes `finalizePartialWithdrawal()` revert; (b) an undisturbed PW still finalizes;
      (c) an intent proved against a stale era is rejected at submit.
      **Depends on P1-1** — the CLI must stop hardcoding `close_freeze_nonce = 0`
      (`src/bin/channel_member.rs:6313`) or this fence bricks every PW. Land P1-1 first or together;
      **never P0-9 alone.**
      ⚠ *Liveness trade-off, must be stated in the commit:* this makes a `requestClose` — by any
      member, honest or not — cancel in-flight partial withdrawals. That is the intended veto, and it
      is also a grief vector (a malicious member can repeatedly freeze). The grief is bounded: the
      burner may re-burn and re-submit, and `requestClose` reverts once the channel is already
      frozen (`:899-900`). Accepted as the price of a 1-of-N veto; recorded rather than engineered
      around.
- [x] ⚠ **Manager bytecode changes ⇒ CREATE2 address changes ⇒
      `CloseLifecycleE2E.t.sol::test_closeLifecycle_endToEnd` fails on the baked recipient.** This is
      the known, documented consequence of *any* manager edit
      (`doc/tasks/a3-p5-plus-plan.md:42`; procedure at `doc/tasks/pw-auth-threat-model.md:486-510`).
      **HEAVY — one fixture set (`close_withdrawal_payout.json` + `close_withdrawal_mle.json`), USER
      ACTION.** **DONE 2026-08-19:** regenerated against manager
      `0xE3024F77093f481Ce393c9251f898B00a89B5613`; full guarded Foundry suite is green.

### Phase 1 — de-mock the submit path

- [x] **P1-1.** `cmd_pw_submit` sources `close_nonce`, `close_freeze_nonce`, `burn_tx_hash`,
      `close_withdrawal_digest`, `snapshot_medium_block_number` from a **real** close proof's PIs
      instead of the literals at `src/bin/channel_member.rs:6310`, `:6313`, `:6318-6320`.
      **Falsifiable:** grep for hardcoded `0u64`/`1u64` in the PW intent builder returns nothing.
- [x] **P1-2.** `SubmitPartialWithdrawal.s.sol` stops synthesising `publicInputs` from
      `expectedCloseLimbs` (`:81-84`) and consumes a real proof file.
- [x] **P1-3.** `DeployPartialWithdrawalE2E.s.sol` and `DeployWalletSettlement.s.sol` gain
      `require(block.chainid == 31337)`, matching the five scripts that already have it
      (`doc/tasks/pw-auth-threat-model.md:433-440`). **Falsifiable:** a `DeployGuards.t.sol` case
      asserts the revert.
- [x] ⚠ **HEAVY** — a real close proof for the mid-burn state is generated and consumed by the E2E.

### Phase 2 — fix the nullifier and the intent's provenance *(closes T10)*

- [x] **P2-1.** `cmd_pw_submit` derives the nullifier via `SettledTransfer::nullifier()` from the
      burn artefact. The keccak at `src/bin/channel_member.rs:6282-6288` is **deleted**, not kept
      alongside. **Falsifiable:** a unit test asserts the CLI's nullifier equals the one the
      `single_withdrawal` circuit commits for the same burn.
- [x] **P2-2.** `withdrawal_recipient` and `withdrawal_amount` come from `last_burn.json`, never from
      `PW_RECIPIENT` or the request body. `PW_RECIPIENT`, if kept, becomes an *assertion* input:
      mismatch ⇒ die before touching the chain. **Falsifiable:** setting `PW_RECIPIENT` to a
      different member's address aborts locally with a named error and sends no transaction.
- [x] **P2-3.** `tests/partial_withdrawal_e2e.rs:452-458` stops using the literal `0xBEEF`.
- [x] **P2-4.** A burn-time guard rejects a burn whose `nonce` slot is already occupied in the base
      account's sent-tx tree (§3.4(ii)), with a message naming the divergence.

### Phase 3 — `cmd_partial_withdraw` *(the payout leg)*

- [ ] **P3-1.** Decision D4 (§7) taken on base-state persistence.
- [ ] **P3-2.** The command proves against the **live** base history — explicitly **not** by calling
      `build_channel_withdrawal`. **Falsifiable:** the new code path contains no call to it, and a
      test proves two consecutive partial withdrawals from the same channel (the second must build on
      the first's post-state; a from-scratch generator cannot).
- [ ] **P3-3.** Every field of the emitted `pw_withdrawal_payout.json` is read out of the proof's
      public inputs, never recomputed (the pattern at `src/wallet_core.rs:4897-4914`, `:5013-5025`).
      **Falsifiable:** mutating any leaf field in the JSON makes `withdrawNative` revert
      `WithdrawalPublicInputsMismatch`.
- [ ] **P3-4.** `cmd_pw_finalize`'s fail-closed tail (`src/bin/channel_member.rs:6502-6543`) is
      replaced by the real payout call **only after** P3-3 is green — and the marker string
      `'STOPPING BEFORE PAYOUT'` that `api/routes/partial-withdrawal.js:14` matches on is removed in
      the same commit as the route's 501 branch, never separately.
- [ ] ⚠ **HEAVY** — this phase produces the repo's **first fixture with `aux_data != 0`**. Every
      existing payout fixture is a non-burn leaf (verified: `withdrawal_payout.json`,
      `close_withdrawal_payout.json`, `c2c_withdrawal_payout.json`, `sepolia_withdrawal_payout.json`
      all carry `"aux_data": "0x00…00"`). This closes the honest coverage gap recorded at
      `doc/tasks/pw-auth-threat-model.md:381-396` and
      `contracts/test/PartialWithdrawalPayout.t.sol:191-197`.

### Phase 4 — adversarial coverage

**DONE 2026-08-22 (P4-1, P4-3, P4-4, P4-5, and the replay half of P4-2).** The prerequisite this
phase always named — "the repo's **first** fixture with `aux_data != 0`" (the Phase 3 HEAVY note) —
now exists and is committed: `src/bin/generate_burn_withdrawal_fixture.rs` proves a real 3-block
lifecycle whose withdrawal leaf carries a nonzero burn descriptor (`build_channel_withdrawal`'s new
`burn_aux_data` mode), emitting `contracts/test/data/burn_{lifecycle,lifecycle_validity_mle,
withdrawal_mle,withdrawal_payout}.json`. The new suite `contracts/test/PartialWithdrawalBurnPayout.t.sol`
runs the shared real-fixture lifecycle harness against that set (a `_fixturePrefix()` override on
`WithdrawNativeE2EBase`). All 8 cases pass on the CI foundry pin (v1.5.1).

- [x] **P4-1.** P0-4's negative test now **passes** (the `Y > X` leaf is rejected), and is kept.
      `test_burnLeaf_amountAboveBurn_rejected` authorizes the tampered `(Y = X+1)` digest so the ONLY
      thing that can stop the payout is the proof binding, and asserts `WithdrawalPublicInputsMismatch`.
      `testFuzz_onlyExactCosignedPair_payable` generalizes it over random amounts.
- [~] **P4-2.** Replay half **DONE** (`test_provenBurnLeaf_nullifierSingleUse`: the paid burn leaf's
      nullifier is single-use across every remaining path). The full cross-lane conservation
      (burn lane + close lane summing to the channel's deposits) additionally needs the close path
      driven against the SAME channel and is left to the close-side suites / the full anvil rehearsal;
      recorded here rather than claimed.
- [x] **P4-3.** A burn leaf without an authorization reverts `PartialWithdrawalNotAuthorized` — and now
      for the *right* reason: `test_provenBurnLeaf_withoutAuthorization_reverts` uses a REAL `aux != 0`
      proof, so `_verifyWithdrawalSet` PASSES and the revert comes from the IMPW flag check itself, not
      the proof binding. This is the branch `PartialWithdrawalPayout.t.sol:198-210` could never reach.
- [x] **P4-4.** A burn leaf cannot be relabelled (`test_provenBurnLeaf_cannotBeRelabelled`: `aux -> 0`
      to dodge the flag, and `aux -> other descriptor`, both rejected on the pis re-fold even WITH an
      authorization for the relabelled digest). The `auxData == 0` normal-leaf-still-pays half is the
      existing `PartialWithdrawalPayout.t.sol::test_provenNonBurnLeaf_stillPays`; the positive burn
      half (a legitimate burn IS payable) is `test_provenBurnLeaf_paysWithAuthorization` — the repo's
      first on-chain `aux != 0` payout.
- [x] **P4-5.** Property test: `testFuzz_onlyExactCosignedPair_payable` — random `(amount, recipient)`
      substitutions on the proved leaf, each authorized, all rejected on the pis re-fold; only the
      exact proved pair (the control test) is payable.
- [ ] **P4-6.** Dedicated attacker-subagent review of the whole path, separate from whoever
      implemented it (CLAUDE.md §Adversarial Thinking). Output reviewed before merge. **Still open —
      the implementer cannot discharge this.**

> **Still open beyond P4-6: the full live anvil rehearsal.** These tests exercise the payout-side
> soundness against a real proof, but through a *committed fixture*, not the resident daemon. The L1
> broadcast driver (`run_partial_withdrawal_payout` + `RunPartialWithdrawalPayout.s.sol` +
> `LiveBalanceService::burn_payout_artifacts`) has still not run against a live chain in CI. That
> rehearsal — deploy, drive the daemon validity loop to a finalized state root, burn, pay out, pull —
> remains the immediate next step, and its groundwork (the burn fixture, `burn_aux_data`, the
> `_fixturePrefix()` seam) is now in place.

### Phase 5 — documentation and the era question

- [ ] **P5-1.** Fix the three stale doc claims in §0.1, plus the stale
      `latestFinalizedStateRoot` docblock (`IntmaxRollup.sol:1472`) and the stale line cites found
      while reading: `ChannelSettlementManager.sol:1194-1196` → real `isMemberRecipient` writes are
      `:800`/`:858`; `ChannelSettlementManager.sol:1170` → the real `tokenCount` check is
      `ChannelSettlementVerifier.sol:430`; the F-WD-2 comment at
      `single_withdrawal_circuit.rs:513-517` cites `:433`/`:501` where the constraints are `:436`/`:508`.
- [ ] **P5-2.** Decision D3 (§7) on the PW era fence, written up **as its own threat model**. Not in
      this plan's scope to implement.
- [ ] **P5-3.** `node/cosigner/branches/close.js:22-39` stops treating a fail-closed exit as
      `PW_FINALIZE_FAILED` — or, post-Phase-3, the fail-closed state no longer exists and the branch
      is simplified.

---

## 6. What this does **not** solve

Stated plainly, per the brief.

1. **It does not make the amount equality unconditional.** Under recommendation C the equality
   `base Transfer.amount == channel-layer debit` becomes enforceable by any single honest co-signer
   and unforgeable by fewer than N. **It remains false under N-of-N collusion.** Making it
   unconditional needs option B (a withdrawal-VK rotation) for the leaf-side half, and — for the
   *encrypted* half, `descriptor.amount == the Regev-proven E-2 debit` — recursive verification of
   the E-2 proof inside the base circuit, which is a different and much larger project. **F-AUX-1 is
   downgraded, not deleted.**
2. **It does not give per-channel escrow.** §4.1. The global `totalEscrowed` remains the only
   on-chain ETH ceiling; cross-channel safety continues to rest entirely on base-layer proof
   soundness.
3. **It does not enable A45 (PW cancel).** It removes the blocker (`close_freeze_nonce = 0`) that
   makes A45 impossible, nothing more. Until A45 lands, **a submitted PW intent cannot be cancelled**
   — the challenge window has no challenger for this lane (§1.6).
4. **It does not fix the chain-key grief.** A bad `pw-submit` still permanently consumes
   `(channelId, finalSettledTxChain)` (§0.4). Phase 2 removes the *known* ways to get it wrong; it
   does not make the operation retryable.
5. **It does not make 1-of-N honesty sufficient for this lane — it makes it *available*.** P0-9 gives
   one honest member a unilateral veto over a pending partial withdrawal, but that veto is a
   watch-and-act control: it requires the honest member to be online within the ≥24 h window, to be
   running a watcher that compares the submitted amount against the co-signed one, and to send a
   transaction. If nobody watches, nothing stops it. **This is why P0-9 is not a substitute for §2**
   — §2 makes the bad intent unconstructible, which needs no one to be awake. Shipping only P0-9
   would be exactly the kind of "sound under an unenforced assumption" outcome this document exists
   to avoid.
6. **It does not analyse the delegate lane.** The owner's answer moves weight onto it (§7/D5); its
   bounds are prior work (`doc/tasks/delegate-account-threat-model.md`), not re-derived here.
7. **It does not touch the always-true deploy verifiers** beyond adding chain guards (P1-3).
   `DeployWalletSettlement.s.sol`'s `WalletMockMleVerifier` is still installed for real close and
   cancel VKs on any chain the relay points it at
   (`doc/tasks/pw-auth-threat-model.md:419-440`) — a separate, arguably more urgent, diff.
8. **It does not re-audit the base layer.** The open items at `doc/tasks/todo.md:70-74`
   (per-tx evidence vs per-block evidence) and F-BLKR-1 are inherited unchanged.

---

## 7. Decisions the owner must take before implementation

**D1 — Burn descriptor layout.** Recommendation:
`keccak(bytes4 IMBD ‖ tx_leaf(32) ‖ recipient(32, the ADDRESS_TAG form as it sits in the leaf) ‖
tokenIndex(4) ‖ amount(32))`.
*Alternative:* include `channel_id` and `nonce` too, making the descriptor a superset of the
nullifier preimage. *Trade-off:* more binding for a longer preimage and a second place that must stay
in sync with `SettledTransfer::nullifier()`. **Recommend the shorter form** — `channel_id` and
`nonce` are already bound through the nullifier, which the IMPW digest carries.
*Privacy note (checked):* the descriptor exposes the burn amount in the settled-tx chain, which is a
close PI. This leaks **nothing new** — a burn's amount is already public in the L1 withdrawal leaf.
Normal inter-channel sends keep `aux_data = 0` and stay hidden. Confirm this reasoning holds for any
future non-burn use of a nonzero `aux_data`; if one is ever added, the §2.2 check must be gated on a
burn marker rather than on `auxData != 0`.

**D2 — C now, or C + B.** Recommendation: **C in Phase 0; schedule B as a separate, VK-rotating PR**
once a burn fixture exists (which Phase 3 produces, so B becomes much cheaper afterwards). Taking B
first means a VK rotation before there is anything to test it against.

**D3 — Era fence on the PW lane. ⬆ UPGRADED to Phase 0 (P0-9) after the owner's answer.** Options:
(i) leave as-is (proof-authenticated but unfenced), (ii) add
`intent.closeFreezeNonce == currentCloseFreezeNonce` plus a re-check at finalize, (iii) add it and
enable A45. **Recommendation is now (ii), in Phase 0** — reversing this document's first draft.
The reason is the owner's answer, not a change of taste: the stated model is 1-of-N honesty, the
only PW control that exists today (`cancelPartialWithdrawal`) requires **N-of-N** (§1.12 item 2), and
the era fence is the one mechanism that would give a single honest member a unilateral veto. Leaving
it out means the code does not implement the model it is documented to rely on.
(iii) stays out of scope: A45 is an N-of-N control and does not change the 1-of-N picture.
The liveness cost is real and is recorded in P0-9 rather than discounted.

**D4 — Live base-state persistence (§3.4(i)).** Options: (a) persist the channel's base IVC head +
block references alongside `channel_backing.json`; (b) re-derive from an indexer/relay each time;
(c) keep the from-scratch generator and accept that a channel supports exactly one lifetime
withdrawal. **(c) is not viable for a mid-channel feature.** Recommendation: **(a)**, and note this
is likely the largest engineering item in the plan — it is infrastructure, not cryptography, and it
should be scoped separately before Phase 3 is estimated.

**D5 — §1.11. ✅ ANSWERED 2026-08-13.** The delegate account is the only party that can move base
funds without channel consent; the model is 1-of-N honesty. Phase 0 no longer blocks on it.
**One follow-up the answer creates, for the owner to note rather than decide:** the model now rests
on the delegate lane's own bounds, which this document did not analyse. `doc/tasks/delegate-account-threat-model.md`
(DLG-1/2, DA1..DA6) and B-1c are the relevant prior work. If a delegate's base-layer reach is *not*
bounded to its own slot, the 1-of-N assumption is carrying more weight there than here. **Out of
scope for this design; flagged so it is not lost.**

---

## 8. Assessment

The brief asked whether the honest answer is *"this cannot be made safe without an in-circuit change
of scope X"*. It is **not** — and the reason is a fact that was not in the brief: the co-signers
already commit to the burn's base `Transfer` through `h2_tag` inside the IMCH signing digest
(`src/common/channel.rs:597`, `src/wallet_core.rs:2174`). F-AUX-1 is a **binding** defect, not a
missing commitment, so a Solidity-plus-native fix closes it with no circuit change and no VK
rotation. That is the good news, and it is the reason this plan can put the security fix *first*
rather than after the feature.

The bad news is threefold. **First**, the exploit is worse than "a co-signer assumption": one member
with *honest* co-signers can inflate the base amount, bounded only by the channel's whole base
balance — so `cmd_partial_withdraw` must not be written before Phase 0 lands. **Second**, the
submit path is currently mocked end to end (§0.5), so the "requires a valid close proof" precondition
in the existing threat model does not hold on the CLI path as shipped. **Third**, the largest
engineering item is not the cryptography at all: there is no persisted live base-layer state for a
channel (§3.4(i)), and a mid-channel withdrawal needs one.

**On the owner's answer (2026-08-13).** It resolves §1.11 favourably — the delegate lane is design
intent, and because members cannot reach base funds outside the consented burn lane, the IMPW flag is
a real chokepoint and §2 applies at exactly the right place. The answer *raises* this design's value.

But it does **not** absorb F-AUX-1, and the reason is structural rather than incidental. A 1-of-N
honesty assumption buys liveness — one honest party posts, challenges, or refuses. F-AUX-1 offers no
refusal point: the honest member signs an honest burn of `X`, and `Y` is chosen afterwards by a
unilateral, self-contained proof. The one control that could stop the resulting payout,
`cancelPartialWithdrawal`, needs a cancel-close proof that **every** active member signs
(`cancel_close_circuit.rs:168-175`, `:493-497`) — so the attacker vetoes his own prosecution. The
lever that *would* be unilateral, the `requestClose` era fence, exists and is wired to the close lane
(`ChannelSettlementManager.sol:932-934`) but deliberately not to this one, on a no-double-counting
rationale (`:1245-1248`) whose premise is precisely what F-AUX-1 breaks.

So: **1-of-N honesty is implemented for close and is not implemented for partial withdrawal, and that
gap is the finding.** Phase 0 stands as a real requirement. The answer adds one item to it (P0-9,
wiring the era fence) which makes the code deliver the stated model — but P0-9 is a 24-hour
watch-and-veto and §2 is a constructive impossibility, so P0-9 is an addition to §2, never a
replacement for it.

**Recorded, not fixed here:** the stranded-burn fund-loss in `cmd_pw_submit` today (§0.4) is live on
this branch and is independent of whether the payout ever ships. It deserves its own fix regardless
of what the owner decides about §7.
