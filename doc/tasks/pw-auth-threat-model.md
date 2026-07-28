# Threat model — partial-withdrawal authorization used as a *sole* payout factor

**Date:** 2026-07-28
**Branch:** `feat/multitoken-channels` (the flaw is PRE-EXISTING on `main` — see §0.4)
**Scope:** `IntmaxRollup.claimAuthorizedWithdrawal`, `ChannelSettlementManager.submitPartialWithdrawalIntent`,
and the Lean audit statements that describe them.
**Status:** written BEFORE the code change, per `CLAUDE.md` §"Default to Planning Mode" /
§"Security-Critical Mindset".

---

## 0. The finding

### 0.1 What the code does

`IntmaxRollup.claimAuthorizedWithdrawal(Withdrawal calldata w)` (`contracts/src/IntmaxRollup.sol:790-805`)
pays native ETH out of the **global** `totalEscrowed` after checking only:

1. `w.tokenIndex == ETH_TOKEN_INDEX`
2. `w.auxData != 0` (it is a burn leaf)
3. `!withdrawalNullifierUsed[w.nullifier]`
4. `partialWithdrawalAuthorized[_withdrawalAuthDigest(w)]`

It never calls `_verifyWithdrawalSet`. **Nothing in this path proves the withdrawal's economics** —
not that the amount was ever burned, not that the recipient is owed anything, not which channel the
escrow belongs to. It then pushes ETH directly (`w.recipient.call{value: w.amount}`), bypassing even
the pull-payment discipline the proof-backed paths use.

### 0.2 Where the authorization comes from

`ChannelSettlementManager.submitPartialWithdrawalIntent`
(`contracts/src/ChannelSettlementManager.sol:1039-1095`) mints the digest. It binds **only**
`withdrawal.auxData` to the cosigned state:

```solidity
bytes32 expectedChain = keccak256(
    abi.encodePacked(uint32(0x494d5443), prevSettledTxChain, withdrawal.auxData)
);
if (expectedChain != intent.finalSettledTxChain) revert PartialWithdrawalChainMismatch();
```

`withdrawal.amount`, `withdrawal.recipient` and `withdrawal.nullifier` are **caller-supplied and flow
untouched** into the IMPW digest at `:1070-1079`. No check reads them.

### 0.3 The exploit

An attacker who can produce **one** valid close proof for a channel **they legitimately own** (i.e. a
channel where they are an N-of-N cosigner — no key compromise, no rogue deployer, no protocol break)
calls `submitPartialWithdrawalIntent` with a truthful `intent`/`auxData` and a fabricated
`(amount, recipient, nullifier)`. After the challenge period, `finalizePartialWithdrawal` mints the
authorization on the rollup, and `claimAuthorizedWithdrawal` pays that arbitrary amount to that
arbitrary recipient out of the **global** ETH escrow — i.e. out of **every other channel's deposits**.
The only ceiling is `totalEscrowed` itself (Solidity-0.8 underflow).

This is materially worse than what the existing Lean audit records. `Assumptions.lean:56-64` frames
the burn-path risk as *"a malicious or key-compromised **deployer** registers an attacker contract as
a settlement manager"*. The real precondition is far weaker: **an honest deployer running the honest,
audited `ChannelSettlementManager` already mints digests for caller-chosen amounts and recipients.**
`BurnAuthorizationsLegitimate` is therefore not merely *assumed* — under its intended reading
("this digest was minted by a flow that establishes the economics") it is **false by construction**.

### 0.4 Provenance

Identical code is on `main` (`git show main:contracts/src/IntmaxRollup.sol:714-730`). Introduced
2026-06-26 (`7fdfd56`). Not introduced by the multi-token work.

### 0.5 The precise framing — a second factor promoted to a sole factor

`withdrawNative` (`:1494-1498`) and `withdrawERC20` (`:1540-1544`) use the **same** IMPW digest, but as
a **second factor layered on top of `_verifyWithdrawalSet`**:

| | economics come from | authorization contributes |
|---|---|---|
| `withdrawNative` / `withdrawERC20` | the verified withdrawal proof (chain re-fold → `pis_hash`, anchored to `latestFinalizedStateRoot`) | channel consent: "the channel agreed this burn may leave" |
| `claimAuthorizedWithdrawal` | **the authorization itself** | everything |

A forged authorization is **already inert against ERC-20 today**: with no matching proven leaf,
`withdrawERC20` never reaches the flag check in a way that pays. The asymmetry — that ETH additionally
has a proof-free door reading the same flag — is the entire bug.

### 0.6 Crux: nothing the Manager can read commits the economics

This is why the Manager cannot be *fixed* into soundness, only *bounded*:

- `auxData` is the tx_leaf,
  `keccak(keccak([IMTL, pk_g, sender_delta_digest]), keccak([IMTL, pk_g, receiver_delta_digest]))`,
  taken over **Regev ciphertext digests**. The amount is computationally hidden inside the ciphertext;
  the receiver wing carries the phantom padding key, not an L1 address.
- The 103-limb close public-input vector carries no burn amount and no burn recipient.
- The **only** artifact that jointly commits `(recipient, tokenIndex, amount, nullifier, auxData)` is
  the base-layer withdrawal-chain leaf — and that is exactly what `_verifyWithdrawalSet` verifies.

So the economics can only come from the base-layer proof. There is no Manager-side substitute.

---

## 1. Why deleting the proof-free path closes the hole completely

**The fix: remove `claimAuthorizedWithdrawal` entirely.** All PW payouts must go through
`withdrawNative` / `withdrawERC20`.

### 1.1 The composition argument

After deletion, every ETH and ERC-20 payout in the contract passes `_verifyWithdrawalSet`, which
enforces (`:1591-1680`):

1. `withdrawalVkInitialized` and a **real** MLE/WHIR verification of the wrapped `WithdrawalCircuit`
   proof under the withdrawal VK (`_verifyMleWithdrawal`) — no stub, no bypass;
2. the proof's `ext_public_state_commitment` (PI limbs 8..16) equals `latestFinalizedStateRoot` — the
   leaves are anchored to a state a validity proof already finalized;
3. an on-chain keccak **re-fold of the supplied `ws`** into `withdrawal_hash` → `pis_hash`
   (limbs 0..8). Every field of every leaf — `recipient`, `tokenIndex`, `amount`, `nullifier`,
   **and `auxData`** — enters that fold. A single tampered byte breaks the hash and reverts.

Therefore, on the remaining paths, `(recipient, tokenIndex, amount, nullifier, auxData)` is **not
caller-declared**: it is the proof's. The IMPW flag can only ever *veto* (`auxData != 0` requires it)
— it can never *supply* a field. Formally, for a burn leaf the payout predicate becomes

```
pays(w)  ⟺  provenLeaf(w)  ∧  authorized(authDigest(w))
```

whereas today it is `provenLeaf(w) ∧ authorized(...)`  **∨**  `authorized(...)`. Deleting the second
disjunct is what closes the hole; the conjunction is monotone-decreasing in permissiveness, so the
change can only ever reject more, never accept more.

### 1.2 A forged authorization becomes inert

A digest minted for a fabricated `(amount, recipient, nullifier)` has, by construction, no
corresponding leaf in any proven withdrawal chain (the prover only emits leaves for real transfers).
`_verifyWithdrawalSet` therefore rejects any `ws` containing it, at step 3, before any state is
touched. **The forged authorization becomes exactly as inert as it already is for ERC-20** — which is
the strongest available evidence that this composition holds, because that half of the system has
been live with the forgeable flag and has never been exploitable through it.

### 1.3 What is *not* claimed

Deleting `claimAuthorizedWithdrawal` does **not** make the PW feature sound; it makes it **absent**
(see §5). It removes an unsound payout, it does not add a sound one. That is deliberate — a correct
incomplete implementation beats an incorrect complete one.

---

## 2. Can deletion strand value on a live deployment?

**No. Evidence, not inference:**

1. **No `ChannelSettlementManager` has ever been deployed to a non-local chain.**
   `contracts/broadcast/` contains exactly one non-31337 chain directory: `Deploy.s.sol/11155111`.
   The only two scripts that deploy a manager and call `registerSettlementManager` —
   `DeployWalletSettlement.s.sol` and `DeployPartialWithdrawalE2E.s.sol` — have **no `11155111`
   directory at all**; all 8 recorded runs are chain 31337 (anvil).

2. **The live rollups do not contain the functions.** Both Sepolia deploys
   (`0x632d84C4798Ed7A4acF9DE3CfafA604216Ab6D33` = rollup#7,
   `0x601cbE31Be0b42A9b5Bb8da413e40607CbD69411` = rollup#8, both 2026-06-16, commit `0f30445`) predate
   the feature. At that commit,
   `grep 'registerSettlementManager|authorizePartialWithdrawal|claimAuthorizedWithdrawal|partialWithdrawalAuthorized'`
   over `contracts/src/IntmaxRollup.sol` returns **nothing**; the feature landed 2026-06-26 in
   `7fdfd56`, ten days later. Independently corroborated by an on-chain bytecode probe recorded at
   `doc/tasks/pw-settle-ec2-plan.md:119-125`: *`registerChannel` PRESENT,
   `registerSettlementManager`/`partialWithdrawalAuthorized`/`claimAuthorizedWithdrawal` MISSING*.

3. **They are immutable.** `grep 'delegatecall|UUPS|Initializable|Proxy|upgrade'` over
   `IntmaxRollup.sol` → zero matches; the same probe found EIP-1967 slot zero. They can never *gain*
   the functions.

4. **The only `settlement.json` in the tree** (`wallet-live-work/ch7/settlement.json`) points at
   canonical **anvil** addresses.

**Conclusion:** the set of authorized-but-unclaimed digests on any live chain is **empty**, and
necessarily so — no live rollup even has the `partialWithdrawalAuthorized` mapping. Deleting the
claim function cannot strand value. On local/anvil stacks the same reasoning applies trivially (they
are disposable, and re-created by the deploy scripts on every run).

---

## 3. One authorized `tx_leaf` still yields at most one payout

`withdrawNative` (`:1488`, `:1500`) and `withdrawERC20` (`:1536`, `:1546`) share the **single**
`withdrawalNullifierUsed` mapping, with check-then-set inside the same call (CEI, before any value
movement; both entry points are `nonReentrant`). Deleting `claimAuthorizedWithdrawal` **removes** a
consumer of that mapping — it cannot weaken single-use.

The token-class guards keep the two remaining paths disjoint: `withdrawNative` requires
`tokenIndex == 0` (`:1487`), `withdrawERC20` requires `tokenIndex != 0` (`:1534`). A given leaf is
payable by exactly one entry point, and once paid its nullifier is burned for both. Additionally, the
IMPW digest itself commits `tokenIndex`, so an ETH authorization can never authorize an ERC-20 payout.

Manager-side, `usedPartialWithdrawalChains[chainKey]` (`:1059`, consumed at `:1104`) already ensures a
given `(channelId, finalSettledTxChain)` mints **at most one** authorization ever. Unchanged.

**Net: strictly fewer payout paths, same nullifier set, same chain-key single-use. No double-payout
surface is created.**

---

## 4. Defence in depth in the Manager — what it does and does NOT prove

Because the proof-backed base half will eventually land (§5), the Manager should never mint an
authorization for an *absurd* claim, even though it can never mint one for a *justified* claim.

### 4.1 Check A — amount cap against the proof-bound per-token fund vector

Require `withdrawal.amount <= intent.channelFundAmounts[slot]`, where `slot` is resolved from
`withdrawal.tokenIndex` through `intent.tokenRegistry[0..tokenCount)`; **fail closed** (revert) if the
token is not in the registry.

*Why this vector is trustworthy:* `_checkCloseProof` → `_runCloseVerify` recomputes
`ChannelSettlementVerifier.tokenFundsDigest(tokenRegistry, tokenCount, channelFundAmounts)`
(`ChannelSettlementVerifier.sol:333-354`) and **strict-binds it to close PI limbs 95..102**. Those
limbs are part of the N-of-N member-signed close statement. So `(channelFundAmounts, tokenRegistry,
tokenCount)` are *member-signed, not caller-declared*. The verifier additionally rejects
`tokenCount ∉ 1..=10` at `:342`, so after `_checkCloseProof` the slot loop is well-formed and the
`uint32[10]` indexing cannot go out of range.

*What it proves:* the claim cannot exceed the funds the channel's own members cosigned into that
token slot. This converts "drain the global escrow" into "drain at most your own channel's declared
balance in that token".

*What it does NOT prove:* **nothing about the burn.** It does not show the amount was burned, that the
claimant is entitled to it, or that it is not being claimed twice across different close states. A
channel member can still claim their whole channel's fund vector for a burn worth one wei. **It bounds
the claim; it does not derive it.**

### 4.2 Check B — recipient must be a channel participant

Require `isMemberRecipient[withdrawal.recipient]`.

*Semantics confirmed:* `isMemberRecipient` (`:627`) is populated **only** in the constructor, at
`:715-720` for the N-of-N members and `:775-778` for delegates, from the `MemberBinding.recipient`
L1 addresses. It is never written elsewhere and has no setter — so it is exactly "an L1 address bound
to a registered participant of *this* channel at construction". Delegates are included, which is
correct here: `:757` documents that a delegate's recipient is registered precisely *for the withdrawal
path*.

*What it proves:* payout cannot be directed to an arbitrary external address. Combined with §4.1, a
forged authorization can at worst move a channel's own declared funds to one of that channel's own
registered addresses.

*What it does NOT prove:* nothing about entitlement **between** participants. Any member can still
name any other member's address, or their own, regardless of who actually burned. **It bounds the
claim; it does not derive it.**

### 4.3 Honest summary of the defence-in-depth layer

Neither check is a soundness fix, and neither is load-bearing for §1. They are containment: they
shrink the blast radius of a bad authorization from *global escrow → arbitrary address* to *own
channel's cosigned funds → own channel's registered address*. **The soundness comes entirely from
deleting the proof-free payout.** If a future change were to re-introduce a proof-free payout, these
checks would NOT make it safe.

### 4.4 Cost of the checks (completeness risk)

Both checks are satisfied by any *honest* partial withdrawal: an honest burn is bounded by the
channel's balance in that token, and an honest PW recipient is the burning member's own registered L1
address (that is exactly what `PW_RECIPIENT` is documented to be in the CLI, and what
`doc/tasks/todo.md:90` specifies: *"withdrawal_recipient = member L1"*). So no honest flow is broken.

---

## 5. Residual risk — PW is non-functional until the proof-backed path lands

**Stated plainly and accepted, not worked around.**

The base-layer half of partial withdrawal was never built:

- `cmd_partial_withdraw` is an unchecked box at `doc/tasks/todo.md:90`.
- The CLI currently invents `nullifier = keccak(tx_leaf ‖ pre_burn_chain)`
  (`src/bin/channel_member.rs:~4136`), whereas a provable leaf must use
  `settled_transfer.nullifier()`.
- No fixture in `contracts/test/data/` contains a valid proof for a burn leaf: the only real-proof
  payout fixture, `withdrawal_payout.json`, has
  `aux_data == 0x00…00` — a normal, non-burn withdrawal.

So after this change **the PW payout does not work end to end.** That is the correct state: the
alternative is a working-but-unsound payout.

### 5.1 What the proof-backed path must prove, to be safe to enable

1. **`auxData` == the tx_leaf the members actually signed** — i.e. the base withdrawal leaf's
   `auxData` is byte-identical to the `withdrawal.auxData` the Manager chain-bound to
   `intent.finalSettledTxChain`. (This is what makes the IMPW second factor meaningful at all.)
2. **`nullifier` == the settled transfer's nullifier** (`settled_transfer.nullifier()`), so the
   channel-layer burn and the base-layer leaf consume the *same* single-use token. The CLI's ad-hoc
   `keccak(tx_leaf ‖ pre_burn_chain)` must be replaced, not accommodated.
3. **base `Transfer.amount` == the channel-layer debit.** ⚠ This is **currently a co-signer
   assumption, not a proven equality** — audit finding **F-AUX-1**. Until it is in-circuit, the
   channel-layer debit and the L1 payout are only equal because the N-of-N cosigners checked it. This
   is the single largest remaining gap and must be closed (or explicitly re-accepted, in writing)
   before PW is enabled.

Until all three hold, re-enabling any PW payout re-opens a variant of this bug.

### 5.2 Interim behaviour chosen

- `src/bin/channel_member.rs` `cmd_pw_finalize`: **fail closed** with an explicit message naming the
  removal and pointing at `doc/tasks/todo.md:90`. Deliberately **not** silently rerouted to
  `withdrawNative`, which would fail with an opaque proof error and hide the real cause.
- `tests/partial_withdrawal_e2e.rs`: the claim phase is **converted to assert the new fail-closed
  behaviour** (the selector is gone → the call must revert), not deleted. Coverage is preserved.

---

## 6. Correcting two misleading claims

Both would be trusted by a future reviewer, which is why they are treated as part of the fix.

### 6.1 `IntmaxRollup.sol:1490-1493`

> "The auth digest binds ALL withdrawal fields so an attacker cannot reuse an authorized tx_leaf with
> different recipient/amount."

**True as REPLAY protection, false as DERIVATION.** Keccak preimage-binding does mean *one* digest
cannot be re-read as a different `(recipient, amount)` tuple. It says nothing about where that tuple
came from — and today it came from the caller. Reworded to state the replay property and explicitly
disclaim the derivation property, pointing at `_verifyWithdrawalSet` as the actual source of the
economics.

### 6.2 Lean: `claimAuthorized_safe`

Read what it actually proves (`doc/audit/zkp/Zkp/Contracts/IntmaxRollupWithdraw.lean:387-392`):

```lean
theorem claimAuthorized_safe {s s' : RollupState} {w : Withdrawal}
    (h : claimAuthorized s w = some s') :
    w.amount ≤ s.totalEscrowed
    ∧ s'.totalEscrowed + w.amount = s.totalEscrowed
    ∧ s'.nullifierUsed.get w.nullifier = true
    ∧ s.partialWithdrawalAuthorized.get (authDigest w) = true
```

Sole hypothesis: "the call did not revert". The conclusion is escrow-arithmetic conservation plus two
guard read-backs. **It proves (a) bookkeeping only — nothing about economic soundness.** Confirmed by:

- `authDigest : Withdrawal → Word` is declared `opaque` with **no axioms** (`:68-71`). The model
  cannot even *state* injectivity, let alone prove it — so the docstring's "binds ALL fields, so it
  can't be reused with a different recipient/amount" (`:374-375`, duplicated at `:68-70`) is
  **unbacked prose**, not a result.
- `w.recipient` is **never read** by the `claimAuthorized` transition (`:331-339`). The model has no
  notion of who was paid.
- Conjunct 4 is a pre-state boolean read-back, trivially satisfied by `Assumptions.rogueAuthState`
  (`:86-91`), which sets *every* digest true.

Also worth recording: there is **no** `claimAuthorized_no_double` theorem. The "no double payout"
narrative at `IntmaxRollupWithdraw.lean:475-481` leans on `claimAuthorized_safe` for the burn path,
but that theorem only gives the *consumption* half; the *reverting* half is in the definition's guard
and was never lifted to a theorem.

**Action taken:** since the modelled function is being deleted, `claimAuthorized_safe` is **renamed
to `claimAuthorized_escrow_conservation`** (a name that cannot be misread as an economic claim), given
an explicit scope note that the **derivation** of the digest's fields was outside the model, and
marked as modelling a **REMOVED** contract function. The unbacked "binds ALL fields" parenthetical is
replaced with a precise statement. The three proof sites that consume it
(`Assumptions.lean:81`, `IntmaxRollupSolvency.lean:98`, `EndToEnd.lean:338`) are updated.

**Why the transition is kept rather than excised:** `EOp.claim` is woven into the `EndToEnd` and
`IntmaxRollupSolvency` inductions. Keeping it means the model's operation set is a strict **superset**
of the deployed one, so every solvency theorem holds *a fortiori* for the shipped contract — a
conservative, strictly-sound position — while avoiding risky surgery on a large development. Its
docstrings now say, unambiguously, that it models a function that no longer exists.

---

## 7. Test gap that let this ship

`claimAuthorizedWithdrawal` had **zero** tests. `PartialWithdrawal.t.sol`'s 19 manager-side tests all
stop at `MockRollupRegistry` — the suite **never crosses the manager → rollup boundary**, so no test
ever asked "what can this authorization actually buy?".

Worse, two existing tests actively encode the misconception:
`test_crossFieldTamper_differentAmountDifferentDigest` and
`test_crossFieldTamper_differentRecipientDifferentDigest` (`:338-354`) assert only that keccak is
injective. They read as economic-soundness coverage and are nothing of the sort.

**Remediation (see the diff):** new tests that follow an authorization through to a real payout
attempt against a **real `IntmaxRollup`**, plus negative tests for the two new Manager checks. The two
misleading tests are retained but re-documented to state what they do and do not establish.

### 7.1 Honest limit on coverage

Requirement (b) — *"a burn leaf still pays when accompanied by a valid proof"* — **cannot be tested
with a real proof today, and no proof is faked.** There is no fixture that produces a valid
`WithdrawalCircuit` proof for a leaf with `auxData != 0`; the only real-proof payout fixture
(`withdrawal_payout.json`) is a normal withdrawal with `aux_data == 0`. Producing one requires the
base-layer burn path that §5 says does not exist. What is covered instead:

- the *non-burn* real-proof payout still works (existing `WithdrawNativeE2E`, kept green) — i.e. the
  deletion did not disturb the honest path;
- **mutating a real-proof leaf's `auxData` to non-zero breaks the chain re-fold and reverts** — this
  is the direct positive evidence that `auxData` is proof-bound and that the burn branch is reachable
  only via a proof;
- an authorization alone buys nothing.

This limitation is stated rather than papered over.

---

## 8. Adjacent findings — RECORDED, NOT FIXED in this diff

Deliberately out of scope (separate concerns, separate review). Flagged here so they are not lost.

### 8.1 `ChannelSettlementManager.fundBpBondCredits` is ungated and free

`contracts/src/ChannelSettlementManager.sol:801-803`:

```solidity
function fundBpBondCredits(uint256 amount) external {
    bpBondCredits += amount;
}
```

**Non-payable and completely ungated** — any address can inflate `bpBondCredits` to `type(uint256).max`
for the price of gas. Inert **today** only because no payout path reads `bpBondCredits`. It is one
wiring change away from being the same class of bug as this one: an unbacked counter that a payout
later trusts. Should be made `payable` with `msg.value == amount` (or access-controlled), before
anything reads it.

### 8.2 `DeployWalletSettlement.s.sol` — vacuous verifier, no chain guard

`contracts/script/DeployWalletSettlement.s.sol:11-19` defines `WalletMockMleVerifier.verify(...)`
returning `true` unconditionally, installs it as the verifier for **both** the close and cancel-close
VKs (`:57`, `:71`), and passes `CHALLENGE_PERIOD = 1` second (`:27`). Anything deployed with this
script has a **vacuous `_checkCloseProof`** and a one-second challenge game.

It has **no chain-id guard** — `grep block.chainid` → no matches — while *every* other deploy script
does (`Deploy.s.sol:35`, `DeployC2C.s.sol:36`, `DeployClose.s.sol:49`, `DeployCloseCli.s.sol:42`,
`DeployTestnetBlockProducer.s.sol:44`). And it is invoked from live relay code
(`hosting/wallet/wallet-relay-ec2.js:700-706` → `src/bin/channel_member.rs:3878`) with whatever
`--rpc-url` the relay supplies, which on the live box is **Sepolia**. Only an unrelated operational
failure (`forge` not installed) has prevented a Sepolia broadcast of an always-true verifier.

`DeployPartialWithdrawalE2E.s.sol` has the **same two properties** (`E2EMockMleVerifier` at `:15-23`,
`CHALLENGE_PERIOD = 1` at `:31`, no chain guard).

**Recommendation — stronger than a banner: both scripts should REFUSE to run against a non-local
chain id**, i.e. `require(block.chainid == 31337, ...)`, matching the existing convention in the other
five scripts. A banner is advisory and can be scrolled past; these scripts install an always-true
proof verifier, and the failure mode is silent and total. A loud banner is the minimum; the guard is
the right fix. (Not applied here — deploy-script change, separate diff.)

### 8.3 Disabled-but-forgeable close variants

`submitSpecialClose` (`:922-924`) and `submitLateOutgoingDebitCorrection` (`:972-977`) revert
unconditionally today (`SpecialCloseDisabled` / `LateOutgoingDebitDisabled`), which is safe. But their
verifier backings are forgeable `_matches` stubs. **They must not be re-enabled as-is** — re-enabling
requires real proof verification first.

### 8.4 Stale security claim in planning doc

`doc/tasks/pw-settle-ec2-plan.md:48-49` states *"`registerChannel` / `registerSettlementManager` have
no owner gate, so any funded key works."* This is **wrong** against current source:
`IntmaxRollup.sol:727-728` is `OnlyDeployer`-gated. A future operator trusting that line would draw a
false conclusion about who can register a settlement manager. Worth correcting.

---

## 9. Cryptographic invariant checklist (per `CLAUDE.md`)

This change touches **payout authorization composition**, not any transcript, challenge derivation,
sumcheck, or commitment scheme. Explicitly:

- **Fiat–Shamir / transcript:** untouched. No challenge derivation is added, removed, or reordered.
- **Polynomial-commitment binding:** untouched. `_verifyWithdrawalSet` and `_verifyMleWithdrawal` are
  not modified — the fix *adds callers' reliance* on them, it does not alter them.
- **Evaluation-point / batch-opening:** untouched.
- **Domain separation:** the IMPW domain tag (`0x494d5057`) and the IMTC chain domain (`0x494d5443`)
  are unchanged; the digest preimage is byte-identical, so no existing digest changes meaning.
- **No primitive implemented from scratch;** no randomness introduced; no security parameter changed.
- **No check weakened.** The change is strictly subtractive on the permissive side (one payout path
  removed) and strictly additive on the restrictive side (two Manager preconditions added).

---

## 10. Verification plan

| Gate | Command | Expectation |
|---|---|---|
| Contracts build | `cd contracts && forge build` | clean |
| Contracts tests | `cd contracts && forge test` | ≥ 233 pass, 0 fail (baseline 233/0) |
| Rust build | `cargo build --release` | clean |
| Rust PW E2E | `cargo test --test partial_withdrawal_e2e --release` | `--ignored`/heavy — must at minimum **compile**; run status reported honestly |
| Lean audit | `cd doc/audit/zkp && lake build` | success, zero `sorry` |
| Node | `cd node && npm test` | 122/0 — only if `node/` is touched |

### 10.1 ⚠ REQUIRED FOLLOW-UP — close-lifecycle fixture regeneration (heavy, NOT run here)

Adding the §4 checks changed `ChannelSettlementManager`'s bytecode, which changes its **CREATE2
address**, which is baked into the close withdrawal payout fixture as the L1 recipient. So
`CloseLifecycleE2E.t.sol::test_closeLifecycle_endToEnd` fails with the intended hard error
(*"manager CREATE2 address != close payout fixture recipient (stale fixtures -- regenerate)"*).

This is the known, documented consequence of any Manager change
(`doc/tasks/a3-p5-plus-plan.md:42`), and this repo consistently classifies fixture regeneration as
**heavy proving / a USER ACTION** (`doc/tasks/regen-and-redeploy-runbook.md:72` — *"each is minutes
of proving"*; `doc/tasks/a3-p6a-stub-revert-plan.md:37` — *"(heavy)"*). Per `CLAUDE.md`
§"No Unauthorized Heavy Computation" it was **deliberately not run**.

Only ONE fixture set is affected — `close_withdrawal_payout.json` is the sole fixture embedding the
address (verified by grep), and its proof `close_withdrawal_mle.json` is regenerated by the same
command. The new address is already computed:

```
WD_RECIPIENT=0x048882880028eb334c60C97Af2911607Ce85Fa5D WD_OUT_PREFIX=close_ \
  cargo run --release --bin generate_withdrawal_fixture
```

(Re-verify with `forge test --match-test test_printCloseManagerAddress -vv` after any further
Manager edit.) Contract test status pending that regeneration: **247 passed, 1 failed**, the single
failure being this fixture drift.

---

## 11. Assessment

The fix is **subtractive**, which is the right shape for a soundness bug: it deletes an unsound
payout rather than trying to reason a caller-supplied amount into legitimacy. The two Manager checks
are containment, and are documented as containment. The consequence — PW is non-functional — is
accepted and recorded rather than engineered around. The Lean statement that could be misread as
blessing the deleted function is renamed and rescoped, and the contract comment that overstated the
digest's binding is corrected.

**Open item deliberately left open:** F-AUX-1 (base `Transfer.amount` == channel-layer debit is a
co-signer assumption, not a proven equality). It must be closed before PW is re-enabled.
