# Doc-vs-code sweep: the exit path

**Scope:** "Someone deposits money and can withdraw it again without losing it."
**Branch:** `feat/falcon-poseidon-sig`, HEAD `8407080`. **Date:** 2026-08-12.
**Method:** every claim below was verified by reading the cited code, not by reading another doc.
Report only — no code, docs, or config were changed by this sweep.

Classification per finding:
**(a)** doc wrong / code right · **(b)** doc right / code missing · **(c)** both drifted · **(d)** cannot tell.

**Summary of the shape of the problem.** The repo's internal audit memos are unusually honest — the
code fails closed and often explains itself in the revert message. The danger is concentrated in the
three artifacts a *non-auditor* reads: `README.md` (decides whether to deposit),
`doc/docs/deploy-runbook.md` (decides what gets deployed), and `api/API-DESIGN.md` (decides what
gets integrated). All three currently describe an exit path that the code does not provide.

---

## F1 — CRITICAL. No real-network deploy script initializes the withdrawal VK. All four live Sepolia rollups cannot pay out a deposit. **(c)**

### The claim

`doc/tasks/regen-and-redeploy-runbook.md:142-149`, "Step 3 — deploy + VK init (target network)":

> :142 `satellite. The per-statement VKs are initialized IN the deploy scripts from the`
> :143 `regenerated fixtures. **Which script initializes what — verified, do not assume:**`
>
> :149 `| `Deploy.s.sol` | rollup-only smoke | YES |`

`doc/docs/deploy-runbook.md:126` — the live Sepolia procedure, in full:

> ```
> cd contracts && forge script script/Deploy.s.sol --rpc-url "$SEPOLIA_RPC_URL" \
>   --private-key "$(cat "$PRIV")" --broadcast --slow    # prints IntmaxRollup addr; run TWICE (ch7, ch8)
> ```

That is the entire on-chain deploy step for the live system. There is no `initializeWithdrawalVk`
step anywhere in `doc/docs/deploy-runbook.md` (251 lines) or in
`doc/docs/sepolia-smoke-runbook.md` (278 lines).

### The code

`contracts/script/Deploy.s.sol` is 73 lines and calls, in order: `new MleVerifier()` (:41),
`new IntmaxRollup(...)` (:44), `rollup.setKzgVerifier(...)` (:57), `rollup.setBlockProducer(...)`
(:60), `vm.stopBroadcast()` (:62). **`initializeWithdrawalVk` is never called.** Same for
`contracts/script/DeployTestnetBlockProducer.s.sol`, the only other production-shaped script.

`contracts/src/IntmaxRollup.sol:1614-1619`, the shared verification core of **both** payout
entry points (`withdrawNative` :1480, `withdrawERC20` :1543):

```solidity
function _verifyWithdrawalSet(...) internal view returns (uint64 wdBlockNumber) {
    if (!withdrawalVkInitialized) revert WithdrawalVkNotSet();
```

There is no other exit for escrowed deposit value: `withdraw()` (:1385) pays only
`pendingWithdrawals` (block-producer stake and fraud rewards, credited at :1454/:1992/:2012), and
`grep -n "emergency\|rescue\|sweep\|selfdestruct\|delegatecall\|upgrade"` over `IntmaxRollup.sol`
returns nothing. `deposit()` only increments `totalEscrowed` (:983).

### On-chain confirmation

`contracts/broadcast/Deploy.s.sol/11155111/` holds four real Sepolia runs. Decoded:

| run | UTC | IntmaxRollup | calls after CREATE |
|---|---|---|---|
| `run-1781625480679.json` | 2026-06-16 15:58 | `0x632d84c4…6d33` | *(none)* |
| `run-1781625661646.json` | 2026-06-16 16:01 | `0x601cbe31…9411` | *(none)* |
| `run-1785574200576.json` | 2026-08-01 08:50 | `0x0ee4c12f…4bf8a` | `setKzgVerifier`, `setBlockProducer` |
| `run-1785574381449.json` | 2026-08-01 08:53 | `0x210f7dad…63f6` | `setKzgVerifier`, `setBlockProducer` |

No `initializeWithdrawalVk` in any of them. The two 2026-08-01 rollups are *post*-`#2b`, so this is
not a stale-artifact story — the newest real deploys have it too.

### Consequence for a depositor

Every one of those rollups holds real Sepolia ETH (`doc/docs/deploy-runbook.md:14-15`: "Two
channels (**7 & 8**), each backed by its OWN real Sepolia deposit"; `setup-backing` performs the
deposit with `INTMAX_DEPOSIT_KEY`). `withdrawNative` and `withdrawERC20` revert
`WithdrawalVkNotSet()` on all four. **No code path returns escrowed deposit value.**

**Recoverability:** `initializeWithdrawalVk` is deployer-only + set-once but has no deadline
(`IntmaxRollup.sol:703-726`), so the deployer *can* still repair a live rollup — provided (i) the
deployer key survives, and (ii) a withdrawal VK matching the circuits **as of that rollup's deploy
commit** can be produced. For the 2026-06-16 pair that means regenerating at the old commit: the
runbook itself (`:44-52`) states `#2b` changed `single_withdrawal_circuit`'s digest and therefore
its VK, and that "Old fixtures will FAIL to verify under regenerated VKs and vice-versa". Funds are
stranded, not provably lost — but the repair is undocumented and non-obvious.

### Why the runbook did not surface it

`:149` marks `Deploy.s.sol` real-network **YES** with the VK column reading "rollup-only smoke". The
word "smoke" is doing load-bearing work that an operator following `doc/docs/deploy-runbook.md` —
which uses that same script for the *production* deploy — has no reason to decode.
`DeployTestnetBlockProducer.s.sol` is **absent from the table entirely**, despite being the only
script whose own docstring (:20-28) positions it for "a public testnet" while pointing at this
runbook for mainnet. The blanket assertion at `:142` is false for both.

This is the same defect class the runbook's own `:153-172` HISTORY section documents and claims to
have closed. That fix closed the *settlement* VKs and left the *base withdrawal* VK open.

---

## F2 — CRITICAL. The README's front-page safety promise — unilateral exit — is false for exactly the users the live demo onboards. **(a)**

### The claim

`README.md:11-13`, the first bullet of "Why INTMAX3":

> `- **L1 security + 1‑of‑N trust.** Every channel ultimately settles on Ethereum L1. Safety needs only`
> `  **one honest party — you**: with the last all‑member‑signed state you can always `close` on‑chain,`
> `  and `withdrawClaimZKP` lets you exit and withdraw **without any other member's cooperation**.`

Echoed at `README.md:89-90` ("**Exit / liveness** — … you exit alone with `withdrawClaimZKP`").

### The code

`contracts/src/ChannelSettlementManager.sol:849-852`, `requestClose()` — step 1 of the two-step
close, and the only way to begin an exit:

```solidity
function requestClose() external {
    if (channelStatus == ChannelLifecycleStatus.Closed) revert ChannelClosed();
    if (channelStatus != ChannelLifecycleStatus.Active) revert ChannelAlreadyFrozen();
    if (!isMemberRecipient[msg.sender]) revert NotChannelMember();
```

`isMemberRecipient` (declared `:658`) has **exactly two writes, both in the constructor** —
`:751` (N-of-N member bindings) and `:809` (delegate bindings) — and **no setter**
(`grep -n "isMemberRecipient" src/ChannelSettlementManager.sol` → `:658, :751, :788, :809, :852,
:1145, :1151`; `:788`/`:1145` are comments, `:852`/`:1151` are the two reads).

Under Option B, L1 registration is cosigners-only and there is no per-join L1 transaction — a
browser user joins as a **delegate after deployment**. `DeployCloseCli.s.sol:218-221` states it
plainly: "Under Option B, L1 registration is cosigners-only, so this is normally 0 while the live
channel has delegates". Such a user is not in `isMemberRecipient` and:

- **cannot call `requestClose()`** — reverts `NotChannelMember()` (`:852`);
- **cannot be a partial-withdrawal payout address** — reverts
  `PartialWithdrawalRecipientNotParticipant()` (`:1151`).

### The precise truth

The second half of the README sentence survives; the first half does not.
`submitWithdrawalClaim` / `submitPostCloseClaim` were deliberately converted to *proof-enforced*
membership rather than `isMemberRecipient` (they are absent from the grep above), so a delegate
**can** collect their share — but only **after some constructor-time member has opened and
finalized a close**. The accurate statement is:

> A delegate can claim without cooperation *once a close exists*. A delegate cannot cause one to
> exist.

That is 1-of-N trust among the *registered cosigners*, not "one honest party — you". If every
constructor-time member declines to open a close, a delegate's funds are locked with no on-chain
recourse.

### Consequence for a depositor

This is the claim on which a user decides to deposit, on the front page, in bold. The population it
is false for is precisely the population the live demo creates — every browser join. Nothing in
`README.md` or `doc/docs/deploy-runbook.md` qualifies it.

*(Independently recorded in-repo as `doc/audit/why-gate8-was-missed.md:428-436` "L3 —
post-deployment delegates cannot begin any exit", written at `898a586`. Confirmed still open at
HEAD. Reported here because the README was never reconciled with it.)*

---

## F3 — CRITICAL/HIGH. Every deploy script sets a 1-second challenge period; four docs state 86,400 seconds. **(c)**

### The claims

`doc/architecture-audit/detail2.md:619` — the constants table the implementation tracks:

> `| `CHALLENGE_PERIOD_SECS` | **86,400** | abstract2.md §2.5 (1 day). Set to the immutable `challengePeriod` of `ChannelSettlementManager` |`

`doc/architecture-audit/abstract2.md:154`: "`CHALLENGE_PERIOD = 1 day` : the challenge period."
`doc/tasks/a3-close-lifecycle-spec.md:24`, in the "現状(既に REAL なもの)" table:

> `| state machine: Active → ClosePending → Closed、GRACE=600s / CHALLENGE=86400s | **REAL** |`

`api/API-DESIGN.md:634`: "Replace a pending close with a newer state during the challenge period
(86,400s)."

### The code

`contracts/src/ChannelSettlementManager.sol:525-527` keeps 86,400 only as a **reference constant**,
never read:

```solidity
/// @notice Reference challenge period (abstract2 §3.5: 1 day). The constructor argument is
/// kept for test configurability but MUST be nonzero.
uint64 public constant CHALLENGE_PERIOD_SECS = 86_400;
```

What is enforced is the constructor argument (`:534` `uint64 public immutable challengePeriod`,
validated only `!= 0` at `:717`). **All four scripts that construct a manager pass 1:**

- `contracts/script/DeployCloseCli.s.sol:24` — `uint64 internal constant CHALLENGE_PERIOD = 1;` (used :226)
- `contracts/script/DeployClose.s.sol:26` — `= 1; // seconds (demo); challengeDeadline ~= +1 block` (used :92)
- `contracts/script/DeployWalletSettlement.s.sol:27` (used :110)
- `contracts/script/DeployPartialWithdrawalE2E.s.sol:31` (used :121)

Enforcement, `ChannelSettlementManager.sol:934` and `:1020-1024`:

```solidity
challengeDeadline: uint64(block.timestamp + challengePeriod),
...
function finalizeClose() external {
    if (!pendingClose.active) revert CloseNotActive();
    if (block.timestamp < pendingClose.challengeDeadline) {
        revert ChallengeWindowOpen();
    }
```

`finalizeClose()` is **permissionless**. `cancelClose` (`:967`) — the only remedy against a stale
close — must land inside that window. The partial-withdrawal window is the same value (`:1182`).

### Consequence for a depositor

At `challengePeriod = 1`, the submitter can call `finalizeClose()` in the next block (~12 s on
Sepolia). No honest member can observe the close, build a `CancelCloseProver` proof (heavy MLE/WHIR
proving), and land it in one block. The stale allocation becomes `finalizedCloseIntentDigest` and
drives every subsequent `submitWithdrawalClaim` payout — **funds are mis-allocated among channel
members, permanently, with the on-chain remedy present but unreachable.** Fund loss, not merely
liveness.

`DeployCloseCli.s.sol` is the script the runbook labels "(CLI/prod path) … real-network? **YES**"
(`regen-and-redeploy-runbook.md:148`). `DeployClose.s.sol:22` says of itself "CHALLENGE_PERIOD is
short (**Sepolia demo**)" — the code intends a public chain — while the runbook's `:150` puts it in
the real-network column as "—". The two disagree about whether it is a real-network script, and it
carries no `block.chainid` guard.

**No script anywhere reads a challenge period from env or from `CHALLENGE_PERIOD_SECS`.** There is
no configuration an operator could set to obtain the documented 1 day.

---

## F4 — HIGH. `DeployClose.s.sol` deploys a manager with a real verifier, no settlement VKs, and pre-Falcon deploy fixtures. **(b)**

### The claim

`doc/tasks/regen-and-redeploy-runbook.md:150`:

> `| `DeployClose.s.sol`, `DeployC2C.s.sol` | withdrawal only | — |`

True as far as it goes. What the table omits is that `DeployClose.s.sol` *also deploys a settlement
stack* and leaves it entirely unkeyed.

### The code

`contracts/script/DeployClose.s.sol`: `new MleVerifier()` (:55, **real**, not a mock),
`new ChannelSettlementVerifier()` (:68), `new ChannelSettlementManager(...)` (:91),
`rollup.initializeWithdrawalVk(...)` (:102).

```
$ grep -n "initializeCloseVk\|initializeWithdrawalClaimVk\|initializePostCloseClaimVk\|initializeCancelCloseVk\|registerSettlementManager" script/DeployClose.s.sol
(no output)
```

`contracts/src/ChannelSettlementVerifier.sol:238`: `if (!closeVkInitialized) revert CloseVkNotSet();`

**Compounding: its deploy fixtures are pre-Falcon.** `DeployClose.s.sol` reads the validity VK,
withdrawal VK and genesis root from `sepolia_lifecycle_validity_mle.json` (:33),
`sepolia_withdrawal_mle.json` (:36) and `sepolia_lifecycle.json` (:39). Those four `sepolia_*`
files were last regenerated at `89cd044` (2026-07-31, "regenerate all VKs and fixtures for Regev
n=2048"), whereas the Falcon migration regenerated everything else at `2e418f6` (2026-08-07).
`doc/tasks/falcon-sig-phase5-notes.md:370` records this as **STOP 1 / "DEFERRED — deploy-time"**.
Confirmed by `git log` on the paths.

*Precision, because it is easy to get wrong:* these files are **not** stale on the CLI-driven exit
path — `cmd_withdraw` (`src/bin/channel_member.rs:2314`) freshly proves and overwrites all four at
`:2462-2468` before invoking the forge steps. The staleness bites only at **deploy** time, which
runs first and is never re-staged.

### Consequence for a depositor

A channel deployed by `DeployClose.s.sol` accepts `requestClose()` — which sets
`isNativeSendAllowed = false`, freezing the channel — and then reverts `CloseVkNotSet()` on every
`submitCloseIntent`. The channel is frozen and unclosable. Partial withdrawal is also unavailable
(no `registerSettlementManager`, F8). Separately, the rollup would be born with a pre-Falcon
validity VK and genesis root, so the CLI's post-Falcon proofs would not verify against it. The
script's header (`:22`) aims it at Sepolia and it has no chain-id guard.

---

## F5 — HIGH. The live full-withdrawal path is structurally dead: the relay's first step is a script that refuses to run off anvil. **(c)**

### The code chain

`hosting/wallet/wallet-relay-ec2.js:928-948` — `POST /api/deploy-settlement`, the first step of the
`full_withdrawal` ticket (`steps: { deploy, close, settle, withdraw, claim }`, `:940`) — execs
`cli(ch, ['deploy-settlement', RPC])`.

`src/bin/channel_member.rs:4754-4841` (`cmd_deploy_settlement`) unconditionally runs:

```rust
.args([ "script", "script/DeployWalletSettlement.s.sol", "--tc", "DeployWalletSettlement",
        "--rpc-url", &rpc, ... ])
```

`contracts/script/DeployWalletSettlement.s.sol:40`:

```solidity
require(block.chainid == 31337, "local-devnet only: this script deploys mock verifiers");
```

`RPC` on the live box is Sepolia (`doc/tasks/pw-settle-ec2-plan.md:88` — systemd
`CHAIN_ID=11155111`). The guard was added in `42640f1` and is **correct** — that script installs
`WalletMockMleVerifier` (`:11-20`), an always-true verifier. But nothing downstream was rerouted.

### The stale doc

`doc/tasks/pw-settle-ec2-plan.md` Phase 3 (`:100-102`) plans exactly the now-blocked broadcast:

> `- [ ] `curl /api/health` OK; then resume the stuck ticket in the browser: Step 2 Settle →`
> `      deploy-settlement broadcasts (~5 Sepolia txs, first time per channel), `pw-submit` returns`

**Every box in Phases 0–4 of that plan is `- [ ]`.** None of it was done. The same doc records live
stranded value at `:118-120`:

> `- ch7 has **6 stranded burn-done partial-withdrawal tickets** (Σ ≈ 0.0215 "ETH" demo balance).`

and at `:121-131` a further blocker: "the Sepolia rollups are too old for the pw feature … cannot
be patched … **the 6 stranded burns can never settle**".

`doc/docs/deploy-runbook.md` — the current live runbook — describes the live system in 251 lines
and never mentions that the close/withdraw legs cannot execute there.

### Consequence for a depositor

A live user clicking withdraw gets a 500 at step 1, forever. The six recorded burns are channel-side
debits already committed; `ChannelSettlementManager.sol:1197-1199` notes a burned amount "is already
excluded from the close's channelFundAmount", so the close path does not recover them either.

---

## F6 — HIGH. `api/API-DESIGN.md` states the partial-withdrawal payout is implemented. The code deliberately `exit(1)`s before payout. **(a)**

### The claim

`api/API-DESIGN.md:551`:

> `**Overview:** Finalize a partial withdrawal on L1. Calls `finalizePartialWithdrawal()` then claims the ETH. (detail2 D row 4)`

`api/API-DESIGN.md:556-558`, "Current status":

> `- CLI: `pw-finalize` — implemented`
> `- Relay: `POST /api/pw-finalize` — implemented`
> `- Contract: `finalizePartialWithdrawal()`, `claimWithdrawalCredit()` — implemented`

### The code

`src/bin/channel_member.rs:5751-5771` — the terminal statement of `cmd_pw_finalize`:

```
pw-finalize: STOPPING BEFORE PAYOUT — the partial-withdrawal payout is not available.
...
  • The command that builds that proof — `cmd_partial_withdraw` — is NOT IMPLEMENTED.
    Tracked as the unchecked box at doc/tasks/todo.md:90.
...
Until it lands, partial withdrawal is intentionally non-functional end to end. This is a
deliberate fail-closed state, not a bug in this run.
```

followed by `exit(1);` (`:5772`). `IntmaxRollup.claimAuthorizedWithdrawal` was removed in `42640f1`
(it paid global escrow against an authorization with no withdrawal proof — the drain hole).
`grep -n "partial_withdraw" src/bin/channel_member.rs` confirms `cmd_partial_withdraw` does not
exist. `doc/tasks/todo.md:105` is still unchecked.

### Consequence

The code is exemplary — it fails closed and explains itself. **The API doc is the hazard.** An
integrator building to `API-DESIGN.md` ships an endpoint documented to return `{ ok: true }` and
"claim the ETH", against a CLI that exits non-zero. Users burn channel balance into a path with no
payout leg — which is how ch7 accumulated six stranded tickets (F5).

---

## F7 — HIGH. Close after a deposit import is refused by the close circuit's balance binding. **(b)** — self-reported, unresolved

### The claim

`doc/tasks/multitoken-todo.md:634-643`, listed as a live deviation:

> `      1. *P1 re-attestation fence:* a close AFTER `cosign-l1-deposit-import` is refused by the`
> `         close circuit's balance binding (`BalanceBindingMismatch`) … So a LIVE close with nonzero amounts[1] (and a nonzero live`
> `         per-token claim payout) awaits that follow-up`

Restated at `:688-694` as one of the outstanding Phase 5 follow-ups.

### The code

`src/circuits/channel/close_circuit.rs:1038-1050` — the native mirror of the in-circuit binding:

```rust
// Native mirrors of the in-circuit balance-binding constraints — same checks, earlier
// and with structured errors (the circuit constraints remain authoritative).
let balance_pis = ...;
if balance_pis.settled_tx_chain != public_inputs.final_settled_tx_chain {
    return Err(ChannelCloseCircuitError::BalanceBindingMismatch(format!(
        "balance proof settled_tx_chain {} != close final_settled_tx_chain {}", ...
```

The mechanism is consistent with `doc/docs/deploy-runbook.md:223-227`: "**§F-1 backing is anchored
at GENESIS only** … Reconciliation against the deposit is the close/settlement step." The backing
balance proof is produced once at `setup-backing`; a later import advances the channel's
`settled_tx_chain` past it, and nothing re-attests. `grep -rn "re-attestation\|reattest"` over
`src/bin/channel_member.rs` and `src/wallet_core.rs` returns **nothing** — the P1 follow-up is
unimplemented.

### Consequence for a depositor

This is the sweep's scope sentence verbatim: deposit → import → **cannot close**. A user who
deposits into an existing channel via `cosign-l1-deposit-import` cannot subsequently exit through
the close path. The funds are escrowed and the exit is refused before a proof is even built.

**Confidence:** the error path and the absent re-attestation are verified; I did **not** build a
close after an import to observe the failure (that is heavy proving, out of scope). The causal claim
is the repo's own, from the team that ran the two-token E2E. Treated as demonstrated-by-the-repo,
not independently reproduced.

---

## F8 — MEDIUM-HIGH. The "CLI/prod path" script never calls `registerSettlementManager`, so `finalizePartialWithdrawal` reverts on every real deployment. **(b)** — already recorded, still open

`contracts/src/IntmaxRollup.sol:786-787`:

```solidity
function authorizePartialWithdrawal(bytes32 authDigest) external {
    if (!isRegisteredSettlementManager[msg.sender]) revert NotRegisteredSettlementManager();
```

`ChannelSettlementManager.sol:1213` calls it from `finalizePartialWithdrawal()`. Repo-wide:

```
$ grep -rn "registerSettlementManager" contracts/script contracts/test api node hosting
script/DeployPartialWithdrawalE2E.s.sol:128      (chainid == 31337 gated, :44)
script/DeployWalletSettlement.s.sol:117          (chainid == 31337 gated, :40)
test/PartialWithdrawalPayout.t.sol:47
```

`DeployCloseCli.s.sol` does not call it (verified by reading all 238 lines).

Already documented at `doc/audit/why-gate8-was-missed.md:437-442` and as the unchecked
`doc/tasks/todo.md:107` ("needed for real deployment"). **Confirmed still open at HEAD.** Listed
because the runbook's Step 3 table (`:146-151`) — the operator-facing artifact that says "verified,
do not assume" — does not carry it, so an operator working from the runbook alone cannot see it.

---

## F9 — MEDIUM. `CLAUDE.md` describes an on-chain architecture that no longer exists. **(a)**

| `CLAUDE.md` | Reality |
|---|---|
| `:102` "Verifies the MLE+WHIR wrapper proof **and Groth16 in parallel**." | `IntmaxRollup.sol:36` "On-chain verification is MLE/WHIR-only (Groth16 removed)". Also :1261, :1748-1750, :1828, :2047. Contradicted by `CLAUDE.md`'s own :43-44. |
| `:120` "→ MLE/WHIR evaluations **→ Groth16 public inputs**" | `IntmaxRollup.sol:1748-1750`: the piHash binding "replaces the removed Groth16 PI binding". |
| `:134` "`Groth16Verifier.sol` / `GnarkGroth16Verifier.sol` — BN254 Groth16 pairing verification" | `contracts/src/` contains exactly 5 files: `BlobKZGVerifier.sol`, `ChannelSettlementManager.sol`, `ChannelSettlementVerifier.sol`, `IntmaxRollup.sol`, `SafeERC20.sol`. Neither exists. |
| `:7`, `:98`, `:114` "post-quantum signatures (**SPHINCS+** with Poseidon)" etc. | This branch is Falcon-512/Poseidon (`src/falcon_sig/`; Phase 5 marked done at `e3a4500`). |
| "The `gpu_merkle` feature is **intentionally not exposed in `Cargo.toml`** on this branch." | `Cargo.toml:185` `gpu_merkle = ["plonky2/gpu_merkle", "starky/gpu_merkle"]`. |
| "Re-enabling it requires bumping … the v2 MLE-verifier soundness fixes … new `gatesDigest` … tracked as a separate PR." | Already migrated: `IntmaxRollup.sol:1883` `mleVerifier.verify(mleProof, vp, whirParams, vk.gatesDigest)`; `MleVerifier.sol:173-175` takes `bytes32 gatesDigest`. |

**Consequence.** The Groth16 line is the fund-relevant one: it tells a reader the finalize path has
**two independent verifiers in parallel**. It has one. Anyone sizing the blast radius of an
MLE/WHIR verifier bug — the thing that gates `finalizedStateRoots`, which gates every withdrawal —
would under-weight it. The rest is stale-map risk during a fixture regeneration, the very operation
F1 depends on.

---

## F10 — LOW-MEDIUM. `doc/docs/deploy-runbook.md` tells a user the only way to lose funds is losing their key. **(a)**

`doc/docs/deploy-runbook.md:239-240`:

> `proof matches the stored ciphertext. Losing the witness ≠ losing funds (refresh regenerates it from`
> `the secret key); only losing the secret key loses funds.`

Scoped to the witness-vs-key distinction and correct *about that distinction*. But as an unqualified
sentence on the live-deployment runbook it is false for the live system: per F1, F2 and F5, **no key
recovers a deposit there**, because no exit path executes. Worth a scope qualifier — it is the kind
of line a user quotes back when deciding how much to deposit.

---

# Deferred items I CLEARED — verified actually done

Recording these so they are not re-investigated. Several are alarming as written and are **no longer
true**.

1. **"limb 94 strict-bind refuses EVERY live CLI close since Option B"**
   (`doc/tasks/multitoken-todo.md:644-649`) and "every live delegate-bearing close is refused at
   limb 94 with `close limb mismatch`" (`doc/tasks/b2-delegate-close-threat-model.md:20-25`).
   **FIXED — the bind is now a one-sided FLOOR, not equality.**
   `contracts/src/ChannelSettlementVerifier.sol:261`
   `if (delegateCount < fields.minDelegateCount) revert CloseDelegateCountOutOfRange();`
   with `:125-135` documenting the change. A close carrying *more* delegates than registered is
   accepted. This is the single scariest stale claim in the corpus — it reads as "no live channel
   can close" and is no longer accurate.

2. **Gate 8 / `ExponentiationGate` — "the change is not carried by the pin … withdrawal claims stop
   verifying … it will silently disappear"** (`doc/tasks/exponentiation-gate-notes.md:3-4`,
   `:228-243`, marked "**Not committed**"). **RESOLVED AND PINNED.** HEAD `8407080` is
   *"build: pin the submodule at the pushed ExponentiationGate commit"*; the submodule at
   `fbf3735b` carries `mle/contracts/src/Plonky2GateEvaluator.sol:22` (gate 8 documented), `:545`
   (`ExponentiationGate::eval_unfiltered` port) and `:231` (the unsupported-gate revert now scoped
   to LookupGate/LookupTableGate only). The notes file's status line is stale.

3. **`postCloseClaim` / `cancelClose` VKs uninitialized on real deployments** (audit622 A-M4;
   `why-gate8-was-missed.md:394-411` L1). **DONE.** `DeployCloseCli.s.sol:115-141`
   (`initializePostCloseClaimVk`) and `:143-167` (`initializeCancelCloseVk`). The runbook's `:148`
   row is now accurate for that script. *(The base withdrawal VK on `Deploy.s.sol` /
   `DeployTestnetBlockProducer.s.sol` is a separate, still-open case: F1.)*

4. **Fail-closed reverts for unset settlement VKs.** **DONE.**
   `ChannelSettlementVerifier.sol:238` (`CloseVkNotSet`), `:1004` (`WithdrawalClaimVkNotSet`),
   `:1050` (`CancelCloseVkNotSet`), `:1111` (`PostCloseClaimVkNotSet`).

5. **`pw-auth-threat-model.md` §8.2** — "both scripts should REFUSE to run against a non-local chain
   id … (Not applied here — deploy-script change, separate diff)". **APPLIED.**
   `DeployWalletSettlement.s.sol:40` and `DeployPartialWithdrawalE2E.s.sol:44`. *(Side effect: this
   is what makes F5 structural.)*

6. **`pw-auth-threat-model.md` §8.1** — `fundBpBondCredits` ungated and free. **FIXED by removal.**
   `grep -n "fundBpBondCredits" contracts/src/ChannelSettlementManager.sol` returns nothing; the
   history note survives at `:834`.

7. **`pw-auth-threat-model.md` §8.4** — "`pw-settle-ec2-plan.md:48-49` states … no owner gate …
   This is **wrong**". **CORRECTED in place** at `pw-settle-ec2-plan.md:48-52`. Matches
   `IntmaxRollup.sol:732`.

8. **`reclaim-stake-threat-model.md:10-18`** — "every posting round beyond the one finalized leaks a
   real-ETH bond … `reclaimStake` is the missing exit". **IMPLEMENTED.**
   `contracts/src/IntmaxRollup.sol:1442` `function reclaimStake(uint256 submissionId) external
   nonReentrant`, with the INV-A defence at `:1737-1741`. (Block-producer stake, not depositor
   funds — but it was a live-ETH stranding item.)

9. **`deposit-import-threat-model.md:427-432`** — "the success message **lies** in deferred mode …
   prints `setup-backing OK: REAL on-chain deposit` unconditionally". **FIXED.**
   `src/bin/channel_member.rs:1326` now prints `"setup-backing OK: NO on-chain deposit made —
   DEFERRED to \`withdraw\`"` on that branch; `:1333` is the real-deposit branch.

10. **gadget-inventory `TODO-2` (`reduce_to_hash_out` canonicity, MEDIUM-HIGH)**, open per
    `doc/audit/zkp/tasks/todo.md:329`. **DONE in code.**
    `src/circuits/withdraw/single_withdrawal_circuit.rs:470` and
    `src/circuits/balance/common/tx_settlement.rs:286` both carry the canonicity-enforcing
    `to_hash_out`. *(The dependent fixture-regen + redeploy is a different question — see F1.)*

11. **`api/API-DESIGN.md:667`** — "CLI: NOT implemented (no `cancel-close` subcommand)".
    **STALE — it is implemented.** `src/bin/channel_member.rs:2877` `"cancel-close" =>
    cmd_cancel_close(&args)`, implementation `:1900-2025`. Same for `:758-759` "post-close-claim
    NOT implemented" → `:2878` `"post-close-claim" => cmd_post_close_claim(&args)`. Worth
    correcting rather than leaving: these lines tell a reader the only on-chain remedy against a
    stale close is absent, which would make F3 look unavoidable when it is not.

12. **`doc/tasks/multitoken-todo.md:54-69`** — unchecked boxes for `MAX_CHANNEL_TOKENS` and
    token-slot plumbing. **DONE.** `src/constants.rs:185` `pub const MAX_CHANNEL_TOKENS: usize =
    10;`; the §N flow is wired through `regen-and-redeploy-runbook.md:11-33`. Checkbox staleness
    only.

13. **`CLAUDE.md` "Known follow-up: gpu_merkle re-enable"** — the v2 `MleVerifier` migration
    "tracked as a separate PR". **DONE.** See F9's last two rows.

14. **Mock-verifier exposure on a public chain.** Both mock-installing scripts are now chain-guarded
    (item 5). `contracts/broadcast/` confirms no `ChannelSettlementManager` has ever been broadcast
    to chain 11155111 — the only non-31337 directories are `Deploy.s.sol/11155111` and
    `RegisterTokens.s.sol/11155111`. The claim at `pw-auth-threat-model.md:145-176` holds.

---

# Speculation (not demonstrated — flagged separately)

- **F1 repair difficulty for the 2026-06-16 rollups.** I did not attempt to regenerate a withdrawal
  VK at commit `0f30445`, so "the old VK is reproducible" is untested. If the pre-`#2b` fixture set
  is not reconstructible, those two rollups' escrow may be *unrecoverable* rather than stranded.
  Worth testing before anything else on this list.

- **Whether the six ch7 burns are formally unrecoverable.** I read the exclusion comment at
  `ChannelSettlementManager.sol:1197-1199` and the ticket record at `pw-settle-ec2-plan.md:118-131`
  (which itself says they "can never settle"), but did not trace `build_burn_send` through the
  channel state to confirm the debit is irreversible by cosigner agreement. Treat "gone" in F5 as
  the pessimistic reading.

- **F3 exploit practicality.** The 1-second window makes `cancelClose` unreachable *in my reading of
  the timing*; I did not measure `CancelCloseProver` wall-clock (heavy proving, out of scope). If a
  cancel proof could be pre-built before the close lands, the window matters less. The 86,400-vs-1
  documentation contradiction is demonstrated regardless.

- **F2 blast radius.** Whether any *current* live delegate holds non-faucet value is not something
  I can determine from the repo; `.claude/deploy-record.md` is gitignored and I did not read chain
  state. The contract-level fact (delegates cannot call `requestClose`) is demonstrated.

---

# Not covered

- **No heavy proving, no `#[ignore]` E2Es, no `forge test`** (per constraints; `pgrep -f forge` was
  clean but the suites are hours). Every claim above is static: source, broadcast JSON, git history.
- **`doc/audit/zkp/` Lean development** — read only for its open-findings list (F-UPDU-1, F-WD-2
  remain open per `tasks/todo.md:325-335`; `SUMMARY.md` marks both CLOSED — an internal
  disagreement I did not adjudicate). The Lean proofs were not checked against the contracts, and
  another agent is active in that tree.
- **`doc/audit/exit-path-facade-sweep.md`** and in-flight audit memos — deliberately untouched.
  `doc/audit/why-gate8-was-missed.md` was read (committed at HEAD); its L3/L4 findings are
  corroborated above (F2, F8), not restated.
- **Circuit internals.** I verified `to_hash_out` is called (cleared item 10) but did not audit the
  gadget's canonicity argument. F7's binding was read, not exercised.
- **Browser/wasm wallet and `node/`** beyond the relay endpoints on the exit path.
- **Whether Steps 1–3 of `regen-and-redeploy-runbook.md` were ever executed against the live
  rollups.** Broadcast records show *deploys*, not fixture provenance. Determining which circuit
  commit each live rollup's validity VK corresponds to needs an on-chain read of
  `mleVk.preprocessedRoot` against regenerated fixtures — not attempted.
- **Escrow-stranding findings recorded in `doc/audit/audit622.md`** (A-M3 `:133` partial-claim
  stranding, A-L1 `:194` surplus with no extraction path, C-H2 `:404` `channel_fund_amount` not
  tied to Σ slot ciphertexts) were surfaced by the sweep but not verified against code — they are
  intra-channel allocation questions rather than doc-vs-code contradictions, and belong to a
  soundness review.
- **Docs read end-to-end:** `CLAUDE.md`, `README.md`, `doc/docs/{deploy-runbook,
  sepolia-smoke-runbook}.md`, `doc/tasks/{regen-and-redeploy-runbook, pw-auth-threat-model,
  pw-settle-ec2-plan, todo, multitoken-todo, a3-close-lifecycle-spec, a3-p5-plus-plan}.md`,
  `doc/architecture-audit/{abstract2,detail2}.md`, `api/API-DESIGN.md`. The remaining ~50 markdown
  files across `doc/` were swept for deferral and completion markers (two parallel passes, full
  coverage list retained) but not read end-to-end; hits touching the exit path were pulled forward
  and verified individually above.

---

*Housekeeping, unrelated to findings:* one of the two sweep passes reported creating
`/Users/plasma/scratch_out.txt` (~56 KB, outside the repo) via a shell redirect, and did not remove
it. Nothing inside the repo was modified by this sweep.
