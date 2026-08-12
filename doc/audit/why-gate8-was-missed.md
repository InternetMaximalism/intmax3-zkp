# Why the audit did not catch the gate-8 on-chain revert

**Subject:** `Plonky2GateEvaluator.sol` reverted on `ExponentiationGate` (gate id 8), making
`submitWithdrawalClaim` unverifiable on-chain for every real proof.
**Status of the defect:** fixed in `4574348` (2026-08-09); see `doc/tasks/exponentiation-gate-notes.md`.
**Purpose of this document:** process retrospective. Not a code change, not a blame exercise.
**Repo state at time of writing:** branch `feat/falcon-poseidon-sig`, HEAD `898a586`.
Line numbers in `doc/tasks/regen-and-redeploy-runbook.md` and `doc/tasks/b2-implementation-notes.md`
refer to the working tree (both are modified relative to HEAD).

---

## 0. Verdict in one paragraph

The audit was **not wrong, and mostly it was not asked** — but the "not asked" is the interesting
part, because the scope boundary that excluded this defect was drawn along a *soundness* axis and
therefore had no edge on the *liveness* axis. Decomposed:

| Cause | Weight | Evidence |
|---|---|---|
| **Correct when written, invalidated later.** The defect did not exist when any of the three audits was written. Gate 8 entered the fixtures on **2026-07-31** (`89cd044`); the audits are dated 2026-06-22, 2026-06-28, 2026-07-02. | **Dominant** | §2 |
| **Out of scope.** `Plonky2GateEvaluator.sol` / `MleVerifier.sol` are excluded as "crypto oracles"; the entire channel claim path has *no Lean model at all*. | **Substantial and legitimate** | §3 |
| **In scope but overlooked.** The test-coverage gap opened **four days before** audit622 and was never flagged; and the audit *did* find a sibling instance of this exact defect class (A-M4) without generalising it. | **Real, and the actionable part** | §5, §6 |
| **Noticed and consciously deferred.** Two separate reviews found it before the E2E did — 2026-08-05 and 2026-08-09 — and both correctly escalated rather than patched. | **This part of the process worked** | §5 |

The single most generalisable finding: **liveness is used in this audit corpus as a *dismissal
category*, not as a property to be proved.** `doc/audit/audit28-06-2026.md:291` classifies
functions as "**LIVENESS / VIEW** (no escrow effect)" — i.e. *liveness ⇒ not fund-relevant ⇒ not
modelled*. Under that classification a verifier that rejects every honest proof is, by
construction, uninteresting.

---

## 1. The defect, restated in audit terms

`contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol:235`:

```solidity
revert("unsupported gate with non-zero filter");
```

This is a **fail-closed capability gate**. Its security profile is asymmetric:

- **Soundness: perfect.** It cannot accept a false statement. It refuses to evaluate a constraint
  it does not implement, rather than skipping it. `doc/tasks/b2-implementation-notes.md:718-719`
  states this correctly: *"Under no circumstances should the evaluator's `revert` be relaxed: it is
  the fail-closed signal that a constraint would otherwise go UNCHECKED on-chain."*
- **Liveness: total failure.** Every honest withdrawal claim reverts. The settlement exit path is
  bricked.

Every question this audit corpus asks is of the form *"can a false statement be accepted?"*. This
defect is the exact logical complement, so no question in the corpus could return `yes` on it.

---

## 2. Timeline — the defect postdates every audit

Established from `git log --follow` on the fixtures and by diffing the gate-name lists across each
regeneration commit.

| Date | SHA | Event | Gate 8 in claim fixtures? |
|---|---|---|---|
| 2026-06-18 | `1031f38` | `feat(settlement): replace ChannelSettlementVerifier stubs with real on-chain ZK (A1)` — claim path becomes real-MLE-gated on-chain; `CloseLifecycleE2E.t.sol` simultaneously adopts the "stop before the claim" comment | n/a |
| 2026-06-19 | `d3b7106` | first `withdrawal_claim_mle.json` / `post_close_claim_mle.json` | **no** |
| **2026-06-22** | — | **`doc/audit/audit622.md`** | **no** |
| **2026-06-28** | `e618f0e` | **`doc/audit/audit28-06-2026.md`** + Lean development | **no** |
| **2026-07-02** | `dd02893` | **`doc/audit/audit02-07-2026.md`** (meta-audit + remediation) | **no** |
| 2026-07-04 | `63323dd` | fixtures regenerated (Option B) | **no** |
| 2026-07-27 | `ab9aa54` | fixtures regenerated (multitoken Phase 5b) | **no** |
| **2026-07-31** | **`89cd044`** | **`chore(fixtures): regenerate all VKs and fixtures for Regev n=2048` — gate 8 appears** | **YES** |
| 2026-08-05 | `a5efa10` | Phase 2.5 review spots it, reports it as pre-existing / separate | yes |
| 2026-08-07 | `2e418f6` | fixtures regenerated (Falcon Phase 4) — gate 8 carried forward | yes |
| 2026-08-09 | `4574348` | E2E reaches the claim step; defect confirmed and fixed | fixed |

Verification of the introducing commit — diff of the gate-name list, `89cd044^` vs `89cd044`:

```
-      "name": "ConstantGate ...
+      "name": "ExponentiationGate ...
```

The two claim fixtures also went from `numSelectors` 3 → 4. `89cd044`'s own commit message explains
the mechanism:

> 1. Claim circuits. `decryption_gadget` derives `KAPPA_BITS = ceil(log2(2n+1))`:
>    9 bits at n=128, 13 at n=2048, over 2048 coefficients. Changes
>    `withdrawal_claim_circuit` and `post_close_claim_circuit`.

The wider bit-width pushed plonky2's recursive FRI verifier off the cheap `exp_power_of_2`
square-chain branch onto `exp_from_bits_const_base`, which emits `ExponentiationGate`
(root-caused in `doc/tasks/b2-implementation-notes.md:706-710`, citing
`plonky2/src/fri/recursive_verifier.rs:48`, `:416`, `:547`).

**Conclusion for §2:** no reviewer reading the repository on 2026-06-22, 06-28 or 07-02 could have
seen this. It is a *later invalidation* of a conclusion that was correct when written.

**But — and this is the process failure — the invalidating commit reasoned about exactly this
failure mode and stopped one step short.** `89cd044`'s message says:

> `forge test` passing was never evidence of correctness here: it only shows each fixture is
> internally consistent, not that current Rust reproduces it. The deploy path is what makes it
> matter — DeployCloseCli builds the on-chain VKs FROM these JSONs at runtime, so **a stale VK means
> a chain that rejects every proof the current code can produce.**

That is a perfectly-formed liveness argument. It was applied to *VK staleness* (does the deployed VK
match the circuit?) and not to *gate-set support* (does the evaluator implement the gates the VK
names?). The commit changed the gate set and did not re-ask the question against the evaluator.

---

## 3. Scope — what the audits actually claimed

### 3.1 audit622 (2026-06-22)

In scope (`doc/audit/audit622.md:31-35`) covers `ChannelSettlementManager.sol`,
`ChannelSettlementVerifier.sol`, `IntmaxRollup.sol`, and `src/circuits/{channel,balance,withdraw,validity}/`.
**The claim path is squarely in scope** — the report's second-highest contract finding is about it:

> `doc/audit/audit622.md` A-H1 — "Intra-channel over-claim via withdrawal-claim `amount`
> (documented residual)"

Out of scope (`doc/audit/audit622.md:37-42`):

> - Low-level cryptographic primitive implementations … beyond circuit gadgets that embed them
> - **MLE/WHIR PCS cryptographic soundness (wrapper is a thin passthrough)**
> - BP censorship, MEV, off-chain P2P availability
> - Production VK deployment verification (noted as operational dependency)

**This is the load-bearing scope line, and it is soundness-shaped.** It excludes MLE/WHIR
*cryptographic soundness*. It does not exclude — and does not mention — whether the on-chain
evaluator is *capable of evaluating the circuits this repo actually builds*. That question falls
into a no-man's-land: not in scope, not excluded, not assigned to anyone.

**And audit622 overclaims on the axis that matters.** `doc/audit/audit622.md:6`:

> **Focus:** Fund solvency and **system liveness**; forged-proof resistance where applicable

Liveness is named as a *focus*, first line of the report. What was actually delivered on that axis
is three MEDIUM findings about griefing and deploy configuration (A-M1, A-M4, B-M4) — no systematic
liveness analysis, no property, no test. A reader is entitled to read line 6 as "honest exit was
checked". It was not. **This is the one scope statement in the corpus that should be narrowed or
backed.**

### 3.2 audit28-06 / the Lean development

`doc/audit/zkp/README.md:1-6`:

> "A line-by-line Lean 4 model of the Intmax3 Plonky2 ZKP circuits, built to either **prove
> soundness** of each circuit statement or to **surface the gap** where soundness cannot be proved
> (a candidate vulnerability)."

`doc/audit/zkp/README.md:8-12`:

> "Scope: ZKP circuits only. **Excluded:** cryptographic primitive implementations (Poseidon,
> SPHINCS+, Regev, MLE/WHIR internals — modeled as uninterpreted functions) and all **channel**
> circuits (`src/circuits/channel/`, …)"

`doc/audit/audit28-06-2026.md:95-99`:

> "**SNARK/PCS verifiers** (Groth16, KZG, MLE/WHIR) … are treated as **verified oracles** — exactly
> the audit boundary used for cryptographic primitives. Contract verifier wrappers (`_verifyMle`,
> `_verifyKZG`, `BlobKZGVerifier`, `MleVerifier`) are the on-chain analog."

`doc/audit/audit28-06-2026.md:286-290` puts `MleVerifier.sol` and *"every
`ChannelSettlementVerifier.sol` entry (proof body)"* in the **CRYPTO ORACLE** bucket.

**This exclusion is legitimate and correctly stated.** `Plonky2GateEvaluator.sol` was never in
scope; `src/circuits/channel/` (which contains `withdrawal_claim_circuit.rs` and
`post_close_claim_circuit.rs`) was explicitly excluded. A confirming grep: the strings
`Plonky2GateEvaluator`, `gateId`, `gatesDigest` and `gate set` appear **nowhere** in `doc/audit/`.

The gap is not that the boundary was drawn — it is that **"treated as a verified oracle" was never
paired with an obligation to discharge it**. Nothing in the corpus says "someone must independently
establish that the deployed `MleVerifier` accepts the proofs this repo produces."

---

## 4. The soundness/completeness asymmetry — hypothesis tested

**Your hypothesis is confirmed for the Lean development, and confirmed with a twist you did not
anticipate. It is *refuted* for audit622's stated threat model, which makes the outcome worse, not
better.**

### 4.1 The Lean development is 100% soundness-shaped — measured

Across 44 `.lean` files / 11,439 LOC / **263 top-level declarations** (262 `theorem`, 1 `lemma`,
0 `axiom`, 0 `sorry`):

| Category | Count |
|---|---|
| Soundness-shaped (`Constraints → spec`, `call succeeded → property`) | 174 |
| Satisfiability / anti-vacuity ("this constraint set is not contradictory") | 20 |
| Structural / plumbing | 69 |
| **Liveness / honest-exit ("an honest user can always withdraw")** | **0** |

The modelling principle is stated one-directionally in `doc/audit/zkp/README.md:26-30`:

```
Constraints : inputs → outputs → Prop        -- conjunction of every emitted gate
nativeSpec  : inputs → outputs               -- the intended (honest) semantics
theorem sound : Constraints i o → o = nativeSpec i
```

The 20 existence-shaped theorems are all explicitly labelled *anti-over-constraint guards*, never
exit guarantees — e.g.
`doc/audit/zkp/Zkp/Circuits/Withdraw/SingleWithdrawalCircuit.lean:540-546`:

> "**Completeness direction / vacuity guard.** … the FULL `Constraints` is satisfiable. In
> particular no conjunct of the model is an unprovable strengthening: the hypothesis list cannot be
> contradictory."

That is satisfiability of a *constraint system*, not acceptance by a *verifier*. Conversely, **nine**
theorems prove that a call *must* revert (`withdrawLeaf_nullifier_once`, `claim_no_double`,
`reclaim_no_double`, …). The corpus formalises the anti-liveness direction only.

Confirming negative: a grep for liveness vocabulary across the Lean artifact finds no formal
statement; the only hits are prose in `doc/audit/zkp/tasks/F-WD-2-threatmodel.md:84`, where liveness
appears solely as a *reason to reject a design* — *"Option A (strictly-increasing): NO-GO as
specified — LIVENESS BLOCKER"*.

### 4.2 The twist: the verifier is not assumed complete — it is worse than that

You hypothesised that the model might assume the verifier "accepts iff the statement holds", which
would assume completeness away. **It does not.** `doc/audit/zkp/Zkp/Contracts/Assumptions.lean`
contains no `axiom`; the verification result enters as a free, unconstrained `Prop`
(`doc/audit/zkp/Zkp/Contracts/IntmaxRollupWithdraw.lean:286-291`):

```lean
def withdrawNative (s : RollupState) (ws : List Withdrawal)
    (mleVerified pisBound : Prop) [Decidable mleVerified] [Decidable pisBound]
    (extCommitment : Word) : Call RollupState :=
  if mleVerified ∧ s.finalizedStateRoots.get extCommitment = true ∧ pisBound
  then withdrawLoop s ws
  else none
```

and the knowledge-soundness bridge is explicitly one-directional
(`doc/audit/zkp/Zkp/EndToEnd.lean:811-819`): `mleVerified → pisBound → ∃ witness …`. There is no
converse field in the 22-field `BridgeAssumptions` record.

**The consequence is sharper than the one you posited.** Because nothing in the corpus ever asserts
that anything *is* accepted, a verifier that rejects every honest proof makes `mleVerified`
permanently false, `withdrawNative` permanently `none`, and **every theorem in the development
vacuously true**. The model cannot distinguish a correct verifier from a brick. The headline theorem
takes success as a *hypothesis* (`doc/audit/zkp/Zkp/EndToEnd.lean:1106-1259`):

```lean
theorem end_to_end_payout_sound
    (hreach : erun s0 ops = some s)
    (hcall  : withdrawNative s ws mleVerified pisBound extC = some s')
    (A : BridgeAssumptions F allowMleDisabled ops ws mleVerified pisBound extC) :
```

`hcall` is an assumption. A system in which `withdrawNative` *never* returns `some` satisfies this
theorem perfectly.

The meta-audit came within one step of naming this. `doc/audit/audit02-07-2026.md` §1 item 8:

> "**Methodology: no completeness guard.** One completeness lemma in the whole artifact; an
> over-constrained transcription would never be caught."

It correctly diagnosed missing completeness — and then scoped the remedy to *transcription fidelity*
(is my Lean model an over-constrained copy of the Rust?) rather than *system liveness* (can an
honest user actually exit?). The word "completeness" was used for the modelling activity, and the
system-level meaning was never reached.

Finally, the residual-trust list — the corpus's own statement of what it does *not* cover
(`doc/audit/zkp/Zkp/EndToEnd.lean:1196-1285`, 7 numbered items) — contains **no liveness /
availability / honest-exit residual**. All seven are soundness residuals.

### 4.3 Refutation: audit622 *did* have liveness in its threat model

This is why "the threat model was soundness-only" is not the full answer. `doc/audit/audit622.md:6`
names liveness as a focus, and the report contains genuine liveness findings:

- `doc/audit/audit622.md:104` A-M1 — "Challenge deadline resets on every replacement (**liveness
  griefing**)"
- `doc/audit/audit622.md:141-146` A-M4 — severity "**MEDIUM (liveness bricking)**":
  > "**Issue:** Some deploy scripts omit `initializePostCloseClaimVk` / `initializeCancelCloseVk`.
  > **Paths revert fail-closed until deployer completes init.**"
- `doc/audit/audit622.md:287` B-M4 — "Stale balance attestation blocks close after inter-channel",
  severity "MEDIUM (liveness)"

**A-M4 is the same defect class as gate 8**: a fail-closed revert, soundness-safe, that makes an
honest exit path impossible. The audit found one instance of the class and did not generalise it
into a property, a test requirement, or a scope item. That is the precise process failure — not
absence of liveness thinking, but **failure to promote a one-off liveness finding into a systematic
check.**

And the classification that made generalisation unlikely is
`doc/audit/audit28-06-2026.md:291`:

> "**LIVENESS / VIEW** (no escrow effect): `_truncateSubmissions`, `_rollbackBatch`, getters,
> constructor/init."

Liveness is defined here as the bucket for things that *do not move funds* — hence not worth
modelling. Bricking the exit path moves funds by exactly the amount that never leaves.

---

## 5. It was noticed — twice — and correctly escalated both times

Your recollection is accurate. `doc/tasks/falcon-sig-phase2_5-notes.md:186-194` (commit `a5efa10`,
**2026-08-05**, four days before the E2E hit it):

> "3. **Pre-existing, unrelated finding surfaced by the review (NOT introduced here, NOT fixed
>    here):** `contracts/test/data/withdrawal_claim_mle.json:1939` and
>    `contracts/test/data/post_close_claim_mle.json:1946` contain
>    `ExponentiationGate { num_power_bits: 66 }` → `gateId 8`, which `Plonky2GateEvaluator.sol`
>    explicitly does not support (`:29-34`, revert at `:222-225`). **No Forge test reads those two
>    fixtures.** This predates Phase 2.5 and is reported to the owner as a separate issue."

and repeated in that document's follow-ups (`:402-404`):

> "The `ExponentiationGate` (`gateId 8`) present in `withdrawal_claim_mle.json` and
> `post_close_claim_mle.json` is an **EXISTING on-chain-revert hazard** unrelated to this change
> … and needs its own investigation."

**Assessment of that judgement: it was correct.** The reviewer was scoped to one file
(`src/falcon_sig/gadget.rs`), identified the defect precisely including the exact fixture line
numbers, identified the reason it was invisible (no Forge test reads those fixtures), declined to
fix it out of scope, and escalated. That is the process working as designed. The same review also
named the *systemic* root cause (`doc/tasks/falcon-sig-phase2_5-notes.md:180-185`):

> "2. **Wrapper gate-set drift is a silent on-chain hazard in general.** Nothing in the Rust
>    pipeline asserts that the wrapper's gate set is within the 13 Solidity-supported IDs;
>    `mle/src/fixture.rs:511` maps unknown gates to `gateId 255`, producing a well-formed fixture, a
>    valid `gatesDigest`, a PASSING Rust `mle_verify`, and an **on-chain REVERT**."

Second sighting, `doc/tasks/b2-implementation-notes.md:645-719` (commit `4574348`, 2026-08-09),
under the heading *"NEW blocker (pre-existing, NOT caused by this fix)"*, with four independent
arguments that it was not introduced by the work in hand, and:

> "**ESCALATED, NOT PATCHED.** … Owner decision required."

**What actually went wrong between 08-05 and 08-09 is a handoff gap, not an analysis gap.** The
2026-08-05 note recorded the defect in a *task* document (`doc/tasks/`), not in an *audit* document
(`doc/audit/`), and not in any tracked findings register. Four days later a different workstream
rediscovered it from scratch by running the E2E. There is no open-findings ledger that a task note
can be written into and that a later reader would consult.

---

## 6. The test-coverage blind spot

**When it opened:** `1031f38` (**2026-06-18**) — `feat(settlement): replace ChannelSettlementVerifier
stubs with real on-chain ZK (A1)`. The same commit that made the claim path real-proof-gated
on-chain also introduced the comment that declines to test it. Verified with `git log -L` on
`contracts/test/CloseLifecycleE2E.t.sol`; the text has been carried forward unchanged and now sits
at `:244-252`:

> "Phase B-D: `submitWithdrawalClaim` now runs a REAL `verifyWithdrawalClaim` MLE/WHIR verification
> (no more stub proof). Driving it here would require a withdrawal-claim MLE fixture … + VK
> co-generated with THIS lifecycle's member set / finalized H1, which this generator pair does not
> yet produce … The withdrawal-claim binding + payout is exercised **independently by the
> mock-verified `ChannelSettlementManager.t.sol`** (real 48-limb strict bind) and the
> withdrawal-claim circuit's own Rust tests. **Stop here rather than fabricate a stub proof on a
> value path.**"

The decision itself is defensible — fabricating a stub proof on a value path would have been worse.
**But the comment contains a coverage claim that is true only on the soundness axis.** The claim
*"exercised independently by the mock-verified `ChannelSettlementManager.t.sol`"* is accurate about
the **binding** (does the contract bind the right fields?) and silent about the **verification**
(does `MleVerifier` accept the proof?). The mock verifier returns true unconditionally, so exactly
the thing that was broken is exactly the thing the mock stubs out. A reader auditing coverage would
read that sentence as "covered".

**Did the audit note the gap?** No. audit622 was written four days after the gap opened, has the
claim path in scope, and its recommendation #15 (`doc/audit/audit622.md:504`) asks for *more* manager
tests — *"Manager tests — withdrawal nullifier replay, challenge deadline extension"* — both
soundness-shaped. No recommendation anywhere in `doc/audit/` asks for a real-proof on-chain
verification test of any claim path.

**Current state of the gap (still open at HEAD `898a586`):** no `.t.sol` reads
`withdrawal_claim_mle.json`, `post_close_claim_mle.json`, or `cancel_close_mle.json` — only the
deploy scripts do. `contracts/test/ExponentiationGate.t.sol` (added by the fix) is unit vectors
against `_evalExponentiation`; it never calls `MleVerifier.verify`. Every settlement-verifier
Foundry test wires `MockMleVerifier`. The only real-proof claim test is
`tests/close_lifecycle_cli_e2e.rs:270`, which is `#[ignore]`d.

---

## 7. The generalisable lesson: what else of this shape is here today

**The defect class:** *a fail-closed check that is soundness-perfect and liveness-fatal, on a path
no test exercises with real artifacts.* Every element of that sentence is load-bearing — the reason
this class evades review is that each element independently looks like good practice (fail closed;
don't fabricate stub proofs; treat the verifier as an oracle).

Candidates found by a dedicated sweep, ranked. **Confirmed** = there is positive evidence an honest
path hits it.

### CONFIRMED

**L1 — `cancelClose` and `submitPostCloseClaim` are bricked on the production deploy path.**
This is audit622 A-M4, still open 7 weeks later, and it is the *closest possible sibling* of the
gate-8 defect.
- `contracts/src/ChannelSettlementVerifier.sol:1050` `revert CancelCloseVkNotSet()`
- `contracts/src/ChannelSettlementVerifier.sol:1111` `revert PostCloseClaimVkNotSet()`
- Verified: `contracts/script/DeployCloseCli.s.sol` (named the "CLI/prod path" by
  `doc/tasks/regen-and-redeploy-runbook.md:147`) calls `initializeCloseVk` and
  `initializeWithdrawalClaimVk` **only**. **No script in the repo calls
  `initializePostCloseClaimVk`.** `initializeCancelCloseVk` is called only by
  `DeployWalletSettlement.s.sol` and `DeployPartialWithdrawalE2E.s.sol`, both anvil-only mock stacks.
- **Documentation overclaim:** `doc/tasks/regen-and-redeploy-runbook.md:143-146` states *"The
  per-statement VKs are initialized IN the deploy scripts from the regenerated fixtures: …
  `initializePostCloseClaimVk(...)`, `initializeCancelCloseVk(...)`"*. That is false for
  `DeployCloseCli.s.sol`. A reader following the runbook ships a chain on which `cancelClose` — the
  only on-chain remedy against a stale close — cannot be called.
- Both are live user-facing commands: `src/bin/channel_member.rs:1988-2025` (`cancel-close`) and
  `:2152-2184` (`post-close-claim`).
- **Zero tests** drive either with a real MLE proof.

**L2 — the systemic root cause is still completely unguarded.**
`contracts/lib/polygon-plonky2/mle/src/fixture.rs:510-512`:
```rust
} else {
    (255, 0, 0, 0)
}
```
Nothing in the repository references `gate_id == 255` or any supported-gate set — no assertion, no
test, no CI check; `src/utils/mle_prover.rs` has none. Meanwhile
`contracts/lib/polygon-plonky2/mle/src/constraint_eval.rs:96-99` states the Rust evaluator "handles
ALL gate types". **An unknown gate therefore yields a well-formed fixture, a valid `gatesDigest`, a
passing Rust `mle_verify`, and an on-chain revert, with no signal until a real submission on a real
chain.** This is the mechanism by which gate 8 shipped, and it is unchanged.

**L3 — post-deployment delegates cannot begin any exit.**
`contracts/src/ChannelSettlementManager.sol:852` `revert NotChannelMember()` (`requestClose`) and
`:1152` `revert PartialWithdrawalRecipientNotParticipant()`. Both gate on `isMemberRecipient`, which
is written **only** in the constructor (`:751`, `:809`) — there is no setter. Under Option B, L1
registration is cosigners-only, so a delegate who joins after deployment has no on-chain way to
start an exit. The asymmetry is the tell: `submitWithdrawalClaim` / `submitPostCloseClaim` were
deliberately converted to *proof-enforced* membership (`:1266-1273`, `:1333-1337`) for exactly this
reason; these two were not.

**L4 — `DeployCloseCli` never calls `registerSettlementManager`.**
`contracts/src/IntmaxRollup.sol:787` `revert NotRegisteredSettlementManager()`. The call appears only
in `DeployWalletSettlement.s.sol:117` and `DeployPartialWithdrawalE2E.s.sol:128`, both
`chainid == 31337`-gated. On the prod path, a user burns channel-side, waits the full challenge
window, and then `finalizePartialWithdrawal` reverts — with the burn already committed.

### PLAUSIBLE

- `contracts/src/ChannelSettlementManager.sol:1156` `PartialWithdrawalChainUsed` — `chainKey` is
  consumed at finalize (`:1201`) while `authDigest` (`:1167-1176`) is built from *caller-supplied*
  fields. One mismatch and the authorization is burned with no way to re-mint it.
- `contracts/src/IntmaxRollup.sol:1494` / `:1554` `WithdrawalNullifierUsed` — inside the per-leaf
  loop, so one already-paid leaf reverts the entire batch. Breaks natural re-aggregation and races
  two honest submitters.
- `contracts/src/IntmaxRollup.sol:1493` / `:1552` `WithdrawalNotEthToken` / `WithdrawalNotErc20Token`
  — a chain mixing asset classes is payable by neither entry point; the separation is enforced only
  by convention in `src/wallet_core.rs:4749-4763`, not by the circuit or the contract.
- `contracts/src/IntmaxRollup.sol:1078` `ChannelAlreadyRegistered` + `ChannelSettlementManager.sol:775`
  `MemberSetMismatch` — `registerChannel` is permissionless and one-shot; a cosigner rotation leaves
  a channel that can neither close nor re-register.

### LATENT (one change away)

- **Lookup gates.** The Solidity `MleVerifier` has **no `num_luts` guard**; the *only* on-chain
  protection is the gate-id revert at `Plonky2GateEvaluator.sol:235`. Porting `LookupGate` without
  the logUp argument would silently make that guard vacuous — converting this liveness bug into a
  **soundness** bug. Rust fails closed (`mle/src/prover.rs:406-411`, `verifier.rs:136-139`). Inert
  today only because Phase 2.5 was rejected.
- `CosetInterpolationConstants.sol:69` / `:79` — `subgroup_bits` supported for 1–5 only; fixtures use
  4. Identical shape, one circuit change away.
- `SumcheckVerifier.sol:39` `"Wrong number of rounds"` — `degreeBits` is baked into a set-once VK;
  any circuit growth permanently invalidates the deployed VK.

### Prior art in-repo — the class has bitten before and was fixed silently

`src/circuits/channel/withdrawal_claim_circuit.rs:362-364` documents an already-fixed instance, in
the correct vocabulary:

> "the former 8-bit check was a stale MAX = 16 leftover that would have REJECTED legal states with
> active > 255 (**completeness, not soundness**)."

That fix was never generalised into a property or a checklist item either. Two independent
occurrences plus audit622 A-M4 make three; this is a pattern, not a coincidence.

### Gate-coverage status at HEAD (for the record)

Every `*_mle.json` in `contracts/test/data/`, gate ids extracted and cross-referenced against the
current evaluator (ids 0–13):

| fixture | degreeBits | numSelectors | gate ids |
|---|---|---|---|
| the 10 validity / withdrawal / close / cancel fixtures | 13 | 3 | 0,1,2,3,4,5,6,7,9,10,11,12,13 |
| `withdrawal_claim_mle.json`, `post_close_claim_mle.json` | 13 | **4** | 0,2,3,4,5,6,7,**8**,9,10,11,12,13 |

No fixture carries gate id 255 or any id the evaluator now lacks. The two claim fixtures are the
sole outliers (gate 8 present, `ConstantGate` absent, `numSelectors` 4) — a genuinely distinct
layout, and the only one that hit the gap.

---

## 8. Process recommendations

Ordered by ratio of defects-caught to effort. Each is specific to an artifact in this repo.

### R1 — Add one property to the audit vocabulary: **Honest-Exit Availability (HEA)**

State it once, in `doc/audit/zkp/README.md` alongside the `theorem sound` schema, and require it per
exit path:

> **HEA.** For each exit path P ∈ {`withdrawNative`, `finalizePartialWithdrawal`,
> `submitWithdrawalClaim`, `submitPostCloseClaim`, `cancelClose`, `finalizeClose`}: there exists a
> reachable state and an honestly-generated witness for which P returns `some` on a
> **default-deployed** chain. Any `revert` on P that is not a function of adversarial input is a
> finding at severity ≥ MEDIUM.

The Lean corpus already has the right machinery — the four "inhabitation" theorems
(`doc/audit/zkp/Zkp/Contracts/IntmaxRollupSolvency.lean:174` `claim_trace_satisfiable`,
`IntmaxRollupStake.lean:275`, `ChannelSettlementManager.lean:341`,
`ChannelSettlementManagerMT.lean:413`) are exactly this shape, written for anti-vacuity. **Promote
inhabitation from an anti-vacuity guard to a required per-exit-path obligation**, and add the four
missing ones. Cheap: the pattern exists and compiles.

Note what HEA would *not* have caught: the Lean model treats the verifier as an unconstrained `Prop`,
so HEA in Lean cannot see gate 8. HEA is necessary for L1/L3/L4; **R2 is what catches gate 8.**

### R2 — Require a real-proof on-chain test per verifier-gated entry point (this is the one that catches gate 8)

Add Foundry tests that call `MleVerifier.verify` (never `MockMleVerifier`) against the checked-in
fixtures for **every** verifier-gated function:

| entry point | fixture | exists today? |
|---|---|---|
| `withdrawNative` / `finalize` | validity / withdrawal | yes |
| `submitCloseIntent` | `close_intent_mle.json` | yes (`CloseLifecycleE2E`) |
| **`submitWithdrawalClaim`** | `withdrawal_claim_mle.json` | **no** |
| **`submitPostCloseClaim`** | `post_close_claim_mle.json` | **no** |
| **`cancelClose`** | `cancel_close_mle.json` | **no** |

These need no proving — the fixtures are checked in. A "verify-only" test that asserts
`MleVerifier.verify(...)` does not revert, decoupled from the member-set / H1 co-generation problem
that `CloseLifecycleE2E.t.sol:244-252` correctly declines to fake, is sufficient and cheap. **Make
"a mock verifier is used" a mandatory disclosure** in any coverage claim: amend the comment at
`contracts/test/CloseLifecycleE2E.t.sol:244-252` so the sentence about
`ChannelSettlementManager.t.sol` says *binding only, mock verifier, proof acceptance untested*.

### R3 — Assert the gate-set invariant in Rust, where the drift originates

`contracts/lib/polygon-plonky2/mle/src/fixture.rs:510-512` must not silently emit `255`. Add a
hard error there (or in `src/utils/mle_prover.rs`) listing the Solidity-supported id set, plus a
cheap Rust test that reads every `contracts/test/data/*_mle.json` and asserts each gate id is
supported. This converts the entire class from "found by incident on a real chain" to "found by
`cargo test`", and would have caught gate 8 on 2026-07-31 at commit `89cd044` — the moment it was
introduced. **Highest value-to-effort item in this document.**

### R4 — Fix the two documentation overclaims

- `doc/audit/audit622.md:6` — "Focus: Fund solvency and **system liveness**". Either narrow to
  *"liveness considered opportunistically; no systematic honest-exit analysis performed"*, or back it
  with R1/R2.
- `doc/tasks/regen-and-redeploy-runbook.md:143-146` — claims `DeployCloseCli.s.sol` initializes all
  four VKs. It initializes two. Fix the script (preferred) or the runbook.
- `doc/audit/zkp/Zkp/EndToEnd.lean:1196-1285` (RESIDUAL TRUST SURFACE, 7 items) — add an 8th:
  *"Verifier completeness. Every theorem here is conditioned on the verifier accepting. A verifier
  that rejects all honest proofs satisfies this development vacuously."*
- `doc/audit/audit28-06-2026.md:291` — the "**LIVENESS / VIEW** (no escrow effect)" bucket conflates
  two unrelated things. Split it: view functions have no escrow effect; **liveness failures on exit
  paths have the maximal escrow effect.**

### R5 — Add a findings ledger so escalations survive a workstream boundary

Gate 8 was correctly identified on 2026-08-05 in `doc/tasks/falcon-sig-phase2_5-notes.md:186-194`,
and independently rediscovered on 2026-08-09. The analysis was never the bottleneck; the *routing*
was. A single `doc/audit/open-findings.md` with one line per escalated item (id, date, severity,
one-line description, status), which any task note must append to when it escalates and which any
new workstream reads first, closes this. Seed it with L1–L4 from §7.

### R6 — Make the "oracle" boundary carry an obligation

Wherever the corpus writes "treated as a verified oracle"
(`doc/audit/audit28-06-2026.md:95-99`, `doc/audit/zkp/Zkp/Contracts/Coverage.lean:122`), require a
named counterparty and a discharge mechanism, exactly as
`doc/audit/zkp/Zkp/Contracts/Assumptions.lean` already does for the four named trust assumptions.
"`MleVerifier` is an oracle" should read "…discharged by R2's real-proof tests + R3's gate-set
assertion", not stand as an unowned exclusion.

### R7 — Add one line to the CLAUDE.md cryptographic invariant checklist

The checklist under §"Cryptographic Invariant Checklist" is entirely soundness-shaped, which
faithfully mirrors this defect. Add a **Completeness / Liveness** block:

```
- [ ] Every fail-closed check added is classified: does it reject only ADVERSARIAL
      inputs, or can an HONEST input reach it? If honest inputs can reach it, that is
      a finding, not a safety feature.
- [ ] Any change to a circuit's gate set, degree bits, or FRI parameters re-verifies
      the on-chain verifier's capability against the NEW fixture, not the old one.
- [ ] "Verifier accepts" is asserted by at least one test using the REAL verifier,
      not a mock, for every verifier-gated entry point.
```

---

## 9. Answer to the question, stated plainly

The audit did not catch it because **the defect did not exist when the audit was written** — gate 8
entered the fixtures on 2026-07-31, five weeks after audit622 and four weeks after the Lean
development. Additionally, `Plonky2GateEvaluator.sol` was legitimately and explicitly out of scope
in every artifact, and the entire channel claim path has no Lean model at all. On those two counts
the audit was not wrong; it was not asked.

Three things are nonetheless genuinely attributable to the process:

1. **A scope statement overclaims.** `doc/audit/audit622.md:6` names "system liveness" as a focus.
   The delivered liveness work is three incidental MEDIUM findings. Nothing systematic was done, and
   no artifact says so.
2. **The class was found and not generalised.** audit622 A-M4
   (`doc/audit/audit622.md:141-146`, "MEDIUM (liveness bricking)", fail-closed reverts on
   `postPostCloseClaim` / `cancelClose` VK init) is the same defect class as gate 8. It was found on
   2026-06-22, is still open at HEAD, and was never turned into a property, a test, or a scope item.
   `src/circuits/channel/withdrawal_claim_circuit.rs:362-364` is a third instance, fixed silently.
3. **The test-coverage gap opened four days before audit622, on an in-scope path, and was never
   flagged** — and the comment documenting it
   (`contracts/test/CloseLifecycleE2E.t.sol:244-252`) makes a coverage claim that is true on the
   soundness axis and misleading on the liveness axis, because the cited alternative uses a mock
   verifier that stubs out precisely the thing that was broken.

The lesson is not "do more liveness analysis". It is narrower and more actionable: **this codebase
systematically treats fail-closed as a synonym for safe.** It is safe on one axis only, and the
other axis has no owner, no property, no test, and — at
`doc/audit/audit28-06-2026.md:291` — a classification label that explicitly marks it as not
fund-relevant. R2 and R3 are the two changes that would have caught gate 8 mechanically, on the day
it was introduced, at negligible cost.
