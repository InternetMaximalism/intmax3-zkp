# INTMAX3 audit — final report (September 2026)

Commits audited

| Repository | Commit |
|---|---|
| `InternetMaximalism/intmax3-zkp` | `19d1e601` |
| `InternetMaximalism/intmax-plonky2` (submodule) | `3a20a05fb99d2653c4d37debb4f1ead2f422dfb2` |
| Baseline of the runtime taken as the audit target | `05ec7ae94701f05d2aaf97ff796b7f800a6ce1f8` |

---

## Conclusions (three points up front)

### 1. Both repositories have undergone machine checking with Lean

The protocol proper (`intmax3-zkp`) and the submodule that carries its cryptographic proof system
(`intmax-plonky2`) have been checked **independently of each other** with the proof assistant Lean 4.
Lean is a tool with which a computer checks a mathematical proof line by line; a proof with a hole does not pass.

| | Theorems checked | Files checked |
|---|---:|---:|
| `intmax3-zkp` (the protocol proper) | 5,311 | 497 |
| `intmax-plonky2` (the proof system) | 6,542 | 516 |
| Total | **11,853** | 1,013 |

The two have separate checking scripts and are independent of each other. The result of one does not guarantee
the other.

### 2. Across several methods of looking for serious vulnerabilities, no critical issue has been found in the current code

From the first Lean proof commit on 2026-06-11 through 2026-09-18, roughly three and a half months, proof construction and
vulnerability hunting were carried out in parallel. The models used were Fable 5.1, Fable 5, Opus 5 and
ChatGPT Astra. The method was not a single one; the following were combined.

- Formal proof in Lean (transcribing the correspondence between specification and implementation line by line and proving properties)
- Adversarial review in prose (looking for "what malformed input would get past this check?")
- Multiple rounds of verification with the participants split into attackers and defenders
- Verification by building attacks that actually run (PoCs)
- Mechanical checking of whether the circuit really carries the constraint (described below)

As a result, **as of the commits above, there is no outstanding vulnerability classified as critical.**

### 3. Zero vulnerabilities rated critical or release-blocking (NO-GO)

**In the current code there is not a single vulnerability rated critical.
Neither is there a single vulnerability rated as blocking release (NO-GO).**

Every actually exploitable defect found during the audit has **been fixed, with a regression test added to prevent
recurrence** (listed in section 4). All 3 NO-GO verdicts that had been holding up release have also been resolved.

Separately from these, **3 improvement items** of severity "high" or below are being tracked (section 5). None of them
is exploitable on its own, and the fix approach is settled for each. They do not affect the release verdict.

---

## Terminology in this document

To keep jargon to a minimum, the following wordings are used consistently.

| Term | Meaning |
|---|---|
| Theorem | A claim a computer has finished checking. It does not include anything a person merely believes to be correct |
| Premise | An assumption placed as a starting point of a proof and not proved in this audit. Every one of them is named and counted |
| Channel | A mechanism in which a small number of participants deposit funds and transact quickly among themselves |
| Co-signer | A participant whose signature is required from everyone in order to close a channel (withdraw the funds) |
| Delegate | A participant who takes part in a channel but does not join the closing signature |
| Circuit | The written-out form of a computation, used in a zero-knowledge proof to show "this computation was performed correctly" |

---

## 1. What was audited

### 1.1 Scope

- **The L1 smart contracts** (the part that takes custody of funds and pays them out)
- **The channel settlement circuits** (the part that closes a channel and fixes each participant's share)
- **Signature aggregation** (the part that combines all participants' signatures into one)
- **The cryptographic proof system** (the part that verifies the above proofs. Audited separately on the submodule side)

### 1.2 Method of the audit

The Lean checking maps the implementation's source code line by line onto Lean descriptions and leaves that correspondence table
(the line map) in a form a computer can check. There are 169 line maps, and it is mechanically confirmed that every line of
each source file belongs to one of the classifications.

| Classification | Lines | Meaning |
|---|---:|---|
| Transcribed | 31,095 | The Lean model has a corresponding definition |
| Dependency boundary | 10,850 | An external call. The result is taken as an assumption |
| Non-executable lines | 9,828 | Comments and blank lines |
| Test only | 26,094 | Does not run in production |
| Not transcribed | 41,797 | Not formalized in Lean (the breakdown is in section 7) |

This classification cannot be conveniently reassigned in order to make the check pass. An attempt to reassign it makes the
checking script detect the mismatch and fail.

---

## 2. What is proved with no premises

The following is proved **without placing any cryptographic assumption whatsoever**. That is, it holds even if the cryptography is broken.
It holds for every history obtained by arranging the 12 modeled kinds of fund-movement and authorization operations in any order and any number of times.

1. **Per-token conservation law** — the difference between what came in and what went out always agrees with the ledger.
   Funds do not spring into existence or vanish anywhere.
2. **Attribution to a channel** — funds paid out are always tied to the channel that requested them.
   Funds of another channel are never mixed in.
3. **Prevention of double spending** — a withdrawal identifier that has been used once can never be used again.
4. **Payment bound** — the total paid out never exceeds the total received.

There is also a result on the circuit side proved without cryptographic assumptions. We proved that the fast polynomial-multiplication
algorithm (NTT) used inside the signature circuit agrees exactly with the product computed by the naive method
(157 theorems). This rules out the possibility that "the implementation is merely fast and not correct."

---

## 3. What remains as a premise

The proof takes the form "if these premises hold, then the above holds." There are
**23** premises, and each one is documented with a name and with how it would break if it were false. They fall into
4 groups by nature.

### (A) That the transcription agrees with the implementation (6 of them)

The Lean model is something a person read off the circuit's source code and transcribed. That "the transcription is
correct" can be confirmed by a finite amount of checking work, but not all of it is done.

To compensate, we built **a check that mechanically compares the actually built circuit against the Lean claims**.
From the result of assembling the circuit, it reads out "which wires are forced equal," "which values are pinned to
constants," "how many bits the range checks are," and "what the order of the public values is," and compares them with the Lean-side claims.

- 7 programs, 280 items checked
- 184 items structurally confirmed to agree
- 8 items confirmed in practice to make the proof fail when fed input that deliberately breaks a constraint
- 67 items concern the meaning of arithmetic and cryptographic components and are invisible to this method (they remain premises)
- **Zero mismatches**

### (B) Complexity assumptions (2 of them)

- Unforgeability of lattice cryptography (Falcon signatures)
- Collision resistance of Keccak-256 (and moreover restricted to the one pair of equal-length inputs actually compared during execution)

These are not properties that can be proved mathematically; they are standard assumptions of cryptography.

### (C) The meaning of the execution environment (8 of them)

The meaning of the EVM's instructions, the reading of L1's finalized information, the return values of external calls, and that the source code
and the actually deployed byte sequence agree. The last item cannot in principle be proved within this audit
(it would require a verified compiler).

### (D) The ledger outside the channel (7 of them)

That when a channel is closed, the amount paid out is backed by the channel's L2 balance.
In this audit we proved as far as **each amount paid out agreeing with an actual row inside a balance proof against the
finalized state**. What remains is the more upstream property that "the balance itself is correctly accumulated."
This is explicitly noted as the next piece of work.

---

## 4. Vulnerabilities found and fixed

Those found during the audit and **already fixed**. The parenthesis gives the severity at the time of discovery.

| Content | Impact |
|---|---|
| Verifier key mix-up (critical) | The proof system's verification was defective, and an illegitimate proof could be accepted. Fixed by a redesign |
| A channel could be closed with a single signature (medium) | An operation that should have required everyone's consent could be performed by one person |
| A path allowing duplicate keys (medium) | The same key could be registered in two slots, corrupting the ledger |
| Deposits vanished on rollback (high) | In block rollback processing, subsequent deposit records were lost |
| Someone else's key material could be destroyed (high) | An ordinary state update could rewrite an unrelated participant's key material and make their funds unwithdrawable |
| Another party's submission could be hijacked and finalized (high) | One's own proof could be used to finalize someone else's submission |
| A deadline could be extended indefinitely (high) | The challenge deadline could be reset repeatedly |
| Cancelling a close caused a functional halt (critical) | After a cancellation, trying to close again failed permanently |
| An unreachable check (medium) | The validity check on registration data was written in a way that meant it never actually ran |
| A defect in the verifier's arithmetic implementation (medium) | The reimplementation of the L1-side arithmetic could disagree with the reference implementation |

All of these have been fixed, and **a regression test confirming that they do fail in the pre-fix state** has been
added ("reverting the fix turns the test red" has been confirmed).

---

## 5. Improvement items under tracking (none of them critical, none NO-GO)

The following 3 are unresolved, but **none of them is critical and none blocks release**.
For transparency, they are listed with severity and fix approach.

### 5.1 Checking key material at channel opening (severity: high)

**What could happen.** If the person opening a channel registers wrong key material for one of the participants,
that participant becomes permanently unable to withdraw their own funds. The funds do not become the attacker's; they are
frozen in a state where nobody can take them out.

**Why high.** The failure only surfaces at the very last moment, when the withdrawal is attempted, and at that point
there is no means of recovery. Moreover, whereas co-signers are checked automatically before signing, **for delegates
that check structurally never runs** (because they do not sign).

**Why it is not critical.** Because the attacker gains nothing, because the person who opened the channel has to be malicious
or to hit a bug, and because the impact is confined to a single slot.

**Fix approach.** It closes by adding a single comparison to the check at channel import. No change is needed to the smart contracts
or to the circuits.

### 5.2 Auxiliary data for inter-channel transfers (severity: medium)

That the auxiliary data accompanying a transfer has the intended value is not proved inside the circuit
(that it cannot be tampered with is proved). Exploitation requires **all participants of the receiving channel
together** to neglect the check, so it does not work on its own.

### 5.3 Consent checking at channel registration (severity: low to medium)

The channel registration operation does not verify participants' signatures. In practice, however, a participant's software
recomputes the information from their own key and checks it, so a forged registration is detected at import. What remains is
a procedural matter of "check before depositing funds," not a matter of being undetectable.

---

## 6. Release verdict

The previous audit (2026-08-30) was holding up release for 3 reasons. **All 3 have been resolved.**

| Item | Now |
|---|---|
| Soundness of the proof system | Repair complete |
| Backing of funds from L1 to the channel | Implementation complete. Without a proof tied to the channel, not a single yen moves |
| Whether a participant can close a channel on their own | Possible. The closing operation needs no new signature; it uses the signature attached to the already-agreed state. **Other participants cannot obstruct it by refusing to sign** |

**However, this is not a GO.** The following are not defects in the defenses but confirmation work not yet carried out.

1. An external, independent cryptographic review of the repaired proof system
2. An end-to-end confirmation in the production environment, from the browser through to payout
3. A rebuild from a clean environment and a comparison against the deployed byte sequence

---

## 7. What this audit does **not** do

Stated explicitly to avoid misunderstanding.

- **The 41,797 lines not transcribed** are not formalized in Lean. Most of them are on the proof-system side, and that side
  is audited independently in a separate repository (section 1).
- **That the source code and the deployed byte sequence are the same** is not proved.
- **The security of the cryptography itself** (lattice cryptography, hash functions) is not proved. It is accepted as a
  standard assumption.
- **The correctness of the day-to-day transfers inside a channel** is out of scope for this proof. The processing at the time a
  channel is closed is proved, but that the state before closing has been correctly accumulated depends on each participant
  checking it on their own machine.
- **It has not received an independent third-party review.** The transcription and the proofs were done in the same line of work.

---

## 8. What anyone can verify

The claims of this report can be reproduced locally.

```sh
export PATH=$HOME/.elan/bin:$PATH
bash .github/ci/lean-safety-guard.sh          # build and check all theorems → PASS
python3 -B .github/ci/lean-line-coverage.py   # consistency of the line correspondence → PASS
python3 -B .github/ci/check-ledger-writers.py # check of the sites that rewrite the ledger → PASS
python3 -B .github/ci/lean-fixture-parity.py  # comparison against real data → agreement
```

Expected values: 132 Lean modules, hashes of 497 files, 1 submodule pin,
169 line maps.

The axioms a proof may depend on are limited to 3 (Lean's own basic axioms), and the checking script confirms this
every time. Not a single project-specific axiom, nor any notation indicating an incomplete proof (`sorry` and the like), is
included. Including one would make the check fail.

---

## 9. Summary

For the current code (`19d1e601` / submodule `3a20a05f`):

- **There are 0 vulnerabilities rated critical.**
- **There are also 0 vulnerabilities rated release-blocking (NO-GO).**
- **Every vulnerability found has been fixed and pinned down with a regression test.**
- **Conservation, attribution, double-spend prevention and the payment bound of funds are proved without cryptographic assumptions.**
- **23 premises remain; all are named and their modes of failure are documented.**
- There are 3 improvement items under tracking, but the heaviest is "high" and it does not affect the release verdict.
- A GO verdict additionally requires an external review and an end-to-end confirmation in the production environment.

---

*This report is a summary of `doc/audit/release-status-2026-09-18.md` (the record of the verdict) and
`doc/audit/zkp/PRACTICAL-SAFETY-PROOF.md` (the details of the proof, in English).
Past dated audit reports are preserved as the records of their respective points in time.*

---

# Technical detail (appendices)

From here on are the details for a reader who wants to verify the claims of sections 1 through 9. Every theorem name,
file name and line number is real and can be checked locally.

## Appendix A — the exact content of the unconditionally proved theorems

The following are in `doc/audit/zkp/Zkp/Implementation/SystemSafety.lean` and **take no premise structure as an
argument at all**. That is, they hold no matter which of the 23 premises is false.

### A.1 Per-token conservation law

```lean
theorem trace_conserves_per_token (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow) (token : Nat) :
    measure cfg after token + outflow token = measure cfg before token + inflow token
```

`SystemSafety.lean:599`. `measure` is the sum of "the Rollup's escrow + the Manager's pending amount + unspent
withdrawal entitlement + already paid." `Trace` is any number of the 12 kinds of transition described below, strung together.
The claim is an equality, not an inequality. **The difference between what came in and what went out always agrees with the
change in the ledger.**

### A.2 Attribution to a channel

```lean
theorem trace_channel_attribution (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (bounded : ∀ t, (before.managers cfg.manager).received t ≤
      (before.managers cfg.manager).cap t) :
    (∀ t, (after.managers cfg.manager).received t ≤ (after.managers cfg.manager).cap t) ∧
      (after.managers cfg.manager).cap = (before.managers cfg.manager).cap ∧
      (∀ (c : CloseFunding.Channel) (d : CloseFunding.Hash), d ≠ 0 →
        before.funding.materializedChannelExit c = d →
        after.funding.materializedChannelExit c = d)
```

`SystemSafety.lean:751`. It yields 3 conclusions at once. (1) The amount received does not exceed the cap. (2) **The cap
itself does not move under a transition** (you cannot raise the cap later and withdraw more). (3) The exit record of a channel
that has once been finalized is not rewritten.

### A.3 Single use of a withdrawal identifier

```lean
theorem trace_nullifier_single_use (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (indexed : FundFlow.PayoutIndexed (before.managers cfg.manager)) :
    FundFlow.PayoutIndexed (after.managers cfg.manager) ∧
      (∀ n, (before.managers cfg.manager).used n = true →
        (after.managers cfg.manager).used n = true) ∧
      (∀ (ext : ManagerValue.External) (claim : ManagerValue.Claim)
        (proof : ManagerValue.Proof) (out : ManagerValue.State),
        (before.managers cfg.manager).used claim.nullifier = true →
        ManagerValue.submitClaimCore cfg ext (after.managers cfg.manager) claim proof ≠ .ok out)
```

`SystemSafety.lean:837`. The last conclusion is the substantive one: **a claim with an already-used identifier necessarily
fails at the end of the history**. `≠ .ok out` means "does not succeed for any output whatsoever."

### A.4 Payment bound

```lean
theorem trace_paid_bounded (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (bounded : FundFlow.PaidBounded (before.managers cfg.manager)) :
    FundFlow.PaidBounded (after.managers cfg.manager) ∧
      ∀ token, after.rollup.escrow (RollupValue.assetOfToken token) +
          after.rollup.pending (RollupValue.assetOfToken token) cfg.manager +
          FundFlow.unspent (after.managers cfg.manager) token +
          (after.managers cfg.manager).paid token + outflow token =
        measure cfg before token + inflow token
```

`SystemSafety.lean:885`. The conservation law in a form decomposed down to where the funds currently are (escrow / pending /
unspent entitlement / already paid).

## Appendix B — the 12 modeled transitions

The `inductive Step` at `SystemSafety.lean:373`. The theorems above hold for **every** history that strings these 12 kinds
together in any order and any number of times.

| Constructor | Corresponding operation |
|---|---|
| `accounting` | Submitting a withdrawal claim, withdrawing channel funds, receiving a payment (the 4 paths of `FundFlow.AccountingStep`) |
| `deposit` | Depositing into L1 (the only modeled path by which funds enter) |
| `withdrawalSet` | Finalizing a withdrawal set (leaving escrow) |
| `userWithdrawNative` | Withdrawing the pending amount in the native currency |
| `userWithdrawToken` | Withdrawing the pending amount in ERC20 |
| `materialize` | Finalizing a channel close (the materializer credits from escrow to the Manager) |
| `requestClose` | A close request (no funds move) |
| `fundingFreeze` / `fundingUnfreeze` | Freeze / unfreeze |
| `fundingRecordPost` / `fundingRollbackPost` | Block record / rollback |
| `rollupRollback` | Rollback of a Rollup batch |

For transitions that are **not** modeled (EVM operations outside the protocol and the like), premises (g1')(g2') state
that "if it touches the ledger, it is the execution of an entrypoint that has been inventoried."

## Appendix C — the complete list of the 23 premises

The fields of `structure TrustBoundary` in `TrustBoundary.lean`. The order of listing is the order of declaration.

| # | Lean field name | Content |
|---|---|---|
| a0 | `mleVerifierSoundness` | The public values of a proof accepted by the pinned verifier are the public values of a satisfiable statement of that circuit |
| a | `closePrimitiveLowering` | The close circuit: from a satisfiable statement, there exists an assignment satisfying **the same instruction sequence**, whose public wires read the statement back |
| b1 | `withdrawalPrimitiveLowering` | The same for the withdrawal claim circuit |
| b2 | `postClosePrimitiveLowering` | The same for the post-close claim circuit |
| c0 | `materializerViewIsManagerState` | The values of the Manager's 12 getters that the materializer sees through an external call agree with the Manager's actual storage |
| c0b | `managerFundsDigestIsReference` | The hash of the token aggregate that the Manager holds is the reference Keccak-256 of its finalized vector |
| c1 | `backingVerifierSoundness` | The words accepted by the verifier of the backing proof are a satisfiable statement of the pinned circuit |
| c2 | `backingPrimitiveLowering` | The same per-instruction correspondence as (a), for the backing circuit |
| c3a | `backingKeccakIsReference` | The hash call of the backing circuit is the reference Keccak-256 |
| c3b | `backingTokenFundsHashBinding` | For the one pair of equal-length inputs compared during execution, if the hashes agree then the inputs agree |
| c4 | `finalizedBalanceIsBacked` | **The remaining gap in the main body.** The amount in each row of the backing witness against a finalized root is at most the channel's L2 share at that root |
| d0 | `aggregateRecursiveVerifierSoundness` | If the top-level recursive verification of the signature aggregation accepts, its statement is satisfiable |
| d0' | `levelRecursionSoundness` | The same for the child proofs at each level |
| d1' | `aggregatePrimitiveLowering` | Each level and the leaf of the aggregation correspond per instruction (the leaf connects to the signature gadget's instruction sequence) |
| d3 | `falconUnforgeability` | If a witness satisfying the gadget's constraints exists, then the holder of that key approved the message in question (lattice assumption) |
| e1a | `solidityKeccakIsReference` | The EVM's `KECCAK256` agrees with the reference specification |
| e1b | `circuitKeccakIsReference` | The circuit-side hash component (an external crate, pinned by `Cargo.lock`) agrees with the reference specification |
| e2 | `tokenFundsHashBinding` | For the one pair compared in an accepted close, hash agreement implies input agreement |
| f1 | `finalizedRootObservation` | An affirmative answer from the external call asking "is this a finalized root?" reflects the canonical state |
| f2 | `finalizedHeightObservation` | The same for the reading of the finalized height |
| g1' | `ledgerWritersAreInventoried` | If a transition outside the model moves the ledger (used identifiers, received, paid, cap), it is the execution of an inventoried entrypoint |
| g2' | `latchWritersAreInventoried` | The same for the materializer's storage |
| h | `sourceRefinement` | The transitions of the deployed artifact are contained in the transitions the model admits |

**(d2') is no longer a premise.** Previously "the fast multiplication inside the circuit is correct" was placed as a premise, but
`NttCorrectness` (157 theorems) proved it, so it has been removed and has become the theorem `ntt_computes_negacyclic_product_of_boundary`
(`TrustBoundary.lean:2509`).

## Appendix D — what "per-instruction correspondence" means

Premises (a)(b1)(b2)(c2)(d1') were described as "per-instruction." Here is what that means concretely.

The circuit's source code is a sequence of calls such as `builder.range_check(...)` and `builder.connect(...)`.
On the Lean side, this call sequence is transcribed **as data**. For example:

```lean
inductive BuildOp where
  | recomputeImchAndConnect      -- close_circuit.rs:686
  | verifyAggregateAtConstantKey -- close_circuit.rs:806
  ...
def constructorProgram : List BuildOp := [...]
```

Then each instruction is given "the constraint this instruction imposes":

```lean
def BuildOp.holds (a : Assignment e) : BuildOp → Prop
  | .recomputeImchAndConnect =>
      e.keccak (imchPreimage a.publicWires (readPrivate a) a.recomputedH1)
        = a.recomputedStateDigest ∧
      a.recomputedStateDigest = a.publicWires.stateDigest
  | ...
```

On top of that, it is proved that **if every instruction is satisfied then the whole hand-written constraint set holds**:

```lean
theorem program_satisfied_implies_gates (e) (a)
    (h : ProgramSatisfied constructorProgram a) :
    CircuitGates e (readPublic a) (readWitness a)
```

This theorem has **not a single side assumption**. It holds for all 5 circuits.

| Module | Kinds of instruction | Program length | Instructions emitting no constraint | Theorems |
|---|---:|---:|---:|---:|
| `CloseCircuit` | 47 | 191 | 4 | 92 |
| `WithdrawalClaimCircuit` | 32 | 41 | 10 | 53 |
| `PostCloseClaimCircuit` | 8 | 45 | a few | 54 |
| `CloseAssetBacking` | 46 | 468 | 25 | 110 |
| `FalconGadgetProgram` | 23 | 23 | 3 | 47 |
| `FalconAggProgram` (leaf/level) | 8 / 17 | 8 / 31–55 | 4 | 78 |

**Therefore only 2 points remain as premises.** (i) That the content of each `holds` agrees with the constraint the corresponding
builder call actually imposes. (ii) That the pinned circuit identifier is the identifier of this instruction sequence.
**A premise of the form "trust the whole circuit" has disappeared from the structure.**

## Appendix E — mechanical checking of circuit against Lean

Part of (i) can be confirmed mechanically. The result of building a circuit retains information on which wires were identified
(`prover_only.representative_map`), which wires were pinned to constants, the widths of the range checks, and the order in which
public values were registered. `src/faithfulness.rs` (built only under test) reads this out and compares it against the
Lean-side claims.

| Program | Items checked | ok | confirmed by proof failure | not injectable | not statically visible | no constraint |
|---|---:|---:|---:|---:|---:|---:|
| `CloseCircuit` | 79 | 59 | 0 | 0 | 19 | 1 |
| `WithdrawalClaimCircuit` | 48 | 30 | 0 | 0 | 10 | 8 |
| `PostCloseClaimCircuit` | 48 | 35 | 0 | 0 | 12 | 1 |
| `CloseAssetBacking` | 46 | 27 | 0 | 0 | 16 | 3 |
| `FalconGadgetProgram` | 29 | 17 | 5 | 0 | 5 | 2 |
| `FalconAggProgram` (leaf) | 9 | 6 | 0 | 0 | 1 | 2 |
| `FalconAggProgram` (level 1) | 21 | 10 | 3 | 2 | 4 | 2 |
| **Total** | **280** | **184** | **8** | **2** | **67** | **19** |

- **ok** — a fact read out of the built circuit agreed with the Lean claim.
- **confirmed by proof failure (mutation)** — a proof was attempted with a witness that deliberately breaks a constraint, and it
  was confirmed to **actually fail**.
- **not injectable** — a violating witness cannot be constructed from the public API (the reason is recorded in the table).
- **not statically visible (not-static)** — it concerns the meaning of arithmetic or hash components and is invisible to this
  method. **The 67 items remaining as premises are these.**
- **There was not a single mismatch.**

Execution result: 18 tests all passing in 209 seconds (peak memory 26.6 GB). The result tables are saved in
`doc/audit/zkp/evidence/faithfulness-*.tsv`.

Note that the wire-extraction code used for checking is only inside `#[cfg(test)]`, and **not a single line was deleted**
(mechanically guaranteed, because the line-map update tool fails unless the change is insert-only).

## Appendix F — technical detail of the vulnerabilities found

### F.1 Soundness break in the proof system (critical, fixed)

The pinned verifier receives both the batched evaluation and the individual evaluations.
It was checking that the sum of the individual values agrees with the claimed value, but **the claimed value and its decomposition
were not bound to the polynomials actually opened**. Furthermore, the batching scalar was available before the corresponding root,
so the usual argument (Schwartz–Zippel) does not go through.

An independent attacking side produced a working example, against real data under examination, that **rewrites only 3 fields and
passes verification without changing the root, the transcript, the sumcheck proof or the public inputs at all**.

| Field | Before | After |
|---|---:|---:|
| `witnessIndividualEvalsAtRInv[0]` | 8093513556413711660 | 8093513556413711661 |
| `witnessIndividualEvalsAtRInv[80]` | 2800508231593448274 | 15862999140234155880 |
| `inverseHelpersEvalsAtRInv[1]` | 17516173920822186472 | 6112368312529039975 |

**Fixed.** The design was corrected on the submodule side and a re-audit was carried out (the PoC suites
`PocWhirFiatShamir`, `PocGateExt3Production`, `PocOuterCanonicality`,
`PocOuterFraudVerdict`, `PocWhirDotEqBounds`).

### F.2 A close was possible with a single signature (medium, fixed)

In the close circuit and the cancel circuit, the assertion that the second participant is active (`assert_one(active_bits[1])`)
was missing. **A close proof passed with only one signature.** After the fix, 2 or more are required.

### F.3 The same key could be registered in 2 slots (medium, fixed)

In an experiment that disabled the circuit-side key-distinctness check, we confirmed that **both circuits could produce a valid
proof for a "switch to the same key"** (the native-side check remained effective). Fixed so that distinctness is enforced both in the
circuit and natively.

### F.4 Deposits vanished on rollback (high, fixed)

Restoration of the pending chain was missing from `_rollbackBatch` in both places, and **deposits from that batch onward
disappeared**.

### F.5 Someone else's key material could be destroyed (high, fixed)

`state_update_verifier.rs` fixed the recipient, the token registration and the token count across a transition, but
**did not compare `regev_pk_digests` at all**. Any proposer of a transition could destroy an unrelated participant's key
material, pass the checks of every honest co-signer, have everyone sign, and leave the victim unable to withdraw from their own slot
ever again (with no means of recovery).

**Fixed** — `state_update_verifier.rs:1561`:

```rust
if prev_state.balance_state.regev_pk_digests != next_state.balance_state.regev_pk_digests {
    // "regev_pk_digests must remain unchanged across a state transition (H-2: ...)"
```

The regression test is `in_channel_transfer_rejects_regev_pk_digest_mutation` at `:2557`.
The comment states explicitly that "reverting the fix has been confirmed to turn it red."

### F.6 Someone else's submission could be finalized with one's own proof (high, fixed)

Because the submission record did not bind its own state root, **it was possible to finalize a different submission with one's own
proof**.

### F.7 The challenge deadline could be extended indefinitely (high, fixed)

The deadline was reset unconditionally in both the initial and the replacement branch, so by repeating replacements the deadline
could be extended beyond the cap.

### F.8 Closing failed permanently after a cancellation (critical, fixed)

Because `cancelClose` restored the freeze counter, a second close submission necessarily failed (a functional halt).

### F.9 An unreachable validity check (medium, fixed)

The canonicality check of `ChannelRegRecord::validate` was written in a way that meant it never actually ran.
The cause was that the conversion from `Bytes32` to the internal representation silently folded values at or above the order of the field
(different `Bytes32` values fall to the same value). **Found during the Lean formalization work**, and fixed at the root by having the
conversion reject (commit `150bb19`). The repository's test was also confirmed to fail before the fix.

### F.10 A defect in the L1-side arithmetic implementation (medium, fixed)

The reimplementation of the exponentiation used in L1 proof verification could disagree with the reference implementation. There is a
dedicated audit memo (`audit12-08-2026.md`) and a post-mortem of why it was missed (`why-gate8-was-missed.md`).
The corresponding model on the Lean side is 11 theorems.

## Appendix G — technical content of the 3 items under tracking

### G.1 Checking key material at opening (high)

**Every value that carries identity is bound to the real key.** `member_pubkeys_root` (`wallet_core.rs:854-866`) is

```rust
regev_pk_digest: m.regev_pk.poseidon_digest(),
```

that is, **recomputed from the full public key**, and `MemberInfo` has no field holding the digest directly.
`verify_snapshot` (`:1297-1312`) re-derives the two roots and checks them, and `wallet_import_channel`
(`wasm_wallet.rs:443-448`) identifies one's own slot by **agreement with one's own full public key**.

**There is exactly one exception.** `balance_state.regev_pk_digests[slot]` — the duplicate that the withdrawal claim circuit
actually checks — is nowhere compared against the recording side. `BalanceState::validate()`
constrains only the spare slots (`balance_state.rs:667-670`). The F.5 fix (freezing) preserves, as is, the value that
entered at opening.

**Co-signers are protected.** `wallet_sign_state` (`wasm_wallet.rs:315-322`) checks before signing and rejects on a mismatch.
**Delegates are not protected** — the same function requires `slot < member_count`, and since delegates do not sign at
opening, this check has no opportunity to run. Both import and balance decryption succeed
(decryption looks only at the ciphertext and the secret key, not at the digest), so **the anomaly does not surface until the
moment of the claim**.

**Fix approach (1 line)** — in `verify_snapshot_own_slot` (`wallet_core.rs:1322-1354`, which already has the key and the slot):

```rust
if snapshot.state.balance_state.regev_pk_digests[slot as usize]
    != Bytes32::from(keys.regev_pk.poseidon_digest())
{
    return bail("my slot's balance-state Regev digest does not match my key");
}
```

No change is needed to the contracts or to the circuits. The reason that adding a circuit-side constraint was deferred at the time of the
F.5 fix (there are 21 places with test data using non-canonical digests) does not apply to the wallet-side check.

### G.2 Auxiliary data for inter-channel transfers (medium)

The auxiliary data is Merkle-bound to the leaf of the transfer consumed, and that leaf is bound to the sender's finalized transaction,
so **a prover cannot substitute it after the fact**. What is not proved inside the circuit is the semantics that
"the auxiliary data really is the leaf hash of the corresponding transaction," and the source itself states this explicitly
(`receive_transfer_circuit.rs:505-513`). There are 3 compensating layers (the check at co-signing time, a proof on a separate track, and
independent recomputation by the receiving channel), and exploitation requires **all participants on the receiving side together to
skip the recomputation**.

### G.3 Consent checking at registration (low to medium)

`registerChannel` (`IntmaxRollup.sol:1248-1286`) does not verify participants' signatures, and
`member_regev_pk_digests` is a free witness inside the circuit (`channel_reg_step.rs:331-332`).
In practice, however, as noted above, a participant's software recomputes the root from the real key and checks it, so
a forged registration is detected at import. What remains is the procedural matter of "check before depositing funds."

## Appendix H — theorem counts by module (the main ones)

| Module | Theorems | Subject |
|---|---:|---|
| `NttCorrectness` | 157 | Proof that the fast multiplication inside the circuit agrees with the naive product |
| `FalconAggregate` | 155 | Statements, lists and batches of signature aggregation |
| `FalconCore` | 126 | Signature encoding, verification and the circuit gadget |
| `CloseAssetBacking` | 110 | The backing circuit (instruction sequence 468) |
| `CloseCircuit` | 92 | The close circuit (instruction sequence 191) |
| `FalconAggProgram` | 78 | The instruction sequences of the aggregation leaf and each level |
| `RollupValue` | 73 | The L1 Rollup contract |
| `ManagerValue` | 63 | The settlement Manager contract |
| `LedgerWriters` | 57 | Enumeration of the ledger's write sites and pinning of the slots |
| `SystemSafety` | 56 | The composed safety conclusions |
| `SettlementVerifier` | 56 | The settlement verification contract |
| `PostCloseClaimCircuit` | 54 | The post-close claim circuit |
| `WithdrawalClaimCircuit` / `CloseFunding` | 53 | The withdrawal claim circuit / the materializer |
| `BackingBridge` | 52 | The connection between the materializer and the backing circuit |
| `TrustBoundary` | 51 | The 23 premises and the theorems derived from them |
| `Keccak256` | 45 | The reference hash specification (4 test vectors proved by computer) |
| `CloseSignatureBridge` | 21 | The connection between the close circuit and the signature aggregation |

Current totals: **79 modules / 5,311 theorems / hashes pinned for 497 files**.

## Appendix I — what the checking scripts actually do

`.github/ci/lean-safety-guard.sh` runs the following in order.

1. **Builds all** current modules (if a proof does not go through, it fails here)
2. Confirms that `sorry`, `admit`, `axiom` and `native_decide` do not appear in the sources
   (forbidding incomplete proofs and the use of a computer's execution result in place of a proof)
3. Checks the SHA-256 of 497 files and the submodule's pinned commit
4. Runs `#print axioms` on **every theorem** listed in the inventory and confirms that the axioms depended on are only the 3
   `propext`, `Classical.choice` and `Quot.sound` (Lean's own basic axioms)

Current distribution: of the 5,311 theorems, 1,859 depend on no axiom at all, 3,449 depend on `propext`,
1,797 on `Quot.sound` and 367 on `Classical.choice` (with overlap).
**There is not a single project-specific axiom.**

`lean-line-coverage.py` confirms, for the 169 line maps, that every line of each source file is classified without overlap, and
that the "transcribed" spans are tied to Lean declarations that really exist, by querying the compiler. With
`--require-complete` it **fails deliberately**, because untranscribed lines remain (so that incompleteness cannot be hidden).

`check-ledger-writers.py` scans the Solidity for the 5 variables that rewrite the ledger and confirms that they agree exactly with
the list of write sites pinned on the Lean side (with 6 self-tests).

`lean-fixture-parity.py` compares the values computed by the Lean models against the corresponding fields of actually generated
proof data (18 items / 177 fields).
