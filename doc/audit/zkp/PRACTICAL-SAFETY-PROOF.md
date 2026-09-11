# A practical safety proof of the INTMAX3 settlement implementation, and the assumptions it rests on

Status: **work in progress, not a release approval.** Revision of this document: 2026-09-11,
as of the commit that lands the fourth audit loop on branch
`codex/implementation-linewise-lean-20260906` (see `git log`).
Runtime baseline `05ec7ae94701f05d2aaf97ff796b7f800a6ce1f8`; MLE/WHIR submodule pinned at
`6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78`.

---

## 1. Abstract

This document describes what has and has not been proved about the implementation of the
INTMAX3 settlement system — the Solidity contracts `IntmaxRollup`, `ChannelSettlementManager`,
`ChannelSettlementVerifier` and `CloseFundingMaterializer`, and the Rust/plonky2 circuits they
consume. The proofs are Lean 4 theorems, kernel-checked, over **handwritten semantic models** of
the source text. They are not a refinement of the compiled artifacts, not a proof of any
cryptographic primitive, and not a claim that a deployment is safe.

Four results are proved with no cryptographic or proof-system assumption at all. Over any finite
sequence of the twelve modeled money and authorization transitions, a per-token accounting
identity holds exactly (`trace_conserves_per_token`); a Manager's received counter never passes
its own close-vector cap and a materialized channel stays latched
(`trace_channel_attribution`); a consumed withdrawal nullifier is never resurrected and cannot be
claimed again (`trace_nullifier_single_use`); and the Manager never pays out more per token than
it received (`trace_paid_bounded`). Two further results are half unconditional: a successful
close or claim verification pins the *exact* public-input record the pinned verifier returned
(`close_acceptance_binds_statement`, `claim_acceptance_binds_statement`); only the "and some
witness satisfies the circuit's gates" conjunct uses assumptions.

One arithmetic property of the deployed circuits is also proved outright, with no environment and
no premise: the in-circuit NTT of the Falcon signature gadget computes the negacyclic product of
`Z_q[X]/(X^512+1)` (`NttCorrectness.ntt_computes_negacyclic_product`). It used to be an assumption;
it is now a theorem, which is why the gate set the audit reads may be called *Falcon's* equation
rather than some other bilinear map (§2.5).

Everything else the system needs is carried as **twenty-three named, unproved fields** of one Lean
structure, `Zkp.Implementation.TrustBoundary`. Each is a `Prop` — not an axiom — so every theorem
names precisely which obligations it borrows and which it does not. The ledger is deliberately
uncomfortable reading: it contains one accepted artifact (the pinned MLE/WHIR proof system, at two
deployed adapters), four instances of plonky2's recursive verifier, three computational assumptions
(Falcon/NTRU unforgeability and two Keccak-256 same-length collisions), a set of EVM- and
source-refinement premises, and one genuine design gap — **the L2 ledger invariant (c4)
`finalizedBalanceIsBacked`**: that the balances the Balance circuit certifies at finalized Rollup
roots are backed by escrow.

What surrounds that gap is now proved rather than assumed. The event that moves money is
`CloseFundingMaterializer.materializeSignedHead`, and
`materialized_credits_are_finalized_l2_balances_of_boundary` derives, from an accepted
materialization, that every credited amount is an active row of a witness satisfying the
close-asset-backing circuit's gate predicate at a head-finalized extended-state root — hence within
that channel's L2 entitlement. `close_vector_backing_gap_is_now_l2_ledger` names exactly what is
left, so the residue cannot be lost. A kernel-checked counterexample,
`mle_assumption_does_not_imply_fund_safety`, exhibits an environment in which the accepted
proof-system assumption holds and fund safety fails anyway; accepting an artifact is recorded here
as a scoping decision, never as evidence.

## 要旨

本書は、INTMAX3 決済実装について**何が証明され、何が証明されていないか**を記述する。対象は
Solidity 契約（`IntmaxRollup`、`ChannelSettlementManager`、`ChannelSettlementVerifier`、
`CloseFundingMaterializer`）と、それらが消費する Rust/plonky2 回路である。証明は Lean 4 の
kernel 検証済み定理であるが、その対象は原文の**手書き意味モデル**であり、コンパイル済み成果物の
refinement ではなく、暗号プリミティブの証明でもなく、配備の安全性の主張でもない。

暗号仮定・証明系仮定を一切用いずに証明されているのは 4 つである。モデル化された 12 の資金・認可
遷移の任意の有限列について、token ごとの会計恒等式が厳密に成立すること
（`trace_conserves_per_token`）、Manager の受領額が自チャネルの cap を超えず materialization の
latch が保持されること（`trace_channel_attribution`）、消費済み nullifier が復活せず再請求が
失敗すること（`trace_nullifier_single_use`）、支払額が受領額を超えないこと
（`trace_paid_bounded`）。さらに close / claim の受理が返り値の公開入力記録を厳密に固定する点は
無条件である（`close_acceptance_binds_statement`、`claim_acceptance_binds_statement`）。

回路側の算術的性質も 1 件、環境も前提もなしに証明された。Falcon 署名 gadget の in-circuit NTT が
`Z_q[X]/(X^512+1)` の negacyclic product を計算すること
（`NttCorrectness.ntt_computes_negacyclic_product`）である。これは以前は仮定 (d2') であったが、
いまや定理であり、監査対象の gate 集合を「Falcon の署名方程式そのもの」と読んでよい根拠となる
（§2.5）。

残りは Lean structure `Zkp.Implementation.TrustBoundary` の **23 個の名前付き未証明 field** として
明示的に保持される。いずれも公理ではなく `Prop` であるため、どの定理がどの前提を借りているかが
機械的に判別できる。内訳は、受容済み成果物 1 件（pinned MLE/WHIR 証明系。配備アダプタ 2 箇所で
参照される）、plonky2 再帰検証器の 4 インスタンス、計算量仮定 3 件（Falcon/NTRU 偽造困難性と
Keccak-256 の同一長衝突 2 件）、EVM・source refinement 系の環境仮定、そして唯一の設計上の隙間
**(c4) `finalizedBalanceIsBacked`（L2 台帳不変量：Balance 回路が finalized root で証明する残高が
escrow に裏付けられていること）** である。

この隙間の周囲は、いまや仮定ではなく証明である。資金が動く事象は
`CloseFundingMaterializer.materializeSignedHead` であり、
`materialized_credits_are_finalized_l2_balances_of_boundary` は、受理された materialization から
「支払われた各金額は、head が finalized と認める extended-state root において
close-asset-backing 回路の gate 述語を満たす witness の active row であり、したがって当該
チャネルの L2 entitlement 以下である」ことを導く。残余は
`close_vector_backing_gap_is_now_l2_ledger` が明示的に名指しするため失われない。
`mle_assumption_does_not_imply_fund_safety` は、受容済み仮定が成立しながら資金安全性が破れる環境を
kernel 検証済みの反例として与える。**成果物の受容は監査の完了ではない。**

---

## 2. What is proved

All theorem references below are `file:line` inside `doc/audit/zkp/Zkp/Implementation/`.

### 2.1 What `Step` and `Trace` model

`SystemSafety.State` (`SystemSafety.lean:81`) is a triple: the Rollup value ledger
(`RollupValue.State`), one Manager value state per Manager address (`Nat → ManagerValue.State`),
and the materializer's storage (`CloseFunding.State`).

`SystemSafety.Step` (`SystemSafety.lean:373`) is an inductive relation
`State → State → Flow → Flow → Prop`, where the two `Flow = Nat → Nat` arguments are the per-token
value the transition lets **in** and lets **out**. It has twelve constructors:

| constructor | models |
| --- | --- |
| `accounting` | the four transitions `FundFlow.AccountingStep` already covers: the Rollup channel-exit credit (the materializer's expanded call), the Manager pull, `submitClaim`, and the `claimCredit` payout |
| `deposit` | `IntmaxRollup.deposit` — the only modeled way value enters |
| `withdrawalSet` | `withdrawNative` / `withdrawERC20` — a proof-backed withdrawal set leaves escrow, some of it as this Manager's pending credit |
| `userWithdrawNative` | the direct native pending pull |
| `userWithdrawToken` | the direct ERC20 pending pull |
| `materialize` | `CloseFundingMaterializer.materializeSignedHead` — latches the channel and credits the whole close vector out of **pooled** escrow |
| `requestClose` | `ManagerValue.requestCloseCore` — freezes the channel, moves no value |
| `fundingFreeze` / `fundingUnfreeze` | the materializer's view of a close request / cancellation |
| `fundingRecordPost` / `fundingRollbackPost` | the materializer's post journal and its rollback |
| `rollupRollback` | `RollupValue.rollbackBatch` under the Rollup's own callback-frame condition |

`Trace` (`SystemSafety.lean:459`) is the reflexive-transitive closure, accumulating inflow and
outflow pointwise.

Three honesty notes about the relation itself, which bound everything in §2.2:

* **Not every deployed entrypoint is a `Step`.** `finalizeCloseGuarded` is modeled (by
  `ManagerValue.finalizeCloseCore`) but is *not* a `Step` constructor, so a real call to it lives
  in the `Unmodeled` relation of `TrustBoundary`. This is the subject of the 2026-09-11 finding in
  §6.4.
* **Some constructors carry explicit call-frame obligations as arguments**, not as global
  assumptions: `TokenCallFrame` (`SystemSafety.lean:125`) on the ERC20 paths,
  `FundFlow.NativePullCallbackFrame` on the native pull, `RollupValue.RollbackCallbackFrame` on
  the rollback. "Unconditional" below means *free of any `TrustBoundary` premise*, not free of
  these frame arguments. They are honest side conditions about what a token or callback contract
  may do to storage, and they are not claims that real ERC20 contracts behave that way.
* `measure` (`SystemSafety.lean:99`) is `FundFlow.accounted` = Rollup escrow for that asset +
  that Manager's Rollup pending credit + the Manager's own `received` counter. It is a **counter
  total, not an observed ERC20 balance.**

### 2.2 The four unconditional results

These four take a `Trace` and nothing from `TrustBoundary`. No instance of the premise structure
appears in their statements.

**(1) Exact per-token accounting identity** — `SystemSafety.trace_conserves_per_token`
(`SystemSafety.lean:599`).

> Along any finite sequence of modeled steps, and for every token,
> `measure after token + outflow token = measure before token + inflow token`.

It is an identity, not an inequality: value enters only through a Rollup deposit and leaves only
through a proof-backed withdrawal set, a direct pending pull, or *another* Manager's
materialization draining the pooled escrow. That last case is why a single-Manager total is not
conserved in general, and it is visible as an outflow term in the theorem rather than excluded by
a hypothesis.

*What it does not say:* nothing about real token custody; nothing about whether the value that
moved belonged to the channel that received it; nothing about any transition outside `Step`.

**(2) Attribution** — `SystemSafety.trace_channel_attribution` (`SystemSafety.lean:751`).

> Given that the Manager's `received` is within its `cap` before the trace: after the trace
> `received ≤ cap` still holds, the `cap` function is **unchanged** by every modeled step, and any
> channel exit already latched with a non-zero digest stays latched at that digest.

`SystemSafety.materialization_credits_are_the_managers_own_vector` (`SystemSafety.lean:772`) adds
that every amount the materializer credits is exactly the Manager's own token-vector getter
value, that the vector has no duplicate token, and that the channel is latched afterwards.

*What it does not say:* that the cap itself is legitimate. The cap is the finalized close vector;
nothing in `RollupValue`, `ManagerValue` or `CloseFunding` alone relates it to the channel's own
entitlement, because escrow is pooled. That legitimacy is supplied, at the step that actually moves
money, by `SystemSafety.materialized_credits_are_backed_by_l2_entitlement`
(`SystemSafety.lean:802`): given a `TrustBoundary` instance, every amount an accepted
`materializeSignedHead` credits is an active row of a witness satisfying
`CloseAssetBacking.CircuitConstraints` at an extended-state root the canonical head finalizes, and
is therefore within that channel's L2 entitlement at that root. The residue is premise (c4) alone
(§3.5) — **not** an opaque deposit map, and **not** attached to close-intent acceptance.

**(3) Nullifier single use** — `SystemSafety.trace_nullifier_single_use`
(`SystemSafety.lean:836`).

> Given `FundFlow.PayoutIndexed` before the trace: it still holds after; every nullifier marked
> used before the trace is still marked used after it; and for any already-used nullifier,
> `ManagerValue.submitClaimCore` on the final state **cannot** return `.ok`.

*What it does not say:* durability against transitions outside `Step`. That is premise (g1'), and
the consequence is recovered separately as `TrustBoundary.durable_nullifier_ledger_of_boundary`.

**(4) Payout bound** — `SystemSafety.trace_paid_bounded` (`SystemSafety.lean:884`).

> Given `paid ≤ received` per token before the trace: it holds after, and the pooled split
> `escrow + pending + unspent + paid + outflow = measure before + inflow` holds per token.

*What it does not say:* `paid ≤ received` is **not** a proof that no other channel's funds were
consumed. It is a statement about one Manager's counters.

### 2.3 The two half-unconditional results

**Close acceptance binds the statement** — `SystemSafety.close_acceptance_binds_statement`
(`SystemSafety.lean:932`). Three conjuncts:

1. the pinned close adapter really returned exactly
   `SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val` — **unconditional**,
   proved by `SettlementCloseBridge.accepted_verification_has_exact_adapter_receipt`
   (`SettlementCloseBridge.lean:108`);
2. that record has exactly `CloseCircuit.publicInputsLength` = 103 words — **unconditional**;
3. some witness satisfies `CloseCircuit.CircuitGates` for that same record — this conjunct alone
   uses premises (a0) and (a), via `TrustBoundary.close_proof_soundness_of_boundary`.

`SystemSafety.claim_acceptance_binds_statement` (`SystemSafety.lean:957`) is the same shape for
the 50-word withdrawal-claim endpoint, under (a0) + (b1).

**Acceptance alone establishes nothing about truth, funding or authorization.** Conjunct 1 says
*which* words were returned, never that they describe a real channel.

### 2.4 The non-implication results

`SystemSafety.mle_assumption_does_not_imply_fund_safety` (`SystemSafety.lean:1349`) constructs an
environment (`unbackedBackingModels`, `SystemSafety.lean:1307`, built on `unbackedModels`, `:1292`)
in which the pinned adapter accepts every proof and every accepted word vector is declared to be a
satisfiable plonky2 statement. It then specialises the backing side concretely: the backing
circuit's opaque dependencies are `CloseAssetBacking.exampleEnvironment` — for which that module
exhibits a satisfying assignment of its whole 468-op builder program — the canonical head finalizes
every root, and the L2 ledger entitles the channel to **nothing**.

In that environment premise (a0) holds, the close endpoint genuinely accepts
(`unbacked_close_is_accepted`, `:1317`), and **no `TrustBoundary` instance exists at all** — because
the satisfying witness carries an active row of amount 22 at a finalized root while the entitlement
is 0, so (c4) `finalizedBalanceIsBacked` is refuted on a genuine satisfying witness. The refuted
field changed this loop (it used to be the old (c) `closeVectorBacked`, refuted by a credit of a
token the channel never deposited); the message did not.

`SystemSafety.mle_assumption_alone_does_not_yield_close_gate_soundness`
(`SystemSafety.lean:1386`) is the logical-independence witness for the lowering premise (a): with
`BalanceProof = Empty` no gate witness can exist, while (a0) still holds.

These are kernel-checked facts, not comments. They are the reason the accepted artifact in §3.2.1
is written as a premise rather than as a result.

### 2.5 The NTT correctness theorem

`Zkp.Implementation.NttCorrectness.ntt_computes_negacyclic_product` (`NttCorrectness.lean:1624`)
proves `FalconGadgetProgram.NttComputesNegacyclicProduct`: the concrete transcribed composition
"forward-transform both operands, multiply pointwise, inverse-transform" —
`FalconGadgetProgram.circuitProduct`, which is what `gadget.rs:684-687` performs with the twiddle
tables, the butterflies and the mod-`q` reductions transcribed — **equals** the schoolbook
negacyclic product of `Z_q[X]/(X^512+1)` (`FalconGadgetProgram.negacyclicProduct`, transcribed from
the Rust test oracle `schoolbook_negacyclic`, `gadget.rs:999-1022`), for q = 12289 and ψ = 49.

This was field (d2') of the premise structure in the previous revision. **It is no longer a field.**
`TrustBoundary.ntt_computes_negacyclic_product_of_boundary` (`TrustBoundary.lean:2507`) re-exports
it verbatim, and its signature is the point: no `Models`, no `TrustBoundary`, no hypothesis. The
statement never mentioned an environment, which is exactly why it could be proved rather than
borrowed.

**The proof route** (module header, `NttCorrectness.lean:1-42`; 157 named theorems, no Mathlib):
congruence mod q as a decidable equality of remainders with an `omega`-friendly form; the
square-and-multiply `powModQ b e = b^e % q` and the 9-bit reversal `bitReverse9` in closed form; the
exact pointwise action of one Cooley-Tukey stage (and of one Gentleman-Sande stage) recovered from
the `foldl` encoding of the source's two nested `for` loops; a stage invariant saying that after the
stage leaving `2^s` blocks of width `2^h`, block `i` holds the input polynomial's residue modulo
`X^(2^h) − ψ^(blockExp h s i)`, which unwound at `s = 9` gives `ntt_forward_eval` — output index `j`
carries the evaluation at `ψ^(2·bitReverse9 j + 1)`, the negacyclic evaluation points; that
evaluation at those points is a ring homomorphism out of `Z_q[X]/(X^512+1)`, hence the pointwise
product is the forward transform of the negacyclic product; and finally that the Gentleman-Sande
loop inverts the Cooley-Tukey loop butterfly by butterfly, each matched stage pair scaling by 2, so
that the nine stages contribute exactly the `512` the final `n⁻¹` scaling of `gadget.rs:500-508`
cancels.

**Two scoping notes, both of which matter.** Only `FalconGadgetProgram.psi_inverse_pinned` and
`n_inv_pinned` are used: **primality of q is never assumed and no inverse table is supplied.**
Nothing is `decide`d on a 512-element object — `rangeList` is kept irreducible and every `decide` is
a closed comparison of small numerals.

**What it buys, precisely.** *Not* the signer-evidence chain:
`TrustBoundary.signature_validity_of_boundary` does not consume it, because (d1') lowers into and
(d3) is stated for the *same* concrete `circuitProduct`. It buys the reading of
`FalconCore.CircuitSatisfied` as *Falcon's own* `verify` — the gate set checks
`s1 = c − s2·h mod (q, X^512+1)` rather than an equation about some other bilinear map. The audit's
signature conclusion therefore now reads "that gate set is Falcon" instead of "the transcribed gate
set is satisfied and its solutions are unforgeable".

**What it is still a statement about.** The handwritten model in `FalconGadgetProgram`, not the Rust
source, not plonky2's gate lowering, and not the vendored Falcon math. That each transcribed builder
call means what the model says is obligation (i) of §3.1; that the transcription reads the source
correctly is (h).

---

## 3. The trust boundary — the assumption ledger

`Zkp.Implementation.TrustBoundary` (`TrustBoundary.lean:893`) is one Lean `structure` whose
fields are exactly the obligations the composition borrows. Nothing in it is an `axiom`; each
field is a `Prop` typed against the existing models, and `Models` (`TrustBoundary.lean:246`)
bundles the environment values (EVM view, installed adapters, keccak callback, the three settlement
circuit gate environments, the materializer environment, the canonical head, the backing circuit's
pinned digest and opaque dependencies, the bound Manager's address, storage snapshot and channel
id, the L2 entitlement map, the Falcon hash environment, the per-level aggregate digests, the
aggregation recursion environment, the authorization relation, the pinned circuit digests, and the
opaque `plonky2Satisfiable` relation) so that no two fields can silently refer to different
verifiers or different hashes.

The `deposits : ChannelDeposits` parameter of the previous revision **is gone**, together with the
field that consumed it; `l2Entitlement : Words8 → Nat → Nat → Nat` — indexed by an extended-state
root, a channel and a token — replaces it, and only (c4) mentions it (§3.5).

There are **twenty-three fields**, in this order: (a0) `mleVerifierSoundness`, (a)
`closePrimitiveLowering`, (b1) `withdrawalPrimitiveLowering`, (b2) `postClosePrimitiveLowering`,
(c0) `materializerViewIsManagerState`, (c0b) `managerFundsDigestIsReference`, (c1)
`backingVerifierSoundness`, (c2) `backingPrimitiveLowering`, (c3a) `backingKeccakIsReference`,
(c3b) `backingTokenFundsHashBinding`, (c4) `finalizedBalanceIsBacked`, (d0)
`aggregateRecursiveVerifierSoundness`, (d0') `levelRecursionSoundness`, (d1')
`aggregatePrimitiveLowering`, (d3) `falconUnforgeability`, (e1a) `solidityKeccakIsReference`,
(e1b) `circuitKeccakIsReference`, (e2) `tokenFundsHashBinding`, (f1) `finalizedRootObservation`,
(f2) `finalizedHeightObservation`, (g1') `ledgerWritersAreInventoried`, (g2')
`latchWritersAreInventoried`, (h) `sourceRefinement`.

**(d2') is not among them.** It was a field in the previous revision and is now the theorem of §2.5.

The structure is inhabited — `rejecting_environment_satisfies_every_premise`
(`TrustBoundary.lean:2690`) — but only degenerately: in an environment where every adapter
reverts, no statement is satisfiable, no recursive verification succeeds, the canonical head
finalizes no root and `Unmodeled` is the empty relation. That is a well-formedness check on the
statement, **not** evidence that any field holds of a real deployment;
`rejecting_environment_accepts_no_close` (`TrustBoundary.lean:2601`) and
`rejecting_environment_materializes_nothing` (`:2627`) record that such an environment authorizes
no fund movement at all. **Five** fields cannot be made vacuous, because they are equations with no
antecedent an environment could deny, and are supplied as hypotheses there instead: the two hash
equations (e1a) and (e1b), the backing hash equation (c3a), and the two Manager-observation
equations (c0) and (c0b). Supplying a field is not discharging it.

### 3.1 Group A — per-primitive faithfulness and digest pinning

The shared shape: each lowering field asks only that a satisfiable plonky2 statement of the
adapter's pinned circuit digest, carrying the words the Solidity side bound, yield an
**assignment** of the wires the Rust constructor allocates which satisfies this project's own
per-builder-call semantics (`BuildOp.holds`) of the *same* ordered program `constructorProgram`,
and whose public wires read back to exactly that statement. Everything downstream of such an
assignment is proved, not assumed: `program_satisfied_implies_gates` in each circuit module takes
**no side hypothesis**.

Four fields have this shape — (a), (b1), (b2) and, since this loop, (c2) `backingPrimitiveLowering`
for the close-asset-backing circuit the materializer verifies (§3.5.4) — plus (d1') for the whole
Falcon aggregation stack.

What every field in this group still borrows is exactly two things, named rather than bundled:

* **(i) primitive-semantics faithfulness** — each `BuildOp.holds` case must be precisely the
  constraint plonky2's corresponding builder call emits. A finite, per-call obligation, each
  clause readable against one line of the Rust constructor, but plonky2's gate semantics is not
  modeled here.
* **(ii) digest pinning** — the pinned adapter's circuit digest must be the digest of the very
  program the model transcribes. Stated separately, outside the structure, as
  `ClosePinnedDigestIsProgramDigest` (`TrustBoundary.lean:550`),
  `WithdrawalPinnedDigestIsProgramDigest` (`:557`), `PostClosePinnedDigestIsProgramDigest`
  (`:565`), `AggregateLevelPinnedDigestIsProgramDigest` (`:587`) and
  `BackingPinnedDigestIsProgramDigest` (`:835`); the
  `*_digest_pinning_and_program_lowering_give_primitive_lowering` theorems
  (`TrustBoundary.lean:638`, `:658`, `:677`, and `:2335` for the backing endpoint) show that (ii)
  plus a program-level lowering is what each field amounts to.

Since this loop, obligation (i) is no longer supported by human reading alone: a `#[cfg(test)]`-only
Rust harness checks the **structural half** of every `holds` claim against the circuit plonky2
actually built, and the resulting tables are checked in under `doc/audit/zkp/evidence/`. What it
covers and what it does not is §5.7.

#### 3.1.1 (a) `closePrimitiveLowering` — `TrustBoundary.lean:984`

**Statement.** For every `SettlementVerifier.CloseFields`, if the close adapter's pinned circuit
digest has a satisfiable plonky2 statement at the 103 bound close words, then there is a
`CloseCircuit.Assignment` satisfying `CloseCircuit.ProgramSatisfied CloseCircuit.constructorProgram`
whose `readPublic` is exactly that statement. Definition: `ClosePrimitiveLowering`
(`TrustBoundary.lean:498`).

**Evidence today.** `CloseCircuit` transcribes `ChannelCloseCircuit::new` as an ordered
`constructorProgram` of 191 entries over a `BuildOp` type with **47 constructors** (one per kind of
builder call); 4 of the 47 kinds emit no constraint (config, build, raw allocation, insertion path)
and say so. `CloseCircuit.program_satisfied_implies_gates` (`CloseCircuit.lean:1740`) proves
the handwritten gate predicate from `ProgramSatisfied` alone, with zero residual
`EnvironmentGates`. Each `holds` case quotes its source line in its docstring. The line map
`line-map/close-circuit.json` links each span to a declaration of the module and is validated by
`.github/ci/lean-line-coverage.py`. Fixture parity checks the 103-word layout against words the
real prover emitted (`close_intent`, 22 comparable fields; §5.4). Mechanically, the faithfulness
table `evidence/faithfulness-CloseCircuit.tsv` carries 79 rows: **59 `ok`** (checked against the
built circuit's copy-constraint partition), 19 `not-static` and 1 `trivial`, with no `MISMATCH`
(§5.7).

**What would refute it.** A builder call whose plonky2 gate set does *not* imply the `holds` case
attributed to it — for instance a `range_check` that is elided by a later optimisation, a
`connect` that is not emitted, or a source line the transcript omits. A deployed adapter whose
pinned digest is not the digest of this program refutes (ii) without touching (i).

**How to check.** Read the 47 `BuildOp.holds` cases side by side with
`src/circuits/channel/close_circuit.rs` at the lines quoted in each docstring, then read the
191-entry `constructorProgram` against the constructor's call order. For (ii), compare the deployed
verifier's `encodedConfiguration` circuit digest with a digest computed from the same builder
sequence.

#### 3.1.2 (b1) `withdrawalPrimitiveLowering` — `TrustBoundary.lean:999`

**Statement.** The same reduction on the 50-word withdrawal-claim endpoint
(`WithdrawalPrimitiveLowering`, `TrustBoundary.lean:513`).

**Evidence today.** 32 `BuildOp` kinds, 10 of which emit no constraint, over a 41-entry
`constructorProgram`;
`WithdrawalClaimCircuit.program_satisfied_implies_gates` (`WithdrawalClaimCircuit.lean:985`);
53 named theorems in the module; `line-map/withdrawal-claim-circuit.json`; fixture case
`withdrawal_claim` with 12 compared fields. Faithfulness table: 48 rows, **30 `ok`**,
10 `not-static`, 8 `trivial`, no `MISMATCH`.

**What would refute it / how to check.** As (a), for the range checks, the eleven-bit active sum,
the ten equality flags, the select chains, the Regev decryption core and the inclusion gadget.

#### 3.1.3 (b2) `postClosePrimitiveLowering` — `TrustBoundary.lean:1015`

**Statement.** The same for the 57-word post-close-claim endpoint; the read-back condition is on
`(readWitness a).p` because that circuit's model reads its registered public inputs out of the raw
witness (`PostClosePrimitiveLowering`, `TrustBoundary.lean:527`).

**Evidence today.** 8 `BuildOp` kinds over a 45-entry `constructorProgram`;
`PostCloseClaimCircuit.program_satisfied_implies_gates`
(`PostCloseClaimCircuit.lean:707`); 54 named theorems; `line-map/post-close-claim-circuit.json`;
fixture case `post_close_claim`, 10 compared fields, 2 explicitly not comparable. Transcribing
this circuit surfaced one **missing builder call** in the earlier model (`add_virtual_target` at
`post_close_claim_circuit.rs:372`), now added. It also showed that the module's `DecryptionHolds`
is *stronger* than the recorded gates (8192-coefficient canonicality, `a ≠ 0`, `c1 ≠ 0`), i.e.
the handwritten `ConstructorGates` was a **lower approximation** of the real circuit. Faithfulness
table: 48 rows, **35 `ok`**, 12 `not-static`, 1 `trivial`, no `MISMATCH`.

**What would refute it / how to check.** As (a), for the range and virtual-allocation widths, the
hash preimage widths, the connects, the two Merkle verifies and the decryption core.

#### 3.1.4 (d1') `aggregatePrimitiveLowering` — `TrustBoundary.lean:1254`

**Statement.** Per-builder-call lowering at every level of the Falcon aggregation stack, down to
and including the signature gadget: `FalconAggProgram.GadgetLevelLowering` over
`fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words`, `m.aggEnv`,
`m.falconHash`. At level 0 (the leaf) the assignment is a `FalconGadgetProgram.GadgetAssignment`
satisfying every one of the 23 `holds` cases of `gadgetProgram` (the transcript of
`FalconSigVerifyTarget::build`, `gadget.rs:651-736`), together with a `LeafAssignment` carrying
the call-site wiring and the leaf's seven other builder calls (`agg.rs:268-305`). At levels 1–3
it satisfies every `holds` case of `levelProgram k` (`agg.rs:370-479`).

**Evidence today.** `FalconGadgetProgram` (47 theorems) transcribes the gadget's 23 builder calls
— 3 of which emit no constraint — including the NTT *without folding it into a callback*:
`powModQ`, `bitReverse9`, the 9-stage CT-DIT `nttForward`, the GS `nttInverse` and `pointwise` are
concrete Lean functions, and all 15,872 mod-`q` reductions carry explicit quotient wires under
`FalconCore.modQGates`. `gadget_program_satisfied_implies_circuit_satisfied`
(`FalconGadgetProgram.lean:632`) derives every field of `FalconCore.CircuitSatisfied` with no side
hypothesis. `FalconAggProgram` (78 theorems) then proves
`leaf_program_satisfied_of_gadget_program` (`:1759`), `level_program_satisfied_implies_compose`
(`:1070`) and the induction over the four circuits
`satisfiable_top_level_gives_witness_list` (`:1409`). A concrete two-signer level-1 instance
witnesses non-vacuity. Line maps `falcon-gadget.json`, `falcon-agg.json`.

This is the one endpoint with **proving** evidence as well as static evidence. The faithfulness
tables carry 29 rows for the gadget (17 `ok`, 5 `mutation`, 5 `not-static`, 2 `trivial`), 9 for the
aggregation leaf (6 `ok`, 1 `not-static`, 2 `trivial`) and 21 for level 1 (10 `ok`, 3 `mutation`,
4 `not-static`, 2 `not-injectable`, 2 `trivial`) — all eight `mutation` rows of the whole evidence
set are here, each naming the proving test that violates exactly that claim and checks verification
fails (§5.7).

**What would refute it.** Any of the listed primitives (`add_proof_target_and_verify`,
`add_proof_target_and_conditionally_verify`, `add_virtual_bool_target_safe`, `sub`, `mul`, `add`,
`assert_zero`, `constant`, `range_check`, `register_public_input(s)`, the Poseidon sponge calls)
enforcing less than the model's `holds` case; or `aggregateLevelDigest k` not being the digest of
the level-`k` transcript, which refutes the separately stated
`AggregateLevelPinnedDigestIsProgramDigest`.

**How to check.** Read `gadgetProgram`, `leafProgram` and `levelProgram k` against
`src/falcon_sig/gadget.rs` and `src/falcon_sig/agg.rs` at the quoted lines.

### 3.1a Arithmetic residue — none

The previous revision carried field (d2') `nttComputesNegacyclicProduct` here, and described it as
the only field of the ledger a determined prover could discharge inside Lean. **It has been
discharged.** It is now `NttCorrectness.ntt_computes_negacyclic_product` (§2.5), the field is gone
from the structure, and this group is empty.

### 3.2 Group B — proof-system artifacts

#### 3.2.1 (a0) `mleVerifierSoundness` — `TrustBoundary.lean:956`

**Statement.** `MleAcceptedStatementsAreSatisfiable` (`TrustBoundary.lean:383`): for an adapter
the settlement verifier actually pins, if the modeled EVM view's `verifyCompactPublicInputs`
returns a word vector for a proof, then that vector is the public-input vector of a plonky2
statement of the circuit the adapter's pinned digest identifies, and that statement has a
satisfying assignment.

**This field is different in kind from the others: it records an operator scoping decision.** The
pinned MLE/WHIR proof system is **accepted as trusted rather than translated**, on the same
footing as the accepted KZG ceremony that `Zkp.Implementation.BlobJournal` does not challenge.
Accepting an artifact is not proving it, so it is written the only honest way it can be: as one
more named, unproved field.

**Scope, exactly.** One artifact: the pinned MLE/WHIR proof system of the
`contracts/lib/polygon-plonky2` submodule — its Rust verifier (`mle/src/verifier_v2.rs` and the
sumcheck/WHIR machinery beneath it) together with its Solidity counterpart
(`PinnedMleVerifierV2.sol`, `CompactMleProofV2.sol` and the `Plonky2GateEvaluator` dispatch). The
submodule is pinned **by commit** — `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78` in
`doc/audit/lean-current-source-manifest.json`, the same gitlink the parent tree carries, with the
Cargo `[patch]` block redirecting every transitive dependency to that checkout. **A different
revision is a different, unaccepted artifact.** Accepting it means accepting, unexamined, that
submodule's WHIR/FRI and sumcheck soundness argument, its claimed security level, its Fiat-Shamir
transcript, its compact-proof codec, and the agreement of its Rust and Solidity sides. Its 68
inventoried files (33,974 lines) stay classified `untranslated` in the inventory and are **not**
counted as verified.

**Scope is per deployed adapter, and the scope is now visible address by address.** (a0) quantifies
over the four adapters `SettlementVerifier.Installed` pins. The materializer's `backingMleVerifier`
is **not** one of those four, so the same acceptance at that address is stated as its own field,
(c1) `backingVerifierSoundness` (§3.5.3). Discharging (c1) means discharging (a0) and no more; it is
written separately so that no reader can lose track of where the acceptance applies.

**What it does not cover.** The circuit-to-gates lowering (that is (a), (b1), (b2)); the KZG
attestation and Proof-DA availability path; plonky2's own recursive verifier, which ships in the
same submodule but is (d0) and (d0'); and the correctness of the public inputs a caller passes in.

**Evidence today.** The commit pin, verified on every guard run (1 submodule pin among 497
reviewed-source hashes). No soundness evidence, by construction.

**What would refute it.** A forged proof accepted by the pinned verifier whose public inputs
belong to no satisfiable statement of the pinned circuit. (The operator's separate record of the
MLE/WHIR security-level work is outside this document's scope.)

**How to check.** Confirm the deployed verifier bytecode corresponds to the pinned submodule
revision, and read the submodule's own soundness argument. Then read
`mle_assumption_does_not_imply_fund_safety` (§2.4) to see what accepting it does *not* buy.

#### 3.2.2 (d0) `aggregateRecursiveVerifierSoundness` — `TrustBoundary.lean:1177`

**Statement.** If the close circuit's in-circuit recursive verification of the Falcon aggregate
proof passes at its constant verifier key `m.closeEnv.aggregateVerifier`, then the circuit
identified by `m.aggregateLevelDigest FalconAggregate.aggLevels` — the **top** circuit of the
stack, level 3 — has a satisfiable statement at the 73 aggregate public-input words.

**Explicitly not covered by (a0).** plonky2's recursive FRI verifier ships in the same pinned
submodule, but it was not accepted, it is a different proof system with a different soundness
argument, and it is invoked in a different place: inside the close circuit, not from the chain.
**Sharing a submodule with an accepted artifact is not an acceptance.**

**Evidence today.** None inside this project — nothing here models a plonky2 proof.

**What would refute it / how to check.** A passing in-circuit verification at that key for a
statement the top aggregation circuit cannot satisfy. Discharging it needs a soundness proof of
plonky2's recursive verifier at that constant key.

#### 3.2.3 (d0') `levelRecursionSoundness` — `TrustBoundary.lean:1204`

**Statement.** `FalconAggProgram.RecursionSound` over the same satisfiability relation and
`m.aggEnv`: each of the three `FalconAggLevelCircuit`s verifies its two children in-circuit at the
**constant** child verifier data it bakes in (`add_proof_target_and_verify`, `agg.rs:399`;
`add_proof_target_and_conditionally_verify`, `agg.rs:403-404`; the constant at `agg.rs:394-398`
with the A7 binding of `agg.rs:99-105`), and a child proof accepted at level `k` means the
level-`(k−1)` circuit really is satisfiable at the public inputs the parent read out of it.

**Same artifact class as (d0), three more instances.** Not covered by (a0) and not covered by
(d0).

**What it buys.** With (d1') it is what replaced the old whole-circuit premise: the aggregation
**tree is no longer assumed to exist** behind a satisfiable top statement — it is *derived*, level
by level, by `FalconAggProgram.satisfiable_top_level_gives_witness_list`, from these two fields and
nothing else.

**Evidence / refutation / checking.** As (d0), at three more keys.

### 3.3 Group C — computational assumptions

These two cannot be discharged by any amount of translation work.

#### 3.3.1 (d3) `falconUnforgeability` — `TrustBoundary.lean:1267`

**Statement.** `CloseSignatureBridge.FalconUnforgeable m.falconHash FalconGadgetProgram.circuitProduct
m.authorized`: a satisfied active gadget instance for public polynomial `h` and message digest `d`
means the holder of `h` authorized `d`. This is `FalconCore.LatticeHardness` /
`ntruShortVectorAssumption` in the form a consumer can use, stated for the **concrete**
`circuitProduct` rather than for a parameter, so it cannot be read against a different product
from the one (d1') lowers into.

**Evidence today.** None here. It is the NTRU/GPV lattice assumption.

**What would refute it.** A polynomial-time forger against Falcon at the deployed parameters.

**How to check.** Read the Falcon security analysis; check that the deployed parameter set is the
one that analysis covers. Note the separately recorded design observations in §6.6 (a padding-slot
norm gate that is trivially satisfiable when one unconstrained wire is 0; an accepted aggregate
that shows neither signer distinctness nor member-set membership) — those are *model-level*
findings about the circuit, not about Falcon.

#### 3.3.2 (e2) `tokenFundsHashBinding` — `TrustBoundary.lean:1321`

**Statement.** For an accepted close and any circuit-side private witness: if
`Keccak256.keccak256` of the circuit's `wordBytes (tokenFundsPreimage w)` equals
`Keccak256.keccak256` of the Solidity-side `tokenFundsPreimage f.tokenRegistry f.tokenCount
f.channelFundAmounts`, then the two byte strings are equal.

**This is a same-length collision claim on one concrete pair, and nothing more.** No global
injectivity, no length-extension assumption, no encoding assumption. The ABI half of the old
premise **has been proved and removed**: `SettlementCloseBridge.token_funds_preimage_injective`
(`SettlementCloseBridge.lean:437`) shows the Solidity layout is injective in
(registry, count, amounts), and `token_funds_compared_strings_same_length`
(`SettlementCloseBridge.lean:484`) shows both compared strings are **368 bytes**, so no padding
ambiguity, domain-separation slip or field-ordering slip can produce the collision.
`TrustBoundary.token_funds_binding_is_same_length_collision` (`TrustBoundary.lean:2058`) packages
exactly this.

**Evidence today.** The two length/injectivity theorems above; the reference Keccak-256
specification of §3.4.2 with four kernel-proved test vectors.

**What would refute it.** A Keccak-256 collision on a specific pair of 368-byte strings of the
pinned layout.

**How to check.** Read the two proved theorems, then judge the residual collision claim on its
own cryptographic merits.

**It has a sibling.** (c3b) `backingTokenFundsHashBinding` (§3.5.6) is the same sentence on the
backing path — the circuit's 92-word token-funds preimage packed big-endian against the Manager's
368-byte Solidity preimage of the same vector. Two same-length collision claims, on two concrete
pairs, is the whole of this group's Keccak content; there is still no global-injectivity assumption
anywhere.

### 3.4 Group D — environment semantics

#### 3.4.1 (e1a) `solidityKeccakIsReference` — `TrustBoundary.lean:1278`

**Statement.** For every canonical byte string (`∀ x ∈ b, x < 256`), the `Keccak` callback the
settlement-verifier model calls — standing for the EVM `KECCAK256` opcode — equals
`Keccak256.digestU256 b`, the reference digest read as a `uint256` the way Solidity reads it.

**Evidence today.** `Zkp.Implementation.Keccak256` (45 theorems) specifies Keccak-256 exactly as
the opcode computes it: Keccak-f[1600] with the standard rotation-offset table and 24 round
constants, rate 1088 bits, the **original Keccak** padding `0x01 … 0x80` (not SHA-3's
`0x06 … 0x80`), little-endian lanes, 32-byte output. Four test vectors are **kernel-proved by
`decide`**: `keccak256_empty_vector` (`Keccak256.lean:404`), `keccak256_abc_vector` (`:411`),
`keccak256_pad_boundary_vector` (`:436`, a 135-byte message — the single-`0x81` padding boundary)
and `keccak256_two_block_vector` (`:463`, a 200-byte two-block message). All four were recomputed
independently with the runtime's own `keccak-hash 0.8.0` crate and agree. The side condition is
discharged for the concrete strings by `word_bytes_are_canonical_bytes`
(`TrustBoundary.lean:1933`).

**What would refute it.** The opcode disagreeing with the reference on some canonical string —
i.e. a bug in this transcription of Keccak, since the opcode is normative.

**How to check.** Re-run the four `decide` proofs; recompute the vectors with any independent
Keccak-256. This is an EVM-semantics premise, kin to (h): it would be discharged by an extracted
EVM semantics, and by nothing inside this audit.

#### 3.4.2 (e1b) `circuitKeccakIsReference` — `TrustBoundary.lean:1296`

**Statement.** The close circuit's `keccak` callback — standing for the external `plonky2_keccak`
gadget, pinned in `Cargo.lock` at git rev `2507786148ae6323d0ea547bf88e1752f901434e`, branch
`wasm-main` — computes the reference Keccak-256 of the big-endian-packed u32 words, repacked into
the circuit's 8-limb `Words8`.

**Explicitly not part of (a).** Field (a)'s faithfulness obligation for the keccak `BuildOp` cases
says only that the gadget *constrains* `out = e.keccak preimage`. It says nothing about *which*
function `e.keccak` is; (e1b) is exactly that and nothing else. **A faithful constraint on a wrong
hash and a right hash left unconstrained are different failures.**

**Evidence today.** The same reference specification; the crate revision is pinned and
`Cargo.lock` is part of the manifest's tooling hashes, so a pin change is visible to the guard.
`reference_keccak_models_satisfy_hash_premises` (`TrustBoundary.lean:2088`) shows (e1a) and (e1b)
are simultaneously satisfiable — they are not a vacuous pair.

**What would refute it / how to check.** A gadget output differing from the reference on any word
vector. Discharged by a correctness proof of the pinned gadget at that revision.

#### 3.4.3 (f1) `finalizedRootObservation` — `TrustBoundary.lean:1335`

**Statement.** If `m.funding.isFinalizedRoot root = .ok true` then `m.head.finalizedRoot root =
true`: the materializer's finality getter — an external call in the model, gating
`validateBackingPublicInputs` and `prepareMaterialization` — reflects the canonical Rollup head.

**Evidence today.** None; it is a cross-contract storage-read refinement the models deliberately
do not assume. `RollupValue.finality_recovery_trace_is_monotone` proves finalized roots survive
the modeled rollback paths, which is a different statement.

**What would refute it.** A reorg, a stale or spoofed getter, or an address mis-binding that makes
the materializer read a different contract's notion of finality.

**How to check.** Verify the deployed address binding and the getter's storage read against the
Rollup's own finalized-root map.

#### 3.4.4 (f2) `finalizedHeightObservation` — `TrustBoundary.lean:1343`

**Statement.** If `m.funding.latestFinalized = .ok n` then `m.head.chain.finalizedBlock = n` — the
height getter guarding `ChannelExitHasUnfinalizedBlocks` reports the canonical head's height.

**Evidence / refutation / checking.** As (f1).

#### 3.4.5 (g1') `ledgerWritersAreInventoried` — `TrustBoundary.lean:1394`

**Statement.** For every transition `Unmodeled s t` that changes the Manager's flagged storage —
the used-nullifier set, the `received` or `paid` counters, or the per-token funding cap — there is
an entrypoint in `LedgerWriters.ManagerEntrypoint` and full states projecting to the two
transition endpoints such that the entrypoint's `run` relates them, and that entrypoint is **not**
already covered by a `SystemSafety.Step` constructor.

**What it replaces.** The old (g1) `durableNullifierLedger` asserted the *consequence* directly.
This field asserts only the inventory; the consequence is now the theorem
`durable_nullifier_ledger_of_boundary` (`TrustBoundary.lean:2538`). The borrowed part shrinks from
"the ledger is durable" to "these are the only writers."

**Evidence today.** `LedgerWriters.flaggedWriteSites` (`LedgerWriters.lean:113`) pins the
write-site inventory of the reviewed Solidity text, with **exactly one assignment per flagged
variable**:

| variable | file:line | shape | covered by a `Step`? |
| --- | --- | --- | --- |
| `usedWithdrawalNullifiers` | `ChannelSettlementManager.sol:2231` | set-only (`= true`), guarded by the `:2208` read | yes (`accounting/submitClaim`) |
| `receivedChannelFunds` | `ChannelSettlementManager.sol:2364` | written by `_pullChannelFunds` | yes (`accounting/pull`) |
| `totalCreditedOut` | `ChannelSettlementManager.sol:2398` | `+=` only, cap-guarded at `:2386` | yes (`accounting/payout`) |
| `finalizedChannelFundAmount` | `ChannelSettlementManager.sol:1681` | `+=` only, inside `_finalizeClose` | **no** |
| `materializedChannelExit` | `CloseFundingMaterializer.sol:461` | set-only, guarded by the `== 0` read at `:434` | yes (`materialize`) |

`flagged_write_sites_count` (`LedgerWriters.lean:130`) and `each_flagged_variable_has_one_writer`
pin the list by `decide`; `.github/ci/check-ledger-writers.py` **re-derives it from the Solidity
sources on every CI run** and fails if any other `.sol` file under `contracts/src` writes one of
the five (6 self-tests). No proxy, `delegatecall`, `selfdestruct`, initializer or assembly
`sstore` touches these contracts, and the Rollup cannot write Manager storage. On the model side,
13 Manager entrypoints and 7 materializer entrypoints are enumerated and framed
(`manager_entrypoints_are_ledger_monotone`, `LedgerWriters.lean:632`;
`non_step_manager_entrypoints_are_ledger_neutral_except_cap`, `:640`;
`finalize_close_only_raises_cap`, `:663`).

**What remains borrowed.** Two things this project does not model: that the deployed **bytecode**
implements the reviewed source — the CI check is a text scan, blind to an inline `sstore` through
an inherited library, a proxy upgrade or a compiler bug — and that EVM storage isolation keeps
every other contract and transaction off these slots. This is the (h)-flavoured residue, now
attached to a finite, re-derivable list instead of to a durability claim.

**What would refute it.** Any additional writer to one of the five variables, in any contract that
can reach that storage.

**How to check.** Run `python3 -B .github/ci/check-ledger-writers.py`; read the five source lines.

#### 3.4.6 (g2') `latchWritersAreInventoried` — `TrustBoundary.lean:1427`

**Statement.** For every `Unmodeled s t` that changes the materializer's storage at all, there is
an entrypoint in `LedgerWriters.MaterializerEntrypoint` whose `run` relates the two worlds.

**Evidence today.** `materializedChannelExit` has exactly one write site,
`CloseFundingMaterializer.sol:461` inside `_materialize`, reached only from the external
`materializeSignedHead` and guarded by the `== 0` read at `:434`; the other six modeled
entrypoints do not name the variable at all.
`LedgerWriters.materializer_entrypoints_keep_the_latch` (`LedgerWriters.lean:826`) then gives the
old consequence as `durable_materialization_latch_of_boundary` (`TrustBoundary.lean:2579`), with
its statement unchanged.

**What remains borrowed / what would refute it / how to check.** As (g1').

#### 3.4.7 (h) `sourceRefinement` — `TrustBoundary.lean:1437`

**Statement.** `∀ s t, Deployed s t → Modeled s t`: every transition of the deployed artifacts on
the represented storage is among the transitions the composition admits.

**This is the widest field and it cannot be discharged inside this project at all.** It needs an
extracted EVM semantics, a verified `solc`, and a verified Rust/plonky2 toolchain. Every model
here is a handwritten reading of source text.

**Evidence today — partial and indirect, and it must not be over-read.** The line maps
(169 of them) tie every physical source line of the mapped files to a status and, for `translated`
spans, to a named declaration of the mapped Lean module, checked by a compiler probe. The fixture
parity suite (§5.4) checks that the models' decoders agree with what the real prover emitted, on
18 fixtures. The `translated` classification covers 31,095 of 119,449 inventoried physical lines.
The faithfulness tables (§5.7) add a mechanical check of one direction on the circuit side: 177
structural claims of five Lean circuit transcripts were checked against the circuit the Rust
constructor actually builds, and none disagreed. **None of that is refinement**: agreement on the
fixtures the prover happened to emit is one point of a relation, not the relation; and a check of
the *structural* half of a transcript says nothing about the Solidity side, the compiler, or the
EVM.

**What would refute it.** Any deployed behaviour outside the modeled step relation — which
already happened once, at the model level: see §6.4.

**How to check.** Read `line-map/*.json` and the modules they point at, and treat the refinement
claim as unproved wherever a span is labelled `dependency-boundary` or `untranslated`.

### 3.5 Group E — the backing path, and the one design gap left in it

#### 3.5.0 Why the old field (c) was retired

The previous revision carried a single field (c) `closeVectorBacked`:

> For every `SettlementVerifier.CloseFields` and proof, if
> `SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true`, then for
> every live token slot `i < f.tokenCount`,
> `(f.channelFundAmounts i).val ≤ m.deposits f.channelId.val (f.tokenRegistry i).val`.

**Three things were wrong with it, and all three are structural, not cosmetic.**

1. **It was attached to the wrong event.** The antecedent is acceptance of a *close intent*.
   Accepting a close intent credits nothing and moves no value. The event that moves money is
   `CloseFundingMaterializer.materializeSignedHead`, and the premise said nothing about it.
2. **Its quantity was not the invariant the system enforces.** `m.deposits channel token` was an
   opaque per-channel deposit attribution — "what this channel put in". **No modeled contract
   maintains such a map**, and with L2 transfers it is not even the right quantity: entitlement
   moves between channels on L2, so a deposit bound is both unenforced and wrong.
3. **It ignored what the contracts actually demand.** Before any credit leaves escrow the
   Materializer requires a **backing proof**: `CloseAssetBacking` recursively verifies a Balance
   proof at a constant verifier key, opens its private commitment, rebuilds the asset tree from the
   very token vector whose keccak digest the Manager's finalized close statement carries, and
   exposes an extended-state commitment the Materializer checks against `isFinalizedRoot`. A
   premise that names none of that cannot be the honest statement of the residue.

The field and the `deposits` parameter are both gone, and so is
`SystemSafety.close_vector_backing_is_exactly_premise_c`, which stated it. Seven fields follow the
path the contracts actually take, each naming exactly one artifact or one step, and **everything
between them is proved**.

#### 3.5.1 What is now proved — the derived chain

`TrustBoundary.materialized_credits_are_finalized_l2_balances_of_boundary`
(`TrustBoundary.lean:2149`), lifted to the composed state as
`SystemSafety.materialized_credits_are_backed_by_l2_entitlement` (`SystemSafety.lean:802`).

> From `CloseFunding.materializeSignedHead m.funding world m.managerAddress proof = .ok (after,
> events)` there exist a backing witness `w` and the materialization plan such that
>
> * `CloseAssetBacking.CircuitConstraints m.backingEnv.merkle m.backingEnv.hash
>   m.backingEnv.recursive w` — `w` satisfies the circuit's handwritten gate predicate;
> * `m.head.finalizedRoot (computedPublicInputs …).extendedStateCommitment.value = true` — at a
>   root the **canonical Rollup head finalizes**;
> * `(computedPublicInputs …).channelId = m.managerChannel` — for the **bound** channel;
> * every credit the Materializer paid out is an **active row** of `w`, token for token and amount
>   for amount;
> * and therefore every credited amount is `≤ m.l2Entitlement root m.managerChannel token`.

The intermediate steps are theorems, not prose.
`BackingBridge.signed_head_credits_are_the_registry_vector` (`BackingBridge.lean:969`)
follows an accepted call back to the compact-verifier return, the Solidity-side `BackingStatement`
it validated and the 26-word circuit public-input record those same words decode to — with the two
independent big-endian limb readings (`CloseFunding.limbsToBytes32` and
`CloseAssetBacking.Words8.value`) **proved equal** on range-checked limbs
(`BackingBridge.limbs_to_bytes32_is_words8_value`, `BackingBridge.lean:101`).
`CloseAssetBacking.program_satisfied_implies_constraints` (`CloseAssetBacking.lean:1848`) derives
every field of `CircuitConstraints` from `ProgramSatisfied constructorProgram` alone — no side
hypothesis, no residual — and `program_satisfied_computes_public_inputs` (`:2030`) derives the 26
registered public wires the same way. `BackingBridge.word_bytes_token_vector_binding` (`:746`)
proves the Solidity ABI layout and the circuit's word packing are the same injective encoding.

`TrustBoundary.close_vector_backing_gap_is_now_l2_ledger` (`TrustBoundary.lean:2312`) then states,
as a theorem, exactly which five sentences remain between "the Materializer paid this vector out of
escrow" and "those amounts were the channel's own L2 balance at a finalized state": (c4), (c1),
(c2), (c3a) and (c3b). Nothing else.

#### 3.5.2 (c0) `materializerViewIsManagerState` — `TrustBoundary.lean:1034`

**Statement** (`MaterializerViewIsManagerState`, `:771`). Every component of the Materializer's
`ManagerView` — twelve separate staticcalls into `ChannelSettlementManager` — returns the
corresponding component of the Manager's storage snapshot, with the channel id nonzero: channel id,
lifecycle status (through `managerStatus`, `:759`), generation, close digest, state root, settled
chain, token-funds digest, token count, the registry entries below the count, and the per-token
caps. Its last three conjuncts are the **ABI width facts** at that boundary (`uint32` registry
entries, a `uint8` count, `uint256` caps); they are listed because the Solidity-side preimage of
(c0b) is typed by those widths and nothing else in this project supplies them.

**Why it exists.** `BackingBridge` derives what the call's own executable checks force, and those
checks read the Manager through getters. Nothing in this project ties a cross-contract getter view
to the callee's storage, so the tie is named rather than assumed silently.

**Evidence today.** None inside this project; it is a cross-contract storage-read refinement of the
same family as (f1)/(f2). It is one of the five fields that cannot be made vacuous (§3), because it
is an equation with no antecedent.

**What would refute it / how to check.** An address mis-binding, a proxy whose getter reads
different storage, or a re-entrant call that changes Manager storage between two of the twelve
staticcalls. Verify the deployed address binding and read the twelve getters against the storage
layout.

#### 3.5.3 (c1) `backingVerifierSoundness` — `TrustBoundary.lean:1068`

**Statement.** If the Materializer's call into its pinned `backingMleVerifier` returns a word
vector, that vector is the public-input vector of a satisfiable plonky2 statement of the circuit
`m.backingCircuitDigest` identifies.

**It is (a0) again, not a new acceptance.** Same pinned MLE/WHIR artifact of
`contracts/lib/polygon-plonky2`, at a different deployed adapter. It is a separate field only
because (a0) is scoped to the four adapters `SettlementVerifier.Installed` pins and the
Materializer's verifier is not one of them — **the scope of an acceptance must stay visible,
address by address**. Discharging it means discharging (a0), and no more.

**Evidence / refutation / checking.** As (a0) (§3.2.1), at one more address; plus the
`requirePinnedVerifier` immutable check in `CloseFundingMaterializer.sol`.

#### 3.5.4 (c2) `backingPrimitiveLowering` — `TrustBoundary.lean:1095`

**Statement** (`BackingPrimitiveLowering`, `:824`). A satisfiable plonky2 statement of the backing
adapter's pinned digest yields an **assignment** of every wire `CloseAssetBackingCircuit::new`
allocates that satisfies every `CloseAssetBacking.BuildOp.holds` case of `constructorProgram`, and
whose 26 registered public wires are exactly those words. The same shape as (a), (b1), (b2).

**Evidence today.** `CloseAssetBacking` (110 named theorems) transcribes the constructor as a
**468-op** `constructorProgram` over a `BuildOp` type with 46 constructors; **25 of the 468 ops are
`True`** because that source call emits no constraint at all (the config choice, the `from_pis`
re-slicing of the verified proof, the deliberately unchecked `PrivateStateTarget::new`, the raw
`token_count` and registry allocations, the ten asset-path allocations, and `build`).
`program_satisfied_implies_constraints` (`CloseAssetBacking.lean:1848`) takes **no side
hypothesis**; `example_program_satisfiable` and `example_program_reads_back` (`:2399`) keep the
468-op list non-vacuous. Line map `line-map/close-asset-backing.json`; fixture case
`close_asset_backing` (raw 26 words, 7 compared fields). Faithfulness table: 41 rows, **20 `ok`**,
20 `not-static`, 1 `trivial`, no `MISMATCH` (§5.7).

Digest pinning is factored out exactly as elsewhere: `BackingPinnedDigestIsProgramDigest` (`:835`)
plus `backing_pinned_digest_and_program_lowering_give_primitive_lowering` (`:2335`).

**What would refute it / how to check.** As (a): a builder call whose plonky2 gate set does not
imply the `holds` case attributed to it, or an adapter whose pinned digest is not this program's.

#### 3.5.5 (c3a) `backingKeccakIsReference` — `TrustBoundary.lean:1109`

**Statement.** The backing circuit's `tokenFundsHash` callback — the `plonky2_keccak` gadget the
circuit uses to hash its reconstructed token vector — computes the reference Keccak-256 of the
big-endian-packed words, repacked into the circuit's 8-limb `Words8`. The (e1b) sentence, for the
fourth circuit.

**Evidence / refutation / checking.** As (e1b) (§3.4.2): the same reference specification, the same
pinned crate revision. It is the third of the five fields supplied as a hypothesis in the
degenerate inhabitation, for the same reason — it is an equation with no antecedent to deny.

#### 3.5.6 (c3b) `backingTokenFundsHashBinding` — `TrustBoundary.lean:1126`

**Statement** (`BackingTokenFundsHashBinding`, `:848`). For an accepted materialization: if the
reference Keccak-256 of the circuit's 92-word token-funds preimage packed big-endian equals the
reference Keccak-256 of the Manager's 368-byte Solidity preimage of its own finalized vector, the
two byte strings are equal.

**A same-length collision claim on one concrete pair, and nothing more** — the (e2) sentence on the
backing path. `BackingBridge.solidity_rows_pack_as_solidity_bytes` (`:677`) packs one string into
the other's shape, so the two are the same length and no padding ambiguity, domain-separation slip
or field-ordering slip can produce the collision.

**Evidence / refutation / checking.** As (e2) (§3.3.2).

#### 3.5.7 (c4) `finalizedBalanceIsBacked` — `TrustBoundary.lean:1150` — **THE RESIDUE**

**Statement** (`FinalizedBalanceIsBacked`, `:868`).

> For every witness `w` satisfying `CloseAssetBacking.CircuitConstraints m.backingEnv.merkle
> m.backingEnv.hash m.backingEnv.recursive` — a verified Balance proof at the pinned constant key,
> an opened private commitment, the asset tree rebuilt from the rows — whose extended-state
> commitment the canonical head finalizes
> (`m.head.finalizedRoot (computedPublicInputs …).extendedStateCommitment.value = true`), every
> **active** row's amount is `≤ m.l2Entitlement root channelId row.registry`.

`m.l2Entitlement : Words8 → Nat → Nat → Nat` (`Models`, `TrustBoundary.lean:301`) is an **explicit
parameter**: `l2Entitlement root channel token` is the number of raw units of `token` the L2 ledger
accounts to `channel` at the finalized extended-state root `root`, as the validity chain computes
it. **Nothing in this project derives it, constrains it, or relates it to escrow.** Only (c4)
mentions it. Naming the ledger as a parameter is what makes the residue a single sentence instead of
a mood.

**What it is not.** It is not a deposit bound — L2 transfers move entitlement between channels, so
"what this channel deposited" was never the right quantity. It is not about the close statement —
close-intent acceptance credits nothing, and this premise is attached to the event that does move
money.

**What discharging it would take — the named next project.** Composing the Balance circuit family,
each member of which already exists as a model in this directory, none of which is composed into
this statement yet:

| step | what it would have to give |
| --- | --- |
| `BalanceCircuit` | that a Balance proof's private state really is the channel's balance at its public state |
| `SwitchBoard` | that the public state is a state of the validity chain |
| `ValidityChain` | that finalized roots are reachable only through valid blocks |
| `DepositChain` / `WithdrawalChain` | that the ledger's per-channel entitlement is backed by escrow |

That composition is the work item, and it is proof work, not review work.

**Evidence today.** None. This is the field with the least supporting evidence in the ledger, and it
is the one the counterexample of §2.4 uses to refute a `TrustBoundary` instance — with a *genuine*
satisfying assignment of the whole 468-op program, an active row of amount 22 at a finalized root,
and an entitlement of 0.

**What would refute it.** A constraint-satisfying backing witness at a head-finalized extended-state
root carrying an active amount above the channel's L2 entitlement at that root.

**How to check.** Read the `Models.l2Entitlement` and `finalizedBalanceIsBacked` docstrings, then
`close_vector_backing_gap_is_now_l2_ledger` (`:2312`) to see that these five sentences are the whole
of what is left, then `materialized_credits_are_finalized_l2_balances_of_boundary` (`:2149`) to see
what is no longer assumed.

---

## 4. How the premises compose

Splitting the old, coarse premises must not cost any consumer its conclusion. Each former premise
is now a theorem about a boundary instance, with the same statement and the same argument list.

| former coarse premise | now derived by | from which fields |
| --- | --- | --- |
| close statement lowering (whole circuit) | `close_statement_lowering_of_boundary` (`TrustBoundary.lean:1657`) | (a) |
| withdrawal statement lowering | `withdrawal_statement_lowering_of_boundary` (`:1667`) | (b1) |
| post-close statement lowering | `post_close_statement_lowering_of_boundary` (`:1677`) | (b2) |
| "acceptance implies a satisfying close witness" | `close_proof_soundness_of_boundary` (`:1690`) | (a0) + (a) |
| "acceptance implies a satisfying withdrawal witness" | `withdrawal_proof_soundness_of_boundary` (`:1707`) | (a0) + (b1) |
| "acceptance implies a satisfying post-close witness" | `post_close_proof_soundness_of_boundary` (`:1725`) | (a0) + (b2) |
| (e1) "the circuit hash and the Solidity hash are the same function" | `circuit_keccak_is_solidity_keccak_of_boundary` (`:1981`) | (e1a) + (e1b) |
| (e2) in its opaque-callback form | `token_funds_hash_binding_of_boundary` (`:2002`) | (e2) + (e1a) |
| (c) "the credited vector is backed" | `materialized_credits_are_finalized_l2_balances_of_boundary` (`:2149`) | (c0) + (c0b) + (c1) + (c2) + (c3a) + (c3b) + (c4) + (f1) — **at materialization, not at close-intent acceptance** |
| (d) "a passing aggregate check means signatures exist" | `signature_validity_of_boundary` (`:2394`) | (d0) + (d0') + (d1') + (d3) |
| (d2') "the in-circuit NTT is the negacyclic product" | `ntt_computes_negacyclic_product_of_boundary` (`:2507`) | **no field at all** — see §2.5 |
| (g1) "the replay ledger is durable" | `durable_nullifier_ledger_of_boundary` (`:2538`) | (g1') + the `LedgerWriters` frame theorems — **with a correction, see §6.4** |
| (g2) "a latched channel exit is never rewritten outside the model" | `durable_materialization_latch_of_boundary` (`:2579`) | (g2') |

Four "what is left" theorems name the residues explicitly rather than in prose:
`close_gap_is_now_per_primitive` (`TrustBoundary.lean:1863`), with its withdrawal (`:1883`) and
post-close (`:1902`) siblings, say that under (a0) plus a per-primitive field an accepted proof
yields **both** a satisfying assignment of the transcribed builder program **and** the handwritten
gate predicate — so no whole-circuit black box remains in the premise;
`signature_gap_is_now_per_primitive` (`:2465`) names exactly (d0), (d0'), (d1'), (d3) as the four
residues of the signature path; and `close_vector_backing_gap_is_now_l2_ledger` (`:2312`) names
exactly (c4), (c1), (c2), (c3a) and (c3b) as the residues of the backing path. Each lists what is
now proved and therefore absent from it.

**(d2') is the one row of that table with no field on its right.** It is listed because a reader of
the previous revision will look for it; the entry records that the obligation became a theorem
rather than being dropped or absorbed.

`signature_validity_of_boundary` concludes `CloseSignatureBridge.SignerEvidence`: between one and
eight witnesses, whose count is the exposed `signerCount`, whose key digests are the exposed key
list left-packed with an exactly-zero suffix, each of which ran against the **one** exposed
message and each of whose key holders authorized that message. Poseidon stays opaque throughout,
so the conclusion speaks of key **digests**, never of public polynomials; tying a digest to a
registered member remains the close circuit's member-set obligation.

One direction is deliberately **not** asserted. The full converse (proof soundness ⇒ the lowering
for all field records) is not provable: `plonky2Satisfiable` is opaque, so for records no proof was
ever accepted for, it may hold while no gate witness exists. That asymmetry is the point — the
lowering is a strictly separate obligation, not a repackaging of acceptance
(`close_gap_is_exactly_statement_lowering`, `TrustBoundary.lean:1760`).

---

## 5. Evidence artifacts and how to reproduce

All commands run from the repository root. The Lean toolchain is pinned (Lean 4.10.0 via elan)
and lives outside the default `PATH`:

```sh
export PATH=/Users/andropov/.elan/bin:$PATH   # or your elan bin directory
```

### 5.1 The main safety guard

```sh
bash .github/ci/lean-safety-guard.sh
```

Expected at this revision:

```
[lean-guard] 497 reviewed source hashes and 1 submodule pins verified
[lean-guard] 132 Lean modules covered; no explicit admissions; current imports isolated
… one line per theorem: "<name>: [<its transitive axioms>]" …
[lean-guard] PASS: complete model builds, reviewed-source pins, and current theorem axiom allowlist
[lean-guard] NOT proved: implementation refinement or cryptographic/environment hypotheses
```

**A reviewed source edited after its hash was pinned stops the guard, and that is the intended
behaviour.** The stop reads `FAIL: reviewed source changed: <path>; review model correspondence
before refreshing manifest`, and clearing it means re-reading the model correspondence and then
accepting the change through `register2.py` — never editing the hash by hand. The same stop is what
caught the runtime defect of §6.3.

The guard builds every current module, rejects any occurrence of `sorry`, `admit`, `axiom` or
`native_decide` in the sources, verifies the SHA-256 of every reviewed source file and the pinned
submodule commit, and then runs `#print axioms` on **every named theorem in the inventory**.

**The `#print axioms` allowlist is exactly three constants:**

```python
KERNEL_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})   # lean-safety-guard.py:106
```

These are Lean's own kernel axioms. **No project-specific axiom is permitted**, and no manifest
field can relax the allowlist. At this revision, 5,311 theorems are probed, and nothing outside the
allowlist is observed. The per-axiom distribution across those theorems is
<!-- TODO: number --> (the previous revision's figures no longer apply and the run that would
refresh them did not reach its summary line).

### 5.2 Counts at this revision

| quantity | value |
| --- | --- |
| Lean modules covered by the guard | 132 |
| current modules with a theorem inventory | 79 |
| reviewed-source SHA-256 hashes pinned | 497 |
| pinned submodules | 1 (`contracts/lib/polygon-plonky2` @ `6cefc6ac`) |
| named theorems in the inventory | 5,311 |
| …of which in `Zkp.Implementation.*` | 5,092, across 74 modules |
| line maps | 169 |
| inventoried source files / physical lines | 237 / 119,449 |
| mechanical faithfulness tables / rows | 7 / 275 |

Two modules were added this loop — `Zkp.Implementation.BackingBridge` (52 theorems) and
`Zkp.Implementation.NttCorrectness` (157) — and six runtime sources grew by the `#[cfg(test)]`-only
faithfulness probes (§5.7), which is the whole of the 2,058-line increase in the inventory: every
one of those lines is classified `test-only`.

Per-module theorem counts for the modules this document leans on:
`SystemSafety` 56, `TrustBoundary` 51, `CloseCircuit` 92, `WithdrawalClaimCircuit` 53,
`PostCloseClaimCircuit` 54, `CloseAssetBacking` 110, `BackingBridge` 52, `NttCorrectness` 157,
`FalconGadgetProgram` 47, `FalconAggProgram` 78,
`CloseSignatureBridge` 21, `Keccak256` 45, `LedgerWriters` 57, `SettlementCloseBridge` 42,
`SettlementVerifier` 56, `ClaimSettlementBridge` 17,
`CloseFunding` 53, `ManagerValue` 63, `RollupValue` 73, `FundFlow` 23.

### 5.3 The line-coverage guard, and why `--require-complete` must exit 1

```sh
python3 -B .github/ci/lean-line-coverage.py
python3 -B .github/ci/lean-line-coverage.py --require-complete   # exit 1 is the CORRECT result
```

Expected at this revision:

```
[lean-lines] checked source inventory: {"core": {"files": 71, "lines": 46588},
                                        "dependency": {"files": 166, "lines": 72861}}
[lean-lines] physical-line classifications: {"dependency-boundary": 10850, "non-executable": 9828,
                                             "test-only": 25892, "translated": 31095,
                                             "untranslated": 41784}
[lean-lines] 169 source maps have compiler-checked declaration links
[lean-lines] INCOMPLETE: untranslated sources, dependency obligations and source/EVM refinement remain
[lean-lines] PASS means inventory/link consistency only, NOT all-line or whole-system proof
```

`--require-complete` asks "is every inventoried line translated and every dependency obligation
discharged?" **It exits 1, and it is supposed to.** The exit code is the machine-readable form of
this document's central caveat: the formalization is incomplete, 41,784 physical lines are
`untranslated`, 10,850 are `dependency-boundary`, and the twenty-three premises of §3 are
undischarged.
A future change that makes it exit 0 without discharging those premises would be a regression in
honesty, not progress. **Never reclassify a span to `translated` in order to make this command
pass.**

### 5.4 Fixture parity

```sh
python3 -B .github/ci/lean-fixture-parity.py
```

Expected: `cases: 18   fields PASS: 177   FAIL: 0   not-comparable: 22`, ~2.5 s.

For each fixture the checker reads the u64 public-input words the **real prover** emitted into
`contracts/test/data`, generates a throw-away Lean probe that imports the audited module and
`#eval`s the module's own decoder, and compares every printed field character for character
against values derived from the companion JSON record and — where the Solidity contract recomputes
a digest — from an independent from-scratch Python keccak recomputation of the Solidity preimage.
Expectations are computed from the fixtures and the Solidity source, **never** from the Lean
output. No module under `Zkp/` is edited and no probe contains a `theorem`, `axiom` or `sorry`.

Cases: `close_intent` (103 words, 22 fields), `pw_close_intent` (no companion record: only length
and the re-encoding roundtrip are asserted), `cancel_close` (29 words, 8), `withdrawal_claim`
(50 words, 12), `post_close_claim` (57 words, 10), `close_asset_backing` (raw 26 words, 7),
`withdrawal_chain[…]` (17 words × 5 fixtures, 8 each) and `validity[…]` (41-word preimage ×
7 fixtures, 11 each).

The strongest case is `withdrawal_chain`: the Lean decoder, the Lean model of the Solidity limb
helpers, the prover's registered words and an independent keccak recomputation of the contract's
152-byte fold preimage and 92-byte outer preimage must all agree, on all five fixtures.

**What this is not.** A single agreeing fixture is one point of a relation, not the relation. These
checks would not catch a model that is wrong on inputs no fixture exercises — different lengths,
out-of-range limbs, wrapping scalars, zero channel ids, other member/token counts. They establish
no refinement, no proof soundness, and no hash-function property. The 22 `not-comparable` fields
are exactly the fields no checked-in record pins down; they are reported so the gap stays visible.
See `doc/audit/zkp/fixture-parity.md` for the per-field tables.

### 5.5 The ledger-writer check and the offline suites

```sh
python3 -B .github/ci/check-ledger-writers.py        # PASS
python3 -B .github/ci/test-check-ledger-writers.py   # 6 self-tests
python3 -B .github/ci/test-lean-safety-guard.py      # 29 tests OK
python3 -B .github/ci/test-lean-line-coverage.py     # 22 tests OK
python3 -B .github/ci/test-lean-fixture-parity.py    # 40 tests OK
git diff --check
```

`check-ledger-writers.py` parses `LedgerWriters.flaggedWriteSites` and re-derives it from
`contracts/src/ChannelSettlementManager.sol` and `contracts/src/CloseFundingMaterializer.sol`,
failing if any other `.sol` file under `contracts/src` writes one of the five flagged variables.
The offline suites need no `lake` and no network.

### 5.6 Rust test evidence

The `lib` unit suite was executed in full on 2026-09-10 in submodule-sized chunks, serially:
**711 of 711 tests executed, all passing after one stale test was fixed** (§6.5). The executed set
was reconciled against `cargo test -- --list` to confirm zero unexecuted and zero unpassed. Two
operational cautions from that run are worth repeating for anyone reproducing it:

* **libtest filters are substring matches.** `withdrawal_claim::` also matches
  `withdrawal_claim_circuit::`; a first pass silently skipped 47 tests and still reported `ok`.
  Always reconcile against `--list`.
* **An OOM `SIGKILL` looks like a test failure.** An unfiltered `--lib` run is killed even at
  `--test-threads=1`; the same tests pass chunk by chunk. Peak observed usage: `wallet_core` ~18 GB
  RSS, `circuits::` up to 30 GB, and one property test (`property_vs_native_oracle`) taking
  45 minutes at 30 GB.

CI runs the chunks that fit a 16 GB runner (`common:: utils:: ethereum_types:: regev::`, 240
tests); `wallet_core::`, `circuits::` and `falcon_sig::` are left to the existing dedicated
`--test` steps, with the measured figures recorded in the workflow comments.

The 18 `faithfulness*` tests of §5.7 are part of this same `lib` suite and inherit both cautions:
they build real circuits, so they must be run `--release` and `--test-threads=1`.

### 5.7 Mechanical faithfulness evidence

This is the evidence the previous revision listed as *planned and not implemented*. It now exists,
it covers part of obligation (i) of §3.1, and the part it does not cover is stated exactly.

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo test --release --locked --lib -- --test-threads=1 faithfulness
```

**The lib suite must run single-threaded.** At any parallelism it is OOM-killed, and the `SIGKILL`
reads as a test failure (§5.6). The run executes the **18 `faithfulness*` test functions** — one
self-check in `src/faithfulness.rs`, one static-table test per transcribed program, and the
mutation tests — and rewrites `doc/audit/zkp/evidence/faithfulness-<program>.tsv`, diffing each
against the checked-in expectation `faithfulness-<program>.ops`. Re-blessing an `.ops` file after a
deliberate change requires `INTMAX_FAITHFULNESS_BLESS=1`, so a silent drift cannot pass. The wall
time and peak memory of the run, measured on the audit machine on 2026-09-11, were 209 s wall
for the 18 tests at a peak RSS of 26.6 GB (the touched-module regression suites that were re-run
alongside took 1,237 s / 33.5 GB and 196 s / 8.8 GB); `evidence/README.md` records the same
figures with the single-threaded requirement and the OOM caveat.

#### What `src/faithfulness.rs` checks

The harness is `#[cfg(test)]`-only and does **no proving** for the static half. After
`CircuitBuilder::build` it reads `CircuitData.prover_only.representative_map` — the path-compressed
union-find over every wire and virtual target, indexed by `Target::index` — and answers four kinds
of question about the circuit plonky2 actually built:

| check | how it is decided |
| --- | --- |
| **representative-map equality** | two targets the Lean op claims equal must share a representative. This is `connect` and everything built on it: `connect_array`, `Bytes32Target::connect`, `assert_zero`, `assert_one` |
| **constant pins** | a target the Lean op claims is wired to a constant must share a representative with an `extra_constant_wire` slot (`ConstantGate`, `RandomAccessGate`) whose gate constant is that value. An unused slot still pins its own wire, so including it cannot make an unconstrained target read as pinned |
| **range-check widths** | `range_check(x, n)` is `split_le`, which adds one `BaseSumGate<2>` row, connects `x` to its sum wire and asserts the limbs above `n` to zero. The checked width is recovered as the highest limb **not** wired to zero, plus one — so a *missing* range check and a *wrong-width* one are both visible, and so is the deliberate absence of one where a Lean op constrains nothing |
| **public-input order** | which wires are registered, and in what order, against the built circuit's public-input target list |

`faithfulness_repview_self_check` pins all three primitives on a purpose-built toy circuit, so the
reader is not asked to trust the reader of the partition either.

The **mutation tests** are the proving half, on the two cheap circuits. For a range or arithmetic
claim they construct a witness violating exactly that claim and assert that verification fails —
e.g. the gadget's complement-based 14-bit coefficient canonicality, the `hash_to_point` sponge
semantics, the mod-`q` quotient pin, the level-1 gated message equality, and the level-1 signer
count. For the settlement circuits, proving is too expensive and the tables say so rather than
claiming coverage.

#### Per-program coverage

Computed from the seven checked-in `.tsv` tables:

| program | rows | `ok` | `mutation` | `not-injectable` | `not-static` | `trivial` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `CloseCircuit` | 79 | 59 | 0 | 0 | 19 | 1 |
| `WithdrawalClaimCircuit` | 48 | 30 | 0 | 0 | 10 | 8 |
| `PostCloseClaimCircuit` | 48 | 35 | 0 | 0 | 12 | 1 |
| `CloseAssetBacking` | 41 | 20 | 0 | 0 | 20 | 1 |
| `FalconGadgetProgram` | 29 | 17 | 5 | 0 | 5 | 2 |
| `FalconAggProgram-leaf` | 9 | 6 | 0 | 0 | 1 | 2 |
| `FalconAggProgram-level1` | 21 | 10 | 3 | 2 | 4 | 2 |
| **total** | **275** | **177** | **8** | **2** | **71** | **17** |

By `kind`, the 275 rows are 76 `range`, 42 `gadget`, 39 `arith`, 34 `connect`, 21 `constant`,
18 `public-inputs`, 17 `no-gate`, 16 `width`, 6 `aliasing`, 4 `config` and 2 `preimage`.

**No disagreement was found.** A row whose Lean `holds` claim does not hold in the built circuit is
recorded as `MISMATCH`, the generating test fails on any such row, and **there is no `MISMATCH` row
in any of the seven tables**. That is the whole of the positive result: 177 structural claims about
five circuits and two aggregation levels were checked against the circuit plonky2 built, and all 177
held.

**What is honestly not covered.** The 71 `not-static` rows are arithmetic and gadget semantics —
invisible to the copy-constraint partition, because the partition records *which wires are equal*,
not *what a gate computes*. **They stay in the per-primitive premise**, in (a), (b1), (b2), (c2) and
(d1'), exactly as before. The 2 `not-injectable` rows are claims whose violation cannot be expressed
through the circuit's public witness API at all (a `set_bool_target` that only accepts a genuine
bool; a level-1 count gap the leaf's verifier already forces to a constant). The 17 `trivial` rows
are ops whose Lean `holds` is `True` — config choices, struct literals, profiling reads — so there
is nothing to check. **Checking 177 of 275 rows is not discharging obligation (i); it is bounding
where a transcription error could still hide.**

#### The line-number caveat

Running the generator requires probe structs and capture statements **inside the constructors**,
because the returned `*Target` structs do not keep the internal wires the Lean ops talk about. They
are `#[cfg(test)]`-only, so the production constraint system is byte-identical and the installing
diff **contains no deletions at all** — but while they are applied, the working-tree line numbers
are shifted downward, by +27 to +41 entering each constructor and +45 to +72 leaving it.

The six line maps were therefore **renumbered onto the probed tree** by
`doc/audit/zkp/agent-tools/shift-linemap.py`, and every inserted line is carried there as a span
with `"status": "test-only"`, labelled `faithfulness probe`: 10 spans in `close-circuit.json`,
10 in `withdrawal-claim-circuit.json`, and 8 each in `post-close-claim-circuit.json`,
`close-asset-backing.json` and `falcon-agg.json`, 6 in `falcon-gadget.json`. Every map's
`source_sha256` and `source_lines` match the file on disk.

**The Lean docstrings still cite the pre-insertion numbering**, and so does the `source` column of
the tables — deliberately, because those are the numbers of the unmodified runtime files. **Read a
`source` cell through the line map, not by adding an offset by hand**; `evidence/README.md`
tabulates the per-file shift at the start and end of each constructor for orientation only.

One secondary result comes free. `shift-linemap.py` aborts unless the change is **insert-only** — no
line deleted, none modified. That it ran to completion on all six files is an independent mechanical
confirmation of the property this whole layer depends on: the probes add lines and change none, so
the runtime constraint system outside `#[cfg(test)]` is unchanged.

---

## 6. Known gaps, in plain words

### 6.1 The L2 ledger residue (c4)

Escrow is pooled. A per-Manager conservation identity does not show that the value credited to a
channel belonged to it.

What the Lean composition now shows is the step the deployed contracts actually take: every amount
an accepted `materializeSignedHead` credits is an active row of a witness satisfying the
close-asset-backing circuit's gate predicate, at an extended-state root the canonical Rollup head
finalizes, for the bound channel
(`TrustBoundary.materialized_credits_are_finalized_l2_balances_of_boundary`, §3.5.1). The credited
vector is therefore, by construction, that channel's **L2 balance at a finalized L2 state**, as
certified by the Balance circuit family.

The remaining residue is one sentence: the **L2 ledger invariant** (c4) — that a balance the Balance
circuit certifies at a finalized root is backed by escrow. It lives in the validity chain
(BalanceCircuit → SwitchBoard → ValidityChain → DepositChain / WithdrawalChain), every member of
which exists as a model in this directory, none of which is composed into the statement yet. It is
**named, not proved, here**, and `close_vector_backing_gap_is_now_l2_ledger` fixes the naming as a
theorem so it cannot drift back into prose.

**This is still the largest open item**, and it is the one place in the ledger where more proof
work, not more review, is what is needed. The scope of the change this loop is worth stating
plainly: the residue did not shrink because a hard thing was proved about escrow — it shrank because
the premise was moved off the wrong event (close-intent acceptance, which credits nothing) and off
the wrong quantity (an opaque per-channel deposit map no contract maintains), onto the event and the
quantity the system actually enforces.

### 6.2 (h) source refinement

Every model is a handwritten reading of Rust and Solidity text. There is no verified `solc`, no
extracted EVM semantics, and no verified Rust/plonky2 toolchain in this project. The line maps,
the hash pins, the fixture parity and the faithfulness tables narrow where a reading could be
wrong; they do not make it a refinement. In particular the ledger-writer CI check is a **text
scan**: it cannot see an inline `sstore` through an inherited library, a proxy upgrade, or a
compiler bug — and the faithfulness harness inspects the circuit a *test build* produces, which is
the same constraint system only because the probes are `#[cfg(test)]` and insert-only (§5.7).

### 6.3 The one confirmed runtime defect found and fixed

Recorded on 2026-09-09; this is the only checkpoint at which the audit changed runtime code.

**The defect.** `TryFrom<Bytes32> for PoseidonHashOut` in `src/utils/poseidon_hash_out.rs`
validated its input by a round-trip: convert the `Bytes32` with `reduce_to_hash_out`, convert back
with `From<PoseidonHashOut> for Bytes32`, and reject if the two differ. But `reduce_to_hash_out`
only regroups eight u32 limbs into four u64s and the `From` impl splits them back the same way;
neither direction reduces modulo the field, so the two are exact inverses for **every** input and
the check **never fired**. As a consequence the three non-canonical-identity rejections in
`ChannelRegRecord::validate` were dead code, and the repository's own test
`common::channel_registration::tests::test_channel_reg_validate_rejects_noncanonical_identity_encodings`
was genuinely failing.

**Why it had not been caught.** The CI workflow ran only the named `--test` integration targets and
never `cargo test --lib`. All three failures of that checkpoint fell through that hole.

**The fix.** An explicit Goldilocks-order element check placed **before** the round-trip, returning
a new error variant `PoseidonHashOutError::NonCanonicalElement(usize)`, with the order pinned as
`GOLDILOCKS_ORDER = 0xFFFF_FFFF_0000_0001` and tied to `GoldilocksField::ORDER` by a
`const _: () = assert!(…)`. `reduce_to_hash_out` and the `From` impl are **unchanged**, so the many
callers that intentionally use the lossy many-to-one reading are unaffected. A
`lib unit tests (pure-logic modules)` CI step was added. Circuits, proof parameters and proof
format were not touched.

**Model follow-up.** The guard immediately detected the source-hash change and stopped, demanding
that the model correspondence be revisited before the manifest was updated — which is the intended
behaviour. Five modules were updated: `H1Gadget` (`native_try_from_requires_canonical_elements`,
`goldilocks_order_bytes_are_now_rejected`), `UtilGadgets` (error-variant set and precedence),
`ChannelRegChain` (a theorem renamed to `byte_round_trip_alone_cannot_reject`, since its old name
contradicted the corrected reading; plus `non_goldilocks_record_rejected` proving the rejection is
now live), `BlockTypes` (docstring correction plus
`non_canonical_pk_g_rejection_is_reachable`) and `TxSettlement`. That the round-trip half is
*still* unreachable is kept as a theorem, `ChannelRegChain.byte_round_trip_alone_cannot_reject`,
rather than deleted.

**A caveat the fix does not remove.** `tx_settlement.rs` reads `send_leaf.tx_tree_root` through the
unchanged many-to-one `reduce_to_hash_out`, so that path still accepts byte strings the fixed
`try_from` rejects — recorded as
`TxSettlement.native_settlement_accepts_bytes_the_fixed_try_from_rejects`. Native rejection of
non-canonical tx-tree roots remains a `CanonicalRoots` premise, and the circuit side depends on
`ToHashOutGates`.

At this revision the diff against the runtime baseline `05ec7ae9` is four files:
`src/utils/poseidon_hash_out.rs`, `src/utils/error.rs`, `src/common/balance_state.rs` (tests only)
and `src/wallet_core.rs` (tests only).

### 6.4 The refuted (g1) clause and its correction

The former premise (g1) `durableNullifierLedger` asserted, among other clauses, that the per-token
funding cap is **unchanged** by transitions outside the modeled step relation: `cap t = cap s`.

**That clause is refuted by the deployed contract.** `ChannelSettlementManager.sol:1681`, inside
`_finalizeClose` and reached from the external `finalizeCloseGuarded`, does
`finalizedChannelFundAmount[baseToken] += …`. The entrypoint *is* modeled — by
`ManagerValue.finalizeCloseCore` — but it is **not** a `SystemSafety.Step` constructor, so a real
`finalizeCloseGuarded` call sits in the `Unmodeled` relation and raises the cap. Any instance of
the old structure over a `Deployed`/`Modeled` pair admitting that call was therefore
**unsatisfiable, not merely unproved**.

The corrected clause is monotone, `cap s tok ≤ cap t tok`, which is what
`durable_nullifier_ledger_of_boundary` concludes and what
`LedgerWriters.manager_entrypoints_are_ledger_monotone` proves;
`LedgerWriters.only_cap_writer_is_outside_step` (`LedgerWriters.lean:143`) pins that this is the
single exception, and `finalize_close_only_raises_cap` gives the exact increment. Nothing
downstream weakens, because `SystemSafety` never consumed (g1) or (g2).

This is worth stating plainly because it is the clearest illustration of what the premise ledger
is for: a coarse, plausible-sounding durability assumption was **false of the deployed source**,
and naming it explicitly is what made the falsity findable.

### 6.5 Stale tests corrected

Three tests asserted things that had stopped being true and passed for the wrong reasons.

* `common::balance_state::tests::balance_state_validate_multi_n` and
  `balance_state_delegate_count_regions_and_h1` asserted that a member count of 16 passes; since
  commit `fd467ea` restricted the sig-cluster to 8, the valid range is 2..=8. Updated to use
  `MAX_SIG_CLUSTER`. Three accompanying negative tests were built from an already-invalid base of
  16 — they asserted "exceeding the limit is rejected" while actually being rejected for a
  different reason — and were rebuilt on a valid base so that they exercise the intended check.
* `wallet_core::slot_capacity_tests::join_path_reaches_slot_256_and_beyond` handed a fabricated
  member `RegevPk::padding()` (the zero polynomial) and noted in its own comment that
  `build_record` does not check keys. Commit `b5bafb7` (2026-09-06) had made `build_record` require
  shape, canonicality, non-zeroness and distinctness of the Regev keys of active slots; the test,
  dating from `f08ba2e` (2026-07-19), was seven weeks older than the check. **The check is
  correct** — a zero `a` is reserved for padding slots — so only the test was changed, to supply a
  distinct non-zero canonical `a[0]` per slot, and its comment was corrected. Runtime unchanged.

### 6.6 Design observations recorded as theorems

These are model-level findings, fixed as Lean theorems where possible. **None is a demonstrated
exploit**; each is a place where a reader should not assume more than the code provides.

* The channel tree does not enforce fund conservation across blocks: `ChannelLeaf` carries no fund
  vector, and the public root is invariant under substituting the IMCH preimage
  (`UpdateChannelTree.native_account_root_ignores_channel_state_fields`).
* `update_channel_tree.rs` verifies no signature at all; it only folds into `bp_sig_chain`.
* Cross-channel transfer matching is not done on the block side: `destination_channel_id` is read
  nowhere.
* No Falcon verifier exists in the vendor tree; the decoder's coefficient range does not imply a
  norm bound (`FalconVendor.decode_range_does_not_imply_norm_bound`).
* Whether the circuit gadget verifies a signature at all turns on one wire the gadget itself does
  not constrain: at 0 the norm-bound check degenerates to a range check on the constant 0
  (`FalconCore.padding_slot_norm_gate_is_trivial`).
* An accepted aggregate proof shows neither signer distinctness nor member-set membership.
* `agg_list.rs:329`'s `range_check(count_minus_one, 4)` admits 1–16 signers; the bound of 8 is
  structural, not enforced there.
* Hash signatures are replayable tokens: the public values carry neither nonce nor expiry.
  Soundness depends on the relying side resolving `pk_b` from a registered leaf and accepting an
  IMPA digest at most once.
* `channel.rs`'s `validate()` constrains structure only: the entire key set can be replaced with
  both roots preserved (`ChannelTypes.validate_accepts_substituted_member_set`).
* Leaves and internal nodes are not domain-separated; the height-32 empty `SendTree` and empty
  `TxV2Tree` have equal roots with no hash assumption.
* `test_utils` is a public module without `cfg(test)`, so the harness's deterministic Falcon key
  derivation is reachable from production builds.
* The domain-non-collision check is test-only and disabled in release.
* `U32LimbTargetTrait::get_witness` silently truncates a field wire at 2^32.
* `U63Target::enforce_ge` is not an order check on the top window (exactly 2^32 − 2 values); the
  32-bit variant is sound.
* A sparse-tree update at an out-of-range index records the leaf without changing the root.
* Documentation/implementation mismatches: `channel_tree.rs` documents a 1024-slot member root but
  implements a height-3, 8-slot one; `agg.rs` documents `AGG_LEVELS = 4` and 137 public inputs
  while the code has 3 and 73 (and `batch.rs:695`'s assert message still says 137 — the text an
  operator reads when it fires).

### 6.7 Untranslated lines

Of 119,449 inventoried physical lines, **41,784 are `untranslated`**. Of those, 33,974 lines in 68
files are the accepted MLE/WHIR submodule (§3.2.1) — accepted, therefore deliberately not
translated and **not counted as verified**. The remaining ≈7,810 lines are the Falcon vendor f64
FFT and the parts each module's own line map explicitly marks as untranslated. A further 10,850
lines are `dependency-boundary`: code whose semantics comes from an imported crate, gadget, hash or
compiler that the model treats as an opaque callback or premise.

The inventory grew by 2,058 lines this loop and **every one of them is `test-only`**: the
`#[cfg(test)]` faithfulness probes of §5.7. No `translated`, `untranslated`,
`dependency-boundary` or `non-executable` total moved.

### 6.8 What "somewhat loose" means here

This audit was carried out under an explicit operator direction that a *somewhat loose* result is
acceptable. It is worth saying precisely which steps are loose, because the looseness is not
uniform.

**Machine-checked, end to end:** every theorem cited in §2 and §4; the derivations
`program_satisfied_implies_gates` in the three settlement circuits,
`CloseAssetBacking.program_satisfied_implies_constraints` in the backing circuit and
`gadget_program_satisfied_implies_circuit_satisfied` in the Falcon gadget; the aggregation
induction `satisfiable_top_level_gives_witness_list`; the NTT correctness theorem of §2.5; the
materialization-to-backing chain of §3.5.1; the four Keccak-256 test vectors; the
`LedgerWriters` frame theorems; the `SettlementCloseBridge` layout injectivity and length results.
All of these are checked by the Lean kernel against the allowlist of §5.1.

**Transcription claims, not machine-checked refinement:**

1. **Source → model.** That each Lean model is a faithful reading of the Rust or Solidity text. The
   line maps make the claim *auditable* (every physical line has a status; every `translated` span
   names a declaration, checked to exist by a compiler probe) but the semantic equivalence itself
   is asserted by a human reader. This is premise (h).
2. **`BuildOp.holds` → plonky2 gate set.** That each transcribed builder call's local proposition
   is exactly what plonky2 emits for that call. The obligation is per `BuildOp` *kind*: 47 kinds for
   the close circuit, 32 for withdrawal claim, 8 for post-close claim, 46 for the close-asset-backing
   circuit, 23 for the Falcon gadget, plus the leaf and level ops of the aggregation stack. The
   ordered programs those kinds are instantiated in are longer —
   `CloseCircuit.constructorProgram` has 191 entries, withdrawal claim 41, post-close claim 45,
   close-asset-backing 468, the Falcon gadget 23, the aggregation leaf 8, and `levelProgram k`
   23 + 8·2^(k−1) (31, 39, 55). This is obligation (i) of §3.1.

   **The structural half is now machine-checked** against the circuit plonky2 built, and 177 of 275
   table rows came back `ok` with no `MISMATCH` (§5.7). **The arithmetic and gadget half is not**:
   71 rows are `not-static`, 8 are covered only by sampled mutation proving on the two cheap
   circuits, and human reading against the quoted source line remains the only support for the rest.
3. **Digest pinning.** That the pinned adapter digests and the per-level aggregate digests are the
   digests of the transcribed programs. Nothing in this project computes a digest from a circuit.
   This is obligation (ii).
4. **Fixture agreement → model correctness.** 18 fixtures agreeing is evidence about layout and
   field identification; it is not a proof about any input the fixtures do not exercise.
5. **Solidity write-site inventory → deployed behaviour.** The CI scan re-derives the five write
   sites from the reviewed text; the step to the deployed bytecode is (g1')/(g2')'s residue.

Readers evaluating the system should treat (1)–(3) as the places where a careful adversarial review
has the most leverage, and §3.5.7 (c4) as the place where more proof work, not more review, is
needed.

---

## 7. Reading guide

### 7.1 Where to start

1. `doc/audit/zkp/Zkp/Implementation/SystemSafety.lean` — read the module header, then `Step`
   (`:373`), then the four theorems of §2.2, then
   `materialized_credits_are_backed_by_l2_entitlement` (`:802`).
2. `doc/audit/zkp/Zkp/Implementation/TrustBoundary.lean` — read the module header (it is the
   narrative of how each premise reached its current shape), then `Models` (`:246`), then the
   `structure` at `:893` field by field. Every field's docstring states what it covers, what it
   does **not** cover, and what would discharge it.
3. `doc/audit/zkp/evidence/README.md` and the seven `faithfulness-*.tsv` tables — what the
   mechanical checks decide, row by row, and the line-number caveat (§5.7).
4. `doc/audit/zkp/implementation-linewise-progress.md` (Japanese) — the dated work record,
   including each loop's before/after premise table.
5. `doc/audit/zkp/tasks/loop-2026-09-11-backing-and-evidence-plan.md` — the plan this loop was
   executed against, including why premise (c) was restated rather than discharged.
6. `doc/audit/zkp/fixture-parity.md` — the per-field fixture tables and their explicit
   non-claims.

### 7.2 Module map

`Zkp.Implementation.*` modules and the source each one models (`doc/audit/lean-current-source-manifest.json`
carries the authoritative, hash-pinned list):

| module | models |
| --- | --- |
| `RollupValue` | `contracts/src/IntmaxRollup.sol` |
| `ManagerValue` | `contracts/src/ChannelSettlementManager.sol` |
| `SettlementVerifier` | `contracts/src/ChannelSettlementVerifier.sol` |
| `CloseFunding` | `contracts/src/CloseFundingMaterializer.sol` |
| `SafeERC20` | `contracts/src/SafeERC20.sol` |
| `BlobJournal` | `contracts/src/BlobKZGVerifier.sol` |
| `CloseCircuit` / `ClosePublicInputs` | `src/circuits/channel/close_circuit.rs`, `close_pis.rs` |
| `CancelCloseCircuit` / `CancelClosePublicInputs` | `src/circuits/channel/cancel_close_circuit.rs`, `cancel_close_pis.rs` |
| `WithdrawalClaimCircuit` / `…PublicInputs` | `src/circuits/channel/withdrawal_claim_circuit.rs`, `withdrawal_claim_pis.rs` |
| `PostCloseClaimCircuit` / `…PublicInputs` | `src/circuits/channel/post_close_claim_circuit.rs`, `post_close_claim_pis.rs` |
| `CloseAssetBacking` | `src/circuits/channel/close_asset_backing_circuit.rs`, including its 468-op `constructorProgram` transcript of `CloseAssetBackingCircuit::new` and the gate-lowering section |
| `ChannelStateUpdate` | `src/circuits/channel/state_update_verifier.rs` |
| `DecryptionGadget` | `src/circuits/channel/decryption_gadget.rs` |
| `BalanceCircuit` / `BalancePublicInputs` / `SwitchBoard` | `src/circuits/balance/balance_circuit.rs`, `balance_pis.rs`, `switch_board.rs` |
| `Spend`, `UpdatePrivateState`, `UpdatePublicState`, `PrivateState` | the balance-common circuits and `src/common/private_state.rs` |
| `ValidityChain`, `DepositChain`, `ChannelRegChain`, `WithdrawalChain`, `BlockStep`, `BlockMessages`, `UpdateChannelTree` | `src/circuits/validity/**`, `src/circuits/withdraw/**` |
| `FalconCore` / `FalconAggregate` / `FalconVendor` | `src/falcon_sig/gadget.rs`, `agg.rs`, `agg_list.rs`, `compat.rs`, the vendor tree |
| `FalconGadgetProgram` | `src/falcon_sig/gadget.rs:651-736` as a 23-call builder transcript |
| `FalconAggProgram` | `src/falcon_sig/agg.rs:268-305` (leaf) and `:370-479` (level) as builder transcripts |
| `NttCorrectness` | **no new source reading** — it proves `FalconGadgetProgram.NttComputesNegacyclicProduct` about the transcript that module already carries (§2.5) |
| `LedgerWriters` | the Solidity write-site inventory of the five flagged storage variables, plus the model-level frame theorems over every modeled Manager and materializer entrypoint (§3.4.5) |
| `RegevCore` / `RegevProofs` | `src/regev/**` |
| `MleProverBridge` | the MLE prover-side bridge and `src/deprecated/**` |
| `IndexedMerkleTree`, `MerkleTrees`, `SparseTrees`, `TreeInstances` | `src/utils/trees/**`, `src/common/trees/**` |
| `EthereumTypes`, `CommonValues`, `UtilGadgets`, `U256Arithmetic`, `H1Gadget`, `BlockTypes`, `ChannelTypes` | `src/ethereum_types/**`, `src/common/**`, `src/utils/**`, `src/constants.rs` |
| `WitnessGenerators`, `Processors`, `FlowHarness`, `BalanceWitnesses`, `CrateLayout` | the witness/processor/e2e layers and the crate module structure |
| `SignatureReleaseLedger` | `hosting/wallet/signature-release-ledger.mjs` |
| **bridges** `SettlementCloseBridge`, `ClaimSettlementBridge`, `CancelCloseBridge`, `CloseEncodingBridge`, `CloseSignatureBridge`, `BackingBridge`, `FundFlow` | relate two already-modeled sides; they add no new source reading. `CloseSignatureBridge` carries the signer-evidence shape the close path consumes; `BackingBridge` (new this loop) composes `CloseFunding` with `CloseAssetBacking` and proves the two big-endian limb readings agree (§3.5.1) |
| **no in-repo source** `Keccak256` | reference specification of an external algorithm (EVM opcode / pinned `plonky2_keccak` crate); 45 theorems, four `decide`-proved test vectors (§3.4.1) |
| **composition** `TrustBoundary`, `SystemSafety`, `LedgerWriters` | premise ledger, composed step relation, write-site inventory |

### 7.3 Line-map schema

Each `doc/audit/zkp/line-map/<name>.json` partitions **one** source file from line 1 to EOF with
no gaps and no overlaps:

```json
{
  "schema_version": 1,
  "source": "<repo-relative path>",
  "source_sha256": "<sha256 of the file bytes>",
  "source_lines": <physical line count>,
  "module": "Zkp.Implementation.<Name>",
  "model": "doc/audit/zkp/Zkp/Implementation/<Name>.lean",
  "refinement": "not-proved",
  "spans": [ { "start": 1, "end": 40, "status": "...", "label": "...",
               "declarations": ["Zkp.Implementation.<Name>.foo"],
               "theorems": ["Zkp.Implementation.<Name>.bar"], "note": "..." } ],
  "boundaries": [ { "name": "...", "obligation": "...", "discharged": false } ]
}
```

`status` is one of `translated`, `dependency-boundary`, `untranslated`, `test-only`,
`non-executable`. A `translated` span **must** name at least one declaration of the mapped module
that models those exact lines; `non-executable`, `test-only` and `untranslated` spans must name no
theorems. `dependency-boundary` marks code whose semantics comes from an imported crate, gadget,
hash or compiler that the model treats as an opaque callback or premise. Every named declaration
must exist in the built module — the validator runs `#check`. `refinement` is always
`"not-proved"`, and every `boundaries` entry has `discharged: false`.

**The honesty rules are the point of the schema**, and they are enforced by convention plus CI, not
by the type system: mark a span `translated` only if the module really has a definition modelling
what those lines do; if the model merely abstracts it as an opaque function, it is
`dependency-boundary`; if nothing corresponds, it is `untranslated`, which is expected and fine for
parts of large files. A theorem about a parser does not cover the verifier that calls it.

### 7.4 Tooling

| path | role |
| --- | --- |
| `.github/ci/lean-safety-guard.sh` / `.py` | build, admission scan, source-hash and submodule pins, per-theorem `#print axioms` against the three-constant allowlist |
| `.github/ci/lean-line-coverage.py` | line-map schema and partition checks, compiler-probed declaration links, classification totals; `--require-complete` is the deliberate exit-1 completeness gate |
| `.github/ci/lean-fixture-parity.py` | probe generator, Lean runner, comparator and reporter for the 18 prover fixtures |
| `.github/ci/check-ledger-writers.py` | re-derives the five Solidity write sites and fails on any other writer under `contracts/src` |
| `doc/audit/zkp/agent-tools/validate-linemap.py` | validates one line map, including the `#check` probe |
| `doc/audit/zkp/agent-tools/register2.py` | registers modules into `Zkp.lean`, the guard's current set, the manifest and the inventory; refuses a source-hash change unless it is explicitly accepted |
| `doc/audit/zkp/agent-tools/shift-linemap.py` | re-bases a line map onto an edited source; **aborts unless the edit is insert-only**, which is what makes the `#[cfg(test)]` faithfulness probes auditable (§5.7) |
| `src/faithfulness.rs` (test-only) | the copy-constraint / constant / range-width / public-input-order reader the faithfulness tables are generated from |
| `doc/audit/zkp/evidence/` | the seven generated `faithfulness-*.tsv` tables, their checked-in `.ops` expectations, and the README that defines every `kind` and `verdict` |
| `doc/audit/lean-current-source-manifest.json` | the pinned reviewed-source hashes, submodule pins and per-module theorem inventory |
| `doc/audit/zkp/implementation-inventory.json` | the file/line inventory and its scope note |

---

## 8. How to read a claim in this document

Three rules, applied consistently above:

1. **"Proved" always names a Lean theorem and its file:line.** If a sentence does not name one, it
   is not a proof claim.
2. **"Assumed" always names a field of `TrustBoundary` by its Lean name and its label.** There are
   twenty-three; there is no twenty-fourth hiding in a comment, and nothing is an `axiom`. A label
   that appears in the previous revision and not in §3 — (c), (d2'), (e1), (d), (g1), (g2) — is
   accounted for in the table of §4, as a theorem.
3. **Evidence and proof are kept apart.** Fixture agreement, test vectors, CI scans, write-site
   inventories and the faithfulness tables of §5.7 are evidence. They narrow where a model could be
   wrong. They are not refinement, and this document never converts one into the other. In
   particular, "177 of 275 rows came back `ok`" is a statement about a check that ran, not about a
   premise that was discharged.

The composition is real, the four unconditional results are real, and the arithmetic theorem of
§2.5 is real. **They do not add up to "funds cannot be stolen or lost."** What they add up to is:
given twenty-three named obligations, four of which no work inside this repository can ever
discharge, the modeled system's accounting, attribution, replay protection and payout bound hold
along every modeled trace; every amount an accepted materialization credits is a Balance-certified
L2 balance of that channel at a finalized root; and the one design residue that remains — that such
a balance is backed by escrow — is written down as (c4) rather than assumed away.
