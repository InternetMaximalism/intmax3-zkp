import Zkp.Implementation.FundFlow
import Zkp.Implementation.SettlementCloseBridge
import Zkp.Implementation.ClaimSettlementBridge

/-!
# The named premise classes of the implementation-model audit

This module carries NO new semantics of any source file. It gathers, as the
fields of one `structure`, exactly the unproved obligations that the composed
implementation models (`RollupValue`, `ManagerValue`, `CloseFunding`,
`SettlementVerifier`, `CloseCircuit`, `WithdrawalClaimCircuit`,
`PostCloseClaimCircuit` and the bridges between them) must borrow from outside
Lean before a system-level fund-safety statement can be made.

Nothing here is an axiom, and nothing here is proved. Each field is a `Prop`
typed against the existing models, so `Zkp.Implementation.SystemSafety` can name
precisely which theorem depends on which borrowed obligation and which theorems
depend on none of them. Discharging any field would require a proof about the
real cryptographic backend, the real EVM, the real L1 chain or the real Rust and
Solidity compilers; none of those objects is modeled anywhere in this project.

`Models` is only the tuple of environment/oracle values the premises talk about,
so that every field mentions the SAME verifier view, the SAME hash function and
the SAME circuit environment as the theorem that consumes it.

One field is different in kind from the others. `mleVerifierSoundness` records an
audit-scoping decision the operator has taken explicitly: the pinned MLE/WHIR
proof system of the `contracts/lib/polygon-plonky2` submodule and its Solidity
counterpart are ACCEPTED as trusted rather than translated, on the same footing
as the accepted KZG ceremony of `Zkp.Implementation.BlobJournal`. Accepting an
artifact is not proving it, so the decision is written here the only honest way
it can be: as one more named, unproved field. What accepting it buys is
`mle_assumption_reduces_close_soundness_to_gate_lowering` — the close-soundness
gap shrinks to the statement-to-`CircuitGates` lowering and nothing else. What it
does not buy is recorded by
`Zkp.Implementation.SystemSafety.mle_assumption_alone_does_not_yield_close_gate_soundness`
and `...mle_assumption_does_not_imply_fund_safety`, which exhibit environments
where the accepted premise holds and the conclusion still fails.

Because the acceptance is taken, all THREE proof-soundness premises are stated
here in their REDUCED form, uniformly: the fields (a), (b1) and (b2) are the
statement-to-`CircuitGates` LOWERING obligations
(`CloseStatementLowering`, `WithdrawalStatementLowering`,
`PostCloseStatementLowering`) and nothing more, because the step from "the pinned
verifier accepted this proof" to "the returned public inputs belong to a
satisfiable plonky2 statement of the pinned circuit" is exactly (a0)
`mleVerifierSoundness`. Splitting the premises this way makes the borrowed halves
disjoint: no field bundles the accepted artifact with an unaccepted lowering. The
older, monolithic "acceptance implies a satisfying witness" conclusions are still
available with the same names and the same argument lists, but now as THEOREMS —
`TrustBoundary.closeProofSoundness`, `TrustBoundary.withdrawalProofSoundness`,
`TrustBoundary.postCloseProofSoundness` — proved from (a0) plus the corresponding
lowering field, so every consumer is unchanged while nothing is assumed twice.

The single inhabitation result below is deliberately degenerate: in an
environment where every proof adapter returns a failure and no plonky2 statement
is satisfiable at all, every acceptance-guarded premise holds vacuously, every
lowering premise holds vacuously, and every storage-frame premise holds because
no transition is admitted. That witnesses only well-formedness of the statement,
and `rejecting_environment_accepts_no_close` records why: such an environment
authorizes no fund movement at all.
-/

namespace Zkp.Implementation.TrustBoundary

/-- Per-channel deposit attribution: `d channel token` is the number of raw units
of `token` that entered the Rollup escrow on behalf of `channel`. No modeled
contract maintains this map; it is the accounting the Balance/validity circuit
family is supposed to enforce off-chain. -/
abbrev ChannelDeposits := Nat → Nat → Nat

/-- Signer-set relation: `r message keys count` states that `message` really was
authorized by `count` of the listed public keys. The close circuit only calls an
opaque `verifyAggregate` predicate; this relation is what a Falcon aggregation
proof is *intended* to mean. -/
abbrev SignerRelation := CloseCircuit.Words8 → List CloseCircuit.Words8 → Nat → Prop

/-- The environment values every premise below is indexed by. Bundling them makes
it impossible for two premises (or a premise and the theorem that uses it) to
silently refer to different verifier views or different hash functions. -/
structure Models (BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type) where
  /-- Modeled EVM external-call view used by `SettlementVerifier`. -/
  evm : SettlementVerifier.EvmView
  /-- Pinned adapter/core addresses installed in the settlement verifier. -/
  installed : SettlementVerifier.Installed
  /-- The Solidity-side keccak boundary function. -/
  keccak : SettlementVerifier.Keccak
  /-- Close-circuit gate environment (hashes, pinned verifiers, insertion tree). -/
  closeEnv : CloseCircuit.Environment BalanceProof AggregateProof Path Root
  /-- Withdrawal-claim circuit gate environment. -/
  claimEnv : WithdrawalClaimCircuit.Environment ClaimPath ClaimCore
  /-- Post-close-claim circuit gate environment. -/
  postEnv : PostCloseClaimCircuit.Environment
  /-- Materializer environment whose getters observe the L1 chain. -/
  funding : CloseFunding.Environment
  /-- The Rollup state the materializer's finality getters are supposed to read. -/
  head : RollupValue.State
  /-- Intended per-channel deposit attribution (see `ChannelDeposits`). -/
  deposits : ChannelDeposits
  /-- Intended meaning of a successful aggregate-signature check. -/
  signers : SignerRelation
  /-- Pinned circuit identity of the adapter deployed at an address: the circuit
  digest and verification-config digest baked into that adapter's pinned
  configuration (`MleProverBridge.ConfigBody.circuitDigest` and
  `MleProverBridge.ConfigFixture.pinnedVerificationConfigDigest` on the Rust
  side, the fixed `encodedConfiguration` of the deployed verifier on the Solidity
  side). It is a parameter here; nothing in this project derives it from a
  circuit, and distinct addresses alone do not prove a deployer pinned the
  intended circuit. -/
  pinnedCircuitDigest : SettlementVerifier.Address → List Nat
  /-- `plonky2Satisfiable digest words` is the intended meaning of: there is a
  plonky2 statement whose circuit is the one `digest` identifies, whose
  public-input vector is `words`, and which has a satisfying assignment. It is
  deliberately opaque — no model in this project defines plonky2 statements,
  gates or assignments — and only `MleAcceptedStatementsAreSatisfiable` and the
  three `*StatementLowering` obligations ever mention it. -/
  plonky2Satisfiable : List Nat → List Nat → Prop

/-- The accepted-artifact assumption in isolation, so that a theorem can take it
without taking the whole premise bundle: for an adapter the settlement verifier
actually pins, a word vector returned by `verifyCompactPublicInputs` is the
public-input vector of a satisfiable plonky2 statement of that adapter's pinned
circuit. `TrustBoundary.mleVerifierSoundness` is exactly this Prop, and its
docstring carries the scope of the acceptance. -/
def MleAcceptedStatementsAreSatisfiable
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ (adapter : SettlementVerifier.Address) (proof : SettlementVerifier.Bytes)
    (words : SettlementVerifier.Limbs),
    adapter ∈ m.installed.adapters.list →
    m.evm.verifyCompactPublicInputs adapter proof = .ok words →
    m.plonky2Satisfiable (m.pinnedCircuitDigest adapter) words

/-! ## The three statement-lowering obligations

Each proof endpoint (close, withdrawal claim, post-close claim) splits its
soundness gap the same way. The step from "the pinned verifier accepted this
proof" to "the returned words are the public inputs of a SATISFIABLE plonky2
statement of the pinned circuit" is the accepted artifact assumption (a0)
`MleAcceptedStatementsAreSatisfiable`, once, for all endpoints. The step from
there to "some witness satisfies the handwritten `CircuitGates` of the model" is
per-endpoint and is NOT covered by the acceptance: it needs the emitted gate set
of the deployed circuit and the corresponding field/gadget lowering. The three
definitions below are exactly those three remaining steps, and they are what the
premise structure carries as fields (a), (b1), (b2). -/

/-- The step the accepted MLE/WHIR premise does NOT cover on the close path: that
the plonky2 statement identified by the close adapter's pinned circuit digest,
carrying the very words the Solidity side bound, is the circuit
`Zkp.Implementation.CloseCircuit` models — so that a satisfying assignment of it
yields a satisfying witness of `CloseCircuit.CircuitGates`. Discharging it needs
the emitted gate set of the deployed circuit and `CloseCircuit.FieldAndGadgetLowering`;
neither the emitted gates nor the plonky2 lowering is modeled in this project. -/
def CloseStatementLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.CloseFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.close)
        (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words →
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w

/-- The same step on the withdrawal-claim path: that the plonky2 statement
identified by the withdrawal adapter's pinned circuit digest, carrying the exact
50 words `ClaimSettlementBridge.withdrawalStatement` describes, is the circuit
`Zkp.Implementation.WithdrawalClaimCircuit` models. Discharging it needs the
emitted gate set of the deployed claim circuit together with
`WithdrawalClaimCircuit.FieldLowering`; neither is modeled here. -/
def WithdrawalStatementLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.WithdrawalFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.withdrawal)
        (ClaimSettlementBridge.withdrawalStatement f).words →
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w

/-- The same step on the post-close-claim path: that the plonky2 statement
identified by the post-close adapter's pinned circuit digest, carrying the exact
57 words `ClaimSettlementBridge.postCloseStatement` describes, is the circuit
`Zkp.Implementation.PostCloseClaimCircuit` models — so that a satisfying
assignment yields a RAW witness whose own public record is that statement and
which satisfies `PostCloseClaimCircuit.ConstructorGates`. -/
def PostCloseStatementLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.PostCloseFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.postClose)
        (ClaimSettlementBridge.postCloseStatement f).words →
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w

/-- The close adapter is one of the four adapters the settlement verifier pins,
so premise (a0) — which is stated only about pinned adapters — does apply to the
close endpoint. -/
theorem close_adapter_is_pinned (installed : SettlementVerifier.Installed) :
    installed.adapters.close ∈ installed.adapters.list := by
  simp [SettlementVerifier.Adapters.list]

/-- The withdrawal-claim adapter is pinned too, so (a0) applies to the withdrawal
endpoint. -/
theorem withdrawal_adapter_is_pinned (installed : SettlementVerifier.Installed) :
    installed.adapters.withdrawal ∈ installed.adapters.list := by
  simp [SettlementVerifier.Adapters.list]

/-- The post-close-claim adapter is pinned too, so (a0) applies to the post-close
endpoint. -/
theorem post_close_adapter_is_pinned (installed : SettlementVerifier.Installed) :
    installed.adapters.postClose ∈ installed.adapters.list := by
  simp [SettlementVerifier.Adapters.list]

/-!
## The premises

`σ` is the combined system state of the composition module, exposed only through
its Manager and materializer projections so that this module stays independent of
how that state is packaged. `Deployed` is the transition relation of the real
compiled artifacts on that same storage, `Modeled` is the composition's own
`Step` relation, and `Unmodeled` is every other transition (entrypoints outside
this audit, other contracts, other transactions) that can touch the same storage
between two modeled steps.
-/

structure TrustBoundary {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    {σ : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (Deployed Modeled Unmodeled : σ → σ → Prop)
    (managerOf : σ → ManagerValue.State) (fundingOf : σ → CloseFunding.State) : Prop where
  /-- **(a0) Pinned MLE/WHIR verifier soundness — an ACCEPTED trust assumption,
  not a proved property.** For an adapter the settlement verifier actually pins,
  if the modeled EVM view's `verifyCompactPublicInputs` returns a word vector for
  a proof — that is, if the pinned MLE/WHIR verifier accepted that proof — then
  that word vector really is the public-input vector of a plonky2 statement of
  the circuit which the adapter's pinned circuit digest identifies, and that
  statement has a satisfying assignment.

  (i) ACCEPTED, NOT PROVED. This field is here at the operator's explicit
  direction, as an audit-scoping decision: the pinned MLE/WHIR submodule is taken
  on trust instead of being translated, on the same footing as the accepted KZG
  ceremony that `Zkp.Implementation.BlobJournal` does not challenge. It is a
  named premise exactly like every other field of this structure — it is not an
  axiom, it is proved nowhere in this project, and no theorem may treat it as
  established.

  (ii) WHAT IT COVERS. Exactly one artifact: the pinned MLE/WHIR proof system of
  the `contracts/lib/polygon-plonky2` submodule — its Rust verifier
  (`mle/src/verifier_v2.rs` and the sumcheck/WHIR machinery beneath it, roughly
  34k lines) together with its Solidity counterpart, `PinnedMleVerifierV2.sol`
  and `CompactMleProofV2.sol` with the `Plonky2GateEvaluator` dispatch they call.
  The submodule is pinned BY COMMIT in the manifest: `submodules` of
  `doc/audit/lean-current-source-manifest.json` records
  `contracts/lib/polygon-plonky2` at `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78`,
  the same gitlink the parent tree carries, and the Cargo `[patch]` block
  redirects every transitive `polygon-plonky2` dependency to that one checkout.
  The acceptance is scoped to that commit and to nothing else: a different
  submodule revision is a different, unaccepted artifact. Accepting it means
  accepting, unexamined by this audit, that submodule's WHIR/FRI and sumcheck
  soundness argument, its claimed security level, its Fiat-Shamir transcript, its
  compact-proof codec, and the agreement of its Rust and Solidity sides.

  (iii) WHAT IT DOES NOT COVER. It says nothing about the circuit-to-gates
  lowering: that the plonky2 statement a digest identifies is the circuit these
  models describe is a separate obligation per endpoint, and is exactly what the
  three fields (a), (b1), (b2) below still require. It says nothing about the KZG
  attestation or Proof-DA availability path, which stays a distinct boundary of
  `MleProverBridge` and `BlobJournal`. It says nothing about the correctness of
  the public inputs a caller passes in: the Solidity binding pins which words
  were returned, it never validates that they describe a real channel. And a
  satisfiable statement is not by itself a safe fund movement — that step still
  needs premises (c), (d), (e1), (e2), (f1), (f2) and (g1). See
  `mle_assumption_reduces_close_soundness_to_gate_lowering` for what the
  acceptance buys, and
  `Zkp.Implementation.SystemSafety.mle_assumption_does_not_imply_fund_safety` for
  an environment in which this premise holds and fund safety fails anyway. -/
  mleVerifierSoundness : MleAcceptedStatementsAreSatisfiable m
  /-- **(a) Close statement lowering — the ONLY remaining half of close-proof
  soundness; the MLE step is (a0).** `SettlementCloseBridge` proves only WHICH
  103-word statement a successful `verifyCloseIntent` returned, never that the
  statement is true. Given (a0), what is still missing is the lowering: a
  satisfiable plonky2 statement of the close adapter's pinned circuit, carrying
  those 103 words, yields a witness satisfying `CloseCircuit.CircuitGates` for
  the same statement. It would be discharged by the emitted gate set of the
  deployed circuit together with `CloseCircuit.FieldAndGadgetLowering`; neither
  the emitted gates nor the plonky2 lowering is modeled in this project. The old
  monolithic "acceptance implies a satisfying witness" form is recovered from
  this field and (a0) by the theorem `TrustBoundary.closeProofSoundness`. -/
  closeStatementLowering : CloseStatementLowering m
  /-- **(b1) Withdrawal-claim statement lowering — lowering only; the MLE step is
  (a0).** `ClaimSettlementBridge` ties an accepted withdrawal claim to the exact
  50-word statement only. Given (a0), the missing direction is the lowering: a
  satisfiable plonky2 statement of the withdrawal adapter's pinned circuit
  carrying those 50 words yields a satisfying witness of
  `WithdrawalClaimCircuit.CircuitGates`. Discharged by the emitted gate set plus
  `WithdrawalClaimCircuit.FieldLowering`. The old monolithic form is recovered by
  `TrustBoundary.withdrawalProofSoundness`. -/
  withdrawalStatementLowering : WithdrawalStatementLowering m
  /-- **(b2) Post-close-claim statement lowering — lowering only; the MLE step is
  (a0).** Same gap for the 57-word post-close endpoint: given (a0), a satisfiable
  plonky2 statement of the post-close adapter's pinned circuit carrying those 57
  words yields a raw witness whose public record is the bound statement and which
  satisfies `PostCloseClaimCircuit.ConstructorGates`. The old monolithic form is
  recovered by `TrustBoundary.postCloseProofSoundness`. -/
  postCloseStatementLowering : PostCloseStatementLowering m
  /-- **(c) Close-vector backing.** The materializer credits the Manager the whole
  finalized close vector, and `CloseFunding` proves only that those amounts are
  the Manager's own getter values. Nothing in the modeled contracts relates them
  to the deposits and settled credits of that channel. This premise, stated over
  the close statement's own fields, is the missing link. It would be discharged
  by the Balance/validity circuit family (`BalanceCircuit`, `ChannelStateUpdate`,
  `CloseAssetBacking`) proving that the close vector never exceeds what the
  channel actually received. -/
  closeVectorBacked :
    ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
      ∀ i : Fin 10, i.val < f.tokenCount.val →
        (f.channelFundAmounts i).val ≤ m.deposits f.channelId.val (f.tokenRegistry i).val
  /-- **(d) Signature-validity oracle.** `CloseCircuit.CircuitGates.aggregateVerified`
  is an opaque predicate call. This premise says a passing aggregate check really
  means the close message was authorized by that many of those keys. It would be
  discharged by a proof about the Falcon aggregation circuit and its pinned
  verifier data, which is a pinned-proof dependency in `CloseCircuit`. -/
  signatureValidity :
    ∀ (proof : AggregateProof) (st : CloseCircuit.AggregateStatement),
      m.closeEnv.verifyAggregate m.closeEnv.aggregateVerifier proof st →
      m.signers st.message st.keys st.signerCount
  /-- **(e1) One hash function.** The circuit's `keccak` callback and the Solidity
  `Keccak` boundary must be the same function, viewed through the model's word
  encoding. `SettlementCloseBridge.circuitHash` is exactly that view; nothing
  proves the deployed gadget and the deployed precompile agree. Discharged by a
  Keccak gadget correctness proof. -/
  circuitKeccakIsSolidityKeccak :
    ∀ words : List Nat,
      m.closeEnv.keccak words = SettlementCloseBridge.circuitHash m.keccak words
  /-- **(e2) Hash binding on the compared pair.** No global injectivity is ever
  assumed. This premise is restricted to the finitely many token-vector preimages
  actually compared inside an accepted close execution: if their digests agree,
  the byte strings agree. It is the `concreteBinding` hypothesis of
  `SettlementCloseBridge.bound_close_preserves_entire_settlement_vector`, and
  would be discharged by collision resistance together with ABI-encoding
  faithfulness. -/
  tokenFundsHashBinding :
    ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
      (w : CloseCircuit.PrivateWitness),
      SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
      m.keccak (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)) =
          m.keccak (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
            f.channelFundAmounts) →
        SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w) =
          SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts
  /-- **(f1) L1 finality observation.** `CloseFunding.validateBackingPublicInputs`
  and `prepareMaterialization` gate on `isFinalizedRoot`. That getter is an
  external call in the model. This premise says a positive answer reflects the
  canonical Rollup head `m.head`. It would be discharged by a cross-contract
  storage-read refinement, which the models deliberately do not assume. -/
  finalizedRootObservation :
    ∀ root : CloseFunding.Hash, m.funding.isFinalizedRoot root = .ok true →
      m.head.finalizedRoot root = true
  /-- **(f2) L1 canonical head.** Same for the height getter guarding
  `ChannelExitHasUnfinalizedBlocks`: the reported latest finalized block is the
  canonical head's height. `RollupValue.finality_recovery_trace_is_monotone`
  proves finalized roots survive the modeled rollback paths; it cannot prove that
  the observation itself is of the canonical chain. -/
  finalizedHeightObservation :
    ∀ n : Nat, m.funding.latestFinalized = .ok n → m.head.chain.finalizedBlock = n
  /-- **(g1) Durable replay ledger.** The composition's trace only steps through
  modeled entrypoints. This premise says the storage those steps rely on for
  replay protection is durable: transitions outside the model never clear a used
  nullifier and never rewrite the Manager's received/paid/cap counters. It would
  be discharged by an exhaustive entrypoint inventory plus EVM storage-layout
  isolation; neither is modeled. -/
  durableNullifierLedger :
    ∀ s t : σ, Unmodeled s t →
      (∀ n, (managerOf s).used n = true → (managerOf t).used n = true) ∧
      (managerOf t).received = (managerOf s).received ∧
      (managerOf t).paid = (managerOf s).paid ∧
      (managerOf t).cap = (managerOf s).cap
  /-- **(g2) Durable materialization latch.** `CloseFunding.materialization_call_one_shot`
  is a statement about two calls on the SAME modeled storage. This premise says
  the latch is not cleared between them by anything outside the model. -/
  durableMaterializationLatch :
    ∀ s t : σ, Unmodeled s t →
      ∀ c : CloseFunding.Channel, (fundingOf s).materializedChannelExit c ≠ 0 →
        (fundingOf t).materializedChannelExit c = (fundingOf s).materializedChannelExit c
  /-- **(h) Source/EVM/compiler refinement.** Every model in this project is a
  handwritten reading of Rust and Solidity text. This premise says the deployed
  artifacts' transitions on the represented storage are among the transitions the
  composition admits. It cannot be discharged inside this project at all: it
  needs an extracted EVM semantics, a verified `solc`, and a verified Rust/plonky2
  toolchain. -/
  sourceRefinement : ∀ s t : σ, Deployed s t → Modeled s t

/-! ## What accepting the pinned MLE/WHIR artifact buys

The old premise "acceptance implies a satisfying witness" was one implication
with two independent halves: from "the pinned verifier accepted this proof" to
"the returned public inputs belong to a satisfiable plonky2 statement of the
pinned circuit" (the accepted premise (a0)), and from there to "some witness
satisfies the handwritten `CircuitGates` for the very same statement" (the
lowering). The first half is what the operator has decided to accept; the second
half is NOT covered by that decision and is carried separately as fields (a),
(b1), (b2) so it cannot be smuggled in. The theorems below are the composition of
the two, per endpoint, and they are the whole of what accepting the submodule
buys. -/

/-- **The composition, stated exactly.** Under the accepted MLE/WHIR premise
(a0), a successful modeled close verification already yields the first half of
the old premise (a): the word vector the pinned adapter returned is the
public-input vector of a satisfiable plonky2 statement of the pinned close
circuit, and it is the exact 103-word close statement (that part is proved, not
assumed). The remaining gap to the old `closeProofSoundness` is then
`CloseStatementLowering` and nothing else: supplying it discharges premise (a)
for every accepted close.

Note what is quantified where. `lowering` is a hypothesis of this theorem, not a
consequence of it; accepting the submodule does not make it more likely to hold.
And the conclusion is still only about gates: even with both halves, it is a
satisfying witness, never a safe payment. -/
theorem mle_assumption_reduces_close_soundness_to_gate_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : CloseStatementLowering m)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    m.evm.verifyCompactPublicInputs m.installed.adapters.close proof =
        .ok (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words ∧
      m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.close)
        (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words ∧
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w := by
  have receipt : m.evm.verifyCompactPublicInputs m.installed.adapters.close proof =
      .ok (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words :=
    SettlementCloseBridge.accepted_verification_has_exact_adapter_receipt
      m.evm m.installed m.keccak f proof accepted
  have satisfiable := mleSound m.installed.adapters.close proof _
    (close_adapter_is_pinned m.installed) receipt
  exact ⟨receipt, satisfiable, lowering f satisfiable⟩

/-- The withdrawal-claim analogue: (a0) plus the exact 50-word adapter receipt of
`ClaimSettlementBridge` give the satisfiable plonky2 statement, and
`WithdrawalStatementLowering` is the only step left to the old premise (b1). -/
theorem mle_assumption_reduces_withdrawal_soundness_to_gate_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : WithdrawalStatementLowering m)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true) :
    m.evm.verifyCompactPublicInputs m.installed.adapters.withdrawal proof =
        .ok (ClaimSettlementBridge.withdrawalStatement f).words ∧
      m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.withdrawal)
        (ClaimSettlementBridge.withdrawalStatement f).words ∧
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w := by
  have receipt : m.evm.verifyCompactPublicInputs m.installed.adapters.withdrawal proof =
      .ok (ClaimSettlementBridge.withdrawalStatement f).words :=
    ClaimSettlementBridge.accepted_withdrawal_has_exact_adapter_receipt
      m.evm m.installed f proof accepted
  have satisfiable := mleSound m.installed.adapters.withdrawal proof _
    (withdrawal_adapter_is_pinned m.installed) receipt
  exact ⟨receipt, satisfiable, lowering f satisfiable⟩

/-- The post-close-claim analogue: (a0) plus the exact 57-word adapter receipt
give the satisfiable plonky2 statement, and `PostCloseStatementLowering` is the
only step left to the old premise (b2). -/
theorem mle_assumption_reduces_post_close_soundness_to_gate_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : PostCloseStatementLowering m)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true) :
    m.evm.verifyCompactPublicInputs m.installed.adapters.postClose proof =
        .ok (ClaimSettlementBridge.postCloseStatement f).words ∧
      m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.postClose)
        (ClaimSettlementBridge.postCloseStatement f).words ∧
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w := by
  have receipt : m.evm.verifyCompactPublicInputs m.installed.adapters.postClose proof =
      .ok (ClaimSettlementBridge.postCloseStatement f).words :=
    ClaimSettlementBridge.accepted_post_close_has_exact_adapter_receipt
      m.evm m.installed f proof accepted
  have satisfiable := mleSound m.installed.adapters.postClose proof _
    (post_close_adapter_is_pinned m.installed) receipt
  exact ⟨receipt, satisfiable, lowering f satisfiable⟩

/-- The close composition read as premise discharge: (a0) plus the lowering give
the old premise (a) in exactly the form `TrustBoundary.closeProofSoundness`
states, and therefore nothing weaker than the lowering can be substituted for
it. -/
theorem mle_assumption_with_lowering_is_close_proof_soundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : CloseStatementLowering m) :
    ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w :=
  fun f proof accepted =>
    (mle_assumption_reduces_close_soundness_to_gate_lowering m mleSound lowering f proof
      accepted).2.2

/-- The same discharge on the withdrawal-claim endpoint: (a0) plus
`WithdrawalStatementLowering` give the old premise (b1) verbatim. -/
theorem mle_assumption_with_lowering_is_withdrawal_proof_soundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : WithdrawalStatementLowering m) :
    ∀ (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true →
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w :=
  fun f proof accepted =>
    (mle_assumption_reduces_withdrawal_soundness_to_gate_lowering m mleSound lowering f proof
      accepted).2.2

/-- The same discharge on the post-close-claim endpoint: (a0) plus
`PostCloseStatementLowering` give the old premise (b2) verbatim. -/
theorem mle_assumption_with_lowering_is_post_close_proof_soundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : PostCloseStatementLowering m) :
    ∀ (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true →
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w :=
  fun f proof accepted =>
    (mle_assumption_reduces_post_close_soundness_to_gate_lowering m mleSound lowering f proof
      accepted).2.2

/-! ## The old monolithic premises, recovered as theorems

Splitting the premise bundle must not cost any consumer its conclusion. The three
theorems below carry the names, the statements and the argument lists the former
`TrustBoundary` FIELDS `closeProofSoundness`, `withdrawalProofSoundness` and
`postCloseProofSoundness` had, so `tb.closeProofSoundness f proof accepted` still
elaborates exactly as before — with the difference that it is now derived from
(a0) plus the corresponding lowering field instead of being assumed outright. -/

namespace TrustBoundary

/-- **(a0) + (a) ⇒ the old premise (a).** An accepted close proof implies some
witness satisfies `CloseCircuit.CircuitGates` for the same 103-word statement.
This used to be a field of the structure; it is now proved from the accepted
MLE/WHIR premise and the close statement lowering. -/
theorem closeProofSoundness {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
      CloseCircuit.CircuitGates m.closeEnv
        (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w :=
  mle_assumption_with_lowering_is_close_proof_soundness m tb.mleVerifierSoundness
    tb.closeStatementLowering f proof accepted

/-- **(a0) + (b1) ⇒ the old premise (b1).** An accepted withdrawal claim implies
some witness satisfies `WithdrawalClaimCircuit.CircuitGates` for the same 50-word
statement. Formerly a field, now proved. -/
theorem withdrawalProofSoundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true) :
    ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
      WithdrawalClaimCircuit.CircuitGates m.claimEnv
        (ClaimSettlementBridge.withdrawalStatement f) w :=
  mle_assumption_with_lowering_is_withdrawal_proof_soundness m tb.mleVerifierSoundness
    tb.withdrawalStatementLowering f proof accepted

/-- **(a0) + (b2) ⇒ the old premise (b2).** An accepted post-close claim implies
a raw witness whose public record is the bound 57-word statement and which
satisfies `PostCloseClaimCircuit.ConstructorGates`. Formerly a field, now
proved. -/
theorem postCloseProofSoundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true) :
    ∃ w : PostCloseClaimCircuit.RawWitness,
      w.p = ClaimSettlementBridge.postCloseStatement f ∧
        PostCloseClaimCircuit.ConstructorGates m.postEnv w :=
  mle_assumption_with_lowering_is_post_close_proof_soundness m tb.mleVerifierSoundness
    tb.postCloseStatementLowering f proof accepted

end TrustBoundary

/-! ## What remains, per endpoint

Each of the three theorems below says the same thing about one endpoint: with the
accepted premise (a0) in hand, the ONLY step left between "the pinned verifier
accepted this proof" and "the model's gate system is satisfied for the bound
statement" is that endpoint's `*StatementLowering`.

The converse direction is stated only in the form that is actually provable. From
the old monolithic soundness one can recover the lowering's conclusion for every
`f` that HAS an accepted proof — and nothing more. The full converse (soundness
⇒ the lowering for all `f`) is NOT provable and is deliberately not asserted:
`plonky2Satisfiable` is an opaque relation, so for fields that no proof was ever
accepted for it may hold while no gate witness exists at all. That asymmetry is
the point — the lowering is a strictly separate obligation, not a repackaging of
acceptance. -/

/-- **Close: the whole remaining gap is `CloseStatementLowering`.** Forward: with
(a0), the lowering yields the old premise (a). Backward, in the only provable
form: the old premise (a) yields the lowering's conclusion exactly on the fields
that have an accepted proof. -/
theorem close_gap_is_exactly_statement_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m) :
    (CloseStatementLowering m →
        ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
          ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
            CloseCircuit.CircuitGates m.closeEnv
              (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w) ∧
      ((∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
          ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
            CloseCircuit.CircuitGates m.closeEnv
              (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w) →
        ∀ f : SettlementVerifier.CloseFields,
          (∃ proof : SettlementVerifier.Bytes,
            SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) →
          m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.close)
              (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words →
            ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
              CloseCircuit.CircuitGates m.closeEnv
                (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w) :=
  ⟨fun lowering => mle_assumption_with_lowering_is_close_proof_soundness m mleSound lowering,
    fun sound f accepted _ => accepted.elim (fun proof call => sound f proof call)⟩

/-- **Withdrawal: the whole remaining gap is `WithdrawalStatementLowering`.** Same
shape as `close_gap_is_exactly_statement_lowering`, including the same reason the
backward direction is restricted to fields that have an accepted proof. -/
theorem withdrawal_gap_is_exactly_statement_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m) :
    (WithdrawalStatementLowering m →
        ∀ (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true →
          ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
            WithdrawalClaimCircuit.CircuitGates m.claimEnv
              (ClaimSettlementBridge.withdrawalStatement f) w) ∧
      ((∀ (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true →
          ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
            WithdrawalClaimCircuit.CircuitGates m.claimEnv
              (ClaimSettlementBridge.withdrawalStatement f) w) →
        ∀ f : SettlementVerifier.WithdrawalFields,
          (∃ proof : SettlementVerifier.Bytes,
            SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true) →
          m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.withdrawal)
              (ClaimSettlementBridge.withdrawalStatement f).words →
            ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
              WithdrawalClaimCircuit.CircuitGates m.claimEnv
                (ClaimSettlementBridge.withdrawalStatement f) w) :=
  ⟨fun lowering => mle_assumption_with_lowering_is_withdrawal_proof_soundness m mleSound lowering,
    fun sound f accepted _ => accepted.elim (fun proof call => sound f proof call)⟩

/-- **Post-close: the whole remaining gap is `PostCloseStatementLowering`.** Same
shape again, with the same restriction on the backward direction. -/
theorem post_close_gap_is_exactly_statement_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m) :
    (PostCloseStatementLowering m →
        ∀ (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true →
          ∃ w : PostCloseClaimCircuit.RawWitness,
            w.p = ClaimSettlementBridge.postCloseStatement f ∧
              PostCloseClaimCircuit.ConstructorGates m.postEnv w) ∧
      ((∀ (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true →
          ∃ w : PostCloseClaimCircuit.RawWitness,
            w.p = ClaimSettlementBridge.postCloseStatement f ∧
              PostCloseClaimCircuit.ConstructorGates m.postEnv w) →
        ∀ f : SettlementVerifier.PostCloseFields,
          (∃ proof : SettlementVerifier.Bytes,
            SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true) →
          m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.postClose)
              (ClaimSettlementBridge.postCloseStatement f).words →
            ∃ w : PostCloseClaimCircuit.RawWitness,
              w.p = ClaimSettlementBridge.postCloseStatement f ∧
                PostCloseClaimCircuit.ConstructorGates m.postEnv w) :=
  ⟨fun lowering => mle_assumption_with_lowering_is_post_close_proof_soundness m mleSound lowering,
    fun sound f accepted _ => accepted.elim (fun proof call => sound f proof call)⟩

/-! ## Well-formedness witness -/

/-- In an environment whose adapters always revert, `verifyCloseIntent` cannot
report success: the external-call failure is returned before any binding. -/
theorem rejecting_environment_accepts_no_close
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (rejects : ∀ adapter proof,
      m.evm.verifyCompactPublicInputs adapter proof = .error [])
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes) :
    SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof ≠ .ok true := by
  simp [SettlementVerifier.verifyCloseIntent, rejects]

/-- Same for both claim endpoints. -/
theorem rejecting_environment_accepts_no_claim
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (rejects : ∀ adapter proof,
      m.evm.verifyCompactPublicInputs adapter proof = .error [])
    (fw : SettlementVerifier.WithdrawalFields) (fp : SettlementVerifier.PostCloseFields)
    (proof : SettlementVerifier.Bytes) :
    SettlementVerifier.verifyWithdrawalClaim m.evm m.installed fw proof ≠ .ok true ∧
    SettlementVerifier.verifyPostCloseClaim m.evm m.installed fp proof ≠ .ok true := by
  constructor <;>
    simp [SettlementVerifier.verifyWithdrawalClaim, SettlementVerifier.verifyPostCloseClaim,
      SettlementVerifier.verifyClaimEndpoint, rejects]

/-- The premise structure is inhabited, but only degenerately: nothing is
accepted, no plonky2 statement of any circuit is satisfiable, no aggregate check
passes, no finality is observed, and no transition outside the model or from the
deployed artifact is admitted. This is a well-formedness check on the statement,
NOT evidence that any field holds of a real deployment. In particular the
hypotheses below describe an environment in which no close, no claim and no
materialization can ever succeed, in which the accepted MLE/WHIR premise
`mleVerifierSoundness` holds only because the pinned adapter never returns a word
vector at all, and in which the three statement-lowering premises hold only
because `noSatisfiableStatements` denies them their antecedent — the lowering
obligations are not discharged here in any useful sense, they are merely
vacuous. -/
theorem rejecting_environment_satisfies_every_premise
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (Modeled : σ → σ → Prop)
    (managerOf : σ → ManagerValue.State) (fundingOf : σ → CloseFunding.State)
    (rejects : ∀ adapter proof,
      m.evm.verifyCompactPublicInputs adapter proof = .error [])
    (noSatisfiableStatements : ∀ digest words, ¬ m.plonky2Satisfiable digest words)
    (noAggregate : ∀ proof st,
      ¬ m.closeEnv.verifyAggregate m.closeEnv.aggregateVerifier proof st)
    (noKeccakGap : ∀ words,
      m.closeEnv.keccak words = SettlementCloseBridge.circuitHash m.keccak words)
    (noFinality : ∀ root, m.funding.isFinalizedRoot root ≠ .ok true)
    (noHeight : ∀ n, m.funding.latestFinalized ≠ .ok n) :
    TrustBoundary m (fun _ _ => False) Modeled (fun _ _ => False) managerOf fundingOf where
  mleVerifierSoundness adapter proof _ _ returned :=
    Except.noConfusion (returned.symm.trans (rejects adapter proof))
  closeStatementLowering :=
    fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)
  withdrawalStatementLowering :=
    fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)
  postCloseStatementLowering :=
    fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)
  closeVectorBacked f proof accepted :=
    absurd accepted (rejecting_environment_accepts_no_close m rejects f proof)
  signatureValidity proof st verified := absurd verified (noAggregate proof st)
  circuitKeccakIsSolidityKeccak := noKeccakGap
  tokenFundsHashBinding f proof _ accepted :=
    absurd accepted (rejecting_environment_accepts_no_close m rejects f proof)
  finalizedRootObservation root observed := absurd observed (noFinality root)
  finalizedHeightObservation n observed := absurd observed (noHeight n)
  durableNullifierLedger _ _ impossible := impossible.elim
  durableMaterializationLatch _ _ impossible := impossible.elim
  sourceRefinement _ _ impossible := impossible.elim

/-! ## What the premises are attached to -/

/-- The statement named in premise (a) is exactly the 103-word close public
input, so the premise cannot be weakened by reading a shorter record. -/
theorem close_premise_statement_has_103_words
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    (SettlementCloseBridge.statement hash f delegates).words.length =
      CloseCircuit.publicInputsLength :=
  CloseCircuit.public_input_word_count _

/-- Premise (a) is stated about the same word list the modeled adapter actually
returned on the accepted call; this is proved, not assumed. -/
theorem close_premise_statement_is_the_adapter_receipt
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    m.evm.verifyCompactPublicInputs m.installed.adapters.close proof =
      .ok (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words :=
  SettlementCloseBridge.accepted_verification_has_exact_adapter_receipt
    m.evm m.installed m.keccak f proof accepted

end Zkp.Implementation.TrustBoundary
