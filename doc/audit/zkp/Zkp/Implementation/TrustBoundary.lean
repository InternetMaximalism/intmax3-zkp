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

The single inhabitation result below is deliberately degenerate: in an
environment where every proof adapter returns a failure, every acceptance-guarded
premise holds vacuously and every storage-frame premise holds because no
transition is admitted. That witnesses only well-formedness of the statement, and
`rejecting_environment_accepts_no_close` records why: such an environment
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
  /-- **(a) Close-proof soundness.** `SettlementCloseBridge` proves only WHICH
  103-word statement a successful `verifyCloseIntent` returned, never that the
  statement is true. This premise says the pinned close adapter is sound: an
  accepted proof implies some witness satisfies `CloseCircuit.CircuitGates` for
  that same statement. It would be discharged by a proof about the plonky2/MLE
  backend and by `CloseCircuit.FieldAndGadgetLowering` for the raw gate set;
  neither the backend nor the emitted gates are modeled in this project. -/
  closeProofSoundness :
    ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w
  /-- **(b1) Withdrawal-claim soundness.** `ClaimSettlementBridge` ties an accepted
  withdrawal claim to the exact 50-word statement only. This premise adds the
  missing direction: acceptance implies a satisfying witness of
  `WithdrawalClaimCircuit.CircuitGates`. Discharged by backend soundness plus
  `WithdrawalClaimCircuit.FieldLowering`. -/
  withdrawalProofSoundness :
    ∀ (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true →
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w
  /-- **(b2) Post-close-claim soundness.** Same gap for the 57-word post-close
  endpoint: acceptance implies a raw witness whose public record is the bound
  statement and which satisfies `PostCloseClaimCircuit.ConstructorGates`. -/
  postCloseProofSoundness :
    ∀ (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true →
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w
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
accepted, no aggregate check passes, no finality is observed, and no transition
outside the model or from the deployed artifact is admitted. This is a
well-formedness check on the statement, NOT evidence that any field holds of a
real deployment. In particular the hypotheses below describe an environment in
which no close, no claim and no materialization can ever succeed. -/
theorem rejecting_environment_satisfies_every_premise
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (Modeled : σ → σ → Prop)
    (managerOf : σ → ManagerValue.State) (fundingOf : σ → CloseFunding.State)
    (rejects : ∀ adapter proof,
      m.evm.verifyCompactPublicInputs adapter proof = .error [])
    (noAggregate : ∀ proof st,
      ¬ m.closeEnv.verifyAggregate m.closeEnv.aggregateVerifier proof st)
    (noKeccakGap : ∀ words,
      m.closeEnv.keccak words = SettlementCloseBridge.circuitHash m.keccak words)
    (noFinality : ∀ root, m.funding.isFinalizedRoot root ≠ .ok true)
    (noHeight : ∀ n, m.funding.latestFinalized ≠ .ok n) :
    TrustBoundary m (fun _ _ => False) Modeled (fun _ _ => False) managerOf fundingOf where
  closeProofSoundness f proof accepted :=
    absurd accepted (rejecting_environment_accepts_no_close m rejects f proof)
  withdrawalProofSoundness f proof accepted :=
    absurd accepted (rejecting_environment_accepts_no_claim m rejects f ⟨0, 0, 0, 0, 0, 0, 0, 0, 0, 0⟩ proof).1
  postCloseProofSoundness f proof accepted :=
    absurd accepted (rejecting_environment_accepts_no_claim m rejects ⟨0, 0, 0, 0, 0, 0, 0, 0, 0, 0⟩ f proof).2
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
