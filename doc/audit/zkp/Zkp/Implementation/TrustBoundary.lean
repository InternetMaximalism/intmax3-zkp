import Zkp.Implementation.FundFlow
import Zkp.Implementation.SettlementCloseBridge
import Zkp.Implementation.ClaimSettlementBridge
import Zkp.Implementation.CloseSignatureBridge
import Zkp.Implementation.FalconAggProgram
import Zkp.Implementation.FalconGadgetProgram
import Zkp.Implementation.LedgerWriters
import Zkp.Implementation.Keccak256

/-!
# The named premise classes of the implementation-model audit

This module carries NO new semantics of any source file. It gathers, as the
fields of one `structure`, exactly the unproved obligations that the composed
implementation models (`RollupValue`, `ManagerValue`, `CloseFunding`,
`SettlementVerifier`, `CloseCircuit`, `WithdrawalClaimCircuit`,
`PostCloseClaimCircuit`, `FalconAggregate`, `FalconCore` and the bridges between
them — `SettlementCloseBridge`, `ClaimSettlementBridge`, `CloseSignatureBridge`)
must borrow from outside Lean before a system-level fund-safety statement can be
made. `Zkp.Implementation.Keccak256` is a reference specification of Keccak-256
in the same sense: it is the function the two hash premises name, not a model of
any in-repo source line.

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
here in their REDUCED, PER-PRIMITIVE form, uniformly: the fields (a), (b1) and
(b2) are `ClosePrimitiveLowering`, `WithdrawalPrimitiveLowering` and
`PostClosePrimitiveLowering`, each of which asks only that a satisfiable plonky2
statement of the pinned digest yield an ASSIGNMENT satisfying this project's own
per-builder-call semantics of the SAME program (`BuildOp.holds` over
`constructorProgram`) that reads back to that statement. The step from "the
pinned verifier accepted this proof" to "the returned public inputs belong to a
satisfiable plonky2 statement of the pinned circuit" is exactly (a0)
`mleVerifierSoundness`; the step from an assignment satisfying the program to the
handwritten gate predicate is PROVED, per circuit, by
`CloseCircuit.program_satisfied_implies_gates`,
`WithdrawalClaimCircuit.program_satisfied_implies_gates` and
`PostCloseClaimCircuit.program_satisfied_implies_gates` — no whole-circuit black
box is assumed anywhere. Splitting the premises this way makes the borrowed
halves disjoint: no field bundles the accepted artifact with an unaccepted
lowering, and no field hides the gate derivation.

Two sub-obligations remain genuinely opaque inside each of (a), (b1), (b2), and
nothing in this project discharges either: (i) PRIMITIVE-SEMANTICS FAITHFULNESS —
each `BuildOp.holds` case must be exactly the constraint plonky2 emits for that
one builder call (`range_check`, `connect`, `add_virtual_bool_target_safe`,
`mul`/`sub`/`add`, `select`, the hash gadgets, the recursive-proof verifies, the
Merkle/insertion gadgets); and (ii) DIGEST PINNING — `pinnedCircuitDigest
adapter` must be the digest of the very program `constructorProgram`
transcribes. Sub-obligation (ii) is also stated on its own, as
`ClosePinnedDigestIsProgramDigest`, `WithdrawalPinnedDigestIsProgramDigest` and
`PostClosePinnedDigestIsProgramDigest`, and the three
`*_digest_pinning_and_program_lowering_give_primitive_lowering` theorems show
that (ii) plus a program-level lowering is what each field amounts to.

The older, statement-level lowering obligations (`CloseStatementLowering`,
`WithdrawalStatementLowering`, `PostCloseStatementLowering`) and the still older,
monolithic "acceptance implies a satisfying witness" conclusions are all still
available with the same statements and the same argument lists, but now as
THEOREMS — `close_statement_lowering_of_boundary`,
`close_proof_soundness_of_boundary`,
`withdrawal_proof_soundness_of_boundary`,
`post_close_proof_soundness_of_boundary` and their siblings — proved from (a0)
plus the corresponding per-primitive field, so every consumer is unchanged while
nothing is assumed twice.

The hash boundary is split the same way, and for the same reason. Keccak-256 is
no longer one opaque callback that the circuit side and the contract side are
merely assumed to share. `Zkp.Implementation.Keccak256` specifies the algorithm,
and the boundary becomes two independent sentences about two different artifacts:
(e1a) `solidityKeccakIsReference` — the EVM `KECCAK256` opcode computes the
reference on canonical bytes — and (e1b) `circuitKeccakIsReference` — the pinned
`plonky2_keccak` gadget computes the reference on the big-endian-packed u32 words.
The old single field is recovered as the theorem
`circuit_keccak_is_solidity_keccak_of_boundary`, and
`reference_keccak_models_satisfy_hash_premises` exhibits the models that satisfy
both halves, so the pair is not vacuous. Field (e2) `tokenFundsHashBinding` is
now stated about `Keccak256.keccak256` itself rather than about the opaque
boundary callback, `token_funds_hash_binding_of_boundary` recovers the old
callback form from it and (e1a), and
`token_funds_binding_is_same_length_collision` states what is left of it: a
collision of Keccak-256 on ONE pair of 368-byte strings, the ABI-faithfulness
half having been proved in `SettlementCloseBridge`.

The signature boundary is split five ways, and every one of the five is now
per-primitive or per-artifact. The old single field `signatureValidity` said that
a passing aggregate check means the close message was authorized by that many of
those keys — one implication bundling a recursive-verifier claim, a
circuit-lowering claim, the aggregation tree's bookkeeping and the whole of
Falcon's cryptography. Its first replacement, the quadruple (d0), (d1), (d2),
(d3), still named two whole gate structures: (d1) `aggregateStatementLowering`
asked for a `FalconAggregate.AggTree` evaluating to the exposed statement, and
(d2) `falconPredicateIsGadget` identified an opaque `Bool` accept callback with
the whole of `FalconCore.CircuitSatisfied`. Both are gone, together with the
`Models` parameters they needed (`sigEnv`, `falconMul`, `aggregateCircuitDigest`).

`Zkp.Implementation.FalconGadgetProgram` transcribes `FalconSigVerifyTarget::build`
(gadget.rs:651-736) as a 23-call builder program and PROVES
`FalconCore.CircuitSatisfied` for the concrete product the circuit computes;
`Zkp.Implementation.FalconAggProgram` transcribes the leaf and level constructors
of `src/falcon_sig/agg.rs` the same way, splices the gadget transcript into the
leaf's signature call, and PROVES the induction over the four circuits — the tree,
the count bounds, the left packing with its exactly-zero suffix and the single
shared message. What is left is carried as: (d0)
`aggregateRecursiveVerifierSoundness` at the top constant key, (d0')
`levelRecursionSoundness` at each level's constant child key, (d1')
`aggregatePrimitiveLowering` — per-builder-call at every level, down to and
including the gadget — (d2') `nttComputesNegacyclicProduct`, and (d3)
`falconUnforgeability`. `signature_validity_of_boundary` composes (d0), (d0'),
(d1') and (d3) into `CloseSignatureBridge.SignerEvidence` (it does not need
(d2')), and `signature_gap_is_now_per_primitive` names those four residues as one
conjunction, replacing the former `signature_gap_is_now_per_signature` — two of
whose conjuncts no longer exist as Props. The digest-pinning half is stated on its
own, outside the structure, as `AggregateLevelPinnedDigestIsProgramDigest`,
exactly as the three settlement endpoints have done since the first loop.

The two durability premises are reduced the same way, and one of them carried a
FALSE clause. `Zkp.Implementation.LedgerWriters` pins the write-site inventory of
the five flagged storage variables — one Solidity assignment each, re-derived from
the sources on every CI run by `.github/ci/check-ledger-writers.py` — and proves
the model-level frame theorems over an enumeration of every modeled entrypoint of
`ManagerValue` and `CloseFunding`. The premises become (g1')
`ledgerWritersAreInventoried` and (g2') `latchWritersAreInventoried`: every
transition outside the model that touches that storage is a run of an inventoried
entrypoint. The old conclusions come back as the theorems
`durable_nullifier_ledger_of_boundary` and
`durable_materialization_latch_of_boundary`.

**THE FINDING (2026-09-11), recorded here and in (g1')'s docstring.** The former
(g1) `durableNullifierLedger` asserted `cap t = cap s` for transitions outside the
model. That clause is REFUTED by the deployed contract:
`ChannelSettlementManager.sol:1681`, inside `_finalizeClose` and reached from the
external `finalizeCloseGuarded`, does `finalizedChannelFundAmount[baseToken] +=
...`; the entrypoint is modeled — by `ManagerValue.finalizeCloseCore` — but it is
NOT a `SystemSafety.Step` constructor, so it lives in the UNMODELED relation and
raises the cap. The corrected clause is MONOTONE, `cap s tok ≤ cap t tok`, which
is what `durable_nullifier_ledger_of_boundary` concludes and what
`LedgerWriters.manager_entrypoints_are_ledger_monotone` proves;
`LedgerWriters.only_cap_writer_is_outside_step` pins that this is the single
exception. Nothing downstream is weakened, because `SystemSafety` never consumed
(g1) or (g2).

The eighteen fields, in order: (a0) `mleVerifierSoundness`, (a)
`closePrimitiveLowering`, (b1) `withdrawalPrimitiveLowering`, (b2)
`postClosePrimitiveLowering`, (c) `closeVectorBacked`, (d0)
`aggregateRecursiveVerifierSoundness`, (d0') `levelRecursionSoundness`, (d1')
`aggregatePrimitiveLowering`, (d2') `nttComputesNegacyclicProduct`, (d3)
`falconUnforgeability`, (e1a) `solidityKeccakIsReference`, (e1b)
`circuitKeccakIsReference`, (e2) `tokenFundsHashBinding`, (f1)
`finalizedRootObservation`, (f2) `finalizedHeightObservation`, (g1')
`ledgerWritersAreInventoried`, (g2') `latchWritersAreInventoried`, (h)
`sourceRefinement`.

The single inhabitation result below is deliberately degenerate: in an
environment where every proof adapter returns a failure, no plonky2 statement is
satisfiable at all and no recursive child verification ever succeeds, every
acceptance-guarded premise holds vacuously, every lowering premise holds
vacuously, the unforgeability premise holds because the authorization relation is
taken to be trivial, and every storage premise holds because no transition outside
the model is admitted. Two fields are the exception and are supplied as
hypotheses rather than made vacuous — the two hash equations and (d2'), which is
a universal claim about two concrete Lean functions and mentions no environment at
all. That witnesses only well-formedness of the statement, and
`rejecting_environment_accepts_no_close` records why: such an environment
authorizes no fund movement at all.
-/

namespace Zkp.Implementation.TrustBoundary

/-- Per-channel deposit attribution: `d channel token` is the number of raw units
of `token` that entered the Rollup escrow on behalf of `channel`. No modeled
contract maintains this map; it is the accounting the Balance/validity circuit
family is supposed to enforce off-chain. -/
abbrev ChannelDeposits := Nat → Nat → Nat

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
  /-- Hash environment of the single-signature model `FalconCore`: the
  `hash_to_point` and Poseidon callbacks the `gadget.rs` gate set is stated over.
  A parameter, exactly like `closeEnv`; nothing here defines Poseidon. The
  polynomial product is NOT a parameter any more: `FalconGadgetProgram`
  transcribes the in-circuit NTT, so every field that used to be read against an
  abstract `falconMul` is now read against the concrete
  `FalconGadgetProgram.circuitProduct`. -/
  falconHash : FalconCore.HashEnvironment
  /-- Pinned circuit identity of EACH level of the Falcon aggregation stack:
  `aggregateLevelDigest k` is the circuit digest of the level-`k` circuit of
  `src/falcon_sig/agg.rs`, with level 0 the LEAF circuit
  (`FalconLeafCircuit::new`, agg.rs:268-305) and level 3
  (`FalconAggregate.aggLevels`) the TOP circuit whose constant verifier key
  `closeEnv.aggregateVerifier` is, i.e. the one the close circuit verifies its
  aggregate proof against. Levels 1 and 2 are the intermediate
  `FalconAggLevelCircuit`s, each of which recursively verifies the level below at
  its own constant child verifier data.

  It is a parameter here, exactly like `pinnedCircuitDigest`; nothing in this
  project derives a digest from a circuit, and nothing proves that the key a
  level circuit pins is the key of the circuit `FalconAggProgram` transcribes at
  that level. That last claim is stated on its own as
  `AggregateLevelPinnedDigestIsProgramDigest` and is not a field. Only (d0),
  (d0') and (d1') mention this map. -/
  aggregateLevelDigest : Nat → List Nat
  /-- Aggregation-stack recursion environment of `src/falcon_sig/agg.rs`: the
  OPAQUE child-verification relation `verifyChild` standing for plonky2's
  in-circuit recursive verifier (`add_proof_target_and_verify` /
  `add_proof_target_and_conditionally_verify`, agg.rs:399 and :403-404), together
  with the CONSTANT child verifier data each level circuit bakes in
  (agg.rs:99-105, :394-404). Premises (d0') and (d1') and the derived signer
  evidence all speak of THIS environment, so the proofs a level circuit is
  claimed to have verified and the assignments its transcript is claimed to admit
  cannot drift apart.

  Its type parameter is the SAME `AggregateProof` that `closeEnv` uses. That is
  deliberate and is part of what the field says: the recursive proof object the
  close circuit verifies at the top of the stack is the same kind of artifact the
  level circuits verify one level down — one plonky2 proof type for the whole
  aggregation stack, not two unrelated ones. Reading (d0) and (d0') against a
  single proof type is what lets the top-level statement (d0) produces feed the
  per-level induction (d0') and (d1') run. -/
  aggEnv : FalconAggProgram.LevelEnvironment AggregateProof
  /-- `authorized h digest` is the intended meaning of a Falcon signature: the
  holder of the public polynomial `h` authorized the message digest `digest`
  (as its 8 `Bytes32` limbs). It replaces the former `signers` relation one level
  down — per SIGNATURE rather than per aggregate — and it is the relation premise
  (d3) concludes and the derived `CloseSignatureBridge.SignerEvidence` reports.
  Poseidon stays opaque, so nothing here ties `h` to a registered member; that
  remains the close circuit's member-set obligation. -/
  authorized : List Nat → List Nat → Prop
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
  gates or assignments — and only `MleAcceptedStatementsAreSatisfiable`, the
  three `*StatementLowering` obligations and the three aggregate-signature fields
  (d0) `aggregateRecursiveVerifierSoundness`, (d0') `levelRecursionSoundness` and
  (d1') `aggregatePrimitiveLowering` ever mention it. The aggregate triple uses it
  at DIFFERENT digests, the four `aggregateLevelDigest k`, and behind a different
  verifier (the close circuit's in-circuit recursive verify and the level
  circuits' own recursive verifies, not the settlement contract's MLE/WHIR call),
  which is precisely why accepting the MLE/WHIR artifact in (a0) says nothing
  about (d0) or (d0'). -/
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

/-! ## The three statement-lowering obligations (now derived, not assumed)

Each proof endpoint (close, withdrawal claim, post-close claim) splits its
soundness gap the same way. The step from "the pinned verifier accepted this
proof" to "the returned words are the public inputs of a SATISFIABLE plonky2
statement of the pinned circuit" is the accepted artifact assumption (a0)
`MleAcceptedStatementsAreSatisfiable`, once, for all endpoints. The step from
there to "some witness satisfies the handwritten `CircuitGates` of the model" is
per-endpoint and is NOT covered by the acceptance.

The three definitions immediately below state that second step at the coarsest
granularity — the whole handwritten gate predicate at once. They are NO LONGER
fields of the premise structure: each is now a THEOREM about a boundary instance
(`close_statement_lowering_of_boundary` and its siblings), derived from the
strictly finer per-primitive premises of the next section. They are kept because
consumers and the `*_gap_is_exactly_statement_lowering` theorems are stated in
their terms. -/

/-- The step the accepted MLE/WHIR premise does NOT cover on the close path: that
the plonky2 statement identified by the close adapter's pinned circuit digest,
carrying the very words the Solidity side bound, is the circuit
`Zkp.Implementation.CloseCircuit` models — so that a satisfying assignment of it
yields a satisfying witness of `CloseCircuit.CircuitGates`. This is the COARSE
form of the obligation: it names the whole handwritten gate predicate. It is not
assumed any more — `close_primitive_lowering_implies_statement_lowering` derives
it from `ClosePrimitiveLowering` through
`CloseCircuit.program_satisfied_implies_gates`. -/
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
`Zkp.Implementation.WithdrawalClaimCircuit` models. Coarse form again, and no
longer assumed: `withdrawal_primitive_lowering_implies_statement_lowering`
derives it from `WithdrawalPrimitiveLowering` through
`WithdrawalClaimCircuit.program_satisfied_implies_gates`. -/
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
which satisfies `PostCloseClaimCircuit.ConstructorGates`. Coarse form again, and
no longer assumed:
`post_close_primitive_lowering_implies_statement_lowering` derives it from
`PostClosePrimitiveLowering` through
`PostCloseClaimCircuit.program_satisfied_implies_gates`. -/
def PostCloseStatementLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.PostCloseFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.postClose)
        (ClaimSettlementBridge.postCloseStatement f).words →
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w

/-! ## The three per-primitive lowering obligations — the OFFICIAL premises

These are fields (a), (b1) and (b2) of `TrustBoundary`. Each replaces the
whole-circuit black box above by the finest obligation the circuit models can
express: a satisfiable plonky2 statement of the pinned digest, carrying the words
the Solidity side bound, yields an ASSIGNMENT of every wire the Rust constructor
allocates which satisfies this project's own per-builder-call semantics
(`BuildOp.holds`) of the SAME ordered program `constructorProgram`, and whose
public wires read back to exactly that statement.

Everything downstream of such an assignment is proved here, not assumed: the
handwritten gate predicates follow by `program_satisfied_implies_gates` in each
circuit module, with no side hypothesis. What is still borrowed is exactly two
things, and they are named rather than bundled:

* (i) PRIMITIVE-SEMANTICS FAITHFULNESS. Every `BuildOp.holds` case must be
  precisely the constraint the corresponding plonky2 builder call emits. This is
  a finite, per-call obligation — one clause at a time, each readable against one
  line of the Rust constructor — but it is not modeled here, because plonky2's
  gate semantics is not modeled here.
* (ii) DIGEST PINNING. `m.pinnedCircuitDigest adapter` must be the digest of the
  circuit that `constructorProgram` transcribes, so that the statement (a0)
  hands over really belongs to THIS program. Stated separately below as
  `ClosePinnedDigestIsProgramDigest` and its siblings.

Neither (i) nor (ii) is proved anywhere in this project, and no theorem may treat
either as established. -/

/-- **(a), official form.** Per-primitive close lowering: a satisfiable plonky2
statement of the close adapter's pinned circuit digest, carrying the 103 close
words, has an assignment of the constructor's wires that satisfies every
`CloseCircuit.BuildOp.holds` case of `CloseCircuit.constructorProgram` and whose
public wires are exactly that statement. Remaining opaque parts: (i) faithfulness
of each `holds` case to the plonky2 primitive it transcribes, (ii)
`ClosePinnedDigestIsProgramDigest`. -/
def ClosePrimitiveLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.CloseFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.close)
        (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words →
      ∃ a : CloseCircuit.Assignment m.closeEnv,
        CloseCircuit.ProgramSatisfied CloseCircuit.constructorProgram a ∧
          CloseCircuit.readPublic a =
            SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val

/-- **(b1), official form.** The same reduction on the withdrawal-claim endpoint:
an assignment satisfying every `WithdrawalClaimCircuit.BuildOp.holds` case of
`WithdrawalClaimCircuit.constructorProgram`, reading back to the bound 50-word
statement. Remaining opaque parts: (i) per-`holds` primitive faithfulness, (ii)
`WithdrawalPinnedDigestIsProgramDigest`. -/
def WithdrawalPrimitiveLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.WithdrawalFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.withdrawal)
        (ClaimSettlementBridge.withdrawalStatement f).words →
      ∃ a : WithdrawalClaimCircuit.Assignment m.claimEnv,
        WithdrawalClaimCircuit.ProgramSatisfied WithdrawalClaimCircuit.constructorProgram a ∧
          WithdrawalClaimCircuit.readPublic a = ClaimSettlementBridge.withdrawalStatement f

/-- **(b2), official form.** The same reduction on the post-close-claim endpoint.
That circuit's model reads the registered public inputs out of the raw witness
itself, so the read-back condition is on `(readWitness a).p` rather than on a
separate `readPublic`. Remaining opaque parts: (i) per-`holds` primitive
faithfulness, (ii) `PostClosePinnedDigestIsProgramDigest`. -/
def PostClosePrimitiveLowering {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) : Prop :=
  ∀ f : SettlementVerifier.PostCloseFields,
    m.plonky2Satisfiable (m.pinnedCircuitDigest m.installed.adapters.postClose)
        (ClaimSettlementBridge.postCloseStatement f).words →
      ∃ a : PostCloseClaimCircuit.Assignment m.postEnv,
        PostCloseClaimCircuit.ProgramSatisfied PostCloseClaimCircuit.constructorProgram a ∧
          (PostCloseClaimCircuit.readWitness a).p = ClaimSettlementBridge.postCloseStatement f

/-! ### Sub-obligation (ii), stated on its own

`digestOf` is the (unmodeled) function taking an ordered builder program to the
circuit digest plonky2 computes for it. Nothing in this project defines it — it
is a parameter, exactly like `Models.pinnedCircuitDigest` — so these three Props
assert only that the adapter the settlement verifier pins carries the digest of
OUR transcribed program. Together with a lowering stated about
`digestOf constructorProgram`, each one yields the corresponding official
premise; that factorization is the content of the three
`*_digest_pinning_and_program_lowering_give_primitive_lowering` theorems below,
and it is the honest reading of what fields (a), (b1), (b2) still borrow. -/

/-- (ii) for the close endpoint: the pinned close adapter's circuit digest is the
digest of `CloseCircuit.constructorProgram`. -/
def ClosePinnedDigestIsProgramDigest
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : List CloseCircuit.BuildOp → List Nat) : Prop :=
  m.pinnedCircuitDigest m.installed.adapters.close = digestOf CloseCircuit.constructorProgram

/-- (ii) for the withdrawal-claim endpoint. -/
def WithdrawalPinnedDigestIsProgramDigest
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : List WithdrawalClaimCircuit.BuildOp → List Nat) : Prop :=
  m.pinnedCircuitDigest m.installed.adapters.withdrawal =
    digestOf WithdrawalClaimCircuit.constructorProgram

/-- (ii) for the post-close-claim endpoint. -/
def PostClosePinnedDigestIsProgramDigest
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : List PostCloseClaimCircuit.BuildOp → List Nat) : Prop :=
  m.pinnedCircuitDigest m.installed.adapters.postClose =
    digestOf PostCloseClaimCircuit.constructorProgram

/-- (ii) for the FOUR circuits of the Falcon aggregation stack, stated once for
all levels. `digestOf k` is the (unmodeled) circuit digest plonky2 computes for
the level-`k` builder transcript of `FalconAggProgram` — `leafProgram` at `k = 0`
and `levelProgram k` at `k ∈ {1, 2, 3}` — so the map, not a single list, is what
has to be pinned. The Prop says the digest map (d0), (d0') and (d1') are all read
against IS that one, at every level of the stack.

This is deliberately NOT a field. Keeping it outside the structure is what makes
(d1') an obligation about the TRANSCRIPT alone: the level lowering says "a
satisfiable statement at `aggregateLevelDigest k` admits an assignment of the
level-`k` transcript", and this Prop is the separate claim that those two
circuits are the same circuit. The old (d1) `aggregateStatementLowering` asserted
both at once; the close, withdrawal and post-close endpoints have kept them apart
since the first loop, and the aggregation stack now does too. Nothing here proves
either half. -/
def AggregateLevelPinnedDigestIsProgramDigest
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : Nat → List Nat) : Prop :=
  ∀ k : Nat, k ≤ FalconAggregate.aggLevels → m.aggregateLevelDigest k = digestOf k

/-- **The per-primitive premise really does yield the coarse one.** Given an
assignment satisfying `CloseCircuit.constructorProgram` whose public wires are
the bound statement, `CloseCircuit.program_satisfied_implies_gates` produces the
gate witness `CloseCircuit.readWitness a` with NO further hypothesis. So nothing
is lost by replacing field (a) with its per-primitive form — the whole-circuit
black box is now derived. -/
theorem close_primitive_lowering_implies_statement_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (lowering : ClosePrimitiveLowering m) : CloseStatementLowering m := by
  intro f satisfiable
  obtain ⟨a, satisfied, readsBack⟩ := lowering f satisfiable
  refine ⟨CloseCircuit.readWitness a, ?_⟩
  have gates := CloseCircuit.program_satisfied_implies_gates m.closeEnv a satisfied
  rwa [readsBack] at gates

/-- The withdrawal-claim analogue, through
`WithdrawalClaimCircuit.program_satisfied_implies_gates`. -/
theorem withdrawal_primitive_lowering_implies_statement_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (lowering : WithdrawalPrimitiveLowering m) : WithdrawalStatementLowering m := by
  intro f satisfiable
  obtain ⟨a, satisfied, readsBack⟩ := lowering f satisfiable
  refine ⟨WithdrawalClaimCircuit.readWitness a, ?_⟩
  have gates := WithdrawalClaimCircuit.program_satisfied_implies_gates m.claimEnv a satisfied
  rwa [readsBack] at gates

/-- The post-close-claim analogue. Here the raw witness read back from the
assignment carries its own public record, so the statement equality of
`PostCloseStatementLowering` is exactly the read-back condition of the premise. -/
theorem post_close_primitive_lowering_implies_statement_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (lowering : PostClosePrimitiveLowering m) : PostCloseStatementLowering m := by
  intro f satisfiable
  obtain ⟨a, satisfied, readsBack⟩ := lowering f satisfiable
  exact ⟨PostCloseClaimCircuit.readWitness a, readsBack,
    PostCloseClaimCircuit.program_satisfied_implies_gates m.postEnv a satisfied⟩

/-- **What field (a) still borrows, factored.** Digest pinning (ii) plus a
lowering stated about the digest of `CloseCircuit.constructorProgram` — whose
only remaining content is (i), the faithfulness of each `BuildOp.holds` case to
the plonky2 primitive it transcribes — give the official premise. Neither factor
is proved here. -/
theorem close_digest_pinning_and_program_lowering_give_primitive_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : List CloseCircuit.BuildOp → List Nat)
    (pinned : ClosePinnedDigestIsProgramDigest m digestOf)
    (perPrimitive : ∀ f : SettlementVerifier.CloseFields,
      m.plonky2Satisfiable (digestOf CloseCircuit.constructorProgram)
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words →
        ∃ a : CloseCircuit.Assignment m.closeEnv,
          CloseCircuit.ProgramSatisfied CloseCircuit.constructorProgram a ∧
            CloseCircuit.readPublic a =
              SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) :
    ClosePrimitiveLowering m := by
  intro f satisfiable
  have identity : m.pinnedCircuitDigest m.installed.adapters.close =
      digestOf CloseCircuit.constructorProgram := pinned
  rw [identity] at satisfiable
  exact perPrimitive f satisfiable

/-- The same factorization on the withdrawal-claim endpoint. -/
theorem withdrawal_digest_pinning_and_program_lowering_give_primitive_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : List WithdrawalClaimCircuit.BuildOp → List Nat)
    (pinned : WithdrawalPinnedDigestIsProgramDigest m digestOf)
    (perPrimitive : ∀ f : SettlementVerifier.WithdrawalFields,
      m.plonky2Satisfiable (digestOf WithdrawalClaimCircuit.constructorProgram)
          (ClaimSettlementBridge.withdrawalStatement f).words →
        ∃ a : WithdrawalClaimCircuit.Assignment m.claimEnv,
          WithdrawalClaimCircuit.ProgramSatisfied WithdrawalClaimCircuit.constructorProgram a ∧
            WithdrawalClaimCircuit.readPublic a = ClaimSettlementBridge.withdrawalStatement f) :
    WithdrawalPrimitiveLowering m := by
  intro f satisfiable
  have identity : m.pinnedCircuitDigest m.installed.adapters.withdrawal =
      digestOf WithdrawalClaimCircuit.constructorProgram := pinned
  rw [identity] at satisfiable
  exact perPrimitive f satisfiable

/-- The same factorization on the post-close-claim endpoint. -/
theorem post_close_digest_pinning_and_program_lowering_give_primitive_lowering
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (digestOf : List PostCloseClaimCircuit.BuildOp → List Nat)
    (pinned : PostClosePinnedDigestIsProgramDigest m digestOf)
    (perPrimitive : ∀ f : SettlementVerifier.PostCloseFields,
      m.plonky2Satisfiable (digestOf PostCloseClaimCircuit.constructorProgram)
          (ClaimSettlementBridge.postCloseStatement f).words →
        ∃ a : PostCloseClaimCircuit.Assignment m.postEnv,
          PostCloseClaimCircuit.ProgramSatisfied PostCloseClaimCircuit.constructorProgram a ∧
            (PostCloseClaimCircuit.readWitness a).p = ClaimSettlementBridge.postCloseStatement f) :
    PostClosePrimitiveLowering m := by
  intro f satisfiable
  have identity : m.pinnedCircuitDigest m.installed.adapters.postClose =
      digestOf PostCloseClaimCircuit.constructorProgram := pinned
  rw [identity] at satisfiable
  exact perPrimitive f satisfiable

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
  lowering: that the plonky2 statement a digest identifies is built by the
  program these models transcribe, and that each builder call constrains what the
  model says it constrains, is a separate obligation per endpoint — exactly what
  the three PER-PRIMITIVE fields (a), (b1), (b2) below still require, under their
  two named opaque halves (i) primitive-semantics faithfulness and (ii) digest
  pinning. It says nothing about the KZG
  attestation or Proof-DA availability path, which stays a distinct boundary of
  `MleProverBridge` and `BlobJournal`. It says nothing about plonky2's own
  recursive verifier, which the close circuit invokes on the Falcon aggregate
  proof and which the three aggregation level circuits invoke on their children:
  those are (d0) and (d0'), separate un-accepted premises, even though the
  recursive verifier ships in the same pinned submodule. It says nothing about the
  correctness of the public inputs a caller passes in: the Solidity binding pins
  which words were returned, it never validates that they describe a real
  channel. And a satisfiable statement is not by itself a safe fund movement —
  that step still needs premises (c), (d0), (d0'), (d1'), (d2'), (d3), (e1a),
  (e1b), (e2), (f1), (f2) and (g1'). See
  `mle_assumption_reduces_close_soundness_to_gate_lowering` for what the
  acceptance buys, and
  `Zkp.Implementation.SystemSafety.mle_assumption_does_not_imply_fund_safety` for
  an environment in which this premise holds and fund safety fails anyway. -/
  mleVerifierSoundness : MleAcceptedStatementsAreSatisfiable m
  /-- **(a) Close PER-PRIMITIVE lowering — the ONLY remaining half of close-proof
  soundness; the MLE step is (a0).** `SettlementCloseBridge` proves only WHICH
  103-word statement a successful `verifyCloseIntent` returned, never that the
  statement is true. Given (a0), what is still missing is the lowering, and it is
  taken here in its finest form: a satisfiable plonky2 statement of the close
  adapter's pinned circuit digest, carrying those 103 words, yields an ASSIGNMENT
  of the wires `ChannelCloseCircuit::new` allocates which satisfies every
  `CloseCircuit.BuildOp.holds` case of `CloseCircuit.constructorProgram` and
  whose public wires read back to that statement.

  Nothing beyond that is assumed: `CloseCircuit.program_satisfied_implies_gates`
  turns such an assignment into a witness of `CloseCircuit.CircuitGates` with no
  side hypothesis, so the whole-circuit `CloseStatementLowering` is a THEOREM
  about this field (`close_statement_lowering_of_boundary`) and the old
  monolithic "acceptance implies a satisfying witness" form is recovered from
  this field and (a0) by `close_proof_soundness_of_boundary`.

  WHAT REMAINS OPAQUE inside this field, and nowhere else: (i) primitive-
  semantics faithfulness — each `BuildOp.holds` case must be exactly the
  constraint plonky2's corresponding builder call emits (`range_check`,
  `connect`, `add_virtual_bool_target_safe`, `mul`/`sub`/`add`, `assert_one`,
  `is_equal`/`and`, `select`, `keccak256`, `add_proof_target_and_verify(_cyclic)`,
  `conditional_get_new_root`); and (ii) digest pinning — `pinnedCircuitDigest
  m.installed.adapters.close` must be the digest of `constructorProgram`, stated
  separately as `ClosePinnedDigestIsProgramDigest` and factored out by
  `close_digest_pinning_and_program_lowering_give_primitive_lowering`. Neither is
  modeled or proved in this project. -/
  closePrimitiveLowering : ClosePrimitiveLowering m
  /-- **(b1) Withdrawal-claim PER-PRIMITIVE lowering — lowering only; the MLE step
  is (a0).** `ClaimSettlementBridge` ties an accepted withdrawal claim to the
  exact 50-word statement only. Given (a0), the missing direction is an
  assignment satisfying every `WithdrawalClaimCircuit.BuildOp.holds` case of
  `WithdrawalClaimCircuit.constructorProgram` whose public wires read back to
  those 50 words; `WithdrawalClaimCircuit.program_satisfied_implies_gates` then
  gives `WithdrawalClaimCircuit.CircuitGates` outright, so
  `withdrawal_statement_lowering_of_boundary` and
  `withdrawal_proof_soundness_of_boundary` are theorems, not assumptions.

  WHAT REMAINS OPAQUE: (i) per-`holds` primitive faithfulness (range checks, the
  eleven-bit active sum, the ten equality flags, the select chains, the Regev
  decryption core, the inclusion gadget); (ii) digest pinning, stated as
  `WithdrawalPinnedDigestIsProgramDigest`. -/
  withdrawalPrimitiveLowering : WithdrawalPrimitiveLowering m
  /-- **(b2) Post-close-claim PER-PRIMITIVE lowering — lowering only; the MLE step
  is (a0).** Same reduction for the 57-word post-close endpoint: given (a0), a
  satisfiable plonky2 statement of the post-close adapter's pinned circuit digest
  carrying those 57 words yields an assignment satisfying every
  `PostCloseClaimCircuit.BuildOp.holds` case of its `constructorProgram` whose
  raw witness carries exactly that statement as its public record;
  `PostCloseClaimCircuit.program_satisfied_implies_gates` then gives
  `PostCloseClaimCircuit.ConstructorGates`, so
  `post_close_statement_lowering_of_boundary` and
  `post_close_proof_soundness_of_boundary` are theorems.

  WHAT REMAINS OPAQUE: (i) per-`holds` primitive faithfulness (the range and
  virtual-allocation widths, the hash preimage widths, the connects, the two
  Merkle verifies, the decryption core); (ii) digest pinning, stated as
  `PostClosePinnedDigestIsProgramDigest`. -/
  postClosePrimitiveLowering : PostClosePrimitiveLowering m
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
  /-- **(d0) Aggregate recursive-verifier soundness at the TOP key — NOT covered
  by (a0).** `CloseCircuit.CircuitGates.aggregateVerified` is an opaque predicate
  call standing for plonky2's in-circuit recursive verification of the Falcon
  aggregation proof against the constant verifier key `aggregateVerifier`. This
  premise says a passing such check means the circuit identified by
  `aggregateLevelDigest FalconAggregate.aggLevels` — the TOP circuit of the
  aggregation stack, the one that key belongs to — really has a satisfiable
  statement at the 73 aggregate public-input words.

  ONE KEY ONLY. This field is about the verify the CLOSE circuit performs, and
  therefore about the top of the stack alone. The three verifies the level
  circuits perform on their children are a different claim at three different
  constant keys, carried separately as (d0') `levelRecursionSoundness`. Splitting
  them is what lets the induction over the four circuits run without any field
  quantifying over proofs the close circuit never sees.

  EXPLICITLY NOT COVERED BY THE ACCEPTED PREMISE (a0). The acceptance recorded in
  (a0) is scoped to ONE artifact: the pinned MLE/WHIR verifier the settlement
  contract calls, Rust and Solidity sides. plonky2's own recursive FRI verifier
  ships in the same pinned `contracts/lib/polygon-plonky2` submodule, but it was
  not accepted, it is a different proof system with a different soundness
  argument, and it is invoked in a different place — inside the close circuit,
  not from the chain. Sharing a submodule with an accepted artifact is not an
  acceptance. So this is a distinct, un-accepted premise, and it would be
  discharged only by a soundness proof of plonky2's recursive verifier at that
  constant key. -/
  aggregateRecursiveVerifierSoundness :
    ∀ (proof : AggregateProof) (st : CloseCircuit.AggregateStatement),
      m.closeEnv.verifyAggregate m.closeEnv.aggregateVerifier proof st →
      m.plonky2Satisfiable (m.aggregateLevelDigest FalconAggregate.aggLevels) st.words
  /-- **(d0') Recursive-verifier soundness at each LEVEL's constant child key —
  NOT covered by (a0) and NOT covered by (d0).** Each of the three
  `FalconAggLevelCircuit`s verifies its two children in-circuit, at the CONSTANT
  child verifier data it bakes in (`add_proof_target_and_verify` on the left,
  agg.rs:399; `add_proof_target_and_conditionally_verify` on the right,
  agg.rs:403-404; the constant is agg.rs:394-398 with the A7 binding of
  agg.rs:99-105). `m.aggEnv.verifyChild` is that verification as an opaque
  relation; this premise says a child proof it accepts at level `k` means the
  level-`(k-1)` circuit really is satisfiable at the public inputs the parent
  read out of it.

  SAME ARTIFACT SCOPE AS (d0), DIFFERENT INSTANCES. It is the same plonky2
  recursive verifier, at three more constant keys, inside three more circuits, and
  it is no more accepted than (d0) is: (a0) covers the MLE/WHIR verifier the
  settlement contract calls, and nothing else. Nothing here models a plonky2
  proof, so this cannot be discharged in this project at all; it would need a
  soundness proof of the recursive verifier at those keys.

  WHAT IT BUYS. Together with (d1') it is what replaces the whole-circuit (d1)
  `aggregateStatementLowering`: the aggregation TREE is no longer assumed to exist
  behind a satisfiable top statement — it is DERIVED, level by level, by
  `FalconAggProgram.satisfiable_top_level_gives_witness_list`, from these two
  fields and nothing else. -/
  levelRecursionSoundness :
    FalconAggProgram.RecursionSound
      (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv
  /-- **(d1') Aggregation-stack PER-PRIMITIVE lowering — replaces the last
  whole-circuit premise of this structure.** For every level of the stack, a
  satisfiable plonky2 statement at that level's pinned digest yields an ASSIGNMENT
  of the wires the corresponding Rust constructor allocates which satisfies this
  project's own per-builder-call semantics of the SAME ordered program, and whose
  registered public inputs read back to exactly those words:

  * at the LEAF (level 0) the assignment is a `FalconGadgetProgram.GadgetAssignment`
    satisfying every one of the 23 `holds` cases of
    `FalconGadgetProgram.gadgetProgram` (the transcript of
    `FalconSigVerifyTarget::build`, gadget.rs:651-736), TOGETHER WITH a
    `FalconAggProgram.LeafAssignment` whose signature wires are that gadget
    assignment's, the call-site wiring `FalconAggProgram.LeafWiring`
    (agg.rs:234-239, :271, :274, :279 and the two `Bytes32Target::new(_, true)`
    range checks of gadget.rs:659-661), and the leaf's seven OTHER builder calls
    of agg.rs:268-305;
  * at levels 1, 2 and 3 the assignment satisfies every `holds` case of
    `FalconAggProgram.levelProgram k`, the transcript of
    `FalconAggLevelCircuit::new` (agg.rs:370-479).

  NO GATE STRUCTURE APPEARS AS A WHOLE ANYWHERE IN IT. That is the whole point of
  this field: the old (d1) `aggregateStatementLowering` asked for a
  `FalconAggregate.AggTree` evaluating to the exposed statement — a claim about
  an entire circuit family — and the old (d2) `falconPredicateIsGadget` related an
  opaque `Bool` callback to `FalconCore.CircuitSatisfied`, another whole gate set.
  Both are gone. The tree, the left packing, the shared message, the signer count
  and `CircuitSatisfied` itself are now DERIVED —
  `FalconAggProgram.leaf_program_satisfied_of_gadget_program`,
  `FalconAggProgram.level_program_satisfied_implies_compose`,
  `FalconAggProgram.satisfiable_top_level_gives_witness_list` and
  `FalconGadgetProgram.gadget_program_satisfied_implies_circuit_satisfied`, none of
  which takes a side hypothesis.

  WHAT REMAINS OPAQUE inside this field, exactly as for (a), (b1), (b2): (i)
  PRIMITIVE-SEMANTICS FAITHFULNESS — each `holds` case must be precisely the
  constraint plonky2 emits for that one builder call
  (`add_proof_target_and_verify`, `add_proof_target_and_conditionally_verify`,
  `add_virtual_bool_target_safe`, `sub`, `mul`, `add`, `assert_zero`, `constant`,
  `range_check`, `register_public_input(s)`, the Poseidon sponge calls); and (ii)
  DIGEST PINNING — that `aggregateLevelDigest k` is the digest of the level-`k`
  transcript, stated separately and NOT as a field, as
  `AggregateLevelPinnedDigestIsProgramDigest`. Neither is modeled or proved here.

  The still-opaque arithmetic content of the signature primitive — that the
  transcribed NTT is the negacyclic product — is (d2'), and this field does not
  need it: `FalconGadgetProgram.circuitProduct` is a concrete function either way. -/
  aggregatePrimitiveLowering :
    FalconAggProgram.GadgetLevelLowering
      (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv
      m.falconHash
  /-- **(d2') The transcribed in-circuit NTT computes the negacyclic product.**
  `FalconGadgetProgram.circuitProduct` is not a callback: it is the CONCRETE
  composition "forward-transform both operands, multiply pointwise,
  inverse-transform" that gadget.rs:684-687 performs, with the twiddle tables,
  the butterflies and the mod-`q` reductions transcribed. This premise says that
  concrete function is the negacyclic product of `Z_q[X]/(X^512+1)` —
  `FalconGadgetProgram.negacyclicProduct`, the schoolbook definition transcribed
  from the Rust test at gadget.rs:999-1022 — on canonical length-512 inputs.

  IT REPLACES A PARAMETER, NOT A PROOF. The models used to carry an opaque
  `falconMul : FalconCore.PolynomialProduct`; (d2) then said the aggregation
  model's `Bool` accept callback was the gadget gate set for THAT product. Both
  are gone. The product is now fixed to the transcribed NTT and the gate set is
  reached through `FalconGadgetProgram.gadget_program_satisfied_implies_circuit_satisfied`,
  which needs no premise at all. What is left is this one arithmetic sentence
  about a concrete algorithm.

  NOT NEEDED BY THE SIGNER-EVIDENCE THEOREM. `signature_validity_of_boundary`
  does not use this field, and neither does anything it calls: the evidence chain
  runs entirely through `FalconCore.CircuitSatisfied` for `circuitProduct`, and
  (d3) is stated for the same concrete product, so the two meet without knowing
  what the NTT computes. This premise is needed only to read
  `FalconCore.CircuitSatisfied` as Falcon's own `verify` — i.e. to say the gate
  set checks the REAL signature equation `s1 = c - s2 * h mod (q, X^512+1)` rather
  than an equation about some other bilinear map. Without it the audit's
  signature conclusion is "the transcribed gate set is satisfied and its solutions
  are unforgeable"; with it, that gate set is Falcon.

  It is an ordinary mathematical claim about a concrete algorithm — the Rust test
  suite checks it on random inputs — and it is the only field of this structure a
  determined prover could discharge inside Lean, by proving the NTT correct. It is
  not discharged here. -/
  nttComputesNegacyclicProduct : FalconGadgetProgram.NttComputesNegacyclicProduct
  /-- **(d3) Falcon unforgeability.** The lattice assumption in the form a consumer
  can use: a satisfied active gadget instance for public polynomial `h` and message
  digest `d` means the holder of `h` authorized `d`. This is
  `FalconCore.LatticeHardness` / `ntruShortVectorAssumption` made into an
  implication, now stated for the CONCRETE `FalconGadgetProgram.circuitProduct`
  rather than for a parameter, so it cannot be read against a different product
  from the one (d1') lowers into. It is a COMPUTATIONAL assumption about NTRU/GPV
  lattices and cannot be discharged in this project at all; no proof about the
  Rust, the circuit or the contracts would establish it. -/
  falconUnforgeability :
    CloseSignatureBridge.FalconUnforgeable m.falconHash FalconGadgetProgram.circuitProduct
      m.authorized
  /-- **(e1a) The Solidity boundary hash IS Keccak-256.** The `Keccak` callback the
  settlement-verifier model calls stands for the EVM `KECCAK256` opcode
  (`keccak256(abi.encodePacked(...))` in the deployed contract). This premise says
  that callback is the reference specification `Zkp.Implementation.Keccak256`, read
  as a `uint256` the way Solidity reads it, on canonical byte strings. It is an
  EVM-semantics premise, kin to (h) `sourceRefinement` rather than to any circuit
  premise: it would be discharged by an extracted EVM semantics in which the opcode
  is specified, and by nothing inside this audit. -/
  solidityKeccakIsReference :
    ∀ b : SettlementVerifier.Bytes, (∀ x ∈ b, x < 256) →
      m.keccak b = Keccak256.digestU256 b
  /-- **(e1b) The in-circuit hash gadget IS Keccak-256.** The close circuit's
  `keccak` callback stands for the external `plonky2_keccak` gadget — the crate
  pinned in `Cargo.lock` at git rev
  `2507786148ae6323d0ea547bf88e1752f901434e` (branch `wasm-main`), which is outside
  this audit's translation scope. This premise says that gadget computes the
  reference Keccak-256 of the big-endian-packed u32 words, packed back into the
  circuit's 8-limb `Words8`.

  NOT A PART OF (a). Field (a)'s per-primitive faithfulness obligation for the
  keccak `BuildOp` cases says only that the gadget CONSTRAINS `out = e.keccak
  preimage` — that the circuit really commits its output to the callback's value.
  It says nothing about WHICH function `e.keccak` is; (e1b) is exactly that, and
  nothing else. The two are independent: a faithful constraint on a wrong hash
  and a right hash left unconstrained are different failures. Discharged by a
  correctness proof of the pinned gadget at that revision. -/
  circuitKeccakIsReference :
    ∀ words : List Nat,
      m.closeEnv.keccak words =
        SettlementCloseBridge.digest
          (Keccak256.digestU256 (SettlementCloseBridge.wordBytes words))
  /-- **(e2) Keccak-256 collision resistance on ONE same-length pair.** No global
  injectivity is ever assumed, and the premise is not about an opaque callback any
  more: it is about the reference `Keccak256.keccak256`, restricted to the
  token-vector preimages actually compared inside an accepted close execution — if
  their digests agree, the byte strings agree. It is the `concreteBinding`
  hypothesis of
  `SettlementCloseBridge.bound_close_preserves_entire_settlement_vector` (through
  `token_funds_hash_binding_of_boundary`, which restores the `m.keccak` form from
  this field and (e1a)).

  THE ABI HALF IS NOW PROVED, NOT BORROWED. The old docstring named "collision
  resistance together with ABI-encoding faithfulness"; the second conjunct is gone.
  `SettlementCloseBridge.token_funds_preimage_injective` proves the Solidity layout
  is injective in (registry, count, amounts), and
  `SettlementCloseBridge.token_funds_compared_strings_same_length` proves both
  compared strings are 368 bytes long, so no length-extension, padding ambiguity,
  domain-separation slip or field-ordering slip can produce the collision — see
  `token_funds_binding_is_same_length_collision`. What remains is solely the
  COMPUTATIONAL claim that Keccak-256 has no collision on that one concrete pair,
  which cannot be discharged in this project. -/
  tokenFundsHashBinding :
    ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
      (w : CloseCircuit.PrivateWitness),
      SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
      Keccak256.keccak256 (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)) =
          Keccak256.keccak256 (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
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
  /-- **(g1') The Manager's ledger writers are inventoried.** A SOURCE-REFINEMENT
  premise, kin to (h) rather than to any circuit premise: every transition outside
  the model that touches the flagged Manager storage — the used-nullifier set, the
  received and paid counters, the per-token funding cap — is a run of one of the
  entrypoints `LedgerWriters.ManagerEntrypoint` enumerates, on states projecting
  to the two the transition relates, and one that `SystemSafety.Step` does not
  already cover.

  WHAT IT REPLACES. The old (g1) `durableNullifierLedger` asserted the CONSEQUENCE
  directly — no unmodeled transition clears a nullifier or moves the counters —
  and it asserted one clause that is FALSE of the deployed contract (see the
  finding below). This field asserts only the inventory; the durability
  consequence is now the THEOREM `durable_nullifier_ledger_of_boundary`, proved
  from this field plus `LedgerWriters.manager_entrypoints_are_ledger_monotone` and
  `LedgerWriters.non_step_manager_entrypoints_are_ledger_neutral_except_cap`. The
  borrowed part shrinks from "the ledger is durable" to "these are the only
  writers".

  **THE FINDING (2026-09-11): the old (g1) clause `cap t = cap s` is REFUTED by the
  deployed contract.** `ChannelSettlementManager.sol:1681`, inside `_finalizeClose`
  and reached from the external `finalizeCloseGuarded`, does
  `finalizedChannelFundAmount[baseToken] += ...`. That entrypoint IS modeled — by
  `ManagerValue.finalizeCloseCore` — but it is NOT a `SystemSafety.Step`
  constructor, so a real `finalizeCloseGuarded` call sits in the UNMODELED
  relation of this structure and raises the cap. Any instance of the old
  structure over a `Deployed`/`Modeled` pair that admits it was therefore
  unsatisfiable, not merely unproved. The corrected clause is MONOTONE,
  `cap s tok ≤ cap t tok`, which is what `durable_nullifier_ledger_of_boundary`
  concludes; `LedgerWriters.only_cap_writer_is_outside_step` pins that this is the
  single exception, and `LedgerWriters.finalize_close_only_raises_cap` gives the
  exact increment. Nothing downstream weakens: `SystemSafety` never consumed (g1).

  WHY IT IS PLAUSIBLE AT SOURCE LEVEL. `LedgerWriters.flaggedWriteSites` is the
  pinned write-site inventory of the reviewed Solidity text, and it has exactly
  ONE assignment per flagged variable — `usedWithdrawalNullifiers` :2231
  (set-only), `receivedChannelFunds` :2364, `totalCreditedOut` :2398 (`+=` only,
  cap-guarded), `finalizedChannelFundAmount` :1681 (`+=` only) — each inside an
  entrypoint this enumeration carries. No proxy, `delegatecall`, `selfdestruct`,
  initializer or assembly `sstore` touches the contract, and the Rollup cannot
  write Manager storage. `.github/ci/check-ledger-writers.py` re-derives the list
  from the sources on every CI run and fails if any other `.sol` file under
  `contracts/src` writes one of them, so the inventory cannot rot silently.

  WHAT REMAINS BORROWED. Two things this project does not model: that the deployed
  BYTECODE implements the reviewed source (the CI check is a text scan, blind to
  an inline `sstore` through an inherited library, a proxy upgrade or a compiler
  bug), and that EVM storage isolation keeps every other contract and every other
  transaction off these slots. Exactly the (h)-flavoured residue, now attached to
  a finite, re-derivable list instead of to a durability claim. -/
  ledgerWritersAreInventoried :
    ∀ s t : σ, Unmodeled s t →
      ((managerOf t).used ≠ (managerOf s).used ∨
        (managerOf t).received ≠ (managerOf s).received ∨
        (managerOf t).paid ≠ (managerOf s).paid ∨
        (managerOf t).cap ≠ (managerOf s).cap) →
      ∃ (call : LedgerWriters.ManagerEntrypoint) (fs ft : ManagerValue.FullState),
        fs.value = managerOf s ∧ ft.value = managerOf t ∧ call.run fs = some ft ∧
          call.stepCovered = false
  /-- **(g2') The materializer's latch writers are inventoried.** The same
  source-refinement premise for `CloseFundingMaterializer`: every transition
  outside the model that changes the materializer's storage at all is a run of one
  of the seven entrypoints `LedgerWriters.MaterializerEntrypoint` enumerates, on
  worlds whose storage components are the two states the transition relates.

  WHAT IT REPLACES. The old (g2) `durableMaterializationLatch` asserted the
  consequence — a latched channel exit is never rewritten by anything outside the
  model — which is now the THEOREM
  `durable_materialization_latch_of_boundary`, proved from this field and
  `LedgerWriters.materializer_entrypoints_keep_the_latch`. As with (g1'), what is
  borrowed shrinks from a durability claim to an inventory claim.

  WHY IT IS PLAUSIBLE AT SOURCE LEVEL. `materializedChannelExit` has exactly one
  write site in the reviewed text, `CloseFundingMaterializer.sol:461` inside
  `_materialize`, reached only from the external `materializeSignedHead` and
  guarded by the `== 0` read at :434 — the row
  `LedgerWriters.flaggedWriteSites` pins and `.github/ci/check-ledger-writers.py`
  re-derives. The other six modeled entrypoints do not name the variable at all,
  and no proxy, `delegatecall`, `selfdestruct` or assembly `sstore` appears in the
  contract.

  WHAT REMAINS BORROWED. The same two things as (g1'): bytecode-equals-source, and
  EVM storage isolation against every other contract and transaction. -/
  latchWritersAreInventoried :
    ∀ s t : σ, Unmodeled s t → fundingOf t ≠ fundingOf s →
      ∃ (call : LedgerWriters.MaterializerEntrypoint) (w v : CloseFunding.World),
        w.storage = fundingOf s ∧ v.storage = fundingOf t ∧ call.run w = some v
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
assumed). The remaining gap to the old close soundness conclusion is then
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
the old premise (a) in exactly the form `close_proof_soundness_of_boundary`
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

/-! ## End-to-end from the OFFICIAL, per-primitive premises

The three theorems above compose (a0) with the coarse statement lowering. The
three below do the same from the premises the structure actually carries: (a0)
plus a per-primitive lowering give, with no further hypothesis, the old
acceptance-implies-gates conclusion. They are the forms every consumer should
read, because their hypotheses are the fields of `TrustBoundary`. -/

/-- **(a0) + the per-primitive field (a) ⇒ the old close soundness conclusion.**
The per-primitive premise is strictly finer than `CloseStatementLowering`, and
the gate derivation in between is proved, not assumed. -/
theorem mle_and_primitive_lowering_is_close_proof_soundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : ClosePrimitiveLowering m) :
    ∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true →
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w :=
  mle_assumption_with_lowering_is_close_proof_soundness m mleSound
    (close_primitive_lowering_implies_statement_lowering m lowering)

/-- **(a0) + the per-primitive field (b1) ⇒ the old withdrawal-claim soundness
conclusion.** -/
theorem mle_and_primitive_lowering_is_withdrawal_proof_soundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : WithdrawalPrimitiveLowering m) :
    ∀ (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true →
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w :=
  mle_assumption_with_lowering_is_withdrawal_proof_soundness m mleSound
    (withdrawal_primitive_lowering_implies_statement_lowering m lowering)

/-- **(a0) + the per-primitive field (b2) ⇒ the old post-close-claim soundness
conclusion.** -/
theorem mle_and_primitive_lowering_is_post_close_proof_soundness
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : PostClosePrimitiveLowering m) :
    ∀ (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes),
      SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true →
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w :=
  mle_assumption_with_lowering_is_post_close_proof_soundness m mleSound
    (post_close_primitive_lowering_implies_statement_lowering m lowering)

/-! ## The old monolithic premises, recovered as theorems

Splitting the premise bundle must not cost any consumer its conclusion. The three
theorems below carry the statements and the argument lists the former
`TrustBoundary` FIELDS `closeProofSoundness`, `withdrawalProofSoundness` and
`postCloseProofSoundness` had, with the boundary instance moved to the front as
an ordinary explicit argument: `close_proof_soundness_of_boundary tb f proof
accepted` proves exactly what `tb.closeProofSoundness f proof accepted` used to
— with the difference that it is now derived from (a0) plus the corresponding
per-primitive lowering field instead of being assumed outright.

The same applies one level down: the statement-level lowerings themselves used to
be the fields, and are now theorems about a boundary instance. -/

/-- The whole-circuit close lowering, recovered from the per-primitive field (a).
This is what `closeStatementLowering` used to assert as a FIELD. -/
theorem close_statement_lowering_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf) :
    CloseStatementLowering m :=
  close_primitive_lowering_implies_statement_lowering m tb.closePrimitiveLowering

/-- The whole-circuit withdrawal-claim lowering, recovered from field (b1). -/
theorem withdrawal_statement_lowering_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf) :
    WithdrawalStatementLowering m :=
  withdrawal_primitive_lowering_implies_statement_lowering m tb.withdrawalPrimitiveLowering

/-- The whole-circuit post-close-claim lowering, recovered from field (b2). -/
theorem post_close_statement_lowering_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf) :
    PostCloseStatementLowering m :=
  post_close_primitive_lowering_implies_statement_lowering m tb.postClosePrimitiveLowering

/-- **(a0) + (a) ⇒ the old premise (a).** An accepted close proof implies some
witness satisfies `CloseCircuit.CircuitGates` for the same 103-word statement.
This used to be a field of the structure; it is now proved from the accepted
MLE/WHIR premise and the per-primitive close lowering. -/
theorem close_proof_soundness_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
      CloseCircuit.CircuitGates m.closeEnv
        (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w :=
  mle_and_primitive_lowering_is_close_proof_soundness m tb.mleVerifierSoundness
    tb.closePrimitiveLowering f proof accepted

/-- **(a0) + (b1) ⇒ the old premise (b1).** An accepted withdrawal claim implies
some witness satisfies `WithdrawalClaimCircuit.CircuitGates` for the same 50-word
statement. Formerly a field, now proved. -/
theorem withdrawal_proof_soundness_of_boundary
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
  mle_and_primitive_lowering_is_withdrawal_proof_soundness m tb.mleVerifierSoundness
    tb.withdrawalPrimitiveLowering f proof accepted

/-- **(a0) + (b2) ⇒ the old premise (b2).** An accepted post-close claim implies
a raw witness whose public record is the bound 57-word statement and which
satisfies `PostCloseClaimCircuit.ConstructorGates`. Formerly a field, now
proved. -/
theorem post_close_proof_soundness_of_boundary
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
  mle_and_primitive_lowering_is_post_close_proof_soundness m tb.mleVerifierSoundness
    tb.postClosePrimitiveLowering f proof accepted

/-! ## What remains, per endpoint

Each of the three theorems below says the same thing about one endpoint: with the
accepted premise (a0) in hand, the ONLY step left between "the pinned verifier
accepted this proof" and "the model's gate system is satisfied for the bound
statement" is that endpoint's `*StatementLowering` — which is itself now derived
from the finer, official `*PrimitiveLowering` field (see the next section).

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

/-! ## Where the gap actually sits now: inside one builder call at a time

The three theorems above are stated against the coarse `*StatementLowering`,
which is no longer a premise of anything. The three below are stated against the
premises the structure really carries, and they say what the reduction bought:
under (a0) plus a per-primitive lowering, an accepted proof yields BOTH a wire
assignment satisfying this project's own semantics of the transcribed builder
program AND the handwritten gate predicate for the bound statement. No
whole-circuit black box is left in the premise; what is left is (i) whether each
`BuildOp.holds` case is faithful to the plonky2 primitive it stands for, and (ii)
whether the pinned digest is the digest of that program — both named, neither
proved, and both strictly smaller than "the deployed circuit satisfies our gate
predicate". The conclusion is still only about gates: a satisfying assignment is
never, by itself, a safe payment. -/

/-- **Close: the black box is gone from the premise.** Under (a0) and the
per-primitive field (a), an accepted close proof yields a satisfying assignment
of `CloseCircuit.constructorProgram` reading back to the bound 103-word
statement, and a witness of `CloseCircuit.CircuitGates` for that same statement.
Only per-`holds` primitive faithfulness and digest pinning remain borrowed. -/
theorem close_gap_is_now_per_primitive
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : ClosePrimitiveLowering m)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    (∃ a : CloseCircuit.Assignment m.closeEnv,
        CloseCircuit.ProgramSatisfied CloseCircuit.constructorProgram a ∧
          CloseCircuit.readPublic a =
            SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) ∧
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w := by
  have composed := mle_assumption_reduces_close_soundness_to_gate_lowering m mleSound
    (close_primitive_lowering_implies_statement_lowering m lowering) f proof accepted
  exact ⟨lowering f composed.2.1, composed.2.2⟩

/-- **Withdrawal claim: the black box is gone from the premise.** Same shape,
through `WithdrawalClaimCircuit.program_satisfied_implies_gates`. -/
theorem withdrawal_gap_is_now_per_primitive
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : WithdrawalPrimitiveLowering m)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true) :
    (∃ a : WithdrawalClaimCircuit.Assignment m.claimEnv,
        WithdrawalClaimCircuit.ProgramSatisfied WithdrawalClaimCircuit.constructorProgram a ∧
          WithdrawalClaimCircuit.readPublic a = ClaimSettlementBridge.withdrawalStatement f) ∧
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w := by
  have composed := mle_assumption_reduces_withdrawal_soundness_to_gate_lowering m mleSound
    (withdrawal_primitive_lowering_implies_statement_lowering m lowering) f proof accepted
  exact ⟨lowering f composed.2.1, composed.2.2⟩

/-- **Post-close claim: the black box is gone from the premise.** Same shape,
with the statement read back out of the raw witness the assignment defines. -/
theorem post_close_gap_is_now_per_primitive
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (mleSound : MleAcceptedStatementsAreSatisfiable m)
    (lowering : PostClosePrimitiveLowering m)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyPostCloseClaim m.evm m.installed f proof = .ok true) :
    (∃ a : PostCloseClaimCircuit.Assignment m.postEnv,
        PostCloseClaimCircuit.ProgramSatisfied PostCloseClaimCircuit.constructorProgram a ∧
          (PostCloseClaimCircuit.readWitness a).p = ClaimSettlementBridge.postCloseStatement f) ∧
      ∃ w : PostCloseClaimCircuit.RawWitness,
        w.p = ClaimSettlementBridge.postCloseStatement f ∧
          PostCloseClaimCircuit.ConstructorGates m.postEnv w := by
  have composed := mle_assumption_reduces_post_close_soundness_to_gate_lowering m mleSound
    (post_close_primitive_lowering_implies_statement_lowering m lowering) f proof accepted
  exact ⟨lowering f composed.2.1, composed.2.2⟩

/-! ## The hash boundary: the old single premise, recovered

Field (e1) used to say "the circuit's keccak callback and the Solidity keccak
boundary are the same function", with no statement of WHICH function either is.
That is two different artifacts — the EVM opcode and the pinned `plonky2_keccak`
gadget — sharing one unnamed value, so a single wrong implementation on either
side would have been indistinguishable from agreement. The pair (e1a)/(e1b) names
the function, `Zkp.Implementation.Keccak256`, and says each artifact computes it;
the old field is then the theorem below and nothing is lost. -/

/-- The bytes `SettlementCloseBridge.wordBytes` produces are canonical: every one
is a real byte. Needed to apply (e1a), which is stated only on canonical strings
because `SettlementVerifier.Bytes` is `List Nat` and the EVM opcode's semantics is
undefined on anything else. -/
theorem word_bytes_are_canonical_bytes (ws : List Nat) :
    ∀ b ∈ SettlementCloseBridge.wordBytes ws, b < 256 := by
  induction ws with
  | nil =>
    intro b hb
    simp [SettlementCloseBridge.wordBytes] at hb
  | cons w ws ih =>
    intro b hb
    simp only [SettlementCloseBridge.wordBytes, List.mem_append] at hb
    rcases hb with head | tail
    · exact SettlementVerifier.beBytes_canonical 4 w b head
    · exact ih b tail

/-- The Solidity-side token-funds preimage is canonical too: it is a concatenation
of fixed-width big-endian encodings, and `SettlementVerifier.beBytes_canonical`
covers each one. -/
theorem token_funds_preimage_bytes_are_canonical
    (registry : Fin 10 → SettlementVerifier.U32) (count : SettlementVerifier.U8)
    (amounts : Fin 10 → SettlementVerifier.U256) :
    ∀ b ∈ SettlementVerifier.tokenFundsPreimage registry count amounts, b < 256 := by
  have append : ∀ xs ys : List Nat, (∀ x ∈ xs, x < 256) → (∀ x ∈ ys, x < 256) →
      ∀ x ∈ xs ++ ys, x < 256 := by
    intro xs ys hx hy x hmem
    rcases List.mem_append.mp hmem with head | tail
    · exact hx x head
    · exact hy x tail
  have joined : ∀ (n : Nat) (g : Fin 10 → Nat),
      ∀ x ∈ (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes n (g i)).join,
        x < 256 := by
    intro n g x hx
    obtain ⟨s, hs, hxs⟩ := List.mem_join.mp hx
    simp only [SettlementVerifier.tenList, List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      exact SettlementVerifier.beBytes_canonical _ _ _ hxs
  intro b hb
  simp only [SettlementVerifier.tokenFundsPreimage] at hb
  refine append _ _ (append _ _ (append _ _ ?_ ?_) ?_) ?_ b hb
  · exact fun x hx => SettlementVerifier.beBytes_canonical _ _ _ hx
  · exact joined 4 (fun i => (registry i).val)
  · exact fun x hx => SettlementVerifier.beBytes_canonical _ _ _ hx
  · exact joined 32 (fun i => (amounts i).val)

/-- **The old field (e1), now a theorem.** (e1a) says the Solidity boundary hash is
the reference Keccak-256 and (e1b) says the circuit gadget is; together they say
the two agree, which is exactly what `circuitKeccakIsSolidityKeccak` used to
assert as a FIELD. The byte-range side condition of (e1a) is discharged by
`word_bytes_are_canonical_bytes`, so the theorem has no hypothesis the old field
did not have. -/
theorem circuit_keccak_is_solidity_keccak_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (words : List Nat) :
    m.closeEnv.keccak words = SettlementCloseBridge.circuitHash m.keccak words := by
  have solidity := tb.solidityKeccakIsReference (SettlementCloseBridge.wordBytes words)
    (word_bytes_are_canonical_bytes words)
  have circuit := tb.circuitKeccakIsReference words
  unfold SettlementCloseBridge.circuitHash
  rw [circuit, solidity]

/-- **The old field (e2), now a theorem.** The premise is stated about the
reference `Keccak256.keccak256`; a consumer holding a collision of the OPAQUE
boundary callback `m.keccak` gets there through (e1a): the callback's value is the
32 reference output bytes read big-endian, and that reading is injective on
32-byte canonical strings (`Keccak256.bytes_to_nat_injective`), so a collision of
the callback on these two canonical preimages IS a collision of the reference
digests. Statement and argument list are those the old field had. -/
theorem token_funds_hash_binding_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (w : CloseCircuit.PrivateWitness)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true)
    (collision :
      m.keccak (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)) =
        m.keccak (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
          f.channelFundAmounts)) :
    SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w) =
      SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts := by
  have witnessSide := tb.solidityKeccakIsReference
    (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w))
    (word_bytes_are_canonical_bytes (CloseCircuit.tokenFundsPreimage w))
  have fieldsSide := tb.solidityKeccakIsReference
    (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts)
    (token_funds_preimage_bytes_are_canonical f.tokenRegistry f.tokenCount f.channelFundAmounts)
  have digests :
      Keccak256.digestU256
          (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)) =
        Keccak256.digestU256
          (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
            f.channelFundAmounts) := by
    rw [← witnessSide, ← fieldsSide]
    exact collision
  have packed :
      Keccak256.bytesToNat (Keccak256.keccak256
          (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w))) =
        Keccak256.bytesToNat (Keccak256.keccak256
          (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
            f.channelFundAmounts)) := by
    have vals := congrArg Fin.val digests
    rwa [Keccak256.digest_u256_val, Keccak256.digest_u256_val] at vals
  have bytes :
      Keccak256.keccak256
          (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)) =
        Keccak256.keccak256
          (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
            f.channelFundAmounts) :=
    Keccak256.bytes_to_nat_injective _ _
      (by rw [Keccak256.keccak256_length, Keccak256.keccak256_length])
      (Keccak256.keccak256_bytes_canonical _) (Keccak256.keccak256_bytes_canonical _) packed
  exact tb.tokenFundsHashBinding f proof w accepted bytes

/-- **What (e2) actually asks for, spelled out.** For a witness of the shape the
close circuit's own constructor produces, the two compared byte strings are BOTH
368 bytes long, and the premise is exactly the implication "equal Keccak-256
digests on that pair ⇒ equal strings". So (e2) is a same-length collision claim on
one fixed, injective ABI layout — not hash injectivity, not a length-extension
assumption, not an encoding assumption. The injectivity of the layout itself is
`SettlementCloseBridge.token_funds_preimage_injective`, proved there; what is left
here is only the collision claim. -/
theorem token_funds_binding_is_same_length_collision
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (w : CloseCircuit.PrivateWitness) (shape : w.Shape)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)).length = 368 ∧
      (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
        f.channelFundAmounts).length = 368 ∧
      (Keccak256.keccak256
            (SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w)) =
          Keccak256.keccak256 (SettlementVerifier.tokenFundsPreimage f.tokenRegistry
            f.tokenCount f.channelFundAmounts) →
        SettlementCloseBridge.wordBytes (CloseCircuit.tokenFundsPreimage w) =
          SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
            f.channelFundAmounts) :=
  ⟨SettlementCloseBridge.witness_token_preimage_length w shape,
    SettlementCloseBridge.token_funds_preimage_length f.tokenRegistry f.tokenCount
      f.channelFundAmounts,
    tb.tokenFundsHashBinding f proof w accepted⟩

/-- **NON-VACUITY of the hash pair.** A model whose Solidity boundary hash is the
reference digest and whose circuit hash gadget is the reference digest of the
big-endian-packed words satisfies (e1a) and (e1b) — by definitional unfolding, no
cryptographic content whatsoever. This is what rules out the reading that the two
new fields are unsatisfiable together: they are simultaneously true of exactly the
environments in which both artifacts really do compute Keccak-256. -/
theorem reference_keccak_models_satisfy_hash_premises
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (solidity : m.keccak = fun b => Keccak256.digestU256 b)
    (circuit : m.closeEnv.keccak = fun words =>
      SettlementCloseBridge.digest
        (Keccak256.digestU256 (SettlementCloseBridge.wordBytes words))) :
    (∀ b : SettlementVerifier.Bytes, (∀ x ∈ b, x < 256) →
        m.keccak b = Keccak256.digestU256 b) ∧
      (∀ words : List Nat,
        m.closeEnv.keccak words =
          SettlementCloseBridge.digest
            (Keccak256.digestU256 (SettlementCloseBridge.wordBytes words))) := by
  constructor
  · intro b _
    simp [solidity]
  · intro words
    simp [circuit]

/-! ## The signature boundary: from four residues to per-primitive evidence

The old field (d) `signatureValidity` concluded an opaque `signers message keys
count` relation — a relation this module had to introduce precisely because
nothing was proved about what an accepted aggregate MEANS. It is gone, and so are
its first two replacements. (d1) `aggregateStatementLowering` asked for a whole
`FalconAggregate.AggTree`, and (d2) `falconPredicateIsGadget` related an opaque
`Bool` accept callback to the whole of `FalconCore.CircuitSatisfied`; both named
a gate structure as a unit. The four fields the structure now carries — (d0),
(d0'), (d1') and (d3) — name only per-builder-call transcripts, two instances of
plonky2's recursive verifier, and the lattice assumption. Everything between them
is PROVED, in `FalconGadgetProgram`, `FalconAggProgram` and
`CloseSignatureBridge`: the 23 gadget gates from the gadget transcript, the leaf
and level statements from their transcripts, the induction over the four
circuits, the count bounds, the left packing with its exactly-zero suffix and the
single shared message. -/

/-- **The old field (d), replaced and strengthened — now from per-primitive
premises only.** An accepted aggregate check yields
`CloseSignatureBridge.SignerEvidence`: between one and eight witnesses, whose
count is the exposed `signerCount`, whose key digests are the exposed key list
left-packed with an exactly-zero suffix, each of which ran against the ONE exposed
message and each of whose key holders authorized that message.

The name, the argument list and the shape of the conclusion are those the theorem
had before; what changed is the environment the evidence is reported in and the
premises it comes from. The environment is `FalconAggProgram.sigEnvOf
m.falconHash` — key digests are `FalconCore.falconPkDigest` in limb form and the
accept callback is the constant `true`, which `SignerEvidence` never reads,
because the per-slot evidence now comes from the gadget transcript rather than
from an opaque `Bool`. The `Models.sigEnv` parameter that used to carry it no
longer exists, so no environment can drift between the premise and the
conclusion.

The premises are (d0) recursion soundness at the top key, (d0') recursion
soundness at each level's constant child key, (d1') per-builder-call lowering all
the way down to the gadget, and (d3) unforgeability at the concrete
`FalconGadgetProgram.circuitProduct` — composed by
`FalconAggProgram.top_level_satisfiable_gives_signer_evidence_per_primitive`.
(d2') is NOT used: the chain never needs to know what the transcribed NTT
computes. Poseidon stays opaque throughout, so the conclusion speaks of key
DIGESTS, never of public polynomials. -/
theorem signature_validity_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (proof : AggregateProof) (st : CloseCircuit.AggregateStatement)
    (verified : m.closeEnv.verifyAggregate m.closeEnv.aggregateVerifier proof st) :
    CloseSignatureBridge.SignerEvidence (FalconAggProgram.sigEnvOf m.falconHash) m.authorized
      st.message st.keys st.signerCount :=
  FalconAggProgram.top_level_satisfiable_gives_signer_evidence_per_primitive m.aggEnv
    (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.falconHash
    m.authorized tb.levelRecursionSoundness tb.aggregatePrimitiveLowering
    tb.falconUnforgeability st
    (tb.aggregateRecursiveVerifierSoundness proof st verified)

/-- **The level-by-level lowering the induction actually consumes.** (d1') is
stated with the leaf's signature primitive spliced out into
`FalconGadgetProgram.gadgetProgram`; `FalconAggProgram.LevelLowering` is the same
obligation with the leaf clause stated through `FalconAggProgram.leafProgram` as
a whole, at the concrete `FalconGadgetProgram.circuitProduct`. The first implies
the second — `FalconAggProgram.gadget_level_lowering_implies_level_lowering` —
so a consumer that wants the coarser form has it, and nothing is assumed twice. -/
theorem level_lowering_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf) :
    FalconAggProgram.LevelLowering
      (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv
      m.falconHash FalconGadgetProgram.circuitProduct :=
  FalconAggProgram.gadget_level_lowering_implies_level_lowering
    (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv
    m.falconHash tb.aggregatePrimitiveLowering

/-- **What is left of the signature gap, named.** This theorem REPLACES
`signature_gap_is_now_per_signature`, which named the previous four residues:
two of them, the coarse (d1) and the gadget-identification (d2), no longer exist
as Props at all, so the old conjunction could not be restated. Exactly these four,
and nothing else, stand between "the close circuit's aggregate check passed" and
"each listed key digest belongs to a holder who authorized this message":

* (d0) plonky2's RECURSIVE VERIFIER is sound at the constant aggregate key the
  close circuit pins — an artifact obligation, and explicitly not part of the
  accepted premise (a0) even though that verifier ships in the same pinned
  submodule;
* (d0') the same verifier is sound at each LEVEL's constant child key — three more
  instances of the same artifact obligation, inside the aggregation circuits;
* (d1') PER-BUILDER-CALL LOWERING at every level, down to and including the 23
  calls of the signature gadget. No gate structure is named as a whole; what is
  borrowed is per-`holds` primitive faithfulness, plus the digest pinning stated
  apart as `AggregateLevelPinnedDigestIsProgramDigest`;
* (d3) FALCON UNFORGEABILITY at the concrete `FalconGadgetProgram.circuitProduct`
  — a computational lattice assumption, the only one of the four that no amount of
  translation work could ever discharge.

WHAT IS NOW PROVED, and therefore absent from this list: the 23 gadget gates from
the gadget transcript (`FalconGadgetProgram.gadget_program_satisfied_implies_circuit_satisfied`);
the leaf statement from the gadget transcript plus the leaf's own calls
(`FalconAggProgram.leaf_program_satisfied_of_gadget_program`,
`FalconAggProgram.leaf_program_satisfied_implies_statement`); each level's exposed
statement from its transcript, gated presence flag and left-packing gate included
(`FalconAggProgram.level_program_satisfied_implies_compose`); the INDUCTION over
the four circuits that turns a satisfiable top statement into a witness list
(`FalconAggProgram.satisfiable_top_level_gives_witness_list`); and the 73-word
public-input LAYOUT shared by the aggregation circuit and the close circuit
(`CloseSignatureBridge.to_agg_statement_public_inputs`). (d2') is not in the list
either, for a different reason: it is a residue of the PRODUCT, not of the
evidence chain, and no theorem above consumes it. -/
theorem signature_gap_is_now_per_primitive
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf) :
    (∀ (proof : AggregateProof) (st : CloseCircuit.AggregateStatement),
        m.closeEnv.verifyAggregate m.closeEnv.aggregateVerifier proof st →
        m.plonky2Satisfiable (m.aggregateLevelDigest FalconAggregate.aggLevels) st.words) ∧
      FalconAggProgram.RecursionSound
        (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv ∧
      FalconAggProgram.GadgetLevelLowering
        (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv
        m.falconHash ∧
      CloseSignatureBridge.FalconUnforgeable m.falconHash FalconGadgetProgram.circuitProduct
        m.authorized :=
  ⟨tb.aggregateRecursiveVerifierSoundness, tb.levelRecursionSoundness,
    tb.aggregatePrimitiveLowering, tb.falconUnforgeability⟩

/-! ## The two durability conclusions, recovered from the write-site inventory

Fields (g1) `durableNullifierLedger` and (g2) `durableMaterializationLatch` used
to assert their consequences outright. They are now theorems about the inventory
premises (g1') and (g2') and the model-level frame theorems of
`Zkp.Implementation.LedgerWriters`, with one correction: (g1)'s clause
`cap t = cap s` was REFUTED by the deployed contract and is replaced by
monotonicity. See the finding recorded in the module header and in (g1')'s
docstring. -/

/-- **The old field (g1), corrected and now proved.** Outside the modeled step
relation, no used withdrawal nullifier is ever cleared, the Manager's received and
paid counters never move, and the per-token funding cap never DECREASES.

The fourth clause is the correction. The old field said `cap t = cap s`; that is
false of the deployed contract, because `finalizeCloseGuarded` reaches
`finalizedChannelFundAmount[baseToken] += ...` at
`ChannelSettlementManager.sol:1681` and is not a `SystemSafety.Step` constructor,
so it is an UNMODELED transition that raises the cap. `cap s tok ≤ cap t tok` is
what the inventoried entrypoints really guarantee
(`LedgerWriters.manager_entrypoints_are_ledger_monotone`), and it is strong enough
for every consumer: `SystemSafety` never used (g1) at all.

The proof splits on whether the transition moved the flagged storage. If it did
not, all four clauses are immediate. If it did, (g1') produces an inventoried,
non-`Step`-covered entrypoint whose run relates the two projections, and the two
`LedgerWriters` frame theorems supply monotonicity and the counter frame. -/
theorem durable_nullifier_ledger_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (s t : σ) (unmodeled : Unmodeled s t) :
    (∀ n, (managerOf s).used n = true → (managerOf t).used n = true) ∧
      (managerOf t).received = (managerOf s).received ∧
      (managerOf t).paid = (managerOf s).paid ∧
      (∀ tok, (managerOf s).cap tok ≤ (managerOf t).cap tok) := by
  by_cases changed :
      (managerOf t).used ≠ (managerOf s).used ∨
        (managerOf t).received ≠ (managerOf s).received ∨
        (managerOf t).paid ≠ (managerOf s).paid ∨
        (managerOf t).cap ≠ (managerOf s).cap
  · obtain ⟨call, fs, ft, sourceValue, targetValue, ran, outside⟩ :=
      tb.ledgerWritersAreInventoried s t unmodeled changed
    have monotone := LedgerWriters.manager_entrypoints_are_ledger_monotone call fs ft ran
    have framed := LedgerWriters.non_step_manager_entrypoints_are_ledger_neutral_except_cap
      call fs ft outside ran
    rw [sourceValue, targetValue] at monotone framed
    exact ⟨monotone.1, framed.2.1, framed.2.2, monotone.2⟩
  · have used : (managerOf t).used = (managerOf s).used :=
      Classical.byContradiction fun differs => changed (Or.inl differs)
    have received : (managerOf t).received = (managerOf s).received :=
      Classical.byContradiction fun differs => changed (Or.inr (Or.inl differs))
    have paid : (managerOf t).paid = (managerOf s).paid :=
      Classical.byContradiction fun differs => changed (Or.inr (Or.inr (Or.inl differs)))
    have cap : (managerOf t).cap = (managerOf s).cap :=
      Classical.byContradiction fun differs => changed (Or.inr (Or.inr (Or.inr differs)))
    exact ⟨fun n live => by rw [used]; exact live, received, paid,
      fun tok => Nat.le_of_eq (congrFun cap tok).symm⟩

/-- **The old field (g2), now proved, with its statement unchanged.** A channel
exit that has already been latched is never rewritten by a transition outside the
model. If the materializer's storage did not change at all the claim is immediate;
otherwise (g2') produces an inventoried entrypoint whose run relates the two
storages, and `LedgerWriters.materializer_entrypoints_keep_the_latch` — which
covers all seven modeled entrypoints, the single `_materialize` writer of
`CloseFundingMaterializer.sol:461` included — gives the conclusion. -/
theorem durable_materialization_latch_of_boundary
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerOf : σ → ManagerValue.State} {fundingOf : σ → CloseFunding.State}
    (tb : TrustBoundary m Deployed Modeled Unmodeled managerOf fundingOf)
    (s t : σ) (unmodeled : Unmodeled s t) (c : CloseFunding.Channel)
    (live : (fundingOf s).materializedChannelExit c ≠ 0) :
    (fundingOf t).materializedChannelExit c = (fundingOf s).materializedChannelExit c := by
  by_cases untouched : fundingOf t = fundingOf s
  · rw [untouched]
  · obtain ⟨call, w, v, sourceStorage, targetStorage, ran⟩ :=
      tb.latchWritersAreInventoried s t unmodeled untouched
    have kept := LedgerWriters.materializer_entrypoints_keep_the_latch call w v ran c
      (by rw [sourceStorage]; exact live)
    rw [sourceStorage, targetStorage] at kept
    exact kept

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
passes, no recursive child verification succeeds at any level, the authorization
relation is trivially true, no finality is observed, and no transition outside the
model or from the deployed artifact is admitted. This is a well-formedness check
on the statement, NOT evidence that any field holds of a real deployment. In
particular the hypotheses below describe an environment in which no close, no
claim and no materialization can ever succeed, in which the accepted MLE/WHIR
premise `mleVerifierSoundness` holds only because the pinned adapter never returns
a word vector at all, and in which the three PER-PRIMITIVE lowering premises (a),
(b1), (b2) hold only because `noSatisfiableStatements` denies them their
antecedent — no assignment of any constructor program is ever exhibited, so
neither half of what those fields borrow (per-`holds` primitive faithfulness,
digest pinning) is discharged here in any useful sense; they are merely vacuous.

The five signature fields are vacuous, trivial, or supplied outright, in three
different ways. (d0) holds because `noAggregate` denies it its antecedent, (d0')
because `noChildVerified` does — the opaque `aggEnv.verifyChild` relation is empty,
so the per-level recursion premise is never tested — and (d1') because
`noSatisfiableStatements` does, at every level, so neither a gadget assignment nor
a leaf nor a level assignment is ever exhibited. (d3) holds because
`authorizedTrivially` makes its conclusion hold of everything, which is the
opposite of the lattice assumption having been discharged.

(d2') is the exception, and it is worth being explicit about why. It cannot be
made vacuous by any choice of environment: `FalconGadgetProgram.NttComputesNegacyclicProduct`
is a UNIVERSAL claim about two concrete Lean functions — the transcribed in-circuit
NTT and the schoolbook negacyclic product — with no reference to `m` at all. There
is no antecedent to deny and no callback to choose, so exhibiting an environment
cannot discharge it; it has to be supplied, and it is supplied here as the
hypothesis `nttProduct`. That mirrors the two hash premises, which are likewise
supplied as equations rather than vacuously: `solidityReference` and
`circuitReference` say the two boundary functions ARE the reference Keccak-256,
which is what `reference_keccak_models_satisfy_hash_premises` shows is achievable,
not something this environment proves.

The two inventory premises (g1') and (g2') are vacuous for the plainest possible
reason: `Unmodeled` is instantiated to the empty relation, so there is no
transition outside the model to inventory. -/
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
    (noChildVerified : ∀ k proof pis, ¬ m.aggEnv.verifyChild k proof pis)
    (nttProduct : FalconGadgetProgram.NttComputesNegacyclicProduct)
    (authorizedTrivially : ∀ h d, m.authorized h d)
    (solidityReference : ∀ b : SettlementVerifier.Bytes, (∀ x ∈ b, x < 256) →
      m.keccak b = Keccak256.digestU256 b)
    (circuitReference : ∀ words : List Nat,
      m.closeEnv.keccak words =
        SettlementCloseBridge.digest
          (Keccak256.digestU256 (SettlementCloseBridge.wordBytes words)))
    (noFinality : ∀ root, m.funding.isFinalizedRoot root ≠ .ok true)
    (noHeight : ∀ n, m.funding.latestFinalized ≠ .ok n) :
    TrustBoundary m (fun _ _ => False) Modeled (fun _ _ => False) managerOf fundingOf where
  mleVerifierSoundness adapter proof _ _ returned :=
    Except.noConfusion (returned.symm.trans (rejects adapter proof))
  closePrimitiveLowering :=
    fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)
  withdrawalPrimitiveLowering :=
    fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)
  postClosePrimitiveLowering :=
    fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)
  closeVectorBacked f proof accepted :=
    absurd accepted (rejecting_environment_accepts_no_close m rejects f proof)
  aggregateRecursiveVerifierSoundness proof st verified :=
    absurd verified (noAggregate proof st)
  levelRecursionSoundness := fun k _ _ proof pis verified =>
    absurd verified (noChildVerified k proof pis)
  aggregatePrimitiveLowering :=
    ⟨fun _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _),
      fun _ _ _ _ satisfiable => absurd satisfiable (noSatisfiableStatements _ _)⟩
  nttComputesNegacyclicProduct := nttProduct
  falconUnforgeability cw digest _ _ _ := authorizedTrivially cw.h digest
  solidityKeccakIsReference := solidityReference
  circuitKeccakIsReference := circuitReference
  tokenFundsHashBinding f proof _ accepted :=
    absurd accepted (rejecting_environment_accepts_no_close m rejects f proof)
  finalizedRootObservation root observed := absurd observed (noFinality root)
  finalizedHeightObservation n observed := absurd observed (noHeight n)
  ledgerWritersAreInventoried _ _ impossible := impossible.elim
  latchWritersAreInventoried _ _ impossible := impossible.elim
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
