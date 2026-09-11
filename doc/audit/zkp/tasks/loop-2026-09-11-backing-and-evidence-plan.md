# Loop plan 2026-09-11 (fourth loop): close-vector backing (c), NTT correctness (d2'), mechanical faithfulness evidence

Operator direction (2026-09-11): fill the gaps toward a publishable practical safety proof,
"somewhat loose is acceptable", autonomous judgment; (a0) and (d3) are out of scope. Priorities
named by the operator: per-primitive faithfulness (a)(b1)(b2)(d1') and its mechanical checking,
(h) source refinement, (d2') the NTT proof, and above all (c) the close-vector backing.

## Why (c) is restated, not just discharged

`closeVectorBacked` says the close statement's amounts are `≤ m.deposits channel token` for an
opaque per-channel deposit map. That is not what the deployed system enforces, and with L2
transfers it is not even the right invariant. What the contracts actually require before any
credit leaves escrow (`CloseFundingMaterializer.materializeSignedHead`) is a BACKING PROOF:
`CloseAssetBacking` recursively verifies a Balance proof, opens its private commitment, binds the
Balance public state to an extended state whose commitment must be a FINALIZED Rollup state root
(`isFinalizedStateRoot`), and reconstructs the asset tree from the very token vector whose keccak
digest the Manager's close statement carries. So the credited vector is, by construction, the
channel's L2 balance at a finalized L2 state as certified by the Balance circuit family. The
residue is the L2 ledger invariant — that Balance-certified balances at finalized roots are
backed by escrow — which lives in the validity chain and is named, not proved, here.

## Layer B1 — `CloseAssetBacking` per-primitive (running)

`BuildOp.holds`, `Assignment`, `ProgramSatisfied`, `program_satisfied_implies_constraints`
(no side hypothesis), `PrimitiveLowering`, non-vacuity. `CircuitConstraints` byte-identical.

## Layer B2 — `Zkp.Implementation.BackingBridge` (new module)

Imports `CloseFunding`, `CloseAssetBacking`, `SettlementVerifier`, `Keccak256`. Derive from
`CloseFunding.materializeSignedHead fe w manager proof = .ok (w', events)`:
* `fe.verifyCompact proof = .ok pi`, `validateBackingPublicInputs fe w.storage manager pi = .ok st`,
  `fe.isFinalizedRoot st.backingRoot = .ok true`, `st.anchor ≤ latestFinalized`,
  `st.tokenFundsDigest = (fe.manager manager).tokenFundsDigest` (getter), `st.settledChain = …settledChain`,
  and the credits are `readVector` of the view's `tokenAt`/`amountAt` (reuse
  `materialization_call_complete_vector`);
* the 26 words parse as `CloseAssetBacking.parsePublicInputs pi = .ok p` with `p.channelId`,
  `p.settledTxChain.value`, `p.tokenFundsDigest.value`, `p.extendedStateCommitment.value`,
  `p.anchorBlockNumber` equal to the Solidity-side `BackingStatement` fields (`limbsToBytes32`
  vs `Words8.value`: prove the two big-endian limb readings agree on checked limbs);
* ONE theorem `materialization_receipt` packaging the above (the analog of
  `SettlementCloseBridge.accepted_verification_has_exact_adapter_receipt`).
Also report what ties `fe.manager manager` (the `ManagerView` getters) to the Manager's modeled
storage in `SystemSafety.Step.materialize` — if nothing does, T3 adds a premise (c0).

## Layer T3 — `TrustBoundary.lean`

`Models`: remove `deposits`; add `backingCircuitDigest : List Nat`, `backingEnv`
(the `CloseAssetBacking` opaque contracts: `MerkleContract`, `HashFunctions`,
`RecursiveVerifierContract`), and `l2` — whatever B2 says is needed to name the ledger residue.
Fields replacing (c):
* (c0) `managerViewIsManagerState` (only if B2 finds the gap): the Materializer's staticcall
  view of the bound Manager equals the Manager's modeled storage projection;
* (c1) `backingVerifierSoundness`: `fe.verifyCompact proof = .ok words → m.plonky2Satisfiable m.backingCircuitDigest words`
  — the SAME pinned MLE artifact as (a0) (the Materializer pins `backingMleVerifier`), stated
  as its own field so its scope is visible;
* (c2) `backingPrimitiveLowering`: satisfiable ⇒ ∃ assignment satisfying
  `CloseAssetBacking.constructorProgram` reading back to the words (from B1);
* (c3) `backingTokenFundsHashBinding`: the (e2)-shaped same-length pair binding between the
  Manager's `tokenFundsPreimage` bytes and the circuit's reconstructed `tokenFundsPreimage count rows`
  under the reference Keccak-256 (`circuitKeccakIsReference`-style equality for the backing
  circuit's keccak callback is part of `backingEnv`'s hash functions — state it);
* (c4) `finalizedBalanceIsBacked` — THE RESIDUE: for a `CloseAssetBacking.CircuitConstraints`
  witness whose extended-state commitment is a root `m.head` finalizes, the asset amounts of
  its rows are within the channel's L2 entitlement at that root. State it over an explicit
  `m.l2Entitlement : Root → Channel → Token → Nat` parameter and document that discharging it
  is the validity-chain composition (BalanceCircuit → SwitchBoard → ValidityChain →
  DepositChain / WithdrawalChain), the named next project.
Derived: `materialized_vector_is_backed_of_boundary` (every credit of an accepted
`materializeSignedHead` is ≤ the L2 entitlement at a finalized root), `close_vector_backing_gap_is_now_l2_ledger`,
and the old (c) form for the Manager's close statement ONLY IF B2 ties the view to the close
statement; otherwise state clearly that (c) attached to the wrong event (close-intent acceptance
credits nothing; materialization does) and retire `close_vector_backing_is_exactly_premise_c` in
`SystemSafety` in favour of the materialization-level theorem. `unbackedModels` /
`mle_assumption_does_not_imply_fund_safety` must be re-targeted (refute (c4) with a concrete
satisfying backing witness of amount 1 and entitlement 0).

## Layer N — `FalconGadgetProgram.NttComputesNegacyclicProduct` proved (new module `NttCorrectness`)

Prove the transcribed iterative NTT equals the schoolbook negacyclic product in `Z_q[X]/(X^512+1)`,
q = 12289, ψ = `ntoPsi`, without Mathlib: (1) the 9-stage CT-DIT loop with bit-reversed twiddles
equals a recursive even/odd NTT; (2) the recursive NTT is evaluation at ψ^(2i+1); (3) pointwise
product of evaluations = evaluation of the negacyclic product (ψ^512 = q−1); (4) the GS inverse
with `nInv` inverts (geometric sums vanish: for 0<k<512, (1−ω^k) has an inverse — supply the
inverse table and `decide` the 511 products = 1, so primality of q is never assumed).
Deliver `theorem ntt_computes_negacyclic_product : FalconGadgetProgram.NttComputesNegacyclicProduct`
and then (T3) drop field (d2') and derive it. If only parts land, deliver the parts as theorems
and report exactly which step remains.

## Layer M — mechanical faithfulness evidence (Rust tests, no runtime change)

For the transcribed programs (CloseCircuit, WithdrawalClaimCircuit, PostCloseClaimCircuit,
FalconGadgetProgram, FalconAggProgram leaf/level, CloseAssetBacking), add `#[cfg(test)]` checks:
1. STATIC (cheap): after `build`, every `connect`/equality-type `holds` claim of the Lean model
   is checked against `CircuitData.prover_only.representative_map` (targets claimed equal share a
   representative; targets claimed to be constants are wired to the constant); every
   `register_public_input(s)` claim is checked against the public-input target list order.
   Emit a machine-readable table (op name, source line, kind, verdict) compared against a
   checked-in expectation file derived from the Lean op lists.
2. MUTATION (proving, sample): for the Falcon gadget and aggregation leaf/level (cheap circuits),
   for each range/arithmetic `holds` claim, prove with a witness violating exactly that claim and
   assert verification fails; for the settlement circuits, a documented sample only.
Report which ops are covered by which check; the uncovered ops remain in the premise.

## Layer P — the public document `doc/audit/zkp/PRACTICAL-SAFETY-PROOF.md`

English, with a Japanese abstract. The main theorem(s) as stated in `SystemSafety` and
`TrustBoundary`, the assumption ledger (every field: statement, evidence, what would refute it,
how to check), the evidence artifacts (guards, fixture parity, Keccak vectors, ledger-writer
check, the mechanical faithfulness tables), the known gaps in plain words ((c4) L2 ledger,
(h), untranslated lines, computational assumptions), and reproduction commands.
