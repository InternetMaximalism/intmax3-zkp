# Loop plan 2026-09-11 (third loop): per-primitive lowering of the Falcon aggregation stack

Planner/verifier: Fable 5.1. Implementers: Opus 5 agents. Standing rules unchanged
(no `sorry`/`admit`/`axiom`/`native_decide`; column-0 `theorem snake_case`; never weaken an
existing gate structure; no runtime change; no push; WIP commits per batch).

## Goal

After the second loop, (d1) `aggregateStatementLowering` is the only whole-circuit premise left
in `TrustBoundary`, and (d2) `falconPredicateIsGadget` relates an opaque `Bool` callback to
`FalconCore.CircuitSatisfied`. This loop gives the aggregation stack the same treatment the
close/claim circuits got in the first loop:

* `agg.rs` leaf circuit (`FalconLeafCircuit::new`, :268-305) and level circuit
  (`FalconAggLevelCircuit::new`, :370-479) become `BuildOp` programs with per-op `holds`
  semantics and `program_satisfied_implies_*` theorems;
* `gadget.rs` (`FalconSigVerifyTarget::build`, :651-737, and the helpers it calls) becomes a
  `BuildOp` program whose satisfaction implies `FalconCore.CircuitSatisfied` for a CONCRETE
  polynomial product (the in-circuit NTT as transcribed), so the opaque `PolynomialProduct`
  boundary becomes "this NTT algorithm computes the negacyclic product";
* `TrustBoundary` replaces (d1) and (d2) — and the `Models.sigEnv` callback — by per-level
  recursion-soundness and per-level per-primitive lowering premises, deriving the signer
  evidence by induction over the four circuits (leaf, level 1, 2, 3).

## Layer A — `Zkp.Implementation.FalconAggProgram` (new module)

Imports `FalconAggregate`, `FalconCore`, `CloseSignatureBridge` (for `digestOfLimbs`).

1. `limbsOfNat : Nat → List Nat` — 8 big-endian 32-bit limbs of `n % 2^256`;
   `digest_of_limbs_limbs_of_nat` (`digestOfLimbs (limbsOfNat n) = n` for `n < 2^256`),
   `limbs_of_nat_length`, `limbs_of_nat_canonical`.
2. Leaf: `LeafOp` (one constructor per builder call of :268-305: `falconSigVerify`
   (`FalconSigVerifyTarget::new`, unconditional ⇒ `verifyBit = 1`), `registerMessageDigest8`,
   `constantOne`, `registerSignerCount`, `registerPkG8`, `addConstGate`, `build`),
   `LeafAssignment` (a `FalconCore.CircuitWitness` for the gadget, the 8 message limbs, the 8
   pk_g limbs, the registered public list), `LeafOp.holds`, `leafProgram`, `readLeafPublic`.
   `holds .falconSigVerify a := FalconCore.CircuitSatisfied e p a.sig ∧ a.sig.verifyBit = 1 ∧
   a.sig.messageDigest = digestOfLimbs a.messageLimbs ∧ a.sig.pkG = digestOfLimbs a.pkGLimbs ∧
   (∀ x ∈ a.messageLimbs, x < 2^32) ∧ …` — state exactly what `Bytes32Target::new(_, true)`
   range checks (gadget.rs:351-353, 660) and cite the lines; the limb/Nat reconciliation is the
   D1 bridge's `digestOfLimbs`.
   Theorem `leaf_program_satisfied_implies_statement`: `ProgramSatisfied leafProgram a →
   readLeafPublic a = FalconAggregate.statementPublicInputs ⟨a.messageLimbs, 1, [a.pkGLimbs]⟩ ∧
   CircuitSatisfied e p a.sig ∧ a.sig.verifyBit = 1 ∧ a.sig.messageDigest = digestOfLimbs a.messageLimbs ∧ a.pkGLimbs = limbsOfNat a.sig.pkG` (or the equivalent).
3. Level `k ∈ {1,2,3}`: `LevelOp` per builder call of :370-479 (`verifyLeftChild` at the
   constant child vd; `addVirtualBoolSafe`; `conditionallyVerifyRightChild`; the positional
   `childPis` reads are pure functions, not ops; `gatedMessageEquality i` for the 8 limbs
   (`sub`, `mul`, `assert_zero` — one op per limb or one op with the loop folded, say which);
   `gatedCountR`; `signerCountAdd`; `halfFullConstant`; `leftFullnessGap`; `gatedGap`;
   `assertZeroGap`; `registerMessage8`; `registerSignerCount`; `registerLeftPks`;
   `registerGatedRightPk i`; `addConstGate`; `build`). Field arithmetic is Goldilocks:
   state `holds` for `sub`/`mul`/`add` MODULO `FalconCore.fieldModulus` and derive the Nat
   equalities under range hypotheses (`count ≤ 8`, limbs `< 2^32`), which the induction supplies.
   `LevelEnvironment` carries the opaque child-verification relation
   `verifyChild : Nat (level) → ProofTy → List Nat (child public inputs) → Prop` and the constant
   verifier-data identity; `holds .verifyLeftChild a := verifyChild k a.leftProof a.leftPis ∧
   a.leftPis.length = falconAggPublicInputsLenAt (k-1)`, and the conditional variant gated by
   the presence bit (when absent, the right PIs are unconstrained EXCEPT their length — say so).
   Theorem `level_program_satisfied_implies_compose`: `ProgramSatisfied (levelProgram k) a →`
   the read-back public list equals `statementPublicInputs (levelCompose k present sl sr)`
   where `sl`/`sr` are the positional decodes of the child PI lists and `present = (a.flag = 1)`,
   given range hypotheses on the children (`decodeCount sl ≤ 2^(k-1)`, limbs canonical,
   well-formed slots) — reuse `FalconAggregate.levelCompose` and its lemmas; note `levelCompose`
   returns `Except`, so the theorem states the `.ok` case and that the gated checks force it.
4. The induction. Parametrize by two Props on an abstract "satisfiable" relation
   `Sat : Nat → List Nat → Prop` (level, public inputs):
   `RecursionSound Sat env := ∀ k ∈ {1,2,3}, ∀ proof pis, env.verifyChild k proof pis → Sat (k-1) pis`
   `LevelLowering Sat env e p := (∀ words, Sat 0 words → ∃ a, ProgramSatisfied leafProgram a ∧ readLeafPublic a = words) ∧ ∀ k ∈ {1,2,3}, ∀ words, Sat k words → ∃ a, ProgramSatisfied (levelProgram k) a ∧ readLevelPublic a = words`.
   Theorem `satisfiable_top_level_gives_witness_list (hrec) (hlow) (words) (hsat : Sat 3 words)`:
   `∃ (message : Limbs) (cws : List FalconCore.CircuitWitness), words = aggExpectedPublicInputs 3 message (cws.map (fun cw => limbsOfNat cw.pkG)) ∧ 1 ≤ cws.length ∧ cws.length ≤ 8 ∧ ∀ cw ∈ cws, CircuitSatisfied e p cw ∧ cw.verifyBit = 1 ∧ cw.messageDigest = digestOfLimbs message`
   by induction on the level (state the general `k` version with `2^k` and `aggExpectedPublicInputs k`).
5. Non-vacuity: a concrete level-1 assignment with two leaves (reuse `FalconCore.zeroWitness`
   -style satisfiable witnesses) for which `ProgramSatisfied` holds.
6. Docstrings citing `agg.rs` lines for every op; module header saying what is derived and what
   the per-op faithfulness residue is.

## Layer G — `Zkp.Implementation.FalconGadgetProgram` (new module)

Imports `FalconCore`. Transcribe `FalconSigVerifyTarget::build` (gadget.rs:651-737) and the
helpers it calls (`h2p_circuit` :353-400, `pk_digest_circuit` :401-433, `ntt_forward` :434-472,
`ntt_inverse` :473-514, `pointwise_mul` :515-539, `reduce_mod_q` :276-289,
`assert_canonical_coeff` :290-310, `goldilocks_mod_q_block` :311-352, `centered_square` :574-593,
`constrain_mod_q_decomposition` :243-275, `twiddle_tables` :170-200) as a `GadgetOp` program
with `holds` semantics over a `GadgetAssignment` that extends `FalconCore.CircuitWitness` with
the intermediate wires (NTT images, products, quotients of the mod-q decompositions). Rules:

* every builder call in `build` gets an op; helper calls inside loops may be one op per helper
  invocation with the loop folded — the docstring must say which loop and the exact count;
* `holds` for a mod-q reduction is `FalconCore.modQGates` (its uniqueness is already proved);
  for the NTT butterflies use the exact field/mod-q arithmetic the source performs, with the
  twiddle tables as CONCRETE Lean definitions (`powModQ`, `bitReverse9`, `twiddleTables`)
  pinned by `decide`d spot checks (e.g. the first few twiddles, `psi^1024 = 1 mod q`,
  `nInv * 512 = 1 mod q`);
* the hash calls (`h2p_circuit`, `pk_digest_circuit`) stay opaque through
  `FalconCore.HashEnvironment` exactly as `CircuitSatisfied` uses them;
* define `circuitProduct : FalconCore.PolynomialProduct := ⟨fun a b => nttInverse (pointwise (nttForward a) (nttForward b))⟩`
  with the CONCRETE functions, and prove
  `gadget_program_satisfied_implies_circuit_satisfied (e) (a) : ProgramSatisfied gadgetProgram a → FalconCore.CircuitSatisfied e circuitProduct (readWitness a)`
  with no side hypothesis (`readWitness` projects the `CircuitWitness` fields);
* a theorem stating the remaining boundary in one line: `NttComputesNegacyclicProduct : Prop :=
  ∀ a b, (∀ c ∈ a, c < q) → (∀ c ∈ b, c < q) → a.length = 512 → b.length = 512 →
  circuitProduct.mul a b = negacyclicProduct a b` with `negacyclicProduct` the schoolbook
  definition (transcribe `schoolbook_negacyclic` from the test at :999) — NOT proved, named;
* non-vacuity: the all-zero honest witness (`FalconCore.zeroWitness`) extended with zero
  intermediates satisfies the program (`example_zero_program_satisfied`); keep it cheap (`decide`
  on 512-length lists may be slow — use `simp`/`List.replicate` lemmas or a smaller structural
  argument).

If the full NTT transcription cannot be finished within the budget, deliver everything else and
leave the three NTT ops with `holds` = "`a.prod = p.mul a.s2 a.h`" for the OPAQUE `p`, state
precisely in the header that the NTT ops are folded into the opaque product, and report it.

## Layer T2 — `TrustBoundary.lean` (after A and G)

* `Models`: remove `sigEnv` and `falconMul` (the product is now `FalconGadgetProgram.circuitProduct`); replace
  `aggregateCircuitDigest : List Nat` by `aggregateLevelDigest : Nat → List Nat` (level 0 = leaf …
  level 3 = the top circuit the close circuit verifies); add `aggEnv : FalconAggProgram.LevelEnvironment`
  (the opaque child-verification relation).
* Fields: (d0) `aggregateRecursiveVerifierSoundness` now at the TOP key only (unchanged
  statement with `aggregateLevelDigest 3`); (d0') `levelRecursionSoundness :
  FalconAggProgram.RecursionSound (fun k words => m.plonky2Satisfiable (m.aggregateLevelDigest k) words) m.aggEnv`;
  (d1') `aggregatePrimitiveLowering : FalconAggProgram.LevelLowering (…) m.aggEnv m.falconHash FalconGadgetProgram.circuitProduct`
  — but with the leaf's gadget op stated through `FalconGadgetProgram.gadgetProgram` (compose
  via `gadget_program_satisfied_implies_circuit_satisfied`), so that no field mentions
  `CircuitSatisfied` as a whole; (d2') `nttComputesNegacyclicProduct : FalconGadgetProgram.NttComputesNegacyclicProduct`
  (needed only if a consumer wants `FalconCore.verify`-level meaning; keep it as the named
  residue of the product); (d3) unchanged; the digest-pinning halves stated separately as
  `AggregatePinnedDigestIsProgramDigest` per level (like `ClosePinnedDigestIsProgramDigest`).
* Derived: old (d1) `aggregateStatementLowering` statement as a theorem? It mentions
  `evalTree m.sigEnv` — with `sigEnv` gone, restate its content as the witness-list form and
  derive `signature_validity_of_boundary` with conclusion
  `CloseSignatureBridge.SignerEvidence (FalconAggProgram.sigEnvOf m.falconHash) m.authorized st.message st.keys st.signerCount`
  where `sigEnvOf e := { pkDigest := fun h => limbsOfNat (falconPkDigest e h), falconAccepts := fun _ _ _ _ => true }`
  (SignerEvidence never reads `falconAccepts`); `signature_gap_is_now_per_primitive`; update
  the degenerate witness and every field enumeration.

## Registration / maps / docs

`register2.py --compose=Zkp.Implementation.FalconAggProgram:doc/audit/zkp/line-map/falcon-agg.json,src/falcon_sig/agg.rs --compose=Zkp.Implementation.FalconGadgetProgram:doc/audit/zkp/line-map/falcon-gadget.json,src/falcon_sig/gadget.rs`;
then link the new theorems into the `falcon-agg.json` / `falcon-gadget.json` spans they cover
(`validate-linemap.py`), progress/handoff docs, commit.

## Layer I — `Zkp.Implementation.LedgerWriters` (new module; premises g1/g2)

Finding from the read-only entrypoint inventory (2026-09-11): the storage behind (g1)/(g2) has
exactly one Solidity write site per variable — `usedWithdrawalNullifiers` :2231
(`submitWithdrawalClaim`, set-only), `receivedChannelFunds` :2364 (`pullChannelFunds` /
`pullChannelTokenFunds`), `totalCreditedOut` :2398 (`claimWithdrawalCredit`),
`finalizedChannelFundAmount` :1681 (`finalizeCloseGuarded`, `+=` only), and
`CloseFundingMaterializer.materializedChannelExit` :461 (`materializeSignedHead`, guarded by
`== 0` at :434). No proxy, `delegatecall`, `selfdestruct`, initializer or assembly `sstore`
touches either contract; the Rollup cannot write Manager storage. BUT `finalizeCloseGuarded`
is modeled (`ManagerValue.finalizeCloseCore`) and is NOT a `SystemSafety.Step` constructor,
so (g1)'s clause `cap t = cap s` for unmodeled transitions is refuted by the deployed
contract. (g1) is therefore corrected to `cap s ≤ cap t` (`SystemSafety` never consumes (g1)
or (g2), so nothing downstream changes), and both premises are reduced to an inventory
statement plus source refinement:

1. Inventory data: `structure WriteSite` (contract, variable, solidity line, entrypoint,
   modeling Lean def name, `Step` constructor name or none) and the pinned list
   `flaggedWriteSites` (the five sites above); `decide`d pins (`each flagged variable has
   exactly one site`, the `Step` coverage of `used`/`received`/`paid`/latch writers, and that
   the only flagged writer outside `Step` is the `cap` site).
2. Model-level frame theorems, one per modeled entrypoint of `ManagerValue` and
   `CloseFunding` (enumerate them as `inductive ManagerEntrypoint` / `inductive
   MaterializerEntrypoint` with a `run` wrapper so the statement is ONE theorem per contract):
   `manager_entrypoints_keep_the_ledger : ∀ call s t, run call s = .ok t → LedgerMonotone s t`
   where `LedgerMonotone s t := (∀ n, s.used n = true → t.used n = true) ∧ s.cap ≤ t.cap
   (pointwise) ∧ (call ∉ Step-covered → t.received = s.received ∧ t.paid = s.paid) ∧ …`, and
   `materializer_entrypoints_keep_the_latch : ∀ call s t, run call s = .ok t → ∀ c,
   s.materializedChannelExit c ≠ 0 → t.materializedChannelExit c = s.materializedChannelExit c`.
   Reuse `SystemSafety.request_close_frames_value`-style proofs (but do not import
   SystemSafety — it will import this module through TrustBoundary) and
   `CloseFunding.materialization_call_one_shot`.
3. CI check `.github/ci/check-ledger-writers.py`: greps the two `.sol` files for every
   assignment/`delete`/`sstore` of the five variables and asserts the (line, entrypoint) set
   equals the Lean inventory (parse the Lean list textually); wire it into the lean job of
   `.github/workflows/ci.yml` next to the other guards, and into `test-*`-style self-test if
   cheap.

Layer T2 then replaces (g1)/(g2) by: (g1') `flaggedWritersAreInventoried` — every deployed
transition that changes one of the five variables is a run of an inventoried entrypoint
(source refinement, kin to (h)); the old (g1) (with `cap` monotone) and (g2) become theorems
from (g1') + the frame theorems.
