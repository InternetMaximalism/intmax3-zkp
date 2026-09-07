import Std

/-!
# WithdrawalChainCircuit: forwarding wrapper around one withdrawal-step proof

Handwritten source semantics of src/circuits/withdraw/withdrawal_chain_circuit.rs
(364 lines: `new`, `generate_cd`, `prove`, `verify`, and a release-only unit test),
together with the two direct helpers it calls for its public-input layout
(`WithdrawalStepPublicInputsTarget::from_pis`/`to_vec` in withdrawal_step.rs and
`vd_vec_len`/`vd_from_pis_slice_target` in utils/cyclic.rs) and plonky2's
`check_cyclic_proof_verifier_data` / `VerifierOnlyCircuitData::from_slice`.
This is NOT a refinement proof of the Rust, plonky2 or Solidity code. Wires and
field elements are integer representatives; plonky2 compilation, proving and
verification are opaque callbacks named in the boundaries.

What the source does (and the model states):
* `new` allocates the step proof target, embeds the step verifier key as circuit
  constants, verifies the step proof in-circuit, re-slices the step proof's first
  `23 + 4 + 4 * 2^cap_height` public-input targets (`from_pis`, which panics on
  fewer) and registers exactly that prefix, in order, as this circuit's public
  inputs. No other gate touches those wires; in particular the constructor
  contains neither `add_verifier_data_public_inputs` nor `connect_verifier_data`.
  Panic order: `from_pis` length assert (during build), then the common-data
  equality assert, then the `success` assert.
* `generate_cd` builds a padded recursion shell and then OVERWRITES
  `num_public_inputs` with `23 + vd_vec_len`; the count matches the registered
  prefix, but no public input is registered while generating it.
* `prove` copies the caller's step proof into the witness and calls the plonky2
  prover. It performs NO native admission check: no verification of the step
  proof, no key or length inspection; every failure is `FailedToProve`.
* `verify` first runs `check_cyclic_proof_verifier_data`, which parses the LAST
  `4 + 4 * 2^cap_height` public-input limbs of the submitted proof (whatever its
  length) as (digest, cap) and compares them, cap first, with THIS circuit's own
  verifier key; only afterwards is `data.verify` (plonky2) consulted. A short
  vector or a foreign key is rejected before plonky2 verification runs.

What this file does NOT do (recorded, not assumed): the in-circuit binding of the
forwarded verifier-key limbs to the chain circuit's own key is not performed
here. It lives in withdrawal_step.rs (`conditionally_connect_vd` against the
previous chain proof) and in withdrawal_circuit.rs
(`add_proof_target_and_verify_cyclic`, which connects the embedded constant key
to the inner proof's key limbs). Soundness of the embedded `verify_proof` gadget
is a plonky2 boundary.

Cross-reference (not imported): Zkp/Implementation/RollupValue.lean
`verifyWithdrawalSet` accepts only a 17-limb public-input vector. The chain
circuit's registered vector has `23 + 4 + 4 * 2^cap_height ≥ 31` limbs, so a
chain proof can never be the artifact the rollup gate consumes; the 17-limb
vector is produced by the separate final `WithdrawalCircuit`. `rollupLimbGate`
below pins that count locally.
-/
namespace Zkp.Implementation.WithdrawalChainCircuit

/-! ## Pinned constants (bytes32.rs, u64.rs, poseidon_hash_out.rs, public_state.rs,
withdrawal_step.rs, cyclic.rs, plonky2 CircuitConfig::default) -/

def bytes32Len : Nat := 8
def u64Len : Nat := 2
def poseidonHashOutLen : Nat := 4
def publicStateU64Len : Nat := 1 + u64Len + 3 * poseidonHashOutLen
def stepPublicInputsLen : Nat := bytes32Len + publicStateU64Len
def defaultCapHeight : Nat := 4
def numCapElements (capHeight : Nat) : Nat := 2 ^ capHeight
def vdVecLen (capHeight : Nat) : Nat := 4 + 4 * numCapElements capHeight
def chainPublicInputsLen (capHeight : Nat) : Nat := stepPublicInputsLen + vdVecLen capHeight
def noopTargetGates : Nat := 2 ^ 12
/-- The limb count required by RollupValue.verifyWithdrawalSet (`pi.length == 17`). -/
def rollupWithdrawalLimbCount : Nat := 17

theorem step_public_inputs_len_pinned : stepPublicInputsLen = 23 := by decide
theorem vd_vec_len_pinned : vdVecLen defaultCapHeight = 68 := by decide
theorem chain_public_inputs_len_pinned : chainPublicInputsLen defaultCapHeight = 91 := by decide
theorem noop_target_pinned : noopTargetGates = 4096 := by decide
theorem rollup_limb_count_pinned : rollupWithdrawalLimbCount = 17 := by decide

theorem vd_vec_len_at_least_eight (h : Nat) : 8 ≤ vdVecLen h := by
  unfold vdVecLen numCapElements
  have := Nat.pos_pow_of_pos h (by decide : 0 < 2)
  omega

theorem chain_public_inputs_len_at_least_31 (h : Nat) : 31 ≤ chainPublicInputsLen h := by
  unfold chainPublicInputsLen
  have := vd_vec_len_at_least_eight h
  rw [step_public_inputs_len_pinned]
  omega

/-! ## Verifier key limbs (`[circuit_digest (4), constants_sigmas_cap (4 * 2^cap_height)]`) -/

structure VerifierKey where
  digest : List Nat
  cap : List Nat
  deriving DecidableEq, Repr

def VerifierKey.limbs (k : VerifierKey) : List Nat := k.digest ++ k.cap

def VerifierKey.WellFormed (capHeight : Nat) (k : VerifierKey) : Prop :=
  k.digest.length = 4 ∧ k.cap.length = 4 * numCapElements capHeight

theorem well_formed_key_limb_count {h : Nat} {k : VerifierKey} (wf : k.WellFormed h) :
    k.limbs.length = vdVecLen h := by
  obtain ⟨d, c⟩ := wf
  simp only [VerifierKey.limbs, List.length_append, d, c, vdVecLen]

inductive VerifyFailure where
  | notEnoughPublicInputs
  | capMismatch
  | digestMismatch
  | proofRejected (detail : String)
  deriving DecidableEq, Repr

/-- The last `vdVecLen` limbs of a public-input vector (plonky2 `from_slice` reads
    `slice[len - 4 - 4*cap_len ..]`, i.e. always the tail, whatever the total length). -/
def keyTail (capHeight : Nat) (slice : List Nat) : List Nat :=
  slice.drop (slice.length - vdVecLen capHeight)

/-- plonky2 `VerifierOnlyCircuitData::from_slice` and the crate's
    `vd_from_pis_slice(_target)`: same layout, same `len >= 4 + 4*cap_len` guard. -/
def vdFromSlice (capHeight : Nat) (slice : List Nat) : Except VerifyFailure VerifierKey :=
  if slice.length < vdVecLen capHeight then .error .notEnoughPublicInputs
  else .ok ⟨(keyTail capHeight slice).take 4, (keyTail capHeight slice).drop 4⟩

theorem key_tail_length {h : Nat} {slice : List Nat} (enough : vdVecLen h ≤ slice.length) :
    (keyTail h slice).length = vdVecLen h := by
  simp only [keyTail, List.length_drop]
  omega

theorem vd_from_slice_short_rejected {h : Nat} {slice : List Nat}
    (short : slice.length < vdVecLen h) :
    vdFromSlice h slice = .error .notEnoughPublicInputs := by
  simp [vdFromSlice, short]

theorem vd_from_slice_reads_last_limbs {h : Nat} {slice : List Nat} {k : VerifierKey}
    (parsed : vdFromSlice h slice = .ok k) :
    vdVecLen h ≤ slice.length ∧ k.limbs = keyTail h slice := by
  unfold vdFromSlice at parsed
  split at parsed
  · contradiction
  · rename_i notShort
    simp only [Except.ok.injEq] at parsed
    subst parsed
    exact ⟨Nat.le_of_not_lt notShort, List.take_append_drop 4 _⟩

theorem own_key_limbs_parse_back {h : Nat} {k : VerifierKey} (wf : k.WellFormed h) :
    vdFromSlice h k.limbs = .ok k := by
  have len := well_formed_key_limb_count wf
  obtain ⟨d, _⟩ := wf
  simp only [vdFromSlice, len, Nat.lt_irrefl, ite_false, keyTail, Nat.sub_self, List.drop_zero]
  cases k with
  | mk digest cap =>
    simp only [VerifierKey.limbs] at *
    rw [← d, List.take_left, List.drop_left]

/-! ## `from_pis` / `to_vec` (withdrawal_step.rs): the chain circuit registers the step
proof's public-input targets, re-sliced and re-concatenated verbatim -/

inductive Panic where
  | fromPisLengthMismatch
  | vdFromPisSliceUnwrap
  | commonDataMismatch
  | buildFailed
  deriving DecidableEq, Repr

structure StepPisTarget where
  withdrawalHashChain : List Nat
  publicState : List Nat
  vd : VerifierKey
  deriving DecidableEq, Repr

def StepPisTarget.toVec (t : StepPisTarget) : List Nat :=
  t.withdrawalHashChain ++ t.publicState ++ t.vd.limbs

def fromPis (capHeight : Nat) (pis : List Nat) : Except Panic StepPisTarget :=
  if pis.length < chainPublicInputsLen capHeight then .error .fromPisLengthMismatch
  else
    match vdFromSlice capHeight ((pis.drop stepPublicInputsLen).take (vdVecLen capHeight)) with
    | .error _ => .error .vdFromPisSliceUnwrap
    | .ok vd => .ok ⟨pis.take bytes32Len, (pis.drop bytes32Len).take publicStateU64Len, vd⟩

theorem take_add_split {α : Type} (l : List α) (m n : Nat) :
    l.take (m + n) = l.take m ++ (l.drop m).take n := by
  induction m generalizing l with
  | zero => simp
  | succ m ih =>
    cases l with
    | nil => simp
    | cons x xs => simp [Nat.succ_add, ih]

theorem from_pis_short_panics {h : Nat} {pis : List Nat}
    (short : pis.length < chainPublicInputsLen h) :
    fromPis h pis = .error .fromPisLengthMismatch := by
  simp [fromPis, short]

theorem from_pis_forwards_step_prefix {h : Nat} {pis : List Nat} {t : StepPisTarget}
    (parsed : fromPis h pis = .ok t) :
    t.toVec = pis.take (chainPublicInputsLen h) := by
  unfold fromPis at parsed
  split at parsed
  · contradiction
  · rename_i notShort
    have enough : chainPublicInputsLen h ≤ pis.length := Nat.le_of_not_lt notShort
    have sliceLen : ((pis.drop stepPublicInputsLen).take (vdVecLen h)).length = vdVecLen h := by
      rw [List.length_take, List.length_drop, Nat.min_eq_left]
      unfold chainPublicInputsLen at enough
      omega
    have parsedSlice : vdFromSlice h ((pis.drop stepPublicInputsLen).take (vdVecLen h)) =
        .ok ⟨((pis.drop stepPublicInputsLen).take (vdVecLen h)).take 4,
             ((pis.drop stepPublicInputsLen).take (vdVecLen h)).drop 4⟩ := by
      simp only [vdFromSlice, keyTail, sliceLen, Nat.lt_irrefl, ite_false, Nat.sub_self,
        List.drop_zero]
    rw [parsedSlice] at parsed
    simp only [Except.ok.injEq] at parsed
    subst parsed
    simp only [StepPisTarget.toVec, VerifierKey.limbs, List.take_append_drop]
    rw [chainPublicInputsLen, take_add_split, stepPublicInputsLen, take_add_split]

theorem from_pis_never_hits_vd_unwrap {h : Nat} {pis : List Nat} :
    fromPis h pis ≠ .error .vdFromPisSliceUnwrap := by
  intro bad
  unfold fromPis at bad
  split at bad
  · simp at bad
  · rename_i notShort
    have enough : chainPublicInputsLen h ≤ pis.length := Nat.le_of_not_lt notShort
    have sliceLen : ((pis.drop stepPublicInputsLen).take (vdVecLen h)).length = vdVecLen h := by
      rw [List.length_take, List.length_drop, Nat.min_eq_left]
      unfold chainPublicInputsLen at enough
      omega
    have : vdFromSlice h ((pis.drop stepPublicInputsLen).take (vdVecLen h)) ≠
        .error .notEnoughPublicInputs := by
      simp [vdFromSlice, sliceLen]
    cases parsed : vdFromSlice h ((pis.drop stepPublicInputsLen).take (vdVecLen h)) with
    | error f =>
      unfold vdFromSlice at parsed
      simp [sliceLen] at parsed
    | ok vd => simp [parsed] at bad

theorem forwarded_vector_has_chain_length {h : Nat} {pis : List Nat} {t : StepPisTarget}
    (parsed : fromPis h pis = .ok t) : t.toVec.length = chainPublicInputsLen h := by
  rw [from_pis_forwards_step_prefix parsed, List.length_take, Nat.min_eq_left]
  unfold fromPis at parsed
  split at parsed
  · contradiction
  · rename_i notShort
    exact Nat.le_of_not_lt notShort

/-! ## Constructor program (`new`, lines 53-77) -/

/-- plonky2 builder calls in source order. `addVerifierDataPublicInputs` and
    `connectVerifierData` are in the vocabulary only to record their ABSENCE. -/
inductive BuildOp where
  | newBuilderWithChainConfig
  | addVirtualProofWithPis
  | constantVerifierData
  | verifyProof
  | fromPis (need : Nat)
  | registerPublicInputs (count : Nat)
  | addVerifierDataPublicInputs
  | connectVerifierData
  | tryBuildWithOptions (commitToSigma : Bool)
  | assertCommonDataEquals
  | assertBuildSuccess
  deriving DecidableEq, Repr

def constructorProgram (capHeight : Nat) : List BuildOp :=
  [.newBuilderWithChainConfig, .addVirtualProofWithPis, .constantVerifierData, .verifyProof,
   .fromPis (chainPublicInputsLen capHeight), .registerPublicInputs (chainPublicInputsLen capHeight),
   .tryBuildWithOptions true, .assertCommonDataEquals, .assertBuildSuccess]

def isRegister : BuildOp → Bool
  | .registerPublicInputs _ => true
  | _ => false

theorem constructor_registers_exactly_once (h : Nat) :
    (constructorProgram h).filter isRegister = [.registerPublicInputs (chainPublicInputsLen h)] := by
  simp [constructorProgram, isRegister]

theorem constructor_never_binds_verifier_data_in_circuit (h : Nat) :
    BuildOp.connectVerifierData ∉ constructorProgram h ∧
    BuildOp.addVerifierDataPublicInputs ∉ constructorProgram h := by
  simp [constructorProgram]

theorem constructor_panic_order (h : Nat) :
    (constructorProgram h)[4]? = some (.fromPis (chainPublicInputsLen h)) ∧
    (constructorProgram h)[7]? = some .assertCommonDataEquals ∧
    (constructorProgram h)[8]? = some .assertBuildSuccess ∧
    (constructorProgram h).length = 9 := ⟨rfl, rfl, rfl, rfl⟩

/-- The parts of plonky2 `CommonCircuitData` the model distinguishes; everything
    else (gates, selectors, FRI params, k_is, ...) is collapsed into an opaque
    equality-compared fingerprint. -/
structure CommonData where
  capHeight : Nat
  numPublicInputs : Nat
  fingerprint : Nat
  deriving DecidableEq, Repr

structure BuildEnvironment where
  capHeight : Nat
  /-- Wire ids of the embedded step proof's public-input targets
      (`withdrawal_step_proof.public_inputs`). -/
  stepPublicInputs : List Nat
  /-- `try_build_with_options::<C>(true)` on the registered wires: opaque plonky2 compilation. -/
  build : List Nat → CommonData × Bool

/-- `new`: returns the registered public-input wires, or the first panic in source order. -/
def newCircuit (e : BuildEnvironment) (chainCd : CommonData) : Except Panic (List Nat) :=
  match fromPis e.capHeight e.stepPublicInputs with
  | .error p => .error p
  | .ok t =>
    let wires := t.toVec
    let built := e.build wires
    if built.1 = chainCd then
      if built.2 then .ok wires else .error .buildFailed
    else .error .commonDataMismatch

/-- Boundary premise: plonky2 `build` reports exactly the registered wire count
    as `num_public_inputs`. -/
def BuildReportsRegisteredCount (e : BuildEnvironment) : Prop :=
  ∀ ws, (e.build ws).1.numPublicInputs = ws.length

theorem short_step_vector_panics_in_from_pis {e : BuildEnvironment} {cd : CommonData}
    (short : e.stepPublicInputs.length < chainPublicInputsLen e.capHeight) :
    newCircuit e cd = .error .fromPisLengthMismatch := by
  simp [newCircuit, from_pis_short_panics short]

theorem common_mismatch_precedes_build_failure {e : BuildEnvironment} {cd : CommonData}
    {t : StepPisTarget} (parsed : fromPis e.capHeight e.stepPublicInputs = .ok t)
    (mismatch : (e.build t.toVec).1 ≠ cd) :
    newCircuit e cd = .error .commonDataMismatch := by
  simp [newCircuit, parsed, mismatch]

theorem build_failure_panics_after_common_check {e : BuildEnvironment} {cd : CommonData}
    {t : StepPisTarget} (parsed : fromPis e.capHeight e.stepPublicInputs = .ok t)
    (same : (e.build t.toVec).1 = cd) (failed : (e.build t.toVec).2 = false) :
    newCircuit e cd = .error .buildFailed := by
  simp [newCircuit, parsed, same, failed]

theorem new_circuit_registers_step_prefix {e : BuildEnvironment} {cd : CommonData}
    {wires : List Nat} (built : newCircuit e cd = .ok wires) :
    wires = e.stepPublicInputs.take (chainPublicInputsLen e.capHeight) ∧
    wires.length = chainPublicInputsLen e.capHeight ∧
    (e.build wires).1 = cd ∧ (e.build wires).2 = true := by
  unfold newCircuit at built
  cases parsed : fromPis e.capHeight e.stepPublicInputs with
  | error p => simp [parsed] at built
  | ok t =>
    simp only [parsed] at built
    split at built
    · rename_i same
      split at built
      · rename_i success
        simp only [Except.ok.injEq] at built
        subst built
        exact ⟨from_pis_forwards_step_prefix parsed, forwarded_vector_has_chain_length parsed,
          same, success⟩
      · contradiction
    · contradiction

theorem new_circuit_common_data_has_chain_count {e : BuildEnvironment} {cd : CommonData}
    {wires : List Nat} (counts : BuildReportsRegisteredCount e)
    (built : newCircuit e cd = .ok wires) :
    cd.numPublicInputs = chainPublicInputsLen e.capHeight := by
  obtain ⟨_, len, same, _⟩ := new_circuit_registers_step_prefix built
  rw [← same, counts wires, len]

/-! ## `generate_cd` (lines 79-92) -/

inductive CdOp where
  | simpleRecursionCircuitData
  | newBuilderDefaultConfig
  | addVirtualProofWithPis
  | addVirtualCap (capHeight : Nat)
  | addVirtualHash
  | verifyProof
  | addNoopGates (target : Nat)
  | registerPublicInputs (count : Nat)
  | build
  | overwriteNumPublicInputs (count : Nat)
  deriving DecidableEq, Repr

def generateCdProgram : List CdOp :=
  [.simpleRecursionCircuitData, .newBuilderDefaultConfig, .addVirtualProofWithPis,
   .addVirtualCap defaultCapHeight, .addVirtualHash, .verifyProof, .addNoopGates noopTargetGates,
   .build, .overwriteNumPublicInputs (chainPublicInputsLen defaultCapHeight)]

/-- The common data `generate_cd` returns: whatever the padded shell built,
    with `num_public_inputs` overwritten. `fingerprint` is the opaque remainder. -/
def generateCd (capHeight fingerprint : Nat) : CommonData :=
  ⟨capHeight, chainPublicInputsLen capHeight, fingerprint⟩

theorem generate_cd_count_is_overwritten_not_registered :
    generateCdProgram.getLast? = some (.overwriteNumPublicInputs 91) ∧
    ∀ n, CdOp.registerPublicInputs n ∉ generateCdProgram := by
  refine ⟨by decide, ?_⟩
  intro n
  simp [generateCdProgram]

theorem generate_cd_count_matches_registered_count (h f : Nat) :
    (generateCd h f).numPublicInputs = chainPublicInputsLen h := rfl

theorem new_circuit_against_generate_cd_is_consistent {e : BuildEnvironment} {f : Nat}
    {wires : List Nat} (built : newCircuit e (generateCd e.capHeight f) = .ok wires) :
    wires.length = (generateCd e.capHeight f).numPublicInputs :=
  (new_circuit_registers_step_prefix built).2.1

/-! ## Rollup comparison: the registered vector is never 17 limbs -/

/-- Local pin of `require (pi.length == 17)` in RollupValue.verifyWithdrawalSet. -/
def rollupLimbGate (pi : List Nat) : Bool := pi.length == rollupWithdrawalLimbCount

theorem registered_chain_vector_fails_rollup_gate {e : BuildEnvironment} {cd : CommonData}
    {wires : List Nat} (built : newCircuit e cd = .ok wires) :
    rollupLimbGate wires = false := by
  obtain ⟨_, len, _, _⟩ := new_circuit_registers_step_prefix built
  have := chain_public_inputs_len_at_least_31 e.capHeight
  simp only [rollupLimbGate, len, rollupWithdrawalLimbCount, beq_eq_false_iff_ne, ne_eq]
  omega

/-! ## Native `prove` (lines 94-103) and `verify` (lines 105-120) -/

structure Proof (Body : Type) where
  body : Body
  publicInputs : List Nat

inductive Error where
  | failedToProve (detail : String)
  | proofVerificationError (detail : VerifyFailure)
  deriving DecidableEq, Repr

structure NativeEnvironment (Body : Type) where
  /-- `self.data.common.config.fri_config.cap_height`. -/
  capHeight : Nat
  /-- `self.data.verifier_only`. -/
  ownKey : VerifierKey
  /-- `pw.set_proof_with_pis_target` followed by `self.data.prove(pw)`: opaque plonky2 prover. -/
  proveData : Proof Body → Except String (Proof Body)
  /-- `self.data.verify(proof)`: opaque plonky2 verifier (including its own shape checks). -/
  verifyData : Proof Body → Except String Unit

def prove {Body : Type} (e : NativeEnvironment Body) (stepProof : Proof Body) :
    Except Error (Proof Body) :=
  match e.proveData stepProof with
  | .error m => .error (.failedToProve m)
  | .ok p => .ok p

theorem prove_is_exactly_the_plonky2_prover {Body : Type} (e : NativeEnvironment Body)
    (s p : Proof Body) : prove e s = .ok p ↔ e.proveData s = .ok p := by
  unfold prove
  cases e.proveData s <;> simp

theorem prove_errors_are_only_failed_to_prove {Body : Type} {e : NativeEnvironment Body}
    {s : Proof Body} {err : Error} (failed : prove e s = .error err) :
    ∃ m, err = .failedToProve m := by
  unfold prove at failed
  cases parsed : e.proveData s with
  | error m =>
    rw [parsed] at failed
    have failed' : Except.error (Error.failedToProve m) = Except.error err := failed
    exact ⟨m, (Except.error.inj failed').symm⟩
  | ok p =>
    rw [parsed] at failed
    have failed' : (Except.ok p : Except Error (Proof Body)) = Except.error err := failed
    cases failed'

/-- No native admission: a prover that accepts every witness makes `prove` accept
    any step proof, including one carrying a foreign key or a short vector. -/
theorem prove_performs_no_key_or_length_check {Body : Type} (e : NativeEnvironment Body)
    (c : Proof Body) (s : Proof Body) :
    prove { e with proveData := fun _ => .ok c } s = .ok c := rfl

/-- plonky2 `check_cyclic_proof_verifier_data`: parse the tail, compare cap then digest. -/
def checkCyclicProofVerifierData (capHeight : Nat) (own : VerifierKey) (pis : List Nat) :
    Except VerifyFailure Unit :=
  match vdFromSlice capHeight pis with
  | .error f => .error f
  | .ok k =>
    if own.cap = k.cap then
      if own.digest = k.digest then .ok () else .error .digestMismatch
    else .error .capMismatch

def verify {Body : Type} (e : NativeEnvironment Body) (proof : Proof Body) : Except Error Unit :=
  match checkCyclicProofVerifierData e.capHeight e.ownKey proof.publicInputs with
  | .error f => .error (.proofVerificationError f)
  | .ok () =>
    match e.verifyData proof with
    | .error m => .error (.proofVerificationError (.proofRejected m))
    | .ok () => .ok ()

theorem cyclic_check_ok_binds_last_limbs {h : Nat} {own : VerifierKey} {pis : List Nat}
    (ok : checkCyclicProofVerifierData h own pis = .ok ()) :
    vdVecLen h ≤ pis.length ∧ keyTail h pis = own.limbs := by
  unfold checkCyclicProofVerifierData at ok
  cases parsed : vdFromSlice h pis with
  | error f => simp [parsed] at ok
  | ok k =>
    simp only [parsed] at ok
    split at ok
    · rename_i capEq
      split at ok
      · rename_i digestEq
        obtain ⟨enough, tail⟩ := vd_from_slice_reads_last_limbs parsed
        refine ⟨enough, ?_⟩
        rw [← tail]
        simp only [VerifierKey.limbs]
        rw [capEq, digestEq]
      · contradiction
    · contradiction

theorem own_key_passes_cyclic_check {h : Nat} {own : VerifierKey} {pis : List Nat}
    (wf : own.WellFormed h) (enough : vdVecLen h ≤ pis.length)
    (tail : keyTail h pis = own.limbs) :
    checkCyclicProofVerifierData h own pis = .ok () := by
  have parsed : vdFromSlice h pis = .ok ⟨(keyTail h pis).take 4, (keyTail h pis).drop 4⟩ := by
    simp [vdFromSlice, Nat.not_lt.mpr enough]
  rw [tail] at parsed
  obtain ⟨d, _⟩ := wf
  cases own with
  | mk digest cap =>
    simp only [VerifierKey.limbs] at parsed d
    rw [← d, List.take_left, List.drop_left] at parsed
    simp [checkCyclicProofVerifierData, parsed]

theorem foreign_key_fails_cyclic_check {h : Nat} {own : VerifierKey} {pis : List Nat}
    (enough : vdVecLen h ≤ pis.length) (foreign : keyTail h pis ≠ own.limbs) :
    checkCyclicProofVerifierData h own pis = .error .capMismatch ∨
    checkCyclicProofVerifierData h own pis = .error .digestMismatch := by
  have parsed : vdFromSlice h pis = .ok ⟨(keyTail h pis).take 4, (keyTail h pis).drop 4⟩ := by
    simp [vdFromSlice, Nat.not_lt.mpr enough]
  unfold checkCyclicProofVerifierData
  rw [parsed]
  by_cases capEq : own.cap = (keyTail h pis).drop 4
  · right
    have digestNe : own.digest ≠ (keyTail h pis).take 4 := by
      intro digestEq
      apply foreign
      rw [VerifierKey.limbs, digestEq, capEq, List.take_append_drop]
    simp [capEq, digestNe]
  · left
    simp [capEq]

theorem short_vector_rejected_before_plonky2 {Body : Type} (e : NativeEnvironment Body)
    (p : Proof Body) (short : p.publicInputs.length < vdVecLen e.capHeight) :
    verify e p = .error (.proofVerificationError .notEnoughPublicInputs) := by
  simp [verify, checkCyclicProofVerifierData, vd_from_slice_short_rejected short]

theorem verify_ok_binds_last_limbs_to_own_key {Body : Type} {e : NativeEnvironment Body}
    {p : Proof Body} (ok : verify e p = .ok ()) :
    vdVecLen e.capHeight ≤ p.publicInputs.length ∧
    keyTail e.capHeight p.publicInputs = e.ownKey.limbs ∧
    e.verifyData p = .ok () := by
  unfold verify at ok
  cases check : checkCyclicProofVerifierData e.capHeight e.ownKey p.publicInputs with
  | error f => simp [check] at ok
  | ok u =>
    obtain ⟨enough, tail⟩ := cyclic_check_ok_binds_last_limbs check
    refine ⟨enough, tail, ?_⟩
    simp only [check] at ok
    cases inner : e.verifyData p with
    | error m => simp [inner] at ok
    | ok v => rfl

/-- Error precedence: with a foreign key the result does not depend on the plonky2
    verifier at all, and the error is never `proofRejected`. -/
theorem foreign_key_rejected_before_plonky2_verification {Body : Type}
    (e : NativeEnvironment Body) (p : Proof Body)
    (foreign : keyTail e.capHeight p.publicInputs ≠ e.ownKey.limbs) :
    (∀ vd, verify { e with verifyData := vd } p = verify e p) ∧
    ∃ f, verify e p = .error (.proofVerificationError f) ∧ ∀ m, f ≠ .proofRejected m := by
  by_cases short : p.publicInputs.length < vdVecLen e.capHeight
  · refine ⟨fun vd => ?_, .notEnoughPublicInputs, ?_, fun m => by simp⟩
    · simp [verify, checkCyclicProofVerifierData, vd_from_slice_short_rejected short]
    · exact short_vector_rejected_before_plonky2 e p short
  · have enough := Nat.not_lt.mp short
    rcases foreign_key_fails_cyclic_check enough foreign with cap | digest
    · refine ⟨fun vd => ?_, .capMismatch, ?_, fun m => by simp⟩
      · simp [verify, cap]
      · simp [verify, cap]
    · refine ⟨fun vd => ?_, .digestMismatch, ?_, fun m => by simp⟩
      · simp [verify, digest]
      · simp [verify, digest]

theorem plonky2_rejection_surfaces_after_key_check {Body : Type} (e : NativeEnvironment Body)
    (p : Proof Body) (m : String) (wf : e.ownKey.WellFormed e.capHeight)
    (enough : vdVecLen e.capHeight ≤ p.publicInputs.length)
    (own : keyTail e.capHeight p.publicInputs = e.ownKey.limbs)
    (rejected : e.verifyData p = .error m) :
    verify e p = .error (.proofVerificationError (.proofRejected m)) := by
  simp [verify, own_key_passes_cyclic_check wf enough own, rejected]

/-- A proof whose public inputs are exactly a forwarded step vector exposes the
    step's forwarded verifier-key limbs in the slot the native `verify` binds. -/
theorem forwarded_vector_key_slot {h : Nat} {t : StepPisTarget}
    (hashLen : t.withdrawalHashChain.length = bytes32Len)
    (stateLen : t.publicState.length = publicStateU64Len) (wf : t.vd.WellFormed h) :
    keyTail h t.toVec = t.vd.limbs := by
  have kl := well_formed_key_limb_count wf
  have prefixLen : (t.withdrawalHashChain ++ t.publicState).length = t.toVec.length - vdVecLen h := by
    simp only [StepPisTarget.toVec, List.length_append, hashLen, stateLen, kl]
    omega
  rw [keyTail, ← prefixLen]
  exact List.drop_left _ _

theorem verify_ok_forwarded_step_key_is_own {Body : Type} {e : NativeEnvironment Body}
    {t : StepPisTarget} {body : Body}
    (hashLen : t.withdrawalHashChain.length = bytes32Len)
    (stateLen : t.publicState.length = publicStateU64Len) (wf : t.vd.WellFormed e.capHeight)
    (ok : verify e ⟨body, t.toVec⟩ = .ok ()) : t.vd.limbs = e.ownKey.limbs := by
  obtain ⟨_, tail, _⟩ := verify_ok_binds_last_limbs_to_own_key ok
  rw [← tail]
  exact (forwarded_vector_key_slot hashLen stateLen wf).symm

/-! ## Positive examples (concrete normal traces) -/

def exampleKey : VerifierKey := ⟨[1, 2, 3, 4], List.replicate 64 7⟩
def exampleChainVector : List Nat := List.replicate 23 0 ++ exampleKey.limbs
def exampleEnv : NativeEnvironment Unit :=
  ⟨defaultCapHeight, exampleKey, fun p => .ok p, fun _ => .ok ()⟩

theorem example_key_well_formed : exampleKey.WellFormed defaultCapHeight := ⟨rfl, rfl⟩

theorem normal_chain_proof_verifies : verify exampleEnv ⟨(), exampleChainVector⟩ = .ok () := rfl

theorem normal_chain_vector_length : exampleChainVector.length = 91 := rfl

theorem foreign_digest_example_rejected :
    verify exampleEnv ⟨(), List.replicate 23 0 ++ [1, 2, 3, 5] ++ List.replicate 64 7⟩ =
      .error (.proofVerificationError .digestMismatch) := rfl

theorem foreign_cap_example_rejected_before_digest :
    verify exampleEnv ⟨(), List.replicate 23 0 ++ [9, 9, 9, 9] ++ List.replicate 64 8⟩ =
      .error (.proofVerificationError .capMismatch) := rfl

theorem short_example_rejected :
    verify exampleEnv ⟨(), List.replicate 67 7⟩ =
      .error (.proofVerificationError .notEnoughPublicInputs) := rfl

theorem normal_from_pis_round_trip :
    (fromPis defaultCapHeight (List.range 91)).map StepPisTarget.toVec = .ok (List.range 91) := rfl

theorem normal_from_pis_takes_prefix_of_longer_vector :
    (fromPis defaultCapHeight (List.range 100)).map StepPisTarget.toVec = .ok (List.range 91) := rfl

theorem normal_from_pis_short_panics :
    fromPis defaultCapHeight (List.range 90) = .error .fromPisLengthMismatch := rfl

theorem normal_prove_is_transparent :
    prove exampleEnv ⟨(), exampleChainVector⟩ = .ok ⟨(), exampleChainVector⟩ := rfl

theorem normal_chain_vector_fails_rollup_gate : rollupLimbGate exampleChainVector = false := rfl

end Zkp.Implementation.WithdrawalChainCircuit
