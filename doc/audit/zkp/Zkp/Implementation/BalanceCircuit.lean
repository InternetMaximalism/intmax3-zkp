import Zkp.Implementation.SwitchBoard

/-!
# Current outer base-balance recursion wrapper

Source: src/circuits/balance/balance_circuit.rs, all 240 lines read, including
tests and the production serialization payload declared after the test module.
This handwritten model is not compiler, Plonky2 or recursive-proof soundness
refinement. It imports only the current implementation models.

new verifies the switch proof under CONSTANT switch verifier data and registers
the parsed entire balance+carried-VD statement. It does not itself compare the
carried balance VD to its own VD. The native verify method FIRST performs that
cyclic tail-key check (cap then digest), and ONLY THEN ordinary proof verification.
All theorems referring to native acceptance use this actual entry point, not
data.verify alone. The proof verifier's exact PI length and cryptographic
soundness remain independent concrete call-boundary obligations.

Common-data equality/build-success are constructor assertions, not a proof of
recursion's algebraic soundness. generate_cd's virtual verifier is deliberately
not strengthened to a fixed verifier. Serialization retains its consumed-byte
count discard and does not re-run constructor consistency checks.
-/
namespace Zkp.Implementation.BalanceCircuit
abbrev Proof := SwitchBoard.Proof
abbrev FullInputs := BalancePublicInputs.FullInputs
abbrev VerifierData := BalancePublicInputs.VerifierData

structure CommonData where
  configIdentity : Nat
  capCount : Nat
  numPublicInputs : Nat
  remainingIdentity : Nat
  deriving DecidableEq, Repr
structure Circuit where
  dataIdentity : Nat
  common : CommonData
  selfVd : VerifierData
  switchProofTarget : Nat
  deriving DecidableEq, Repr
structure BuildResult where
  circuit : Circuit
  success : Bool

inductive Fault where
  | commonDataMismatchPanic
  | failedBuildPanic
  | targetParsingPanic
  | failedToProve (detail : String)
  | cyclicVerification (detail : String)
  | proofVerification (detail : String)
  | serialization (stage : String)
  deriving DecidableEq, Repr
abbrev Result (α : Type) := Except Fault α

inductive BuildOp where
  | builderWithBalanceConfig
  | allocateSwitchProof
  | constantSwitchVerifier
  | verifySwitchProof
  | parseFullPublicInputs
  | registerFullPublicInputs
  | tryBuildWithOptionsTrue
  | assertExactCommonData
  | assertBuildSuccess
  deriving DecidableEq, Repr
def buildPlan : List BuildOp :=
  [.builderWithBalanceConfig,.allocateSwitchProof,.constantSwitchVerifier,.verifySwitchProof,
   .parseFullPublicInputs,.registerFullPublicInputs,.tryBuildWithOptionsTrue,
   .assertExactCommonData,.assertBuildSuccess]
def finishBuild (expected : CommonData) (built : BuildResult) : Result Circuit :=
  if built.circuit.common ≠ expected then .error .commonDataMismatchPanic
  else if built.success then .ok built.circuit else .error .failedBuildPanic

structure ConstructorEnvironment where
  build : CommonData → VerifierData → BuildResult
def new (e : ConstructorEnvironment) (balanceCommon : CommonData)
    (switchVd : VerifierData) : Result Circuit := finishBuild balanceCommon (e.build balanceCommon switchVd)

inductive GenerateOp where
  | simpleRecursionData
  | defaultBuilder
  | virtualProofOfSimpleData
  | virtualVerifierCap
  | virtualVerifierDigest
  | verifyWithVirtualVerifier
  | padTo4096Gates
  | buildCommon
  | replacePublicInputCount
  deriving DecidableEq, Repr
def generatePlan : List GenerateOp :=
  [.simpleRecursionData,.defaultBuilder,.virtualProofOfSimpleData,.virtualVerifierCap,
   .virtualVerifierDigest,.verifyWithVirtualVerifier,.padTo4096Gates,
   .buildCommon,.replacePublicInputCount]
def generatedCommon (built : CommonData) : CommonData :=
  {built with numPublicInputs := BalancePublicInputs.balanceLength +
    BalancePublicInputs.verifierLength built.capCount}

structure GateEnvironment where
  capCount : Nat
  fixedSwitchVd : VerifierData
  verifyRecursive : VerifierData → Proof → Prop
structure CircuitGates (e : GateEnvironment) (switchProof : Proof) (output : FullInputs) : Prop where
  fixedVerifierCall : e.verifyRecursive e.fixedSwitchVd switchProof
  parsedStatement : BalancePublicInputs.fullFromTarget e.capCount switchProof.publicInputs = .ok output

structure ProveEnvironment where
  proveData : Circuit → Nat → Proof → Except String Proof
def prove (e : ProveEnvironment) (c : Circuit) (switchProof : Proof) : Result Proof :=
  match e.proveData c c.switchProofTarget switchProof with
  | .error detail => .error (.failedToProve detail)
  | .ok proof => .ok proof

/-- The cyclic helper reads the LAST configured VD words. Unlike the full
    statement parser it does not impose the balance-prefix length. -/
def readCyclicTail (capCount : Nat) (words : List Nat) : Result VerifierData :=
  if BalancePublicInputs.verifierLength capCount ≤ words.length then
    match BalancePublicInputs.readVerifier capCount
        (words.drop (words.length - BalancePublicInputs.verifierLength capCount)) with
    | .error _ => .error (.cyclicVerification "verifier data decoding failed")
    | .ok vd => .ok vd
  else .error (.cyclicVerification "not enough public inputs")
def checkCyclic (c : Circuit) (proof : Proof) : Result Unit := do
  let carried ← readCyclicTail c.common.capCount proof.publicInputs
  if carried.cap ≠ c.selfVd.cap then
    .error (.cyclicVerification "constants_sigmas_cap mismatch") else pure ()
  if carried.digest ≠ c.selfVd.digest then
    .error (.cyclicVerification "circuit_digest mismatch") else pure ()
  return ()
structure VerifyEnvironment where
  verifyData : Circuit → Proof → Except String Unit
def verify (e : VerifyEnvironment) (c : Circuit) (proof : Proof) : Result Unit := do
  let _ ← checkCyclic c proof
  match e.verifyData c proof with
  | .error detail => .error (.proofVerification detail)
  | .ok () => .ok ()

structure Payload where
  data : List Nat
  switchProofTarget : Nat
structure CodecEnvironment where
  encodeCircuitData : Circuit → Except String (List Nat)
  encodePayload : Payload → Except String (List Nat)
  decodePayload : List Nat → Except String (Payload × Nat)
  decodeCircuitData : List Nat → Except String Circuit
def toBytes (e : CodecEnvironment) (c : Circuit) : Result (List Nat) := do
  let data ← match e.encodeCircuitData c with
    | .error _ => .error (.serialization "balance circuit data")
    | .ok bytes => .ok bytes
  match e.encodePayload ⟨data,c.switchProofTarget⟩ with
  | .error _ => .error (.serialization "balance circuit")
  | .ok bytes => .ok bytes
def fromBytes (e : CodecEnvironment) (bytes : List Nat) : Result Circuit := do
  let (payload,_) ← match e.decodePayload bytes with
    | .error _ => .error (.serialization "balance circuit")
    | .ok p => .ok p
  let data ← match e.decodeCircuitData payload.data with
    | .error _ => .error (.serialization "balance circuit data")
    | .ok c => .ok c
  return {data with switchProofTarget := payload.switchProofTarget}

theorem constructor_checks_common_before_success (expected : CommonData) (built : BuildResult)
    (mismatch : built.circuit.common ≠ expected) :
    finishBuild expected built = .error .commonDataMismatchPanic := by
  simp [finishBuild,mismatch]
theorem constructor_success_has_exact_common (expected : CommonData) (built : BuildResult)
    (c : Circuit) (accepted : finishBuild expected built = .ok c) :
    c = built.circuit ∧ c.common = expected ∧ built.success = true := by
  unfold finishBuild at accepted
  split at accepted
  · contradiction
  split at accepted
  · have h := Except.ok.inj accepted; subst c; simp_all
  · contradiction
theorem generated_common_has_exact_public_width (built : CommonData) :
    (generatedCommon built).numPublicInputs = BalancePublicInputs.balanceLength +
      BalancePublicInputs.verifierLength built.capCount := rfl
theorem generated_common_preserves_configuration (built : CommonData) :
    (generatedCommon built).configIdentity = built.configIdentity ∧
    (generatedCommon built).capCount = built.capCount ∧
    (generatedCommon built).remainingIdentity = built.remainingIdentity := ⟨rfl,rfl,rfl⟩
theorem target_verifies_exact_fixed_switch_key (e : GateEnvironment) (proof : Proof)
    (output : FullInputs) (gates : CircuitGates e proof output) :
    e.verifyRecursive e.fixedSwitchVd proof := gates.fixedVerifierCall
theorem target_forwards_exact_parsed_statement (e : GateEnvironment) (proof : Proof)
    (output : FullInputs) (gates : CircuitGates e proof output) :
    BalancePublicInputs.fullFromTarget e.capCount proof.publicInputs = .ok output := gates.parsedStatement
theorem prove_assigns_the_supplied_switch_proof (e : ProveEnvironment) (c : Circuit) (proof : Proof)
    (result : Proof) (successful : e.proveData c c.switchProofTarget proof = .ok result) :
    prove e c proof = .ok result := by simp [prove,successful]

theorem cyclic_failure_precedes_ordinary_verification (e : VerifyEnvironment) (c : Circuit)
    (proof : Proof) (err : Fault) (rejected : checkCyclic c proof = .error err) :
    verify e c proof = .error err := by simp [verify,rejected,Bind.bind,Except.bind]
theorem accepted_native_verification_checks_both_layers (e : VerifyEnvironment) (c : Circuit)
    (proof : Proof) (accepted : verify e c proof = .ok ()) :
    checkCyclic c proof = .ok () ∧ e.verifyData c proof = .ok () := by
  cases cyclic : checkCyclic c proof with
  | error err => simp [verify,cyclic,Bind.bind,Except.bind] at accepted
  | ok unitResult =>
    cases unitResult
    cases checked : e.verifyData c proof with
    | error err => simp [verify,cyclic,checked,Bind.bind,Except.bind] at accepted
    | ok value => cases value; exact ⟨rfl,rfl⟩
theorem cyclic_check_binds_cap_and_digest (c : Circuit) (proof : Proof)
    (accepted : checkCyclic c proof = .ok ()) :
    readCyclicTail c.common.capCount proof.publicInputs = .ok c.selfVd := by
  cases parsed : readCyclicTail c.common.capCount proof.publicInputs with
  | error err => simp [checkCyclic,parsed,Bind.bind,Except.bind] at accepted
  | ok carried =>
    by_cases cap : carried.cap = c.selfVd.cap
    · by_cases digest : carried.digest = c.selfVd.digest
      · have h : carried = c.selfVd := by
          change (⟨carried.digest,carried.cap⟩ : VerifierData) = ⟨c.selfVd.digest,c.selfVd.cap⟩
          rw [cap,digest]
        simp [h]
      · simp [checkCyclic,parsed,cap,digest,Bind.bind,Except.bind,Pure.pure,Except.pure] at accepted
    · simp [checkCyclic,parsed,cap,Bind.bind,Except.bind,Pure.pure,Except.pure] at accepted

theorem cyclic_tail_of_full_encoding (p : FullInputs) :
    readCyclicTail p.vd.cap.length p.words = .ok p.vd := by
  have length := BalancePublicInputs.full_encoding_length p
  have dropped : p.words.drop BalancePublicInputs.balanceLength = p.vd.words := by
    simp [BalancePublicInputs.FullInputs.words,←BalancePublicInputs.balance_word_count p.pis]
  have parsed := BalancePublicInputs.verifier_prefix_roundtrip p.vd []
  simp only [List.append_nil] at parsed
  simp [readCyclicTail,length,Nat.add_sub_cancel_left,dropped,parsed,Nat.le_add_left]

theorem accepted_exact_statement_carries_actual_balance_key (e : VerifyEnvironment) (c : Circuit)
    (proof : Proof) (statement : FullInputs)
    (sameWords : proof.publicInputs = statement.words)
    (capShape : c.common.capCount = statement.vd.cap.length)
    (accepted : verify e c proof = .ok ()) : statement.vd = c.selfVd := by
  have checked := cyclic_check_binds_cap_and_digest c proof
    (accepted_native_verification_checks_both_layers e c proof accepted).1
  rw [sameWords,capShape,cyclic_tail_of_full_encoding] at checked
  exact Except.ok.inj checked

theorem selector_then_outer_verification_binds_selected_key
    (se : SwitchBoard.GateEnvironment) (sw : SwitchBoard.TargetWitness)
    (sg : SwitchBoard.CircuitGates se sw) (e : VerifyEnvironment) (c : Circuit)
    (proof : Proof) (sameWords : proof.publicInputs = sw.output.words)
    (capShape : c.common.capCount = sw.output.vd.cap.length)
    (accepted : verify e c proof = .ok ()) :
    (sw.candidate sw.flags.choose).vd = c.selfVd := by
  have key := accepted_exact_statement_carries_actual_balance_key e c proof sw.output
    sameWords capShape accepted
  rw [SwitchBoard.selected_output_is_whole_candidate se sw sg] at key
  exact key

theorem decoded_payload_keeps_target_without_constructor_check (e : CodecEnvironment)
    (bytes : List Nat) (payload : Payload) (consumed : Nat) (data : Circuit)
    (outer : e.decodePayload bytes = .ok (payload,consumed))
    (inner : e.decodeCircuitData payload.data = .ok data) :
    fromBytes e bytes = .ok {data with switchProofTarget := payload.switchProofTarget} := by
  simp [fromBytes,outer,inner,Bind.bind,Except.bind,Pure.pure,Except.pure]
theorem serialized_data_failure_precedes_payload (e : CodecEnvironment) (c : Circuit)
    (err : String) (failed : e.encodeCircuitData c = .error err) :
    toBytes e c = .error (.serialization "balance circuit data") := by
  simp [toBytes,failed,Bind.bind,Except.bind]

def normalCommon : CommonData := ⟨1,2,41,7⟩
def normalVd : VerifierData := ⟨BalancePublicInputs.Root.zero,
  [BalancePublicInputs.Root.zero,BalancePublicInputs.Root.zero]⟩
def normalCircuit : Circuit := ⟨9,normalCommon,normalVd,12⟩
theorem normal_constructor_finishes :
    finishBuild normalCommon ⟨normalCircuit,true⟩ = .ok normalCircuit := by
  simp [finishBuild,normalCircuit]
theorem normal_encoding_checks_its_own_cyclic_key :
    checkCyclic normalCircuit ⟨(⟨BalancePublicInputs.normalInputs,normalVd⟩ : FullInputs).words,0⟩ = .ok () := by
  have tail := cyclic_tail_of_full_encoding (⟨BalancePublicInputs.normalInputs,normalVd⟩ : FullInputs)
  simpa [checkCyclic,normalCircuit,normalCommon,normalVd,Bind.bind,Except.bind,Pure.pure,Except.pure]
    using congrArg (fun result => result.map (fun _ => ())) tail

end Zkp.Implementation.BalanceCircuit
