import Zkp.Implementation.BalancePublicInputs

/-!
# Current balance switch board

Source: src/circuits/balance/switch_board.rs, all 837 lines read. This is a
handwritten source model, not compiler or recursive-proof soundness refinement.
It does not claim that branch acceptance implies conservation of money.

Safe Boolean allocation and the field sum-one check yield exactly one mode.
Selection below is the actual four-product sum, applied to EVERY public word,
including the carried balance verifier data. Inactive branch proofs are NOT
unconstrained: dummy::conditionally_verify_proof verifies them under a fixed
dummy verifier, whereas the active proof uses the fixed real branch verifier.

The independent virtual balance VD is used by the genesis candidate only.
Non-genesis candidates retain their carried VD; neither native admission nor
this constructor equates it to the independently supplied balance VD. The
outer BalanceCircuit.verify cyclic-key check is a distinct necessary boundary.
Spend validity is a SendTx detail, not one of the four mode flags here.
`NativeEnvironment` fixes one cap count and one balance VD per instantiation,
whereas the source derives `vd_len` from the caller-supplied `balance_vd` at
each prove call; the model is a per-call instantiation, not a proof that the
prove-time config equals the constructor `balance_config`.

The gate model concerns integer representatives after local field/Boolean and
verifier-gadget lowering. It gives explicit local proof-call obligations, not
an assumed accepted-implies-safe predicate. Genesis empty-tree roots and the
private-state hash are dependency values, with their actual preimage exposed.
Opaque serialization callbacks preserve call order and failure labels, not
generated serde/bincode/gate implementations. No constructor validation of
deserialized target/data consistency is invented.
-/
namespace Zkp.Implementation.SwitchBoard
abbrev Root := BalancePublicInputs.Root
abbrev FullInputs := BalancePublicInputs.FullInputs
abbrev VerifierData := BalancePublicInputs.VerifierData

inductive Mode where
  | initial | transfer | deposit | send
  deriving DecidableEq, Repr
def modes : List Mode := [.initial,.transfer,.deposit,.send]
def proofModes : List Mode := [.transfer,.deposit,.send]
def Mode.index : Mode → Nat
  | .initial => 0 | .transfer => 1 | .deposit => 2 | .send => 3

structure Flags where
  initial : Bool
  transfer : Bool
  deposit : Bool
  send : Bool
  deriving DecidableEq, Repr
def Flags.get (f : Flags) : Mode → Bool
  | .initial => f.initial | .transfer => f.transfer | .deposit => f.deposit | .send => f.send
def bit (b : Bool) : Nat := if b then 1 else 0
def Flags.total (f : Flags) : Nat := bit f.initial+bit f.transfer+bit f.deposit+bit f.send
def Flags.choose (f : Flags) : Mode :=
  if f.initial then .initial else if f.transfer then .transfer else if f.deposit then .deposit else .send
def Flags.only (m : Mode) : Flags :=
  ⟨decide (m=.initial),decide (m=.transfer),decide (m=.deposit),decide (m=.send)⟩
def weightedCell (f : Flags) (row : Mode → Nat) : Nat :=
  bit f.initial*row .initial + bit f.transfer*row .transfer +
    bit f.deposit*row .deposit + bit f.send*row .send

structure Proof where
  publicInputs : List Nat
  body : Nat
  deriving DecidableEq, Repr
structure NativeWitness where
  initial : Option (Nat × Root)
  transfer : Option Proof
  deposit : Option Proof
  send : Option Proof
def NativeWitness.flags (w : NativeWitness) : Flags :=
  ⟨w.initial.isSome,w.transfer.isSome,w.deposit.isSome,w.send.isSome⟩
def NativeWitness.proof (w : NativeWitness) : Mode → Option Proof
  | .initial => none | .transfer => w.transfer | .deposit => w.deposit | .send => w.send

inductive Error where
  | invalidBalanceProof (mode : Mode)
  | invalidBalanceVd
  | publicInputs (fault : BalancePublicInputs.Fault)
  | invalidInput
  | dummyNotProvided (index : Nat)
  | failedToProve
  | unreachablePanic
  | codec (stage : String)
  deriving DecidableEq, Repr
abbrev Result (α : Type) := Except Error α
def liftPublic {α : Type} : BalancePublicInputs.Result α → Result α
  | .error err => .error (.publicInputs err)
  | .ok value => .ok value

structure NativeEnvironment where
  genesis : BalancePublicInputs.GenesisEnvironment
  capCount : Nat
  balanceVd : VerifierData
  convertFields : List Nat → BalancePublicInputs.Result (List Nat)
  fixedBranchVd : Mode → VerifierData
  verifyAt : VerifierData → Proof → Except String Unit
def NativeEnvironment.verifyBranch (e : NativeEnvironment) (m : Mode) (p : Proof) : Except String Unit :=
  e.verifyAt (e.fixedBranchVd m) p
def verifyAndDecode (e : NativeEnvironment) (mode : Mode) (proof : Proof) : Result FullInputs := do
  match e.verifyBranch mode proof with
  | .error _ => .error (.invalidBalanceProof mode)
  | .ok () => pure ()
  liftPublic (BalancePublicInputs.fullFromNative e.convertFields e.capCount proof.publicInputs)
def toPublicInputs (e : NativeEnvironment) (w : NativeWitness) : Result FullInputs :=
  if w.flags.total ≠ 1 then .error .invalidInput else
  match w.initial with
  | some (channel,salt) => .ok ⟨BalancePublicInputs.initialInputs e.genesis channel salt,e.balanceVd⟩
  | none => match w.transfer with
    | some proof => verifyAndDecode e .transfer proof
    | none => match w.deposit with
      | some proof => verifyAndDecode e .deposit proof
      | none => match w.send with
        | some proof => verifyAndDecode e .send proof
        | none => .error .unreachablePanic

inductive BuildOp where
  | virtualBalanceVd
  | safeModeFlag (mode : Mode)
  | sumFlagsAndAssertOne
  | checkedInitialChannel
  | virtualSalt
  | constantEmptyPrivateRootsAndNonce
  | hashInitialPrivateState
  | constantGenesisPublicStateAndSettledChain
  | initialCandidateWithVirtualBalanceVd
  | conditionalProofUnderRealOrDummyVd (mode : Mode)
  | parseFullCandidate (mode : Mode)
  | multiplyAddWholeCandidateVectors
  | checkedNewPublicInputsAndVirtualVd
  | connectEverySelectedWord
  | registerNewFullInputs
  | build
  | generateDummy (mode : Mode)
  deriving DecidableEq, Repr
def targetBuildPlan : List BuildOp :=
  [.virtualBalanceVd] ++ modes.map BuildOp.safeModeFlag ++
  [.sumFlagsAndAssertOne,.checkedInitialChannel,.virtualSalt,
   .constantEmptyPrivateRootsAndNonce,.hashInitialPrivateState,
   .constantGenesisPublicStateAndSettledChain,.initialCandidateWithVirtualBalanceVd] ++
  (proofModes.map (fun m => [.conditionalProofUnderRealOrDummyVd m,.parseFullCandidate m])).join ++
  [.multiplyAddWholeCandidateVectors,.checkedNewPublicInputsAndVirtualVd,.connectEverySelectedWord]
def circuitBuildPlan : List BuildOp := targetBuildPlan ++
  [.registerNewFullInputs,.build] ++ proofModes.map BuildOp.generateDummy

structure TargetWitness where
  flags : Flags
  initialChannel : Nat
  initialSalt : Root
  balanceVd : VerifierData
  branchProofs : Mode → Proof
  candidate : Mode → FullInputs
  output : FullInputs

/-- Real and dummy verification relations are concrete calls at fixed supplied
    common/VK data. Actual proof gadget soundness is not assumed here. -/
structure GateEnvironment where
  genesis : BalancePublicInputs.GenesisEnvironment
  capCount : Nat
  fixedRealVd : Mode → VerifierData
  fixedDummyVd : Mode → VerifierData
  verifyAt : VerifierData → Proof → Prop
def GateEnvironment.verifyReal (e : GateEnvironment) (m : Mode) (p : Proof) : Prop :=
  e.verifyAt (e.fixedRealVd m) p
def GateEnvironment.verifyDummy (e : GateEnvironment) (m : Mode) (p : Proof) : Prop :=
  e.verifyAt (e.fixedDummyVd m) p

structure CircuitGates (e : GateEnvironment) (w : TargetWitness) : Prop where
  oneHot : w.flags.total = 1
  initialChannelRange : w.initialChannel < BalancePublicInputs.wordBase
  genesisCandidate : w.candidate .initial =
    ⟨BalancePublicInputs.initialInputs e.genesis w.initialChannel w.initialSalt,w.balanceVd⟩
  parsedCandidates : ∀ m, m ≠ .initial →
    BalancePublicInputs.fullFromTarget e.capCount (w.branchProofs m).publicInputs = .ok (w.candidate m)
  actualProofCalls : ∀ m, m ≠ .initial →
    if w.flags.get m then e.verifyReal m (w.branchProofs m)
    else e.verifyDummy m (w.branchProofs m)
  candidateShape : ∀ m, (w.candidate m).vd.cap.length = e.capCount
  outputShape : w.output.vd.cap.length = e.capCount
  checkedOutput : BalancePublicInputs.AllocationChecks w.output.pis
  selectedWords : ∀ i, i < w.output.words.length →
    w.output.words.getD i 0 = weightedCell w.flags (fun m => (w.candidate m).words.getD i 0)

/-- Source-local arithmetic before integer lifting. Bool here is the checked
    Boolean-wire representation; candidates are canonical field representatives.
    The sum/connect equations remain modular until the bridge proved below. -/
structure ModularSelectorGates (modulus : Nat) (w : TargetWitness) : Prop where
  characteristic : 4 < modulus
  flagEquation : w.flags.total % modulus = 1
  canonicalCandidates : ∀ m i, i < w.output.words.length → (w.candidate m).words.getD i 0 < modulus
  wordEquations : ∀ i, i < w.output.words.length →
    w.output.words.getD i 0 = weightedCell w.flags (fun m => (w.candidate m).words.getD i 0) % modulus

inductive Assignment where
  | flag (mode : Mode) (value : Bool)
  | initial (channel : Nat) (salt : Root)
  | branchProof (mode : Mode) (proof : Proof)
  | balanceVd (vd : VerifierData)
  | newPublicInputs (pis : FullInputs)
  deriving DecidableEq, Repr
inductive Request where
  | write (assignment : Assignment)
  | dummy (mode : Mode)
  deriving DecidableEq, Repr
abbrev DummyMap := Nat → Option Proof
structure FillResult where
  writes : List Assignment
  outcome : Result Unit
  deriving Repr
def resolveRequest (dummy : DummyMap) : Request → Result Assignment
  | .write value => .ok value
  | .dummy mode => match dummy mode.index with
    | none => .error (.dummyNotProvided mode.index)
    | some proof => .ok (.branchProof mode proof)
def executeRequests (dummy : DummyMap) : List Request → FillResult
  | [] => ⟨[],.ok ()⟩
  | request::rest => match resolveRequest dummy request with
    | .error err => ⟨[],.error err⟩
    | .ok value =>
      let tail := executeRequests dummy rest
      ⟨value::tail.writes,tail.outcome⟩
def fillRequests (e : NativeEnvironment) (w : NativeWitness) (pis : FullInputs) : List Request :=
  modes.map (fun m => .write (.flag m (w.flags.get m))) ++
  [.write (match w.initial with
    | some (channel,salt) => .initial channel salt
    | none => .initial 0 BalancePublicInputs.Root.zero)] ++
  proofModes.map (fun m => match w.proof m with
    | some proof => .write (.branchProof m proof)
    | none => .dummy m) ++
  [.write (.balanceVd e.balanceVd),.write (.newPublicInputs pis)]
def setWitness (e : NativeEnvironment) (w : NativeWitness) (pis : FullInputs) (dummy : DummyMap) : FillResult :=
  if w.flags.total ≠ 1 then ⟨[],.error .invalidInput⟩
  else executeRequests dummy (fillRequests e w pis)
def prove (e : NativeEnvironment) (w : NativeWitness) (dummy : DummyMap)
    (proveData : List Assignment → Except String Proof) : Result Proof := do
  let pis ← toPublicInputs e w
  let filled := setWitness e w pis dummy
  let _ ← filled.outcome
  match proveData (filled.writes ++ [.newPublicInputs pis]) with
  | .error _ => .error .failedToProve
  | .ok proof => .ok proof

/- Serialization is a source-ordered effect model. `dummyProofs` is a List
   standing for a HashMap: iteration order is a chosen enumeration, the
   `[1,2,3]` order theorem is set-membership only, and duplicate indices in a
   decoded payload are collapsed by serde (last wins) before the index match;
   the list model admits duplicates and is used only for the index-domain
   rejection theorem. Neither sorted order nor uniqueness is a theorem here. -/
structure Circuit where
  data : Nat
  transferVd : Nat
  depositVd : Nat
  sendVd : Nat
  dummyProofs : List (Nat × Proof)
  target : Nat
  publicInputsTarget : Nat
structure BuildEnvironment where
  buildTargetAndData : Nat → Nat → Nat → Nat → Nat × Nat × Nat
  makeDummy : Nat → Proof
def new (e : BuildEnvironment) (balanceConfig transfer deposit send : Nat) : Circuit :=
  let (data,target,publicInputs) := e.buildTargetAndData balanceConfig transfer deposit send
  ⟨data,transfer,deposit,send,
    [(1,e.makeDummy transfer),(2,e.makeDummy deposit),(3,e.makeDummy send)],target,publicInputs⟩
structure Payload where
  data : List Nat
  transferVd : List Nat
  depositVd : List Nat
  sendVd : List Nat
  dummyProofs : List (Nat × List Nat)
  target : Nat
  publicInputsTarget : Nat
structure CodecEnvironment where
  serializeData : Nat → Result (List Nat)
  serializeVd : Mode → Nat → Result (List Nat)
  proofBytes : Proof → List Nat
  encodePayload : Payload → Result (List Nat)
  decodePayload : List Nat → Result (Payload × Nat)
  deserializeData : List Nat → Result Nat
  deserializeVd : Mode → List Nat → Result Nat
  deserializeProof : Nat → List Nat → Result Proof
def serialize (e : CodecEnvironment) (c : Circuit) : Result (List Nat) := do
  let data ← e.serializeData c.data
  let transfer ← e.serializeVd .transfer c.transferVd
  let deposit ← e.serializeVd .deposit c.depositVd
  let send ← e.serializeVd .send c.sendVd
  e.encodePayload ⟨data,transfer,deposit,send,
    c.dummyProofs.map (fun (i,p) => (i,e.proofBytes p)),c.target,c.publicInputsTarget⟩
def deserializeDummies (e : CodecEnvironment) (transfer deposit send : Nat) :
    List (Nat × List Nat) → Result (List (Nat × Proof))
  | [] => .ok []
  | (index,bytes)::rest => do
    let vd ← match index with
      | 1 => .ok transfer | 2 => .ok deposit | 3 => .ok send
      | _ => .error (.codec "balance switch board dummy proof index")
    let proof ← e.deserializeProof vd bytes
    let tail ← deserializeDummies e transfer deposit send rest
    return (index,proof)::tail
def deserialize (e : CodecEnvironment) (bytes : List Nat) : Result Circuit := do
  let (p,_) ← e.decodePayload bytes
  let data ← e.deserializeData p.data
  let transfer ← e.deserializeVd .transfer p.transferVd
  let deposit ← e.deserializeVd .deposit p.depositVd
  let send ← e.deserializeVd .send p.sendVd
  let dummy ← deserializeDummies e transfer deposit send p.dummyProofs
  return ⟨data,transfer,deposit,send,dummy,p.target,p.publicInputsTarget⟩

theorem safe_flag_sum_is_small (flags : Flags) : flags.total ≤ 4 := by
  cases flags with
  | mk a b c d => cases a <;> cases b <;> cases c <;> cases d <;> decide
theorem field_sum_one_yields_integer_one (flags : Flags) (modulus : Nat)
    (large : 4 < modulus) (fieldEquation : flags.total % modulus = 1) : flags.total = 1 := by
  have small := safe_flag_sum_is_small flags
  rw [Nat.mod_eq_of_lt (by omega)] at fieldEquation
  exact fieldEquation
theorem one_hot_has_exact_selected_mode (flags : Flags) (one : flags.total = 1) :
    flags.get flags.choose = true ∧ ∀ m, m ≠ flags.choose → flags.get m = false := by
  cases flags with
  | mk a b c d => cases a <;> cases b <;> cases c <;> cases d <;>
    simp_all [Flags.total,bit,Flags.choose,Flags.get] <;> intro m hm <;> cases m <;> simp_all
theorem only_mode_is_one_hot (mode : Mode) : (Flags.only mode).total = 1 := by
  cases mode <;> decide
theorem only_mode_is_chosen (mode : Mode) : (Flags.only mode).choose = mode := by
  cases mode <;> rfl
theorem constructor_retains_fixed_verifiers (e : BuildEnvironment) (config a b c : Nat) :
    (new e config a b c).transferVd = a ∧ (new e config a b c).depositVd = b ∧
    (new e config a b c).sendVd = c := ⟨rfl,rfl,rfl⟩
theorem constructor_builds_all_three_dummy_slots (e : BuildEnvironment) (config a b c : Nat) :
    ((new e config a b c).dummyProofs.map Prod.fst) = [1,2,3] := rfl
theorem weighted_sum_is_exact_selected_cell (flags : Flags) (one : flags.total = 1)
    (row : Mode → Nat) : weightedCell flags row = row flags.choose := by
  cases flags with
  | mk a b c d => cases a <;> cases b <;> cases c <;> cases d <;>
    simp_all [Flags.total,bit,weightedCell,Flags.choose]

theorem modular_gates_determine_unique_whole_selection (modulus : Nat) (w : TargetWitness)
    (raw : ModularSelectorGates modulus w) :
    w.flags.total = 1 ∧ ∀ i, i < w.output.words.length →
      w.output.words.getD i 0 = weightedCell w.flags (fun m => (w.candidate m).words.getD i 0) := by
  have one := field_sum_one_yields_integer_one w.flags modulus raw.characteristic raw.flagEquation
  refine ⟨one,?_⟩
  intro i hi
  have equation := raw.wordEquations i hi
  rw [weighted_sum_is_exact_selected_cell w.flags one] at equation ⊢
  rwa [Nat.mod_eq_of_lt (raw.canonicalCandidates w.flags.choose i hi)] at equation

theorem selected_output_is_whole_candidate (e : GateEnvironment) (w : TargetWitness)
    (gates : CircuitGates e w) : w.output = w.candidate w.flags.choose := by
  apply BalancePublicInputs.full_encoding_injective (gates.outputShape.trans (gates.candidateShape _).symm)
  apply List.ext_getElem
  · simp [BalancePublicInputs.full_encoding_length,gates.outputShape,gates.candidateShape]
  · intro i hi hj
    have h := gates.selectedWords i hi
    rw [weighted_sum_is_exact_selected_cell w.flags gates.oneHot] at h
    simpa only [List.getD_eq_getElem?,List.getElem?_eq_getElem hi,
      List.getElem?_eq_getElem hj,Option.getD_some] using h
theorem selected_output_preserves_every_identity (e : GateEnvironment) (w : TargetWitness)
    (gates : CircuitGates e w) :
    w.output.pis.channelId = (w.candidate w.flags.choose).pis.channelId ∧
    w.output.pis.publicState = (w.candidate w.flags.choose).pis.publicState ∧
    w.output.pis.privateCommitment = (w.candidate w.flags.choose).pis.privateCommitment ∧
    w.output.pis.settledChain = (w.candidate w.flags.choose).pis.settledChain ∧
    w.output.vd = (w.candidate w.flags.choose).vd := by
  rw [selected_output_is_whole_candidate e w gates]
  exact ⟨rfl,rfl,rfl,rfl,rfl⟩
theorem selected_noninitial_proof_uses_real_key (e : GateEnvironment) (w : TargetWitness)
    (gates : CircuitGates e w) (noninitial : w.flags.choose ≠ .initial) :
    e.verifyReal w.flags.choose (w.branchProofs w.flags.choose) := by
  have call := gates.actualProofCalls _ noninitial
  rw [(one_hot_has_exact_selected_mode w.flags gates.oneHot).1] at call
  exact call
theorem inactive_proof_uses_dummy_key (e : GateEnvironment) (w : TargetWitness)
    (gates : CircuitGates e w) (m : Mode) (noninitial : m ≠ .initial)
    (inactive : m ≠ w.flags.choose) : e.verifyDummy m (w.branchProofs m) := by
  have call := gates.actualProofCalls m noninitial
  rw [(one_hot_has_exact_selected_mode w.flags gates.oneHot).2 m inactive] at call
  exact call
theorem genesis_output_is_exact (e : GateEnvironment) (w : TargetWitness)
    (gates : CircuitGates e w) (initial : w.flags.choose = .initial) :
    w.output = ⟨BalancePublicInputs.initialInputs e.genesis w.initialChannel w.initialSalt,w.balanceVd⟩ := by
  rw [selected_output_is_whole_candidate e w gates,initial,gates.genesisCandidate]

theorem invalid_native_cardinality_stops_admission (e : NativeEnvironment) (w : NativeWitness)
    (invalid : w.flags.total ≠ 1) : toPublicInputs e w = .error .invalidInput := by
  simp [toPublicInputs,invalid]
theorem invalid_native_cardinality_writes_nothing (e : NativeEnvironment) (w : NativeWitness)
    (pis : FullInputs) (dummy : DummyMap) (invalid : w.flags.total ≠ 1) :
    setWitness e w pis dummy = ⟨[],.error .invalidInput⟩ := by simp [setWitness,invalid]
theorem admitted_proof_call_succeeded (e : NativeEnvironment) (m : Mode) (proof : Proof)
    (pis : FullInputs) (accepted : verifyAndDecode e m proof = .ok pis) :
    e.verifyBranch m proof = .ok () := by
  cases h : e.verifyBranch m proof with
  | error err => simp [verifyAndDecode,h,Bind.bind,Except.bind] at accepted
  | ok value => cases value; rfl
theorem genesis_native_admission (e : NativeEnvironment) (channel : Nat) (salt : Root) :
    toPublicInputs e ⟨some (channel,salt),none,none,none⟩ =
      .ok ⟨BalancePublicInputs.initialInputs e.genesis channel salt,e.balanceVd⟩ := rfl
theorem transfer_native_admission_calls_only_transfer (e : NativeEnvironment) (proof : Proof) :
    toPublicInputs e ⟨none,some proof,none,none⟩ = verifyAndDecode e .transfer proof := rfl
theorem missing_dummy_stops_remaining_assignments (dummy : DummyMap) (m : Mode)
    (rest : List Request) (missing : dummy m.index = none) :
    executeRequests dummy (.dummy m::rest) = ⟨[],.error (.dummyNotProvided m.index)⟩ := by
  simp [executeRequests,resolveRequest,missing]
theorem earlier_assignment_survives_later_failure (dummy : DummyMap) (value : Assignment)
    (rest : List Request) :
    (executeRequests dummy (.write value::rest)).writes = value::(executeRequests dummy rest).writes := rfl
theorem native_prove_runs_admission_first (e : NativeEnvironment) (w : NativeWitness)
    (dummy : DummyMap) (proveData : List Assignment → Except String Proof) (err : Error)
    (rejected : toPublicInputs e w = .error err) : prove e w dummy proveData = .error err := by
  simp [prove,rejected,Bind.bind,Except.bind]
theorem unsupported_dummy_index_rejected (e : CodecEnvironment) (a b c : Nat)
    (index : Nat) (bytes : List Nat) (rest : List (Nat × List Nat))
    (not1 : index ≠ 1) (not2 : index ≠ 2) (not3 : index ≠ 3) :
    deserializeDummies e a b c ((index,bytes)::rest) =
      .error (.codec "balance switch board dummy proof index") := by
  cases index with
  | zero => rfl
  | succ n => cases n with
    | zero => contradiction
    | succ n => cases n with
      | zero => contradiction
      | succ n => cases n with
        | zero => contradiction
        | succ n => rfl

/-- Finite provenance trace: the semantic relation of the chosen branch is
    deliberately left open. Each edge must supply its concrete VD-preserving
    conclusion; selection itself then preserves that VD without lane mixing. -/
inductive KeyTrace : VerifierData → List VerifierData → Prop where
  | nil (key : VerifierData) : KeyTrace key []
  | step {key next : VerifierData} {rest : List VerifierData} :
      next = key → KeyTrace next rest → KeyTrace key (next::rest)
theorem key_trace_preserves_original_key {key : VerifierData} {trace : List VerifierData}
    (h : KeyTrace key trace) : ∀ vd ∈ trace, vd = key := by
  induction h with
  | nil => simp
  | step equal _tail ih =>
    intro vd member
    rcases List.mem_cons.mp member with h | h
    · exact h.trans equal
    · exact (ih vd h).trans equal
theorem selected_output_key_matches_branch_predecessor (e : GateEnvironment) (w : TargetWitness)
    (gates : CircuitGates e w) (previousKey : VerifierData)
    (branchKey : (w.candidate w.flags.choose).vd = previousKey) : w.output.vd = previousKey := by
  rw [selected_output_is_whole_candidate e w gates,branchKey]
theorem normal_transfer_mode_selects_whole_word (row : Mode → Nat) :
    weightedCell (Flags.only .transfer) row = row .transfer := by simp [weightedCell,Flags.only,bit]
theorem normal_key_trace (key : VerifierData) : KeyTrace key [key,key,key] :=
  .step rfl (.step rfl (.step rfl (.nil key)))

end Zkp.Implementation.SwitchBoard
