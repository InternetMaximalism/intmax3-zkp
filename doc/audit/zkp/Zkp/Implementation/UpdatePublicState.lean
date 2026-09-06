import Zkp.Implementation.BalancePublicInputs

/-!
# Public-state history update

Manual translation of all 124 lines of update_public_state.rs. The current
15-field-element PublicState representation is shared with BalancePublicInputs.
Equal states take the native no-op path and constructor substitutes a fixed
63-sibling dummy proof. Different states require the OLD state at its OLD block
index to open under the NEW state's previous-state root. There is no explicit
strict height-increase or timestamp comparison in this helper.

The target always constructs/evaluates the Merkle gadget, even on the no-op
branch. Only its final equality is conditional. Hash/path/gate lowering, range
effects of the 63-bit Merkle index decomposition and authenticated L1 history
remain explicit boundaries; conditional verification is not a proof that a
root comes from the current canonical chain.
-/

namespace Zkp.Implementation.UpdatePublicState

abbrev State := BalancePublicInputs.PublicState
abbrev Root := BalancePublicInputs.Root
abbrev Proof := List Root

def height : Nat := 63
def dummyProof : Proof := List.replicate height BalancePublicInputs.Root.zero

structure Update where
  newState : State
  oldState : State
  proof : Proof
  deriving DecidableEq, Repr

inductive Error where
  | proofRequired
  | rootMismatch (calculated expected : Root)
  deriving DecidableEq, Repr

abbrev RootCall := Proof → State → Nat → Root

def nativeNew (getRoot : RootCall) (newState oldState : State) (proof : Option Proof) :
    Except Error Update :=
  if newState = oldState then .ok ⟨newState, oldState, dummyProof⟩ else
  match proof with
  | none => .error .proofRequired
  | some path =>
    let calculated := getRoot path oldState oldState.blockNumber
    if calculated ≠ newState.previousRoot then
      .error (.rootMismatch calculated newState.previousRoot)
    else .ok ⟨newState, oldState, path⟩

def nativeVerify (getRoot : RootCall) (u : Update) : Except Error Unit :=
  if u.newState = u.oldState then .ok () else
  let calculated := getRoot u.proof u.oldState u.oldState.blockNumber
  if calculated ≠ u.newState.previousRoot then
    .error (.rootMismatch calculated u.newState.previousRoot)
  else .ok ()

def expectedOldRoot (getRoot : RootCall) (u : Update) : Root :=
  getRoot u.proof u.oldState u.oldState.blockNumber

def ValidUpdate (getRoot : RootCall) (u : Update) : Prop :=
  u.newState = u.oldState ∨ expectedOldRoot getRoot u = u.newState.previousRoot

theorem native_equal_constructor_uses_dummy (root : RootCall) (s : State) (proof : Option Proof) :
    nativeNew root s s proof = .ok ⟨s, s, dummyProof⟩ := by simp [nativeNew]

theorem dummy_has_63_siblings : dummyProof.length = 63 := by simp [dummyProof, height]

theorem native_equal_verify_needs_no_root (root : RootCall) (s : State) (proof : Proof) :
    nativeVerify root ⟨s, s, proof⟩ = .ok () := by simp [nativeVerify]

theorem changed_state_needs_proof (root : RootCall) (n o : State) (different : n ≠ o) :
    nativeNew root n o none = .error .proofRequired := by simp [nativeNew, different]

theorem native_changed_success (root : RootCall) (n o : State) (proof : Proof)
    (different : n ≠ o) (opening : root proof o o.blockNumber = n.previousRoot) :
    nativeNew root n o (some proof) = .ok ⟨n, o, proof⟩ := by
  simp [nativeNew, different, opening]

theorem native_verify_iff_local_history (root : RootCall) (u : Update) :
    nativeVerify root u = .ok () ↔ ValidUpdate root u := by
  by_cases equal : u.newState = u.oldState
  · simp [nativeVerify, ValidUpdate, equal]
  · by_cases _opening : expectedOldRoot root u = u.newState.previousRoot
    · simp [nativeVerify, ValidUpdate, expectedOldRoot, equal] at *
    · simp [nativeVerify, ValidUpdate, expectedOldRoot, equal] at *

theorem native_verify_changed_binds_old_state_and_index (root : RootCall) (u : Update)
    (different : u.newState ≠ u.oldState) (verified : nativeVerify root u = .ok ()) :
    root u.proof u.oldState u.oldState.blockNumber = u.newState.previousRoot := by
  have valid := (native_verify_iff_local_history root u).mp verified
  exact valid.resolve_left different

theorem native_new_success_preserves_requested_states (root : RootCall) (n o : State)
    (proof : Option Proof) (u : Update) (success : nativeNew root n o proof = .ok u) :
    u.newState = n ∧ u.oldState = o := by
  by_cases equal : n = o
  · have h : (⟨n, o, dummyProof⟩ : Update) = u := by simpa [nativeNew, equal] using success
    rw [← h]
    exact ⟨rfl, rfl⟩
  · cases proof with
    | none => simp [nativeNew, equal] at success
    | some path =>
      by_cases opening : root path o o.blockNumber = n.previousRoot
      · have h : (⟨n, o, path⟩ : Update) = u := by
          simpa [nativeNew, equal, opening] using success
        rw [← h]
        exact ⟨rfl, rfl⟩
      · simp [nativeNew, equal, opening] at success

theorem native_new_success_is_locally_verified (root : RootCall) (n o : State)
    (proof : Option Proof) (u : Update) (success : nativeNew root n o proof = .ok u) :
    nativeVerify root u = .ok () := by
  by_cases equal : n = o
  · have h : (⟨n, o, dummyProof⟩ : Update) = u := by simpa [nativeNew, equal] using success
    rw [← h]
    simp [nativeVerify, equal]
  · cases proof with
    | none => simp [nativeNew, equal] at success
    | some path =>
      by_cases opening : root path o o.blockNumber = n.previousRoot
      · have h : (⟨n, o, path⟩ : Update) = u := by
          simpa [nativeNew, equal, opening] using success
        rw [← h]
        simp [nativeVerify, equal, opening]
      · simp [nativeNew, equal, opening] at success

/-- PublicStateTarget::is_equal compares all five source fields, with the
timestamp comparison covering both u32 words. -/
def statesEqual (n o : State) : Bool :=
  decide (n.blockNumber = o.blockNumber) &&
  decide (n.timestampHi = o.timestampHi ∧ n.timestampLo = o.timestampLo) &&
  decide (n.accountRoot = o.accountRoot) && decide (n.depositRoot = o.depositRoot) &&
  decide (n.previousRoot = o.previousRoot)

theorem equality_flag_iff_all_fields (n o : State) : statesEqual n o = true ↔ n = o := by
  cases n
  cases o
  simp [statesEqual, BalancePublicInputs.PublicState.mk.injEq, and_assoc]

theorem equality_flag_false_iff_different (n o : State) :
    statesEqual n o = false ↔ n ≠ o := by
  rw [← Bool.not_eq_true, equality_flag_iff_all_fields]

structure Witness where
  statesEqualWire : Bool
  shouldVerifyWire : Bool
  computedRoot : Root

structure CircuitGates (getRoot : RootCall) (u : Update) (w : Witness) : Prop where
  pathHeight : u.proof.length = height
  equalityGate : w.statesEqualWire = statesEqual u.newState u.oldState
  notGate : w.shouldVerifyWire = !w.statesEqualWire
  merkleEvaluation : w.computedRoot = expectedOldRoot getRoot u
  conditionalRoot : w.shouldVerifyWire = true → w.computedRoot = u.newState.previousRoot

theorem target_always_evaluates_old_merkle_path (h : CircuitGates root u w) :
    w.computedRoot = root u.proof u.oldState u.oldState.blockNumber := h.merkleEvaluation

theorem target_changed_enables_verification (h : CircuitGates root u w)
    (different : u.newState ≠ u.oldState) : w.shouldVerifyWire = true := by
  rw [h.notGate, h.equalityGate, (equality_flag_false_iff_different _ _).mpr different]
  rfl

theorem target_changed_binds_old_opening (h : CircuitGates root u w)
    (different : u.newState ≠ u.oldState) :
    root u.proof u.oldState u.oldState.blockNumber = u.newState.previousRoot := by
  exact h.merkleEvaluation.symm.trans (h.conditionalRoot (target_changed_enables_verification h different))

theorem target_equal_disables_only_final_comparison (h : CircuitGates root u w)
    (equal : u.newState = u.oldState) : w.shouldVerifyWire = false := by
  rw [h.notGate, h.equalityGate, (equality_flag_iff_all_fields _ _).mpr equal]
  rfl

theorem target_implies_native_local_verification (h : CircuitGates root u w) :
    nativeVerify root u = .ok () := by
  apply (native_verify_iff_local_history root u).mpr
  by_cases equal : u.newState = u.oldState
  · exact Or.inl equal
  · exact Or.inr (target_changed_binds_old_opening h equal)

theorem target_witness_of_native_local_verification (root : RootCall) (u : Update)
    (path : u.proof.length = height) (verified : nativeVerify root u = .ok ()) :
    CircuitGates root u ⟨statesEqual u.newState u.oldState,
      !statesEqual u.newState u.oldState, expectedOldRoot root u⟩ := by
  refine ⟨path, rfl, rfl, rfl, ?_⟩
  intro enabled
  have different : u.newState ≠ u.oldState := by
    intro equal
    rw [(equality_flag_iff_all_fields _ _).mpr equal] at enabled
    cases enabled
  exact native_verify_changed_binds_old_state_and_index root u different verified

inductive Allocation where
  | newState (checked : Bool)
  | oldState (checked : Bool)
  | merklePath (height : Nat)
  deriving DecidableEq, Repr

def allocation : List Allocation := [.newState false, .oldState false, .merklePath height]

theorem constructor_uses_unchecked_state_allocations : allocation =
    [.newState false, .oldState false, .merklePath 63] := rfl

inductive Write where
  | newState (value : State)
  | oldState (value : State)
  | proof (value : Proof)
  deriving DecidableEq, Repr

def witnessWrites (u : Update) : List Write :=
  [.newState u.newState, .oldState u.oldState, .proof u.proof]

theorem witness_write_order (u : Update) : witnessWrites u =
    [.newState u.newState, .oldState u.oldState, .proof u.proof] := rfl

end Zkp.Implementation.UpdatePublicState
