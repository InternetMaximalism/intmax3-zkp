import Zkp.Implementation.PrivateState
import Zkp.Implementation.U256Arithmetic

/-!
# Incoming asset / nullifier update, with explicit dependency calls

Source: src/circuits/balance/common/update_private_state.rs, production 1–194.
This translates the native early returns, checked-allocation flag, old-leaf
opening, final-carry-zero addition, replacement-root wiring, cloned fields and
witness order. Source-to-Lean compiler refinement is not proved.

Nullifier insertion, asset hash/path calculations and native U256 addition are
explicit call boundaries. Their outputs are not assertions of authenticated
ownership or freshness. The target sum theorem uses the existing PER-LIMB
AddGates relation and derives the entire integer sum; it does not assume a
whole-funds invariant. Result range checks and native/target call agreement
are visible prerequisites where needed. Native addition overflow is a panic,
not a recoverable MerkleProofError. Dependency panics and witness-write errors
are not hidden by a liveness claim: the native equations concern normal returns
of the modeled dependency calls.
-/

namespace Zkp.Implementation.UpdatePrivateState


structure Amount where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  w4 : Nat
  w5 : Nat
  w6 : Nat
  w7 : Nat
  deriving DecidableEq, Repr

def amountWords (a : Amount) : List Nat :=
  [a.w0, a.w1, a.w2, a.w3, a.w4, a.w5, a.w6, a.w7]

def value (a : Amount) : Nat := U256Arithmetic.valueBE (amountWords a)
def Checked (a : Amount) : Prop := U256Arithmetic.Checked U256Arithmetic.wordBase (amountWords a)

def fromSmall (n : Nat) : Amount := ⟨0, 0, 0, 0, 0, 0, 0, n⟩

theorem amount_has_eight_words (a : Amount) : (amountWords a).length = 8 := rfl

theorem small_amount_value (n : Nat) : value (fromSmall n) = n := by
  simp [value, fromSmall, amountWords, U256Arithmetic.valueBE, U256Arithmetic.valueLE]

/-- Source `nullifier: Bytes32` shares the 8-limb width of `U256`; the alias
records that it is an opaque 256-bit word, not a token amount. -/
abbrev Bytes32 := Amount

structure Inputs (NullifierProof : Type) where
  tokenIndex : Nat
  amount : Amount
  nullifier : Bytes32
  previous : PrivateState.State
  nullifierProof : NullifierProof
  previousBalance : Amount
  assetSiblings : List PrivateState.Hash4

def NativeRepresentable (i : Inputs N) : Prop :=
  i.tokenIndex < 2 ^ 32 ∧ Checked i.amount ∧ Checked i.nullifier ∧
  PrivateState.NativeRepresentable i.previous ∧ Checked i.previousBalance

structure Output (NullifierProof : Type) where
  inputs : Inputs NullifierProof
  next : PrivateState.State

structure Dependencies (NullifierProof : Type) where
  hash : List Nat → PrivateState.Hash4
  nullifierRoot : NullifierProof → PrivateState.Hash4 → Amount → Except String PrivateState.Hash4
  assetRoot : List PrivateState.Hash4 → Amount → Nat → PrivateState.Hash4
  nativeAdd : Amount → Amount → Option Amount

def updatedState (hash : List Nat → PrivateState.Hash4) (previous : PrivateState.State)
    (assetRoot nullifierRoot : PrivateState.Hash4) : PrivateState.State :=
  { previous with
    assetRoot := assetRoot
    nullifierRoot := nullifierRoot
    prevCommitment := PrivateState.commitment hash previous }

inductive MerkleError where
  | nullifier (detail : String)
  | asset (calculated expected : PrivateState.Hash4)
  deriving DecidableEq, Repr

inductive NativeResult (N : Type) where
  | error (error : MerkleError)
  | additionPanic
  | success (output : Output N)

def nativeNew (d : Dependencies N) (i : Inputs N) : NativeResult N :=
  let previousCommitment := PrivateState.commitment d.hash i.previous
  match d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier with
  | .error detail => .error (.nullifier detail)
  | .ok nullifierRoot =>
    let calculated := d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex
    if calculated ≠ i.previous.assetRoot then
      .error (.asset calculated i.previous.assetRoot)
    else
      match d.nativeAdd i.previousBalance i.amount with
      | none => .additionPanic
      | some newLeaf =>
        .success ⟨i, { i.previous with
          assetRoot := d.assetRoot i.assetSiblings newLeaf i.tokenIndex,
          nullifierRoot := nullifierRoot, prevCommitment := previousCommitment }⟩

theorem native_nullifier_error_first (d : Dependencies N) (i : Inputs N) (e : String)
    (h : d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier = .error e) :
    nativeNew d i = .error (.nullifier e) := by simp [nativeNew, h]

theorem native_asset_error_before_add (d : Dependencies N) (i : Inputs N) (nr : PrivateState.Hash4)
    (hn : d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier = .ok nr)
    (ha : d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex ≠ i.previous.assetRoot) :
    nativeNew d i = .error (.asset
      (d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex) i.previous.assetRoot) := by
  simp [nativeNew, hn, ha]

theorem native_add_overflow_is_panic (d : Dependencies N) (i : Inputs N) (nr : PrivateState.Hash4)
    (hn : d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier = .ok nr)
    (ha : d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex = i.previous.assetRoot)
    (hs : d.nativeAdd i.previousBalance i.amount = none) :
    nativeNew d i = .additionPanic := by simp [nativeNew, hn, ha, hs]

theorem native_success_of_actual_returns (d : Dependencies N) (i : Inputs N)
    (nr : PrivateState.Hash4) (leaf : Amount)
    (hn : d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier = .ok nr)
    (ha : d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex = i.previous.assetRoot)
    (hs : d.nativeAdd i.previousBalance i.amount = some leaf) :
    nativeNew d i = .success ⟨i, updatedState d.hash i.previous
      (d.assetRoot i.assetSiblings leaf i.tokenIndex) nr⟩ := by
  simp [nativeNew, hn, ha, hs, updatedState, PrivateState.commitment]

/-- Extract the actual same-proof, same-index dependency returns. -/
theorem native_success_extracts (d : Dependencies N) (i : Inputs N) (o : Output N)
    (h : nativeNew d i = .success o) :
    ∃ nr leaf,
      d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier = .ok nr ∧
      d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex = i.previous.assetRoot ∧
      d.nativeAdd i.previousBalance i.amount = some leaf ∧
      o = ⟨i, updatedState d.hash i.previous
        (d.assetRoot i.assetSiblings leaf i.tokenIndex) nr⟩ := by
  cases hn : d.nullifierRoot i.nullifierProof i.previous.nullifierRoot i.nullifier with
  | error e => simp [nativeNew, hn] at h
  | ok nr =>
    by_cases ha : d.assetRoot i.assetSiblings i.previousBalance i.tokenIndex = i.previous.assetRoot
    · cases hs : d.nativeAdd i.previousBalance i.amount with
      | none => simp [nativeNew, hn, ha, hs] at h
      | some leaf =>
        have ho : (⟨i, updatedState d.hash i.previous
            (d.assetRoot i.assetSiblings leaf i.tokenIndex) nr⟩ : Output N) = o := by
          simpa [nativeNew, hn, ha, hs, updatedState] using h
        exact ⟨nr, leaf, rfl, ha, rfl, ho.symm⟩
    · simp [nativeNew, hn, ha] at h

structure CircuitWitness where
  newLeaf : Amount
  newNullifierRoot : PrivateState.Hash4
  next : PrivateState.State

/-- This is the local body only. The four imported gate families are named
explicitly, rather than asserting nullifier freshness or total fund safety. -/
structure CircuitGates (hash : List Nat → PrivateState.Hash4)
    (assetRoot : List PrivateState.Hash4 → Amount → Nat → PrivateState.Hash4)
    (nullifierCall : N → PrivateState.Hash4 → Amount → PrivateState.Hash4 → Prop)
    (isChecked : Bool) (i : Inputs N) (w : CircuitWitness) : Prop where
  localRanges : isChecked = true →
    i.tokenIndex < 2 ^ 32 ∧ Checked i.amount ∧ Checked i.nullifier ∧ Checked i.previousBalance
  fixedAssetPath : i.assetSiblings.length = 32
  nullifierInvocation : nullifierCall i.nullifierProof i.previous.nullifierRoot
    i.nullifier w.newNullifierRoot
  oldAssetOpening : assetRoot i.assetSiblings i.previousBalance i.tokenIndex = i.previous.assetRoot
  addition : U256Arithmetic.AddGates (amountWords i.previousBalance) (amountWords i.amount) (amountWords w.newLeaf)
  outputWiring : w.next = updatedState hash i.previous
    (assetRoot i.assetSiblings w.newLeaf i.tokenIndex) w.newNullifierRoot

variable {N : Type} {hash : List Nat → PrivateState.Hash4}
  {assetRoot : List PrivateState.Hash4 → Amount → Nat → PrivateState.Hash4}
  {nullifierCall : N → PrivateState.Hash4 → Amount → PrivateState.Hash4 → Prop}
  {checked : Bool} {i : Inputs N} {w a b : CircuitWitness}

theorem circuit_credits_exact_amount
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    value w.newLeaf = value i.previousBalance + value i.amount :=
  (U256Arithmetic.target_add_is_exact h.addition).symm

theorem circuit_credit_does_not_decrease_balance
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    value i.previousBalance ≤ value w.newLeaf := by
  have := circuit_credits_exact_amount h
  omega

theorem circuit_sum_below_u256_when_result_checked
    (h : CircuitGates hash assetRoot nullifierCall checked i w)
    (hr : Checked w.newLeaf) :
    value i.previousBalance + value i.amount < 2 ^ 256 := by
  have hr' : U256Arithmetic.Checked U256Arithmetic.wordBase (amountWords w.newLeaf).reverse := by
    intro x hx
    exact hr x (List.mem_reverse.mp hx)
  have bound := U256Arithmetic.target_add_cannot_wrap h.addition hr'
  simpa [value, U256Arithmetic.u256_width_is_exact] using bound

theorem circuit_carries_link_to_existing_arithmetic
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    U256Arithmetic.AddTrace U256Arithmetic.wordBase (amountWords i.previousBalance).reverse
      (amountWords i.amount).reverse (amountWords w.newLeaf).reverse 0 0 := h.addition.2

theorem circuit_keeps_sent_root_nonce_salt
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    w.next.sentTxRoot = i.previous.sentTxRoot ∧
    w.next.nonce = i.previous.nonce ∧ w.next.salt = i.previous.salt := by
  rw [h.outputWiring]
  exact ⟨rfl, rfl, rfl⟩

theorem circuit_links_full_previous_commitment
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    w.next.prevCommitment = hash (PrivateState.words i.previous) := by
  rw [h.outputWiring]
  rfl

theorem circuit_replaces_same_token_same_path
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    assetRoot i.assetSiblings i.previousBalance i.tokenIndex = i.previous.assetRoot ∧
    w.next.assetRoot = assetRoot i.assetSiblings w.newLeaf i.tokenIndex := by
  exact ⟨h.oldAssetOpening, by rw [h.outputWiring]; rfl⟩

/-- The gadget is invoked with the incoming nullifier and the output root; this is
the invocation relation only, not insertion soundness or freshness. -/
theorem circuit_invokes_nullifier_gadget_with_incoming_nullifier
    (h : CircuitGates hash assetRoot nullifierCall checked i w) :
    nullifierCall i.nullifierProof i.previous.nullifierRoot i.nullifier w.next.nullifierRoot := by
  rw [h.outputWiring]
  exact h.nullifierInvocation

theorem enabled_checks_bound_input_words
    (h : CircuitGates hash assetRoot nullifierCall true i w) :
    i.tokenIndex < 2 ^ 32 ∧ Checked i.amount ∧ Checked i.nullifier ∧ Checked i.previousBalance :=
  h.localRanges rfl

/-- Marker only: an unchecked allocation contributes no range obligation, so this
is true by construction and must not be read as a range guarantee. -/
theorem false_flag_adds_no_direct_range_obligation :
    (false = true → tokenIndex < 2 ^ 32 ∧ Checked amount ∧ Checked nullifier ∧ Checked balance) := by
  intro h
  cases h

/-- Vacuity guard: the local gate family is inhabited by the native success path.
The nullifier gadget is instantiated as the native callee's own success relation
and the native/target U256 agreement is an explicit premise; this exhibits
satisfiability only, not soundness of either callee. -/
theorem target_witness_of_native_success (d : Dependencies N) (i : Inputs N) (o : Output N)
    (checked : Bool) (h : nativeNew d i = .success o)
    (path : i.assetSiblings.length = 32)
    (ranges : checked = true →
      i.tokenIndex < 2 ^ 32 ∧ Checked i.amount ∧ Checked i.nullifier ∧ Checked i.previousBalance)
    (add : ∀ leaf, d.nativeAdd i.previousBalance i.amount = some leaf →
      U256Arithmetic.AddGates (amountWords i.previousBalance) (amountWords i.amount)
        (amountWords leaf)) :
    ∃ w : CircuitWitness,
      CircuitGates d.hash d.assetRoot
        (fun p r n out => d.nullifierRoot p r n = .ok out) checked i w ∧ w.next = o.next := by
  obtain ⟨nr, leaf, hn, ha, hs, ho⟩ := native_success_extracts d i o h
  refine ⟨⟨leaf, nr, o.next⟩, ⟨ranges, path, hn, ha, add leaf hs, ?_⟩, rfl⟩
  rw [ho]

theorem same_previous_and_amount_give_same_value
    (ha : CircuitGates hash assetRoot nullifierCall checked i a)
    (hb : CircuitGates hash assetRoot nullifierCall checked i b) : value a.newLeaf = value b.newLeaf := by
  rw [circuit_credits_exact_amount ha, circuit_credits_exact_amount hb]

theorem native_keeps_sent_root_nonce_salt (d : Dependencies N) (i : Inputs N) (o : Output N)
    (h : nativeNew d i = .success o) :
    o.next.sentTxRoot = i.previous.sentTxRoot ∧
    o.next.nonce = i.previous.nonce ∧ o.next.salt = i.previous.salt := by
  obtain ⟨nr, leaf, _, _, _, rfl⟩ := native_success_extracts d i o h
  exact ⟨rfl, rfl, rfl⟩

theorem native_copies_exact_inputs (d : Dependencies N) (i : Inputs N) (o : Output N)
    (h : nativeNew d i = .success o) : o.inputs = i := by
  obtain ⟨nr, leaf, _, _, _, rfl⟩ := native_success_extracts d i o h
  rfl

inductive Allocation where
  | virtualTokenIndex | rangeToken32
  | amount (checked : Bool) | nullifier (checked : Bool) | previousState
  | nullifierProof (checked : Bool) | previousBalance (checked : Bool)
  | assetPath (height : Nat)
  deriving DecidableEq, Repr

def allocate (checked : Bool) : List Allocation :=
  [.virtualTokenIndex] ++ (if checked then [.rangeToken32] else []) ++
  [.amount checked, .nullifier checked, .previousState, .nullifierProof checked,
   .previousBalance checked, .assetPath 32]

theorem checked_allocation_program : allocate true =
    [.virtualTokenIndex, .rangeToken32, .amount true, .nullifier true,
     .previousState, .nullifierProof true, .previousBalance true, .assetPath 32] := rfl

theorem unchecked_allocation_program : allocate false =
    [.virtualTokenIndex, .amount false, .nullifier false,
     .previousState, .nullifierProof false, .previousBalance false, .assetPath 32] := rfl

inductive Write (N : Type) where
  | tokenIndex (index : Nat)
  | amount (value : Amount)
  | nullifier (value : Amount)
  | previousState (value : PrivateState.State)
  | nullifierProof (value : N)
  | previousBalance (value : Amount)
  | assetPath (value : List PrivateState.Hash4)
  | nextState (value : PrivateState.State)

def witnessWrites (o : Output N) : List (Write N) :=
  [.tokenIndex o.inputs.tokenIndex, .amount o.inputs.amount, .nullifier o.inputs.nullifier,
   .previousState o.inputs.previous, .nullifierProof o.inputs.nullifierProof,
   .previousBalance o.inputs.previousBalance, .assetPath o.inputs.assetSiblings, .nextState o.next]

theorem witness_write_count (o : Output N) : (witnessWrites o).length = 8 := rfl

theorem witness_also_assigns_derived_state (o : Output N) :
    (witnessWrites o)[7]? = some (.nextState o.next) := rfl

theorem normal_credit_7_plus_2 :
    U256Arithmetic.AddGates (amountWords (fromSmall 7)) (amountWords (fromSmall 2))
      (amountWords (fromSmall 9)) := U256Arithmetic.normal_u256_add

theorem normal_credit_value_9 : value (fromSmall 9) = 9 := small_amount_value 9

end Zkp.Implementation.UpdatePrivateState
