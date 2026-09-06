import Zkp.Implementation.WithdrawalClaimCircuit
import Zkp.Implementation.ClosePublicInputs
import Zkp.Implementation.CloseEncodingBridge

/-!
# Native withdrawal claim admission and50-word codec

Handwritten source model of withdrawal_claim_pis.rs (584 lines), not compiler
refinement. PublicInputs shares the claim circuit's record so the layout bridge
is a proved identity, not an assumed equal encoding. NativeWidths captures Rust
u32/u64/u8 value domains. Native decoder amount limbs are raw u64 shift/OR, NOT
independently u32-range-checked; canonical roundtrip needs NativeWidths and
nonzero channel. Error categories/order and bounds panics are separate.

The strong native helper is NOT automatically invoked by circuit.fill_witness.
Both public wrappers execute every structural/H1/recipient/nullifier/slot check;
only the external E3 call is conditional. The in-circuit route skips E3 and
requires the actual circuit decryption proof downstream. No verification is
claimed from an empty/stub external proof.

BalanceState.validate, state H1 (computed from the complete represented state),
Regev key/ciphertext digest and external E3 verification remain explicit
dependency callbacks. No key-digest-in-state check, member.memberSlot equality,
or amount/fund cap is invented: the native body does not contain them.
Source unsigned comments saying SIS/SPHINCS/full1024 scalar H1 are not current
implementation guarantees. Native shape constraints belong to validate/types;
fallback bounds panic preserves the source behavior if a dependency is not
given its real validation semantics. Tests were read but not executed.
-/
namespace Zkp.Implementation.WithdrawalClaimPublicInputs
open Zkp.Implementation.WithdrawalClaimCircuit (Words2 Words8 Address Ten)
abbrev PublicInputs := Zkp.Implementation.WithdrawalClaimCircuit.PublicInputs

def publicInputLength : Nat := 50
def limbBase : Nat := 2^32
def scalarLimit : Nat := 2^64

def toU64Vec (p : PublicInputs) : List Nat := p.words
def splitU64 (n : Nat) : Words2 := CloseCircuit.Words2.fromNat n
def joinValue := ClosePublicInputs.joinValue
def normalizeAmount (w : Words2) : Words2 :=
  splitU64 (joinValue w.hi w.lo)

inductive Error where
  | invalidLength (actual : Nat)
  | invalidField (field : String)
  | closeIntentMismatch
  | closeWithdrawalMismatch
  | recipientMismatch
  | nullifierMismatch
  | finalBalanceStateMismatch (detail : String)
  | memberSlotMismatch (detail : String)
  | invalidClaimProof (detail : String)
  deriving DecidableEq, Repr

inductive Fault where
  | returned (error : Error)
  | boundsPanic
  deriving DecidableEq, Repr
abbrev Result (α : Type) := Except Fault α

def fail {α : Type} (e : Error) : Result α := .error (.returned e)
def checkWords (field : String) (xs : List Nat) : Result Unit :=
  if xs.all (fun x => decide (x < limbBase)) then .ok () else fail (.invalidField field)

def decodeFields (p : PublicInputs) : Result PublicInputs := do
  let _ ← checkWords "close_intent_digest" p.closeId.words
  if p.channelId ≥ limbBase ∨ p.channelId = 0 then
    fail (.invalidField "channel_id")
  else pure ()
  let _ ← checkWords "final_balance_state_h1" p.h1.words
  let _ ← checkWords "member_pk_g" p.memberPk.words
  let _ ← checkWords "recipient" p.recipient.words
  let _ ← checkWords "user_amount_digest" p.ciphertextDigest.words
  let _ ← checkWords "withdrawal_nullifier" p.nullifier.words
  if p.tokenSlot ≥ 256 then fail (.invalidField "token_slot") else pure ()
  if p.tokenIndex ≥ limbBase then fail (.invalidField "token_index") else pure ()
  return {p with amount := normalizeAmount p.amount}

def fromU64Slice (xs : List Nat) : Result PublicInputs :=
  if xs.length != publicInputLength then fail (.invalidLength xs.length)
  else decodeFields (WithdrawalClaimCircuit.readPublicFields xs)

def joinU64 : List Nat → Result Nat
  | hi::lo::_ => .ok (joinValue hi lo)
  | _ => .error .boundsPanic

def NativeWidths (p : PublicInputs) : Prop :=
  WithdrawalClaimCircuit.PublicInputs.AllocationChecks p ∧ p.tokenSlot < 256

structure Ciphertext where
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr
structure Key where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr

structure Intent where
  channelId : Nat
  h1 : Words8
  withdrawalDigest : Words8
  stateDigest : Words8
  freezeNonce : Words2
  opaqueRest : List Nat

structure CloseWithdrawal where
  channelId : Nat
  stateDigest : Words8
  h1 : Words8
  stateRoot : Words8
  burnHash : Words8
  amount : Words8
  proofBytes : List Nat

structure Member where
  pk : Words8
  memberSlot : Nat
  recipient : Address

structure Claim where
  closeId : Words8
  memberPk : Words8
  recipient : Address
  ciphertext : Ciphertext
  nullifier : Words8
  tokenSlot : Nat
  proofBytes : List Nat

structure State where
  channelId : Nat
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : Ten Nat
  ciphertexts : List (Ten Ciphertext)
  keyDigests : Fin 1024 → Words8
  recipients : Fin 1024 → Address
  pendingAdds : List (Ten Nat)
  settledChain : Words8
  accumulatorRoot : Words8
  stateVersion : Words2

structure Witness where
  closeIntent : Intent
  closeTx : CloseWithdrawal
  member : Member
  claim : Claim
  state : State
  memberIndex : Nat
  key : Key
  amount : Nat

def closeIntentPreimage (i : Intent) : List Nat :=
  [0x494d4353,i.channelId] ++ i.stateDigest.words ++ i.freezeNonce.words
def closeWithdrawalPreimage (tx : CloseWithdrawal) : List Nat :=
  [0x494d434c,tx.channelId] ++ tx.stateDigest.words ++ tx.h1.words ++
  tx.stateRoot.words ++ tx.burnHash.words ++ tx.amount.words

structure Environment where
  hashWords : List Nat → Words8
  keyDigest : Key → Words8
  ciphertextDigest : Ciphertext → Words8
  validateState : State → Except String Unit
  stateH1 : State → Words8
  verifyExternal : Nat → Key → Ciphertext → Nat → List Nat → Except String Unit

def expectedCloseId (e : Environment) (w : Witness) : Words8 :=
  e.hashWords (closeIntentPreimage w.closeIntent)
def expectedNullifier (e : Environment) (w : Witness) : Words8 :=
  e.hashWords (WithdrawalClaimCircuit.nullifierPreimage (expectedCloseId e w)
    (e.keyDigest w.key) w.claim.tokenSlot)

def selectedCiphertext (w : Witness) : Result Ciphertext :=
  match w.state.ciphertexts[w.memberIndex]? with
  | none => .error .boundsPanic
  | some row =>
    if h : w.claim.tokenSlot < 10 then .ok (row ⟨w.claim.tokenSlot,h⟩)
    else .error .boundsPanic

def selectedRecipient (w : Witness) : Result Address :=
  if h : w.memberIndex < 1024 then .ok (w.state.recipients ⟨w.memberIndex,h⟩)
  else .error .boundsPanic

def selectedTokenIndex (w : Witness) : Result Nat :=
  if h : w.claim.tokenSlot < 10 then .ok (w.state.registry ⟨w.claim.tokenSlot,h⟩)
  else .error .boundsPanic

def project (e : Environment) (w : Witness) (tokenIndex : Nat) : PublicInputs := {
  closeId := expectedCloseId e w
  channelId := w.closeIntent.channelId
  h1 := w.closeIntent.h1
  memberPk := w.member.pk
  recipient := w.member.recipient
  ciphertextDigest := e.ciphertextDigest w.claim.ciphertext
  nullifier := w.claim.nullifier
  amount := splitU64 w.amount
  tokenSlot := w.claim.tokenSlot
  tokenIndex := tokenIndex }

def structuralChecks (e : Environment) (w : Witness) : Result Unit :=
  if w.claim.closeId != expectedCloseId e w then fail .closeIntentMismatch else
  if e.hashWords (closeWithdrawalPreimage w.closeTx) != w.closeIntent.withdrawalDigest ∨
      w.closeTx.h1 != w.closeIntent.h1 ∨ w.closeTx.channelId != w.closeIntent.channelId then
    fail .closeWithdrawalMismatch
  else
  if w.member.pk != w.claim.memberPk ∨ w.member.recipient != w.claim.recipient then
    fail .recipientMismatch
  else
  if expectedNullifier e w != w.claim.nullifier then fail .nullifierMismatch else
  if w.claim.tokenSlot ≥ w.state.tokenCount then
    fail (.memberSlotMismatch "token_slot out of range")
  else
  match e.validateState w.state with
  | .error details => fail (.finalBalanceStateMismatch details)
  | .ok () =>
    if e.stateH1 w.state != w.closeIntent.h1 then
      fail (.finalBalanceStateMismatch "h1 mismatch")
    else
    if w.state.channelId != w.closeIntent.channelId then
      fail (.finalBalanceStateMismatch "channel_id mismatch")
    else
    if w.memberIndex ≥ 1024 then fail (.memberSlotMismatch "member_index out of range") else
    if w.memberIndex ≥ w.state.memberCount + w.state.delegateCount then
      fail (.memberSlotMismatch "padding slot")
    else
    match selectedCiphertext w with
    | .error err => .error err
    | .ok ciphertext =>
      if w.claim.ciphertext != ciphertext then
        fail (.memberSlotMismatch "ciphertext mismatch")
      else
      match selectedRecipient w with
      | .error err => .error err
      | .ok recipient =>
        if w.member.recipient != recipient then fail .recipientMismatch else .ok ()

def toPublicInputsInner (e : Environment) (w : Witness) (level : Nat)
    (verifyExternalProof : Bool) : Result PublicInputs := do
  let _ ← structuralChecks e w
  if verifyExternalProof then
    match e.verifyExternal level w.key w.claim.ciphertext w.amount w.claim.proofBytes with
    | .error details => fail (.invalidClaimProof details)
    | .ok () => pure ()
  else pure ()
  let token ← selectedTokenIndex w
  return project e w token

def toPublicInputs (e : Environment) (w : Witness) (level : Nat) : Result PublicInputs :=
  toPublicInputsInner e w level true

def toPublicInputsForInCircuitDecryption (e : Environment) (w : Witness) (level : Nat) :
    Result PublicInputs := toPublicInputsInner e w level false

theorem public_width_and_circuit_encoding (p : PublicInputs) :
    (toU64Vec p).length = 50 ∧ toU64Vec p = p.words :=
  ⟨WithdrawalClaimCircuit.public_input_width_is_50 p,rfl⟩

theorem encoded_native_fields_read_exactly (p : PublicInputs) :
    WithdrawalClaimCircuit.readPublicFields (toU64Vec p) = p :=
  WithdrawalClaimCircuit.read_public_encoding p

theorem normalized_canonical_amount (w : Words2) (hi : w.hi < limbBase) (lo : w.lo < limbBase) :
    normalizeAmount w = w := by
  have h := ClosePublicInputs.normalized_canonical_scalar
    (CloseEncodingBridge.toNativeWords2 w) ⟨hi,lo⟩
  have mapped := congrArg CloseEncodingBridge.toCircuitWords2 h
  exact mapped

theorem word_check_exact (field : String) (xs : List Nat) :
    checkWords field xs = .ok () ↔ ∀ x ∈ xs, x < limbBase := by
  simp [checkWords,fail,List.all_eq_true]

theorem decode_fields_round_trip (p : PublicInputs) (widths : NativeWidths p) (nonzero : p.channelId ≠ 0) :
    decodeFields p = .ok p := by
  obtain ⟨all,slot⟩ := widths
  have channel : p.channelId < limbBase := all _ (by simp [WithdrawalClaimCircuit.PublicInputs.words])
  have index : p.tokenIndex < limbBase := all _ (by simp [WithdrawalClaimCircuit.PublicInputs.words])
  have hi : p.amount.hi < limbBase := all _ (by simp [WithdrawalClaimCircuit.PublicInputs.words,CloseCircuit.Words2.words])
  have lo : p.amount.lo < limbBase := all _ (by simp [WithdrawalClaimCircuit.PublicInputs.words,CloseCircuit.Words2.words])
  have closeCheck : checkWords "close_intent_digest" p.closeId.words = .ok () :=
    (word_check_exact _ _).mpr (fun x hx => all x (by simp [WithdrawalClaimCircuit.PublicInputs.words,hx]))
  have h1Check : checkWords "final_balance_state_h1" p.h1.words = .ok () :=
    (word_check_exact _ _).mpr (fun x hx => all x (by simp [WithdrawalClaimCircuit.PublicInputs.words,hx]))
  have memberCheck : checkWords "member_pk_g" p.memberPk.words = .ok () :=
    (word_check_exact _ _).mpr (fun x hx => all x (by simp [WithdrawalClaimCircuit.PublicInputs.words,hx]))
  have recipientCheck : checkWords "recipient" p.recipient.words = .ok () :=
    (word_check_exact _ _).mpr (fun x hx => all x (by simp [WithdrawalClaimCircuit.PublicInputs.words,hx]))
  have ctCheck : checkWords "user_amount_digest" p.ciphertextDigest.words = .ok () :=
    (word_check_exact _ _).mpr (fun x hx => all x (by simp [WithdrawalClaimCircuit.PublicInputs.words,hx]))
  have nullifierCheck : checkWords "withdrawal_nullifier" p.nullifier.words = .ok () :=
    (word_check_exact _ _).mpr (fun x hx => all x (by simp [WithdrawalClaimCircuit.PublicInputs.words,hx]))
  simp [decodeFields,closeCheck,h1Check,memberCheck,recipientCheck,ctCheck,nullifierCheck,
    Nat.not_le_of_gt channel,nonzero,Nat.not_le_of_gt slot,Nat.not_le_of_gt index,
    normalized_canonical_amount p.amount hi lo,Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem native_codec_roundtrip (p : PublicInputs) (widths : NativeWidths p) (nonzero : p.channelId ≠ 0) :
    fromU64Slice (toU64Vec p) = .ok p := by
  simp only [fromU64Slice,(public_width_and_circuit_encoding p).1,publicInputLength,
    bne_self_eq_false,Bool.false_eq_true,if_false,encoded_native_fields_read_exactly]
  exact decode_fields_round_trip p widths nonzero

theorem incorrect_length_fails_before_field_decoding (xs : List Nat)
    (length : xs.length ≠ publicInputLength) :
    fromU64Slice xs = fail (.invalidLength xs.length) := by simp [fromU64Slice,length]

theorem native_statement_encoding_injective {p q : PublicInputs}
    (equal : toU64Vec p = toU64Vec q) : p = q :=
  WithdrawalClaimCircuit.public_encoding_injective equal

theorem projection_uses_derived_asset_and_bound_fields (e : Environment) (w : Witness) (index : Nat) :
    (project e w index).tokenIndex = index ∧
    (project e w index).recipient = w.member.recipient ∧
    (project e w index).nullifier = w.claim.nullifier ∧
    (project e w index).amount = splitU64 w.amount := ⟨rfl,rfl,rfl,rfl⟩

/-- Consequences are extracted from the actual ordered Result computation,
    not supplied as an accepted-state safety premise. validate/H1/E3 semantics
    remain separate dependency obligations. -/
theorem successful_structural_checks_expose_actual_guards (e : Environment) (w : Witness)
    (accepted : structuralChecks e w = .ok ()) :
    w.claim.closeId = expectedCloseId e w ∧
    e.hashWords (closeWithdrawalPreimage w.closeTx) = w.closeIntent.withdrawalDigest ∧
    w.closeTx.h1 = w.closeIntent.h1 ∧ w.closeTx.channelId = w.closeIntent.channelId ∧
    w.member.pk = w.claim.memberPk ∧ w.member.recipient = w.claim.recipient ∧
    expectedNullifier e w = w.claim.nullifier ∧ w.claim.tokenSlot < w.state.tokenCount ∧
    e.validateState w.state = .ok () ∧ e.stateH1 w.state = w.closeIntent.h1 ∧
    w.state.channelId = w.closeIntent.channelId ∧ w.memberIndex < 1024 ∧
    w.memberIndex < w.state.memberCount+w.state.delegateCount ∧
    selectedCiphertext w = .ok w.claim.ciphertext ∧
    selectedRecipient w = .ok w.member.recipient := by
  unfold structuralChecks at accepted
  unfold fail at accepted
  by_cases close : (w.claim.closeId != expectedCloseId e w) = true
  · rw [if_pos close] at accepted; contradiction
  rw [if_neg close] at accepted
  by_cases tx : (e.hashWords (closeWithdrawalPreimage w.closeTx) != w.closeIntent.withdrawalDigest) = true ∨
      (w.closeTx.h1 != w.closeIntent.h1) = true ∨ (w.closeTx.channelId != w.closeIntent.channelId) = true
  · rw [if_pos tx] at accepted; contradiction
  rw [if_neg tx] at accepted
  by_cases member : (w.member.pk != w.claim.memberPk) = true ∨
      (w.member.recipient != w.claim.recipient) = true
  · rw [if_pos member] at accepted; contradiction
  rw [if_neg member] at accepted
  by_cases nullifier : (expectedNullifier e w != w.claim.nullifier) = true
  · rw [if_pos nullifier] at accepted; contradiction
  rw [if_neg nullifier] at accepted
  by_cases token : w.claim.tokenSlot ≥ w.state.tokenCount
  · rw [if_pos token] at accepted; contradiction
  rw [if_neg token] at accepted
  cases validation : e.validateState w.state with
  | error err => rw [validation] at accepted; contradiction
  | ok unitResult =>
    cases unitResult
    rw [validation] at accepted
    dsimp only at accepted
    by_cases h1 : (e.stateH1 w.state != w.closeIntent.h1) = true
    · rw [if_pos h1] at accepted; contradiction
    rw [if_neg h1] at accepted
    by_cases channel : (w.state.channelId != w.closeIntent.channelId) = true
    · rw [if_pos channel] at accepted; contradiction
    rw [if_neg channel] at accepted
    by_cases capacity : w.memberIndex ≥ 1024
    · rw [if_pos capacity] at accepted; contradiction
    rw [if_neg capacity] at accepted
    by_cases active : w.memberIndex ≥ w.state.memberCount + w.state.delegateCount
    · rw [if_pos active] at accepted; contradiction
    rw [if_neg active] at accepted
    cases ciphertext : selectedCiphertext w with
    | error err => rw [ciphertext] at accepted; contradiction
    | ok ct =>
      rw [ciphertext] at accepted
      dsimp only at accepted
      by_cases ctEqual : (w.claim.ciphertext != ct) = true
      · rw [if_pos ctEqual] at accepted; contradiction
      rw [if_neg ctEqual] at accepted
      cases recipient : selectedRecipient w with
      | error err => rw [recipient] at accepted; contradiction
      | ok address =>
        rw [recipient] at accepted
        dsimp only at accepted
        by_cases recipientEqual : (w.member.recipient != address) = true
        · rw [if_pos recipientEqual] at accepted; contradiction
        simp_all

theorem in_circuit_route_still_runs_all_structural_checks (e : Environment) (w : Witness)
    (level : Nat) (p : PublicInputs)
    (accepted : toPublicInputsForInCircuitDecryption e w level = .ok p) :
    structuralChecks e w = .ok () := by
  cases check : structuralChecks e w with
  | error err => simp [toPublicInputsForInCircuitDecryption,toPublicInputsInner,check,Bind.bind,Except.bind] at accepted
  | ok value => cases value; rfl

theorem in_circuit_route_does_not_consult_external_proof (e f : Environment)
    (w : Witness) (level : Nat)
    (structural : structuralChecks e w = structuralChecks f w)
    (projection : ∀ index, project e w index = project f w index) :
    toPublicInputsForInCircuitDecryption e w level = toPublicInputsForInCircuitDecryption f w level := by
  simp only [toPublicInputsForInCircuitDecryption,toPublicInputsInner,structural]
  cases structuralChecks f w <;>
    simp [Bind.bind,Except.bind,Pure.pure,Except.pure,projection]

theorem standard_route_requires_external_verification (e : Environment) (w : Witness)
    (level : Nat) (p : PublicInputs) (accepted : toPublicInputs e w level = .ok p) :
    structuralChecks e w = .ok () ∧
    e.verifyExternal level w.key w.claim.ciphertext w.amount w.claim.proofBytes = .ok () := by
  cases checked : structuralChecks e w with
  | error err => simp [toPublicInputs,toPublicInputsInner,checked,Bind.bind,Except.bind] at accepted
  | ok unitResult =>
    cases unitResult
    cases external : e.verifyExternal level w.key w.claim.ciphertext w.amount w.claim.proofBytes with
    | error err => simp [toPublicInputs,toPublicInputsInner,checked,external,fail,Bind.bind,Except.bind] at accepted
    | ok value => cases value; exact ⟨rfl,rfl⟩

theorem close_intent_guard_precedes_remaining_checks (e : Environment) (w : Witness)
    (mismatch : w.claim.closeId ≠ expectedCloseId e w) :
    structuralChecks e w = fail .closeIntentMismatch := by
  simp [structuralChecks,mismatch,fail,Bind.bind,Except.bind]

theorem close_identity_preimage_width (i : Intent) : (closeIntentPreimage i).length = 12 := by
  simp [closeIntentPreimage,CloseCircuit.Words8.words,CloseCircuit.Words2.words]

theorem close_withdrawal_preimage_width (tx : CloseWithdrawal) :
    (closeWithdrawalPreimage tx).length = 42 := by
  simp [closeWithdrawalPreimage,CloseCircuit.Words8.words]

def normalPublicInputs : PublicInputs := {
  closeId := CloseCircuit.Words8.zero
  channelId := 3
  h1 := CloseCircuit.Words8.zero
  memberPk := CloseCircuit.Words8.zero
  recipient := ⟨1,2,3,4,5⟩
  ciphertextDigest := CloseCircuit.Words8.zero
  nullifier := CloseCircuit.Words8.zero
  amount := ⟨0,77⟩
  tokenSlot := 1
  tokenIndex := 7 }

theorem ordinary_native_codec_roundtrip :
    fromU64Slice (toU64Vec normalPublicInputs) = .ok normalPublicInputs := by
  apply native_codec_roundtrip
  · simp [NativeWidths,WithdrawalClaimCircuit.PublicInputs.AllocationChecks,
      WithdrawalClaimCircuit.Checked,WithdrawalClaimCircuit.PublicInputs.words,normalPublicInputs,
      CloseCircuit.Words8.words,CloseCircuit.Words8.zero,CloseCircuit.Words2.words,
      WithdrawalClaimCircuit.Address.words,WithdrawalClaimCircuit.wordBase]
  · decide

end Zkp.Implementation.WithdrawalClaimPublicInputs
